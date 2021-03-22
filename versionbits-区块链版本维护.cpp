// Copyright (c) 2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "versionbits.h"

#include "consensus/params.h"

const struct BIP9DeploymentInfo VersionBitsDeploymentInfo[Consensus::MAX_VERSION_BITS_DEPLOYMENTS] = {
    {
        /*.name =*/ "testdummy",
        /*.gbt_force =*/ true,
        /*.check_mn_protocol =*/ false,
    },
    {
        /*.name =*/ "csv",
        /*.gbt_force =*/ true,
        /*.check_mn_protocol =*/ false,
    },
    {
        /*.name =*/ "segwit",
        /*.gbt_force =*/ true,
        /*.check_mn_protocol =*/ true,
    }
};

ThresholdState AbstractThresholdConditionChecker::GetStateFor(const CBlockIndex* pindexPrev, const Consensus::Params& params, ThresholdConditionCache& cache) const
{
    int nPeriod = Period(params);
    int nThreshold = Threshold(params);
    int64_t nTimeStart = BeginTime(params);
    int64_t nTimeTimeout = EndTime(params);

    // A block's state is always the same as that of the first of its period, so it is computed based on a pindexPrev whose height equals a multiple of nPeriod - 1.
    //块的状态始终与其周期中第一个周期的状态相同，因此，根据其高度等于nPeriod-1的倍数的pindexPrev进行计算。
    if (pindexPrev != NULL) {
        pindexPrev = pindexPrev->GetAncestor(pindexPrev->nHeight - ((pindexPrev->nHeight + 1) % nPeriod));
    }

    // Walk backwards in steps of nPeriod to find a pindexPrev whose information is known
    //向后走nPeriod步骤以查找其信息已知的pindexPrev
    std::vector<const CBlockIndex*> vToCompute;
    while (cache.count(pindexPrev) == 0) {
        if (pindexPrev == NULL) {
            // The genesis block is by definition defined.
             //根据定义定义了创世块。
            cache[pindexPrev] = THRESHOLD_DEFINED;
            break;
        }
        if (pindexPrev->GetMedianTimePast() < nTimeStart) {
            // Optimization: don't recompute down further, as we know every earlier block will be before the start time
             //优化：不要进一步重新计算，因为我们知道每个较早的块都将在开始时间之前
            cache[pindexPrev] = THRESHOLD_DEFINED;
            break;
        }
        vToCompute.push_back(pindexPrev);
        pindexPrev = pindexPrev->GetAncestor(pindexPrev->nHeight - nPeriod);
    }

    // At this point, cache[pindexPrev] is known
    //至此，知道cache [pindexPrev]
    assert(cache.count(pindexPrev));
    ThresholdState state = cache[pindexPrev];

    // Now walk forward and compute the state of descendants of pindexPrev
    //现在向前走并计算pindexPrev的后代状态
    while (!vToCompute.empty()) {
        ThresholdState stateNext = state;
        pindexPrev = vToCompute.back();
        vToCompute.pop_back();

        switch (state) {
        case THRESHOLD_DEFINED: {
            if (pindexPrev->GetMedianTimePast() >= nTimeTimeout) {
                stateNext = THRESHOLD_FAILED;
            } else if (pindexPrev->GetMedianTimePast() >= nTimeStart) {
                stateNext = THRESHOLD_STARTED;
            }
            break;
        }
        case THRESHOLD_STARTED: {
            if (pindexPrev->GetMedianTimePast() >= nTimeTimeout) {
                stateNext = THRESHOLD_FAILED;
                break;
            }
            // We need to count //我们需要计算
            const CBlockIndex* pindexCount = pindexPrev;
            int count = 0;
            for (int i = 0; i < nPeriod; i++) {
                if (Condition(pindexCount, params)) {
                    count++;
                }
                pindexCount = pindexCount->pprev;
            }
            if (count >= nThreshold) {
                stateNext = THRESHOLD_LOCKED_IN;
            }
            break;
        }
        case THRESHOLD_LOCKED_IN: {
            // Always progresses into ACTIVE. //始终进入活动状态。
            stateNext = THRESHOLD_ACTIVE;
            break;
        }
        case THRESHOLD_FAILED:
        case THRESHOLD_ACTIVE: {
            // Nothing happens, these are terminal states.//没有任何反应，这些是终端状态。
            break;
        }
        }
        cache[pindexPrev] = state = stateNext;
    }

    return state;
}

namespace
{
/**
 * Class to implement versionbits logic.*实现版本位逻辑的类。
 */
class VersionBitsConditionChecker : public AbstractThresholdConditionChecker
{
private:
    const Consensus::DeploymentPos id;

protected:
    int64_t BeginTime(const Consensus::Params& params) const
    {
        return params.vDeployments[id].nStartTime;
    }
    int64_t EndTime(const Consensus::Params& params) const
    {
        return params.vDeployments[id].nTimeout;
    }
    int Period(const Consensus::Params& params) const
    {
        return params.nMinerConfirmationWindow;
    }
    int Threshold(const Consensus::Params& params) const
    {
        return params.nRuleChangeActivationThreshold;
    }

    bool Condition(const CBlockIndex* pindex, const Consensus::Params& params) const
    {
        return (((pindex->nVersion & VERSIONBITS_TOP_MASK) == VERSIONBITS_TOP_BITS) && (pindex->nVersion & Mask(params)) != 0);
    }

public:
    VersionBitsConditionChecker(Consensus::DeploymentPos id_) : id(id_) {}
    uint32_t Mask(const Consensus::Params& params) const
    {
        return ((uint32_t)1) << params.vDeployments[id].bit;
    }
};

}

ThresholdState VersionBitsState(const CBlockIndex* pindexPrev, const Consensus::Params& params, Consensus::DeploymentPos pos, VersionBitsCache& cache)
{
    return VersionBitsConditionChecker(pos).GetStateFor(pindexPrev, params, cache.caches[pos]);
}

uint32_t VersionBitsMask(const Consensus::Params& params, Consensus::DeploymentPos pos)
{
    return VersionBitsConditionChecker(pos).Mask(params);
}

void VersionBitsCache::Clear()
{
    for (unsigned int d = 0; d < Consensus::MAX_VERSION_BITS_DEPLOYMENTS; d++) {
        caches[d].clear();
    }
}
