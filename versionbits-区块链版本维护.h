// Copyright (c) 2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef VDS_CONSENSUS_VERSIONBITS
#define VDS_CONSENSUS_VERSIONBITS

#include "chain.h"
#include <map>

/** What block version to use for new blocks (pre versionbits) */
// * *用于新块的块版本（预版本位）* /
static const int32_t VERSIONBITS_LAST_OLD_BLOCK_VERSION = 4;
/** What bits to set in version for versionbits blocks */
// * *版本中为版本位块设置的位* /
static const int32_t VERSIONBITS_TOP_BITS = 0x20000000UL;
/** What bitmask determines whether versionbits is in use */
// * *哪个位掩码确定版本位是否正在使用中* /
static const int32_t VERSIONBITS_TOP_MASK = 0xE0000000UL;
/** Total bits available for versionbits */
// * *版本位可用的总位* /
static const int32_t VERSIONBITS_NUM_BITS = 29;

enum ThresholdState {
    THRESHOLD_DEFINED,
    THRESHOLD_STARTED,
    THRESHOLD_LOCKED_IN,
    THRESHOLD_ACTIVE,
    THRESHOLD_FAILED,
};

// A map that gives the state for blocks whose height is a multiple of Period().
// The map is indexed by the block's parent, however, so all keys in the map
// will either be NULL or a block with (height + 1) % Period() == 0.
//给出高度为Period（）倍数的块的状态的映射。
//但是，该地图由该块的父级索引，因此，该地图中的所有键
//将为NULL或（height + 1）％Period（）== 0的块。

typedef std::map<const CBlockIndex*, ThresholdState> ThresholdConditionCache;

struct BIP9DeploymentInfo {
    /** Deployment name */ / * *部署名称* /
    const char *name;
    /** Whether GBT clients can safely ignore this rule in simplified usage */
    // * * GBT客户端是否可以安全地忽略此规则，以简化使用方式* /
    bool gbt_force;
    /** Whether to check current MN protocol or not */
     // * *是否检查当前的MN协议* /
    bool check_mn_protocol;
};

extern const struct BIP9DeploymentInfo VersionBitsDeploymentInfo[];

/**
 * Abstract class that implements BIP9-style threshold logic, and caches results.
 * *实现BIP9样式阈值逻辑并缓存结果的抽象类。
 */
class AbstractThresholdConditionChecker {
protected:
    virtual bool Condition(const CBlockIndex* pindex, const Consensus::Params& params) const =0;
    virtual int64_t BeginTime(const Consensus::Params& params) const =0;
    virtual int64_t EndTime(const Consensus::Params& params) const =0;
    virtual int Period(const Consensus::Params& params) const =0;
    virtual int Threshold(const Consensus::Params& params) const =0;

public:
    // Note that the function below takes a pindexPrev as input: they compute information for block B based on its parent.
    //请注意，下面的函数将pindexPrev作为输入：它们基于块B的父代计算块B的信息。
    ThresholdState GetStateFor(const CBlockIndex* pindexPrev, const Consensus::Params& params, ThresholdConditionCache& cache) const;
};

struct VersionBitsCache
{
    ThresholdConditionCache caches[Consensus::MAX_VERSION_BITS_DEPLOYMENTS];

    void Clear();
};

ThresholdState VersionBitsState(const CBlockIndex* pindexPrev, const Consensus::Params& params, Consensus::DeploymentPos pos, VersionBitsCache& cache);
uint32_t VersionBitsMask(const Consensus::Params& params, Consensus::DeploymentPos pos);

#endif
