// Copyright (c) 2014-2019 The vds Core developers
// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2013 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "clientversion.h"
#include "rpc/server.h"
#include "init.h"
#include "validation.h"
#include "noui.h"
#include "scheduler.h"
#include "util.h"
#include "masternodeconfig.h"
#include "httpserver.h"
#include "httprpc.h"

#include <boost/algorithm/string/predicate.hpp>
#include <boost/filesystem.hpp>
#include <boost/thread.hpp>

#include <stdio.h>


/* Introduction text for doxygen: */
//doxygen的介绍性文本

/*! \mainpage Developer documentation
 *主页 开发者文档
 * \section intro_sec Introduction
 *节 intro_sec 介绍
 * This is the developer documentation of the reference client for an experimental new digital currency called Bitcoin (https://www.bitcoin.org/),
 * 这是一个名为 "比特币 "的实验性新数字货币的参考客户端的开发者文档
 *
 * which enables instant payments to anyone, anywhere in the world. Bitcoin uses peer-to-peer technology to operate
 * 它可以让世界上任何地方的任何人都能即时支付。比特币使用点对点技术来操作。
 *
 * with no central authority: managing transactions and issuing money are carried out collectively by the network.
 *没有中央权力机构：管理交易和发行货币由网络集体进行；
 *
 * The software is a community-driven open source project, released under the MIT license.
 *该软件是一个社区驱动的开源项目，在MIT许可下发布。
 *
 * \section Navigation//节导航
 * Use the buttons <code>Namespaces</code>, <code>Classes</code> or <code>Files</code> at the top of the page to start navigating the code.
 *//使用页面顶部的按钮<code>Namespaces</code>、<code>Classes</code>或<code>Files</code>开始浏览代码。


static bool fDaemon;//静态函数 布尔常量 父守护程序

void WaitForShutdown(boost::thread_group* threadGroup)//使用线程组，void waitForShutdown(); 这个方法会挂起发出调用的线程直到通信器关闭为止。
{
    bool fShutdown = ShutdownRequested();//关机请求
    // Tell the main threads to shutdown.告诉主线程关闭
    while (!fShutdown) {
        MilliSleep(200);//睡眠时间200毫秒。
        fShutdown = ShutdownRequested();//关机请求
    }
    if (threadGroup) {
        Interrupt(*threadGroup);//// 中断
        threadGroup->join_all();
    }

}

//////////////////////////////////////////////////////////////////////////////
//
// Start
//
bool AppInit(int argc, char* argv[])//应用程序初始化
{
    boost::thread_group threadGroup;
    CScheduler scheduler;

    bool fRet = false;
    //
    // Parameters//参数
    //
    // If Qt is used, parameters/vds.conf are parsed in qt/vds.cpp's main()如果使用Qt，则参数/vds.conf公司在qt中解析/vds.cpp公司的主（）
    ParseParameters(argc, argv);//解析参数

    // Process help and version before taking care about data dir//在处理数据目录之前先处理帮助和版本
    if (mapArgs.count("-?") || mapArgs.count("-h") ||  mapArgs.count("-help") || mapArgs.count("-version")) {
        std::string strUsage = _("Vds Daemon") + " " + _("version") + " " + FormatFullVersion() + "\n" + PrivacyInfo();

        if (mapArgs.count("-version")) {
            strUsage += LicenseInfo();
        } else {
            strUsage += "\n" + _("Usage:") + "\n" +
                        "  vdsd [options]                     " + _("Start Vds Daemon") + "\n";

            strUsage += "\n" + HelpMessage(HMM_BITCOIND);
        }

        fprintf(stdout, "%s", strUsage.c_str());
        return true;
    }

    try {
        bool datadirFromCmdLine = mapArgs.count("-datadir") != 0;
        if (datadirFromCmdLine && !boost::filesystem::is_directory(GetDataDir(false))) {
            fprintf(stderr, "Error: Specified data directory \"%s\" does not exist.\n", mapArgs["-datadir"].c_str());
            return false;
        }
        try {
            ReadConfigFile(mapArgs, mapMultiArgs);
        } catch (const missing_zcash_conf& e) {
            fprintf(stderr,
                    (_("Before starting vdsd, you need to create a configuration file:\n"//在启动vdsd之前，您需要创建一个配置文件
                       "%s\n"
                       "It can be completely empty! That indicates you are happy with the default\n"//它可以是完全空的！表示您对默认值满意\n
                       "configuration of vdsd. But requiring a configuration file to start ensures\n"//vdsd的配置。但是需要一个配置文件来启动可以确保
                       "that vdsd won't accidentally compromise your privacy if there was a default\n"//如果有默认设置，vdsd不会意外地损害你的隐私
                       "option you needed to change.\n"//你需要改变的选项
                       "\n"
                       "You can look at the example configuration file for suggestions of default\n"//您可以查看示例配置文件以获得默认建议
                       "options that you may want to change. It should be in one of these locations,\n"//可能需要更改的选项。应该在其中一个地方
                       "depending on how you installed Vds:\n") +//取决于您如何安装Vds
                     _("- Source code:  %s\n"
                       "- .deb package: %s\n")).c_str(),
                    GetConfigFile().string().c_str(),
                    "contrib/debian/examples/vds.conf",
                    "/usr/share/doc/vds/examples/vds.conf");
            return false;
        } catch (const std::exception& e) {
            fprintf(stderr, "Error reading configuration file: %s\n", e.what());//读取配置文件时出错
            return false;
        }
        if (!datadirFromCmdLine && !boost::filesystem::is_directory(GetDataDir(false))) {
            fprintf(stderr, "Error: Specified data directory \"%s\" from config file does not exist.\n", mapArgs["-datadir"].c_str());//错误：配置文件中指定的数据目录\“%s\”不存在
            return EXIT_FAILURE;
        }
        // Check for -testnet or -regtest parameter (Params() calls are only valid after this clause)//检查-testnet或-regtest参数（Params（）调用仅在此子句之后有效）
        try {
            SelectParams(ChainNameFromCommandLine());
        } catch (const std::exception& e) {
            fprintf(stderr, "Error: %s\n", e.what());
            return false;
        }

        // parse masternode.conf//解析主节点配置文件
        std::string strErr;
        if (!masternodeConfig.read(strErr)) {
            fprintf(stderr, "Error reading masternode configuration file: %s\n", strErr.c_str());//读取主节点配置文件时出错
            return false;
        }

        // Command-line RPC//命令行RPC
        bool fCommandLine = false;
        for (int i = 1; i < argc; i++)
            if (!IsSwitchChar(argv[i][0]) && !boost::algorithm::istarts_with(argv[i], "vds:"))
                fCommandLine = true;

        if (fCommandLine) {
            fprintf(stderr, "Error: There is no RPC client functionality in vdsd. Use the vds-cli utility instead.\n");//错误：vdsd中没有RPC客户端功能。请改用vds cli实用程序。
            exit(1);
        }
#ifndef WIN32
        fDaemon = GetBoolArg("-daemon", false);//守护程序
        if (fDaemon) {
            fprintf(stdout, "Vds server starting\n");//Vds服务器启动

            // Daemonize//守护程序大小
            pid_t pid = fork();
            if (pid < 0) {
                fprintf(stderr, "Error: fork() returned %d errno %d\n", pid, errno);//错误：fork（）返回%d错误号
                return false;
            }
            if (pid > 0) { // Parent process, pid is child process id//父进程，pid是子进程id
                return true;
            }
            // Child process falls through to rest of initialization//子进程将传递到初始化的其余部分

            pid_t sid = setsid();
            if (sid < 0)
                fprintf(stderr, "Error: setsid() returned %d errno %d\n", sid, errno);
        }
#endif
        SoftSetBoolArg("-server", true);

        // Set this early so that parameter interactions go to console//尽早设置，以便参数交互转到控制台
        InitLogging();
        InitParameterInteraction();

        fRet = AppInit2(threadGroup, scheduler);
    } catch (const std::exception& e) {
        PrintExceptionContinue(&e, "AppInit()");
    } catch (...) {
        PrintExceptionContinue(NULL, "AppInit()");
    }

    if (!fRet) {
        Interrupt(threadGroup);
        // threadGroup.join_all(); was left out intentionally here, because we didn't re-test all of//threadGroup.join\u全部（）；被故意遗漏在这里，因为我们没有重新测试所有
        // the startup-failure cases to make sure they don't result in a hang due to some//启动失败案例，以确保它们不会由于某些原因导致挂起
        // thread-blocking-waiting-for-another-thread-during-startup case//线程阻塞在启动过程中等待另一个线程
    } else {
        WaitForShutdown(&threadGroup);
    }

    Shutdown();
    return fRet;
}


int main(int argc, char* argv[])
{
    SetupEnvironment();//设置环境变量，SetupEnvironment 函数，主要用来设置系统的环境变量，包括：malloc 分配内存的行为、Locale、文件路径的本地化设置等。

    // Connect bitcoind signal handlers
    noui_connect();//设置信号处理，noui_connect 函数，设置连接到 bitcoind 的信号的处理。

    return (AppInit(argc, argv) ? EXIT_SUCCESS : EXIT_FAILURE);//启动系统，AppInit 函数，进行系统启动。
}
