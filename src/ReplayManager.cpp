#include "ReplayManager.hpp"
#include "FileSystem.hpp"
#include "GameManager.hpp"
#include "Rng.hpp"
#include "Supervisor.hpp"
#include "utils.hpp"

namespace th06
{
DIFFABLE_STATIC(ReplayManager *, g_ReplayManager)

ZunResult ReplayManager::RegisterChain(i32 isDemo, char *replayFile)
{
    ReplayManager *replayMgr;

    if (g_Supervisor.framerateMultiplier < 0.99f && !isDemo)
    {
        return ZUN_SUCCESS;
    }
    g_Supervisor.framerateMultiplier = 1.0f;
    if (g_ReplayManager == NULL)
    {
        replayMgr = new ReplayManager();
        g_ReplayManager = replayMgr;
        replayMgr->replayData = NULL;
        replayMgr->isDemo = isDemo;
        replayMgr->replayFile = replayFile;
        switch (isDemo)
        {
        case false:
            replayMgr->calcChain = g_Chain.CreateElem((ChainCallback)ReplayManager::OnUpdate);
            replayMgr->calcChain->addedCallback = (ChainAddedCallback)AddedCallback;
            replayMgr->calcChain->deletedCallback = (ChainDeletedCallback)DeletedCallback;
            replayMgr->drawChain = g_Chain.CreateElem((ChainCallback)ReplayManager::OnDraw);
            replayMgr->calcChain->arg = replayMgr;
            if (g_Chain.AddToCalcChain(replayMgr->calcChain, TH_CHAIN_PRIO_CALC_REPLAYMANAGER))
            {
                return ZUN_ERROR;
            }
            replayMgr->calcChainDemoHighPrio = NULL;
            break;
        case true:
            replayMgr->calcChain = g_Chain.CreateElem((ChainCallback)ReplayManager::OnUpdateDemoHighPrio);
            replayMgr->calcChain->addedCallback = (ChainAddedCallback)AddedCallbackDemo;
            replayMgr->calcChain->deletedCallback = (ChainDeletedCallback)DeletedCallback;
            replayMgr->drawChain = g_Chain.CreateElem((ChainCallback)ReplayManager::OnDraw);
            replayMgr->calcChain->arg = replayMgr;
            if (g_Chain.AddToCalcChain(replayMgr->calcChain, TH_CHAIN_PRIO_CALC_LOW_PRIO_REPLAYMANAGER_DEMO))
            {
                return ZUN_ERROR;
            }
            replayMgr->calcChainDemoHighPrio = g_Chain.CreateElem((ChainCallback)ReplayManager::OnUpdateDemoLowPrio);
            replayMgr->calcChainDemoHighPrio->arg = replayMgr;
            g_Chain.AddToCalcChain(replayMgr->calcChainDemoHighPrio, TH_CHAIN_PRIO_CALC_HIGH_PRIO_REPLAYMANAGER_DEMO);
            break;
        }
        replayMgr->drawChain->arg = replayMgr;
        g_Chain.AddToDrawChain(replayMgr->drawChain, TH_CHAIN_PRIO_DRAW_REPLAYMANAGER);
    }
    else
    {
        switch (isDemo)
        {
        case false:
            AddedCallback(g_ReplayManager);
            break;
        case true:
            return AddedCallbackDemo(g_ReplayManager);
            break;
        }
    }
    return ZUN_SUCCESS;
}

__inline StageReplayData *AllocateStageReplayData(i32 size)
{
    return (StageReplayData *)malloc(size);
}

#pragma var_order(stageReplayData, idx, oldStageReplayData)
ZunResult ReplayManager::AddedCallback(ReplayManager *mgr)
{
    StageReplayData *stageReplayData;
    StageReplayData *oldStageReplayData;
    i32 idx;

    mgr->frameId = 0;
    if (mgr->replayData == NULL)
    {
        mgr->replayData = new ReplayData();
        memcpy(&mgr->replayData->magic[0], "T6RP", 4);
        mgr->replayData->shottypeChara = g_GameManager.character * 2 + g_GameManager.shotType;
        mgr->replayData->version = 0x102;
        mgr->replayData->difficulty = g_GameManager.difficulty;
        memcpy(&mgr->replayData->name, "NO NAME", 4);
        for (idx = 0; idx < ARRAY_SIZE_SIGNED(mgr->replayData->stageReplayData); idx += 1)
        {
            mgr->replayData->stageReplayData[idx] = NULL;
        }
    }
    else
    {
        oldStageReplayData = mgr->replayData->stageReplayData[g_GameManager.currentStage - 2];
        if (oldStageReplayData == NULL)
        {
            return ZUN_ERROR;
        }
        oldStageReplayData->score = g_GameManager.score;
    }
    if (mgr->replayData->stageReplayData[g_GameManager.currentStage - 1] != NULL)
    {
        utils::DebugPrint2("error : replay.cpp");
    }
    mgr->replayData->stageReplayData[g_GameManager.currentStage - 1] = AllocateStageReplayData(sizeof(StageReplayData));
    stageReplayData = mgr->replayData->stageReplayData[g_GameManager.currentStage - 1];
    stageReplayData->bombsRemaining = g_GameManager.bombsRemaining;
    stageReplayData->livesRemaining = g_GameManager.livesRemaining;
    stageReplayData->power = g_GameManager.currentPower;
    stageReplayData->rank = g_GameManager.rank;
    stageReplayData->pointItemsCollected = g_GameManager.pointItemsCollected;
    stageReplayData->randomSeed = g_GameManager.randomSeed;
    stageReplayData->powerItemCountForScore = g_GameManager.powerItemCountForScore;
    mgr->replayInputs = stageReplayData->replayInputs;
    mgr->replayInputs->frameNum = 0;
    mgr->replayInputs->inputKey = 0;
    mgr->unk44 = 0;
    return ZUN_SUCCESS;
}

ZunResult ReplayManager::AddedCallbackDemo(ReplayManager *mgr)
{
    i32 idx;
    StageReplayData *replayData;

    mgr->frameId = 0;
    if (mgr->replayData == NULL)
    {
        mgr->replayData = (ReplayData *)FileSystem::OpenPath(mgr->replayFile, g_GameManager.demoMode == 0);
        if (ValidateReplayData(mgr->replayData, g_LastFileSize) != ZUN_SUCCESS)
        {
            return ZUN_ERROR;
        }
        for (idx = 0; idx < ARRAY_SIZE_SIGNED(mgr->replayData->stageReplayData); idx += 1)
        {
            if (mgr->replayData->stageReplayData[idx] != NULL)
            {
                mgr->replayData->stageReplayData[idx] =
                    (StageReplayData *)((i32)mgr->replayData->stageReplayData[idx] + (i32)mgr->replayData);
            }
        }
    }
    if (mgr->replayData->stageReplayData[g_GameManager.currentStage - 1] == NULL)
    {
        return ZUN_ERROR;
    }
    replayData = mgr->replayData->stageReplayData[g_GameManager.currentStage - 1];
    g_GameManager.character = mgr->replayData->shottypeChara / 2;
    g_GameManager.shotType = mgr->replayData->shottypeChara % 2;
    g_GameManager.difficulty = (Difficulty)mgr->replayData->difficulty;
    g_GameManager.pointItemsCollected = replayData->pointItemsCollected;
    g_Rng.Initialize(replayData->randomSeed);
    g_GameManager.rank = replayData->rank;
    g_GameManager.livesRemaining = replayData->livesRemaining;
    g_GameManager.bombsRemaining = replayData->bombsRemaining;
    g_GameManager.currentPower = replayData->power;
    mgr->replayInputs = replayData->replayInputs;
    g_GameManager.powerItemCountForScore = replayData->powerItemCountForScore;
    if (2 <= g_GameManager.currentStage && mgr->replayData->stageReplayData[g_GameManager.currentStage - 2] != NULL)
    {
        g_GameManager.guiScore = mgr->replayData->stageReplayData[g_GameManager.currentStage - 2]->score;
        g_GameManager.score = g_GameManager.guiScore;
    }
    return ZUN_SUCCESS;
}
}; // namespace th06
