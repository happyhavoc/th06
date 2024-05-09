#include "EffectManager.hpp"

#include "AnmManager.hpp"
#include "Chain.hpp"
#include "ChainPriorities.hpp"
#include "GameManager.hpp"
#include "ZunResult.hpp"

DIFFABLE_STATIC(EffectManager, g_EffectManager);

DIFFABLE_STATIC(ChainElem, g_EffectManagerCalcChain);
DIFFABLE_STATIC(ChainElem, g_EffectManagerDrawChain);

ZunResult EffectManager::RegisterChain()
{
    EffectManager *mgr = &g_EffectManager;
    mgr->Reset();
    g_EffectManagerCalcChain.callback = (ChainCallback)mgr->OnUpdate;
    g_EffectManagerCalcChain.addedCallback = NULL;
    g_EffectManagerCalcChain.deletedCallback = NULL;
    g_EffectManagerCalcChain.addedCallback = (ChainAddedCallback)mgr->AddedCallback;
    g_EffectManagerCalcChain.deletedCallback = (ChainAddedCallback)mgr->AddedCallback;
    g_EffectManagerCalcChain.arg = mgr;
    if (g_Chain.AddToCalcChain(&g_EffectManagerCalcChain, TH_CHAIN_PRIO_CALC_EFFECTMANAGER))
    {
        return ZUN_ERROR;
    }
    g_EffectManagerDrawChain.callback = (ChainCallback)mgr->OnDraw;
    g_EffectManagerDrawChain.addedCallback = NULL;
    g_EffectManagerDrawChain.deletedCallback = NULL;
    g_EffectManagerDrawChain.arg = mgr;
    g_Chain.AddToDrawChain(&g_EffectManagerDrawChain, TH_CHAIN_PRIO_DRAW_EFFECTMANAGER);
    return ZUN_SUCCESS;
}

ZunResult EffectManager::AddedCallback(EffectManager *mgr)
{
    mgr->Reset();
    switch (g_GameManager.currentStage)
    {
    case 0:
    case 1:
        if (g_AnmManager->LoadAnm(0xb, "data/eff01.anm", 0x2b3) != ZUN_SUCCESS)
        {
            return ZUN_ERROR;
        }
        break;
    case 2:
        if (g_AnmManager->LoadAnm(0xb, "data/eff02.anm", 0x2b3) != ZUN_SUCCESS)
        {
            return ZUN_ERROR;
        }
        break;
    case 3:
        if (g_AnmManager->LoadAnm(0xb, "data/eff03.anm", 0x2b3) != ZUN_SUCCESS)
        {
            return ZUN_ERROR;
        }
        break;
    case 4:
        if (g_AnmManager->LoadAnm(0xb, "data/eff04.anm", 0x2b3) != ZUN_SUCCESS)
        {
            return ZUN_ERROR;
        }
        break;
    case 5:
        if (g_AnmManager->LoadAnm(0xb, "data/eff05.anm", 0x2b3) != ZUN_SUCCESS)
        {
            return ZUN_ERROR;
        }
        break;
    case 6:
        if (g_AnmManager->LoadAnm(0xb, "data/eff06.anm", 0x2b3) != ZUN_SUCCESS)
        {
            return ZUN_ERROR;
        }
        break;
    case 7:
        if (g_AnmManager->LoadAnm(0xb, "data/eff07.anm", 0x2b3) != ZUN_SUCCESS)
        {
            return ZUN_ERROR;
        }
        break;
    }
    return ZUN_SUCCESS;
}

void EffectManager::Reset()
{
    memset(this, 0, sizeof(*this));
}
