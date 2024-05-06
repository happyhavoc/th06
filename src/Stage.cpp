#include "Stage.hpp"
#include "Chain.hpp"
#include "ChainPriorities.hpp"

DIFFABLE_STATIC(ChainElem, g_StageCalcChain)
DIFFABLE_STATIC(ChainElem, g_StageOnDrawHighPrioChain)
DIFFABLE_STATIC(ChainElem, g_StageOnDrawLowPrioChain)

#pragma var_order(stg, timer)
ZunResult Stage::RegisterChain(u32 stage)
{

    Stage *stg = &g_Stage;
    ZunTimer *timer;

    memset(stg, 0, sizeof(Stage));
    stg->stdData = NULL;

    timer = &stg->timer;
    timer->current = 0;
    timer->subFrame = 0.0;
    timer->previous = -999;
    stg->stage = stage;
    g_StageCalcChain.callback = (ChainCallback)Stage::OnUpdate;
    g_StageCalcChain.addedCallback = NULL;
    g_StageCalcChain.deletedCallback = NULL;
    g_StageCalcChain.addedCallback = (ChainAddedCallback)Stage::AddedCallback;
    g_StageCalcChain.deletedCallback = (ChainDeletedCallback)Stage::DeletedCallback;
    g_StageCalcChain.arg = stg;

    if (g_Chain.AddToCalcChain(&g_StageCalcChain, TH_CHAIN_PRIO_CALC_STAGE))
    {
        return ZUN_ERROR;
    }
    g_StageOnDrawHighPrioChain.callback = (ChainCallback)OnDrawHighPrio;
    g_StageOnDrawHighPrioChain.addedCallback = NULL;
    g_StageOnDrawHighPrioChain.deletedCallback = NULL;
    g_StageOnDrawHighPrioChain.arg = stg;
    g_Chain.AddToDrawChain(&g_StageOnDrawHighPrioChain, TH_CHAIN_PRIO_DRAW_HIGH_PRIO_STAGE);
    g_StageOnDrawLowPrioChain.callback = (ChainCallback)OnDrawLowPrio;
    g_StageOnDrawLowPrioChain.addedCallback = NULL;
    g_StageOnDrawLowPrioChain.deletedCallback = NULL;
    g_StageOnDrawLowPrioChain.arg = stg;
    g_Chain.AddToDrawChain(&g_StageOnDrawLowPrioChain, TH_CHAIN_PRIO_DRAW_LOW_PRIO_STAGE);

    return ZUN_SUCCESS;
}

DIFFABLE_STATIC(Stage, g_Stage)
