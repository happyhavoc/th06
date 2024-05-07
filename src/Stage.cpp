#include "Stage.hpp"
#include "Chain.hpp"
#include "ChainPriorities.hpp"
#include "Colors.hpp"
#include "GameManager.hpp"
#include "Supervisor.hpp"
#include <d3d8.h>

DIFFABLE_STATIC(ChainElem, g_StageCalcChain)
DIFFABLE_STATIC(ChainElem, g_StageOnDrawHighPrioChain)
DIFFABLE_STATIC(ChainElem, g_StageOnDrawLowPrioChain)

DIFFABLE_STATIC(StageFile, g_StageFiles[8])

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

#pragma var_order(interpFinal, interpInitial, scriptTimer, facingDirTimer)
ZunResult Stage::AddedCallback(Stage *stage)
{
    ZunTimer *facingDirTimer;
    ZunTimer *scriptTimer;

    D3DXVECTOR3 interpFinal;
    D3DXVECTOR3 interpInitial;

    scriptTimer = &stage->scriptTime;
    scriptTimer->current = 0;
    scriptTimer->subFrame = 0.0;
    scriptTimer->previous = -999;
    stage->instructionIndex = 0;
    stage->position.x = 0.0;
    stage->position.y = 0.0;
    stage->position.z = 0.0;
    stage->spellcardState = NOT_RUNNING;
    stage->skyFogInterpDuration = 0;

    if (stage->LoadStageData(g_StageFiles[g_GameManager.currentStage].anmFile,
                             g_StageFiles[g_GameManager.currentStage].stdFile) != ZUN_SUCCESS)
    {
        return ZUN_ERROR;
    }
    stage->skyFog.color = COLOR_BLACK;
    stage->skyFog.nearPlane = 200.0;
    stage->skyFog.farPlane = 500.0;
    interpFinal.x = 0;
    interpFinal.y = 0;
    interpFinal.z = 1.0;
    stage->facingDirInterpFinal = interpFinal;

    interpInitial.x = 0;
    interpInitial.y = 0;
    interpInitial.z = 1.0;
    stage->facingDirInterpInitial = interpInitial;

    stage->facingDirInterpDuration = 1;
    facingDirTimer = &stage->facingDirInterpTimer;
    facingDirTimer->current = 0;
    facingDirTimer->subFrame = 0.0;
    facingDirTimer->previous = -999;
    stage->unpauseFlag = 0;

    g_Supervisor.d3dDevice->SetRenderState(D3DRS_FOGCOLOR, (stage->skyFog).color);
    g_Supervisor.d3dDevice->SetRenderState(D3DRS_FOGSTART, *(DWORD *)&(stage->skyFog).nearPlane);
    g_Supervisor.d3dDevice->SetRenderState(D3DRS_FOGEND, *(DWORD *)&(stage->skyFog).farPlane);
    return ZUN_SUCCESS;
}

DIFFABLE_STATIC(Stage, g_Stage)
