#include "Stage.hpp"
#include "AnmIdx.hpp"
#include "AnmManager.hpp"
#include "Chain.hpp"
#include "ChainPriorities.hpp"
#include "FileSystem.hpp"
#include "GameManager.hpp"
#include "Supervisor.hpp"
#include "ZunColor.hpp"
#include "utils.hpp"
#include <d3d8.h>

DIFFABLE_STATIC(ChainElem, g_StageCalcChain)
DIFFABLE_STATIC(ChainElem, g_StageOnDrawHighPrioChain)
DIFFABLE_STATIC(ChainElem, g_StageOnDrawLowPrioChain)

DIFFABLE_STATIC_ARRAY_ASSIGN(StageFile, 8, g_StageFiles) = {
    {"dummy", "dummy"},
    {"data/stg1bg.anm", "data/stage1.std"},
    {"data/stg2bg.anm", "data/stage2.std"},
    {"data/stg3bg.anm", "data/stage3.std"},
    {"data/stg4bg.anm", "data/stage4.std"},
    {"data/stg5bg.anm", "data/stage5.std"},
    {"data/stg6bg.anm", "data/stage6.std"},
    {"data/stg7bg.anm", "data/stage7.std"},
};

#pragma var_order(stg, timer)
ZunResult Stage::RegisterChain(u32 stage)
{

    Stage *stg = &g_Stage;
    ZunTimer *timer;

    memset(stg, 0, sizeof(Stage));
    stg->stdData = NULL;

    timer = &stg->timer;
    timer->InitializeForPopup();

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
    scriptTimer->InitializeForPopup();

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
    facingDirTimer->InitializeForPopup();
    stage->unpauseFlag = 0;

    g_Supervisor.d3dDevice->SetRenderState(D3DRS_FOGCOLOR, stage->skyFog.color);
    g_Supervisor.d3dDevice->SetRenderState(D3DRS_FOGSTART, *(DWORD *)&stage->skyFog.nearPlane);
    g_Supervisor.d3dDevice->SetRenderState(D3DRS_FOGEND, *(DWORD *)&stage->skyFog.farPlane);
    return ZUN_SUCCESS;
}

#pragma var_order(vmIdx, idx, curObj, curQuad, sizeVmArr, padding1, padding2, padding3, padding4, padding5, padding6)
ZunResult Stage::LoadStageData(char *anmpath, char *stdpath)
{
    RawStageObject *curObj;
    RawStageQuadBasic *curQuad;
    i32 idx;
    i32 vmIdx;
    u32 sizeVmArr;
    u32 padding1, padding2, padding3, padding4, padding5, padding6;

    if (g_AnmManager->LoadAnm(ANM_FILE_STAGEBG, anmpath, ANM_OFFSET_STAGEBG) != ZUN_SUCCESS)
    {
        return ZUN_ERROR;
    }
    this->stdData = (RawStageHeader *)FileSystem::OpenPath(stdpath, false);
    if (this->stdData == NULL)
    {
        GameErrorContextLog(&g_GameErrorContext, TH_ERR_STAGE_DATA_CORRUPTED);
        return ZUN_ERROR;
    }
    this->objectsCount = this->stdData->nbObjects;
    this->quadCount = this->stdData->nbFaces;
    this->objectInstances = (RawStageObjectInstance *)(this->stdData->facesOffset + (i32)this->stdData);
    this->beginningOfScript = (RawStageInstr *)(this->stdData->scriptOffset + (i32)this->stdData);
    this->objects = (RawStageObject **)(this->stdData + 1);
    for (idx = 0; idx < this->objectsCount; idx++)
    {
        this->objects[idx] = (RawStageObject *)((i32)this->objects[idx] + (i32)this->stdData);
    }
    sizeVmArr = this->quadCount * sizeof(AnmVm);
    this->quadVms = (AnmVm *)malloc(sizeVmArr);
    for (idx = 0, vmIdx = 0; idx < this->objectsCount; idx++)
    {
        curObj = this->objects[idx];
        curObj->flags = 1;
        curQuad = &curObj->firstQuad;
        while (0 <= curQuad->type)
        {
            g_AnmManager->ExecuteAnmIdx(&this->quadVms[vmIdx], curQuad->anmScript + ANM_OFFSET_STAGEBG);
            curQuad->vmIdx = vmIdx++;
            curQuad = (RawStageQuadBasic *)((u8 *)curQuad + curQuad->byteSize);
        }
    }
    return ZUN_SUCCESS;
}

DIFFABLE_STATIC(Stage, g_Stage)
