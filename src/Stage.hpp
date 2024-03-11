#pragma once

#include "AnmManager.hpp"
#include "ZunTimer.hpp"
#include "diffbuild.hpp"
#include "inttypes.hpp"

struct StageCameraSky
{
    f32 nearPlane;
    f32 farPlane;
    D3DCOLOR color;
};
C_ASSERT(sizeof(StageCameraSky) == 0xc);

struct Stage
{
    AnmVm *quadVms;
    u8 *stdData;
    i32 quadCount;
    i32 objectsCount;
    // TODO: This has type StdRawObject**
    void *objects;
    // TODO: This has type StdRawInstance*
    void *objectInstances;
    // TODO: This has type StdRawInstr*
    void *beginningOfScript;
    ZunTimer scriptTime;
    i32 instructionIndex;
    ZunTimer timer;
    u32 stage;
    D3DXVECTOR3 position;
    StageCameraSky skyFog;
    StageCameraSky skyFogInterpInitial;
    StageCameraSky skyFogInterpFinal;
    i32 skyFogInterpDuration;
    ZunTimer skyFogInterpTimer;
    u8 skyFogNeedsSetup;
    i32 spellcardEclRelated0;
    i32 spellcardEclRelated1;
    AnmVm unk1;
    AnmVm unk2;
    u8 unpauseFlag;
    D3DXVECTOR3 facingDirInterpInitial;
    D3DXVECTOR3 facingDirInterpFinal;
    i32 facingDirInterpDuration;
    ZunTimer facingDirInterpTimer;
    D3DXVECTOR3 positionInterpFinal;
    i32 positionInterpEndTime;
    D3DXVECTOR3 positionInterpInitial;
    i32 positionInterpStartTime;
};
C_ASSERT(sizeof(Stage) == 0x2f4);

DIFFABLE_EXTERN(Stage, g_Stage)
