#pragma once

#include "AnmVm.hpp"
#include "Chain.hpp"
#include "ZunTimer.hpp"
#include "diffbuild.hpp"
#include "inttypes.hpp"
#include "zwave.hpp"
#include <d3d8.h>
#include <d3dx8math.h>

struct RawStageHeader
{
    u16 nbObjects;
    u16 nbFaces;
    u32 facesOffset;
    u32 scriptOffset;
    u32 unk_c;
    char stageName[128];
    char song1Name[128];
    char song2Name[128];
    char song3Name[128];
    char song4Name[128];
    char song1Path[128];
    char song2Path[128];
    char song3Path[128];
    char song4Path[128];
};
C_ASSERT(sizeof(RawStageHeader) == 0x490);

struct StageCameraSky
{
    f32 nearPlane;
    f32 farPlane;
    D3DCOLOR color;
};
C_ASSERT(sizeof(StageCameraSky) == 0xc);

enum SpellcardState
{
    NOT_RUNNING,
    RUNNING,
    RAN_FOR_60_FRAMES
};

struct StageFile
{
    char *anmFile;
    char *stdFile;
};
C_ASSERT(sizeof(StageFile) == 0x8);

struct Stage
{
    static ZunResult RegisterChain(u32 stage);
    static ChainCallbackResult OnUpdate(Stage *stage);
    static ChainCallbackResult OnDrawHighPrio(Stage *stage);
    static ChainCallbackResult OnDrawLowPrio(Stage *stage);
    static ZunResult AddedCallback(Stage *stage);
    static ZunResult DeletedCallback(Stage *stage);

    ZunResult LoadStageData(char *anmpath, char *stdpath);

    AnmVm *quadVms;
    RawStageHeader *stdData;
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
    SpellcardState spellcardState;
    i32 ticksSinceSpellcardStarted;
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
