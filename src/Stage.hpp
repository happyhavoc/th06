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
    i16 nbObjects;
    i16 nbFaces;
    i32 facesOffset;
    i32 scriptOffset;
    i32 unk_c;
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

struct RawStageQuadBasic
{
    i16 type;
    i16 byteSize;
    i16 anmScript;
    i16 vmIdx;
    D3DXVECTOR3 position;
    D3DXVECTOR2 size;
};
C_ASSERT(sizeof(RawStageQuadBasic) == 0x1c);

struct RawStageObject
{
    i16 id;
    i8 unk2;
    i8 flags;
    D3DXVECTOR3 position;
    D3DXVECTOR3 size;
    RawStageQuadBasic firstQuad;
};
C_ASSERT(sizeof(RawStageObject) == 0x38);

struct RawStageObjectInstance
{
    i16 id;
    i16 unk2;
    D3DXVECTOR3 position;
};
C_ASSERT(sizeof(RawStageObjectInstance) == 0x10);

struct RawStageInstr
{
    i32 frame;
    i16 opcode;
    i16 size;
    i32 args[3];
};
C_ASSERT(sizeof(RawStageInstr) == 0x14);

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

enum StageOpcode
{
    STDOP_CAMERA_POSITION_KEY,
    STDOP_FOG,
    STDOP_CAMERA_FACING,
    STDOP_CAMERA_FACING_INTERP_LINEAR,
    STDOP_FOG_INTERP,
    STDOP_PAUSE,
};

struct Stage
{
    static ZunResult RegisterChain(u32 stage);
    static ChainCallbackResult OnUpdate(Stage *stage);
    static ChainCallbackResult OnDrawHighPrio(Stage *stage);
    static ChainCallbackResult OnDrawLowPrio(Stage *stage);
    static ZunResult AddedCallback(Stage *stage);
    static ZunResult DeletedCallback(Stage *stage);

    ZunResult LoadStageData(char *anmpath, char *stdpath);
    ZunResult UpdateObjects();
    ZunResult RenderObjects(i32 zLevel);

    AnmVm *quadVms;
    RawStageHeader *stdData;
    i32 quadCount;
    i32 objectsCount;
    RawStageObject **objects;
    RawStageObjectInstance *objectInstances;
    RawStageInstr *beginningOfScript;
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
    i8 skyFogNeedsSetup;
    SpellcardState spellcardState;
    i32 ticksSinceSpellcardStarted;
    AnmVm spellcardBackground;
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
