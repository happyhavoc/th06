#pragma once

#include <d3d8.h>
#include <d3dx8math.h>

#include "ZunColor.hpp"
#include "ZunMath.hpp"
#include "ZunResult.hpp"
#include "ZunTimer.hpp"
#include "diffbuild.hpp"
#include "inttypes.hpp"

struct AnmLoadedSprite
{
    i32 sourceFileIndex;
    ZunVec2 startPixelInclusive;
    ZunVec2 endPixelInclusive;
    f32 textureHeight;
    f32 textureWidth;
    ZunVec2 uvStart;
    ZunVec2 uvEnd;
    f32 heightPx;
    f32 widthPx;
    i32 spriteId;
};
C_ASSERT(sizeof(AnmLoadedSprite) == 0x38);

#define AnmOpcode_Exit 0
#define AnmOpcode_SetActiveSprite 1
#define AnmOpcode_SetScale 2
#define AnmOpcode_SetAlpha 3
#define AnmOpcode_SetColor 4
#define AnmOpcode_Jump 5
#define AnmOpcode_Nop 6
#define AnmOpcode_FlipX 7
#define AnmOpcode_FlipY 8
#define AnmOpcode_SetRotation 9
#define AnmOpcode_SetPosition 10
#define AnmOpcode_SetScaleSpeed 11
#define AnmOpcode_Fade 12
#define AnmOpcode_SetBlendAdditive 13
#define AnmOpcode_SetBlendDefault 14
#define AnmOpcode_ExitHide 15
#define AnmOpcode_SetRandomSprite 16
#define AnmOpcode_SetTranslation 17
#define AnmOpcode_PosTimeLinear 18
#define AnmOpcode_PosTimeDecel 19
#define AnmOpcode_PosTimeAccel 20
#define AnmOpcode_Stop 21
#define AnmOpcode_InterruptLabel 22
#define AnmOpcode_23 23
#define AnmOpcode_StopHide 24
#define AnmOpcode_25 25
#define AnmOpcode_SetAutoRotate 26
#define AnmOpcode_27 27
#define AnmOpcode_28 28
#define AnmOpcode_SetVisibility 29
#define AnmOpcode_30 30
#define AnmOpcode_31 31

struct AnmRawInstr
{
    i16 time;
    u8 opcode;
    u8 argsCount;
    u32 args[10];
};

enum AnmVmFlagsEnum
{
    AnmVmFlags_0 = 1 << 0,
    AnmVmFlags_1 = 1 << 1,
    AnmVmFlags_2 = 1 << 2,
    AnmVmFlags_3 = 1 << 3,
    AnmVmFlags_4 = 1 << 4,
    AnmVmFlags_5 = 1 << 5,
    AnmVmFlags_FlipX = 1 << 6,
    AnmVmFlags_FlipY = 1 << 7,
    AnmVmFlags_8 = 1 << 8,
    AnmVmFlags_9 = 1 << 9,
    AnmVmFlags_10 = 1 << 10,
    AnmVmFlags_11 = 1 << 11,
    AnmVmFlags_12 = 1 << 12,
    AnmVmFlags_13 = 1 << 13,
    AnmVmFlags_14 = 1 << 14,
    AnmVmFlags_15 = 1 << 15,
};

enum AnmVmBlendMode
{
    AnmVmBlendMode_InvSrcAlpha,
    AnmVmBlendMode_One,
};

enum AnmVmColorOp
{
    AnmVmColorOp_Modulate,
    AnmVmColorOp_Add,
};

union AnmVmFlags {
    u32 flags;
    struct
    {
        u32 flag0 : 1;
        u32 flag1 : 1;
        u32 blendMode : 1;
        u32 colorOp : 1;
        u32 flag4 : 1;
        u32 flag5 : 1;
        u32 flip : 2;
        u32 flag8 : 1;
        u32 flag9 : 1;
        u32 posTime : 2;
        u32 zWriteDisable : 1;
        u32 flag13 : 1;
        u32 flag14 : 1;
        u32 flag15 : 1;
    };
};

struct AnmVm
{
    AnmVm();

    void Initialize();

    D3DXVECTOR3 rotation;
    D3DXVECTOR3 angleVel;
    f32 scaleY;
    f32 scaleX;
    f32 scaleInterpFinalY;
    f32 scaleInterpFinalX;
    D3DXVECTOR2 uvScrollPos;
    ZunTimer currentTimeInScript;
    D3DXMATRIX matrix;
    ZunColor color;
    AnmVmFlags flags;

    i16 alphaInterpEndTime;
    i16 scaleInterpEndTime;
    u16 autoRotate;
    i16 pendingInterrupt;
    i16 posInterpEndTime;
    // Two padding bytes
    D3DXVECTOR3 pos;
    f32 scaleInterpInitialY;
    f32 scaleInterpInitialX;
    ZunTimer scaleInterpTime;
    i16 spriteNumber;
    i16 anotherSpriteNumber;
    i16 anmFileIndex;
    // Two padding bytes
    AnmRawInstr *beginingOfScript;
    AnmRawInstr *currentInstruction;
    AnmLoadedSprite *sprite;
    D3DCOLOR alphaInterpInitial;
    D3DCOLOR alphaInterpFinal;
    D3DXVECTOR3 posInterpInitial;
    D3DXVECTOR3 posInterpFinal;
    D3DXVECTOR3 posOffset;
    ZunTimer posInterpTime;
    i32 timeOfLastSpriteSet;
    ZunTimer alphaInterpTime;
    u8 fontWidth;
    u8 fontHeight;
    // Two final padding bytes
};
C_ASSERT(sizeof(AnmVm) == 0x110);
