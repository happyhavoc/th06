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

struct AnmRawInstr
{
};

enum AnmVmFlagsEnum
{
    AnmVmFlags_0 = 1 << 0,
    AnmVmFlags_1 = 1 << 1,
    AnmVmFlags_2 = 1 << 2,
    AnmVmFlags_3 = 1 << 3,
    AnmVmFlags_4 = 1 << 4,
    AnmVmFlags_5 = 1 << 5,
    AnmVmFlags_6 = 1 << 6,
    AnmVmFlags_7 = 1 << 7,
    AnmVmFlags_8 = 1 << 8,
    AnmVmFlags_9 = 1 << 9,
    AnmVmFlags_10 = 1 << 10,
    AnmVmFlags_11 = 1 << 11,
    AnmVmFlags_12 = 1 << 12,
    AnmVmFlags_13 = 1 << 13,
    AnmVmFlags_14 = 1 << 14,
    AnmVmFlags_15 = 1 << 15,
};

union AnmVmFlags {
    u32 flags;
    struct
    {
        u32 flag0 : 1;
        u32 flag1 : 1;
        u32 flag2 : 1;
        u32 flag3 : 1;
        u32 flag4 : 1;
        u32 flag5 : 1;
        u32 flag6 : 2;
        u32 flag8 : 1;
        u32 flag9 : 1;
        u32 flag10 : 2;
        u32 flag12 : 1;
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
    u16 alphaInterpEndTime;
    u16 scaleInterpEndTime;
    u16 autoRotate;
    i16 pendingInterrupt;
    u16 posInterpEndTime;
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
