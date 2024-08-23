#pragma once

#include "ZunBool.hpp"
#include "ZunResult.hpp"
#include "diffbuild.hpp"
#include "inttypes.hpp"
#include <Windows.h>
#include <d3dx8math.h>

// Forward declaration to avoid include loop.
struct Enemy;
struct EnemyEclContext;
struct EnemyManager;

struct EclTimelineInstrArgs
{
    u32 uintVar1;
    u32 uintVar2;
    u32 uintVar3;
    u16 ushortVar1;
    u16 ushortVar2;
    u32 uintVar4;

    D3DXVECTOR3 *Var1AsVec()
    {
        return (D3DXVECTOR3 *)&this->uintVar1;
    }
};

struct EclTimelineInstr
{
    i16 time;
    i16 arg0;
    i16 opCode;
    i16 size;
    EclTimelineInstrArgs args;
};

struct EclRawInstr
{
    i32 time;
    i16 opCode;
    i16 offsetToNext;
    u32 unk_8;
    i32 eclVarId;
    f32 floatVar1;
    f32 floatVar2;
    f32 floatVar3;
    u16 unk_1c;
    u16 unk_1e;
    u16 unk_20;
};
C_ASSERT(sizeof(EclRawInstr) == 0x24);

struct EclRawHeader
{
    i16 subCount;
    i16 mainCount;
    EclTimelineInstr *timelineOffsets[3];
    void *subOffsets[0];
};
C_ASSERT(sizeof(EclRawHeader) == 0x10);

struct EclManager
{
    ZunResult Load(char *ecl);
    ZunResult RunEcl(Enemy *enemy);
    ZunResult CallEclSub(EnemyEclContext *enemyEcl, i16 subId);

    EclRawHeader *eclFile;
    void **subTable;
    EclTimelineInstr *timeline;
};
C_ASSERT(sizeof(EclManager) == 0xc);

DIFFABLE_EXTERN(EclManager, g_EclManager);
