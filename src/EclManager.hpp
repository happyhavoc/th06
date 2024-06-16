#pragma once

#include "ZunBool.hpp"
#include "ZunResult.hpp"
#include "diffbuild.hpp"
#include "inttypes.hpp"
#include <Windows.h>

// Forward declaration to avoid include loop.
struct Enemy;
struct EnemyEclContext;

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

struct RunningSpellcardInfo
{
    ZunBool isCapturing;
    ZunBool isActive;
    u32 captureScore;
    u32 idx;
    ZunBool usedBomb;
};
C_ASSERT(sizeof(RunningSpellcardInfo) == 0x14);

struct EclRawHeader
{
    i16 subCount;
    i16 mainCount;
    void *timelineOffsets[3];
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
    void *timeline;
};
C_ASSERT(sizeof(EclManager) == 0xc);

DIFFABLE_EXTERN(RunningSpellcardInfo, g_RunningSpellcardInfo);
DIFFABLE_EXTERN(EclManager, g_EclManager);
