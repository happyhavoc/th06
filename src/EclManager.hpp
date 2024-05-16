#pragma once

#include "ZunResult.hpp"
#include "diffbuild.hpp"
#include "inttypes.hpp"
#include <Windows.h>

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

struct EclManager
{
    ZunResult Load(char *ecl);
};

DIFFABLE_EXTERN(EclManager, g_EclManager);
