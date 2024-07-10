#pragma once
#include "inttypes.hpp"
#include <Windows.h>

struct ZunVec2
{
    f32 x;
    f32 y;
};
C_ASSERT(sizeof(ZunVec2) == 0x8);

struct ZunVec3
{
    f32 x;
    f32 y;
    f32 z;
};
C_ASSERT(sizeof(ZunVec3) == 0xC);

#define ZUN_PI ((f32)(3.14159265358979323846))

#define sincos(in, out_sine, out_cosine)                                                                               \
    {                                                                                                                  \
        __asm { \
        __asm fld in \
        __asm fsincos \
        __asm fstp out_cosine \
        __asm fstp out_sine }                                            \
    }
