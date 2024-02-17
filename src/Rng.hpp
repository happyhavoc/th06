#pragma once

#include "diffbuild.hpp"
#include "inttypes.hpp"

struct Rng
{
    u16 seed;
    u32 generationCount;

    u16 GetRandomU16();
    u32 GetRandomU32();
    f32 GetRandomF32ZeroToOne();
};

DIFFABLE_EXTERN(Rng, g_Rng);
