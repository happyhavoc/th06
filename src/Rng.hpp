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

    u16 GetRandomU16InRange(u16 range)
    {
        return range != 0 ? this->GetRandomU16() % range : 0;
    }

    f32 GetRandomF32InRange(f32 range)
    {
        return this->GetRandomF32ZeroToOne() * range;
    }
};

DIFFABLE_EXTERN(Rng, g_Rng);
