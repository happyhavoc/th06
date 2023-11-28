#pragma once

#include "diffbuild.hpp"
#include "inttypes.hpp"

struct Rng
{
    u16 seed;
    u32 unk;
};

DIFFABLE_EXTERN(Rng, g_Rng);
