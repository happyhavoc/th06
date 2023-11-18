#pragma once

#include "diffbuild.hpp"
#include "inttypes.hpp"

struct Stage
{
    u8 skyFogNeedsSetup;
};

DIFFABLE_EXTERN(Stage, g_Stage)
