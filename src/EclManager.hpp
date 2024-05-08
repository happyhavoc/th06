#pragma once

#include "ZunResult.hpp"
#include "diffbuild.hpp"

struct EclManager
{
    ZunResult Load(char *ecl);
};

DIFFABLE_EXTERN(EclManager, g_EclManager);
