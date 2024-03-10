#pragma once

#include <Windows.h>
#include "inttypes.hpp"

struct ZunTimer
{
    ZunTimer();

    i32 previous;
    f32 subFrame;
    i32 current;
};
C_ASSERT(sizeof(ZunTimer) == 0xc);
