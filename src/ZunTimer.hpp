#pragma once

#include "inttypes.hpp"
#include <Windows.h>

struct ZunTimer
{
    i32 previous;
    f32 subFrame;
    i32 current;

    ZunTimer()
    {
        this->Initialize();
    }

    void Initialize();
    void Increment(i32 value);
    void Decrement(i32 value);
};
C_ASSERT(sizeof(ZunTimer) == 0xc);
