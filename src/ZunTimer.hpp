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

    void InitializeForPopup()
    {
        this->current = 0;
        this->subFrame = 0;
        this->previous = -999;
    }
};
C_ASSERT(sizeof(ZunTimer) == 0xc);
