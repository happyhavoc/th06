#pragma once

#include "diffbuild.hpp"
#include <Windows.h>

struct SoundPlayer
{
    void Init(HWND window);
    void Release(void);
};

DIFFABLE_EXTERN(SoundPlayer, g_SoundPlayer)
