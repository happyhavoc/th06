#pragma once

#include <Windows.h>

#include "ZunResult.hpp"
#include "diffbuild.hpp"
#include "inttypes.hpp"

struct SoundPlayer
{
    void Init(HWND window);
    ZunResult InitSoundBuffers();
    void Release(void);
};

DIFFABLE_EXTERN(SoundPlayer, g_SoundPlayer)
