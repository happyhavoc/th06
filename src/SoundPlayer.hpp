#pragma once

#include <Windows.h>

#include "ZunResult.hpp"
#include "diffbuild.hpp"
#include "inttypes.hpp"

struct SoundPlayer
{
    void InitializeDSound(HWND window);
    ZunResult InitSoundBuffers();
    ZunResult Release(void);
};

DIFFABLE_EXTERN(SoundPlayer, g_SoundPlayer)
