#pragma once

#include <Windows.h>

struct SoundPlayer
{
    void Init(HWND window);
    void Release(void);
};

extern SoundPlayer g_SoundPlayer;
