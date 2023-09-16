#pragma once

#include "inttypes.hpp"
#include <windows.h>

struct GameWindow
{
    i32 Render(void);

    HWND window;
    i32 isAppClosing;
    i32 lastActiveAppValue;
    i32 isAppActive;
    u8 curFrame;
};

extern GameWindow g_GameWindow;
