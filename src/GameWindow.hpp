#pragma once

#include <windows.h>

struct GameWindow
{
    int Render(void);

    HWND window;
    int isAppClosing;
    int lastActiveAppValue;
    int isAppActive;
    BYTE curFrame;
};

extern GameWindow g_GameWindow;
