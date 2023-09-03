#pragma once

#include <windows.h>

struct GameWindow
{
    HWND window;
    int isAppClosing;
    int lastActiveAppValue;
    int isAppActive;
};

extern GameWindow g_GameWindow;
