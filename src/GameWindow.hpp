#pragma once

#include "diffbuild.hpp"
#include "inttypes.hpp"
#include <windows.h>

enum RenderResult
{
    RENDER_RESULT_KEEP_RUNNING,
    RENDER_RESULT_EXIT_SUCCESS,
    RENDER_RESULT_EXIT_ERROR,
};

struct GameWindow
{
    RenderResult Render();
    static void Present();

    HWND window;
    i32 isAppClosing;
    i32 lastActiveAppValue;
    i32 isAppActive;
    u8 curFrame;
    i32 screenSaveActive;
    i32 lowPowerActive;
    i32 powerOffActive;
};

DIFFABLE_EXTERN(GameWindow, g_GameWindow)
DIFFABLE_EXTERN(i32, g_TickCountToEffectiveFramerate)
DIFFABLE_EXTERN(double, g_LastFrameTime)
