#define _WIN32_WINNT 0x0500

#include <windows.h>

#include <D3DX8.h>
#include <stdio.h>

#include "GameContext.hpp"
#include "GameErrorContext.hpp"
#include "GameWindow.hpp"
#include "i18n.hpp"
#include "utils.hpp"

void ResetKeyboard(void)
{
    BYTE key_states[256];

    GetKeyboardState(key_states);
    for (int idx = 0; idx < 256; idx++)
    {
        *(key_states + idx) &= 0x7f;
    }
    SetKeyboardState(key_states);
}

void SetupConsole(void)
{
    HWND hWnd = GetConsoleWindow();

    if (hWnd == NULL)
    {
        AllocConsole();
    }
    else
    {
        ShowWindow(hWnd, SW_SHOW);
    }
}

// TODO: Implement
LRESULT __stdcall WindowProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    return DefWindowProc(hWnd, uMsg, wParam, lParam);
}

void CreateGameWindow(HINSTANCE hInstance)
{
    WNDCLASS base_class;
    int width;
    int height;

    memset(&base_class, 0, sizeof(base_class));

    base_class.hbrBackground = (HBRUSH)GetStockObject(WHITE_BRUSH);
    base_class.hCursor = LoadCursor(NULL, IDC_ARROW);
    base_class.hInstance = hInstance;
    base_class.lpfnWndProc = WindowProc;
    g_GameWindow.lastActiveAppValue = 0;
    g_GameWindow.isAppActive = 0;
    base_class.lpszClassName = "BASE";
    RegisterClass(&base_class);
    if (g_GameContext.cfg.windowed == 0)
    {
        width = 640;
        height = 480;
        g_GameWindow.window =
            CreateWindowEx(0, "BASE", TH_WINDOW_TITLE, WS_OVERLAPPEDWINDOW, 0, 0, width, height, 0, 0, hInstance, 0);
    }
    else
    {
        width = GetSystemMetrics(SM_CXFIXEDFRAME) * 2 + 640;
        height = 480 + GetSystemMetrics(SM_CYFIXEDFRAME) * 2 + GetSystemMetrics(SM_CYCAPTION);
        g_GameWindow.window = CreateWindowEx(0, "BASE", TH_WINDOW_TITLE, WS_VISIBLE | WS_MINIMIZEBOX | WS_SYSMENU,
                                             CW_USEDEFAULT, CW_USEDEFAULT, width, height, 0, 0, hInstance, 0);
    }
    g_GameContext.hwndGameWindow = g_GameWindow.window;
}

static int g_SCREENSAVEACTIVE;
static int g_LOWPOWERACTIVE;
static int g_POWEROFFACTIVE;

int __stdcall WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd)
{
    if (CheckForRunningGameInstance())
    {
        g_GameErrorContext.Flush();

        return 1;
    }

    g_GameContext.hInstance = hInstance;

    g_GameContext.Parse(TH_CONFIG_FILE);

    if (InitD3dInterface())
    {
        g_GameErrorContext.Flush();
        return 1;
    }

    SystemParametersInfo(SPI_GETSCREENSAVEACTIVE, 0, &g_SCREENSAVEACTIVE, 0);
    SystemParametersInfo(SPI_GETLOWPOWERACTIVE, 0, &g_LOWPOWERACTIVE, 0);
    SystemParametersInfo(SPI_GETPOWEROFFACTIVE, 0, &g_POWEROFFACTIVE, 0);
    SystemParametersInfo(SPI_GETSCREENSAVEACTIVE, 0, NULL, SPIF_SENDCHANGE);
    SystemParametersInfo(SPI_GETLOWPOWERACTIVE, 0, NULL, SPIF_SENDCHANGE);
    SystemParametersInfo(SPI_GETPOWEROFFACTIVE, 0, NULL, SPIF_SENDCHANGE);

    while (TRUE)
    {
        CreateGameWindow(hInstance);
        // if (InitD3dRendering()) {
        //     break;
        // }
        ResetKeyboard();
    }

    return 0;
}
