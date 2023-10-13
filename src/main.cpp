#define _WIN32_WINNT 0x0500

#include <windows.h>

#include <D3DX8.h>
#include <stdio.h>

#include "Chain.hpp"
#include "FileSystem.hpp"
#include "GameContext.hpp"
#include "GameErrorContext.hpp"
#include "GameWindow.hpp"
#include "SoundPlayer.hpp"
#include "VeryBigStruct.hpp"
#include "i18n.hpp"
#include "utils.hpp"

i32 AddInputChain(void)
{
    return 0;
}

i32 InitD3dDevice(void)
{
    return 0;
}

i32 InitD3dRendering(void)
{
    return 0;
}

void ResetKeyboard(void)
{
    u8 key_states[256];

    GetKeyboardState(key_states);
    for (i32 idx = 0; idx < 256; idx++)
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
    switch (uMsg)
    {
    case 0x3c9:
        if (g_GameContext.midiOutput != NULL)
        {
            g_GameContext.midiOutput->UnprepareHeader((LPMIDIHDR)lParam);
        }
        break;
    case WM_ACTIVATEAPP:
        g_GameWindow.lastActiveAppValue = wParam;
        if (g_GameWindow.lastActiveAppValue != 0)
        {
            g_GameWindow.isAppActive = 0;
        }
        else
        {
            g_GameWindow.isAppActive = 1;
        }
        break;
    case WM_SETCURSOR:
        if (!g_GameContext.cfg.windowed)
        {
            if (g_GameWindow.isAppActive != 0)
            {
                SetCursor(LoadCursorA(NULL, IDC_ARROW));
                ShowCursor(1);
            }
            else
            {
                ShowCursor(0);
                SetCursor((HCURSOR)0x0);
            }
        }
        else
        {
            SetCursor(LoadCursorA(NULL, IDC_ARROW));
            ShowCursor(1);
        }

        return 1;
    case WM_CLOSE:
        g_GameWindow.isAppClosing = 1;
        return 1;
    }
    return DefWindowProcA(hWnd, uMsg, wParam, lParam);
}

void CreateGameWindow(HINSTANCE hInstance)
{
    WNDCLASS base_class;
    i32 width;
    i32 height;

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

static i32 g_ScreenSaveActive;
static i32 g_LowPowerActive;
static i32 g_PowerOffActive;

int __stdcall WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd)
{
    i32 renderResult = 0;
    i32 testCoopLevelRes;
    i32 testResetRes;
    MSG msg;
    VeryBigStruct *vbs;

    if (CheckForRunningGameInstance())
    {
        g_GameErrorContext.Flush();

        return 1;
    }

    g_GameContext.hInstance = hInstance;

    if (g_GameContext.Parse(TH_CONFIG_FILE))
    {
        g_GameErrorContext.Flush();
        return -1;
    }

    if (InitD3dInterface())
    {
        g_GameErrorContext.Flush();
        return 1;
    }

    SystemParametersInfo(SPI_GETSCREENSAVEACTIVE, 0, &g_ScreenSaveActive, 0);
    SystemParametersInfo(SPI_GETLOWPOWERACTIVE, 0, &g_LowPowerActive, 0);
    SystemParametersInfo(SPI_GETPOWEROFFACTIVE, 0, &g_PowerOffActive, 0);
    SystemParametersInfo(SPI_SETSCREENSAVEACTIVE, 0, NULL, SPIF_SENDCHANGE);
    SystemParametersInfo(SPI_SETLOWPOWERACTIVE, 0, NULL, SPIF_SENDCHANGE);
    SystemParametersInfo(SPI_SETPOWEROFFACTIVE, 0, NULL, SPIF_SENDCHANGE);

    for (;;)
    {
        CreateGameWindow(hInstance);

        if (InitD3dRendering())
        {
            g_GameErrorContext.Flush();
            return 1;
        }

        g_SoundPlayer.Init(g_GameWindow.window);
        GetJoystickCaps();
        ResetKeyboard();

        vbs = new VeryBigStruct();
        g_VeryBigStruct = vbs;

        if (AddInputChain() != 0)
        {
            goto exit;
        }
        if (!g_GameContext.cfg.windowed)
        {
            ShowCursor(FALSE);
        }

        g_GameWindow.curFrame = 0;

        while (!g_GameWindow.isAppClosing)
        {
            if (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE))
            {
                TranslateMessage(&msg);
                DispatchMessage(&msg);
            }
            else
            {
                testCoopLevelRes = g_GameContext.d3dDevice->TestCooperativeLevel();
                if (testCoopLevelRes == D3D_OK)
                {
                    renderResult = g_GameWindow.Render();
                    if (renderResult != 0)
                    {
                        break;
                    }
                }
                else if (testCoopLevelRes == D3DERR_DEVICENOTRESET)
                {
                    g_VeryBigStruct->ReleaseD3dSurfaces();
                    testResetRes = g_GameContext.d3dDevice->Reset(&g_GameContext.presentParameters);
                    if (testResetRes != 0)
                    {
                        break;
                    }
                    InitD3dDevice();
                    g_GameContext.unk198 = 3;
                }
            }
        }
        break;
    }

    g_Chain.Release();
    g_SoundPlayer.Release();

    delete g_VeryBigStruct;
    g_VeryBigStruct = NULL;
    if (g_GameContext.d3dDevice != NULL)
    {
        g_GameContext.d3dDevice->Release();
        g_GameContext.d3dDevice = NULL;
    }

    ShowWindow(g_GameWindow.window, 0);
    MoveWindow(g_GameWindow.window, 0, 0, 0, 0, 0);
    DestroyWindow(g_GameWindow.window);

    if (renderResult == 2)
    {
        g_GameErrorContext.RstContext();
        GameErrorContextLog(&g_GameErrorContext, TH_ERR_OPTION_CHANGED_RESTART);

        if (!g_GameContext.cfg.windowed)
        {
            ShowCursor(TRUE);
        }
    }
    else
    {
        FileSystem::WriteDataToFile(TH_CONFIG_FILE, &g_GameContext.cfg, sizeof(g_GameContext.cfg));
        SystemParametersInfo(SPI_SETSCREENSAVEACTIVE, g_ScreenSaveActive, NULL, SPIF_SENDCHANGE);
        SystemParametersInfo(SPI_SETLOWPOWERACTIVE, g_LowPowerActive, NULL, SPIF_SENDCHANGE);
        SystemParametersInfo(SPI_SETPOWEROFFACTIVE, g_PowerOffActive, NULL, SPIF_SENDCHANGE);

        if (g_GameContext.d3dIface != NULL)
        {
            g_GameContext.d3dIface->Release();
            g_GameContext.d3dIface = NULL;
        }
    }

exit:
    ShowCursor(TRUE);
    g_GameErrorContext.Flush();
    return 0;
}
