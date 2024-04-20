#define _WIN32_WINNT 0x0500

#include <windows.h>

#include <D3DX8.h>
#include <stdio.h>

#include "AnmManager.hpp"
#include "Chain.hpp"
#include "FileSystem.hpp"
#include "GameErrorContext.hpp"
#include "GameWindow.hpp"
#include "SoundPlayer.hpp"
#include "Stage.hpp"
#include "Supervisor.hpp"
#include "ZunResult.hpp"
#include "i18n.hpp"
#include "utils.hpp"

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

int __stdcall WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd)
{
    i32 renderResult = 0;
    i32 testCoopLevelRes;
    i32 testResetRes;
    MSG msg;
    AnmManager *anm;

    if (CheckForRunningGameInstance())
    {
        g_GameErrorContext.Flush();

        return 1;
    }

    g_Supervisor.hInstance = hInstance;

    if (g_Supervisor.LoadConfig(TH_CONFIG_FILE) != ZUN_SUCCESS)
    {
        g_GameErrorContext.Flush();
        return -1;
    }

    if (InitD3dInterface())
    {
        g_GameErrorContext.Flush();
        return 1;
    }

    SystemParametersInfo(SPI_GETSCREENSAVEACTIVE, 0, &g_GameWindow.screenSaveActive, 0);
    SystemParametersInfo(SPI_GETLOWPOWERACTIVE, 0, &g_GameWindow.lowPowerActive, 0);
    SystemParametersInfo(SPI_GETPOWEROFFACTIVE, 0, &g_GameWindow.powerOffActive, 0);
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

        g_SoundPlayer.InitializeDSound(g_GameWindow.window);
        GetJoystickCaps();
        ResetKeyboard();

        anm = new AnmManager();
        g_AnmManager = anm;

        if (Supervisor::RegisterChain() != ZUN_SUCCESS)
        {
            goto exit;
        }
        if (!g_Supervisor.cfg.windowed)
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
                testCoopLevelRes = g_Supervisor.d3dDevice->TestCooperativeLevel();
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
                    g_AnmManager->ReleaseSurfaces();
                    testResetRes = g_Supervisor.d3dDevice->Reset(&g_Supervisor.presentParameters);
                    if (testResetRes != 0)
                    {
                        break;
                    }
                    InitD3dDevice();
                    g_Supervisor.unk198 = 3;
                }
            }
        }
        break;
    }

    g_Chain.Release();
    g_SoundPlayer.Release();

    delete g_AnmManager;
    g_AnmManager = NULL;
    if (g_Supervisor.d3dDevice != NULL)
    {
        g_Supervisor.d3dDevice->Release();
        g_Supervisor.d3dDevice = NULL;
    }

    ShowWindow(g_GameWindow.window, 0);
    MoveWindow(g_GameWindow.window, 0, 0, 0, 0, 0);
    DestroyWindow(g_GameWindow.window);

    if (renderResult == 2)
    {
        g_GameErrorContext.RstContext();
        GameErrorContextLog(&g_GameErrorContext, TH_ERR_OPTION_CHANGED_RESTART);

        if (!g_Supervisor.cfg.windowed)
        {
            ShowCursor(TRUE);
        }
    }
    else
    {
        FileSystem::WriteDataToFile(TH_CONFIG_FILE, &g_Supervisor.cfg, sizeof(g_Supervisor.cfg));
        SystemParametersInfo(SPI_SETSCREENSAVEACTIVE, g_GameWindow.screenSaveActive, NULL, SPIF_SENDCHANGE);
        SystemParametersInfo(SPI_SETLOWPOWERACTIVE, g_GameWindow.lowPowerActive, NULL, SPIF_SENDCHANGE);
        SystemParametersInfo(SPI_SETPOWEROFFACTIVE, g_GameWindow.powerOffActive, NULL, SPIF_SENDCHANGE);

        if (g_Supervisor.d3dIface != NULL)
        {
            g_Supervisor.d3dIface->Release();
            g_Supervisor.d3dIface = NULL;
        }
    }

exit:
    ShowCursor(TRUE);
    g_GameErrorContext.Flush();
    return 0;
}
