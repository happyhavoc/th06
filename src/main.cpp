#define _WIN32_WINNT 0x0500

#include <windows.h>

#include <D3DX8.h>
#include <stdio.h>

#include "AnmManager.hpp"
#include "Chain.hpp"
#include "FileSystem.hpp"
#include "GameContext.hpp"
#include "GameErrorContext.hpp"
#include "GameWindow.hpp"
#include "SoundPlayer.hpp"
#include "Stage.hpp"
#include "i18n.hpp"
#include "utils.hpp"

i32 AddInputChain(void)
{
    return 0;
}

#pragma var_order(fogVal, fogDensity, anm1, anm2, anm3, anm4)
void InitD3dDevice(void)
{
    int fogVal;
    int fogDensity;
    AnmManager *anm1;
    AnmManager *anm2;
    AnmManager *anm3;
    AnmManager *anm4;

    if (((g_GameContext.cfg.opts >> GCOS_TURN_OFF_DEPTH_TEST) & 1) == 0)
    {
        g_GameContext.d3dDevice->SetRenderState(D3DRS_ZENABLE, 1);
    }
    else
    {
        g_GameContext.d3dDevice->SetRenderState(D3DRS_ZENABLE, 0);
    }
    g_GameContext.d3dDevice->SetRenderState(D3DRS_LIGHTING, 0);
    g_GameContext.d3dDevice->SetRenderState(D3DRS_CULLMODE, 1);
    g_GameContext.d3dDevice->SetRenderState(D3DRS_ALPHABLENDENABLE, 1);
    if (((g_GameContext.cfg.opts >> GCOS_SUPPRESS_USE_OF_GOROUD_SHADING) & 1) == 0)
    {
        g_GameContext.d3dDevice->SetRenderState(D3DRS_SHADEMODE, D3DSHADE_GOURAUD);
    }
    else
    {
        g_GameContext.d3dDevice->SetRenderState(D3DRS_SHADEMODE, D3DSHADE_FLAT);
    }
    g_GameContext.d3dDevice->SetRenderState(D3DRS_SRCBLEND, D3DBLEND_SRCALPHA);
    g_GameContext.d3dDevice->SetRenderState(D3DRS_DESTBLEND, D3DBLEND_INVSRCALPHA);
    if (((g_GameContext.cfg.opts >> GCOS_TURN_OFF_DEPTH_TEST) & 1) == 0)
    {
        g_GameContext.d3dDevice->SetRenderState(D3DRS_ZFUNC, D3DCMP_LESSEQUAL);
    }
    else
    {
        g_GameContext.d3dDevice->SetRenderState(D3DRS_ZFUNC, D3DCMP_ALWAYS);
    }
    g_GameContext.d3dDevice->SetRenderState(D3DRS_ALPHATESTENABLE, 1);
    g_GameContext.d3dDevice->SetRenderState(D3DRS_ALPHAREF, 4);
    g_GameContext.d3dDevice->SetRenderState(D3DRS_ALPHAFUNC, 7);
    if (((g_GameContext.cfg.opts >> GCOS_DONT_USE_FOG) & 1) == 0)
    {
        g_GameContext.d3dDevice->SetRenderState(D3DRS_FOGENABLE, 1);
    }
    else
    {
        g_GameContext.d3dDevice->SetRenderState(D3DRS_FOGENABLE, 0);
    }
    fogDensity = 0x3f800000;
    g_GameContext.d3dDevice->SetRenderState(D3DRS_FOGDENSITY, fogDensity);
    g_GameContext.d3dDevice->SetRenderState(D3DRS_FOGTABLEMODE, 3);
    g_GameContext.d3dDevice->SetRenderState(D3DRS_FOGCOLOR, 0xffa0a0a0);
    fogVal = 0x447a0000;
    g_GameContext.d3dDevice->SetRenderState(D3DRS_FOGSTART, fogVal);
    fogVal = 0x459c4000;
    g_GameContext.d3dDevice->SetRenderState(D3DRS_FOGEND, fogVal);
    if (((g_GameContext.cfg.opts >> GCOS_NO_COLOR_COMP) & 1) == 0)
    {
        g_GameContext.d3dDevice->SetTextureStageState(0, D3DTSS_ALPHAOP, 4);
    }
    else
    {
        g_GameContext.d3dDevice->SetTextureStageState(0, D3DTSS_ALPHAOP, 2);
    }
    g_GameContext.d3dDevice->SetTextureStageState(0, D3DTSS_ALPHAARG1, 2);
    if (((g_GameContext.cfg.opts >> GCOS_DONT_USE_VERTEX_BUF) & 1) == 0)
    {
        g_GameContext.d3dDevice->SetTextureStageState(0, D3DTSS_ALPHAARG2, 3);
    }
    else
    {
        g_GameContext.d3dDevice->SetTextureStageState(0, D3DTSS_ALPHAARG2, 0);
    }
    if (((g_GameContext.cfg.opts >> GCOS_NO_COLOR_COMP) & 1) == 0)
    {
        g_GameContext.d3dDevice->SetTextureStageState(0, D3DTSS_COLOROP, 4);
    }
    else
    {
        g_GameContext.d3dDevice->SetTextureStageState(0, D3DTSS_COLOROP, 2);
    }
    g_GameContext.d3dDevice->SetTextureStageState(0, D3DTSS_COLORARG1, 2);
    if (((g_GameContext.cfg.opts >> GCOS_DONT_USE_VERTEX_BUF) & 1) == 0)
    {
        g_GameContext.d3dDevice->SetTextureStageState(0, D3DTSS_COLORARG2, 3);
    }
    else
    {
        g_GameContext.d3dDevice->SetTextureStageState(0, D3DTSS_COLORARG2, 0);
    }
    g_GameContext.d3dDevice->SetTextureStageState(0, D3DTSS_MIPFILTER, 0);
    g_GameContext.d3dDevice->SetTextureStageState(0, D3DTSS_MAGFILTER, 2);
    g_GameContext.d3dDevice->SetTextureStageState(0, D3DTSS_MINFILTER, 2);
    g_GameContext.d3dDevice->SetTextureStageState(0, D3DTSS_TEXTURETRANSFORMFLAGS, 2);
    g_GameContext.d3dDevice->SetTextureStageState(0, D3DTSS_ADDRESSW, 3);
    g_GameContext.d3dDevice->SetTextureStageState(0, D3DTSS_ADDRESSU, 1);
    g_GameContext.d3dDevice->SetTextureStageState(0, D3DTSS_ADDRESSV, 1);
    if (g_AnmManager != NULL)
    {
        anm1 = g_AnmManager;
        anm1->currentBlendMode = 0xff;
        anm2 = g_AnmManager;
        anm2->currentColorOp = 0xff;
        anm3 = g_AnmManager;
        anm3->currentVertexShader = 0xff;
        anm4 = g_AnmManager;
        anm4->currentTexture = NULL;
    }
    g_Stage.skyFogNeedsSetup = 1;
    return;
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
    AnmManager *anm;

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

        anm = new AnmManager();
        g_AnmManager = anm;

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
                    g_AnmManager->ReleaseD3dSurfaces();
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

    delete g_AnmManager;
    g_AnmManager = NULL;
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
