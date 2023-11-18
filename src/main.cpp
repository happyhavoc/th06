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

#define GAME_WINDOW_WIDTH 640
#define GAME_WINDOW_HEIGHT 480

i32 AddInputChain(void)
{
    return 0;
}

#pragma var_order(fogVal, fogDensity, anm1, anm2, anm3, anm4)
void InitD3dDevice(void)
{
    f32 fogVal;
    f32 fogDensity;
    AnmManager *anm1;
    AnmManager *anm2;
    AnmManager *anm3;
    AnmManager *anm4;

    if (((g_GameContext.cfg.opts >> GCOS_TURN_OFF_DEPTH_TEST) & 1) == 0)
    {
        g_GameContext.d3dDevice->SetRenderState(D3DRS_ZENABLE, TRUE);
    }
    else
    {
        g_GameContext.d3dDevice->SetRenderState(D3DRS_ZENABLE, FALSE);
    }
    g_GameContext.d3dDevice->SetRenderState(D3DRS_LIGHTING, FALSE);
    g_GameContext.d3dDevice->SetRenderState(D3DRS_CULLMODE, D3DCULL_NONE);
    g_GameContext.d3dDevice->SetRenderState(D3DRS_ALPHABLENDENABLE, TRUE);
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
    g_GameContext.d3dDevice->SetRenderState(D3DRS_ALPHATESTENABLE, TRUE);
    g_GameContext.d3dDevice->SetRenderState(D3DRS_ALPHAREF, 4);
    g_GameContext.d3dDevice->SetRenderState(D3DRS_ALPHAFUNC, D3DCMP_GREATEREQUAL);
    if (((g_GameContext.cfg.opts >> GCOS_DONT_USE_FOG) & 1) == 0)
    {
        g_GameContext.d3dDevice->SetRenderState(D3DRS_FOGENABLE, TRUE);
    }
    else
    {
        g_GameContext.d3dDevice->SetRenderState(D3DRS_FOGENABLE, FALSE);
    }
    fogDensity = 1.0;
    g_GameContext.d3dDevice->SetRenderState(D3DRS_FOGDENSITY, *(u32 *)&fogDensity);
    g_GameContext.d3dDevice->SetRenderState(D3DRS_FOGTABLEMODE, D3DFOG_LINEAR);
    g_GameContext.d3dDevice->SetRenderState(D3DRS_FOGCOLOR, 0xffa0a0a0);
    fogVal = 1000.0;
    g_GameContext.d3dDevice->SetRenderState(D3DRS_FOGSTART, *(u32 *)&fogVal);
    fogVal = 5000.0;
    g_GameContext.d3dDevice->SetRenderState(D3DRS_FOGEND, *(u32 *)&fogVal);
    if (((g_GameContext.cfg.opts >> GCOS_NO_COLOR_COMP) & 1) == 0)
    {
        g_GameContext.d3dDevice->SetTextureStageState(0, D3DTSS_ALPHAOP, D3DTOP_MODULATE);
    }
    else
    {
        g_GameContext.d3dDevice->SetTextureStageState(0, D3DTSS_ALPHAOP, D3DTOP_SELECTARG1);
    }
    g_GameContext.d3dDevice->SetTextureStageState(0, D3DTSS_ALPHAARG1, D3DTA_TEXTURE);
    if (((g_GameContext.cfg.opts >> GCOS_DONT_USE_VERTEX_BUF) & 1) == 0)
    {
        g_GameContext.d3dDevice->SetTextureStageState(0, D3DTSS_ALPHAARG2, D3DTA_TFACTOR);
    }
    else
    {
        g_GameContext.d3dDevice->SetTextureStageState(0, D3DTSS_ALPHAARG2, D3DTA_DIFFUSE);
    }
    if (((g_GameContext.cfg.opts >> GCOS_NO_COLOR_COMP) & 1) == 0)
    {
        g_GameContext.d3dDevice->SetTextureStageState(0, D3DTSS_COLOROP, D3DTOP_MODULATE);
    }
    else
    {
        g_GameContext.d3dDevice->SetTextureStageState(0, D3DTSS_COLOROP, D3DTOP_SELECTARG1);
    }
    g_GameContext.d3dDevice->SetTextureStageState(0, D3DTSS_COLORARG1, D3DTA_TEXTURE);
    if (((g_GameContext.cfg.opts >> GCOS_DONT_USE_VERTEX_BUF) & 1) == 0)
    {
        g_GameContext.d3dDevice->SetTextureStageState(0, D3DTSS_COLORARG2, D3DTA_TFACTOR);
    }
    else
    {
        g_GameContext.d3dDevice->SetTextureStageState(0, D3DTSS_COLORARG2, D3DTA_DIFFUSE);
    }
    g_GameContext.d3dDevice->SetTextureStageState(0, D3DTSS_MIPFILTER, D3DTEXF_NONE);
    g_GameContext.d3dDevice->SetTextureStageState(0, D3DTSS_MAGFILTER, D3DTEXF_LINEAR);
    g_GameContext.d3dDevice->SetTextureStageState(0, D3DTSS_MINFILTER, D3DTEXF_LINEAR);
    g_GameContext.d3dDevice->SetTextureStageState(0, D3DTSS_TEXTURETRANSFORMFLAGS, D3DTTFF_COUNT2);
    g_GameContext.d3dDevice->SetTextureStageState(0, D3DTSS_ADDRESSW, D3DTADDRESS_CLAMP);
    g_GameContext.d3dDevice->SetTextureStageState(0, D3DTSS_ADDRESSU, D3DTADDRESS_WRAP);
    g_GameContext.d3dDevice->SetTextureStageState(0, D3DTSS_ADDRESSV, D3DTADDRESS_WRAP);
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

void Clear(D3DCOLOR color)
{
    g_GameContext.d3dDevice->Clear(0, NULL, D3DCLEAR_TARGET | D3DCLEAR_ZBUFFER, color, 1.0, 0);
    if (g_GameContext.d3dDevice->Present(NULL, NULL, NULL, NULL) < 0)
    {
        g_GameContext.d3dDevice->Reset(&g_GameContext.presentParameters);
    }
    g_GameContext.d3dDevice->Clear(0, NULL, D3DCLEAR_TARGET | D3DCLEAR_ZBUFFER, color, 1.0, 0);
    if (g_GameContext.d3dDevice->Present(NULL, NULL, NULL, NULL) < 0)
    {
        g_GameContext.d3dDevice->Reset(&g_GameContext.presentParameters);
    }
    return;
}

void SetViewport(D3DCOLOR color)
{
    g_GameContext.viewport.X = 0;
    g_GameContext.viewport.Y = 0;
    g_GameContext.viewport.Width = GAME_WINDOW_WIDTH;
    g_GameContext.viewport.Height = GAME_WINDOW_HEIGHT;
    g_GameContext.viewport.MinZ = 0.0;
    g_GameContext.viewport.MaxZ = 1.0;
    g_GameContext.d3dDevice->SetViewport(&g_GameContext.viewport);
    Clear(color);
}

#pragma var_order(using_d3d_hal, display_mode, present_params, camera_distance, half_height, half_width, aspect_ratio, \
                  field_of_view_y, up, at, eye, should_run_at_60_fps)
i32 InitD3dRendering(void)
{
    u8 using_d3d_hal;
    D3DPRESENT_PARAMETERS present_params;
    D3DDISPLAYMODE display_mode;
    D3DXVECTOR3 eye;
    D3DXVECTOR3 at;
    D3DXVECTOR3 up;
    float half_width;
    float half_height;
    float aspect_ratio;
    float field_of_view_y;
    float camera_distance;

    using_d3d_hal = 1;
    memset(&present_params, 0, sizeof(D3DPRESENT_PARAMETERS));
    g_GameContext.d3dIface->GetAdapterDisplayMode(0, &display_mode);
    if (!g_GameContext.cfg.windowed)
    {
        if ((((g_GameContext.cfg.opts >> GCOS_FORCE_16BIT_COLOR_MODE) & 1) == 1))
        {
            present_params.BackBufferFormat = D3DFMT_R5G6B5;
            g_GameContext.cfg.colorMode16bit = 1;
        }
        else if (g_GameContext.cfg.colorMode16bit == 0xff)
        {
            if ((display_mode.Format == D3DFMT_X8R8G8B8) || (display_mode.Format == D3DFMT_A8R8G8B8))
            {
                present_params.BackBufferFormat = D3DFMT_X8R8G8B8;
                g_GameContext.cfg.colorMode16bit = 0;
                GameErrorContextLog(&g_GameErrorContext, TH_ERR_SCREEN_INIT_32BITS);
            }
            else
            {
                present_params.BackBufferFormat = D3DFMT_R5G6B5;
                g_GameContext.cfg.colorMode16bit = 1;
                GameErrorContextLog(&g_GameErrorContext, TH_ERR_SCREEN_INIT_16BITS);
            }
        }
        else if (g_GameContext.cfg.colorMode16bit == 0)
        {
            present_params.BackBufferFormat = D3DFMT_X8R8G8B8;
        }
        else
        {
            present_params.BackBufferFormat = D3DFMT_R5G6B5;
        }
        if (!((g_GameContext.cfg.opts >> GCOS_FORCE_60FPS) & 1))
        {
            present_params.FullScreen_PresentationInterval = D3DPRESENT_INTERVAL_ONE;
        }
        else
        {
            present_params.FullScreen_RefreshRateInHz = 60;
            present_params.FullScreen_PresentationInterval = D3DPRESENT_INTERVAL_ONE;
            GameErrorContextLog(&g_GameErrorContext, TH_ERR_SET_REFRESH_RATE_60HZ);
        }
        if (g_GameContext.cfg.frameskipConfig == 0)
        {
            present_params.SwapEffect = D3DSWAPEFFECT_FLIP;
        }
        else
        {
            present_params.SwapEffect = D3DSWAPEFFECT_COPY_VSYNC;
        }
    }
    else
    {
        present_params.BackBufferFormat = display_mode.Format;
        present_params.SwapEffect = D3DSWAPEFFECT_COPY;
        present_params.Windowed = 1;
    }
    present_params.BackBufferWidth = GAME_WINDOW_WIDTH;
    present_params.BackBufferHeight = GAME_WINDOW_HEIGHT;
    present_params.EnableAutoDepthStencil = true;
    present_params.AutoDepthStencilFormat = D3DFMT_D16;
    present_params.Flags = D3DPRESENTFLAG_LOCKABLE_BACKBUFFER;
    g_GameContext.lockableBackbuffer = 1;
    memcpy(&g_GameContext.presentParameters, &present_params, sizeof(D3DPRESENT_PARAMETERS));
    for (;;)
    {
        if (((g_GameContext.cfg.opts >> GCOS_REFERENCE_RASTERIZER_MODE) & 1) != 0)
        {
            goto REFERENCE_RASTERIZER_MODE;
        }
        else
        {
            if (g_GameContext.d3dIface->CreateDevice(0, D3DDEVTYPE_HAL, g_GameWindow.window,
                                                     D3DCREATE_HARDWARE_VERTEXPROCESSING, &present_params,
                                                     &g_GameContext.d3dDevice) < 0)
            {
                GameErrorContextLog(&g_GameErrorContext, TH_ERR_TL_HAL_UNAVAILABLE);
                if (g_GameContext.d3dIface->CreateDevice(0, D3DDEVTYPE_HAL, g_GameWindow.window,
                                                         D3DCREATE_SOFTWARE_VERTEXPROCESSING, &present_params,
                                                         &g_GameContext.d3dDevice) < 0)
                {
                    GameErrorContextLog(&g_GameErrorContext, TH_ERR_HAL_UNAVAILABLE);
                REFERENCE_RASTERIZER_MODE:
                    if (g_GameContext.d3dIface->CreateDevice(0, D3DDEVTYPE_REF, g_GameWindow.window, 0x20,
                                                             &present_params, &g_GameContext.d3dDevice) < 0)
                    {
                        if (((g_GameContext.cfg.opts >> GCOS_FORCE_60FPS) & 1) != 0 && !g_GameContext.vsyncEnabled)
                        {
                            GameErrorContextLog(&g_GameErrorContext, TH_ERR_CANT_CHANGE_REFRESH_RATE_FORCE_VSYNC);
                            present_params.FullScreen_RefreshRateInHz = 0;
                            g_GameContext.vsyncEnabled = 1;
                            present_params.FullScreen_PresentationInterval = D3DPRESENT_INTERVAL_IMMEDIATE;
                            continue;
                        }
                        else
                        {
                            if (present_params.Flags == 1)
                            {
                                GameErrorContextLog(&g_GameErrorContext, TH_ERR_BACKBUFFER_NONLOCKED);
                                present_params.Flags = 0;
                                g_GameContext.lockableBackbuffer = 0;
                                continue;
                            }
                            else
                            {
                                GameErrorContextFatal(&g_GameErrorContext, TH_ERR_D3D_INIT_FAILED);
                                if (g_GameContext.d3dIface != NULL)
                                {
                                    g_GameContext.d3dIface->Release();
                                    g_GameContext.d3dIface = NULL;
                                }
                                return 1;
                            }
                        }
                    }
                    else
                    {
                        GameErrorContextLog(&g_GameErrorContext, TH_USING_REF_MODE);
                        g_GameContext.hasD3dHardwareVertexProcessing = 0;
                        using_d3d_hal = 0;
                    }
                }
                else
                {
                    GameErrorContextLog(&g_GameErrorContext, TH_USING_HAL_MODE);
                    g_GameContext.hasD3dHardwareVertexProcessing = 0;
                }
            }
            else
            {
                GameErrorContextLog(&g_GameErrorContext, TH_USING_TL_HAL_MODE);
                g_GameContext.hasD3dHardwareVertexProcessing = 1;
            }
            break;
        }
    }

    half_width = (float)GAME_WINDOW_WIDTH / 2.0;
    half_height = (float)GAME_WINDOW_HEIGHT / 2.0;
    aspect_ratio = (float)GAME_WINDOW_WIDTH / (float)GAME_WINDOW_HEIGHT;
    field_of_view_y = 0.52359879; // PI / 6.0f
    camera_distance = half_height / tanf(field_of_view_y / 2.0f);
    up.x = 0.0;
    up.y = 1.0;
    up.z = 0.0;
    at.x = half_width;
    at.y = -half_height;
    at.z = 0.0;
    eye.x = half_width;
    eye.y = -half_height;
    eye.z = -camera_distance;
    D3DXMatrixLookAtLH(&g_GameContext.viewMatrix, &eye, &at, &up);
    D3DXMatrixPerspectiveFovLH(&g_GameContext.projectionMatrix, field_of_view_y, aspect_ratio, 100.0, 10000.0);
    g_GameContext.d3dDevice->SetTransform(D3DTS_VIEW, &g_GameContext.viewMatrix);
    g_GameContext.d3dDevice->SetTransform(D3DTS_PROJECTION, &g_GameContext.projectionMatrix);
    g_GameContext.d3dDevice->GetViewport(&g_GameContext.viewport);
    g_GameContext.d3dDevice->GetDeviceCaps(&g_GameContext.d3dCaps);
    if (((((g_GameContext.cfg.opts >> GCOS_USE_D3D_HW_TEXTURE_BLENDING) & 1) == 0) &&
         ((g_GameContext.d3dCaps.TextureOpCaps & D3DTEXOPCAPS_ADD) == 0)))
    {
        GameErrorContextLog(&g_GameErrorContext, TH_ERR_NO_SUPPORT_FOR_D3DTEXOPCAPS_ADD);
        g_GameContext.cfg.opts = g_GameContext.cfg.opts | (1 << GCOS_USE_D3D_HW_TEXTURE_BLENDING);
    }
    u32 should_run_at_60_fps;
    if ((((g_GameContext.cfg.opts >> GCOS_FORCE_60FPS) & 1) != 0) && (g_GameContext.vsyncEnabled != 0))
    {
        should_run_at_60_fps = true;
    }
    else
    {
        should_run_at_60_fps = false;
    }
    if (should_run_at_60_fps && ((g_GameContext.d3dCaps.PresentationIntervals & D3DPRESENT_INTERVAL_IMMEDIATE) == 0))
    {
        GameErrorContextLog(&g_GameErrorContext, TH_ERR_CANT_FORCE_60FPS_NO_ASYNC_FLIP);
        g_GameContext.cfg.opts = g_GameContext.cfg.opts & ~(1 << GCOS_FORCE_60FPS);
    }
    if ((((g_GameContext.cfg.opts >> GCOS_FORCE_16BIT_COLOR_MODE) & 1) == 0) && (using_d3d_hal != 0))
    {
        if (g_GameContext.d3dIface->CheckDeviceFormat(0, D3DDEVTYPE_HAL, present_params.BackBufferFormat, 0,
                                                      D3DRTYPE_TEXTURE, D3DFMT_A8R8G8B8) == 0)
        {
            g_GameContext.colorMode16Bits = 1;
        }
        else
        {
            g_GameContext.colorMode16Bits = 0;
            g_GameContext.cfg.opts = g_GameContext.cfg.opts | (1 << GCOS_FORCE_16BIT_COLOR_MODE);
            GameErrorContextLog(&g_GameErrorContext, TH_ERR_D3DFMT_A8R8G8B8_UNSUPPORTED);
        }
    }
    InitD3dDevice();
    SetViewport(0);
    g_GameWindow.isAppClosing = 0;
    g_GameContext.lastFrameTime = 0;
    g_GameContext.framerateMultiplier = 0.0;
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
        width = GAME_WINDOW_WIDTH;
        height = GAME_WINDOW_HEIGHT;
        g_GameWindow.window =
            CreateWindowEx(0, "BASE", TH_WINDOW_TITLE, WS_OVERLAPPEDWINDOW, 0, 0, width, height, 0, 0, hInstance, 0);
    }
    else
    {
        width = GetSystemMetrics(SM_CXFIXEDFRAME) * 2 + GAME_WINDOW_WIDTH;
        height = GAME_WINDOW_HEIGHT + GetSystemMetrics(SM_CYFIXEDFRAME) * 2 + GetSystemMetrics(SM_CYCAPTION);
        g_GameWindow.window = CreateWindowEx(0, "BASE", TH_WINDOW_TITLE, WS_VISIBLE | WS_MINIMIZEBOX | WS_SYSMENU,
                                             CW_USEDEFAULT, CW_USEDEFAULT, width, height, 0, 0, hInstance, 0);
    }
    g_GameContext.hwndGameWindow = g_GameWindow.window;
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
        SystemParametersInfo(SPI_SETSCREENSAVEACTIVE, g_GameWindow.screenSaveActive, NULL, SPIF_SENDCHANGE);
        SystemParametersInfo(SPI_SETLOWPOWERACTIVE, g_GameWindow.lowPowerActive, NULL, SPIF_SENDCHANGE);
        SystemParametersInfo(SPI_SETPOWEROFFACTIVE, g_GameWindow.powerOffActive, NULL, SPIF_SENDCHANGE);

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
