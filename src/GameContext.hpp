#pragma once

#include <d3d8.h>
#include <dinput.h>

enum GameConfigOpts
{
    DONT_USE_VERTEX_BUF = 1 << 0x1,
    FORCE_16BIT_COLOR_MODE = 1 << 0x2,
    CLEAR_BACKBUFFER_ON_REFRESH = 1 << 0x3,
    DISPLAY_MINIMUM_GRAPHICS = 1 << 0x4,
    SUPPRESS_USE_OF_GOROUD_SHADING = 1 << 0x5,
    TURN_OFF_DEPTH_TEST = 1 << 0x6,
    FORCE_60FPS = 1 << 0x7,
    NO_COLOR_COMP = 1 << 0x8,
    REFERENCE_RASTERIZER_MODE = 1 << 0x9,
    DONT_USE_FOG = 1 << 0xa,
    NO_DIRECTINPUT_PAD = 1 << 0xb,
};

struct ControllerMapping
{
    short shootButton;
    short bombButton;
    short focusButton;
    short menuButton;
    short upButton;
    short downButton;
    short leftButton;
    short rightButton;
    short unkButton;
};

struct GameConfiguration
{
    ControllerMapping controllerMapping;
    // Always 0x102 for 1.02
    int version;
    char lifeCount;
    char bombCount;
    char colorMode16bit;
    // 0 is off, 1 for wav, 2 for midi
    char musicMode;
    char playSounds;
    char unk7;
    char windowed;
    // 0 = fullspeed, 1 = 1/2 speed, 2 = 1/4 speed.
    char frameskipConfig;
    short padXAxis;
    short padYAxis;
    char unk[16];
    // GameConfigOpts bitfield.
    int opts;
};

struct GameContext
{
    int Parse(char *path);

    HINSTANCE hInstance;
    PDIRECT3D8 d3dIface;
    PDIRECT3DDEVICE8 d3dDevice;
    LPDIRECTINPUT8 dinputIface;
    LPDIRECTINPUTDEVICE8A keyboard;
    LPDIRECTINPUTDEVICE8A controller;
    DIDEVCAPS controllerCaps;
    HWND hwndGameWindow;
    D3DMATRIX viewMatrix;
    D3DMATRIX projectionMatrix;
    D3DVIEWPORT8 viewport;
    D3DPRESENT_PARAMETERS presentParameters;
    GameConfiguration cfg;

    int unk198;
};
int InitD3dInterface(void);

WORD GetJoystickCaps(void);

extern GameContext g_GameContext;
