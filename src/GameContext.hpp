#pragma once

#include <d3d8.h>
#include <dinput.h>

#include "MidiOutput.hpp"
#include "inttypes.hpp"

enum GameConfigOpts
{
    USE_D3D_HW_TEXTURE_BLENDING = 1 << 0x0,
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
    i16 shootButton;
    i16 bombButton;
    i16 focusButton;
    i16 menuButton;
    i16 upButton;
    i16 downButton;
    i16 leftButton;
    i16 rightButton;
    i16 skipButton;
};

enum MusicMode
{
    OFF = 0,
    WAV = 1,
    MIDI = 2
};

struct GameConfiguration
{
    ControllerMapping controllerMapping;
    // Always 0x102 for 1.02
    i32 version;
    i8 lifeCount;
    i8 bombCount;
    i8 colorMode16bit;
    MusicMode musicMode;
    i8 playSounds;
    i8 defaultDifficulty;
    u8 windowed;
    // 0 = fullspeed, 1 = 1/2 speed, 2 = 1/4 speed.
    i8 frameskipConfig;
    i16 padXAxis;
    i16 padYAxis;
    i8 unk[16];
    // GameConfigOpts bitfield.
    i32 opts;
};

struct GameContext
{
    i32 Parse(char *path);

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

    i32 unk198;
    i32 vsyncEnabled;

    MidiOutput *midiOutput;
};

enum TouhouButton
{
    TH_BUTTON_SHOOT = 1 << 0,
    TH_BUTTON_BOMB = 1 << 1,
    TH_BUTTON_FOCUS = 1 << 2,
    TH_BUTTON_MENU = 1 << 3,
    TH_BUTTON_UP = 1 << 4,
    TH_BUTTON_DOWN = 1 << 5,
    TH_BUTTON_LEFT = 1 << 6,
    TH_BUTTON_RIGHT = 1 << 7,
    TH_BUTTON_SKIP = 1 << 8,
    TH_BUTTON_UNK9 = 1 << 9,
    TH_BUTTON_UNK10 = 1 << 10,
    TH_BUTTON_UNK11 = 1 << 11,
    TH_BUTTON_UNK12 = 1 << 12,

    TH_BUTTON_UP_LEFT = TH_BUTTON_UP | TH_BUTTON_LEFT,
    TH_BUTTON_UP_RIGHT = TH_BUTTON_UP | TH_BUTTON_RIGHT,
    TH_BUTTON_DOWN_LEFT = TH_BUTTON_DOWN | TH_BUTTON_LEFT,
    TH_BUTTON_DOWN_RIGHT = TH_BUTTON_DOWN | TH_BUTTON_RIGHT,
};

i32 InitD3dInterface(void);

u16 GetJoystickCaps(void);
u32 SetButtonFromControllerInputs(u16 *outButtons, i16 controllerButtonToTest, enum TouhouButton touhouButton,
                                  u32 inputButtons);

unsigned int SetButtonFromDirectInputJoystate(u16 *outButtons, i16 controllerButtonToTest,
                                              enum TouhouButton touhouButton, u8 *inputButtons);
u16 GetControllerInput(u16 buttons);
u16 GetInput(void);

extern ControllerMapping g_ControllerMapping;
extern GameContext g_GameContext;
