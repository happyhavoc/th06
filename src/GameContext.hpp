#pragma once

#include <d3d8.h>
#include <d3dx8math.h>
#include <dinput.h>

#include "MidiOutput.hpp"
#include "diffbuild.hpp"
#include "inttypes.hpp"

enum GameConfigOptsShifts
{
    GCOS_USE_D3D_HW_TEXTURE_BLENDING = 0x0,
    GCOS_DONT_USE_VERTEX_BUF = 0x1,
    GCOS_FORCE_16BIT_COLOR_MODE = 0x2,
    GCOS_CLEAR_BACKBUFFER_ON_REFRESH = 0x3,
    GCOS_DISPLAY_MINIMUM_GRAPHICS = 0x4,
    GCOS_SUPPRESS_USE_OF_GOROUD_SHADING = 0x5,
    GCOS_TURN_OFF_DEPTH_TEST = 0x6,
    GCOS_FORCE_60FPS = 0x7,
    GCOS_NO_COLOR_COMP = 0x8,
    GCOS_REFERENCE_RASTERIZER_MODE = 0x9,
    GCOS_DONT_USE_FOG = 0xa,
    GCOS_NO_DIRECTINPUT_PAD = 0xb,
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
    u8 colorMode16bit;
    MusicMode musicMode;
    i8 playSounds;
    i8 defaultDifficulty;
    u8 windowed;
    // 0 = fullspeed, 1 = 1/2 speed, 2 = 1/4 speed.
    u8 frameskipConfig;
    i16 padXAxis;
    i16 padYAxis;
    i8 unk[16];
    // GameConfigOpts bitfield.
    u32 opts;
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
    D3DXMATRIX viewMatrix;
    D3DXMATRIX projectionMatrix;
    D3DVIEWPORT8 viewport;
    D3DPRESENT_PARAMETERS presentParameters;
    GameConfiguration cfg;

    i32 unk198;
    i32 vsyncEnabled;
    i32 lastFrameTime;
    float framerateMultiplier;

    MidiOutput *midiOutput;

    u8 hasD3dHardwareVertexProcessing;
    u8 lockableBackbuffer;
    u8 colorMode16Bits;

    D3DCAPS8 d3dCaps;
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

DIFFABLE_EXTERN(ControllerMapping, g_ControllerMapping)
DIFFABLE_EXTERN(GameContext, g_GameContext)
