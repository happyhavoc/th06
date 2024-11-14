#pragma once

#include <d3d8.h>
#include <d3dx8math.h>
#include <dinput.h>

#include "Chain.hpp"
#include "MidiOutput.hpp"
#include "ZunBool.hpp"
#include "ZunResult.hpp"
#include "diffbuild.hpp"
#include "inttypes.hpp"
#include "pbg3/Pbg3Archive.hpp"

namespace th06
{
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
    u8 lifeCount;
    u8 bombCount;
    u8 colorMode16bit;
    u8 musicMode;
    u8 playSounds;
    u8 defaultDifficulty;
    u8 windowed;
    // 0 = fullspeed, 1 = 1/2 speed, 2 = 1/4 speed.
    u8 frameskipConfig;
    i16 padXAxis;
    i16 padYAxis;
    i8 unk[16];
    // GameConfigOpts bitfield.
    u32 opts;

    u32 IsSoftwareTexturing()
    {
        return this->opts >> GCOS_NO_COLOR_COMP & 1 | this->opts >> GCOS_USE_D3D_HW_TEXTURE_BLENDING & 1;
    }
};

#define IN_PBG3_INDEX 0
#define MD_PBG3_INDEX 1
#define ST_PBG3_INDEX 2
#define CM_PBG3_INDEX 4
#define ED_PBG3_INDEX 5

typedef char Pbg3ArchiveName[32];

enum SupervisorState
{
    SUPERVISOR_STATE_INIT,
    SUPERVISOR_STATE_MAINMENU,
    SUPERVISOR_STATE_GAMEMANAGER,
    SUPERVISOR_STATE_GAMEMANAGER_REINIT,
    SUPERVISOR_STATE_EXITSUCCESS,
    SUPERVISOR_STATE_EXITERROR,
    SUPERVISOR_STATE_RESULTSCREEN,
    SUPERVISOR_STATE_RESULTSCREEN_FROMGAME,
    SUPERVISOR_STATE_MAINMENU_REPLAY,
    SUPERVISOR_STATE_MUSICROOM,
    SUPERVISOR_STATE_ENDING,
};

struct Supervisor
{
    static ZunResult RegisterChain();
    static ChainCallbackResult OnUpdate(Supervisor *s);
    static ChainCallbackResult OnDraw(Supervisor *s);
    static ZunResult AddedCallback(Supervisor *s);
    static ZunResult DeletedCallback(Supervisor *s);
    static void DrawFpsCounter();

    ZunBool ReadMidiFile(u32 midiFileIdx, char *path);
    i32 PlayMidiFile(i32 midiFileIdx);
    ZunResult PlayAudio(char *path);
    ZunResult StopAudio();
    ZunResult SetupMidiPlayback(char *path);
    ZunResult FadeOutMusic(f32 fadeOutSeconds);

    static ZunResult SetupDInput(Supervisor *s);

    i32 LoadPbg3(i32 pbg3FileIdx, char *filename);
    void ReleasePbg3(i32 pbg3FileIdx);

    ZunResult LoadConfig(char *path);

    void TickTimer(i32 *frames, f32 *subframes);

    f32 FramerateMultiplier()
    {
        return this->effectiveFramerateMultiplier;
    }

    u32 IsUnknown()
    {
        return this->cfg.opts >> GCOS_CLEAR_BACKBUFFER_ON_REFRESH & 1 |
               this->cfg.opts >> GCOS_DISPLAY_MINIMUM_GRAPHICS & 1;
    }

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
    GameConfiguration defaultConfig;
    i32 calcCount;
    i32 wantedState;
    i32 curState;
    i32 wantedState2;

    i32 unk194;
    i32 unk198;
    ZunBool isInEnding;

    i32 vsyncEnabled;
    i32 lastFrameTime;
    f32 effectiveFramerateMultiplier;
    f32 framerateMultiplier;

    MidiOutput *midiOutput;

    f32 unk1b4;
    f32 unk1b8;

    Pbg3Archive *pbg3Archives[16];
    Pbg3ArchiveName pbg3ArchiveNames[16];

    u8 hasD3dHardwareVertexProcessing;
    u8 lockableBackbuffer;
    u8 colorMode16Bits;

    u32 startupTimeBeforeMenuMusic;
    D3DCAPS8 d3dCaps;
};
C_ASSERT(sizeof(Supervisor) == 0x4d8);

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
    TH_BUTTON_Q = 1 << 9,
    TH_BUTTON_S = 1 << 10,
    TH_BUTTON_HOME = 1 << 11,
    TH_BUTTON_ENTER = 1 << 12,

    TH_BUTTON_UP_LEFT = TH_BUTTON_UP | TH_BUTTON_LEFT,
    TH_BUTTON_UP_RIGHT = TH_BUTTON_UP | TH_BUTTON_RIGHT,
    TH_BUTTON_DOWN_LEFT = TH_BUTTON_DOWN | TH_BUTTON_LEFT,
    TH_BUTTON_DOWN_RIGHT = TH_BUTTON_DOWN | TH_BUTTON_RIGHT,
    TH_BUTTON_DIRECTION = TH_BUTTON_DOWN | TH_BUTTON_RIGHT | TH_BUTTON_UP | TH_BUTTON_LEFT,

    TH_BUTTON_SELECTMENU = TH_BUTTON_ENTER | TH_BUTTON_SHOOT,
    TH_BUTTON_RETURNMENU = TH_BUTTON_MENU | TH_BUTTON_BOMB,
    TH_BUTTON_WRONG_CHEATCODE =
        TH_BUTTON_SHOOT | TH_BUTTON_BOMB | TH_BUTTON_MENU | TH_BUTTON_Q | TH_BUTTON_S | TH_BUTTON_ENTER,
    TH_BUTTON_ANY = 0xFFFF,
};

namespace Controller
{
u16 GetJoystickCaps(void);
u32 SetButtonFromControllerInputs(u16 *outButtons, i16 controllerButtonToTest, enum TouhouButton touhouButton,
                                  u32 inputButtons);

unsigned int SetButtonFromDirectInputJoystate(u16 *outButtons, i16 controllerButtonToTest,
                                              enum TouhouButton touhouButton, u8 *inputButtons);

u16 GetControllerInput(u16 buttons);
u8 *GetControllerState();
u16 GetInput(void);
BOOL CALLBACK ControllerCallback(LPCDIDEVICEOBJECTINSTANCEA lpddoi, LPVOID pvRef);
BOOL CALLBACK EnumGameControllersCb(LPCDIDEVICEINSTANCEA pdidInstance, LPVOID pContext);
void ResetKeyboard(void);
}; // namespace Controller

DIFFABLE_EXTERN(ControllerMapping, g_ControllerMapping)
DIFFABLE_EXTERN(Supervisor, g_Supervisor)
DIFFABLE_EXTERN(u16, g_LastFrameInput)
DIFFABLE_EXTERN(u16, g_CurFrameInput)
DIFFABLE_EXTERN(u16, g_IsEigthFrameOfHeldInput)
DIFFABLE_EXTERN(IDirect3DSurface8 *, g_TextBufferSurface)
DIFFABLE_EXTERN(u16, g_NumOfFramesInputsWereHeld);
}; // namespace th06
