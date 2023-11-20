#include "GameContext.hpp"
#include "FileSystem.hpp"
#include "GameErrorContext.hpp"
#include "i18n.hpp"
#include "inttypes.hpp"
#include "utils.hpp"

#include <stdio.h>
#include <string.h>

DIFFABLE_STATIC(GameContext, g_GameContext)
DIFFABLE_STATIC(ControllerMapping, g_ControllerMapping)
DIFFABLE_STATIC(JOYCAPSA, g_JoystickCaps)

i32 InitD3dInterface(void)
{
    g_GameContext.d3dIface = Direct3DCreate8(D3D_SDK_VERSION);

    if (g_GameContext.d3dIface == NULL)
    {
        GameErrorContextFatal(&g_GameErrorContext, TH_ERR_D3D_ERR_COULD_NOT_CREATE_OBJ);
        return 1;
    }
    return 0;
}

// TODO: Not a perfect match.
i32 GameContext::Parse(char *path)
{
    u8 *data;
    FILE *wavFile;

    memset(&g_GameContext.cfg, 0, sizeof(GameConfiguration));
    g_GameContext.cfg.opts = g_GameContext.cfg.opts | (1 << GCOS_USE_D3D_HW_TEXTURE_BLENDING);
    data = FileSystem::OpenPath(path, 1);
    if (data == NULL)
    {
        g_GameContext.cfg.lifeCount = 2;
        g_GameContext.cfg.bombCount = 3;
        g_GameContext.cfg.colorMode16bit = 0xff;
        g_GameContext.cfg.version = 0x102;
        g_GameContext.cfg.padXAxis = 600;
        g_GameContext.cfg.padYAxis = 600;
        wavFile = fopen("bgm/th06_01.wav", "rb");
        if (wavFile == NULL)
        {
            g_GameContext.cfg.musicMode = MIDI;
            DebugPrint(TH_ERR_NO_WAVE_FILE);
        }
        else
        {
            g_GameContext.cfg.musicMode = WAV;
            fclose(wavFile);
        }
        g_GameContext.cfg.playSounds = 1;
        g_GameContext.cfg.defaultDifficulty = 1;
        g_GameContext.cfg.windowed = false;
        g_GameContext.cfg.frameskipConfig = 0;
        g_GameContext.cfg.controllerMapping = g_ControllerMapping;
        GameErrorContextLog(&g_GameErrorContext, TH_ERR_CONFIG_NOT_FOUND);
    }
    else
    {
        memcpy(&g_GameContext.cfg, data, sizeof(GameConfiguration));
        if ((4 < g_GameContext.cfg.lifeCount) || (3 < g_GameContext.cfg.bombCount) ||
            (1 < g_GameContext.cfg.colorMode16bit) || (MIDI < g_GameContext.cfg.musicMode) ||
            (4 < g_GameContext.cfg.defaultDifficulty) || (1 < g_GameContext.cfg.playSounds) ||
            (1 < g_GameContext.cfg.windowed) || (2 < g_GameContext.cfg.frameskipConfig) ||
            (g_GameContext.cfg.version != 0x102) || (g_LastFileSize != 0x38))
        {
            g_GameContext.cfg.lifeCount = 2;
            g_GameContext.cfg.bombCount = 3;
            g_GameContext.cfg.colorMode16bit = 0xff;
            g_GameContext.cfg.version = 0x102;
            g_GameContext.cfg.padXAxis = 600;
            g_GameContext.cfg.padYAxis = 600;
            wavFile = fopen("bgm/th06_01.wav", "rb");
            if (wavFile == NULL)
            {
                g_GameContext.cfg.musicMode = MIDI;
                DebugPrint(TH_ERR_NO_WAVE_FILE);
            }
            else
            {
                g_GameContext.cfg.musicMode = WAV;
                fclose(wavFile);
            }
            g_GameContext.cfg.playSounds = 1;
            g_GameContext.cfg.defaultDifficulty = 1;
            g_GameContext.cfg.windowed = false;
            g_GameContext.cfg.frameskipConfig = 0;
            g_GameContext.cfg.controllerMapping = g_ControllerMapping;
            g_GameContext.cfg.opts = g_GameContext.cfg.opts | (1 << GCOS_USE_D3D_HW_TEXTURE_BLENDING);
            GameErrorContextLog(&g_GameErrorContext, TH_ERR_CONFIG_CORRUPTED);
        }
        g_ControllerMapping = g_GameContext.cfg.controllerMapping;
        free(data);
    }
    if (((this->cfg.opts >> GCOS_DONT_USE_VERTEX_BUF) & 1) != 0)
    {
        GameErrorContextLog(&g_GameErrorContext, TH_ERR_NO_VERTEX_BUFFER);
    }
    if (((this->cfg.opts >> GCOS_DONT_USE_FOG) & 1) != 0)
    {
        GameErrorContextLog(&g_GameErrorContext, TH_ERR_NO_FOG);
    }
    if (((this->cfg.opts >> GCOS_FORCE_16BIT_COLOR_MODE) & 1) != 0)
    {
        GameErrorContextLog(&g_GameErrorContext, TH_ERR_USE_16BIT_TEXTURES);
    }
    if (((this->cfg.opts >> GCOS_CLEAR_BACKBUFFER_ON_REFRESH) & 1 != 0 ||
         (this->cfg.opts >> GCOS_DISPLAY_MINIMUM_GRAPHICS) & 1) != 0)
    {
        GameErrorContextLog(&g_GameErrorContext, TH_ERR_FORCE_BACKBUFFER_CLEAR);
    }
    if (((this->cfg.opts >> GCOS_DISPLAY_MINIMUM_GRAPHICS) & 1) != 0)
    {
        GameErrorContextLog(&g_GameErrorContext, TH_ERR_DONT_RENDER_ITEMS);
    }
    if (((this->cfg.opts >> GCOS_SUPPRESS_USE_OF_GOROUD_SHADING) & 1) != 0)
    {
        GameErrorContextLog(&g_GameErrorContext, TH_ERR_NO_GOURAUD_SHADING);
    }
    if (((this->cfg.opts >> GCOS_TURN_OFF_DEPTH_TEST) & 1) != 0)
    {
        GameErrorContextLog(&g_GameErrorContext, TH_ERR_NO_DEPTH_TESTING);
    }
    if (((this->cfg.opts >> GCOS_FORCE_60FPS) & 1) != 0)
    {
        GameErrorContextLog(&g_GameErrorContext, TH_ERR_FORCE_60FPS_MODE);
        this->vsyncEnabled = 0;
    }
    if (((this->cfg.opts >> GCOS_NO_COLOR_COMP) & 1) != 0)
    {
        GameErrorContextLog(&g_GameErrorContext, TH_ERR_NO_TEXTURE_COLOR_COMPOSITING);
    }
    if (((this->cfg.opts >> GCOS_NO_COLOR_COMP) & 1) != 0)
    {
        GameErrorContextLog(&g_GameErrorContext, TH_ERR_LAUNCH_WINDOWED);
    }
    if (((this->cfg.opts >> GCOS_REFERENCE_RASTERIZER_MODE) & 1) != 0)
    {
        GameErrorContextLog(&g_GameErrorContext, TH_ERR_FORCE_REFERENCE_RASTERIZER);
    }
    if (((this->cfg.opts >> GCOS_NO_DIRECTINPUT_PAD) & 1) != 0)
    {
        GameErrorContextLog(&g_GameErrorContext, TH_ERR_DO_NOT_USE_DIRECTINPUT);
    }
    if (FileSystem::WriteDataToFile(path, &g_GameContext.cfg, sizeof(GameConfiguration)) == 0)
    {
        return 0;
    }
    else
    {
        GameErrorContextFatal(&g_GameErrorContext, TH_ERR_FILE_CANNOT_BE_EXPORTED, path);
        GameErrorContextFatal(&g_GameErrorContext, TH_ERR_FOLDER_HAS_WRITE_PROTECT_OR_DISK_FULL);
        return -1;
    }
}

u16 GetJoystickCaps(void)
{
    JOYINFOEX pji;

    pji.dwSize = sizeof(JOYINFOEX);
    pji.dwFlags = JOY_RETURNALL;

    if (joyGetPosEx(0, &pji) != MMSYSERR_NOERROR)
    {
        GameErrorContextLog(&g_GameErrorContext, TH_ERR_NO_PAD_FOUND);
        return 1;
    }

    joyGetDevCapsA(0, &g_JoystickCaps, sizeof(g_JoystickCaps));
    return 0;
}

u32 SetButtonFromControllerInputs(u16 *outButtons, i16 controllerButtonToTest, enum TouhouButton touhouButton,
                                  u32 inputButtons)
{
    DWORD mask;

    if (controllerButtonToTest < 0)
    {
        return 0;
    }

    mask = 1 << controllerButtonToTest;

    *outButtons |= (inputButtons & mask ? touhouButton & 0xFFFF : 0);

    return inputButtons & mask ? touhouButton & 0xFFFF : 0;
}

#define JOYSTICK_MIDPOINT(min, max) ((min + max) / 2)
#define JOYSTICK_BUTTON_PRESSED(button, x, y) (x > y ? button : 0)
#define JOYSTICK_BUTTON_PRESSED_INVERT(button, x, y) (x < y ? button : 0)
#define KEYBOARD_KEY_PRESSED(button, x) keyboardState[x] & 0x80 ? button : 0

u32 SetButtonFromDirectInputJoystate(u16 *outButtons, i16 controllerButtonToTest, enum TouhouButton touhouButton,
                                     u8 *inputButtons)
{
    if (controllerButtonToTest < 0)
    {
        return 0;
    }

    *outButtons |= (inputButtons[controllerButtonToTest] & 0x80 ? touhouButton & 0xFFFF : 0);

    return inputButtons[controllerButtonToTest] & 0x80 ? touhouButton & 0xFFFF : 0;
}

DIFFABLE_STATIC(u16, g_FocusButtonConflictState)

u16 GetControllerInput(u16 buttons)
{
    // NOTE: Those names are like this to get perfect stack frame matching
    // TODO: Give meaningfull names that still match.
    JOYINFOEX aa;
    u32 ab;
    u32 ac;
    DIJOYSTATE2 a0;
    u32 a2;
    HRESULT aaa;

    if (g_GameContext.controller == NULL)
    {
        memset(&aa, 0, sizeof(aa));
        aa.dwSize = sizeof(JOYINFOEX);
        aa.dwFlags = JOY_RETURNALL;

        if (joyGetPosEx(0, &aa) != MMSYSERR_NOERROR)
        {
            return buttons;
        }

        ac = SetButtonFromControllerInputs(&buttons, g_GameContext.cfg.controllerMapping.shootButton, TH_BUTTON_SHOOT,
                                           aa.dwButtons);

        if (g_GameContext.cfg.controllerMapping.shootButton != g_GameContext.cfg.controllerMapping.focusButton)
        {
            SetButtonFromControllerInputs(&buttons, g_GameContext.cfg.controllerMapping.focusButton, TH_BUTTON_FOCUS,
                                          aa.dwButtons);
        }
        else
        {
            if (ac != 0)
            {
                if (g_FocusButtonConflictState < 16)
                {
                    g_FocusButtonConflictState++;
                }

                if (g_FocusButtonConflictState >= 8)
                {
                    buttons |= TH_BUTTON_FOCUS;
                }
            }
            else
            {
                if (g_FocusButtonConflictState > 8)
                {
                    g_FocusButtonConflictState -= 8;
                }
                else
                {
                    g_FocusButtonConflictState = 0;
                }
            }
        }

        SetButtonFromControllerInputs(&buttons, g_GameContext.cfg.controllerMapping.bombButton, TH_BUTTON_BOMB,
                                      aa.dwButtons);
        SetButtonFromControllerInputs(&buttons, g_GameContext.cfg.controllerMapping.menuButton, TH_BUTTON_MENU,
                                      aa.dwButtons);
        SetButtonFromControllerInputs(&buttons, g_GameContext.cfg.controllerMapping.upButton, TH_BUTTON_UP,
                                      aa.dwButtons);
        SetButtonFromControllerInputs(&buttons, g_GameContext.cfg.controllerMapping.downButton, TH_BUTTON_DOWN,
                                      aa.dwButtons);
        SetButtonFromControllerInputs(&buttons, g_GameContext.cfg.controllerMapping.leftButton, TH_BUTTON_LEFT,
                                      aa.dwButtons);
        SetButtonFromControllerInputs(&buttons, g_GameContext.cfg.controllerMapping.rightButton, TH_BUTTON_RIGHT,
                                      aa.dwButtons);
        SetButtonFromControllerInputs(&buttons, g_GameContext.cfg.controllerMapping.skipButton, TH_BUTTON_SKIP,
                                      aa.dwButtons);

        ab = ((g_JoystickCaps.wXmax - g_JoystickCaps.wXmin) / 2 / 2);

        buttons |= JOYSTICK_BUTTON_PRESSED(TH_BUTTON_RIGHT, aa.dwXpos,
                                           JOYSTICK_MIDPOINT(g_JoystickCaps.wXmin, g_JoystickCaps.wXmax) + ab);
        buttons |= JOYSTICK_BUTTON_PRESSED(
            TH_BUTTON_LEFT, JOYSTICK_MIDPOINT(g_JoystickCaps.wXmin, g_JoystickCaps.wXmax) - ab, aa.dwXpos);

        ab = ((g_JoystickCaps.wYmax - g_JoystickCaps.wYmin) / 2 / 2);
        buttons |= JOYSTICK_BUTTON_PRESSED(TH_BUTTON_DOWN, aa.dwYpos,
                                           JOYSTICK_MIDPOINT(g_JoystickCaps.wYmin, g_JoystickCaps.wYmax) + ab);
        buttons |= JOYSTICK_BUTTON_PRESSED(
            TH_BUTTON_UP, JOYSTICK_MIDPOINT(g_JoystickCaps.wYmin, g_JoystickCaps.wYmax) - ab, aa.dwYpos);

        return buttons;
    }
    else
    {
        // FIXME: Next if not matching.
        aaa = g_GameContext.controller->Poll();
        if (FAILED(aaa))
        {
            i32 retryCount = 0;

            DebugPrint2("error : DIERR_INPUTLOST\n");
            aaa = g_GameContext.controller->Acquire();

            while (aaa == DIERR_INPUTLOST)
            {
                aaa = g_GameContext.controller->Acquire();
                DebugPrint2("error : DIERR_INPUTLOST %d\n", retryCount);

                retryCount++;

                if (retryCount >= 400)
                {
                    return buttons;
                }
            }

            return buttons;
        }
        else
        {
            memset(&a0, 0, sizeof(a0));

            aaa = g_GameContext.controller->GetDeviceState(sizeof(a0), &a0);

            if (FAILED(aaa))
            {
                return buttons;
            }

            a2 = SetButtonFromDirectInputJoystate(&buttons, g_GameContext.cfg.controllerMapping.shootButton,
                                                  TH_BUTTON_SHOOT, a0.rgbButtons);

            if (g_GameContext.cfg.controllerMapping.shootButton != g_GameContext.cfg.controllerMapping.focusButton)
            {
                SetButtonFromDirectInputJoystate(&buttons, g_GameContext.cfg.controllerMapping.focusButton,
                                                 TH_BUTTON_FOCUS, a0.rgbButtons);
            }
            else
            {
                if (a2 != 0)
                {
                    if (g_FocusButtonConflictState < 16)
                    {
                        g_FocusButtonConflictState++;
                    }

                    if (g_FocusButtonConflictState >= 8)
                    {
                        buttons |= TH_BUTTON_FOCUS;
                    }
                }
                else
                {
                    if (g_FocusButtonConflictState > 8)
                    {
                        g_FocusButtonConflictState -= 8;
                    }
                    else
                    {
                        g_FocusButtonConflictState = 0;
                    }
                }
            }

            SetButtonFromDirectInputJoystate(&buttons, g_GameContext.cfg.controllerMapping.bombButton, TH_BUTTON_BOMB,
                                             a0.rgbButtons);
            SetButtonFromDirectInputJoystate(&buttons, g_GameContext.cfg.controllerMapping.menuButton, TH_BUTTON_MENU,
                                             a0.rgbButtons);
            SetButtonFromDirectInputJoystate(&buttons, g_GameContext.cfg.controllerMapping.upButton, TH_BUTTON_UP,
                                             a0.rgbButtons);
            SetButtonFromDirectInputJoystate(&buttons, g_GameContext.cfg.controllerMapping.downButton, TH_BUTTON_DOWN,
                                             a0.rgbButtons);
            SetButtonFromDirectInputJoystate(&buttons, g_GameContext.cfg.controllerMapping.leftButton, TH_BUTTON_LEFT,
                                             a0.rgbButtons);
            SetButtonFromDirectInputJoystate(&buttons, g_GameContext.cfg.controllerMapping.rightButton, TH_BUTTON_RIGHT,
                                             a0.rgbButtons);
            SetButtonFromDirectInputJoystate(&buttons, g_GameContext.cfg.controllerMapping.skipButton, TH_BUTTON_SKIP,
                                             a0.rgbButtons);

            buttons |= JOYSTICK_BUTTON_PRESSED(TH_BUTTON_RIGHT, a0.lX, g_GameContext.cfg.padXAxis);
            buttons |= JOYSTICK_BUTTON_PRESSED_INVERT(TH_BUTTON_LEFT, a0.lX, -g_GameContext.cfg.padXAxis);
            buttons |= JOYSTICK_BUTTON_PRESSED(TH_BUTTON_DOWN, a0.lY, g_GameContext.cfg.padYAxis);
            buttons |= JOYSTICK_BUTTON_PRESSED_INVERT(TH_BUTTON_UP, a0.lY, -g_GameContext.cfg.padYAxis);
        }
    }

    return buttons;
}

u16 GetInput(void)
{
    u8 keyboardState[256];
    u16 buttons;

    buttons = 0;

    if (g_GameContext.keyboard == NULL)
    {
        GetKeyboardState(keyboardState);

        buttons |= KEYBOARD_KEY_PRESSED(TH_BUTTON_UP, VK_UP);
        buttons |= KEYBOARD_KEY_PRESSED(TH_BUTTON_DOWN, VK_DOWN);
        buttons |= KEYBOARD_KEY_PRESSED(TH_BUTTON_LEFT, VK_LEFT);
        buttons |= KEYBOARD_KEY_PRESSED(TH_BUTTON_RIGHT, VK_RIGHT);
        buttons |= KEYBOARD_KEY_PRESSED(TH_BUTTON_UP, VK_NUMPAD8);
        buttons |= KEYBOARD_KEY_PRESSED(TH_BUTTON_DOWN, VK_NUMPAD2);
        buttons |= KEYBOARD_KEY_PRESSED(TH_BUTTON_LEFT, VK_NUMPAD4);
        buttons |= KEYBOARD_KEY_PRESSED(TH_BUTTON_RIGHT, VK_NUMPAD6);
        buttons |= KEYBOARD_KEY_PRESSED(TH_BUTTON_UP_LEFT, VK_NUMPAD7);
        buttons |= KEYBOARD_KEY_PRESSED(TH_BUTTON_UP_RIGHT, VK_NUMPAD9);
        buttons |= KEYBOARD_KEY_PRESSED(TH_BUTTON_DOWN_LEFT, VK_NUMPAD1);
        buttons |= KEYBOARD_KEY_PRESSED(TH_BUTTON_DOWN_RIGHT, VK_NUMPAD3);
        buttons |= KEYBOARD_KEY_PRESSED(TH_BUTTON_UNK11, VK_HOME);
        buttons |= KEYBOARD_KEY_PRESSED(TH_BUTTON_SHOOT, 'Z');
        buttons |= KEYBOARD_KEY_PRESSED(TH_BUTTON_BOMB, 'X');
        buttons |= KEYBOARD_KEY_PRESSED(TH_BUTTON_FOCUS, VK_SHIFT);
        buttons |= KEYBOARD_KEY_PRESSED(TH_BUTTON_MENU, VK_ESCAPE);
        buttons |= KEYBOARD_KEY_PRESSED(TH_BUTTON_SKIP, VK_CONTROL);
        buttons |= KEYBOARD_KEY_PRESSED(TH_BUTTON_UNK9, 'Q');
        buttons |= KEYBOARD_KEY_PRESSED(TH_BUTTON_UNK10, 'S');
        buttons |= KEYBOARD_KEY_PRESSED(TH_BUTTON_UNK12, VK_RETURN);
    }
    else
    {
        HRESULT res = g_GameContext.keyboard->GetDeviceState(sizeof(keyboardState), keyboardState);

        buttons = 0;

        if (res == DIERR_INPUTLOST)
        {
            g_GameContext.keyboard->Acquire();

            return GetControllerInput(buttons);
        }

        buttons |= KEYBOARD_KEY_PRESSED(TH_BUTTON_UP, DIK_UP);
        buttons |= KEYBOARD_KEY_PRESSED(TH_BUTTON_DOWN, DIK_DOWN);
        buttons |= KEYBOARD_KEY_PRESSED(TH_BUTTON_LEFT, DIK_LEFT);
        buttons |= KEYBOARD_KEY_PRESSED(TH_BUTTON_RIGHT, DIK_RIGHT);
        buttons |= KEYBOARD_KEY_PRESSED(TH_BUTTON_UP, DIK_NUMPAD8);
        buttons |= KEYBOARD_KEY_PRESSED(TH_BUTTON_DOWN, DIK_NUMPAD2);
        buttons |= KEYBOARD_KEY_PRESSED(TH_BUTTON_LEFT, DIK_NUMPAD4);
        buttons |= KEYBOARD_KEY_PRESSED(TH_BUTTON_RIGHT, DIK_NUMPAD6);
        buttons |= KEYBOARD_KEY_PRESSED(TH_BUTTON_UP_LEFT, DIK_NUMPAD7);
        buttons |= KEYBOARD_KEY_PRESSED(TH_BUTTON_UP_RIGHT, DIK_NUMPAD9);
        buttons |= KEYBOARD_KEY_PRESSED(TH_BUTTON_DOWN_LEFT, DIK_NUMPAD1);
        buttons |= KEYBOARD_KEY_PRESSED(TH_BUTTON_DOWN_RIGHT, DIK_NUMPAD3);
        buttons |= KEYBOARD_KEY_PRESSED(TH_BUTTON_UNK11, DIK_HOME);
        buttons |= KEYBOARD_KEY_PRESSED(TH_BUTTON_SHOOT, DIK_Z);
        buttons |= KEYBOARD_KEY_PRESSED(TH_BUTTON_BOMB, DIK_X);
        buttons |= KEYBOARD_KEY_PRESSED(TH_BUTTON_FOCUS, DIK_LSHIFT);
        buttons |= KEYBOARD_KEY_PRESSED(TH_BUTTON_FOCUS, DIK_RSHIFT);
        buttons |= KEYBOARD_KEY_PRESSED(TH_BUTTON_MENU, DIK_ESCAPE);
        buttons |= KEYBOARD_KEY_PRESSED(TH_BUTTON_SKIP, DIK_LCONTROL);
        buttons |= KEYBOARD_KEY_PRESSED(TH_BUTTON_SKIP, DIK_RCONTROL);
        buttons |= KEYBOARD_KEY_PRESSED(TH_BUTTON_UNK9, DIK_Q);
        buttons |= KEYBOARD_KEY_PRESSED(TH_BUTTON_UNK10, DIK_S);
        buttons |= KEYBOARD_KEY_PRESSED(TH_BUTTON_UNK12, DIK_RETURN);
    }

    return GetControllerInput(buttons);
}
