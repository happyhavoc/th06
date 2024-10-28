#include "Supervisor.hpp"
#include "AnmManager.hpp"
#include "AsciiManager.hpp"
#include "Chain.hpp"
#include "ChainPriorities.hpp"
#include "Ending.hpp"
#include "FileSystem.hpp"
#include "GameErrorContext.hpp"
#include "GameManager.hpp"
#include "GameWindow.hpp"
#include "MainMenu.hpp"
#include "MusicRoom.hpp"
#include "Replay.hpp"
#include "ResultScreen.hpp"
#include "Rng.hpp"
#include "SoundPlayer.hpp"
#include "TextHelper.hpp"
#include "i18n.hpp"
#include "inttypes.hpp"
#include "utils.hpp"

#include <stdio.h>
#include <string.h>

namespace th06
{
DIFFABLE_STATIC(Supervisor, g_Supervisor)
DIFFABLE_STATIC(ControllerMapping, g_ControllerMapping)
DIFFABLE_STATIC(JOYCAPSA, g_JoystickCaps)
DIFFABLE_STATIC(IDirect3DSurface8 *, g_TextBufferSurface)
DIFFABLE_STATIC(u16, g_LastFrameInput);
DIFFABLE_STATIC(u16, g_CurFrameInput);
DIFFABLE_STATIC(u16, g_IsEigthFrameOfHeldInput);
DIFFABLE_STATIC(u16, g_NumOfFramesInputsWereHeld);
DIFFABLE_STATIC(u16, g_FocusButtonConflictState)

// TODO: Not a perfect match.
ZunResult Supervisor::LoadConfig(char *path)
{
    u8 *data;
    FILE *wavFile;

    memset(&g_Supervisor.cfg, 0, sizeof(GameConfiguration));
    g_Supervisor.cfg.opts = g_Supervisor.cfg.opts | (1 << GCOS_USE_D3D_HW_TEXTURE_BLENDING);
    data = FileSystem::OpenPath(path, 1);
    if (data == NULL)
    {
        g_Supervisor.cfg.lifeCount = 2;
        g_Supervisor.cfg.bombCount = 3;
        g_Supervisor.cfg.colorMode16bit = 0xff;
        g_Supervisor.cfg.version = 0x102;
        g_Supervisor.cfg.padXAxis = 600;
        g_Supervisor.cfg.padYAxis = 600;
        wavFile = fopen("bgm/th06_01.wav", "rb");
        if (wavFile == NULL)
        {
            g_Supervisor.cfg.musicMode = MIDI;
            utils::DebugPrint(TH_ERR_NO_WAVE_FILE);
        }
        else
        {
            g_Supervisor.cfg.musicMode = WAV;
            fclose(wavFile);
        }
        g_Supervisor.cfg.playSounds = 1;
        g_Supervisor.cfg.defaultDifficulty = 1;
        g_Supervisor.cfg.windowed = false;
        g_Supervisor.cfg.frameskipConfig = 0;
        g_Supervisor.cfg.controllerMapping = g_ControllerMapping;
        GameErrorContext::Log(&g_GameErrorContext, TH_ERR_CONFIG_NOT_FOUND);
    }
    else
    {
        memcpy(&g_Supervisor.cfg, data, sizeof(GameConfiguration));
        if ((4 < g_Supervisor.cfg.lifeCount) || (3 < g_Supervisor.cfg.bombCount) ||
    }

    return TRUE;
}
#pragma optimize("", on)

#pragma optimize("s", on)
ZunResult Supervisor::PlayAudio(char *path)
{
    char wavName[256];
    char wavPos[256];
    char *pathExtension;

    if (g_Supervisor.cfg.musicMode == MIDI)
    {
        if (g_Supervisor.midiOutput != NULL)
        {
            MidiOutput *midiOutput = g_Supervisor.midiOutput;
            midiOutput->StopPlayback();
            midiOutput->LoadFile(path);
            midiOutput->Play();
        }
    }
    else if (g_Supervisor.cfg.musicMode == WAV)
    {
        strcpy(wavName, path);
        strcpy(wavPos, path);
        pathExtension = strrchr(wavName, L'.');
        pathExtension[1] = 'w';
        pathExtension[2] = 'a';
        pathExtension[3] = 'v';
        pathExtension = strrchr(wavPos, L'.');
        pathExtension[1] = 'p';
        pathExtension[2] = 'o';
        pathExtension[3] = 's';
        g_SoundPlayer.LoadWav(wavName);
        if (g_SoundPlayer.LoadPos(wavPos) < ZUN_SUCCESS)
        {
            g_SoundPlayer.PlayBGM(FALSE);
        }
        else
        {
            g_SoundPlayer.PlayBGM(TRUE);
        }
    }
    else
    {
        return ZUN_ERROR;
    }
    return ZUN_SUCCESS;
}
#pragma optimize("", on)

#pragma optimize("s", on)
ZunResult Supervisor::StopAudio()
{
    if (g_Supervisor.cfg.musicMode == MIDI)
    {
        if (g_Supervisor.midiOutput != NULL)
        {
            g_Supervisor.midiOutput->StopPlayback();
        }
    }
    else
    {
        if (g_Supervisor.cfg.musicMode == WAV)
        {
            g_SoundPlayer.StopBGM();
        }
        else
        {
            return ZUN_ERROR;
        }
    }

    return ZUN_SUCCESS;
}
#pragma optimize("", on)

#pragma optimize("s", on)
ZunResult Supervisor::SetupMidiPlayback(char *path)
{
    // There doesn't seem to be a way to recreate the jump assembly needed without gotos?
    // Standard short circuiting boolean operators and nested conditionals don't seem to work, at least
    if (g_Supervisor.cfg.musicMode == MIDI)
    {
        goto success;
    }
    else if (g_Supervisor.cfg.musicMode == WAV)
    {
        goto success;
    }
    else
    {
        return ZUN_ERROR;
    }

success:
    return ZUN_SUCCESS;
}
#pragma optimize("", on)

#pragma optimize("s", on)
ZunResult Supervisor::FadeOutMusic(f32 fadeOutSeconds)
{
    i32 unused1;
    i32 unused2;
    i32 unused3;

    if (g_Supervisor.cfg.musicMode == MIDI)
    {
        if (g_Supervisor.midiOutput != NULL)
        {
            g_Supervisor.midiOutput->SetFadeOut(1000.0f * fadeOutSeconds);
        }
    }
    else
    {
        if (g_Supervisor.cfg.musicMode == WAV)
        {
            if (this->effectiveFramerateMultiplier == 0.0f)
            {
                g_SoundPlayer.FadeOut(fadeOutSeconds);
            }
            else
            {
                if (this->effectiveFramerateMultiplier > 1.0f)
                {
                    g_SoundPlayer.FadeOut(fadeOutSeconds);
                }
                else
                {
                    g_SoundPlayer.FadeOut(fadeOutSeconds / this->effectiveFramerateMultiplier);
                }
            }
        }
        else
        {
            return ZUN_ERROR;
        }
    }

    return ZUN_SUCCESS;
}
#pragma optimize("", on)

#pragma optimize("s", on)
// this is for rebinding keys
u8 *th06::Controller::GetControllerState()
{
    static u32 controllerData[32];
    memset(&controllerData, 0, sizeof(controllerData));
    if (g_Supervisor.controller == NULL)
    {
        // TODO: not tested
        JOYINFOEX joyinfo;
        memset(&joyinfo, 0, sizeof(JOYINFOEX));
        joyinfo.dwSize = sizeof(JOYINFOEX);
        joyinfo.dwFlags = JOY_RETURNALL;
        MMRESULT MVar1 = joyGetPosEx(0, &joyinfo);
        if (MVar1 == 0)
        {
            u32 local_3c = joyinfo.dwButtons;
            for (u32 local_40 = 0; local_40 < 32; local_40 += 1)
            {
                if ((local_3c & 1) != 0)
                {
                    *(u8 *)((int)controllerData + local_40) = 0x80;
                }
                local_3c = local_3c >> 1;
            }
        }
    }
    else
    {
        HRESULT HVar2 = g_Supervisor.controller->Poll();
        if (FAILED(HVar2))
        {
            int local_retryCount = 0;
            utils::DebugPrint2("error : DIERR_INPUTLOST\n");
            HRESULT local_44 = g_Supervisor.controller->Acquire();
            do
            {
                if (local_44 != DIERR_INPUTLOST)
                    break;
                local_44 = g_Supervisor.controller->Acquire();
                utils::DebugPrint2("error : DIERR_INPUTLOST %d\n", local_retryCount);
                local_retryCount++;
            } while (local_retryCount < 400);
        }
        else
        {
            DIJOYSTATE2 local_15c;
            HVar2 = g_Supervisor.controller->GetDeviceState(0x110, &local_15c);
            // TODO: is there no "HVar2 =" in ZUN code?
            if (SUCCEEDED(HVar2))
            {
                memcpy(&controllerData, local_15c.rgbButtons, sizeof(local_15c.rgbButtons));
            }
        }
    }
    return (byte *)controllerData;
}
#pragma optimize("", on)
}; // namespace th06