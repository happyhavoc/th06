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
#include "ReplayManager.hpp"
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

#pragma optimize("s", on)
#pragma var_order(data, wavFile, wavFile2)
ZunResult Supervisor::LoadConfig(char *path)
{
    GameConfiguration *data;
    FILE *wavFile;
    FILE *wavFile2;

    memset(&g_Supervisor.cfg, 0, sizeof(GameConfiguration));
    g_Supervisor.cfg.opts = g_Supervisor.cfg.opts | (1 << GCOS_USE_D3D_HW_TEXTURE_BLENDING);
    data = (GameConfiguration *)FileSystem::OpenPath(path, 1);
    if (data == NULL)
    {
        g_Supervisor.cfg.lifeCount = 2;
        g_Supervisor.cfg.bombCount = 3;
        g_Supervisor.cfg.colorMode16bit = 0xff;
        g_Supervisor.cfg.version = GAME_VERSION;
        g_Supervisor.cfg.padXAxis = 600;
        g_Supervisor.cfg.padYAxis = 600;
        wavFile = fopen("bgm/th06_01.wav", "rb");
        if (wavFile != NULL)
        {
            g_Supervisor.cfg.musicMode = WAV;
            fclose(wavFile);
        }
        else
        {
            g_Supervisor.cfg.musicMode = MIDI;
            utils::DebugPrint(TH_ERR_NO_WAVE_FILE);
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
        g_Supervisor.cfg = *data;
        if ((g_Supervisor.cfg.lifeCount >= 5) || (g_Supervisor.cfg.bombCount >= 4) ||
            (g_Supervisor.cfg.colorMode16bit >= 2) || (g_Supervisor.cfg.musicMode >= 3) ||
            (g_Supervisor.cfg.defaultDifficulty >= 5) || (g_Supervisor.cfg.playSounds >= 2) ||
            (g_Supervisor.cfg.windowed >= 2) || (g_Supervisor.cfg.frameskipConfig >= 3) ||
            (g_Supervisor.cfg.version != GAME_VERSION) || (g_LastFileSize != 0x38))
        {
            g_Supervisor.cfg.lifeCount = 2;
            g_Supervisor.cfg.bombCount = 3;
            g_Supervisor.cfg.colorMode16bit = 0xff;
            g_Supervisor.cfg.version = GAME_VERSION;
            g_Supervisor.cfg.padXAxis = 600;
            g_Supervisor.cfg.padYAxis = 600;
            wavFile2 = fopen("bgm/th06_01.wav", "rb");
            if (wavFile2 != NULL)
            {
                g_Supervisor.cfg.musicMode = WAV;
                fclose(wavFile2);
            }
            else
            {
                g_Supervisor.cfg.musicMode = MIDI;
                utils::DebugPrint(TH_ERR_NO_WAVE_FILE);
            }
            g_Supervisor.cfg.playSounds = 1;
            g_Supervisor.cfg.defaultDifficulty = 1;
            g_Supervisor.cfg.windowed = false;
            g_Supervisor.cfg.frameskipConfig = 0;
            g_Supervisor.cfg.controllerMapping = g_ControllerMapping;
            memset(&g_Supervisor.cfg.opts, 0, sizeof(GameConfigOptsShifts));
            g_Supervisor.cfg.opts |= (1 << GCOS_USE_D3D_HW_TEXTURE_BLENDING);
            GameErrorContext::Log(&g_GameErrorContext, TH_ERR_CONFIG_CORRUPTED);
        }
        g_ControllerMapping = g_Supervisor.cfg.controllerMapping;
        free(data);
    }
    if (((this->cfg.opts >> GCOS_DONT_USE_VERTEX_BUF) & 1) != 0)
    {
        GameErrorContext::Log(&g_GameErrorContext, TH_ERR_NO_VERTEX_BUFFER);
    }
    if (((this->cfg.opts >> GCOS_DONT_USE_FOG) & 1) != 0)
    {
        GameErrorContext::Log(&g_GameErrorContext, TH_ERR_NO_FOG);
    }
    if (((this->cfg.opts >> GCOS_FORCE_16BIT_COLOR_MODE) & 1) != 0)
    {
        GameErrorContext::Log(&g_GameErrorContext, TH_ERR_USE_16BIT_TEXTURES);
    }
    if (this->IsUnknown())
    {
        GameErrorContext::Log(&g_GameErrorContext, TH_ERR_FORCE_BACKBUFFER_CLEAR);
    }
    if (((this->cfg.opts >> GCOS_DISPLAY_MINIMUM_GRAPHICS) & 1) != 0)
    {
        GameErrorContext::Log(&g_GameErrorContext, TH_ERR_DONT_RENDER_ITEMS);
    }
    if (((this->cfg.opts >> GCOS_SUPPRESS_USE_OF_GOROUD_SHADING) & 1) != 0)
    {
        GameErrorContext::Log(&g_GameErrorContext, TH_ERR_NO_GOURAUD_SHADING);
    }
    if (((this->cfg.opts >> GCOS_TURN_OFF_DEPTH_TEST) & 1) != 0)
    {
        GameErrorContext::Log(&g_GameErrorContext, TH_ERR_NO_DEPTH_TESTING);
    }
    if (((this->cfg.opts >> GCOS_FORCE_60FPS) & 1) != 0)
    {
        GameErrorContext::Log(&g_GameErrorContext, TH_ERR_FORCE_60FPS_MODE);
        this->vsyncEnabled = 0;
    }
    if (((this->cfg.opts >> GCOS_NO_COLOR_COMP) & 1) != 0)
    {
        GameErrorContext::Log(&g_GameErrorContext, TH_ERR_NO_TEXTURE_COLOR_COMPOSITING);
    }
    if (((this->cfg.opts >> GCOS_NO_COLOR_COMP) & 1) != 0)
    {
        GameErrorContext::Log(&g_GameErrorContext, TH_ERR_LAUNCH_WINDOWED);
    }
    if (((this->cfg.opts >> GCOS_REFERENCE_RASTERIZER_MODE) & 1) != 0)
    {
        GameErrorContext::Log(&g_GameErrorContext, TH_ERR_FORCE_REFERENCE_RASTERIZER);
    }
    if (((this->cfg.opts >> GCOS_NO_DIRECTINPUT_PAD) & 1) != 0)
    {
        GameErrorContext::Log(&g_GameErrorContext, TH_ERR_DO_NOT_USE_DIRECTINPUT);
    }
    if (FileSystem::WriteDataToFile(path, &g_Supervisor.cfg, sizeof(GameConfiguration)) != 0)
    {
        GameErrorContext::Fatal(&g_GameErrorContext, TH_ERR_FILE_CANNOT_BE_EXPORTED, path);
        GameErrorContext::Fatal(&g_GameErrorContext, TH_ERR_FOLDER_HAS_WRITE_PROTECT_OR_DISK_FULL);
        return ZUN_ERROR;
    }

    return ZUN_SUCCESS;
}
#pragma optimize("", on)

#pragma optimize("s", on)
#pragma var_order(chain, supervisor)
ZunResult Supervisor::RegisterChain()
{
    ChainElem *chain;
    Supervisor *supervisor = &g_Supervisor;

    supervisor->wantedState = 0;
    supervisor->curState = -1;
    supervisor->calcCount = 0;

    chain = g_Chain.CreateElem((ChainCallback)Supervisor::OnUpdate);
    chain->arg = supervisor;
    chain->addedCallback = (ChainAddedCallback)Supervisor::AddedCallback;
    chain->deletedCallback = (ChainDeletedCallback)Supervisor::DeletedCallback;
    if (g_Chain.AddToCalcChain(chain, TH_CHAIN_PRIO_CALC_SUPERVISOR) != 0)
    {
        return ZUN_ERROR;
    }

    chain = g_Chain.CreateElem((ChainCallback)Supervisor::OnDraw);
    chain->arg = supervisor;
    g_Chain.AddToDrawChain(chain, TH_CHAIN_PRIO_DRAW_SUPERVISOR);

    return ZUN_SUCCESS;
}
#pragma optimize("", on)

#pragma optimize("s", on)
ChainCallbackResult Supervisor::OnUpdate(Supervisor *s)
{

    if (g_SoundPlayer.backgroundMusic != NULL)
    {
        g_SoundPlayer.backgroundMusic->UpdateFadeOut();
    }
    g_LastFrameInput = g_CurFrameInput;
    g_CurFrameInput = Controller::GetInput();
    g_IsEigthFrameOfHeldInput = 0;
    if (g_LastFrameInput == g_CurFrameInput)
    {
        if (0x1e <= g_NumOfFramesInputsWereHeld)
        {
            if (g_NumOfFramesInputsWereHeld % 8 == 0)
            {
                g_IsEigthFrameOfHeldInput = 1;
            }
            if (0x26 <= g_NumOfFramesInputsWereHeld)
            {
                g_NumOfFramesInputsWereHeld = 0x1e;
            }
        }
        g_NumOfFramesInputsWereHeld++;
    }
    else
    {
        g_NumOfFramesInputsWereHeld = 0;
    }

    if (s->wantedState != s->curState)
    {
        s->wantedState2 = s->wantedState;
        switch (s->wantedState)
        {
        case SUPERVISOR_STATE_INIT:
        REINIT_MAINMENU:
            s->curState = SUPERVISOR_STATE_MAINMENU;
            g_Supervisor.d3dDevice->ResourceManagerDiscardBytes(0);
            if (MainMenu::RegisterChain(0) != ZUN_SUCCESS)
            {
                return CHAIN_CALLBACK_RESULT_EXIT_GAME_SUCCESS;
            }
            break;
        case SUPERVISOR_STATE_MAINMENU:
            switch (s->curState)
            {
            case SUPERVISOR_STATE_EXITSUCCESS:
                return CHAIN_CALLBACK_RESULT_EXIT_GAME_SUCCESS;
            case SUPERVISOR_STATE_GAMEMANAGER:
                if (GameManager::RegisterChain() != ZUN_SUCCESS)
                {
                    return CHAIN_CALLBACK_RESULT_EXIT_GAME_SUCCESS;
                }
                break;
            case SUPERVISOR_STATE_EXITERROR:
                return CHAIN_CALLBACK_RESULT_EXIT_GAME_ERROR;
            case SUPERVISOR_STATE_RESULTSCREEN:
                if (ResultScreen::RegisterChain(NULL) != ZUN_SUCCESS)
                {
                    return CHAIN_CALLBACK_RESULT_EXIT_GAME_SUCCESS;
                }
                break;
            case SUPERVISOR_STATE_MUSICROOM:
                if (MusicRoom::RegisterChain() != ZUN_SUCCESS)
                {
                    return CHAIN_CALLBACK_RESULT_EXIT_GAME_SUCCESS;
                }
                break;
            case SUPERVISOR_STATE_ENDING:
                GameManager::CutChain();
                if (Ending::RegisterChain() != ZUN_SUCCESS)
                {
                    return CHAIN_CALLBACK_RESULT_EXIT_GAME_SUCCESS;
                }
                break;
            }
            break;

        case SUPERVISOR_STATE_RESULTSCREEN:
            switch (s->curState)
            {
            case SUPERVISOR_STATE_EXITSUCCESS:
                return CHAIN_CALLBACK_RESULT_EXIT_GAME_SUCCESS;
            case SUPERVISOR_STATE_MAINMENU:
                s->curState = SUPERVISOR_STATE_INIT;
                goto REINIT_MAINMENU;
            }
            break;
        case SUPERVISOR_STATE_GAMEMANAGER:
            switch (s->curState)
            {
            case SUPERVISOR_STATE_EXITSUCCESS:
                return CHAIN_CALLBACK_RESULT_EXIT_GAME_SUCCESS;

            case SUPERVISOR_STATE_MAINMENU:
            RETURN_TO_MENU_FROM_GAME:
                GameManager::CutChain();
                s->curState = SUPERVISOR_STATE_INIT;
                ReplayManager::SaveReplay(NULL, NULL);
                goto REINIT_MAINMENU;

            case SUPERVISOR_STATE_RESULTSCREEN_FROMGAME:
                GameManager::CutChain();
                if (ResultScreen::RegisterChain(TRUE) != ZUN_SUCCESS)
                {
                    return CHAIN_CALLBACK_RESULT_EXIT_GAME_SUCCESS;
                }
                break;
            case SUPERVISOR_STATE_GAMEMANAGER_REINIT:
                GameManager::CutChain();
                if (GameManager::RegisterChain() != ZUN_SUCCESS)
                {
                    return CHAIN_CALLBACK_RESULT_EXIT_GAME_SUCCESS;
                }
                if (s->curState == SUPERVISOR_STATE_MAINMENU)
                {
                    goto RETURN_TO_MENU_FROM_GAME;
                }
                s->curState = SUPERVISOR_STATE_GAMEMANAGER;
                break;
            case SUPERVISOR_STATE_MAINMENU_REPLAY:
                GameManager::CutChain();
                s->curState = SUPERVISOR_STATE_INIT;
                ReplayManager::SaveReplay(NULL, NULL);
                s->curState = SUPERVISOR_STATE_MAINMENU;
                g_Supervisor.d3dDevice->ResourceManagerDiscardBytes(0);
                if (MainMenu::RegisterChain(1) != ZUN_SUCCESS)
                {
                    return CHAIN_CALLBACK_RESULT_EXIT_GAME_SUCCESS;
                }
                break;

            case 10:
                GameManager::CutChain();
                if (Ending::RegisterChain() != ZUN_SUCCESS)
                {
                    return CHAIN_CALLBACK_RESULT_EXIT_GAME_SUCCESS;
                }
                break;
            }
            break;
        case SUPERVISOR_STATE_RESULTSCREEN_FROMGAME:
            switch (s->curState)
            {
            case SUPERVISOR_STATE_EXITSUCCESS:
                ReplayManager::SaveReplay(NULL, NULL);
                return CHAIN_CALLBACK_RESULT_EXIT_GAME_SUCCESS;
            case SUPERVISOR_STATE_MAINMENU:
                s->curState = SUPERVISOR_STATE_INIT;
                ReplayManager::SaveReplay(NULL, NULL);
                goto REINIT_MAINMENU;
            }
            break;
        case SUPERVISOR_STATE_MUSICROOM:
            switch (s->curState)
            {
            case SUPERVISOR_STATE_EXITSUCCESS:
                return CHAIN_CALLBACK_RESULT_EXIT_GAME_SUCCESS;

            case SUPERVISOR_STATE_MAINMENU:
                s->curState = SUPERVISOR_STATE_INIT;
                goto REINIT_MAINMENU;
            }
            break;
        case SUPERVISOR_STATE_ENDING:
            switch (s->curState)
            {
            case SUPERVISOR_STATE_EXITSUCCESS:
                return CHAIN_CALLBACK_RESULT_EXIT_GAME_SUCCESS;
            case SUPERVISOR_STATE_MAINMENU:
                s->curState = SUPERVISOR_STATE_INIT;
                goto REINIT_MAINMENU;
            case SUPERVISOR_STATE_RESULTSCREEN_FROMGAME:
                if (ResultScreen::RegisterChain(TRUE) != ZUN_SUCCESS)
                {
                    return CHAIN_CALLBACK_RESULT_EXIT_GAME_SUCCESS;
                }
            }
            break;
        }
        g_CurFrameInput = g_LastFrameInput = g_IsEigthFrameOfHeldInput = 0;
    }

    s->wantedState = s->curState;
    s->calcCount++;
    return CHAIN_CALLBACK_RESULT_CONTINUE;
}
#pragma optimize("", on)

#pragma optimize("s", on)
#pragma var_order(anmm0, anmm1, anmm2, anmm3, anmm4, anmm5)
ChainCallbackResult Supervisor::OnDraw(Supervisor *s)
{
    AnmManager *anmm0 = g_AnmManager;
    anmm0->currentVertexShader = 0xff;

    AnmManager *anmm1 = g_AnmManager;
    anmm1->currentSprite = NULL;

    AnmManager *anmm2 = g_AnmManager;
    anmm2->currentTexture = NULL;

    AnmManager *anmm3 = g_AnmManager;
    anmm3->currentColorOp = 0xff;

    AnmManager *anmm4 = g_AnmManager;
    anmm4->currentBlendMode = 0xff;

    AnmManager *anmm5 = g_AnmManager;
    anmm5->currentZWriteDisable = 0xff;

    Supervisor::DrawFpsCounter();
    return CHAIN_CALLBACK_RESULT_CONTINUE;
}
#pragma optimize("", on)

#pragma optimize("s", on)
#pragma var_order(i)
ZunResult Supervisor::AddedCallback(Supervisor *s)
{
    i32 i;

    for (i = 0; i < (i32)(sizeof(s->pbg3Archives) / sizeof(s->pbg3Archives[0])); i++)
    {
        s->pbg3Archives[i] = NULL;
    }

    g_Pbg3Archives = s->pbg3Archives;
    if (s->LoadPbg3(IN_PBG3_INDEX, TH_IN_DAT_FILE))
    {
        return ZUN_ERROR;
    }
    g_AnmManager->LoadSurface(0, "data/title/th06logo.jpg");
    g_AnmManager->CopySurfaceToBackBuffer(0, 0, 0, 0, 0);
    if (g_Supervisor.d3dDevice->Present(0, 0, 0, 0) < 0)
        g_Supervisor.d3dDevice->Reset(&g_Supervisor.presentParameters);

    g_AnmManager->CopySurfaceToBackBuffer(0, 0, 0, 0, 0);
    if (g_Supervisor.d3dDevice->Present(0, 0, 0, 0) < 0)
        g_Supervisor.d3dDevice->Reset(&g_Supervisor.presentParameters);

    g_AnmManager->ReleaseSurface(0);

    s->startupTimeBeforeMenuMusic = timeGetTime();
    Supervisor::SetupDInput(s);

    s->midiOutput = new MidiOutput();

    g_Rng.Initialize(timeGetTime());

    g_SoundPlayer.InitSoundBuffers();
    if (g_AnmManager->LoadAnm(ANM_FILE_TEXT, "data/text.anm", ANM_OFFSET_TEXT) != 0)
    {
        return ZUN_ERROR;
    }

    if (AsciiManager::RegisterChain() != 0)
    {
        GameErrorContext::Log(&g_GameErrorContext, TH_ERR_ASCIIMANAGER_INIT_FAILED);
        return ZUN_ERROR;
    }

    s->unk198 = 0;
    g_AnmManager->SetupVertexBuffer();
    TextHelper::CreateTextBuffer();
    s->ReleasePbg3(IN_PBG3_INDEX);
    if (g_Supervisor.LoadPbg3(MD_PBG3_INDEX, TH_MD_DAT_FILE) != 0)
        return ZUN_ERROR;

    return ZUN_SUCCESS;
}
#pragma optimize("", on)

#pragma optimize("s", on)
ZunResult Supervisor::DeletedCallback(Supervisor *s)
{
    i32 pbg3Idx;

    g_AnmManager->ReleaseVertexBuffer();
    for (pbg3Idx = 0; pbg3Idx < ARRAY_SIZE_SIGNED(s->pbg3Archives); pbg3Idx += 1)
    {
        s->ReleasePbg3(pbg3Idx);
    }
    g_AnmManager->ReleaseAnm(0);
    AsciiManager::CutChain();
    g_SoundPlayer.StopBGM();
    if (s->midiOutput != NULL)
    {
        s->midiOutput->StopPlayback();
        delete s->midiOutput;
        s->midiOutput = NULL;
    }
    ReplayManager::SaveReplay(NULL, NULL);
    TextHelper::ReleaseTextBuffer();
    if (s->keyboard != NULL)
    {
        s->keyboard->Unacquire();
    }
    if (s->keyboard != NULL)
    {
        s->keyboard->Release();
        s->keyboard = NULL;
    }
    if (s->controller != NULL)
    {
        s->controller->Unacquire();
    }
    if (s->controller != NULL)
    {
        s->controller->Release();
        s->controller = NULL;
    }
    if (s->dinputIface != NULL)
    {
        s->dinputIface->Release();
        s->dinputIface = NULL;
    }
    return ZUN_SUCCESS;
}
#pragma optimize("", on)

#pragma optimize("s", on)
#pragma var_order(curTime, framerate, fps, elapsed, fpsCounterPos)
void Supervisor::DrawFpsCounter()
{
    DWORD curTime;
    float framerate;
    float elapsed;
    float fps;
    D3DXVECTOR3 fpsCounterPos;

    static u32 g_NumFramesSinceLastTime = 0;
    static DWORD g_LastTime = timeGetTime();
    static char g_FpsCounterBuffer[256];

    curTime = timeGetTime();
    g_NumFramesSinceLastTime = g_NumFramesSinceLastTime + 1 + (u32)g_Supervisor.cfg.frameskipConfig;
    if (500 <= curTime - g_LastTime)
    {
        elapsed = (curTime - g_LastTime) / 1000.f;
        fps = g_NumFramesSinceLastTime / elapsed;
        g_LastTime = curTime;
        g_NumFramesSinceLastTime = 0;
        sprintf(g_FpsCounterBuffer, "%.02ffps", fps);
        if (g_GameManager.isInMenu != 0)
        {
            framerate = 60.f / g_Supervisor.framerateMultiplier;
            g_Supervisor.unk1b8 = g_Supervisor.unk1b8 + framerate;

            if (framerate * .89999998f < fps)
                g_Supervisor.unk1b4 = g_Supervisor.unk1b4 + framerate;
            else if (framerate * 0.69999999f < fps)
                g_Supervisor.unk1b4 = framerate * .8f + g_Supervisor.unk1b4;
            else if (framerate * 0.5f < fps)
                g_Supervisor.unk1b4 = framerate * .6f + g_Supervisor.unk1b4;
            else
                g_Supervisor.unk1b4 = framerate * .5f + g_Supervisor.unk1b4;
        }
    }
    if (!g_Supervisor.isInEnding)
    {
        fpsCounterPos.x = 512.0;
        fpsCounterPos.y = 464.0;
        fpsCounterPos.z = 0.0;
        g_AsciiManager.AddString(&fpsCounterPos, g_FpsCounterBuffer);
    }
    return;
}
#pragma optimize("", on)

#pragma optimize("s", on)
void Supervisor::ReleasePbg3(i32 pbg3FileIdx)
{
    if (this->pbg3Archives[pbg3FileIdx] == NULL)
    {
        return;
    }

    // Double free! Release is called internally by the Pbg3Archive destructor,
    // and as such should not be called directly. By calling it directly here,
    // it ends up being called twice, which will cause the resources owned by
    // Pbg3Archive to be freed multiple times, which can result in crashes.
    //
    // For some reason, this double-free doesn't cause crashes in the original
    // game. However, this can cause problems in dllbuilds of the game. Maybe
    // some accuracy improvements in the PBG3 handling will remove this
    // difference.
    this->pbg3Archives[pbg3FileIdx]->Release();
    delete this->pbg3Archives[pbg3FileIdx];
    this->pbg3Archives[pbg3FileIdx] = NULL;
}
#pragma optimize("", on)

#pragma optimize("s", on)
i32 Supervisor::LoadPbg3(i32 pbg3FileIdx, char *filename)
{
    if (this->pbg3Archives[pbg3FileIdx] == NULL || strcmp(filename, this->pbg3ArchiveNames[pbg3FileIdx]) != 0)
    {
        this->ReleasePbg3(pbg3FileIdx);
        this->pbg3Archives[pbg3FileIdx] = new Pbg3Archive();
        utils::DebugPrint("%s open ...\n", filename);
        if (this->pbg3Archives[pbg3FileIdx]->Load(filename) != 0)
        {
            strcpy(this->pbg3ArchiveNames[pbg3FileIdx], filename);

            char verPath[128];
            sprintf(verPath, "ver%.4x.dat", GAME_VERSION);
            i32 res = this->pbg3Archives[pbg3FileIdx]->FindEntry(verPath);
            if (res < 0)
            {
                GameErrorContext::Fatal(&g_GameErrorContext, "error : データのバージョンが違います\n");
                return 1;
            }
        }
        else
        {
            delete this->pbg3Archives[pbg3FileIdx];
            // Let's really make sure this is null by nulling twice. I assume
            // there's some kind of inline function here, like it's actually
            // calling this->pbg3Archives.delete(pbg3FileIdx), followed by a
            // manual nulling?
            this->pbg3Archives[pbg3FileIdx] = NULL;
            this->pbg3Archives[pbg3FileIdx] = NULL;
        }
    }
    return 0;
}
#pragma optimize("", on)

#pragma optimize("s", on)
ZunResult Supervisor::SetupDInput(Supervisor *supervisor)
{
    HINSTANCE hInst;

    hInst = (HINSTANCE)GetWindowLongA(supervisor->hwndGameWindow, GWL_HINSTANCE);
    if (supervisor->cfg.opts >> GCOS_NO_DIRECTINPUT_PAD & 1)
    {
        return ZUN_ERROR;
    }

    if (DirectInput8Create(hInst, DIRECTINPUT_VERSION, IID_IDirectInput8A, (LPVOID *)&supervisor->dinputIface, NULL) <
        0)
    {
        supervisor->dinputIface = NULL;
        GameErrorContext::Log(&g_GameErrorContext, TH_ERR_DIRECTINPUT_NOT_AVAILABLE);
        return ZUN_ERROR;
    }

    if (supervisor->dinputIface->CreateDevice(GUID_SysKeyboard, &supervisor->keyboard, NULL) < 0)
    {
        if (supervisor->dinputIface)
        {
            supervisor->dinputIface->Release();
            supervisor->dinputIface = NULL;
        }
        GameErrorContext::Log(&g_GameErrorContext, TH_ERR_DIRECTINPUT_NOT_AVAILABLE);
        return ZUN_ERROR;
    }

    if (supervisor->keyboard->SetDataFormat(&c_dfDIKeyboard) < 0)
    {
        if (supervisor->keyboard)
        {
            supervisor->keyboard->Release();
            supervisor->keyboard = NULL;
        }

        if (supervisor->dinputIface)
        {
            supervisor->dinputIface->Release();
            supervisor->dinputIface = NULL;
        }

        GameErrorContext::Log(&g_GameErrorContext, TH_ERR_DIRECTINPUT_SETDATAFORMAT_NOT_AVAILABLE);
        return ZUN_ERROR;
    }

    if (supervisor->keyboard->SetCooperativeLevel(supervisor->hwndGameWindow,
                                                  DISCL_NONEXCLUSIVE | DISCL_FOREGROUND | DISCL_NOWINKEY) < 0)
    {
        if (supervisor->keyboard)
        {
            supervisor->keyboard->Release();
            supervisor->keyboard = NULL;
        }

        if (supervisor->dinputIface)
        {
            supervisor->dinputIface->Release();
            supervisor->dinputIface = NULL;
        }

        GameErrorContext::Log(&g_GameErrorContext, TH_ERR_DIRECTINPUT_SETCOOPERATIVELEVEL_NOT_AVAILABLE);
        return ZUN_ERROR;
    }

    supervisor->keyboard->Acquire();
    GameErrorContext::Log(&g_GameErrorContext, TH_ERR_DIRECTINPUT_INITIALIZED);

    supervisor->dinputIface->EnumDevices(DI8DEVCLASS_GAMECTRL, Controller::EnumGameControllersCb, NULL,
                                         DIEDFL_ATTACHEDONLY);
    if (supervisor->controller)
    {
        supervisor->controller->SetDataFormat(&c_dfDIJoystick2);
        supervisor->controller->SetCooperativeLevel(supervisor->hwndGameWindow, DISCL_EXCLUSIVE | DISCL_FOREGROUND);

        g_Supervisor.controllerCaps.dwSize = sizeof(g_Supervisor.controllerCaps);

        supervisor->controller->GetCapabilities(&g_Supervisor.controllerCaps);
        supervisor->controller->EnumObjects(Controller::ControllerCallback, NULL, DIDFT_ALL);

        GameErrorContext::Log(&g_GameErrorContext, TH_ERR_PAD_FOUND);
    }
    return ZUN_SUCCESS;
}
#pragma optimize("", on)

#pragma optimize("s", on)
void Supervisor::TickTimer(i32 *frames, f32 *subframes)
{
    if (this->framerateMultiplier <= 0.99f)
    {
        *subframes = *subframes + this->effectiveFramerateMultiplier;
        if (*subframes >= 1.0f)
        {
            *frames = *frames + 1;
            *subframes = *subframes - 1.0f;
        }
    }
    else
    {
        *frames = *frames + 1;
    }
}
#pragma optimize("", on)

u16 Controller::GetJoystickCaps(void)
{
    JOYINFOEX pji;

    pji.dwSize = sizeof(JOYINFOEX);
    pji.dwFlags = JOY_RETURNALL;

    if (joyGetPosEx(0, &pji) != MMSYSERR_NOERROR)
    {
        GameErrorContext::Log(&g_GameErrorContext, TH_ERR_NO_PAD_FOUND);
        return 1;
    }

    joyGetDevCapsA(0, &g_JoystickCaps, sizeof(g_JoystickCaps));
    return 0;
}

u32 Controller::SetButtonFromControllerInputs(u16 *outButtons, i16 controllerButtonToTest,
                                              enum TouhouButton touhouButton, u32 inputButtons)
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

u32 Controller::SetButtonFromDirectInputJoystate(u16 *outButtons, i16 controllerButtonToTest,
                                                 enum TouhouButton touhouButton, u8 *inputButtons)
{
    if (controllerButtonToTest < 0)
    {
        return 0;
    }

    *outButtons |= (inputButtons[controllerButtonToTest] & 0x80 ? touhouButton & 0xFFFF : 0);

    return inputButtons[controllerButtonToTest] & 0x80 ? touhouButton & 0xFFFF : 0;
}

u16 Controller::GetControllerInput(u16 buttons)
{
    // NOTE: Those names are like this to get perfect stack frame matching
    // TODO: Give meaningfull names that still match.
    JOYINFOEX aa;
    u32 ab;
    u32 ac;
    DIJOYSTATE2 a0;
    u32 a2;
    HRESULT aaa;

    if (g_Supervisor.controller == NULL)
    {
        memset(&aa, 0, sizeof(aa));
        aa.dwSize = sizeof(JOYINFOEX);
        aa.dwFlags = JOY_RETURNALL;

        if (joyGetPosEx(0, &aa) != MMSYSERR_NOERROR)
        {
            return buttons;
        }

        ac = SetButtonFromControllerInputs(&buttons, g_Supervisor.cfg.controllerMapping.shootButton, TH_BUTTON_SHOOT,
                                           aa.dwButtons);

        if (g_ControllerMapping.shootButton != g_ControllerMapping.focusButton)
        {
            SetButtonFromControllerInputs(&buttons, g_Supervisor.cfg.controllerMapping.focusButton, TH_BUTTON_FOCUS,
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

        SetButtonFromControllerInputs(&buttons, g_Supervisor.cfg.controllerMapping.bombButton, TH_BUTTON_BOMB,
                                      aa.dwButtons);
        SetButtonFromControllerInputs(&buttons, g_Supervisor.cfg.controllerMapping.menuButton, TH_BUTTON_MENU,
                                      aa.dwButtons);
        SetButtonFromControllerInputs(&buttons, g_Supervisor.cfg.controllerMapping.upButton, TH_BUTTON_UP,
                                      aa.dwButtons);
        SetButtonFromControllerInputs(&buttons, g_Supervisor.cfg.controllerMapping.downButton, TH_BUTTON_DOWN,
                                      aa.dwButtons);
        SetButtonFromControllerInputs(&buttons, g_Supervisor.cfg.controllerMapping.leftButton, TH_BUTTON_LEFT,
                                      aa.dwButtons);
        SetButtonFromControllerInputs(&buttons, g_Supervisor.cfg.controllerMapping.rightButton, TH_BUTTON_RIGHT,
                                      aa.dwButtons);
        SetButtonFromControllerInputs(&buttons, g_Supervisor.cfg.controllerMapping.skipButton, TH_BUTTON_SKIP,
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
        aaa = g_Supervisor.controller->Poll();
        if (FAILED(aaa))
        {
            i32 retryCount = 0;

            utils::DebugPrint2("error : DIERR_INPUTLOST\n");
            aaa = g_Supervisor.controller->Acquire();

            while (aaa == DIERR_INPUTLOST)
            {
                aaa = g_Supervisor.controller->Acquire();
                utils::DebugPrint2("error : DIERR_INPUTLOST %d\n", retryCount);

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

            aaa = g_Supervisor.controller->GetDeviceState(sizeof(a0), &a0);

            if (FAILED(aaa))
            {
                return buttons;
            }

            a2 = SetButtonFromDirectInputJoystate(&buttons, g_Supervisor.cfg.controllerMapping.shootButton,
                                                  TH_BUTTON_SHOOT, a0.rgbButtons);

            if (g_Supervisor.cfg.controllerMapping.shootButton != g_Supervisor.cfg.controllerMapping.focusButton)
            {
                SetButtonFromDirectInputJoystate(&buttons, g_Supervisor.cfg.controllerMapping.focusButton,
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

            SetButtonFromDirectInputJoystate(&buttons, g_Supervisor.cfg.controllerMapping.bombButton, TH_BUTTON_BOMB,
                                             a0.rgbButtons);
            SetButtonFromDirectInputJoystate(&buttons, g_Supervisor.cfg.controllerMapping.menuButton, TH_BUTTON_MENU,
                                             a0.rgbButtons);
            SetButtonFromDirectInputJoystate(&buttons, g_Supervisor.cfg.controllerMapping.upButton, TH_BUTTON_UP,
                                             a0.rgbButtons);
            SetButtonFromDirectInputJoystate(&buttons, g_Supervisor.cfg.controllerMapping.downButton, TH_BUTTON_DOWN,
                                             a0.rgbButtons);
            SetButtonFromDirectInputJoystate(&buttons, g_Supervisor.cfg.controllerMapping.leftButton, TH_BUTTON_LEFT,
                                             a0.rgbButtons);
            SetButtonFromDirectInputJoystate(&buttons, g_Supervisor.cfg.controllerMapping.rightButton, TH_BUTTON_RIGHT,
                                             a0.rgbButtons);
            SetButtonFromDirectInputJoystate(&buttons, g_Supervisor.cfg.controllerMapping.skipButton, TH_BUTTON_SKIP,
                                             a0.rgbButtons);

            buttons |= JOYSTICK_BUTTON_PRESSED(TH_BUTTON_RIGHT, a0.lX, g_Supervisor.cfg.padXAxis);
            buttons |= JOYSTICK_BUTTON_PRESSED_INVERT(TH_BUTTON_LEFT, a0.lX, -g_Supervisor.cfg.padXAxis);
            buttons |= JOYSTICK_BUTTON_PRESSED(TH_BUTTON_DOWN, a0.lY, g_Supervisor.cfg.padYAxis);
            buttons |= JOYSTICK_BUTTON_PRESSED_INVERT(TH_BUTTON_UP, a0.lY, -g_Supervisor.cfg.padYAxis);
        }
    }

    return buttons;
}

u16 Controller::GetInput(void)
{
    u8 keyboardState[256];
    u16 buttons;

    buttons = 0;

    if (g_Supervisor.keyboard == NULL)
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
        buttons |= KEYBOARD_KEY_PRESSED(TH_BUTTON_HOME, VK_HOME);
        buttons |= KEYBOARD_KEY_PRESSED(TH_BUTTON_SHOOT, 'Z');
        buttons |= KEYBOARD_KEY_PRESSED(TH_BUTTON_BOMB, 'X');
        buttons |= KEYBOARD_KEY_PRESSED(TH_BUTTON_FOCUS, VK_SHIFT);
        buttons |= KEYBOARD_KEY_PRESSED(TH_BUTTON_MENU, VK_ESCAPE);
        buttons |= KEYBOARD_KEY_PRESSED(TH_BUTTON_SKIP, VK_CONTROL);
        buttons |= KEYBOARD_KEY_PRESSED(TH_BUTTON_Q, 'Q');
        buttons |= KEYBOARD_KEY_PRESSED(TH_BUTTON_S, 'S');
        buttons |= KEYBOARD_KEY_PRESSED(TH_BUTTON_ENTER, VK_RETURN);
    }
    else
    {
        HRESULT res = g_Supervisor.keyboard->GetDeviceState(sizeof(keyboardState), keyboardState);

        buttons = 0;

        if (res == DIERR_INPUTLOST)
        {
            g_Supervisor.keyboard->Acquire();

            return Controller::GetControllerInput(buttons);
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
        buttons |= KEYBOARD_KEY_PRESSED(TH_BUTTON_HOME, DIK_HOME);
        buttons |= KEYBOARD_KEY_PRESSED(TH_BUTTON_SHOOT, DIK_Z);
        buttons |= KEYBOARD_KEY_PRESSED(TH_BUTTON_BOMB, DIK_X);
        buttons |= KEYBOARD_KEY_PRESSED(TH_BUTTON_FOCUS, DIK_LSHIFT);
        buttons |= KEYBOARD_KEY_PRESSED(TH_BUTTON_FOCUS, DIK_RSHIFT);
        buttons |= KEYBOARD_KEY_PRESSED(TH_BUTTON_MENU, DIK_ESCAPE);
        buttons |= KEYBOARD_KEY_PRESSED(TH_BUTTON_SKIP, DIK_LCONTROL);
        buttons |= KEYBOARD_KEY_PRESSED(TH_BUTTON_SKIP, DIK_RCONTROL);
        buttons |= KEYBOARD_KEY_PRESSED(TH_BUTTON_Q, DIK_Q);
        buttons |= KEYBOARD_KEY_PRESSED(TH_BUTTON_S, DIK_S);
        buttons |= KEYBOARD_KEY_PRESSED(TH_BUTTON_ENTER, DIK_RETURN);
    }

    return Controller::GetControllerInput(buttons);
}

#pragma optimize("s", on)
#pragma var_order(diprange, pvRefBackup)
BOOL CALLBACK Controller::ControllerCallback(LPCDIDEVICEOBJECTINSTANCEA lpddoi, LPVOID pvRef)
{
    LPVOID pvRefBackup;
    DIPROPRANGE diprange;
    pvRefBackup = pvRef;

    if (lpddoi->dwType & DIDFT_AXIS)
    {
        diprange.diph.dwSize = sizeof(diprange);
        diprange.diph.dwHeaderSize = sizeof(diprange.diph);
        diprange.diph.dwHow = DIPH_BYID;
        diprange.diph.dwObj = lpddoi->dwType;
        diprange.lMin = -1000;
        diprange.lMax = 1000;

        if (g_Supervisor.controller->SetProperty(DIPROP_RANGE, &diprange.diph) < 0)
        {
            return FALSE;
        }
    }
    return TRUE;
}
#pragma optimize("", on)

#pragma optimize("s", on)
BOOL CALLBACK Controller::EnumGameControllersCb(LPCDIDEVICEINSTANCEA pdidInstance, LPVOID pContext)
{
    HRESULT result;

    if (!g_Supervisor.controller)
    {
        result = g_Supervisor.dinputIface->CreateDevice(pdidInstance->guidInstance, &g_Supervisor.controller, NULL);
        if (result < 0)
        {
            return TRUE;
        }
    }
    return FALSE;
}
#pragma optimize("", on)

void Controller::ResetKeyboard(void)
{
    u8 key_states[256];

    GetKeyboardState(key_states);
    for (i32 idx = 0; idx < 256; idx++)
    {
        *(key_states + idx) &= 0x7f;
    }
    SetKeyboardState(key_states);
}

#pragma optimize("s", on)
ZunBool Supervisor::ReadMidiFile(u32 midiFileIdx, char *path)
{
    // Return conventions seem opposite of normal? But they're never used anyway
    if (g_Supervisor.cfg.musicMode == MIDI)
    {
        if (g_Supervisor.midiOutput != NULL)
        {
            g_Supervisor.midiOutput->ReadFileData(midiFileIdx, path);
        }

        return FALSE;
    }

    return TRUE;
}
#pragma optimize("", on)

#pragma optimize("s", on)
i32 Supervisor::PlayMidiFile(i32 midiFileIdx)
{
    MidiOutput *globalMidiController;

    if (g_Supervisor.cfg.musicMode == MIDI)
    {
        if (g_Supervisor.midiOutput != NULL)
        {
            globalMidiController = g_Supervisor.midiOutput;
            globalMidiController->StopPlayback();
            globalMidiController->ParseFile(midiFileIdx);
            globalMidiController->Play();
        }

        return FALSE;
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

DIFFABLE_STATIC_ARRAY(u8, (32 * 4), g_ControllerData)

#pragma optimize("", on)
#pragma var_order(joyinfoex, joyButtonBit, joyButtonIndex, dires, dijoystate2, diRetryCount)
// This is for rebinding keys
u8 *th06::Controller::GetControllerState()
{
    JOYINFOEX joyinfoex;
    u32 joyButtonBit;
    u32 joyButtonIndex;

    i32 dires;
    DIJOYSTATE2 dijoystate2;
    i32 diRetryCount;

    memset(&g_ControllerData, 0, sizeof(g_ControllerData));
    if (g_Supervisor.controller == NULL)
    {
        memset(&joyinfoex, 0, sizeof(JOYINFOEX));
        joyinfoex.dwSize = sizeof(JOYINFOEX);
        joyinfoex.dwFlags = JOY_RETURNALL;
        if (joyGetPosEx(0, &joyinfoex) != JOYERR_NOERROR)
        {
            return g_ControllerData;
        }
        for (joyButtonBit = joyinfoex.dwButtons, joyButtonIndex = 0; joyButtonIndex < 32;
             joyButtonIndex += 1, joyButtonBit >>= 1)
        {
            if ((joyButtonBit & 1) != 0)
            {
                g_ControllerData[joyButtonIndex] = 0x80;
            }
        }
        return g_ControllerData;
    }
    else
    {
        dires = g_Supervisor.controller->Poll();
        if (FAILED(dires))
        {
            diRetryCount = 0;
            utils::DebugPrint2("error : DIERR_INPUTLOST\n");
            dires = g_Supervisor.controller->Acquire();
            while (dires == DIERR_INPUTLOST)
            {
                dires = g_Supervisor.controller->Acquire();
                utils::DebugPrint2("error : DIERR_INPUTLOST %d\n", diRetryCount);
                diRetryCount++;
                if (diRetryCount >= 400)
                {
                    return g_ControllerData;
                }
            }
            return g_ControllerData;
        }
        /* dires = */ g_Supervisor.controller->GetDeviceState(sizeof(DIJOYSTATE2), &dijoystate2);
        // TODO: seems ZUN forgot "dires =" above
        if (FAILED(dires))
        {
            return g_ControllerData;
        }
        memcpy(&g_ControllerData, dijoystate2.rgbButtons, sizeof(dijoystate2.rgbButtons));
        return g_ControllerData;
    }
}
#pragma optimize("", on)
}; // namespace th06
