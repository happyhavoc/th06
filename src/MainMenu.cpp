#include <D3DX8.h>
#include <cstdio>
#include <direct.h>
#include <windows.h>

#include "MainMenu.hpp"

#include "AnmManager.hpp"
#include "Filesystem.hpp"
#include "GameErrorContext.hpp"
#include "ChainPriorities.hpp"
#include "GameManager.hpp"
#include "ReplayData.hpp"
#include "SoundPlayer.hpp"
#include "Supervisor.hpp"
#include "i18n.hpp"
#include "utils.hpp"

#define WAS_PRESSED(key) (((g_CurFrameInput & (key)) != 0) && (g_CurFrameInput & (key)) != (g_LastFrameInput & (key)))

/* COLORS */
/* we can move them to their own header if referenced somewhere else :) */
#define COLOR_BLACK 0xff000000
#define COLOR_WHITE 0xffffffff
#define COLOR_RED 0xffff0000
// TODO: find a better name for this color
#define COLOR_START_MENU_ITEM_INACTIVE 0x80300000

#pragma optimize("s", on)
#pragma var_order(time, i, vector3Ptr)
ZunResult MainMenu::BeginStartup()
{
    D3DXVECTOR3 vector3Ptr; // we have to add Ptr,
                            // because otherwise it gets 0.7% less on decomp.me for some reason
    DWORD time;
    int i;

    if (LoadTitleAnm(this) != ZUN_SUCCESS)
    {
        g_Supervisor.curState = SUPERVISOR_STATE_EXITSUCCESS;
        return ZUN_ERROR;
    }
    if (g_Supervisor.startupTimeBeforeMenuMusic > 0)
    {
        time = timeGetTime();
        while ((time - g_Supervisor.startupTimeBeforeMenuMusic >= 0) &&
               (3000 > time - g_Supervisor.startupTimeBeforeMenuMusic))
        {
            time = timeGetTime();
        }
        g_Supervisor.startupTimeBeforeMenuMusic = 0;
        g_Supervisor.PlayAudio("bgm/th06_01.mid");
    }
    for (i = 0; i < ARRAY_SIZE(this->vm); i++)
    {
        this->vm[i].pendingInterrupt = 1;
        this->vm[i].flags |= AnmVmFlags_3;
        if ((g_Supervisor.cfg.opts & (1 << GCOS_USE_D3D_HW_TEXTURE_BLENDING)) == 0)
        {
            this->vm[i].color = COLOR_BLACK;
        }
        else
        {
            this->vm[i].color = COLOR_WHITE;
        }
        vector3Ptr.x = 0.0;
        vector3Ptr.y = 0.0;
        vector3Ptr.z = 0.0;
        this->vm[i].pos2 = vector3Ptr;
    }
    this->gameState = STATE_PRE_INPUT;
    return ZUN_SUCCESS;
}
#pragma optimize("", on)

#pragma optimize("s", on)
#pragma var_order(i, loadedTitle01, loadedTitle02, loadedTitle03, loadedTitle04, loadedTitle01s, loadedTitle04s)
ZunResult MainMenu::LoadTitleAnm(MainMenu *menu)
{
    i32 i;
    // a bunch of ZunResults so the stack size is right
    ZunResult loadedTitle01;
    ZunResult loadedTitle02;
    ZunResult loadedTitle03;
    ZunResult loadedTitle04;
    ZunResult loadedTitle01s;
    ZunResult loadedTitle04s;

    g_Supervisor.LoadPbg3(3, TH_TL_DAT_FILE);
    for (i = 0x1b; i <= 0x24; i++)
    {
        g_AnmManager->ReleaseAnm(i);
    }
    if (g_AnmManager->LoadAnm(0x15, "data/title01.anm", 0x100))
    {
        return ZUN_ERROR;
    }
    if (g_AnmManager->LoadAnm(0x18, "data/title02.anm", 0x11b))
    {
        return ZUN_ERROR;
    }
    if (g_AnmManager->LoadAnm(0x19, "data/title03.anm", 0x11f))
    {
        return ZUN_ERROR;
    }
    if (g_AnmManager->LoadAnm(0x1a, "data/title04.anm", 0x122))
    {
        return ZUN_ERROR;
    }
    if (g_AnmManager->LoadAnm(0x16, "data/title01s.anm", 0x17a))
    {
        return ZUN_ERROR;
    }
    if (g_AnmManager->LoadAnm(0x17, "data/title04s.anm", 0x195))
    {
        return ZUN_ERROR;
    }

    for (i = 0; i < 80; i++)
    {
        g_AnmManager->ExecuteAnmIdx(&menu->vm[i], 0x100 + i);
        menu->vm[i].flags &= 0xfffffffe;
        menu->vm[i].anotherSpriteNumber = menu->vm[i].spriteNumber;
        menu->vm[i].flags |= AnmVmFlags_12;
    }

    if (g_AnmManager->LoadSurface(0, "data/title/title00.jpg"))
    {
        return ZUN_ERROR;
    }

    return ZUN_SUCCESS;
}
#pragma optimize("", on)

#pragma optimize("s", on)
#pragma var_order(i, drawVm)
ZunResult MainMenu::DrawStartMenu(void)
{
    i32 i;
    i = MoveCursor(this, 8);
    if ((this->cursor == 1) && !g_GameManager.hasReachedMaxClears(0, 0) && !g_GameManager.hasReachedMaxClears(0, 1) &&
        !g_GameManager.hasReachedMaxClears(1, 0) && !g_GameManager.hasReachedMaxClears(1, 1))
    {
        this->cursor += i;
    }
    AnmVm *drawVm = this->vm;
    for (i = 0; i < 8; i++, drawVm++ /* zun why */)
    {
        DrawMenuItem(drawVm, i, this->cursor, COLOR_RED, COLOR_START_MENU_ITEM_INACTIVE, 122);
    }
    if (this->stateTimer >= 0x14)
    {
        if (WAS_PRESSED(TH_BUTTON_SELECTMENU))
        {
            switch (this->cursor)
            {
            case 0:
                for (i = 0; i < ARRAY_SIZE_SIGNED(this->vm); i++)
                {
                    this->vm[i].pendingInterrupt = 4;
                }
                this->gameState = STATE_DIFFICULTY_LOAD;
                g_GameManager.unk_1823 = 0;
                if (EXTRA <= g_GameManager.difficulty)
                {
                    g_GameManager.difficulty = NORMAL;
                }
                if (EXTRA <= g_Supervisor.cfg.defaultDifficulty)
                {
                    g_Supervisor.cfg.defaultDifficulty = NORMAL;
                }
                this->stateTimer = 0;
                this->unk_81fc = 0x40000000;
                this->maybeMenuTextColor = COLOR_BLACK;
                this->unk_820c = 0;
                this->isActive = 60;
                g_SoundPlayer.PlaySoundByIdx(10, 0);
                break;
            case 1:
                if (!(!g_GameManager.hasReachedMaxClears(0, 0) && !g_GameManager.hasReachedMaxClears(0, 1) &&
                      !g_GameManager.hasReachedMaxClears(1, 0) && !g_GameManager.hasReachedMaxClears(1, 1)))
                {
                    for (i = 0; i < ARRAY_SIZE_SIGNED(this->vm); i++)
                    {
                        this->vm[i].pendingInterrupt = 4;
                    }
                    this->gameState = STATE_DIFFICULTY_LOAD;
                    g_GameManager.unk_1823 = 0;
                    g_GameManager.difficulty = EXTRA;
                    this->stateTimer = 0;
                    this->unk_81fc = 0x40000000;
                    this->maybeMenuTextColor = COLOR_BLACK;
                    this->unk_820c = 0;
                    this->isActive = 60;
                    g_SoundPlayer.PlaySoundByIdx(10, 0);
                }
                else
                {
                    g_SoundPlayer.PlaySoundByIdx(0xb, 0);
                }
                break;
            case 2:
                g_GameManager.unk_1823 = 1;
                for (i = 0; i < ARRAY_SIZE_SIGNED(this->vm); i++)
                {
                    this->vm[i].pendingInterrupt = 4;
                }
                this->gameState = STATE_DIFFICULTY_LOAD;
                if (EXTRA <= g_GameManager.difficulty)
                {
                    g_GameManager.difficulty = NORMAL;
                }
                if (EXTRA <= g_Supervisor.cfg.defaultDifficulty)
                {
                    g_Supervisor.cfg.defaultDifficulty = NORMAL;
                }
                this->stateTimer = 0;
                this->unk_81fc = 0x40000000;
                this->maybeMenuTextColor = COLOR_BLACK;
                this->unk_820c = 0;
                this->isActive = 60;
                g_SoundPlayer.PlaySoundByIdx(10, 0);
                break;
            case 3:
                for (i = 0; i < ARRAY_SIZE_SIGNED(this->vm); i++)
                {
                    this->vm[i].pendingInterrupt = 4;
                }
                this->gameState = STATE_REPLAY_LOAD;
                g_GameManager.unk_1823 = 0;
                this->stateTimer = 0;
                this->unk_81fc = 0x40000000;
                this->maybeMenuTextColor = COLOR_BLACK;
                this->unk_820c = 0;
                this->isActive = 60;
                g_SoundPlayer.PlaySoundByIdx(10, 0);
                break;
            case 4:
                for (i = 0; i < ARRAY_SIZE_SIGNED(this->vm); i++)
                {
                    this->vm[i].pendingInterrupt = 4;
                }
                this->gameState = STATE_SCORE;
                this->stateTimer = 0;
                this->unk_81fc = 0x40000000;
                this->maybeMenuTextColor = COLOR_BLACK;
                this->unk_820c = 0;
                this->isActive = 60;
                g_SoundPlayer.PlaySoundByIdx(10, 0);
                break;
            case 5:
                this->gameState = STATE_MUSIC_ROOM;
                this->stateTimer = 0;
                for (i = 0; i < ARRAY_SIZE_SIGNED(this->vm); i++)
                {
                    this->vm[i].pendingInterrupt = 4;
                }
                g_SoundPlayer.PlaySoundByIdx(10, 0);
                break;
            case 6:
                this->gameState = STATE_OPTIONS;
                this->stateTimer = 0;
                for (i = 0; i < ARRAY_SIZE_SIGNED(this->vm); i++)
                {
                    this->vm[i].pendingInterrupt = 3;
                }
                this->cursor = 0;
                this->colorMode16bit = g_Supervisor.cfg.colorMode16bit;
                this->windowed = g_Supervisor.cfg.windowed;
                this->frameskipConfig = g_Supervisor.cfg.frameskipConfig;
                g_SoundPlayer.PlaySoundByIdx(10, 0);
                break;
            case 7:
                this->gameState = STATE_QUIT;
                this->stateTimer = 0;
                for (i = 0; i < ARRAY_SIZE_SIGNED(this->vm); i++)
                {
                    this->vm[i].pendingInterrupt = 4;
                }
                g_SoundPlayer.PlaySoundByIdx(0xb, 0);
                break;
            }
        }
        if (WAS_PRESSED(TH_BUTTON_Q))
        {
            this->gameState = STATE_QUIT;
            this->stateTimer = 0;
            for (i = 0; i < ARRAY_SIZE_SIGNED(this->vm); i++)
            {
                this->vm[i].pendingInterrupt = 4;
            }
            g_SoundPlayer.PlaySoundByIdx(0xb, 0);
        }
        if (WAS_PRESSED(TH_BUTTON_RETURNMENU))
        {
            this->cursor = 7;
            g_SoundPlayer.PlaySoundByIdx(0xb, 0);
        }
    }
    return ZUN_SUCCESS;
}
#pragma optimize("", on)

#pragma optimize("s", on)
void MainMenu::DrawMenuItem(AnmVm *vm, int itemNumber, int cursor, D3DCOLOR currentItemColor, D3DCOLOR otherItemColor,
                            int vm_amount)
{
    D3DXVECTOR3 otherItemPos;
    D3DXVECTOR3 currentItemPos;

    if (itemNumber == cursor)
    {
        if (((g_Supervisor.cfg.opts >> GCOS_USE_D3D_HW_TEXTURE_BLENDING & 1) |
             (g_Supervisor.cfg.opts >> GCOS_NO_COLOR_COMP & 1)) == 0)
        {
            vm->color = currentItemColor;
        }
        else
        {
            g_AnmManager->SetActiveSprite(vm, vm->anotherSpriteNumber + vm_amount);
            vm->color = currentItemColor & D3DCOLOR_RGBA(0x00, 0x00, 0x00, 0xff) |
                        D3DCOLOR_RGBA(0xff, 0xff, 0xff, 0x00); // just... why?
        }

        currentItemPos.x = -4.0f;
        currentItemPos.y = -4.0f;
        currentItemPos.z = 0.0f;
        vm->pos2 = currentItemPos;
    }
    else
    {
        if ((g_Supervisor.cfg.opts >> GCOS_USE_D3D_HW_TEXTURE_BLENDING & 1 |
             g_Supervisor.cfg.opts >> GCOS_NO_COLOR_COMP & 1) == 0)
        {
            vm->color = otherItemColor;
        }

        else
        {
            g_AnmManager->SetActiveSprite(vm, vm->anotherSpriteNumber);
            vm->color = otherItemColor & D3DCOLOR_RGBA(0x00, 0x00, 0x00, 0xff) |
                        D3DCOLOR_RGBA(0xff, 0xff, 0xff, 0x00); // again, why?
        }
        otherItemPos.x = 0.0f;
        otherItemPos.y = 0.0f;
        otherItemPos.z = 0.0f;
        vm->pos2 = otherItemPos;
    }
}
#pragma optimize("", on)

#pragma optimize("s", on)
#pragma function("memset")
ZunResult MainMenu::RegisterChain(u32 isDemo)
{
    MainMenu *menu = &g_MainMenu;

    memset(menu, 0, sizeof(MainMenu));
    g_GameManager.isInGameMenu = 0;
    DebugPrint(TH_DBG_MAINMENU_VRAM, g_Supervisor.d3dDevice->GetAvailableTextureMem());
    menu->gameState = isDemo ? STATE_REPLAY_LOAD : STATE_STARTUP;
    g_Supervisor.framerateMultiplier = 0.0;
    menu->chainCalc = g_Chain.CreateElem((ChainCallback)MainMenu::OnUpdate);
    menu->chainCalc->arg = menu;
    menu->chainCalc->addedCallback = (ChainAddedCallback)MainMenu::AddedCallback;
    menu->chainCalc->deletedCallback = (ChainDeletedCallback)MainMenu::DeletedCallback;
    menu->stateTimer = 0;
    if (g_Chain.AddToCalcChain(menu->chainCalc, TH_CHAIN_PRIO_CALC_MAINMENU) != 0)
    {
        return ZUN_ERROR;
    }
    menu->chainDraw = g_Chain.CreateElem((ChainCallback)MainMenu::OnDraw);
    menu->chainDraw->arg = menu;
    g_Chain.AddToDrawChain(menu->chainDraw, TH_CHAIN_PRIO_DRAW_MAINMENU);
    menu->lastFrameTime = 0;
    menu->stateTimer = 0x3c;
    menu->frameCountForRefreshRateCalc = 0;
    return ZUN_SUCCESS;
}
#pragma optimize("", on)

#pragma optimize("s", on)
#pragma function(strcpy)
#pragma var_order(anmVm, cur, replayFileHandle, replayFileIdx, replayData, replayFilePath, replayFileInfo, uh, uh2,    \
                  padding)
i32 MainMenu::ReplayHandling()
{
    AnmVm *anmVm;
    i32 cur;
    HANDLE replayFileHandle;
    u32 replayFileIdx;
    ReplayData *replayData;
    char replayFilePath[32];
    WIN32_FIND_DATA replayFileInfo;
    u8 padding[0x20]; // idk

    switch (this->gameState)
    {
    case STATE_REPLAY_LOAD:
        if (this->stateTimer == 60)
        {
            if (LoadReplayMenu(this))
            {
                GameErrorContextLog(&g_GameErrorContext, "japanese");
                g_Supervisor.curState = SUPERVISOR_STATE_EXITSUCCESS;
                return ZUN_SUCCESS;
            }
            else
            {
                replayFileIdx = 0;
                for (cur = 0; cur < 15; cur++)
                {
                    sprintf(replayFilePath, "./replay/th6_%.2d.rpy", cur + 1);
                    replayData = (ReplayData *)FileSystem::OpenPath(replayFilePath, 1);
                    if (replayData == NULL)
                    {
                        continue;
                    }
                    if (!ValidateReplayData(replayData, g_LastFileSize))
                    {
                        // FIXME: wrong assembly
                        memcpy(&this->replayFileData[replayFileIdx], replayData, 0x50);
                        strcpy(this->replayFilePaths[replayFileIdx], replayFilePath);
                        sprintf(this->replayFileName[replayFileIdx], "No.%.2d", cur + 1);
                        replayFileIdx++;
                    }
                    free(replayData);
                }
                _mkdir("./replay");
                _chdir("./replay");
                replayFileHandle = FindFirstFileA("th6_ud????.rpy", &replayFileInfo);
                if (replayFileHandle != INVALID_HANDLE_VALUE)
                {
                    for (cur = 0; cur < 0x2d; cur++)
                    {
                        replayData = (ReplayData *)FileSystem::OpenPath(replayFilePath, 1);
                        if (replayData == NULL)
                        {
                            continue;
                        }
                        if (!ValidateReplayData(replayData, g_LastFileSize))
                        {
                            // FIXME: wrong assembly
                            memcpy(&this->replayFileData[replayFileIdx], replayData, 0x50);
                            sprintf(this->replayFilePaths[replayFileIdx], "./replay/%s", replayFileInfo.cFileName);
                            sprintf(this->replayFileName[replayFileIdx], "User ");
                            replayFileIdx++;
                        }
                        free(replayData);
                        if (!FindNextFileA(replayFileHandle, &replayFileInfo))
                            break;
                    }
                }
                FindClose(replayFileHandle);
                _chdir("../");
                this->replayFilesNum = replayFileIdx;
                this->unk_81fc = 0;
                this->wasActive = this->isActive;
                this->isActive = 0;
                this->gameState = STATE_REPLAY_ANIM;
                anmVm = this->vm;
                for (cur = 0; cur < ARRAY_SIZE_SIGNED(this->vm); cur++, anmVm++)
                {
                    anmVm->pendingInterrupt = 15;
                }
                this->cursor = 0;
            }
            break;
        }
        break;
    case STATE_REPLAY_UNLOAD:
        if (this->stateTimer == 0x24)
        {
            this->gameState = STATE_STARTUP;
            this->stateTimer = 0;
        }
        break;
    case STATE_REPLAY_ANIM:
        if (this->stateTimer < 0x28)
        {
            break;
        }
        if (this->replayFilesNum != NULL)
        {
            MoveCursor(this, this->replayFilesNum);
            this->chosenReplay = this->cursor;
            if (WAS_PRESSED(TH_BUTTON_SELECTMENU))
            {
                this->gameState = STATE_REPLAY_SELECT;
                anmVm = &(this->vm[97]);
                for (cur = 0; cur < 0x19; cur += 1, anmVm++)
                {
                    anmVm->pendingInterrupt = 0x11;
                }
                anmVm = &this->vm[99 + this->chosenReplay];
                anmVm->pendingInterrupt = 0x10;
                this->stateTimer = 0;
                this->cursor = 0;
                g_SoundPlayer.PlaySoundByIdx(10, 0);
                this->currentReplay = (ReplayData *)FileSystem::OpenPath(this->replayFilePaths[this->chosenReplay], 1);
                ValidateReplayData(this->currentReplay, g_LastFileSize);
                for (cur = 0; cur < ARRAY_SIZE_SIGNED(this->currentReplay->stageScore); cur++)
                {
                    if (this->currentReplay->stageScore[cur] != NULL)
                    {
                        this->currentReplay->stageScore[cur] =
                            (StageReplayData *)((u32)this->currentReplay + (u32)this->currentReplay->stageScore[cur]);
                    }
                }

                do
                {
                    // FIXME: there's an additional jump
                    if (this->replayFileData[this->chosenReplay].stageScore[this->cursor])
                        goto leaveDo;
                    this->cursor = this->cursor + 1;
                } while ((int)this->cursor < ARRAY_SIZE_SIGNED(this->currentReplay->stageScore));
                return ZUN_SUCCESS;
            }
        }
    leaveDo:
        if (WAS_PRESSED(TH_BUTTON_RETURNMENU))
        {
            this->gameState = STATE_REPLAY_UNLOAD;
            this->stateTimer = 0;
            for (cur = 0; cur < ARRAY_SIZE_SIGNED(this->vm); cur++)
            {
                this->vm[cur].pendingInterrupt = 4;
            }
            g_SoundPlayer.PlaySoundByIdx(0xb, 0);
            this->cursor = 0;
            break;
        }
        break;
    case STATE_REPLAY_SELECT:
        if (this->stateTimer < 0x28)
        {
            break;
        }
        cur = MoveCursor(this, 7);
        if (cur < 0)
        {
            while (this->replayFileData[this->chosenReplay].stageScore[this->cursor] == NULL)
            {
                this->cursor--;
                if (this->cursor < 0)
                {
                    this->cursor = 6;
                }
            }
        }
        else if (cur > 0)
        {
            while (this->replayFileData[this->chosenReplay].stageScore[this->cursor] == NULL)
            {
                this->cursor++;
                if (this->cursor >= 7)
                {
                    this->cursor = 0;
                }
            }
        }
        if (WAS_PRESSED(TH_BUTTON_SELECTMENU) && this->currentReplay[this->cursor].stageScore)
        {
            g_GameManager.unk_1c = 1;
            g_Supervisor.framerateMultiplier = 1.0;
            strcpy(g_GameManager.replayFile, this->replayFilePaths[this->chosenReplay]);
            g_GameManager.difficulty = (Difficulty)this->currentReplay->difficulty;
            g_GameManager.character = this->currentReplay->shottypeChara / 2;
            g_GameManager.shotType = this->currentReplay->shottypeChara % 2;
            cur = 0;
            while (this->currentReplay->stageScore[cur] == NULL)
            {
                cur++;
            }
            g_GameManager.livesRemaining = this->currentReplay->stageScore[cur]->livesRemaining;
            g_GameManager.bombsRemaining = this->currentReplay->stageScore[cur]->bombsRemaining;
            ReplayData *uh = this->currentReplay;
            free(uh);
            this->currentReplay = NULL;
            g_GameManager.currentStage = this->cursor;
            g_Supervisor.curState = SUPERVISOR_STATE_GAMEMANAGER;
            return 1;
        }
        if (WAS_PRESSED(TH_BUTTON_RETURNMENU))
        {
            ReplayData *uh2 = this->currentReplay;
            free(uh2);
            this->currentReplay = NULL;
            this->gameState = STATE_REPLAY_ANIM;
            this->stateTimer = 0;
            for (cur = 0; cur < ARRAY_SIZE_SIGNED(this->vm); cur++)
            {
                this->vm[cur].pendingInterrupt = 4;
            }
            g_SoundPlayer.PlaySoundByIdx(0xb, 0);
            this->gameState = STATE_REPLAY_ANIM;
            anmVm = this->vm;
            for (cur = 0; cur < ARRAY_SIZE_SIGNED(this->vm); cur += 1, anmVm++)
            {
                anmVm->pendingInterrupt = 0xf;
            }
            this->cursor = this->chosenReplay;
        }
    }
    return 0;
}

DIFFABLE_STATIC(MainMenu, g_MainMenu);
