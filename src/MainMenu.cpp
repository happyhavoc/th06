#include <D3DX8.h>
#include <windows.h>
#include <cstdio>

#include "MainMenu.hpp"

#include "AnmManager.hpp"
#include "GameManager.hpp"
#include "SoundPlayer.hpp"
#include "Filesystem.hpp"
#include "ReplayData.hpp"
#include "GameErrorContext.hpp"
#include "Supervisor.hpp"
#include "i18n.hpp"

#define WAS_PRESSED(key) (((g_CurFrameInput & key) != 0) && (g_CurFrameInput & key) != (g_LastFrameInput & key))

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
    for (i = 0; i < 122; i++)
    {
        this->vm[i].pendingInterrupt = 1;
        this->vm[i].flags |= AnmVmFlags_3;
        if ((g_Supervisor.cfg.opts & (1 << GCOS_USE_D3D_HW_TEXTURE_BLENDING)) == 0)
        {
            this->vm[i].color = 0xff000000;
        }
        else
        {
            this->vm[i].color = 0xffffffff;
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
    int i;
    i = MoveCursor(this, 8);
    if ((this->cursor == 1) && !g_GameManager.hasReachedMaxClears(0, 0) && !g_GameManager.hasReachedMaxClears(0, 1) &&
            !g_GameManager.hasReachedMaxClears(1, 0) && !g_GameManager.hasReachedMaxClears(1, 1))
    {
        this->cursor += i;
    }
    AnmVm *drawVm = this->vm;
    for (i = 0; i < 8; i++, drawVm++ /* zun why */)
    {
        DrawMenuItem(drawVm, i, this->cursor, 0xffff0000, 0x80300000, 122);
    }
    if (this->stateTimer >= 0x14)
    {
        if (WAS_PRESSED(0x1001))
        {
            switch (this->cursor)
            {
                case 0:
                    for (i = 0; i < 122; i++)
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
                    this->maybeMenuTextColor = 0xff000000;
                    this->unk_820c = 0;
                    this->isActive = 60;
                    g_SoundPlayer.PlaySoundByIdx(10, 0);
                    break;
                case 1:
                    if (!(!g_GameManager.hasReachedMaxClears(0, 0) && !g_GameManager.hasReachedMaxClears(0, 1) &&
                                !g_GameManager.hasReachedMaxClears(1, 0) && !g_GameManager.hasReachedMaxClears(1, 1)))
                    {
                        for (i = 0; i < 122; i++)
                        {
                            this->vm[i].pendingInterrupt = 4;
                        }
                        this->gameState = STATE_DIFFICULTY_LOAD;
                        g_GameManager.unk_1823 = 0;
                        g_GameManager.difficulty = EXTRA;
                        this->stateTimer = 0;
                        this->unk_81fc = 0x40000000;
                        this->maybeMenuTextColor = 0xff000000;
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
                    for (i = 0; i < 122; i++)
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
                    this->maybeMenuTextColor = 0xff000000;
                    this->unk_820c = 0;
                    this->isActive = 60;
                    g_SoundPlayer.PlaySoundByIdx(10, 0);
                    break;
                case 3:
                    for (i = 0; i < 122; i++)
                    {
                        this->vm[i].pendingInterrupt = 4;
                    }
                    this->gameState = STATE_REPLAY_LOAD;
                    g_GameManager.unk_1823 = 0;
                    this->stateTimer = 0;
                    this->unk_81fc = 0x40000000;
                    this->maybeMenuTextColor = 0xff000000;
                    this->unk_820c = 0;
                    this->isActive = 60;
                    g_SoundPlayer.PlaySoundByIdx(10, 0);
                    break;
                case 4:
                    for (i = 0; i < 122; i++)
                    {
                        this->vm[i].pendingInterrupt = 4;
                    }
                    this->gameState = STATE_SCORE;
                    this->stateTimer = 0;
                    this->unk_81fc = 0x40000000;
                    this->maybeMenuTextColor = 0xff000000;
                    this->unk_820c = 0;
                    this->isActive = 60;
                    g_SoundPlayer.PlaySoundByIdx(10, 0);
                    break;
                case 5:
                    this->gameState = STATE_MUSIC_ROOM;
                    this->stateTimer = 0;
                    for (i = 0; i < 122; i++)
                    {
                        this->vm[i].pendingInterrupt = 4;
                    }
                    g_SoundPlayer.PlaySoundByIdx(10, 0);
                    break;
                case 6:
                    this->gameState = STATE_OPTIONS;
                    this->stateTimer = 0;
                    for (i = 0; i < 122; i++)
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
                    for (i = 0; i < 122; i++)
                    {
                        this->vm[i].pendingInterrupt = 4;
                    }
                    g_SoundPlayer.PlaySoundByIdx(0xb, 0);
                    break;
            }
        }
        if (WAS_PRESSED(0x200))
        {
            this->gameState = STATE_QUIT;
            this->stateTimer = 0;
            for (i = 0; i < 122; i++)
            {
                this->vm[i].pendingInterrupt = 4;
            }
            g_SoundPlayer.PlaySoundByIdx(0xb, 0);
        }
        if (WAS_PRESSED(0xA))
        {
            this->cursor = 7;
            g_SoundPlayer.PlaySoundByIdx(0xb, 0);
        }
    }
    return ZUN_SUCCESS;
}
#pragma optimize("", on)

void _strcpy(char* dst, char* src) { strcpy(dst,src); }

#pragma optimize("s", on)
#pragma var_order(anmVm, cur, replayFileHandle, replayFileIdx, replayData, replayFilePath, replayFileInfo, padding)
i32 MainMenu::ReplayHandling()
{
    AnmVm* anmVm;
    i32 cur;
    HANDLE replayFileHandle;
    u32 replayFileIdx;
    ReplayData* replayData;
    char replayFilePath[32];
    WIN32_FIND_DATA replayFileInfo;
    u8 padding[0x28]; // idk

    switch(this->gameState) { 
        case STATE_REPLAY_LOAD:
            if(this->stateTimer == 0x3c) { 
                if(LoadReplayMenu(this)) {
                    GameErrorContextLog(&g_GameErrorContext, "japanese");
                    g_Supervisor.curState = 4;
                    return ZUN_SUCCESS;
                } else {
                    replayFileIdx = 0; 
                    for(cur = 0; cur < 15; cur++) {
                        sprintf(replayFilePath, "./replay/th6_%.2d.rpy", cur+1);
                        replayData = (ReplayData*)FileSystem::OpenPath(replayFilePath, 1);
                        if(replayData == NULL) {
                            continue;
                        }
                        if(!validateReplayData(replayData, g_LastFileSize)) {
                            // FIXME: wrong assembly
                            memcpy(&this->replayFileData[replayFileIdx], replayData, 0x14);
                            // HACK: i dont think it should be this way
                            _strcpy(this->replayFilePaths[replayFileIdx], replayFilePath);
                            sprintf(this->replayFileName[replayFileIdx], "No.%.2d", cur+1);
                            replayFileIdx++;
                        }
                        free(replayData);
                    }
                    FileSystem::CreateDirectoryInCWD("./replay");
                    FileSystem::ChangeCWD("./replay");
                    replayFileHandle = FindFirstFileA("th6_ud????.rpy", &replayFileInfo);
                    if(replayFileHandle != INVALID_HANDLE_VALUE) {
                        for(cur = 0; cur < 0x2d; cur++) {
                            replayData = (ReplayData*)FileSystem::OpenPath(replayFilePath, 1);
                            if(replayData == NULL) {
                                continue;
                            }
                            if(!validateReplayData(replayData, g_LastFileSize)) {
                                // FIXME: wrong assembly
                                memcpy(&this->replayFileData[replayFileIdx], replayData, 0x14);
                                sprintf(this->replayFilePaths[replayFileIdx], "./replay/%s", replayFileInfo.cFileName);
                                sprintf(this->replayFileName[replayFileIdx], "User ");
                                replayFileIdx++;
                            }
                            free(replayData);
                            if(!FindNextFileA(replayFileHandle, &replayFileInfo)) break;
                        }
                    }
                    FindClose(replayFileHandle);
                    FileSystem::ChangeCWD("../");
                    this->replayFilesNum = replayFileIdx;
                    this->unk_81fc = 0;
                    this->wasActive = this->isActive;
                    this->isActive = 0;
                    this->gameState = STATE_REPLAY_ANIM;
                    anmVm = this->vm;
                    for(cur = 0; cur < 122; cur++, anmVm++) {
                        anmVm->pendingInterrupt = 15;
                    }
                    this->cursor = 0;
                }
                break;
            }
            break;
        case STATE_REPLAY_UNLOAD: 
            if(this->stateTimer == 0x24) {
                this->gameState = STATE_STARTUP;
                this->stateTimer = 0;
            }
            break;
        case STATE_REPLAY_ANIM: 
            if(this->stateTimer < 0x28) {
                break;
            }
            if(this->replayFilesNum != NULL) {
                MoveCursor(this, this->replayFilesNum);
                this->chosenReplay = this->cursor;
                if(WAS_PRESSED(0x1001)) {
                    this->gameState = STATE_REPLAY_SELECT;
                    anmVm = &(this->vm[97]);
                    for(cur = 0; cur < 0x19; cur += 1, anmVm++) {
                        anmVm->pendingInterrupt = 0x11;
                    }
                    anmVm = &this->vm[99 + this->chosenReplay];
                    anmVm->pendingInterrupt = 0x10;
                    this->stateTimer = 0;
                    this->cursor = 0;
                    g_SoundPlayer.PlaySoundByIdx(10,0);
                    this->currentReplay = (ReplayData*) FileSystem::OpenPath(this->replayFilePaths[this->chosenReplay],1);
                    validateReplayData(this->currentReplay,g_LastFileSize);
                    for(cur = 0; cur < 7; cur++) {
                        if(this->currentReplay->stageScore[cur + 1] != NULL) {
                            // FIXME: I dont understand this code at all, so i just yoinked it from the ghidra server
                            this->currentReplay->stageScore[cur + 1] =
                                (StageReplayData *)
                                ((int)this->currentReplay->stageScore + (int)(this->currentReplay->stageScore[cur + 1][-1].replayInputs + 0xd2e8));
                        }
                    }
                    do {
                        // FIXME: there's an additional jump
                        if(!this->replayFileData[this->chosenReplay].stageScore[this->cursor + 1]) goto leaveDo;
                        this->cursor = this->cursor + 1;
                    } while ((int)this->cursor < 7);
                    return ZUN_SUCCESS;
                }
            }
leaveDo:
            if(WAS_PRESSED(0xA)) {
                this->gameState = STATE_REPLAY_UNLOAD;
                this->stateTimer = 0;
                for(cur = 0; cur < 122; cur++) {
                    this->vm[cur].pendingInterrupt = 4;
                }
                g_SoundPlayer.PlaySoundByIdx(0xb, 0);
                this->cursor = 0;
                break;
            }
            break;
        case STATE_REPLAY_SELECT:
            if(this->stateTimer < 0x28) {
                break;
            }
            cur = MoveCursor(this, 7);
            if(cur < 0) {
                while(this->replayFileData[this->chosenReplay].stageScore[this->cursor+1] == NULL) {
                    this->cursor--;
                    if(this->cursor < 0) {
                        this->cursor = 6;
                    }
                }
            } else if(cur > 0) {
                while(this->replayFileData[this->chosenReplay].stageScore[this->cursor+1] == NULL) {
                    this->cursor++;
                    if(this->cursor >= 7) {
                        this->cursor = 0;
                    }
                }
            }
            if(WAS_PRESSED(0x1001) && this->currentReplay[this->cursor].stageScore) {
                g_GameManager.unk_1c = 1;
                g_Supervisor.framerateMultiplier = 1.0;
                _strcpy(g_GameManager.replayFile, this->replayFilePaths[this->chosenReplay]);
                g_GameManager.difficulty = (Difficulty)this->currentReplay->difficulty;
                g_GameManager.character  = this->currentReplay->shottypeChara / 2;
                g_GameManager.shottype   = this->currentReplay->shottypeChara % 2;
                cur = 0;
                while(this->currentReplay->stageScore[cur+1] == NULL) {
                    cur++;
                }
                g_GameManager.livesRemaining = this->currentReplay->stageScore[cur+1]->livesRemaining;
                g_GameManager.bombsRemaining = this->currentReplay->stageScore[cur+1]->bombsRemaining;
                free(this->currentReplay);
                this->currentReplay = NULL;
                g_GameManager.currentStage = this->cursor;
                g_Supervisor.curState = 2;
                return 1;
            }
            if(WAS_PRESSED(0x10)) {
                free(this->currentReplay);
                this->currentReplay = NULL;
                this->gameState = STATE_REPLAY_ANIM;
                this->stateTimer = 0;
                for(cur = 0; cur < 122; cur++) {
                    this->vm[cur].pendingInterrupt = 4;
                }
                g_SoundPlayer.PlaySoundByIdx(0xb,0);
                this->gameState = STATE_REPLAY_ANIM;
                anmVm = this->vm;
                for(cur = 0; cur < 122; cur += 1, anmVm++) {
                    anmVm->pendingInterrupt = 0xf;
                }
                this->cursor = this->chosenReplay;

            }
    }
    return 0;
}


#pragma optimize("", on)