#include <D3DX8.h>
#include <windows.h>

#include "MainMenu.hpp"

#include "AnmManager.hpp"
#include "GameManager.hpp"
#include "SoundPlayer.hpp"
#include "Supervisor.hpp"
#include "i18n.hpp"

#define WAS_PRESSED(key) (((g_CurFrameInput & key ) != 0) && (g_CurFrameInput & key ) != (g_LastFrameInput & key ))

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


DIFFABLE_STATIC(u16, g_LastFrameInput);
DIFFABLE_STATIC(u16, g_CurFrameInput);

#pragma optimize("s", on)
#pragma var_order(i, drawVm)
ZunResult MainMenu::DrawStartMenu(void) {
    int i;
    i = MoveCursor(this, 8);
    if((this->cursor == 1) && !g_GameManager.hasReachedMaxClears(0,0) &&
        !g_GameManager.hasReachedMaxClears(0,1) &&
        !g_GameManager.hasReachedMaxClears(1,0) &&
        !g_GameManager.hasReachedMaxClears(1,1)
        ) {
        this->cursor += i;
    }
    AnmVm* drawVm = this->vm;
    for(i=0; i < 8; i++, drawVm++ /* zun why */) {
        DrawMenuItem(drawVm, i, this->cursor, 0xffff0000, 0x80300000, 122);
    }
    if(this->stateTimer >= 0x14) {
        if(WAS_PRESSED(0x1001)) {
            switch(this->cursor) {
                case 0:
                    for (i = 0; i < 122; i++) {
                        this->vm[i].pendingInterrupt = 4;
                    }
                    this->gameState = STATE_DIFFICULTY_LOAD;
                    g_GameManager.unk_1823 = 0;
                    if(EXTRA <= g_GameManager.difficulty) {
                        g_GameManager.difficulty = NORMAL;
                    }
                    if(EXTRA <= g_Supervisor.cfg.defaultDifficulty) {
                        g_Supervisor.cfg.defaultDifficulty = NORMAL;
                    }
                    this->stateTimer = 0;
                    this->unk_81fc = 0x40000000;
                    this->maybeMenuTextColor = 0xff000000;
                    this->unk_820c = 0;
                    this->isActive = 60;
                    g_SoundPlayer.PlaySoundByIdx(10,0);
                    break;
                case 1: 
                    if(!(!g_GameManager.hasReachedMaxClears(0,0) &&
                        !g_GameManager.hasReachedMaxClears(0,1) &&
                        !g_GameManager.hasReachedMaxClears(1,0) &&
                        !g_GameManager.hasReachedMaxClears(1,1))) {
                        for (i = 0; i < 122; i++) {
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
                        g_SoundPlayer.PlaySoundByIdx(10,0);
                    } else {
                        g_SoundPlayer.PlaySoundByIdx(0xb,0);
                    }
                    break;
                case 2:
                    g_GameManager.unk_1823 = 1;
                    for (i = 0; i < 122; i++) {
                        this->vm[i].pendingInterrupt = 4;
                    }
                    this->gameState = STATE_DIFFICULTY_LOAD;
                    if(EXTRA <= g_GameManager.difficulty) {
                        g_GameManager.difficulty = NORMAL;
                    }
                    if(EXTRA <= g_Supervisor.cfg.defaultDifficulty) {
                        g_Supervisor.cfg.defaultDifficulty = NORMAL;
                    }
                    this->stateTimer = 0;
                    this->unk_81fc = 0x40000000;
                    this->maybeMenuTextColor = 0xff000000;
                    this->unk_820c = 0;
                    this->isActive = 60;
                    g_SoundPlayer.PlaySoundByIdx(10,0);
                    break;
                case 3:
                    for(i = 0; i < 122; i++) {
                        this->vm[i].pendingInterrupt = 4;
                    }
                    this->gameState = STATE_REPLAY_LOAD;
                    g_GameManager.unk_1823 = 0;
                    this->stateTimer = 0;
                    this->unk_81fc = 0x40000000;
                    this->maybeMenuTextColor = 0xff000000;
                    this->unk_820c = 0;
                    this->isActive = 60;
                    g_SoundPlayer.PlaySoundByIdx(10,0);
                    break;
                case 4:
                    for(i = 0; i < 122; i++) {
                        this->vm[i].pendingInterrupt = 4;
                    }
                    this->gameState = STATE_SCORE;
                    this->stateTimer = 0;
                    this->unk_81fc = 0x40000000;
                    this->maybeMenuTextColor = 0xff000000;
                    this->unk_820c = 0;
                    this->isActive = 60;
                    g_SoundPlayer.PlaySoundByIdx(10,0);
                    break;
                case 5:
                    this->gameState = STATE_MUSIC_ROOM;
                    this->stateTimer = 0;
                    for(i = 0; i < 122; i++) {
                        this->vm[i].pendingInterrupt = 4;
                    }
                    g_SoundPlayer.PlaySoundByIdx(10, 0);
                    break;
                case 6:
                    this->gameState = STATE_OPTIONS;
                    this->stateTimer = 0;
                    for(i = 0; i < 122; i++) {
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
                    for(i = 0; i < 122; i++) {
                        this->vm[i].pendingInterrupt = 4;
                    }
                    g_SoundPlayer.PlaySoundByIdx(0xb, 0);
                    break;
            }
    }
    if(WAS_PRESSED(0x200)) {
        this->gameState = STATE_QUIT;
        this->stateTimer = 0;
        for(i = 0; i < 122; i++) {
            this->vm[i].pendingInterrupt = 4;
        }
        g_SoundPlayer.PlaySoundByIdx(0xb,0);
    }
    if(WAS_PRESSED(0xA)) {
        this->cursor = 7;
        g_SoundPlayer.PlaySoundByIdx(0xb, 0);
    }
}
return ZUN_SUCCESS;
}
#pragma optimize("", on)

