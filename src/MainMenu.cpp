#include <D3DX8.h>
#include <windows.h>

#include "MainMenu.hpp"

#include "AnmManager.hpp"
#include "Supervisor.hpp"
#include "i18n.hpp"

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
