#include <D3DX8.h>
#include <windows.h>

#include "MainMenu.hpp"
#include "Supervisor.hpp"

#pragma optimize("s", on)
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
    else
    {
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
            this->vm[i].flags |= AnmVmFlags_8;
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
}
#pragma optimize("", on)
