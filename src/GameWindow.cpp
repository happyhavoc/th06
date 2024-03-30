#include "GameWindow.hpp"
#include "SoundPlayer.hpp"
#include "Stage.hpp"
#include "Supervisor.hpp"
#include "diffbuild.hpp"

DIFFABLE_STATIC(GameWindow, g_GameWindow)
DIFFABLE_STATIC(i32, g_TickCountToEffectiveFramerate)
DIFFABLE_STATIC(f64, g_LastFrameTime)

#define FRAME_TIME (1000. / 60.)

#pragma var_order(res, viewport, slowdown, local_34, delta, curtime)
RenderResult GameWindow::Render()
{
    i32 res;
    f64 slowdown;
    D3DVIEWPORT8 viewport;
    f64 delta;
    u32 curtime;
    f64 local_34;

    if (this->lastActiveAppValue == 0)
    {
        return RENDER_RESULT_KEEP_RUNNING;
    }

    if (this->curFrame == 0)
    {
    LOOP_USING_GOTO_BECAUSE_WHY_NOT:
        if (g_Supervisor.cfg.frameskipConfig <= this->curFrame)
        {
            if ((((g_Supervisor.cfg.opts >> GCOS_DISPLAY_MINIMUM_GRAPHICS) & 1) |
                 ((g_Supervisor.cfg.opts >> GCOS_CLEAR_BACKBUFFER_ON_REFRESH) & 1)) != 0)
            {
                viewport.X = 0;
                viewport.Y = 0;
                viewport.Width = 640;
                viewport.Height = 480;
                viewport.MinZ = 0.0;
                viewport.MaxZ = 1.0;
                g_Supervisor.d3dDevice->SetViewport(&viewport);
                g_Supervisor.d3dDevice->Clear(0, NULL, 3, g_Stage.skyFog.color, 1.0, 0);
                g_Supervisor.d3dDevice->SetViewport(&g_Supervisor.viewport);
            }
            g_Supervisor.d3dDevice->BeginScene();
            g_Chain.RunDrawChain();
            g_Supervisor.d3dDevice->EndScene();
            g_Supervisor.d3dDevice->SetTexture(0, NULL);
        }

        g_Supervisor.viewport.X = 0;
        g_Supervisor.viewport.Y = 0;
        g_Supervisor.viewport.Width = 640;
        g_Supervisor.viewport.Height = 480;
        g_Supervisor.d3dDevice->SetViewport(&g_Supervisor.viewport);
        res = g_Chain.RunCalcChain();
        g_SoundPlayer.PlaySounds();
        if (res == 0)
        {
            return RENDER_RESULT_EXIT_SUCCESS;
        }
        if (res == -1)
        {
            return RENDER_RESULT_EXIT_ERROR;
        }
        this->curFrame++;
    }

    if (g_Supervisor.cfg.windowed == false)
    {
        i32 bVar1;
        if (!(((g_Supervisor.cfg.opts >> GCOS_FORCE_60FPS & 1) == 0) || (g_Supervisor.vsyncEnabled == 0)))
        {
            bVar1 = true;
        }
        else
        {
            bVar1 = false;
        }
        if (!bVar1)
            goto BREAK_BUT_WITHOUT_BREAK_BECAUSE_IM_USING_A_GOTO_BASED_LOOP;
    }
    if (this->curFrame != 0)
    {
        g_Supervisor.framerateMultiplier = 1.0;
        timeBeginPeriod(1);
        slowdown = timeGetTime();
        if (slowdown < g_LastFrameTime)
        {
            g_LastFrameTime = slowdown;
        }
        local_34 = fabs(slowdown - g_LastFrameTime);
        timeEndPeriod(1);
        if (local_34 >= FRAME_TIME)
        {
            do
            {
                g_LastFrameTime += FRAME_TIME;
                local_34 -= FRAME_TIME;
            } while (local_34 >= FRAME_TIME);

            if (g_Supervisor.cfg.frameskipConfig < this->curFrame)
                goto I_HAVE_NO_CLUE_WHY_BUT_I_MUST_JUMP_HERE;
            goto LOOP_USING_GOTO_BECAUSE_WHY_NOT;
        }
    }

BREAK_BUT_WITHOUT_BREAK_BECAUSE_IM_USING_A_GOTO_BASED_LOOP:
    if (g_Supervisor.cfg.windowed == false)
    {
        i32 bVar2;
        if (!(((g_Supervisor.cfg.opts >> GCOS_FORCE_60FPS & 1) == 0) || (g_Supervisor.vsyncEnabled == 0)))
        {
            bVar2 = true;
        }
        else
        {
            bVar2 = false;
        }
        if (!bVar2)
        {
            if (g_Supervisor.cfg.frameskipConfig >= this->curFrame)
            {
                Present();
                goto LOOP_USING_GOTO_BECAUSE_WHY_NOT;
            }

        I_HAVE_NO_CLUE_WHY_BUT_I_MUST_JUMP_HERE:
            Present();
            if (g_Supervisor.framerateMultiplier == 0.f)
            {
                if (2 <= g_TickCountToEffectiveFramerate)
                {
                    timeBeginPeriod(1);
                    curtime = timeGetTime();
                    if (curtime < g_Supervisor.lastFrameTime)
                    {
                        g_Supervisor.lastFrameTime = curtime;
                    }
                    delta = curtime - g_Supervisor.lastFrameTime;
                    delta = (delta * 60.) / 2. / 1000.;
                    delta /= (g_Supervisor.cfg.frameskipConfig + 1);
                    if (delta >= .865)
                    {
                        delta = 1.0;
                    }
                    else if (delta >= .6)
                    {
                        delta = 0.8;
                    }
                    else
                    {
                        delta = 0.5;
                    }
                    g_Supervisor.effectiveFramerateMultiplier = delta;
                    g_Supervisor.lastFrameTime = curtime;
                    timeEndPeriod(1);
                    g_TickCountToEffectiveFramerate = 0;
                }
            }
            else
            {
                g_Supervisor.effectiveFramerateMultiplier = g_Supervisor.framerateMultiplier;
            }
            this->curFrame = 0;
            g_TickCountToEffectiveFramerate = g_TickCountToEffectiveFramerate + 1;
        }
    }
    return RENDER_RESULT_KEEP_RUNNING;
}
