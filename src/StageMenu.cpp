#include "StageMenu.hpp"
#include "AnmManager.hpp"
#include "GameManager.hpp"
#include "Gui.hpp"
#include "utils.hpp"

StageMenu::StageMenu()
{
}

enum UpdateGameMenuState
{
    GAME_MENU_PAUSE_OPENING,
    GAME_MENU_PAUSE_CURSOR_UNPAUSE,
    GAME_MENU_PAUSE_CURSOR_QUIT,
    GAME_MENU_PAUSE_SELECTED_UNPAUSE,
    GAME_MENU_QUIT_CURSOR_YES,
    GAME_MENU_QUIT_CURSOR_NO,
    GAME_MENU_QUIT_SELECTED_YES,
};

#define GAME_MENU_SPRITE_TITLE_PAUSE 0
#define GAME_MENU_SPRITE_CURSOR_UNPAUSE 1
#define GAME_MENU_SPRITE_CURSOR_QUIT 2
#define GAME_MENU_SPRITE_TITLE_QUIT 3
#define GAME_MENU_SPRITE_CURSOR_YES 4
#define GAME_MENU_SPRITE_CURSOR_NO 5

#define GAME_MENU_SPRITES_START_PAUSE GAME_MENU_SPRITE_TITLE_PAUSE
#define GAME_MENU_SPRITES_COUNT_PAUSE 3
#define GAME_MENU_SPRITES_END_PAUSE (GAME_MENU_SPRITES_START_PAUSE + GAME_MENU_SPRITES_COUNT_PAUSE)
#define GAME_MENU_SPRITES_START_QUIT GAME_MENU_SPRITE_TITLE_QUIT
#define GAME_MENU_SPRITES_COUNT_QUIT 3
#define GAME_MENU_SPRITES_END_QUIT (GAME_MENU_SPRITES_START_QUIT + GAME_MENU_SPRITES_COUNT_QUIT)

i32 StageMenu::OnUpdateGameMenu()
{
    i32 vmIdx;

    if (WAS_PRESSED(TH_BUTTON_MENU))
    {
        this->curState = GAME_MENU_PAUSE_SELECTED_UNPAUSE;
        for (vmIdx = 0; vmIdx < ARRAY_SIZE_SIGNED(this->menuSprites); vmIdx++)
        {
            if (this->menuSprites[vmIdx].flags.isVisible)
            {
                this->menuSprites[vmIdx].pendingInterrupt = 2;
            }
        }
        this->numFrames = 0;
        this->menuBackground.pendingInterrupt = 1;
    }
    if (WAS_PRESSED(TH_BUTTON_Q))
    {
        this->curState = GAME_MENU_QUIT_SELECTED_YES;
        for (vmIdx = 0; vmIdx < ARRAY_SIZE_SIGNED(this->menuSprites); vmIdx++)
        {
            if (this->menuSprites[vmIdx].flags.isVisible)
            {
                this->menuSprites[vmIdx].pendingInterrupt = 2;
            }
        }
        this->numFrames = 0;
    }
    switch (this->curState)
    {
    case GAME_MENU_PAUSE_OPENING:
        for (vmIdx = 0; vmIdx < ARRAY_SIZE_SIGNED(this->menuSprites); vmIdx++)
        {
            g_AnmManager->SetAndExecuteScriptIdx(&this->menuSprites[vmIdx], vmIdx + 2);
        }
        for (vmIdx = GAME_MENU_SPRITES_START_PAUSE; vmIdx < GAME_MENU_SPRITES_END_PAUSE; vmIdx++)
        {
            this->menuSprites[vmIdx].pendingInterrupt = 1;
        }
        this->curState++;
        this->numFrames = 0;
        if (g_Supervisor.lockableBackbuffer)
        {
            g_AnmManager->RequestScreenshot();
            g_AnmManager->SetAndExecuteScriptIdx(&this->menuBackground, ANM_SCRIPT_CAPTURE_PAUSE_BG);
            this->menuBackground.pos.x = GAME_REGION_LEFT;
            this->menuBackground.pos.y = GAME_REGION_TOP;
            this->menuBackground.pos.z = 0.0f;
        }
    case GAME_MENU_PAUSE_CURSOR_UNPAUSE:
        this->menuSprites[GAME_MENU_SPRITE_CURSOR_UNPAUSE].color = COLOR_LIGHT_RED;
        this->menuSprites[GAME_MENU_SPRITE_CURSOR_QUIT].color = COLOR_SET_ALPHA(COLOR_GREY, 0x80);
        this->menuSprites[GAME_MENU_SPRITE_CURSOR_UNPAUSE].scaleY = 1.7f;
        this->menuSprites[GAME_MENU_SPRITE_CURSOR_UNPAUSE].scaleX = 1.7f;
        this->menuSprites[GAME_MENU_SPRITE_CURSOR_QUIT].scaleY = 1.5f;
        this->menuSprites[GAME_MENU_SPRITE_CURSOR_QUIT].scaleX = 1.5f;
        this->menuSprites[GAME_MENU_SPRITE_CURSOR_UNPAUSE].posOffset = D3DXVECTOR3(-4.0f, -4.0f, 0.0f);
        this->menuSprites[GAME_MENU_SPRITE_CURSOR_QUIT].posOffset = D3DXVECTOR3(0.0f, 0.0f, 0.0f);
        if (4 <= this->numFrames)
        {
            if (WAS_PRESSED(TH_BUTTON_UP) || WAS_PRESSED(TH_BUTTON_DOWN))
            {
                this->curState = GAME_MENU_PAUSE_CURSOR_QUIT;
            }
            if (WAS_PRESSED(TH_BUTTON_SHOOT))
            {
                for (vmIdx = GAME_MENU_SPRITES_START_PAUSE; vmIdx < GAME_MENU_SPRITES_END_PAUSE; vmIdx++)
                {
                    this->menuSprites[vmIdx].pendingInterrupt = 2;
                }
                this->curState = GAME_MENU_PAUSE_SELECTED_UNPAUSE;
                this->numFrames = 0;
                this->menuBackground.pendingInterrupt = 1;
            }
        }
        break;
    case GAME_MENU_PAUSE_CURSOR_QUIT:
        this->menuSprites[GAME_MENU_SPRITE_CURSOR_UNPAUSE].color = COLOR_SET_ALPHA(COLOR_GREY, 0x80);
        this->menuSprites[GAME_MENU_SPRITE_CURSOR_QUIT].color = COLOR_LIGHT_RED;
        this->menuSprites[GAME_MENU_SPRITE_CURSOR_UNPAUSE].scaleY = 1.5f;
        this->menuSprites[GAME_MENU_SPRITE_CURSOR_UNPAUSE].scaleX = 1.5f;
        this->menuSprites[GAME_MENU_SPRITE_CURSOR_QUIT].scaleY = 1.7f;
        this->menuSprites[GAME_MENU_SPRITE_CURSOR_QUIT].scaleX = 1.7f;
        this->menuSprites[GAME_MENU_SPRITE_CURSOR_UNPAUSE].posOffset = D3DXVECTOR3(0.0f, 0.0f, 0.0f);
        this->menuSprites[GAME_MENU_SPRITE_CURSOR_QUIT].posOffset = D3DXVECTOR3(-4.0f, -4.0f, 0.0f);
        if (4 <= this->numFrames)
        {
            if (WAS_PRESSED(TH_BUTTON_UP) || WAS_PRESSED(TH_BUTTON_DOWN))
            {
                this->curState = GAME_MENU_PAUSE_CURSOR_UNPAUSE;
            }
            if (WAS_PRESSED(TH_BUTTON_SHOOT))
            {
                for (vmIdx = GAME_MENU_SPRITES_START_PAUSE; vmIdx < GAME_MENU_SPRITES_END_PAUSE; vmIdx++)
                {
                    this->menuSprites[vmIdx].pendingInterrupt = 2;
                }
                for (vmIdx = GAME_MENU_SPRITES_START_QUIT; vmIdx < GAME_MENU_SPRITES_END_QUIT; vmIdx++)
                {
                    this->menuSprites[vmIdx].pendingInterrupt = 1;
                }
                this->curState = GAME_MENU_QUIT_CURSOR_NO;
                this->numFrames = 0;
            }
        }
        break;
    case GAME_MENU_PAUSE_SELECTED_UNPAUSE:
        /* Close menu, wait 20 frames for the animation? */
        if (20 <= this->numFrames)
        {
            this->curState = GAME_MENU_PAUSE_OPENING;
            g_GameManager.isInGameMenu = 0;
            for (vmIdx = 0; vmIdx < ARRAY_SIZE_SIGNED(this->menuSprites); vmIdx++)
            {
                this->menuSprites[vmIdx].SetInvisible();
            }
        }
        break;
    case GAME_MENU_QUIT_CURSOR_YES:
        this->menuSprites[GAME_MENU_SPRITE_CURSOR_YES].color = COLOR_LIGHT_RED;
        this->menuSprites[GAME_MENU_SPRITE_CURSOR_NO].color = COLOR_SET_ALPHA(COLOR_GREY, 0x80);
        this->menuSprites[GAME_MENU_SPRITE_CURSOR_YES].scaleY = 1.7f;
        this->menuSprites[GAME_MENU_SPRITE_CURSOR_YES].scaleX = 1.7f;
        this->menuSprites[GAME_MENU_SPRITE_CURSOR_NO].scaleY = 1.5f;
        this->menuSprites[GAME_MENU_SPRITE_CURSOR_NO].scaleX = 1.5f;
        this->menuSprites[GAME_MENU_SPRITE_CURSOR_YES].posOffset = D3DXVECTOR3(-4.0f, -4.0f, 0.0f);
        this->menuSprites[GAME_MENU_SPRITE_CURSOR_NO].posOffset = D3DXVECTOR3(0.0f, 0.0f, 0.0f);
        if (4 <= this->numFrames)
        {
            if (WAS_PRESSED(TH_BUTTON_UP) || WAS_PRESSED(TH_BUTTON_DOWN))
            {
                this->curState = GAME_MENU_QUIT_CURSOR_NO;
            }
            if (WAS_PRESSED(TH_BUTTON_SHOOT))
            {
                for (vmIdx = GAME_MENU_SPRITES_START_QUIT; vmIdx < GAME_MENU_SPRITES_END_QUIT; vmIdx++)
                {
                    this->menuSprites[vmIdx].pendingInterrupt = 2;
                }
                this->curState = GAME_MENU_QUIT_SELECTED_YES;
                this->numFrames = 0;
            }
        }
        break;
    case GAME_MENU_QUIT_CURSOR_NO:
        this->menuSprites[GAME_MENU_SPRITE_CURSOR_YES].color = COLOR_SET_ALPHA(COLOR_GREY, 0x80);
        this->menuSprites[GAME_MENU_SPRITE_CURSOR_NO].color = COLOR_LIGHT_RED;
        this->menuSprites[GAME_MENU_SPRITE_CURSOR_YES].scaleY = 1.5f;
        this->menuSprites[GAME_MENU_SPRITE_CURSOR_YES].scaleX = 1.5f;
        this->menuSprites[GAME_MENU_SPRITE_CURSOR_NO].scaleY = 1.7f;
        this->menuSprites[GAME_MENU_SPRITE_CURSOR_NO].scaleX = 1.7f;
        this->menuSprites[GAME_MENU_SPRITE_CURSOR_YES].posOffset = D3DXVECTOR3(0.0f, 0.0f, 0.0f);
        this->menuSprites[GAME_MENU_SPRITE_CURSOR_NO].posOffset = D3DXVECTOR3(-4.0f, -4.0f, 0.0f);
        if (GAME_MENU_SPRITE_CURSOR_YES <= this->numFrames)
        {
            if (WAS_PRESSED(TH_BUTTON_UP) || WAS_PRESSED(TH_BUTTON_DOWN))
            {
                this->curState = GAME_MENU_QUIT_CURSOR_YES;
            }
            if (WAS_PRESSED(TH_BUTTON_SHOOT))
            {
                for (vmIdx = GAME_MENU_SPRITES_START_PAUSE; vmIdx < GAME_MENU_SPRITES_END_PAUSE; vmIdx++)
                {
                    this->menuSprites[vmIdx].pendingInterrupt = 1;
                }
                for (vmIdx = GAME_MENU_SPRITES_START_QUIT; vmIdx < GAME_MENU_SPRITES_END_QUIT; vmIdx++)
                {
                    this->menuSprites[vmIdx].pendingInterrupt = 2;
                }
                this->curState = GAME_MENU_PAUSE_CURSOR_QUIT;
                this->numFrames = 0;
            }
        }
        break;
    case GAME_MENU_QUIT_SELECTED_YES:
        if (20 <= this->numFrames)
        {
            this->curState = GAME_MENU_PAUSE_OPENING;
            g_GameManager.isInGameMenu = 0;
            g_Supervisor.curState = SUPERVISOR_STATE_MAINMENU;
            for (vmIdx = 0; vmIdx < ARRAY_SIZE_SIGNED(this->menuSprites); vmIdx++)
            {
                this->menuSprites[vmIdx].SetInvisible();
            }
        }
    }
    for (vmIdx = 0; vmIdx < ARRAY_SIZE_SIGNED(this->menuSprites); vmIdx++)
    {
        g_AnmManager->ExecuteScript(&this->menuSprites[vmIdx]);
    }
    if (g_Supervisor.lockableBackbuffer)
    {
        g_AnmManager->ExecuteScript(&this->menuBackground);
    }
    this->numFrames++;
    return 0;
}

void StageMenu::OnDrawGameMenu()
{
    i32 vmIdx;

    if (g_GameManager.isInGameMenu)
    {
        g_Supervisor.viewport.X = g_GameManager.arcadeRegionTopLeftPos.x;
        g_Supervisor.viewport.Y = g_GameManager.arcadeRegionTopLeftPos.y;
        g_Supervisor.viewport.Width = g_GameManager.arcadeRegionSize.x;
        g_Supervisor.viewport.Height = g_GameManager.arcadeRegionSize.y;
        g_Supervisor.d3dDevice->SetViewport(&g_Supervisor.viewport);
        if (g_Supervisor.lockableBackbuffer && this->curState != GAME_MENU_PAUSE_OPENING)
        {
            AnmVm menuBackground = this->menuBackground;
            menuBackground.flags.zWriteDisable = 1;
            g_AnmManager->DrawNoRotation(&menuBackground);
        }
        for (vmIdx = 0; vmIdx < ARRAY_SIZE_SIGNED(this->menuSprites); vmIdx++)
        {
            if (this->menuSprites[vmIdx].flags.isVisible)
            {
                g_AnmManager->DrawNoRotation(&this->menuSprites[vmIdx]);
            }
        }
    }
    return;
}

enum RetryGameMenuState
{
    RETRY_MENU_OPENING,
    RETRY_MENU_CURSOR_YES,
    RETRY_MENU_CURSOR_NO,
    RETRY_MENU_SELECTED_YES,
    RETRY_MENU_SELECTED_NO,
};

#define RETRY_MENU_SPRITE_TITLE 0
#define RETRY_MENU_SPRITE_RETRIES_LABEL 1
#define RETRY_MENU_SPRITE_YES 2
#define RETRY_MENU_SPRITE_NO 3
#define RETRY_MENU_SPRITE_RETRIES_NUMBER 4

#define RETRY_MENU_SPRITES_START RETRY_MENU_SPRITE_TITLE
#define RETRY_MENU_SPRITES_COUNT 4
#define RETRY_MENU_SPRITES_END (RETRY_MENU_SPRITES_START + RETRY_MENU_SPRITES_COUNT)

i32 StageMenu::OnUpdateRetryMenu()
{
    i32 idx;

    if (g_GameManager.isInPracticeMode)
    {
        g_GameManager.isInRetryMenu = 0;
        g_GameManager.guiScore = g_GameManager.score;
        g_Supervisor.curState = SUPERVISOR_STATE_RESULTSCREEN_FROMGAME;
        return 1;
    }
    if (g_GameManager.isInReplay)
    {
        g_GameManager.isInRetryMenu = 0;
        g_Supervisor.curState = SUPERVISOR_STATE_MAINMENU_REPLAY;
        g_GameManager.guiScore = g_GameManager.score;
        return 1;
    }
    if (g_GameManager.numRetries >= 3 || g_GameManager.difficulty >= EXTRA)
    {
        g_GameManager.isInRetryMenu = 0;
        g_Supervisor.curState = SUPERVISOR_STATE_RESULTSCREEN_FROMGAME;
        g_GameManager.guiScore = g_GameManager.score;
        return 1;
    }
    switch (this->curState)
    {
    case RETRY_MENU_OPENING:
        if (this->numFrames == 0)
        {
            for (idx = RETRY_MENU_SPRITES_START; idx < RETRY_MENU_SPRITES_END; idx++)
            {
                if (idx < 2)
                {
                    g_AnmManager->SetAndExecuteScriptIdx(&this->menuSprites[idx], idx + 8);
                }
                else
                {
                    g_AnmManager->SetAndExecuteScriptIdx(&this->menuSprites[idx], idx + 4);
                }
                this->menuSprites[idx].pendingInterrupt = 1;
            }
            if (g_Supervisor.lockableBackbuffer)
            {
                g_AnmManager->RequestScreenshot();
                g_AnmManager->SetAndExecuteScriptIdx(&this->menuBackground, ANM_SCRIPT_CAPTURE_PAUSE_BG);
                this->menuBackground.pos.x = GAME_REGION_LEFT;
                this->menuBackground.pos.y = GAME_REGION_TOP;
                this->menuBackground.pos.z = 0.0f;
            }
        }
        if (this->numFrames > 8)
            break;
        this->curState += RETRY_MENU_CURSOR_NO;
        this->numFrames = 0;
    case RETRY_MENU_CURSOR_YES:
        this->menuSprites[RETRY_MENU_SPRITE_YES].color = COLOR_LIGHT_RED;
        this->menuSprites[RETRY_MENU_SPRITE_NO].color = COLOR_SET_ALPHA(COLOR_GREY, 0x80);
        this->menuSprites[RETRY_MENU_SPRITE_YES].scaleY = 1.7f;
        this->menuSprites[RETRY_MENU_SPRITE_YES].scaleX = 1.7f;
        this->menuSprites[RETRY_MENU_SPRITE_NO].scaleY = 1.5f;
        this->menuSprites[RETRY_MENU_SPRITE_NO].scaleX = 1.5f;
        this->menuSprites[RETRY_MENU_SPRITE_YES].posOffset = D3DXVECTOR3(-4.0f, -4.0f, 0.0f);
        this->menuSprites[RETRY_MENU_SPRITE_NO].posOffset = D3DXVECTOR3(0.0f, 0.0f, 0.0f);
        if (3 < this->numFrames)
        {
            if (WAS_PRESSED(TH_BUTTON_UP) || WAS_PRESSED(TH_BUTTON_DOWN))
            {
                this->curState = RETRY_MENU_CURSOR_NO;
            }
            if (WAS_PRESSED(TH_BUTTON_SHOOT))
            {
                for (idx = RETRY_MENU_SPRITES_START; idx < RETRY_MENU_SPRITES_END; idx++)
                {
                    this->menuSprites[idx].pendingInterrupt = 2;
                }
                this->curState = RETRY_MENU_SELECTED_YES;
                this->menuBackground.pendingInterrupt = 1;
                this->numFrames = 0;
            }
        }
        break;
    case RETRY_MENU_CURSOR_NO:
        this->menuSprites[RETRY_MENU_SPRITE_NO].color = COLOR_LIGHT_RED;
        this->menuSprites[RETRY_MENU_SPRITE_YES].color = COLOR_SET_ALPHA(COLOR_GREY, 0x80);
        this->menuSprites[RETRY_MENU_SPRITE_YES].scaleY = 1.5f;
        this->menuSprites[RETRY_MENU_SPRITE_YES].scaleX = 1.5f;
        this->menuSprites[RETRY_MENU_SPRITE_NO].scaleY = 1.7f;
        this->menuSprites[RETRY_MENU_SPRITE_NO].scaleX = 1.7f;
        this->menuSprites[RETRY_MENU_SPRITE_NO].posOffset = D3DXVECTOR3(-4.0f, -4.0f, 0.0f);
        this->menuSprites[RETRY_MENU_SPRITE_YES].posOffset = D3DXVECTOR3(0.0f, 0.0f, 0.0f);
        if (this->numFrames >= 30)
        {
            if (WAS_PRESSED(TH_BUTTON_UP) || WAS_PRESSED(TH_BUTTON_DOWN))
            {
                this->curState = RETRY_MENU_CURSOR_YES;
            }
            if (WAS_PRESSED(TH_BUTTON_SHOOT))
            {
                for (idx = RETRY_MENU_SPRITES_START; idx < RETRY_MENU_SPRITES_END; idx++)
                {
                    this->menuSprites[idx].pendingInterrupt = 2;
                }
                this->curState = RETRY_MENU_SELECTED_NO;
                this->numFrames = 0;
            }
        }
        break;
    case RETRY_MENU_SELECTED_NO:
        if (this->numFrames >= 20)
        {
            this->curState = 0;
            this->numFrames = 0;
            g_GameManager.isInRetryMenu = 0;
            g_Supervisor.curState = SUPERVISOR_STATE_RESULTSCREEN_FROMGAME;
            for (idx = RETRY_MENU_SPRITES_START; idx < RETRY_MENU_SPRITES_END; idx++)
            {
                this->menuSprites[idx].SetInvisible();
            }
            g_GameManager.guiScore = g_GameManager.score;
            return 0;
        }
        break;
    case RETRY_MENU_SELECTED_YES:
        if (this->numFrames >= 30)
        {
            this->curState = 0;
            this->numFrames = 0;
            g_GameManager.isInRetryMenu = 0;
            for (idx = RETRY_MENU_SPRITES_START; idx < RETRY_MENU_SPRITES_END; idx++)
            {
                this->menuSprites[idx].SetInvisible();
            }
            g_GameManager.numRetries++;
            g_GameManager.guiScore = g_GameManager.numRetries;
            g_GameManager.nextScoreIncrement = 0;
            g_GameManager.score = g_GameManager.guiScore;
            g_GameManager.livesRemaining = g_Supervisor.defaultConfig.lifeCount;
            g_GameManager.bombsRemaining = g_Supervisor.defaultConfig.bombCount;
            g_GameManager.grazeInStage = 0;
            g_GameManager.currentPower = 0;
            g_GameManager.pointItemsCollectedInStage = 0;
            g_GameManager.extraLives = 0;
            g_Gui.flags.flag0 = 2;
            g_Gui.flags.flag1 = 2;
            g_Gui.flags.flag3 = 2;
            g_Gui.flags.flag4 = 2;
            g_Gui.flags.flag2 = 2;
            return 0;
        }
        break;
    }
    for (idx = RETRY_MENU_SPRITES_START; idx < RETRY_MENU_SPRITES_END; idx++)
    {
        g_AnmManager->ExecuteScript(&this->menuSprites[idx]);
    }
    if (g_Supervisor.lockableBackbuffer)
    {
        g_AnmManager->ExecuteScript(&this->menuBackground);
    }
    this->numFrames++;
    return 0;
}

void StageMenu::OnDrawRetryMenu()
{
    int idx;

    if (g_GameManager.isInRetryMenu)
    {
        g_Supervisor.viewport.X = g_GameManager.arcadeRegionTopLeftPos.x;
        g_Supervisor.viewport.Y = g_GameManager.arcadeRegionTopLeftPos.y;
        g_Supervisor.viewport.Width = g_GameManager.arcadeRegionSize.x;
        g_Supervisor.viewport.Height = g_GameManager.arcadeRegionSize.y;
        g_Supervisor.d3dDevice->SetViewport(&g_Supervisor.viewport);
        if (g_Supervisor.lockableBackbuffer && (this->curState != RETRY_MENU_OPENING || this->numFrames > 2))
        {
            g_AnmManager->DrawNoRotation(&this->menuBackground);
        }
        if (this->curState == RETRY_MENU_CURSOR_YES || this->curState == RETRY_MENU_CURSOR_NO)
        {
            this->menuSprites[RETRY_MENU_SPRITE_RETRIES_NUMBER] = this->menuSprites[RETRY_MENU_SPRITE_RETRIES_LABEL];
            this->menuSprites[RETRY_MENU_SPRITE_RETRIES_NUMBER].pos.x +=
                8.0f * this->menuSprites[RETRY_MENU_SPRITE_RETRIES_NUMBER].scaleX;
            this->menuSprites[RETRY_MENU_SPRITE_RETRIES_NUMBER].sprite =
                &g_AnmManager->sprites[30 - g_GameManager.numRetries];
            g_AnmManager->DrawNoRotation(&this->menuSprites[RETRY_MENU_SPRITE_RETRIES_NUMBER]);
        }
        for (idx = RETRY_MENU_SPRITES_START; idx < RETRY_MENU_SPRITES_END; idx++)
        {
            if (this->menuSprites[idx].flags.isVisible)
            {
                g_AnmManager->DrawNoRotation(&this->menuSprites[idx]);
            }
        }
    }
    return;
}
