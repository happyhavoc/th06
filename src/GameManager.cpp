#include "GameManager.hpp"
#include "Gui.hpp"
#include "ScreenEffect.hpp"
#include "SoundPlayer.hpp"
#include "Stage.hpp"
#include "Supervisor.hpp"
#include "utils.hpp"

#include <d3d8types.h>

DIFFABLE_STATIC(GameManager, g_GameManager);

#define GAME_REGION_TOP 16.0
#define GAME_REGION_LEFT 32.0

#define GAME_REGION_WIDTH 384.0
#define GAME_REGION_HEIGHT 448.0

#define MAX_SCORE 999999999

#define DEMO_FADEOUT_FRAMES 3600
#define DEMO_FRAMES 3720

#define GUI_SCORE_STEP 78910

const int EXTRA_LIVES_SCORES[5] = {10000000, 20000000, 40000000, 60000000, 1900000000};
#define MAX_LIVES 8

#pragma optimize("s", on)
GameManager::GameManager()
{

    memset(this, 0, sizeof(GameManager));

    (this->arcadeRegionTopLeftPos).x = GAME_REGION_LEFT;
    (this->arcadeRegionTopLeftPos).y = GAME_REGION_TOP;
    (this->arcadeRegionSize).x = GAME_REGION_WIDTH;
    (this->arcadeRegionSize).y = GAME_REGION_HEIGHT;
}
#pragma optimize("", on)

#pragma optimize("s", on)
void GameManager::IncreaseSubrank(i32 amount)
{
    this->subRank = this->subRank + amount;
    while (this->subRank >= 100)
    {
        this->rank++;
        this->subRank -= 100;
    }
    if (this->rank > this->maxRank)
    {
        this->rank = this->maxRank;
    }
}
#pragma optimize("", on)

#pragma optimize("s", on)
void GameManager::DecreaseSubrank(i32 amount)
{
    this->subRank = this->subRank - amount;
    while (this->subRank < 0)
    {
        this->rank--;
        this->subRank += 100;
    }
    if (this->rank < this->minRank)
    {
        this->rank = this->minRank;
    }
}
#pragma optimize("", on)

#pragma var_order(score_increment, is_in_menu)
#pragma optimize("s", on)
ChainCallbackResult GameManager::OnUpdate(GameManager *gameManager)
{
    u32 is_in_menu;
    u32 score_increment;

    if (gameManager->demoMode)
    {
        if (WAS_PRESSED(TH_BUTTON_ANY))
        {
            g_Supervisor.curState = SUPERVISOR_STATE_MAINMENU;
        }
        gameManager->demoFrames++;
        if (gameManager->demoFrames == DEMO_FADEOUT_FRAMES)
        {
            ScreenEffect::RegisterChain(SCREEN_EFFECT_FADE_OUT, 0x78, 0, 0, 0);
        }
        if (gameManager->demoFrames >= DEMO_FRAMES)
        {
            g_Supervisor.curState = SUPERVISOR_STATE_MAINMENU;
        }
    }
    if (!gameManager->isInRetryMenu && !gameManager->isInGameMenu && !gameManager->demoMode &&
        WAS_PRESSED(TH_BUTTON_MENU))
    {
        gameManager->isInGameMenu = 1;
        g_GameManager.arcadeRegionTopLeftPos.x = GAME_REGION_LEFT;
        g_GameManager.arcadeRegionTopLeftPos.y = GAME_REGION_TOP;
        g_GameManager.arcadeRegionSize.x = GAME_REGION_WIDTH;
        g_GameManager.arcadeRegionSize.y = GAME_REGION_HEIGHT;
        g_Supervisor.unk198 = 3;
    }

    if (!gameManager->isInRetryMenu && !gameManager->isInGameMenu)
    {
        is_in_menu = 1;
    }
    else
    {
        is_in_menu = 0;
    }

    gameManager->isInMenu = is_in_menu;

    g_Supervisor.viewport.X = gameManager->arcadeRegionTopLeftPos.x;
    g_Supervisor.viewport.Y = gameManager->arcadeRegionTopLeftPos.y;
    g_Supervisor.viewport.Width = gameManager->arcadeRegionSize.x;
    g_Supervisor.viewport.Height = gameManager->arcadeRegionSize.y;
    g_Supervisor.viewport.MinZ = 0.5;
    g_Supervisor.viewport.MaxZ = 1.0;

    SetupCamera(0);

    g_Supervisor.d3dDevice->SetViewport(&g_Supervisor.viewport);
    g_Supervisor.d3dDevice->Clear(0, NULL, D3DCLEAR_ZBUFFER, g_Stage.skyFog.color, 1.0, 0);

    // Seems like gameManager->isInGameMenu was supposed to have 3 states, but all the times it ends up checking both
    if (gameManager->isInGameMenu == 1 || gameManager->isInGameMenu == 2 || gameManager->isInRetryMenu)
    {
        return CHAIN_CALLBACK_RESULT_BREAK;
    }
    else
    {
        if (gameManager->score >= MAX_SCORE + 1)
        {
            gameManager->score = MAX_SCORE - 9;
        }
        if (gameManager->guiScore != gameManager->score)
        {
            if (gameManager->score < gameManager->guiScore)
            {
                gameManager->score = gameManager->guiScore;
            }

            score_increment = (gameManager->score - gameManager->guiScore) >> 5;
            if (score_increment >= GUI_SCORE_STEP)
            {
                score_increment = GUI_SCORE_STEP;
            }
            else if (score_increment < 10)
            {
                score_increment = 10;
            }
            score_increment = score_increment - score_increment % 10;

            if (gameManager->nextScoreIncrement < score_increment)
            {
                gameManager->nextScoreIncrement = score_increment;
            }
            if (gameManager->guiScore + gameManager->nextScoreIncrement > gameManager->score)
            {
                gameManager->nextScoreIncrement = gameManager->score - gameManager->guiScore;
            }

            gameManager->guiScore += gameManager->nextScoreIncrement;
            if (gameManager->guiScore >= gameManager->score)
            {
                gameManager->nextScoreIncrement = 0;
                gameManager->guiScore = gameManager->score;
            }
            if (gameManager->extraLives >= 0 && EXTRA_LIVES_SCORES[gameManager->extraLives] <= gameManager->guiScore)
            {
                if (gameManager->livesRemaining < MAX_LIVES)
                {
                    gameManager->livesRemaining++;
                    g_SoundPlayer.PlaySoundByIdx(0x1c, 0);
                }
                g_Gui.flags = g_Gui.flags & 0xfffffffc | 2;
                gameManager->extraLives++;
                g_GameManager.IncreaseSubrank(200);
            }
            if (gameManager->highScore < gameManager->guiScore)
            {
                gameManager->highScore = gameManager->guiScore;
            }
        }
        gameManager->gameFrames++;
        return CHAIN_CALLBACK_RESULT_CONTINUE;
    }
}
#pragma optimize("", on)
