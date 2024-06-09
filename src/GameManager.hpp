#pragma once

#include <Windows.h>
#include <d3d8.h>
#include <d3dx8math.h>

#include "Chain.hpp"
#include "ResultScreen.hpp"
#include "ZunResult.hpp"
#include "diffbuild.hpp"
#include "inttypes.hpp"

enum Difficulty
{
    EASY,
    NORMAL,
    HARD,
    LUNATIC,
    EXTRA,
};

enum StageNumber
{
    STAGE1,
    STAGE2,
    STAGE3,
    STAGE4,
    STAGE5,
    FINAL_STAGE,
    EXTRA_STAGE,
};

#define PSCR_NUM_CHARS_SHOTTYPES 4
#define PSCR_NUM_STAGES 6
#define PSCR_NUM_DIFFICULTIES 4

#define GAME_REGION_TOP 16.0
#define GAME_REGION_LEFT 32.0

#define GAME_REGION_WIDTH 384.0
#define GAME_REGION_HEIGHT 448.0

struct GameManager
{
    GameManager();
    static ZunResult RegisterChain();
    static void CutChain();
    static ChainCallbackResult OnUpdate(GameManager *gameManager);
    static ChainCallbackResult OnDraw(GameManager *gameManager);
    static ZunResult AddedCallback(GameManager *gameManager);
    static ZunResult DeletedCallback(GameManager *gameManager);

    i32 HasReachedMaxClears(i32 character, i32 shottype);
    void IncreaseSubrank(i32 amount);
    void DecreaseSubrank(i32 amount);
    i32 IsInBounds(f32 x, f32 y, f32 width, f32 height);

    u32 guiScore;
    u32 score;
    u32 nextScoreIncrement;
    u32 highScore;
    Difficulty difficulty;
    u32 grazeInStage;
    u32 grazeInTotal;
    u32 isInReplay;
    u32 deaths;
    u32 bombsUsed;
    u32 unk_28;
    i8 isTimeStopped;
    Catk catk[64];
    Clrd clrd[4];
    Pscr pscr[PSCR_NUM_CHARS_SHOTTYPES][PSCR_NUM_STAGES][PSCR_NUM_DIFFICULTIES];
    u16 currentPower;
    i8 unk_1812;
    i8 unk_1813;
    u16 pointItemsCollectedInStage;
    u16 unk_1816;
    u8 numRetries;
    i8 powerItemCountForScore;
    i8 livesRemaining;
    i8 bombsRemaining;
    i8 extraLives;
    u8 character;
    u8 shotType;
    u8 isInGameMenu;
    u8 isInRetryMenu;
    u8 isInMenu;
    i8 isGameCompleted;
    u8 isInPracticeMode;
    u8 demoMode;
    i8 unk_1825;
    i8 unk_1826;
    i8 unk_1827;
    i32 demoFrames;
    i8 replayFile[256];
    i8 unk_192c[256];
    u16 randomSeed;
    u32 gameFrames;
    i32 currentStage;
    u32 menuCursorBackup;
    D3DXVECTOR2 arcadeRegionTopLeftPos;
    D3DXVECTOR2 arcadeRegionSize;
    D3DXVECTOR2 playerMovementAreaTopLeftPos;
    D3DXVECTOR2 playerMovementAreaSize;
    f32 cameraDistance;
    D3DXVECTOR3 stageCameraFacingDir;
    u32 counat;
    i32 rank;
    i32 maxRank;
    i32 minRank;
    i32 subRank;
};
C_ASSERT(sizeof(GameManager) == 0x1a80);

DIFFABLE_EXTERN(GameManager, g_GameManager);

void SetupCamera(f32);
void SetupCameraStageBackground(f32);
