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

struct GameManager
{
    GameManager();
    static ZunResult RegisterChain();
    static void CutChain();
    static ChainCallbackResult OnUpdate(GameManager *gameManager);
    i32 hasReachedMaxClears(i32 character, i32 shottype);
    void IncreaseSubrank(i32 amount);
    void DecreaseSubrank(i32 amount);

    u32 guiScore;
    u32 score;
    u32 nextScoreIncrement;
    u32 highScore;
    Difficulty difficulty;
    u32 grazeInStage;
    u32 unk_18;
    u32 unk_1c;
    u32 unk_20;
    u32 unk_24;
    u32 unk_28;
    u32 unk_2c;
    u8 catk[0x1000];
    Clrd clrd[4];
    Pscr pscr[96];
    u16 currentPower;
    i8 unk_1812;
    i8 unk_1813;
    u16 pointItemsCollectedInStage;
    i8 unk_1816;
    i8 unk_1817;
    i8 numRetries;
    i8 powerItemCountForScore;
    i8 livesRemaining;
    i8 bombsRemaining;
    i8 extraLives;
    u8 character;
    u8 shotType;
    u8 isInGameMenu;
    u8 isInRetryMenu;
    u8 isInMenu;
    i8 unk_1822;
    u8 unk_1823;
    u8 demoMode;
    i8 unk_1825;
    i8 unk_1826;
    i8 unk_1827;
    i32 demoFrames;
    i8 replayFile[256];
    i8 unk_192c[256];
    i32 unk_1a2c;
    u32 gameFrames;
    i32 currentStage;
    u32 menuCursorBackup;
    D3DXVECTOR2 arcadeRegionTopLeftPos;
    D3DXVECTOR2 arcadeRegionSize;
    f32 unk_1a4c;
    f32 unk_1a50;
    f32 unk_1a54;
    f32 unk_1a58;
    i32 unk_1a5c;
    D3DXVECTOR3 stageCameraFacingDir;
    u32 counat;
    i32 rank;
    i32 maxRank;
    i32 minRank;
    i32 subRank;
};
C_ASSERT(sizeof(GameManager) == 0x1a80);

DIFFABLE_EXTERN(GameManager, g_GameManager);

void SetupCamera(float);