#pragma once

#include <Windows.h>
#include <d3d8.h>
#include <d3dx8math.h>

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
    static ZunResult RegisterChain();
    static void CutChain();
    i32 hasReachedMaxClears(i32 character, i32 shottype);

    u8 padding[0xf];
    Difficulty difficulty;
    u32 grazeInStage;
    u32 unk_18;
    u32 unk_1c;
    u32 padding[4];
    u8 catk[64][0x1000 / 64];
    u8 clrd[4][0x60 / 4];
    u8 pscr[96][0x780 / 96];
    u16 currentPower;
    u16 unk_1812;
    u16 pointItemsCollectedInStage;
    u16 unk_1816;
    u8 numRetries;
    u8 powerItemCountForScore;
    u8 livesRemaining;
    u8 bombsRemaining;
    u8 unk_181c;
    u8 character;
    u8 shottype;
    bool isInGameMenu;
    bool isInRetryMenu;
    bool isInMenu;
    u8 unk_1822;
    u8 unk_1823;
    bool demoMode;
    u8 padding2[7];
    char replayFile[256];
    u8 unk_192c[256];
    u16 unk_1a2c;
    u8 padding3[2];
    u32 unk_1a30;
    i32 currentStage;
    i32 unk_1a38;
    D3DXVECTOR2 arcadeRegionTopLeft;
    D3DXVECTOR2 arcadeRegionSize;
    f32 padding4[4];
    u8 padding5[4];
    D3DXVECTOR3 stageCameraFacingDir;
    u32 counat;
    u32 rank;
    u32 maxRank;
    u32 minRank;
    u32 subRank;
};

C_ASSERT(sizeof(GameManager) == 0x1a80);

DIFFABLE_EXTERN(GameManager, g_GameManager);
