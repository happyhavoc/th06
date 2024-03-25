#pragma once

#include <Windows.h>

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
    u8 padding2[0x180a];
    bool isInGameMenu;
    bool isInRetryMenu;
    bool isInMenu;
    u8 padding3[2];
    u8 unk_1823;
    u8 padding4[0x25b];
};
C_ASSERT(sizeof(GameManager) == 0x1a80);

DIFFABLE_EXTERN(GameManager, g_GameManager);
