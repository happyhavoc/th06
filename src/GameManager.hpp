#pragma once

#include <Windows.h>

#include "diffbuild.hpp"
#include "inttypes.hpp"

struct GameManager
{
    u8 padding[0x181f];
    bool isInGameMenu;
    bool isInRetryMenu;
    u8 padding2[0x25f];
};
C_ASSERT(sizeof(GameManager) == 0x1a80);

DIFFABLE_EXTERN(GameManager, g_GameManager);
