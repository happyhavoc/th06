#pragma once

#include <Windows.h>

#include "diffbuild.hpp"
#include "inttypes.hpp"

struct GameManager
{
    u8 padding[0x181f];
    bool isInGameMenu;
    bool isInRetryMenu;
    bool isInMenu;
    u8 padding2[0x25e];
};
C_ASSERT(sizeof(GameManager) == 0x1a80);

DIFFABLE_EXTERN(GameManager, g_GameManager);
