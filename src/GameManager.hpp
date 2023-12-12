#pragma once

#include "diffbuild.hpp"
#include "inttypes.hpp"

struct GameManager
{
    u8 padding[0x181f];
    bool isInGameMenu;
    bool isInRetryMenu;
};

DIFFABLE_EXTERN(GameManager, g_GameManager);
