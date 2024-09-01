#pragma once

#include "AnmVm.hpp"
#include "inttypes.hpp"

struct StageMenu
{
    StageMenu();

    i32 OnUpdateGameMenu();
    i32 OnUpdateRetryMenu();

    void OnDrawGameMenu();
    void OnDrawRetryMenu();

    // Current state of this menu.
    u32 curState;
    // Number of frames since last state change. Used to delay certain actions
    // until an animation is finished.
    u32 numFrames;
    AnmVm vms0[6];
    AnmVm vm1;
};
C_ASSERT(sizeof(StageMenu) == 0x778);
