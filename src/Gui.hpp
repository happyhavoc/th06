#pragma once

#include "diffbuild.hpp"
#include "inttypes.hpp"
#include <Windows.h>

struct Gui
{

    u32 flags;
    void *impl; // TODO:GuiImpl
    f32 unk_8;
    f32 blueSpellcardBarLength;
    u32 unk_10;
    i32 eclSetLives;
    i32 eclSpellcardRelated;
    i32 unk_1c;
    bool bossPresent;
    float bossHealthBar1;
    float bossHealthBar2;
};
C_ASSERT(sizeof(Gui) == 0x2c);

DIFFABLE_EXTERN(Gui, g_Gui);