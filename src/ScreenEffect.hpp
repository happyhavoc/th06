#pragma once

#include <Windows.h>
#include <d3d8types.h>

#include "ZunResult.hpp"
#include "inttypes.hpp"

enum ScreenEffects
{
    SCREEN_EFFECT_UNK_0,
    SCREEN_EFFECT_UNK_1,
    SCREEN_EFFECT_FADE_OUT,
};

struct ScreenEffect
{
    static ZunResult RegisterChain(u32 screenEffect, u32 param1, u32 param2, u32 param3, u32 param4);
};

void SetViewport(D3DCOLOR color);
