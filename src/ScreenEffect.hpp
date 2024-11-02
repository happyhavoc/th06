#pragma once

#include <Windows.h>
#include <d3d8types.h>
#include <string.h>

#include "ZunResult.hpp"
#include "inttypes.hpp"
#include "Chain.hpp"
#include "ZunTimer.hpp"

namespace th06
{
struct ZunRect
{
    f32 left;
    f32 top;
    f32 right;
    f32 bottom;
};

enum ScreenEffects
{
    SCREEN_EFFECT_FADE_IN,
    SCREEN_EFFECT_SHAKE,
    SCREEN_EFFECT_FADE_OUT,
};

struct ScreenEffect
{
    // In fade effects, effectParam1 is an RGB color to fade to. In the shake effect, params 1 and 2 control shakiness
    static ScreenEffect *RegisterChain(u32 effect, u32 ticks, u32 effectParam1, u32 effectParam2,
                                       u32 unusedEffectParam);
    
    ZunResult AddedCallback(ScreenEffect *effect);
    ZunResult DeletedCallback(ScreenEffect *effect);

    ChainCallbackResult DrawFadeIn(ScreenEffect *effect);
    ChainCallbackResult CalcFadeIn(ScreenEffect *effect);
    ChainCallbackResult ShakeScreen(ScreenEffect *effect);
    ChainCallbackResult DrawFadeOut(ScreenEffect *effect);
    ChainCallbackResult CalcFadeOut(ScreenEffect *effect);

    static void DrawSquare(ZunRect *rect, D3DCOLOR rectColor);
    static void Clear(D3DCOLOR color);
    static void SetViewport(D3DCOLOR color);

    enum ScreenEffects usedEffect;
    ChainElem *calcChainElement;
    ChainElem *drawChainElement;
    u32 unused;
    i32 fadeAlpha;
    i32 effectLength;
    i32 genericParam; // effectParam1
    i32 shakinessParam; // effectParam2
    ZunTimer timer;
};
}; // namespace th06
