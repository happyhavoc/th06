#pragma once

#include "Chain.hpp"
#include "Effect.hpp"
#include "ZunColor.hpp"
#include "ZunResult.hpp"
#include "inttypes.hpp"

struct EffectManager
{
    i32 nextIndex;
    i32 activeEffects;
    Effect effects[512];
    Effect dummyEffect;

    static ZunResult RegisterChain();
    static ChainCallbackResult OnUpdate(EffectManager *mgr);
    static ZunResult AddedCallback(EffectManager *mgr);
    static ZunResult DeletedCallback(EffectManager *mgr);
    static ChainCallbackResult OnDraw(EffectManager *mgr);
    void Reset();
    Effect *SpawnParticles(i32 effectIdx, D3DXVECTOR3 *pos, i32 count, ZunColor color);
};
C_ASSERT(sizeof(EffectManager) == 0x2f984);

DIFFABLE_EXTERN(EffectManager, g_EffectManager);
