#pragma once

#include "Chain.hpp"
#include "Effect.hpp"
#include "inttypes.hpp"
#include "ZunResult.hpp"

struct EffectManager {
    i32 nextIndex;
    EffectManager* nextManager;
    Effect effects[512];
    Effect dummyEffect;
    
    static ZunResult RegisterChain();
    static ChainCallbackResult OnUpdate(EffectManager* mgr);
    static ZunResult AddedCallback(EffectManager* mgr);
    static ZunResult DeletedCallback(EffectManager* mgr);
    static ChainCallbackResult OnDraw(EffectManager* mgr);
    void Reset();
};
C_ASSERT(sizeof(EffectManager) == 0x2f984);

DIFFABLE_EXTERN(EffectManager, g_EffectManager);
