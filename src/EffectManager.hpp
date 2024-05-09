#pragma once

#include "Effect.hpp"
#include "inttypes.hpp"
#include "ZunResult.hpp"

struct EffectManager {
    i32 nextIndex;
    EffectManager* nextManager;
    Effect effects[512];
    Effect dummyEffect;
    
    static ZunResult AddedCallback(EffectManager* mgr);
    void Reset();
};
C_ASSERT(sizeof(EffectManager) == 0x2f984);
