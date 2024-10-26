#pragma once

#include "AnmVm.hpp"
#include "ZunTimer.hpp"
#include "inttypes.hpp"

namespace th06
{
struct Effect;

typedef i32 (*EffectUpdateCallback)(Effect *);
struct Effect
{
    AnmVm vm;
    D3DXVECTOR3 pos1;
    D3DXVECTOR3 unk_11c;
    D3DXVECTOR3 unk_128;
    D3DXVECTOR3 position;
    D3DXVECTOR3 pos2;
    D3DXQUATERNION quaternion;
    f32 unk_15c;
    f32 angleRelated;
    ZunTimer timer;
    i32 unk_170;
    EffectUpdateCallback updateCallback;
    i8 inUseFlag;
    i8 effectId;
    i8 unk_17a;
    i8 unk_17b;
};
C_ASSERT(sizeof(Effect) == 0x17c);

struct EffectInfo
{
    i32 anmIdx;
    EffectUpdateCallback updateCallback;
};
C_ASSERT(sizeof(EffectInfo) == 0x8);
}; // namespace th06
