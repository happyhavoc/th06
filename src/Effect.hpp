#pragma once

#include "AnmVm.hpp"
#include "ZunTimer.hpp"
#include "inttypes.hpp"

struct Effect
{
    AnmVm vm;
    D3DXVECTOR3 pos1;
    f32 unk_11c;
    f32 unk_120;
    f32 unk_124;
    f32 unk_128;
    f32 unk_12c;
    f32 unk_130;
    D3DXVECTOR3 position;
    D3DXVECTOR3 pos2;
    D3DXQUATERNION quaternion;
    f32 unk_15c;
    f32 angleRelated;
    ZunTimer timer;
    i32 unk_170;
    i32 *effectUpdateCallback;
    i8 inUseFlag;
    i8 effectId;
    i8 unk_17a;
    i8 unk_17b;
};
C_ASSERT(sizeof(Effect) == 0x17c);
