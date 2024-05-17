#pragma once

#include "diffbuild.hpp"
#include "inttypes.hpp"

#include <d3dx8math.h>

enum ItemType // This enum is 1 byte in size on Enemy
{
    ITEM_POWER_SMALL,
    ITEM_POINT,
    ITEM_POWER_BIG,
    ITEM_BOMB,
    ITEM_FULL_POWER,
    ITEM_LIFE,
    ITEM_POINT_BULLET,
    ITEM_NO_ITEM
};

struct ItemManager
{
    void SpawnItem(D3DXVECTOR3 *position, ItemType type, i32 state);
};

DIFFABLE_EXTERN(ItemManager, g_ItemManager);
