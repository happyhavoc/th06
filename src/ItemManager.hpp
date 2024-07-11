#pragma once

#include "AnmVm.hpp"
#include "ZunTimer.hpp"
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
    ITEM_NO_ITEM = 0xffffffff,
};

struct Item
{
    AnmVm sprite;
    D3DXVECTOR3 currentPosition;
    D3DXVECTOR3 startPosition;
    D3DXVECTOR3 targetPosition;
    ZunTimer timer;
    u8 itemType;
    u8 isInUse;
    u8 unk_142;
    u8 state;
};
C_ASSERT(sizeof(Item) == 0x144);

struct ItemManager
{
    void SpawnItem(D3DXVECTOR3 *position, ItemType type, i32 state);

    Item items[512];
    Item dummyItemForFailedSpawns;
    u32 nextIndex;
    u32 itemCount;
};
C_ASSERT(sizeof(ItemManager) == 0x2894c);

DIFFABLE_EXTERN(ItemManager, g_ItemManager);
