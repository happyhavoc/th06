#include "ItemManager.hpp"

#include "AnmManager.hpp"
#include "Rng.hpp"
#include "utils.hpp"

#include <d3dx8math.h>

namespace th06
{
DIFFABLE_STATIC(ItemManager, g_ItemManager);

void ItemManager::SpawnItem(D3DXVECTOR3 *position, ItemType itemType, int state)
{
    Item *item;
    i32 idx;

    item = &this->items[this->nextIndex];
    for (idx = 0; idx < ARRAY_SIZE_SIGNED(this->items); idx++)
    {
        this->nextIndex++;
        if (item->isInUse)
        {
            if (this->nextIndex >= ARRAY_SIZE_SIGNED(this->items))
            {
                this->nextIndex = 0;
                item = &this->items[0];
            }
            else
            {
                item++;
            }
            continue;
        }
        if (this->nextIndex >= ARRAY_SIZE_SIGNED(this->items))
        {
            this->nextIndex = 0;
        }
        item->isInUse = 1;
        item->currentPosition = *position;
        item->startPosition.x = 0.0f;
        item->startPosition.y = -2.2f;
        item->startPosition.z = 0.0f;
        item->itemType = itemType;
        item->state = state;
        item->timer.InitializeForPopup();
        if (state == 2)
        {
            // From 48.0f to 336.0f
            item->targetPosition.x = g_Rng.GetRandomF32ZeroToOne() * 288.0f + 48.0f;
            // From -64.0 to 128.0f
            item->targetPosition.y = g_Rng.GetRandomF32ZeroToOne() * 192.0f - 64.0f;
            item->targetPosition.z = 0.0;
            item->startPosition = item->currentPosition;
        }
        g_AnmManager->SetAndExecuteScriptIdx(&item->sprite, ANM_SCRIPT_BULLET3_ITEMS_START + itemType);
        item->sprite.color = COLOR_WHITE;
        item->unk_142 = 1;
        return;
    }
    return;
}
}; // namespace th06
