#include "GameManager.hpp"

DIFFABLE_STATIC(GameManager, g_GameManager);

#pragma optimize("s", on)
GameManager::GameManager()
{

    memset(this, 0, sizeof(GameManager));

    (this->arcadeRegionTopLeftPos).x = 32.0;
    (this->arcadeRegionTopLeftPos).y = 16.0;
    (this->arcadeRegionSize).x = 384.0;
    (this->arcadeRegionSize).y = 448.0;
}
#pragma optimize("s", off)
