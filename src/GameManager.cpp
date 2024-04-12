#include "GameManager.hpp"

DIFFABLE_STATIC(GameManager, g_GameManager);

#define GAME_REGION_TOP 16.0
#define GAME_REGION_LEFT 32.0

#define GAME_REGION_WIDTH 384.0
#define GAME_REGION_HEIGHT 448.0

#pragma optimize("s", on)
GameManager::GameManager()
{

    memset(this, 0, sizeof(GameManager));

    (this->arcadeRegionTopLeftPos).x = GAME_REGION_LEFT;
    (this->arcadeRegionTopLeftPos).y = GAME_REGION_TOP;
    (this->arcadeRegionSize).x = GAME_REGION_WIDTH;
    (this->arcadeRegionSize).y = GAME_REGION_HEIGHT;
}
#pragma optimize("", on)

#pragma optimize("s", on)
void GameManager::IncreaseSubrank(i32 amount)
{
    this->subRank = this->subRank + amount;
    while (this->subRank >= 100)
    {
        this->rank++;
        this->subRank -= 100;
    }
    if (this->rank > this->maxRank)
    {
        this->rank = this->maxRank;
    }
}
#pragma optimize("", on)

#pragma optimize("s", on)
void GameManager::DecreaseSubrank(i32 amount)
{
    this->subRank = this->subRank - amount;
    while (this->subRank < 0)
    {
        this->rank--;
        this->subRank += 100;
    }
    if (this->rank < this->minRank)
    {
        this->rank = this->minRank;
    }
}
#pragma optimize("", on)
