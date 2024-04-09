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

#pragma optimize("s", on)
void GameManager::IncreaseSubrank(i32 amount)
{
    this->subRank = this->subRank + amount;
    while (this->subRank >= 100)
    {
        this->rank++;
        this->subRank = this->subRank - 100;
    }
    if ((this->rank > this->maxRank))
    {
        this->rank = this->maxRank;
    }
    return;
}
#pragma optimize("s", off)

#pragma optimize("s", on)
void GameManager::DecreaseSubrank(i32 amount)
{
    this->subRank = this->subRank - amount;
    while (this->subRank < 0)
    {
        this->rank--;
        this->subRank = this->subRank + 100;
    }
    if (this->rank < this->minRank)
    {
        this->rank = this->minRank;
    }
    return;
}
#pragma optimize("s", off)
