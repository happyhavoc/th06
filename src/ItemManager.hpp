#include "inttypes.hpp"

enum ItemType // This enum is 1 byte in size on Enemy
{
    ITEM_POWER_SMALL = 0,
    ITEM_POINT = 1,
    ITEM_POWER_BIG = 2,
    ITEM_BOMB = 3,
    ITEM_FULL_POWER = 4,
    ITEM_LIFE = 5,
    ITEM_POINT_BULLET = 6,
    ITEM_NO_ITEM = 7
};