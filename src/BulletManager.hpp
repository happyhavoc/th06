#pragma once

#include "ZunBool.hpp"
#include "ZunResult.hpp"
#include "diffbuild.hpp"
#include "inttypes.hpp"

struct BulletManager
{
    static ZunResult RegisterChain(char *bulletAnmFile);

    void RemoveAllBullets(ZunBool turnIntoItem);
};

DIFFABLE_EXTERN(BulletManager, g_BulletManager);
