#include "BulletManager.hpp"
#include "AnmManager.hpp"
#include "Chain.hpp"
#include "ChainPriorities.hpp"
#include "GameManager.hpp"
#include "ItemManager.hpp"
#include "Player.hpp"
#include "ZunColor.hpp"
#include "ZunMath.hpp"
#include "utils.hpp"

DIFFABLE_STATIC(BulletManager, g_BulletManager);
DIFFABLE_STATIC(ChainElem, g_BulletManagerCalcChain);
DIFFABLE_STATIC(ChainElem, g_BulletManagerDrawChain);
DIFFABLE_STATIC_ARRAY_ASSIGN(u32, 28, g_EffectsColorWithTextureBlending) = {
    0xff000000, 0xff303030, 0xff606060, 0xff500000, 0xff900000, 0xffff2020, 0xff400040,
    0xff800080, 0xffff30ff, 0xff000050, 0xff000090, 0xff2020ff, 0xff203060, 0xff304090,
    0xff3080ff, 0xff005000, 0xff009000, 0xff20ff20, 0xff206000, 0xff409010, 0xff80ff20,
    0xff505000, 0xff909000, 0xffffff20, 0xff603000, 0xff904010, 0xfff08020, 0xffffffff};

DIFFABLE_STATIC_ARRAY_ASSIGN(u32, 28, g_EffectsColorWithoutTextureBlending) = {
    0xfff0f0f0, 0xfff0f0f0, 0xffffffff, 0xffffe0e0, 0xffffe0e0, 0xffffe0e0, 0xffffe0ff,
    0xffffe0ff, 0xffffe0ff, 0xffe0e0ff, 0xffe0e0ff, 0xffe0e0ff, 0xffe0ffff, 0xffe0ffff,
    0xffe0ffff, 0xffe0ffe0, 0xffe0ffe0, 0xffe0ffe0, 0xffe0ffe0, 0xffe0ffe0, 0xffe0ffe0,
    0xffffffe0, 0xffffffe0, 0xffffffe0, 0xffffe0e0, 0xffffe0e0, 0xffffe0e0, 0xffffffff};
DIFFABLE_STATIC_ASSIGN(u32 *, g_EffectsColor) = g_EffectsColorWithTextureBlending;

struct BulletTypeInfo
{
    u32 bulletAnmScriptIdx;
    u32 bulletSpawnEffectFastAnmScriptIdx;
    u32 bulletSpawnEffectNormalAnmScriptIdx;
    u32 bulletSpawnEffectSlowAnmScriptIdx;
    u32 bulletSpawnEffectDonutAnmScriptIdx;
};

#define ASB3(x) ANM_SCRIPT_BULLET3_##x
#define ASB4(x) ANM_SCRIPT_BULLET4_##x
DIFFABLE_STATIC_ARRAY_ASSIGN(BulletTypeInfo, 10, g_BulletTypeInfos) = {
    {ASB3(PELLET), ASB3(SPAWN_PELLET_FAST), ASB3(SPAWN_PELLET_NORMAL), ASB3(SPAWN_PELLET_SLOW),
     ASB3(SPAWN_DONUT_SMALL)},
    {ASB3(RING_BALL), ASB3(SPAWN_BIG_BALL_FAST), ASB3(SPAWN_BIG_BALL_NORMAL), ASB3(SPAWN_BIG_BALL_SLOW),
     ASB3(SPAWN_DONUT_MEDIUM)},
    {ASB3(RICE), ASB3(SPAWN_BIG_BALL_FAST), ASB3(SPAWN_BIG_BALL_NORMAL), ASB3(SPAWN_BIG_BALL_SLOW),
     ASB3(SPAWN_DONUT_MEDIUM)},
    {ASB3(BALL), ASB3(SPAWN_BIG_BALL_FAST), ASB3(SPAWN_BIG_BALL_NORMAL), ASB3(SPAWN_BIG_BALL_SLOW),
     ASB3(SPAWN_DONUT_MEDIUM)},
    {ASB3(KUNAI), ASB3(SPAWN_BIG_BALL_FAST), ASB3(SPAWN_BIG_BALL_NORMAL), ASB3(SPAWN_BIG_BALL_SLOW),
     ASB3(SPAWN_DONUT_MEDIUM)},
    {ASB3(SHARD), ASB3(SPAWN_BIG_BALL_FAST), ASB3(SPAWN_BIG_BALL_NORMAL), ASB3(SPAWN_BIG_BALL_SLOW),
     ASB3(SPAWN_DONUT_MEDIUM)},
    {ASB3(BIG_BALL), ASB3(SPAWN_BIG_BALL_HUGE), ASB3(SPAWN_BIG_BALL_HUGE), ASB3(SPAWN_BIG_BALL_HUGE),
     ASB3(SPAWN_DONUT_BIG)},
    {ASB3(FIREBALL), ASB3(SPAWN_BIG_BALL_HUGE), ASB3(SPAWN_BIG_BALL_HUGE), ASB3(SPAWN_BIG_BALL_HUGE),
     ASB3(SPAWN_DONUT_BIG)},
    {ASB3(DAGGER), ASB3(SPAWN_BIG_BALL_HUGE), ASB3(SPAWN_BIG_BALL_HUGE), ASB3(SPAWN_BIG_BALL_HUGE),
     ASB3(SPAWN_DONUT_BIG)},
    {ASB4(BUBBLE), ASB4(SPAWN_BUBBLE_SLOW), ASB4(SPAWN_BUBBLE_SLOW), ASB4(SPAWN_BUBBLE_SLOW),
     ASB4(SPAWN_BUBBLE_NORMAL)},
};

ZunResult BulletManager::RegisterChain(char *bulletAnmPath)
{
    BulletManager *mgr = &g_BulletManager;
    if (((g_Supervisor.cfg.opts >> GCOS_USE_D3D_HW_TEXTURE_BLENDING) & 1) == 0)
    {
        g_EffectsColor = g_EffectsColorWithTextureBlending;
    }
    else
    {
        g_EffectsColor = g_EffectsColorWithoutTextureBlending;
    }
    mgr->InitializeToZero();
    mgr->bulletAnmPath = bulletAnmPath;
    g_BulletManagerCalcChain.callback = (ChainCallback)BulletManager::OnUpdate;
    g_BulletManagerCalcChain.addedCallback = NULL;
    g_BulletManagerCalcChain.deletedCallback = NULL;
    g_BulletManagerCalcChain.addedCallback = (ChainAddedCallback)BulletManager::AddedCallback;
    g_BulletManagerCalcChain.deletedCallback = (ChainDeletedCallback)BulletManager::DeletedCallback;
    g_BulletManagerCalcChain.arg = mgr;
    if (g_Chain.AddToCalcChain(&g_BulletManagerCalcChain, TH_CHAIN_PRIO_CALC_BULLETMANAGER) != ZUN_SUCCESS)
    {
        return ZUN_ERROR;
    }
    g_BulletManagerDrawChain.callback = (ChainCallback)BulletManager::OnDraw;
    g_BulletManagerDrawChain.addedCallback = NULL;
    g_BulletManagerDrawChain.deletedCallback = NULL;
    g_BulletManagerDrawChain.arg = mgr;
    g_Chain.AddToDrawChain(&g_BulletManagerDrawChain, TH_CHAIN_PRIO_DRAW_BULLETMANAGER);
    return ZUN_SUCCESS;
}

#define ZUN_MIN(x, y) ((x) > (y) ? (y) : (x))

ZunResult BulletManager::AddedCallback(BulletManager *mgr)
{
    u32 idx;

    if ((ZunBool)(g_Supervisor.curState != SUPERVISOR_STATE_GAMEMANAGER_REINIT))
    {
        if (g_AnmManager->LoadAnm(ANM_FILE_BULLET3, "data/etama3.anm", ANM_OFFSET_BULLET3) != ZUN_SUCCESS)
        {
            return ZUN_ERROR;
        }
        if (g_AnmManager->LoadAnm(ANM_FILE_BULLET4, "data/etama4.anm", ANM_OFFSET_BULLET4) != ZUN_SUCCESS)
        {
            return ZUN_ERROR;
        }
    }
    for (idx = 0; idx < 10; idx++)
    {
        g_AnmManager->SetAndExecuteScriptIdx(&mgr->bulletTypeTemplates[idx].spriteBullet,
                                             g_BulletTypeInfos[idx].bulletAnmScriptIdx);
        g_AnmManager->SetAndExecuteScriptIdx(&mgr->bulletTypeTemplates[idx].spriteSpawnEffectFast,
                                             g_BulletTypeInfos[idx].bulletSpawnEffectFastAnmScriptIdx);
        g_AnmManager->SetAndExecuteScriptIdx(&mgr->bulletTypeTemplates[idx].spriteSpawnEffectNormal,
                                             g_BulletTypeInfos[idx].bulletSpawnEffectNormalAnmScriptIdx);
        g_AnmManager->SetAndExecuteScriptIdx(&mgr->bulletTypeTemplates[idx].spriteSpawnEffectSlow,
                                             g_BulletTypeInfos[idx].bulletSpawnEffectSlowAnmScriptIdx);
        g_AnmManager->SetAndExecuteScriptIdx(&mgr->bulletTypeTemplates[idx].spriteSpawnEffectDonut,
                                             g_BulletTypeInfos[idx].bulletSpawnEffectDonutAnmScriptIdx);
        mgr->bulletTypeTemplates[idx].spriteBullet.baseSpriteIndex =
            mgr->bulletTypeTemplates[idx].spriteBullet.activeSpriteIndex;
        mgr->bulletTypeTemplates[idx].bulletHeight = mgr->bulletTypeTemplates[idx].spriteBullet.sprite->heightPx;
        if (mgr->bulletTypeTemplates[idx].spriteBullet.sprite->heightPx <= 8.0f)
        {
            mgr->bulletTypeTemplates[idx].grazeSize.x = 4.0f;
            mgr->bulletTypeTemplates[idx].grazeSize.y = 4.0f;
        }
        else if (mgr->bulletTypeTemplates[idx].spriteBullet.sprite->heightPx <= 16.0f)
        {
            switch (g_BulletTypeInfos[idx].bulletAnmScriptIdx)
            {
            case ANM_SCRIPT_BULLET3_RICE:
                mgr->bulletTypeTemplates[idx].grazeSize.x = 4.0f;
                mgr->bulletTypeTemplates[idx].grazeSize.y = 4.0f;
                break;
            case ANM_SCRIPT_BULLET3_KUNAI:
                mgr->bulletTypeTemplates[idx].grazeSize.x = 5.0f;
                mgr->bulletTypeTemplates[idx].grazeSize.y = 5.0f;
                break;
            case ANM_SCRIPT_BULLET3_SHARD:
                mgr->bulletTypeTemplates[idx].grazeSize.x = 4.0f;
                mgr->bulletTypeTemplates[idx].grazeSize.y = 4.0f;
                break;
            default:
                mgr->bulletTypeTemplates[idx].grazeSize.x = 6.0f;
                mgr->bulletTypeTemplates[idx].grazeSize.y = 6.0f;
                break;
            }
        }
        else if (mgr->bulletTypeTemplates[idx].spriteBullet.sprite->heightPx <= 32.0f)
        {
            switch (g_BulletTypeInfos[idx].bulletAnmScriptIdx)
            {
            case ANM_SCRIPT_BULLET3_FIREBALL:
                mgr->bulletTypeTemplates[idx].grazeSize.x = 11.0f;
                mgr->bulletTypeTemplates[idx].grazeSize.y = 11.0f;
                break;
            case ANM_SCRIPT_BULLET3_DAGGER:
                mgr->bulletTypeTemplates[idx].grazeSize.x = 9.0f;
                mgr->bulletTypeTemplates[idx].grazeSize.y = 9.0f;
                break;
            default:
                mgr->bulletTypeTemplates[idx].grazeSize.x = 16.0f;
                mgr->bulletTypeTemplates[idx].grazeSize.y = 16.0f;
            }
        }
        else
        {
            mgr->bulletTypeTemplates[idx].grazeSize.x = 32.0f;
            mgr->bulletTypeTemplates[idx].grazeSize.y = 32.0f;
        }
    }
    memset(&g_ItemManager, 0, sizeof(ItemManager));
    return ZUN_SUCCESS;
}

void __inline sincosmul(D3DXVECTOR3 *out_vel, f32 input, f32 multiplier)
{
    __asm {
        mov eax, out_vel
        fld input
        fsincos
        fmul [multiplier]
        fstp [eax]
        fmul [multiplier]
        fstp [eax+4]
    }
}

f32 __inline invertf(f32 x)
{
    return 1.f / x;
}

#pragma var_order(local_8, idx, local_10, local_14, local_20, curBullet, local_28, curLaser, local_38, res)
ChainCallbackResult BulletManager::OnUpdate(BulletManager *mgr)
{
    i32 res;
    D3DXVECTOR3 local_20;
    i32 local_28;
    D3DXVECTOR3 local_38;
    f32 local_14;

    Bullet *curBullet;
    Laser *curLaser;
    f32 local_10;
    i32 idx;
    i32 local_8;

    curBullet = &mgr->bullets[0];
    if (g_GameManager.isTimeStopped)
    {
        return CHAIN_CALLBACK_RESULT_CONTINUE;
    }
    g_ItemManager.OnUpdate();
    mgr->bulletCount = 0;
    for (idx = 0; idx < ARRAY_SIZE_SIGNED(mgr->bullets); idx++, curBullet++)
    {
        if (curBullet->state == 0)
            continue;

        mgr->bulletCount++;
        switch (curBullet->state)
        {
        case 2:
            curBullet->pos += invertf(2.f) * curBullet->velocity * g_Supervisor.effectiveFramerateMultiplier;
            if (g_AnmManager->ExecuteScript(&curBullet->sprites.spriteSpawnEffectFast) == 0)
            {
                break;
            }
            goto HELL;
        case 3:
            curBullet->pos += invertf(2.5f) * curBullet->velocity * g_Supervisor.effectiveFramerateMultiplier;
            if (g_AnmManager->ExecuteScript(&curBullet->sprites.spriteSpawnEffectNormal) == 0)
            {
                break;
            }
            goto HELL;
        case 4:
            curBullet->pos += invertf(3.f) * curBullet->velocity * g_Supervisor.effectiveFramerateMultiplier;
            if (g_AnmManager->ExecuteScript(&curBullet->sprites.spriteSpawnEffectSlow) == 0)
            {
                break;
            }
        HELL:
            curBullet->state = 1;
            curBullet->timer.InitializeForPopup();
        case 1:
            if (curBullet->exFlags != 0)
            {
                if (curBullet->exFlags & 1)
                {
                    if ((ZunBool)(curBullet->timer.current <= 16))
                    {
                        local_10 = 5.0f - curBullet->timer.AsFramesFloat() * 5.0f / 16.0f;
                        sincosmul(&curBullet->velocity, curBullet->angle, local_10 + curBullet->speed);
                    }
                    else
                    {
                        curBullet->exFlags ^= 1;
                    }
                }
                else if (curBullet->exFlags & 0x10)
                {
                    if ((ZunBool)(curBullet->timer.current >= curBullet->ex5Int0))
                    {
                        curBullet->exFlags &= ~0x10;
                    }
                    else
                    {
                        curBullet->velocity += curBullet->ex4Acceleration * g_Supervisor.effectiveFramerateMultiplier;
                        curBullet->angle = atan2f(curBullet->velocity.y, curBullet->velocity.x);
                    }
                }
                else if (curBullet->exFlags & 0x20)
                {
                    if ((ZunBool)(curBullet->timer.current >= curBullet->ex5Int0))
                    {
                        curBullet->exFlags &= ~0x20;
                    }
                    else
                    {
                        curBullet->angle = AddNormalizeAngle(
                            curBullet->angle, g_Supervisor.effectiveFramerateMultiplier * curBullet->ex5Float1);
                        curBullet->speed += g_Supervisor.effectiveFramerateMultiplier * curBullet->ex5Float0;
                        // Has to be done in asm. Just, great.
                        sincosmul(&curBullet->velocity, curBullet->angle, curBullet->speed);
                    }
                }
                if (curBullet->exFlags & 0x40)
                {
                    if ((ZunBool)(curBullet->timer.current >=
                                  curBullet->dirChangeInterval * (curBullet->dirChangeNumTimes + 1)))
                    {
                        curBullet->dirChangeNumTimes++;
                        if (curBullet->dirChangeNumTimes >= curBullet->dirChangeMaxTimes)
                        {
                            curBullet->exFlags &= ~0x40;
                        }
                        curBullet->angle = curBullet->angle + curBullet->dirChangeRotation;
                        curBullet->speed = curBullet->dirChangeSpeed;
                        local_10 = curBullet->speed;
                    }
                    else
                    {
                        local_10 = curBullet->speed - ((curBullet->timer.AsFramesFloat() -
                                                        (curBullet->dirChangeInterval * curBullet->dirChangeNumTimes)) *
                                                       curBullet->speed) /
                                                          curBullet->dirChangeInterval;
                    }
                    sincosmul(&curBullet->velocity, curBullet->angle, local_10);
                }
                else if (curBullet->exFlags & 0x100)
                {
                    if ((ZunBool)(curBullet->timer.current >=
                                  curBullet->dirChangeInterval * (curBullet->dirChangeNumTimes + 1)))
                    {
                        curBullet->dirChangeNumTimes++;
                        if (curBullet->dirChangeNumTimes >= curBullet->dirChangeMaxTimes)
                        {
                            curBullet->exFlags &= ~0x100;
                        }
                        curBullet->angle = curBullet->dirChangeRotation;
                        curBullet->speed = curBullet->dirChangeSpeed;
                        local_10 = curBullet->speed;
                    }
                    else
                    {
                        local_10 = curBullet->speed - ((curBullet->timer.AsFramesFloat() -
                                                        (curBullet->dirChangeInterval * curBullet->dirChangeNumTimes)) *
                                                       curBullet->speed) /
                                                          curBullet->dirChangeInterval;
                    }
                    sincosmul(&curBullet->velocity, curBullet->angle, local_10);
                }
                else if (curBullet->exFlags & 0x80)
                {
                    if ((ZunBool)(curBullet->timer.current >=
                                  curBullet->dirChangeInterval * (curBullet->dirChangeNumTimes + 1)))
                    {
                        curBullet->dirChangeNumTimes++;
                        if (curBullet->dirChangeNumTimes >= curBullet->dirChangeMaxTimes)
                        {
                            curBullet->exFlags &= ~0x80;
                        }
                        curBullet->angle = g_Player.AngleToPlayer(&curBullet->pos) + curBullet->dirChangeRotation;
                        curBullet->speed = curBullet->dirChangeSpeed;
                        local_10 = curBullet->speed;
                    }
                    else
                    {
                        local_10 = curBullet->speed - ((curBullet->timer.AsFramesFloat() -
                                                        (curBullet->dirChangeInterval * curBullet->dirChangeNumTimes)) *
                                                       curBullet->speed) /
                                                          curBullet->dirChangeInterval;
                    }
                    sincosmul(&curBullet->velocity, curBullet->angle, local_10);
                }
                else if (curBullet->exFlags & 0x400)
                {
                    if (g_GameManager.IsInBounds(curBullet->pos.x, curBullet->pos.y,
                                                 curBullet->sprites.spriteBullet.sprite->widthPx,
                                                 curBullet->sprites.spriteBullet.sprite->heightPx) == 0)
                    {
                        if (curBullet->pos.x < 0.0f || curBullet->pos.x >= 384.0f)
                        {
                            curBullet->angle = -curBullet->angle - ZUN_PI;
                            curBullet->angle = AddNormalizeAngle(curBullet->angle, 0.0);
                        }
                        if (curBullet->pos.y < 0.0f || curBullet->pos.y >= 448.0f)
                        {
                            curBullet->angle = -curBullet->angle;
                        }
                        curBullet->speed = curBullet->dirChangeSpeed;
                        local_10 = curBullet->speed;
                        sincosmul(&curBullet->velocity, curBullet->angle, local_10);
                        curBullet->dirChangeNumTimes++;
                        if (curBullet->dirChangeNumTimes >= curBullet->dirChangeMaxTimes)
                        {
                            curBullet->exFlags &= ~0x400;
                        }
                    }
                }
                else if (curBullet->exFlags & 0x800)
                {
                    if (g_GameManager.IsInBounds(curBullet->pos.x, curBullet->pos.y,
                                                 curBullet->sprites.spriteBullet.sprite->widthPx,
                                                 curBullet->sprites.spriteBullet.sprite->heightPx) == 0)
                    {
                        if (curBullet->pos.x < 0.0f || curBullet->pos.x >= 384.0f)
                        {
                            curBullet->angle = -curBullet->angle - ZUN_PI;
                            curBullet->angle = AddNormalizeAngle(curBullet->angle, 0.0f);
                        }
                        if (curBullet->pos.y < 0.0f)
                        {
                            curBullet->angle = -curBullet->angle;
                        }
                        curBullet->speed = curBullet->dirChangeSpeed;
                        local_10 = curBullet->speed;
                        sincosmul(&curBullet->velocity, curBullet->angle, local_10);
                        curBullet->dirChangeNumTimes++;
                        if (curBullet->dirChangeNumTimes >= curBullet->dirChangeMaxTimes)
                        {
                            curBullet->exFlags &= ~0x800;
                        }
                    }
                }
            }
            curBullet->pos += g_Supervisor.FramerateMultiplier() * curBullet->velocity;
            if (g_GameManager.IsInBounds(curBullet->pos.x, curBullet->pos.y,
                                         curBullet->sprites.spriteBullet.sprite->widthPx,
                                         curBullet->sprites.spriteBullet.sprite->heightPx) == 0)
            {
                if ((curBullet->exFlags & 0x40) == 0 && (curBullet->exFlags & 0x100) == 0 &&
                    (curBullet->exFlags & 0x80) == 0 && (curBullet->exFlags & 0x400) == 0 &&
                    (curBullet->exFlags & 0x800) == 0 && curBullet->unk_5c0 == 0)
                {
                    memset(curBullet, 0, sizeof(Bullet));
                    continue;
                }
                else
                {
                    curBullet->unk_5c0++;
                    if (curBullet->unk_5c0 >= 0x100)
                    {
                        memset(curBullet, 0, sizeof(Bullet));
                        continue;
                    }
                }
            }
            else
            {
                curBullet->unk_5c0 = 0;
            }
            if (curBullet->isGrazed == 0)
            {
                local_8 = g_Player.CheckGraze(&curBullet->pos, &curBullet->sprites.grazeSize);
                if (local_8 == 1)
                {
                    curBullet->isGrazed = 1;
                    goto bulletGrazed;
                }
                else if (local_8 == 2)
                {
                    curBullet->state = 5;
                    g_ItemManager.SpawnItem(&curBullet->pos, ITEM_POINT_BULLET, 1);
                }
            }
            else if (curBullet->isGrazed == 1)
            {
            bulletGrazed:
                local_8 = g_Player.CalcKillBoxCollision(&curBullet->pos, &curBullet->sprites.grazeSize);
                if (local_8 != 0)
                {
                    curBullet->state = 5;
                    if (local_8 == 2)
                    {
                        g_ItemManager.SpawnItem(&curBullet->pos, ITEM_POINT_BULLET, 1);
                    }
                }
            }
            g_AnmManager->ExecuteScript(&curBullet->sprites.spriteBullet);
            break;
        case 5:
            curBullet->pos += invertf(2.0f) * curBullet->velocity * g_Supervisor.effectiveFramerateMultiplier;
            if (g_AnmManager->ExecuteScript(&curBullet->sprites.spriteSpawnEffectDonut) != 0)
            {
                memset(curBullet, 0, sizeof(Bullet));
                continue;
            }
            break;
        }
        curBullet->timer.Tick();
    }

    curLaser = &mgr->lasers[0];
    for (idx = 0; idx < ARRAY_SIZE_SIGNED(mgr->lasers); idx++, curLaser++)
    {
        if (!curLaser->inUse)
        {
            continue;
        }

        curLaser->endOffset += g_Supervisor.effectiveFramerateMultiplier * curLaser->speed;
        if (curLaser->startLength < curLaser->endOffset - curLaser->startOffset)
        {
            curLaser->startOffset = curLaser->endOffset - curLaser->startLength;
        }
        if (curLaser->startOffset < 0.0f)
        {
            curLaser->startOffset = 0.0f;
        }
        local_20.y = curLaser->width / 2.0f;
        local_20.x = curLaser->endOffset - curLaser->startOffset;
        local_38.x = (curLaser->endOffset - curLaser->startOffset) / 2.0f + curLaser->startOffset + curLaser->pos.x;
        local_38.y = curLaser->pos.y;
        curLaser->vm0.scaleX = curLaser->width / curLaser->vm0.sprite->widthPx;
        local_14 = curLaser->endOffset - curLaser->startOffset;
        curLaser->vm0.scaleY = local_14 / curLaser->vm0.sprite->heightPx;
        curLaser->vm0.rotation.z = ZUN_PI / 2.0f - curLaser->angle;
        switch (curLaser->state)
        {
        case 0:
            if (curLaser->flags & 1)
            {
                local_28 = curLaser->timer.AsFramesFloat() * 255.0f / curLaser->startTime;
                if (255 < local_28)
                {
                    local_28 = 255;
                }
                curLaser->vm0.color = local_28 << 24;
            }
            else
            {
                res = ZUN_MIN(curLaser->startTime, 30);
                if (curLaser->startTime - res < curLaser->timer.AsFrames())
                {
                    local_14 = curLaser->timer.AsFramesFloat() * curLaser->width / curLaser->startTime;
                }
                else
                {
                    local_14 = 1.2f;
                }
                curLaser->vm0.scaleX = local_14 / 16.0f;
                local_20.x = local_14 / 2.0f;
            }
            if ((ZunBool)(curLaser->timer.current >= curLaser->grazeDelay))
            {
                g_Player.CalcLaserHitbox(&local_38, &local_20, &curLaser->pos, curLaser->angle,
                                         curLaser->timer.AsFrames() % 12 == 0);
            }
            if ((ZunBool)(curLaser->timer.current < curLaser->startTime))
            {
                break;
            }
            curLaser->timer.InitializeForPopup();
            curLaser->state++;
        case 1:
            g_Player.CalcLaserHitbox(&local_38, &local_20, &curLaser->pos, curLaser->angle,
                                     curLaser->timer.AsFrames() % 12 == 0);
            if ((ZunBool)(curLaser->timer.current < curLaser->duration))
            {
                break;
            }
            curLaser->timer.InitializeForPopup();
            curLaser->state++;
            if (curLaser->endTime == 0)
            {
                curLaser->inUse = 0;
                continue;
            }
        case 2:
            if (curLaser->flags & 1)
            {
                local_28 = curLaser->timer.AsFramesFloat() * 255.0f / curLaser->startTime;
                if (255 < local_28)
                {
                    local_28 = 255;
                }
                curLaser->vm0.color = local_28 << 24;
            }
            else
            {
                if (0 < curLaser->endTime)
                {
                    local_14 =
                        curLaser->width - (curLaser->timer.AsFramesFloat() * curLaser->width) / curLaser->endTime;
                    curLaser->vm0.scaleX = local_14 / 16.0f;
                    local_20.x = local_14 / 2.0f;
                }
            }
            if ((ZunBool)(curLaser->timer.current < curLaser->grazeInterval))
            {
                g_Player.CalcLaserHitbox(&local_38, &local_20, &curLaser->pos, curLaser->angle,
                                         curLaser->timer.AsFrames() % 12 == 0);
            }
            if ((ZunBool)(curLaser->timer.current < curLaser->endTime))
            {
                break;
            }
            curLaser->inUse = 0;
            continue;
        }
        if (curLaser->startOffset >= 640.0f)
        {
            curLaser->inUse = 0;
        }
        curLaser->timer.Tick();
        g_AnmManager->ExecuteScript(&curLaser->vm0);
    }

    mgr->time.Tick();
    return CHAIN_CALLBACK_RESULT_CONTINUE;
}

void __inline fsincos_wrapper(f32 *out_sine, f32 *out_cosine, f32 angle)
{
    __asm {
        fld [angle]
        fsincos
        mov eax, [out_cosine]
        fstp [eax]
        mov eax, [out_sine]
        fstp [eax]
    }
}

#pragma var_order(idx, sine, curLaser, laserOffset, cosine, curBullet1, curBullet2)
ChainCallbackResult BulletManager::OnDraw(BulletManager *mgr)
{
    i32 idx;
    f32 sine;
    Laser *curLaser;
    f32 laserOffset;
    f32 cosine;
    Bullet *curBullet1;
    Bullet *curBullet2;

    g_Supervisor.d3dDevice->SetRenderState(D3DRS_ZFUNC, D3DCMP_ALWAYS);
    for (curLaser = &mgr->lasers[0], idx = 0; idx < ARRAY_SIZE_SIGNED(mgr->lasers); idx++, curLaser++)
    {
        if (!curLaser->inUse)
        {
            continue;
        }
        fsincos_wrapper(&sine, &cosine, curLaser->angle);
        laserOffset = (curLaser->endOffset - curLaser->startOffset) / 2.0f + curLaser->startOffset;
        curLaser->vm0.pos.x = cosine * laserOffset + curLaser->pos.x;
        curLaser->vm0.pos.y = sine * laserOffset + curLaser->pos.y;
        curLaser->vm0.pos.z = 0.0f;
        curLaser->color = COLOR_COMBINE_ALPHA(COLOR_WHITE, curLaser->color);
        g_AnmManager->Draw3(&curLaser->vm0);
        if (curLaser->startOffset < 16.0f || curLaser->speed == 0.0f)
        {
            curLaser->vm1.pos.x = cosine * curLaser->startOffset + curLaser->pos.x;
            curLaser->vm1.pos.y = sine * curLaser->startOffset + curLaser->pos.y;
            curLaser->vm1.pos.z = 0.0f;
            curLaser->vm1.color = curLaser->vm0.color;
            curLaser->vm1.flags.colorOp = AnmVmColorOp_Add;
            curLaser->vm1.color = COLOR_SET_ALPHA2(curLaser->vm1.color, 0xff);
            curLaser->vm1.scaleX = (curLaser->width / 10.0f) * ((16.0f - curLaser->startOffset) / 16.0f);
            curLaser->vm1.scaleY = curLaser->vm1.scaleX;
            if (curLaser->vm1.scaleY < 0.0f)
            {
                curLaser->vm1.scaleX = curLaser->width / 10.0f;
                curLaser->vm1.scaleY = curLaser->vm1.scaleX;
            }
            g_AnmManager->Draw3(&curLaser->vm1);
        }
    }
    g_ItemManager.OnDraw();
    if (g_Supervisor.hasD3dHardwareVertexProcessing)
    {
        for (curBullet1 = &mgr->bullets[0], idx = 0; idx < ARRAY_SIZE_SIGNED(mgr->bullets); idx++, curBullet1++)
        {
            if (curBullet1->state == 0)
            {
                continue;
            }
            if (curBullet1->sprites.bulletHeight > 16)
            {
                BulletManager::DrawBullet(curBullet1);
            }
        }
        for (curBullet1 = &mgr->bullets[0], idx = 0; idx < ARRAY_SIZE_SIGNED(mgr->bullets); idx++, curBullet1++)
        {
            if (curBullet1->state == 0)
            {
                continue;
            }
            if (curBullet1->sprites.bulletHeight == 16 &&
                (curBullet1->sprites.spriteBullet.anmFileIndex == ANM_SCRIPT_BULLET3_RING_BALL ||
                 curBullet1->sprites.spriteBullet.anmFileIndex == ANM_SCRIPT_BULLET3_BALL))
            {
                BulletManager::DrawBullet(curBullet1);
            }
        }
        for (curBullet1 = &mgr->bullets[0], idx = 0; idx < ARRAY_SIZE_SIGNED(mgr->bullets); idx++, curBullet1++)
        {
            if (curBullet1->state == 0)
            {
                continue;
            }
            if (curBullet1->sprites.bulletHeight == 16 &&
                curBullet1->sprites.spriteBullet.anmFileIndex != ANM_SCRIPT_BULLET3_RING_BALL &&
                curBullet1->sprites.spriteBullet.anmFileIndex != ANM_SCRIPT_BULLET3_BALL)
            {
                BulletManager::DrawBullet(curBullet1);
            }
        }
        for (curBullet1 = &mgr->bullets[0], idx = 0; idx < ARRAY_SIZE_SIGNED(mgr->bullets); idx++, curBullet1++)
        {
            if (curBullet1->state == 0)
            {
                continue;
            }
            if (curBullet1->sprites.bulletHeight == 8)
            {
                BulletManager::DrawBullet(curBullet1);
            }
        }
    }
    else
    {
        for (curBullet2 = &mgr->bullets[0], idx = 0; idx < ARRAY_SIZE_SIGNED(mgr->bullets); idx++, curBullet2++)
        {
            if (curBullet2->state == 0)
            {
                continue;
            }
            if (curBullet2->sprites.bulletHeight > 16)
            {
                BulletManager::DrawBulletNoHwVertex(curBullet2);
            }
        }
        for (curBullet2 = &mgr->bullets[0], idx = 0; idx < ARRAY_SIZE_SIGNED(mgr->bullets); idx++, curBullet2++)
        {
            if (curBullet2->state == 0)
            {
                continue;
            }
            if (curBullet2->sprites.bulletHeight == 16 &&
                (curBullet2->sprites.spriteBullet.anmFileIndex == ANM_SCRIPT_BULLET3_RING_BALL ||
                 curBullet2->sprites.spriteBullet.anmFileIndex == ANM_SCRIPT_BULLET3_BALL))
            {
                BulletManager::DrawBulletNoHwVertex(curBullet2);
            }
        }
        for (curBullet2 = &mgr->bullets[0], idx = 0; idx < ARRAY_SIZE_SIGNED(mgr->bullets); idx++, curBullet2++)
        {
            if (curBullet2->state == 0)
            {
                continue;
            }
            if (curBullet2->sprites.bulletHeight == 16 &&
                curBullet2->sprites.spriteBullet.anmFileIndex != ANM_SCRIPT_BULLET3_RING_BALL &&
                curBullet2->sprites.spriteBullet.anmFileIndex != ANM_SCRIPT_BULLET3_BALL)
            {
                BulletManager::DrawBulletNoHwVertex(curBullet2);
            }
        }
        for (curBullet2 = &mgr->bullets[0], idx = 0; idx < ARRAY_SIZE_SIGNED(mgr->bullets); idx++, curBullet2++)
        {
            if (curBullet2->state == 0)
            {
                continue;
            }
            if (curBullet2->sprites.bulletHeight == 8)
            {
                BulletManager::DrawBulletNoHwVertex(curBullet2);
            }
        }
    }
    g_Supervisor.d3dDevice->SetRenderState(D3DRS_ZFUNC, D3DCMP_LESSEQUAL);
    return CHAIN_CALLBACK_RESULT_CONTINUE;
}
