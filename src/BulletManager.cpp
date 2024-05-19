#include "BulletManager.hpp"
#include "AnmManager.hpp"
#include "Chain.hpp"
#include "ChainPriorities.hpp"
#include "ItemManager.hpp"

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
