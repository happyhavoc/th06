#include "EnemyManager.hpp"
#include "AnmManager.hpp"
#include "BulletManager.hpp"
#include "Chain.hpp"
#include "ChainPriorities.hpp"
#include "EffectManager.hpp"
#include "GameManager.hpp"
#include "Gui.hpp"
#include "Player.hpp"
#include "Rng.hpp"
#include "diffbuild.hpp"
#include "utils.hpp"

#define ITEM_SPAWNS 3
#define ITEM_TABLES 8

DIFFABLE_STATIC(EnemyManager, g_EnemyManager)
DIFFABLE_STATIC(ChainElem, g_EnemyManagerCalcChain)
DIFFABLE_STATIC(ChainElem, g_EnemyManagerDrawChain)

ZunResult EnemyManager::RegisterChain(char *stgEnm1, char *stgEnm2)
{
    EnemyManager *mgr = &g_EnemyManager;
    mgr->Initialize();
    mgr->stgEnmAnmFilename = stgEnm1;
    mgr->stgEnm2AnmFilename = stgEnm2;
    g_EnemyManagerCalcChain.callback = (ChainCallback)mgr->OnUpdate;
    g_EnemyManagerCalcChain.addedCallback = NULL;
    g_EnemyManagerCalcChain.deletedCallback = NULL;
    g_EnemyManagerCalcChain.addedCallback = (ChainAddedCallback)mgr->AddedCallback;
    g_EnemyManagerCalcChain.deletedCallback = (ChainAddedCallback)mgr->DeletedCallback;
    g_EnemyManagerCalcChain.arg = mgr;
    if (g_Chain.AddToCalcChain(&g_EnemyManagerCalcChain, TH_CHAIN_PRIO_CALC_ENEMYMANAGER))
    {
        return ZUN_ERROR;
    }
    g_EnemyManagerDrawChain.callback = (ChainCallback)mgr->OnDraw;
    g_EnemyManagerDrawChain.addedCallback = NULL;
    g_EnemyManagerDrawChain.deletedCallback = NULL;
    g_EnemyManagerDrawChain.arg = mgr;
    if (g_Chain.AddToDrawChain(&g_EnemyManagerDrawChain, TH_CHAIN_PRIO_DRAW_ENEMYMANAGER))
    {
        return ZUN_ERROR;
    }
    return ZUN_SUCCESS;
}

ZunResult EnemyManager::AddedCallback(EnemyManager *enemyManager)
{
    Enemy *enemies = enemyManager->enemies;

    if (enemyManager->stgEnmAnmFilename &&
        g_AnmManager->LoadAnm(ANM_FILE_ENEMY, enemyManager->stgEnmAnmFilename, ANM_OFFSET_ENEMY) != ZUN_SUCCESS)
    {
        return ZUN_ERROR;
    }
    if (enemyManager->stgEnm2AnmFilename &&
        g_AnmManager->LoadAnm(ANM_FILE_ENEMY2, enemyManager->stgEnm2AnmFilename, ANM_OFFSET_ENEMY) != ZUN_SUCCESS)
    {
        return ZUN_ERROR;
    }

    enemyManager->randomItemSpawnIndex = g_Rng.GetRandomU16InRange(ITEM_SPAWNS);
    enemyManager->randomItemTableIndex = g_Rng.GetRandomU16InRange(ITEM_TABLES);

    enemyManager->spellcardCapture = 0;
    enemyManager->timelineInstr = NULL;

    return ZUN_SUCCESS;
}

DIFFABLE_STATIC_ARRAY_ASSIGN(u8, 32, g_RandomItems) = {
    ITEM_POWER_SMALL, ITEM_POWER_SMALL, ITEM_POINT,       ITEM_POWER_SMALL, ITEM_POINT,       ITEM_POWER_SMALL,
    ITEM_POWER_SMALL, ITEM_POINT,       ITEM_POINT,       ITEM_POINT,       ITEM_POWER_SMALL, ITEM_POWER_SMALL,
    ITEM_POWER_SMALL, ITEM_POINT,       ITEM_POINT,       ITEM_POWER_SMALL, ITEM_POINT,       ITEM_POWER_SMALL,
    ITEM_POINT,       ITEM_POWER_SMALL, ITEM_POINT,       ITEM_POWER_SMALL, ITEM_POINT,       ITEM_POWER_SMALL,
    ITEM_POINT,       ITEM_POWER_SMALL, ITEM_POWER_SMALL, ITEM_POINT,       ITEM_POINT,       ITEM_POINT,
    ITEM_POWER_SMALL, ITEM_POWER_BIG};

#pragma var_order(local_8, damage, enemyIdx, enemyHitbox, enemyVmIdx, enemyLifeBeforeDmg, curEnemy)
ChainCallbackResult EnemyManager::OnUpdate(EnemyManager *mgr)
{
    Enemy *curEnemy;
    i32 enemyLifeBeforeDmg;
    i32 enemyVmIdx;
    D3DXVECTOR3 enemyHitbox;
    i32 enemyIdx;
    i32 damage;
    i32 local_8;

    local_8 = 0;
    mgr->RunEclTimeline();
    for (curEnemy = &mgr->enemies[0], mgr->enemyCount = 0, enemyIdx = 0; enemyIdx < ARRAY_SIZE_SIGNED(mgr->enemies);
         enemyIdx++, curEnemy++)
    {
        if (!curEnemy->flags.unk5)
        {
            continue;
        }
        mgr->enemyCount++;
        curEnemy->Move();
        curEnemy->ClampPos();
        if (curEnemy->flags.unk8 == 0 &&
            g_GameManager.IsInBounds(curEnemy->position.x, curEnemy->position.y, curEnemy->primaryVm.sprite->widthPx,
                                     curEnemy->primaryVm.sprite->heightPx))
        {
            curEnemy->flags.unk8 = 1;
        }
        if (curEnemy->flags.unk8 == 1 &&
            !g_GameManager.IsInBounds(curEnemy->position.x, curEnemy->position.y, curEnemy->primaryVm.sprite->widthPx,
                                      curEnemy->primaryVm.sprite->heightPx))
        {
            curEnemy->flags.unk5 = 0;
            curEnemy->Despawn();
            continue;
        }
        if (0 <= curEnemy->lifeCallbackThreshold)
        {
            curEnemy->HandleLifeCallback();
        }
        if (0 <= curEnemy->timerCallbackThreshold)
        {
            curEnemy->HandleTimerCallback();
        }
        if (g_EclManager.RunEcl(curEnemy) == ZUN_ERROR)
        {
            curEnemy->flags.unk5 = 0;
            curEnemy->Despawn();
            continue;
        }
        curEnemy->ClampPos();
        curEnemy->primaryVm.color = curEnemy->color;
        g_AnmManager->ExecuteScript(&curEnemy->primaryVm);
        curEnemy->color = curEnemy->primaryVm.color;
        for (enemyVmIdx = 0; enemyVmIdx < 8; enemyVmIdx++)
        {
            if (0 <= curEnemy->vms[enemyVmIdx].anmFileIndex && g_AnmManager->ExecuteScript(&curEnemy->vms[enemyVmIdx]))
            {
                curEnemy->vms[enemyVmIdx].anmFileIndex = -1;
            }
        }
        local_8 = 0;
        if (curEnemy->flags.unk8 != 0 && !curEnemy->flags.unk15)
        {
            enemyLifeBeforeDmg = curEnemy->life;
            if (curEnemy->flags.unk7 && curEnemy->flags.unk6)
            {
                // There's something weird going on here, stack-wise.
                enemyHitbox = curEnemy->HitboxDimensions(1.5f);
                if (g_Player.CalcKillBoxCollision(&curEnemy->position, &enemyHitbox) == 1 && curEnemy->flags.unk6 &&
                    !curEnemy->flags.unk9)
                {
                    curEnemy->life -= 10;
                }
            }
            if (curEnemy->flags.unk6 != 0)
            {
                damage = g_Player.DidHitEnemy(&curEnemy->position, &curEnemy->hitboxDimensions, &local_8);
                if (70 <= damage)
                {
                    damage = 70;
                }
                g_GameManager.score = (damage / 5) * 10 + g_GameManager.score;
                if (mgr->spellcardCapture != 0)
                {
                    if (local_8 == 0)
                    {
                        if (damage > 7)
                        {
                            damage = damage / 7;
                        }
                        else if (damage != 0)
                        {
                            damage = 1;
                        }
                    }
                    else if (mgr->unk_ee5d4 != 0)
                    {
                        if (damage > 3)
                        {
                            damage = damage / 3;
                        }
                        else if (damage != 0)
                        {
                            damage = 1;
                        }
                    }
                    else
                    {
                        damage = 0;
                    }
                }
                if (curEnemy->flags.unk10 != 0)
                {
                    curEnemy->life -= damage;
                }
                if (g_Player.positionOfLastEnemyHit.y < curEnemy->position.y)
                {
                    g_Player.positionOfLastEnemyHit = curEnemy->position;
                }
            }
            if (0 >= curEnemy->life && curEnemy->flags.unk6 != 0)
            {
                curEnemy->lifeCallbackThreshold = -1;
                curEnemy->timerCallbackThreshold = -1;
                switch (curEnemy->flags.unk11)
                {
                case 3:
                    curEnemy->life = 1;
                    curEnemy->flags.unk10 = 0;
                    curEnemy->flags.unk11 = 0;
                    g_Gui.bossPresent = 0;
                    g_EffectManager.SpawnEffect(curEnemy->deathAnm1, &curEnemy->position, 1, COLOR_WHITE);
                    g_EffectManager.SpawnEffect(curEnemy->deathAnm1, &curEnemy->position, 1, COLOR_WHITE);
                    g_EffectManager.SpawnEffect(curEnemy->deathAnm1, &curEnemy->position, 1, COLOR_WHITE);
                    break;
                case 1:
                    g_GameManager.AddScore(curEnemy->score);
                    curEnemy->flags.unk6 = 0;
                    goto LAB_00412a4d;
                case 0:
                    g_GameManager.AddScore(curEnemy->score);
                    curEnemy->flags.unk5 = 0;
                LAB_00412a4d:
                    if (curEnemy->flags.unk9)
                    {
                        g_Gui.bossPresent = 0;
                        Enemy::ResetEffectArray(curEnemy);
                    }
                case 2:
                    if (curEnemy->itemDrop >= 0)
                    {
                        g_EffectManager.SpawnEffect(curEnemy->deathAnm2 + 4, &curEnemy->position, 3, 0xffffffff);
                        g_ItemManager.SpawnItem(&curEnemy->position, (ItemType)curEnemy->itemDrop, local_8);
                    }
                    else if (curEnemy->itemDrop == ITEM_NO_ITEM)
                    {
                        if (mgr->randomItemSpawnIndex % 3 == 0)
                        {
                            g_EffectManager.SpawnEffect(curEnemy->deathAnm2 + 4, &curEnemy->position, 6, COLOR_WHITE);
                            g_ItemManager.SpawnItem(&curEnemy->position,
                                                    (ItemType)g_RandomItems[mgr->randomItemTableIndex], local_8);
                            mgr->randomItemTableIndex++;
                            if (ARRAY_SIZE_SIGNED(g_RandomItems) <= mgr->randomItemTableIndex)
                            {
                                mgr->randomItemTableIndex = 0;
                            }
                        }
                        mgr->randomItemSpawnIndex++;
                    }
                    if (curEnemy->flags.unk9 && !g_RunningSpellcardInfo.isActive)
                    {
                        g_BulletManager.DespawnBullets(12800, false);
                    }
                    curEnemy->life = 0;
                    break;
                }
                g_SoundPlayer.PlaySoundByIdx((SoundIdx)((enemyIdx % 2) + SOUND_2), 0);
                g_EffectManager.SpawnEffect(curEnemy->deathAnm1, &curEnemy->position, 1, 0xffffffff);
                g_EffectManager.SpawnEffect(curEnemy->deathAnm2 + 4, &curEnemy->position, 4, 0xffffffff);
                if (0 <= curEnemy->deathCallbackSub)
                {
                    curEnemy->bulletRankSpeedLow = -0.5;
                    curEnemy->bulletRankSpeedHigh = 0.5;
                    curEnemy->bulletRankAmount1Low = 0;
                    curEnemy->bulletRankAmount1High = 0;
                    curEnemy->bulletRankAmount2Low = 0;
                    curEnemy->bulletRankAmount2High = 0;
                    curEnemy->stackDepth = 0;
                    g_EclManager.CallEclSub(&curEnemy->currentContext, curEnemy->deathCallbackSub);
                    curEnemy->deathCallbackSub = -1;
                }
            }
            if (curEnemy->flags.unk9 != 0 && !g_Gui.HasCurrentMsgIdx())
            {
                g_Gui.SetBossHealthBar(curEnemy->LifePercent());
            }
            if (curEnemy->unk_e41 != 0)
            {
                curEnemy->unk_e41--;
                curEnemy->primaryVm.flags.colorOp = AnmVmColorOp_Modulate;
            }
            else if (enemyLifeBeforeDmg > curEnemy->life)
            {
                g_SoundPlayer.PlaySoundByIdx(SOUND_TOTAL_BOSS_DEATH, 0);
                curEnemy->primaryVm.flags.colorOp = AnmVmColorOp_Add;
                curEnemy->unk_e41 = 4;
            }
            else
            {
                curEnemy->primaryVm.flags.colorOp = AnmVmColorOp_Modulate;
            }
        }
        Enemy::UpdateEffects(curEnemy);
        if (g_GameManager.isTimeStopped == 0)
        {
            curEnemy->bossTimer.Tick();
        }
    }
    mgr->timelineTime.Tick();
    return CHAIN_CALLBACK_RESULT_CONTINUE;
}

#pragma var_order(curEnemyIdx, curEnemyVm, curEnemyVmIdx, curEnemy)
ChainCallbackResult EnemyManager::OnDraw(EnemyManager *mgr)
{
    AnmVm *curEnemyVm;
    Enemy *curEnemy;
    i32 curEnemyVmIdx;
    i32 curEnemyIdx;

    for (curEnemy = &mgr->enemies[0], curEnemyIdx = 0; curEnemyIdx < ARRAY_SIZE_SIGNED(mgr->enemies);
         curEnemyIdx++, curEnemy++)
    {
        if (!curEnemy->flags.unk5)
        {
            continue;
        }
        if (curEnemy->flags.unk15)
        {
            continue;
        }

        for (curEnemyVm = &curEnemy->vms[0], curEnemyVmIdx = 0; curEnemyVmIdx < 4; curEnemyVmIdx++, curEnemyVm++)
        {
            if (0 <= curEnemyVm->anmFileIndex)
            {
                if (curEnemyVm->autoRotate != 0)
                {
                    curEnemyVm->rotation.z = curEnemy->angle;
                }
                curEnemyVm->pos = curEnemy->position + curEnemyVm->posOffset;
                curEnemyVm->pos.z = 0.495f;
                g_AnmManager->Draw2(curEnemyVm);
            }
        }
        if (curEnemy->flags.unk13 != 0)
        {
            curEnemy->primaryVm.rotation.z = curEnemy->angle;
        }
        curEnemy->primaryVm.pos = curEnemy->position + curEnemy->primaryVm.posOffset;
        curEnemy->primaryVm.pos.z = 0.494f;
        g_AnmManager->Draw2(&curEnemy->primaryVm);
        for (curEnemyVmIdx = 4; curEnemyVmIdx < 8; curEnemyVmIdx++, curEnemyVm++)
        {
            if (0 <= curEnemyVm->anmFileIndex)
            {
                if (curEnemyVm->autoRotate != 0)
                {
                    curEnemyVm->rotation.z = curEnemy->angle;
                }
                curEnemyVm->pos = curEnemy->position + curEnemyVm->posOffset;
                curEnemyVm->pos.z = 0.495f;
                g_AnmManager->Draw2(curEnemyVm);
            }
        }
    }
    return CHAIN_CALLBACK_RESULT_CONTINUE;
}
