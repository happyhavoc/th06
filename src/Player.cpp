#include "Player.hpp"

#include "AnmManager.hpp"
#include "AnmVm.hpp"
#include "BulletData.hpp"
#include "BulletManager.hpp"
#include "ChainPriorities.hpp"
#include "EclManager.hpp"
#include "EffectManager.hpp"
#include "EnemyManager.hpp"
#include "GameManager.hpp"
#include "Gui.hpp"
#include "ItemManager.hpp"
#include "Rng.hpp"
#include "ScreenEffect.hpp"
#include "SoundPlayer.hpp"
#include "Supervisor.hpp"
#include "ZunBool.hpp"
#include "i18n.hpp"
#include "utils.hpp"

namespace th06
{
DIFFABLE_STATIC(Player, g_Player);

DIFFABLE_STATIC_ARRAY_ASSIGN(CharacterData, 4, g_CharData) = {
    /* ReimuA  */ {4.0, 2.0, 4.0, 2.0, Player::FireBulletReimuA, Player::FireBulletReimuA},
    /* ReimuB  */ {4.0, 2.0, 4.0, 2.0, Player::FireBulletReimuA, Player::FireBulletReimuB},
    /* MarisaA */ {5.0, 2.5, 5.0, 2.5, Player::FireBulletMarisaA, Player::FireBulletMarisaA},
    /* MarisaB */ {5.0, 2.5, 5.0, 2.5, Player::FireBulletMarisaB, Player::FireBulletMarisaB},
};

DIFFABLE_STATIC_ARRAY_ASSIGN(BombData, 4, g_BombData) = {
    /* ReimuA  */ {Player::BombReimuACalc, Player::BombReimuADraw},
    /* ReimuB  */ {Player::BombReimuBCalc, Player::BombReimuBDraw},
    /* MarisaA */ {Player::BombMarisaACalc, Player::BombMarisaADraw},
    /* MarisaB */ {Player::BombMarisaBCalc, Player::BombMarisaBDraw},
};

Player::Player()
{
}

ZunResult Player::RegisterChain(u8 unk)
{
    Player *p = &g_Player;
    memset(p, 0, sizeof(Player));

    p->invulnerabilityTimer.InitializeForPopup();
    p->unk_9e1 = unk;
    p->chainCalc = g_Chain.CreateElem((ChainCallback)Player::OnUpdate);
    p->chainDraw1 = g_Chain.CreateElem((ChainCallback)Player::OnDrawHighPrio);
    p->chainDraw2 = g_Chain.CreateElem((ChainCallback)Player::OnDrawLowPrio);
    p->chainCalc->arg = p;
    p->chainDraw1->arg = p;
    p->chainDraw2->arg = p;
    p->chainCalc->addedCallback = (ChainAddedCallback)Player::AddedCallback;
    p->chainCalc->deletedCallback = (ChainDeletedCallback)Player::DeletedCallback;
    if (g_Chain.AddToCalcChain(p->chainCalc, TH_CHAIN_PRIO_CALC_PLAYER))
    {
        return ZUN_ERROR;
    }
    g_Chain.AddToDrawChain(p->chainDraw1, TH_CHAIN_PRIO_DRAW_LOW_PRIO_PLAYER);
    g_Chain.AddToDrawChain(p->chainDraw2, TH_CHAIN_PRIO_DRAW_HIGH_PRIO_PLAYER);
    return ZUN_SUCCESS;
}

void Player::CutChain()
{
    g_Chain.Cut(g_Player.chainCalc);
    g_Player.chainCalc = NULL;
    g_Chain.Cut(g_Player.chainDraw1);
    g_Player.chainDraw1 = NULL;
    g_Chain.Cut(g_Player.chainDraw2);
    g_Player.chainDraw2 = NULL;
    return;
}

ZunResult Player::AddedCallback(Player *p)
{
    PlayerBullet *curBullet;
    i32 idx;

    switch (g_GameManager.character)
    {
    case CHARA_REIMU:
        // This is likely an inline function from g_Supervisor returning an i32.
        if ((i32)(g_Supervisor.curState != SUPERVISOR_STATE_GAMEMANAGER_REINIT) &&
            g_AnmManager->LoadAnm(ANM_FILE_PLAYER, "data/player00.anm", ANM_OFFSET_PLAYER) != ZUN_SUCCESS)
        {
            return ZUN_ERROR;
        }
        g_AnmManager->SetAndExecuteScriptIdx(&p->playerSprite, ANM_SCRIPT_PLAYER_IDLE);
        break;
    case CHARA_MARISA:
        if ((i32)(g_Supervisor.curState != SUPERVISOR_STATE_GAMEMANAGER_REINIT) &&
            g_AnmManager->LoadAnm(ANM_FILE_PLAYER, "data/player01.anm", ANM_OFFSET_PLAYER) != ZUN_SUCCESS)
        {
            return ZUN_ERROR;
        }
        g_AnmManager->SetAndExecuteScriptIdx(&p->playerSprite, ANM_SCRIPT_PLAYER_IDLE);
        break;
    }
    p->positionCenter.x = g_GameManager.arcadeRegionSize.x / 2.0f;
    p->positionCenter.y = g_GameManager.arcadeRegionSize.y - 64.0f;
    p->positionCenter.z = 0.49;
    p->orbsPosition[0].z = 0.49;
    p->orbsPosition[1].z = 0.49;
    for (idx = 0; idx < ARRAY_SIZE_SIGNED(p->bombRegionSizes); idx++)
    {
        p->bombRegionSizes[idx].x = 0.0;
    }
    p->hitboxSize.x = 1.25;
    p->hitboxSize.y = 1.25;
    p->hitboxSize.z = 5.0;
    p->grabItemSize.x = 12.0;
    p->grabItemSize.y = 12.0;
    p->grabItemSize.z = 5.0;
    p->playerDirection = MOVEMENT_NONE;
    memcpy(&p->characterData, &g_CharData[g_GameManager.CharacterShotType()], sizeof(CharacterData));
    p->characterData.diagonalMovementSpeed = p->characterData.orthogonalMovementSpeed / sqrtf(2.0);
    p->characterData.diagonalMovementSpeedFocus = p->characterData.orthogonalMovementSpeedFocus / sqrtf(2.0);
    p->fireBulletCallback = p->characterData.fireBulletCallback;
    p->fireBulletFocusCallback = p->characterData.fireBulletFocusCallback;
    p->playerState = PLAYER_STATE_SPAWNING;
    p->invulnerabilityTimer.SetCurrent(120);
    p->orbState = ORB_HIDDEN;
    g_AnmManager->SetAndExecuteScriptIdx(&p->orbsSprite[0], ANM_SCRIPT_PLAYER_ORB_LEFT);
    g_AnmManager->SetAndExecuteScriptIdx(&p->orbsSprite[1], ANM_SCRIPT_PLAYER_ORB_RIGHT);
    for (curBullet = &p->bullets[0], idx = 0; idx < ARRAY_SIZE_SIGNED(p->bullets); idx++, curBullet++)
    {
        curBullet->bulletState = 0;
    }
    p->fireBulletTimer.SetCurrent(-1);
    p->bombInfo.calc = g_BombData[g_GameManager.CharacterShotType()].calc;
    p->bombInfo.draw = g_BombData[g_GameManager.CharacterShotType()].draw;
    p->bombInfo.isInUse = 0;
    for (idx = 0; idx < ARRAY_SIZE_SIGNED(p->laserTimer); idx++)
    {
        p->laserTimer[idx].InitializeForPopup();
    }
    p->verticalMovementSpeedMultiplierDuringBomb = 1.0;
    p->horizontalMovementSpeedMultiplierDuringBomb = 1.0;
    p->respawnTimer = 8;
    return ZUN_SUCCESS;
}

ZunResult Player::DeletedCallback(Player *p)
{
    if ((i32)(g_Supervisor.curState != SUPERVISOR_STATE_GAMEMANAGER_REINIT))
    {
        g_AnmManager->ReleaseAnm(ANM_FILE_PLAYER);
    }
    return ZUN_SUCCESS;
}

#pragma var_order(idx, scaleFactor1, scaleFactor2, lastEnemyHit)
ChainCallbackResult Player::OnUpdate(Player *p)
{
    f32 scaleFactor1, scaleFactor2;
    i32 idx;
    D3DXVECTOR3 lastEnemyHit;

    if (g_GameManager.isTimeStopped)
    {
        return CHAIN_CALLBACK_RESULT_CONTINUE;
    }
    for (idx = 0; idx < ARRAY_SIZE_SIGNED(p->bombRegionSizes); idx++)
    {
        p->bombRegionSizes[idx].x = 0.0;
    }
    for (idx = 0; idx < ARRAY_SIZE_SIGNED(p->bombProjectiles); idx++)
    {
        p->bombProjectiles[idx].size.x = 0.0;
    }
    if (p->bombInfo.isInUse)
    {
        p->bombInfo.calc(p);
    }
    else if (!g_Gui.HasCurrentMsgIdx() && p->respawnTimer != 0 && 0 < g_GameManager.bombsRemaining &&
             WAS_PRESSED(TH_BUTTON_BOMB) && p->bombInfo.calc != NULL)
    {
        g_GameManager.bombsUsed++;
        g_GameManager.bombsRemaining--;
        g_Gui.flags.flag1 = 2;
        p->bombInfo.isInUse = 1;
        p->bombInfo.timer.SetCurrent(0);
        p->bombInfo.duration = 999;
        p->bombInfo.calc(p);
        g_EnemyManager.spellcardInfo.isCapturing = false;
        g_GameManager.DecreaseSubrank(200);
        g_EnemyManager.spellcardInfo.usedBomb = g_EnemyManager.spellcardInfo.isActive;
    }
    if (p->playerState == PLAYER_STATE_DEAD)
    {
        if (p->respawnTimer != 0)
        {
            p->respawnTimer--;
            if (p->respawnTimer == 0)
            {
                g_GameManager.powerItemCountForScore = 0;
                if (g_GameManager.livesRemaining > 0)
                {
                    g_ItemManager.SpawnItem(&p->positionCenter, ITEM_POWER_BIG, 2);
                    g_ItemManager.SpawnItem(&p->positionCenter, ITEM_POWER_SMALL, 2);
                    g_ItemManager.SpawnItem(&p->positionCenter, ITEM_POWER_SMALL, 2);
                    g_ItemManager.SpawnItem(&p->positionCenter, ITEM_POWER_SMALL, 2);
                    g_ItemManager.SpawnItem(&p->positionCenter, ITEM_POWER_SMALL, 2);
                    g_ItemManager.SpawnItem(&p->positionCenter, ITEM_POWER_SMALL, 2);
                    if (g_GameManager.currentPower <= 16)
                    {
                        g_GameManager.currentPower = 0;
                    }
                    else
                    {
                        g_GameManager.currentPower -= 16;
                    }
                    g_Gui.flags.flag2 = 2;
                }
                else
                {
                    g_ItemManager.SpawnItem(&p->positionCenter, ITEM_FULL_POWER, 2);
                    g_ItemManager.SpawnItem(&p->positionCenter, ITEM_FULL_POWER, 2);
                    g_ItemManager.SpawnItem(&p->positionCenter, ITEM_FULL_POWER, 2);
                    g_ItemManager.SpawnItem(&p->positionCenter, ITEM_FULL_POWER, 2);
                    g_ItemManager.SpawnItem(&p->positionCenter, ITEM_FULL_POWER, 2);
                    g_GameManager.currentPower = 0;
                    g_Gui.flags.flag2 = 2;
                    g_GameManager.extraLives = 255;
                }
                g_GameManager.DecreaseSubrank(1600);
            }
        }
        else
        {
            scaleFactor1 = p->invulnerabilityTimer.AsFramesFloat() / 30.0f;
            p->playerSprite.scaleY = 3.0f * scaleFactor1 + 1.0f;
            p->playerSprite.scaleX = 1.0f - 1.0f * scaleFactor1;
            p->playerSprite.color =
                COLOR_SET_ALPHA(COLOR_WHITE, (u32)(255.0f - p->invulnerabilityTimer.AsFramesFloat() * 255.0f / 30.0f));
            p->playerSprite.flags.blendMode = AnmVmBlendMode_One;
            p->previousHorizontalSpeed = 0.0f;
            p->previousVerticalSpeed = 0.0f;
            if (p->invulnerabilityTimer.AsFrames() >= 30)
            {
                p->playerState = PLAYER_STATE_SPAWNING;
                p->positionCenter.x = g_GameManager.arcadeRegionSize.x / 2.0f;
                p->positionCenter.y = g_GameManager.arcadeRegionSize.y - 64.0f;
                p->positionCenter.z = 0.2;
                p->invulnerabilityTimer.SetCurrent(0);
                p->playerSprite.scaleX = 3.0;
                p->playerSprite.scaleY = 3.0;
                g_AnmManager->SetAndExecuteScriptIdx(&p->playerSprite, ANM_SCRIPT_PLAYER_IDLE);
                if (g_GameManager.livesRemaining <= 0)
                {
                    g_GameManager.isInRetryMenu = 1;
                }
                else
                {
                    g_GameManager.livesRemaining--;
                    g_Gui.flags.flag0 = 2;
                    if (g_GameManager.difficulty < 4 && g_GameManager.isInPracticeMode == 0)
                    {
                        g_GameManager.bombsRemaining = g_Supervisor.defaultConfig.bombCount;
                    }
                    else
                    {
                        g_GameManager.bombsRemaining = 3;
                    }
                    g_Gui.flags.flag1 = 2;
                    goto spawning;
                }
            }
        }
    }
    else if (p->playerState == PLAYER_STATE_SPAWNING)
    {
    spawning:
        p->bulletGracePeriod = 90;
        scaleFactor2 = 1.0f - p->invulnerabilityTimer.AsFramesFloat() / 30.0f;
        p->playerSprite.scaleY = 2.0f * scaleFactor2 + 1.0f;
        p->playerSprite.scaleX = 1.0f - 1.0f * scaleFactor2;
        p->playerSprite.flags.blendMode = AnmVmBlendMode_One;
        p->verticalMovementSpeedMultiplierDuringBomb = 1.0;
        p->horizontalMovementSpeedMultiplierDuringBomb = 1.0;
        p->playerSprite.color = COLOR_SET_ALPHA(COLOR_WHITE, p->invulnerabilityTimer.AsFrames() * 255 / 30);
        p->respawnTimer = 0;
        if (30 <= p->invulnerabilityTimer.AsFrames())
        {
            p->playerState = PLAYER_STATE_INVULNERABLE;
            p->playerSprite.scaleX = 1.0;
            p->playerSprite.scaleY = 1.0;
            p->playerSprite.color = COLOR_WHITE;
            p->playerSprite.flags.blendMode = AnmVmBlendMode_InvSrcAlpha;
            p->invulnerabilityTimer.SetCurrent(240);
            p->respawnTimer = 6;
        }
    }
    if (p->bulletGracePeriod != 0)
    {
        p->bulletGracePeriod--;
        g_BulletManager.RemoveAllBullets(0);
    }
    if (p->playerState == PLAYER_STATE_INVULNERABLE)
    {
        p->invulnerabilityTimer.Decrement(1);
        if (p->invulnerabilityTimer.AsFrames() <= 0)
        {
            p->playerState = PLAYER_STATE_ALIVE;
            p->invulnerabilityTimer.SetCurrent(0);
            p->playerSprite.flags.colorOp = AnmVmColorOp_Modulate;
            p->playerSprite.color = COLOR_WHITE;
        }
        else if (p->invulnerabilityTimer.AsFrames() % 8 < 2)
        {
            p->playerSprite.flags.colorOp = AnmVmColorOp_Add;
            p->playerSprite.color = 0xff404040;
        }
        else
        {
            p->playerSprite.flags.colorOp = AnmVmColorOp_Modulate;
            p->playerSprite.color = COLOR_WHITE;
        }
    }
    else
    {
        p->invulnerabilityTimer.Tick();
    }
    if (p->playerState != PLAYER_STATE_DEAD && p->playerState != PLAYER_STATE_SPAWNING)
    {
        p->HandlePlayerInputs();
    }
    g_AnmManager->ExecuteScript(&p->playerSprite);
    Player::UpdatePlayerBullets(p);
    if (p->orbState != ORB_HIDDEN)
    {
        g_AnmManager->ExecuteScript(&p->orbsSprite[0]);
        g_AnmManager->ExecuteScript(&p->orbsSprite[1]);
    }
    lastEnemyHit.x = -999.0;
    lastEnemyHit.y = -999.0;
    lastEnemyHit.z = 0.0;
    p->positionOfLastEnemyHit = lastEnemyHit;
    Player::UpdateFireBulletsTimer(p);
    return CHAIN_CALLBACK_RESULT_CONTINUE;
}

#pragma var_order(bullet, idx, enemyBottomRight, bulletBottomRight, enemyTopLeft, damage, bulletTopLeft)
i32 Player::CalcDamageToEnemy(D3DXVECTOR3 *enemyPos, D3DXVECTOR3 *enemyHitboxSize, ZunBool *hitWithLazerDuringBomb)
{
    ZunVec3 bulletTopLeft;
    i32 damage;
    ZunVec3 enemyTopLeft;
    i32 idx;
    PlayerBullet *bullet;

    ZunVec3 bulletBottomRight;
    ZunVec3 enemyBottomRight;

    damage = 0;

    ZunVec3::SetVecCorners(&enemyTopLeft, &enemyBottomRight, enemyPos, enemyHitboxSize);
    bullet = &this->bullets[0];
    if (hitWithLazerDuringBomb)
    {
        *hitWithLazerDuringBomb = false;
    }
    for (idx = 0; idx < ARRAY_SIZE_SIGNED(this->bullets); idx++, bullet++)
    {
        if (bullet->bulletState == BULLET_STATE_UNUSED ||
            bullet->bulletState != BULLET_STATE_FIRED && bullet->bulletType != BULLET_TYPE_2)
        {
            continue;
        }

        ZunVec3::SetVecCorners(&bulletTopLeft, &bulletBottomRight, &bullet->position, &bullet->size);

        if (bulletTopLeft.y > enemyBottomRight.y || bulletTopLeft.x > enemyBottomRight.x ||
            bulletBottomRight.y < enemyTopLeft.y || bulletBottomRight.x < enemyTopLeft.x)
        {
            continue;
        }
        /* Bullet is hitting the enemy */
        if (!this->bombInfo.isInUse)
        {
            damage += bullet->damage;
        }
        else
        {
            damage += bullet->damage / 3 != 0 ? bullet->damage / 3 : 1;
        }

        if (bullet->bulletType == BULLET_TYPE_2)
        {
            bullet->damage = bullet->damage / 4;
            if (bullet->damage == 0)
            {
                bullet->damage = 1;
            }
            switch (bullet->sprite.anmFileIndex)
            {
            case ANM_SCRIPT_PLAYER_MARISA_A_ORB_BULLET_1:
                bullet->size.x = 32.0f;
                bullet->size.y = 32.0f;
                break;
            case ANM_SCRIPT_PLAYER_MARISA_A_ORB_BULLET_2:
                bullet->size.x = 42.0f;
                bullet->size.y = 42.0f;
                break;
            case ANM_SCRIPT_PLAYER_MARISA_A_ORB_BULLET_3:
                bullet->size.x = 48.0f;
                bullet->size.y = 48.0f;
                break;
            case ANM_SCRIPT_PLAYER_MARISA_A_ORB_BULLET_4:
                bullet->size.x = 48.0f;
                bullet->size.y = 48.0f;
            }
            if (bullet->unk_140.AsFrames() % 6 == 0)
            {
                g_EffectManager.SpawnParticles(PARTICLE_EFFECT_UNK_5, &bullet->position, 1, COLOR_WHITE);
            }
        }

        if (bullet->bulletType != BULLET_TYPE_LASER)
        {
            if (bullet->bulletState == BULLET_STATE_FIRED)
            {
                g_AnmManager->SetAndExecuteScriptIdx(&bullet->sprite, bullet->sprite.anmFileIndex + 0x20);
                g_EffectManager.SpawnParticles(PARTICLE_EFFECT_UNK_5, &bullet->position, 1, COLOR_WHITE);
                bullet->position.z = 0.1;
            }
            bullet->bulletState = BULLET_STATE_COLLIDED;
            bullet->velocity.x /= 8.0f;
            bullet->velocity.y /= 8.0f;
        }
        else
        {
            this->unk_9e4++;
            if (this->unk_9e4 % 8 == 0)
            {
                *bulletTopLeft.AsD3dXVec() = *enemyPos;
                bulletTopLeft.x = bullet->position.x;

                g_EffectManager.SpawnParticles(PARTICLE_EFFECT_UNK_5, bulletTopLeft.AsD3dXVec(), 1, COLOR_WHITE);
            }
        }
    }
    for (idx = 0; idx < ARRAY_SIZE_SIGNED(this->bombRegionSizes); idx++)
    {
        if (this->bombRegionSizes[idx].x <= 0.0f)
        {
            continue;
        }

        *bulletTopLeft.AsD3dXVec() = this->bombRegionPositions[idx] - this->bombRegionSizes[idx] / 2.0f;
        *bulletBottomRight.AsD3dXVec() = this->bombRegionPositions[idx] + this->bombRegionSizes[idx] / 2.0f;
        if (bulletTopLeft.x > enemyBottomRight.x || bulletBottomRight.x < enemyTopLeft.x ||
            bulletTopLeft.y > enemyBottomRight.y || bulletBottomRight.y < enemyTopLeft.y)
        {
            continue;
        }
        damage += this->bombRegionDamages[idx];
        this->unk_838[idx] += this->bombRegionDamages[idx];
        this->unk_9e4++;
        if (this->unk_9e4 % 4 == 0)
        {
            g_EffectManager.SpawnParticles(PARTICLE_EFFECT_UNK_3, enemyPos, 1, COLOR_WHITE);
        }
        if (this->bombInfo.isInUse && hitWithLazerDuringBomb)
        {
            *hitWithLazerDuringBomb = true;
        }
    }
    return damage;
}

#pragma var_order(vector, idx, vecLength, bullet)
void Player::UpdatePlayerBullets(Player *player)
{
    ZunVec2 vector;
    PlayerBullet *bullet;
    f32 vecLength;
    i32 idx;

    for (idx = 0; idx < ARRAY_SIZE_SIGNED(player->laserTimer); idx++)
    {
        if (player->laserTimer[idx].AsFrames() != 0)
        {
            player->laserTimer[idx].Decrement(1);
        }
    }
    bullet = &player->bullets[0];
    for (idx = 0; idx < ARRAY_SIZE_SIGNED(player->bullets); idx++, bullet++)
    {
        if (bullet->bulletState == BULLET_STATE_UNUSED)
        {
            continue;
        }

        switch (bullet->bulletType)
        {
        case BULLET_TYPE_1:
            if (bullet->bulletState == BULLET_STATE_FIRED)
            {
                if (player->positionOfLastEnemyHit.x > -100.0f && bullet->unk_140.AsFrames() < 40 &&
                    bullet->unk_140.HasTicked())
                {
                    vector.x = player->positionOfLastEnemyHit.x - bullet->position.x;
                    vector.y = player->positionOfLastEnemyHit.y - bullet->position.y;

                    vecLength = vector.VectorLength() / (bullet->unk_134.y / 4.0f);
                    if (vecLength < 1.0f)
                    {
                        vecLength = 1.0f;
                    }

                    vector.x = vector.x / vecLength + bullet->velocity.x;
                    vector.y = vector.y / vecLength + bullet->velocity.y;

                    vecLength = vector.VectorLengthF64();

                    bullet->unk_134.y = ZUN_MIN(vecLength, 10.0f);

                    if (bullet->unk_134.y < 1.0f)
                    {
                        bullet->unk_134.y = 1.0f;
                    }

                    bullet->velocity.x = (vector.x * bullet->unk_134.y) / vecLength;
                    bullet->velocity.y = (vector.y * bullet->unk_134.y) / vecLength;
                }
                else
                {
                    if (bullet->unk_134.y < 10.0f)
                    {
                        bullet->unk_134.y += 0.33333333f;
                        vector.x = bullet->velocity.x;
                        vector.y = bullet->velocity.y;
                        vecLength = vector.VectorLengthF64();
                        bullet->velocity.x = vector.x * bullet->unk_134.y / vecLength;
                        bullet->velocity.y = vector.y * bullet->unk_134.y / vecLength;
                    }
                }
            }

            break;

        case BULLET_TYPE_2:
            if (bullet->bulletState == BULLET_STATE_FIRED)
            {
                bullet->velocity.y -= 0.3f;
            }
            break;
        case BULLET_TYPE_LASER:

            if (player->laserTimer[bullet->unk_152] == 70)
            {
                bullet->sprite.pendingInterrupt = 1;
            }
            else if (player->laserTimer[bullet->unk_152] == 1)
            {
                bullet->sprite.pendingInterrupt = 1;
            }

            bullet->position = player->orbsPosition[bullet->spawnPositionIdx - 1];

            bullet->position.x += bullet->sidewaysMotion;
            bullet->position.y /= 2.0f;
            bullet->position.z = 0.44f;

            bullet->sprite.scaleY = (bullet->position.y * 2) / 14.0f;

            bullet->size.y = bullet->position.y * 2;
            break;
        }

        bullet->MoveHorizontal(&bullet->position.x);

        bullet->MoveVertical(&bullet->position.y);

        bullet->sprite.pos.z = bullet->position.z;
        if (bullet->bulletType != BULLET_TYPE_LASER &&
            !g_GameManager.IsInBounds(bullet->position.x, bullet->position.y, bullet->sprite.sprite->widthPx,
                                      bullet->sprite.sprite->heightPx))
        {
            bullet->bulletState = BULLET_STATE_UNUSED;
        }

        if (g_AnmManager->ExecuteScript(&bullet->sprite))
        {
            bullet->bulletState = BULLET_STATE_UNUSED;
        }
        bullet->unk_140.Tick();
    }
}

#pragma var_order(x1, y1, x2, y2)
ChainCallbackResult Player::OnDrawHighPrio(Player *p)
{
    Player::DrawBullets(p);
    if (p->bombInfo.isInUse != 0 && p->bombInfo.draw != NULL)
    {
        p->bombInfo.draw(p);
    }
    p->playerSprite.pos.x = g_GameManager.arcadeRegionTopLeftPos.x + p->positionCenter.x;
    p->playerSprite.pos.y = g_GameManager.arcadeRegionTopLeftPos.y + p->positionCenter.y;
    p->playerSprite.pos.z = 0.49;
    if (!g_GameManager.isInRetryMenu)
    {
        g_AnmManager->DrawNoRotation(&p->playerSprite);
        if (p->orbState != ORB_HIDDEN &&
            (p->playerState == PLAYER_STATE_ALIVE || p->playerState == PLAYER_STATE_INVULNERABLE))
        {
            p->orbsSprite[0].pos = p->orbsPosition[0];
            p->orbsSprite[1].pos = p->orbsPosition[1];
            f32 *x1 = &p->orbsSprite[0].pos.x;
            *x1 += g_GameManager.arcadeRegionTopLeftPos.x;
            f32 *y1 = &p->orbsSprite[0].pos.y;
            *y1 += g_GameManager.arcadeRegionTopLeftPos.y;
            f32 *x2 = &p->orbsSprite[1].pos.x;
            *x2 += g_GameManager.arcadeRegionTopLeftPos.x;
            f32 *y2 = &p->orbsSprite[1].pos.y;
            *y2 += g_GameManager.arcadeRegionTopLeftPos.y;
            p->orbsSprite[0].pos.z = 0.491;
            p->orbsSprite[1].pos.z = 0.491;
            g_AnmManager->Draw(&p->orbsSprite[0]);
            g_AnmManager->Draw(&p->orbsSprite[1]);
        }
    }
    return CHAIN_CALLBACK_RESULT_CONTINUE;
}

ChainCallbackResult Player::OnDrawLowPrio(Player *p)
{
    Player::DrawBulletExplosions(p);
    return CHAIN_CALLBACK_RESULT_CONTINUE;
}

#pragma var_order(playerDirection, verticalSpeed, horizontalSpeed, verticalOrbOffset, horizontalOrbOffset,             \
                  intermediateFloat, posCenterY, posCenterX)
ZunResult Player::HandlePlayerInputs()
{
    float intermediateFloat;

    float *posCenterY;
    float *posCenterX;
    float horizontalOrbOffset;
    float verticalOrbOffset;

    float horizontalSpeed = 0.0;
    float verticalSpeed = 0.0;
    PlayerDirection playerDirection = this->playerDirection;

    this->playerDirection = MOVEMENT_NONE;
    if (IS_PRESSED(TH_BUTTON_UP))
    {
        this->playerDirection = MOVEMENT_UP;
        if (IS_PRESSED(TH_BUTTON_LEFT))
        {
            this->playerDirection = MOVEMENT_UP_LEFT;
        }
        if (IS_PRESSED(TH_BUTTON_RIGHT))
        {
            this->playerDirection = MOVEMENT_UP_RIGHT;
        }
    }
    else
    {
        if (IS_PRESSED(TH_BUTTON_DOWN))
        {
            this->playerDirection = MOVEMENT_DOWN;
            if (IS_PRESSED(TH_BUTTON_LEFT))
            {
                this->playerDirection = MOVEMENT_DOWN_LEFT;
            }
            if (IS_PRESSED(TH_BUTTON_RIGHT))
            {
                this->playerDirection = MOVEMENT_DOWN_RIGHT;
            }
        }
        else
        {
            if (IS_PRESSED(TH_BUTTON_LEFT))
            {
                this->playerDirection = MOVEMENT_LEFT;
            }
            if (IS_PRESSED(TH_BUTTON_RIGHT))
            {
                this->playerDirection = MOVEMENT_RIGHT;
            }
        }
    }
    if (IS_PRESSED(TH_BUTTON_FOCUS))
    {
        this->isFocus = true;
    }
    else
    {
        this->isFocus = false;
    }

    switch (this->playerDirection)
    {
    case MOVEMENT_RIGHT:
        if (IS_PRESSED(TH_BUTTON_FOCUS))
        {
            horizontalSpeed = this->characterData.orthogonalMovementSpeedFocus;
        }
        else
        {
            horizontalSpeed = this->characterData.orthogonalMovementSpeed;
        }
        break;
    case MOVEMENT_LEFT:
        if (IS_PRESSED(TH_BUTTON_FOCUS))
        {
            horizontalSpeed = -this->characterData.orthogonalMovementSpeedFocus;
        }
        else
        {
            horizontalSpeed = -this->characterData.orthogonalMovementSpeed;
        }
        break;
    case MOVEMENT_UP:
        if (IS_PRESSED(TH_BUTTON_FOCUS))
        {
            verticalSpeed = -this->characterData.orthogonalMovementSpeedFocus;
        }
        else
        {
            verticalSpeed = -this->characterData.orthogonalMovementSpeed;
        }
        break;
    case MOVEMENT_DOWN:
        if (IS_PRESSED(TH_BUTTON_FOCUS))
        {
            verticalSpeed = this->characterData.orthogonalMovementSpeedFocus;
        }
        else
        {
            verticalSpeed = this->characterData.orthogonalMovementSpeed;
        }
        break;
    case MOVEMENT_UP_LEFT:
        if (IS_PRESSED(TH_BUTTON_FOCUS))
        {
            horizontalSpeed = -this->characterData.diagonalMovementSpeedFocus;
        }
        else
        {
            horizontalSpeed = -this->characterData.diagonalMovementSpeed;
        }
        verticalSpeed = horizontalSpeed;
        break;
    case MOVEMENT_DOWN_LEFT:
        if (IS_PRESSED(TH_BUTTON_FOCUS))
        {
            horizontalSpeed = -this->characterData.diagonalMovementSpeedFocus;
        }
        else
        {
            horizontalSpeed = -this->characterData.diagonalMovementSpeed;
        }
        verticalSpeed = -horizontalSpeed;
        break;
    case MOVEMENT_UP_RIGHT:
        if (IS_PRESSED(TH_BUTTON_FOCUS))
        {
            horizontalSpeed = this->characterData.diagonalMovementSpeedFocus;
        }
        else
        {
            horizontalSpeed = this->characterData.diagonalMovementSpeed;
        }
        verticalSpeed = -horizontalSpeed;
        break;
    case MOVEMENT_DOWN_RIGHT:
        if (IS_PRESSED(TH_BUTTON_FOCUS))
        {
            horizontalSpeed = this->characterData.diagonalMovementSpeedFocus;
        }
        else
        {
            horizontalSpeed = this->characterData.diagonalMovementSpeed;
        }
        verticalSpeed = horizontalSpeed;
    }

    if (horizontalSpeed < 0.0f && this->previousHorizontalSpeed >= 0.0f)
    {
        g_AnmManager->SetAndExecuteScriptIdx(&this->playerSprite, ANM_SCRIPT_PLAYER_MOVING_LEFT);
    }
    else if (!horizontalSpeed && this->previousHorizontalSpeed < 0.0f)
    {
        g_AnmManager->SetAndExecuteScriptIdx(&this->playerSprite, ANM_SCRIPT_PLAYER_STOPPING_LEFT);
    }

    if (horizontalSpeed > 0.0f && this->previousHorizontalSpeed <= 0.0f)
    {
        g_AnmManager->SetAndExecuteScriptIdx(&this->playerSprite, ANM_SCRIPT_PLAYER_MOVING_RIGHT);
    }
    else if (!horizontalSpeed && this->previousHorizontalSpeed > 0.0f)
    {
        g_AnmManager->SetAndExecuteScriptIdx(&this->playerSprite, ANM_SCRIPT_PLAYER_STOPPING_RIGHT);
    }

    this->previousHorizontalSpeed = horizontalSpeed;
    this->previousVerticalSpeed = verticalSpeed;

    // TODO: Match stack variables here
    posCenterX = &this->positionCenter.x;
    *posCenterX +=
        horizontalSpeed * this->horizontalMovementSpeedMultiplierDuringBomb * g_Supervisor.effectiveFramerateMultiplier;
    posCenterY = &this->positionCenter.y;
    *posCenterY +=
        verticalSpeed * this->verticalMovementSpeedMultiplierDuringBomb * g_Supervisor.effectiveFramerateMultiplier;

    if (this->positionCenter.x < g_GameManager.playerMovementAreaTopLeftPos.x)
    {
        this->positionCenter.x = g_GameManager.playerMovementAreaTopLeftPos.x;
    }
    else if (g_GameManager.playerMovementAreaTopLeftPos.x + g_GameManager.playerMovementAreaSize.x <
             this->positionCenter.x)
    {
        this->positionCenter.x = g_GameManager.playerMovementAreaTopLeftPos.x + g_GameManager.playerMovementAreaSize.x;
    }

    if (this->positionCenter.y < g_GameManager.playerMovementAreaTopLeftPos.y)
    {
        this->positionCenter.y = g_GameManager.playerMovementAreaTopLeftPos.y;
    }
    else if (g_GameManager.playerMovementAreaTopLeftPos.y + g_GameManager.playerMovementAreaSize.y <
             this->positionCenter.y)
    {
        this->positionCenter.y = g_GameManager.playerMovementAreaTopLeftPos.y + g_GameManager.playerMovementAreaSize.y;
    }

    this->hitboxTopLeft = this->positionCenter - this->hitboxSize;

    this->hitboxBottomRight = this->positionCenter + this->hitboxSize;

    this->grabItemTopLeft = this->positionCenter - this->grabItemSize;

    this->grabItemBottomRight = this->positionCenter + this->grabItemSize;

    this->orbsPosition[0] = this->positionCenter;
    this->orbsPosition[1] = this->positionCenter;

    verticalOrbOffset = 0.0;
    horizontalOrbOffset = verticalOrbOffset;

    if (g_GameManager.currentPower < 8)
    {
        this->orbState = ORB_HIDDEN;
    }
    else if (this->orbState == ORB_HIDDEN)
    {
        this->orbState = ORB_UNFOCUSED;
    }

    switch (this->orbState)
    {
    case ORB_HIDDEN:
        this->focusMovementTimer.InitializeForPopup();
        break;

    case ORB_UNFOCUSED:
        horizontalOrbOffset = 24.0;
        this->focusMovementTimer.InitializeForPopup();
        if (this->isFocus)
        {
            this->orbState = ORB_FOCUSING;
        }
        else
        {
            break;
        }

    CASE_ORB_FOCUSING:
    case ORB_FOCUSING:
        this->focusMovementTimer.Tick();

        intermediateFloat = this->focusMovementTimer.AsFramesFloat() / 8.0f;
        verticalOrbOffset = (1.0f - intermediateFloat) * 32.0f + -32.0f;
        intermediateFloat *= intermediateFloat;
        horizontalOrbOffset = -16.0f * intermediateFloat + 24.0f;

        if ((ZunBool)(this->focusMovementTimer.current >= 8))
        {
            this->orbState = ORB_FOCUSED;
        }
        if (!this->isFocus)
        {

            this->orbState = ORB_UNFOCUSING;
            this->focusMovementTimer.SetCurrent(8 - this->focusMovementTimer.AsFrames());

            goto CASE_ORB_UNFOCUSING;
        }
        else
        {
            break;
        }

    case ORB_FOCUSED:
        horizontalOrbOffset = 8.0;
        verticalOrbOffset = -32.0;
        this->focusMovementTimer.InitializeForPopup();
        if (!this->isFocus)
        {
            this->orbState = ORB_UNFOCUSING;
        }
        else
        {
            break;
        }

    CASE_ORB_UNFOCUSING:
    case ORB_UNFOCUSING:
        this->focusMovementTimer.Tick();

        intermediateFloat = this->focusMovementTimer.AsFramesFloat() / 8.0f;
        verticalOrbOffset = (32.0f * intermediateFloat) + -32.0f;
        intermediateFloat *= intermediateFloat;
        intermediateFloat = 1.0f - intermediateFloat;
        horizontalOrbOffset = -16.0f * intermediateFloat + 24.0f;
        if ((ZunBool)(this->focusMovementTimer.current >= 8))
        {
            this->orbState = ORB_UNFOCUSED;
        }
        if (this->isFocus)
        {
            this->orbState = ORB_FOCUSING;
            this->focusMovementTimer.SetCurrent(8 - this->focusMovementTimer.AsFrames());
            goto CASE_ORB_FOCUSING;
        }
    }

    this->orbsPosition[0].x -= horizontalOrbOffset;
    this->orbsPosition[1].x += horizontalOrbOffset;
    this->orbsPosition[0].y += verticalOrbOffset;
    this->orbsPosition[1].y += verticalOrbOffset;
    if (IS_PRESSED(TH_BUTTON_SHOOT) && !g_Gui.HasCurrentMsgIdx())
    {
        this->StartFireBulletTimer(this);
    }
    this->previousFrameInput = g_CurFrameInput;
    return ZUN_SUCCESS;
}

#pragma var_order(bulletIdx, bullets)
void Player::DrawBullets(Player *p)
{
    i32 bulletIdx;
    PlayerBullet *bullets;

    bullets = p->bullets;
    for (bulletIdx = 0; bulletIdx < ARRAY_SIZE_SIGNED(p->bullets); bulletIdx++, bullets++)
    {
        if (bullets->bulletState != BULLET_STATE_FIRED)
        {
            continue;
        }
        if (bullets->sprite.autoRotate)
        {
            bullets->sprite.rotation.z = ZUN_PI / 2 - utils::AddNormalizeAngle(bullets->unk_134.z, ZUN_PI);
        }
        g_AnmManager->Draw2(&bullets->sprite);
    }
}

#pragma var_order(bulletIdx, bullets)
void Player::DrawBulletExplosions(Player *p)
{
    i32 bulletIdx;
    PlayerBullet *bullets;

    bullets = p->bullets;
    for (bulletIdx = 0; bulletIdx < ARRAY_SIZE_SIGNED(p->bullets); bulletIdx++, bullets++)
    {
        if (bullets->bulletState != BULLET_STATE_COLLIDED)
        {
            continue;
        }
        if (bullets->sprite.autoRotate)
        {
            bullets->sprite.rotation.z = ZUN_PI / 2 - utils::AddNormalizeAngle(bullets->unk_134.z, ZUN_PI);
        }
        bullets->sprite.pos.z = 0.4f;
        g_AnmManager->Draw2(&bullets->sprite);
    }
}

void Player::StartFireBulletTimer(Player *p)
{
    if (p->fireBulletTimer.AsFrames() < 0)
    {
        p->fireBulletTimer.InitializeForPopup();
    }
}

ZunResult Player::UpdateFireBulletsTimer(Player *p)
{
    if (p->fireBulletTimer.AsFrames() < 0)
    {
        return ZUN_SUCCESS;
    }

    if (p->fireBulletTimer.HasTicked() && (!g_Player.bombInfo.isInUse || g_GameManager.character != CHARA_MARISA ||
                                           g_GameManager.shotType != SHOT_TYPE_B))
    {
        p->SpawnBullets(p, p->fireBulletTimer.AsFrames());
    }

    p->fireBulletTimer.Tick();

    if (p->fireBulletTimer.AsFrames() >= 30 || p->playerState == PLAYER_STATE_DEAD ||
        p->playerState == PLAYER_STATE_SPAWNING)
    {
        p->fireBulletTimer.SetCurrent(-1);
    }
    return ZUN_SUCCESS;
}

#pragma var_order(relY, relX)
f32 Player::AngleFromPlayer(D3DXVECTOR3 *pos)
{
    f32 relX;
    f32 relY;

    relX = pos->x - this->positionCenter.x;
    relY = pos->y - this->positionCenter.y;
    if (relY == 0.0f && relX == 0.0f)
    {
        return ZUN_PI / 2;
    }
    return atan2f(relY, relX);
}

#pragma var_order(relY, relX)
f32 Player::AngleToPlayer(D3DXVECTOR3 *pos)
{
    f32 relX;
    f32 relY;

    relX = this->positionCenter.x - pos->x;
    relY = this->positionCenter.y - pos->y;
    if (relY == 0.0f && relX == 0.0f)
    {
        // Shoot down. An angle of 0 means to the right, and the angle goes
        // clockwise.
        return RADIANS(90.0f);
    }
    return atan2f(relY, relX);
}

#pragma var_order(idx, curBulletIdx, curBullet, bulletResult)
void Player::SpawnBullets(Player *p, u32 timer)
{
    FireBulletResult bulletResult;
    PlayerBullet *curBullet;
    i32 curBulletIdx;
    u32 idx;

    idx = 0;
    curBullet = p->bullets;

    for (curBulletIdx = 0; curBulletIdx < ARRAY_SIZE_SIGNED(p->bullets); curBulletIdx++, curBullet++)
    {
        if (curBullet->bulletState != BULLET_STATE_UNUSED)
        {
            continue;
        }
    WHILE_LOOP:
        if (!p->isFocus)
        {
            bulletResult = (*p->fireBulletCallback)(p, curBullet, idx, timer);
        }
        else
        {
            bulletResult = (*p->fireBulletFocusCallback)(p, curBullet, idx, timer);
        }
        if (bulletResult >= 0)
        {
            curBullet->sprite.pos.x = curBullet->position.x;
            curBullet->sprite.pos.y = curBullet->position.y;
            curBullet->sprite.pos.z = 0.495;
            curBullet->bulletState = BULLET_STATE_FIRED;
        }
        if (bulletResult == FBR_STOP_SPAWNING)
        {
            return;
        }
        if (bulletResult > 0)
        {
            return;
        }
        idx++;
        if (bulletResult == FBR_SPAWN_MORE)
        {
            goto WHILE_LOOP;
        }
    }
}

#pragma var_order(bulletData, bulletFrame, pfVar4, unused, unused2)
FireBulletResult Player::FireSingleBullet(Player *player, PlayerBullet *bullet, i32 bulletIdx,
                                          i32 framesSinceLastBullet, CharacterPowerData *powerData)
{
    CharacterPowerBulletData *bulletData;
    f32 *pfVar4;
    i32 bulletFrame;
    i32 unused;
    i32 unused2;

    while (g_GameManager.currentPower >= powerData->power)
    {
        powerData++;
    }

    bulletData = powerData->bullets + bulletIdx;

    if (bulletData->bulletType == BULLET_TYPE_LASER)
    {
        bulletFrame = bulletData->bulletFrame;
        if (!player->laserTimer[bulletFrame].AsFrames())
        {
            player->laserTimer[bulletFrame].SetCurrent(bulletData->waitBetweenBullets);

            bullet->unk_152 = bulletFrame;
            bullet->spawnPositionIdx = bulletData->spawnPositionIdx;
            bullet->sidewaysMotion = bulletData->motion.x;
            bullet->unk_134.x = bulletData->motion.y;
            goto SHOOT_BULLET;
        }
    }
    else if (framesSinceLastBullet % bulletData->waitBetweenBullets == bulletData->bulletFrame)
    {
    SHOOT_BULLET:

        g_AnmManager->SetAndExecuteScriptIdx(&bullet->sprite, bulletData->anmFileIdx);
        if (!bulletData->spawnPositionIdx)
        {
            bullet->position = player->positionCenter;
        }
        else
        {
            bullet->position = player->orbsPosition[bulletData->spawnPositionIdx - 1];
        }
        pfVar4 = &bullet->position.x;
        *pfVar4 = *pfVar4 + bulletData->motion.x;
        pfVar4 = &bullet->position.y;
        *pfVar4 = *pfVar4 + bulletData->motion.y;

        bullet->position.z = 0.495f;

        bullet->size.x = bulletData->size.x;
        bullet->size.y = bulletData->size.y;
        bullet->size.z = 1.0f;
        bullet->unk_134.z = bulletData->direction;
        bullet->unk_134.y = bulletData->velocity;

        bullet->velocity.x = cosf(bulletData->direction) * bulletData->velocity;

        bullet->velocity.y = sinf(bulletData->direction) * bulletData->velocity;

        bullet->unk_140.InitializeForPopup();

        bullet->bulletType = bulletData->bulletType;
        bullet->damage = bulletData->unk_1c;
        if (bulletData->bulletSoundIdx >= 0)
        {
            g_SoundPlayer.PlaySoundByIdx((SoundIdx)bulletData->bulletSoundIdx, 0);
        }

        return bulletIdx >= powerData->numBullets - 1;
    }

    if (bulletIdx >= powerData->numBullets - 1)
    {
        return FBR_STOP_SPAWNING;
    }
    else
    {
        return FBR_SPAWN_MORE;
    }
}

FireBulletResult Player::FireBulletReimuA(Player *player, PlayerBullet *bullet, u32 bulletIdx,
                                          u32 framesSinceLastBullet)
{
    return player->FireSingleBullet(player, bullet, bulletIdx, framesSinceLastBullet, g_CharacterPowerDataReimuA);
}

FireBulletResult Player::FireBulletReimuB(Player *player, PlayerBullet *bullet, u32 bulletIdx,
                                          u32 framesSinceLastBullet)
{
    return player->FireSingleBullet(player, bullet, bulletIdx, framesSinceLastBullet, g_CharacterPowerDataReimuB);
}

FireBulletResult Player::FireBulletMarisaA(Player *player, PlayerBullet *bullet, u32 bulletIdx,
                                           u32 framesSinceLastBullet)
{
    return player->FireSingleBullet(player, bullet, bulletIdx, framesSinceLastBullet, g_CharacterPowerDataMarisaA);
}

FireBulletResult Player::FireBulletMarisaB(Player *player, PlayerBullet *bullet, u32 bulletIdx,
                                           u32 framesSinceLastBullet)
{
    return player->FireSingleBullet(player, bullet, bulletIdx, framesSinceLastBullet, g_CharacterPowerDataMarisaB);
}

#pragma var_order(bombTopLeft, i, bulletBottomRight, bulletTopLeft, bombProjectile, bombBottomRight)
i32 Player::CheckGraze(D3DXVECTOR3 *center, D3DXVECTOR3 *size)
{
    D3DXVECTOR3 bombBottomRight;
    PlayerRect *bombProjectile;
    D3DXVECTOR3 bombTopLeft;
    D3DXVECTOR3 bulletBottomRight;
    D3DXVECTOR3 bulletTopLeft;
    i32 i;

    bulletTopLeft.x = center->x - size->x / 2.0f - 20.0f;
    bulletTopLeft.y = center->y - size->y / 2.0f - 20.0f;
    bulletBottomRight.x = center->x + size->x / 2.0f + 20.0f;
    bulletBottomRight.y = center->y + size->y / 2.0f + 20.0f;
    bombProjectile = this->bombProjectiles;

    for (i = 0; i < ARRAY_SIZE_SIGNED(this->bombProjectiles); i++, bombProjectile++)
    {
        if (bombProjectile->size.x == 0.0f)
        {
            continue;
        }

        bombTopLeft.x = bombProjectile->pos.x - bombProjectile->size.x / 2.0f;
        bombTopLeft.y = bombProjectile->pos.y - bombProjectile->size.y / 2.0f;
        bombBottomRight.x = bombProjectile->size.x / 2.0f + bombProjectile->pos.x;
        bombBottomRight.y = bombProjectile->size.y / 2.0f + bombProjectile->pos.y;

        // Bomb clips bullet's hitbox, destroys bullet upon return
        if (!(bombTopLeft.x > bulletBottomRight.x || bombBottomRight.x < bulletTopLeft.x ||
              bombTopLeft.y > bulletBottomRight.y || bombBottomRight.y < bulletTopLeft.y))
        {
            return 2;
        }
    }

    if (this->playerState == PLAYER_STATE_DEAD || this->playerState == PLAYER_STATE_SPAWNING)
    {
        return 0;
    }
    if (this->hitboxTopLeft.x > bulletBottomRight.x || this->hitboxBottomRight.x < bulletTopLeft.x ||
        this->hitboxTopLeft.y > bulletBottomRight.y || this->hitboxBottomRight.y < bulletTopLeft.y)
    {
        return 0;
    }

    // Bullet clips player's graze hitbox, add score and check for death upon return
    this->ScoreGraze(center);
    return 1;
}

#pragma var_order(padding1, bombProjectileTop, bombProjectileLeft, curBombIdx, padding2, bulletBottom, bulletRight,    \
                  padding3, bulletTop, bulletLeft, curBombProjectile, padding4, bombProjectileBottom,                  \
                  bombProjectileRight)
i32 Player::CalcKillBoxCollision(D3DXVECTOR3 *bulletCenter, D3DXVECTOR3 *bulletSize)
{
    PlayerRect *curBombProjectile;
    f32 bulletLeft, bulletTop, bulletRight, bulletBottom;
    f32 bombProjectileLeft, bombProjectileTop, bombProjectileRight, bombProjectileBottom;
    i32 curBombIdx;
    i32 padding1, padding2, padding3, padding4;

    curBombProjectile = this->bombProjectiles;
    bulletLeft = bulletCenter->x - bulletSize->x / 2.0f;
    bulletTop = bulletCenter->y - bulletSize->y / 2.0f;
    bulletRight = bulletCenter->x + bulletSize->x / 2.0f;
    bulletBottom = bulletCenter->y + bulletSize->y / 2.0f;
    for (curBombIdx = 0; curBombIdx < ARRAY_SIZE_SIGNED(this->bombProjectiles); curBombIdx++, curBombProjectile++)
    {
        if (curBombProjectile->size.x == 0.0f)
        {
            continue;
        }
        bombProjectileLeft = curBombProjectile->pos.x - curBombProjectile->size.x / 2.0f;
        bombProjectileTop = curBombProjectile->pos.y - curBombProjectile->size.y / 2.0f;
        bombProjectileRight = curBombProjectile->pos.x + curBombProjectile->size.x / 2.0f;
        bombProjectileBottom = curBombProjectile->pos.y + curBombProjectile->size.y / 2.0f;
        if (!(bombProjectileLeft > bulletRight || bombProjectileRight < bulletLeft ||
              bombProjectileTop > bulletBottom || bombProjectileBottom < bulletTop))
        {
            return 2;
        }
    }
    if (this->hitboxTopLeft.x > bulletRight || this->hitboxTopLeft.y > bulletBottom ||
        this->hitboxBottomRight.x < bulletLeft || this->hitboxBottomRight.y < bulletTop)
    {
        return 0;
    }
    else if (this->playerState != PLAYER_STATE_ALIVE)
    {
        return 1;
    }
    else
    {
        this->Die();
        return 1;
    }
}

#pragma var_order(playerRelativeTopLeft, laserBottomRight, laserTopLeft, playerRelativeBottomRight)
i32 Player::CalcLaserHitbox(D3DXVECTOR3 *laserCenter, D3DXVECTOR3 *laserSize, D3DXVECTOR3 *rotation, f32 angle,
                            i32 canGraze)
{
    D3DXVECTOR3 laserTopLeft;
    D3DXVECTOR3 laserBottomRight;
    D3DXVECTOR3 playerRelativeTopLeft;
    D3DXVECTOR3 playerRelativeBottomRight;

    laserTopLeft = this->positionCenter - *rotation;
    utils::Rotate(&laserBottomRight, &laserTopLeft, angle);
    laserBottomRight.z = 0;
    laserTopLeft = laserBottomRight + *rotation;
    playerRelativeTopLeft = laserTopLeft - this->hitboxSize;
    playerRelativeBottomRight = laserTopLeft + this->hitboxSize;

    laserTopLeft = *laserCenter - *laserSize * invertf(2.0f);
    laserBottomRight = *laserCenter + *laserSize * invertf(2.0f);

    if (!(playerRelativeTopLeft.x > laserBottomRight.x || playerRelativeBottomRight.x < laserTopLeft.x ||
          playerRelativeTopLeft.y > laserBottomRight.y || playerRelativeBottomRight.y < laserTopLeft.y))
    {
        goto LASER_COLLISION;
    }
    if (canGraze == 0)
    {
        return 0;
    }

    laserTopLeft.x -= 48.0f;
    laserTopLeft.y -= 48.0f;
    laserBottomRight.x += 48.0f;
    laserBottomRight.y += 48.0f;

    if (playerRelativeTopLeft.x > laserBottomRight.x || playerRelativeBottomRight.x < laserTopLeft.x ||
        playerRelativeTopLeft.y > laserBottomRight.y || playerRelativeBottomRight.y < laserTopLeft.y)
    {
        return 0;
    }
    if (this->playerState == PLAYER_STATE_DEAD || this->playerState == PLAYER_STATE_SPAWNING)
    {
        return 0;
    }

    this->ScoreGraze(&this->positionCenter);
    return 2;

LASER_COLLISION:
    if (this->playerState != PLAYER_STATE_ALIVE)
    {
        return 0;
    }

    this->Die();
    return 1;
}

#pragma var_order(itemBottomRight, itemTopLeft)
i32 Player::CalcItemBoxCollision(D3DXVECTOR3 *itemCenter, D3DXVECTOR3 *itemSize)
{
    if (this->playerState != PLAYER_STATE_ALIVE && this->playerState != PLAYER_STATE_INVULNERABLE)
    {
        return 0;
    }
    D3DXVECTOR3 itemTopLeft;
    memcpy(&itemTopLeft, &(*itemCenter - *itemSize / 2.0f), sizeof(D3DXVECTOR3));
    D3DXVECTOR3 itemBottomRight;
    memcpy(&itemBottomRight, &(*itemCenter + *itemSize / 2.0f), sizeof(D3DXVECTOR3));

    if (this->grabItemTopLeft.x > itemBottomRight.x || this->grabItemBottomRight.x < itemTopLeft.x ||
        this->grabItemTopLeft.y > itemBottomRight.y || this->grabItemBottomRight.y < itemTopLeft.y)
    {
        return 0;
    }
    else
    {
        return 1;
    }
}

void Player::ScoreGraze(D3DXVECTOR3 *center)
{
    D3DXVECTOR3 particlePosition;

    if (g_Player.bombInfo.isInUse == 0)
    {
        if (g_GameManager.grazeInStage < 9999)
        {
            g_GameManager.grazeInStage++;
        }
        if (g_GameManager.grazeInTotal < 999999)
        {
            g_GameManager.grazeInTotal++;
        }
    }

    particlePosition = (this->positionCenter + *center) * invertf(2.0f);
    g_EffectManager.SpawnParticles(PARTICLE_EFFECT_UNK_8, &particlePosition, 1, COLOR_WHITE);
    g_GameManager.AddScore(500);
    g_GameManager.IncreaseSubrank(6);
    g_Gui.flags.flag3 = 2;
    g_SoundPlayer.PlaySoundByIdx(SOUND_GRAZE, 0);
}

#pragma var_order(curLaserTimerIdx)
void Player::Die()
{
    int curLaserTimerIdx;

    g_EnemyManager.spellcardInfo.isCapturing = 0;
    g_EffectManager.SpawnParticles(PARTICLE_EFFECT_UNK_12, &this->positionCenter, 1, COLOR_NEONBLUE);
    g_EffectManager.SpawnParticles(PARTICLE_EFFECT_UNK_6, &this->positionCenter, 16, COLOR_WHITE);
    this->playerState = PLAYER_STATE_DEAD;
    this->invulnerabilityTimer.InitializeForPopup();
    g_SoundPlayer.PlaySoundByIdx(SOUND_PICHUN, 0);
    g_GameManager.deaths++;
    for (curLaserTimerIdx = 0; curLaserTimerIdx < ARRAY_SIZE_SIGNED(this->laserTimer); curLaserTimerIdx++)
    {
        this->laserTimer[curLaserTimerIdx].SetCurrent(2);
    }
    return;
}

// MSVC allocates stack space for unused inlined variables and one of Zun's inlined bomb functions has an unused
// variable This keeps the stack where it should be for when that happens, since it isn't clear what the original
// function was
void inline WasteStackSpace()
{
    D3DXVECTOR3 waste;
}

#pragma var_order(angle, i, bombSprite, vecLength, bombPivot, bombIdx)
void Player::BombReimuACalc(Player *player)
{
    i32 i;
    f32 vecLength;
    i32 bombIdx;
    D3DXVECTOR3 bombPivot;
    AnmVm *bombSprite;
    ZunVec2 angle;

    if (player->bombInfo.timer >= player->bombInfo.duration)
    {
        g_Gui.EndPlayerSpellcard();
        player->bombInfo.isInUse = 0;
        return;
    }
    if (player->bombInfo.timer.HasTicked() && player->bombInfo.timer == 0)
    {
        g_Gui.ShowBombNamePortrait(ANM_SCRIPT_FACE_BOMB_PORTRAIT, TH_REIMU_A_BOMB_NAME);
        player->bombInfo.duration = 300;
        player->invulnerabilityTimer.SetCurrent(360);

        for (i = 0; i < 8; i = i + 1)
        {
            player->bombInfo.reimuABombProjectilesState[i] = 0;
        }
        g_ItemManager.RemoveAllItems();
        g_EffectManager.SpawnParticles(PARTICLE_EFFECT_UNK_12, &player->positionCenter, 1, COLOR_NEONBLUE);

        player->bombProjectiles[8].pos.x = (player->positionCenter).x;
        player->bombProjectiles[8].pos.y = (player->positionCenter).y;

        player->bombProjectiles[8].size.x = 256.0f;
        player->bombProjectiles[8].size.y = 256.0f;
    }
    if (player->bombInfo.timer >= 60 && player->bombInfo.timer < 180)
    {

        if (player->bombInfo.timer.AsFrames() % 16 == 0 && (i = (player->bombInfo.timer.AsFrames() - 60) / 16))
        {
            WasteStackSpace();
            WasteStackSpace();

            player->bombInfo.reimuABombProjectilesState[i] = 1;
            player->bombInfo.reimuABombProjectilesRelated[i] = 4.0f;
            player->bombInfo.bombRegionPositions[i] = player->positionCenter;

            angle.x = g_Rng.GetRandomF32ZeroToOne() * ZUN_2PI - ZUN_PI;

            player->bombInfo.bombRegionVelocities[i].x =
                cosf(angle.x) * player->bombInfo.reimuABombProjectilesRelated[i];

            player->bombInfo.bombRegionVelocities[i].y =
                sinf(angle.x) * player->bombInfo.reimuABombProjectilesRelated[i];
            player->unk_838[i] = 0;

            for (bombSprite = &player->bombInfo.sprites[0][i * 4], bombIdx = 0; bombIdx < 4; bombIdx++, bombSprite++)
            {
                g_AnmManager->ExecuteAnmIdx(bombSprite, ANM_SCRIPT_PLAYER_REIMU_A_BOMB_ARRAY + bombIdx);
            }
            g_SoundPlayer.PlaySoundByIdx(SOUND_BOMB_REIMU_A, 0);
        }
    }
    player->playerState = PLAYER_STATE_INVULNERABLE;
    for (i = 0; i < ARRAY_SIZE_SIGNED(player->bombInfo.reimuABombProjectilesState); i++)
    {
        if (player->bombInfo.reimuABombProjectilesState[i] == 0)
        {
            continue;
        }
        if (player->bombInfo.reimuABombProjectilesState[i] == 1)
        {
            if (player->bombInfo.timer.HasTicked())
            {
                if (player->positionOfLastEnemyHit.x > -100.0f)
                {
                    bombPivot = player->positionOfLastEnemyHit;
                }
                else
                {
                    bombPivot = player->positionCenter;
                }
                angle.x = bombPivot.x - player->bombInfo.bombRegionPositions[i].x;
                angle.y = bombPivot.y - player->bombInfo.bombRegionPositions[i].y;

                vecLength = sqrtf(angle.x * angle.x + angle.y * angle.y) /
                            (player->bombInfo.reimuABombProjectilesRelated[i] / 8.0f);
                if (vecLength < 1.0f)
                {
                    vecLength = 1.0f;
                }
                angle.x = angle.x / vecLength + player->bombInfo.bombRegionVelocities[i].x;
                angle.y = angle.y / vecLength + player->bombInfo.bombRegionVelocities[i].y;
                vecLength = sqrtf(angle.x * angle.x + angle.y * angle.y);

                player->bombInfo.reimuABombProjectilesRelated[i] = ZUN_MIN(vecLength, 10.0f);

                if (player->bombInfo.reimuABombProjectilesRelated[i] < 1.0f)
                {
                    player->bombInfo.reimuABombProjectilesRelated[i] = 1.0f;
                }

                player->bombInfo.bombRegionVelocities[i].x =
                    (angle.x * player->bombInfo.reimuABombProjectilesRelated[i]) / vecLength;
                player->bombInfo.bombRegionVelocities[i].y =
                    (angle.y * player->bombInfo.reimuABombProjectilesRelated[i]) / vecLength;

                player->bombRegionSizes[i].x = 48.0f;
                player->bombRegionSizes[i].y = 48.0f;

                player->bombRegionPositions[i] = player->bombInfo.bombRegionPositions[i];
                player->bombRegionDamages[i] = 8;

                player->bombProjectiles[i].pos.x = player->bombInfo.bombRegionPositions[i].x;
                player->bombProjectiles[i].pos.y = player->bombInfo.bombRegionPositions[i].y;

                player->bombProjectiles[i].size.x = 48.0f;
                player->bombProjectiles[i].size.y = 48.0f;

                if (player->unk_838[i] >= 100 || player->bombInfo.timer >= player->bombInfo.duration - 30)
                {
                    g_EffectManager.SpawnParticles(PARTICLE_EFFECT_UNK_6, &player->bombInfo.bombRegionPositions[i], 8,
                                                   COLOR_WHITE);
                    g_EffectManager.SpawnParticles(PARTICLE_EFFECT_UNK_12, &player->bombInfo.bombRegionPositions[i], 1,
                                                   COLOR_NEONBLUE);
                    player->bombInfo.reimuABombProjectilesState[i] = 2;

                    player->bombInfo.sprites[0][i * 4].pendingInterrupt = 1;
                    player->bombInfo.sprites[0][i * 4 + 1].pendingInterrupt = 1;
                    player->bombInfo.sprites[0][i * 4 + 2].pendingInterrupt = 1;
                    player->bombInfo.sprites[0][i * 4 + 3].pendingInterrupt = 1;

                    player->bombRegionSizes[i].x = 256.0f;
                    player->bombRegionSizes[i].y = 256.0f;

                    player->bombRegionDamages[i] = 200;

                    player->bombProjectiles[i].size.x = 256.0f;
                    player->bombProjectiles[i].size.y = 256.0f;

                    player->bombInfo.bombRegionVelocities[i] / 100.0f; // ZUN moment

                    g_SoundPlayer.PlaySoundByIdx(SOUND_F, 0);
                    ScreenEffect::RegisterChain(SCREEN_EFFECT_UNK_1, 16, 8, 0, 0);
                }
            }
        }
        else if (player->bombInfo.reimuABombProjectilesState[i] != 0 && player->bombInfo.timer.HasTicked())
        {
            player->bombInfo.reimuABombProjectilesState[i]++;
            if (player->bombInfo.reimuABombProjectilesState[i] >= 30)
            {
                player->bombInfo.reimuABombProjectilesState[i] = 0;
            }
        }
        player->bombInfo.bombRegionPositions[i].x +=
            g_Supervisor.effectiveFramerateMultiplier * player->bombInfo.bombRegionVelocities[i].x;
        player->bombInfo.bombRegionPositions[i].y +=
            g_Supervisor.effectiveFramerateMultiplier * player->bombInfo.bombRegionVelocities[i].y;

        g_AnmManager->ExecuteScript(&player->bombInfo.sprites[0][i * 4]);
        g_AnmManager->ExecuteScript(&player->bombInfo.sprites[0][i * 4 + 1]);
        g_AnmManager->ExecuteScript(&player->bombInfo.sprites[0][i * 4 + 2]);
        g_AnmManager->ExecuteScript(&player->bombInfo.sprites[0][i * 4 + 3]);
    }
    player->bombInfo.timer.Tick();
}

#pragma var_order(i, bombSprite, unusedVector)
void Player::BombReimuBCalc(Player *player)
{
    AnmVm *bombSprite;
    i32 i;
    D3DXVECTOR3 unusedVector;

    if (player->bombInfo.timer >= player->bombInfo.duration)
    {
        g_Gui.EndPlayerSpellcard();
        player->bombInfo.isInUse = 0;
        return;
    }

    if (player->bombInfo.timer.HasTicked() && player->bombInfo.timer == 0)
    {
        g_ItemManager.RemoveAllItems();
        g_Gui.ShowBombNamePortrait(ANM_SCRIPT_FACE_ENEMY_SPELLCARD_PORTRAIT, TH_REIMU_B_BOMB_NAME);
        player->bombInfo.duration = 140;
        player->invulnerabilityTimer.SetCurrent(200);
        bombSprite = player->bombInfo.sprites[0];

        WasteStackSpace();
        WasteStackSpace();

        for (i = 0; i < 4; i++, bombSprite++)
        {
            g_AnmManager->ExecuteAnmIdx(bombSprite, ANM_SCRIPT_PLAYER_REIMU_B_BOMB_ARRAY + i);
        }

        g_SoundPlayer.PlaySoundByIdx(SOUND_BOMB_REIMARI, 0);
        player->bombInfo.bombRegionPositions[0].x = player->positionCenter.x;
        player->bombInfo.bombRegionPositions[0].y = 224.0f;
        player->bombInfo.bombRegionPositions[0].z = 0.42f;
        player->bombInfo.bombRegionPositions[1].x = 192.0f;
        player->bombInfo.bombRegionPositions[1].y = player->positionCenter.y;
        player->bombInfo.bombRegionPositions[1].z = 0.415f;
        player->bombInfo.bombRegionPositions[2].x = player->positionCenter.x;
        player->bombInfo.bombRegionPositions[2].y = 224.0f;
        player->bombInfo.bombRegionPositions[2].z = 0.41f;
        player->bombInfo.bombRegionPositions[3].x = 192.0f;
        player->bombInfo.bombRegionPositions[3].y = player->positionCenter.y;
        player->bombInfo.bombRegionPositions[3].z = 0.405f;
        ScreenEffect::RegisterChain(SCREEN_EFFECT_UNK_1, 60, 2, 6, 0);
    }
    else
    {
        if (player->bombInfo.timer == 60)
        {
            ScreenEffect::RegisterChain(SCREEN_EFFECT_UNK_1, 80, 20, 0, 0);
        }

        player->bombProjectiles[0].size.x = 62.0f;
        player->bombProjectiles[0].size.y = 448.0f;
        player->bombProjectiles[1].size.x = 384.0f;
        player->bombProjectiles[1].size.y = 62.0f;
        player->bombProjectiles[2].size.x = 62.0f;
        player->bombProjectiles[2].size.y = 448.0f;
        player->bombProjectiles[3].size.x = 384.0f;
        player->bombProjectiles[3].size.y = 62.0f;

        for (i = 0; i < 4; i++)
        {
            g_AnmManager->ExecuteScript(&player->bombInfo.sprites[0][i]);
            if (player->bombInfo.timer.HasTicked() && player->bombInfo.timer.AsFrames() % 2 != 0)
            {
                player->bombProjectiles[i].pos.x =
                    player->bombInfo.bombRegionPositions[i].x + player->bombInfo.sprites[0][i].posOffset.x;
                player->bombProjectiles[i].pos.y =
                    player->bombInfo.bombRegionPositions[i].y + player->bombInfo.sprites[0][i].posOffset.y;
                player->bombRegionSizes[i].x = player->bombProjectiles[i].size.x;
                player->bombRegionSizes[i].y = player->bombProjectiles[i].size.y;
                player->bombRegionPositions[i] =
                    player->bombInfo.bombRegionPositions[i] + player->bombInfo.sprites[0][i].posOffset;
                player->bombRegionDamages[i] = 8;
            }
        }
    }

    player->playerState = PLAYER_STATE_INVULNERABLE;
    player->bombInfo.timer.Tick();
}

#pragma var_order(i, starSprite, unused, starAngle)
void Player::BombMarisaACalc(Player *player)
{

    f32 starAngle;
    i32 unused[3];
    AnmVm *starSprite;
    i32 i;

    if (player->bombInfo.timer >= player->bombInfo.duration)
    {
        g_Gui.EndPlayerSpellcard();
        player->bombInfo.isInUse = 0;
        return;
    }

    if (player->bombInfo.timer.HasTicked() && player->bombInfo.timer == 0)
    {
        g_ItemManager.RemoveAllItems();
        g_Gui.ShowBombNamePortrait(ANM_SCRIPT_FACE_ENEMY_SPELLCARD_PORTRAIT, TH_MARISA_A_BOMB_NAME);
        player->bombInfo.duration = 250;
        player->invulnerabilityTimer.SetCurrent(300);

        starSprite = player->bombInfo.sprites[0];
        for (i = 0; i < ARRAY_SIZE_SIGNED(player->bombInfo.sprites); i++, starSprite++)
        {
            WasteStackSpace();
            WasteStackSpace();

            g_AnmManager->ExecuteAnmIdx(starSprite, ANM_SCRIPT_PLAYER_MARISA_A_BLUE_STAR + i % 3);
            player->bombInfo.bombRegionPositions[i] = player->positionCenter;

            starAngle = i * ZUN_2PI / 8.0f;

            player->bombInfo.bombRegionVelocities[i].x = cosf(starAngle) * 2;

            player->bombInfo.bombRegionVelocities[i].y = sinf(starAngle) * 2;
            player->bombInfo.bombRegionVelocities[i].z = 0.0f;
        }
        g_SoundPlayer.PlaySoundByIdx(SOUND_BOMB_REIMARI, 0);
        ScreenEffect::RegisterChain(SCREEN_EFFECT_UNK_1, 0x78, 4, 1, 0);
    }
    else
    {
        for (i = 0; i < ARRAY_SIZE_SIGNED(player->bombInfo.sprites); i++)
        {
            player->bombInfo.bombRegionPositions[i] +=
                player->bombInfo.bombRegionVelocities[i] * g_Supervisor.effectiveFramerateMultiplier;

            if (player->bombInfo.timer.HasTicked() && player->bombInfo.timer.AsFrames() % 3 != 0)
            {
                player->bombProjectiles[i].pos.x = player->bombInfo.bombRegionPositions[i].x;
                player->bombProjectiles[i].pos.y = player->bombInfo.bombRegionPositions[i].y;
                player->bombProjectiles[i].size.x = 128.0f;
                player->bombProjectiles[i].size.y = 128.0f;
                player->bombRegionSizes[i].x = 128.0f;
                player->bombRegionSizes[i].y = 128.0f;

                player->bombRegionPositions[i] = player->bombInfo.bombRegionPositions[i];
                player->bombRegionDamages[i] = 8;
            }
            g_AnmManager->ExecuteScript(&player->bombInfo.sprites[0][i]);
        }
    }
    player->playerState = PLAYER_STATE_INVULNERABLE;
    player->bombInfo.timer.Tick();

    return;
}

#pragma var_order(i, bombSprite, unusedVector)
void Player::BombMarisaBCalc(Player *player)
{
    AnmVm *bombSprite;
    i32 i;
    D3DXVECTOR3 unusedVector;

    if (player->bombInfo.timer >= player->bombInfo.duration)
    {
        g_Gui.EndPlayerSpellcard();
        player->bombInfo.isInUse = 0;
        player->verticalMovementSpeedMultiplierDuringBomb = 1.0f;
        player->horizontalMovementSpeedMultiplierDuringBomb = 1.0f;
        return;
    }

    if (player->bombInfo.timer.HasTicked() && player->bombInfo.timer == 0)
    {
        g_ItemManager.RemoveAllItems();
        g_Gui.ShowBombNamePortrait(ANM_SCRIPT_FACE_BOMB_PORTRAIT, TH_MARISA_B_BOMB_NAME);
        player->bombInfo.duration = 300;
        player->invulnerabilityTimer.SetCurrent(360);
        bombSprite = player->bombInfo.sprites[0];
        for (i = 0; i < 4; i++, bombSprite++)
        {
            g_AnmManager->ExecuteAnmIdx(bombSprite, ANM_SCRIPT_PLAYER_MARISA_B_MASTER_SPARK + i);
            player->bombInfo.bombRegionPositions[i] = player->positionCenter;
        }
        g_SoundPlayer.PlaySoundByIdx(SOUND_BOMB_MARISA_B, 0);
        player->verticalMovementSpeedMultiplierDuringBomb = 0.3f;
        player->horizontalMovementSpeedMultiplierDuringBomb = 0.3f;
    }
    else
    {
        WasteStackSpace();
        WasteStackSpace();

        if (player->bombInfo.timer == 60)
        {
            ScreenEffect::RegisterChain(SCREEN_EFFECT_UNK_1, 60, 1, 7, 0);
        }
        else if (player->bombInfo.timer == 120)
        {
            ScreenEffect::RegisterChain(SCREEN_EFFECT_UNK_1, 200, 24, 0, 0);
        }

        if (player->bombInfo.timer.HasTicked() && player->bombInfo.timer.AsFrames() % 4 != 0)
        {
            player->bombProjectiles[0].pos.x = 192.0f;
            player->bombProjectiles[0].pos.y = player->positionCenter.y / 2.0f;
            player->bombProjectiles[0].size.x = 384.0f;
            player->bombProjectiles[0].size.y = player->positionCenter.y;
            player->bombRegionSizes[0].x = 384.0f;
            player->bombRegionSizes[0].y = player->positionCenter.y;
            player->bombRegionPositions[0].x = player->bombProjectiles[0].pos.x;
            player->bombRegionPositions[0].y = player->bombProjectiles[0].pos.y;
            player->bombRegionDamages[0] = 12;
        }

        g_AnmManager->ExecuteScript(&player->bombInfo.sprites[0][0]);
        g_AnmManager->ExecuteScript(&player->bombInfo.sprites[0][1]);
        g_AnmManager->ExecuteScript(&player->bombInfo.sprites[0][2]);
        g_AnmManager->ExecuteScript(&player->bombInfo.sprites[0][3]);
    }

    player->playerState = PLAYER_STATE_INVULNERABLE;
    player->bombInfo.timer.Tick();
}

#pragma var_order(bombSprite, idx)
void Player::BombReimuADraw(Player *player)
{
    i32 idx;
    AnmVm *bombSprite;

    Player::DarkenViewport(player);
    bombSprite = &player->bombInfo.sprites[0][0];
    for (idx = 0; idx < ARRAY_SIZE_SIGNED(player->bombInfo.sprites); idx++)
    {
        if (player->bombInfo.reimuABombProjectilesState[idx] == 0)
        {
            bombSprite = &bombSprite[4];
            continue;
        }

        bombSprite->pos = player->bombInfo.bombRegionPositions[idx] + bombSprite->posOffset;
        player->SetToTopLeftPos(bombSprite);
        g_AnmManager->DrawNoRotation(bombSprite);
        bombSprite++;

        bombSprite->pos = player->bombInfo.bombRegionPositions[idx] + bombSprite->posOffset;
        player->SetToTopLeftPos(bombSprite);
        g_AnmManager->DrawNoRotation(bombSprite);
        bombSprite++;

        bombSprite->pos = player->bombInfo.bombRegionPositions[idx] + bombSprite->posOffset;
        player->SetToTopLeftPos(bombSprite);
        g_AnmManager->DrawNoRotation(bombSprite);
        bombSprite++;

        bombSprite->pos = player->bombInfo.bombRegionPositions[idx] + bombSprite->posOffset;
        player->SetToTopLeftPos(bombSprite);
        g_AnmManager->DrawNoRotation(bombSprite);
        bombSprite++;
    }
    return;
}

#pragma var_order(bombSprite, i)
void Player::BombReimuBDraw(Player *player)
{
    AnmVm *bombSprite;
    i32 i;

    Player::DarkenViewport(player);
    bombSprite = player->bombInfo.sprites[0];
    for (i = 0; i < 4; i++, bombSprite++)
    {
        bombSprite->pos = player->bombInfo.bombRegionPositions[i] + bombSprite->posOffset;
        bombSprite->pos.x += g_GameManager.arcadeRegionTopLeftPos.x;
        bombSprite->pos.y += g_GameManager.arcadeRegionTopLeftPos.y;
        bombSprite->pos.z = 0.0f;
        g_AnmManager->Draw(bombSprite);
    }
}

#pragma var_order(bombSprite, idx)
void Player::BombMarisaADraw(Player *player)
{

    AnmVm *bombSprite;
    i32 idx;

    Player::DarkenViewport(player);
    bombSprite = &player->bombInfo.sprites[0][0];
    for (idx = 0; idx < ARRAY_SIZE_SIGNED(player->bombInfo.sprites); idx++)
    {

        bombSprite->pos = player->bombInfo.bombRegionPositions[idx];
        bombSprite->pos.x += g_GameManager.arcadeRegionTopLeftPos.x;
        bombSprite->pos.y += g_GameManager.arcadeRegionTopLeftPos.y;
        bombSprite->pos.z = 0.0f;
        bombSprite->scaleX = 3.2f;
        bombSprite->scaleY = 3.2f;
        g_AnmManager->Draw(bombSprite);

        bombSprite->pos -= player->bombInfo.bombRegionVelocities[idx] * 6.0f;
        bombSprite->pos.x += -32.0f;
        bombSprite->pos.y += -32.0f;
        bombSprite->pos.z = 0.0f;
        bombSprite->scaleX = 2.2f;
        bombSprite->scaleY = 2.2f;
        g_AnmManager->Draw(bombSprite);

        bombSprite->pos -= player->bombInfo.bombRegionVelocities[idx] * 2.0f;
        bombSprite->pos.x += 64.0f;
        bombSprite->pos.y += 64.0f;
        bombSprite->pos.z = 0.0f;

        bombSprite->pos -= player->bombInfo.bombRegionVelocities[idx] * 2.0f;
        bombSprite->pos.x += -32.0f;
        bombSprite->pos.y += -32.0f;
        bombSprite->pos.z = 0.0f;
        bombSprite->scaleX = 1.0f;
        bombSprite->scaleY = 1.0f;
        g_AnmManager->Draw(bombSprite);
        bombSprite++;
    }
}

#pragma var_order(bombSprite, i, spriteAngle)
void Player::BombMarisaBDraw(Player *player)
{
    AnmVm *bombSprite;
    i32 i;
    f32 spriteAngle;

    Player::DarkenViewport(player);
    bombSprite = player->bombInfo.sprites[0];
    for (i = 0; i < 4; i++)
    {
        spriteAngle = (((ZUN_PI / 5) * i) / 3.0f - ZUN_PI) + ((2 * ZUN_PI) / 5);
        bombSprite->pos = player->positionCenter;
        bombSprite->pos.x += (cosf(spriteAngle) * bombSprite->sprite->heightPx * bombSprite->scaleY) / 2.0f;
        bombSprite->pos.y += (sinf(spriteAngle) * bombSprite->sprite->heightPx * bombSprite->scaleY) / 2.0f;
        spriteAngle = (ZUN_PI / 2) - spriteAngle;
        bombSprite->rotation.z = utils::AddNormalizeAngle(spriteAngle, ZUN_PI);
        bombSprite->pos.x += g_GameManager.arcadeRegionTopLeftPos.x;
        bombSprite->pos.y += g_GameManager.arcadeRegionTopLeftPos.y;
        bombSprite->pos.z = 0.0f;
        g_AnmManager->Draw(bombSprite);
        bombSprite++;
    }
}

#pragma var_order(local8, viewport, darkeningTimeLeft)
void Player::DarkenViewport(Player *player)
{
    ZunRect viewport;
    f32 darkeningTimeLeft;
    i32 darknessLevel; // Controls alpha level of black rectangle drawn over view

    viewport.left = 32.0f;
    viewport.top = 16.0f;
    viewport.right = 416.0f;
    viewport.bottom = 464.0f;

    if (player->bombInfo.timer < 60)
    {
        darkeningTimeLeft = (player->bombInfo.timer.AsFramesFloat() * 176.0f) / 60.0f;
        darknessLevel = darkeningTimeLeft >= 176.0f ? 176 : (i32)darkeningTimeLeft;
    }
    else if (player->bombInfo.timer >= player->bombInfo.duration + -60)
    {
        darkeningTimeLeft = ((player->bombInfo.duration - player->bombInfo.timer.AsFramesFloat()) * 176.0f) / 60.0f;
        darknessLevel = darkeningTimeLeft < 0.0f ? 0 : (i32)darkeningTimeLeft;
    }
    else
    {
        darknessLevel = 176;
    }

    ScreenEffect::DrawSquare(&viewport, darknessLevel << 24);
}

}; // namespace th06
