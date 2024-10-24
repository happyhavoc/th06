#include "Enemy.hpp"
#include "BulletManager.hpp"
#include "EclManager.hpp"
#include "EffectManager.hpp"
#include "EnemyManager.hpp"
#include "GameManager.hpp"
#include "Gui.hpp"
#include "Player.hpp"
#include "Rng.hpp"
#include "ZunBool.hpp"
#include "utils.hpp"

namespace th06
{
struct PatchouliShottypeVars {
    struct {
        i32 var1;
        i32 var2;
        i32 var3;
    } shotVars[2];
};
C_ASSERT(sizeof(PatchouliShottypeVars) == 0x18);

DIFFABLE_STATIC_ARRAY_ASSIGN(PatchouliShottypeVars, 2, g_PatchouliShottypeVars) = {
    {{{0, 3, 1}, {2, 3, 4}}}, 
    {{{1, 4, 0}, {4, 2, 4}}}
};
DIFFABLE_STATIC(i32, g_PlayerShot);
DIFFABLE_STATIC(f32, g_PlayerDistance);
DIFFABLE_STATIC(f32, g_PlayerAngle);
DIFFABLE_STATIC_ARRAY(f32, 6, g_StarAngleTable);
DIFFABLE_STATIC(D3DXVECTOR3, g_EnemyPosVector);
DIFFABLE_STATIC(D3DXVECTOR3, g_PlayerPosVector);

i32 *Enemy::GetVar(Enemy *enemy, EclVarId *eclVarId, EclValueType *valueType)
{
    if (valueType != NULL)
        *valueType = ECL_VALUE_TYPE_UNDEFINED;

    switch (*eclVarId)
    {
    case ECL_VAR_I32_0:
        if (valueType != NULL)
            *valueType = ECL_VALUE_TYPE_INT;
        return &enemy->currentContext.var0;

    case ECL_VAR_I32_1:
        if (valueType != NULL)
            *valueType = ECL_VALUE_TYPE_INT;
        return &enemy->currentContext.var1;

    case ECL_VAR_I32_2:
        if (valueType != NULL)
            *valueType = ECL_VALUE_TYPE_INT;
        return &enemy->currentContext.var2;

    case ECL_VAR_I32_3:
        if (valueType != NULL)
            *valueType = ECL_VALUE_TYPE_INT;
        return &enemy->currentContext.var3;

    case ECL_VAR_F32_0:
        if (valueType != NULL)
            *valueType = ECL_VALUE_TYPE_FLOAT;
        return (i32 *)&enemy->currentContext.float0;

    case ECL_VAR_F32_1:
        if (valueType != NULL)
            *valueType = ECL_VALUE_TYPE_FLOAT;
        return (i32 *)&enemy->currentContext.float1;

    case ECL_VAR_F32_2:
        if (valueType != NULL)
            *valueType = ECL_VALUE_TYPE_FLOAT;
        return (i32 *)&enemy->currentContext.float2;

    case ECL_VAR_F32_3:
        if (valueType != NULL)
            *valueType = ECL_VALUE_TYPE_FLOAT;
        return (i32 *)&enemy->currentContext.float3;

    case ECL_VAR_I32_4:
        if (valueType != NULL)
            *valueType = ECL_VALUE_TYPE_INT;
        return &enemy->currentContext.var4;

    case ECL_VAR_I32_5:
        if (valueType != NULL)
            *valueType = ECL_VALUE_TYPE_INT;
        return &enemy->currentContext.var5;

    case ECL_VAR_I32_6:
        if (valueType != NULL)
            *valueType = ECL_VALUE_TYPE_INT;
        return &enemy->currentContext.var6;

    case ECL_VAR_I32_7:
        if (valueType != NULL)
            *valueType = ECL_VALUE_TYPE_INT;
        return &enemy->currentContext.var7;

    case ECL_VAR_DIFFICULTY:
        if (valueType != NULL)
            *valueType = ECL_VALUE_TYPE_READONLY;
        return (int *)&g_GameManager.difficulty;

    case ECL_VAR_RANK:
        if (valueType != NULL)
            *valueType = ECL_VALUE_TYPE_READONLY;
        return &g_GameManager.rank;

    case ECL_VAR_ENEMY_POS_X:
        if (valueType != NULL)
            *valueType = ECL_VALUE_TYPE_FLOAT;
        return (i32 *)&enemy->position;

    case ECL_VAR_ENEMY_POS_Y:
        if (valueType != NULL)
            *valueType = ECL_VALUE_TYPE_FLOAT;
        return (i32 *)&enemy->position.y;

    case ECL_VAR_ENEMY_POS_Z:
        if (valueType != NULL)
            *valueType = ECL_VALUE_TYPE_FLOAT;
        return (i32 *)&enemy->position.z;

    case ECL_VAR_PLAYER_POS_X:
        if (valueType != NULL)
            *valueType = ECL_VALUE_TYPE_READONLY;
        return (i32 *)&g_Player.positionCenter;

    case ECL_VAR_PLAYER_POS_Y:
        if (valueType != NULL)
            *valueType = ECL_VALUE_TYPE_READONLY;
        return (i32 *)&g_Player.positionCenter.y;

    case ECL_VAR_PLAYER_POS_Z:
        if (valueType != NULL)
            *valueType = ECL_VALUE_TYPE_READONLY;
        return (i32 *)&g_Player.positionCenter.z;

    case ECL_VAR_PLAYER_ANGLE:
        g_PlayerAngle = g_Player.AngleToPlayer(&enemy->position);
        if (valueType != NULL)
            *valueType = ECL_VALUE_TYPE_READONLY;
        return (i32 *)&g_PlayerAngle;

    case ECL_VAR_ENEMY_TIMER:
        if (valueType != NULL)
            *valueType = ECL_VALUE_TYPE_INT;
        return &enemy->bossTimer.current;

    case ECL_VAR_PLAYER_DISTANCE:
        g_PlayerDistance = D3DXVec3Length(&(g_Player.positionCenter - enemy->position));
        if (valueType != NULL)
            *valueType = ECL_VALUE_TYPE_READONLY;
        return (i32 *)&g_PlayerDistance;

    case ECL_VAR_ENEMY_LIFE:
        if (valueType != NULL)
            *valueType = ECL_VALUE_TYPE_INT;
        return &enemy->life;

    case ECL_VAR_PLAYER_SHOT:
        g_PlayerShot = g_GameManager.character * 2 + g_GameManager.shotType;
        if (valueType != NULL)
            *valueType = ECL_VALUE_TYPE_INT;
        return &g_PlayerShot;
    }
    return (i32 *)eclVarId;
}

f32 *Enemy::GetVarFloat(Enemy *enemy, f32 *eclVarId, EclValueType *valueType)
{
    i32 varId = *eclVarId;
    i32 *res = Enemy::GetVar(enemy, (EclVarId *)&varId, valueType);
    if (res == &varId)
    {
        return eclVarId;
    }
    else
    {
        return (f32 *)res;
    }
}

#pragma var_order(lhsPtr, rhsPtr, lhsType)
void Enemy::SetVar(Enemy *enemy, EclVarId lhs, void *rhs)
{
    i32 *lhsPtr;
    EclValueType lhsType;
    i32 *rhsPtr;

    rhsPtr = Enemy::GetVar(enemy, (EclVarId *)rhs, NULL);
    lhsPtr = GetVar(enemy, &lhs, &lhsType);
    if (lhsType == ECL_VALUE_TYPE_INT)
    {
        *lhsPtr = *rhsPtr;
    }
    else if (lhsType == ECL_VALUE_TYPE_FLOAT)
    {
        *(f32 *)lhsPtr = *(f32 *)rhsPtr;
    }
    return;
}

#pragma var_order(outPtr, rhsPtr, lhsPtr, outType)
void Enemy::MathAdd(Enemy *enemy, EclVarId outVarId, EclVarId *lhsVarId, EclVarId *rhsVarId)
{
    EclValueType outType;
    i32 *outPtr;
    i32 *lhsPtr;
    i32 *rhsPtr;

    // Get output variable.
    outPtr = Enemy::GetVar(enemy, &outVarId, &outType);
    if (outType == ECL_VALUE_TYPE_INT)
    {
        lhsPtr = Enemy::GetVar(enemy, lhsVarId, NULL);
        rhsPtr = Enemy::GetVar(enemy, rhsVarId, NULL);
        *outPtr = *lhsPtr + *rhsPtr;
    }
    else if (outType == ECL_VALUE_TYPE_FLOAT)
    {
        lhsPtr = (i32 *)Enemy::GetVarFloat(enemy, (f32 *)lhsVarId, NULL);
        rhsPtr = (i32 *)Enemy::GetVarFloat(enemy, (f32 *)rhsVarId, NULL);
        *(f32 *)outPtr = *(f32 *)lhsPtr + *(f32 *)rhsPtr;
    }
    return;
}

void Enemy::Move()
{
    if (!this->flags.unk4)
    {
        this->position.x += g_Supervisor.effectiveFramerateMultiplier * this->axisSpeed.x;
    }
    else
    {
        this->position.x -= g_Supervisor.effectiveFramerateMultiplier * this->axisSpeed.x;
    }
    this->position.y += g_Supervisor.effectiveFramerateMultiplier * this->axisSpeed.y;
    this->position.z += g_Supervisor.effectiveFramerateMultiplier * this->axisSpeed.z;
}

void Enemy::ClampPos()
{
    if (this->flags.shouldClampPos)
    {
        if (this->position.x < this->lowerMoveLimit.x)
        {
            this->position.x = this->lowerMoveLimit.x;
        }
        else if (this->position.x > this->upperMoveLimit.x)
        {
            this->position.x = this->upperMoveLimit.x;
        }

        if (this->position.y < this->lowerMoveLimit.y)
        {
            this->position.y = this->lowerMoveLimit.y;
        }
        else if (this->position.y > this->upperMoveLimit.y)
        {
            this->position.y = this->upperMoveLimit.y;
        }
    }
}

#pragma var_order(curEnemy, i)
ZunBool Enemy::HandleLifeCallback()
{

    i32 i;
    Enemy *curEnemy;

    if (this->life < this->lifeCallbackThreshold)
    {
        this->life = this->lifeCallbackThreshold;
        g_EclManager.CallEclSub(&this->currentContext, this->lifeCallbackSub);
        this->lifeCallbackThreshold = -1;
        this->timerCallbackSub = this->deathCallbackSub;
        this->bulletRankSpeedLow = -0.5f;
        this->bulletRankSpeedHigh = 0.5f;
        this->bulletRankAmount1Low = 0;
        this->bulletRankAmount1High = 0;
        this->bulletRankAmount2Low = 0;
        this->bulletRankAmount2High = 0;
        this->stackDepth = 0;

        curEnemy = g_EnemyManager.enemies;
        for (i = 0; i < ARRAY_SIZE_SIGNED(g_EnemyManager.enemies); i++, curEnemy++)
        {
            if (!curEnemy->flags.unk5)
            {
                continue;
            }
            if (curEnemy->flags.isBoss)
            {
                continue;
            }
            curEnemy->life = 0;

            if (!curEnemy->flags.unk6 && curEnemy->deathCallbackSub >= 0)
            {
                g_EclManager.CallEclSub(&curEnemy->currentContext, curEnemy->deathCallbackSub);
                curEnemy->deathCallbackSub = -1;
            }
        }
        return true;
    }

    return false;
}

#pragma var_order(curEnemy, i)
ZunBool Enemy::HandleTimerCallback()
{

    Enemy *curEnemy;
    i32 i;

    if (this->flags.isBoss)
    {
        g_Gui.SetSpellcardSeconds((this->timerCallbackThreshold - this->bossTimer.AsFrames()) / 60);
    }

    if (this->HasBossTimerFinished())
    {
        if (this->lifeCallbackThreshold > 0)
        {
            this->life = this->lifeCallbackThreshold;
            this->lifeCallbackThreshold = -1;
        }
        g_EclManager.CallEclSub(&this->currentContext, this->timerCallbackSub);
        this->timerCallbackThreshold = -1;
        this->timerCallbackSub = this->deathCallbackSub;
        this->bossTimer.InitializeForPopup();
        if (!this->flags.unk16)
        {
            g_EnemyManager.spellcardInfo.isCapturing = false;
            if (g_EnemyManager.spellcardInfo.isActive)
            {
                g_EnemyManager.spellcardInfo.isActive++;
            }
            g_BulletManager.RemoveAllBullets(0);
        }

        curEnemy = g_EnemyManager.enemies;
        for (i = 0; i < ARRAY_SIZE_SIGNED(g_EnemyManager.enemies); i++, curEnemy++)
        {
            if (!curEnemy->flags.unk5)
            {
                continue;
            }
            if (curEnemy->flags.isBoss)
            {
                continue;
            }
            curEnemy->life = 0;

            if (!curEnemy->flags.unk6 && curEnemy->deathCallbackSub >= 0)
            {
                g_EclManager.CallEclSub(&curEnemy->currentContext, curEnemy->deathCallbackSub);
                curEnemy->deathCallbackSub = -1;
            }
        }
        this->bulletRankSpeedLow = -0.5f;
        this->bulletRankSpeedHigh = 0.5f;
        this->bulletRankAmount1Low = 0;
        this->bulletRankAmount1High = 0;
        this->bulletRankAmount2Low = 0;
        this->bulletRankAmount2High = 0;
        this->stackDepth = 0;
        return true;
    }
    return false;
}

void Enemy::Despawn()
{
    if (!this->flags.unk11)
    {
        this->flags.unk5 = 0;
    }
    else
    {
        this->flags.unk6 = 0;
    }
    if (this->flags.isBoss)
    {
        g_Gui.bossPresent = false;
    }
    if (this->effectIdx != 0)
    {
        this->ResetEffectArray(this);
    }
}

void Enemy::ResetEffectArray(Enemy *enemy)
{
    i32 idx;

    for (idx = 0; idx < enemy->effectIdx; idx++)
    {
        if (!enemy->effectArray[idx])
        {
            continue;
        }
        enemy->effectArray[idx]->unk_17a = 1;
        enemy->effectArray[idx] = NULL;
    }
    enemy->effectIdx = 0;
}

#pragma var_order(effect, i)
void Enemy::UpdateEffects(Enemy *enemy)
{
    Effect *effect;
    i32 i;

    for (i = 0; i < enemy->effectIdx; i++)
    {
        effect = enemy->effectArray[i];
        if (!effect)
        {
            continue;
        }

        effect->position = enemy->position;
        if (effect->unk_15c < enemy->effectDistance)
        {
            effect->unk_15c += 0.3f;
        }

        effect->angleRelated = utils::AddNormalizeAngle(effect->angleRelated, ZUN_PI / 100);
    }
}

#pragma var_order(i, currentBullet, effectIndex, velocityVector, bulletTimer, accelerationMultiplier, accelerationAngle)
void Enemy::ExInsCirnoRainbowBallJank(Enemy *enemy, EclRawInstr *instr)
{
    f32 accelerationAngle;
    f32 accelerationMultiplier;
    ZunTimer *bulletTimer;
    Bullet *currentBullet;
    i32 effectIndex;
    i32 i;
    D3DXVECTOR3 velocityVector;

    currentBullet = g_BulletManager.bullets;
    effectIndex = instr->args.exInstr.i32Param;

    g_EffectManager.SpawnParticles(PARTICLE_EFFECT_UNK_12, &enemy->position, 1, COLOR_WHITE);
    for (i = 0; i < (i32) ARRAY_SIZE(g_BulletManager.bullets); i++, currentBullet++)
    {
        if (currentBullet->state == 0 || currentBullet->state == 5)
        {
            continue;
        }
        
        currentBullet->spriteOffset = 0x000f;
        g_AnmManager->SetActiveSprite(&currentBullet->sprites.spriteBullet, 
                                      currentBullet->sprites.spriteBullet.baseSpriteIndex + currentBullet->spriteOffset);
        switch (effectIndex)
        {
            case 0:
                currentBullet->speed = 0.0;
                velocityVector.x = 0.0;
                velocityVector.y = 0.0;
                velocityVector.z = 0.0;
                currentBullet->velocity = velocityVector;
                break;
            case 1:
                currentBullet->exFlags |= 0x10;
                currentBullet->ex5Int0 = 220;
                bulletTimer = &currentBullet->timer;
                bulletTimer->current = 0;
                bulletTimer->subFrame = 0.0;
                bulletTimer->previous = -999;
                accelerationMultiplier = 0.01;
                accelerationAngle = g_Rng.GetRandomF32ZeroToOne() * (2 * ZUN_PI) - ZUN_PI;
                sincosmul(&currentBullet->ex4Acceleration, accelerationAngle, accelerationMultiplier);
                break;
        }
    }
}

void Enemy::ExInsShootAtRandomArea(Enemy *enemy, EclRawInstr *instr)
{
    f32 bulletSpeed;

    bulletSpeed = instr->args.exInstr.i32Param;
    enemy->bulletProps.position = enemy->position + enemy->shootOffset;
    enemy->bulletProps.position.x = (g_Rng.GetRandomF32ZeroToOne() * bulletSpeed + (enemy->position).x)
                                    - bulletSpeed / 2.0f;
    bulletSpeed *= 0.75f;
    enemy->bulletProps.position.y = (g_Rng.GetRandomF32ZeroToOne() * bulletSpeed + (enemy->position).y)
                                    - bulletSpeed / 2.0f;
    g_BulletManager.SpawnBulletPattern(&enemy->bulletProps);
}

#pragma var_order(i, propsSpeedBackup, starPatterTarget1, targetDistance, \
                  starPatternTarget0, patternPosition, baseTargetPosition)
void Enemy::ExInsShootStarPattern(Enemy *enemy, EclRawInstr *instr)
{
    // Variable names are more quick guesses at functionality than anything else, they should not be trusted
    D3DXVECTOR3 baseTargetPosition;
    i32 i;
    f32 propsSpeedBackup;
    f32 patternPosition;
    D3DXVECTOR3 starPatternTarget0;
    D3DXVECTOR3 starPatterTarget1;
    f32 targetDistance;

    if (enemy->currentContext.var2 >= enemy->currentContext.var3)
    {
        enemy->currentContext.funcSetFunc = NULL;
        return;
    }
    
    if (enemy->currentContext.var2 == 0)
    {
        g_EnemyPosVector = enemy->position;
        g_PlayerPosVector = g_Player.positionCenter;
        g_StarAngleTable[0] = g_Rng.GetRandomF32ZeroToOne() * (ZUN_PI * 2) - ZUN_PI;
        g_StarAngleTable[1] = utils::AddNormalizeAngle(g_StarAngleTable[0], 4 * ZUN_PI / 5);
    }
    if (enemy->currentContext.var2 % 30 == 0)
    {
        g_StarAngleTable[0] = g_StarAngleTable[1];
        g_StarAngleTable[1] = utils::AddNormalizeAngle(g_StarAngleTable[1], 4 * ZUN_PI / 5);
        g_StarAngleTable[2] = utils::AddNormalizeAngle(g_StarAngleTable[1], 4 * ZUN_PI / 5);
        g_StarAngleTable[3] = utils::AddNormalizeAngle(g_StarAngleTable[2], 4 * ZUN_PI / 5);
        g_StarAngleTable[4] = utils::AddNormalizeAngle(g_StarAngleTable[3], 4 * ZUN_PI / 5);
        g_StarAngleTable[5] = utils::AddNormalizeAngle(g_StarAngleTable[4], 4 * ZUN_PI / 5);
    }
    if (enemy->currentContext.var2 % 6 == 0)
    {
        patternPosition = (f32) enemy->currentContext.var2 / (f32) enemy->currentContext.var3;
        targetDistance = patternPosition * 0.1f;

        baseTargetPosition = (g_PlayerPosVector - g_EnemyPosVector) * targetDistance + g_EnemyPosVector;
        baseTargetPosition.z = 0.0f;

        patternPosition += 0.5f;
        enemy->bulletProps.angle1 = (ZUN_PI / 3) * patternPosition;
        
        for (i = 0; i < 5; i++)
        {
            targetDistance = (enemy->currentContext.var2 % 30) / 30.0f;
            sincosmul(&starPatternTarget0, g_StarAngleTable[i], enemy->currentContext.float3);
            sincosmul(&starPatterTarget1, g_StarAngleTable[i + 1], enemy->currentContext.float3);
            starPatternTarget0 = (starPatterTarget1 - starPatternTarget0) * targetDistance + starPatternTarget0;
            starPatternTarget0.z = 0;
            enemy->bulletProps.position = baseTargetPosition + starPatternTarget0;
            propsSpeedBackup = enemy->bulletProps.speed1;
            enemy->bulletProps.speed1 = g_Rng.GetRandomF32InRange(enemy->bulletProps.speed2) + enemy->bulletProps.speed1;
            g_BulletManager.SpawnBulletPattern(&enemy->bulletProps);
            enemy->bulletProps.speed1 = propsSpeedBackup;
            enemy->bulletProps.angle1 -= (ZUN_PI / 6) * patternPosition;
        }
        g_SoundPlayer.PlaySoundByIdx(SOUND_16, 0);
    }
    enemy->currentContext.var2++;
}

void Enemy::ExInsPatchouliShottypeSetVars(Enemy *enemy, EclRawInstr *instr)
{
    enemy->currentContext.var1 = g_PatchouliShottypeVars[g_GameManager.character].shotVars[g_GameManager.shotType].var1;
    enemy->currentContext.var2 = g_PatchouliShottypeVars[g_GameManager.character].shotVars[g_GameManager.shotType].var2;
    enemy->currentContext.var3 = g_PatchouliShottypeVars[g_GameManager.character].shotVars[g_GameManager.shotType].var3;
}

#pragma var_order(playerBulletOffset, bulletsLeft, i, currentBullet)
void Enemy::ExInsStage56Func4(Enemy *enemy, EclRawInstr *instr)
{
    i32 bulletsLeft;
    Bullet *currentBullet;
    i32 i;
    ZunVec2 playerBulletOffset;

    if (instr->args.exInstr.i32Param < 2) 
    {
        g_EffectManager.SpawnParticles(PARTICLE_EFFECT_UNK_12, &enemy->position, 1, COLOR_WHITE);
        g_GameManager.isTimeStopped = instr->args.exInstr.u8Param;
    }
    else
    {
        bulletsLeft = 14;
        currentBullet = g_BulletManager.bullets;
        if (g_GameManager.difficulty <= NORMAL)
        {
            for (i = 0; i < (i32) ARRAY_SIZE(g_BulletManager.bullets); i++, currentBullet++)
            {
                if (currentBullet->state == 0 || currentBullet->state == 5)
                {
                    continue;
                }

                if (currentBullet->sprites.spriteBullet.sprite != NULL &&
                    currentBullet->sprites.spriteBullet.sprite->heightPx >= 30.0f &&
                    currentBullet->spriteOffset != 5 && (g_Rng.GetRandomU16() % 4 == 0))
                {
                    currentBullet->spriteOffset = 5;
                    g_AnmManager->SetActiveSprite(&currentBullet->sprites.spriteBullet, 
                                                  currentBullet->sprites.spriteBullet.baseSpriteIndex + 
                                                  currentBullet->spriteOffset);

                    playerBulletOffset.x = (currentBullet->pos.x) - g_Player.positionCenter.x;
                    playerBulletOffset.y = (currentBullet->pos.y) - g_Player.positionCenter.y;

                    if (playerBulletOffset.VectorLength() > 128.0f)
                    {
                        currentBullet->angle = g_Rng.GetRandomF32ZeroToOne() * ((ZUN_PI * 3) / 4) + (ZUN_PI / 4);
                    }
                    else
                    {
                        currentBullet->angle = g_Player.AngleFromPlayer(&currentBullet->pos) + (ZUN_PI / 2) + 
                                               g_Rng.GetRandomF32InRange(ZUN_PI * 2);
                    }

                    sincosmul(&currentBullet->velocity, currentBullet->angle, currentBullet->speed);
                    bulletsLeft--;
                    if (bulletsLeft == 0)
                    {
                        break;
                    }
                }
            }
        }
        else
        {
            bulletsLeft = 52;
            for (i = 0; i < (i32) ARRAY_SIZE(g_BulletManager.bullets); i++, currentBullet++)
            {
                if (currentBullet->state == 0 || currentBullet->state == 5)
                {
                    continue;
                }

                if (currentBullet->sprites.spriteBullet.sprite != NULL &&
                    currentBullet->sprites.spriteBullet.sprite->heightPx >= 30.0f &&
                    currentBullet->spriteOffset != 5 && (g_Rng.GetRandomU16() % 4 == 0))
                {
                    currentBullet->spriteOffset = 5;
                    g_AnmManager->SetActiveSprite(&currentBullet->sprites.spriteBullet, 
                                                  currentBullet->sprites.spriteBullet.baseSpriteIndex + 
                                                  currentBullet->spriteOffset);

                    playerBulletOffset.x = (currentBullet->pos.x) - g_Player.positionCenter.x;
                    playerBulletOffset.y = (currentBullet->pos.y) - g_Player.positionCenter.y;

                    if (playerBulletOffset.VectorLength() > 128.0f)
                    {
                        currentBullet->angle = g_Rng.GetRandomF32ZeroToOne() * (ZUN_PI * 2);
                    }
                    else
                    {
                        currentBullet->angle = g_Player.AngleFromPlayer(&currentBullet->pos) + (ZUN_PI / 2) + 
                                               g_Rng.GetRandomF32InRange(ZUN_PI * 2);
                    }

                    sincosmul(&currentBullet->velocity, currentBullet->angle, currentBullet->speed);
                    bulletsLeft--;
                    if (bulletsLeft == 0)
                    {
                        break;
                    }
                }
            }
        }
    }
    enemy->currentContext.var2 = 0;
}

#pragma var_order(patternPosition, i, bulletProps, sinOut, bpPositionOffset, matrixOutSeed, matrixIn, \
                  bulletAngle, cosOut, matrixInSeed, matrixOut)
void Enemy::ExInsStage5Func5(Enemy *enemy, EclRawInstr *instr)
{
    D3DXVECTOR3 bpPositionOffset;
    f32 bulletAngle;
    EnemyBulletShooter bulletProps;
    f32 cosOut;
    i32 i;
    D3DXVECTOR3 matrixIn;
    f32 matrixInSeed;
    D3DXVECTOR3 matrixOut;
    f32 matrixOutSeed; // Later reused to store angles for trig function calls
    i32 patternPosition;
    f32 sinOut;

    if (enemy->currentContext.var2 % 9 == 0)
    {
        memset(&bulletProps, 0, sizeof(bulletProps));

        patternPosition = enemy->currentContext.var2 / 9;
        bulletProps.sprite = 8;
        bulletProps.aimMode = 0;
        if (g_GameManager.difficulty <= NORMAL)
        {
            bulletProps.count1 = 1;
        }
        else
        {
            bulletProps.count1 = 3;
        }
        bulletProps.count2 = 1;
        bulletProps.angle2 = ZUN_PI / 6;
        bulletProps.unk_4a = 0;
        bulletProps.flags = 0;

        matrixOutSeed = 0.5f - patternPosition * 0.5f / 9.0f;
        matrixOut = g_Player.positionCenter - enemy->position;
        D3DXVec3Normalize(&matrixIn, &matrixOut);
        if ((patternPosition & 1) != 0)
        {
            matrixInSeed = -256.0f;
        }
        else
        {
            matrixInSeed = 256.0f;
        }
        matrixIn *= matrixInSeed;
        matrixOut *= matrixOutSeed;
        bpPositionOffset = matrixOut + matrixIn;
        matrixIn = -matrixIn;
        
        matrixOutSeed = ZUN_PI / 4;
        cosOut = cosf(matrixOutSeed);
        sinOut = sinf(matrixOutSeed);
        matrixOut = matrixIn;
        matrixIn.x = matrixOut.x * cosOut + matrixOut.y * sinOut;
        matrixIn.y = -matrixOut.x * sinOut + matrixOut.y * cosOut;
        matrixOutSeed = -ZUN_PI / 18;
        cosOut = cosf(matrixOutSeed);
        sinOut = sinf(matrixOutSeed);
        bulletProps.angle1 = 0.0;
        bulletAngle = -ZUN_PI / 4;

        for (i = 0; i < 9; i++, bulletAngle += ZUN_PI / 18)
        {
            matrixOut = matrixIn;
            matrixIn.x = matrixOut.x * cosOut + matrixOut.y * sinOut;
            matrixIn.y = -matrixOut.x * sinOut + matrixOut.y * cosOut;

            bulletProps.position = matrixIn + enemy->position + bpPositionOffset;
            bulletProps.speed1 = 2.0;
            if ((patternPosition & 1) != 0 && g_GameManager.difficulty <= NORMAL)
            {
                bulletProps.angle1 = bulletAngle;
            }
            bulletProps.spriteOffset = 3;
            g_BulletManager.SpawnBulletPattern(&bulletProps);
        }
        g_SoundPlayer.PlaySoundByIdx(SOUND_7, 0);
    }
    enemy->currentContext.var2++;
}

#pragma var_order(effect, baseAngleModifier, distanceModifier, finalAngle, particlePos)
void Enemy::ExInsStage6XFunc6(Enemy *enemy, EclRawInstr *instr)
{
    i32 baseAngleModifier;
    f32 distanceModifier;
    Effect *effect;
    f32 finalAngle;
    D3DXVECTOR3 particlePos;

    if (enemy->flags.unk15 != 0)
    {
        ResetEffectArray(enemy);
        return;
    }
    enemy->exInsFunc6Angle += RADIANS(1.0f);
    if (enemy->exInsFunc6Angle >= RADIANS(45.0f))
    {
        enemy->exInsFunc6Angle -= RADIANS(90.0f);
    }

    // Run every 8 frames for first 30 frames, then every 4 for next 30, then every 2 for next 60, then every frame
    if (enemy->exInsFunc6Timer.HasTicked() &&
       ( enemy->exInsFunc6Timer > 120 || 
        (enemy->exInsFunc6Timer > 60 && enemy->exInsFunc6Timer.current % 2 == 0) ||
        (enemy->exInsFunc6Timer > 30 && enemy->exInsFunc6Timer.current % 4 == 0) ||
         enemy->exInsFunc6Timer.current % 8 == 0))
    {
        baseAngleModifier = enemy->exInsFunc6Timer.current % 16;
        baseAngleModifier = g_Rng.GetRandomU16InRange(baseAngleModifier / 2) + baseAngleModifier / 2;
        distanceModifier = (baseAngleModifier * 160.0f) / 16.0f + 32.0f;
        finalAngle = enemy->exInsFunc6Angle - (baseAngleModifier * RADIANS(180.0f)) / 40.0f;
        if (distanceModifier < RADIANS(-45.0f))
        {
            distanceModifier += RADIANS(90.0f);
        }

        particlePos = enemy->position;
        particlePos.x += cosf(finalAngle) * distanceModifier;
        particlePos.y += sinf(finalAngle) * distanceModifier;
        effect = g_EffectManager.SpawnParticles(PARTICLE_EFFECT_UNK_19, &particlePos, 1, COLOR_DEEPBLUE);
        effect->unk_11c.x = (g_Rng.GetRandomF32ZeroToOne() * 40.0f - 20.0f) / 60.0f;
        effect->unk_11c.y = (8.0f * baseAngleModifier) / 60.0f - (4.0f / 15.0f);
        effect->unk_11c.z = 0.0;
        effect->unk_128 = -effect->unk_11c * invertf(120.0f);

        particlePos = enemy->position;
        particlePos.x -= cosf(finalAngle) * distanceModifier;
        particlePos.y += sinf(finalAngle) * distanceModifier;
        effect = g_EffectManager.SpawnParticles(PARTICLE_EFFECT_UNK_19, &particlePos, 1, COLOR_DEEPBLUE);
        effect->unk_11c.x = (g_Rng.GetRandomF32ZeroToOne() * 40.0f - 20.0f) / 60.0f;
        effect->unk_11c.y = (8.0f * baseAngleModifier) / 60.0f - (4.0f / 15.0f);
        effect->unk_11c.z = 0.0;
        effect->unk_128 = -effect->unk_11c * invertf(120.0f);
    }
 
    enemy->exInsFunc6Timer.Tick();
}

#pragma var_order(laserProps, i, lengthMultiplier, attackType, innerLoopCount, angleDiff, outerLoopCount, \
                  laserAngle, randomAngleModifier, positionVectors)
void Enemy::ExInsStage6Func7(Enemy *enemy, EclRawInstr *instr)
{
    f32 angleDiff;
    i32 attackType;
    i32 i;
    i32 innerLoopCount;
    f32 laserAngle;
    EnemyLaserShooter laserProps;
    f32 lengthMultiplier;
    i32 outerLoopCount;
    f32 randomAngleModifier;

    memset(&laserProps, 0, sizeof(laserProps));

    D3DXVECTOR3 positionVectors[8];

    attackType = instr->args.exInstr.i32Param;
    randomAngleModifier = g_Rng.GetRandomF32ZeroToOne() * (ZUN_PI * 2);
    
    for (outerLoopCount = 0; outerLoopCount < 2; outerLoopCount++)
    {
        if (outerLoopCount == 0)
        {
            laserAngle = -ZUN_PI + randomAngleModifier;
            angleDiff = ZUN_PI / 4;
        }
        else
        {
            laserAngle = (7 * -ZUN_PI / 8) + randomAngleModifier;
            angleDiff = -ZUN_PI / 4;
        }

        lengthMultiplier = 32.0f;
        for (i = 0; i < 8; i++)
        {
            positionVectors[i] = enemy->position;
            positionVectors[i].x += cosf(laserAngle) * lengthMultiplier;
            positionVectors[i].y += sinf(laserAngle) * lengthMultiplier;
            laserAngle += ZUN_PI / 4;
        }

        if (outerLoopCount == 0)
        {
            laserAngle = -ZUN_PI + randomAngleModifier;
        }
        else
        {
            laserAngle = (7 * -ZUN_PI / 8) + randomAngleModifier;
        }

        for (innerLoopCount = 0; innerLoopCount < 3; innerLoopCount++)
        {
            if (innerLoopCount < 2)
            {
                lengthMultiplier = 112.0f;
            }
            else
            {
                lengthMultiplier = 480.0f;
            }
            for (i = 0; i < 8; i++)
            {
                laserProps.position = positionVectors[i];
                laserProps.sprite = 1;
                if (attackType == 0)
                {
                    if (g_GameManager.difficulty <= NORMAL)
                    {
                        laserProps.spriteOffset = 2;
                    }
                    else
                    {
                        laserProps.spriteOffset = 8;
                    }
                    laserProps.angle = laserAngle;
                    laserProps.speed = 0.0f;
                    laserProps.startOffset = 0.0f;
                    if (g_GameManager.difficulty <= NORMAL)
                    {
                        laserProps.endOffset = lengthMultiplier;
                        laserProps.startLength = lengthMultiplier;
                    }
                    else
                    {
                        laserProps.endOffset = 440.0f;
                        laserProps.startLength = 440.0f;
                    }                    
                    if (g_GameManager.difficulty <= NORMAL)
                    {
                        laserProps.width = 28.0f;
                    }
                    else
                    {   laserProps.width = 20.0f;

                    }
                    laserProps.startTime = innerLoopCount * 16 + 60;
                    laserProps.duration = 90 - innerLoopCount * 16;
                    laserProps.stopTime = 16;
                    laserProps.grazeDelay = 50;
                    laserProps.grazeDistance = 16;
                    laserProps.flags = 2;
                    laserProps.type = 1;
                    g_BulletManager.SpawnLaserPattern(&laserProps);
                }
                else
                {
                    enemy->bulletProps.position = laserProps.position;
                    g_BulletManager.SpawnBulletPattern(&enemy->bulletProps);
                }
                positionVectors[i].x += cosf(laserAngle) * lengthMultiplier;
                positionVectors[i].y += sinf(laserAngle) * lengthMultiplier;
                laserAngle += ZUN_PI / 4;
            }
            laserAngle += angleDiff - (ZUN_PI * 2);
        }
    }
}

void Enemy::ExInsStage4Func12(Enemy *enemy, EclRawInstr *instr)
{
    i32 i;

    for (i = 0; i < 8; i++)
    {
        if (enemy->lasers[i] != NULL && enemy->lasers[i]->inUse != 0)
        {
            enemy->bulletProps.position = D3DXVECTOR3(64.0, 0.0, 0.0);
            utils::Rotate(&enemy->bulletProps.position, &enemy->bulletProps.position, enemy->lasers[i]->angle);
            enemy->bulletProps.position += enemy->position;
            g_BulletManager.SpawnBulletPattern(&enemy->bulletProps);
        }
    }
}
}; // namespace th06
