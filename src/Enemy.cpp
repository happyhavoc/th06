#include "Enemy.hpp"
#include "BulletManager.hpp"
#include "EclManager.hpp"
#include "EnemyManager.hpp"
#include "GameManager.hpp"
#include "Gui.hpp"
#include "Player.hpp"
#include "ZunBool.hpp"
#include "utils.hpp"

namespace th06
{
DIFFABLE_STATIC(i32, g_PlayerShot);
DIFFABLE_STATIC(f32, g_PlayerDistance);
DIFFABLE_STATIC(f32, g_PlayerAngle);

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

#pragma var_order(outPtr, rhsPtr, lhsPtr, outType)
void Enemy::MathSub(Enemy *enemy, EclVarId outVarId, EclVarId *lhsVarId, EclVarId *rhsVarId)
{
    EclValueType outType;
    i32 *outPtr;
    i32 *lhsPtr;
    i32 *rhsPtr;

    outPtr = Enemy::GetVar(enemy, &outVarId, &outType);
    if (outType == ECL_VALUE_TYPE_INT)
    {
        lhsPtr = Enemy::GetVar(enemy, lhsVarId, NULL);
        rhsPtr = Enemy::GetVar(enemy, rhsVarId, NULL);
        *outPtr = *lhsPtr - *rhsPtr;
    }
    else if (outType == ECL_VALUE_TYPE_FLOAT)
    {
        lhsPtr = (i32 *)Enemy::GetVarFloat(enemy, (f32 *)lhsVarId, NULL);
        rhsPtr = (i32 *)Enemy::GetVarFloat(enemy, (f32 *)rhsVarId, NULL);
        *(f32 *)outPtr = *(f32 *)lhsPtr - *(f32 *)rhsPtr;
    }
    return;
}

#pragma var_order(outPtr, rhsPtr, lhsPtr, outType)
void Enemy::MathMul(Enemy *enemy, EclVarId outVarId, EclVarId *lhsVarId, EclVarId *rhsVarId)
{
    EclValueType outType;
    i32 *outPtr;
    i32 *lhsPtr;
    i32 *rhsPtr;

    lhsPtr = Enemy::GetVar(enemy, lhsVarId, NULL);
    rhsPtr = Enemy::GetVar(enemy, rhsVarId, NULL);
    outPtr = Enemy::GetVar(enemy, &outVarId, &outType);
    if (outType == ECL_VALUE_TYPE_INT)
    {
        lhsPtr = Enemy::GetVar(enemy, lhsVarId, NULL);
        rhsPtr = Enemy::GetVar(enemy, rhsVarId, NULL);
        *outPtr = *lhsPtr * *rhsPtr;
    }
    else if (outType == ECL_VALUE_TYPE_FLOAT)
    {
        lhsPtr = (i32 *)Enemy::GetVarFloat(enemy, (f32 *)lhsVarId, NULL);
        rhsPtr = (i32 *)Enemy::GetVarFloat(enemy, (f32 *)rhsVarId, NULL);
        *(f32 *)outPtr = *(f32 *)lhsPtr * *(f32 *)rhsPtr;
    }
    return;
}

#pragma var_order(outPtr, rhsPtr, lhsPtr, outType)
void Enemy::MathDiv(Enemy *enemy, EclVarId outVarId, EclVarId *lhsVarId, EclVarId *rhsVarId)
{
    EclValueType outType;
    i32 *outPtr;
    i32 *lhsPtr;
    i32 *rhsPtr;

    outPtr = Enemy::GetVar(enemy, &outVarId, &outType);
    if (outType == ECL_VALUE_TYPE_INT)
    {
        lhsPtr = Enemy::GetVar(enemy, lhsVarId, NULL);
        rhsPtr = Enemy::GetVar(enemy, rhsVarId, NULL);
        *outPtr = *lhsPtr / *rhsPtr;
    }
    else if (outType == ECL_VALUE_TYPE_FLOAT)
    {
        lhsPtr = (i32 *)Enemy::GetVarFloat(enemy, (f32 *)lhsVarId, NULL);
        rhsPtr = (i32 *)Enemy::GetVarFloat(enemy, (f32 *)rhsVarId, NULL);
        *(f32 *)outPtr = *(f32 *)lhsPtr / *(f32 *)rhsPtr;
    }
    return;
}

#pragma var_order(outPtr, rhsPtr, lhsPtr, outType)
void Enemy::MathMod(Enemy *enemy, EclVarId outVarId, EclVarId *lhsVarId, EclVarId *rhsVarId)
{
    EclValueType outType;
    i32 *outPtr;
    i32 *lhsPtr;
    i32 *rhsPtr;

    outPtr = Enemy::GetVar(enemy, &outVarId, &outType);
    if (outType == ECL_VALUE_TYPE_INT)
    {
        lhsPtr = Enemy::GetVar(enemy, lhsVarId, NULL);
        rhsPtr = Enemy::GetVar(enemy, rhsVarId, NULL);
        *outPtr = *lhsPtr % *rhsPtr;
    }
    else if (outType == ECL_VALUE_TYPE_FLOAT)
    {
        lhsPtr = (i32 *)Enemy::GetVarFloat(enemy, (f32 *)lhsVarId, NULL);
        rhsPtr = (i32 *)Enemy::GetVarFloat(enemy, (f32 *)rhsVarId, NULL);
        *(f32 *)outPtr = fmodf(*(f32 *)lhsPtr, *(f32 *)rhsPtr);
    }
    return;
}

#pragma var_order(y2Ptr, outPtr, x1Ptr, y1Ptr, outType, x2Ptr)
void Enemy::MathAtan2(Enemy *enemy, EclVarId outVarId, f32 *x1, f32 *y1, f32 *y2, f32 *x2)
{
    EclValueType outType;
    f32 *outPtr;
    f32 *y1Ptr, *x1Ptr, *x2Ptr, *y2Ptr;

    outPtr = (f32 *)Enemy::GetVar(enemy, &outVarId, &outType);
    if (outType == ECL_VALUE_TYPE_FLOAT)
    {
        y1Ptr = Enemy::GetVarFloat(enemy, x1, NULL);
        x1Ptr = Enemy::GetVarFloat(enemy, y1, NULL);
        y2Ptr = Enemy::GetVarFloat(enemy, y2, NULL);
        x2Ptr = Enemy::GetVarFloat(enemy, x2, NULL);
        *outPtr = atan2f(*x2Ptr - *x1Ptr, *y2Ptr - *y1Ptr);
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
}; // namespace th06
