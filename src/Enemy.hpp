#pragma once

#include "AnmVm.hpp"
#include "BulletManager.hpp"
#include "EclManager.hpp"
#include "Effect.hpp"
#include "ItemManager.hpp"
#include "SoundPlayer.hpp"
#include "ZunBool.hpp"
#include "ZunResult.hpp"
#include "ZunTimer.hpp"
#include "inttypes.hpp"
#include <Windows.h>
#include <d3d8.h>
#include <d3dx8math.h>

namespace th06
{
struct Enemy;

struct EnemyBulletShooter
{
    i16 sprite;
    i16 spriteOffset;
    D3DXVECTOR3 position;
    f32 angle1;
    f32 angle2;
    f32 speed1;
    f32 speed2;
    f32 exFloats[4];
    i32 exInts[4];
    i32 unk_40;
    i16 count1;
    i16 count2;
    u16 aimMode;
    u16 unk_4a;
    u32 flags;
    SoundIdx sfx;
};
C_ASSERT(sizeof(EnemyBulletShooter) == 0x54);

struct EnemyLaserShooter
{
    i16 sprite;
    i16 color;
    D3DXVECTOR3 position;
    f32 angle;
    u32 unk_14;
    f32 speed;
    u32 unk_1c;
    f32 startOffset;
    f32 endOffset;
    f32 startLength;
    f32 width;
    i32 startTime;
    i32 duration;
    i32 stopTime;
    i32 grazeDelay;
    i32 grazeDistance;
    u32 unk_44;
    u16 type;
    u32 flags;
    u32 unk_50;
};
C_ASSERT(sizeof(EnemyLaserShooter) == 0x54);

struct EnemyEclContext
{
    EclRawInstr *currentInstr;
    ZunTimer time;
    void (*funcSetFunc)(Enemy *, EclRawInstr *);
    i32 var0;
    i32 var1;
    i32 var2;
    i32 var3;
    f32 float0;
    f32 float1;
    f32 float2;
    f32 float3;
    i32 var4;
    i32 var5;
    i32 var6;
    i32 var7;
    i32 compareRegister;
    u16 subId;
};
C_ASSERT(sizeof(EnemyEclContext) == 0x4c);

struct EnemyFlags
{
    // First byte
    u8 unk1 : 2;
    u8 unk2 : 3;
    u8 unk3 : 1;
    u8 unk4 : 1;
    u8 unk5 : 1;

    // Second byte
    u8 unk6 : 1;
    u8 unk7 : 1;
    u8 unk8 : 1;
    u8 isBoss : 1;
    u8 unk10 : 1;
    u8 unk11 : 3;

    // Third byte
    bool shouldClampPos : 1;
    u8 unk13 : 1;
    u8 unk14 : 1;
    u8 unk15 : 1;
    u8 unk16 : 1;

    // Rest is padding.
};

enum EclValueType
{
    ECL_VALUE_TYPE_INT,
    ECL_VALUE_TYPE_FLOAT,
    ECL_VALUE_TYPE_READONLY,
    ECL_VALUE_TYPE_UNDEFINED,
};

struct Enemy
{
    void Move();
    void ClampPos();
    ZunBool HandleLifeCallback();
    ZunBool HandleTimerCallback();
    void Despawn();

    static void ResetEffectArray(Enemy *enemy);
    static void UpdateEffects(Enemy *enemy);

    static i32 *GetVar(Enemy *enemy, EclVarId *varId, EclValueType *valueType);
    static f32 *GetVarFloat(Enemy *enemy, f32 *varId, EclValueType *valueType);
    static void SetVar(Enemy *enemy, EclVarId lhs, void *rhs);

    static void MathAdd(Enemy *enemy, EclVarId out, EclVarId *lhs, EclVarId *rhs);
    static void MathSub(Enemy *enemy, EclVarId out, EclVarId *lhs, EclVarId *rhs);
    static void MathMul(Enemy *enemy, EclVarId out, EclVarId *lhs, EclVarId *rhs);
    static void MathDiv(Enemy *enemy, EclVarId out, EclVarId *lhs, EclVarId *rhs);
    static void MathMod(Enemy *enemy, EclVarId out, EclVarId *lhs, EclVarId *rhs);
    static void MathAtan2(Enemy *enemy, EclVarId out, f32 *a1, f32 *a2, f32 *b1, f32 *b2);

    static void MoveDirTime(Enemy *enemy, EclRawInstr *instr);
    static void MovePosTime(Enemy *enemy, EclRawInstr *instr);
    static void MoveTime(Enemy *enemy, EclRawInstr *instr);

    f32 LifePercent()
    {
        return (f32)this->life / (f32)this->maxLife;
    }

    D3DXVECTOR3 HitboxDimensions(f32 shrinkFactor)
    {
        return (1.0f / shrinkFactor) * this->hitboxDimensions;
    }

    ZunBool HasBossTimerFinished()
    {
        return this->bossTimer.current >= this->timerCallbackThreshold;
    }

    static i32 BulletRankAmountInner(i32 low, i32 high, i32 scaleFactor)
    {
        return scaleFactor * (high - low) / 32 + low;
    }

    i32 BulletRankAmount1(i32 scaleFactor)
    {
        return Enemy::BulletRankAmountInner(this->bulletRankAmount1Low, this->bulletRankAmount1High, scaleFactor);
    }

    i32 BulletRankAmount2(i32 scaleFactor)
    {
        return Enemy::BulletRankAmountInner(this->bulletRankAmount2Low, this->bulletRankAmount2High, scaleFactor);
    }

    static f32 BulletRankSpeedInner(f32 low, f32 high, f32 scaleFactor)
    {
        return scaleFactor * (high - low) / 32 + low;
    }

    f32 BulletRankSpeed(f32 scaleFactor)
    {
        return Enemy::BulletRankSpeedInner(this->bulletRankSpeedLow, this->bulletRankSpeedHigh, scaleFactor);
    }

    static i32 ShootIntervalInner(i32 low, i32 high, i32 scaleFactor)
    {
        return scaleFactor * (high - low) / 32 + low;
    }

    i32 ShootInterval(i32 scaleFactor)
    {
        return Enemy::ShootIntervalInner(this->shootInterval / 5, -this->shootInterval / 5, scaleFactor);
    }

    AnmVm primaryVm;
    AnmVm vms[8];
    EnemyEclContext currentContext;
    EnemyEclContext savedContextStack[8];
    i32 stackDepth;
    i32 unk_c40;
    i32 deathCallbackSub;
    i32 interrupts[8];
    i32 runInterrupt;
    D3DXVECTOR3 position;
    D3DXVECTOR3 hitboxDimensions;
    D3DXVECTOR3 axisSpeed;
    f32 angle;
    f32 angularVelocity;
    f32 speed;
    f32 acceleration;
    D3DXVECTOR3 shootOffset;
    D3DXVECTOR3 moveInterp;
    D3DXVECTOR3 moveInterpStartPos;
    ZunTimer moveInterpTimer;
    i32 moveInterpStartTime;
    f32 bulletRankSpeedLow;
    f32 bulletRankSpeedHigh;
    i16 bulletRankAmount1Low;
    i16 bulletRankAmount1High;
    i16 bulletRankAmount2Low;
    i16 bulletRankAmount2High;
    i32 life;
    i32 maxLife;
    i32 score;
    ZunTimer bossTimer;
    ZunColor color;
    EnemyBulletShooter bulletProps;
    i32 shootInterval;
    ZunTimer shootIntervalTimer;
    EnemyLaserShooter laserProps;
    Laser *lasers[32]; // This looks like a structure
    i32 laserStore;
    u8 deathAnm1;
    u8 deathAnm2;
    u8 deathAnm3;
    i8 itemDrop;
    u8 bossId;
    u8 unk_e41;
    ZunTimer unk_e44;
    EnemyFlags flags;
    u8 anmExFlags;
    i16 anmExDefaults;
    i16 anmExFarLeft;
    i16 anmExFarRight;
    i16 anmExLeft;
    i16 anmExRight;
    D3DXVECTOR2 lowerMoveLimit;
    D3DXVECTOR2 upperMoveLimit;
    Effect *effectArray[12];
    u32 effectIdx;
    f32 effectDistance;
    i32 lifeCallbackThreshold;
    i32 lifeCallbackSub;
    i32 timerCallbackThreshold;
    i32 timerCallbackSub;
    f32 unk_eb8;
    ZunTimer unk_ebc;
};
C_ASSERT(sizeof(Enemy) == 0xec8);
}; // namespace th06
