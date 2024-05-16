#pragma once

#include "AnmVm.hpp"
#include "EclManager.hpp"
#include "Effect.hpp"
#include "ItemManager.hpp"
#include "SoundPlayer.hpp"
#include "ZunResult.hpp"
#include "ZunTimer.hpp"
#include "inttypes.hpp"
#include <Windows.h>
#include <d3d8.h>
#include <d3dx8math.h>

struct Enemy;

struct EnemyBulletShooter
{
    u16 sprite;
    u16 color;
    D3DXVECTOR3 position;
    f32 angle1;
    f32 angle2;
    f32 speed1;
    f32 speed2;
    f32 exFloats[4];
    i32 exInts[4];
    i32 unk_40;
    u16 count1;
    u16 count2;
    u16 aimMode;
    u32 flags;
    SoundIdx sfx;
};
C_ASSERT(sizeof(EnemyBulletShooter) == 0x54);

struct EnemyLaserShooter
{
    u16 sprite;
    u16 color;
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
    u32 unk_4c;
    u32 unk_50;
};
C_ASSERT(sizeof(EnemyLaserShooter) == 0x54);

struct EnemyEclContext
{
    EclRawInstr *currentInstr;
    ZunTimer time;
    void (*funcSetFunc)(Enemy *);
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

struct Enemy
{
    AnmVm primaryVm;
    AnmVm vms[8];
    EnemyEclContext currentContext;
    EnemyEclContext savedContextStack[8];
    i32 stackDepth;
    i32 unk_c40;
    i16 deathCallbackSub;
    i16 interrupts[16];
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
    u16 bulletRankAmount1Low;
    u16 bulletRankAmount1High;
    u16 bulletRankAmount2Low;
    u16 bulletRankAmount2High;
    i32 life;
    i32 maxLife;
    i32 score;
    ZunTimer bossTimer;
    ZunColor color;
    EnemyBulletShooter bulletProps;
    i32 shootInterval;
    ZunTimer shootIntervalTimer;
    EnemyLaserShooter laserProps;
    void *lasers[32]; // This looks like a structure
    i32 laserStore;
    i8 deathAnm1;
    i8 deathAnm2;
    i8 deathAnm3;
    i8 itemDrop;
    i8 bossId;
    i8 unk_e41;
    ZunTimer unk_e44;
    i8 flags1;
    i8 flags2;
    i8 flags3;
    i8 anmExFlags;
    i16 anmExDefaults;
    i16 anmExFarLeft;
    i16 anmExFarRight;
    i16 anmExLeft;
    i16 anmExRight;
    D3DXVECTOR2 lowerMoveLimit;
    D3DXVECTOR2 upperMoveLimit;
    Effect *effectArray[12];
    i32 effectIdx;
    f32 effectDistance;
    i32 lifeCallbackThreshold;
    i32 lifeCallbackSub;
    i32 timerCallbackThreshold;
    i32 timerCallbackSub;
    f32 unk_eb8;
    ZunTimer unk_ebc;
};
C_ASSERT(sizeof(Enemy) == 0xec8);
