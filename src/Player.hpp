#pragma once

#include <d3dx8math.h>

#include "AnmVm.hpp"
#include "Chain.hpp"
#include "ZunResult.hpp"
#include "inttypes.hpp"

struct Player;

enum Character
{
    CHARA_REIMU,
    CHARA_MARISA,
};

enum PlayerState
{
    PLAYER_STATE_ALIVE,
    PLAYER_STATE_SPAWNING,
    PLAYER_STATE_DEAD,
    PLAYER_STATE_USING_BOMB,
};

enum ExtraBulletSpawnState
{
    EXTRA_BULLET_SPAWN_STATE_NONE,
    EXTRA_BULLET_SPAWN_STATE_UNFOCUSED,
    EXTRA_BULLET_SPAWN_STATE_FOCUSING,
    EXTRA_BULLET_SPAWN_STATE_FULLY_FOCUSED,
    EXTRA_BULLET_SPAWN_STATE_UNFOCUSING,
};

struct BombData
{
    void (*calc)(Player *p);
    void (*draw)(Player *p);
};

struct PlayerRect
{
    D3DXVECTOR2 pos;
    D3DXVECTOR2 size;
};
C_ASSERT(sizeof(PlayerRect) == 0x10);

struct PlayerBullet
{
    AnmVm vm;
    D3DXVECTOR3 position;
    D3DXVECTOR3 size;
    D3DXVECTOR2 velocity;
    f32 sidewaysMotion;
    D3DXVECTOR3 unk_134;
    ZunTimer unk_140;
    u16 unk_14c;
    u16 bulletState;
    u16 bulletType;
    u16 unk_152;
    u16 unk_154;
};
C_ASSERT(sizeof(PlayerBullet) == 0x158);

struct PlayerInner
{
    u32 isUsingBomb;
    u32 unk_4;
    ZunTimer unk_8;
    void (*bombCalc)(Player *p);
    void (*bombDraw)(Player *p);
    u32 unk_1c[8];
    f32 unk_3c[8];
    D3DXVECTOR3 unk_5c[8];
    D3DXVECTOR3 unk_bc[8];
    AnmVm vms[8][4];
};
C_ASSERT(sizeof(PlayerInner) == 0x231c);

typedef u32 FireBulletResult;
typedef FireBulletResult (*FireBulletCallback)(Player *, PlayerBullet *, u32, u32);
struct CharacterData
{
    f32 orthogonalMovementSpeed;
    f32 orthogonalMovementSpeedFocus;
    f32 diagonalMovementSpeed;
    f32 diagonalMovementSpeedFocus;
    FireBulletCallback fireBulletCallback;
    FireBulletCallback fireBulletFocusCallback;
};
C_ASSERT(sizeof(CharacterData) == 0x18);

struct Player
{
    Player();

    static ZunResult RegisterChain(u8 unk);
    static ChainCallbackResult OnUpdate(Player *p);
    static ChainCallbackResult OnDrawHighPrio(Player *p);
    static ChainCallbackResult OnDrawLowPrio(Player *p);
    static ZunResult AddedCallback(Player *p);
    static ZunResult DeletedCallback(Player *p);

    static FireBulletResult FireBulletReimuA(Player *, PlayerBullet *, u32, u32);
    static FireBulletResult FireBulletReimuB(Player *, PlayerBullet *, u32, u32);
    static FireBulletResult FireBulletMarisaA(Player *, PlayerBullet *, u32, u32);
    static FireBulletResult FireBulletMarisaB(Player *, PlayerBullet *, u32, u32);

    static void BombReimuACalc(Player *);
    static void BombReimuBCalc(Player *);
    static void BombMarisaACalc(Player *);
    static void BombMarisaBCalc(Player *);
    static void BombReimuADraw(Player *);
    static void BombReimuBDraw(Player *);
    static void BombMarisaADraw(Player *);
    static void BombMarisaBDraw(Player *);

    AnmVm vm0;
    AnmVm vm1[3];
    D3DXVECTOR3 positionCenter;
    D3DXVECTOR3 unk_44c;
    D3DXVECTOR3 hitboxTopLeft;
    D3DXVECTOR3 hitboxBottomRight;
    D3DXVECTOR3 grabItemTopLeft;
    D3DXVECTOR3 grabItemBottomRight;
    D3DXVECTOR3 hitboxSize;
    D3DXVECTOR3 grabItemSize;
    D3DXVECTOR3 bulletSpawnPositions[2];
    D3DXVECTOR3 unk_4b8[32];
    D3DXVECTOR3 unk_638[32];
    i32 unk_7b8[32];
    i32 unk_838[32];
    PlayerRect unk_8b8;
    PlayerRect unk_8c8;
    PlayerRect unk_8d8;
    PlayerRect unk_8e8;
    PlayerRect unk_8f8;
    PlayerRect unk_908;
    PlayerRect unk_918;
    PlayerRect unk_928;
    PlayerRect unk_938;
    PlayerRect unk_948;
    PlayerRect unk_958;
    PlayerRect unk_968;
    PlayerRect unk_978;
    PlayerRect unk_988;
    PlayerRect unk_998;
    PlayerRect unk_9a8;
    ZunTimer laserTimer[2];
    f32 horizontalMovementSpeedMultiplierDuringBomb;
    f32 verticalMovementSpeedMultiplierDuringBomb;
    i32 respawnTimer;
    i32 unk_9dc;
    u8 playerState;
    u8 unk_9e1;
    u8 extraBulletSpawnState;
    u8 isFocus;
    u8 unk_9e4;
    ZunTimer focusMovementTimer;
    CharacterData characterData;
    i32 playerDirection;
    f32 unk_a10;
    i32 unk_a14;
    i16 unk_a18;
    D3DXVECTOR3 positionOfLastEnemyHit;
    PlayerBullet bullets[80];
    ZunTimer fireBulletTimer;
    ZunTimer blinkingPlayerTimer;
    FireBulletCallback fireBulletCallback;
    FireBulletCallback fireBulletFocusCallback;
    PlayerInner inner;
    ChainElem *chainCalc;
    ChainElem *chainDraw1;
    ChainElem *chainDraw2;
};
C_ASSERT(sizeof(Player) == 0x98f0);
