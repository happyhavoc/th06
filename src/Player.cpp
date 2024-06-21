#include "Player.hpp"

#include "AnmManager.hpp"
#include "AnmVm.hpp"
#include "BulletManager.hpp"
#include "ChainPriorities.hpp"
#include "EclManager.hpp"
#include "GameManager.hpp"
#include "Gui.hpp"
#include "ItemManager.hpp"
#include "Supervisor.hpp"
#include "ZunBool.hpp"
#include "utils.hpp"

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
    for (idx = 0; idx < ARRAY_SIZE_SIGNED(p->unk_638); idx++)
    {
        p->unk_638[idx].x = 0.0;
    }
    p->hitboxSize.x = 1.25;
    p->hitboxSize.y = 1.25;
    p->hitboxSize.z = 5.0;
    p->grabItemSize.x = 12.0;
    p->grabItemSize.y = 12.0;
    p->grabItemSize.z = 5.0;
    p->playerDirection = MOVEMENT_NONE;
    memcpy(&p->characterData, &g_CharData[g_GameManager.character * 2 + g_GameManager.shotType], sizeof(CharacterData));
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
    p->bombInfo.calc = g_BombData[g_GameManager.character * 2 + g_GameManager.shotType].calc;
    p->bombInfo.draw = g_BombData[g_GameManager.character * 2 + g_GameManager.shotType].draw;
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
    for (idx = 0; idx < ARRAY_SIZE_SIGNED(p->unk_638); idx++)
    {
        p->unk_638[idx].x = 0.0;
    }
    for (idx = 0; idx < ARRAY_SIZE_SIGNED(p->unk_8b8); idx++)
    {
        p->unk_8b8[idx].size.x = 0.0;
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
        g_RunningSpellcardInfo.isCapturing = false;
        g_GameManager.DecreaseSubrank(200);
        g_RunningSpellcardInfo.usedBomb = g_RunningSpellcardInfo.isActive;
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
    int bulletIdx;
    PlayerBullet *bullets = p->bullets;

    for (bulletIdx = 0; bulletIdx < ARRAY_SIZE_SIGNED(p->bullets); bulletIdx++, bullets++)
    {
        if (bullets->bulletState != BULLET_STATE_FIRED)
        {
            continue;
        }
        if (bullets->sprite.autoRotate)
        {
            bullets->sprite.rotation.z = ZUN_PI / 2 - AddNormalizeAngle(bullets->unk_134.z, ZUN_PI);
        }
        g_AnmManager->Draw2(&bullets->sprite);
    }
}