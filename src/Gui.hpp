#pragma once

#include "Enemy.hpp"
#include "diffbuild.hpp"
#include "inttypes.hpp"
#include <Windows.h>

#include "Chain.hpp"
#include "GuiImpl.hpp"

namespace th06
{
struct GuiFlags
{
    u32 flag0 : 2;
    u32 flag1 : 2;
    u32 flag2 : 2;
    u32 flag3 : 2;
    u32 flag4 : 2;
};

struct Gui
{
    static ZunResult RegisterChain();
    static void CutChain();
    static ZunResult AddedCallback(Gui *);
    static ZunResult DeletedCallback(Gui *);
    static ChainCallbackResult OnUpdate(Gui *);
    static ChainCallbackResult OnDraw(Gui *);

    ZunResult ActualAddedCallback();
    ZunResult LoadMsg(char *path);
    void FreeMsgFile();

    ZunBool IsStageFinished();

    void UpdateStageElements();
    ZunBool HasCurrentMsgIdx();

    void DrawStageElements();
    void DrawGameScene();

    void MsgRead(i32 msgIdx);
    ZunBool MsgWait();

    void ShowSpellcard(i32 spellcardSprite, char *spellcardName);
    void ShowSpellcardBonus(u32 spellcardScore);
    void ShowBombNamePortrait(u32 sprite, char *bombName);
    void EndEnemySpellcard();
    void EndPlayerSpellcard();

    void ShowFullPowerMode(i32 fmtArg);

    void SetBossHealthBar(f32 val)
    {
        this->bossHealthBar1 = val;
    }

    bool BossPresent()
    {
        return this->bossPresent;
    }

    void SetSpellcardSeconds(i32 val)
    {
        this->spellcardSecondsRemaining = val;
    }

    i32 SpellcardSecondsRemaining()
    {
        return this->spellcardSecondsRemaining;
    }

    void TickTimer(ZunTimer *timer)
    {
        timer->NextTick();
    }

    GuiFlags flags;
    GuiImpl *impl;
    f32 bombSpellcardBarLength;
    f32 blueSpellcardBarLength;
    u32 bossUIOpacity;
    i32 eclSetLives;
    i32 spellcardSecondsRemaining;
    i32 lastSpellcardSecondsRemaining;
    bool bossPresent;
    f32 bossHealthBar1;
    f32 bossHealthBar2;
};
C_ASSERT(sizeof(Gui) == 0x2c);

DIFFABLE_EXTERN(Gui, g_Gui);
}; // namespace th06
