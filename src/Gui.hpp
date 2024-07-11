#pragma once

#include "diffbuild.hpp"
#include "inttypes.hpp"
#include <Windows.h>

#include "Chain.hpp"
#include "GuiImpl.hpp"

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
    static ZunResult AddedCallback(Gui *);
    static ZunResult DeletedCallback(Gui *);
    static ChainCallbackResult OnUpdate(Gui *);
    static ChainCallbackResult OnDraw(Gui *);

    ZunResult ActualAddedCallback();
    ZunResult LoadMsg(char *path);
    void FreeMsgFile();

    ZunBool IsStageFinished();

    void CalculateStageScore();
    ZunBool HasCurrentMsgIdx();

    void DrawStageElements();
    void DrawGameScene();

    void MsgRead(i32 msgIdx);
    ZunBool MsgWait();

    void SetBossHealthBar(f32 val)
    {
        this->bossHealthBar1 = val;
    }

    bool BossPresent()
    {
        return this->bossPresent;
    }

    GuiFlags flags;
    GuiImpl *impl;
    f32 unk_8;
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
