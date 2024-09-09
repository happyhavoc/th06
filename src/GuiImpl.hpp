#pragma once

#include "AnmVm.hpp"
#include "ZunTimer.hpp"
#include "diffbuild.hpp"
#include "inttypes.hpp"

namespace th06
{
struct MsgRawEntry
{
};

struct MsgRawHeader
{
    i32 numEntries;
    MsgRawEntry *entries[1];
};
C_ASSERT(sizeof(MsgRawHeader) == 0x8);

struct GuiMsgVm
{
    MsgRawHeader *msgFile;
    void *currentInstr;
    i32 currentMsgIdx;
    ZunTimer timer;
    i32 framesElapsedDuringPause;
    AnmVm portraits[2];
    AnmVm dialogueLines[2];
    AnmVm introLines[2];
    D3DCOLOR textColorsA[4];
    D3DCOLOR textColorsB[4];
    u32 fontSize;
    u32 ignoreWaitCounter;
    bool dialogueSkippable;
};
C_ASSERT(sizeof(GuiMsgVm) == 0x6a8);

struct GuiFormattedText
{
    D3DXVECTOR3 pos;
    i32 fmtArg;
    i32 isShown;
    ZunTimer timer;
};
C_ASSERT(sizeof(GuiFormattedText) == 0x20);

struct GuiImpl
{
    ZunResult RunMsg();
    ZunResult DrawDialogue();
    void MsgRead(i32 msgIdx);

    AnmVm vms[26];
    u8 bossHealthBarState;
    AnmVm stageNameSprite;
    AnmVm songNameSprite;
    AnmVm playerSpellcardPortrait;
    AnmVm enemySpellcardPortrait;
    AnmVm bombSpellcardName;
    AnmVm enemySpellcardName;
    AnmVm bombSpellcardBackground;
    AnmVm enemySpellcardBackground;
    AnmVm loadingScreenSprite;
    GuiMsgVm msg;
    u32 finishedStage;
    u32 stageScore;
    GuiFormattedText bonusScore;
    GuiFormattedText fullPowerMode;
    GuiFormattedText spellCardBonus;
};
C_ASSERT(sizeof(GuiImpl) == 0x2c44);
}; // namespace th06
