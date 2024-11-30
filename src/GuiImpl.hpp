#pragma once

#include "AnmVm.hpp"
#include "ZunTimer.hpp"
#include "diffbuild.hpp"
#include "inttypes.hpp"

namespace th06
{

enum MsgOps
{
    MSG_OPCODE_MSGDELETE,
    MSG_OPCODE_PORTRAITANMSCRIPT,
    MSG_OPCODE_PORTRAITANMSPRITE,
    MSG_OPCODE_TEXTDIALOGUE,
    MSG_OPCODE_WAIT,
    MSG_OPCODE_ANMINTERRUPT,
    MSG_OPCODE_ECLRESUME,
    MSG_OPCODE_MUSIC,
    MSG_OPCODE_TEXTINTRO,
    MSG_OPCODE_STAGERESULTS,
    MSG_OPCODE_MSGHALT,
    MSG_OPCODE_STAGEEND,
    MSG_OPCODE_MUSICFADEOUT,
    MSG_OPCODE_WAITSKIPPABLE,
};

struct MsgRawInstrArgPortraitAnmScript
{
    i16 portraitIdx;
    i16 anmScriptIdx;
};
struct MsgRawInstrArgText
{
    i16 textColor;
    i16 textLine;
    char text[1];
};
struct MsgRawInstrArgAnmInterrupt
{
    i16 unk1;
    u8 unk2;
};
union MsgRawInstrArgs {
    MsgRawInstrArgPortraitAnmScript portraitAnmScript;
    MsgRawInstrArgText text;
    i32 dialogueSkippable;
    i32 wait;
    MsgRawInstrArgAnmInterrupt anmInterrupt;
    i32 music;
};
struct MsgRawInstr
{
    u16 time;
    u8 opcode;
    u8 argSize;
    MsgRawInstrArgs args;
};

struct MsgRawHeader
{
    i32 numInstrs;
    MsgRawInstr *instrs[1];
};
C_ASSERT(sizeof(MsgRawHeader) == 0x8);

struct GuiMsgVm
{
    MsgRawHeader *msgFile;
    MsgRawInstr *currentInstr;
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
    u8 dialogueSkippable;
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
    GuiImpl();
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
