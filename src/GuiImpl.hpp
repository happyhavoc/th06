#pragma once

#include "AnmVm.hpp"
#include "diffbuild.hpp"
#include "inttypes.hpp"
#include "ZunTimer.hpp"

struct MsgRawHeader {
    i32 numEntries;
    void* entries;
};
C_ASSERT(sizeof(MsgRawHeader) == 0x8);

struct GuiMsgVm {
    MsgRawHeader* msgFile;
    void* currentInstr;
    u32 currentMsgIdx;
    ZunTimer timer;
    i32 framesElapsedDuringPause;
    AnmVm portraits[2];
    AnmVm dialogue_lines[2];
    AnmVm introLines[2];
    D3DCOLOR textColorsA[4];
    D3DCOLOR textColorsB[4];
    u32 fontSize;
    u32 ignoreWaitCounter;
    bool dialogueSkippable;
};
C_ASSERT(sizeof(GuiMsgVm) == 0x6a8);

struct GuiImplChildB {
    D3DXVECTOR3 vec;
    i32 unk_0xc;
    i32 unk_0x10;
    ZunTimer timer;
};
C_ASSERT(sizeof(GuiImplChildB) == 0x20);

struct GuiImpl {
    AnmVm vms[26];
    i8 unk_0x1ba0[4];
    AnmVm vm1;
    AnmVm vm2;
    AnmVm vm3;
    AnmVm vm4;
    AnmVm vm5;
    AnmVm vm6;
    AnmVm vm7;
    AnmVm vm8;
    AnmVm vm9;
    GuiMsgVm msg;
    u32 finishedStage;
    u32 stageScore;
    GuiImplChildB children[3];
};
C_ASSERT(sizeof(GuiImpl) == 0x2c44);
