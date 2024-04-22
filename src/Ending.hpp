#pragma once

#include "AnmVm.hpp"
#include "Chain.hpp"
#include "ZunResult.hpp"
#include "ZunTimer.hpp"

struct Ending
{
    Ending();
    static ZunResult RegisterChain();
    int DeletedCallback();

    u8 unk_00;
    u8 unk_01;
    u8 unk_02;
    u8 unk_03;
    ChainElem *chainElem;
    f32 unk1;
    i32 unk2;
    i32 unk3;
    AnmVm anmVm[16];
    char *endFileData;
    u8 unk_dependent_on_clrd;
    u8 unk_1119;
    u8 unk_111a;
    u8 unk_111b;
    ZunTimer Timer1;
    ZunTimer Timer2;
    ZunTimer Timer3;
    long minWaitResetFrames;
    long minWaitFrames;
    long line2Delay;
    long topLineDelay;
    u8 unk_1150;
    u8 unk_1151;
    u8 unk_1152;
    u8 unk_1153;
    i32 possibly_times_file_parsed;
    long textColor;
    D3DCOLOR unk_d3dcolor;
    int timeFading;
    long fadeFrames;
    int fadeType;
    char *endFileDataPtr;
};