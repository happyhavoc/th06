#pragma once

#include "AnmVm.hpp"
#include "Chain.hpp"
#include "ZunResult.hpp"
#include "ZunTimer.hpp"
#include "inttypes.hpp"

namespace th06
{
struct Ending
{
    Ending();
    static ZunResult RegisterChain();
    static ChainCallbackResult OnUpdate(Ending *ending);
    static ChainCallbackResult OnDraw(Ending *ending);
    static ZunResult AddedCallback(Ending *ending);
    static ZunResult DeletedCallback(Ending *ending);

    ChainElem *calcChain;
    ChainElem *drawChain;
    ZunTimer anmTimer4;
    AnmVm sprites[16];
    char *endFileData;
    i32 unk_111a;
    ZunTimer timer1;
    ZunTimer timer2;
    ZunTimer timer3;
    i32 minWaitResetFrames;
    i32 minWaitFrames;
    i32 line2Delay;
    i32 topLineDelay;
    i32 unk_1150;
    i32 timesFileParsed;
    ZunColor textColor;
    ZunColor unk_115c;
    i32 timeFading;
    i32 fadeFrames;
    i32 fadeType;
    char *endFileDataPtr;
};
C_ASSERT(sizeof(Ending) == 0x1170);
}; // namespace th06
