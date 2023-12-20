#include "MidiOutput.hpp"

MidiTimer::MidiTimer()
{
    timeGetDevCaps(&this->timeCaps, sizeof(TIMECAPS));
    this->timerId = 0;
}
MidiOutput::MidiOutput()
{
    // TODO: Stub
}

MidiOutput::~MidiOutput()
{
}

ZunResult MidiOutput::UnprepareHeader(LPMIDIHDR param_1)
{
    // TODO: Unimplemented
    return ZUN_ERROR;
}
