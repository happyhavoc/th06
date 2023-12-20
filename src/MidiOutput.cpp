#include "MidiOutput.hpp"

MidiTimer::MidiTimer()
{
    timeGetDevCaps(&this->timeCaps, sizeof(TIMECAPS));
    this->timerId = 0;
}
void MidiTimer::OnTimerElapsed()
{
}
MidiTimer::~MidiTimer()
{
    this->StopTimer();
    timeEndPeriod(this->timeCaps.wPeriodMin);
}
i32 MidiTimer::StopTimer()
{
    // TODO: Stub
    return 0;
}

MidiDevice::MidiDevice()
{
    this->handle = NULL;
    this->deviceId = 0;
}
MidiDevice::~MidiDevice()
{
    this->Close();
}
ZunResult MidiDevice::Close()
{
    // TODO: Stub
    return ZUN_ERROR;
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
