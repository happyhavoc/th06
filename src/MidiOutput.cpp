#include "inttypes.hpp"
#include <Windows.h>
#include <mmreg.h>
#include <mmsystem.h>

#include "MidiOutput.hpp"

namespace th06
{
MidiTimer::MidiTimer()
{
    timeGetDevCaps(&this->timeCaps, sizeof(TIMECAPS));
    this->timerId = 0;
}

void MidiTimer::OnTimerElapsed()
{
}

i32 MidiTimer::StopTimer()
{
    if (this->timerId != 0)
    {
        timeKillEvent(this->timerId);
    }

    timeEndPeriod(this->timeCaps.wPeriodMin);
    this->timerId = 0;

    return 1;
}

u32 MidiTimer::StartTimer(u32 delay, LPTIMECALLBACK cb, DWORD_PTR data)
{
    this->StopTimer();
    timeBeginPeriod(this->timeCaps.wPeriodMin);

    if (cb != NULL)
    {
        this->timerId = timeSetEvent(delay, this->timeCaps.wPeriodMin, cb, data, TIME_PERIODIC);
    }
    else
    {
        this->timerId = timeSetEvent(delay, this->timeCaps.wPeriodMin, (LPTIMECALLBACK)MidiTimer::DefaultTimerCallback,
                                     (DWORD_PTR)this, TIME_PERIODIC);
    }

    return this->timerId;
}

void MidiTimer::DefaultTimerCallback(u32 uTimerID, u32 uMsg, DWORD_PTR dwUser, DWORD_PTR dw1, DWORD_PTR dw2)
{
    MidiTimer *timer = (MidiTimer *)dwUser;

    timer->OnTimerElapsed();
}

MidiTimer::~MidiTimer()
{
    this->StopTimer();
    timeEndPeriod(this->timeCaps.wPeriodMin);
}

MidiDevice::MidiDevice()
{
    this->handle = NULL;
    this->deviceId = 0;
}

ZunResult MidiDevice::Close()
{
    if (this->handle == 0)
    {
        return ZUN_ERROR;
    }

    midiOutReset(this->handle);
    midiOutClose(this->handle);
    this->handle = 0;

    return ZUN_SUCCESS;
}

MidiDevice::~MidiDevice()
{
    this->Close();
}

MidiOutput::MidiOutput()
{
    this->tracks = NULL;
    this->division = 0;
    this->unk120 = 0;
    this->numTracks = 0;
    this->unk2c4 = 0;
    this->unk2c8 = 0;
    this->unk2cc = 0;
    this->unk2d0 = 0;
    this->unk2d4 = 0;
    this->unk2d8 = 0;
    this->unk2dc = 0;
    this->unk2e0 = 0;

    for (int i = 0; i < sizeof(this->midiFileData) / sizeof(this->midiFileData[0]); i++)
    {
        this->midiFileData[i] = 0;
    }
    for (int i = 0; i < sizeof(this->midiHeaders) / sizeof(this->midiHeaders[0]); i++)
    {
        this->midiHeaders[i] = 0;
    }
    this->midiHeadersCursor = 0;
}

MidiOutput::~MidiOutput()
{
    this->StopPlayback();
    this->ClearTracks();
    for (i32 i = 0; i < 32; i++)
    {
        this->ReleaseFileData(i);
    }
}

}; // namespace th06
