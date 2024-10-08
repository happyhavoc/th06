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
