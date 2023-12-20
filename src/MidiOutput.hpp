#pragma once

#include "ZunResult.hpp"
#include "inttypes.hpp"
#include <Windows.h>

struct MidiTimer
{
    MidiTimer();
    ~MidiTimer();

    virtual void OnTimerElapsed();

    i32 StopTimer();

    u32 timerId;
    TIMECAPS timeCaps;
};

struct MidiTrack
{
    u32 trackPlaying;
    u32 unk2;
    u32 trackLength;
    u32 unk3;
    u8 *trackData;
    void *unk4;
    void *unk5;
    u32 unk6;
};

struct MidiDevice
{
    MidiDevice();
    ~MidiDevice();

    ZunResult Close();

    HMIDIOUT handle;
    u32 deviceId;
};

struct MidiOutput : MidiTimer
{
    MidiOutput();
    ~MidiOutput();

    ZunResult UnprepareHeader(LPMIDIHDR param_1);

    ZunResult StopPlayback();
    void ClearTracks();
    void UnloadFile(u32 idx);

    MIDIHDR *midiHeaders[32];
    i32 midiHeadersCursor;
    u8 *midiFileData[32];
    u32 numTracks;
    u32 format;
    u32 division;
    u32 unk120;
    u32 unk124;
    u32 unk128;
    u32 unk12c;
    u32 unk130;
    u32 unk134;
    MidiTrack *tracks;
    MidiDevice midiOutDev;
    u8 unk144[384];
    u8 unk2c4;
    u32 unk2c8;
    u32 unk2cc;
    u32 unk2d0;
    u32 unk2d4;
    u32 unk2d8;
    u32 unk2dc;
    u32 unk2e0;
    u32 unk2e4;
    u32 unk2e8;
    u32 unk2ec;
    u32 unk2f0;
    u32 unk2f4;
    u32 unk2f8;
    u32 unk2fc;
};
