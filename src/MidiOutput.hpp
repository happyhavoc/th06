#pragma once

#include "ZunBool.hpp"
#include "ZunResult.hpp"
#include "inttypes.hpp"
#include <Windows.h>

namespace th06
{
struct MidiTimer
{
    MidiTimer();
    ~MidiTimer();

    virtual void OnTimerElapsed();

    i32 StopTimer();
    u32 StartTimer(u32 delay, LPTIMECALLBACK cb, DWORD_PTR data);

    static void DefaultTimerCallback(u32 uTimerID, u32 uMsg, DWORD_PTR dwUser, DWORD_PTR dw1, DWORD_PTR dw2);

    u32 timerId;
    TIMECAPS timeCaps;
};
C_ASSERT(sizeof(MidiTimer) == 0x10);

struct MidiTrack
{
    u32 trackPlaying;
    u32 trackLengthOther;
    u32 trackLength;
    u32 unk3;
    u8 *trackData;
    u8 *curTrackDataCursor;
    u8 *startTrackDataMaybe;
    u32 unk6;
};
C_ASSERT(sizeof(MidiTrack) == 0x20);

struct MidiDevice
{
    MidiDevice();
    ~MidiDevice();

    ZunResult Close();
    ZunBool OpenDevice(u32 uDeviceId);
    ZunBool SendShortMsg(u8 midiStatus, u8 firstByte, u8 secondByte);
    ZunBool SendLongMsg(LPMIDIHDR pmh);

    HMIDIOUT handle;
    u32 deviceId;
};
C_ASSERT(sizeof(MidiDevice) == 0x8);

struct MidiOutput : MidiTimer
{
    MidiOutput();
    ~MidiOutput();

    void OnTimerElapsed();

    ZunResult UnprepareHeader(LPMIDIHDR pmh);

    ZunResult StopPlayback();
    void LoadTracks();
    void ClearTracks();
    ZunResult ReadFileData(u32 idx, char *path);
    void ReleaseFileData(u32 idx);
    void ParseFile(u32 idx);

    ZunResult ParseFile(i32 idx);
    ZunResult LoadFile(char *midiPath);
    ZunResult Play();

    u32 SetFadeOut(u32 ms);
    static u16 Ntohs(u16 val);
    static u32 SkipVariableLength(u8 **curTrackDataCursor);

    MIDIHDR *midiHeaders[32];
    i32 midiHeadersCursor;
    u8 *midiFileData[32];
    i32 numTracks;
    u32 format;
    u32 divisions;
    u32 tempo;
    u32 unk124;
    f64 unk128;
    f64 unk130;
    MidiTrack *tracks;
    MidiDevice midiOutDev;
    u8 unk144[384];
    u8 unk2c4;
    f32 fadeOutVolumeMultiplier;
    u32 fadeOutLastSetVolume;
    u32 unk2d0;
    u32 unk2d4;
    u32 unk2d8;
    u32 unk2dc;
    u32 fadeOutFlag;
    u32 fadeOutInterval;
    u32 fadeOutElapsedMS;
    u32 unk2ec;
    u32 unk2f0;
    u32 unk2f4;
    u32 unk2f8;
    u32 unk2fc;
};
C_ASSERT(sizeof(MidiOutput) == 0x300);
}; // namespace th06
