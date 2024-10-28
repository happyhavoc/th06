#include "inttypes.hpp"
#include <Windows.h>
#include <mmreg.h>
#include <mmsystem.h>

#include "FileSystem.hpp"
#include "MidiOutput.hpp"
#include "Supervisor.hpp"
#include "i18n.hpp"
#include "utils.hpp"

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

ZunBool MidiDevice::OpenDevice(u32 uDeviceId)
{
    if (this->handle != 0)
    {
        if (this->deviceId != uDeviceId)
        {
            this->Close();
        }
        else
        {
            return false;
        }
    }

    this->deviceId = uDeviceId;

    return midiOutOpen(&this->handle, uDeviceId, (DWORD_PTR)g_Supervisor.hwndGameWindow, NULL, CALLBACK_WINDOW) !=
           MMSYSERR_NOERROR;
}

union MidiShortMsg {
    struct
    {
        u8 midiStatus;
        i8 firstByte;
        i8 secondByte;
        i8 unused;
    } msg;
    u32 dwMsg;
};

ZunBool MidiDevice::SendShortMsg(u8 midiStatus, u8 firstByte, u8 secondByte)
{
    MidiShortMsg pkt;

    if (this->handle == 0)
    {
        return false;
    }
    else
    {
        pkt.msg.midiStatus = midiStatus;
        pkt.msg.firstByte = firstByte;
        pkt.msg.secondByte = secondByte;
        return midiOutShortMsg(this->handle, pkt.dwMsg) != MMSYSERR_NOERROR;
    }
}

ZunBool MidiDevice::SendLongMsg(LPMIDIHDR pmh)
{
    if (this->handle == 0)
    {
        return false;
    }
    else
    {
        if (midiOutPrepareHeader(this->handle, pmh, sizeof(*pmh)) != MMSYSERR_NOERROR)
        {
            return true;
        }

        return midiOutLongMsg(this->handle, pmh, sizeof(*pmh)) != MMSYSERR_NOERROR;
    }
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
    this->fadeOutVolumeMultiplier = 0;
    this->fadeOutLastSetVolume = 0;
    this->unk2d0 = 0;
    this->unk2d4 = 0;
    this->unk2d8 = 0;
    this->unk2dc = 0;
    this->fadeOutFlag = 0;

    for (int i = 0; i < ARRAY_SIZE_SIGNED(this->midiFileData); i++)
    {
        this->midiFileData[i] = NULL;
    }

    for (int i = 0; i < ARRAY_SIZE_SIGNED(this->midiHeaders); i++)
    {
        this->midiHeaders[i] = NULL;
    }

    this->midiHeadersCursor = 0;
}

void MidiOutput::LoadTracks()
{
    i32 trackIndex;
    MidiTrack *track = this->tracks;

    this->fadeOutVolumeMultiplier = 1.0;
    this->unk2dc = 0;
    this->fadeOutFlag = 0;
    this->unk128 = 0;
    this->unk130 = 0;

    for (trackIndex = 0; trackIndex < this->numTracks; trackIndex++, track++)
    {
        track->curTrackDataCursor = track->trackData;
        track->startTrackDataMaybe = track->curTrackDataCursor;
        track->trackPlaying = 1;
        track->trackLengthOther = MidiOutput::SkipVariableLength(&track->curTrackDataCursor);
    }
}

#pragma var_order(trackIndex, data, tracks)
void MidiOutput::ClearTracks()
{
    i32 trackIndex;
    u8 *data;
    MidiTrack *tracks;

    for (trackIndex = 0; trackIndex < this->numTracks; trackIndex++)
    {
        data = this->tracks[trackIndex].trackData;
        free(data);
    }

    tracks = this->tracks;
    free(tracks);
    this->tracks = NULL;
    this->numTracks = 0;
}

ZunResult MidiOutput::UnprepareHeader(LPMIDIHDR pmh)
{
    if (pmh == NULL)
    {
        utils::DebugPrint2("error :\n");
    }

    if (this->midiOutDev.handle == 0)
    {
        utils::DebugPrint2("error :\n");
    }

    i32 i;
    for (i = 0; i < ARRAY_SIZE_SIGNED(this->midiHeaders); i++)
    {
        if (this->midiHeaders[i] == pmh)
        {
            this->midiHeaders[i] = NULL;
            goto success;
        }
    }

    return ZUN_ERROR;

success:
    MMRESULT res = midiOutUnprepareHeader(this->midiOutDev.handle, pmh, sizeof(*pmh));
    if (res != MMSYSERR_NOERROR)
    {
        utils::DebugPrint2("error :\n");
    }

    void *lpData = pmh->lpData;
    free(lpData);
    free(pmh);
    return ZUN_SUCCESS;
}

ZunResult MidiOutput::StopPlayback()
{
    if (this->tracks == NULL)
    {
        return ZUN_ERROR;
    }
    else
    {
        for (i32 i = 0; i < ARRAY_SIZE_SIGNED(this->midiHeaders); i++)
        {
            if (this->midiHeaders[this->midiHeadersCursor] != NULL)
            {
                this->UnprepareHeader(this->midiHeaders[this->midiHeadersCursor]);
            }
        }

        this->StopTimer();
        this->midiOutDev.Close();

        return ZUN_SUCCESS;
    }
}

ZunResult MidiOutput::ReadFileData(u32 idx, char *path)
{
    if (g_Supervisor.cfg.musicMode != MIDI)
    {
        return ZUN_SUCCESS;
    }

    this->StopPlayback();
    this->ReleaseFileData(idx);

    this->midiFileData[idx] = FileSystem::OpenPath(path, false);

    if (this->midiFileData[idx] == (byte *)0x0)
    {
        g_GameErrorContext.Log(&g_GameErrorContext, TH_ERR_MIDI_FAILED_TO_READ_FILE, path);
        return ZUN_ERROR;
    }

    return ZUN_SUCCESS;
}

void MidiOutput::ReleaseFileData(u32 idx)
{
    u8 *data = this->midiFileData[idx];
    free(data);

    this->midiFileData[idx] = NULL;
}

ZunResult MidiOutput::LoadFile(char *midiPath)
{
    if (this->ReadFileData(0x1f, midiPath) != ZUN_SUCCESS)
    {
        return ZUN_ERROR;
    }

    this->ParseFile(0x1f);
    this->ReleaseFileData(0x1f);

    return ZUN_SUCCESS;
}

ZunResult MidiOutput::Play()
{
    if (this->tracks == NULL)
    {
        return ZUN_ERROR;
    }

    this->LoadTracks();
    this->midiOutDev.OpenDevice(0xFFFFFFFF);
    this->StartTimer(1, NULL, NULL);

    return ZUN_SUCCESS;
}

u32 MidiOutput::SetFadeOut(u32 ms)
{
    this->fadeOutVolumeMultiplier = 0.0;
    this->fadeOutInterval = ms;
    this->fadeOutElapsedMS = 0;
    this->unk2dc = 0;
    this->fadeOutFlag = 1;

    return 0;
}

u16 MidiOutput::Ntohs(u16 val)
{
    u8 tmp[2];

    tmp[0] = ((u8 *)&val)[1];
    tmp[1] = ((u8 *)&val)[0];

    return *(const u16 *)(&tmp);
}

u32 MidiOutput::SkipVariableLength(u8 **curTrackDataCursor)
{
    u32 length;
    u8 tmp;

    length = 0;
    do
    {
        tmp = **curTrackDataCursor;
        *curTrackDataCursor = *curTrackDataCursor + 1;
        length = length * 0x80 + (tmp & 0x7f);
    } while ((tmp & 0x80) != 0);

    return length;
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
