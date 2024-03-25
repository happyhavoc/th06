#pragma once

#include <Windows.h>

#include "ZunResult.hpp"
#include "diffbuild.hpp"
#include "inttypes.hpp"
#include "zwave.hpp"

struct SoundPlayer
{
    void InitializeDSound(HWND window);
    ZunResult InitSoundBuffers();
    ZunResult Release(void);

    void PlaySounds();
    void PlaySoundByIdx(i32 idx, i32 unused);

    CSoundManager manager;
    i32 unk4;
    LPDIRECTSOUNDBUFFER soundBuffers[128];
    LPDIRECTSOUNDBUFFER duplicateSoundBuffers[128];
    i32 unk408[128];
    LPDIRECTSOUNDBUFFER initSoundBuffer;
    HWND gameWindow;
    CSoundManager *managerptr;
    DWORD notifyThreadId;
    HANDLE notifyThreadHandle;
    i32 unk61c;
    u32 soundBuffersToPlay[3];
    CStreamingSound *streamingSound;
    HANDLE streamingSoundUpdateEvent;
};
C_ASSERT(sizeof(SoundPlayer) == 0x634);

DIFFABLE_EXTERN(SoundPlayer, g_SoundPlayer)
