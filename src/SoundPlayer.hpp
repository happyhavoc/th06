#pragma once

#include <Windows.h>

#include "ZunResult.hpp"
#include "diffbuild.hpp"
#include "inttypes.hpp"
#include "zwave.hpp"

struct SoundBufferIdxVolume {
    i32 bufferIdx;
    i16 volume;
    i16 unk;
};
C_ASSERT(sizeof(SoundBufferIdxVolume) == 0x8);

struct SoundPlayer
{
    SoundPlayer();

    ZunResult InitializeDSound(HWND window);
    ZunResult InitSoundBuffers();
    ZunResult Release(void);

    ZunResult LoadSound(i32 idx, char* path);
    void PlaySounds();
    void PlaySoundByIdx(i32 idx, i32 unused);
    ZunResult PlayBGM(BOOL isLooping);
    void StopBGM();

    static DWORD __stdcall BackgroundMusicPlayerThread(LPVOID lpThreadParameter);

    ZunResult LoadWav(char *path);
    ZunResult LoadPos(char *path);

    LPDIRECTSOUND dsoundHdl;
    i32 unk4;
    LPDIRECTSOUNDBUFFER soundBuffers[128];
    LPDIRECTSOUNDBUFFER duplicateSoundBuffers[128];
    i32 unk408[128];
    LPDIRECTSOUNDBUFFER initSoundBuffer;
    HWND gameWindow;
    CSoundManager *manager;
    DWORD backgroundMusicThreadId;
    HANDLE backgroundMusicThreadHandle;
    i32 unk61c;
    u32 soundBuffersToPlay[3];
    CStreamingSound *backgroundMusic;
    HANDLE backgroundMusicUpdateEvent;
    BOOL isLooping;
};
C_ASSERT(sizeof(SoundPlayer) == 0x638);


DIFFABLE_EXTERN(SoundBufferIdxVolume, g_SoundBufferIdxVol[32]);
DIFFABLE_EXTERN(char, *g_SFXList[26]);
DIFFABLE_EXTERN(SoundPlayer, g_SoundPlayer)
