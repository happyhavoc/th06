#include "SoundPlayer.hpp"
#include "Supervisor.hpp"
#include "i18n.hpp"
#include "utils.hpp"

#define BACKGROUND_MUSIC_BUFFER_SIZE 0x8000
#define BACKGROUND_MUSIC_WAV_NUM_CHANNELS 2
#define BACKGROUND_MUSIC_WAV_BITS_PER_SAMPLE 16
#define BACKGROUND_MUSIC_WAV_BLOCK_ALIGN BACKGROUND_MUSIC_WAV_BITS_PER_SAMPLE / 8 * BACKGROUND_MUSIC_WAV_NUM_CHANNELS

SoundPlayer::SoundPlayer()
{
    memset(this, 0, sizeof(SoundPlayer));
    for (i32 i = 0; i < ARRAY_SIZE_SIGNED(this->unk408); i++)
    {
        this->unk408[i] = -1;
    }
}

#pragma var_order(bufDesc, audioBuffer2Start, audioBuffer2Len, audioBuffer1Len, audioBuffer1Start, wavFormat)
ZunResult SoundPlayer::InitializeDSound(HWND gameWindow)
{
    DSBUFFERDESC bufDesc;
    tWAVEFORMATEX wavFormat;
    LPVOID audioBuffer1Start;
    DWORD audioBuffer1Len;
    LPVOID audioBuffer2Start;
    DWORD audioBuffer2Len;

    this->manager = new CSoundManager();
    if (this->manager->Initialize(gameWindow, 2, 2, 44100, 16) < ZUN_SUCCESS)
    {
        GameErrorContextLog(&g_GameErrorContext, TH_ERR_SOUNDPLAYER_FAILED_TO_INITIALIZE_OBJECT);
        if (this->manager != NULL)
        {
            delete this->manager;
            this->manager = NULL;
        }
        return ZUN_ERROR;
    }

    this->dsoundHdl = this->manager->GetDirectSound();
    this->backgroundMusicThreadHandle = NULL;
    memset(&bufDesc, 0, sizeof(DSBUFFERDESC));
    bufDesc.dwSize = sizeof(DSBUFFERDESC);
    bufDesc.dwFlags = DSBCAPS_GLOBALFOCUS | DSBCAPS_LOCSOFTWARE;
    bufDesc.dwBufferBytes = BACKGROUND_MUSIC_BUFFER_SIZE;
    memset(&wavFormat, 0, sizeof(tWAVEFORMATEX));
    wavFormat.cbSize = 0;
    wavFormat.wFormatTag = WAVE_FORMAT_PCM;
    wavFormat.nChannels = BACKGROUND_MUSIC_WAV_NUM_CHANNELS;
    wavFormat.nSamplesPerSec = 44100;
    wavFormat.nAvgBytesPerSec = 176400;
    wavFormat.nBlockAlign = BACKGROUND_MUSIC_WAV_BLOCK_ALIGN;
    wavFormat.wBitsPerSample = BACKGROUND_MUSIC_WAV_BITS_PER_SAMPLE;
    bufDesc.lpwfxFormat = &wavFormat;
    if (this->dsoundHdl->CreateSoundBuffer(&bufDesc, &this->initSoundBuffer, NULL) < ZUN_SUCCESS)
    {
        return ZUN_ERROR;
    }
    if (this->initSoundBuffer->Lock(0, BACKGROUND_MUSIC_BUFFER_SIZE, &audioBuffer1Start, &audioBuffer1Len,
                                    &audioBuffer2Start, &audioBuffer2Len, 0) < ZUN_SUCCESS)
    {
        return ZUN_ERROR;
    }

    memset(audioBuffer1Start, 0, BACKGROUND_MUSIC_BUFFER_SIZE);
    this->initSoundBuffer->Unlock(audioBuffer1Start, audioBuffer1Len, audioBuffer2Start, audioBuffer2Len);
    this->initSoundBuffer->Play(0, 0, 1);
    /* 4 times per second */
    SetTimer(gameWindow, 0, 250, NULL);
    this->gameWindow = gameWindow;
    GameErrorContextLog(&g_GameErrorContext, TH_DBG_SOUNDPLAYER_INIT_SUCCESS);
    return ZUN_SUCCESS;
}

DIFFABLE_STATIC(SoundPlayer, g_SoundPlayer)
