#include "SoundPlayer.hpp"

void SoundPlayer::InitializeDSound(HWND window)
{
}

ZunResult SoundPlayer::InitSoundBuffers()
{
    return ZUN_ERROR;
}

ZunResult SoundPlayer::Release(void)
{
    return ZUN_ERROR;
}

DIFFABLE_STATIC(SoundPlayer, g_SoundPlayer)
