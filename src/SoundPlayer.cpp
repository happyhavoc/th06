#include "SoundPlayer.hpp"

void SoundPlayer::Init(HWND window)
{
}

ZunResult SoundPlayer::InitSoundBuffers()
{
    return ZUN_ERROR;
}

void SoundPlayer::Release(void)
{
}

DIFFABLE_STATIC(SoundPlayer, g_SoundPlayer)
