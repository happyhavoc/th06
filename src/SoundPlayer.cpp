#include "SoundPlayer.hpp"
#include "utils.hpp"

SoundPlayer::SoundPlayer()
{
    memset(this, 0, sizeof(SoundPlayer));
    for (i32 i = 0; i < ARRAY_SIZE_SIGNED(this->unk408); i++)
    {
        this->unk408[i] = -1;
    }
}

DIFFABLE_STATIC(SoundPlayer, g_SoundPlayer)
