#pragma once

#include "inttypes.hpp"

namespace th06
{
struct ReplayDataInput
{
    u32 frameNum;
    u16 inputKey;
    u16 padding;
};

struct StageReplayData
{
    i32 score;
    i16 randomSeed;
    i16 pointItemsCollected;
    i8 power;
    i8 livesRemaining;
    i8 bombsRemaining;
    i8 rank;
    i8 powerItemCountForScore;
    i8 padding[3];
    ReplayDataInput replayInputs[53998];
};
C_ASSERT(sizeof(StageReplayData) == 0x69780);

struct ReplayData
{
    char *magic;
    i16 version;
    u8 shottypeChara;
    u8 difficulty;
    i32 checksum;
    i16 paddingBytes;
    i8 key;
    i8 unk_f;
    char date[8];
    i8 unk_21;
    char name[8];
    i8 padding[11];
    f32 slowdownRate;
    i8 padding2[4];
    StageReplayData *stageReplayData[7];
};
C_ASSERT(sizeof(ReplayData) == 0x50);
}; // namespace th06
