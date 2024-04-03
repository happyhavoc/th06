#pragma once

#include "inttypes.hpp"

struct ReplayDataInput
{
    u32 frameNum;
    u16 inputKey;
    u16 padding;
};

struct StageReplayData
{
    u32 score;
    u16 randomSeed;
    u16 unk_6;
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
    u16 version;
    i8 shottypeChara;
    i8 difficulty;
    u32 checksum;
    u16 paddingBytes;
    u8 key;
    i8 padding[33];
    StageReplayData *stageScore[7];
    i8 padding2[4];
};
C_ASSERT(sizeof(ReplayData) == 0x50);

ZunResult validateReplayData(ReplayData *data, i32 fileSize);
