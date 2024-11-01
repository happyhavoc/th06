#pragma once

#include "ReplayData.hpp"

namespace th06
{
struct ReplayManager
{
    static ZunResult RegisterChain(i32 isDemo, char *replayFile);
    static void StopRecording();
    static void SaveReplay(char *replay_path, char *param_2);
    static ZunResult ValidateReplayData(ReplayData *data, i32 fileSize);
};
}; // namespace th06
