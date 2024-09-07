#pragma once

namespace th06
{
struct ReplayManager
{
    static ZunResult RegisterChain(i32 isDemo, char *replayFile);
    static void StopRecording();
};
}; // namespace th06
