#pragma once

struct ReplayManager
{
    static ZunResult RegisterChain(i32 isDemo, char *replayFile);
    static void StopRecording();
};
