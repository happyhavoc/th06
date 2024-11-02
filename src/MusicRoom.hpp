#pragma once

#include "ZunResult.hpp"
#include "Chain.hpp"

namespace th06
{
struct MusicRoom
{
    static ZunResult __stdcall AddedCallback(MusicRoom* musicRoom);
    static ZunResult __stdcall DeletedCallback(MusicRoom* musicRoom);
    void drawMusicList();
    ZunResult FUN_00424e8f();
    static ChainCallbackResult __stdcall OnDraw(MusicRoom* musicRoom);
    static ChainCallbackResult __stdcall OnUpdate(MusicRoom* musicRoom);
    static ZunResult RegisterChain();
};
}; // namespace th06
