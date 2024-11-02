#pragma once

#include "ZunResult.hpp"
#include "Chain.hpp"

namespace th06
{
struct MusicRoom
{
    static ZunResult AddedCallback(MusicRoom* musicRoom);
    static ZunResult DeletedCallback(MusicRoom* musicRoom);
    void DrawMusicList();
    ZunResult FUN_00424e8f();
    static ChainCallbackResult OnDraw(MusicRoom* musicRoom);
    static ChainCallbackResult OnUpdate(MusicRoom* musicRoom);
    static ZunResult RegisterChain();
};
}; // namespace th06
