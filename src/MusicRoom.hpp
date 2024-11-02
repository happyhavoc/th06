#pragma once

#include "ZunResult.hpp"
#include "Chain.hpp"
#include "inttypes.hpp"

namespace th06
{
struct MusicRoom
{
    MusicRoom();
    static ZunResult AddedCallback(MusicRoom* musicRoom);
    static ZunResult DeletedCallback(MusicRoom* musicRoom);
    void DrawMusicList();
    ZunResult FUN_00424e8f();
    static ChainCallbackResult OnDraw(MusicRoom* musicRoom);
    static ChainCallbackResult OnUpdate(MusicRoom* musicRoom);
    static ZunResult RegisterChain();

    ChainElem* calc_chain;
    ChainElem* draw_chain;
};
}; // namespace th06
