#pragma once

#include "ZunResult.hpp"
#include "Chain.hpp"
#include "inttypes.hpp"
#include "AnmVm.hpp"

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
    int unk_0x8;
    int shouldDrawMusicList;
    int cursor;
    int musicPtr;
    int listingOffset;
    int currOffset;
    MusicRoom* musicRoomPtr;
    AnmVm mainVM[1];
    AnmVm anmArray[32];
    AnmVm anmArray2[16];




};
}; // namespace th06
