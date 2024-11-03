#include "MusicRoom.hpp"
#include "Chain.hpp"

namespace th06 {
    DIFFABLE_STATIC(MusicRoom, g_MusicRoom);
    DIFFABLE_STATIC(u32, g_MRHasConstructed);

    #pragma optimize("s", on)
    ZunResult MusicRoom::RegisterChain(void) {
        int iVar1;
        int iVar2;
        int iVar3;
        MusicRoom *musicRoom;

        if (!(g_MRHasConstructed & 1)) {
            g_MRHasConstructed |= 1;
            MusicRoom();
        }

        memset(musicRoom, 0, sizeof(MusicRoom));

        musicRoom->calc_chain = g_Chain.CreateElem((ChainCallback)MusicRoom::OnUpdate);
        musicRoom->calc_chain->arg = musicRoom;
        musicRoom->calc_chain->addedCallback = (ChainAddedCallback)MusicRoom::AddedCallback;
        musicRoom->calc_chain->deletedCallback = (ChainDeletedCallback)MusicRoom::DeletedCallback;

        if (g_Chain.AddToCalcChain(musicRoom->calc_chain, 2)) {
            return ZUN_ERROR;
        }

        musicRoom->draw_chain = g_Chain.CreateElem((ChainCallback)MusicRoom::OnDraw);
        musicRoom->draw_chain->arg = musicRoom;
        g_Chain.AddToDrawChain(musicRoom->draw_chain, 0);

        return ZUN_SUCCESS;
    };

    MusicRoom::MusicRoom() {

    }

    MusicRoom::~MusicRoom() {

    }
    #pragma optimize("", on)



} // namespace th06

