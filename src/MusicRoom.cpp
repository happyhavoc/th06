#include "MusicRoom.hpp"

namespace th06 {
    DIFFABLE_STATIC(MusicRoom, g_MusicRoom);
    DIFFABLE_STATIC(ChainElem, g_MusicRoomDrawChain);
    
    ZunResult MusicRoom::RegisterChain(void) {

        return ZUN_SUCCESS;
    };

} // namespace th06

