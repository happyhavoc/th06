#include "MusicRoom.hpp"
#include "AnmManager.hpp"
#include "Chain.hpp"
#include "ChainPriorities.hpp"
#include "FileSystem.hpp"

namespace th06
{
#pragma optimize("s", on)
ZunResult MusicRoom::RegisterChain()
{
    static MusicRoom g_MusicRoom;
    MusicRoom *musicRoom;

    musicRoom = &g_MusicRoom;
    memset(musicRoom, 0, sizeof(MusicRoom));

    musicRoom->calc_chain = g_Chain.CreateElem((ChainCallback)MusicRoom::OnUpdate);
    musicRoom->calc_chain->arg = musicRoom;
    musicRoom->calc_chain->addedCallback = (ChainAddedCallback)MusicRoom::AddedCallback;
    musicRoom->calc_chain->deletedCallback = (ChainDeletedCallback)MusicRoom::DeletedCallback;

    if (g_Chain.AddToCalcChain(musicRoom->calc_chain, TH_CHAIN_PRIO_CALC_MAINMENU))
    {
        return ZUN_ERROR;
    }

    musicRoom->draw_chain = g_Chain.CreateElem((ChainCallback)MusicRoom::OnDraw);
    musicRoom->draw_chain->arg = musicRoom;
    g_Chain.AddToDrawChain(musicRoom->draw_chain, TH_CHAIN_PRIO_DRAW_MAINMENU);

    return ZUN_SUCCESS;
};

ZunResult MusicRoom::AddedCallback(MusicRoom *musicRoom)
{

    AnmManager* anmMgr;
    u8* filePtr;
    MusicRoom* musicRoomObj;
    char* currChar;

    if (g_AnmManager->LoadSurface(0, "data/result/music.jpg"))
    {
        return ZUN_ERROR;
    }
    if (g_AnmManager->LoadAnm(0x29, "data/music00.anm", ANM_OFFSET_MUSICROOM_00) != ZUN_SUCCESS) {
        return ZUN_ERROR;
    }
    if (g_AnmManager->LoadAnm(0x2a, "data/music01.anm", ANM_OFFSET_MUSICROOM_01) != ZUN_SUCCESS) {
        return ZUN_ERROR;
    }
    if (g_AnmManager->LoadAnm(0x2b, "data/music02.anm", ANM_OFFSET_MUSICROOM_02) != ZUN_SUCCESS) {
        return ZUN_ERROR;
    }

    musicRoom->mainVM[0].anmFileIndex = ANM_OFFSET_MUSICROOM_00;
    g_AnmManager->SetAndExecuteScript(&musicRoom->mainVM[0], anmMgr->scripts[ANM_OFFSET_MUSICROOM_00]);
    musicRoom->unk_0x8 = 0;

    filePtr = FileSystem::OpenPath("data/musiccmt.txt", 0);

    if (filePtr == NULL)
    {
        return ZUN_ERROR;
    } else {
        musicRoomObj = new MusicRoom();
    }
};

ZunResult MusicRoom::DeletedCallback(MusicRoom *musicRoom)
{
    delete musicRoom->musicRoomPtr;
    musicRoom->musicRoomPtr = NULL;

    g_AnmManager->ReleaseSurface(0);
    g_AnmManager->ReleaseAnm(0x29);
    g_AnmManager->ReleaseAnm(0x2a);
    g_AnmManager->ReleaseAnm(0x2b);
    g_Chain.Cut(musicRoom->draw_chain);
    musicRoom->draw_chain = NULL;

    return ZUN_SUCCESS;
};

ChainCallbackResult MusicRoom::OnUpdate(MusicRoom *musicRoom)
{
    i32 shouldDraw2 = musicRoom->shouldDrawMusicList;
    for (;;)
    {
        switch (musicRoom->shouldDrawMusicList)
        {
        case false:
            if (!musicRoom->FUN_00424e8f())
            {
                break;
            }

            continue;

        case true:
            if (musicRoom->DrawMusicList())
            {
                return CHAIN_CALLBACK_RESULT_CONTINUE_AND_REMOVE_JOB;
            }
        }
        break;
    }

    if (shouldDraw2 != musicRoom->shouldDrawMusicList)
    {
        musicRoom->unk_0x8 = 0;
    }
    else
    {
        musicRoom->unk_0x8++;
    }
    g_AnmManager->ExecuteScript(musicRoom->mainVM);
    return CHAIN_CALLBACK_RESULT_CONTINUE;
};

ZunResult MusicRoom::FUN_00424e8f()
{
    if (0x8 <= this->unk_0x8)
    {
        this->shouldDrawMusicList = 1;
    }

    return ZUN_SUCCESS;
};

#pragma optimize("", on)
} // namespace th06
