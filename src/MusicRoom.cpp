#include "MusicRoom.hpp"
#include "AnmManager.hpp"
#include "Chain.hpp"
#include "ChainPriorities.hpp"
#include "FileSystem.hpp"
#include "utils.hpp"
#include <string.h>

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
}

ZunResult MusicRoom::DeletedCallback(MusicRoom *musicRoom)
{
    delete musicRoom->trackDescriptors;
    musicRoom->trackDescriptors = NULL;

    g_AnmManager->ReleaseSurface(0);
    g_AnmManager->ReleaseAnm(ANM_FILE_MUSIC00);
    g_AnmManager->ReleaseAnm(ANM_FILE_MUSIC01);
    g_AnmManager->ReleaseAnm(ANM_FILE_MUSIC02);
    g_Chain.Cut(musicRoom->draw_chain);
    musicRoom->draw_chain = NULL;

    return ZUN_SUCCESS;
}

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
    g_AnmManager->ExecuteScript(musicRoom->mainVm);
    return CHAIN_CALLBACK_RESULT_CONTINUE;
}

#pragma var_order(i, lineIndex, currChar, charIndex, fileBase, lineCharBuffer)
ZunResult MusicRoom::AddedCallback(MusicRoom *musicRoom)
{
    u32 charIndex;
    char *currChar;
    char *fileBase;
    i32 i;
    char lineCharBuffer[64];
    i32 lineIndex;

    if (g_AnmManager->LoadSurface(0, "data/result/music.jpg") != ZUN_SUCCESS)
    {
        return ZUN_ERROR;
    }

    if (g_AnmManager->LoadAnm(ANM_FILE_MUSIC00, "data/music00.anm", ANM_OFFSET_MUSIC00) != ZUN_SUCCESS)
    {
        return ZUN_ERROR;
    }

    if (g_AnmManager->LoadAnm(ANM_FILE_MUSIC01, "data/music01.anm", ANM_OFFSET_MUSIC01) != ZUN_SUCCESS)
    {
        return ZUN_ERROR;
    }

    if (g_AnmManager->LoadAnm(ANM_FILE_MUSIC02, "data/music02.anm", ANM_OFFSET_MUSIC02) != ZUN_SUCCESS)
    {
        return ZUN_ERROR;
    }

    g_AnmManager->SetAndExecuteScriptIdx(musicRoom->mainVm, ANM_OFFSET_MUSIC00);
    musicRoom->unk_0x8 = 0;
    currChar = (char *)FileSystem::OpenPath("data/musiccmt.txt", 0);
    fileBase = currChar;

    if (currChar == NULL)
    {
        return ZUN_ERROR;
    }

    musicRoom->trackDescriptors = new TrackDescriptor[ARRAY_SIZE_SIGNED(musicRoom->titleSprites)]();

    i = -1;
    while (currChar - fileBase < (i32)g_LastFileSize)
    {
        if (*currChar == '@')
        {
            currChar++;
            i++;
            charIndex = 0;

            while (*currChar != '\n' && *currChar != '\r')
            {
                musicRoom->trackDescriptors[i].path[charIndex] = *currChar;
                currChar++;
                charIndex++;
                if (currChar - fileBase >= (i32)g_LastFileSize)
                {
                    goto finishMusiccmtRead;
                }
            }

            while (*currChar == '\n' || *currChar == '\r')
            {
                currChar++;
                if (currChar - fileBase >= (i32)g_LastFileSize)
                {
                    goto finishMusiccmtRead;
                }
            }

            charIndex = 0;
            while (*currChar != '\n' && *currChar != '\r')
            {
                musicRoom->trackDescriptors[i].title[charIndex] = *currChar;
                currChar++;
                charIndex++;
                if (currChar - fileBase >= (i32)g_LastFileSize)
                {
                    goto finishMusiccmtRead;
                }
            }

            // Dead code. Is it a bug? Was it an intentional quick and dirty change? Who knows?
            // Has the effect of offsetting the description text by a line
            while (*currChar == '\n' && *currChar == '\r')
            {
                currChar++;
                if (currChar - fileBase >= (i32)g_LastFileSize)
                {
                    goto finishMusiccmtRead;
                }
            }

            for (lineIndex = 0; lineIndex < 8; lineIndex++)
            {
                if (*currChar == '@')
                {
                    break;
                }

                memset(musicRoom->trackDescriptors[i].description[lineIndex], 0,
                       sizeof(musicRoom->trackDescriptors[i].description[lineIndex]));
                charIndex = 0;
                while (*currChar != '\n' && *currChar != '\r')
                {
                    musicRoom->trackDescriptors[i].description[lineIndex][charIndex] = *currChar;
                    currChar++;
                    charIndex++;
                    if (currChar - fileBase >= (i32)g_LastFileSize)
                    {
                        goto finishMusiccmtRead;
                    }
                }

                while (*currChar == '\n' || *currChar == '\r')
                {
                    currChar++;
                    if (currChar - fileBase >= (i32)g_LastFileSize)
                    {
                        goto finishMusiccmtRead;
                    }
                }
            }
        }
        else
        {
            currChar++;
        }
    }

finishMusiccmtRead:
    musicRoom->numDescriptors = i + 1;

    for (i = 0; i < musicRoom->numDescriptors; i++)
    {
        g_AnmManager->InitializeAndSetSprite(&musicRoom->titleSprites[i], ANM_OFFSET_MUSIC01 + i);
        AnmManager::DrawVmTextFmt(g_AnmManager, &musicRoom->titleSprites[i], COLOR_MUSIC_ROOM_SONG_TITLE_TEXT,
                                  COLOR_MUSIC_ROOM_SONG_TITLE_SHADOW, musicRoom->trackDescriptors[i].title);
        musicRoom->titleSprites[i].pos.x = 93.0f;
        musicRoom->titleSprites[i].pos.y = 104.0f + ((i + 1) * 18) - 20.0f;
        musicRoom->titleSprites[i].pos.z = 0.0f;
        musicRoom->titleSprites[i].flags.anchor = AnmVmAnchor_TopLeft;
    }

    for (i = 0; i < ARRAY_SIZE_SIGNED(musicRoom->descriptionSprites); i++)
    {
        g_AnmManager->InitializeAndSetSprite(&musicRoom->descriptionSprites[i], ANM_SCRIPT_TEXT_MUSIC_ROOM_DESC + i);
        memset(lineCharBuffer, 0, sizeof(lineCharBuffer));

        if (i % 2 == 0 || strlen(musicRoom->trackDescriptors[musicRoom->selectedSongIndex].description[i / 2]) > 32)
        {
            memcpy(lineCharBuffer, &musicRoom->trackDescriptors[0].description[i / 2][(i % 2) * 32], 32);
        }

        if (lineCharBuffer[0] != '\0')
        {
            musicRoom->descriptionSprites[i].flags.flag1 = 1;
            AnmManager::DrawVmTextFmt(g_AnmManager, &musicRoom->descriptionSprites[i], COLOR_MUSIC_ROOM_SONG_DESC_TEXT,
                                      COLOR_MUSIC_ROOM_SONG_DESC_SHADOW, lineCharBuffer);
        }
        else
        {
            musicRoom->descriptionSprites[i].flags.flag1 = 0;
        }

        musicRoom->descriptionSprites[i].pos.x = ((f32)(i % 2)) * 248.0f + 96.0f;
        musicRoom->descriptionSprites[i].pos.y = 320.0f + ((i / 2) << 4);
        musicRoom->descriptionSprites[i].pos.z = 0.0f;
        musicRoom->descriptionSprites[i].flags.anchor = AnmVmAnchor_TopLeft;
    }

    free(fileBase);

    return ZUN_SUCCESS;
}

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