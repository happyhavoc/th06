#pragma once

#include <D3D8.h>

#include "AnmVm.hpp"
#include "Chain.hpp"
#include "ZunResult.hpp"
#include "inttypes.hpp"

enum GameState
{
    STATE_STARTUP,
    STATE_PRE_INPUT,
    STATE_MAIN_MENU,
    STATE_OPTIONS,
    STATE_QUIT,
    STATE_KEYCONFIG,
    STATE_DIFFICULTY_LOAD,
    STATE_DIFFICULTY_SELECT,
    STATE_CHARACTER_LOAD,
    STATE_CHARACTER_SELECT,
    STATE_SCORE,
    STATE_SHOT_SELECT,
    STATE_REPLAY_LOAD,
    STATE_REPLAY_ANIM,
    STATE_REPLAY_UNLOAD,
    STATE_REPLAY_SELECT,
    STATE_MUSIC_ROOM,
};

struct MainMenu
{
    ZunResult BeginStartup();
    static ZunResult LoadTitleAnm(MainMenu *menu);
    static ZunResult RegisterChain(u32 is_demo);

    AnmVm vm[122];
    i32 cursor;
    i8 padding[0x40];
    u32 unk_81e4;
    i32 chosenReplay;
    i32 replayFilesNum;
    GameState gameState;
    i32 stateTimer;
    i32 idleFrames;
    f32 unk_81fc;
    D3DCOLOR maybeMenuTextColor;
    D3DCOLOR color2;
    D3DCOLOR color1;
    u32 unk_820c;
    u32 isActive;
    u32 wasActive;
    i8 padding2[4];
    i16 controlMapping[9];
    i8 padding3[6];
    ChainElem *chainCalc;
    ChainElem *chainDraw;
    char replayFilePaths[60][512];
    char replayFileName[60][8];
    i8 replayFileData[60][0x50];
    i8 *currentReplay;
    i32 *unk_10ee0;
    f32 *unk_10ee4;
    i8 padding4[64];
    u32 unk_10f28;
    u32 unk_10f2c;
    u32 time_related;
};
C_ASSERT(sizeof(MainMenu) == 0x10f34);
