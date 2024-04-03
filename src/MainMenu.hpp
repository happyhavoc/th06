#pragma once

#include <D3D8.h>

#include "AnmVm.hpp"
#include "Chain.hpp"
#include "ReplayData.hpp"
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
    ZunResult DrawStartMenu();
    static i32 MoveCursor(MainMenu *menu, i32 menu_length);
    static void DrawMenuItem(AnmVm *vm, i32 itemNumber, i32 cursor, D3DCOLOR activeItemColor,
                             D3DCOLOR inactiveItemColor, i32 spriteIdx /* I think*/);

    i32 ReplayHandling();
    static ZunResult LoadReplayMenu(MainMenu *menu);

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
    i32 unk_81fc;
    D3DCOLOR maybeMenuTextColor;
    D3DCOLOR color2;
    D3DCOLOR color1;
    u32 unk_820c;
    u32 isActive;
    u32 wasActive;
    i8 padding2[4];
    i16 controlMapping[9];
    i8 padding3[2];
    u8 colorMode16bit;
    u8 windowed;
    u8 frameskipConfig;
    i8 padding4;
    ChainElem *chainCalc;
    ChainElem *chainDraw;
    char replayFilePaths[60][512];
    char replayFileName[60][8];
    ReplayData replayFileData[60];
    ReplayData *currentReplay;
    i32 *unk_10ee0;
    f32 *unk_10ee4;
    i8 padding5[64];
    u32 unk_10f28;
    u32 unk_10f2c;
    u32 time_related;
};
C_ASSERT(sizeof(MainMenu) == 0x10f34);
