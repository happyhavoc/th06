#pragma once

#include <d3dx8math.h>

#include "AnmManager.hpp"
#include "Chain.hpp"
#include "ZunResult.hpp"
#include "inttypes.hpp"

struct AsciiManagerString
{
    char text[64];
    D3DXVECTOR3 position;
    D3DCOLOR color;
    D3DXVECTOR2 scale;
    // If true, we are drawing the currently selected element of the MainMenu
    // class.
    u32 isSelected;
    // If true, we are drawing an element of the Gui class.
    u32 isGui;
};

struct StageMenu
{
    StageMenu();

    // Current state of this menu.
    u32 curState;
    // Number of frames since last state change. Used to delay certain actions
    // until an animation is finished.
    u32 numFrames;
    AnmVm vms0[6];
    AnmVm vm1;
};

struct AsciiManagerPopup
{
    char digits[8];
    D3DXVECTOR3 position;
    D3DCOLOR color;
    AnmTimer timer;
    u8 inUse;
    u8 characterCount;
};

// The AsciiManager is responsible for drawing various textual elements on the
// screen:
//
// - The FPS counter
// - The in-game menus
// - Various text elements such as the "Stage clear" prompt.
struct AsciiManager
{
    AsciiManager();

    static ZunResult RegisterChain();

    static ChainCallbackResult OnUpdate(AsciiManager *s);
    static ChainCallbackResult OnDrawLowPrio(AsciiManager *s);
    static ChainCallbackResult OnDrawHighPrio(AsciiManager *s);
    static ZunResult AddedCallback(AsciiManager *s);
    static void DeletedCallback(AsciiManager *s);

    void InitializeVms();

    AnmVm vm0;
    AnmVm vm1;
    AsciiManagerString strings[256];
    u32 numStrings;
    D3DCOLOR color;
    D3DXVECTOR2 scale;
    // If true, we are drawing an element of the Gui class.
    u32 isGui;
    // If true, we are drawing the currently selected element of the MainMenu
    // class.
    u32 isSelected;
    u32 nextPopupIndex1;
    u32 nextPopupIndex2;
    // Seems unused
    u32 unk3;
    // Menu that shows up when the player presses the menu button while in-game.
    StageMenu gameMenu;
    // Menu that shows up when the player dies after losing their last life.
    StageMenu retryMenu;
    AsciiManagerPopup popups[515];
};
