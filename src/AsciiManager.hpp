#pragma once

#include <d3dx8math.h>

#include "AnmManager.hpp"
#include "Chain.hpp"
#include "StageMenu.hpp"
#include "ZunResult.hpp"
#include "ZunTimer.hpp"
#include "inttypes.hpp"

namespace th06
{
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
C_ASSERT(sizeof(AsciiManagerString) == 0x60);

struct AsciiManagerPopup
{
    char digits[8];
    D3DXVECTOR3 position;
    D3DCOLOR color;
    ZunTimer timer;
    u8 inUse;
    u8 characterCount;
};
C_ASSERT(sizeof(AsciiManagerPopup) == 0x28);

struct WeirdPadding
{
    WeirdPadding()
    {
        i32 pad11, pad12, pad13, pad14, pad15, pad16, pad17, pad18;
        i32 pad21, pad22, pad23, pad24, pad25, pad26, pad27, pad28;
        i32 pad31, pad32;
    }
    u32 unk;
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
    static void CutChain();

    static ChainCallbackResult OnUpdate(AsciiManager *s);
    static ChainCallbackResult OnDrawMenus(AsciiManager *s);
    static ChainCallbackResult OnDrawPopups(AsciiManager *s);
    static ZunResult AddedCallback(AsciiManager *s);
    static ZunResult DeletedCallback(AsciiManager *s);

    void InitializeVms();

    void DrawStrings();
    void DrawPopupsWithHwVertexProcessing();
    void DrawPopupsWithoutHwVertexProcessing();

    void AddString(D3DXVECTOR3 *position, char *text);
    void AddFormatText(D3DXVECTOR3 *position, const char *fmt, ...);
    void CreatePopup1(D3DXVECTOR3 *position, i32 value, D3DCOLOR color);
    void CreatePopup2(D3DXVECTOR3 *position, i32 value, D3DCOLOR color);

    void SetColor(ZunColor color)
    {
        this->color = color;
    }

    AnmVm vm0;
    AnmVm vm1;
    AsciiManagerString strings[256];
    i32 numStrings;
    D3DCOLOR color;
    D3DXVECTOR2 scale;
    // If true, we are drawing an element of the Gui class.
    u32 isGui;
    // If true, we are drawing the currently selected element of the MainMenu
    // class.
    ZunBool isSelected;
    i32 nextPopupIndex1;
    i32 nextPopupIndex2;
    // Seems unused
    WeirdPadding unk3;
    // Menu that shows up when the player presses the menu button while in-game.
    StageMenu gameMenu;
    // Menu that shows up when the player dies after losing their last life.
    StageMenu retryMenu;
    AsciiManagerPopup popups[515];
};
C_ASSERT(sizeof(AsciiManager) == 0xc1ac);
DIFFABLE_EXTERN(AsciiManager, g_AsciiManager);
}; // namespace th06
