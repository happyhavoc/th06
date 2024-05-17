#pragma once

#include "inttypes.hpp"

/* COLORS */
#define COLOR_BLACK 0xff000000
#define COLOR_WHITE 0xffffffff
#define COLOR_RED 0xffff0000
#define COLOR_PINK 0xffffe0e0

#define COLOR_MENU_ACTIVE_BACKGROUND 0x40000000
// TODO: find a better name for this color
#define COLOR_START_MENU_ITEM_INACTIVE 0x80300000

#define COLOR_MENU_ITEM_HIGHLIGHT 0x80202050
#define COLOR_MENU_ITEM_DEFAULT 0x800000ff

// Note: Little endian!
union ZunColor {
    u32 color;
    u8 bytes[4];
    struct
    {
        u8 blue;
        u8 green;
        u8 red;
        u8 alpha;
    };
};
