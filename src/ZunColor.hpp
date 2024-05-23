#pragma once

#include "inttypes.hpp"

/* COLORS */
#define COLOR_BLACK 0xff000000
#define COLOR_GREY 0xff808080
#define COLOR_WHITE 0xffffffff
#define COLOR_RED 0xffff0000
#define COLOR_PINK 0xffffe0e0

#define COLOR_RGB_MASK 0x00FFFFFF
#define COLOR_ALPHA_MASK 0xFF000000
#define COLOR_RGB(color) ((color) & COLOR_RGB_MASK)
#define COLOR_ALPHA(color) (((color) & COLOR_ALPHA_MASK) >> 24)
#define COLOR_SET_ALPHA(color, alpha) (((alpha) << 24) | COLOR_RGB(color))
#define COLOR_SET_ALPHA2(color, alpha) (COLOR_RGB(color) | (((alpha) & 0xff) << 24))
#define COLOR_COMBINE_ALPHA(color, alpha) (((alpha) & COLOR_ALPHA_MASK) | COLOR_RGB(color))

#define COLOR_MENU_ACTIVE_BACKGROUND 0x40000000
// TODO: find a better name for this color
#define COLOR_START_MENU_ITEM_INACTIVE 0x80300000

#define COLOR_MENU_ITEM_HIGHLIGHT 0x800000ff
#define COLOR_MENU_ITEM_DEFAULT 0x80202050

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
