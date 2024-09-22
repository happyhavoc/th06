#pragma once

#include "ZunColor.hpp"
#include "inttypes.hpp"

#include <d3d8.h>

namespace th06
{
struct TextHelper
{
    static void CreateTextBuffer();
    static void RenderTextToTexture(i32 xPos, i32 yPos, i32 spriteWidth, i32 spriteHeight, i32 fontHeight,
                                    i32 fontWidth, ZunColor textColor, ZunColor shadowColor, char *string,
                                    IDirect3DTexture8 *outTexture);
};
}; // namespace th06
