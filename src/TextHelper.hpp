#pragma once

#include "ZunColor.hpp"
#include "inttypes.hpp"

#include <d3d8.h>

namespace th06
{
struct FormatInfo
{
    D3DFORMAT format;
    i32 bitCount;
    u32 alphaMask;
    u32 redMask;
    u32 greenMask;
    u32 blueMask;
};
struct TextHelper
{
    static void CreateTextBuffer();
    static void RenderTextToTexture(i32 xPos, i32 yPos, i32 spriteWidth, i32 spriteHeight, i32 fontHeight,
                                    i32 fontWidth, ZunColor textColor, ZunColor shadowColor, char *string,
                                    IDirect3DTexture8 *outTexture);

    TextHelper();
    ~TextHelper();
    bool AllocateBufferWithFallback(i32 width, i32 height, D3DFORMAT format);
    bool ReleaseBuffer();
    bool InvertAlpha(i32 x, i32 y, i32 spriteWidth, i32 fontHeight);
    bool CopyTextToSurface(IDirect3DSurface8 *outSurface);

    D3DFORMAT format;
    i32 width;
    i32 height;
    u32 imageSizeInBytes;
    i32 imageWidthInBytes;
    HDC hdc;
    HGDIOBJ gdiObj;
    HGDIOBJ gdiObj2;
    u8 *buffer;
};
}; // namespace th06
