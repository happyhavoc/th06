#include "TextHelper.hpp"
#include "GameErrorContext.hpp"
#include "GameWindow.hpp"
#include "Supervisor.hpp"
#include "i18n.hpp"

#include <SDL2/SDL_ttf.h>
#include <algorithm>
#include <cstring>
#include <iconv.h>

namespace th06
{

// DIFFABLE_STATIC_ARRAY_ASSIGN(FormatInfo, 7, g_FormatInfoArray) = {
//     {D3DFMT_X8R8G8B8, 32, 0x00000000, 0x00FF0000, 0x0000FF00, 0x000000FF},
//     {D3DFMT_A8R8G8B8, 32, 0xFF000000, 0x00FF0000, 0x0000FF00, 0x000000FF},
//     {D3DFMT_X1R5G5B5, 16, 0x00000000, 0x00007C00, 0x000003E0, 0x0000001F},
//     {D3DFMT_R5G6B5, 16, 0x00000000, 0x0000F800, 0x000007E0, 0x0000001F},
//     {D3DFMT_A1R5G5B5, 16, 0x0000F000, 0x00007C00, 0x000003E0, 0x0000001F},
//     {D3DFMT_A4R4G4B4, 16, 0x0000F000, 0x00000F00, 0x000000F0, 0x0000000F},
//     {(D3DFORMAT)-1, 0, 0, 0, 0, 0},
// };

DIFFABLE_STATIC(TTF_Font *, g_Font);
DIFFABLE_STATIC_ASSIGN(iconv_t, g_Iconv) = (iconv_t)-1;

TextHelper::TextHelper()
{
    //    this->format = (D3DFORMAT)-1;
    //    this->width = 0;
    //    this->height = 0;
    //    this->hdc = 0;
    //    this->gdiObj2 = 0;
    //    this->gdiObj = 0;
    //    this->buffer = NULL;
}

TextHelper::~TextHelper()
{
    TTF_Quit();
    this->ReleaseBuffer();
}

bool TextHelper::ReleaseBuffer()
{
    //    if (this->hdc)
    //    {
    //        SelectObject(this->hdc, this->gdiObj);
    //        DeleteDC(this->hdc);
    //        DeleteObject(this->gdiObj2);
    //        this->format = (D3DFORMAT)-1;
    //        this->width = 0;
    //        this->height = 0;
    //        this->hdc = 0;
    //        this->gdiObj2 = 0;
    //        this->gdiObj = 0;
    //        this->buffer = NULL;
    return true;
    //    }
    //    else
    //    {
    //        return false;
    //    }
}

#define TEXT_BUFFER_HEIGHT 64

// Extended to initialize all globals for text helper
ZunResult TextHelper::CreateTextBuffer()
{
    TTF_Init();

    // Primary font is MSゴシック, which is nonfree and has to be taken from a Windows install
    // Fallback is Noto Sans Regular (JP) which is redistributable
    if ((g_Font = TTF_OpenFont(TH_PRIMARY_FONT_FILENAME, 10), g_Font == NULL) &&
        (std::printf("%s\n", TTF_GetError()), g_Font = TTF_OpenFont(TH_FALLBACK_FONT_FILENAME, 10), g_Font == NULL))
    {
        std::printf("%s\n", TTF_GetError());

        GameErrorContext::Fatal(&g_GameErrorContext, TH_ERR_FONTS_NOT_FOUND);
        return ZUN_ERROR;
    }

    g_Iconv = iconv_open("UTF-8", "MS932");

    if (g_Iconv == (iconv_t)-1)
    {
        GameErrorContext::Fatal(&g_GameErrorContext, TH_ERR_ICONV_INIT_FAILED);
        return ZUN_ERROR;
    }

    g_TextBufferSurface =
        SDL_CreateRGBSurfaceWithFormat(0, GAME_WINDOW_WIDTH, TEXT_BUFFER_HEIGHT, 32, SDL_PIXELFORMAT_RGBA32);

    SDL_SetSurfaceBlendMode(g_TextBufferSurface, SDL_BLENDMODE_NONE);

    return ZUN_SUCCESS;
}

// bool TextHelper::AllocateBufferWithFallback(i32 width, i32 height, D3DFORMAT format)
// {
//     if (this->TryAllocateBuffer(width, height, format))
//     {
//         return true;
//     }
//
//     if (format == D3DFMT_A1R5G5B5 || format == D3DFMT_A4R4G4B4)
//     {
//         return this->TryAllocateBuffer(width, height, D3DFMT_A8R8G8B8);
//     }
//     if (format == D3DFMT_R5G6B5)
//     {
//         return this->TryAllocateBuffer(width, height, D3DFMT_X8R8G8B8);
//     }
//     return false;
// }
//
// struct THBITMAPINFO
// {
//     BITMAPINFOHEADER bmiHeader;
//     RGBQUAD bmiColors[17];
// };
//
// bool TextHelper::TryAllocateBuffer(i32 width, i32 height, D3DFORMAT format)
// {
//     HGDIOBJ originalBitmapObj;
//     u8 *bitmapData;
//     HBITMAP bitmapObj;
//     FormatInfo *formatInfo;
//     THBITMAPINFO bitmapInfo;
//     u32 padding;
//     HDC deviceContext;
//     i32 imageWidthInBytes;
//
//     this->ReleaseBuffer();
//     memset(&bitmapInfo, 0, sizeof(THBITMAPINFO));
//     formatInfo = this->GetFormatInfo(format);
//     if (formatInfo == NULL)
//     {
//         return false;
//     }
//     imageWidthInBytes = ((((width * formatInfo->bitCount) / 8) + 3) / 4) * 4;
//     bitmapInfo.bmiHeader.biSize = sizeof(THBITMAPINFO);
//     bitmapInfo.bmiHeader.biWidth = width;
//     bitmapInfo.bmiHeader.biHeight = -(height + 1);
//     bitmapInfo.bmiHeader.biPlanes = 1;
//     bitmapInfo.bmiHeader.biBitCount = formatInfo->bitCount;
//     bitmapInfo.bmiHeader.biSizeImage = height * imageWidthInBytes;
//     if (format != D3DFMT_X1R5G5B5 && format != D3DFMT_X8R8G8B8)
//     {
//         bitmapInfo.bmiHeader.biCompression = 3;
//         ((u32 *)bitmapInfo.bmiColors)[0] = formatInfo->redMask;
//         ((u32 *)bitmapInfo.bmiColors)[1] = formatInfo->greenMask;
//         ((u32 *)bitmapInfo.bmiColors)[2] = formatInfo->blueMask;
//         ((u32 *)bitmapInfo.bmiColors)[3] = formatInfo->alphaMask;
//     }
//     bitmapObj = CreateDIBSection(NULL, (BITMAPINFO *)&bitmapInfo, 0, (void **)&bitmapData, NULL, 0);
//     if (bitmapObj == NULL)
//     {
//         return false;
//     }
//     memset(bitmapData, 0, bitmapInfo.bmiHeader.biSizeImage);
//     deviceContext = CreateCompatibleDC(NULL);
//     originalBitmapObj = SelectObject(deviceContext, bitmapObj);
//     this->hdc = deviceContext;
//     this->gdiObj2 = bitmapObj;
//     this->buffer = bitmapData;
//     this->imageSizeInBytes = bitmapInfo.bmiHeader.biSizeImage;
//     this->gdiObj = originalBitmapObj;
//     this->width = width;
//     this->height = height;
//     this->format = format;
//     this->imageWidthInBytes = imageWidthInBytes;
//     return true;
// }
//
// FormatInfo *TextHelper::GetFormatInfo(D3DFORMAT format)
// {
//     i32 local_8;
//
//     for (local_8 = 0; g_FormatInfoArray[local_8].format != -1 && g_FormatInfoArray[local_8].format != format;
//     local_8++)
//     {
//     }
//     if (format == -1)
//     {
//         return NULL;
//     }
//     return &g_FormatInfoArray[local_8];
// }
//
// struct A1R5G5B5
// {
//     u16 blue : 5;
//     u16 green : 5;
//     u16 red : 5;
//     u16 alpha : 1;
// };
//

bool TextHelper::InvertAlpha(i32 x, i32 y, i32 spriteWidth, i32 fontHeight)
{
    u8 *bufferCursor;
    i32 gradientArea;
    i32 i = 0;

    gradientArea = spriteWidth * fontHeight;

    SDL_LockSurface(g_TextBufferSurface);

    // In D3D EoSD this function mostly inverts the alpha, but on A1R5G5B5 surfaces specifically it also
    //   creates a gradient. D3D EoSD will always attempt to create an A1R5G5B5 surface for the text buffer,
    //   will only attempt use other formats as a fallback, and in those cases the text will be bugged anyway. 
    //   As part of the port from GDI to SDL_ttf, we've converted the text buffer surface to always be RGBA32
    //   and no longer need the alpha inversion, but we still want that gradient to be applied

    for (bufferCursor = (u8 *)g_TextBufferSurface->pixels; i < gradientArea; i++, bufferCursor += 4)
    {
        if (bufferCursor[3]) // A
        {
            bufferCursor[0] = bufferCursor[0] - bufferCursor[0] * i / gradientArea / 2; // R
            bufferCursor[1] = bufferCursor[1] - bufferCursor[1] * i / gradientArea / 2; // G
            bufferCursor[2] = bufferCursor[2] - bufferCursor[2] * i / gradientArea / 4; // B
        }
    }

    SDL_UnlockSurface(g_TextBufferSurface);

    return true;
}
//
// bool TextHelper::CopyTextToSurface(SDL_Surface *outSurface)
// {
//     D3DLOCKED_RECT lockedRect;
//     u8 *srcBuf;
//     D3DSURFACE_DESC outSurfaceDesc;
//     size_t srcWidthBytes;
//     int curHeight;
//     RECT rectToLock;
//     int dstWidthBytes;
//     u8 *dstBuf;
//     i32 width;
//     i32 height;
//     D3DFORMAT thisFormat;
//     i32 thisHeight;
//
//     if (!(bool)(u32)(this->gdiObj2 != NULL))
//     {
//         return false;
//     }
//     outSurface->GetDesc(&outSurfaceDesc);
//     rectToLock.left = 0;
//     rectToLock.top = 0;
//     rectToLock.right = width = this->width;
//     rectToLock.bottom = height = this->height;
//     if (outSurface->LockRect(&lockedRect, &rectToLock, 0))
//     {
//         return false;
//     }
//     dstWidthBytes = lockedRect.Pitch;
//     srcWidthBytes = this->imageWidthInBytes;
//     srcBuf = this->buffer;
//     dstBuf = (u8 *)lockedRect.pBits;
//     thisFormat = this->format;
//     if (outSurfaceDesc.Format == thisFormat)
//     {
//         for (curHeight = 0; thisHeight = this->height, curHeight < thisHeight; curHeight++)
//         {
//             memcpy(dstBuf, srcBuf, srcWidthBytes);
//             srcBuf += srcWidthBytes;
//             dstBuf += dstWidthBytes;
//         }
//     }
//     outSurface->UnlockRect();
//     return true;
// }
//

// Text strings in asset files are encoded using Shift_JIS. This allows RenderTextToTexture to handle both UTF-8 and
// Shift_JIS. This also does not check for overlong encoding, but that shouldn't matter
bool isUTF8Encoded(char *string)
{
#define UTF8_1BYTE_MASK 0x80
#define UTF8_2BYTE_MASK 0xE0
#define UTF8_3BYTE_MASK 0xF0
#define UTF8_4BYTE_MASK 0xF8

#define UTF8_2NDBYTE_MASK 0xC0

// 0xxx xxxx
#define UTF8_1BYTE_PREFIX 0x00
// 110x xxxx
#define UTF8_2BYTE_PREFIX 0xC0
// 1110 xxxx
#define UTF8_3BYTE_PREFIX 0xE0
// 1111 0xxx
#define UTF8_4BYTE_PREFIX 0xF0

// 10xx xxxx
#define UTF8_2NDBYTE_PREFIX 0x80

    bool isMultiByteParse = false;
    int codepointLen = 0;

    while (*string != '\0')
    {
        unsigned char c = *(unsigned char *)string;

        if (!isMultiByteParse)
        {
            if ((c & UTF8_1BYTE_MASK) != UTF8_1BYTE_PREFIX)
            {
                isMultiByteParse = true;

                if ((c & UTF8_2BYTE_MASK) == UTF8_2BYTE_PREFIX)
                    codepointLen = 1;
                else if ((c & UTF8_3BYTE_MASK) == UTF8_3BYTE_PREFIX)
                    codepointLen = 2;
                else if ((c & UTF8_4BYTE_MASK) == UTF8_4BYTE_PREFIX)
                    codepointLen = 3;
                else
                    return false;
            }
        }
        else
        {
            if ((c & UTF8_2NDBYTE_MASK) != UTF8_2NDBYTE_PREFIX)
                return false;

            if (--codepointLen == 0)
                isMultiByteParse = false;
        }

        string++;
    }

    return true;

#undef UTF8_1BYTE_MASK
#undef UTF8_2BYTE_MASK
#undef UTF8_3BYTE_MASK
#undef UTF8_4BYTE_MASK

#undef UTF8_2NDBYTE_MASK

#undef UTF8_1BYTE_PREFIX
#undef UTF8_2BYTE_PREFIX
#undef UTF8_3BYTE_PREFIX
#undef UTF8_4BYTE_PREFIX

#undef UTF8_2NDBYTE_PREFIX
}

void SurfaceOverwriteBlend(SDL_Surface *srcSurface, SDL_Surface *dstSurface, u32 x)
{
    // Source surface is A8R8G8B8
    // Dest surface is RGBA32
    // We want to overwrite dest unless source has alpha 0

    SDL_LockSurface(srcSurface);
    SDL_LockSurface(dstSurface);

    u32 *srcData = (u32 *)srcSurface->pixels;
    u8 *dstData = (u8 *)dstSurface->pixels;

    for (int i = 0; i < srcSurface->h; i++)
    {
        for (int j = 0; j < srcSurface->w; j++)
        {
            if ((srcData[j] & 0xFF00'0000) != 0)
            {
                dstData[i * dstSurface->pitch + (x + j) * 4] = (srcData[j] >> 16) & 0xFF;
                dstData[i * dstSurface->pitch + (x + j) * 4 + 1] = (srcData[j] >> 8) & 0xFF;
                dstData[i * dstSurface->pitch + (x + j) * 4 + 2] = srcData[j] & 0xFF;
                dstData[i * dstSurface->pitch + (x + j) * 4 + 3] = (srcData[j] >> 24) & 0xFF;
            }
        }

        srcData += srcSurface->pitch / 4;
    }

    SDL_UnlockSurface(dstSurface);
    SDL_UnlockSurface(srcSurface);
}

void TextHelper::RenderTextToTexture(i32 xPos, i32 yPos, i32 spriteWidth, i32 spriteHeight, i32 fontHeight,
                                     i32 fontWidth, ZunColor textColor, ZunColor shadowColor, char *string,
                                     TextureData *outTexture)
{
    SDL_Rect finalCopySrc;
    SDL_Rect finalCopyDst;
    SDL_Rect shadowRect;
    SDL_Rect textRect;

    //    HGDIOBJ h;
    //    LPDIRECT3DSURFACE8 destSurface;
    //    RECT destRect;
    //    RECT srcRect;
    //    D3DSURFACE_DESC textSurfaceDesc;
    //    HFONT font;
    //    HDC hdc;

    char convertedText[1024];

    if (!isUTF8Encoded(string))
    {
        // Standard doesn't specify what happens with the length fields during state reset, so give a value to be safe
        size_t stringBytes = 1024;
        size_t outBytes = 1024;

        iconv(g_Iconv, NULL, &stringBytes, NULL, &outBytes); // Resets iconv state

        stringBytes = std::strlen(string);
        outBytes = sizeof(convertedText) - 1;
        char *convEnd = convertedText;

        if (iconv(g_Iconv, (char **)&string, &stringBytes, &convEnd, &outBytes) == (size_t)-1)
        {
            // Just don't render text in case of error
            return;
        }

        *convEnd = '\0';
    }
    else
    {
        std::strcpy(convertedText, string);
    }

    TTF_SetFontSize(g_Font, fontHeight * 2);

    //    font = CreateFontA(fontHeight * 2, 0, 0, 0, FW_BOLD, false, false, false, SHIFTJIS_CHARSET,
    //    OUT_DEFAULT_PRECIS,
    //                       CLIP_DEFAULT_PRECIS, ANTIALIASED_QUALITY, FF_ROMAN | FIXED_PITCH, TH_FONT_NAME);

    //    TextHelper textHelper;
    //    g_TextBufferSurface->GetDesc(&textSurfaceDesc);
    //    textHelper.AllocateBufferWithFallback(textSurfaceDesc.Width, textSurfaceDesc.Height, textSurfaceDesc.Format);
    //    hdc = textHelper.hdc;
    //    h = SelectObject(hdc, font);
    //    textHelper.InvertAlpha(0, 0, spriteWidth * 2, fontHeight * 2 + 6);
    //    SetBkMode(hdc, TRANSPARENT);

    finalCopySrc.x = 0;
    finalCopySrc.y = 0;
    finalCopySrc.w = spriteWidth * 2 - 2;
    finalCopySrc.h = fontHeight * 2 - 2;

    SDL_FillRect(g_TextBufferSurface, &finalCopySrc, 0);

    SDL_Surface *shadowText = NULL;

    if (shadowColor != COLOR_WHITE)
    {
        // Render shadow.
        SDL_Color sdlShadowColor;
        sdlShadowColor.a = 0xFF;
        sdlShadowColor.b = (shadowColor >> 16) & 0xFF;
        sdlShadowColor.g = (shadowColor >> 8) & 0xFF;
        sdlShadowColor.r = shadowColor & 0xFF;

        shadowText = TTF_RenderUTF8_Blended(g_Font, convertedText, sdlShadowColor);
        // SetTextColor(hdc, shadowColor);
        // TextOutA(hdc, xPos * 2 + 3, 2, string, strlen(string));

        if (shadowText != NULL)
        {
            shadowRect.x = xPos * 2 + 3;
            shadowRect.y = 2;
            shadowRect.w = shadowText->w;
            shadowRect.h = shadowText->h;

            SDL_SetSurfaceBlendMode(shadowText, SDL_BLENDMODE_NONE);
            SDL_BlitSurface(shadowText, NULL, g_TextBufferSurface, &shadowRect);

            SDL_FreeSurface(shadowText);
        }
    }

    SDL_Color sdlTextColor;
    sdlTextColor.a = 0xFF;
    sdlTextColor.b = (textColor >> 16) & 0xFF;
    sdlTextColor.g = (textColor >> 8) & 0xFF;
    sdlTextColor.r = textColor & 0xFF;

    SDL_Surface *regularText = TTF_RenderUTF8_Blended(g_Font, convertedText, sdlTextColor);

    if (regularText != NULL)
    {
        textRect.x = xPos * 2;
        textRect.y = 0;
        textRect.w = regularText->w;
        textRect.h = regularText->h;

        SurfaceOverwriteBlend(regularText, g_TextBufferSurface, xPos * 2);

        //        SDL_SetSurfaceBlendMode(regularText, SDL_BLENDMODE_BLEND);
        //        SDL_BlitSurface(regularText, NULL, g_TextBufferSurface, &textRect);

        SDL_FreeSurface(regularText);
    }

    if (!outTexture->textureData)
    {
        outTexture->textureData = (u8 *)malloc(outTexture->width * outTexture->height * 4);
        memset(outTexture->textureData, 0, outTexture->width * outTexture->height * 4);
    }

//    outTexture->format = ;
    SDL_Surface *textureSurface = SDL_CreateRGBSurfaceWithFormatFrom(
        outTexture->textureData, outTexture->width, outTexture->height, SDL_BITSPERPIXEL(SDL_PIXELFORMAT_RGBA32),
        outTexture->width * SDL_BYTESPERPIXEL(SDL_PIXELFORMAT_RGBA32), SDL_PIXELFORMAT_RGBA32);

    // Render main text.
    // SetTextColor(hdc, textColor);
    // TextOutA(hdc, xPos * 2, 0, string, strlen(string));

    // SelectObject(hdc, h);
    InvertAlpha(0, 0, spriteWidth * 2, fontHeight * 2 + 6);
    // textHelper.CopyTextToSurface(g_TextBufferSurface);
    // SelectObject(hdc, h);
    // DeleteObject(font);

    finalCopyDst.x = 0;
    finalCopyDst.y = yPos;
    finalCopyDst.w = spriteWidth;
    finalCopyDst.h = 16;

    // outTexture->GetSurfaceLevel(0, &destSurface);
    // D3DXLoadSurfaceFromSurface(destSurface, NULL, &destRect, g_TextBufferSurface, NULL, &srcRect, 4, 0);

    if (SDL_SoftStretchLinear(g_TextBufferSurface, &finalCopySrc, textureSurface, &finalCopyDst) < 0)
    {
        SDL_Log("SDL_BlitScaled failed! Error: %s", SDL_GetError());
    }

    g_glFuncTable.glBindTexture(GL_TEXTURE_2D, outTexture->handle);

    g_glFuncTable.glTexSubImage2D(GL_TEXTURE_2D, 0, 0, 0, outTexture->width, outTexture->height, GL_RGBA,
                                  GL_UNSIGNED_BYTE, outTexture->textureData);

    g_glFuncTable.glBindTexture(GL_TEXTURE_2D, 0);

    SDL_FreeSurface(textureSurface);

    return;
}

// Extended to free all globals for text helper
void th06::TextHelper::ReleaseTextBuffer()
{
    if (g_Font != NULL)
    {
        TTF_CloseFont(g_Font);
        g_Font = NULL;
    }

    if (g_Iconv != (iconv_t)-1)
    {
        iconv_close(g_Iconv);
        g_Iconv = (iconv_t)-1;
    }

    if (g_TextBufferSurface != NULL)
    {
        SDL_FreeSurface(g_TextBufferSurface);
        g_TextBufferSurface = NULL;
    }

    return;
}

}; // namespace th06
