#include "TextHelper.hpp"
#include "GameWindow.hpp"
#include "Supervisor.hpp"
#include "i18n.hpp"

namespace th06
{

#define TEXT_BUFFER_HEIGHT 64
#pragma optimize("s", on)
void TextHelper::CreateTextBuffer()
{
    g_Supervisor.d3dDevice->CreateImageSurface(GAME_WINDOW_WIDTH, TEXT_BUFFER_HEIGHT, D3DFMT_A1R5G5B5,
                                               &g_TextBufferSurface);
}
#pragma optimize("", on)

#pragma optimize("s", on)
#pragma function(strlen)
#pragma var_order(hdc, font, textSurfaceDesc, h, textHelper, hdc, srcRect, destRect, destSurface)
void TextHelper::RenderTextToTexture(i32 xPos, i32 yPos, i32 spriteWidth, i32 spriteHeight, i32 fontHeight,
                                     i32 fontWidth, ZunColor textColor, ZunColor shadowColor, char *string,
                                     IDirect3DTexture8 *outTexture)
{
    HGDIOBJ h;
    LPDIRECT3DSURFACE8 destSurface;
    RECT destRect;
    RECT srcRect;
    D3DSURFACE_DESC textSurfaceDesc;
    HFONT font;
    HDC hdc;

    font = CreateFontA(fontHeight * 2, 0, 0, 0, FW_BOLD, false, false, false, SHIFTJIS_CHARSET, OUT_DEFAULT_PRECIS,
                       CLIP_DEFAULT_PRECIS, ANTIALIASED_QUALITY, FF_ROMAN | FIXED_PITCH, TH_FONT_NAME);
    TextHelper textHelper;
    g_TextBufferSurface->GetDesc(&textSurfaceDesc);
    textHelper.AllocateBufferWithFallback(textSurfaceDesc.Width, textSurfaceDesc.Height, textSurfaceDesc.Format);
    hdc = textHelper.hdc;
    h = SelectObject(hdc, font);
    textHelper.InvertAlpha(0, 0, spriteWidth * 2, fontHeight * 2 + 6);
    SetBkMode(hdc, TRANSPARENT);

    if (shadowColor != COLOR_WHITE)
    {
        // Render shadow.
        SetTextColor(hdc, shadowColor);
        TextOutA(hdc, xPos * 2 + 3, 2, string, strlen(string));
    }
    // Render main text.
    SetTextColor(hdc, textColor);
    TextOutA(hdc, xPos * 2, 0, string, strlen(string));

    SelectObject(hdc, h);
    textHelper.InvertAlpha(0, 0, spriteWidth * 2, fontHeight * 2 + 6);
    textHelper.CopyTextToSurface(g_TextBufferSurface);
    SelectObject(hdc, h);
    DeleteObject(font);
    destRect.left = 0;
    destRect.top = yPos;
    destRect.right = spriteWidth;
    destRect.bottom = yPos + 16;
    srcRect.left = 0;
    srcRect.top = 0;
    srcRect.right = spriteWidth * 2 - 2;
    srcRect.bottom = fontHeight * 2 - 2;
    outTexture->GetSurfaceLevel(0, &destSurface);
    D3DXLoadSurfaceFromSurface(destSurface, NULL, &destRect, g_TextBufferSurface, NULL, &srcRect, 4, 0);
    if (destSurface != NULL)
    {
        destSurface->Release();
        destSurface = NULL;
    }
    return;
}
#pragma optimize("", on)
}; // namespace th06
