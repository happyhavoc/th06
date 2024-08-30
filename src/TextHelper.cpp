#include "TextHelper.hpp"
#include "GameWindow.hpp"
#include "Supervisor.hpp"

#define TEXT_BUFFER_HEIGHT 64
#pragma optimize("s", on)
void TextHelper::CreateTextBuffer()
{
    g_Supervisor.d3dDevice->CreateImageSurface(GAME_WINDOW_WIDTH, TEXT_BUFFER_HEIGHT, D3DFMT_A1R5G5B5,
                                               &g_TextBufferSurface);
}
#pragma optimize("", on)
