#include "ScreenEffect.hpp"
#include "GameWindow.hpp"
#include "Supervisor.hpp"

namespace th06
{

void Clear(D3DCOLOR color)
{
    g_Supervisor.d3dDevice->Clear(0, NULL, D3DCLEAR_TARGET | D3DCLEAR_ZBUFFER, color, 1.0, 0);
    if (g_Supervisor.d3dDevice->Present(NULL, NULL, NULL, NULL) < 0)
    {
        g_Supervisor.d3dDevice->Reset(&g_Supervisor.presentParameters);
    }
    g_Supervisor.d3dDevice->Clear(0, NULL, D3DCLEAR_TARGET | D3DCLEAR_ZBUFFER, color, 1.0, 0);
    if (g_Supervisor.d3dDevice->Present(NULL, NULL, NULL, NULL) < 0)
    {
        g_Supervisor.d3dDevice->Reset(&g_Supervisor.presentParameters);
    }
    return;
}

// Why is this not in GameWindow.cpp? Don't ask me...
void SetViewport(D3DCOLOR color)
{
    g_Supervisor.viewport.X = 0;
    g_Supervisor.viewport.Y = 0;
    g_Supervisor.viewport.Width = GAME_WINDOW_WIDTH;
    g_Supervisor.viewport.Height = GAME_WINDOW_HEIGHT;
    g_Supervisor.viewport.MinZ = 0.0;
    g_Supervisor.viewport.MaxZ = 1.0;
    g_Supervisor.d3dDevice->SetViewport(&g_Supervisor.viewport);
    Clear(color);
}
}; // namespace th06
