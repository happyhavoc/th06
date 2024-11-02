#include "ScreenEffect.hpp"
#include "AnmManager.hpp"
#include "GameWindow.hpp"
#include "Supervisor.hpp"

namespace th06
{

void ScreenEffect::Clear(D3DCOLOR color)
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
void ScreenEffect::SetViewport(D3DCOLOR color)
{
    g_Supervisor.viewport.X = 0;
    g_Supervisor.viewport.Y = 0;
    g_Supervisor.viewport.Width = GAME_WINDOW_WIDTH;
    g_Supervisor.viewport.Height = GAME_WINDOW_HEIGHT;
    g_Supervisor.viewport.MinZ = 0.0;
    g_Supervisor.viewport.MaxZ = 1.0;
    g_Supervisor.d3dDevice->SetViewport(&g_Supervisor.viewport);
    ScreenEffect::Clear(color);
}

ChainCallbackResult ScreenEffect::CalcFadeIn(ScreenEffect *effect)
{
    if (effect->effectLength != 0)
    {
        effect->fadeAlpha = (255.0f - ((effect->timer.AsFramesFloat() * 255.0f)) / effect->effectLength);
        if (effect->fadeAlpha < 0)
        {
            effect->fadeAlpha = 0;
        }
    }

    if (effect->timer >= effect->effectLength)
    {
        return CHAIN_CALLBACK_RESULT_CONTINUE_AND_REMOVE_JOB;
    }

    effect->timer.Tick();
    return CHAIN_CALLBACK_RESULT_CONTINUE;
}

void ScreenEffect::DrawSquare(ZunRect *rect, D3DCOLOR rectColor)
{
    VertexDiffuseXyzrwh vertices[4];

    // In the original code, VertexDiffuseXyzrwh almost certainly is a vec3 with a trailing w, which would make these simple vec3 assigns
    memcpy(&vertices[0].position, &D3DXVECTOR3(rect->left, rect->top, 0.0f), sizeof(D3DXVECTOR3));
    memcpy(&vertices[1].position, &D3DXVECTOR3(rect->right, rect->top, 0.0f), sizeof(D3DXVECTOR3));
    memcpy(&vertices[2].position, &D3DXVECTOR3(rect->left, rect->bottom, 0.0f), sizeof(D3DXVECTOR3));
    memcpy(&vertices[3].position, &D3DXVECTOR3(rect->right, rect->bottom, 0.0f), sizeof(D3DXVECTOR3));
    vertices[0].position.w = vertices[1].position.w = vertices[2].position.w = vertices[3].position.w = 1.00f;
    vertices[0].diffuse = vertices[1].diffuse = vertices[2].diffuse = vertices[3].diffuse = rectColor;

    if (((g_Supervisor.cfg.opts >> GCOS_NO_COLOR_COMP) & 0x01) == 0)
    {
        g_Supervisor.d3dDevice->SetTextureStageState(0, D3DTSS_ALPHAOP, D3DTOP_SELECTARG1);
        g_Supervisor.d3dDevice->SetTextureStageState(0, D3DTSS_COLOROP, D3DTOP_SELECTARG1);
    }
    g_Supervisor.d3dDevice->SetTextureStageState(0, D3DTSS_ALPHAARG1, D3DTA_DIFFUSE);
    g_Supervisor.d3dDevice->SetTextureStageState(0, D3DTSS_COLORARG1, D3DTA_DIFFUSE);
    if (((g_Supervisor.cfg.opts >> GCOS_TURN_OFF_DEPTH_TEST) & 0x01) == 0)
    {
        g_Supervisor.d3dDevice->SetRenderState(D3DRS_ZFUNC, D3DCMP_ALWAYS);
        g_Supervisor.d3dDevice->SetRenderState(D3DRS_ZWRITEENABLE, FALSE);
    }
    
    g_Supervisor.d3dDevice->SetRenderState(D3DRS_DESTBLEND, D3DBLEND_INVSRCALPHA);
    g_Supervisor.d3dDevice->SetVertexShader(D3DFVF_DIFFUSE | D3DFVF_XYZRHW);
    g_Supervisor.d3dDevice->DrawPrimitiveUP(D3DPT_TRIANGLESTRIP, 2, vertices, sizeof(*vertices));
    g_AnmManager->SetCurrentVertexShader(0xff);
    g_AnmManager->SetCurrentSprite(NULL);
    g_AnmManager->SetCurrentTexture(NULL);
    g_AnmManager->SetCurrentColorOp(0xff);
    g_AnmManager->SetCurrentBlendMode(0xff);
    g_AnmManager->SetCurrentZWriteDisable(0xff);

    if (((g_Supervisor.cfg.opts >> GCOS_NO_COLOR_COMP) & 0x01) == 0)
    {
        g_Supervisor.d3dDevice->SetTextureStageState(0, D3DTSS_ALPHAOP, D3DTOP_MODULATE);
        g_Supervisor.d3dDevice->SetTextureStageState(0, D3DTSS_COLOROP, D3DTOP_MODULATE);
    }
    g_Supervisor.d3dDevice->SetTextureStageState(0, D3DTSS_ALPHAARG1, D3DTA_TEXTURE);
    g_Supervisor.d3dDevice->SetTextureStageState(0, D3DTSS_COLORARG1, D3DTA_TEXTURE);
    g_Supervisor.d3dDevice->SetRenderState(D3DRS_ZFUNC, D3DCMP_LESSEQUAL);
}
}; // namespace th06
