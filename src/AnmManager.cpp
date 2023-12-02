#include "AnmManager.hpp"
#include "FileSystem.hpp"
#include "GameErrorContext.hpp"
#include "Supervisor.hpp"
#include "i18n.hpp"

AnmManager::AnmManager()
{
}
AnmManager::~AnmManager()
{
}

void AnmManager::SetupVertexBuffer()
{
    // TODO: stub
}

void AnmManager::ReleaseD3dSurfaces(void)
{
}

ZunResult AnmManager::LoadSurface(i32 surfaceIdx, char *path)
{
    if (this->surfaces[surfaceIdx] != NULL)
    {
        this->ReleaseSurface(surfaceIdx);
    }
    u8 *data = FileSystem::OpenPath(path, 0);
    if (data == NULL)
    {
        GameErrorContextFatal(&g_GameErrorContext, TH_ERR_CANNOT_BE_LOADED, path);
        return ZUN_ERROR;
    }

    LPDIRECT3DSURFACE8 surface;
    if (g_Supervisor.d3dDevice->CreateImageSurface(0x280, 0x400, g_Supervisor.presentParameters.BackBufferFormat,
                                                   &surface) != D3D_OK)
    {
        return ZUN_ERROR;
    }

    if (D3DXLoadSurfaceFromFileInMemory(surface, NULL, NULL, data, g_LastFileSize, NULL, D3DX_FILTER_NONE, 0,
                                        &this->surfaceSourceInfo[surfaceIdx]) != D3D_OK)
    {
        goto fail;
    }
    if (g_Supervisor.d3dDevice->CreateRenderTarget(this->surfaceSourceInfo[surfaceIdx].Width,
                                                   this->surfaceSourceInfo[surfaceIdx].Height,
                                                   g_Supervisor.presentParameters.BackBufferFormat, D3DMULTISAMPLE_NONE,
                                                   TRUE, &this->surfaces[surfaceIdx]) != D3D_OK)
    {
        goto fail;
    }
    if (g_Supervisor.d3dDevice->CreateImageSurface(
            this->surfaceSourceInfo[surfaceIdx].Width, this->surfaceSourceInfo[surfaceIdx].Height,
            g_Supervisor.presentParameters.BackBufferFormat, &this->surfaces[surfaceIdx]) != D3D_OK)
    {
        goto fail;
    }
    if (g_Supervisor.d3dDevice->CreateImageSurface(
            this->surfaceSourceInfo[surfaceIdx].Width, this->surfaceSourceInfo[surfaceIdx].Height,
            g_Supervisor.presentParameters.BackBufferFormat, &this->surfacesBis[surfaceIdx]) != D3D_OK)
    {
        goto fail;
    }

    if (D3DXLoadSurfaceFromSurface(this->surfaces[surfaceIdx], NULL, NULL, surface, NULL, NULL, D3DX_FILTER_NONE, 0) !=
        D3D_OK)
    {
        goto fail;
    }

    if (D3DXLoadSurfaceFromSurface(this->surfacesBis[surfaceIdx], NULL, NULL, surface, NULL, NULL, D3DX_FILTER_NONE,
                                   0) != D3D_OK)
    {
        goto fail;
    }

    if (surface != NULL)
    {
        surface->Release();
        surface = NULL;
    }
    free(data);
    return ZUN_SUCCESS;

fail:
    if (surface != NULL)
    {
        surface->Release();
        surface = NULL;
    }
    free(data);
    return ZUN_ERROR;
}

void AnmManager::ReleaseSurface(i32 surfaceIdx)
{
    if (this->surfaces[surfaceIdx] != NULL)
    {
        this->surfaces[surfaceIdx]->Release();
        this->surfaces[surfaceIdx] = NULL;
    }
    if (this->surfacesBis[surfaceIdx] != NULL)
    {
        this->surfacesBis[surfaceIdx]->Release();
        this->surfacesBis[surfaceIdx] = NULL;
    }
    return;
}

void AnmManager::CopySurfaceToBackBuffer(i32 surfaceIdx, i32 left, i32 top, i32 x, i32 y)
{
    if (this->surfacesBis[surfaceIdx] == NULL)
    {
        return;
    }

    IDirect3DSurface8 *destSurface;
    if (g_Supervisor.d3dDevice->GetBackBuffer(0, D3DBACKBUFFER_TYPE_MONO, &destSurface) != D3D_OK)
    {
        return;
    }
    if (this->surfaces[surfaceIdx] == NULL)
    {
        if (g_Supervisor.d3dDevice->CreateRenderTarget(
                this->surfaceSourceInfo[surfaceIdx].Width, this->surfaceSourceInfo[surfaceIdx].Height,
                g_Supervisor.presentParameters.BackBufferFormat, D3DMULTISAMPLE_NONE, TRUE,
                &this->surfaces[surfaceIdx]) != D3D_OK)
        {
            if (g_Supervisor.d3dDevice->CreateImageSurface(
                    this->surfaceSourceInfo[surfaceIdx].Width, this->surfaceSourceInfo[surfaceIdx].Height,
                    g_Supervisor.presentParameters.BackBufferFormat, &this->surfaces[surfaceIdx]) != D3D_OK)
            {
                destSurface->Release();
                return;
            }
        }
        if (D3DXLoadSurfaceFromSurface(this->surfaces[surfaceIdx], NULL, NULL, this->surfacesBis[surfaceIdx], NULL,
                                       NULL, D3DX_FILTER_NONE, 0) != D3D_OK)
        {
            destSurface->Release();
            return;
        }
    }

    RECT sourceRect;
    POINT destPoint;
    sourceRect.left = left;
    sourceRect.top = top;
    sourceRect.right = this->surfaceSourceInfo[surfaceIdx].Width;
    sourceRect.bottom = this->surfaceSourceInfo[surfaceIdx].Height;
    destPoint.x = x;
    destPoint.y = y;
    g_Supervisor.d3dDevice->CopyRects(this->surfaces[surfaceIdx], &sourceRect, 1, destSurface, &destPoint);
    destSurface->Release();
}

ZunResult AnmManager::LoadAnm(i32 surfaceIdx, char *path, i32 unk)
{
    // TODO: stub
    return ZUN_ERROR;
}

DIFFABLE_STATIC(AnmManager *, g_AnmManager)
