#include "AnmManager.hpp"
#include "FileSystem.hpp"
#include "GameErrorContext.hpp"
#include "Supervisor.hpp"
#include "i18n.hpp"
#include "utils.hpp"

// Structure of a vertex with SetVertexShade FVF set to D3DFVF_TEX1 | D3DFVF_XYZRWH
struct VertexTex1Xyzrwh
{
    D3DXVECTOR4 pos;
    D3DXVECTOR2 textureUV;
};

// Structure of a vertex with SetVertexShade FVF set to D3DFVF_TEX1 | D3DFVF_DIFFUSE | D3DFVF_XYZRWH
struct VertexTex1DiffuseXyzrwh
{
    D3DXVECTOR4 pos;
    D3DCOLOR diffuse;
    D3DXVECTOR2 textureUV;
};

// Structure of a vertex with SetVertexShade FVF set to D3DFVF_TEX1 | D3DFVF_DIFFUSE | D3DFVF_XYZ
struct VertexTex1DiffuseXyz
{
    D3DXVECTOR3 pos;
    D3DCOLOR diffuse;
    D3DXVECTOR2 textureUV;
};

DIFFABLE_STATIC(VertexTex1Xyzrwh, g_PrimitivesToDrawVertexBuf[4]);
DIFFABLE_STATIC(VertexTex1DiffuseXyzrwh, g_PrimitivesToDrawNoVertexBuf[4]);

#ifndef DIFFBUILD
D3DFORMAT g_TextureFormatD3D8Mapping[6] = {
    D3DFMT_UNKNOWN, D3DFMT_A8R8G8B8, D3DFMT_A1R5G5B5, D3DFMT_R5G6B5, D3DFMT_R8G8B8, D3DFMT_A4R4G4B4,
};
#endif

// Stack layout here doesn't match because of extra unused stack slot.
// This might mean that some empty constructors are called and inlined here.
AnmManager::AnmManager()
{
    this->maybeLoadedSpriteCount = 0;

    memset(this, 0, sizeof(AnmManager));

    for (int spriteIndex = 0; spriteIndex < ARRAY_SIZE_SIGNED(this->sprites); spriteIndex++)
    {
        this->sprites[spriteIndex].sourceFileIndex = -1;
    }

    g_PrimitivesToDrawVertexBuf[3].pos.w = 1.0;
    g_PrimitivesToDrawVertexBuf[2].pos.w = g_PrimitivesToDrawVertexBuf[3].pos.w;
    g_PrimitivesToDrawVertexBuf[1].pos.w = g_PrimitivesToDrawVertexBuf[2].pos.w;
    g_PrimitivesToDrawVertexBuf[0].pos.w = g_PrimitivesToDrawVertexBuf[1].pos.w;
    g_PrimitivesToDrawVertexBuf[0].textureUV.x = 0.0;
    g_PrimitivesToDrawVertexBuf[0].textureUV.y = 0.0;
    g_PrimitivesToDrawVertexBuf[1].textureUV.x = 1.0;
    g_PrimitivesToDrawVertexBuf[1].textureUV.y = 0.0;
    g_PrimitivesToDrawVertexBuf[2].textureUV.x = 0.0;
    g_PrimitivesToDrawVertexBuf[2].textureUV.y = 1.0;
    g_PrimitivesToDrawVertexBuf[3].textureUV.x = 1.0;
    g_PrimitivesToDrawVertexBuf[3].textureUV.y = 1.0;

    g_PrimitivesToDrawNoVertexBuf[3].pos.w = 1.0;
    g_PrimitivesToDrawNoVertexBuf[2].pos.w = g_PrimitivesToDrawNoVertexBuf[3].pos.w;
    g_PrimitivesToDrawNoVertexBuf[1].pos.w = g_PrimitivesToDrawNoVertexBuf[2].pos.w;
    g_PrimitivesToDrawNoVertexBuf[0].pos.w = g_PrimitivesToDrawNoVertexBuf[1].pos.w;
    g_PrimitivesToDrawNoVertexBuf[0].textureUV.x = 0.0;
    g_PrimitivesToDrawNoVertexBuf[0].textureUV.y = 0.0;
    g_PrimitivesToDrawNoVertexBuf[1].textureUV.x = 1.0;
    g_PrimitivesToDrawNoVertexBuf[1].textureUV.y = 0.0;
    g_PrimitivesToDrawNoVertexBuf[2].textureUV.x = 0.0;
    g_PrimitivesToDrawNoVertexBuf[2].textureUV.y = 1.0;
    g_PrimitivesToDrawNoVertexBuf[3].textureUV.x = 1.0;
    g_PrimitivesToDrawNoVertexBuf[3].textureUV.y = 1.0;

    this->vertexBuffer = NULL;
    this->currentTexture = NULL;
    this->currentBlendMode = 0;
    this->currentColorOp = 0;
    this->currentTextureFactor = 1;
    this->currentVertexShader = 0;
    this->currentZWriteDisable = 0;
    this->screenshotTextureId = -1;
}
AnmManager::~AnmManager()
{
}

ZunResult AnmManager::CreateEmptyTexture(i32 textureIdx, u32 width, u32 height, i32 textureFormat)
{
    D3DXCreateTexture(g_Supervisor.d3dDevice, width, height, 1, 0, g_TextureFormatD3D8Mapping[textureFormat],
                      D3DPOOL_MANAGED, this->textures + textureIdx);

    return ZUN_SUCCESS;
}

ZunResult AnmManager::SetActiveSprite(AnmVm *vm, u32 sprite_index)
{
    if (this->sprites[sprite_index].sourceFileIndex < 0)
    {
        return ZUN_ERROR;
    }

    vm->spriteNumber = (i16)sprite_index;
    vm->sprite = this->sprites + sprite_index;
    D3DXMatrixIdentity(&vm->matrix);
    vm->matrix.m[0][0] = vm->sprite->widthPx / vm->sprite->textureWidth;
    vm->matrix.m[1][1] = vm->sprite->heightPx / vm->sprite->textureHeight;

    return ZUN_SUCCESS;
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
}

void AnmManager::ReleaseSurfaces(void)
{
    for (int idx = 0; idx < ARRAY_SIZE_SIGNED(this->surfaces); idx++)
    {
        if (this->surfaces[idx] != NULL)
        {
            this->surfaces[idx]->Release();
            this->surfaces[idx] = NULL;
        }
    }
}

void AnmManager::ReleaseTexture(i32 textureIdx)
{
    if (this->textures[textureIdx] != NULL)
    {
        this->textures[textureIdx]->Release();
        this->textures[textureIdx] = NULL;
    }

    void *imageDataArray = this->imageDataArray[textureIdx];
    free(imageDataArray);

    this->imageDataArray[textureIdx] = NULL;
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

ZunResult AnmManager::LoadAnm(i32 anmIdx, char *path, i32 spriteIdxOffset)
{
    this->ReleaseAnm(anmIdx);
    this->anmFiles[anmIdx] = (AnmRawEntry *)FileSystem::OpenPath(path, 0);
    AnmRawEntry *anmData = this->anmFiles[anmIdx];
    if (anmData == NULL)
    {
        GameErrorContextFatal(&g_GameErrorContext, TH_ERR_ANMMANAGER_SPRITE_CORRUPTED, path);
        return ZUN_ERROR;
    }

    anmData->textureIdx = anmIdx;
    char *anmName = (char *)((u8 *)anmData + anmData->nameOffset);
    if (*anmName == '@')
    {
        this->CreateEmptyTexture(anmData->textureIdx, anmData->width, anmData->height, anmData->format);
    }
    else
    {
        if (this->LoadTexture(anmData->textureIdx, anmName, anmData->format, anmData->colorKey) != 0)
        {
            GameErrorContextFatal(&g_GameErrorContext, TH_ERR_ANMMANAGER_TEXTURE_CORRUPTED, anmName);
            return ZUN_ERROR;
        }
    }
    if (anmData->mipmapNameOffset != 0)
    {
        anmName = (char *)((u8 *)anmData + anmData->mipmapNameOffset);
        if (this->LoadTextureMipmap(anmData->textureIdx, anmName, anmData->format, anmData->colorKey) != 0)
        {
            GameErrorContextFatal(&g_GameErrorContext, TH_ERR_ANMMANAGER_TEXTURE_CORRUPTED, anmName);
            return ZUN_ERROR;
        }
    }
    anmData->spriteIdxOffset = spriteIdxOffset;
    u32 *curSpriteOffset = (u32 *)anmData->data;
    for (i32 i = 0; i < this->anmFiles[anmIdx]->numSprites; i++, curSpriteOffset++)
    {
        AnmRawSprite *rawSprite = (AnmRawSprite *)((u8 *)anmData + *curSpriteOffset);
        AnmLoadedSprite loadedSprite;
        loadedSprite.sourceFileIndex = this->anmFiles[anmIdx]->textureIdx;
        loadedSprite.startPixelInclusive.x = rawSprite->offset.x;
        loadedSprite.startPixelInclusive.y = rawSprite->offset.y;
        loadedSprite.endPixelInclusive.x = rawSprite->offset.x + rawSprite->size.x;
        loadedSprite.endPixelInclusive.y = rawSprite->offset.y + rawSprite->size.y;
        loadedSprite.textureWidth = (float)anmData->width;
        loadedSprite.textureHeight = (float)anmData->height;
        this->LoadSprite(rawSprite->id + spriteIdxOffset, &loadedSprite);
    }
    for (i = 0; i < anmData->numScripts; i++, curSpriteOffset += 2)
    {
        this->scripts[curSpriteOffset[0] + spriteIdxOffset] = (AnmRawInstr *)((u8 *)anmData + curSpriteOffset[1]);
        this->spriteIndices[curSpriteOffset[0] + spriteIdxOffset] = spriteIdxOffset;
    }
    this->anmFilesSpriteIndexOffsets[anmIdx] = spriteIdxOffset;
    return ZUN_SUCCESS;
}

DIFFABLE_STATIC(AnmManager *, g_AnmManager)
