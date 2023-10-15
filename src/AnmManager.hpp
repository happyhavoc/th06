#pragma once

#include <d3d8.h>
#include <d3dx8math.h>

#include "inttypes.hpp"

struct AnmLoadedSprite
{
};
struct AnmVm
{
};
struct AnmRawInstr
{
};
struct AnmRawEntry
{
};
struct RenderVertexInfo
{
};

struct AnmManager
{
    AnmManager();
    ~AnmManager();

    void ReleaseD3dSurfaces(void);

    AnmLoadedSprite sprites[2048];
    AnmVm virtualMachine;
    IDirect3DTexture8 *textures[264];
    void *imageDataArray[256];
    i32 maybeLoadedSpriteCount;
    AnmRawInstr *scripts[2048];
    i32 spriteIndices[2048];
    AnmRawEntry *anmFiles[128];
    u32 anmFilesSpriteIndexOffsets[128];
    IDirect3DSurface8 *surfaces[32];
    IDirect3DSurface8 *surfacesBis[32];
    D3DXIMAGE_INFO surfaceSourceInfo[32];
    D3DCOLOR currentTextureFactor;
    IDirect3DTexture8 *currentTexture;
    u8 currentBlendMode;
    u8 currentColorOp;
    u8 currentVertexShader;
    u8 currentZWriteDisable;
    AnmLoadedSprite *currentSprite;
    IDirect3DVertexBuffer8 *vertexBuffer;
    RenderVertexInfo vertexBufferContents[4];
    i32 heightsMaybe;
};

extern AnmManager *g_AnmManager;
