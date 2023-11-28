#pragma once

#include <d3d8.h>
#include <d3dx8math.h>

#include "ZunResult.hpp"
#include "diffbuild.hpp"
#include "inttypes.hpp"

struct AnmLoadedSprite
{
    u32 sourceFileIndex;
    D3DXVECTOR2 startPixelInclusive;
    D3DXVECTOR2 endPixelInclusive;
    f32 textureHeight;
    f32 textureWidth;
    D3DXVECTOR2 uvStart;
    D3DXVECTOR2 uvEnd;
    f32 heightPx;
    f32 widthPx;
    i32 spriteId;
};

struct AnmTimer
{
    i32 previous;
    f32 subFrame;
    i32 current;
};

struct AnmRawInstr
{
};
struct AnmVm
{
    D3DXVECTOR3 rotation;
    D3DXVECTOR3 angleVel;
    f32 scaleY;
    f32 scaleX;
    f32 scaleInterpFinalY;
    f32 scaleInterpFinalX;
    D3DXVECTOR2 uvScrollPos;
    AnmTimer currentTimeInScript;
    D3DMATRIX matrix;
    D3DCOLOR color;
    u32 flags;
    u16 alphaInterpEndTime;
    u16 scaleInterpEndTime;
    u16 autoRotate;
    i16 pendingInterrupt;
    u16 posInterpEndTime;
    // Two padding bytes
    D3DXVECTOR3 pos;
    f32 scaleInterpInitialY;
    f32 scaleInterpInitialX;
    AnmTimer scaleInterpTime;
    i16 spriteNumber;
    i16 anotherSpriteNumber;
    i16 anmFileIndex;
    // Two padding bytes
    AnmRawInstr *beginingOfScript;
    AnmRawInstr *currentInstruction;
    AnmLoadedSprite *sprite;
    D3DCOLOR alphaInterpInitial;
    D3DCOLOR alphaInterpFinal;
    D3DXVECTOR3 posInterpInitial;
    D3DXVECTOR3 posInterpFinal;
    D3DXVECTOR3 pos2;
    AnmTimer posInterpTime;
    i32 timeOfLastSpriteSet;
    AnmTimer alphaInterpTime;
    u8 fontWidth;
    u8 fontHeight;
    // Two final padding bytes
};
struct AnmRawEntry
{
};

struct RenderVertexInfo
{
    D3DXVECTOR3 position;
    D3DCOLOR diffuseColor;
    D3DXVECTOR2 textureUV;
};

struct AnmManager
{
    AnmManager();
    ~AnmManager();

    void SetupVertexBuffer();

    void ReleaseD3dSurfaces(void);
    ZunResult LoadSurface(i32 surfaceIdx, char *path);
    void ReleaseSurface(i32 surfaceIdx);
    void CopySurfaceToBackBuffer(i32 surfaceIdx, i32 left, i32 top, i32 x, i32 y);

    ZunResult LoadAnm(i32 anmIdx, char *path, i32 unk);

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

DIFFABLE_EXTERN(AnmManager *, g_AnmManager)
