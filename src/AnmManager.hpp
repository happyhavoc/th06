#pragma once

#include <d3d8.h>
#include <d3dx8math.h>

#include "ZunResult.hpp"
#include "ZunTimer.hpp"
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
C_ASSERT(sizeof(AnmLoadedSprite) == 0x38);

struct AnmRawInstr
{
};
struct AnmVm
{
    AnmVm();

    void Initialize();

    D3DXVECTOR3 rotation;
    D3DXVECTOR3 angleVel;
    f32 scaleY;
    f32 scaleX;
    f32 scaleInterpFinalY;
    f32 scaleInterpFinalX;
    D3DXVECTOR2 uvScrollPos;
    ZunTimer currentTimeInScript;
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
    ZunTimer scaleInterpTime;
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
    ZunTimer posInterpTime;
    i32 timeOfLastSpriteSet;
    ZunTimer alphaInterpTime;
    u8 fontWidth;
    u8 fontHeight;
    // Two final padding bytes
};
C_ASSERT(sizeof(AnmVm) == 0x110);

struct AnmRawSprite
{
    u32 id;
    D3DXVECTOR2 offset;
    D3DXVECTOR2 size;
};

struct AnmRawEntry
{
    i32 numSprites;
    i32 numScripts;
    u32 textureIdx;
    u32 width;
    u32 height;
    u32 format;
    u32 colorKey;
    u32 nameOffset;
    u32 spriteIdxOffset;
    u32 mipmapNameOffset;
    u32 version;
    u32 unk1;
    u32 textureOffset;
    u32 hasData;
    u32 nextOffset;
    u32 unk2;
    u8 data[0];
};

struct RenderVertexInfo
{
    D3DXVECTOR3 position;
    D3DXVECTOR2 textureUV;
};
C_ASSERT(sizeof(RenderVertexInfo) == 0x14);

struct AnmManager
{
    AnmManager();
    ~AnmManager();

    void SetupVertexBuffer();

    ZunResult CreateEmptyTexture(u32 textureIdx, u32 width, u32 height, u32 textureFormat);
    ZunResult LoadTexture(u32 textureIdx, char *textureName, u32 textureFormat, D3DCOLOR colorKey);
    ZunResult LoadTextureMipmap(u32 textureIdx, char *textureName, u32 textureFormat, D3DCOLOR colorKey);

    void LoadSprite(u32 spriteIdx, AnmLoadedSprite *sprite);
    ZunResult SetActiveSprite(AnmVm *vm, u32 spriteIdx);

    void ReleaseSurfaces(void);
    ZunResult LoadSurface(i32 surfaceIdx, char *path);
    void ReleaseSurface(i32 surfaceIdx);
    void CopySurfaceToBackBuffer(i32 surfaceIdx, i32 left, i32 top, i32 x, i32 y);

    void ReleaseAnm(i32 anmIdx);
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
    i32 screenshotTextureId;
    i32 screenshotLeft;
    i32 screenshotTop;
    i32 screenshotWidth;
    i32 screenshotHeight;
};
C_ASSERT(sizeof(AnmManager) == 0x2112c);

DIFFABLE_EXTERN(AnmManager *, g_AnmManager)
