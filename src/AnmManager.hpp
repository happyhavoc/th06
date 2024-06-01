#pragma once

#include <d3d8.h>
#include <d3dx8math.h>

#include "AnmIdx.hpp"
#include "AnmVm.hpp"
#include "ZunResult.hpp"
#include "ZunTimer.hpp"
#include "diffbuild.hpp"
#include "inttypes.hpp"

// structure of a vertex with SetVertexShade FVF set to D3DFVF_DIFFUSE | D3DFVF_XYZRHW
struct VertexDiffuseXyzrwh
{
    D3DXVECTOR4 position;
    D3DCOLOR diffuse;
};

// Structure of a vertex with SetVertexShade FVF set to D3DFVF_TEX1 | D3DFVF_XYZRHW
struct VertexTex1Xyzrwh
{
    D3DXVECTOR4 position;
    D3DXVECTOR2 textureUV;
};

// Structure of a vertex with SetVertexShade FVF set to D3DFVF_TEX1 | D3DFVF_DIFFUSE | D3DFVF_XYZRHW
struct VertexTex1DiffuseXyzrwh
{
    D3DXVECTOR4 position;
    D3DCOLOR diffuse;
    D3DXVECTOR2 textureUV;
};

// Structure of a vertex with SetVertexShade FVF set to D3DFVF_TEX1 | D3DFVF_DIFFUSE | D3DFVF_XYZ
struct VertexTex1DiffuseXyz
{
    D3DXVECTOR3 position;
    D3DCOLOR diffuse;
    D3DXVECTOR2 textureUV;
};

struct AnmRawSprite
{
    u32 id;
    D3DXVECTOR2 offset;
    D3DXVECTOR2 size;
};

struct AnmRawScript
{
    u32 id;
    AnmRawInstr *firstInstruction;
};

struct AnmRawEntry
{
    i32 numSprites;
    i32 numScripts;
    u32 textureIdx;
    i32 width;
    i32 height;
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
    u32 spriteOffsets[10];
    AnmRawScript scripts[10];
};
C_ASSERT(sizeof(AnmRawEntry) == 0xb8);

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

    void ReleaseVertexBuffer();
    void SetupVertexBuffer();

    ZunResult CreateEmptyTexture(i32 textureIdx, u32 width, u32 height, i32 textureFormat);
    ZunResult LoadTexture(i32 textureIdx, char *textureName, i32 textureFormat, D3DCOLOR colorKey);
    ZunResult LoadTextureAlphaChannel(i32 textureIdx, char *textureName, i32 textureFormat, D3DCOLOR colorKey);
    void ReleaseTexture(i32 textureIdx);
    void TakeScreenshotIfRequested();

    void SetAndExecuteScript(AnmVm *vm, AnmRawInstr *beginingOfScript);
    void SetAndExecuteScriptIdx(AnmVm *vm, i32 anmFileIdx)
    {
        vm->anmFileIndex = anmFileIdx;
        this->SetAndExecuteScript(vm, this->scripts[anmFileIdx]);
    }

    void SetCurrentVertexShader(u8 vertexShader)
    {
        this->currentVertexShader = vertexShader;
    }
    void SetCurrentColorOp(u8 colorOp)
    {
        this->currentColorOp = colorOp;
    }
    void SetCurrentBlendMode(u8 blendMode)
    {
        this->currentBlendMode = blendMode;
    }
    void SetCurrentZWriteDisable(u8 zwriteDisable)
    {
        this->currentZWriteDisable = zwriteDisable;
    }

    i32 ExecuteScript(AnmVm *vm);
    ZunResult Draw(AnmVm *vm);
    static void DrawStringFormat(AnmManager *mgr, AnmVm *vm, ZunColor textColor, ZunColor shadowColor, char *fmt, ...);
    static void DrawStringFormat2(AnmManager *mgr, AnmVm *vm, ZunColor textColor, ZunColor shadowColor, char *fmt, ...);
    ZunResult DrawNoRotation(AnmVm *vm);
    ZunResult DrawInner(AnmVm *vm, i32 unk);

    void LoadSprite(u32 spriteIdx, AnmLoadedSprite *sprite);
    ZunResult SetActiveSprite(AnmVm *vm, u32 spriteIdx);

    void ReleaseSurfaces(void);
    ZunResult LoadSurface(i32 surfaceIdx, char *path);
    void ReleaseSurface(i32 surfaceIdx);
    void CopySurfaceToBackBuffer(i32 surfaceIdx, i32 left, i32 top, i32 x, i32 y);

    void TranslateRotation(VertexTex1Xyzrwh *param_1, float x, float y, float sine, float cosine, float xOffset,
                           float yOffset);

    void ReleaseAnm(i32 anmIdx);
    ZunResult LoadAnm(i32 anmIdx, char *path, i32 spriteIdxOffset);
    void ExecuteAnmIdx(AnmVm *vm, i32 anmFileIdx);

    void SetRenderStateForVm(AnmVm *vm);

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

f32 AddNormalizeAngle(f32 a, f32 b);

DIFFABLE_EXTERN(AnmManager *, g_AnmManager);
DIFFABLE_EXTERN(D3DFORMAT, g_TextureFormatD3D8Mapping[6]);
