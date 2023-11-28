#include "AnmManager.hpp"

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
    // TODO: stub
    return ZUN_ERROR;
}

void AnmManager::ReleaseSurface(i32 surfaceIdx)
{
    // TODO: stub
}

void AnmManager::CopySurfaceToBackBuffer(i32 surfaceIdx, i32 left, i32 top, i32 x, i32 y)
{
    // TODO: stub
}

ZunResult AnmManager::LoadAnm(i32 surfaceIdx, char *path, i32 unk)
{
    // TODO: stub
    return ZUN_ERROR;
}

DIFFABLE_STATIC(AnmManager *, g_AnmManager)
