#pragma once

struct AnmManager
{
    AnmManager();
    ~AnmManager();

    void ReleaseD3dSurfaces(void);
    char data[0x2112c];
};

extern AnmManager *g_AnmManager;
