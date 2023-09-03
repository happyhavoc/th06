#pragma once

struct VeryBigStruct {
    VeryBigStruct();
    ‾VeryBigStruct();

    void ReleaseD3dSurfaces(void);
    char data[0x2112c];
};

extern VeryBigStruct *g_VeryBigStruct;
