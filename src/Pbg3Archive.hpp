#pragma once

#include "inttypes.hpp"

struct Pbg3Archive
{
    u32 FindEntry(char *path);
    u8 *ReadAndValidateEntry(u32 entryIdx, char *filename);
    u32 GetEntrySize(u32 entryIdx);
};

extern Pbg3Archive **g_Pbg3Archives;
