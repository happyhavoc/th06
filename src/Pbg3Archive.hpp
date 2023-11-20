#pragma once

#include "diffbuild.hpp"
#include "inttypes.hpp"

struct Pbg3Archive
{
    u32 FindEntry(char *path);
    u8 *ReadAndValidateEntry(u32 entryIdx, char *filename);
    u32 GetEntrySize(u32 entryIdx);
};

DIFFABLE_EXTERN(Pbg3Archive **, g_Pbg3Archives)
