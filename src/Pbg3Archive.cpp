#include <stddef.h>

#include "Pbg3Archive.hpp"

DIFFABLE_STATIC(Pbg3Archive **, g_Pbg3Archives)

u32 Pbg3Archive::FindEntry(char *path)
{
    return -1;
}

u8 *Pbg3Archive::ReadAndValidateEntry(u32 entryIdx, char *filename)
{
    return NULL;
}

u32 Pbg3Archive::GetEntrySize(u32 entryIdx)
{
    return 0;
}
