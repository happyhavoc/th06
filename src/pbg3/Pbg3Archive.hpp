#pragma once

#include "diffbuild.hpp"
#include "inttypes.hpp"
#include "pbg3/Pbg3Parser.hpp"

namespace th06
{
struct Pbg3Entry
{
    u32 unk1;
    u32 unk2;
    u32 uncompressedSize;
    u32 dataOffset;
    u32 checksum;
    char filename[256];
};
ZUN_ASSERT_SIZE(Pbg3Entry, 0x114);

class Pbg3Archive
{
  public:
    Pbg3Archive();
    ~Pbg3Archive();

    i32 Release();

    i32 Load(char *path);
    i32 ParseHeader();
    i32 FindEntry(char *path);
    u32 GetEntrySize(u32 entryIdx);
    u8 *ReadEntryRaw(u32 *outSize, u32 *outChecksum, i32 entryIdx);
    u8 *ReadDecompressEntry(u32 entryIdx, char *filename);

  private:
    Pbg3Parser *parser;
    void *unk;
    u32 numOfEntries;
    u32 fileTableOffset;
    Pbg3Entry *entries;
};
ZUN_ASSERT_SIZE(Pbg3Archive, 0x14);

DIFFABLE_EXTERN(Pbg3Archive **, g_Pbg3Archives)
}; // namespace th06
