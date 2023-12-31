#pragma once

#include "FileAbstraction.hpp"
#include "IPbg3Parser.hpp"
#include "inttypes.hpp"

class Pbg3Parser : public IPbg3Parser, public FileAbstraction
{
  public:
    Pbg3Parser();
    i32 OpenArchive(char *path);
    i32 ReadBit();
    u32 ReadInt(u32 numBitsAsPowersOf2);
    u8 ReadByteAssumeAligned();
    i32 SeekToOffset(u32 fileOffset);
    i32 SeekToNextByte();
    i32 ReadByteAlignedData(u8 *data, u32 bytesToRead);
    i32 GetLastWriteTime(LPFILETIME lastWriteTime);

    void Close();
    i32 ReadByte();

    ~Pbg3Parser();
};
C_ASSERT(sizeof(Pbg3Parser) == 0x24);
