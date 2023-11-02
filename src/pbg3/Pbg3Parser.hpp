#pragma once

#include "FileAbstraction.hpp"
#include "inttypes.hpp"

class IPbg3Parser
{
  public:
    IPbg3Parser();
    u32 ReadVarInt();
    u32 ReadMagic();
    u32 ReadString(char *out, u32 maxSize);
    virtual i32 ReadBit() = 0;
    virtual u32 ReadInt(u32 numBitsAsPowersOf2) = 0;
    virtual u8 ReadByteAssumeAligned() = 0;
    virtual i32 SeekToOffset(u32 fileOffset) = 0;
    virtual i32 SeekToNextByte() = 0;
    virtual i32 ReadByteAlignedData(u8 *data, u32 bytesToRead) = 0;
    virtual i32 GetLastWriteTime(LPFILETIME lastWriteTime) = 0;

  protected:
    u32 offsetInFile;
    u32 fileSize;
    u32 curByte;
    u32 bitIdxInCurByte;
    u32 crc;
};

class Pbg3Parser : public IPbg3Parser
{
  public:
    Pbg3Parser();
    i32 Open(char *path);
    i32 ReadBit();
    u32 ReadInt(u32 numBitsAsPowersOf2);
    u8 ReadByteAssumeAligned();
    i32 SeekToOffset(u32 fileOffset);
    i32 SeekToNextByte();
    i32 ReadByteAlignedData(u8 *data, u32 bytesToRead);
    i32 GetLastWriteTime(LPFILETIME lastWriteTime);

    ~Pbg3Parser();

  private:
    FileAbstraction fileAbstraction;
};
