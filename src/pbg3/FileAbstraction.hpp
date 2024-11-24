#pragma once

#include <Windows.h>

#include "inttypes.hpp"

namespace th06
{
class IFileAbstraction
{
  public:
    virtual i32 Open(char *filename, char *mode) = 0;
    virtual void Close() = 0;
    virtual i32 Read(u8 *data, u32 dataLen, u32 *numBytesRead) = 0;
    virtual i32 Write(u8 *data, u32 dataLen, u32 *outWritten) = 0;
    virtual i32 ReadByte() = 0;
    virtual i32 WriteByte(u32 b) = 0;
    virtual i32 Seek(u32 amount, u32 seekFrom) = 0;
    virtual u32 Tell() = 0;
    virtual u32 GetSize() = 0;
    virtual u8 *ReadWholeFile(u32 maxSize) = 0;
};

class FileAbstraction : public IFileAbstraction
{
  public:
    FileAbstraction();
    ~FileAbstraction();

    virtual i32 Open(char *filename, char *mode);
    virtual void Close();
    virtual i32 Read(u8 *data, u32 dataLen, u32 *numBytesRead);
    virtual i32 Write(u8 *data, u32 dataLen, u32 *outWritten);
    virtual i32 ReadByte();
    virtual i32 WriteByte(u32 b);
    virtual i32 Seek(u32 amount, u32 seekFrom);
    virtual u32 Tell();
    virtual u32 GetSize();
    virtual u8 *ReadWholeFile(u32 maxSize);

    BOOL HasNonNullHandle()
    {
        return this->handle != NULL;
    }
    BOOL HasValidHandle()
    {
        return this->handle != INVALID_HANDLE_VALUE;
    }
    i32 GetLastWriteTime(LPFILETIME lastWriteTime)
    {
        return GetFileTime(this->handle, NULL, NULL, lastWriteTime);
    }

  protected:
    HANDLE handle;

  private:
    DWORD access;
};
C_ASSERT(sizeof(FileAbstraction) == 0xc);
}; // namespace th06
