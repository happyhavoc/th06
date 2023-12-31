#include "Pbg3Parser.hpp"

void IPbg3Parser::Reset()
{
    this->bitIdxInCurByte = 128;
    this->offsetInFile = 0;
    this->fileSize = 0;
    this->curByte = 0;
    this->crc = 0;
}

u32 IPbg3Parser::ReadVarInt()
{
    u32 res = 0;
    i32 varintHdr = 0;

    if (this->ReadBit())
    {
        varintHdr = 2;
    }
    if (this->ReadBit())
    {
        varintHdr |= 1;
    }

    u32 intLen;
    switch (varintHdr)
    {
    case 0:
        intLen = 0x80;
        break;
    case 1:
        intLen = 0x8000;
        break;
    case 2:
        intLen = 0x800000;
        break;
    case 3:
        intLen = 0x80000000;
        break;
    default:
        // TODO: There's probably a way to match without goto, but
        // I can't figure it out... a simple `return 0;` won't share
        // the function epilogue with the other return res.
        goto end;
    }

    do
    {
        if (this->ReadBit())
        {
            res |= intLen;
        }
        intLen >>= 1;
    } while (intLen != 0);
end:
    return res;
}

u32 IPbg3Parser::ReadMagic()
{
    u32 b0 = this->ReadInt(8);
    u32 b1 = b0 + (this->ReadInt(8) << 8);
    u32 b2 = b1 + (this->ReadInt(8) << 16);
    u32 b3 = b2 + (this->ReadInt(8) << 24);

    return b3;
}

u32 IPbg3Parser::ReadString(char *out, u32 maxSize)
{
    if (out == NULL)
        return FALSE;

    for (u32 idx = 0; idx < maxSize; idx++)
    {
        out[idx] = this->ReadInt(8);
        if (out[idx] == '\0')
        {
            return TRUE;
        }
    }

    return FALSE;
}

Pbg3Parser::Pbg3Parser() : IPbg3Parser(), fileAbstraction()
{
    this->Reset();
}

i32 Pbg3Parser::Open(char *path)
{
    this->fileAbstraction.Close();
    this->Reset();
    if (this->fileAbstraction.Open(path, "r") == FALSE)
    {
        return FALSE;
    }
    this->fileSize = this->fileAbstraction.GetSize();
    return TRUE;
}

i32 Pbg3Parser::ReadBit()
{
    if (!this->fileAbstraction.HasNonNullHandle())
    {
        return FALSE;
    }

    if (this->bitIdxInCurByte == 0x80)
    {
        this->curByte = this->fileAbstraction.ReadByte();
        if (this->curByte == -1)
        {
            return FALSE;
        }
        this->offsetInFile += 1;
        this->crc += this->curByte;
    }

    i32 res = this->curByte & this->bitIdxInCurByte;
    this->bitIdxInCurByte >>= 1;
    if (this->bitIdxInCurByte == 0)
    {
        this->bitIdxInCurByte = 0x80;
    }
    return res != 0;
}

u32 Pbg3Parser::ReadInt(u32 numBitsAsPowersOf2)
{
    u32 remainingBits = 1 << (numBitsAsPowersOf2 - 1);
    u32 result = 0;

    if (!this->fileAbstraction.HasNonNullHandle())
    {
        return 0;
    }

    while (remainingBits != 0)
    {
        if (this->bitIdxInCurByte == 0x80)
        {
            this->curByte = this->fileAbstraction.ReadByte();
            if (this->curByte == -1)
            {
                return FALSE;
            }
            this->offsetInFile += 1;
            this->crc += this->curByte;
        }
        u32 bitIdx = this->bitIdxInCurByte;
        if ((bitIdx & this->curByte) != 0)
        {
            result |= remainingBits;
        }
        remainingBits >>= 1;
        this->bitIdxInCurByte >>= 1;
        if (this->bitIdxInCurByte == 0)
        {
            this->bitIdxInCurByte = 0x80;
        }
    }

    return result;
}

u8 Pbg3Parser::ReadByteAssumeAligned()
{
    if (this->offsetInFile < this->fileSize)
    {
        this->offsetInFile += 1;
    }

    return this->fileAbstraction.ReadByte();
}

i32 Pbg3Parser::SeekToOffset(u32 fileOffset)
{
    if (fileOffset >= this->fileSize)
    {
        return FALSE;
    }

    if (this->SeekToNextByte() == FALSE)
    {
        return FALSE;
    }

    if (this->fileAbstraction.Seek(fileOffset, FILE_BEGIN) == FALSE)
    {
        return FALSE;
    }

    this->offsetInFile = fileOffset;
    this->crc = 0;
    return TRUE;
}

i32 Pbg3Parser::SeekToNextByte()
{
    if (!this->fileAbstraction.HasNonNullHandle())
    {
        return FALSE;
    }

    while (this->bitIdxInCurByte != 0x80)
    {
        this->ReadBit();
    }
    return TRUE;
}

i32 Pbg3Parser::ReadByteAlignedData(u8 *data, u32 bytesToRead)
{
    u32 numBytesRead;

    this->SeekToNextByte();
    return this->fileAbstraction.Read(data, bytesToRead, &numBytesRead);
}

i32 Pbg3Parser::GetLastWriteTime(LPFILETIME lastWriteTime)
{
    // Yes, this is comparing against INVALID_HANDLE_VALUE instead of NULL. Why?
    // Unclear.
    if (!this->fileAbstraction.HasValidHandle())
    {
        return FALSE;
    }

    // EWWWW abstraction violation much? (Maybe this is an inlined function?)
    return this->fileAbstraction.GetLastWriteTime(lastWriteTime);
}

Pbg3Parser::~Pbg3Parser()
{
    this->fileAbstraction.Close();
}
