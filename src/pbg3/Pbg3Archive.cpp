#include <stddef.h>

#include "pbg3/Pbg3Archive.hpp"

namespace th06
{
DIFFABLE_STATIC(Pbg3Archive **, g_Pbg3Archives)

Pbg3Archive::Pbg3Archive()
{
    this->fileTableOffset = 0;
    this->numOfEntries = 0;
    this->entries = NULL;
    this->parser = NULL;
    this->unk = 0;
}

i32 Pbg3Archive::ParseHeader()
{
    if (this->parser->ReadMagic() != 0x33474250)
    {
        delete this->parser;
        return FALSE;
    }

    this->numOfEntries = this->parser->ReadVarInt();
    this->fileTableOffset = this->parser->ReadVarInt();
    if (this->parser->SeekToOffset(this->fileTableOffset) == FALSE)
    {
        delete this->parser;
        return FALSE;
    }

    this->entries = new Pbg3Entry[this->numOfEntries];
    if (this->entries == NULL)
    {
        delete this->parser;
        return FALSE;
    }

    for (u32 idx = 0; idx < this->numOfEntries; idx += 1)
    {
        this->entries[idx].unk2 = this->parser->ReadVarInt();
        this->entries[idx].unk1 = this->parser->ReadVarInt();
        this->entries[idx].checksum = this->parser->ReadVarInt();
        this->entries[idx].dataOffset = this->parser->ReadVarInt();
        this->entries[idx].uncompressedSize = this->parser->ReadVarInt();
        if (this->parser->ReadString(this->entries[idx].filename, sizeof(this->entries[idx].filename)) == FALSE)
        {
            delete this->parser;
            delete[] this->entries;
            return FALSE;
        }
    }

    return TRUE;
}

i32 Pbg3Archive::Release()
{
    this->fileTableOffset = 0;
    this->numOfEntries = 0;
    if (this->parser != NULL)
    {
        delete this->parser;
        this->parser = NULL;
    }
    if (this->entries != NULL)
    {
        delete[] this->entries;
        this->entries = NULL;
    }
    delete this->unk;
    return 1;
}

i32 Pbg3Archive::FindEntry(char *path)
{
    if (this->numOfEntries == 0)
    {
        return -1;
    }

    for (u32 entryIdx = 0; entryIdx < this->numOfEntries; entryIdx += 1)
    {
        char *entryFilename = this->entries[entryIdx].filename;
        i32 res = strcmp(entryFilename, path);
        if (res == 0)
        {
            return entryIdx;
        }
    }
    return -1;
}

u32 Pbg3Archive::GetEntrySize(u32 entryIdx)
{
    if (this->numOfEntries <= entryIdx)
    {
        return 0;
    }

    return this->entries[entryIdx].uncompressedSize;
}

u8 *Pbg3Archive::ReadEntryRaw(u32 *outSize, u32 *outChecksum, i32 entryIdx)
{
    if (this->parser == NULL)
    {
        return NULL;
    }

    if (entryIdx >= this->numOfEntries)
        return NULL;

    if (outSize == NULL)
        return NULL;

    if (outChecksum == NULL)
        return NULL;

    if (this->parser->SeekToOffset(this->entries[entryIdx].dataOffset) == FALSE)
        return NULL;

    u32 size;
    if (entryIdx == this->numOfEntries - 1)
    {
        size = this->fileTableOffset - this->entries[entryIdx].dataOffset;
    }
    else
    {
        size = this->entries[entryIdx + 1].dataOffset - this->entries[entryIdx].dataOffset;
    }

    u8 *data = (u8 *)malloc(size);
    if (data == NULL)
        return NULL;

    if (this->parser->ReadByteAlignedData(data, size) == FALSE)
    {
        free(data);
        return NULL;
    }

    *outChecksum = this->entries[entryIdx].checksum;
    *outSize = size;
    return data;
}

Pbg3Archive::~Pbg3Archive()
{
    this->Release();
}

i32 Pbg3Archive::Load(char *path)
{
    if (this->Release() == NULL)
    {
        return FALSE;
    }

    this->parser = new Pbg3Parser();
    if ( this->parser == NULL )
    {
        return FALSE;
    }

    if (this->parser->OpenArchive(path) == FALSE)
    {
        delete this->parser;
        // TODO: There should be an instruction here:
        //     mov dword ptr [esi], 0x0
        // This corresponds directly to this C++ code:
        //     this->parser = NULL;
        // But inserting this line of code causes a branch in the ASM wrapper code for the scalar deleting destructor
        // call to point to the wrong place!
        return FALSE;
    }

    return this->ParseHeader();
}

#define LZSS_DICTSIZE 0x2000
#define LZSS_DICTSIZE_MASK 0x1fff
#define LZSS_MIN_MATCH 3

class BitStream
{
  public:
    BitStream(u8 *data, u32 size) : data(data), size(size), curByte(0), curByteIdx(0), curBitIdx(0x80), m_checksum(0)
    {
    }
    u32 Read(u32 numBits)
    {
        u32 ret = 0;
        while (numBits != 0)
        {
            if (this->curBitIdx == 0x80)
            {
                this->curByte = *this->data;
                if (this->curByteIdx < this->size)
                {
                    this->data += 1;
                    this->curByteIdx += 1;
                }
                else
                {
                    this->curByte = 0;
                }
                this->m_checksum += this->curByte;
            }
            if ((this->curByte & this->curBitIdx) != 0)
            {
                ret |= (1 << (numBits - 1));
            }
            numBits--;
            this->curBitIdx >>= 1;
            if (this->curBitIdx == 0)
            {
                this->curBitIdx = 0x80;
            }
        }
        return ret;
    }

    u32 checksum()
    {
        return this->m_checksum;
    }

  private:
    u8 *data;
    u8 curByte;
    u32 curByteIdx;
    u32 curBitIdx;
    u32 size;
    u32 m_checksum;
};

u8 *Pbg3Archive::ReadDecompressEntry(u32 entryIdx, char *filename)
{
    if (entryIdx >= this->numOfEntries)
        return NULL;

    if (this->parser == NULL)
        return NULL;

    u32 size = this->entries[entryIdx].uncompressedSize;
    u8 *out = (u8 *)malloc(size);
    if (out == NULL)
        return NULL;

    u32 expectedCsum;
    u8 *rawData = this->ReadEntryRaw(&size, &expectedCsum, entryIdx);

    if (rawData == NULL)
    {
        free(out);
        return NULL;
    }

    u8 dict[LZSS_DICTSIZE];
    memset(dict, 0, sizeof(dict));
    u32 dictHead = 1;

    u32 bytesWritten = 0;

    BitStream bs = BitStream(rawData, size);
    while (TRUE)
    {
        if (bs.Read(1) != 0)
        {
            u8 c = bs.Read(8);
            out[bytesWritten] = c;
            bytesWritten += 1;
            dict[dictHead] = c;
            dictHead = (dictHead + 1) & LZSS_DICTSIZE_MASK;
        }
        else
        {
            u32 matchOffset = bs.Read(13);
            if (!matchOffset)
                break;

            u32 matchLen = bs.Read(4) + LZSS_MIN_MATCH;

            for (u32 i = 0; i < matchLen; ++i)
            {
                u8 c = dict[(matchOffset + i) & LZSS_DICTSIZE_MASK];
                out[bytesWritten] = c;
                bytesWritten += 1;
                dict[dictHead] = c;
                dictHead = (dictHead + 1) & LZSS_DICTSIZE_MASK;
            }
        }
    }

    if (this->entries[entryIdx].checksum != bs.checksum())
    {
        free(out);
        out = NULL;
    }

    free(rawData);
    return out;
}
}; // namespace th06
