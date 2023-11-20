#include <stdio.h>
#include <string.h>

#include "FileSystem.hpp"
#include "Pbg3Archive.hpp"
#include "utils.hpp"

DIFFABLE_STATIC(u32, g_LastFileSize)

#pragma var_order(pbg3Idx, entryname, entryIdx, fsize, data, file)
u8 *FileSystem::OpenPath(char *filepath, int isExternalResource)
{
    u8 *data;
    FILE *file;
    size_t fsize;
    i32 entryIdx;
    char *entryname;
    i32 pbg3Idx;

    entryIdx = -1;
    if (isExternalResource == 0)
    {
        entryname = strrchr(filepath, '\\');
        if (entryname == (char *)0x0)
        {
            entryname = filepath;
        }
        else
        {
            entryname = entryname + 1;
        }
        entryname = strrchr(entryname, '/');
        if (entryname == (char *)0x0)
        {
            entryname = filepath;
        }
        else
        {
            entryname = entryname + 1;
        }
        if (g_Pbg3Archives != NULL)
        {
            for (pbg3Idx = 0; pbg3Idx < 0x10; pbg3Idx += 1)
            {
                if (g_Pbg3Archives[pbg3Idx] != NULL)
                {
                    entryIdx = g_Pbg3Archives[pbg3Idx]->FindEntry(entryname);
                    if (entryIdx >= 0)
                    {
                        break;
                    }
                }
            }
        }
        if (entryIdx < 0)
        {
            return NULL;
        }
    }
    if (entryIdx >= 0)
    {
        DebugPrint2("%s Decode ... \n", entryname);
        data = g_Pbg3Archives[pbg3Idx]->ReadAndValidateEntry(entryIdx, entryname);
        g_LastFileSize = g_Pbg3Archives[pbg3Idx]->GetEntrySize(entryIdx);
    }
    else
    {
        DebugPrint2("%s Load ... \n", filepath);
        file = fopen(filepath, "rb");
        if (file == NULL)
        {
            DebugPrint2("error : %s is not found.\n", filepath);
            return NULL;
        }
        else
        {
            fseek(file, 0, SEEK_END);
            fsize = ftell(file);
            g_LastFileSize = fsize;
            fseek(file, 0, SEEK_SET);
            data = (u8 *)malloc(fsize);
            fread(data, 1, fsize, file);
            fclose(file);
        }
    }
    return data;
}

int FileSystem::WriteDataToFile(char *path, void *data, size_t size)
{
    FILE *f;

    f = fopen(path, "wb");
    if (f == (FILE *)0x0)
    {
        return -1;
    }
    else
    {
        if (fwrite(data, 1, size, f) != size)
        {
            fclose(f);
            return -2;
        }
        else
        {
            fclose(f);
            return 0;
        }
    }
}
