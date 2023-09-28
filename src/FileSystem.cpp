#include <stdio.h>
#include <string.h>

#include "FileSystem.hpp"
#include "Pbg3Archive.hpp"
#include "utils.hpp"

u32 g_LastFileSize;

u8 *OpenPath(char *filepath, int isExternalResource)
{
    // char *slashPos;
    u8 *buf;
    FILE *fileOb;
    size_t fsize;
    // this is pbg3Idx
    i32 pleaseGiveMeC;
    char *entryname;
    i32 i;

    pleaseGiveMeC = -1;
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
            for (i = 0; i < 0x10; i += 1)
            {
                if (g_Pbg3Archives[i] != NULL)
                {
                    pleaseGiveMeC = g_Pbg3Archives[i]->FindEntry(entryname);
                    if (pleaseGiveMeC >= 0)
                    {
                        break;
                    }
                }
            }
        }
        if (pleaseGiveMeC < 0)
        {
            return NULL;
        }
    }
    if (pleaseGiveMeC >= 0)
    {
        DebugPrint2("%s Decode ... \n", entryname);
        buf = g_Pbg3Archives[i]->ReadAndValidateEntry(pleaseGiveMeC, entryname);
        g_LastFileSize = g_Pbg3Archives[i]->GetEntrySize(pleaseGiveMeC);
    }
    else
    {
        DebugPrint2("%s Load ... \n", filepath);
        fileOb = fopen(filepath, "rb");
        if (fileOb == NULL)
        {
            DebugPrint2("error : %s is not found.\n", filepath);
            return NULL;
        }
        else
        {
            fseek(fileOb, 0, SEEK_END);
            fsize = ftell(fileOb);
            g_LastFileSize = fsize;
            fseek(fileOb, 0, SEEK_SET);
            buf = (u8 *)malloc(fsize);
            fread(buf, 1, fsize, fileOb);
            fclose(fileOb);
        }
    }
    return buf;
}

int WriteDataToFile(char *path, void *data, size_t size)
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
