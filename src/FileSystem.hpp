#pragma once

#include "inttypes.hpp"

namespace FileSystem
{
u8 *OpenPath(char *filepath, int isExternalResource);
int WriteDataToFile(char *path, void *data, size_t size);
} // namespace FileSystem

extern u32 g_LastFileSize;
