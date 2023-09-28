#pragma once

#include "inttypes.hpp"

u8 *OpenPath(char *filepath, int isExternalResource);
int WriteDataToFile(char *path, void *data, size_t size);

extern u32 g_LastFileSize;
