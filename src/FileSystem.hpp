#pragma once

#include "ZunResult.hpp"
#include "diffbuild.hpp"
#include "inttypes.hpp"

namespace th06
{
namespace FileSystem
{
u8 *OpenPath(const char *filepath, int isExternalResource);
int WriteDataToFile(const char *path, void *data, std::size_t size);
} // namespace FileSystem
DIFFABLE_EXTERN(u32, g_LastFileSize)
}; // namespace th06
