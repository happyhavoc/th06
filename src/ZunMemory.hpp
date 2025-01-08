#pragma once

#include <stdlib.h>

namespace th06
{
namespace ZunMemory
{
inline void *Alloc(u32 size)
{
    return malloc(size);
}

inline void Free(void *ptr)
{
    free(ptr);
}
}; // namespace ZunMemory
}; // namespace th06
