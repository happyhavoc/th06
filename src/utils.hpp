#pragma once
#include "GameErrorContext.hpp"
#include "ZunResult.hpp"

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))
#define ARRAY_SIZE_SIGNED(x) ((i32)sizeof(x) / (i32)sizeof(x[0]))

#define ZUN_BIT(a) (1 << (a))
#define ZUN_MASK(a) (ZUN_BIT(a) - 1)
#define ZUN_RANGE(a, count) (ZUN_MASK((a) + (count)) & ~ZUN_MASK(a))
#define ZUN_CLEAR_BITS(a, keep_mask) (a & ~keep_mask)

ZunResult CheckForRunningGameInstance(void);
void DebugPrint(const char *fmt, ...);
void DebugPrint2(const char *fmt, ...);
