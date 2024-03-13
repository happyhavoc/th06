#pragma once
#include "GameErrorContext.hpp"
#include "ZunResult.hpp"

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))
#define ARRAY_SIZE_SIGNED(x) ((i32)sizeof(x) / (i32)sizeof(x[0]))

ZunResult CheckForRunningGameInstance(void);
void DebugPrint(const char *fmt, ...);
void DebugPrint2(const char *fmt, ...);
