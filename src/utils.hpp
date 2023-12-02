#pragma once
#include "GameErrorContext.hpp"
#include "ZunResult.hpp"

ZunResult CheckForRunningGameInstance(void);
void DebugPrint(const char *fmt, ...);
void DebugPrint2(const char *fmt, ...);
