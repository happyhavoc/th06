#pragma once

#include "inttypes.hpp"
#include <Windows.h>

struct MidiOutput
{
    i32 UnprepareHeader(LPMIDIHDR param_1);
};
