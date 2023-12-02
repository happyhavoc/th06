#pragma once

#include "ZunResult.hpp"
#include "inttypes.hpp"
#include <Windows.h>

struct MidiOutput
{
    ZunResult UnprepareHeader(LPMIDIHDR param_1);
};
