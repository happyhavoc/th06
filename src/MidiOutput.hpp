#pragma once

#include "ZunResult.hpp"
#include "inttypes.hpp"
#include <Windows.h>

struct MidiOutput
{
    MidiOutput();
    ~MidiOutput();

    ZunResult UnprepareHeader(LPMIDIHDR param_1);
};
