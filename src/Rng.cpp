#include "Rng.hpp"

DIFFABLE_STATIC(Rng, g_Rng);

unsigned short Rng::GetRandomU16(void)
{
    unsigned short a = (this->seed ^ 0x9630) - 0x6553;

    this->seed = (((a & 0xc000) >> 14) + a * 4) & 0xFFFF;
    this->generationCount++;
    return this->seed;
}

unsigned int Rng::GetRandomU32(void)
{
    return GetRandomU16() << 16 | GetRandomU16();
}

float Rng::GetRandomF32ZeroToOne(void)
{
    return (float)GetRandomU32() / (float)0xFFFFFFFF;
}
