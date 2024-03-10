#include "ZunTimer.hpp"
#include "Supervisor.hpp"

ZunTimer::ZunTimer()
{
    this->current = 0;
    this->previous = -1;
    this->subFrame = 0.0;
}

#pragma optimize("s", on)
void ZunTimer::Increment(i32 value)
{
    if (g_Supervisor.framerateMultiplier > 0.99f)
    {
        this->current = this->current + value;
    }
    else
    {
        if (value < 0)
        {
            Decrement(-value);
        }
        else
        {
            this->previous = this->current;
            this->subFrame = g_Supervisor.effectiveFramerateMultiplier * (float)value + this->subFrame;

            while (this->subFrame >= 1.0f)
            {
                this->current++;
                this->subFrame = this->subFrame - 1.0f;
            }
        }
    }
}

void ZunTimer::Decrement(i32 value)
{
    if (g_Supervisor.framerateMultiplier > 0.99f)
    {
        this->current = this->current - value;
    }
    else
    {
        if (value < 0)
        {
            Increment(-value);
        }
        else
        {
            this->previous = this->current;
            this->subFrame = this->subFrame - g_Supervisor.effectiveFramerateMultiplier * (float)value;

            while (this->subFrame < 0.0f)
            {
                this->current--;
                this->subFrame = this->subFrame + 1.0f;
            }
        }
    }
}
#pragma optimize("s", off)
