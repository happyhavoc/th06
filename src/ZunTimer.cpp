#include "ZunTimer.hpp"
#include "Supervisor.hpp"

ZunTimer::ZunTimer()
{
    this->current = 0;
    this->previous = -1;
    this->subFrame = 0.0;
}
