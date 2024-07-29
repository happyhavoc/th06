#include "Enemy.hpp"

void Enemy::Move()
{
    if (!this->flags.unk4)
    {
        this->position.x += g_Supervisor.effectiveFramerateMultiplier * this->axisSpeed.x;
    }
    else
    {
        this->position.x -= g_Supervisor.effectiveFramerateMultiplier * this->axisSpeed.x;
    }
    this->position.y += g_Supervisor.effectiveFramerateMultiplier * this->axisSpeed.y;
    this->position.z += g_Supervisor.effectiveFramerateMultiplier * this->axisSpeed.z;
}
