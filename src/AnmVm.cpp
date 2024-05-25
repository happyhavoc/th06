#include "AnmVm.hpp"

AnmVm::AnmVm()
{
    this->activeSpriteIndex = -1;
}

void AnmVm::Initialize()
{
    this->uvScrollPos.y = 0.0;
    this->uvScrollPos.x = 0.0;
    this->scaleInterpFinalX = 0.0;
    this->scaleInterpFinalY = 0.0;
    this->angleVel.z = 0.0;
    this->angleVel.y = 0.0;
    this->angleVel.x = 0.0;
    this->rotation.z = 0.0;
    this->rotation.y = 0.0;
    this->rotation.x = 0.0;
    this->scaleX = 1.0;
    this->scaleY = 1.0;
    this->scaleInterpEndTime = 0;
    this->alphaInterpEndTime = 0;
    this->color = D3DCOLOR_RGBA(0xff, 0xff, 0xff, 0xff);
    D3DXMatrixIdentity(&this->matrix);
    this->flags.flags = AnmVmFlags_0 | AnmVmFlags_1;
    this->autoRotate = 0;
    this->pendingInterrupt = 0;
    this->posInterpEndTime = 0;
    this->currentTimeInScript.Initialize();
}
