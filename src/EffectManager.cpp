#include "EffectManager.hpp"

#include "AnmManager.hpp"
#include "GameManager.hpp"
#include "ZunResult.hpp"

ZunResult EffectManager::AddedCallback(EffectManager* mgr) {
    mgr->Reset();
    switch(g_GameManager.currentStage) {
        case 0:
        case 1:
            if(g_AnmManager->LoadAnm(0xb, "data/eff01.anm", 0x2b3) != ZUN_SUCCESS) {
                return ZUN_ERROR;
            }
            break;
        case 2:
            if(g_AnmManager->LoadAnm(0xb, "data/eff02.anm", 0x2b3) != ZUN_SUCCESS) {
                return ZUN_ERROR;
            }
            break;
        case 3:
            if(g_AnmManager->LoadAnm(0xb, "data/eff03.anm", 0x2b3) != ZUN_SUCCESS) {
                return ZUN_ERROR;
            }
            break;
        case 4:
            if(g_AnmManager->LoadAnm(0xb, "data/eff04.anm", 0x2b3) != ZUN_SUCCESS) {
                return ZUN_ERROR;
            }
            break;
        case 5:
            if(g_AnmManager->LoadAnm(0xb, "data/eff05.anm", 0x2b3) != ZUN_SUCCESS) {
                return ZUN_ERROR;
            }
            break;
        case 6:
            if(g_AnmManager->LoadAnm(0xb, "data/eff06.anm", 0x2b3) != ZUN_SUCCESS) {
                return ZUN_ERROR;
            }
            break;
        case 7:
            if(g_AnmManager->LoadAnm(0xb, "data/eff07.anm", 0x2b3) != ZUN_SUCCESS) {
                return ZUN_ERROR;
            }
            break;
    }
    return ZUN_SUCCESS;
}

void EffectManager::Reset() {
    memset(this, 0, sizeof(*this));
}

DIFFABLE_STATIC(EffectManager, g_EffectManager);
