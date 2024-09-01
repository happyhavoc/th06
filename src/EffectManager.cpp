#include "EffectManager.hpp"

#include "AnmManager.hpp"
#include "Chain.hpp"
#include "ChainPriorities.hpp"
#include "GameManager.hpp"
#include "ZunResult.hpp"
#include "utils.hpp"

DIFFABLE_STATIC(EffectManager, g_EffectManager);

DIFFABLE_STATIC(ChainElem, g_EffectManagerCalcChain);
DIFFABLE_STATIC(ChainElem, g_EffectManagerDrawChain);

DIFFABLE_STATIC_ARRAY_ASSIGN(EffectInfo, 20, g_Effects) = {
    {ANM_SCRIPT_BULLET4_SPAWN_BUBBLE_EXPLOSION_SMALL, NULL},
    {ANM_SCRIPT_BULLET4_SPAWN_BUBBLE_EXPLOSION_SPIRAL, NULL},
    {ANM_SCRIPT_BULLET4_SPAWN_BUBBLE_EXPLOSION_NORMAL, NULL},
    {ANM_SCRIPT_BULLET4_SPAWN_GLOW_1, EffectManager::EffectUpdateCallback2},
    {ANM_SCRIPT_BULLET4_SPAWN_WHITE_PARTICLE, EffectManager::EffectUpdateCallback1},
    {ANM_SCRIPT_BULLET4_SPAWN_RED_PARTICLE, EffectManager::EffectUpdateCallback1},
    {ANM_SCRIPT_BULLET4_SPAWN_GREEN_PARTICLE, EffectManager::EffectUpdateCallback1},
    {ANM_SCRIPT_BULLET4_SPAWN_BLUE_PARTICLE, EffectManager::EffectUpdateCallback1},
    {ANM_SCRIPT_BULLET4_SPAWN_WHITE_PARTICLE_SMALL, EffectManager::EffectUpdateCallback1},
    {ANM_SCRIPT_BULLET4_SPAWN_RED_PARTICLE_SMALL, EffectManager::EffectUpdateCallback1},
    {ANM_SCRIPT_BULLET4_SPAWN_GREEN_PARTICLE_SMALL, EffectManager::EffectUpdateCallback1},
    {ANM_SCRIPT_BULLET4_SPAWN_BLUE_PARTICLE_SMALL, EffectManager::EffectUpdateCallback1},
    {ANM_SCRIPT_BULLET4_SCRIPT_17, NULL},
    {ANM_SCRIPT_BULLET4_SCRIPT_18, EffectManager::EffectUpdateCallback4},
    {ANM_SCRIPT_BULLET4_SCRIPT_18, EffectManager::EffectUpdateCallback4},
    {ANM_SCRIPT_BULLET4_SCRIPT_18, EffectManager::EffectUpdateCallback4},
    {ANM_SCRIPT_EFFECTS_SPELLCARD_BACKGROUND, NULL},
    {ANM_SCRIPT_BULLET4_SPAWN_GLOW_2, EffectManager::EffectUpdateCallback5},
    {ANM_SCRIPT_BULLET4_SPAWN_WHITE_PARTICLE, EffectManager::EffectUpdateCallback6},
    {ANM_SCRIPT_BULLET4_SCRIPT_19, EffectManager::EffectUpdateCallback3},
};

ZunResult EffectManager::RegisterChain()
{
    EffectManager *mgr = &g_EffectManager;
    mgr->Reset();
    g_EffectManagerCalcChain.callback = (ChainCallback)mgr->OnUpdate;
    g_EffectManagerCalcChain.addedCallback = NULL;
    g_EffectManagerCalcChain.deletedCallback = NULL;
    g_EffectManagerCalcChain.addedCallback = (ChainAddedCallback)mgr->AddedCallback;
    g_EffectManagerCalcChain.deletedCallback = (ChainAddedCallback)mgr->AddedCallback;
    g_EffectManagerCalcChain.arg = mgr;
    if (g_Chain.AddToCalcChain(&g_EffectManagerCalcChain, TH_CHAIN_PRIO_CALC_EFFECTMANAGER))
    {
        return ZUN_ERROR;
    }
    g_EffectManagerDrawChain.callback = (ChainCallback)mgr->OnDraw;
    g_EffectManagerDrawChain.addedCallback = NULL;
    g_EffectManagerDrawChain.deletedCallback = NULL;
    g_EffectManagerDrawChain.arg = mgr;
    g_Chain.AddToDrawChain(&g_EffectManagerDrawChain, TH_CHAIN_PRIO_DRAW_EFFECTMANAGER);
    return ZUN_SUCCESS;
}

ZunResult EffectManager::AddedCallback(EffectManager *mgr)
{
    mgr->Reset();
    switch (g_GameManager.currentStage)
    {
    case 0:
    case 1:
        if (g_AnmManager->LoadAnm(ANM_FILE_EFFECTS, "data/eff01.anm", ANM_OFFSET_EFFECTS) != ZUN_SUCCESS)
        {
            return ZUN_ERROR;
        }
        break;
    case 2:
        if (g_AnmManager->LoadAnm(ANM_FILE_EFFECTS, "data/eff02.anm", ANM_OFFSET_EFFECTS) != ZUN_SUCCESS)
        {
            return ZUN_ERROR;
        }
        break;
    case 3:
        if (g_AnmManager->LoadAnm(ANM_FILE_EFFECTS, "data/eff03.anm", ANM_OFFSET_EFFECTS) != ZUN_SUCCESS)
        {
            return ZUN_ERROR;
        }
        break;
    case 4:
        if (g_AnmManager->LoadAnm(ANM_FILE_EFFECTS, "data/eff04.anm", ANM_OFFSET_EFFECTS) != ZUN_SUCCESS)
        {
            return ZUN_ERROR;
        }
        break;
    case 5:
        if (g_AnmManager->LoadAnm(ANM_FILE_EFFECTS, "data/eff05.anm", ANM_OFFSET_EFFECTS) != ZUN_SUCCESS)
        {
            return ZUN_ERROR;
        }
        break;
    case 6:
        if (g_AnmManager->LoadAnm(ANM_FILE_EFFECTS, "data/eff06.anm", ANM_OFFSET_EFFECTS) != ZUN_SUCCESS)
        {
            return ZUN_ERROR;
        }
        break;
    case 7:
        if (g_AnmManager->LoadAnm(ANM_FILE_EFFECTS, "data/eff07.anm", ANM_OFFSET_EFFECTS) != ZUN_SUCCESS)
        {
            return ZUN_ERROR;
        }
        break;
    }
    return ZUN_SUCCESS;
}

void EffectManager::Reset()
{
    memset(this, 0, sizeof(*this));
}

ChainCallbackResult EffectManager::OnUpdate(EffectManager *mgr)
{
    i32 effectIdx;
    Effect *effect;

    effect = &mgr->effects[0];
    mgr->activeEffects = 0;
    for (effectIdx = 0; effectIdx < ARRAY_SIZE_SIGNED(mgr->effects); effectIdx++, effect++)
    {
        if (effect->inUseFlag == 0)
        {
            continue;
        }
        mgr->activeEffects++;
        if (effect->updateCallback != NULL && (effect->updateCallback)(effect) != 1)
        {
            effect->inUseFlag = 0;
        }
        if (g_AnmManager->ExecuteScript(&effect->vm) != 0)
        {
            effect->inUseFlag = 0;
        }
        effect->timer.Tick();
    }
    return CHAIN_CALLBACK_RESULT_CONTINUE;
}

ChainCallbackResult EffectManager::OnDraw(EffectManager *mgr)
{
    int effectIdx;
    Effect *effect;

    effect = &mgr->effects[0];
    for (effectIdx = 0; effectIdx < ARRAY_SIZE_SIGNED(mgr->effects); effectIdx++, effect++)
    {
        if (effect->inUseFlag == 0)
        {
            continue;
        }
        effect->vm.pos = effect->pos1;
        g_AnmManager->Draw3(&effect->vm);
    }
    return CHAIN_CALLBACK_RESULT_CONTINUE;
}

#pragma var_order(effect, idx)
Effect *EffectManager::SpawnParticles(i32 effectIdx, D3DXVECTOR3 *pos, i32 count, ZunColor color)
{
    i32 idx;
    Effect *effect;

    effect = &this->effects[this->nextIndex];
    for (idx = 0; idx < ARRAY_SIZE_SIGNED(this->effects); idx++)
    {
        this->nextIndex++;
        if (this->nextIndex >= ARRAY_SIZE_SIGNED(this->effects))
        {
            this->nextIndex = 0;
        }
        if (effect->inUseFlag)
        {
            if (this->nextIndex == 0)
            {
                effect = &this->effects[0];
            }
            else
            {
                effect++;
            }
            continue;
        }

        effect->inUseFlag = 1;
        effect->effectId = effectIdx;
        effect->pos1 = *pos;

        g_AnmManager->SetAndExecuteScriptIdx(&effect->vm, g_Effects[effectIdx].anmIdx);

        effect->vm.color = color;
        effect->updateCallback = g_Effects[effectIdx].updateCallback;
        effect->timer.InitializeForPopup();
        effect->unk_17a = 0;
        effect->unk_17b = 0;
        count--;

        if (count == 0)
            break;

        if (this->nextIndex == 0)
        {
            effect = &this->effects[0];
        }
        else
        {
            effect++;
        }
    }
    return idx >= ARRAY_SIZE_SIGNED(this->effects) ? &this->dummyEffect : effect;
}