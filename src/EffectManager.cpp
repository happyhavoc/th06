#include "EffectManager.hpp"

#include "AnmManager.hpp"
#include "Chain.hpp"
#include "ChainPriorities.hpp"
#include "GameManager.hpp"
#include "Rng.hpp"
#include "ZunResult.hpp"
#include "utils.hpp"

namespace th06
{
DIFFABLE_STATIC(EffectManager, g_EffectManager);

DIFFABLE_STATIC(ChainElem, g_EffectManagerCalcChain);
DIFFABLE_STATIC(ChainElem, g_EffectManagerDrawChain);

DIFFABLE_STATIC_ARRAY_ASSIGN(EffectInfo, 20, g_Effects) = {
    {ANM_SCRIPT_BULLET4_SPAWN_BUBBLE_EXPLOSION_SMALL, NULL},
    {ANM_SCRIPT_BULLET4_SPAWN_BUBBLE_EXPLOSION_SPIRAL, NULL},
    {ANM_SCRIPT_BULLET4_SPAWN_BUBBLE_EXPLOSION_NORMAL, NULL},
    {ANM_SCRIPT_BULLET4_SPAWN_GLOW_1, EffectManager::EffectCallbackRandomSplashBig},
    {ANM_SCRIPT_BULLET4_SPAWN_WHITE_PARTICLE, EffectManager::EffectCallbackRandomSplash},
    {ANM_SCRIPT_BULLET4_SPAWN_RED_PARTICLE, EffectManager::EffectCallbackRandomSplash},
    {ANM_SCRIPT_BULLET4_SPAWN_GREEN_PARTICLE, EffectManager::EffectCallbackRandomSplash},
    {ANM_SCRIPT_BULLET4_SPAWN_BLUE_PARTICLE, EffectManager::EffectCallbackRandomSplash},
    {ANM_SCRIPT_BULLET4_SPAWN_WHITE_PARTICLE_SMALL, EffectManager::EffectCallbackRandomSplash},
    {ANM_SCRIPT_BULLET4_SPAWN_RED_PARTICLE_SMALL, EffectManager::EffectCallbackRandomSplash},
    {ANM_SCRIPT_BULLET4_SPAWN_GREEN_PARTICLE_SMALL, EffectManager::EffectCallbackRandomSplash},
    {ANM_SCRIPT_BULLET4_SPAWN_BLUE_PARTICLE_SMALL, EffectManager::EffectCallbackRandomSplash},
    {ANM_SCRIPT_BULLET4_SCRIPT_17, NULL},
    {ANM_SCRIPT_BULLET4_SCRIPT_18, EffectManager::EffectUpdateCallback4},
    {ANM_SCRIPT_BULLET4_SCRIPT_18, EffectManager::EffectUpdateCallback4},
    {ANM_SCRIPT_BULLET4_SCRIPT_18, EffectManager::EffectUpdateCallback4},
    {ANM_SCRIPT_EFFECTS_SPELLCARD_BACKGROUND, NULL},
    {ANM_SCRIPT_BULLET4_SPAWN_GLOW_2, EffectManager::EffectCallbackAttract},
    {ANM_SCRIPT_BULLET4_SPAWN_WHITE_PARTICLE, EffectManager::EffectCallbackAttractSlow},
    {ANM_SCRIPT_BULLET4_SCRIPT_19, EffectManager::EffectCallbackStill},
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

void EffectManager::CutChain()
{
    g_Chain.Cut(&g_EffectManagerCalcChain);
    g_Chain.Cut(&g_EffectManagerDrawChain);
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

ZunResult EffectManager::DeletedCallback(EffectManager *p)
{
    g_AnmManager->ReleaseAnm(ANM_FILE_EFFECTS);

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
        if (effect->updateCallback != NULL && (effect->updateCallback)(effect) != EFFECT_CALLBACK_RESULT_DONE)
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

i32 EffectManager::EffectCallbackRandomSplash(Effect *effect)
{
    if (effect->timer == 0 && effect->timer.HasTicked())
    {
        effect->unk_11c.x = (g_Rng.GetRandomF32ZeroToOne() * 256.0f - 128.0f) / 12.0f;
        effect->unk_11c.y = (g_Rng.GetRandomF32ZeroToOne() * 256.0f - 128.0f) / 12.0f;
        effect->unk_11c.z = 0.0f;

        effect->unk_128 = -effect->unk_11c / 19.0f;
    }

    effect->pos1 += effect->unk_11c * g_Supervisor.effectiveFramerateMultiplier;
    effect->unk_11c += effect->unk_128 * g_Supervisor.effectiveFramerateMultiplier;

    return EFFECT_CALLBACK_RESULT_DONE;
}

i32 EffectManager::EffectCallbackRandomSplashBig(Effect *effect)
{
    if (effect->timer == 0 && effect->timer.HasTicked())
    {
        effect->unk_11c.x = (g_Rng.GetRandomF32ZeroToOne() * 256.0f - 128.0f) * 4.0f / 33.0f;
        effect->unk_11c.y = (g_Rng.GetRandomF32ZeroToOne() * 256.0f - 128.0f) * 4.0f / 33.0f;
        effect->unk_11c.z = 0.0f;

        effect->unk_128 = -effect->unk_11c / 20.0f;
    }

    effect->pos1 += effect->unk_11c * g_Supervisor.effectiveFramerateMultiplier;
    effect->unk_11c += effect->unk_128 * g_Supervisor.effectiveFramerateMultiplier;

    return EFFECT_CALLBACK_RESULT_DONE;
}

i32 EffectManager::EffectCallbackStill(Effect *effect)
{
    effect->pos1 += effect->unk_11c * g_Supervisor.effectiveFramerateMultiplier;
    effect->unk_11c += effect->unk_128 * g_Supervisor.effectiveFramerateMultiplier;

    return EFFECT_CALLBACK_RESULT_DONE;
}

#pragma var_order(posOffset, verticalAngle, local_54, horizontalAngle, normalizedPos, alpha)
i32 EffectManager::EffectUpdateCallback4(Effect *effect)
{
    D3DXVECTOR3 posOffset;
    f32 verticalAngle;
    D3DXMATRIX local_54;
    f32 horizontalAngle;
    D3DXVECTOR3 normalizedPos;
    f32 alpha;

    D3DXVec3Normalize(&normalizedPos, &effect->pos2);

    verticalAngle = sinf(effect->angleRelated);
    horizontalAngle = cosf(effect->angleRelated);

    effect->quaternion.x = normalizedPos.x * verticalAngle;
    effect->quaternion.y = normalizedPos.y * verticalAngle;
    effect->quaternion.z = normalizedPos.z * verticalAngle;
    effect->quaternion.w = horizontalAngle;
    D3DXMatrixRotationQuaternion(&local_54, &effect->quaternion);

    posOffset.x = normalizedPos.y * 1.0f - normalizedPos.z * 0.0f;
    posOffset.y = normalizedPos.z * 0.0f - normalizedPos.x * 1.0f;
    posOffset.z = normalizedPos.x * 0.0f - normalizedPos.y * 0.0f;

    if (D3DXVec3LengthSq(&posOffset) < 0)
    {
        normalizedPos = D3DXVECTOR3(1.0f, 0.0f, 0.0f);
    }
    else
    {
        D3DXVec3Normalize(&posOffset, &posOffset);
    }

    posOffset *= effect->unk_15c;
    D3DXVec3TransformCoord(&posOffset, &posOffset, &local_54);
    posOffset.z *= 6.0f;

    effect->pos1 = posOffset + effect->position;

    if (effect->unk_17a)
    {
        effect->unk_17b++;

        if (effect->unk_17b >= 16)
        {
            return EFFECT_CALLBACK_RESULT_STOP;
        }

        alpha = 1.0f - effect->unk_17b / 16.0f;
        effect->vm.color = COLOR_SET_ALPHA3(effect->vm.color, (i32)(alpha * 255.0f));

        effect->vm.scaleY = 2.0f - alpha;
        effect->vm.scaleX = effect->vm.scaleY;
    }

    return EFFECT_CALLBACK_RESULT_DONE;
}

i32 EffectManager::EffectCallbackAttract(Effect *effect)
{
    f32 angle;

    if (effect->timer == 0 && effect->timer.HasTicked())
    {
        effect->position = effect->pos1;

        angle = g_Rng.GetRandomF32ZeroToOne() * ZUN_2PI - ZUN_PI;
        effect->pos2.x = cosf(angle);
        effect->pos2.y = sinf(angle);
        effect->pos2.z = 0.0;
    }

    angle = 256.0f - effect->timer.AsFramesFloat() * 256.0f / 60.0f;

    effect->pos1 = angle * effect->pos2 + effect->position;

    return EFFECT_CALLBACK_RESULT_DONE;
}

i32 EffectManager::EffectCallbackAttractSlow(Effect *effect)
{
    f32 angle;

    if (effect->timer == 0 && effect->timer.HasTicked())
    {
        effect->position = effect->pos1;

        angle = g_Rng.GetRandomF32ZeroToOne() * ZUN_2PI - ZUN_PI;
        effect->pos2.x = cosf(angle);
        effect->pos2.y = sinf(angle);
        effect->pos2.z = 0.0;
    }

    angle = 256.0f - effect->timer.AsFramesFloat() * 256.0f / 240.0f;

    effect->pos1 = angle * effect->pos2 + effect->position;

    return EFFECT_CALLBACK_RESULT_DONE;
}

}; // namespace th06
