#include "AsciiManager.hpp"

#include "AnmManager.hpp"
#include "ChainPriorities.hpp"
#include "GameManager.hpp"
#include "Supervisor.hpp"
#include "utils.hpp"
#include <stdio.h>

DIFFABLE_STATIC(AsciiManager, g_AsciiManager)
DIFFABLE_STATIC(ChainElem, g_AsciiManagerCalcChain)
DIFFABLE_STATIC(ChainElem, g_AsciiManagerOnDrawMenusChain)
DIFFABLE_STATIC(ChainElem, g_AsciiManagerOnDrawPopupsChain)

AsciiManager::AsciiManager()
{
}

StageMenu::StageMenu()
{
}

ChainCallbackResult AsciiManager::OnUpdate(AsciiManager *mgr)
{
    if (!g_GameManager.isInGameMenu && !g_GameManager.isInRetryMenu)
    {
        AsciiManagerPopup *curPopup = &mgr->popups[0];
        i32 i = 0;
        for (; i < ARRAY_SIZE_SIGNED(mgr->popups); i++, curPopup++)
        {
            if (!curPopup->inUse)
            {
                continue;
            }

            curPopup->position.y -= 0.5f * g_Supervisor.effectiveFramerateMultiplier;
            ZunTimer *timer = &curPopup->timer;
            timer->previous = timer->current;
            g_Supervisor.TickTimer(&timer->current, &timer->subFrame);
            if ((bool)(curPopup->timer.current > 60))
            {
                curPopup->inUse = false;
            }
        }
    }
    else if (g_GameManager.isInGameMenu)
    {
        mgr->gameMenu.OnUpdateGameMenu();
    }
    if (g_GameManager.isInRetryMenu)
    {
        mgr->retryMenu.OnUpdateRetryMenu();
    }

    return CHAIN_CALLBACK_RESULT_CONTINUE;
}

ChainCallbackResult AsciiManager::OnDrawMenus(AsciiManager *mgr)
{
    mgr->DrawStrings();
    mgr->numStrings = 0;
    mgr->gameMenu.OnDrawGameMenu();
    mgr->retryMenu.OnDrawRetryMenu();
    return CHAIN_CALLBACK_RESULT_CONTINUE;
}

ChainCallbackResult AsciiManager::OnDrawPopups(AsciiManager *mgr)
{
    if (g_Supervisor.hasD3dHardwareVertexProcessing)
    {
        mgr->DrawPopupsWithHwVertexProcessing();
    }
    else
    {
        mgr->DrawPopupsWithoutHwVertexProcessing();
    }
    return CHAIN_CALLBACK_RESULT_CONTINUE;
}

ZunResult AsciiManager::RegisterChain()
{
    AsciiManager *mgr = &g_AsciiManager;

    g_AsciiManagerCalcChain.callback = (ChainCallback)AsciiManager::OnUpdate;
    g_AsciiManagerCalcChain.addedCallback = NULL;
    g_AsciiManagerCalcChain.deletedCallback = NULL;
    g_AsciiManagerCalcChain.addedCallback = (ChainAddedCallback)AsciiManager::AddedCallback;
    g_AsciiManagerCalcChain.deletedCallback = (ChainDeletedCallback)AsciiManager::DeletedCallback;
    g_AsciiManagerCalcChain.arg = mgr;
    if (g_Chain.AddToCalcChain(&g_AsciiManagerCalcChain, TH_CHAIN_PRIO_CALC_ASCIIMANAGER) != ZUN_SUCCESS)
    {
        return ZUN_ERROR;
    }

    g_AsciiManagerOnDrawMenusChain.callback = (ChainCallback)OnDrawMenus;
    g_AsciiManagerOnDrawMenusChain.addedCallback = NULL;
    g_AsciiManagerOnDrawMenusChain.deletedCallback = NULL;
    g_AsciiManagerOnDrawMenusChain.arg = mgr;
    g_Chain.AddToDrawChain(&g_AsciiManagerOnDrawMenusChain, TH_CHAIN_PRIO_DRAW_ASCIIMANAGER_MENUS);

    g_AsciiManagerOnDrawPopupsChain.callback = (ChainCallback)OnDrawPopups;
    g_AsciiManagerOnDrawPopupsChain.addedCallback = NULL;
    g_AsciiManagerOnDrawPopupsChain.deletedCallback = NULL;
    g_AsciiManagerOnDrawPopupsChain.arg = mgr;
    g_Chain.AddToDrawChain(&g_AsciiManagerOnDrawPopupsChain, TH_CHAIN_PRIO_DRAW_ASCIIMANAGER_POPUPS);

    return ZUN_SUCCESS;
}

ZunResult AsciiManager::AddedCallback(AsciiManager *s)
{
    int x, y, z;

    if (g_AnmManager->LoadAnm(1, "data/ascii.anm", 0) != ZUN_SUCCESS)
    {
        return ZUN_ERROR;
    }
    if (g_AnmManager->LoadAnm(2, "data/asciis.anm", 0x77) != ZUN_SUCCESS)
    {
        return ZUN_ERROR;
    }
    if (g_AnmManager->LoadAnm(3, "data/capture.anm", 0x718) != ZUN_SUCCESS)
    {
        return ZUN_ERROR;
    }
    s->InitializeVms();
    return ZUN_SUCCESS;
}

#pragma var_order(vm1, mgr1, mgr0)
void AsciiManager::InitializeVms()
{
    memset(this, 0, sizeof(AsciiManager));

    this->color = 0xffffffff;
    this->scale.x = 1.0;
    this->scale.y = 1.0;

    // TODO: What is this flag for?
    this->vm1.flags.flags |= AnmVmFlags_9 | AnmVmFlags_8;
    AnmVm *vm1 = &this->vm1;
    AnmManager *mgr1 = g_AnmManager;
    vm1->Initialize();
    mgr1->SetActiveSprite(vm1, 0);

    AnmManager *mgr0 = g_AnmManager;
    this->vm0.Initialize();
    mgr0->SetActiveSprite(&this->vm0, 0x20);

    this->vm1.pos.z = 0.1;
    this->isSelected = 0;
}

ZunResult AsciiManager::DeletedCallback(AsciiManager *s)
{
    g_AnmManager->ReleaseAnm(1);
    g_AnmManager->ReleaseAnm(2);
    g_AnmManager->ReleaseAnm(3);
    return ZUN_SUCCESS;
}

void AsciiManager::CutChain()
{
    g_Chain.Cut(&g_AsciiManagerCalcChain);
    g_Chain.Cut(&g_AsciiManagerOnDrawMenusChain);
    // What about g_AsciiManagerOnDrawPopupsChain? It looks like zun forgot
    // to free it!
}

void AsciiManager::AddString(D3DXVECTOR3 *position, char *text)
{
    if (this->numStrings >= 0x100)
    {
        return;
    }

    AsciiManagerString *curString = &this->strings[this->numStrings];
    this->numStrings += 1;
    // Hello unguarded strcpy my old friend. If text is bigger than 64
    // characters, kboom.
    strcpy(curString->text, text);
    curString->position = *position;
    curString->color = this->color;
    curString->scale.x = this->scale.x;
    curString->scale.y = this->scale.y;
    curString->isGui = this->isGui;
    if (((g_Supervisor.cfg.opts >> GCOS_USE_D3D_HW_TEXTURE_BLENDING & 1) |
         (g_Supervisor.cfg.opts >> GCOS_NO_COLOR_COMP) & 1) != 0)
    {
        curString->isSelected = this->isSelected;
    }
    else
    {
        curString->isSelected = 0;
    }
}

void AsciiManager::AddFormatText(D3DXVECTOR3 *position, const char *fmt, ...)
{
    char tmpBuffer[512];
    va_list args;

    va_start(args, fmt);
    vsprintf(tmpBuffer, fmt, args);
    AddString(position, tmpBuffer);

    va_end(args);
}

void AsciiManager::CreatePopup1(D3DXVECTOR3 *position, i32 value, D3DCOLOR color)
{
    AsciiManagerPopup *popup;
    i32 characterCount;

    if (this->nextPopupIndex1 >= (ARRAY_SIZE_SIGNED(this->popups) - 3))
    {
        this->nextPopupIndex1 = 0;
    }

    popup = &this->popups[this->nextPopupIndex1];
    popup->inUse = 1;
    characterCount = 0;

    if (value >= 0)
    {
        while (value)
        {
            popup->digits[characterCount++] = (char)(value % 10);

            value /= 10;
        }
    }
    else
    {
        popup->digits[characterCount++] = '\n';
    }

    if (characterCount == 0)
    {
        popup->digits[characterCount++] = '\0';
    }

    popup->characterCount = characterCount;
    popup->color = color;
    popup->timer.InitializeForPopup();
    popup->position = *position;

    this->nextPopupIndex1++;
}

void AsciiManager::CreatePopup2(D3DXVECTOR3 *position, i32 value, D3DCOLOR color)
{
    AsciiManagerPopup *popup;
    i32 characterCount;

    if (this->nextPopupIndex2 >= 3)
    {
        this->nextPopupIndex2 = 0;
    }

    popup = &this->popups[0x200 + this->nextPopupIndex2];
    popup->inUse = 1;
    characterCount = 0;

    if (value >= 0)
    {
        while (value)
        {
            popup->digits[characterCount++] = (char)(value % 10);

            value /= 10;
        }
    }
    else
    {
        popup->digits[characterCount++] = '\n';
    }

    if (characterCount == 0)
    {
        popup->digits[characterCount++] = '\0';
    }

    popup->characterCount = characterCount;
    popup->color = color;
    popup->timer.InitializeForPopup();
    popup->position = *position;

    this->nextPopupIndex2++;
}
