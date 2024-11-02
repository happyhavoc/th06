#include "AsciiManager.hpp"

#include "AnmManager.hpp"
#include "ChainPriorities.hpp"
#include "GameManager.hpp"
#include "Supervisor.hpp"
#include "utils.hpp"
#include <stdio.h>

namespace th06
{
DIFFABLE_STATIC(AsciiManager, g_AsciiManager)
DIFFABLE_STATIC(ChainElem, g_AsciiManagerCalcChain)
DIFFABLE_STATIC(ChainElem, g_AsciiManagerOnDrawMenusChain)
DIFFABLE_STATIC(ChainElem, g_AsciiManagerOnDrawPopupsChain)

AsciiManager::AsciiManager()
{
    i32 pad01, pad02, pad03, pad04, pad05, pad06, pad07, pad08;
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
            curPopup->timer.Tick();
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

    if (g_AnmManager->LoadAnm(ANM_FILE_ASCII, "data/ascii.anm", ANM_OFFSET_ASCII) != ZUN_SUCCESS)
    {
        return ZUN_ERROR;
    }
    if (g_AnmManager->LoadAnm(ANM_FILE_ASCIIS, "data/asciis.anm", ANM_OFFSET_ASCIIS) != ZUN_SUCCESS)
    {
        return ZUN_ERROR;
    }
    if (g_AnmManager->LoadAnm(ANM_FILE_CAPTURE, "data/capture.anm", ANM_OFFSET_CAPTURE) != ZUN_SUCCESS)
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

    this->vm1.flags.anchor = AnmVmAnchor_TopLeft;
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
    g_AnmManager->ReleaseAnm(ANM_FILE_ASCII);
    g_AnmManager->ReleaseAnm(ANM_FILE_ASCIIS);
    g_AnmManager->ReleaseAnm(ANM_FILE_CAPTURE);
    return ZUN_SUCCESS;
}

void AsciiManager::CutChain()
{
    g_Chain.Cut(&g_AsciiManagerCalcChain);
    g_Chain.Cut(&g_AsciiManagerOnDrawMenusChain);
    // What about g_AsciiManagerOnDrawPopupsChain? It looks like zun forgot
    // to free it!
}

#pragma var_order(charWidth, i, string, text, guiString, padding_1, padding_2, padding_3)
void AsciiManager::DrawStrings(void)
{
    i32 padding_1;
    i32 padding_2;
    i32 padding_3;
    i32 i;
    BOOL guiString;
    f32 charWidth;
    AsciiManagerString *string;
    u8 *text;

    guiString = TRUE;
    string = this->strings;
    this->vm0.flags.isVisible = 1;
    this->vm0.flags.anchor = AnmVmAnchor_TopLeft;
    for (i = 0; i < this->numStrings; i++, string++)
    {
        this->vm0.pos = string->position;
        text = (u8 *)string->text;
        this->vm0.scaleX = string->scale.x;
        this->vm0.scaleY = string->scale.y;
        charWidth = 14 * string->scale.x;
        if (guiString != string->isGui)
        {
            guiString = string->isGui;
            if (guiString)
            {
                g_Supervisor.viewport.X = g_GameManager.arcadeRegionTopLeftPos.x;
                g_Supervisor.viewport.Y = g_GameManager.arcadeRegionTopLeftPos.y;
                g_Supervisor.viewport.Width = g_GameManager.arcadeRegionSize.x;
                g_Supervisor.viewport.Height = g_GameManager.arcadeRegionSize.y;
                g_Supervisor.d3dDevice->SetViewport(&g_Supervisor.viewport);
            }
            else
            {
                g_Supervisor.viewport.X = 0;
                g_Supervisor.viewport.Y = 0;
                g_Supervisor.viewport.Width = 640;
                g_Supervisor.viewport.Height = 480;
                g_Supervisor.d3dDevice->SetViewport(&g_Supervisor.viewport);
            }
        }
        while (*text != NULL)
        {
            if (*text == '\n')
            {
                this->vm0.pos.y = 16 * string->scale.y + this->vm0.pos.y;
                this->vm0.pos.x = string->position.x;
            }
            else if (*text == ' ')
            {
                this->vm0.pos.x += charWidth;
            }
            else
            {
                if (string->isSelected == FALSE)
                {
                    this->vm0.sprite = &g_AnmManager->sprites[*text - 0x15];
                    this->vm0.color = string->color;
                }
                else
                {
                    this->vm0.sprite = &g_AnmManager->sprites[*text + 0x61];
                    this->vm0.color = 0xFFFFFFFF;
                }
                g_AnmManager->DrawNoRotation(&this->vm0);
                this->vm0.pos.x += charWidth;
            }
            text++;
        }
    }
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
    if (g_Supervisor.cfg.IsSoftwareTexturing())
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
}; // namespace th06
