#include "AsciiManager.hpp"

#include "AnmManager.hpp"
#include "ChainPriorities.hpp"
#include "GameManager.hpp"
#include "Supervisor.hpp"

DIFFABLE_STATIC(AsciiManager, g_AsciiManager)
DIFFABLE_STATIC(ChainElem, g_AsciiManagerCalcChain)
DIFFABLE_STATIC(ChainElem, g_AsciiManagerOnDrawMenusChain)
DIFFABLE_STATIC(ChainElem, g_AsciiManagerOnDrawHighPrioChain)

AsciiManager::AsciiManager()
{
}

StageMenu::StageMenu()
{
    // TODO: Stub
}

ChainCallbackResult AsciiManager::OnUpdate(AsciiManager *mgr)
{
    if (!g_GameManager.isInGameMenu && !g_GameManager.isInRetryMenu)
    {
        AsciiManagerPopup *curPopup = &mgr->popups[0];
        i32 i = 0;
        for (; i < (int)(sizeof(mgr->popups) / sizeof(mgr->popups[0])); i++, curPopup++)
        {
            if (!curPopup->inUse)
            {
                continue;
            }
            curPopup->position.y -= 0.5 * g_Supervisor.effectiveFramerateMultiplier;
            AnmTimer *timer = &curPopup->timer;
            timer->previous = timer->current;
            g_Supervisor.TickTimer(&timer->current, &timer->subFrame);
            curPopup->inUse = curPopup->timer.current > 60;
        }
    }
    if (g_GameManager.isInGameMenu)
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

    g_AsciiManagerOnDrawHighPrioChain.callback = (ChainCallback)OnDrawHighPrio;
    g_AsciiManagerOnDrawHighPrioChain.addedCallback = NULL;
    g_AsciiManagerOnDrawHighPrioChain.deletedCallback = NULL;
    g_AsciiManagerOnDrawHighPrioChain.arg = mgr;
    g_Chain.AddToDrawChain(&g_AsciiManagerOnDrawHighPrioChain, TH_CHAIN_PRIO_DRAW_ASCIIMANAGER_HIGHPRIO);

    return ZUN_SUCCESS;
}

ChainCallbackResult AsciiManager::OnDrawHighPrio(AsciiManager *s)
{
    // TODO: Stub
    return CHAIN_CALLBACK_RESULT_EXIT_GAME_SUCCESS;
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

void AsciiManager::InitializeVms()
{
    // TODO: Stub
}

void AsciiManager::DeletedCallback(AsciiManager *s)
{
    // TODO: Stub
}

void AsciiManager::DrawStrings()
{
    // TODO: Stub
}

i32 StageMenu::OnUpdateGameMenu()
{
    // TODO: Stub
    return 1;
}

i32 StageMenu::OnUpdateRetryMenu()
{
    // TODO: Stub
    return 1;
}

void StageMenu::OnDrawGameMenu()
{
    // TODO: Stub
}

void StageMenu::OnDrawRetryMenu()
{
    // TODO: Stub
}
