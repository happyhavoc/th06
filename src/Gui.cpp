#include "Gui.hpp"
#include "Chain.hpp"
#include "ChainPriorities.hpp"

DIFFABLE_STATIC(Gui, g_Gui);
DIFFABLE_STATIC(ChainElem, g_GuiCalcChain);
DIFFABLE_STATIC(ChainElem, g_GuiDrawChain);

#pragma optimize("s", on)
ZunResult Gui::RegisterChain(void)
{
    Gui *gui = &g_Gui;
    if ((i32)(g_Supervisor.curState != SUPERVISOR_STATE_GAMEMANAGER_REINIT))
    {
        memset(gui, 0, sizeof(Gui));
        gui->impl = new GuiImpl();
    }
    g_GuiCalcChain.callback = (ChainCallback)Gui::OnUpdate;
    g_GuiCalcChain.addedCallback = NULL;
    g_GuiCalcChain.deletedCallback = NULL;
    g_GuiCalcChain.addedCallback = (ChainAddedCallback)Gui::AddedCallback;
    g_GuiCalcChain.deletedCallback = (ChainDeletedCallback)Gui::DeletedCallback;
    g_GuiCalcChain.arg = gui;
    if (g_Chain.AddToCalcChain(&g_GuiCalcChain, TH_CHAIN_PRIO_CALC_GUI) != ZUN_SUCCESS)
    {
        return ZUN_ERROR;
    }
    g_GuiDrawChain.callback = (ChainCallback)Gui::OnDraw;
    g_GuiDrawChain.addedCallback = NULL;
    g_GuiDrawChain.deletedCallback = NULL;
    g_GuiDrawChain.arg = gui;
    g_Chain.AddToDrawChain(&g_GuiDrawChain, TH_CHAIN_PRIO_DRAW_GUI);
    return ZUN_SUCCESS;
}
#pragma optimize("", on)

ZunResult Gui::AddedCallback(Gui *gui)
{
    return gui->ActualAddedCallback();
}
