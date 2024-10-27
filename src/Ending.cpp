#include "Ending.hpp"
#include "Chain.hpp"
#include "ChainPriorities.hpp"

namespace th06
{

ZunResult Ending::RegisterChain()
{
    Ending *ending;

    ending = new Ending();
    ending->calcChain = g_Chain.CreateElem((ChainCallback)Ending::OnUpdate);
    ending->calcChain->arg = ending;
    ending->calcChain->addedCallback = (ChainAddedCallback)Ending::AddedCallback;
    ending->calcChain->deletedCallback = (ChainDeletedCallback)Ending::DeletedCallback;
    if (g_Chain.AddToCalcChain(ending->calcChain, TH_CHAIN_PRIO_CALC_ENDING))
    {
        return ZUN_ERROR;
    }

    ending->drawChain = g_Chain.CreateElem((ChainCallback)Ending::OnDraw);
    ending->drawChain->arg = ending;
    g_Chain.AddToDrawChain(ending->drawChain, TH_CHAIN_PRIO_DRAW_ENDING);

    return ZUN_SUCCESS;
}
}; // namespace th06