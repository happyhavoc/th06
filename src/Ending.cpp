#include "Ending.hpp"
#include "AnmManager.hpp"
#include "Supervisor.hpp"

i32 Ending::DeletedCallback(void)
{
    AnmManager *anmManager;
    g_AnmManager->ReleaseAnm(44);
    g_AnmManager->ReleaseAnm(45);
    g_AnmManager->ReleaseAnm(46);

    g_Supervisor.curState = 7;
    g_AnmManager->ReleaseSurface(0);
    anmManager = g_AnmManager;
    free(this->endFileData);
    g_Chain.Cut(this->chainElem);
    this->chainElem = (ChainElem *)0x0;
    anmManager = g_AnmManager;
    free(this);
    g_Supervisor.isInEnding = 0;
    g_Supervisor.ReleasePbg3(5);
    return 0;
}