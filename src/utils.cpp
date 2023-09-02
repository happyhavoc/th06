#include <windows.h>

#include "i18n.hpp"
#include "utils.hpp"

HANDLE g_ExclusiveMutex;

int CheckForRunningGameInstance(void)
{
    g_ExclusiveMutex = CreateMutex(NULL, TRUE, TEXT("Touhou Koumakyou App"));

    if (g_ExclusiveMutex == NULL)
    {
        return -1;
    }
    else if (GetLastError() == ERROR_ALREADY_EXISTS)
    {
        GameErrorContextFatal(&g_GameErrorContext, TH_ERR_ALREADY_RUNNING);
        return -1;
    }

    return 0;
}