#include <windows.h>

#include "i18n.hpp"
#include "utils.hpp"

DIFFABLE_STATIC(HANDLE, g_ExclusiveMutex)

i32 CheckForRunningGameInstance(void)
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

void DebugPrint(const char *fmt, ...)
{
#ifdef DEBUG
    char tmpBuffer[512];

    va_start(args, fmt);
    vsprintf(tmpBuffer, fmt, args);
    va_end(args, fmt);

    printf("DEBUG2: %s\n", tmpBuffer);
#endif
}

void DebugPrint2(const char *fmt, ...)
{
#ifdef DEBUG
    char tmpBuffer[512];

    va_start(args, fmt);
    vsprintf(tmpBuffer, fmt, args);
    va_end(args, fmt);

    printf("DEBUG2: %s\n", tmpBuffer);
#endif
}
