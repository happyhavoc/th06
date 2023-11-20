#include <windows.h>

#include "GameErrorContext.hpp"
#include <stdio.h>

DIFFABLE_STATIC(GameErrorContext, g_GameErrorContext)

const char *GameErrorContextFatal(GameErrorContext *ctx, const char *fmt, ...)
{
    char tmpBuffer[512];
    size_t tmpBufferSize;
    va_list args;

    va_start(args, fmt);
    vsprintf(tmpBuffer, fmt, args);

    tmpBufferSize = strlen(tmpBuffer);

    if (ctx->m_BufferEnd + tmpBufferSize < &ctx->m_Buffer[sizeof(ctx->m_Buffer) - 1])
    {
        strcpy(ctx->m_BufferEnd, tmpBuffer);

        ctx->m_BufferEnd += tmpBufferSize;
        *ctx->m_BufferEnd = '\0';
    }

    va_end(args);

    ctx->m_ShowMessageBox = true;

    return fmt;
}

const char *GameErrorContextLog(GameErrorContext *ctx, const char *fmt, ...)
{
    char tmpBuffer[512];
    size_t tmpBufferSize;
    va_list args;

    va_start(args, fmt);
    vsprintf(tmpBuffer, fmt, args);

    tmpBufferSize = strlen(tmpBuffer);

    if (ctx->m_BufferEnd + tmpBufferSize < &ctx->m_Buffer[sizeof(ctx->m_Buffer) - 1])
    {
        strcpy(ctx->m_BufferEnd, tmpBuffer);

        ctx->m_BufferEnd += tmpBufferSize;
        *ctx->m_BufferEnd = '\0';
    }

    va_end(args);

    return fmt;
}

void GameErrorContext::Flush()
{
    FILE *logFile;

    if (m_BufferEnd != m_Buffer)
    {
        GameErrorContextLog(this, TH_ERR_LOGGER_END);

        if (m_ShowMessageBox)
        {
            MessageBoxA(NULL, m_Buffer, "log", MB_ICONERROR);
        }

        logFile = fopen("./log.txt", "wt");

        fprintf(logFile, m_Buffer);
        fclose(logFile);
    }
}
