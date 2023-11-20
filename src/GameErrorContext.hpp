#pragma once

#include <windows.h>

#include "diffbuild.hpp"
#include "i18n.hpp"
#include "inttypes.hpp"

class GameErrorContext;

const char *GameErrorContextFatal(GameErrorContext *ctx, const char *fmt, ...);
const char *GameErrorContextLog(GameErrorContext *ctx, const char *fmt, ...);

class GameErrorContext
{
  public:
    char m_Buffer[0x800];
    char *m_BufferEnd;
    u8 m_ShowMessageBox;

    GameErrorContext()
    {
        m_BufferEnd = m_Buffer;
        m_Buffer[0] = '\0';
        // Required to get some mov eax, [m_Buffer_ptr]
        m_ShowMessageBox = false;
        GameErrorContextLog(this, TH_ERR_LOGGER_END);
    }

    ~GameErrorContext()
    {
    }

    void RstContext()
    {
        m_BufferEnd = m_Buffer;
        m_Buffer[0] = '\0';
    }

    void Flush();
};

DIFFABLE_EXTERN(GameErrorContext, g_GameErrorContext)
