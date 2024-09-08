#pragma once

#include <windows.h>

#include "diffbuild.hpp"
#include "i18n.hpp"
#include "inttypes.hpp"

namespace th06
{
class GameErrorContext;

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
        Log(this, TH_ERR_LOGGER_START);
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

    static const char *Fatal(GameErrorContext *ctx, const char *fmt, ...);
    static const char *Log(GameErrorContext *ctx, const char *fmt, ...);
};

DIFFABLE_EXTERN(GameErrorContext, g_GameErrorContext)
}; // namespace th06
