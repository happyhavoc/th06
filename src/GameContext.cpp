#include "GameContext.hpp"
#include "GameErrorContext.hpp"
#include "i18n.hpp"

GameContext g_GameContext;

int InitD3dInterface(void)
{
    g_GameContext.d3dIface = Direct3DCreate8(D3D_SDK_VERSION);

    if (g_GameContext.d3dIface == NULL)
    {
        GameErrorContextFatal(&g_GameErrorContext, TH_ERR_D3D_ERR_COULD_NOT_CREATE_OBJ);
        return 1;
    }
    return 0;
}

// TODO: Implement this.
int GameContext::Parse(char *path)
{
    return -1;
}
