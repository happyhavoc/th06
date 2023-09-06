#include "GameContext.hpp"
#include "GameErrorContext.hpp"
#include "i18n.hpp"

GameContext g_GameContext;
JOYCAPSA g_JoystickCaps;

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

WORD GetJoystickCaps(void)
{
    JOYINFOEX pji;

    pji.dwSize = sizeof(JOYINFOEX);
    pji.dwFlags = JOY_RETURNALL;

    if (joyGetPosEx(0, &pji) != MMSYSERR_NOERROR)
    {
        GameErrorContextLog(&g_GameErrorContext, TH_ERR_NO_PAD_FOUND);
        return 1;
    }

    joyGetDevCapsA(0, &g_JoystickCaps, sizeof(g_JoystickCaps));
    return 0;
}

DWORD SetButtonFromControllerInputs(WORD *outButtons, SHORT controllerButtonToTest, DWORD touhouButton,
                                    DWORD inputButtons)
{
    DWORD mask;

    if (controllerButtonToTest < 0)
    {
        return 0;
    }

    mask = 1 << controllerButtonToTest;

    *outButtons |= (inputButtons & mask ? touhouButton & 0xFFFF : 0);

    return inputButtons & mask ? touhouButton & 0xFFFF : 0;
}

DWORD SetButtonFromDirectInputJoystate(WORD *outButtons, SHORT controllerButtonToTest, DWORD touhouButton,
                                       BYTE *inputButtons)
{
    if (controllerButtonToTest < 0)
    {
        return 0;
    }

    *outButtons |= (inputButtons[controllerButtonToTest] & 0x80 ? touhouButton & 0xFFFF : 0);

    return inputButtons[controllerButtonToTest] & 0x80 ? touhouButton & 0xFFFF : 0;
}
