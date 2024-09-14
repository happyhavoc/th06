#include "GuiImpl.hpp"

#include "AnmManager.hpp"
#include "ZunColor.hpp"

namespace th06
{

#pragma var_order(dialogueBoxHeight, vertices)
#pragma optimize("s", on)
ZunResult GuiImpl::DrawDialogue()
{
    f32 dialogueBoxHeight;

    if (this->msg.currentMsgIdx < 0)
    {
        return ZUN_ERROR;
    }
    if (g_GameManager.currentStage == 6 && (this->msg.currentMsgIdx == 1 || this->msg.currentMsgIdx == 11))
    {
        return ZUN_SUCCESS;
    }
    if ((i32)(this->msg.timer.current < 60))
    {
        dialogueBoxHeight = this->msg.timer.AsFramesFloat() * 48.0f / 60.0f;
    }
    else
    {
        dialogueBoxHeight = 48.0f;
    }
    VertexDiffuseXyzrwh vertices[4];
    // Probably not what Zun wrote, but I don't like Zun's design. My guess is
    // Zun made a separate vertex structure with a D3DXVECTOR3 for the xyz, a
    // separate f32 for the w, and a D3DCOLOR for the diffuse. This kinda makes
    // no sense though - the position is a D3DXVECTOR4.
    memcpy(&vertices[0].position,
           &D3DXVECTOR3(g_GameManager.arcadeRegionTopLeftPos.x + (g_GameManager.arcadeRegionSize.x - 256.0f) / 2.0f -
                            16.0f,
                        384.0f, 0.0f),
           sizeof(D3DXVECTOR3));

    memcpy(&vertices[1].position,
           &D3DXVECTOR3(g_GameManager.arcadeRegionTopLeftPos.x + (g_GameManager.arcadeRegionSize.x - 256.0f) / 2.0f +
                            256.0f + 16.0f,
                        384.0f, 0.0f),
           sizeof(D3DXVECTOR3));

    memcpy(&vertices[2].position,
           &D3DXVECTOR3(g_GameManager.arcadeRegionTopLeftPos.x + (g_GameManager.arcadeRegionSize.x - 256.0f) / 2.0f -
                            16.0f,
                        384.0f + dialogueBoxHeight, 0.0f),
           sizeof(D3DXVECTOR3));

    memcpy(&vertices[3].position,
           &D3DXVECTOR3(g_GameManager.arcadeRegionTopLeftPos.x + (g_GameManager.arcadeRegionSize.x - 256.0f) / 2.0f +
                            256.0f + 16.0f,
                        384.0f + dialogueBoxHeight, 0.0f),
           sizeof(D3DXVECTOR3));

    vertices[0].diffuse = vertices[1].diffuse = 0xd0000000;
    vertices[2].diffuse = vertices[3].diffuse = 0x90000000;
    vertices[0].position.w = vertices[1].position.w = vertices[2].position.w = vertices[3].position.w = 1.0f;
    g_AnmManager->DrawNoRotation(&this->msg.portraits[0]);
    g_AnmManager->DrawNoRotation(&this->msg.portraits[1]);
    if (((g_Supervisor.cfg.opts >> GCOS_NO_COLOR_COMP) & 1) == 0)
    {
        g_Supervisor.d3dDevice->SetTextureStageState(0, D3DTSS_ALPHAOP, D3DTOP_SELECTARG1);
        g_Supervisor.d3dDevice->SetTextureStageState(0, D3DTSS_COLOROP, D3DTOP_SELECTARG1);
    }
    g_Supervisor.d3dDevice->SetTextureStageState(0, D3DTSS_ALPHAARG1, D3DTA_DIFFUSE);
    g_Supervisor.d3dDevice->SetTextureStageState(0, D3DTSS_COLORARG1, D3DTA_DIFFUSE);
    if (((g_Supervisor.cfg.opts >> GCOS_TURN_OFF_DEPTH_TEST) & 1) == 0)
    {
        g_Supervisor.d3dDevice->SetRenderState(D3DRS_ZWRITEENABLE, 0);
    }
    g_Supervisor.d3dDevice->SetVertexShader(D3DFVF_DIFFUSE | D3DFVF_XYZRHW);
    g_Supervisor.d3dDevice->DrawPrimitiveUP(D3DPT_TRIANGLESTRIP, 2, vertices, sizeof(vertices[0]));
    g_AnmManager->SetCurrentVertexShader(0xff);
    g_AnmManager->SetCurrentColorOp(0xff);
    g_AnmManager->SetCurrentBlendMode(0xff);
    g_AnmManager->SetCurrentZWriteDisable(0xff);
    if (((g_Supervisor.cfg.opts >> GCOS_NO_COLOR_COMP) & 1) == 0)
    {
        g_Supervisor.d3dDevice->SetTextureStageState(0, D3DTSS_ALPHAOP, 4);
        g_Supervisor.d3dDevice->SetTextureStageState(0, D3DTSS_COLOROP, 4);
    }
    g_Supervisor.d3dDevice->SetTextureStageState(0, D3DTSS_ALPHAARG1, 2);
    g_Supervisor.d3dDevice->SetTextureStageState(0, D3DTSS_COLORARG1, 2);
    g_AnmManager->DrawNoRotation(&this->msg.dialogueLines[0]);
    g_AnmManager->DrawNoRotation(&this->msg.dialogueLines[1]);
    g_AnmManager->DrawNoRotation(&this->msg.introLines[0]);
    g_AnmManager->DrawNoRotation(&this->msg.introLines[1]);
    return ZUN_SUCCESS;
}
#pragma optimize("", on)

#pragma optimize("s", on)
void GuiImpl::MsgRead(i32 msgIdx)
{
    MsgRawHeader *msgFile;

    if (this->msg.msgFile->numEntries <= msgIdx)
    {
        return;
    }
    msgFile = this->msg.msgFile;
    memset(&this->msg, 0, sizeof(GuiMsgVm));
    this->msg.currentMsgIdx = msgIdx;
    this->msg.msgFile = msgFile;
    this->msg.currentInstr = this->msg.msgFile->entries[msgIdx];
    this->msg.dialogueLines[0].anmFileIndex = -1;
    this->msg.dialogueLines[1].anmFileIndex = -1;
    this->msg.fontSize = 15;
    this->msg.textColorsA[0] = COLOR_RGB(COLOR_GUI_1);
    this->msg.textColorsA[1] = COLOR_RGB(COLOR_GUI_2);
    this->msg.textColorsB[0] = 0;
    this->msg.textColorsB[1] = 0;
    this->msg.dialogueSkippable = 1;
    if (g_GameManager.currentStage == 6 && (msgIdx == 0 || msgIdx == 10))
    {
        g_AnmManager->LoadAnm(ANM_FILE_EFFECTS, "data/eff06.anm", ANM_OFFSET_EFFECTS);
    }
    else if (g_GameManager.currentStage == 7 && (msgIdx == 0 || msgIdx == 10))
    {
        g_AnmManager->LoadAnm(ANM_FILE_EFFECTS, "data/eff07.anm", ANM_OFFSET_EFFECTS);
        g_AnmManager->LoadAnm(ANM_FILE_FACE_STAGE_A, "data/face12c.anm", ANM_OFFSET_FACE_STAGE_A);
    }
    return;
}
#pragma optimize("", on)
}; // namespace th06
