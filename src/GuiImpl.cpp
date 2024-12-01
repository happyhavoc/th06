#include "GuiImpl.hpp"

#include "AnmManager.hpp"
#include "Controller.hpp"
#include "Stage.hpp"
#include "ZunColor.hpp"
#include "utils.hpp"

namespace th06
{

#pragma optimize("s", on)

GuiImpl::GuiImpl() {

};

ZunResult GuiImpl::RunMsg()
{
    MsgRawInstrArgs *args;

    if (this->msg.currentMsgIdx < 0)
    {
        return ZUN_ERROR;
    }
    if (this->msg.ignoreWaitCounter > 0)
    {
        this->msg.ignoreWaitCounter--;
    }
    if (this->msg.dialogueSkippable && IS_PRESSED(TH_BUTTON_SKIP))
    {
        this->msg.timer.SetCurrent(this->msg.currentInstr->time);
    }
    while ((i32)(this->msg.timer.current >= this->msg.currentInstr->time))
    {
        switch (this->msg.currentInstr->opcode)
        {
        case MSG_OPCODE_MSGDELETE:
            this->msg.currentMsgIdx = 0xffffffff;
            return ZUN_ERROR;
        case MSG_OPCODE_PORTRAITANMSCRIPT:
            args = &this->msg.currentInstr->args;
            g_AnmManager->SetAndExecuteScriptIdx(
                &this->msg.portraits[args->portraitAnmScript.portraitIdx],
                args->portraitAnmScript.anmScriptIdx +
                    (args->portraitAnmScript.portraitIdx == 0 ? ANM_SCRIPT_FACE_START : ANM_SCRIPT_FACE_START + 2));
            break;
        case MSG_OPCODE_PORTRAITANMSPRITE:
            args = &this->msg.currentInstr->args;
            g_AnmManager->SetActiveSprite(
                &this->msg.portraits[args->portraitAnmScript.portraitIdx],
                args->portraitAnmScript.anmScriptIdx +
                    (args->portraitAnmScript.portraitIdx == 0 ? ANM_SCRIPT_FACE_START : ANM_SCRIPT_FACE_START + 8));
            break;
        case MSG_OPCODE_TEXTDIALOGUE:
            args = &this->msg.currentInstr->args;
            if (args->text.textLine == 0 && 0 <= this->msg.dialogueLines[1].anmFileIndex)
            {
                AnmManager::DrawVmTextFmt(g_AnmManager, &this->msg.dialogueLines[1],
                                          this->msg.textColorsA[args->text.textColor],
                                          this->msg.textColorsB[args->text.textColor], " ");
            }
            g_AnmManager->SetAndExecuteScriptIdx(&this->msg.dialogueLines[args->text.textLine],
                                                 0x702 + args->text.textLine);
            this->msg.dialogueLines[args->text.textLine].fontWidth =
                this->msg.dialogueLines[args->text.textLine].fontHeight = this->msg.fontSize;
            AnmManager::DrawVmTextFmt(g_AnmManager, &this->msg.dialogueLines[args->text.textLine],
                                      this->msg.textColorsA[args->text.textColor],
                                      this->msg.textColorsB[args->text.textColor], args->text.text);
            this->msg.framesElapsedDuringPause = 0;
            break;
        case MSG_OPCODE_WAIT:
            if (!this->msg.dialogueSkippable || !IS_PRESSED(TH_BUTTON_SKIP))
            {
                if (!WAS_PRESSED(TH_BUTTON_SHOOT) || this->msg.framesElapsedDuringPause < 8)
                {
                    if (this->msg.framesElapsedDuringPause >= this->msg.currentInstr->args.wait)
                    {
                        break;
                    }
                    this->msg.framesElapsedDuringPause += 1;
                    goto SKIP_TIME_INCREMENT;
                }
            }
            break;
        case MSG_OPCODE_ANMINTERRUPT:
            args = &this->msg.currentInstr->args;
            if (args->anmInterrupt.unk1 < 2)
            {
                this->msg.portraits[args->anmInterrupt.unk1].pendingInterrupt = args->anmInterrupt.unk2;
            }
            else
            {
                this->msg.dialogueLines[args->anmInterrupt.unk1 - 2].pendingInterrupt = args->anmInterrupt.unk2;
            }
            break;
        case MSG_OPCODE_ECLRESUME:
            this->msg.ignoreWaitCounter += 1;
            break;
        case MSG_OPCODE_MUSIC:
            g_AnmManager->SetAndExecuteScriptIdx(&this->songNameSprite, 0x701);
            this->songNameSprite.fontWidth = 16;
            this->songNameSprite.fontHeight = 16;
            AnmManager::DrawStringFormat(g_AnmManager, &this->songNameSprite, COLOR_RGB(COLOR_LIGHTCYAN),
                                         COLOR_RGB(COLOR_BLACK), "♪%s",
                                         g_Stage.stdData->songNames[this->msg.currentInstr->args.music]);
            if (g_Supervisor.PlayMidiFile(this->msg.currentInstr->args.music) != 0)
            {
                g_Supervisor.PlayAudio(g_Stage.stdData->songPaths[this->msg.currentInstr->args.music]);
            }
            break;
        case MSG_OPCODE_TEXTINTRO:
            args = &this->msg.currentInstr->args;
            g_AnmManager->SetAndExecuteScriptIdx(&this->msg.introLines[args->text.textLine],
                                                 args->text.textLine + 0x704);
            AnmManager::DrawStringFormat(g_AnmManager, &this->msg.introLines[args->text.textLine],
                                         this->msg.textColorsA[args->text.textColor],
                                         this->msg.textColorsB[args->text.textColor], args->text.text);
            this->msg.framesElapsedDuringPause = 0;
            break;
        case MSG_OPCODE_STAGERESULTS:
            this->finishedStage = 1;
            if (g_GameManager.currentStage < 6)
            {
                g_AnmManager->SetAndExecuteScriptIdx(&this->loadingScreenSprite,
                                                     ANM_SCRIPT_LOADING_SHOW_LOADING_SCREEN);
            }
            else
            {
                g_GameManager.extraLives = 0xff;
            }
            break;
        case MSG_OPCODE_MSGHALT:
            goto SKIP_TIME_INCREMENT;
        case MSG_OPCODE_MUSICFADEOUT:
            g_Supervisor.FadeOutMusic(4.0);
            break;
        case MSG_OPCODE_STAGEEND:
            g_GameManager.guiScore = g_GameManager.score;
            if (g_GameManager.isInPracticeMode)
            {
                g_GameManager.guiScore = g_GameManager.score;
                g_Supervisor.curState = SUPERVISOR_STATE_RESULTSCREEN_FROMGAME;
                goto SKIP_TIME_INCREMENT;
            }
            if (g_GameManager.currentStage < 5 || (g_GameManager.difficulty != EASY && g_GameManager.currentStage == 5))
            {
                g_Supervisor.curState = SUPERVISOR_STATE_GAMEMANAGER_REINIT;
            }
            else if (!g_GameManager.isInReplay)
            {
                if (g_GameManager.difficulty == EXTRA)
                {
                    g_GameManager.isGameCompleted = 1;
                    g_GameManager.guiScore = g_GameManager.score;
                    g_Supervisor.curState = SUPERVISOR_STATE_RESULTSCREEN_FROMGAME;
                    goto SKIP_TIME_INCREMENT;
                }
                else
                {
                    g_Supervisor.curState = SUPERVISOR_STATE_ENDING;
                }
            }
            else
            {
                g_Supervisor.curState = SUPERVISOR_STATE_MAINMENU_REPLAY;
            }
            goto SKIP_TIME_INCREMENT;
        case MSG_OPCODE_WAITSKIPPABLE:
            this->msg.dialogueSkippable = this->msg.currentInstr->args.dialogueSkippable;
            break;
        }
        this->msg.currentInstr =
            (MsgRawInstr *)(((i32) & this->msg.currentInstr->args) + this->msg.currentInstr->argSize);
    }
    this->msg.timer.NextTick();
SKIP_TIME_INCREMENT:
    g_AnmManager->ExecuteScript(&this->msg.portraits[0]);
    g_AnmManager->ExecuteScript(&this->msg.portraits[1]);
    g_AnmManager->ExecuteScript(&this->msg.dialogueLines[0]);
    g_AnmManager->ExecuteScript(&this->msg.dialogueLines[1]);
    g_AnmManager->ExecuteScript(&this->msg.introLines[0]);
    g_AnmManager->ExecuteScript(&this->msg.introLines[1]);
    if ((i32)(this->msg.timer.current < 60) && this->msg.dialogueSkippable && IS_PRESSED(TH_BUTTON_SKIP))
    {
        this->msg.timer.SetCurrent(60);
    }
    return ZUN_SUCCESS;
}
#pragma optimize("", on)

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

    if (this->msg.msgFile->numInstrs <= msgIdx)
    {
        return;
    }
    msgFile = this->msg.msgFile;
    memset(&this->msg, 0, sizeof(GuiMsgVm));
    this->msg.currentMsgIdx = msgIdx;
    this->msg.msgFile = msgFile;
    this->msg.currentInstr = this->msg.msgFile->instrs[msgIdx];
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
