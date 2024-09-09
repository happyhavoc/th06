#include "GuiImpl.hpp"

#include "AnmManager.hpp"
#include "ZunColor.hpp"

namespace th06
{
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
