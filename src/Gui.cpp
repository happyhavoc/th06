#include "Gui.hpp"
#include "AnmManager.hpp"
#include "Chain.hpp"
#include "ChainPriorities.hpp"
#include "GameManager.hpp"
#include "Player.hpp"
#include "Stage.hpp"
#include "utils.hpp"

DIFFABLE_STATIC(Gui, g_Gui);
DIFFABLE_STATIC(ChainElem, g_GuiCalcChain);
DIFFABLE_STATIC(ChainElem, g_GuiDrawChain);

#pragma optimize("s", on)
ZunResult Gui::RegisterChain(void)
{
    Gui *gui = &g_Gui;
    if ((i32)(g_Supervisor.curState != SUPERVISOR_STATE_GAMEMANAGER_REINIT))
    {
        memset(gui, 0, sizeof(Gui));
        gui->impl = new GuiImpl();
    }
    g_GuiCalcChain.callback = (ChainCallback)Gui::OnUpdate;
    g_GuiCalcChain.addedCallback = NULL;
    g_GuiCalcChain.deletedCallback = NULL;
    g_GuiCalcChain.addedCallback = (ChainAddedCallback)Gui::AddedCallback;
    g_GuiCalcChain.deletedCallback = (ChainDeletedCallback)Gui::DeletedCallback;
    g_GuiCalcChain.arg = gui;
    if (g_Chain.AddToCalcChain(&g_GuiCalcChain, TH_CHAIN_PRIO_CALC_GUI) != ZUN_SUCCESS)
    {
        return ZUN_ERROR;
    }
    g_GuiDrawChain.callback = (ChainCallback)Gui::OnDraw;
    g_GuiDrawChain.addedCallback = NULL;
    g_GuiDrawChain.deletedCallback = NULL;
    g_GuiDrawChain.arg = gui;
    g_Chain.AddToDrawChain(&g_GuiDrawChain, TH_CHAIN_PRIO_DRAW_GUI);
    return ZUN_SUCCESS;
}
#pragma optimize("", on)

ZunResult Gui::AddedCallback(Gui *gui)
{
    return gui->ActualAddedCallback();
}

#pragma optimize("s", on)
ZunResult Gui::ActualAddedCallback()
{
    i32 idx;

    if ((i32)(g_Supervisor.curState != SUPERVISOR_STATE_GAMEMANAGER_REINIT))
    {
        memset(this->impl, 0, sizeof(GuiImpl));
        if (g_AnmManager->LoadAnm(ANM_FILE_FRONT, "data/front.anm", ANM_OFFSET_FRONT) != ZUN_SUCCESS)
        {
            return ZUN_ERROR;
        }
        if (g_AnmManager->LoadAnm(ANM_FILE_LOADING, "data/loading.anm", ANM_OFFSET_LOADING) != ZUN_SUCCESS)
        {
            return ZUN_ERROR;
        }
        this->impl->loadingScreenSprite.activeSpriteIndex = -1;
        switch (g_GameManager.character)
        {
        case CHARA_REIMU:
            if (g_AnmManager->LoadAnm(ANM_FILE_FACE_CHARA_A, "data/face00a.anm", ANM_OFFSET_FACE_CHARA_A) !=
                ZUN_SUCCESS)
            {
                return ZUN_ERROR;
            }
            if (g_AnmManager->LoadAnm(ANM_FILE_FACE_CHARA_B, "data/face00b.anm", ANM_OFFSET_FACE_CHARA_B) !=
                ZUN_SUCCESS)
            {
                return ZUN_ERROR;
            }
            if (g_AnmManager->LoadAnm(ANM_FILE_FACE_CHARA_C, "data/face00c.anm", ANM_OFFSET_FACE_CHARA_C) !=
                ZUN_SUCCESS)
            {
                return ZUN_ERROR;
            }
            break;
        case CHARA_MARISA:
            if (g_AnmManager->LoadAnm(ANM_FILE_FACE_CHARA_A, "data/face01a.anm", ANM_OFFSET_FACE_CHARA_A) !=
                ZUN_SUCCESS)
            {
                return ZUN_ERROR;
            }
            if (g_AnmManager->LoadAnm(ANM_FILE_FACE_CHARA_B, "data/face01b.anm", ANM_OFFSET_FACE_CHARA_B) !=
                ZUN_SUCCESS)
            {
                return ZUN_ERROR;
            }
            if (g_AnmManager->LoadAnm(ANM_FILE_FACE_CHARA_C, "data/face01c.anm", ANM_OFFSET_FACE_CHARA_C) !=
                ZUN_SUCCESS)
            {
                return ZUN_ERROR;
            }
            break;
        }
    }
    else
    {
        g_AnmManager->SetAndExecuteScriptIdx(&this->impl->loadingScreenSprite, ANM_SCRIPT_LOADING_SHOW_LOADING_SCREEN);
        this->impl->loadingScreenSprite.pendingInterrupt = 1;
    }
    switch (g_GameManager.currentStage)
    {
    case 1:
        if (g_AnmManager->LoadAnm(ANM_FILE_FACE_STAGE_A, "data/face03a.anm", ANM_OFFSET_FACE_STAGE_A) != ZUN_SUCCESS)
        {
            return ZUN_ERROR;
        }
        if (g_AnmManager->LoadAnm(ANM_FILE_FACE_STAGE_B, "data/face03b.anm", ANM_OFFSET_FACE_STAGE_B) != ZUN_SUCCESS)
        {
            return ZUN_ERROR;
        }
        if (this->LoadMsg("data/msg1.dat") != ZUN_SUCCESS)
        {
            return ZUN_ERROR;
        }
        break;
    case 2:
        if (g_AnmManager->LoadAnm(ANM_FILE_FACE_STAGE_A, "data/face05a.anm", ANM_OFFSET_FACE_STAGE_A) != ZUN_SUCCESS)
        {
            return ZUN_ERROR;
        }
        if (this->LoadMsg("data/msg2.dat") != ZUN_SUCCESS)
        {
            return ZUN_ERROR;
        }
        break;
    case 3:
        if (g_AnmManager->LoadAnm(ANM_FILE_FACE_STAGE_A, "data/face06a.anm", ANM_OFFSET_FACE_STAGE_A) != ZUN_SUCCESS)
        {
            return ZUN_ERROR;
        }
        if (g_AnmManager->LoadAnm(ANM_FILE_FACE_STAGE_B, "data/face06b.anm", ANM_OFFSET_FACE_STAGE_B) != ZUN_SUCCESS)
        {
            return ZUN_ERROR;
        }
        if (this->LoadMsg("data/msg3.dat") != ZUN_SUCCESS)
        {
            return ZUN_ERROR;
        }
        break;
    case 4:
        if (g_AnmManager->LoadAnm(ANM_FILE_FACE_STAGE_A, "data/face08a.anm", ANM_OFFSET_FACE_STAGE_A) != ZUN_SUCCESS)
        {
            return ZUN_ERROR;
        }
        if (g_AnmManager->LoadAnm(ANM_FILE_FACE_STAGE_B, "data/face08b.anm", ANM_OFFSET_FACE_STAGE_B) != ZUN_SUCCESS)
        {
            return ZUN_ERROR;
        }
        if (this->LoadMsg("data/msg4.dat") != ZUN_SUCCESS)
        {
            return ZUN_ERROR;
        }
        break;
    case 5:
        if (g_AnmManager->LoadAnm(ANM_FILE_FACE_STAGE_A, "data/face09a.anm", ANM_OFFSET_FACE_STAGE_A) != ZUN_SUCCESS)
        {
            return ZUN_ERROR;
        }
        if (g_AnmManager->LoadAnm(ANM_FILE_FACE_STAGE_B, "data/face09b.anm", ANM_OFFSET_FACE_STAGE_B) != ZUN_SUCCESS)
        {
            return ZUN_ERROR;
        }
        if (this->LoadMsg("data/msg5.dat") != ZUN_SUCCESS)
        {
            return ZUN_ERROR;
        }
        break;
    case 6:
        if (g_AnmManager->LoadAnm(ANM_FILE_FACE_STAGE_A, "data/face09b.anm", ANM_OFFSET_FACE_STAGE_A) != ZUN_SUCCESS)
        {
            return ZUN_ERROR;
        }
        if (g_AnmManager->LoadAnm(ANM_FILE_FACE_STAGE_B, "data/face10a.anm", ANM_OFFSET_FACE_STAGE_B) != ZUN_SUCCESS)
        {
            return ZUN_ERROR;
        }
        if (g_AnmManager->LoadAnm(ANM_FILE_FACE_STAGE_C, "data/face10b.anm", ANM_OFFSET_FACE_STAGE_C) != ZUN_SUCCESS)
        {
            return ZUN_ERROR;
        }
        if (this->LoadMsg("data/msg6.dat") != ZUN_SUCCESS)
        {
            return ZUN_ERROR;
        }
        break;
    default:
        if (g_AnmManager->LoadAnm(ANM_FILE_FACE_STAGE_A, "data/face08a.anm", ANM_OFFSET_FACE_STAGE_A) != ZUN_SUCCESS)
        {
            return ZUN_ERROR;
        }
        if (g_AnmManager->LoadAnm(ANM_FILE_FACE_STAGE_B, "data/face12a.anm", ANM_OFFSET_FACE_STAGE_B) != ZUN_SUCCESS)
        {
            return ZUN_ERROR;
        }
        if (g_AnmManager->LoadAnm(ANM_FILE_FACE_STAGE_C, "data/face12b.anm", ANM_OFFSET_FACE_STAGE_C) != ZUN_SUCCESS)
        {
            return ZUN_ERROR;
        }
        if (this->LoadMsg("data/msg7.dat") != ZUN_SUCCESS)
        {
            return ZUN_ERROR;
        }
        break;
    }
    if ((i32)(g_Supervisor.curState != SUPERVISOR_STATE_GAMEMANAGER_REINIT))
    {
        for (idx = 0; idx < ARRAY_SIZE_SIGNED(this->impl->vms); idx++)
        {
            g_AnmManager->SetAndExecuteScriptIdx(&this->impl->vms[idx], ANM_SCRIPT_FRONT_START + idx);
        }
    }
    this->bossPresent = false;
    this->impl->bossHealthBarState = 0;
    this->bossHealthBar1 = 0.0;
    this->bossHealthBar2 = 0.0;
    g_AnmManager->SetAndExecuteScriptIdx(&this->impl->playerSpellcardPortrait, ANM_SCRIPT_FACE_BOMB_PORTRAIT);
    g_AnmManager->SetAndExecuteScriptIdx(&this->impl->enemySpellcardPortrait, ANM_SCRIPT_FACE_ENEMY_SPELLCARD_PORTRAIT);
    g_AnmManager->SetAndExecuteScriptIdx(&this->impl->bombSpellcardName, ANM_SCRIPT_TEXT_BOMB_NAME);
    g_AnmManager->SetAndExecuteScriptIdx(&this->impl->enemySpellcardName, ANM_SCRIPT_TEXT_ENEMY_SPELLCARD_NAME);
    g_AnmManager->SetAndExecuteScriptIdx(&this->impl->bombSpellcardBackground, ANM_SCRIPT_FRONT_BOMB_NAME_BACKGROUND);
    g_AnmManager->SetAndExecuteScriptIdx(&this->impl->enemySpellcardBackground,
                                         ANM_SCRIPT_FRONT_ENEMY_SPELLCARD_BACKGROUND);
    this->impl->playerSpellcardPortrait.currentInstruction = NULL;
    this->impl->bombSpellcardName.currentInstruction = NULL;
    this->impl->enemySpellcardPortrait.currentInstruction = NULL;
    this->impl->enemySpellcardName.currentInstruction = NULL;
    this->impl->playerSpellcardPortrait.flags.flag0 = 0;
    this->impl->bombSpellcardName.flags.flag0 = 0;
    this->impl->enemySpellcardPortrait.flags.flag0 = 0;
    this->impl->enemySpellcardName.flags.flag0 = 0;
    this->impl->bombSpellcardName.fontWidth = 15;
    this->impl->bombSpellcardName.fontHeight = 15;
    this->impl->enemySpellcardName.fontWidth = 15;
    this->impl->enemySpellcardName.fontHeight = 15;
    g_AnmManager->SetAndExecuteScriptIdx(&this->impl->stageNameSprite, ANM_SCRIPT_TEXT_STAGE_NAME);
    g_AnmManager->SetAndExecuteScriptIdx(&this->impl->songNameSprite, ANM_SCRIPT_TEXT_SONG_NAME);
    AnmManager::DrawStringFormat2(g_AnmManager, &this->impl->stageNameSprite, COLOR_RGB(COLOR_LIGHTCYAN),
                                  COLOR_RGB(COLOR_BLACK), g_Stage.stdData->stageName);
    this->impl->songNameSprite.fontWidth = 16;
    this->impl->songNameSprite.fontHeight = 16;
    AnmManager::DrawStringFormat(g_AnmManager, &this->impl->songNameSprite, COLOR_RGB(COLOR_LIGHTCYAN),
                                 COLOR_RGB(COLOR_BLACK), TH_SONG_NAME, g_Stage.stdData->song1Name);
    this->impl->msg.currentMsgIdx = 0xffffffff;
    this->impl->finishedStage = 0;
    this->impl->bonusScore.isShown = 0;
    this->impl->fullPowerMode.isShown = 0;
    this->impl->spellCardBonus.isShown = 0;
    this->flags = this->flags & 0xfffffffc | 2;
    this->flags = this->flags & 0xfffffff3 | 8;
    this->flags = this->flags & 0xffffff3f | 0x80;
    this->flags = this->flags & 0xfffffcff | 0x200;
    this->flags = this->flags & 0xffffffcf | 0x20;
    return ZUN_SUCCESS;
}
#pragma optimize("", on)
