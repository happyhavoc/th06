#include "Ending.hpp"
#include "AnmIdx.hpp"
#include "AnmManager.hpp"
#include "Chain.hpp"
#include "ChainPriorities.hpp"
#include "FileSystem.hpp"
#include "GameErrorContext.hpp"
#include "GameManager.hpp"
#include "Player.hpp"
#include "Supervisor.hpp"
#include "i18n.hpp"

namespace th06
{

ZunResult Ending::RegisterChain()
{
    Ending *ending;

    ending = new Ending();
    ending->calcChain = g_Chain.CreateElem((ChainCallback)Ending::OnUpdate);
    ending->calcChain->arg = ending;
    ending->calcChain->addedCallback = (ChainAddedCallback)Ending::AddedCallback;
    ending->calcChain->deletedCallback = (ChainDeletedCallback)Ending::DeletedCallback;
    if (g_Chain.AddToCalcChain(ending->calcChain, TH_CHAIN_PRIO_CALC_ENDING))
    {
        return ZUN_ERROR;
    }

    ending->drawChain = g_Chain.CreateElem((ChainCallback)Ending::OnDraw);
    ending->drawChain->arg = ending;
    g_Chain.AddToDrawChain(ending->drawChain, TH_CHAIN_PRIO_DRAW_ENDING);

    return ZUN_SUCCESS;
}

#pragma var_order(unused, shotTypeAndCharacter)
ZunResult Ending::AddedCallback(Ending *ending)
{
    i32 shotTypeAndCharacter;
    i32 unused;

    unused = g_GameManager.character * 2 + g_GameManager.shotType;

    g_GameManager.isGameCompleted = true;
    g_Supervisor.isInEnding = true;
    g_Supervisor.LoadPbg3(ED_PBG3_INDEX, TH_ED_DAT_FILE);
    g_AnmManager->LoadAnm(ANM_FILE_STAFF01, "data/staff01.anm", ANM_OFFSET_STAFF01);
    g_AnmManager->LoadAnm(ANM_FILE_STAFF02, "data/staff02.anm", ANM_OFFSET_STAFF02);
    g_AnmManager->LoadAnm(ANM_FILE_STAFF03, "data/staff03.anm", ANM_OFFSET_STAFF03);

    g_AnmManager->SetCurrentTexture(NULL);
    g_AnmManager->SetCurrentSprite(NULL);
    g_AnmManager->SetCurrentBlendMode(0xff);
    g_AnmManager->SetCurrentVertexShader(0xff);

    shotTypeAndCharacter = g_GameManager.character * 2 + g_GameManager.shotType;
    ending->unk_111a = 0;
    if (g_GameManager.numRetries == 0)
    {
        if (g_GameManager.clrd[shotTypeAndCharacter].difficultyClearedWithRetries[g_GameManager.difficulty] == 99)
        {
            ending->unk_111a = 1;
        }

        g_GameManager.clrd[shotTypeAndCharacter].difficultyClearedWithRetries[g_GameManager.difficulty] = 99;
    }
    else
    {
        if (g_GameManager.clrd[shotTypeAndCharacter].difficultyClearedWithoutRetries[g_GameManager.difficulty] == 99)
        {
            ending->unk_111a = 1;
        }
    }
    g_GameManager.clrd[shotTypeAndCharacter].difficultyClearedWithoutRetries[g_GameManager.difficulty] = 99;
    if (g_GameManager.difficulty == EASY || g_GameManager.numRetries != 0)
    {
        switch (g_GameManager.character)
        {
        case CHARA_REIMU:
            if (ending->LoadEnding("data/end00b.end") != ZUN_SUCCESS)
            {
                return ZUN_ERROR;
            }
            break;
        case CHARA_MARISA:
            if (ending->LoadEnding("data/end10b.end") != ZUN_SUCCESS)
            {
                return ZUN_ERROR;
            }
            break;
        }
    }
    else
    {
        switch (g_GameManager.character)
        {
        case CHARA_REIMU:
            if (g_GameManager.shotType == SHOT_TYPE_A)
            {
                if (ending->LoadEnding("data/end00.end") != ZUN_SUCCESS)
                {
                    return ZUN_ERROR;
                }
            }
            else
            {
                if (ending->LoadEnding("data/end01.end") != ZUN_SUCCESS)
                {
                    return ZUN_ERROR;
                }
            }
            break;
        case CHARA_MARISA:
            if (g_GameManager.shotType == SHOT_TYPE_A)
            {
                if (ending->LoadEnding("data/end10.end") != ZUN_SUCCESS)
                {
                    return ZUN_ERROR;
                }
            }
            else
            {
                if (ending->LoadEnding("data/end11.end") != ZUN_SUCCESS)
                {
                    return ZUN_ERROR;
                }
            }
            break;
        }
    }
    return ZUN_SUCCESS;
}

ZunResult Ending::LoadEnding(char *endFilePath)
{
    char *endFileDat;

    endFileDat = this->endFileData;
    this->endFileData = (char *)FileSystem::OpenPath(endFilePath, false);
    if (this->endFileData == NULL)
    {
        GameErrorContext::Log(&g_GameErrorContext, TH_ERR_ENDING_END_FILE_CORRUPTED);
        return ZUN_ERROR;
    }
    else
    {
        this->endFileDataPtr = this->endFileData;
        this->line2Delay = 8;
        this->timer2.InitializeForPopup();
        this->timer1.InitializeForPopup();
        if (endFileDat != NULL)
        {
            free(endFileDat);
        }
        return ZUN_SUCCESS;
    }
}

}; // namespace th06