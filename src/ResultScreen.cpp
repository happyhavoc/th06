#include "ResultScreen.hpp"
#include "AnmManager.hpp"
#include "AsciiManager.hpp"
#include "BulletManager.hpp"
#include "Chain.hpp"
#include "ChainPriorities.hpp"
#include "FileSystem.hpp"
#include "GameManager.hpp"
#include "Player.hpp"
#include "SoundPlayer.hpp"
#include "Stage.hpp"
#include "i18n.hpp"
#include "utils.hpp"

namespace th06
{

DIFFABLE_STATIC_ASSIGN(u32, g_DefaultMagic) = 'DMYS';
DIFFABLE_STATIC_ARRAY_ASSIGN(char *, 6, g_CharacterList) = {TH_HAKUREI_REIMU_SPIRIT,  TH_HAKUREI_REIMU_DREAM,
                                                            TH_KIRISAME_MARISA_DEVIL, TH_KIRISAME_MARISA_LOVE,
                                                            TH_SATSUKI_RIN_FLOWER,    TH_SATSUKI_RIN_WIND};
DIFFABLE_STATIC_ARRAY_ASSIGN(char *, 4, g_ShortCharacterList2) = {"ReimuA ", "ReimuB ", "MarisaA", "MarisaB"};

DIFFABLE_STATIC_ASSIGN(char *, g_AlphabetList) =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ.,:;･@abcdefghijklmnopqrstuvwxyz+-/*=%0123456789(){}[]<>#!?'\"$      --";

#define DEFAULT_HIGH_SCORE_NAME "Nanashi "

#pragma function(memset)
#pragma optimize("s", on)
ResultScreen::ResultScreen()
{
    i32 unused[12];
    memset(this, 0, sizeof(ResultScreen));
    this->cursor = 1;
}
#pragma optimize("", on)

#pragma optimize("s", on)
#pragma var_order(resultScreen, unused)
ZunResult ResultScreen::RegisterChain(i32 unk)
{

    i32 unused[16];
    ResultScreen *resultScreen;
    resultScreen = new ResultScreen();

    utils::DebugPrint(TH_DBG_RESULTSCREEN_COUNAT, g_GameManager.counat);

    resultScreen->calcChain = g_Chain.CreateElem((ChainCallback)ResultScreen::OnUpdate);
    resultScreen->calcChain->addedCallback = (ChainAddedCallback)ResultScreen::AddedCallback;
    resultScreen->calcChain->deletedCallback = (ChainDeletedCallback)ResultScreen::DeletedCallback;
    resultScreen->calcChain->arg = resultScreen;

    if (unk != 0)
    {
        if (!g_GameManager.isInPracticeMode)
        {
            resultScreen->resultScreenState = RESULT_SCREEN_STATE_WRITING_HIGHSCORE_NAME;
        }
        else
        {
            resultScreen->resultScreenState = RESULT_SCREEN_STATE_EXIT;
        }
    }

    if (g_Chain.AddToCalcChain(resultScreen->calcChain, TH_CHAIN_PRIO_CALC_RESULTSCREEN))
    {
        return ZUN_ERROR;
    }

    resultScreen->drawChain = g_Chain.CreateElem((ChainCallback)ResultScreen::OnDraw);
    resultScreen->drawChain->arg = resultScreen;
    g_Chain.AddToDrawChain(resultScreen->drawChain, TH_CHAIN_PRIO_DRAW_RESULTSCREEN);

    return ZUN_SUCCESS;
}
#pragma optimize("", on)

#pragma function("strcpy")
#pragma optimize("s", on)
#pragma var_order(i, sprite, character, slot)
ZunResult ResultScreen::AddedCallback(ResultScreen *resultScreen)
{

    i32 slot;
    i32 characterShot;
    AnmVm *sprite;
    i32 i;

    if (resultScreen->resultScreenState != RESULT_SCREEN_STATE_EXIT)
    {

        if (g_AnmManager->LoadSurface(0, "data/result/result.jpg") != ZUN_SUCCESS)
        {
            return ZUN_ERROR;
        }

        if (g_AnmManager->LoadAnm(ANM_FILE_RESULT00, "data/result00.anm", ANM_OFFSET_RESULT00) != ZUN_SUCCESS)
        {
            return ZUN_ERROR;
        }

        if (g_AnmManager->LoadAnm(ANM_FILE_RESULT01, "data/result01.anm", ANM_OFFSET_RESULT01) != ZUN_SUCCESS)
        {
            return ZUN_ERROR;
        }

        if (g_AnmManager->LoadAnm(ANM_FILE_RESULT02, "data/result02.anm", ANM_OFFSET_RESULT02) != ZUN_SUCCESS)
        {
            return ZUN_ERROR;
        }

        if (g_AnmManager->LoadAnm(ANM_FILE_RESULT03, "data/result03.anm", ANM_OFFSET_RESULT03) != ZUN_SUCCESS)
        {
            return ZUN_ERROR;
        }

        sprite = &resultScreen->unk_40[0];
        for (i = 0; i < ARRAY_SIZE_SIGNED(resultScreen->unk_40); i++, sprite++)
        {

            sprite->pos = D3DXVECTOR3(0.0f, 0.0f, 0.0f);
            sprite->posOffset = D3DXVECTOR3(0.0f, 0.0f, 0.0f);

            // Execute all the scripts from the start of result00 to the end of result02
            g_AnmManager->SetAndExecuteScriptIdx(sprite, ANM_SCRIPT_RESULT00_START + i);
        }

        sprite = &resultScreen->unk_28a0[0];
        for (i = 0; i < ARRAY_SIZE_SIGNED(resultScreen->unk_28a0); i++, sprite++)
        {
            g_AnmManager->InitializeAndSetSprite(sprite, ANM_SCRIPT_TEXT_RESULTSCREEN_CHARACTER_NAME + i);

            sprite->pos = D3DXVECTOR3(0.0f, 0.0f, 0.0f);

            sprite->flags.anchor = AnmVmAnchor_TopLeft;

            sprite->fontWidth = 15;
            sprite->fontHeight = 15;
        }
    }

    for (i = 0; i < HSCR_NUM_DIFFICULTIES; i++)
    {
        for (characterShot = 0; characterShot < HSCR_NUM_CHARS_SHOTTYPES; characterShot++)
        {
            for (slot = 0; slot < HSCR_NUM_SCORES_SLOTS; slot++)
            {
                resultScreen->defaultScore[i][characterShot][slot].score = 1000000 - slot * 100000;
                resultScreen->defaultScore[i][characterShot][slot].base.magic = g_DefaultMagic;
                resultScreen->defaultScore[i][characterShot][slot].difficulty = i;
                resultScreen->defaultScore[i][characterShot][slot].base.version = 16;
                resultScreen->defaultScore[i][characterShot][slot].base.unkLen = 28;
                resultScreen->defaultScore[i][characterShot][slot].base.th6kLen = 28;
                resultScreen->defaultScore[i][characterShot][slot].stage = 1;
                resultScreen->defaultScore[i][characterShot][slot].base.unk_9 = 0;

                resultScreen->LinkScoreEx(resultScreen->defaultScore[i][characterShot] + slot, i, characterShot);

                strcpy(resultScreen->defaultScore[i][characterShot][slot].name, DEFAULT_HIGH_SCORE_NAME);
            }
        }
    }

    resultScreen->unk_14 = 0;
    resultScreen->scoreDat = ResultScreen::OpenScore("score.dat");

    for (i = 0; i < HSCR_NUM_DIFFICULTIES; i++)
    {
        for (characterShot = 0; characterShot < HSCR_NUM_CHARS_SHOTTYPES; characterShot++)
        {
            ResultScreen::GetHighScore(resultScreen->scoreDat, &resultScreen->scores[i][characterShot], characterShot,
                                       i);
        }
    }

    if (resultScreen->resultScreenState != RESULT_SCREEN_STATE_WRITING_HIGHSCORE_NAME &&
        resultScreen->resultScreenState != RESULT_SCREEN_STATE_EXIT)
    {
        ParseCatk(resultScreen->scoreDat, g_GameManager.catk);
        ParseClrd(resultScreen->scoreDat, g_GameManager.clrd);
        ParsePscr(resultScreen->scoreDat, (Pscr *)g_GameManager.pscr);
    }

    if (resultScreen->resultScreenState == RESULT_SCREEN_STATE_EXIT &&
        g_GameManager.pscr[g_GameManager.CharacterShotType()][g_GameManager.currentStage - 1][g_GameManager.difficulty]
                .score < g_GameManager.score)
    {
        g_GameManager.pscr[g_GameManager.CharacterShotType()][g_GameManager.currentStage - 1][g_GameManager.difficulty]
            .score = g_GameManager.score;
    }

    resultScreen->unk_39a0.activeSpriteIndex = -1;

    return ZUN_SUCCESS;
}
#pragma optimize("", on)
#pragma intrinsic("strcpy")

#pragma optimize("s", on)
void ResultScreen::MoveCursor(ResultScreen *resultScreen, i32 length)
{
    if (WAS_PRESSED_WEIRD(TH_BUTTON_UP))
    {
        resultScreen->cursor--;
        if (resultScreen->cursor < 0)
        {
            resultScreen->cursor += length;
        }
        g_SoundPlayer.PlaySoundByIdx(SOUND_MOVE_MENU, 0);
    }
    if (WAS_PRESSED_WEIRD(TH_BUTTON_DOWN))
    {
        resultScreen->cursor++;
        if (resultScreen->cursor >= length)
        {
            resultScreen->cursor -= length;
        }
        g_SoundPlayer.PlaySoundByIdx(SOUND_MOVE_MENU, 0);
    }
}
#pragma optimize("", on)

#pragma optimize("s", on)
ZunBool ResultScreen::MoveCursorHorizontally(ResultScreen *resultScreen, i32 length)
{
    if (WAS_PRESSED_WEIRD(TH_BUTTON_LEFT))
    {
        resultScreen->cursor--;
        if (resultScreen->cursor < 0)
        {
            resultScreen->cursor += length;
        }
        g_SoundPlayer.PlaySoundByIdx(SOUND_MOVE_MENU, 0);
        return true;
    }
    else if (WAS_PRESSED_WEIRD(TH_BUTTON_RIGHT))
    {
        resultScreen->cursor++;
        if (resultScreen->cursor >= length)
        {
            resultScreen->cursor -= length;
        }
        g_SoundPlayer.PlaySoundByIdx(SOUND_MOVE_MENU, 0);
        return true;
    }
    else
    {
        return false;
    }
}
#pragma optimize("", on)

#pragma optimize("s", on)
ZunResult ResultScreen::CheckConfirmButton()
{
    AnmVm *viewport;

    switch (this->resultScreenState)
    {
    case RESULT_SCREEN_STATE_STATS_SCREEN:
        if (this->frameTimer <= 30)
        {
            viewport = &this->unk_40[37];
            viewport->pendingInterrupt = 16;
        }
        if (this->frameTimer >= 90 && WAS_PRESSED(TH_BUTTON_SELECTMENU))
        {
            viewport = &this->unk_40[37];
            viewport->pendingInterrupt = 2;
            this->frameTimer = 0;
            this->resultScreenState = RESULT_SCREEN_STATE_STATS_TO_SAVE_TRANSITION;
        }
        break;

    case RESULT_SCREEN_STATE_STATS_TO_SAVE_TRANSITION:
        if (this->frameTimer >= 30)
        {
            this->frameTimer = 59;
            this->resultScreenState = RESULT_SCREEN_STATE_SAVE_REPLAY_QUESTION;
        }
        break;
    }
    return ZUN_SUCCESS;
}
#pragma optimize("", on)

#pragma optimize("s", on)
#pragma var_order(scoreData, bytesShifted, xorValue, checksum, bytes, remainingData, decryptedFilePointer, fileLen,    \
                  scoreDatSize, scoreListNodeSize)
ScoreDat *ResultScreen::OpenScore(char *path)
{
    u8 *bytes;
    i32 bytesShifted;
    i32 fileLen;
    Th6k *decryptedFilePointer;
    i32 remainingData;
    i32 scoreListNodeSize;
    u16 checksum;
    u8 xorValue;
    i32 scoreDatSize;
    ScoreDat *scoreData;

    scoreData = (ScoreDat *)FileSystem::OpenPath(path, true);
    if (scoreData == NULL)
    {
    FAILED_TO_READ:
        scoreDatSize = sizeof(ScoreDat);
        scoreData = (ScoreDat *)malloc(scoreDatSize);
        scoreData->dataOffset = sizeof(ScoreDat);
        scoreData->fileLen = sizeof(ScoreDat);
    }
    else
    {
        if (g_LastFileSize < sizeof(ScoreDat))
        {
            free(scoreData);
            goto FAILED_TO_READ;
        }

        remainingData = g_LastFileSize - 2;
        checksum = 0;
        xorValue = 0;
        bytesShifted = 0;
        bytes = &scoreData->xorseed[1];

        while (0 < remainingData)
        {

            xorValue += bytes[0];
            // Invert top 3 bits and bottom 5 bits
            xorValue = (xorValue & 0xe0) >> 5 | (xorValue & 0x1f) << 3;
            // xor one byte later with the resulting inverted bits
            bytes[1] ^= xorValue;
            if (bytesShifted >= 2)
            {
                checksum += bytes[1];
            }
            bytes++;
            remainingData--;
            bytesShifted++;
        }
        if (scoreData->csum != checksum)
        {
            free(scoreData);
            goto FAILED_TO_READ;
        }
        fileLen = scoreData->fileLen;
        decryptedFilePointer = scoreData->ShiftBytes(scoreData->dataOffset);
        fileLen -= scoreData->dataOffset;
        while (fileLen > 0)
        {
            if (decryptedFilePointer->magic == 'K6HT')
                break;

            decryptedFilePointer = decryptedFilePointer->ShiftBytes(decryptedFilePointer->th6kLen);
            fileLen = fileLen - decryptedFilePointer->th6kLen;
        }
        if (fileLen <= 0)
        {
            free(scoreData);
            goto FAILED_TO_READ;
        };
    }
    scoreListNodeSize = sizeof(ScoreListNode);
    scoreData->scores = (ScoreListNode *)malloc(scoreListNodeSize);
    scoreData->scores->next = NULL;
    scoreData->scores->data = NULL;
    scoreData->scores->prev = NULL;
    return scoreData;
}
#pragma optimize("", on)

#pragma optimize("s", on)
#pragma var_order(parsedCatk, cursor, sd)
ZunResult ResultScreen::ParseCatk(ScoreDat *scoreDat, Catk *outCatk)
{

    i32 cursor;
    Catk *parsedCatk;
    ScoreDat *sd;
    sd = scoreDat;

    if (outCatk == NULL)
    {
        return ZUN_ERROR;
    }

    parsedCatk = (Catk *)sd->ShiftBytes(sd->dataOffset);
    cursor = sd->fileLen - sd->dataOffset;
    while (cursor > 0)
    {
        if (parsedCatk->base.magic == 'KTAC' && parsedCatk->base.version == 16)
        {
            if (parsedCatk->idx >= CATK_NUM_CAPTURES)
                break;

            outCatk[parsedCatk->idx] = *parsedCatk;
        }
        cursor -= parsedCatk->base.th6kLen;
        parsedCatk = (Catk *)&parsedCatk->name[parsedCatk->base.th6kLen - 0x18];
    }
    return ZUN_SUCCESS;
}
#pragma optimize("", on)

#pragma optimize("s", on)
#pragma var_order(parsedClrd, characterShotType, cursor, difficulty, sd)
ZunResult ResultScreen::ParseClrd(ScoreDat *scoreDat, Clrd *outClrd)
{
    i32 cursor;
    Clrd *parsedClrd;
    ScoreDat *sd;
    i32 characterShotType;
    i32 difficulty;
    sd = scoreDat;

    if (outClrd == NULL)
    {
        return ZUN_ERROR;
    }

    for (characterShotType = 0; characterShotType < CLRD_NUM_CHARACTERS; characterShotType++)
    {
        memset(&outClrd[characterShotType], 0, sizeof(Clrd));

        outClrd[characterShotType].base.magic = 'DRLC';
        outClrd[characterShotType].base.unkLen = sizeof(Clrd);
        outClrd[characterShotType].base.th6kLen = sizeof(Clrd);
        outClrd[characterShotType].base.version = 16;
        outClrd[characterShotType].characterShotType = characterShotType;

        for (difficulty = 0; difficulty < ARRAY_SIZE_SIGNED(outClrd[0].difficultyClearedWithoutRetries); difficulty++)
        {
            outClrd[characterShotType].difficultyClearedWithRetries[difficulty] = 1;
            outClrd[characterShotType].difficultyClearedWithoutRetries[difficulty] = 1;
        }
    }

    parsedClrd = (Clrd *)sd->ShiftBytes(sd->dataOffset);
    cursor = sd->fileLen - sd->dataOffset;
    while (cursor > 0)
    {
        if (parsedClrd->base.magic == 'DRLC' && parsedClrd->base.version == 16)
        {
            if (parsedClrd->characterShotType >= CLRD_NUM_CHARACTERS)
                break;

            outClrd[parsedClrd->characterShotType] = *parsedClrd;
        }
        cursor -= parsedClrd->base.th6kLen;
        parsedClrd = (Clrd *)((i32)&parsedClrd->base + parsedClrd->base.th6kLen);
    }
    return ZUN_SUCCESS;
}
#pragma optimize("", on)

#pragma optimize("s", on)
#pragma var_order(pscr, parsedPscr, character, stage, cursor, difficulty, sd)
ZunResult ResultScreen::ParsePscr(ScoreDat *scoreDat, Pscr *outClrd)
{
    i32 cursor;
    Pscr *parsedPscr;
    ScoreDat *sd;
    i32 stage;
    i32 character;
    i32 difficulty;
    sd = scoreDat;
    Pscr *pscr;

    if (outClrd == NULL)
    {
        return ZUN_ERROR;
    }

    for (pscr = outClrd, character = 0; character < PSCR_NUM_CHARS_SHOTTYPES; character++)
    {
        for (stage = 0; stage < PSCR_NUM_STAGES; stage++)
        {
            for (difficulty = 0; difficulty < PSCR_NUM_DIFFICULTIES; difficulty++, pscr++)
            {

                memset(pscr, 0, sizeof(Pscr));

                pscr->base.magic = 'RCSP';
                pscr->base.unkLen = sizeof(Pscr);
                pscr->base.th6kLen = sizeof(Pscr);
                pscr->base.version = 16;
                pscr->character = character;
                pscr->difficulty = difficulty;
                pscr->stage = stage;
            }
        }
    }

    parsedPscr = (Pscr *)sd->ShiftBytes(sd->dataOffset);
    cursor = sd->fileLen - sd->dataOffset;

    while (cursor > 0)
    {
        if (parsedPscr->base.magic == 'RCSP' && parsedPscr->base.version == 16)
        {
            pscr = parsedPscr;
            if (pscr->character >= PSCR_NUM_CHARS_SHOTTYPES || pscr->difficulty >= PSCR_NUM_DIFFICULTIES + 1 ||
                pscr->stage >= PSCR_NUM_STAGES + 1)
                break;

            outClrd[pscr->character * 6 * 4 + pscr->stage * 4 + pscr->difficulty] = *pscr;
        }
        cursor -= parsedPscr->base.th6kLen;
        parsedPscr = parsedPscr->ShiftBytes(parsedPscr->base.th6kLen);
    }
    return ZUN_SUCCESS;
}
#pragma optimize("", on)

#pragma optimize("s", on)
#pragma var_order(i, vm, characterShotType, difficulty)
ChainCallbackResult ResultScreen::OnUpdate(ResultScreen *resultScreen)
{
    i32 difficulty;
    i32 characterShotType;
    AnmVm *vm;
    i32 i;
    switch (resultScreen->resultScreenState)
    {

    case RESULT_SCREEN_STATE_EXIT:
        g_Supervisor.curState = SUPERVISOR_STATE_MAINMENU;
        return CHAIN_CALLBACK_RESULT_CONTINUE_AND_REMOVE_JOB;

    case RESULT_SCREEN_STATE_INIT:

        if (resultScreen->frameTimer == 0)
        {

            vm = &resultScreen->unk_40[0];
            for (i = 0; i < ARRAY_SIZE_SIGNED(resultScreen->unk_40); i++, vm++)
            {
                vm->pendingInterrupt = 1;
                vm->flags.colorOp = 1;
                if (((g_Supervisor.cfg.opts >> GCOS_USE_D3D_HW_TEXTURE_BLENDING) & 1) == 0)
                {
                    vm->color &= COLOR_BLACK;
                }
                else
                {
                    vm->color &= COLOR_WHITE;
                }
            }

            vm = &resultScreen->unk_40[1];
            for (i = 0; i <= 6; i++, vm++)
            {
                if (i == resultScreen->cursor)
                {
                    if (((g_Supervisor.cfg.opts >> GCOS_USE_D3D_HW_TEXTURE_BLENDING) & 1) == 0)
                    {
                        vm->color = COLOR_DARK_GREY;
                    }
                    else
                    {
                        vm->color = COLOR_WHITE;
                    }

                    vm->posOffset = D3DXVECTOR3(-4.0f, -4.0f, 0.0f);
                }
                else
                {
                    if (((g_Supervisor.cfg.opts >> GCOS_USE_D3D_HW_TEXTURE_BLENDING) & 1) == 0)
                    {
                        vm->color = COLOR_SET_ALPHA(COLOR_BLACK, 176);
                    }
                    else
                    {
                        vm->color = COLOR_SET_ALPHA(COLOR_WHITE, 176);
                    }
                    vm->posOffset = D3DXVECTOR3(0.0f, 0.0f, 0.0f);
                }
            }
        }

        if (resultScreen->frameTimer < 20)
        {
            break;
        }

        resultScreen->resultScreenState++;
        resultScreen->frameTimer = 0;

    case RESULT_SCREEN_STATE_CHOOSING_DIFFICULTY:

        ResultScreen::MoveCursor(resultScreen, 7);

        vm = &resultScreen->unk_40[1];
        for (i = 0; i <= 6; i++, vm++)
        {
            if (i == resultScreen->cursor)
            {
                if (((g_Supervisor.cfg.opts >> GCOS_USE_D3D_HW_TEXTURE_BLENDING) & 1) == 0)
                {
                    vm->color = COLOR_DARK_GREY;
                }
                else
                {
                    vm->color = COLOR_WHITE;
                }
                vm->posOffset = D3DXVECTOR3(-4.0f, -4.0f, 0.0f);
            }
            else
            {
                if (((g_Supervisor.cfg.opts >> GCOS_USE_D3D_HW_TEXTURE_BLENDING) & 1) == 0)
                {
                    vm->color = COLOR_SET_ALPHA(COLOR_BLACK, 176);
                }
                else
                {
                    vm->color = COLOR_SET_ALPHA(COLOR_WHITE, 176);
                }
                vm->posOffset = D3DXVECTOR3(0.0f, 0.0f, 0.0f);
            }
        }

        if (WAS_PRESSED(TH_BUTTON_SELECTMENU))
        {
            vm = &resultScreen->unk_40[0];
            switch (resultScreen->cursor)
            {
            case RESULT_SCREEN_CURSOR_EASY:
            case RESULT_SCREEN_CURSOR_NORMAL:
            case RESULT_SCREEN_CURSOR_HARD:
            case RESULT_SCREEN_CURSOR_LUNATIC:
            case RESULT_SCREEN_CURSOR_EXTRA:
                for (i = 0; i < ARRAY_SIZE_SIGNED(resultScreen->unk_40); i++, vm++)
                {
                    vm->pendingInterrupt = resultScreen->cursor + 3;
                }
                resultScreen->diffSelected = resultScreen->cursor;

                resultScreen->resultScreenState = resultScreen->cursor + RESULT_SCREEN_STATE_BEST_SCORES_EASY;
                resultScreen->unk_c = resultScreen->resultScreenState;
                resultScreen->frameTimer = 0;
                resultScreen->cursor = resultScreen->unk_14;
                resultScreen->charUsed = -1;
                resultScreen->lastSpellcardSelected = -1;
                break;

            case RESULT_SCREEN_CURSOR_SPELLCARDS:
                for (i = 0; i < ARRAY_SIZE_SIGNED(resultScreen->unk_40); i++, vm++)
                {
                    vm->pendingInterrupt = resultScreen->cursor + 3;
                }
                resultScreen->diffSelected = resultScreen->cursor;
                resultScreen->resultScreenState = RESULT_SCREEN_STATE_SPELLCARDS;
                resultScreen->unk_c = resultScreen->resultScreenState;
                resultScreen->frameTimer = 0;
                resultScreen->charUsed = -1;
                resultScreen->cursor = resultScreen->previousCursor;
                resultScreen->lastSpellcardSelected = -1;
                break;

            case RESULT_SCREEN_CURSOR_EXIT:
                for (i = 0; i < ARRAY_SIZE_SIGNED(resultScreen->unk_40); i++, vm++)
                {
                    vm->pendingInterrupt = 2;
                }
                resultScreen->resultScreenState = RESULT_SCREEN_STATE_EXITING;
                g_SoundPlayer.PlaySoundByIdx(SOUND_BACK, 0);
            }
        }
        if (WAS_PRESSED(TH_BUTTON_RETURNMENU))
        {
            resultScreen->cursor = RESULT_SCREEN_CURSOR_EXIT;
            g_SoundPlayer.PlaySoundByIdx(SOUND_BACK, 0);
        }
        break;

    case RESULT_SCREEN_STATE_EXITING:

        if (resultScreen->frameTimer < 60)
        {
            break;
        }
        else
        {
            g_Supervisor.curState = SUPERVISOR_STATE_MAINMENU;
            return CHAIN_CALLBACK_RESULT_CONTINUE_AND_REMOVE_JOB;
        }

    case RESULT_SCREEN_STATE_BEST_SCORES_EXTRA:

        if (IS_PRESSED(TH_BUTTON_FOCUS) || IS_PRESSED(TH_BUTTON_SKIP))
        {

            if (resultScreen->cheatCodeStep < 5)
            {
                if (WAS_PRESSED(TH_BUTTON_HOME))
                {
                    resultScreen->cheatCodeStep++;
                }
                else if (WAS_PRESSED(TH_BUTTON_WRONG_CHEATCODE))
                {
                    resultScreen->cheatCodeStep = 0;
                }
            }
            else if (resultScreen->cheatCodeStep < 7)
            {
                if (WAS_PRESSED(TH_BUTTON_Q))
                {

                    resultScreen->cheatCodeStep++;
                }
                else if (WAS_PRESSED(TH_BUTTON_WRONG_CHEATCODE))
                {
                    resultScreen->cheatCodeStep = 0;
                }
            }
            else if (resultScreen->cheatCodeStep < 10)
            {
                if (WAS_PRESSED(TH_BUTTON_S))
                {
                    resultScreen->cheatCodeStep++;
                }
                else if (WAS_PRESSED(TH_BUTTON_WRONG_CHEATCODE))
                {
                    resultScreen->cheatCodeStep = 0;
                }
            }
            else
            {
                for (characterShotType = 0; characterShotType < HSCR_NUM_CHARS_SHOTTYPES; characterShotType++)
                {
                    for (difficulty = 0; difficulty < HSCR_NUM_DIFFICULTIES; difficulty++)
                    {
                        g_GameManager.clrd[characterShotType].difficultyClearedWithRetries[difficulty] = 99;
                        g_GameManager.clrd[characterShotType].difficultyClearedWithoutRetries[difficulty] = 99;
                    }
                }
                resultScreen->cheatCodeStep = 0;
                g_SoundPlayer.PlaySoundByIdx(SOUND_1UP, 0);
            }
        }
        else
        {
            resultScreen->cheatCodeStep = 0;
        }
    case RESULT_SCREEN_STATE_BEST_SCORES_EASY:
    case RESULT_SCREEN_STATE_BEST_SCORES_NORMAL:
    case RESULT_SCREEN_STATE_BEST_SCORES_HARD:
    case RESULT_SCREEN_STATE_BEST_SCORES_LUNATIC:

        if (resultScreen->charUsed != resultScreen->cursor && resultScreen->frameTimer == 20)
        {
            resultScreen->charUsed = resultScreen->cursor;
            AnmManager::DrawStringFormat2(g_AnmManager, &resultScreen->unk_28a0[0], COLOR_RGB(COLOR_WHITE),
                                          COLOR_RGB(COLOR_BLACK), g_CharacterList[resultScreen->charUsed * 2]);
            AnmManager::DrawStringFormat2(g_AnmManager, &resultScreen->unk_28a0[1], COLOR_RGB(COLOR_WHITE),
                                          COLOR_RGB(COLOR_BLACK), g_CharacterList[resultScreen->charUsed * 2 + 1]);
        }
        if (resultScreen->frameTimer < 30)
        {
            break;
        }
        if (ResultScreen::MoveCursorHorizontally(resultScreen, 2))
        {
            resultScreen->frameTimer = 0;
            vm = &resultScreen->unk_40[0];
            for (i = 0; i < ARRAY_SIZE_SIGNED(resultScreen->unk_40); i++, vm++)
            {
                vm->pendingInterrupt = resultScreen->diffSelected + 3;
            }
        }
        if (WAS_PRESSED(TH_BUTTON_RETURNMENU))
        {
            g_SoundPlayer.PlaySoundByIdx(SOUND_BACK, 0);
            resultScreen->resultScreenState = RESULT_SCREEN_STATE_INIT;
            resultScreen->frameTimer = 1;
            vm = &resultScreen->unk_40[0];
            for (i = 0; i < ARRAY_SIZE_SIGNED(resultScreen->unk_40); i++, vm++)
            {
                vm->pendingInterrupt = 1;
            }
            resultScreen->unk_14 = resultScreen->cursor;
            resultScreen->cursor = resultScreen->diffSelected;
        }

        break;

    case RESULT_SCREEN_STATE_SPELLCARDS:

        if (resultScreen->lastSpellcardSelected != resultScreen->cursor && resultScreen->frameTimer == 20)
        {

            resultScreen->lastSpellcardSelected = resultScreen->cursor;
            for (i = resultScreen->lastSpellcardSelected * 10; i < resultScreen->lastSpellcardSelected * 10 + 10; i++)
            {
                if (i >= ARRAY_SIZE_SIGNED(g_GameManager.catk))
                {
                    break;
                }
                if (g_GameManager.catk[i].numAttempts == 0)
                {
                    AnmManager::DrawVmTextFmt(g_AnmManager, &resultScreen->unk_28a0[i % 10], COLOR_RGB(COLOR_WHITE),
                                              COLOR_RGB(COLOR_BLACK), TH_UNKNOWN_SPELLCARD);
                }
                else
                {
                    AnmManager::DrawVmTextFmt(g_AnmManager, &resultScreen->unk_28a0[i % 10], COLOR_RGB(COLOR_WHITE),
                                              COLOR_RGB(COLOR_BLACK), g_GameManager.catk[i].name);
                }
            }
        }
        if (resultScreen->frameTimer < 30)
        {
            break;
        }
        if (ResultScreen::MoveCursorHorizontally(resultScreen, 7))
        {
            resultScreen->frameTimer = 0;
            vm = &resultScreen->unk_40[0];
            for (i = 0; i < ARRAY_SIZE_SIGNED(resultScreen->unk_40); i++, vm++)
            {
                vm->pendingInterrupt = resultScreen->diffSelected + 3;
            }
        }
        if (WAS_PRESSED(TH_BUTTON_RETURNMENU))
        {
            g_SoundPlayer.PlaySoundByIdx(SOUND_BACK, 0);
            resultScreen->resultScreenState = RESULT_SCREEN_STATE_INIT;
            resultScreen->frameTimer = 1;
            vm = &resultScreen->unk_40[0];
            for (i = 0; i < ARRAY_SIZE_SIGNED(resultScreen->unk_40); i++, vm++)
            {
                vm->pendingInterrupt = 1;
            }
            resultScreen->previousCursor = resultScreen->cursor;
            resultScreen->cursor = resultScreen->diffSelected;
        }
        break;

    case RESULT_SCREEN_STATE_WRITING_HIGHSCORE_NAME:
        resultScreen->HandleResultKeyboard();
        break;

    case RESULT_SCREEN_STATE_SAVE_REPLAY_QUESTION:
    case RESULT_SCREEN_STATE_UNK_11:
    case RESULT_SCREEN_STATE_CHOOSING_REPLAY_FILE:
    case RESULT_SCREEN_STATE_WRITING_REPLAY_NAME:
    case RESULT_SCREEN_STATE_OVERWRITE_REPLAY_FILE:
        resultScreen->HandleReplaySaveKeyboard();
        break;

    case RESULT_SCREEN_STATE_STATS_SCREEN:
    case RESULT_SCREEN_STATE_STATS_TO_SAVE_TRANSITION:
        resultScreen->CheckConfirmButton();
        break;
    };

    vm = &resultScreen->unk_40[0];
    for (i = 0; i < ARRAY_SIZE_SIGNED(resultScreen->unk_40); i++, vm++)
    {
        g_AnmManager->ExecuteScript(vm);
    }
    resultScreen->frameTimer++;
    return CHAIN_CALLBACK_RESULT_CONTINUE;
}
#pragma optimize("", on)

#pragma optimize("s", on)
#pragma var_order(strPos, row, name, sprite, ShootScoreListNodeA, column, ShootScoreListNodeB, spritePos,              \
                  spellcardIdx, charPos, unused, unused2, unused3, unk, keyboardCharacter)
ChainCallbackResult th06::ResultScreen::OnDraw(ResultScreen *resultScreen)
{
    u8 unused[12];
    u8 unused2;
    u8 unused3;

    AnmVm *sprite;
    char keyboardCharacter;
    u8 unk;
    ZunVec2 charPos;

    i32 spellcardIdx;
    ZunVec3 spritePos;
    ScoreListNode *ShootScoreListNodeB;
    i32 column;
    i32 row;
    ScoreListNode *ShootScoreListNodeA;

    char name[9];

    D3DXVECTOR3 strPos;

    sprite = &resultScreen->unk_40[0];
    g_Supervisor.viewport.X = 0;
    g_Supervisor.viewport.Y = 0;
    g_Supervisor.viewport.Width = 640;
    g_Supervisor.viewport.Height = 480;

    g_Supervisor.d3dDevice->SetViewport(&g_Supervisor.viewport);
    g_AnmManager->CopySurfaceToBackBuffer(0, 0, 0, 0, 0);

    for (row = 0; row < ARRAY_SIZE_SIGNED(resultScreen->unk_40); row++, sprite++)
    {
        *spritePos.AsD3dXVec() = sprite->pos;
        sprite->pos += sprite->posOffset;
        g_AnmManager->DrawNoRotation(sprite);
        sprite->pos = *spritePos.AsD3dXVec();
    }
    sprite = &resultScreen->unk_40[14];
    if (sprite->pos.x < 640.0f)
    {
        if (resultScreen->unk_c != 8)
        {
            *spritePos.AsD3dXVec() = sprite->pos;
            resultScreen->unk_28a0->pos = *spritePos.AsD3dXVec();
            g_AnmManager->DrawNoRotation(&resultScreen->unk_28a0[0]);

            spritePos.AsD3dXVec()->x += 320.0f;

            resultScreen->unk_28a0[1].pos = *spritePos.AsD3dXVec();
            g_AnmManager->DrawNoRotation(&resultScreen->unk_28a0[1]);

            spritePos.AsD3dXVec()->x -= -320.0f;
            spritePos.AsD3dXVec()->y += 18.0f;
            spritePos.AsD3dXVec()->y += 320.0f;

            ShootScoreListNodeA = resultScreen->scores[resultScreen->diffSelected][resultScreen->charUsed * 2].next;
            ShootScoreListNodeB = resultScreen->scores[resultScreen->diffSelected][resultScreen->charUsed * 2 + 1].next;
            for (row = 0; row < 10; row++)
            {
                if (resultScreen->resultScreenState == RESULT_SCREEN_STATE_WRITING_HIGHSCORE_NAME)
                {
                    if (g_GameManager.shotType == SHOT_TYPE_A)
                    {
                        if (ShootScoreListNodeA->data->base.unk_9 != 0)
                        {
                            g_AsciiManager.color = 0xfff0f0ff;

                            strcpy(name, "       ");
                            name[8] = 0;

                            name[resultScreen->cursor >= 8 ? 7 : resultScreen->cursor] = '_';
                            g_AsciiManager.AddFormatText(spritePos.AsD3dXVec(), "   %8s", &name);
                        }
                        else
                        {
                            g_AsciiManager.color = COLOR_SET_ALPHA(0x20ffffc0, 0x80);
                        }
                    }
                    else
                    {
                        g_AsciiManager.color = 0x80ffc0c0;
                    }
                }
                else
                {
                    g_AsciiManager.color = 0xffffc0c0;
                }
                g_AsciiManager.AddFormatText(spritePos.AsD3dXVec(), "%2d", row + 1);

                spritePos.x += 36.0f;
                if (ShootScoreListNodeA->data->stage <= 6)
                {
                    g_AsciiManager.AddFormatText(spritePos.AsD3dXVec(), "%8s %9d(%d)", ShootScoreListNodeA->data->name,
                                                 ShootScoreListNodeA->data->score, ShootScoreListNodeA->data->stage);
                }
                else if (ShootScoreListNodeA->data->stage == 7)
                {
                    g_AsciiManager.AddFormatText(spritePos.AsD3dXVec(), "%8s %9d(1)", ShootScoreListNodeA->data->name,
                                                 ShootScoreListNodeA->data->score);
                }
                else
                {
                    g_AsciiManager.AddFormatText(spritePos.AsD3dXVec(), "%8s %9d(C)", ShootScoreListNodeA->data->name,
                                                 ShootScoreListNodeA->data->score);
                }
                spritePos.AsD3dXVec()->x += 300.0f;
                if (resultScreen->resultScreenState == RESULT_SCREEN_STATE_WRITING_HIGHSCORE_NAME)
                {
                    if (g_GameManager.shotType == SHOT_TYPE_B)
                    {
                        if (ShootScoreListNodeB->data->base.unk_9 != 0)
                        {
                            g_AsciiManager.color = 0xfffff0f0;

                            strcpy(name, "       ");
                            name[8] = 0;

                            name[resultScreen->cursor >= 8 ? 7 : resultScreen->cursor] = '_';
                            g_AsciiManager.AddFormatText(spritePos.AsD3dXVec(), "%8s", &name);
                        }
                        else
                        {
                            g_AsciiManager.color = 0xc0c0c0ff;
                        }
                    }
                    else
                    {
                        g_AsciiManager.color = 0x80c0c0ff;
                    }
                }
                else
                {
                    g_AsciiManager.color = 0xffc0c0ff;
                }
                if (ShootScoreListNodeB->data->stage <= 6)
                {
                    g_AsciiManager.AddFormatText(spritePos.AsD3dXVec(), "%8s %9d(%d)", ShootScoreListNodeB->data->name,
                                                 ShootScoreListNodeB->data->score, ShootScoreListNodeB->data->stage);
                }
                else if (ShootScoreListNodeB->data->stage == 7)
                {
                    g_AsciiManager.AddFormatText(spritePos.AsD3dXVec(), "%8s %9d(1)", ShootScoreListNodeB->data->name,
                                                 ShootScoreListNodeB->data->score);
                }
                else
                {
                    g_AsciiManager.AddFormatText(spritePos.AsD3dXVec(), "%8s %9d(C)", ShootScoreListNodeB->data->name,
                                                 ShootScoreListNodeB->data->score);
                }
                spritePos.AsD3dXVec()->x -= 336.0f;
                spritePos.AsD3dXVec()->y += 336.0f;
                ShootScoreListNodeA = ShootScoreListNodeA->next;
                ShootScoreListNodeB = ShootScoreListNodeB->next;
            }
        }
        else
        {

            *spritePos.AsD3dXVec() = sprite->pos;
            spritePos.AsD3dXVec()->y += 16.0f;

            for (row = 0; row < 10; row++)
            {
                spellcardIdx = resultScreen->lastSpellcardSelected * 10 + row;
                if (spellcardIdx >= ARRAY_SIZE_SIGNED(g_GameManager.catk))
                {
                    break;
                }

                resultScreen->unk_28a0[row].pos = *spritePos.AsD3dXVec();
                if (g_GameManager.catk[spellcardIdx].numAttempts == 0)
                {
                    g_AsciiManager.color = 0x80c0c0ff;
                }
                else if (g_GameManager.catk[spellcardIdx].numSuccess == 0)
                {
                    g_AsciiManager.color = 0xffc0a0a0;
                }
                else
                {
                    g_AsciiManager.color = 0xfff0f0ff - row * 0x80800;
                }
                g_AsciiManager.AddFormatText(spritePos.AsD3dXVec(), "No.%.2d", spellcardIdx + 1);

                // TODO: This is really cursed, there has to be a better way
                (*(ZunVec3 *)&resultScreen->unk_28a0[row].pos).AsD3dXVec()->x += 96.0f;

                g_AnmManager->DrawNoRotation(&resultScreen->unk_28a0[row]);

                spritePos.AsD3dXVec()->x += 368.0f;

                g_AsciiManager.AddFormatText(spritePos.AsD3dXVec(), "%3d/%3d",
                                             g_GameManager.catk[spellcardIdx].numSuccess,
                                             g_GameManager.catk[spellcardIdx].numAttempts);
                spritePos.AsD3dXVec()->x -= 368.0f;
                spritePos.AsD3dXVec()->y += 30.0f;
            }
        }
    }
    if (resultScreen->resultScreenState == RESULT_SCREEN_STATE_WRITING_HIGHSCORE_NAME ||
        resultScreen->resultScreenState == RESULT_SCREEN_STATE_WRITING_REPLAY_NAME)
    {
        *spritePos.AsD3dXVec() = D3DXVECTOR3(160.0f, 356.0f, 0.0f);

        for (row = 0; row < RESULT_KEYBOARD_ROWS; row++)
        {
            for (column = 0; column < RESULT_KEYBOARD_COLUMNS; column++)
            {
                charPos.y = 0.0f;
                charPos.x = 0.0f;
                if (resultScreen->selectedCharacter == row * RESULT_KEYBOARD_COLUMNS + column)
                {
                    g_AsciiManager.color = COLOR_KEYBOARD_KEY_HIGHLIGHT;
                    if (resultScreen->frameTimer % 64 < 32)
                    {
                        charPos.y = 1.2f + 0.8f * (resultScreen->frameTimer % 0x20) / 32.0f;
                    }
                    else
                    {
                        charPos.y = 2.0f - 0.8f * (resultScreen->frameTimer % 0x20) / 32.0f;
                    }
                    g_AsciiManager.scale.x = charPos.y;
                    g_AsciiManager.scale.y = charPos.y;
                    charPos.y = -(charPos.y - 1.0f) * 8.0f;
                    charPos.x = charPos.y;
                }
                else
                {
                    g_AsciiManager.color = COLOR_KEYBOARD_KEY_NORMAL;
                    g_AsciiManager.scale.x = 1.0f;
                    g_AsciiManager.scale.y = 1.0f;
                }
                strPos = *spritePos.AsD3dXVec();
                strPos.x += charPos.y;
                strPos.y += charPos.x;
                keyboardCharacter = g_AlphabetList[row * RESULT_KEYBOARD_COLUMNS + column];
                unk = 0;

                if (row == 5)
                {
                    if (column == 14)
                    {
                        keyboardCharacter = 0x80; // SP
                    }
                    else if (column == 15)
                    {
                        keyboardCharacter = 0x81; // END
                    }
                }

                g_AsciiManager.AddString(&strPos, &keyboardCharacter);

                spritePos.AsD3dXVec()->x += 20.0f;
            }
            spritePos.AsD3dXVec()->x -= column * 20;
            spritePos.AsD3dXVec()->y += 18.0f;
        }
    }
    g_AsciiManager.scale.x = 1.0;
    g_AsciiManager.scale.y = 1.0;
    if ((resultScreen->resultScreenState >= RESULT_SCREEN_STATE_SAVE_REPLAY_QUESTION) &&
        (resultScreen->resultScreenState <= RESULT_SCREEN_STATE_OVERWRITE_REPLAY_FILE))
    {
        sprite = &resultScreen->unk_40[15];
        for (row = 0; row < 6; row++, sprite++)
        {
            g_AnmManager->DrawNoRotation(sprite);
        }
        sprite = &resultScreen->unk_40[21];
        *spritePos.AsD3dXVec() = sprite->pos;
        sprite++;
        g_AsciiManager.AddFormatText(spritePos.AsD3dXVec(), "No.   Name     Date     Player Score");
        for (row = 0; row < ARRAY_SIZE_SIGNED(resultScreen->replays); row++)
        {
            *spritePos.AsD3dXVec() = sprite->pos;
            sprite++;
            if (row == resultScreen->replayNumber)
            {
                g_AsciiManager.color = COLOR_LIGHT_RED;
            }
            else
            {
                g_AsciiManager.color = COLOR_GREY;
            }
            if (resultScreen->resultScreenState == RESULT_SCREEN_STATE_WRITING_REPLAY_NAME)
            {
                g_AsciiManager.AddFormatText(spritePos.AsD3dXVec(), "No.%.2d %8s %8s %7s %9d", row + 1,
                                             &resultScreen->replayName, resultScreen->defaultReplayMaybe.date,
                                             g_ShortCharacterList2[g_GameManager.CharacterShotType()],
                                             resultScreen->defaultReplayMaybe.score);
                g_AsciiManager.color = 0xfff0f0ff;

                strcpy(name, "       ");

                name[8] = 0;

                name[resultScreen->cursor >= 8 ? 7 : resultScreen->cursor] = '_';
                g_AsciiManager.AddFormatText(spritePos.AsD3dXVec(), "      %8s", &name);
            }
            else if (*(i32 *)&resultScreen->replays[row].magic != *(i32 *)"T6RP" ||
                     resultScreen->replays[row].version != 0x102)
            {
                g_AsciiManager.AddFormatText(spritePos.AsD3dXVec(), "No.%.2d -------- --/--/-- -------         0",
                                             row + 1);
            }
            else
            {
                g_AsciiManager.AddFormatText(spritePos.AsD3dXVec(), "No.%.2d %8s %8s %7s %9d", row + 1,
                                             resultScreen->replays[row].name, resultScreen->replays[row].date,
                                             g_ShortCharacterList2[resultScreen->replays[row].shottypeChara],
                                             resultScreen->replays[row].score);
            }
        }
    }
    g_AsciiManager.color = COLOR_WHITE;
    resultScreen->DrawFinalStats();

    return CHAIN_CALLBACK_RESULT_CONTINUE;
}
#pragma optimize("", on)

}; // namespace th06