#pragma once

#include "AnmVm.hpp"
#include "ZunResult.hpp"
#include "inttypes.hpp"

namespace th06
{

enum ResultScreenState
{
    RESULT_SCREEN_STATE_UNK_0 = 0,
    RESULT_SCREEN_STATE_UNK_1,
    RESULT_SCREEN_STATE_UNK_2,
    RESULT_SCREEN_STATE_UNK_3,
    RESULT_SCREEN_STATE_UNK_4,
    RESULT_SCREEN_STATE_UNK_5,
    RESULT_SCREEN_STATE_UNK_6,
    RESULT_SCREEN_STATE_UNK_7,
    RESULT_SCREEN_STATE_UNK_8,
    RESULT_SCREEN_STATE_UNK_9,
    RESULT_SCREEN_STATE_UNK_10,
    RESULT_SCREEN_STATE_UNK_11,
    RESULT_SCREEN_STATE_UNK_12,
    RESULT_SCREEN_STATE_UNK_13,
    RESULT_SCREEN_STATE_UNK_14,
    RESULT_SCREEN_STATE_UNK_15,
    RESULT_SCREEN_STATE_UNK_16,
    RESULT_SCREEN_STATE_UNK_17,
};
struct Th6k
{
    u32 magic;
    u16 th6kLen;
    u16 unkLen;
    u8 version;
};
C_ASSERT(sizeof(Th6k) == 0xc);

struct Catk
{
    Th6k base;
    i32 captureScore;
    u16 idx;
    u8 nameCsum;
    u8 characterShotType;
    u32 unk_14;
    char name[32];
    u32 numAttempts;
    u16 numSuccess;
    u16 unk_3e;
};
C_ASSERT(sizeof(Catk) == 0x40);

struct Clrd
{
    Th6k base;
    u8 difficultyClearedWithRetries[5];
    u8 difficultyClearedWithoutRetries[5];
    u8 characterShotType;
};
C_ASSERT(sizeof(Clrd) == 0x18);

struct Pscr
{
    Th6k base;
    i32 score;
    u8 character;
    u8 difficulty;
    u8 stage;
};
C_ASSERT(sizeof(Pscr) == 0x14);

struct Hscr
{
    Th6k base;
    u32 score;
    u8 character;
    u8 difficulty;
    u8 stage;
    u8 name[9];
};
C_ASSERT(sizeof(Hscr) == 0x1c);

struct ScoreListNode
{
    ScoreListNode()
    {
        this->prev = NULL;
        this->next = NULL;
        this->data = NULL;
    }

    ScoreListNode *prev;
    ScoreListNode *next;
    Hscr *data;
};
C_ASSERT(sizeof(ScoreListNode) == 0xc);

struct ScoreDat
{
    u8 xorseed[2];
    u16 csum;
    u8 unk[4];
    u32 dataOffset;
    ScoreListNode *scores;
    u32 fileLen;
};
C_ASSERT(sizeof(ScoreDat) == 0x14);

struct ResultScreen
{
    ResultScreen();

    static ZunResult RegisterChain(i32 unk);
    static ChainCallbackResult OnUpdate(ResultScreen *r);
    static ChainCallbackResult OnDraw(ResultScreen *r);
    static ZunResult AddedCallback(ResultScreen *r);
    static ZunResult DeletedCallback(ResultScreen *r);

    static ScoreDat *OpenScore(char *path);
    static ZunResult ParseCatk(ScoreDat *s, Catk *catk);
    static ZunResult ParseClrd(ScoreDat *s, Clrd *out);
    static ZunResult ParsePscr(ScoreDat *s, Pscr *out);
    static u32 GetHighScore(ScoreDat *score_dat, ScoreListNode *node, u32 character, u32 difficulty);
    static void ReleaseScoreDat(ScoreDat *s);

    ScoreDat *scoreDat;
    i32 unk_4;
    i32 resultScreenState;
    i32 unk_c;
    i32 cursor;
    i32 unk_14[3];
    i32 selectedCharacter;
    i32 charUsed;
    i32 unk_28;
    i32 *unk_2c;
    i32 unk_30[4];
    AnmVm unk_40[38];
    AnmVm unk_28a0[16];
    AnmVm unk_39a0;
    ScoreListNode scores[20];
    Hscr defaultScore[5][4][10];
    Hscr hscr;
    u8 unk_519c[12];
    ChainElem *calcChain;
    ChainElem *drawChain;
    u8 unk_51b0[1216];
    char date[9];
    u8 unk_5679[11];
    u32 score;
    u8 unk_5688[40];
};
C_ASSERT(sizeof(ResultScreen) == 0x56b0);
}; // namespace th06
