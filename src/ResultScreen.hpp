#pragma once

#include "ZunResult.hpp"
#include "inttypes.hpp"

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
    static ZunResult RegisterChain(i32 unk);

    static ScoreDat *OpenScore(char *path);
    static ZunResult ParseCatk(ScoreDat *s, Catk *catk);
    static ZunResult ParseClrd(ScoreDat *s, Clrd *out);
    static ZunResult ParsePscr(ScoreDat *s, Pscr *out);
    static u32 GetHighScore(ScoreDat *score_dat, ScoreListNode *node, u32 character, u32 difficulty);
    static void ReleaseScoreDat(ScoreDat *s);
};
