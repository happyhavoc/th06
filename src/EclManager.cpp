#include "EclManager.hpp"
#include "FileSystem.hpp"
#include "GameErrorContext.hpp"

DIFFABLE_STATIC(RunningSpellcardInfo, g_RunningSpellcardInfo);
DIFFABLE_STATIC(EclManager, g_EclManager);

ZunResult EclManager::Load(char *eclPath)
{
    i32 idx;

    this->eclFile = (EclRawHeader *)FileSystem::OpenPath(eclPath, false);
    if (this->eclFile == NULL)
    {
        GameErrorContextLog(&g_GameErrorContext, TH_ERR_ECLMANAGER_ENEMY_DATA_CORRUPT);
        return ZUN_ERROR;
    }
    this->eclFile->timelineOffsets[0] = (void *)((int)this->eclFile->timelineOffsets[0] + (int)this->eclFile);
    this->subTable = &this->eclFile->subOffsets[0];
    for (idx = 0; idx < this->eclFile->subCount; idx++)
    {
        this->subTable[idx] = (void *)((int)this->subTable[idx] + (int)this->eclFile);
    }
    this->timeline = this->eclFile->timelineOffsets[0];
    return ZUN_SUCCESS;
}
