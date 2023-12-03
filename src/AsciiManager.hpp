#pragma once

#include "Chain.hpp"
#include "ZunResult.hpp"
#include "inttypes.hpp"

struct AsciiManager
{
    static ZunResult RegisterChain();

    static ChainCallbackResult OnUpdate(AsciiManager *s);
    static ChainCallbackResult OnDrawLowPrio(AsciiManager *s);
    static ChainCallbackResult OnDrawHighPrio(AsciiManager *s);
    static ZunResult AddedCallback(AsciiManager *s);
    static void DeletedCallback(AsciiManager *s);

    void InitializeVms();
};
