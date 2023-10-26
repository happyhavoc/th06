// This wraps the C1XX.DLL to add two new pragmas to the CL.EXE compiler:
//
// - var_order, which allows fixing the order of stack variables. To use, call
//   it before your function with #pragma var_order(var1, var2, var3). The
//   variables will then be placed on the stack, from highest to lowest (so
//   var1 will be at EBP-4, var2 at EBP-8, and var3 at EBP-12).
// - var_debug, which gives some information about how stack variables are
//   added to CL's internal data structures.
//
// To use this, first, build it with CL.EXE:
//
// $ cl.exe /LD pragma_var_order.cpp
//
// Then, rename the C1XX.DLL file to C1XXOrig.dll in your MSVC7 installation,
// usually found in C:\Program Files\Micrsoft Visual Studio .NET\VC7\BIN.
// Finally, put the compiled DLL where the C1XX.DLL used to be.
//
// Original by Treeki: https://gist.github.com/Treeki/b4552be7537bdbc11706fefc3e5efd0b
// Modified by EstexNT to work on MSVC7: https://gist.github.com/EstexNT/e98a1384b906a3eedaaa3eeb7e58cd9d

#include <stdio.h>
#include <windows.h>

HMODULE originalDLL = NULL;

inline DWORD dllAddr(DWORD address)
{
    return ((DWORD)originalDLL) + address;
}

template <typename T> T dllPtr(DWORD address)
{
    T ptr = (T)(((DWORD)originalDLL) + address);
    return ptr;
}

struct FileEntry;
struct Parser;
struct ParserCtx;
struct Token;
struct TokenStream;

Parser *parser;
DWORD _Parser_Parse_addr;
__declspec(naked) Token *__fastcall _Parser_Parse_shim(Parser *parser)
{
    __asm {
        push [_Parser_Parse_addr]
        retn
    }
}

struct HashNode;
typedef void(__fastcall *ScanListCallback_t)(HashNode *ident);
typedef void (*ScanList_t)();
ScanList_t ScanList;

// the two shims below are required because of custom calling conventions in the original executable for those functions
__declspec(naked) void __cdecl ScanList_shim(ScanListCallback_t cb)
{
    __asm {
        mov esi, [esp + 4] // cb
        push [ScanList]
        retn
    }
}

typedef Token *(*ExpectToken_t)();
ExpectToken_t ExpectToken;

__declspec(naked) Token *__cdecl ExpectToken_shim(unsigned int tk)
{
    __asm {
        mov edi, [esp + 4] // tk
        push [ExpectToken]
        retn
    }
}

struct HashNode
{
    HashNode *next;
    const char *str;
    int hash;
    int xC;
    unsigned char tk;
    unsigned char keywordType;
};

struct Entry
{
    HashNode *name;
    struct Entry *next;
};

struct Object
{
    int x0;
    int x4;
    Entry entry;
};

struct SrcInfo
{
    FileEntry *file;
    int line;
};

enum
{
    L_OPEN_PAREN = 0x31,
    L_CLOSE_PAREN = 0x32
};

struct Token
{
    unsigned char tk;
    unsigned char _[7];
    union {
        unsigned char rawData[0x28];
        char *string;
        HashNode *identifier;
        TokenStream *tokenStream;
    };
};

struct TokenStream
{
    // we don't care about the internals here :p
    virtual Token *FetchToken();
    virtual Token *PeekToken();
    virtual void UnfetchToken(Token *token);
    virtual void AppendToken(Token *token);
    virtual BOOL GetType();
    virtual void Reset();
    virtual ~TokenStream();
};

struct ParserCtx
{
    TokenStream *stream;
    ParserCtx *parent;
    SrcInfo srcInfo;
    int x10;
    void (*teardownFunc)(void);
};

struct Parser
{
    SrcInfo srcInfo;
    ParserCtx *ctx;

    Token *Parse()
    {
        return _Parser_Parse_shim(this);
    }
};

struct Scope
{
    void *vtable;
    void *x4;
    void *x8;
    void *xC;
    void *x10;
    Entry **nodes;
    int hashMask;

    void Add(Object *object); // custom
};

// custom functions
int __fastcall IdentifyPragma(int a, const char *str);

void HandlePragmaHack();
DWORD HandlePragmaAfterSwitch;

// **************************************************
// Load our nonsense
// **************************************************
union PTMFCrimes {
    void (Scope::*addFn)(Object *);
    void *rawPtr;
};

void Branch(DWORD address, void *target)
{
    DWORD sourceV = dllAddr(address);
    DWORD targetV = (DWORD)target;
    DWORD delta = targetV - (sourceV + 5);

    *dllPtr<unsigned char *>(address) = 0xE9;
    *dllPtr<DWORD *>(address + 1) = delta;
}
void Call(DWORD address, void *target)
{
    DWORD sourceV = dllAddr(address);
    DWORD targetV = (DWORD)target;
    DWORD delta = targetV - (sourceV + 5);

    *dllPtr<unsigned char *>(address) = 0xE8;
    *dllPtr<DWORD *>(address + 1) = delta;
}

class Unprotector
{
    const char *mName;
    void *mAddress;
    DWORD mSize;
    DWORD mOldProtect;
    BOOL mSuccess;

  public:
    Unprotector(const char *name, DWORD address, DWORD size, DWORD newProtect)
    {
        mName = name;
        mAddress = dllPtr<void *>(address);
        mSize = size;
        mSuccess = false;

        if (VirtualProtect(mAddress, mSize, newProtect, &mOldProtect))
        {
            // printf("Protected %s (%p..%p) - oldProtect=%x newProtect=%x\n", mName, mAddress, (char*)mAddress + mSize,
            // mOldProtect, newProtect);
            mSuccess = true;
        }
        else
        {
            printf("!!! Failed to protect %s !!!\n", mName);
        }
    }

    ~Unprotector()
    {
        if (mSuccess)
        {
            if (VirtualProtect(mAddress, mSize, mOldProtect, &mOldProtect))
            {
                // printf("Unprotected %s\n", mName);
            }
            else
            {
                printf("!!! Failed to unprotect %s !!!\n", mName);
            }
        }
        else
        {
            printf("%s was not protected\n", mName);
        }
    }
};

void InjectHacks()
{
    PTMFCrimes crimes;
    Unprotector textProt(".text", 0x1000, 0x140000, PAGE_EXECUTE_READWRITE);
    Unprotector rdataProt(".rdata", 0x141000, 0x33000, PAGE_READWRITE);

    ExpectToken = (ExpectToken_t)dllAddr(0x18eaf);
    ScanList = (ScanList_t)dllAddr(0x64f54);

    parser = dllPtr<Parser *>(0x1a1b7c);
    _Parser_Parse_addr = dllAddr(0x3550);

    Branch(0x19fc7, IdentifyPragma);

    HandlePragmaAfterSwitch = dllAddr(0x19070);
    Call(0x18f19, HandlePragmaHack);
    *dllPtr<unsigned char *>(0x18f1e) = 0x90; // call is only 5 bytes but the replaced insn is 6

    crimes.addFn = &Scope::Add;
    *dllPtr<void **>(0x1424b4) = crimes.rawPtr;
    *dllPtr<void **>(0x1424e8) = crimes.rawPtr;
    *dllPtr<void **>(0x14251c) = crimes.rawPtr;
}

// **************************************************
// Custom code
// **************************************************
#pragma test

// this is likely custom calling convention too but it matches with __fastcall so..
int __fastcall IdentifyPragma(int a, const char *str)
{
    const char **nameTable = dllPtr<const char **>(0x146090);
    unsigned char *offsets = dllPtr<unsigned char *>(0x145cc0);
    int *values = dllPtr<int *>(0x145ce0);

    // printf("pragma: %s\n", str);
    if (!strcmp(str, "var_debug"))
        return 98;
    if (!strcmp(str, "var_order"))
        return 99;

    if (str[0] >= 'a')
    {
        int start = offsets[str[0] - '_'];
        int end = offsets[str[0] - '_' + 1];
        for (int i = start; i < end; i++)
        {
            if (!strcmp(nameTable[i], str + 1))
                return values[i];
        }
    }
    return -1;
}

bool varDebug = false;
void DoVarDebug()
{
    varDebug = true;
}

HashNode *ordering[256];
int orderingPos = 0;
Scope *outerScope = NULL;

void __fastcall VarOrderCB(HashNode *ident)
{
    // printf("got [%s]\n", ident->str);
    ordering[orderingPos++] = ident;
}

void DoVarOrder()
{
    if (ExpectToken_shim(L_OPEN_PAREN))
    {
        // printf("scan begin\n");
        outerScope = NULL;
        orderingPos = 0;
        ScanList_shim(VarOrderCB);
        ExpectToken_shim(L_CLOSE_PAREN);
        // printf("scan end - %d vars\n", orderingPos);
    }
}

// replaces 18f19 (ja 84e99)
__declspec(naked) void HandlePragmaHack()
{
    __asm {
        // what do we have here?
        cmp eax, 98
        je callVarDebug
        cmp eax, 99
        je callVarOrder

            // we don't know how to process this so just come back
            // the switch block will catch the original comparison anyway
        cmp eax, 255
        retn

    callVarDebug:
        call DoVarDebug
        add esp, 4 // kill our existing return ptr
        push [HandlePragmaAfterSwitch] // ...and replace it
        retn
    callVarOrder:
        call DoVarOrder
        add esp, 4 // kill our existing return ptr
        push [HandlePragmaAfterSwitch] // ...and replace it
        retn
    }
}

void Scope::Add(Object *object)
{
    unsigned short index = object->entry.name->hash & hashMask;
    if (hashMask == 15 && outerScope == NULL && orderingPos > 0)
    {
        outerScope = this;
        hashMask = 0;
    }
    if (hashMask == 0)
    {
        index = 0;

        // find the right place in the list to put it, based off our ordering

        // if the requested ordering is [a,b,c,d]
        // then we want the linked list chain a->b->c->d

        // first, what's the new var's position in the ordering list?
        int indexOfName = -1;
        for (int i = 0; i < orderingPos; i++)
        {
            if (object->entry.name == ordering[i])
            {
                indexOfName = i;
                break;
            }
        }

        Entry *addAfter = NULL;

        // if this variable is in the list, then find the last existing one before it
        if (indexOfName >= 0)
        {
            for (Entry *scan = nodes[0]; scan; scan = scan->next)
            {
                for (int i = 0; i < indexOfName; i++)
                {
                    if (scan->name == ordering[i])
                    {
                        addAfter = scan;
                        break;
                    }
                }
            }
        }

        if (varDebug)
        {
            if (addAfter)
            {
                printf("scope:%p add:%s idx:%d after:%s\n", this, object->entry.name->str, indexOfName,
                       addAfter->name->str);
            }
            else
            {
                printf("scope:%p add:%s idx:%d at start\n", this, object->entry.name->str, indexOfName);
            }
        }

        if (addAfter)
        {
            // place the new lad into the list here
            object->entry.next = addAfter->next;
            addAfter->next = &object->entry;
        }
        else
        {
            // place the new lad onto the beginning of the list as usual
            object->entry.next = nodes[index];
            nodes[index] = &object->entry;
        }
    }
    else
    {
        // original behaviour for other kinds of scopes
        object->entry.next = nodes[index];
        nodes[index] = &object->entry;
    }
}

// **************************************************
// Expose the original API
// **************************************************
typedef int(__stdcall *ICPType)(int, int, int);
typedef void(__stdcall *ACPType)(int);
ICPType originalICP = NULL;
ACPType originalACP = NULL;

extern "C" int __declspec(dllexport) __stdcall InvokeCompilerPass(int a, int b, int c)
{
    if (!originalDLL)
    {
        originalDLL = LoadLibrary("C1XXOrig.dll");
        originalICP = (ICPType)GetProcAddress(originalDLL, "_InvokeCompilerPass@12");
        originalACP = (ACPType)GetProcAddress(originalDLL, "_AbortCompilerPass@4");
        // printf("got %p\n (icp=%p acp=%p)\n", originalDLL, originalICP, originalACP);
        InjectHacks();
    }

    // printf("compiling\n");
    int result = originalICP(a, b, c);
    // printf("compile complete\n");
    return result;
}

extern "C" void __declspec(dllexport) __stdcall AbortCompilerPass(int a)
{
    originalACP(a);
}

extern "C" BOOL WINAPI DllMain(HINSTANCE const instance, DWORD const reason, LPVOID const reserved)
{
    switch (reason)
    {
    case DLL_PROCESS_ATTACH:
        break;
    case DLL_PROCESS_DETACH:
        if (originalDLL)
        {
            FreeLibrary(originalDLL);
            originalDLL = NULL;
            originalICP = NULL;
            originalACP = NULL;
        }
        break;
    }

    return TRUE;
}
