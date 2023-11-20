// Helpers to improve the diff quality of DIFFBUILDs.
//
// A DIFFBUILD is a build of the project made not to be run, but to be diffed
// against the original TH06 to find inaccuracies in our reimplementation. To
// make a DIFFBUILD, one must call the makefile with DIFFBUILD=1
//
// This helper provides two macros: DIFFABLE_EXTERN and DIFFABLE_STATIC. All
// static variables should be defined and declared through those macros. So for
// instance, instead of
//
// ```
// Stage g_Stage;
// ```
//
// One should write
//
// ```
// DIFFABLE_STATIC(Stage, g_Stage)
// ```
//
// The first argument is the type, while the second argument is the name of the
// static variable.

#pragma once

#ifdef DIFFBUILD
#define DIFFABLE_EXTERN(type, name)                                                                                    \
    extern "C"                                                                                                         \
    {                                                                                                                  \
        extern type name;                                                                                              \
    }
#define DIFFABLE_STATIC(type, name)                                                                                    \
    extern "C"                                                                                                         \
    {                                                                                                                  \
        extern type name;                                                                                              \
    }
#else
#define DIFFABLE_EXTERN(type, name) extern type name;
#define DIFFABLE_STATIC(type, name) type name;
#endif
