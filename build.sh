#!/usr/bin/env bash
set -e

NPROC=$(nproc)
BUILD_TYPE="Debug"

for arg in "$@"; do
    if [ "$arg" = "--clean" ]; then
        CLEAN=true
    elif [ "$arg" = "Release" ] || [ "$arg" = "Debug" ] || [ "$arg" = "All" ]; then
        BUILD_TYPE=$arg
    fi
done

if [ "$CLEAN" = true ]; then
    rm -rf build obj
    rm -f th06_*
fi


premake5 --cc=clang ninja
cd build

if [ "$BUILD_TYPE" = "All" ]; then
    ninja -j${NPROC} Debug Release
else
    ninja -j${NPROC} $BUILD_TYPE
fi
