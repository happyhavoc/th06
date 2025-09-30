NPROC=$(nproc)

CLEAN=false
for arg in "$@"; do
    if [ "$arg" = "--clean" ]; then
        CLEAN=TRUE
    fi
done;

if [ "$CLEAN" = "TRUE" ]; then
    rm -rf build
    rm -rf obj/
    rm th06
fi

premake5 --cc=clang ninja
cd build
ninja -j${NPROC}
