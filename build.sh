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

premake5 --cc=clang gmake
cd build
make -j${nproc} && cd ..
