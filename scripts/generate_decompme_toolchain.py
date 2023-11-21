# Generates a toolchain compatible with decompme's win9x support[0] from a
# prefix generated with create_th06_prefix
#
# [0]: https://github.com/decompme/decomp.me/pull/802
import os
import shutil
from pathlib import Path


def main():
    script_path = Path(os.path.dirname(os.path.realpath(__file__)))

    prefix_path = script_path / "prefix"

    vc7_path = prefix_path / "PROGRAM FILES" / "MICROSOFT VISUAL STUDIO .NET" / "VC7"
    ide_path = (
        prefix_path
        / "PROGRAM FILES"
        / "MICROSOFT VISUAL STUDIO .NET"
        / "COMMON7"
        / "IDE"
    )
    dx8sdk_path = prefix_path / "mssdk"

    decompme_toolchain = script_path / "msvc70"

    decompme_toolchain.mkdir()

    # First, create bin directory
    decompme_bin = decompme_toolchain / "Bin"
    decompme_bin.mkdir()
    # Copy all the programs in vc7_path bin to our bin. Lowercase them.
    vc7_bin = vc7_path / "BIN"
    for src_file in vc7_bin.glob("*"):
        if not src_file.is_file():
            continue

        dst_file = decompme_bin / src_file.relative_to(vc7_bin)
        dst_file = dst_file.parent / dst_file.name.lower()

        print(src_file, "->", dst_file)
        shutil.copyfile(src_file, dst_file)

    # Copy a handful of necessary dlls from ide_path to our bin
    shutil.copyfile(ide_path / "MSPDB70.DLL", decompme_bin / "mspdb70.dll")
    shutil.copyfile(ide_path / "MSOBJ10.DLL", decompme_bin / "msobj10.dll")

    # Next, create the Include directory
    decompme_include = decompme_toolchain / "Include"
    decompme_include.mkdir()

    # Start with VC7 includes.
    vc7_include = vc7_path / "INCLUDE"
    for src_file in vc7_include.rglob("*"):
        if not src_file.is_file():
            continue

        dst_file = decompme_include / src_file.relative_to(vc7_include)
        dst_file = dst_file.parent / dst_file.name.upper()

        # First, ensure parent directory exists
        dst_file.parent.mkdir(exist_ok=True)

        # Then, copy the file.
        shutil.copyfile(src_file, dst_file)

    # Then, copy the PlatformSDK
    platform_sdk_include = vc7_path / "PlatformSDK" / "Include"
    for src_file in platform_sdk_include.rglob("*"):
        if not src_file.is_file():
            continue

        dst_file = decompme_include / src_file.relative_to(platform_sdk_include)
        dst_file = dst_file.parent / dst_file.name.upper()

        # First, ensure parent directory exists
        dst_file.parent.mkdir(exist_ok=True)

        # Then, copy the file.
        shutil.copyfile(src_file, dst_file)

    # Finally, copy DXSDK
    dx8sdk_include = dx8sdk_path / "include"
    for src_file in dx8sdk_include.rglob("*"):
        if not src_file.is_file():
            continue

        dst_file = decompme_include / src_file.relative_to(dx8sdk_include)
        dst_file = dst_file.parent / dst_file.name.upper()

        # First, ensure parent directory exists
        dst_file.parent.mkdir(exist_ok=True)

        # Then, copy the file.
        shutil.copyfile(src_file, dst_file)


if __name__ == "__main__":
    main()
