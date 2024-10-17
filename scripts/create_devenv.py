from argparse import ArgumentParser, Namespace
from datetime import datetime
import hashlib
import os
import os.path
from pathlib import Path
import platform
import shutil
import stat
import subprocess
import sys
import zipfile

try:
    from typing import Optional
except ImportError:
    pass
import urllib.request

from winhelpers import run_windows_program, get_windows_path

SCRIPTS_DIR = Path(__file__).parent


def run_msiextract(msi_file_path: Path, output_dir: Path) -> int:
    return subprocess.check_call(
        ["msiextract", str(msi_file_path)], cwd=str(output_dir)
    )


def cmd_quote(s):
    if '"' in s:
        raise ValueError(
            "Couldn't quote '{s}' as it contains the double quote \" character.".format(
                s=s
            )
        )
    if " " not in s:
        return s
    return '"' + s.replace("\\", "\\\\").replace('"', '"') + '"'


def run_msiextract_win32(msi_file_path: Path, output_dir: Path) -> int:
    return subprocess.check_call(
        "msiexec /a "
        + cmd_quote(str(msi_file_path))
        + " /qb TARGETDIR="
        + cmd_quote(str(output_dir)),
        cwd=str(output_dir),
        # We need to use shell=True as msiexec does some very funky parsing of the command line arguments.
        shell=True,
    )


def translate_msiextract_name(raw_name: str) -> "Optional[str]":
    name = raw_name.split(":")[0]

    if name == ".":
        return None

    return name


def msiextract(msi_file_path: Path, output_dir: Path) -> int:
    os.makedirs(str(output_dir), exist_ok=True)
    if sys.platform == "win32":
        run_msiextract_win32(msi_file_path, output_dir)

        return

    run_msiextract(msi_file_path, output_dir)

    for dir in output_dir.glob("**/.:*"):
        parent_dir = dir.parent

        for entry in dir.glob("*"):
            new_entry = parent_dir / entry.name
            print("Renaming " + str(entry) + " -> " + str(new_entry))
            if not new_entry.exists():
                shutil.move(str(entry), str(new_entry))
            else:
                copytree_exist_ok(str(entry), str(new_entry))
                shutil.rmtree(str(entry))

        dir.rmdir()

    should_continue = True
    while should_continue:
        renamed_something = False

        for entry in output_dir.glob("**"):
            if entry.is_dir():
                new_name = translate_msiextract_name(entry.name)

                if new_name is None:
                    continue

                new_entry = entry.parent / new_name

                if entry != new_entry:
                    print("Renaming " + str(entry) + " -> " + str(new_entry))
                    if not new_entry.exists():
                        shutil.move(str(entry), str(new_entry))
                        renamed_something = True
                        break
                    else:
                        copytree_exist_ok(str(entry), str(new_entry))
                        shutil.rmtree(str(entry))
                        renamed_something = True
                        break

        should_continue = renamed_something


def copytree_exist_ok(src: Path, dst: Path):
    if sys.version_info >= (3, 8):
        shutil.copytree(src, dst, dirs_exist_ok=True)
    else:
        import distutils.dir_util

        distutils.dir_util.copy_tree(str(src), str(dst))


def check_file(path: Path, message: str) -> Path:
    if not path.exists():
        sys.stderr.write(message + "\n")
        sys.exit(1)

    return path.absolute()


ONLY_CHOICES = ["vs", "dx8", "py", "pragma", "ninja", "satsuki", "ghidra", "objdiff"]


def parse_arguments() -> Namespace:
    parser = ArgumentParser(description="Prepare devenv")
    parser.add_argument(
        "--only",
        action="append",
        choices=ONLY_CHOICES,
        help="Only run certain steps. Possible values are "
        + ", ".join(ONLY_CHOICES)
        + ".",
    )
    parser.add_argument("dl_cache_path", help="Path to download the requirements in")
    parser.add_argument("output_path", help="The output directory")
    parser.add_argument(
        "--download",
        action="store_true",
        help="Only download the components, don't install them.",
    )
    parser.add_argument(
        "--torrent",
        action="store_true",
        help="Use torrent downloads where possible. Requires aria2 to already be installed on *nix systems.",
    )
    parser.add_argument(
        "--no-download",
        action="store_true",
        help="Don't download anything, use predownloaded files from dl_cache_path and install.",
    )

    return parser.parse_args()


def get_sha256(path):
    h = hashlib.new("sha256")
    with path.open("rb") as f:
        while True:
            data = f.read(16 * 4096 * 4096)
            if not data:
                break
            h.update(data)
    return h.hexdigest()


units = {"GB": 1024**3, "MB": 1024**2, "KiB": 1024**1}


def parse_size(size):
    for unit, val in units.items():
        if size > val:
            return format(float(size) / val, ".2f") + unit

    return str(size) + "B"


clear_line_sequence = "" if sys.platform == "win32" else "\033[2K"

last_refresh = datetime.now()


def progress_bar(blocks_transfered, block_size, total_bytes):
    global last_refresh

    if (datetime.now() - last_refresh).total_seconds() < 1:
        return

    # Progress bar size
    size = 80

    bytes_transfered = blocks_transfered * block_size

    x = int(size * bytes_transfered / total_bytes)
    clear_line_sequence = "" if sys.platform == "win32" else "\033[2K"
    print(
        "{}[{}{}] {}/{}".format(
            clear_line_sequence,
            "#" * x,
            "." * (size - x),
            parse_size(bytes_transfered),
            parse_size(total_bytes),
        ),
        end="\r",
        file=sys.stdout,
        flush=True,
    )
    last_refresh = datetime.now()


def download_requirement(dl_cache_path, requirement, no_download):
    path = dl_cache_path / requirement["filename"]
    file_found = False
    if path.exists():
        if filesize_equal(path, requirement):
            if get_sha256(path) == requirement["sha256"]:
                file_found = True

    if not file_found and "filename-alternative" in requirement:
        path = dl_cache_path / requirement["filename-alternative"]
        if path.exists():
            if filesize_equal(path, requirement):
                if get_sha256(path) == requirement["sha256"]:
                    file_found = True
                    path_proper = dl_cache_path / requirement["filename"]
                    print(
                        "Renaming {fa} into {f}.".format(
                            fa=requirement["filename-alternative"],
                            f=requirement["filename"],
                        )
                    )
                    os.rename(path, path_proper)
                    path = path_proper

    if no_download:
        if not file_found:
            print(requirement["url"])
            if "filesize" in requirement:
                print("filesize: " + str(requirement["filesize"]))
        return

    if not no_download and file_found:
        return

    hash = None
    for url in requirement["url"]:
        print("Downloading " + requirement["name"] + " from " + url)
        try:
            urllib.request.urlretrieve(url, str(path), progress_bar)
            print(clear_line_sequence, end="", flush=True, file=sys.stdout)
        except Exception as err:
            print(clear_line_sequence, end="", flush=True, file=sys.stdout)
            print("Download from " + url + " failed: " + str(err))
            continue

        hash = get_sha256(path)
        if hash == requirement["sha256"]:
            break
        print(
            "Download from "
            + url
            + " produced a mismatched hash. Got "
            + hash
            + ", expected "
            + requirement["sha256"]
        )
    if hash != requirement["sha256"]:
        raise Exception("Could not download " + requirement["name"])


def filesize_equal(path, requirement):
    if "filesize" not in requirement:
        return True
    filesize = requirement["filesize"]
    return os.path.getsize(str(path)) == filesize


def is_win():
    return sys.platform in ["win32", "cygwin"]


def is_x86_64():
    return platform.machine() in ["AMD64", "x86_64"]


def is_x86():
    return platform.machine() in ["i686", "x86"]


def download_requirement_torrent(dl_cache_path, requirement, aria2c_path):
    path = dl_cache_path / requirement["filename"]
    if path.exists() and get_sha256(path) == requirement["sha256"]:
        return

    print("Downloading " + requirement["name"] + " using torrent")
    # Run aria2c to download the torrent, make sure to save only the file we want.
    subprocess.check_call(
        str(aria2c_path)
        + " --dir "
        + str(dl_cache_path)
        + " --summary-interval=0 --seed-time=0 "
        + str(requirement["torrent"]),
        shell=True,
    )
    # After downloading, take the target file in the torrent_directory and move it back to the root of the dl_cache_path
    shutil.move(
        str(dl_cache_path / requirement["torrent_dirname"] / requirement["filename"]),
        str(path),
    )
    print(clear_line_sequence, end="", flush=True, file=sys.stdout)
    hash = get_sha256(path)
    if hash != requirement["sha256"]:
        raise Exception(
            "Download failed: Got hash " + hash + ", expected " + requirement["sha256"]
        )
    try:
        os.rmdir(str(dl_cache_path / requirement["torrent_dirname"]))
        os.remove(str(dl_cache_path / requirement["torrent_dirname"] + ".torrent"))
    except Exception:
        print("Failed to remove torrent directory, should be removed manually.")
        pass


def download_requirements(dl_cache_path, steps, should_torrent, no_download):
    requirements = [
        {
            "name": "Direct X 8.0",
            "only": "dx8",
            "url": [
                "https://archive.org/download/dx8sdk/dx8sdk.exe",
                "https://dl.roblab.la/dx8sdk.exe",
            ],
            "filename": "dx8sdk.exe",
            "filesize": 144441256,
            "sha256": "719f8fe4f02af5f435aac4a90bf9ef958210e6bd1d1e9715f26d13b10a73cb6c",
        },
        {
            "name": "Visual Studio .NET 2002 Professional Edition",
            "only": "vs",
            "url": [
                "https://archive.org/download/en_vs.net_pro_full/en_vs.net_pro_full.exe",
                "https://dl.bobpony.com/software/visualstudio/dotnet2002/en_vs.net_pro_full.exe",
            ],
            "torrent": "https://archive.org/download/en_vs.net_pro_full/en_vs.net_pro_full_archive.torrent",
            "filename": "en_vs.net_pro_full.exe",
            "torrent_dirname": "en_vs.net_pro_full",
            "filesize": 1706945024,
            "sha256": "440949f3d152ee0375050c2961fc3c94786780b5aae7f6a861a5837e03bf2dac",
        },
        {
            "name": "Python 3.4.4",
            "only": "py",
            "url": ["https://www.python.org/ftp/python/3.4.4/python-3.4.4.msi"],
            "filename": "python-3.4.4.msi",
            "filesize": 24932352,
            "sha256": "46c8f9f63cf02987e8bf23934b2f471e1868b24748c5bb551efcf4863b43ca6c",
        },
        {
            "name": "WiRunSQL",
            "only": "py",
            "url": [
                "https://raw.githubusercontent.com/microsoft/Windows-classic-samples/44d192fd7ec6f2422b7d023891c5f805ada2c811/Samples/Win7Samples/sysmgmt/msi/scripts/WiRunSQL.vbs"
            ],
            "filename": "WiRunSQL.vbs",
            "filesize": 3041,
            "sha256": "ef18c6d0b0163e371daaa1dd3fdf08030bc0b0999e4b2b90a1a736f7eb12784b",
        },
        {
            "name": "Ninja",
            "only": "ninja",
            "url": [
                "https://github.com/ninja-build/ninja/releases/download/v1.6.0/ninja-win.zip"
            ],
            "filename": "ninja-win.zip",
            "filesize": 159957,
            "sha256": "18f55bc5de27c20092e86ace8ef3dd3311662dc6193157e3b65c6bc94ce006d5",
        },
        {
            "name": "satsuki",
            "only": "satsuki",
            "condition": is_win() and is_x86_64(),
            "url": [
                "https://github.com/happyhavoc/satsuki/releases/download/v0.1.2/x86_64-windows-satsuki.exe"
            ],
            "filename": "satsuki.exe",
            "filename-alternative": "x86_64-windows-satsuki.exe",
            "filesize": 7513088,
            "sha256": "93baba162813f291f9975bce2440fb4c709bb40c5b120c2188852309a2025908",
        },
        {
            "name": "satsuki",
            "only": "satsuki",
            "condition": is_win() and is_x86(),
            "url": [
                "https://github.com/happyhavoc/satsuki/releases/download/v0.1.2/i686-windows-satsuki.exe"
            ],
            "filename": "satsuki.exe",
            "sha256": "fabda8be8b6c927d4f98f44aad80f5eaac9b8f6bc81eea7d834c1cea0b877a91",
        },
        {
            "name": "satsuki",
            "only": "satsuki",
            "condition": sys.platform == "darwin" and is_x86_64(),
            "url": [
                "https://github.com/happyhavoc/satsuki/releases/download/v0.1.2/x86_64-macos-satsuki"
            ],
            "filename": "satsuki",
            "sha256": "6ebe6df938767443e78103f2188dc3ea6fb2955a5c7cc91ff22c841cdcbc2a9f",
        },
        {
            "name": "satsuki",
            "only": "satsuki",
            "condition": sys.platform == "darwin" and platform.machine() == "arm64",
            "url": [
                "https://github.com/happyhavoc/satsuki/releases/download/v0.1.2/aarch64-macos-satsuki"
            ],
            "filename": "satsuki",
            "sha256": "410b520173cf2897b1414eee96bad089f4d9d24f18f697e3f6546786eb27702d",
        },
        {
            "name": "satsuki",
            "only": "satsuki",
            "condition": sys.platform == "linux" and is_x86_64(),
            "url": [
                "https://github.com/happyhavoc/satsuki/releases/download/v0.1.2/x86_64-linux-satsuki"
            ],
            "filename": "satsuki",
            "sha256": "e7a5f586b0f8febe5a1a6a3a0178486ec124c5dabc8ffb17bf0b892194dd8116",
        },
        # TODO: objdiff windows x86
        {
            "name": "objdiff-cli",
            "only": "objdiff",
            "condition": is_win() and is_x86_64(),
            "url": [
                "https://github.com/encounter/objdiff/releases/download/v2.0.0-beta.6/objdiff-cli-windows-x86_64.exe"
            ],
            "filename": "objdiff-cli.exe",
            "filename-alternative": "objdiff-cli-windows-x86_64.exe",
            "filesize": 7110144,
            "sha256": "7e757fe74dc7949f62b684eed740eb18ee361e9cb414fa550283175713e88961",
        },
        {
            "name": "objdiff-cli",
            "only": "objdiff",
            "condition": sys.platform == "darwin" and is_x86_64(),
            "url": [
                "https://github.com/encounter/objdiff/releases/download/v2.0.0-beta.6/objdiff-cli-macos-x86_64"
            ],
            "filename": "objdiff-cli",
            "sha256": "00dba386808ef9ba3ec5ae57b8f2799aa4117982d95eed0b14f5586dac42803a",
        },
        {
            "name": "objdiff-cli",
            "only": "objdiff",
            "condition": sys.platform == "darwin" and platform.machine() == "arm64",
            "url": [
                "https://github.com/encounter/objdiff/releases/download/v2.0.0-beta.6/objdiff-cli-macos-arm64"
            ],
            "filename": "objdiff-cli",
            "sha256": "d0b885f0a20323befe620b84c8205b0866020ddc5e9af8bd3666f231ae33fcbe",
        },
        {
            "name": "objdiff-cli",
            "only": "objdiff",
            "condition": sys.platform == "linux" and is_x86_64(),
            "url": [
                "https://github.com/encounter/objdiff/releases/download/v2.0.0-beta.6/objdiff-cli-linux-x86_64"
            ],
            "filename": "objdiff-cli",
            "sha256": "f76a7976e694db496686eb14495e54dd83ee9cdef286a98537bfbce0c2328ba1",
        },
        {
            "name": "ghidra",
            "only": "ghidra",
            "url": [
                "https://github.com/happyhavoc/ghidra-ci/releases/download/2024-08-31/release.zip"
            ],
            "filename": "ghidra.zip",
            "filename-alternative": "release.zip",
            "filesize": 501858473,
            "sha256": "524f6bdfa134afbe722498953eb21efacd93a876842e31fd04f93592270976a3",
        },
        {
            "name": "ghidra-delinker",
            "only": "ghidra",
            "url": [
                "https://github.com/happyhavoc/ghidra-delinker-extension/releases/download/v0.5.0-th06.1/ghidra_11.1_PUBLIC_20240831_ghidra-delinker-extension.zip"
            ],
            "filename": "ghidra-delinker.zip",
            "filename-alternative": "ghidra_11.1_PUBLIC_20240831_ghidra-delinker-extension.zip",
            "filesize": 7850347,
            "sha256": "a9b063294412fb095d749d06905a05cdd42714b82818141d6844955f11680691",
        },
    ]

    if no_download:
        print(
            'Please download the following urls manually and add them in the "{dl}" folder:'.format(
                dl=dl_cache_path
            )
        )
        for requirement in requirements:
            if requirement["only"] in steps:
                if "condition" not in requirement or requirement["condition"]:
                    download_requirement(dl_cache_path, requirement, no_download)
        print("Url list ended.")
        print(
            "After you downloaded everything, run this again but without --no-download argument."
        )
        return

    if should_torrent:
        # Download aria2c
        if sys.platform == "win32":
            aria2c_path = dl_cache_path / "aria2c.exe"
            if not aria2c_path.exists():
                print("Downloading aria2c")
                urllib.request.urlretrieve(
                    "https://github.com/aria2/aria2/releases/download/release-1.37.0/aria2-1.37.0-win-64bit-build1.zip",
                    str(dl_cache_path / "aria2.zip"),
                )
                shutil.unpack_archive(
                    str(dl_cache_path / "aria2.zip"), str(dl_cache_path), format="zip"
                )
                os.remove(str(dl_cache_path / "aria2.zip"))
                # Move aria2c to the correct location
                shutil.move(
                    str(dl_cache_path / "aria2-1.37.0-win-64bit-build1" / "aria2c.exe"),
                    str(aria2c_path),
                )
                shutil.rmtree(
                    str(dl_cache_path / "aria2-1.37.0-win-64bit-build1"),
                    ignore_errors=True,
                )
        else:
            # assuming its already in their PATH, because it should be installed before selecting torrent downloads on linux.
            aria2c_path = "aria2c"
            if not shutil.which(aria2c_path):
                # throw an error if aria2c is not installed
                raise Exception(
                    "aria2c is not installed, please install it before selecting torrent downloads!"
                )

        for requirement in requirements:
            if "torrent" in requirement:
                download_requirement_torrent(dl_cache_path, requirement, aria2c_path)

    for requirement in requirements:
        if requirement["only"] in steps:
            if "condition" not in requirement or requirement["condition"]:
                download_requirement(dl_cache_path, requirement, no_download)


def install_compiler_sdk(installer_path, tmp_dir, tmp2_dir, output_path):
    print("Installing Compiler and Platform SDK")
    compiler_directories = [
        "PROGRAM FILES/MICROSOFT VISUAL STUDIO .NET/COMMON7/IDE",
        "PROGRAM FILES/MICROSOFT VISUAL STUDIO .NET/VC7/BIN",
        "PROGRAM FILES/MICROSOFT VISUAL STUDIO .NET/VC7/INCLUDE",
        "PROGRAM FILES/MICROSOFT VISUAL STUDIO .NET/VC7/LIB",
    ]

    sdk_directories = ["Program Files/Microsoft Visual Studio .NET/Vc7/PlatformSDK"]
    shutil.rmtree(str(tmp_dir), ignore_errors=True)
    os.makedirs(str(tmp_dir), exist_ok=True)
    shutil.unpack_archive(str(installer_path), str(tmp_dir), format="zip")

    for compiler_directory_part in compiler_directories:
        dst_required_directory_path = output_path / compiler_directory_part
        src_required_directory_path = tmp_dir / compiler_directory_part
        copytree_exist_ok(src_required_directory_path, dst_required_directory_path)

    msvcr70_dll_src_path = tmp_dir / "MSVCR70.DLL"
    shutil.copy(
        str(msvcr70_dll_src_path),
        str(output_path / "PROGRAM FILES/MICROSOFT VISUAL STUDIO .NET/VC7/BIN"),
    )

    # Extract and grab Windows SDK
    os.makedirs(str(tmp2_dir), exist_ok=True)
    msiextract(tmp_dir / "VS_SETUP.MSI", tmp2_dir)
    shutil.rmtree(str(tmp_dir), ignore_errors=True)

    for sdk_directory_part in sdk_directories:
        dst_required_directory_path = output_path / sdk_directory_part
        src_required_directory_path = tmp2_dir / sdk_directory_part
        copytree_exist_ok(src_required_directory_path, dst_required_directory_path)

    shutil.rmtree(str(tmp2_dir), ignore_errors=True)

    # Uniformalize everything
    should_continue = True
    while should_continue:
        renamed_something = False

        for entry in output_path.glob("**"):
            new_name = entry.name.upper()

            if new_name == entry.name or entry == output_path:
                continue

            new_entry = entry.parent / new_name

            if (
                entry.exists()
                and new_entry.exists()
                and os.path.samefile(str(entry), str(new_entry))
            ):
                continue

            if entry.is_file():
                shutil.copy(str(entry), str(new_entry))
                entry.unlink()
            else:
                copytree_exist_ok(entry, new_entry)
                shutil.rmtree(str(entry))

            renamed_something = True
            break

        should_continue = renamed_something


def install_directx8(dx8sdk_installer_path, tmp_dir, output_path):
    print("Installing DirectX 8.0 SDK")
    shutil.rmtree(str(tmp_dir), ignore_errors=True)
    os.makedirs(str(tmp_dir), exist_ok=True)
    shutil.unpack_archive(str(dx8sdk_installer_path), str(tmp_dir), format="zip")
    dx8sdk_dst_dir = output_path / "mssdk"
    shutil.rmtree(str(dx8sdk_dst_dir), ignore_errors=True)
    shutil.move(str(tmp_dir), str(dx8sdk_dst_dir))
    shutil.rmtree(str(tmp_dir), ignore_errors=True)


def install_python(python_installer_path, wirunsql_path, tmp_dir, output_path):
    print("Installing Python")
    shutil.rmtree(str(tmp_dir), ignore_errors=True)
    os.makedirs(str(tmp_dir), exist_ok=True)
    shutil.copyfile(str(python_installer_path), str(tmp_dir / "python.msi"))

    # On windows, make sure we extract the msvcrt100.dll properly
    if sys.platform == "win32":
        run_windows_program(
            [
                "cscript",
                str(wirunsql_path),
                str(tmp_dir / "python.msi"),
                "UPDATE Feature SET Level=1 WHERE Feature='PrivateCRT'",
            ]
        )

    os.makedirs(str(tmp_dir / "python"), exist_ok=True)
    msiextract(tmp_dir / "python.msi", tmp_dir / "python")
    python_dst_dir = output_path / "python"
    shutil.rmtree(str(python_dst_dir), ignore_errors=True)
    shutil.move(str(tmp_dir / "python"), str(python_dst_dir))
    shutil.rmtree(str(tmp_dir), ignore_errors=True)


def install_pragma_var_order(tmp_dir, output_path):
    print("Installing pragma_var_order")
    os.makedirs(str(tmp_dir), exist_ok=True)
    win32_path_to_pragma_var_order = get_windows_path(
        SCRIPTS_DIR / "pragma_var_order.cpp"
    )
    run_windows_program(
        [
            str(SCRIPTS_DIR / "th06run.bat"),
            "CL.EXE",
            win32_path_to_pragma_var_order,
            "/o" + str(tmp_dir / "hackery.dll"),
            "/link",
            "/DLL",
        ],
        add_env={"DEVENV_PREFIX": str(output_path)},
    )
    VC7 = output_path / "PROGRAM FILES/MICROSOFT VISUAL STUDIO .NET/VC7"
    if not (VC7 / "BIN/C1XXOrig.DLL").exists():
        shutil.move(str(VC7 / "BIN/C1XX.DLL"), str(VC7 / "BIN/C1XXOrig.DLL"))
    shutil.move(str(tmp_dir / "hackery.dll"), str(VC7 / "BIN/C1XX.DLL"))
    shutil.rmtree(str(tmp_dir), ignore_errors=True)


def install_ninja(ninja_zip_path, output_path):
    print("Installing ninja")
    install_path = output_path / "ninja"
    os.makedirs(str(install_path), exist_ok=True)
    shutil.unpack_archive(str(ninja_zip_path), str(install_path))


def install_satsuki(dl_cache_path, output_path):
    print("Installing satsuki")
    if sys.platform in ["win32", "cygwin"]:
        satsuki_name = "satsuki.exe"
    else:
        satsuki_name = "satsuki"

    install_path = output_path / "satsuki"
    os.makedirs(str(install_path), exist_ok=True)
    shutil.copyfile(str(dl_cache_path / satsuki_name), str(install_path / satsuki_name))
    mode = os.stat(str(install_path / satsuki_name)).st_mode | stat.S_IXUSR
    os.chmod(str(install_path / satsuki_name), mode)


def install_ghidra(dl_cache_path, tmp_dir, output_path):
    install_path = output_path / "ghidra"
    with zipfile.ZipFile(str(dl_cache_path / "ghidra.zip")) as ghidra_zip:
        ghidra_zip.extractall(str(tmp_dir))
        for item in ghidra_zip.infolist():
            if not item.filename.endswith("/"):
                file_attr = item.external_attr >> 16
                os.chmod(str(tmp_dir / item.filename), file_attr)

    # Find the ghidra folder, and move it.
    for item in tmp_dir.iterdir():
        if item.name.startswith("ghidra_") and item.is_dir():
            print(str(item) + "->" + str(install_path))
            shutil.move(str(item), str(install_path))
            break

    # Next, install ghidra-delinker-extension
    shutil.unpack_archive(
        str(dl_cache_path / "ghidra-delinker.zip"),
        str(install_path / "Ghidra" / "Extensions"),
        format="zip",
    )


def install_objdiff(dl_cache_path, output_path):
    print("Installing objdiff")
    if sys.platform in ["win32", "cygwin"]:
        objdiff_cli_name = "objdiff-cli.exe"
    else:
        objdiff_cli_name = "objdiff-cli"

    install_path = output_path / "objdiff"
    os.makedirs(str(install_path), exist_ok=True)
    shutil.copyfile(
        str(dl_cache_path / objdiff_cli_name), str(install_path / objdiff_cli_name)
    )
    mode = os.stat(str(install_path / objdiff_cli_name)).st_mode | stat.S_IXUSR
    os.chmod(str(install_path / objdiff_cli_name), mode)


def main(args: Namespace) -> int:
    dl_cache_path = Path(args.dl_cache_path).absolute()
    output_path = Path(args.output_path).absolute()

    tmp_dir = output_path / "tmp"
    tmp2_dir = output_path / "tmp2"

    if args.only is None or len(args.only) == 0:
        steps = set(ONLY_CHOICES)
    else:
        steps = set(args.only)

    os.makedirs(str(dl_cache_path), exist_ok=True)
    download_requirements(dl_cache_path, steps, args.torrent, args.no_download)

    if not args.download and not args.no_download:
        program_files = output_path / "PROGRAM FILES"
        os.makedirs(str(program_files), exist_ok=True)

        dx8sdk_installer_path = dl_cache_path / "dx8sdk.exe"
        installer_path = dl_cache_path / "en_vs.net_pro_full.exe"
        python_installer_path = dl_cache_path / "python-3.4.4.msi"
        wirunsql_path = dl_cache_path / "WiRunSQL.vbs"
        ninja_zip_path = dl_cache_path / "ninja-win.zip"

        if "vs" in steps:
            install_compiler_sdk(installer_path, tmp_dir, tmp2_dir, output_path)
        if "dx8" in steps:
            install_directx8(dx8sdk_installer_path, tmp_dir, output_path)
        if "py" in steps:
            install_python(python_installer_path, wirunsql_path, tmp_dir, output_path)
        if "pragma" in steps:
            install_pragma_var_order(tmp_dir, output_path)
        if "ninja" in steps:
            install_ninja(ninja_zip_path, output_path)
        if "satsuki" in steps:
            install_satsuki(dl_cache_path, output_path)
        if "ghidra" in steps:
            install_ghidra(dl_cache_path, tmp_dir, output_path)
        if "objdiff" in steps:
            install_objdiff(dl_cache_path, output_path)

    return 0


if __name__ == "__main__":
    sys.exit(main(parse_arguments()))
