from argparse import ArgumentParser, Namespace
from datetime import datetime
import glob
import hashlib
from pathlib import Path
import shutil
import subprocess
import sys
from typing import Optional
import urllib.request
import os

SCRIPTS_DIR = Path(__file__).parent


def run_generic_extract(msi_file_path: Path, output_dir: Path) -> int:
    return subprocess.check_call(["7z", "x", "-y", str(msi_file_path)], cwd=output_dir)


def run_msiextract(msi_file_path: Path, output_dir: Path) -> int:
    return subprocess.check_call(["msiextract", str(msi_file_path)], cwd=output_dir)


def run_msiextract_win32(msi_file_path: Path, output_dir: Path) -> int:
    return subprocess.check_call(
        ["msiexec", "/a", str(msi_file_path), "/qb", f"TARGETDIR={output_dir}"],
        cwd=output_dir,
    )


def run_windows_program(args, add_env=None, cwd=None):
    env = dict(os.environ)
    if add_env is not None:
        for k, v in add_env.items():
            env[k] = v

    if sys.platform == "win32":
        subprocess.check_call(args, env=env, cwd=cwd)
    else:
        subprocess.check_call([os.getenv("WINE", "wine")] + args, env=env, cwd=cwd)


def get_windows_path(path):
    if sys.platform == "win32":
        return path
    else:
        return subprocess.check_output(
            [os.getenv("WINE", "wine"), "winepath", "-w", str(path)], text=True
        ).strip()


def translate_msiextract_name(raw_name: str) -> Optional[str]:
    name = raw_name.split(":")[0]

    if name == ".":
        return None

    return name


def msiextract(msi_file_path: Path, output_dir: Path) -> int:
    output_dir.mkdir(parents=True, exist_ok=True)
    if sys.platform == "win32":
        run_msiextract_win32(msi_file_path, output_dir)

        return

    run_msiextract(msi_file_path, output_dir)

    for dir in glob.iglob(f"{output_dir}/**/.:*", recursive=True):
        dir = Path(dir)
        parent_dir = dir.parent

        for entry in dir.glob("*"):
            new_entry = parent_dir / entry.name
            shutil.move(entry, new_entry)

        dir.rmdir()

    should_continue = True
    while should_continue:
        renamed_something = False

        for entry in glob.iglob(f"{output_dir}/**", recursive=True):
            entry = Path(entry)

            if entry.is_dir():
                new_name = translate_msiextract_name(entry.name)

                if new_name is None:
                    continue

                new_entry = entry.parent / new_name

                if entry != new_entry:
                    shutil.move(entry, new_entry)
                    renamed_something = True
                    break

        should_continue = renamed_something


def check_file(path: Path, message: str) -> Path:
    if not path.exists():
        sys.stderr.write(f"{message}\n")
        sys.exit(1)

    return path.absolute()


def parse_arguments() -> Namespace:
    parser = ArgumentParser(description="Prepare devenv")
    parser.add_argument(
        "--only",
        action="append",
        choices=["vs", "dx8", "py", "pragma", "cygwin"],
        help="Only run certain steps. Possible values are vs, dx8, py, pragma and cygwin.",
    )
    parser.add_argument("dl_cache_path", help="Path to download the requirements in")
    parser.add_argument("output_path", help="The output directory")
    parser.add_argument(
        "--download",
        action="store_true",
        help="Only download the components, don't install them.",
    )

    return parser.parse_args()


def get_sha256(path):
    h = hashlib.new("sha256")
    with open(path, "rb") as f:
        h.update(f.read())
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


def download_requirement(dl_cache_path, requirement):
    path = dl_cache_path / requirement["filename"]
    if path.exists() and get_sha256(path) == requirement["sha256"]:
        return

    print("Downloading " + requirement["name"])
    urllib.request.urlretrieve(requirement["url"], path, progress_bar)
    print(clear_line_sequence, end="", flush=True, file=sys.stdout)
    hash = get_sha256(path)
    if hash != requirement["sha256"]:
        raise Exception(
            "Download failed: Got hash " + hash + ", expected " + requirement["sha256"]
        )


def download_requirements(dl_cache_path, steps):
    requirements = [
        {
            "name": "Direct X 8.0",
            "only": "dx8",
            "url": "https://archive.org/download/dx8sdk/dx8sdk.exe",
            "filename": "dx8sdk.exe",
            "sha256": "719f8fe4f02af5f435aac4a90bf9ef958210e6bd1d1e9715f26d13b10a73cb6c",
        },
        {
            "name": "Visual Studio .NET 2002 Professional Edition",
            "only": "vs",
            "url": "https://archive.org/download/en_vs.net_pro_full/en_vs.net_pro_full.exe",
            "filename": "en_vs.net_pro_full.exe",
            "sha256": "440949f3d152ee0375050c2961fc3c94786780b5aae7f6a861a5837e03bf2dac",
        },
        {
            "name": "Python 3.4.4",
            "only": "py",
            "url": "https://www.python.org/ftp/python/3.4.4/python-3.4.4.msi",
            "filename": "python-3.4.4.msi",
            "sha256": "46c8f9f63cf02987e8bf23934b2f471e1868b24748c5bb551efcf4863b43ca6c",
        },
        {
            "name": "Visual C++ 10.0 Runtime",
            "only": "py",
            "url": "https://download.microsoft.com/download/1/6/5/165255E7-1014-4D0A-B094-B6A430A6BFFC/vcredist_x86.exe",
            "filename": "vcredist_x86.exe",
            "sha256": "99dce3c841cc6028560830f7866c9ce2928c98cf3256892ef8e6cf755147b0d8",
        },
        {
            "name": "Cygwin",
            "only": "cygwin",
            # On darwin, for whatever reason, the 32-bit installer fails. Let's
            # just grab the 64-bit installer instead.
            "condition": sys.platform == "darwin",
            "url": "http://ctm.crouchingtigerhiddenfruitbat.org/pub/cygwin/setup/snapshots/setup-x86_64-2.874.exe",
            "filename": "cygwin-setup-2.874.exe",
            "sha256": "58f9f42f5dbd52c5e3ecd24e537603ee8897ea15176b7acdc34afcef83e5c19a",
        },
        {
            "name": "Cygwin",
            "only": "cygwin",
            "condition": sys.platform != "darwin",
            "url": "http://ctm.crouchingtigerhiddenfruitbat.org/pub/cygwin/setup/snapshots/setup-x86-2.874.exe",
            "filename": "cygwin-setup-2.874.exe",
            "sha256": "a79e4f57ce98a4d4bacb8fbb66fcea3de92ef30b34ab8b76e11c8bd3b426fd31",
        },
    ]

    for requirement in requirements:
        if requirement["only"] in steps:
            if "condition" not in requirement or requirement["condition"]:
                download_requirement(dl_cache_path, requirement)


def install_compiler_sdk(installer_path, tmp_dir, tmp2_dir, output_path):
    print("Installing Compiler and Platform SDK")
    compiler_directories = [
        "PROGRAM FILES/MICROSOFT VISUAL STUDIO .NET/COMMON7/IDE",
        "PROGRAM FILES/MICROSOFT VISUAL STUDIO .NET/VC7/BIN",
        "PROGRAM FILES/MICROSOFT VISUAL STUDIO .NET/VC7/INCLUDE",
        "PROGRAM FILES/MICROSOFT VISUAL STUDIO .NET/VC7/LIB",
    ]

    sdk_directories = ["Program Files/Microsoft Visual Studio .NET/Vc7/PlatformSDK"]
    shutil.rmtree(tmp_dir, ignore_errors=True)
    tmp_dir.mkdir(parents=True, exist_ok=True)
    run_generic_extract(installer_path, tmp_dir)

    for compiler_directory_part in compiler_directories:
        dst_required_directory_path = output_path / compiler_directory_part
        src_required_directory_path = tmp_dir / compiler_directory_part
        shutil.copytree(
            src_required_directory_path, dst_required_directory_path, dirs_exist_ok=True
        )

    msvcr70_dll_src_path = tmp_dir / "MSVCR70.DLL"
    shutil.copy(
        msvcr70_dll_src_path,
        output_path / "PROGRAM FILES/MICROSOFT VISUAL STUDIO .NET/VC7/BIN",
    )

    # Extract and grab Windows SDK
    tmp2_dir.mkdir(parents=True, exist_ok=True)
    msiextract(tmp_dir / "VS_SETUP.MSI", tmp2_dir)
    shutil.rmtree(tmp_dir, ignore_errors=True)

    for sdk_directory_part in sdk_directories:
        dst_required_directory_path = output_path / sdk_directory_part
        src_required_directory_path = tmp2_dir / sdk_directory_part
        shutil.copytree(
            src_required_directory_path, dst_required_directory_path, dirs_exist_ok=True
        )

    shutil.rmtree(tmp2_dir, ignore_errors=True)

    # Unifromalise everything
    should_continue = True
    while should_continue:
        renamed_something = False

        for entry in glob.iglob(f"{output_path}/**", recursive=True):
            entry = Path(entry)

            new_name = entry.name.upper()

            if new_name == entry.name or entry == output_path:
                continue

            new_entry = entry.parent / new_name

            if entry.exists() and new_entry.exists() and entry.samefile(new_entry):
                continue

            if entry.is_file():
                shutil.copy(entry, new_entry)
                entry.unlink()
            else:
                shutil.copytree(entry, new_entry, dirs_exist_ok=True)
                shutil.rmtree(entry)

            renamed_something = True
            break

        should_continue = renamed_something


def install_directx8(dx8sdk_installer_path, tmp_dir, output_path):
    print("Installing DirectX 8.0 SDK")
    shutil.rmtree(tmp_dir, ignore_errors=True)
    tmp_dir.mkdir(parents=True, exist_ok=True)
    run_generic_extract(dx8sdk_installer_path, tmp_dir)
    dx8sdk_dst_dir = output_path / "mssdk"
    shutil.move(tmp_dir, dx8sdk_dst_dir)
    shutil.rmtree(tmp_dir, ignore_errors=True)


def install_python(
    python_installer_path, vcredist_installer_path, tmp_dir, output_path
):
    print("Installing Python")
    shutil.rmtree(tmp_dir, ignore_errors=True)
    tmp_dir.mkdir(parents=True, exist_ok=True)
    msiextract(python_installer_path, tmp_dir)
    python_dst_dir = output_path / "python"
    shutil.move(tmp_dir, python_dst_dir)
    shutil.rmtree(tmp_dir, ignore_errors=True)

    print("Installing MSVCR100.DLL for Python")
    shutil.rmtree(tmp_dir, ignore_errors=True)
    tmp_dir.mkdir(parents=True, exist_ok=True)
    run_generic_extract(vcredist_installer_path, tmp_dir)
    run_generic_extract(tmp_dir / "vc_red.cab", tmp_dir)
    shutil.move(tmp_dir / "F_CENTRAL_msvcr100_x86", python_dst_dir / "msvcr100.dll")
    shutil.rmtree(tmp_dir, ignore_errors=True)


def install_cygwin(cygwin_installer_path, tmp_dir, output_path):
    print("Installing cygwin")
    tmp_dir.mkdir(parents=True, exist_ok=True)
    local_package_dir_win32 = get_windows_path(tmp_dir / "cygwin_cache")
    cygwin_dir_win32 = get_windows_path(output_path / "cygwin")
    run_windows_program(
        [
            cygwin_installer_path,
            "--quiet-mode",
            "--only-site",
            "--site",
            "http://ctm.crouchingtigerhiddenfruitbat.org/pub/cygwin/circa/2002/11/12/084110",
            "--no-verify",
            "--root",
            cygwin_dir_win32,
            "--local-package-dir",
            local_package_dir_win32,
            "--no-shortcuts",
            "--no-startmenu",
            "--no-desktop",
            "--arch",
            "x86",
            "--packages",
            "gcc",
        ],
        cwd=str(tmp_dir),
    )
    shutil.rmtree(tmp_dir, ignore_errors=True)


def install_pragma_var_order(tmp_dir, output_path):
    print("Installing pragma_var_order")
    tmp_dir.mkdir(parents=True, exist_ok=True)
    run_windows_program(
        [
            str(SCRIPTS_DIR / "th06run.bat"),
            "CL.EXE",
            str(SCRIPTS_DIR / "pragma_var_order.cpp"),
            "/ohackery.dll",
            "/link",
            "/DLL",
        ],
        add_env={"DEVENV_PREFIX": str(output_path)},
        cwd=str(tmp_dir),
    )
    VC7 = output_path / "PROGRAM FILES/MICROSOFT VISUAL STUDIO .NET/VC7"
    if not (VC7 / "BIN/C1XXOrig.DLL").exists():
        shutil.move(VC7 / "BIN/C1XX.DLL", VC7 / "BIN/C1XXOrig.DLL")
    shutil.move(tmp_dir / "hackery.dll", VC7 / "BIN/C1XX.DLL")
    shutil.rmtree(tmp_dir, ignore_errors=True)


def main(args: Namespace) -> int:
    dl_cache_path = Path(args.dl_cache_path).absolute()
    output_path = Path(args.output_path).absolute()

    tmp_dir = output_path / "tmp"
    tmp2_dir = output_path / "tmp2"

    if args.only is None or len(args.only) == 0:
        steps = set(["vs", "dx8", "py", "pragma", "cygwin"])
    else:
        steps = set(args.only)

    dl_cache_path.mkdir(exist_ok=True)
    download_requirements(dl_cache_path, steps)

    if not args.download:
        program_files = output_path / "PROGRAM FILES"
        program_files.mkdir(parents=True, exist_ok=True)

        dx8sdk_installer_path = dl_cache_path / "dx8sdk.exe"
        installer_path = dl_cache_path / "en_vs.net_pro_full.exe"
        python_installer_path = dl_cache_path / "python-3.4.4.msi"
        vcredist_installer_path = dl_cache_path / "vcredist_x86.exe"
        cygwin_installer_path = dl_cache_path / "cygwin-setup-2.874.exe"

        if "vs" in steps:
            install_compiler_sdk(installer_path, tmp_dir, tmp2_dir, output_path)
        if "dx8" in steps:
            install_directx8(dx8sdk_installer_path, tmp_dir, output_path)
        if "py" in steps:
            install_python(
                python_installer_path, vcredist_installer_path, tmp_dir, output_path
            )
        if "pragma" in steps:
            install_pragma_var_order(tmp_dir, output_path)
        if "cygwin" in steps:
            install_cygwin(cygwin_installer_path, tmp_dir, output_path)

    return 0


if __name__ == "__main__":
    sys.exit(main(parse_arguments()))
