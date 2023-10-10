from argparse import ArgumentParser, Namespace
import glob
from pathlib import Path
import shutil
import subprocess
import sys
from typing import Optional


def run_generic_extract(msi_file_path: Path, output_dir: Path) -> int:
    return subprocess.check_call(["7z", "x", "-y", msi_file_path], cwd=output_dir)


def run_msiextract(msi_file_path: Path, output_dir: Path) -> int:
    return subprocess.check_call(["msiextract", msi_file_path], cwd=output_dir)


def run_msiextract_win32(msi_file_path: Path, output_dir: Path) -> int:
    return subprocess.check_call(["msiexec", "/a", msi_file_path, "/qb", f"TARGETDIR={output_dir}"], cwd=output_dir)


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
    parser.add_argument("input_path", help="Path with required input files")
    parser.add_argument("output_path", help="The output directory")

    return parser.parse_args()


def main(args: Namespace) -> int:
    input_path = Path(args.input_path).absolute()
    output_path = Path(args.output_path).absolute()

    dx8sdk_installer_path = check_file(
        input_path / "dx8sdk.exe",
        "Missing installer for DirectX 8.0 SDK",
    )
    installer_path = check_file(
        input_path / "en_vs.net_pro_full.exe",
        "Missing installer for Visual Studio .NET 2002 Professional Edition",
    )
    python_installer_path = check_file(
        input_path / "python-3.4.4.msi",
        "Missing installer for Python 3.4.4",
    )
    vcredist_installer_path = check_file(
        input_path / "vcredist_x86.exe",
        "Missing installer for Visual C++ 2010 Runtime",
    )

    program_files = output_path / "PROGRAM FILES"
    program_files.mkdir(parents=True, exist_ok=True)

    tmp_dir = output_path / "tmp"
    tmp2_dir = output_path / "tmp2"

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
        shutil.copytree(src_required_directory_path, dst_required_directory_path, dirs_exist_ok=True)

    msvcr70_dll_src_path = tmp_dir / "MSVCR70.DLL"
    shutil.copy(msvcr70_dll_src_path, output_path / "PROGRAM FILES/MICROSOFT VISUAL STUDIO .NET/VC7/BIN")

    # Extract and grab Windows SDK
    tmp2_dir.mkdir(parents=True, exist_ok=True)
    msiextract(tmp_dir / "VS_SETUP.MSI", tmp2_dir)
    shutil.rmtree(tmp_dir, ignore_errors=True)

    for sdk_directory_part in sdk_directories:
        dst_required_directory_path = output_path / sdk_directory_part
        src_required_directory_path = tmp2_dir / sdk_directory_part
        shutil.copytree(src_required_directory_path, dst_required_directory_path, dirs_exist_ok=True)

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

    print("Installing DirectX 8.0 SDK")
    shutil.rmtree(tmp_dir, ignore_errors=True)
    tmp_dir.mkdir(parents=True, exist_ok=True)
    run_generic_extract(dx8sdk_installer_path, tmp_dir)
    dx8sdk_dst_dir = output_path / "mssdk"
    shutil.move(tmp_dir, dx8sdk_dst_dir)
    shutil.rmtree(tmp_dir, ignore_errors=True)

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

    return 0


if __name__ == '__main__':
    sys.exit(main(parse_arguments()))
