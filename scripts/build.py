import argparse
from pathlib import Path

from configure import BuildType, configure
from winhelpers import run_windows_program

SCRIPTS_DIR = Path(__file__).parent


def build(build_type):
    configure(build_type)

    # Then, run the build. We use run_windows_program to automatically go through
    # wine if running on linux/macos. scripts/th06run.bat will setup PATH and other
    # environment variables for the MSVC toolchain to work before calling ninja.
    run_windows_program(
        [str(SCRIPTS_DIR / "th06run.bat"), "ninja", "build/th06e.exe"],
        cwd=str(SCRIPTS_DIR.parent),
    )


def main():
    parser = argparse.ArgumentParser("th06-build")
    parser.add_argument(
        "--build-type", choices=["normal", "diffbuild"], default="normal"
    )
    args = parser.parse_args()

    # First, create the build.ninja file that will be used to build.
    if args.build_type == "normal":
        build_type = BuildType.NORMAL
    elif args.build_type == "diffbuild":
        build_type = BuildType.DIFFBUILD

    build(build_type)


if __name__ == "__main__":
    main()
