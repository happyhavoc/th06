import argparse
from pathlib import Path

from configure import BuildType, configure
from winhelpers import run_windows_program

SCRIPTS_DIR = Path(__file__).parent


def build(build_type, verbose=False, jobs=1, object_name=None):
    configure(build_type)

    ninja_args = []
    if verbose:
        ninja_args += ["-v"]

    if jobs != 0:
        ninja_args += ["-j" + str(jobs)]

    if build_type == BuildType.TESTS:
        ninja_args += ["build/th06e-tests.exe"]
    elif build_type == BuildType.DLLBUILD:
        ninja_args += ["build/th06e.dll"]
    elif build_type == BuildType.OBJDIFFBUILD and object_name is not None:
        ninja_args += [f"build/objdiff/src/{object_name}"]
    elif build_type == BuildType.OBJDIFFBUILD:
        ninja_args += ["objdiff"]
    else:
        ninja_args += ["build/th06e.exe"]

    # Then, run the build. We use run_windows_program to automatically go through
    # wine if running on linux/macos. scripts/th06run.bat will setup PATH and other
    # environment variables for the MSVC toolchain to work before calling ninja.
    run_windows_program(
        [str(SCRIPTS_DIR / "th06run.bat"), "ninja"] + ninja_args,
        cwd=str(SCRIPTS_DIR.parent),
    )


def main():
    parser = argparse.ArgumentParser("th06-build")
    parser.add_argument(
        "--build-type",
        choices=["normal", "diffbuild", "tests", "dllbuild", "objdiffbuild"],
        default="normal",
    )
    parser.add_argument(
        "-j",
        "--jobs",
        type=int,
        default=1,
        help="""Number of jobs to run in parallel. Set to 0 to run one job per CPU core. Defaults to 1.
        Note that parallel builds may not work when running through wine. See https://github.com/happyhavoc/th06/issues/79 for more information.""",
    )
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--object-name", required=False)
    args = parser.parse_args()
    object_name = None

    # First, create the build.ninja file that will be used to build.
    if args.build_type == "normal":
        build_type = BuildType.NORMAL
    elif args.build_type == "diffbuild":
        build_type = BuildType.DIFFBUILD
    elif args.build_type == "tests":
        build_type = BuildType.TESTS
    elif args.build_type == "dllbuild":
        build_type = BuildType.DLLBUILD
    elif args.build_type == "objdiffbuild":
        build_type = BuildType.OBJDIFFBUILD

    if args.object_name is not None:
        object_name = Path(args.object_name).name
    build(build_type, args.verbose, args.jobs, object_name=object_name)


if __name__ == "__main__":
    main()
