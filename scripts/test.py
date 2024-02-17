from pathlib import Path

from build import BuildType, build
from winhelpers import run_windows_program

SCRIPTS_DIR = Path(__file__).parent


def main():
    # Run the build for tests
    build(BuildType.TESTS)

    # Then, run the tests
    run_windows_program(
        [SCRIPTS_DIR.parent / "build" / "th06e-tests.exe"],
        cwd=str(SCRIPTS_DIR.parent),
    )


if __name__ == "__main__":
    main()
