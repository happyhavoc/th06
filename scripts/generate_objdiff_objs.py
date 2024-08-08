from winhelpers import run_windows_program_output, run_windows_program
import os
from pathlib import Path

SCRIPTS_DIR = Path(__file__).parent


def rename_symbols(filename):
    out_folder = SCRIPTS_DIR.parent / "build" / "objdiff" / "src"
    asm_folder = SCRIPTS_DIR.parent / "build" / "objdiff" / "asm"

    class_name = filename.removesuffix(".obj")
    nm_arguments = ["nm", "build" / Path(filename), "-j"]

    # We run nm to get the list of symbols of that specific .obj
    out = run_windows_program_output(nm_arguments).decode().splitlines()

    objcopy_arguments = ["objcopy", "--input-target=pe-i386", "--output-target=pe-i386"]

    # We filter to only the symbols with the namespace=filename, and we scrape everything but the function name
    # and we save all the renames onto syms.txt
    # TODO: Implement constructors/destructors
    seen = {}
    with open("syms.txt", "w") as f:
        for line in out:
            if seen.get(line, False):
                continue
            seen[line] = True

            parts = line.split("@")
            if class_name not in line:
                continue
            if len(parts) > 1:
                if parts[1] != class_name:
                    continue
            else:
                continue
            objcopy_argument = "{} {}".format(line, parts[0].removeprefix("?"))
            f.write(objcopy_argument + os.linesep)

    if not out_folder.exists():
        out_folder.mkdir(parents=True, exist_ok=True)
        asm_folder.mkdir(parents=True, exist_ok=True)

    run_windows_program(
        objcopy_arguments
        + [
            "--redefine-syms=syms.txt",
            SCRIPTS_DIR.parent / "build" / filename,
            SCRIPTS_DIR.parent / "build" / "objdiff" / "src" / filename,
        ]
    )
    os.remove("syms.txt")
