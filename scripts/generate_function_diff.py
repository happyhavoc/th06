#!/usr/bin/env python

import difflib
from pathlib import Path
import sys
import os
import subprocess


def generate_function_diff(fn_name):
    base_dir = Path(__file__).parent.parent
    build_dir = base_dir / "build"
    config_dir = base_dir / "config"
    diff_dir = base_dir / "diff"
    resource_dir = base_dir / "resources"

    fs_fn_name = fn_name.replace(":", "__")

    orig_asm_path = diff_dir / fs_fn_name / "orig.asm"
    reimpl_asm_path = diff_dir / fs_fn_name / "reimpl.asm"

    os.makedirs(diff_dir / fs_fn_name, exist_ok=True)
    with open(orig_asm_path, "w") as out:
        try:
            out = subprocess.run(
                [
                    "satsuki",
                    "--mapping-file-csv",
                    str(config_dir / "mapping.csv"),
                    "disassemble",
                    str(resource_dir / "game.exe"),
                    "--resolve-names",
                    fn_name,
                ],
                stdout=out,
                stderr=subprocess.PIPE,
                check=True,
            )
        except subprocess.CalledProcessError as e:
            e.stderr = b"original: " + e.stderr
            raise

    with open(reimpl_asm_path, "w") as out:
        try:
            out = subprocess.run(
                [
                    "satsuki",
                    "--mapping-file-csv",
                    str(config_dir / "mapping.csv"),
                    "disassemble",
                    str(build_dir / "th06e.exe"),
                    "--pdb-file",
                    str(build_dir / "th06e.pdb"),
                    "--resolve-names",
                    fn_name,
                ],
                stdout=out,
                stderr=subprocess.PIPE,
                check=True,
            )
        except subprocess.CalledProcessError as e:
            e.stderr = b"reimpl: " + e.stderr
            raise

    return orig_asm_path.read_text(), reimpl_asm_path.read_text()


def main():
    fn_name = sys.argv[1]
    orig, reimpl = generate_function_diff(fn_name)

    base_dir = Path(__file__).parent.parent
    diff_dir = base_dir / "diff"
    fs_fn_name = fn_name.replace(":", "__")

    diff = "\n".join(
        difflib.unified_diff(
            orig.split("\n"),
            reimpl.split("\n"),
            "Original",
            "Reimplementation",
            n=20,
            lineterm="",
        )
    )

    print(diff)

    with open(diff_dir / fs_fn_name / "diff.diff", "w") as f:
        f.write(diff)


if __name__ == "__main__":
    main()
