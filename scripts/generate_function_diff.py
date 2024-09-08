#!/usr/bin/env python

import argparse
import csv
import difflib
import json
from pathlib import Path
import tempfile
import os
import subprocess

BASE_DIR = Path(__file__).parent.parent
BUILD_DIR = BASE_DIR / "build"
CONFIG_DIR = BASE_DIR / "config"
RESOURCE_DIR = BASE_DIR / "resources"


def generate_function_diff_objdiff(fn_name):
    with open(CONFIG_DIR / "ghidra_ns_to_obj.csv") as f:
        ghidra_ns_to_obj = csv.reader(f)
        for vals in ghidra_ns_to_obj:
            obj = vals[0]
            if any(
                fn_name == val or fn_name.startswith(val + "::") for val in vals[1:]
            ):
                break
        else:
            raise Exception(
                "No object file contains function "
                + fn_name
                + " in ghidra_ns_to_obj mapping"
            )

    with tempfile.NamedTemporaryFile() as f:
        subprocess.run(
            [
                str(BASE_DIR / "scripts" / "prefix" / "objdiff" / "objdiff-cli"),
                "diff",
                "--relax-reloc-diffs",
                "-u",
                obj,
                fn_name,
                "-o",
                f.name,
            ],
            check=True,
        )
        data = json.load(f)

    left_sects = data["left"]["sections"]
    right_sects = data["right"]["sections"]

    left_fun = next(
        (
            left_fun
            for sect in left_sects
            for left_fun in sect["functions"]
            if left_fun["symbol"]["name"] == fn_name
        ),
        None,
    )
    right_fun = next(
        (
            right_fun
            for sect in right_sects
            for right_fun in sect["functions"]
            if right_fun["symbol"]["name"] == fn_name
        ),
        None,
    )

    if left_fun is None:
        raise Exception("Failed to find function " + fn_name + " in original obj")

    if right_fun is None:
        raise Exception(
            "Failed to find function " + fn_name + " in reimplementation obj"
        )

    out_res = ""
    left_instrs = ""
    right_instrs = ""

    for left_instr, right_instr in zip(
        left_fun["instructions"], right_fun["instructions"]
    ):
        if "instruction" in left_instr:
            left_instrs += left_instr["instruction"]["formatted"] + "\n"
        if "instruction" in right_instr:
            right_instrs += right_instr["instruction"]["formatted"] + "\n"

        if "diff_kind" not in left_instr:
            out_res += " " + left_instr["instruction"]["formatted"] + "\n"
        elif left_instr["diff_kind"] == "DIFF_INSERT":
            out_res += "+" + right_instr["instruction"]["formatted"] + "\n"
        elif left_instr["diff_kind"] == "DIFF_DELETE":
            out_res += "-" + left_instr["instruction"]["formatted"] + "\n"
        else:
            out_res += "-" + left_instr["instruction"]["formatted"] + "\n"
            out_res += "+" + right_instr["instruction"]["formatted"] + "\n"

    return left_instrs, right_instrs, out_res, left_fun["match_percent"] / 100


def generate_function_diff_satsuki(fn_name):
    try:
        orig = subprocess.run(
            [
                str(BASE_DIR / "scripts/prefix/satsuki/satsuki"),
                "--mapping-file-csv",
                str(CONFIG_DIR / "mapping.csv"),
                "disassemble",
                str(RESOURCE_DIR / "game.exe"),
                "--resolve-names",
                fn_name,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            encoding="utf-8",
            check=True,
        ).stdout
    except subprocess.CalledProcessError as e:
        e.stderr = b"original: " + e.stderr
        raise

    try:
        reimpl = subprocess.run(
            [
                str(BASE_DIR / "scripts/prefix/satsuki/satsuki"),
                "--mapping-file-csv",
                str(CONFIG_DIR / "mapping.csv"),
                "disassemble",
                str(BUILD_DIR / "th06e.exe"),
                "--pdb-file",
                str(BUILD_DIR / "th06e.pdb"),
                "--resolve-names",
                fn_name,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            encoding="utf-8",
            check=True,
        ).stdout
    except subprocess.CalledProcessError as e:
        e.stderr = b"reimpl: " + e.stderr
        raise

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
    ratio = difflib.SequenceMatcher(None, orig, reimpl).ratio()

    return orig, reimpl, diff, ratio


def main():
    parser = argparse.ArgumentParser(
        prog="generate_function_diff", description="Generate the diff of a function."
    )
    parser.add_argument(
        "--diff-method",
        action="store",
        choices=["satsuki", "objdiff"],
        default="satsuki",
        help="Which program to use to generate the diff.",
    )
    parser.add_argument("fun", help="Function to diff.")
    args = parser.parse_args()

    fn_name = args.fun
    if args.diff_method == "satsuki":
        left, right, diff, ratio = generate_function_diff_satsuki(fn_name)
    elif args.diff_method == "objdiff":
        left, right, diff, ratio = generate_function_diff_objdiff(fn_name)

    print(diff)

    diff_dir = BASE_DIR / "diff"
    fs_fn_name = fn_name.replace(":", "__")
    orig_asm_path = diff_dir / fs_fn_name / "orig.asm"
    reimpl_asm_path = diff_dir / fs_fn_name / "reimpl.asm"
    diff_file_path = diff_dir / fs_fn_name / "diff.diff"

    os.makedirs(diff_dir / fs_fn_name, exist_ok=True)

    with open(orig_asm_path, "w") as f:
        f.write(left)

    with open(reimpl_asm_path, "w") as f:
        f.write(right)

    with open(diff_file_path, "w") as f:
        f.write(diff)


if __name__ == "__main__":
    main()
