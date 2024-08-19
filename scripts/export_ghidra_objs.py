#!/usr/bin/env nix-shell
#!nix-shell -p python311 -i python3

import argparse
import os
from pathlib import Path
import tempfile
import urllib.request

import ghidra_helpers

SCRIPT_PATH = Path(os.path.realpath(__file__)).parent


def main():
    parser = argparse.ArgumentParser(
        description="Export a ghidra database history to git",
    )
    parser.add_argument("--local-project-dir", help="Path to the local ghidra project")
    parser.add_argument("--local-project-name", help="Path to the local ghidra project")
    parser.add_argument("--import-xml", action="store_true", help="Use the XML export")
    parser.add_argument("--program", help="Program to export", default="th06_102h.exe")
    args = parser.parse_args()

    os.makedirs(str(SCRIPT_PATH.parent / "build" / "objdiff" / "asm"), exist_ok=True)

    if args.import_xml:
        with tempfile.TemporaryDirectory() as tempdir:
            filename, _ = urllib.request.urlretrieve(
                "https://raw.githubusercontent.com/happyhavoc/th06-re/xml/th06_102h.exe.xml"
            )
            ghidra_helpers.runAnalyze(
                str(tempdir),
                "Touhou 06",
                analysis=True,
                extraArgs=[
                    "-import",
                    SCRIPT_PATH.parent / "resources" / "game.exe",
                    "-postScript",
                    SCRIPT_PATH / "ghidra" / "ImportFromXml.java",
                    filename,
                    "-postScript",
                    SCRIPT_PATH / "ghidra" / "ExportDelinker.java",
                    str(SCRIPT_PATH.parent / "build" / "objdiff" / "asm"),
                ],
            )
    else:
        repo = args.local_project_dir
        project_name = args.local_project_name
        program = args.program

        ghidra_helpers.runAnalyze(
            repo,
            project_name,
            program,
            extraArgs=[
                "-preScript",
                SCRIPT_PATH / "ghidra" / "ExportDelinker.java",
                str(SCRIPT_PATH.parent / "build" / "objdiff" / "asm"),
            ],
        )


if __name__ == "__main__":
    main()
