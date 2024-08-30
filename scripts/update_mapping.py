#!/usr/bin/env nix-shell
#!nix-shell -p python311 -i python3

import argparse
import os
from pathlib import Path

import ghidra_helpers

SCRIPT_PATH = Path(os.path.realpath(__file__)).parent


def updateMapping(args, mapping_path):
    ghidra_helpers.runAnalyze(
        args.GHIDRA_REPO_NAME,
        args.program,
        args.username,
        args.ssh_key,
        ["-preScript", "GenerateMapping.java", mapping_path],
    )


def main():
    parser = argparse.ArgumentParser(
        description="Export a ghidra database history to git",
    )
    parser.add_argument("GHIDRA_REPO_NAME")
    parser.add_argument(
        "--username", help="Username to use when connecting to the ghidra server."
    )
    parser.add_argument(
        "--ssh-key",
        help="""SSH key to use to authenticate to a ghidra server.
                        Note that the ghidra server must have SSH authentication enabled for this to work.
                        To enable SSH auth, add -ssh in the wrapper.parameters of the Ghidra Server's server.conf""",
    )
    parser.add_argument("--program", help="Program to export")
    args = parser.parse_args()

    mapping_path = SCRIPT_PATH.parent / "config" / "mapping.csv"

    updateMapping(args, mapping_path)


if __name__ == "__main__":
    main()
