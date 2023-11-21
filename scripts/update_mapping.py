#!/usr/bin/env nix-shell
#!nix-shell -p python311 -i python3

import argparse
import os
from pathlib import Path
import subprocess

SCRIPT_PATH = Path(os.path.realpath(__file__)).parent


def runAnalyze(args, extraArgs):
    commonAnalyzeHeadlessArgs = ["analyzeHeadless", args.GHIDRA_REPO_NAME]
    commonAnalyzeHeadlessArgs += [
        "-noanalysis",
        "-readOnly",
        "-scriptPath",
        str(SCRIPT_PATH / "ghidra"),
    ]
    if args.ssh_key:
        commonAnalyzeHeadlessArgs += ["-keystore", args.ssh_key]

    # TODO: If program is not provided, export all files from server.
    if args.program:
        commonAnalyzeHeadlessArgs += ["-process", args.program]

    commonAnalyzeHeadlessEnv = os.environ.copy()
    commonAnalyzeHeadlessEnv["_JAVA_OPTIONS"] = (
        f"-Duser.name={args.username} " + os.environ.get("_JAVA_OPTIONS", "")
    )

    return subprocess.run(
        commonAnalyzeHeadlessArgs + extraArgs, env=commonAnalyzeHeadlessEnv, check=True
    )


def updateMapping(args, mapping_path):
    runAnalyze(args, ["-preScript", "GenerateMappingToml.java", mapping_path])


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

    mapping_path = SCRIPT_PATH.parent / "config" / "mapping.toml"

    updateMapping(args, mapping_path)


if __name__ == "__main__":
    main()
