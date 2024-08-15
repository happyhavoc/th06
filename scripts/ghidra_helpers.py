import os
from pathlib import Path
import re
import shutil
import subprocess


SCRIPT_PATH = Path(os.path.realpath(__file__)).parent


def findAnalyzeHeadless():
    # The standard way to locate ghidra is to look at the GHIDRA_HOME
    # environment variable, which points to the ghidra installation folder.
    if os.getenv("GHIDRA_HOME") is not None:
        ghidra_home = Path(os.getenv("GHIDRA_HOME"))
        if os.name == "nt":
            analyze_headless = ghidra_home / "support" / "analyzeHeadless.bat"
        else:
            analyze_headless = ghidra_home / "support" / "analyzeHeadless"
        if analyze_headless.exists():
            return analyze_headless

    # ArchLinux and Nix add a ghidra-analyzeHeadless symlink that points to the
    # analyzeHeadless script of the ghidra installation.
    if shutil.which("ghidra-analyzeHeadless") is not None:
        return "ghidra-analyzeHeadless"

    # Some people just add the support folder to the PATH. Let's support that
    # too.
    if shutil.which("analyzeHeadless") is not None:
        return "analyzeHeadless"

    raise Exception(
        "Could not find Ghidra installation. Please install ghidra from https://ghidra-sre.org/ and set your GHIDRA_HOME environment variable to the installation directory"
    )


def runAnalyze(
    ghidra_repo_name,
    project_name="Touhou 06",
    program=None,
    analysis=False,
    username=None,
    ssh_key=None,
    extraArgs=[],
):
    commonAnalyzeHeadlessArgs = [findAnalyzeHeadless(), ghidra_repo_name]

    if not re.match("^ghidra://", ghidra_repo_name):
        # Set a project name
        commonAnalyzeHeadlessArgs += [project_name]

    commonAnalyzeHeadlessArgs += [
        "-readOnly",
        "-scriptPath",
        str(SCRIPT_PATH / "ghidra"),
    ]

    if not analysis:
        commonAnalyzeHeadlessArgs += ["-noanalysis"]

    if ssh_key:
        commonAnalyzeHeadlessArgs += ["-keystore", ssh_key]

    # TODO: If program is not provided, export all files from server.
    if program:
        commonAnalyzeHeadlessArgs += ["-process", program]

    commonAnalyzeHeadlessEnv = os.environ.copy()
    if username is not None:
        commonAnalyzeHeadlessEnv["_JAVA_OPTIONS"] = (
            f"-Duser.name={username} " + os.environ.get("_JAVA_OPTIONS", "")
        )

    allArgs = commonAnalyzeHeadlessArgs + extraArgs
    print("Running " + str(allArgs))
    return subprocess.run(allArgs, env=commonAnalyzeHeadlessEnv, check=True)
