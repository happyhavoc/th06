import os
from pathlib import Path
import subprocess
import sys

SCRIPTS_DIR = Path(__file__).parent


def run_windows_program(args, add_env=None, cwd=None):
    env = dict(os.environ)
    if add_env is not None:
        for k, v in add_env.items():
            env[k] = v

    if sys.platform == "win32":
        subprocess.check_call(args, env=env, cwd=cwd)
    else:
        wine = os.environ.get("WINE", "wine")
        subprocess.check_call([wine] + args, env=wine_env(env), cwd=cwd)


def run_windows_program_output(args, add_env=None, cwd=None) -> str:
    env = dict(os.environ)
    if add_env is not None:
        for k, v in add_env.items():
            env[k] = v

    if sys.platform == "win32":
        return subprocess.check_output(args, env=env, cwd=cwd)
    else:
        wine = os.environ.get("WINE", "wine")
        return subprocess.check_output([wine] + args, env=wine_env(env), cwd=cwd)


def get_windows_path(path):
    if sys.platform == "win32":
        return str(path)
    else:
        wine = os.environ.get("WINE", "wine")
        return subprocess.check_output(
            [wine, "winepath", "-w", str(path)], text=True
        ).strip()


def wine_env(env):
    env = dict(env)
    env["WINEPREFIX"] = os.environ["HOME"] + "/.wineth06"
    env["WINEPATH"] = str(SCRIPTS_DIR) + ";" + os.environ.get("WINEPATH", "")
    env["WINEDEBUG"] = "-all"
    return env
