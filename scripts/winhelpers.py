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
        subprocess.check_call([str(SCRIPTS_DIR / "wineth06")] + args, env=env, cwd=cwd)


def get_windows_path(path):
    if sys.platform == "win32":
        return str(path)
    else:
        return subprocess.check_output(
            [str(SCRIPTS_DIR / "wineth06"), "winepath", "-w", str(path)], text=True
        ).strip()
