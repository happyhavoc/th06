import os
import subprocess
import sys


def run_windows_program(args, add_env=None, cwd=None):
    env = dict(os.environ)
    if add_env is not None:
        for k, v in add_env.items():
            env[k] = v

    if sys.platform == "win32":
        subprocess.check_call(args, env=env, cwd=cwd)
    else:
        subprocess.check_call([os.getenv("WINE", "wine")] + args, env=env, cwd=cwd)


def get_windows_path(path):
    if sys.platform == "win32":
        return str(path)
    else:
        return subprocess.check_output(
            [os.getenv("WINE", "wine"), "winepath", "-w", str(path)], text=True
        ).strip()
