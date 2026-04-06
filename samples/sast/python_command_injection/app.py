"""SAST fixture: command injection patterns."""

import os
import shlex
import subprocess


def vulnerable_os_system() -> None:
    user_cmd = input("Command to run: ")
    os.system("echo scanning && " + user_cmd)


def vulnerable_subprocess_shell() -> None:
    arg = input("List directory argument: ")
    subprocess.run(f"ls {arg}", shell=True, check=False)


def safe_subprocess_usage() -> None:
    arg = input("Directory name: ")
    safe_arg = shlex.quote(arg)
    # The command string remains constant, user input is escaped.
    subprocess.run(["sh", "-c", f"ls {safe_arg}"], check=False)


if __name__ == "__main__":
    vulnerable_os_system()
