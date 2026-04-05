import subprocess
import sys


def relay(arg: str) -> str:
    return arg


def vulnerable() -> None:
    subprocess.run(relay(sys.argv[1]), shell=True)
