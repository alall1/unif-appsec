import shlex
import subprocess
import sys


def safe() -> None:
    subprocess.run(shlex.quote(sys.argv[1]), shell=True)
