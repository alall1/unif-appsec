import subprocess
import sys


def vulnerable() -> None:
    subprocess.run(sys.argv[1], shell=True)
