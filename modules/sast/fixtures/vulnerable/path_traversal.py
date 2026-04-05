import sys


def vulnerable() -> None:
    open(sys.argv[1], "r")
