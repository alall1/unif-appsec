import sys


def vulnerable() -> None:
    code = sys.argv[1]
    exec(code)
