import sys


def vulnerable() -> None:
    code = sys.argv[1]
    eval(code)
