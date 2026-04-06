"""SAST fixture: eval/exec injection patterns."""

import ast


def vulnerable_eval() -> None:
    expression = input("Expression: ")
    print(eval(expression))


def vulnerable_exec() -> None:
    code = input("Python code: ")
    exec(code)


def safe_literal_eval() -> None:
    value = input("Literal (like {'a': 1}): ")
    print(ast.literal_eval(value))


def near_miss_static_eval() -> None:
    # Dangerous API, but static trusted input.
    print(eval("1 + 1"))


if __name__ == "__main__":
    vulnerable_eval()
