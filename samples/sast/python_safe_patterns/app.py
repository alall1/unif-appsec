"""SAST fixture: safe patterns and near-misses."""

import ast
import subprocess


ALLOWED_COMMANDS = {"date", "whoami", "uname"}


def safe_command_allowlist() -> None:
    cmd = input("Allowed command: ")
    if cmd not in ALLOWED_COMMANDS:
        raise ValueError("Command not allowed")
    subprocess.run([cmd], check=False)


def safe_literal_parsing() -> dict:
    payload = input("Literal dict payload: ")
    parsed = ast.literal_eval(payload)
    if not isinstance(parsed, dict):
        raise ValueError("Expected dict")
    return parsed


def near_miss_exec_constant() -> None:
    # This is intentionally static; useful for false-positive resistance testing.
    exec("result = 1 + 2")


if __name__ == "__main__":
    safe_command_allowlist()
