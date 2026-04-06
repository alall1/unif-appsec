"""SAST fixture: path traversal patterns."""

from pathlib import Path


BASE_DIR = Path("samples/sast/python_path_traversal/data").resolve()


def vulnerable_file_read() -> str:
    filename = input("Filename to read: ")
    target = BASE_DIR / filename
    return target.read_text(encoding="utf-8")


def safe_file_read() -> str:
    filename = input("Filename to read: ")
    requested = (BASE_DIR / filename).resolve()
    if BASE_DIR not in requested.parents and requested != BASE_DIR:
        raise ValueError("Path traversal attempt rejected")
    return requested.read_text(encoding="utf-8")


if __name__ == "__main__":
    print(vulnerable_file_read())
