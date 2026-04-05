import hashlib


def safe() -> None:
    hashlib.sha256(b"data")
