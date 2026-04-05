import hashlib


def vulnerable() -> None:
    hashlib.md5(b"data")
