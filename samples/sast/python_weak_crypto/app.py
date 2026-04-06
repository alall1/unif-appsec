"""SAST fixture: weak crypto/hash patterns."""

import hashlib
import secrets


def vulnerable_hash(password: str) -> str:
    return hashlib.md5(password.encode("utf-8")).hexdigest()


def vulnerable_signature(data: str) -> str:
    return hashlib.sha1(data.encode("utf-8")).hexdigest()


def safe_hash(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def safe_token() -> str:
    return secrets.token_urlsafe(16)


if __name__ == "__main__":
    print(vulnerable_hash("demo-password"))
