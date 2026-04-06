from __future__ import annotations

import re


def materialize_url_template(url: str) -> str:
    """Replace `{param}` path templates with a benign placeholder for live requests."""
    return re.sub(r"\{[^{}]+\}", "1", url)


SQL_ERROR_MARKERS = (
    "sql syntax",
    "sqlite_exception",
    "sqlite3.operationalerror",
    "postgresql",
    "mysql server version",
    "ora-0",
    "syntax error near",
    "unclosed quotation",
    "quoted string not properly terminated",
)

INFO_LEAK_MARKERS = (
    "traceback (most recent call last)",
    "stack trace",
    "exception in thread",
    "internal server error",
    "aws_access_key_id",
    "begin rsa private key",
    "-----begin certificate-----",
)


def contains_any(haystack: str, needles: tuple[str, ...]) -> list[str]:
    low = haystack.lower()
    return [n for n in needles if n in low]
