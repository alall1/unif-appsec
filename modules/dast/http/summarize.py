from __future__ import annotations

from typing import Mapping


def _truncate(s: str, max_bytes: int) -> str:
    raw = s.encode("utf-8")
    if len(raw) <= max_bytes:
        return s
    cut = max(0, max_bytes - 40)
    return raw[:cut].decode("utf-8", errors="ignore") + "\n... [truncated] ..."


def summarize_request(
    method: str,
    url: str,
    headers: Mapping[str, str],
    body_preview: str | None,
    *,
    max_bytes: int,
) -> str:
    lines = [f"{method.upper()} {url}"]
    for k in sorted(headers.keys(), key=lambda x: x.lower()):
        lines.append(f"{k}: {headers[k]}")
    if body_preview:
        lines.append("")
        lines.append(_truncate(body_preview, max_bytes))
    return _truncate("\n".join(lines), max_bytes)


def summarize_response(
    status: int,
    headers: Mapping[str, str],
    body_preview: str,
    *,
    max_bytes: int,
) -> str:
    lines = [f"HTTP {status}"]
    for k in sorted(headers.keys(), key=lambda x: x.lower()):
        lines.append(f"{k}: {headers[k]}")
    lines.append("")
    lines.append(_truncate(body_preview, max_bytes))
    return _truncate("\n".join(lines), max_bytes)
