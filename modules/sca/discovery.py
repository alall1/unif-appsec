from __future__ import annotations

import fnmatch
from pathlib import Path

SUPPORTED_MANIFEST_BASENAMES = ("requirements.txt", "poetry.lock", "Pipfile.lock")


def _rel_posix(p: Path, root: Path) -> str:
    try:
        rel = p.resolve().relative_to(root.resolve())
    except Exception:
        rel = p
    return "/".join([x for x in rel.parts if x not in (".", "")]) or "."


def _match_any(rel_posix: str, patterns: list[str]) -> bool:
    for pat in patterns:
        if not pat:
            continue
        if fnmatch.fnmatch(rel_posix, pat) or fnmatch.fnmatch(rel_posix, pat.replace("\\", "/")):
            return True
    return False


def discover_manifests(
    scan_root: Path,
    *,
    include_paths: list[str] | None = None,
    exclude_paths: list[str] | None = None,
    include_manifests: list[str] | None = None,
    exclude_manifests: list[str] | None = None,
) -> list[Path]:
    root = scan_root.resolve()
    inc_paths = list(include_paths or [])
    exc_paths = list(exclude_paths or [])
    inc_man = list(include_manifests or [])
    exc_man = list(exclude_manifests or [])

    candidates: list[Path] = []
    for base in SUPPORTED_MANIFEST_BASENAMES:
        candidates.extend(root.rglob(base))

    out: list[Path] = []
    for p in sorted(set(candidates), key=lambda x: _rel_posix(x, root)):
        rel = _rel_posix(p, root)

        if inc_paths and not _match_any(rel, inc_paths) and not any(rel.startswith(ip.rstrip("/") + "/") for ip in inc_paths if ip):
            continue
        if exc_paths and (_match_any(rel, exc_paths) or any(rel.startswith(ep.rstrip("/") + "/") for ep in exc_paths if ep)):
            continue

        if inc_man and not _match_any(rel, inc_man):
            continue
        if exc_man and _match_any(rel, exc_man):
            continue

        out.append(p)

    return out

