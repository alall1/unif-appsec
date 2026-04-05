from __future__ import annotations

import fnmatch
from pathlib import Path


def _normalize_rel(path: Path, root: Path) -> str:
    try:
        rel = path.resolve().relative_to(root.resolve())
    except ValueError:
        rel = path
    parts: list[str] = []
    for p in rel.parts:
        if p == ".":
            continue
        if p == "..":
            if parts:
                parts.pop()
            continue
        parts.append(p)
    return "/".join(parts) if parts else "."


def _is_excluded(rel_posix: str, patterns: list[str]) -> bool:
    for pat in patterns:
        if not pat:
            continue
        if fnmatch.fnmatch(rel_posix, pat) or fnmatch.fnmatch(rel_posix, pat.replace("\\", "/")):
            return True
        if rel_posix == pat or rel_posix.startswith(pat.rstrip("*") + "/"):
            return True
    return False


def _is_included(rel_posix: str, patterns: list[str]) -> bool:
    if not patterns:
        return True
    for pat in patterns:
        if not pat:
            continue
        if fnmatch.fnmatch(rel_posix, pat) or fnmatch.fnmatch(rel_posix, pat.replace("\\", "/")):
            return True
        if rel_posix == pat or rel_posix.startswith(pat.rstrip("/") + "/"):
            return True
    return False


def collect_python_files(
    scan_root: Path,
    *,
    target_path: Path | None = None,
    include_paths: list[str] | None = None,
    exclude_paths: list[str] | None = None,
) -> list[Path]:
    """
    Collect ``.py`` files under ``scan_root``.

    If ``target_path`` is a file, return only that file (if Python and passes filters).
    ``include_paths`` / ``exclude_paths`` are matched against POSIX paths relative to
    ``scan_root`` (glob-friendly via :func:`fnmatch.fnmatch`).
    """
    root = scan_root.resolve()
    inc = list(include_paths or [])
    exc = list(exclude_paths or [])

    files: list[Path] = []
    if target_path is not None:
        tp = target_path.resolve()
        if tp.is_file():
            candidates = [tp] if tp.suffix == ".py" else []
        elif tp.is_dir():
            candidates = sorted(tp.rglob("*.py"))
        else:
            return []
    else:
        candidates = sorted(root.rglob("*.py"))

    for p in candidates:
        rel = _normalize_rel(p, root)
        if not _is_included(rel, inc):
            continue
        if _is_excluded(rel, exc):
            continue
        files.append(p)

    return files
