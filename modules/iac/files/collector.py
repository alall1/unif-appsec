from __future__ import annotations

import fnmatch
from pathlib import Path
from typing import Optional


def _matches_any(rel_posix: str, patterns: list[str]) -> bool:
    for pat in patterns:
        if not pat:
            continue
        if fnmatch.fnmatch(rel_posix, pat) or fnmatch.fnmatch(rel_posix, pat.replace("\\", "/")):
            return True
    return False


def _is_included(rel_posix: str, include_patterns: list[str]) -> bool:
    if not include_patterns:
        return True
    for pat in include_patterns:
        if not pat:
            continue
        if fnmatch.fnmatch(rel_posix, pat) or fnmatch.fnmatch(rel_posix, pat.replace("\\", "/")):
            return True
        # Directory-prefix semantics for simple patterns like "modules/"
        if rel_posix == pat or rel_posix.startswith(pat.rstrip("/") + "/"):
            return True
    return False


def _is_excluded(rel_posix: str, exclude_patterns: list[str]) -> bool:
    if not exclude_patterns:
        return False
    for pat in exclude_patterns:
        if not pat:
            continue
        if fnmatch.fnmatch(rel_posix, pat) or fnmatch.fnmatch(rel_posix, pat.replace("\\", "/")):
            return True
        if rel_posix == pat or rel_posix.startswith(pat.rstrip("/") + "/"):
            return True
    return False


def _rel_posix(p: Path, root: Path) -> str:
    try:
        rel = p.resolve().relative_to(root.resolve())
    except Exception:
        rel = p
    parts = [x for x in rel.parts if x not in (".", "")]
    return "/".join(parts) if parts else "."


def collect_tf_files(
    scan_root: Path,
    *,
    target_path: Optional[Path] = None,
    include_paths: Optional[list[str]] = None,
    exclude_paths: Optional[list[str]] = None,
    module_include_paths: Optional[list[str]] = None,
    module_exclude_paths: Optional[list[str]] = None,
) -> list[Path]:
    """
    Deterministically collect Terraform HCL files in scope.

    Baseline v2 behavior:
    - Only `.tf` files are considered.
    - `include_paths` / `exclude_paths` apply to POSIX paths relative to `scan_root`.
    - module-specific include/exclude are treated as additional filters.
    """
    root = scan_root.resolve()

    inc = list(include_paths or [])
    exc = list(exclude_paths or [])
    mod_inc = list(module_include_paths or [])
    mod_exc = list(module_exclude_paths or [])

    candidates: list[Path] = []
    if target_path is not None:
        tp = target_path.resolve()
        if tp.is_file():
            candidates = [tp] if tp.suffix == ".tf" else []
        elif tp.is_dir():
            candidates = sorted(tp.rglob("*.tf"))
        else:
            candidates = []
    else:
        candidates = sorted(root.rglob("*.tf"))

    out: list[Path] = []
    for p in candidates:
        rel = _rel_posix(p, root)
        if not _is_included(rel, inc):
            continue
        if _is_excluded(rel, exc):
            continue
        # Module-specific filters: treat as additional include/exclude.
        if not _is_included(rel, mod_inc):
            continue
        if _is_excluded(rel, mod_exc):
            continue
        out.append(p)

    # Stable ordering by normalized relative path
    out.sort(key=lambda p: _rel_posix(p, root))
    return out

