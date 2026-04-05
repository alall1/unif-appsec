from __future__ import annotations

import ast
from pathlib import Path


def parse_python_file(path: Path) -> tuple[ast.Module | None, str | None]:
    """
    Parse *path* as Python source. Returns ``(tree, None)`` or ``(None, error_message)``.
    """
    try:
        src = path.read_text(encoding="utf-8")
    except OSError as exc:
        return None, f"read_failed:{exc}"
    except UnicodeDecodeError as exc:
        return None, f"decode_failed:{exc}"

    try:
        tree = ast.parse(src, filename=str(path), type_comments=False)
    except SyntaxError as exc:
        return None, f"syntax_error:{exc.msg} (line {exc.lineno})"

    return tree, None
