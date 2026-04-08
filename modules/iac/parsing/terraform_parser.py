from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional


@dataclass(frozen=True)
class TerraformBlock:
    type: str
    attributes: dict[str, Any] = field(default_factory=dict)
    blocks: dict[str, list["TerraformBlock"]] = field(default_factory=dict)


@dataclass(frozen=True)
class TerraformResource:
    terraform_type: str
    name: str
    provider: str
    address: str
    config_path: str
    attributes: dict[str, Any]
    blocks: dict[str, list[TerraformBlock]]


_RESOURCE_HEADER_RE = re.compile(r'resource\s+"([^"]+)"\s+"([^"]+)"\s*{', re.MULTILINE)


def _strip_comments(text: str) -> str:
    # Best-effort stripping for v2 baseline fixtures (no attempt at full HCL compliance).
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    text = re.sub(r"//.*?$", "", text, flags=re.MULTILINE)
    text = re.sub(r"^\s*#.*?$", "", text, flags=re.MULTILINE)
    return text


def _infer_provider(terraform_type: str) -> str:
    # Common Terraform convention: provider prefix is everything before the first underscore.
    # Example: "aws_s3_bucket" -> "aws"
    if "_" in terraform_type:
        return terraform_type.split("_", 1)[0] or "unknown"
    return "unknown"


def _find_matching_brace(text: str, open_brace_idx: int) -> int:
    # open_brace_idx must point at `{`.
    depth = 0
    in_str = False
    esc = False
    for i in range(open_brace_idx, len(text)):
        ch = text[i]
        if in_str:
            if esc:
                esc = False
                continue
            if ch == "\\":
                esc = True
                continue
            if ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return i
    raise ValueError("Unmatched brace in Terraform input.")


def _parse_quoted_string(s: str, *, start_quote_idx: int) -> tuple[str, int]:
    # Returns (value, end_quote_idx_exclusive)
    assert s[start_quote_idx] == '"'
    i = start_quote_idx + 1
    out_chars: list[str] = []
    esc = False
    while i < len(s):
        ch = s[i]
        if esc:
            out_chars.append(ch)
            esc = False
            i += 1
            continue
        if ch == "\\":
            esc = True
            i += 1
            continue
        if ch == '"':
            return ("".join(out_chars), i + 1)
        out_chars.append(ch)
        i += 1
    raise ValueError("Unterminated quoted string in Terraform input.")


def _parse_list_value(s: str, *, start_idx: int) -> tuple[list[Any], int]:
    # Very small subset: list of quoted strings and booleans, e.g. ["a", "b"] or [true, false].
    assert s[start_idx] == "["
    i = start_idx + 1
    items: list[Any] = []
    cur: list[str] = []
    in_str = False
    esc = False
    while i < len(s):
        ch = s[i]
        if in_str:
            if esc:
                cur.append(ch)
                esc = False
                i += 1
                continue
            if ch == "\\":
                esc = True
                i += 1
                continue
            if ch == '"':
                in_str = False
                cur.append(ch)
                i += 1
                continue
            cur.append(ch)
            i += 1
            continue
        if ch == '"':
            in_str = True
            cur.append(ch)
            i += 1
            continue
        if ch == "]":
            token = "".join(cur).strip()
            if token:
                items.append(_parse_scalar_token(token))
            return items, i + 1
        if ch == ",":
            token = "".join(cur).strip()
            if token:
                items.append(_parse_scalar_token(token))
            cur = []
            i += 1
            continue
        cur.append(ch)
        i += 1
    raise ValueError("Unterminated list in Terraform input.")


def _parse_scalar_token(token: str) -> Any:
    t = token.strip().rstrip(",")
    if t in ("true", "false"):
        return t == "true"
    if t.startswith('"') and t.endswith('"') and len(t) >= 2:
        # Strip quotes; no attempt at full escaping.
        return t[1:-1]
    # Integer-only for v2 baseline
    if re.fullmatch(r"-?\d+", t or ""):
        try:
            return int(t)
        except Exception:
            return t
    return t


def _parse_value(value_src: str) -> Any:
    v = value_src.strip().rstrip(",")
    if not v:
        return None
    if v.startswith("["):
        items, _ = _parse_list_value(v, start_idx=0)
        return items
    if v.startswith('"'):
        if len(v) >= 2 and v.endswith('"'):
            # Single-line literal
            return v[1:-1]
        # Multi-line/escaped is out of baseline scope.
        return v
    if v in ("true", "false"):
        return v == "true"
    if re.fullmatch(r"-?\d+", v or ""):
        try:
            return int(v)
        except Exception:
            return v
    # Keep as raw string for non-literal expressions; rules may decide to skip.
    return v


_BLOCK_START_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_-]*)\s*{")
_ASSIGN_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_-]*)\s*=")


def _parse_body(body: str, *, stop_on_end: Optional[str] = None) -> TerraformBlock:
    # Parse sequential statements into attributes and nested blocks until end-of-body.
    # stop_on_end is reserved for future use; current baseline parses full body substring.
    i = 0
    attributes: dict[str, Any] = {}
    blocks: dict[str, list[TerraformBlock]] = {}

    while i < len(body):
        # Skip whitespace/newlines
        if body[i].isspace():
            i += 1
            continue

        # Nested block?
        m_block = _BLOCK_START_RE.match(body, i)
        if m_block:
            block_type = m_block.group(1)
            open_brace_idx = m_block.end() - 1
            close_idx = _find_matching_brace(body, open_brace_idx)
            inner = body[open_brace_idx + 1 : close_idx]
            parsed_inner = _parse_body(inner)
            tb = TerraformBlock(type=block_type, attributes=parsed_inner.attributes, blocks=parsed_inner.blocks)
            blocks.setdefault(block_type, []).append(tb)
            i = close_idx + 1
            continue

        # Assignment?
        m_assign = _ASSIGN_RE.match(body, i)
        if m_assign:
            key = m_assign.group(1)
            # Value starts after '='
            value_start = m_assign.end()
            # End-of-statement: newline (baseline fixtures keep single-line values)
            nl = body.find("\n", value_start)
            if nl == -1:
                nl = len(body)
            value_src = body[value_start:nl].strip()
            attributes[key] = _parse_value(value_src)
            i = nl + 1
            continue

        # Unknown token: skip to next newline to avoid infinite loops.
        nl = body.find("\n", i)
        if nl == -1:
            break
        i = nl + 1

    return TerraformBlock(type="__root__", attributes=attributes, blocks=blocks)


def parse_terraform_file(tf_path: Path, *, scan_root: Path) -> list[TerraformResource]:
    text = tf_path.read_text(encoding="utf-8")
    text = _strip_comments(text)

    cfg_rel: str
    try:
        cfg_rel = str(tf_path.resolve().relative_to(scan_root.resolve())).replace("\\", "/")
    except Exception:
        cfg_rel = str(tf_path)

    resources: list[TerraformResource] = []
    for m in _RESOURCE_HEADER_RE.finditer(text):
        r_type = m.group(1)
        r_name = m.group(2)
        open_brace_idx = m.end() - 1
        close_idx = _find_matching_brace(text, open_brace_idx)
        body = text[open_brace_idx + 1 : close_idx]
        parsed = _parse_body(body)

        provider = _infer_provider(r_type)
        address = f"{r_type}.{r_name}"
        resources.append(
            TerraformResource(
                terraform_type=r_type,
                name=r_name,
                provider=provider,
                address=address,
                config_path=cfg_rel,
                attributes=parsed.attributes,
                blocks=parsed.blocks,
            )
        )

    return resources

