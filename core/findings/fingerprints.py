from __future__ import annotations

import hashlib
import re
import urllib.parse
from pathlib import Path
from typing import Optional

from core.findings.models import CodeLocation, Finding, HttpLocation, LocationExtension


def _posix_relative_safe(path: Path, scan_root: Path) -> str:
    try:
        abs_path = path.resolve()
        root = scan_root.resolve()
        rel = abs_path.relative_to(root)
    except Exception:
        rel = path
    parts: list[str] = []
    for p in Path(rel).parts:
        if p == ".":
            continue
        if p == "..":
            if parts:
                parts.pop()
            continue
        parts.append(p)
    return "/".join(parts) if parts else "."


def _canonical_url_for_fingerprint(url: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    scheme = (parsed.scheme or "").lower()
    netloc = parsed.netloc.lower()
    path = urllib.parse.unquote(parsed.path or "")
    query = parsed.query or ""
    pairs: list[tuple[str, str]] = urllib.parse.parse_qsl(query, keep_blank_values=True)
    pairs.sort(key=lambda kv: (kv[0].encode("utf-8"), kv[1].encode("utf-8")))
    encoded = urllib.parse.urlencode(pairs, doseq=True, safe="")
    return urllib.parse.urlunsplit((scheme, netloc, path, encoded, ""))


def _primary_code_location(locations: Optional[list[LocationExtension]], location_type: str) -> Optional[CodeLocation]:
    if location_type != "code" or not locations:
        return None
    for loc in locations:
        if isinstance(loc, CodeLocation):
            return loc
    return None


def _primary_http_location(locations: Optional[list[LocationExtension]], location_type: str) -> Optional[HttpLocation]:
    if location_type != "http" or not locations:
        return None
    for loc in locations:
        if isinstance(loc, HttpLocation):
            return loc
    return None


def build_location_key(finding: Finding, scan_root: Path) -> str:
    """§9.11 location_key for fingerprint canonical material."""
    lt = finding.location_type
    locs = finding.locations

    if lt == "code":
        cl = _primary_code_location(locs, lt)
        if cl is None:
            return ""
        fp = _posix_relative_safe(Path(cl.file_path), scan_root)
        fn = cl.function_name or ""
        return f"{fp}|start_line={cl.start_line}|end_line={cl.end_line}|function={fn}"

    if lt == "http":
        hl = _primary_http_location(locs, lt)
        if hl is None:
            return ""
        method = hl.method.upper()
        cu = _canonical_url_for_fingerprint(hl.url)
        param = hl.parameter or ""
        es = hl.endpoint_signature or ""
        return f"{method}|url={cu}|param={param}|endpoint_sig={es}"

    if lt in ("dependency", "resource"):
        parts: list[str] = []
        if locs:
            loc0 = locs[0]
            d = loc0.model_dump(exclude_none=True)
            for k in sorted(d.keys()):
                parts.append(f"{k}={d[k]}")
        return "|".join(parts)

    return ""


def canonical_fingerprint_material(finding: Finding, scan_root: Path) -> str:
    loc_key = build_location_key(finding, scan_root)
    lines = [
        f"schema_version={finding.schema_version}",
        f"engine={finding.engine}",
        f"module={finding.module}",
        f"rule_id={finding.rule_id}",
        f"location_type={finding.location_type}",
        f"evidence_type={finding.evidence_type}",
        f"location_key={loc_key}",
    ]
    return "\n".join(lines) + "\n"


_FP1_RE = re.compile(r"^fp1:[0-9a-f]{64}$")


def compute_fingerprint(finding: Finding, scan_root: Path) -> str:
    material = canonical_fingerprint_material(finding, scan_root)
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()
    return f"fp1:{digest}"


def is_valid_fp1(value: str) -> bool:
    return bool(_FP1_RE.match(value))
