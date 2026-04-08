from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class Advisory:
    ecosystem: str
    package_name: str
    advisory_id: str
    advisory_source: str
    advisory_url: str | None
    vulnerable_specifiers: list[str]
    fixed_versions: list[str]
    title: str
    severity: str
    cvss: str | None
    cwe_ids: list[str]


def _as_str_list(v: Any) -> list[str]:
    if v is None:
        return []
    if isinstance(v, list):
        return [str(x) for x in v if str(x).strip()]
    return [str(v)]


def load_advisories_from_json(path: Path) -> list[Advisory]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or "advisories" not in raw:
        raise ValueError("advisory db must be an object with key 'advisories'")
    items = raw["advisories"]
    if not isinstance(items, list):
        raise ValueError("'advisories' must be a list")
    out: list[Advisory] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        out.append(
            Advisory(
                ecosystem=str(item.get("ecosystem") or ""),
                package_name=str(item.get("package_name") or ""),
                advisory_id=str(item.get("advisory_id") or ""),
                advisory_source=str(item.get("advisory_source") or ""),
                advisory_url=(str(item["advisory_url"]) if item.get("advisory_url") else None),
                vulnerable_specifiers=_as_str_list(item.get("vulnerable_specifiers")),
                fixed_versions=_as_str_list(item.get("fixed_versions")),
                title=str(item.get("title") or ""),
                severity=str(item.get("severity") or "medium"),
                cvss=(str(item["cvss"]) if item.get("cvss") else None),
                cwe_ids=_as_str_list(item.get("cwe_ids")),
            )
        )
    return out

