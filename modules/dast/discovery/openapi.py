from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

from modules.dast.discovery.models import DiscoveredEndpoint, InsertionPoint


def _load_spec(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() in {".yaml", ".yml"}:
        loaded = yaml.safe_load(text)
    else:
        loaded = json.loads(text)
    if not isinstance(loaded, dict):
        raise ValueError("OpenAPI document must be a JSON/YAML object")
    return loaded


def _server_base(spec: dict[str, Any], fallback_base: str) -> str:
    servers = spec.get("servers")
    if isinstance(servers, list) and servers:
        u = servers[0].get("url") if isinstance(servers[0], dict) else None
        if isinstance(u, str) and u.strip():
            base = u.strip()
            if not base.endswith("/"):
                base = base + "/"
            return base
    if not fallback_base.endswith("/"):
        return fallback_base + "/"
    return fallback_base


def _join(base: str, path: str) -> str:
    from urllib.parse import urljoin

    return urljoin(base, path.lstrip("/"))


def endpoints_from_openapi(spec_path: Path, fallback_base: str) -> list[DiscoveredEndpoint]:
    spec = _load_spec(spec_path)
    ver = str(spec.get("openapi") or spec.get("swagger") or "")
    if not ver.startswith("3."):
        # V1: focus on OpenAPI 3.x; swagger 2.0 partially supported if paths exist
        pass

    base = _server_base(spec, fallback_base)
    paths = spec.get("paths") or {}
    if not isinstance(paths, dict):
        return []

    out: list[DiscoveredEndpoint] = []
    for pth, item in paths.items():
        if not isinstance(pth, str) or not isinstance(item, dict):
            continue
        for method, op in item.items():
            m = method.upper()
            if m not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}:
                continue
            if not isinstance(op, dict):
                continue
            url = _join(base, pth)
            points: list[InsertionPoint] = []
            params = op.get("parameters") or []
            if isinstance(params, list):
                for prm in params:
                    if not isinstance(prm, dict):
                        continue
                    name = prm.get("name")
                    inn = str(prm.get("in") or "").lower()
                    if not isinstance(name, str) or not name:
                        continue
                    if inn in ("query", "path", "header"):
                        points.append(InsertionPoint(name=name, location=inn))  # type: ignore[arg-type]

            out.append(
                DiscoveredEndpoint(
                    method=m,
                    url=url,
                    insertion_points=points,
                    source="openapi",
                )
            )
    return out
