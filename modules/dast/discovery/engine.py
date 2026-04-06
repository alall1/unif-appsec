from __future__ import annotations

import urllib.parse
from typing import Any

from core.findings.models import StructuredDiagnostic
from core.plugins.base import ScanContext

from modules.dast.discovery.crawl import crawl_same_origin, dedupe_endpoints, html_insertion_points
from modules.dast.discovery.models import DiscoveredEndpoint, InsertionPoint
from modules.dast.discovery.openapi import endpoints_from_openapi
from modules.dast.http.client import HttpClient
from modules.dast.targeting.models import UrlResolution


def _join(base: str, path_or_url: str) -> str:
    p = path_or_url.strip()
    if urllib.parse.urlsplit(p).scheme:
        return p
    if not base.endswith("/"):
        base = base + "/"
    return urllib.parse.urljoin(base, p.lstrip("/"))


def endpoints_from_seeds(seeds: list[dict[str, Any]], base_url: str) -> list[DiscoveredEndpoint]:
    out: list[DiscoveredEndpoint] = []
    for raw in seeds:
        if not isinstance(raw, dict):
            continue
        method = str(raw.get("method", "GET")).upper()
        url = raw.get("url")
        path = raw.get("path")
        if isinstance(url, str):
            full = url
        elif isinstance(path, str):
            full = _join(base_url, path)
        else:
            continue
        points: list[InsertionPoint] = []
        params = raw.get("parameters") or raw.get("params")
        if isinstance(params, list):
            for prm in params:
                if not isinstance(prm, dict):
                    continue
                name = prm.get("name")
                inn = str(prm.get("in", "query")).lower()
                if isinstance(name, str) and name and inn in ("query", "path", "header", "form"):
                    points.append(InsertionPoint(name=name, location=inn))  # type: ignore[arg-type]
        out.append(DiscoveredEndpoint(method=method, url=full, insertion_points=points, source="seed"))
    return out


def _merge_insertion_points(existing: list[InsertionPoint], extra: list[InsertionPoint]) -> list[InsertionPoint]:
    seen = {(p.name, p.location) for p in existing}
    merged = list(existing)
    for p in extra:
        k = (p.name, p.location)
        if k not in seen:
            merged.append(p)
            seen.add(k)
    return merged


def enrich_endpoint_from_html(ep: DiscoveredEndpoint, html: str) -> DiscoveredEndpoint:
    extra = html_insertion_points(html)
    if not extra:
        return ep
    return DiscoveredEndpoint(
        method=ep.method,
        url=ep.url,
        insertion_points=_merge_insertion_points(ep.insertion_points, extra),
        source=ep.source,
    )


class DiscoveryEngine:
    """Discovery phase: explicit target → OpenAPI → seeds → optional same-origin crawl (§12.4)."""

    def discover(
        self,
        *,
        resolution: UrlResolution,
        openapi_path: Any,
        endpoint_seeds: list[dict[str, Any]],
        crawl_enabled: bool,
        crawl_max_depth: int | None,
        client: HttpClient,
        request_headers: dict[str, str],
        max_crawl_depth: int,
        context: ScanContext,
    ) -> tuple[list[DiscoveredEndpoint], list[StructuredDiagnostic]]:
        warnings: list[StructuredDiagnostic] = []
        endpoints: list[DiscoveredEndpoint] = []

        # 1) Explicit target configuration
        endpoints.append(
            DiscoveredEndpoint(
                method="GET",
                url=resolution.primary_url,
                insertion_points=[],
                source="target",
            )
        )

        # 2) OpenAPI
        if openapi_path is not None:
            try:
                endpoints.extend(endpoints_from_openapi(openapi_path, resolution.base_url))
            except Exception as exc:  # noqa: BLE001
                warnings.append(
                    StructuredDiagnostic(
                        code="dast_openapi_parse_failed",
                        message=str(exc),
                        details={"path": str(openapi_path)},
                    )
                )

        # 3) Config seeds
        endpoints.extend(endpoints_from_seeds(endpoint_seeds, resolution.base_url))

        endpoints = dedupe_endpoints(endpoints)

        # Observed HTML on primary URL: merge form fields into matching GET endpoints
        if not context.timed_out():
            try:
                resp = client.request("GET", resolution.primary_url, headers=request_headers)
                ctype = (resp.headers.get("content-type") or "").lower()
                if "text/html" in ctype or resp.body_text.lstrip().lower().startswith("<!doctype html"):
                    primary_norm = urllib.parse.urldefrag(resolution.primary_url)[0]
                    for i, ep in enumerate(endpoints):
                        if ep.method.upper() == "GET" and urllib.parse.urldefrag(ep.url)[0] == primary_norm:
                            endpoints[i] = enrich_endpoint_from_html(ep, resp.body_text)
            except Exception as exc:  # noqa: BLE001
                warnings.append(
                    StructuredDiagnostic(
                        code="dast_discovery_fetch_failed",
                        message=f"Primary URL fetch for discovery failed: {exc}",
                        details={"url": resolution.primary_url},
                    )
                )

        # 4) Optional crawl
        if crawl_enabled and not context.timed_out():
            depth = crawl_max_depth if crawl_max_depth is not None else max_crawl_depth
            try:
                crawled = crawl_same_origin(
                    start_url=resolution.primary_url,
                    client=client,
                    auth_headers=request_headers,
                    max_depth=depth,
                    scope=resolution.scope,
                )
                endpoints.extend(crawled)
            except Exception as exc:  # noqa: BLE001
                warnings.append(
                    StructuredDiagnostic(
                        code="dast_crawl_failed",
                        message=str(exc),
                    )
                )

        endpoints = dedupe_endpoints(endpoints)
        return endpoints, warnings
