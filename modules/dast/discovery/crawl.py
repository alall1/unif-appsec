from __future__ import annotations

import html.parser
import urllib.parse
from typing import Iterable

from modules.dast.discovery.models import DiscoveredEndpoint, InsertionPoint
from modules.dast.http.client import HttpClient
from modules.dast.targeting.models import ScopePolicy, url_is_in_scope


class _LinkCollector(html.parser.HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []
        self.forms: list[tuple[str, str, list[tuple[str, str]]]] = []  # action, method, [(name, default)]

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        ad = {k.lower(): (v or "") for k, v in attrs}
        if tag.lower() == "a":
            href = ad.get("href", "").strip()
            if href and not href.startswith(("#", "javascript:", "mailto:")):
                self.links.append(href)
        if tag.lower() == "form":
            action = ad.get("action", "").strip() or "."
            method = ad.get("method", "get").upper() or "GET"
            self.forms.append((action, method, []))
        if tag.lower() in ("input", "select", "textarea") and self.forms:
            name = ad.get("name", "").strip()
            if name:
                self.forms[-1][2].append((name, ad.get("value", "").strip()))


def html_insertion_points(html: str) -> list[InsertionPoint]:
    parser = _LinkCollector()
    try:
        parser.feed(html)
    except Exception:
        return []
    out: list[InsertionPoint] = []
    for _, _, fields in parser.forms:
        for name, _ in fields:
            if name:
                out.append(InsertionPoint(name=name, location="form"))
    return out


def _resolve_link(base_url: str, href: str) -> str:
    return urllib.parse.urljoin(base_url, href)


def crawl_same_origin(
    *,
    start_url: str,
    client: HttpClient,
    auth_headers: dict[str, str],
    max_depth: int,
    scope: ScopePolicy,
) -> list[DiscoveredEndpoint]:
    """HTML link and form extraction only; same-origin; no JavaScript."""
    if max_depth < 1:
        return []

    seen_urls: set[tuple[str, str]] = set()
    queue: list[tuple[str, int]] = [(start_url, 0)]
    out: list[DiscoveredEndpoint] = []

    while queue:
        url, depth = queue.pop(0)
        if depth > max_depth:
            continue
        if not url_is_in_scope(url, scope):
            continue
        key = ("GET", urllib.parse.urldefrag(url)[0])
        if key in seen_urls:
            continue
        seen_urls.add(key)

        resp = client.request("GET", url, headers=auth_headers)
        ctype = (resp.headers.get("content-type") or "").lower()
        if "text/html" not in ctype and not resp.body_text.lstrip().lower().startswith("<!doctype html"):
            continue

        parser = _LinkCollector()
        try:
            parser.feed(resp.body_text)
        except Exception:
            continue

        for href in parser.links:
            abs_u = _resolve_link(url, href)
            if not url_is_in_scope(abs_u, scope):
                continue
            canon = urllib.parse.urldefrag(abs_u)[0]
            mkey = ("GET", canon)
            if mkey not in seen_urls:
                out.append(DiscoveredEndpoint(method="GET", url=canon, insertion_points=[], source="crawl"))
                if depth + 1 <= max_depth:
                    queue.append((canon, depth + 1))

        for action, method, fields in parser.forms:
            abs_u = _resolve_link(url, action)
            if not url_is_in_scope(abs_u, scope):
                continue
            m = method if method in {"GET", "POST"} else "GET"
            points = [InsertionPoint(name=n, location="form") for n, _ in fields]
            ep = DiscoveredEndpoint(method=m, url=abs_u, insertion_points=points, source="crawl")
            out.append(ep)

    return dedupe_endpoints(out)


def dedupe_endpoints(eps: Iterable[DiscoveredEndpoint]) -> list[DiscoveredEndpoint]:
    seen: set[tuple[str, str]] = set()
    out: list[DiscoveredEndpoint] = []
    for e in eps:
        u = urllib.parse.urldefrag(e.url)[0]
        k = (e.method.upper(), u)
        if k in seen:
            continue
        seen.add(k)
        e.url = u
        e.method = e.method.upper()
        out.append(e)
    return out
