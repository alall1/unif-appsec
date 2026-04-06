from __future__ import annotations

import urllib.parse
from dataclasses import dataclass
from typing import Any
from pathlib import Path

from core.config.models import ResolvedConfig, ScanTarget


@dataclass(frozen=True)
class ScopePolicy:
    """V1: default same-origin only; optional allowlist for explicit multi-host (honest, minimal)."""

    allowed_origins: frozenset[str]
    allow_cross_origin: bool = False

    def origin_allowed(self, origin: str) -> bool:
        if self.allow_cross_origin:
            return True
        return origin in self.allowed_origins


def _origin_from_parsed(parsed: urllib.parse.SplitResult) -> str:
    scheme = (parsed.scheme or "").lower()
    netloc = parsed.netloc.lower()
    return f"{scheme}://{netloc}"


def parse_http_url(url: str) -> urllib.parse.SplitResult | None:
    try:
        p = urllib.parse.urlsplit(url.strip())
    except ValueError:
        return None
    if not p.scheme or not p.netloc:
        return None
    return p


@dataclass(frozen=True)
class UrlResolution:
    primary_url: str
    base_url: str
    origin: str
    scope: ScopePolicy


def resolve_urls(
    *,
    target_url: str | None,
    base_url: str | None,
    allow_cross_origin: bool,
    extra_allowed_origins: list[str] | None,
) -> UrlResolution | None:
    if not target_url:
        return None
    pt = parse_http_url(target_url)
    if pt is None:
        return None
    origin = _origin_from_parsed(pt)
    primary = urllib.parse.urlunsplit((pt.scheme.lower(), pt.netloc.lower(), pt.path or "", pt.query, ""))

    if base_url:
        bt = parse_http_url(base_url)
        if bt is None:
            return None
        base = urllib.parse.urlunsplit((bt.scheme.lower(), bt.netloc.lower(), bt.path or "", "", ""))
        if not base.endswith("/"):
            base = base + "/"
        bo = _origin_from_parsed(bt)
        origins = {origin, bo}
    else:
        root = urllib.parse.urlunsplit((pt.scheme.lower(), pt.netloc.lower(), "/", "", ""))
        base = root
        origins = {origin}

    if extra_allowed_origins:
        for o in extra_allowed_origins:
            ot = parse_http_url(o)
            if ot is not None:
                origins.add(_origin_from_parsed(ot))

    scope = ScopePolicy(frozenset(origins), allow_cross_origin=allow_cross_origin)
    return UrlResolution(primary_url=primary, base_url=base, origin=origin, scope=scope)


@dataclass
class DastTargetConfig:
    """Effective DAST options merged from ResolvedConfig.dast and ScanTarget."""

    target_url: str | None
    base_url: str | None
    openapi_path: Path | None
    allowed_schemes: frozenset[str]
    follow_redirects: bool
    allow_cross_origin: bool
    extra_allowed_origins: list[str]
    endpoint_seeds: list[dict[str, Any]]
    crawl_enabled: bool
    crawl_max_depth: int | None
    timeout_seconds: float
    checks_disabled: frozenset[str]
    passive_enabled: bool
    active_enabled: bool
    auth_headers: dict[str, str]
    bearer_token: str | None
    initial_cookies: dict[str, str]
    reauth_hook: str | None


def _path_or_none(raw: Any, scan_root: Path) -> Path | None:
    if raw is None or raw == "":
        return None
    p = Path(str(raw)).expanduser()
    if not p.is_absolute():
        p = scan_root / p
    return p


def build_dast_target_config(target: ScanTarget, config: ResolvedConfig, scan_root: Path) -> DastTargetConfig:
    d = dict(config.dast)
    target_url = target.url or d.get("target_url")
    if isinstance(target_url, str):
        target_url = target_url.strip() or None
    base_url = d.get("base_url")
    if isinstance(base_url, str):
        base_url = base_url.strip() or None

    openapi_raw = target.openapi_path or d.get("openapi_path")
    openapi_path = None
    if openapi_raw is not None:
        openapi_path = Path(openapi_raw).expanduser() if isinstance(openapi_raw, Path) else _path_or_none(openapi_raw, scan_root)

    schemes = d.get("allowed_schemes")
    if isinstance(schemes, list) and schemes:
        allowed_schemes = frozenset(str(s).lower() for s in schemes)
    else:
        allowed_schemes = frozenset({"http", "https"})

    crawl = d.get("crawl") or {}
    crawl_enabled = bool(crawl.get("enabled", False))
    crawl_max = crawl.get("max_depth")
    crawl_max_depth = int(crawl_max) if crawl_max is not None else None

    checks = d.get("checks") or {}
    passive_block = checks.get("passive") or {}
    active_block = checks.get("active") or {}
    passive_enabled = passive_block.get("enabled", True) is not False
    active_enabled = active_block.get("enabled", True) is not False
    disabled = checks.get("disabled")
    checks_disabled: frozenset[str] = frozenset()
    if isinstance(disabled, list):
        checks_disabled = frozenset(str(x) for x in disabled)

    auth = d.get("auth") or {}
    headers = auth.get("headers") if isinstance(auth.get("headers"), dict) else {}
    auth_headers = {str(k): str(v) for k, v in headers.items()}
    bearer = auth.get("bearer_token") or auth.get("bearer")
    bearer_token = str(bearer) if bearer else None
    cookies_raw = auth.get("cookies") if isinstance(auth.get("cookies"), dict) else {}
    initial_cookies = {str(k): str(v) for k, v in cookies_raw.items()}
    reauth_hook = auth.get("reauth_hook")
    reauth_hook_s = str(reauth_hook) if reauth_hook else None

    seeds = d.get("endpoint_seeds")
    endpoint_seeds: list[dict[str, Any]] = list(seeds) if isinstance(seeds, list) else []

    timeout = float(d.get("timeout", 15.0))

    extra_hosts = d.get("allowed_hosts")
    extra_allowed_origins: list[str] = list(extra_hosts) if isinstance(extra_hosts, list) else []

    return DastTargetConfig(
        target_url=target_url,
        base_url=base_url,
        openapi_path=openapi_path,
        allowed_schemes=allowed_schemes,
        follow_redirects=bool(d.get("follow_redirects", True)),
        allow_cross_origin=bool(d.get("allow_cross_origin", False)),
        extra_allowed_origins=extra_allowed_origins,
        endpoint_seeds=endpoint_seeds,
        crawl_enabled=crawl_enabled,
        crawl_max_depth=crawl_max_depth,
        timeout_seconds=timeout,
        checks_disabled=checks_disabled,
        passive_enabled=passive_enabled,
        active_enabled=active_enabled,
        auth_headers=auth_headers,
        bearer_token=bearer_token,
        initial_cookies=initial_cookies,
        reauth_hook=reauth_hook_s,
    )


def validate_dast_target(target: ScanTarget, config: ResolvedConfig, scan_root: Path) -> tuple[list[str], DastTargetConfig]:
    """Return (error_messages, cfg). Empty errors means OK."""
    cfg = build_dast_target_config(target, config, scan_root)
    errors: list[str] = []
    if not cfg.target_url:
        errors.append("DAST requires target_url (CLI --target-url or dast.target_url).")
        return errors, cfg

    parsed = parse_http_url(cfg.target_url)
    if parsed is None:
        errors.append(f"Invalid target URL: {cfg.target_url!r}")
        return errors, cfg

    if parsed.scheme.lower() not in cfg.allowed_schemes:
        errors.append(
            f"URL scheme {parsed.scheme!r} not allowed; allowed: {sorted(cfg.allowed_schemes)}"
        )

    resolved = resolve_urls(
        target_url=cfg.target_url,
        base_url=cfg.base_url,
        allow_cross_origin=cfg.allow_cross_origin,
        extra_allowed_origins=cfg.extra_allowed_origins,
    )
    if resolved is None:
        errors.append("Could not resolve DAST scope from target/base URL.")
        return errors, cfg

    if cfg.openapi_path is not None and not cfg.openapi_path.is_file():
        errors.append(f"OpenAPI file not found: {cfg.openapi_path}")

    return errors, cfg


def url_is_in_scope(url: str, scope: ScopePolicy) -> bool:
    p = parse_http_url(url)
    if p is None:
        return False
    return scope.origin_allowed(_origin_from_parsed(p))


