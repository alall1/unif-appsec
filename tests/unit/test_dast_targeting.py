from __future__ import annotations

from pathlib import Path

from core.config.loader import load_resolved_config
from core.config.models import ScanTarget

from modules.dast.targeting.models import (
    build_dast_target_config,
    resolve_urls,
    validate_dast_target,
)


def test_validate_requires_target_url() -> None:
    cfg = load_resolved_config(
        None,
        {"scan": {"modules": ["http_dast"], "profile": "fast"}, "dast": {"crawl": {"enabled": False}}},
    )
    errs, _ = validate_dast_target(ScanTarget(), cfg, Path.cwd())
    assert any("target_url" in e.lower() for e in errs)


def test_resolve_urls_base_and_scope() -> None:
    r = resolve_urls(
        target_url="https://A.example/x",
        base_url="https://a.example/api/",
        allow_cross_origin=False,
        extra_allowed_origins=[],
    )
    assert r is not None
    assert r.origin == "https://a.example"


def test_build_dast_target_merges_scan_target_url() -> None:
    cfg = load_resolved_config(
        None,
        {
            "scan": {"modules": ["http_dast"], "profile": "fast"},
            "dast": {"crawl": {"enabled": False}},
        },
    )
    st = ScanTarget(url="https://scan-target.example/")
    dcfg = build_dast_target_config(st, cfg, Path.cwd())
    assert dcfg.target_url == "https://scan-target.example/"
