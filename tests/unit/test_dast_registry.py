from __future__ import annotations

from pathlib import Path

from core.config.loader import load_resolved_config
from core.config.models import ScanTarget

from modules.dast.checks.registry import checks_for_config, default_check_registry
from modules.dast.targeting.models import build_dast_target_config


def test_default_registry_non_empty() -> None:
    reg = default_check_registry()
    assert len(reg.passive_checks()) >= 1
    assert len(reg.active_checks()) >= 1


def test_checks_disabled_filters() -> None:
    cfg = load_resolved_config(
        None,
        {"scan": {"modules": ["http_dast"], "profile": "fast"}, "dast": {"crawl": {"enabled": False}}},
    )
    dcfg = build_dast_target_config(ScanTarget(url="https://x/"), cfg, Path.cwd())
    dcfg.checks_disabled = frozenset({"dast.active.reflected_xss"})
    passive, active = checks_for_config(dcfg)
    assert all(c.rule_id != "dast.active.reflected_xss" for c in active)
