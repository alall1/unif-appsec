from __future__ import annotations

from pathlib import Path

from core.config.loader import load_resolved_config
from core.config.models import ScanTarget
from core.orchestration.runner import run_scan
from core.plugins.registry import PluginRegistry
from tests.fixtures.stub_plugin import FailingPlugin, StubSastPlugin


def test_stub_scan_exit_policy(tmp_path: Path) -> None:
    target_file = tmp_path / "t.py"
    target_file.write_text("x = 1\n", encoding="utf-8")

    reg = PluginRegistry()
    reg.register(StubSastPlugin())

    cfg = load_resolved_config(
        None,
        {
            "config_version": "1",
            "scan": {"modules": ["stub_sast"], "profile": "balanced"},
            "policies": {"fail_on_severity": "high", "confidence_threshold": "low"},
        },
    )
    result, code = run_scan(reg, cfg, ScanTarget(path=target_file))
    assert code == 1
    assert len(result.findings) == 1
    assert result.findings[0].module == "stub_sast"


def test_partial_failure_exit_2(tmp_path: Path) -> None:
    target_file = tmp_path / "t.py"
    target_file.write_text("x = 1\n", encoding="utf-8")

    reg = PluginRegistry()
    reg.register(StubSastPlugin())
    reg.register(FailingPlugin())

    cfg = load_resolved_config(
        None,
        {
            "config_version": "1",
            "scan": {"modules": ["stub_sast", "failing_stub"], "profile": "balanced"},
            "policies": {"fail_on_severity": "critical"},
        },
    )
    result, code = run_scan(reg, cfg, ScanTarget(path=target_file))
    assert code == 2
    assert len(result.findings) == 1
