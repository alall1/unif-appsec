from __future__ import annotations

from pathlib import Path

from core.config.loader import load_resolved_config
from core.config.models import ScanTarget
from core.findings.normalize import normalize_finding
from core.orchestration.runner import resolve_scan_root, run_scan
from core.plugins.registry import PluginRegistry
from modules.sast.plugin import PythonSastPlugin

REPO = Path(__file__).resolve().parents[2]


def test_python_sast_plugin_finds_issues_in_fixtures_dir(tmp_path: Path) -> None:
    reg = PluginRegistry()
    reg.register(PythonSastPlugin())
    vuln_dir = REPO / "modules" / "sast" / "fixtures" / "vulnerable"
    cfg = load_resolved_config(
        None,
        {
            "config_version": "1",
            "scan": {"modules": ["python_sast"], "profile": "balanced", "include_paths": [], "exclude_paths": []},
        },
    )
    result, code = run_scan(reg, cfg, ScanTarget(path=vuln_dir))
    assert code == 1
    assert len(result.findings) >= 5
    rule_ids = {f.rule_id for f in result.findings}
    assert "sast.python.command_injection.subprocess_shell" in rule_ids
    root = resolve_scan_root(ScanTarget(path=vuln_dir))
    for f in result.findings:
        assert f.engine == "sast"
        assert f.module == "python_sast"
        nf = normalize_finding(f, root)
        assert nf.fingerprint.startswith("fp1:")


def test_validate_rejects_empty_python_tree(tmp_path: Path) -> None:
    reg = PluginRegistry()
    reg.register(PythonSastPlugin())
    empty = tmp_path / "empty_dir"
    empty.mkdir()
    cfg = load_resolved_config(
        None,
        {"config_version": "1", "scan": {"modules": ["python_sast"], "profile": "balanced"}},
    )
    err = reg.get("python_sast").validate_target(ScanTarget(path=empty), cfg)  # type: ignore[union-attr]
    assert err and err[0].code == "sast_no_python_files"
