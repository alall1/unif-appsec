from __future__ import annotations

from pathlib import Path

from core.config.loader import load_resolved_config


def test_profile_precedence_cli_over_file(tmp_path: Path) -> None:
    cfg = tmp_path / "c.yaml"
    cfg.write_text(
        """
config_version: "1"
scan:
  profile: deep
  modules: [stub_sast]
policies:
  fail_on_severity: low
""",
        encoding="utf-8",
    )
    resolved = load_resolved_config(
        cfg,
        {"policies": {"fail_on_severity": "critical"}},
        profile_from_cli="fast",
    )
    assert resolved.scan.profile == "fast"
    assert resolved.policies.fail_on_severity == "critical"
    assert resolved.limits.max_scan_duration_seconds == 120


def test_file_overrides_profile_defaults(tmp_path: Path) -> None:
    cfg = tmp_path / "c.yaml"
    cfg.write_text(
        """
config_version: "1"
scan:
  profile: balanced
  modules: [stub_sast]
limits:
  max_findings_per_module: 3
""",
        encoding="utf-8",
    )
    resolved = load_resolved_config(cfg, profile_from_cli=None)
    assert resolved.limits.max_findings_per_module == 3
