from __future__ import annotations

from core.config.loader import load_resolved_config


def test_cli_only_includes_config_version_and_profile_defaults() -> None:
    resolved = load_resolved_config(
        None,
        {
            "scan": {"modules": ["stub_sast"], "profile": "balanced"},
        },
    )
    assert resolved.config_version == "1"
    assert resolved.scan.modules == ["stub_sast"]
    assert resolved.limits.max_scan_duration_seconds == 600
