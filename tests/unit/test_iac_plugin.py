from __future__ import annotations

from pathlib import Path

from core.config.loader import load_resolved_config
from core.config.models import ScanTarget
from core.orchestration.runner import run_scan
from core.plugins.registry import PluginRegistry
from modules.iac.plugin import TerraformIacPlugin


def test_iac_emits_findings_for_insecure_fixture() -> None:
    reg = PluginRegistry()
    reg.register(TerraformIacPlugin())

    cfg = load_resolved_config(
        None,
        {
            "config_version": "1",
            "scan": {"modules": ["terraform_iac"], "profile": "fast"},
            "policies": {"fail_on_severity": "critical", "confidence_threshold": "low"},
        },
    )

    target = ScanTarget(path=Path("tests/fixtures/iac/insecure").resolve())
    result, exit_code = run_scan(reg, cfg, target)

    assert exit_code in (0, 1, 2)
    iac_findings = [f for f in result.findings if f.engine == "iac"]
    assert iac_findings, "expected IaC findings from insecure fixtures"

    for f in iac_findings:
        assert f.module == "terraform_iac"
        assert f.location_type == "resource"
        assert f.evidence_type == "metadata_only"
        assert f.iac_details is not None
        assert f.iac_details.provider
        assert f.iac_details.resource_type
        assert f.iac_details.resource_address
        assert f.iac_details.check_id
        assert f.iac_evidence is not None
        assert f.iac_evidence.config_path


def test_iac_no_findings_for_safe_fixture() -> None:
    reg = PluginRegistry()
    reg.register(TerraformIacPlugin())

    cfg = load_resolved_config(
        None,
        {
            "config_version": "1",
            "scan": {"modules": ["terraform_iac"], "profile": "fast"},
        },
    )

    target = ScanTarget(path=Path("tests/fixtures/iac/safe").resolve())
    result, _ = run_scan(reg, cfg, target)

    assert [f for f in result.findings if f.engine == "iac"] == []

