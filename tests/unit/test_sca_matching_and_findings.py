from __future__ import annotations

from pathlib import Path

from core.config.loader import load_resolved_config
from core.config.models import ScanTarget
from core.orchestration.runner import run_scan
from core.plugins.registry import PluginRegistry
from modules.sca.plugin import PythonScaPlugin


def test_sca_emits_finding_for_vulnerable_requirements_fixture() -> None:
    reg = PluginRegistry()
    reg.register(PythonScaPlugin())

    cfg = load_resolved_config(
        None,
        {
            "config_version": "1",
            "scan": {"modules": ["python_sca"], "profile": "fast"},
            "policies": {"fail_on_severity": "critical", "confidence_threshold": "low"},
        },
    )

    target = ScanTarget(path=Path("tests/fixtures/sca/vulnerable").resolve())
    result, exit_code = run_scan(reg, cfg, target)

    assert exit_code in (0, 1, 2)
    assert any(f.engine == "sca" for f in result.findings)
    f = next(x for x in result.findings if x.engine == "sca")
    assert f.module == "python_sca"
    assert f.location_type == "dependency"
    assert f.evidence_type == "metadata_only"
    assert f.sca_details is not None
    assert f.sca_details.ecosystem == "pypi"
    assert f.sca_details.advisory_source
    assert f.sca_evidence is not None
    assert f.sca_evidence.advisory_id


def test_sca_no_findings_for_safe_fixture() -> None:
    reg = PluginRegistry()
    reg.register(PythonScaPlugin())

    cfg = load_resolved_config(
        None,
        {
            "config_version": "1",
            "scan": {"modules": ["python_sca"], "profile": "fast"},
        },
    )
    target = ScanTarget(path=Path("tests/fixtures/sca/safe").resolve())
    result, _ = run_scan(reg, cfg, target)
    assert [f for f in result.findings if f.engine == "sca"] == []

