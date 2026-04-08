from __future__ import annotations

from core.config.models import ResolvedConfig, ScanConfig, SuppressionRuleDependencyCoordinate
from core.findings.models import DependencyLocation, Finding
from core.policy.suppression import apply_suppressions


def test_rule_dependency_coordinate_suppresses() -> None:
    f = Finding(
        finding_id="1",
        fingerprint="fp1:" + "a" * 64,
        engine="sca",
        module="python_sca",
        rule_id="sca.vuln.OSV-EXAMPLE-REQUESTS-0001",
        title="t",
        severity="high",
        confidence="high",
        category="dependency_vulnerability",
        status="open",
        location_type="dependency",
        evidence_type="metadata_only",
        created_at="2026-04-03T12:00:00Z",
        suppressed=False,
        locations=[
            DependencyLocation(
                ecosystem="pypi",
                package_name="requests",
                package_version="2.31.0",
                dependency_path=None,
            )
        ],
    )

    cfg = ResolvedConfig(
        config_version="1",
        scan=ScanConfig(modules=["python_sca"], profile="fast"),
        suppressions=[
            SuppressionRuleDependencyCoordinate(
                rule_id="sca.vuln.OSV-EXAMPLE-REQUESTS-0001",
                ecosystem="pypi",
                package_name="requests",
                package_version="2.31.0",
                justification="suppress for test",
            )
        ],
    )

    from pathlib import Path

    out = apply_suppressions([f], cfg, Path(".").resolve())
    assert out[0].suppressed is True
    assert out[0].status == "suppressed"
    assert out[0].suppression_reason == "suppress for test"

