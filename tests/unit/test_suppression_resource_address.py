from __future__ import annotations

from pathlib import Path

from core.config.models import ResolvedConfig, ScanConfig, SuppressionRuleResourceAddress
from core.findings.models import DependencyLocation, Finding, ResourceLocation
from core.policy.suppression import apply_suppressions


def test_rule_resource_address_suppresses_iac_finding_only() -> None:
    rule_id = "iac.terraform.aws_s3_bucket_public_access_block.not_fully_enabled"
    resource_address = "aws_s3_bucket_public_access_block.pab_insecure"

    iac_finding = Finding(
        finding_id="1",
        fingerprint="fp1:" + "a" * 64,
        engine="iac",
        module="terraform_iac",
        rule_id=rule_id,
        title="t",
        severity="medium",
        confidence="high",
        category="infrastructure_public_exposure",
        status="open",
        location_type="resource",
        evidence_type="metadata_only",
        created_at="2026-04-03T12:00:00Z",
        suppressed=False,
        locations=[
            ResourceLocation(
                provider="aws",
                resource_type="aws_s3_bucket_public_access_block",
                resource_id=resource_address,
                resource_path="tests/fixtures/iac/insecure/main.tf",
            )
        ],
        iac_details=None,
        iac_evidence=None,
    )

    # Same rule_id, but this is a dependency finding; it must not match the resource-address suppression shape.
    dep_finding = Finding(
        finding_id="2",
        fingerprint="fp1:" + "b" * 64,
        engine="sca",
        module="python_sca",
        rule_id=rule_id,
        title="t",
        severity="medium",
        confidence="high",
        category="dependency_vulnerability",
        status="open",
        location_type="dependency",
        evidence_type="metadata_only",
        created_at="2026-04-03T12:00:00Z",
        suppressed=False,
        locations=[
            DependencyLocation(ecosystem="pypi", package_name="requests", package_version="2.31.0", dependency_path=None)
        ],
    )

    cfg = ResolvedConfig(
        config_version="1",
        scan=ScanConfig(modules=["terraform_iac"], profile="fast"),
        suppressions=[
            SuppressionRuleResourceAddress(
                rule_id=rule_id,
                provider="aws",
                resource_address=resource_address,
                justification="suppress for test",
            )
        ],
    )

    out = apply_suppressions([iac_finding, dep_finding], cfg, Path(".").resolve())
    assert out[0].suppressed is True
    assert out[0].status == "suppressed"
    assert out[0].suppression_reason == "suppress for test"

    assert out[1].suppressed is False
    assert out[1].status == "open"

