from __future__ import annotations

import uuid
from pathlib import Path

from core.findings.models import Finding, IacDetails, IacEvidence, ResourceLocation
from core.orchestration.constants import IAC_MODULE_NAME

from modules.iac.rules.evaluator import IacViolation


def to_iac_finding(*, violation: IacViolation) -> Finding:
    res = violation.resource
    loc = ResourceLocation(
        provider=res.provider,
        resource_type=res.terraform_type,
        resource_id=res.address,
        resource_path=res.config_path,
    )

    evidence = IacEvidence(
        config_path=res.config_path,
        provider=res.provider,
        resource_type=res.terraform_type,
        resource_name=res.name,
        attribute_path=violation.attribute_path,
        expected_vs_actual=violation.expected_vs_actual,
        check_inputs=violation.check_inputs or None,
    )

    details = IacDetails(
        provider=res.provider,
        resource_type=res.terraform_type,
        resource_address=res.address,
        check_id=violation.rule.id,
        resource_name=res.name,
        expected_value=violation.expected_value,
        observed_value=violation.observed_value,
        remediation_hint=violation.rule.remediation_hint,
    )

    # Fingerprint + finding_id are normalized/recomputed by core orchestration (§9.11).
    return Finding(
        schema_version="1",
        finding_id=str(uuid.uuid4()),
        fingerprint="fp1:" + "0" * 64,
        engine="iac",
        module=IAC_MODULE_NAME,
        rule_id=violation.rule.id,
        title=violation.rule.title,
        severity=violation.rule.severity,  # type: ignore[arg-type]
        confidence=violation.rule.confidence,  # type: ignore[arg-type]
        category=violation.rule.category,
        status="open",
        location_type="resource",
        evidence_type="metadata_only",
        created_at=Finding.utc_now_rfc3339(),
        suppressed=False,
        description=violation.rule.message,
        locations=[loc],
        iac_evidence=evidence,
        iac_details=details,
    )

