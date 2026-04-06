from __future__ import annotations

import uuid
from dataclasses import dataclass

from core.findings.models import DastEvidence, Finding, HttpLocation
from core.orchestration.constants import DAST_MODULE_NAME


@dataclass
class RawDastFinding:
    rule_id: str
    title: str
    severity: str
    confidence: str
    category: str
    method: str
    url: str
    parameter: str | None
    endpoint_signature: str | None
    dast_evidence: DastEvidence
    description: str | None = None
    subcategory: str | None = None
    remediation: str | None = None
    correlation: dict | None = None


def raw_findings_to_normalized(raw_list: list[RawDastFinding]) -> list[Finding]:
    out: list[Finding] = []
    for raw in raw_list:
        out.append(
            Finding(
                schema_version="1",
                finding_id=str(uuid.uuid4()),
                fingerprint="fp1:" + "0" * 64,
                engine="dast",
                module=DAST_MODULE_NAME,
                rule_id=raw.rule_id,
                title=raw.title,
                severity=raw.severity,  # type: ignore[arg-type]
                confidence=raw.confidence,  # type: ignore[arg-type]
                category=raw.category,
                status="open",
                location_type="http",
                evidence_type="http_exchange",
                created_at=Finding.utc_now_rfc3339(),
                suppressed=False,
                description=raw.description,
                subcategory=raw.subcategory,
                remediation=raw.remediation,
                correlation=raw.correlation,
                locations=[
                    HttpLocation(
                        url=raw.url,
                        method=raw.method.upper(),
                        parameter=raw.parameter,
                        endpoint_signature=raw.endpoint_signature,
                    )
                ],
                dast_evidence=raw.dast_evidence,
            )
        )
    return out
