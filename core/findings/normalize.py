from __future__ import annotations

import uuid
from pathlib import Path

from core.findings.fingerprints import compute_fingerprint
from core.findings.models import Finding

_VALID_SEVERITY = frozenset({"info", "low", "medium", "high", "critical"})
_VALID_CONFIDENCE = frozenset({"low", "medium", "high"})


def normalize_finding(finding: Finding, scan_root: Path) -> Finding:
    """Coerce severity/confidence, assign fingerprint per §9.11, ensure finding_id exists."""
    sev = finding.severity if finding.severity in _VALID_SEVERITY else "medium"
    conf = finding.confidence if finding.confidence in _VALID_CONFIDENCE else "medium"
    finding = finding.model_copy(update={"severity": sev, "confidence": conf})
    fp = compute_fingerprint(finding, scan_root)
    fid = finding.finding_id or str(uuid.uuid4())
    return finding.model_copy(update={"fingerprint": fp, "finding_id": fid})


def sort_findings_stable(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (f.fingerprint.encode("utf-8"), f.finding_id.encode("utf-8")))


def prepare_findings_for_export(findings: list[Finding]) -> list[Finding]:
    return sort_findings_stable(findings)
