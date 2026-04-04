from __future__ import annotations

import uuid
from pathlib import Path

from core.findings.fingerprints import compute_fingerprint
from core.findings.models import Finding


def normalize_finding(finding: Finding, scan_root: Path) -> Finding:
    """Assign fingerprint per §9.11; ensure finding_id exists."""
    fp = compute_fingerprint(finding, scan_root)
    fid = finding.finding_id or str(uuid.uuid4())
    return finding.model_copy(update={"fingerprint": fp, "finding_id": fid})


def sort_findings_stable(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (f.fingerprint.encode("utf-8"), f.finding_id.encode("utf-8")))


def prepare_findings_for_export(findings: list[Finding]) -> list[Finding]:
    return sort_findings_stable(findings)
