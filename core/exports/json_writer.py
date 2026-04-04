from __future__ import annotations

import json
from pathlib import Path

from core.config.models import LimitsConfig
from core.exports.evidence_limits import enforce_max_evidence_bytes_on_dict
from core.exports.redaction import redact_finding_dict
from core.orchestration.results import AggregateScanResult


def prepare_aggregate_for_export(result: AggregateScanResult, limits: LimitsConfig) -> dict:
    """Apply evidence limits and redaction; stable structure."""
    findings_out: list[dict] = []
    for f in result.findings:
        d = f.model_dump(exclude_none=True)
        d = enforce_max_evidence_bytes_on_dict(d, limits)
        d = redact_finding_dict(d, limits)
        findings_out.append(d)

    payload: dict = {
        "scan_result_schema_version": result.scan_result_schema_version,
        "findings": findings_out,
        "module_results": [m.model_dump(exclude_none=True) for m in result.module_results],
    }
    if result.scan_errors:
        payload["scan_errors"] = [e.model_dump(exclude_none=True) for e in result.scan_errors]
    return payload


def write_scan_json(result: AggregateScanResult, path: Path, *, limits: LimitsConfig, pretty: bool) -> None:
    payload = prepare_aggregate_for_export(result, limits)
    path.parent.mkdir(parents=True, exist_ok=True)
    indent = 2 if pretty else None
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=indent) + "\n", encoding="utf-8")
