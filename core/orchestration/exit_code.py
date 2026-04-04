from __future__ import annotations

from core.findings.models import Finding
from core.config.models import PoliciesConfig

_SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_CONFIDENCE_ORDER = {"low": 0, "medium": 1, "high": 2}


def finding_counts_for_fail(f: Finding, policies: PoliciesConfig) -> bool:
    """§8.8 — contributes to exit 1 when True."""
    if f.suppressed:
        return False
    sev_ok = _SEVERITY_ORDER[f.severity] >= _SEVERITY_ORDER[policies.fail_on_severity]
    conf_ok = _CONFIDENCE_ORDER[f.confidence] >= _CONFIDENCE_ORDER[policies.confidence_threshold]
    return sev_ok and conf_ok


def compute_exit_code(
    *,
    has_scan_level_failure: bool,
    has_module_errors: bool,
    findings_fail: bool,
) -> int:
    if has_scan_level_failure or has_module_errors:
        return 2
    if findings_fail:
        return 1
    return 0
