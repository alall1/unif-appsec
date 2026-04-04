from __future__ import annotations

from core.config.models import PoliciesConfig
from core.findings.models import CodeLocation, Finding
from core.orchestration.exit_code import compute_exit_code, finding_counts_for_fail


def _f(**kwargs) -> Finding:
    defaults = dict(
        finding_id="1",
        fingerprint="fp1:" + "b" * 64,
        engine="sast",
        module="m",
        rule_id="r",
        title="t",
        severity="high",
        confidence="high",
        category="c",
        status="open",
        location_type="code",
        evidence_type="code_match",
        created_at="2026-04-03T12:00:00Z",
        suppressed=False,
        locations=[CodeLocation(file_path="a.py", start_line=1, end_line=1)],
    )
    defaults.update(kwargs)
    return Finding(**defaults)


def test_suppressed_does_not_fail() -> None:
    pol = PoliciesConfig(fail_on_severity="low", confidence_threshold="low")
    f = _f(suppressed=True, severity="critical", confidence="high")
    assert finding_counts_for_fail(f, pol) is False


def test_confidence_threshold_filters() -> None:
    pol = PoliciesConfig(fail_on_severity="low", confidence_threshold="high")
    f = _f(severity="critical", confidence="low")
    assert finding_counts_for_fail(f, pol) is False


def test_exit_code_priority_module_error() -> None:
    assert (
        compute_exit_code(
            has_scan_level_failure=False,
            has_module_errors=True,
            findings_fail=True,
        )
        == 2
    )
