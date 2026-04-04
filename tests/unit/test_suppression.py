from __future__ import annotations

from pathlib import Path

from core.config.models import ResolvedConfig, ScanConfig, SuppressionFingerprint
from core.findings.models import CodeLocation, Finding
from core.policy.suppression import apply_suppressions


def _finding(fp: str) -> Finding:
    p = Path("src/x.py")
    return Finding(
        finding_id="1",
        fingerprint=fp,
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
        locations=[CodeLocation(file_path=str(p), start_line=10, end_line=10)],
    )


def test_fingerprint_suppression_wins_attribution(tmp_path: Path) -> None:
    fp_val = "fp1:" + "a" * 64
    f = _finding(fp_val)
    cfg = ResolvedConfig(
        config_version="1",
        scan=ScanConfig(modules=["m"]),
        suppressions=[
            SuppressionFingerprint(fingerprint=fp_val, justification="by fp"),
        ],
    )
    out = apply_suppressions([f], cfg, tmp_path)
    assert len(out) == 1
    assert out[0].suppressed is True
    assert out[0].status == "suppressed"
    assert out[0].suppression_reason == "by fp"
