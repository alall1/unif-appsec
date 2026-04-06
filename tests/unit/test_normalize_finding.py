from __future__ import annotations

from pathlib import Path

from core.findings.normalize import normalize_finding
from core.findings.models import CodeLocation, Finding


def test_normalize_coerces_invalid_severity_confidence(tmp_path: Path) -> None:
    p = tmp_path / "a.py"
    p.write_text("x=1\n", encoding="utf-8")
    f = Finding.model_construct(
        finding_id="x",
        fingerprint="fp1:" + "0" * 64,
        engine="sast",
        module="python_sast",
        rule_id="r",
        title="t",
        severity="not-a-level",
        confidence="bogus",
        category="c",
        status="open",
        location_type="code",
        evidence_type="code_match",
        created_at="2026-04-03T12:00:00Z",
        suppressed=False,
        locations=[CodeLocation(file_path=str(p), start_line=1, end_line=1)],
    )
    out = normalize_finding(f, tmp_path)
    assert out.severity == "medium"
    assert out.confidence == "medium"
    assert out.fingerprint.startswith("fp1:")
