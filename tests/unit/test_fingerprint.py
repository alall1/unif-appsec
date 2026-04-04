from __future__ import annotations

from pathlib import Path

from core.findings.fingerprints import canonical_fingerprint_material, compute_fingerprint, is_valid_fp1
from core.findings.models import CodeLocation, Finding


def test_fp1_format_and_stability(tmp_path: Path) -> None:
    root = tmp_path
    p = root / "pkg" / "a.py"
    p.parent.mkdir(parents=True)
    p.write_text("x=1\n", encoding="utf-8")

    f = Finding(
        finding_id="id-1",
        fingerprint="fp1:" + "0" * 64,
        engine="sast",
        module="python_sast",
        rule_id="r1",
        title="t",
        severity="medium",
        confidence="medium",
        category="c",
        status="open",
        location_type="code",
        evidence_type="code_match",
        created_at="2026-04-03T12:00:00Z",
        suppressed=False,
        locations=[CodeLocation(file_path=str(p), start_line=2, end_line=2, function_name="fn")],
    )
    fp = compute_fingerprint(f, root)
    assert is_valid_fp1(fp)
    fp2 = compute_fingerprint(f, root)
    assert fp == fp2

    material = canonical_fingerprint_material(f, root)
    assert "location_key=" in material
    assert "rule_id=r1" in material


def test_finding_id_does_not_change_fingerprint(tmp_path: Path) -> None:
    root = tmp_path
    p = root / "b.py"
    p.write_text("pass\n", encoding="utf-8")
    base = dict(
        fingerprint="fp1:" + "0" * 64,
        engine="sast",
        module="m",
        rule_id="r",
        title="t",
        severity="low",
        confidence="low",
        category="c",
        status="open",
        location_type="code",
        evidence_type="metadata_only",
        created_at="2026-04-03T12:00:00Z",
        suppressed=False,
        locations=[CodeLocation(file_path=str(p), start_line=1, end_line=1)],
    )
    f1 = Finding(finding_id="a", **base)
    f2 = Finding(finding_id="b", **base)
    assert compute_fingerprint(f1, root) == compute_fingerprint(f2, root)
