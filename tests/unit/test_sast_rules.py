from __future__ import annotations

from pathlib import Path

from modules.sast.rules.loader import filter_rules, load_rules_pack

RULES = Path(__file__).resolve().parents[2] / "modules" / "sast" / "rules" / "v1_baseline.yaml"


def test_load_baseline_pack() -> None:
    pack = load_rules_pack(RULES)
    assert pack.schema_version == "1"
    ids = {r.id for r in pack.rules}
    assert "sast.python.command_injection.subprocess_shell" in ids
    assert "sast.python.crypto.weak_hash_md5_sha1" in ids


def test_filter_enabled_disabled() -> None:
    pack = load_rules_pack(RULES)
    only = filter_rules(pack.rules, enabled=["sast.python.crypto.weak_hash_md5_sha1"], disabled=None)
    assert len(only) == 1
    none = filter_rules(pack.rules, enabled=None, disabled=["sast.python.crypto.weak_hash_md5_sha1"])
    assert "sast.python.crypto.weak_hash_md5_sha1" not in {r.id for r in none}
