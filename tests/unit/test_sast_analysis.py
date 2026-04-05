from __future__ import annotations

from pathlib import Path

from modules.sast.analyzer.engine import analyze_file
from modules.sast.rules.loader import load_rules_pack
from modules.sast.symbols.map import build_symbol_map

REPO = Path(__file__).resolve().parents[2]
FIXTURES = REPO / "modules" / "sast" / "fixtures"
RULES = REPO / "modules" / "sast" / "rules" / "v1_baseline.yaml"


def _analyze(path: Path) -> list[str]:
    pack = load_rules_pack(RULES)
    rules = pack.rules
    src = path.read_text(encoding="utf-8")
    tree = __import__("ast").parse(src, filename=str(path))
    symap = build_symbol_map(tree)
    raw = analyze_file(path, tree, src, symap, rules, max_taint_depth=6)
    out: list[str] = []
    for r in raw:
        for p in r.particles:
            out.append(r.rule.id)
    return sorted(out)


def test_cmd_injection_detected() -> None:
    ids = _analyze(FIXTURES / "vulnerable" / "cmd_injection.py")
    assert "sast.python.command_injection.subprocess_shell" in ids


def test_cmd_injection_sanitized_safe() -> None:
    ids = _analyze(FIXTURES / "safe" / "cmd_injection_shlex.py")
    assert "sast.python.command_injection.subprocess_shell" not in ids


def test_eval_and_exec() -> None:
    assert "sast.python.eval_exec.unsafe_eval" in _analyze(FIXTURES / "vulnerable" / "eval_injection.py")
    assert "sast.python.eval_exec.unsafe_exec" in _analyze(FIXTURES / "vulnerable" / "exec_injection.py")


def test_eval_constant_not_flagged() -> None:
    ids = _analyze(FIXTURES / "safe" / "eval_static.py")
    assert "sast.python.eval_exec.unsafe_eval" not in ids


def test_sql_injection_and_safe_parameterized() -> None:
    assert "sast.python.sql_injection.string_execute" in _analyze(FIXTURES / "vulnerable" / "sql_injection.py")
    assert "sast.python.sql_injection.string_execute" not in _analyze(FIXTURES / "safe" / "sql_parameterized.py")


def test_path_open() -> None:
    assert "sast.python.path_traversal.open_path" in _analyze(FIXTURES / "vulnerable" / "path_traversal.py")
    assert "sast.python.path_traversal.open_path" not in _analyze(FIXTURES / "safe" / "path_constant.py")


def test_weak_hash() -> None:
    assert "sast.python.crypto.weak_hash_md5_sha1" in _analyze(FIXTURES / "vulnerable" / "weak_hash.py")
    assert "sast.python.crypto.weak_hash_md5_sha1" not in _analyze(FIXTURES / "safe" / "strong_hash.py")


def test_interproc_relay() -> None:
    assert "sast.python.command_injection.subprocess_shell" in _analyze(FIXTURES / "vulnerable" / "interproc_relay.py")
