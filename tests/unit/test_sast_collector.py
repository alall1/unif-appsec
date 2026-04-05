from __future__ import annotations

from pathlib import Path

from modules.sast.files.collector import collect_python_files


def test_collect_single_file(tmp_path: Path) -> None:
    root = tmp_path
    f = root / "a.py"
    f.write_text("x=1\n", encoding="utf-8")
    out = collect_python_files(root, target_path=f)
    assert out == [f]


def test_exclude_glob(tmp_path: Path) -> None:
    root = tmp_path
    (root / "keep.py").write_text("x=1\n", encoding="utf-8")
    (root / "skip.py").write_text("x=1\n", encoding="utf-8")
    out = collect_python_files(root, exclude_paths=["skip.py"])
    assert len(out) == 1
    assert out[0].name == "keep.py"


def test_include_filter(tmp_path: Path) -> None:
    root = tmp_path
    (root / "a.py").write_text("x=1\n", encoding="utf-8")
    sub = root / "pkg"
    sub.mkdir()
    (sub / "b.py").write_text("x=1\n", encoding="utf-8")
    out = collect_python_files(root, include_paths=["pkg/*"])
    assert len(out) == 1
    assert out[0].name == "b.py"
