import ast
from pathlib import Path

from minisast.analyzer import Analyzer
from minisast.finding import Finding


def find_python_files(path: Path):
    if path.is_file():
        if path.suffix == ".py":
            return [path]
        return []

    return sorted(p for p in path.rglob("*.py") if p.is_file())


def scan_file(file_path: Path):
    try:
        source = file_path.read_text(encoding="utf-8")
    except Exception as e:
        return [
            Finding(
                file=str(file_path),
                line=0,
                rule_id="READ_ERROR",
                severity="LOW",
                message=str(e),
            )
        ]

    try:
        tree = ast.parse(source, filename=str(file_path))
    except SyntaxError as e:
        return [
            Finding(
                file=str(file_path),
                line=e.lineno or 0,
                rule_id="SYNTAX_ERROR",
                severity="LOW",
                message=e.msg,
            )
        ]

    analyzer = Analyzer(file_path)
    return analyzer.analyze(tree)


def scan_path(path: Path):
    findings = []
    for file_path in find_python_files(path):
        findings.extend(scan_file(file_path))
    return findings
