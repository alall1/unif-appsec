from __future__ import annotations

import ast
import uuid
from pathlib import Path

from core.findings.models import CodeLocation, Finding, SastEvidence
from core.orchestration.constants import SAST_MODULE_NAME

from modules.sast.analyzer.engine import RawFinding
from modules.sast.traces.builder import particle_to_trace_steps


def _rel_file_path(file_path: Path, scan_root: Path) -> str:
    try:
        return str(file_path.resolve().relative_to(scan_root.resolve()))
    except ValueError:
        return str(file_path)


def _snippet_for_node(source: str, tree: ast.Module, node: ast.AST) -> str | None:
    seg = ast.get_source_segment(source, node)
    if seg:
        s = seg.strip()
        if len(s) > 400:
            return s[:400] + "..."
        return s
    return None


def _code_location(
    file_path: Path,
    scan_root: Path,
    node: ast.AST,
    *,
    function_name: str | None,
) -> CodeLocation:
    rel = _rel_file_path(file_path, scan_root)
    start_line = getattr(node, "lineno", 1) or 1
    end_line = getattr(node, "end_lineno", None) or start_line
    start_col = getattr(node, "col_offset", None)
    end_col = getattr(node, "end_col_offset", None)
    if start_col is not None:
        start_col += 1
    if end_col is not None:
        end_col += 1
    return CodeLocation(
        file_path=rel,
        start_line=start_line,
        end_line=end_line,
        start_col=start_col,
        end_col=end_col,
        function_name=function_name,
    )


def _function_for_line(tree: ast.Module, lineno: int) -> str | None:
    best: ast.FunctionDef | ast.AsyncFunctionDef | None = None
    best_start = -1
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            end = getattr(node, "end_lineno", None) or node.lineno
            if node.lineno <= lineno <= end and node.lineno >= best_start:
                best = node
                best_start = node.lineno
    return best.name if best else None


def _sink_qualified_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Call):
        fn = node.func
        if isinstance(fn, ast.Name):
            return fn.id
        if isinstance(fn, ast.Attribute):
            parts: list[str] = []
            cur: ast.AST = fn
            while isinstance(cur, ast.Attribute):
                parts.append(cur.attr)
                cur = cur.value
            if isinstance(cur, ast.Name):
                parts.append(cur.id)
                return ".".join(reversed(parts))
    return None


def raw_findings_to_findings(
    raws: list[RawFinding],
    *,
    file_path: Path,
    scan_root: Path,
    source_text: str,
    tree: ast.Module,
) -> list[Finding]:
    """Convert analyzer output to normalized :class:`Finding` models (fingerprints filled by core)."""
    findings: list[Finding] = []
    rel = _rel_file_path(file_path, scan_root)
    for raw in raws:
        rule = raw.rule
        sink_ln = getattr(raw.sink_node, "lineno", 1) or 1
        fn_name = _function_for_line(tree, sink_ln)
        for particle in raw.particles:
            loc = _code_location(file_path, scan_root, raw.sink_node, function_name=fn_name)
            trace = particle_to_trace_steps(particle, file_path=rel)
            sink_q = _sink_qualified_name(raw.sink_node)
            src_label = next((e.label for e in particle.events if e.kind == "source"), None)
            trace_summary = " -> ".join(filter(None, (s.label or s.kind for s in trace)))

            if rule.analysis == "sink_only":
                ev_type = "code_match"
            else:
                ev_type = "code_trace"

            sev = rule.severity
            conf = rule.confidence
            if sev not in ("info", "low", "medium", "high", "critical"):
                sev = "medium"
            if conf not in ("low", "medium", "high"):
                conf = "medium"

            correlation: dict[str, str] = {}
            if rule.cwe:
                correlation["cwe"] = rule.cwe
            if sink_q:
                correlation["sink_type"] = sink_q
            correlation["file_path"] = loc.file_path
            if loc.function_name:
                correlation["function_name"] = loc.function_name

            findings.append(
                Finding(
                    finding_id=str(uuid.uuid4()),
                    fingerprint="fp1:" + "0" * 64,
                    engine="sast",
                    module=SAST_MODULE_NAME,
                    rule_id=rule.id,
                    title=rule.title,
                    severity=sev,  # type: ignore[arg-type]
                    confidence=conf,  # type: ignore[arg-type]
                    category=rule.category,
                    status="open",
                    location_type="code",
                    evidence_type=ev_type,  # type: ignore[arg-type]
                    created_at=Finding.utc_now_rfc3339(),
                    suppressed=False,
                    description=rule.message,
                    references=list(rule.references) if rule.references else None,
                    tags=list(rule.tags) if rule.tags else None,
                    correlation=correlation or None,
                    locations=[loc],
                    sast_evidence=SastEvidence(
                        code_snippet=_snippet_for_node(source_text, tree, raw.sink_node),
                        matched_sink=sink_q,
                        matched_source=src_label,
                        trace_summary=trace_summary or None,
                    ),
                    trace=trace if ev_type == "code_trace" else None,
                )
            )
    return findings
