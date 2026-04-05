from __future__ import annotations

import time
from pathlib import Path
from typing import Any, Sequence

from core.config.models import ResolvedConfig, ScanTarget
from core.findings.models import Finding, ModuleMetrics, ModuleScanResult, StructuredDiagnostic
from core.orchestration.constants import SAST_MODULE_NAME
from core.plugins.base import AppSecPlugin, ScanContext

from modules.sast.analyzer.engine import analyze_file
from modules.sast.files.collector import collect_python_files
from modules.sast.findings.mapper import raw_findings_to_findings
from modules.sast.parser.parse import parse_python_file
from modules.sast.rules.loader import filter_rules, load_rules_pack
from modules.sast.symbols.map import build_symbol_map

_BUNDLED_RULES = Path(__file__).resolve().parent / "rules" / "v1_baseline.yaml"


def _rules_path(module_config: dict[str, Any], scan_root: Path) -> Path:
    raw = module_config.get("rules_path")
    if not raw:
        return _BUNDLED_RULES
    p = Path(str(raw)).expanduser()
    if not p.is_absolute():
        p = scan_root / p
    return p


class PythonSastPlugin(AppSecPlugin):
    """Python AST SAST with bounded intrafile taint (master spec §11)."""

    name = SAST_MODULE_NAME
    version = "0.1.0"

    def supported_target_types(self) -> Sequence[str]:
        return ("path",)

    def supported_profiles(self) -> Sequence[str]:
        return ()

    def validate_target(self, target: ScanTarget, config: ResolvedConfig) -> list[StructuredDiagnostic]:
        if target.path is None:
            return [
                StructuredDiagnostic(
                    code="sast_missing_path",
                    message="SAST requires a filesystem target path.",
                )
            ]
        p = target.path
        if not p.exists():
            return [StructuredDiagnostic(code="sast_path_missing", message=f"Path does not exist: {p}")]
        if not p.is_file() and not p.is_dir():
            return [StructuredDiagnostic(code="sast_invalid_path", message=f"Not a file or directory: {p}")]

        scan_root = p.parent.resolve() if p.is_file() else p.resolve()
        files = collect_python_files(
            scan_root,
            target_path=p if p.is_file() else None,
            include_paths=list(config.scan.include_paths),
            exclude_paths=list(config.scan.exclude_paths),
        )
        if not files:
            return [
                StructuredDiagnostic(
                    code="sast_no_python_files",
                    message="Target contains no Python (.py) files after include/exclude filters.",
                    details={"path": str(p)},
                )
            ]
        return []

    def scan(self, target: ScanTarget, config: ResolvedConfig, context: ScanContext) -> ModuleScanResult:
        assert target.path is not None
        t0 = time.perf_counter()
        warnings: list[StructuredDiagnostic] = []
        errors: list[StructuredDiagnostic] = []
        findings: list[Finding] = []

        scan_root = context.scan_root
        p = target.path.resolve()
        mod_cfg = context.module_config

        lang = str(mod_cfg.get("language") or "python").lower()
        if lang != "python":
            warnings.append(
                StructuredDiagnostic(
                    code="sast_language_unsupported",
                    message=f"SAST V1 analyzes Python only; config language={lang!r} ignored.",
                    details={"language": lang},
                )
            )

        rules_file = _rules_path(mod_cfg, scan_root)
        if not rules_file.is_file():
            errors.append(
                StructuredDiagnostic(
                    code="sast_rules_missing",
                    message=f"SAST rules file not found: {rules_file}",
                    details={"rules_path": str(rules_file)},
                )
            )
            return ModuleScanResult(
                findings=[],
                warnings=warnings,
                errors=errors,
                metrics=ModuleMetrics(duration_ms=(time.perf_counter() - t0) * 1000.0, files_analyzed=0),
            )

        try:
            pack = load_rules_pack(rules_file)
        except Exception as exc:  # noqa: BLE001
            errors.append(
                StructuredDiagnostic(
                    code="sast_rules_invalid",
                    message=f"Failed to load SAST rules: {exc}",
                    details={"rules_path": str(rules_file)},
                )
            )
            return ModuleScanResult(
                findings=[],
                warnings=warnings,
                errors=errors,
                metrics=ModuleMetrics(duration_ms=(time.perf_counter() - t0) * 1000.0, files_analyzed=0),
            )

        enabled = mod_cfg.get("enabled_rules")
        disabled = mod_cfg.get("disabled_rules")
        rules = filter_rules(
            pack.rules,
            enabled=list(enabled) if isinstance(enabled, list) else None,
            disabled=list(disabled) if isinstance(disabled, list) else None,
        )
        if not rules:
            warnings.append(
                StructuredDiagnostic(
                    code="sast_no_active_rules",
                    message="No SAST rules remain after enabled/disabled filtering.",
                )
            )

        max_depth = int(mod_cfg.get("max_taint_depth", 4))

        files = collect_python_files(
            scan_root,
            target_path=p if p.is_file() else None,
            include_paths=list(config.scan.include_paths),
            exclude_paths=list(config.scan.exclude_paths),
        )
        files_analyzed = 0

        for fp in files:
            if context.timed_out():
                errors.append(
                    StructuredDiagnostic(
                        code="sast_aborted_timeout",
                        message="SAST scan stopped early due to scan duration limit.",
                    )
                )
                break

            source_text = fp.read_text(encoding="utf-8")
            tree, parse_err = parse_python_file(fp)
            if tree is None:
                errors.append(
                    StructuredDiagnostic(
                        code="sast_parse_error",
                        message=parse_err or "parse_error",
                        details={"file": str(fp)},
                    )
                )
                continue

            files_analyzed += 1
            symap = build_symbol_map(tree)
            deadline = context.timed_out if context.deadline_monotonic is not None else None
            raw = analyze_file(
                fp,
                tree,
                source_text,
                symap,
                rules,
                max_taint_depth=max_depth,
                deadline=deadline,
            )
            findings.extend(
                raw_findings_to_findings(
                    raw,
                    file_path=fp,
                    scan_root=scan_root,
                    source_text=source_text,
                    tree=tree,
                )
            )

        duration_ms = (time.perf_counter() - t0) * 1000.0
        return ModuleScanResult(
            findings=findings,
            warnings=warnings,
            errors=errors,
            metrics=ModuleMetrics(duration_ms=duration_ms, files_analyzed=files_analyzed),
        )
