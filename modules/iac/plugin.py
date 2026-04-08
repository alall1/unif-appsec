from __future__ import annotations

import time
from pathlib import Path
from typing import Any, Sequence

from core.config.models import ResolvedConfig, ScanTarget
from core.findings.models import Finding, ModuleMetrics, ModuleScanResult, StructuredDiagnostic
from core.orchestration.constants import IAC_MODULE_NAME
from core.plugins.base import AppSecPlugin, ScanContext

from modules.iac.files.collector import collect_tf_files
from modules.iac.findings.mapper import to_iac_finding
from modules.iac.parsing.terraform_parser import parse_terraform_file, TerraformResource
from modules.iac.rules.evaluator import evaluate_iac_rules
from modules.iac.rules.loader import load_iac_rules_pack


_BUNDLED_RULE_PACK = Path(__file__).resolve().parent / "rules" / "terraform_baseline.yaml"


class TerraformIacPlugin(AppSecPlugin):
    """
    Terraform-only IaC (V2):
    - static misconfiguration scanning for `.tf` files
    - deterministic parsing and rule evaluation
    - normalized findings with `location_type=resource` and `engine=iac`
    """

    name = IAC_MODULE_NAME
    version = "0.1.0"

    def supported_target_types(self) -> Sequence[str]:
        return ("path",)

    def supported_profiles(self) -> Sequence[str]:
        return ()

    def validate_target(self, target: ScanTarget, config: ResolvedConfig) -> list[StructuredDiagnostic]:
        if target.path is None:
            return [
                StructuredDiagnostic(
                    code="iac_missing_path",
                    message="IaC requires a filesystem target path.",
                )
            ]
        p = target.path
        if not p.exists():
            return [StructuredDiagnostic(code="iac_path_missing", message=f"Path does not exist: {p}")]
        if not p.is_file() and not p.is_dir():
            return [StructuredDiagnostic(code="iac_invalid_path", message=f"Not a file or directory: {p}")]
        return []

    def scan(self, target: ScanTarget, config: ResolvedConfig, context: ScanContext) -> ModuleScanResult:
        assert target.path is not None
        t0 = time.perf_counter()

        warnings: list[StructuredDiagnostic] = []
        errors: list[StructuredDiagnostic] = []
        findings: list[Finding] = []

        scan_root = context.scan_root
        mod_cfg = context.module_config

        providers = mod_cfg.get("providers")
        provider_filter: list[str] | None = None
        if isinstance(providers, list):
            provider_filter = [str(p) for p in providers if p]

        tf_files = collect_tf_files(
            scan_root,
            target_path=target.path if target.path.is_file() else None,
            include_paths=list(config.scan.include_paths),
            exclude_paths=list(config.scan.exclude_paths),
            module_include_paths=[str(x) for x in (mod_cfg.get("include_paths") or []) if x],
            module_exclude_paths=[str(x) for x in (mod_cfg.get("exclude_paths") or []) if x],
        )

        if not tf_files:
            warnings.append(
                StructuredDiagnostic(
                    code="iac_no_supported_tf_files",
                    message="No supported Terraform (.tf) files found for IaC v2 baseline checks.",
                )
            )
            return ModuleScanResult(
                findings=[],
                warnings=warnings,
                errors=[],
                metrics=ModuleMetrics(
                    duration_ms=(time.perf_counter() - t0) * 1000.0,
                    files_scanned=0,
                    resources_evaluated=0,
                    checks_executed=0,
                ),
            )

        rules_file = _BUNDLED_RULE_PACK
        rules: list[Any] = []
        try:
            rule_pack = load_iac_rules_pack(rules_file)
            rules = rule_pack.rules
        except Exception as exc:  # noqa: BLE001
            errors.append(
                StructuredDiagnostic(
                    code="iac_rules_missing_or_invalid",
                    message=f"Failed to load IaC rules pack: {exc}",
                    details={"rules_path": str(rules_file)},
                )
            )
            return ModuleScanResult(
                findings=[],
                warnings=warnings,
                errors=errors,
                metrics=ModuleMetrics(
                    duration_ms=(time.perf_counter() - t0) * 1000.0,
                    files_scanned=len(tf_files),
                    resources_evaluated=0,
                    checks_executed=0,
                ),
            )

        resources: list[TerraformResource] = []
        for fp in tf_files:
            if context.timed_out():
                errors.append(
                    StructuredDiagnostic(
                        code="iac_aborted_timeout",
                        message="IaC scan stopped early due to scan duration limit.",
                    )
                )
                break

            try:
                resources.extend(parse_terraform_file(fp, scan_root=scan_root))
            except Exception as exc:  # noqa: BLE001
                warnings.append(
                    StructuredDiagnostic(
                        code="iac_tf_parse_warning",
                        message=f"Failed to parse {fp.name}: {exc}",
                        details={"file": str(fp)},
                    )
                )

        violations = evaluate_iac_rules(
            resources,
            rules,
            provider_filter=provider_filter,
        )

        for v in violations:
            findings.append(to_iac_finding(violation=v))

        duration_ms = (time.perf_counter() - t0) * 1000.0
        # Best-effort metric: (resource, rule) pairs that were evaluated could be bigger than violations.
        checks_executed = len(resources) * len(rules)
        return ModuleScanResult(
            findings=findings,
            warnings=warnings,
            errors=errors,
            metrics=ModuleMetrics(
                duration_ms=duration_ms,
                files_scanned=len(tf_files),
                resources_evaluated=len(resources),
                checks_executed=checks_executed,
            ),
        )

