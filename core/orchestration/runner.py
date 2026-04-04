from __future__ import annotations

import time
import traceback
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FuturesTimeout
from pathlib import Path

from core.config.models import ResolvedConfig, ScanTarget
from core.findings.models import Finding, ModuleMetrics, ModuleScanResult, StructuredDiagnostic
from core.findings.normalize import normalize_finding, prepare_findings_for_export
from core.logging.setup import get_logger
from core.orchestration.constants import DAST_MODULE_NAME, SAST_MODULE_NAME
from core.orchestration.exit_code import compute_exit_code, finding_counts_for_fail
from core.orchestration.planner import planned_module_names
from core.orchestration.results import AggregateScanResult, ModuleResultSummary
from core.plugins.base import ScanContext
from core.plugins.registry import PluginRegistry
from core.policy.suppression import apply_suppressions

V1_PROFILES = frozenset({"fast", "balanced", "deep"})


def resolve_scan_root(target: ScanTarget) -> Path:
    if target.path is None:
        return Path.cwd().resolve()
    p = target.path.resolve()
    if p.is_file():
        return p.parent
    return p


def _module_config_slice(plugin_name: str, config: ResolvedConfig) -> dict:
    if plugin_name == SAST_MODULE_NAME:
        return dict(config.sast)
    if plugin_name == DAST_MODULE_NAME:
        return dict(config.dast)
    return {}


def _cap_findings(findings: list[Finding], max_n: int) -> list[Finding]:
    if len(findings) <= max_n:
        return findings
    ordered = sorted(findings, key=lambda f: (f.fingerprint.encode("utf-8"), f.finding_id.encode("utf-8")))
    return ordered[:max_n]


def run_scan(
    registry: PluginRegistry,
    config: ResolvedConfig,
    target: ScanTarget,
    *,
    logger_name: str = "unif_appsec",
) -> tuple[AggregateScanResult, int]:
    log = get_logger(logger_name)
    scan_root = resolve_scan_root(target)
    aggregate = AggregateScanResult()
    has_module_errors = False

    modules = planned_module_names(config)
    if not modules:
        aggregate.scan_errors.append(
            StructuredDiagnostic(
                code="no_modules_selected",
                message="No scan modules configured; set scan.modules or use CLI flags.",
            )
        )
        exit_code = compute_exit_code(
            has_scan_level_failure=True,
            has_module_errors=False,
            findings_fail=False,
        )
        return aggregate, exit_code

    all_findings: list[Finding] = []

    for mod_name in modules:
        plugin = registry.get(mod_name)
        if plugin is None:
            has_module_errors = True
            aggregate.module_results.append(
                ModuleResultSummary(
                    module=mod_name,
                    errors=[
                        StructuredDiagnostic(
                            code="plugin_not_registered",
                            message=f"No plugin registered for module {mod_name!r}.",
                            details={"module": mod_name},
                        )
                    ],
                )
            )
            continue

        supported = list(plugin.supported_profiles())
        if supported and config.scan.profile not in supported:
            aggregate.module_results.append(
                ModuleResultSummary(
                    module=plugin.name,
                    warnings=[
                        StructuredDiagnostic(
                            code="unsupported_profile",
                            message=(
                                f"Module {plugin.name!r} does not support profile "
                                f"{config.scan.profile!r}; skipping."
                            ),
                            details={"profile": config.scan.profile, "supported": list(supported)},
                        )
                    ],
                    metrics=ModuleMetrics(),
                )
            )
            continue

        val_errors = plugin.validate_target(target, config)
        if val_errors:
            has_module_errors = True
            aggregate.module_results.append(
                ModuleResultSummary(module=plugin.name, errors=list(val_errors))
            )
            continue

        deadline = None
        if config.limits.max_scan_duration_seconds:
            deadline = time.monotonic() + float(config.limits.max_scan_duration_seconds)

        ctx = ScanContext(
            logger=log.getChild(plugin.name),
            scan_root=scan_root,
            limits=config.limits,
            policies=config.policies,
            module_config=_module_config_slice(plugin.name, config),
            deadline_monotonic=deadline,
        )

        def _invoke() -> ModuleScanResult:
            return plugin.scan(target, config, ctx)

        try:
            with ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(_invoke)
                result = future.result(timeout=float(config.limits.max_scan_duration_seconds))
        except FuturesTimeout:
            has_module_errors = True
            result = ModuleScanResult(
                errors=[
                    StructuredDiagnostic(
                        code="module_timeout",
                        message=f"Module {plugin.name!r} exceeded max_scan_duration_seconds.",
                        details={"limit_seconds": config.limits.max_scan_duration_seconds},
                    )
                ]
            )
        except Exception as exc:  # noqa: BLE001 — surface as module error (§6.3)
            has_module_errors = True
            log.exception("Module %s failed", plugin.name)
            result = ModuleScanResult(
                errors=[
                    StructuredDiagnostic(
                        code="module_exception",
                        message=str(exc),
                        details={"traceback": traceback.format_exc()},
                    )
                ]
            )

        if result.errors:
            has_module_errors = True

        capped = _cap_findings(list(result.findings), config.limits.max_findings_per_module)
        normalized: list[Finding] = []
        for raw in capped:
            try:
                nf = normalize_finding(raw, scan_root)
                normalized.append(nf)
            except Exception as exc:  # noqa: BLE001
                has_module_errors = True
                result.errors.append(
                    StructuredDiagnostic(
                        code="finding_normalization_failed",
                        message=str(exc),
                        details={"finding_id": getattr(raw, "finding_id", None)},
                    )
                )

        all_findings.extend(normalized)

        aggregate.module_results.append(
            ModuleResultSummary(
                module=plugin.name,
                warnings=list(result.warnings),
                errors=list(result.errors),
                metrics=result.metrics,
            )
        )

    suppressed = apply_suppressions(all_findings, config, scan_root)
    final_findings = prepare_findings_for_export(suppressed)
    aggregate.findings = final_findings

    findings_fail = any(finding_counts_for_fail(f, config.policies) for f in final_findings)

    exit_code = compute_exit_code(
        has_scan_level_failure=bool(aggregate.scan_errors),
        has_module_errors=has_module_errors,
        findings_fail=findings_fail,
    )
    return aggregate, exit_code
