from __future__ import annotations

import time
from pathlib import Path
from typing import Any, Sequence

from core.config.models import ResolvedConfig, ScanTarget
from core.findings.models import ModuleScanResult, StructuredDiagnostic
from core.orchestration.constants import SCA_MODULE_NAME
from core.plugins.base import AppSecPlugin, ScanContext

from modules.sca.advisories import load_advisories_from_json
from modules.sca.discovery import SUPPORTED_MANIFEST_BASENAMES, discover_manifests
from modules.sca.findings_mapper import to_sca_finding
from modules.sca.inventory import PackageCoordinate
from modules.sca.matcher import advisories_for_package, is_vulnerable_version
from modules.sca.parsers.pipfile_lock import parse_pipfile_lock
from modules.sca.parsers.poetry_lock import parse_poetry_lock
from modules.sca.parsers.requirements_txt import parse_requirements_txt

_BUNDLED_ADVISORIES = Path(__file__).resolve().parent / "fixtures" / "advisories" / "pypi_advisories.json"


def _advisory_db_path(module_config: dict[str, Any], scan_root: Path) -> Path:
    raw = module_config.get("advisory_db_path")
    if not raw:
        return _BUNDLED_ADVISORIES
    p = Path(str(raw)).expanduser()
    if not p.is_absolute():
        p = scan_root / p
    return p


def _parse_inventory(path: Path) -> tuple[list[PackageCoordinate], list[str]]:
    if path.name == "requirements.txt":
        return parse_requirements_txt(path)
    if path.name == "poetry.lock":
        return parse_poetry_lock(path)
    if path.name == "Pipfile.lock":
        return parse_pipfile_lock(path)
    return [], [f"{path.name}: unsupported manifest (v2 baseline is {SUPPORTED_MANIFEST_BASENAMES})"]


class PythonScaPlugin(AppSecPlugin):
    """
    Python ecosystem SCA (V2):
      - manifest/lockfile-first
      - deterministic inventory extraction
      - advisory matching
    """

    name = SCA_MODULE_NAME
    version = "0.1.0"

    def supported_target_types(self) -> Sequence[str]:
        return ("path",)

    def supported_profiles(self) -> Sequence[str]:
        return ()

    def validate_target(self, target: ScanTarget, config: ResolvedConfig) -> list[StructuredDiagnostic]:
        if target.path is None:
            return [
                StructuredDiagnostic(
                    code="sca_missing_path",
                    message="SCA requires a filesystem target path.",
                )
            ]
        p = target.path
        if not p.exists():
            return [StructuredDiagnostic(code="sca_path_missing", message=f"Path does not exist: {p}")]
        if not p.is_file() and not p.is_dir():
            return [StructuredDiagnostic(code="sca_invalid_path", message=f"Not a file or directory: {p}")]
        return []

    def scan(self, target: ScanTarget, config: ResolvedConfig, context: ScanContext) -> ModuleScanResult:
        t0 = time.perf_counter()
        warnings: list[StructuredDiagnostic] = []
        errors: list[StructuredDiagnostic] = []
        findings = []

        scan_root = context.scan_root
        mod_cfg = context.module_config

        manifests = discover_manifests(
            scan_root,
            include_paths=list(config.scan.include_paths),
            exclude_paths=list(config.scan.exclude_paths),
            include_manifests=list(mod_cfg.get("include_manifests") or []),
            exclude_manifests=list(mod_cfg.get("exclude_manifests") or []),
        )
        if not manifests:
            warnings.append(
                StructuredDiagnostic(
                    code="sca_no_supported_manifests",
                    message="No supported dependency manifests/lockfiles found for SCA v2 baseline.",
                    details={"supported": list(SUPPORTED_MANIFEST_BASENAMES)},
                )
            )
            duration_ms = (time.perf_counter() - t0) * 1000.0
            return ModuleScanResult(
                findings=[],
                warnings=warnings,
                errors=[],
                metrics={
                    "duration_ms": duration_ms,
                    "manifests_scanned": 0,
                    "packages_evaluated": 0,
                    "advisories_matched": 0,
                },
            )

        adv_path = _advisory_db_path(mod_cfg, scan_root)
        try:
            advisories = load_advisories_from_json(adv_path)
        except Exception as exc:  # noqa: BLE001
            errors.append(
                StructuredDiagnostic(
                    code="sca_advisory_db_invalid",
                    message=str(exc),
                    details={"path": str(adv_path)},
                )
            )
            duration_ms = (time.perf_counter() - t0) * 1000.0
            return ModuleScanResult(
                findings=[],
                warnings=warnings,
                errors=errors,
                metrics={"duration_ms": duration_ms},
            )

        inventory: list[PackageCoordinate] = []
        parse_warnings: list[str] = []
        for mf in manifests:
            if context.timed_out():
                errors.append(
                    StructuredDiagnostic(
                        code="sca_aborted_timeout",
                        message="SCA scan stopped early due to scan duration limit.",
                    )
                )
                break
            pkgs, w = _parse_inventory(mf)
            inventory.extend(pkgs)
            parse_warnings.extend(w)

        for msg in parse_warnings[:200]:
            warnings.append(
                StructuredDiagnostic(
                    code="sca_manifest_line_ignored",
                    message=msg,
                )
            )
        if len(parse_warnings) > 200:
            warnings.append(
                StructuredDiagnostic(
                    code="sca_manifest_warnings_truncated",
                    message="Manifest parse warnings truncated.",
                    details={"total": len(parse_warnings), "shown": 200},
                )
            )

        inventory = sorted(
            inventory,
            key=lambda p: (p.ecosystem, p.package_name.lower(), p.package_version, p.source_file),
        )

        advisories_matched = 0
        for pkg in inventory:
            for adv in advisories_for_package(advisories, pkg):
                try:
                    if not is_vulnerable_version(pkg.package_version, adv.vulnerable_specifiers):
                        continue
                except Exception as exc:  # noqa: BLE001
                    warnings.append(
                        StructuredDiagnostic(
                            code="sca_version_parse_failed",
                            message=f"Could not evaluate version match for {pkg.package_name}=={pkg.package_version}: {exc}",
                        )
                    )
                    continue
                findings.append(to_sca_finding(scan_root=scan_root, pkg=pkg, advisory=adv))
                advisories_matched += 1

        duration_ms = (time.perf_counter() - t0) * 1000.0
        return ModuleScanResult(
            findings=findings,
            warnings=warnings,
            errors=errors,
            metrics={
                "duration_ms": duration_ms,
                "manifests_scanned": len(manifests),
                "packages_evaluated": len(inventory),
                "advisories_matched": advisories_matched,
            },
        )

