from __future__ import annotations

from core.config.models import ResolvedConfig, ScanTarget
from core.orchestration.constants import DAST_MODULE_NAME, SAST_MODULE_NAME


def _dast_target_url_resolved(target: ScanTarget, config: ResolvedConfig) -> str | None:
    raw = target.url
    if raw is not None and str(raw).strip():
        return str(raw).strip()
    cfg_url = config.dast.get("target_url")
    if cfg_url is not None and str(cfg_url).strip():
        return str(cfg_url).strip()
    return None


def inferred_module_names(target: ScanTarget, config: ResolvedConfig) -> list[str]:
    """When ``scan.modules`` is omitted, infer from path / effective DAST URL (§8.1 flows)."""
    has_path = target.path is not None
    dast_url = _dast_target_url_resolved(target, config)
    has_dast = bool(dast_url)
    if has_path and has_dast:
        return [SAST_MODULE_NAME, DAST_MODULE_NAME]
    if has_path:
        return [SAST_MODULE_NAME]
    if has_dast:
        return [DAST_MODULE_NAME]
    return []


def planned_module_names(config: ResolvedConfig, target: ScanTarget) -> list[str]:
    if config.scan.modules:
        return list(config.scan.modules)
    if config.scan_modules_key_present:
        return []
    return inferred_module_names(target, config)
