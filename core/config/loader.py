from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any, Optional

import yaml

from core.config.defaults import PROFILE_NAMES, profile_defaults
from core.config.models import (
    LimitsConfig,
    OutputConfig,
    PoliciesConfig,
    ProjectConfig,
    ResolvedConfig,
    SarifOutputConfig,
    ScanConfig,
)


def deep_merge_dict(base: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    """Recursive dict merge; overlay values replace base for non-dict leaves and lists."""
    result: dict[str, Any] = dict(base)
    for key, value in overlay.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = deep_merge_dict(result[key], value)
        else:
            result[key] = value
    return result


def _read_file_dict(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    suffix = path.suffix.lower()
    if suffix in {".yaml", ".yml"}:
        loaded = yaml.safe_load(text)
    elif suffix == ".json":
        loaded = json.loads(text)
    else:
        raise ValueError(f"Unsupported config extension for {path}; use .json, .yaml, or .yml")
    if not isinstance(loaded, dict):
        raise ValueError("Config file must contain a JSON/YAML object at the root")
    return loaded


def _coerce_resolved(merged: dict[str, Any]) -> ResolvedConfig:
    version = merged.get("config_version")
    if version is None:
        raise ValueError("config_version is required")
    if str(version) != "1":
        raise ValueError(f"Unsupported config_version: {version!r} (only '1' is supported)")

    scan_raw = merged.get("scan") or {}
    scan_modules_key_present = "modules" in scan_raw
    profile_name = str(scan_raw.get("profile", "balanced"))
    if profile_name not in PROFILE_NAMES:
        raise ValueError(f"scan.profile must be one of {list(PROFILE_NAMES)}, got {profile_name!r}")

    output_raw = merged.get("output") or {}
    sarif_raw = output_raw.get("sarif") or {}
    output = OutputConfig(
        format=output_raw.get("format", "json"),
        path=output_raw.get("path", "appsec-results.json"),
        pretty=bool(output_raw.get("pretty", False)),
        sarif=SarifOutputConfig(
            enabled=bool(sarif_raw.get("enabled", False)),
            path=sarif_raw.get("path"),
        ),
    )

    policies_raw = merged.get("policies") or {}
    policies = PoliciesConfig(
        fail_on_severity=policies_raw.get("fail_on_severity", "medium"),
        confidence_threshold=policies_raw.get("confidence_threshold", "low"),
    )

    limits_raw = merged.get("limits") or {}
    limits = LimitsConfig.model_validate(limits_raw)

    scan = ScanConfig.model_validate(scan_raw)

    project = ProjectConfig.model_validate(merged.get("project") or {})

    return ResolvedConfig(
        config_version=str(version),
        scan_modules_key_present=scan_modules_key_present,
        project=project,
        scan=scan,
        output=output,
        policies=policies,
        limits=limits,
        sast=dict(merged.get("sast") or {}),
        dast=dict(merged.get("dast") or {}),
        sca=dict(merged.get("sca") or {}),
        iac=dict(merged.get("iac") or {}),
        suppressions=merged.get("suppressions") or [],
    )


def merge_config_layers(
    file_document: Optional[dict[str, Any]],
    cli_overlay: Optional[dict[str, Any]],
) -> dict[str, Any]:
    """§8.5: profile defaults → entire config document → CLI overlay.

    When the CLI sets ``scan.profile``, the file's ``scan.profile`` must not change which
    profile defaults are chosen before the file overlay is applied (CLI wins for profile name).
    """
    pre = copy.deepcopy(file_document or {})
    cli = dict(cli_overlay or {})
    scan_cli = cli.get("scan") or {}
    cli_profile = scan_cli.get("profile")

    if cli_profile is not None:
        scan_pre = dict(pre.get("scan") or {})
        scan_pre.pop("profile", None)
        pre["scan"] = scan_pre

    scan_pre2 = pre.get("scan") or {}
    file_profile = scan_pre2.get("profile")
    chosen = cli_profile or file_profile or "balanced"
    chosen = str(chosen)

    merged = deep_merge_dict(profile_defaults(chosen), pre)
    merged = deep_merge_dict(merged, cli)
    return merged


def load_resolved_config(
    config_path: Optional[Path],
    cli_overlay: Optional[dict[str, Any]] = None,
    *,
    profile_from_cli: Optional[str] = None,
) -> ResolvedConfig:
    file_doc: Optional[dict[str, Any]] = None
    if config_path is not None:
        file_doc = _read_file_dict(config_path)

    cli = dict(cli_overlay or {})
    if profile_from_cli is not None:
        cli.setdefault("scan", {})["profile"] = profile_from_cli

    merged = merge_config_layers(file_doc, cli)
    return _coerce_resolved(merged)
