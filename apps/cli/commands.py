from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path
from typing import Sequence

from pydantic import ValidationError

from core.config.loader import load_resolved_config
from core.config.models import ScanTarget
from core.exports.json_writer import write_scan_json
from core.logging.setup import configure_logging
from core.orchestration.constants import DAST_MODULE_NAME, SAST_MODULE_NAME
from core.orchestration.exit_code import finding_counts_for_fail
from core.orchestration.results import AggregateScanResult
from core.orchestration.runner import run_scan
from core.plugins.registry import PluginRegistry


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="appsec", description="Unified AppSec Platform CLI")
    p.add_argument("--verbose", action="store_true", help="Enable debug logging")
    sub = p.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Run security scan modules")
    scan.add_argument("target", nargs="?", default=None, help="Filesystem target path (SAST)")

    mod = scan.add_mutually_exclusive_group()
    mod.add_argument("--sast", action="store_const", const="sast", dest="module_choice", help="Run SAST module only")
    mod.add_argument("--dast", action="store_const", const="dast", dest="module_choice", help="Run DAST module only")
    mod.add_argument("--all", action="store_const", const="all", dest="module_choice", help="Run SAST and DAST modules")

    scan.add_argument("--config", type=Path, default=None, help="Path to config file (.yaml/.yml/.json)")
    scan.add_argument("--profile", default=None, choices=["fast", "balanced", "deep"])
    scan.add_argument("--format", default=None, choices=["json"], help="Output format")
    scan.add_argument("--output", default=None, help="Output file path")
    scan.add_argument(
        "--fail-on",
        dest="fail_on_severity",
        default=None,
        choices=["info", "low", "medium", "high", "critical"],
    )
    scan.add_argument(
        "--confidence-threshold",
        default=None,
        choices=["low", "medium", "high"],
    )
    scan.add_argument("--include", action="append", default=None, help="Include path (repeatable)")
    scan.add_argument("--exclude", action="append", default=None, help="Exclude path (repeatable)")
    scan.add_argument("--target-url", default=None, help="DAST target URL override")
    scan.add_argument("--openapi", type=Path, default=None, help="OpenAPI spec path for DAST")

    return p


def _cli_overlay_from_args(args: argparse.Namespace) -> dict:
    overlay: dict = {}
    if args.profile is not None:
        overlay.setdefault("scan", {})["profile"] = args.profile

    if args.module_choice == "sast":
        overlay.setdefault("scan", {})["modules"] = [SAST_MODULE_NAME]
    elif args.module_choice == "dast":
        overlay.setdefault("scan", {})["modules"] = [DAST_MODULE_NAME]
    elif args.module_choice == "all":
        overlay.setdefault("scan", {})["modules"] = [SAST_MODULE_NAME, DAST_MODULE_NAME]

    if args.format is not None:
        overlay.setdefault("output", {})["format"] = args.format
    if args.output is not None:
        overlay.setdefault("output", {})["path"] = args.output
    if args.fail_on_severity is not None:
        overlay.setdefault("policies", {})["fail_on_severity"] = args.fail_on_severity
    if args.confidence_threshold is not None:
        overlay.setdefault("policies", {})["confidence_threshold"] = args.confidence_threshold
    if args.include:
        overlay.setdefault("scan", {})["include_paths"] = list(args.include)
    if args.exclude:
        overlay.setdefault("scan", {})["exclude_paths"] = list(args.exclude)
    if args.target_url is not None:
        overlay.setdefault("dast", {})["target_url"] = args.target_url
    if args.openapi is not None:
        overlay.setdefault("dast", {})["openapi_path"] = str(args.openapi)

    return overlay


def _build_scan_target(args: argparse.Namespace) -> ScanTarget:
    path = Path(args.target).resolve() if args.target else None
    openapi_path = Path(args.openapi).resolve() if args.openapi else None
    return ScanTarget(path=path, url=args.target_url, openapi_path=openapi_path)


def _print_human_summary(result: AggregateScanResult, *, output_path: Path, exit_code: int, policies) -> None:
    active = [f for f in result.findings if not f.suppressed]
    sev = Counter(f.severity for f in active)
    mods = ", ".join(m.module for m in result.module_results) or "(none)"

    print("Scan summary", file=sys.stderr)
    print(f"  Modules run: {mods}", file=sys.stderr)
    print(f"  Active findings: {len(active)} (total rows: {len(result.findings)})", file=sys.stderr)
    for level in ("critical", "high", "medium", "low", "info"):
        if sev[level]:
            print(f"    {level}: {sev[level]}", file=sys.stderr)

    print(f"  Output: {output_path}", file=sys.stderr)

    failing = [f for f in result.findings if finding_counts_for_fail(f, policies)]
    if exit_code == 0:
        print("  Exit: 0 (no unsuppressed findings meeting fail policy)", file=sys.stderr)
    elif exit_code == 1:
        print(
            f"  Exit: 1 (policy fail: {len(failing)} finding(s) meet severity/confidence thresholds)",
            file=sys.stderr,
        )
    else:
        print("  Exit: 2 (usage/config/runtime/module failure)", file=sys.stderr)
        for mr in result.module_results:
            for err in mr.errors:
                print(f"  Module error [{mr.module}] {err.code}: {err.message}", file=sys.stderr)
        for err in result.scan_errors:
            print(f"  Scan error {err.code}: {err.message}", file=sys.stderr)


def execute_scan(argv: Sequence[str] | None, registry: PluginRegistry) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    if args.command != "scan":
        parser.error("Only 'scan' is implemented")

    configure_logging(verbose=bool(args.verbose))

    cli_overlay = _cli_overlay_from_args(args)
    try:
        config = load_resolved_config(args.config, cli_overlay, profile_from_cli=args.profile)
    except (ValueError, ValidationError) as exc:
        print(f"Config error: {exc}", file=sys.stderr)
        return 2

    target = _build_scan_target(args)

    result, exit_code = run_scan(registry, config, target)

    out_path = Path(config.output.path).resolve()
    try:
        write_scan_json(result, out_path, limits=config.limits, pretty=config.output.pretty)
    except OSError as exc:
        print(f"Failed to write output: {exc}", file=sys.stderr)
        return 2

    _print_human_summary(result, output_path=out_path, exit_code=exit_code, policies=config.policies)
    return exit_code
