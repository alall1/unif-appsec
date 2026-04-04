# Unified AppSec Platform — Core

This directory tree implements the **core platform** described in `docs/master_spec.md`: CLI, configuration (with profile and precedence rules), plugin registry, scan orchestration, normalized findings, fingerprints, suppressions, resource and evidence limits, redaction hooks, JSON export, logging, and exit codes.

Real **SAST** and **DAST** analysis live in separate modules that register as plugins; they are not part of this core package.

## Install

```bash
cd /path/to/unif-appsec
python3 -m pip install -e ".[dev]"
```

## Layout

| Path | Role |
|------|------|
| `apps/cli/` | `appsec` entrypoint and argument parsing |
| `core/config/` | Load/merge/validate configuration |
| `core/findings/` | Finding and `ModuleScanResult` models, fingerprint §9.11, normalization/sort §9.12 |
| `core/orchestration/` | Planner, runner (timeouts, caps), aggregate scan envelope, exit code policy |
| `core/plugins/` | `AppSecPlugin` contract and `PluginRegistry` |
| `core/policy/` | Suppression precedence §13.4 |
| `core/exports/` | JSON writer, evidence limits, redaction, SARIF stub/design |
| `core/logging/` | Logging setup |
| `schemas/` | JSON Schema drafts aligned with runtime models |
| `examples/` | Sample config and example scan JSON |
| `tests/` | Unit tests (stub plugin under `tests/fixtures/`) |

## Registering plugins

The default `appsec` console script uses an **empty** registry. Integrations should call `registry.register(MyPlugin())` before running a scan, or use `apps.cli.main.run_with_registry(registry)` from a custom entrypoint.

```python
from apps.cli.commands import execute_scan
from core.plugins.registry import PluginRegistry

registry = PluginRegistry()
registry.register(MySastPlugin())
raise SystemExit(execute_scan(["scan", "/repo", "--sast"], registry))
```

## Behavior summary

- **Config precedence:** profile defaults (`fast` / `balanced` / `deep`) → project file → CLI flags (§8.5). If the CLI sets `--profile`, the file’s `scan.profile` does not change which profile defaults seed the merge (CLI wins for the profile name).
- **Exit codes:** `0` success under policy; `1` unsuppressed findings meeting severity and confidence thresholds; `2` usage, config, runtime, or any module failure (§8.8, §6.3).
- **Findings:** sorted by `fingerprint` then `finding_id` (§9.12). Fingerprints are computed in core (`fp1:` + SHA-256) and must not depend on `finding_id`, timestamps, or suppression fields (§9.11).
- **Suppressions:** applied after findings are produced; scan/module errors are never suppressed (§13.4).
- **Limits:** per-module wall-clock timeout, max findings per module (deterministic cap after sorting), per-finding evidence size, and redaction/truncation aligned with `limits.max_response_body_bytes` / `max_evidence_bytes` (§8.9, §15.3).

## JSON Schemas

Runtime validation uses Pydantic models; `schemas/*.json` are reference documents. Keep them aligned when the spec or models change.

## License

Project license as defined by the repository root (add `LICENSE` if missing).
