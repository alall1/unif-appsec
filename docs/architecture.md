# Architecture

This document clarifies how the Unified AppSec Platform is structured and how data flows through it. It is derived from and aligned with [master_spec.md](./master_spec.md); the master spec remains authoritative.

## Goals (V1)

- One core platform with pluggable SAST and DAST modules.
- CLI-first orchestration, typed models, testable boundaries.
- Normalized findings for all modules; scan errors kept separate from findings.
- Honest scope: no dashboard, database, SaaS, or enterprise-scale claims beyond what the spec defines.

## Layered Components

| Layer | Responsibility |
|--------|-----------------|
| **CLI** | Parse commands and flags, invoke orchestration, print human summary, map policy to exit codes. |
| **Config** | Load and validate versioned config, merge defaults, resolve profiles, expose typed settings to orchestration and plugins. |
| **Orchestration** | Validate targets, select modules, run scans in order per plan, aggregate `ModuleScanResult`, apply suppressions, enforce limits, coordinate export. |
| **Plugin registry** | Discover/register modules; the core knows only the plugin contract, not module internals. |
| **Findings / results** | Normalized finding models, fingerprinting, normalization helpers; aggregate scan result containing findings plus per-module errors/warnings/metrics. |
| **Export** | JSON (required), SARIF (should-have per spec); deterministic sorting and stable structure; evidence redaction. |
| **SAST module** | Python-only, AST-based, bounded intrafile interprocedural taint; emits findings via `ModuleScanResult`. |
| **DAST module** | HTTP/API-first discovery and audit; shallow same-origin HTML-only crawl when enabled; emits findings via `ModuleScanResult`. |

Core platform code must not embed SAST or DAST analysis logic. Modules must not reimplement CLI, config loading, or direct file output for findings (they return structured results only).

## End-to-End Scan Flow

1. CLI receives `appsec scan [target] [flags]`.
2. Config is loaded, validated, and merged: start from profile defaults, overlay the full config document (including `sast` / `dast`), then overlay CLI flags for corresponding settings (see master spec §8.5).
3. Targets are validated (SAST path rules; DAST URL, scheme, redirect, and scope rules).
4. Modules are selected (`--sast`, `--dast`, `--all`, or `scan.modules` in config). If `scan.modules` is **omitted** from the merged configuration document, the planner infers modules from the effective target: filesystem path → SAST; effective DAST URL (CLI `--target-url` or `dast.target_url`) → DAST; both → run both. If `scan.modules` is **present** in the merged document (including an explicit empty list `[]`), that list is used as-is—no inference.
5. Profile is resolved (`fast` | `balanced` | `deep`).
6. Each selected module runs: `validate_target` then `scan` → `ModuleScanResult`.
7. Findings are aggregated; resource limits (max findings per module, evidence bytes, etc.) are applied as specified.
8. Suppressions are applied to findings (not to scan errors).
9. Machine-readable output is written: JSON must use the aggregate envelope (`scan_result_schema_version`, top-level `findings`, `module_results`) per master spec §9.10.3; finding order follows §9.12. SARIF when implemented.
10. Exit code is computed from policy and failure state.

## Partial Failure and Exit Codes

- **0**: Completed; no unsuppressed findings at or above configured severity **and** confidence thresholds.
- **1**: Completed; at least one unsuppressed finding meets or exceeds those thresholds.
- **2**: Usage, config validation, runtime, or **any** module failure (V1 default per master spec).

If one module fails and another succeeds: successful module findings remain exportable when safe; module-level errors are recorded in the aggregated scan result. This implies exit **2** even when partial findings exist—a deliberate tradeoff documented in the spec.

## Determinism vs Live DAST

- **Deterministic (V1 commitments)**: stable field names and output shape; fingerprints per master spec §9.11; exported finding list order per §9.12; stable aggregate envelope per §9.10.3.
- **Not guaranteed**: identical DAST observations across repeated runs against a live target (network, timing, server state).

Design implication: tests and CI should prefer replay fixtures or controlled local targets for DAST behavior assertions; reserve “live” tests for smoke scenarios.

## Safety and Scope Boundaries

- SAST must not execute target code.
- DAST must respect host/scope configuration; no following external hosts unless explicitly allowed.
- Paths and URLs must be resolved safely; evidence export must redact sensitive material per spec.

## Extension Points (Future, Not V1 Scope)

The schema and orchestration reserve concepts for IAST, SCA, and IaC without requiring V1 implementations. New modules plug in through the same plugin contract and `ModuleScanResult`.

## Repository Shape (Informative)

The master spec recommends a layout under `apps/cli`, `core/*`, `modules/sast`, `modules/dast`, `schemas`, `tests`, including `schemas/scan_result.schema.json` for the aggregate scan document. This document does not mandate filenames beyond what the spec lists; implementation may adjust as long as boundaries above are preserved.
