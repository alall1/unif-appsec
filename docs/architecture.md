# Architecture

This document clarifies how the Unified AppSec Platform is structured and how data flows through it. It is derived from and aligned with `master_spec.md`; the master spec remains authoritative.

- **V1 behavior** in this document is **normative** and must remain intact.
- **V2 additions** are called out explicitly and must be **additive** only.

---

## Goals (V1 – unchanged)

- **One core platform with pluggable SAST and DAST modules.**
- **CLI-first orchestration, typed models, testable boundaries.**
- **Normalized findings for all modules; scan errors kept separate from findings.**
- **Honest scope:** no dashboard, database, SaaS, or enterprise-scale claims beyond what the spec defines.

These goals match the current implementation:
- The CLI (`apps/cli`) invokes the orchestration runner in `core/orchestration/runner.py`.
- Config is modeled by `core/config/models.py` and merged by the loader.
- Plugins are registered via `core/plugins/registry.py` and implement `core/plugins/base.py::AppSecPlugin`.
- Findings, module results, and scan aggregates live under `core/findings/*` and `core/orchestration/results.py`.

---

## Layered Components (post‑V2 view)

The **layering remains the same as V1**; V2 only adds new modules that plug into the same contracts.

| Layer | Responsibility | V1/V2 status |
|--------|-----------------|-------------|
| **CLI** | Parse commands and flags, invoke orchestration, print human summary, map policy to exit codes. | **Unchanged from V1** |
| **Config** | Load and validate versioned config, merge defaults, resolve profiles, expose typed settings to orchestration and plugins. | **Unchanged from V1** (V2 adds SCA/IaC config sections in the same shape) |
| **Orchestration** | Validate targets, select modules, run scans, aggregate `ModuleScanResult`, apply suppressions, enforce limits, coordinate export. | **Unchanged from V1** |
| **Plugin registry** | Discover/register modules; the core knows only the plugin contract, not module internals. | **Unchanged from V1** |
| **Findings / results** | Normalized finding models, fingerprinting, normalization helpers; aggregate scan result containing findings plus per-module errors/warnings/metrics. | **Unchanged from V1** (V2 adds new typed extensions) |
| **Export** | JSON (required), SARIF (should-have per spec); deterministic sorting and stable structure; evidence redaction. | **Unchanged from V1** |
| **SAST module** | Python-only, AST-based, bounded intrafile interprocedural taint; emits findings via `ModuleScanResult`. | **Unchanged from V1** |
| **DAST module** | HTTP/API-first discovery and audit; shallow same-origin HTML-only crawl when enabled; emits findings via `ModuleScanResult`. | **Unchanged from V1** |
| **SCA module (V2)** | Dependency/manifest scanner that emits dependency findings with `location_type=dependency`. | **New in V2 (planned)** |
| **IaC module (V2)** | Terraform-only static misconfiguration scanner emitting resource findings with `location_type=resource`. | **New in V2 (planned)** |

Core platform code must not embed SAST, DAST, SCA, or IaC analysis logic. All modules must return findings only through `ModuleScanResult` and must not reimplement CLI, config loading, or direct file output.

---

## Execution Model and Data Flow (V1 – unchanged)

### End-to-End Scan Flow

1. **CLI invocation**: `appsec scan [target] [flags]` (see CLI and config docs).
2. **Config resolution**:
   - Start from profile defaults (`fast` / `balanced` / `deep`).
   - Overlay the full config document (including `scan`, `sast`, `dast`, and future `sca` / `iac` sections).
   - Overlay CLI flags for corresponding settings (per master spec §8.5).
3. **Target validation**:
   - SAST validates filesystem targets per SAST rules (path exists, file/dir, at least one `.py` after filters).
   - DAST validates URLs, schemes, redirects, and scope rules.
4. **Module selection**:
   - Planner in `core/orchestration/planner.py` chooses module names using:
     - `scan.modules` from merged config when present (including `[]`).
     - Otherwise, auto-inference from target type: filesystem path → SAST; DAST URL/OpenAPI → DAST; both → both.
5. **Profile resolution**:
   - Effective profile is the resolved `scan.profile` (`fast` / `balanced` / `deep`).
6. **Per-module execution**:
   - For each selected module, orchestration:
     - Enforces `supported_profiles()` semantics (skip with warning if unsupported).
     - Runs `validate_target`; validation failures become **module errors**, not findings.
     - Builds a `ScanContext` (logger, scan root, limits, policies, module config, deadline).
     - Runs `scan(...)` under a per-module timeout.
7. **Aggregation**:
   - Per-module `ModuleScanResult` findings are capped by `max_findings_per_module`, normalized, and collected.
   - Module warnings/errors/metrics are stored in `module_results`.
8. **Suppression**:
   - `core/policy/suppression.py::apply_suppressions` applies config suppressions, sets `status` and `suppressed`, and records `suppression_reason`.
   - Scan errors and module errors are **never** suppressed.
9. **Export**:
   - `AggregateScanResult` holds:
     - `scan_result_schema_version`
     - final `findings` list (already suppressed/normalized and sorted for export)
     - `module_results` (per-module warnings/errors/metrics)
     - optional `scan_errors` for top-level failures.
   - JSON export writes this envelope for machine use.
10. **Exit code**:
    - Exit codes are computed by `core/orchestration/exit_code.py`:
      - `0` – completed; no unsuppressed findings at/above thresholds.
      - `1` – completed; at least one unsuppressed finding meets severity **and** confidence thresholds.
      - `2` – any scan-level failure or any module errors.

This execution model is **unchanged from V1** and remains the contract for V2.

---

## Module Boundaries and Responsibilities

### Core vs Modules (V1 – unchanged)

- **Core platform responsibilities (code matches spec):**
  - CLI entrypoint and argument parsing.
  - Config loading, merging, and validation into `ResolvedConfig`.
  - Target planning and module selection.
  - Plugin lifecycle (`AppSecPlugin` interfaces, registry).
  - Execution context, timing, and resource limits.
  - Finding normalization, fingerprinting, suppression, aggregation, and export.
  - Exit code computation.

- **Module responsibilities (code matches spec):**
  - Domain-specific analysis only (SAST/DAST and, in V2, SCA/IaC).
  - Implement `supported_target_types`, `supported_profiles`, `validate_target`, and `scan`.
  - Produce **normalized** findings and structured warnings/errors/metrics in `ModuleScanResult`.
  - Never perform CLI parsing or write final output files.

### SAST Module (V1 – unchanged)

- Implemented by `modules/sast/plugin.py::PythonSastPlugin`.
- **Scope and boundaries (match spec §11):**
  - Python-only, AST-based static analysis.
  - Bounded **intrafile** interprocedural taint tracking using rule-defined sources/sinks/sanitizers/propagators.
  - Rule families cover command injection, eval/exec, SQL injection, path traversal, and weak crypto/hash.
  - Does not promise interfile, framework-wide, or whole-program soundness.
- **Key guarantees to preserve:**
  - Target validation enforces presence of at least one `.py` file after include/exclude filters.
  - Rules are loaded from a bundled `v1_baseline.yaml` unless overridden via `sast.rules_path`.
  - Unsupported languages (non-Python) yield warnings, not crashes.
  - Parse errors are reported as **module errors** with `code="sast_parse_error"`, not as findings.
  - All emitted findings are normalized through the shared model and returned via `ModuleScanResult`.

### DAST Module (V1 – unchanged)

- Implemented by `modules/dast/plugin.py::HttpDastPlugin`.
- **Scope and boundaries (match spec §12):**
  - HTTP/API-first scanner.
  - Explicit **discovery** and **audit** phases, separated in code (`DiscoveryEngine`, `AuditEngine`).
  - Discovery honors config and scope; optional shallow same-origin HTML-only crawl with no JavaScript execution.
  - Audit runs passive and active checks with rate limiting and evidence capture.
- **Key guarantees to preserve:**
  - Target validation is strict for URL, scheme, and scope; failures become module errors.
  - `supported_target_types()` is `("url",)`, keeping DAST out of filesystem-only contexts.
  - Auth is limited to static headers, bearer token, and cookies; no implied SSO/MFA support.
  - Findings carry HTTP locations and structured HTTP evidence; network/runtime errors are separate module errors.

---

## V2 Additive Modules: SCA and IaC

V2 introduces **two new module families** that plug into the **same architecture**:

### SCA Module (V2 – new)

- **Design position:**
  - Implemented as an additional `AppSecPlugin` with:
    - `engine="sca"`
    - `location_type="dependency"`
    - `evidence_type="metadata_only"` (typically).
- **Scope (per master spec §20.1):**
  - Python-only dependency scanning.
  - Inputs: `requirements.txt`, `poetry.lock`, `Pipfile.lock` under the scan root.
  - Responsibilities:
    - Locate supported manifests/lockfiles under the same filesystem targets used for SAST.
    - Parse files into normalized dependency coordinates.
    - Match against configured/bundled advisory data.
    - Emit normalized findings using the shared core fields plus optional `sca_details` and SCA evidence.
- **Boundaries (must remain narrow):**
  - No reachability or exploitability analysis.
  - No image/container or live system inventory.
  - No new ecosystems beyond the Python baseline above without a spec change.

### IaC Module (V2 – new)

- **Design position:**
  - Implemented as an additional `AppSecPlugin` with:
    - `engine="iac"`
    - `location_type="resource"`
    - `evidence_type="metadata_only"` (typically).
- **Scope (per master spec §20.2):**
  - Terraform-only static misconfiguration scanning.
  - Inputs: `.tf` files under the scan root.
  - Responsibilities:
    - Collect Terraform HCL files in scope.
    - Parse only the configuration shapes required by V2 checks.
    - Evaluate rule-driven misconfiguration checks.
    - Emit normalized findings with optional `iac_details` and IaC evidence.
- **Boundaries (must remain narrow):**
  - No live cloud or state file analysis.
  - No multi-format IaC support beyond Terraform.
  - No graph-heavy cross-account reasoning.

### IAST (Deferred)

- IAST remains **explicitly deferred to V3**.
- The architecture reserves:
  - Trace models and correlation objects.
  - `engine="iast"` in `EngineName`.
- **V2 must not** introduce runtime IAST behavior or change the frozen V1 contracts described in the master spec.

---

## Extension Points and Boundaries (Guidance for Future Work)

- **Plugin surface (unchanged from V1):**
  - All future modules **must** implement `AppSecPlugin` and return `ModuleScanResult`.
  - The core must not gain per-module special cases; SCA and IaC are “just more plugins”.

- **Findings model (unchanged from V1, extended in V2):**
  - The required core fields are frozen.
  - Extension happens through typed objects (`sast_evidence`, `dast_evidence`, `sca_details`, `iac_details`, traces, locations).

- **Config model (unchanged precedence):**
  - Profiles → config file → CLI remains the only precedence order.
  - SCA and IaC config sections (when implemented) must follow the same shape and override rules as `sast` / `dast`.

- **Error model (unchanged from V1):**
  - Findings never carry error status; `status` is only `open` or `suppressed`.
  - Module and scan errors remain separate arrays in `ModuleScanResult` and `AggregateScanResult`.

---

## Repository Shape (Informative – unchanged)

The master spec recommends a layout under `apps/cli`, `core/*`, `modules/sast`, `modules/dast`, `schemas`, `tests`, including `schemas/scan_result.schema.json` for the aggregate scan document. The current repository follows this structure for V1 SAST and DAST.

For V2:
- **SCA and IaC modules should live under** `modules/sca` and `modules/iac` (or equivalent), mirroring the SAST/DAST layout.
- **Schema updates** (`finding.schema.json`, `scan_result.schema.json`, `config.schema.json`) must be kept in lockstep with runtime models when SCA and IaC are implemented.

These structural choices are additive and must **not** change existing SAST/DAST behavior or contracts.

