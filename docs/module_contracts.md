# Module Contracts

This document specifies the plugin boundary between the core platform and scan modules, as defined in `master_spec.md` Sections 5, 9.9–9.10, 10, and 20. The master spec is authoritative.

- **V1 contracts** are frozen and must remain intact.
- **V2 modules (SCA and IaC)** plug into the **same contracts** and use the same `ModuleScanResult` and finding model.

---

## Plugin Interface (conceptual – unchanged from V1)

Each module registers a plugin that exposes at minimum:

| Member | Description |
|--------|-------------|
| `name` | Stable module identifier. |
| `version` | Module version string. |
| `supported_target_types()` | Which target kinds this module accepts (e.g. `("path",)` or `("url",)`). |
| `supported_profiles()` | Declares supported profile names; see semantics below. |
| `validate_target(target, config)` | Pre-flight validation; failures become scan/module errors, not findings. |
| `scan(target, config, context) -> ModuleScanResult` | Executes the scan. |

Optional:

- `healthcheck() -> status` for diagnostics.

### `supported_profiles()` semantics (unchanged)

- **Non-empty list:** plugin runs only for those profile names; core must reject or skip the module when the selected profile is absent (behavior is explicit and tested).
- **Empty list:** plugin accepts all platform profiles (`fast`, `balanced`, `deep`).

The current SAST and DAST plugins follow this contract (`PythonSastPlugin`, `HttpDastPlugin`); SCA and IaC plugins must do the same.

---

## ModuleScanResult (unchanged from V1)

Every `scan` invocation returns a **ModuleScanResult** (master spec §9.10.1) containing:

| Field | Content |
|--------|---------|
| `findings` | Normalized findings (unified schema, core fields + typed extensions). |
| `warnings` | Array of `{ code, message, details? }` (non-fatal). |
| `errors` | Array of `{ code, message, details? }` (failures—not findings). |
| `metrics` | Object; include when applicable `duration_ms`, `files_analyzed` (SAST), `requests_sent` (DAST), and module-specific counters; unknown keys ignored by consumers. |

Plugins may use internal models internally; **normalization must occur before** returning results to the core. The core merges `ModuleScanResult` into the aggregate JSON envelope (`AggregateScanResult`); plugins do not emit the top-level file directly.

V2 SCA and IaC modules:
- Must return findings only in `findings`.
- Must surface their own warnings/errors/metrics via this same structure.

---

## Plugin Rules (unchanged from V1)

Plugins **must**:

- Return normalized findings only via `ModuleScanResult` (no alternative side-channel for findings).
- Avoid direct CLI behavior (no argument parsing, no stdout ownership for machine output).
- Avoid direct output writing for findings (core export layer writes JSON/SARIF).
- Use shared config objects and typed accessors provided by the core.
- Use shared logging facilities.

The core **must not** depend on module internals beyond this contract. This is true for SAST/DAST today and must remain true when SCA and IaC are added.

---

## Target Validation (V1 – unchanged)

Validation failures surface as **errors** on the module or scan result, not as findings.

- **SAST**:
  - Path exists.
  - Path is a file or directory.
  - After include/exclude filters, at least one supported file type is present (Python `.py` in V1).
- **DAST**:
  - URL syntactically valid.
  - Scheme allowed by config.
  - Redirect behavior follows config.
  - Host and scope rules satisfied (no off-scope hosts unless explicitly allowed).

V2 modules must follow the same pattern:

- **SCA (V2)**:
  - Repository path exists and is a file or directory.
  - At least one supported manifest/lockfile (`requirements.txt`, `poetry.lock`, `Pipfile.lock`) is present within scope (subject to any include/exclude rules).
  - If nothing is found, return **warnings** and no findings (unless a future config option demands hard-fail).
- **IaC (V2)**:
  - Repository path exists and is a file or directory.
  - At least one `.tf` file is present within scope (subject to any include/exclude rules).
  - If nothing is found, return **warnings** and no findings (unless a future config option demands hard-fail).

---

## SAST Module Obligations (V1 – unchanged)

- Python source only; AST-based analysis.
- V1 does **not** require built-in Flask/Django/FastAPI request sources; optional rule packs may add explicitly named adapters (master spec §11.7.1).
- Bounded **intrafile** interprocedural taint (see master spec “not supported” list).
- Rule-driven sources, sinks, sanitizers, propagators; taint traces where applicable.
- Emit findings with appropriate `location_type`/`evidence_type`:
  - `location_type="code"`.
  - `evidence_type="code_trace"`, `code_match`, or `metadata_only` as appropriate.

These obligations are already met by `PythonSastPlugin` and must not be weakened by V2.

---

## DAST Module Obligations (V1 – unchanged)

- HTTP/API-first; discovery phase then audit phase (separate in code architecture).
- Discovery priority: OpenAPI, explicit seeds, and target config **over** crawler-driven discovery.
- Crawler (if enabled):
  - Same-origin only.
  - HTML links/forms only.
  - Shallow depth as configured.
  - **No** JavaScript execution; no claim of complete route discovery.
- Passive and active checks per spec; evidence suitable for `http_exchange` and related fields.
- Respect rate limits, timeouts, and scope from config.

These obligations are already met by `HttpDastPlugin` and must remain unchanged in V2.

---

## SCA Module Obligations (V2 additive)

The SCA module is a **new module family** that uses the same plugin contract:

- **Plugin shape**:
  - Implements `AppSecPlugin` with:
    - `name` identifying the SCA module (e.g. `python_sca`).
    - `supported_target_types()` including `"path"` (repository filesystem target).
    - `supported_profiles()` following the same semantics as other modules.
- **Responsibilities** (per master spec §20.1):
  - Locate supported dependency manifests/lockfiles.
  - Parse and extract normalized package coordinates.
  - Match against advisory data.
  - Emit normalized findings with:
    - `engine="sca"`
    - `location_type="dependency"`
    - `evidence_type="metadata_only"` (unless a spec change defines more).
    - Optional `sca_details` extension object.
  - Populate relevant metrics, e.g. `manifests_scanned`, `packages_evaluated`, `advisories_matched`.
- **Boundaries**:
  - No reachability/exploitability analysis.
  - No container/image scanning.
  - No new ecosystems beyond the Python baseline without an explicit spec update.

SCA must not add new exit-code meanings or bypass the unified finding/error model.

---

## IaC Module Obligations (V2 additive)

The IaC module is another **new module family** plugging into the same contract:

- **Plugin shape**:
  - Implements `AppSecPlugin` with:
    - `name` identifying the IaC module (e.g. `terraform_iac`).
    - `supported_target_types()` including `"path"` (repository filesystem target).
    - `supported_profiles()` with the same semantics.
- **Responsibilities** (per master spec §20.2):
  - Collect supported Terraform `.tf` files in scope.
  - Parse required configuration forms for V2 checks.
  - Evaluate rule-driven static checks.
  - Emit normalized findings with:
    - `engine="iac"`
    - `location_type="resource"`
    - `evidence_type="metadata_only"` (unless a spec change defines more).
    - Optional `iac_details` extension object.
  - Populate relevant metrics, e.g. `files_scanned`, `resources_evaluated`, `checks_executed`.
- **Boundaries**:
  - No live cloud validation.
  - No multi-format IaC support beyond Terraform `.tf`.
  - No graph-heavy cloud reasoning beyond what simple static checks require.

IaC must also strictly respect the existing error and exit-code behavior.

---

## Findings vs Errors (critical – unchanged from V1)

| Situation | Where it lives |
|-----------|----------------|
| Vulnerability or policy violation detected | Normalized **finding** (`status` is `open` or `suppressed` after suppression pass). |
| Network timeout, crash, bad config, unsupported target | **Module error** or **scan error** (never a finding). |
| Scanner limitation (“not modeled”) | Typically **no finding**; may emit a **warning**. |

- Do **not** add `status: error` on findings.
- Do **not** encode module or scan errors in findings.

This rule applies identically to SAST, DAST, SCA, and IaC in V2.

---

## Context Object (implementation – unchanged from V1)

The `scan(..., context)` argument is a `ScanContext` created by the core and should provide, without coupling modules to CLI:

- Logger instance (scoped to the module).
- Abort/cancellation or timeout awareness aligned with `max_scan_duration_seconds`.
- Read-only view of effective limits and policies needed for safe scanning.
- Module-specific configuration slice (`sast`, `dast`, and in V2 `sca`, `iac` keyed by plugin name).
- Paths or handles for temporary storage if specified by implementation.

Exact fields are implementation-defined but must not break the “no direct CLI/output” rule and must remain compatible with the V1 contract when V2 modules are added.

---

## Testing Expectations (unchanged from V1)

- **Unit tests**:
  - `validate_target` edge cases.
  - Normalized finding shape for representative rules/checks.
  - Metrics and warning/error behavior for failure cases.
- **Integration tests**:
  - Plugin registration and discovery.
  - Combined runs across multiple modules.
  - Partial failure behavior and exit codes.
  - Deterministic export of findings and module results.

V2 SCA and IaC modules should receive the same level of testing and must not regress any existing SAST/DAST contract tests.

