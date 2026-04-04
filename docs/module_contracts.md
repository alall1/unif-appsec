# Module Contracts

This document specifies the plugin boundary between the core platform and scan modules, as defined in [master_spec.md](./master_spec.md) Sections 5, 9.9–9.10, and 10. The master spec is authoritative.

## Plugin Interface (Conceptual)

Each module registers a plugin that exposes at minimum:

| Member | Description |
|--------|-------------|
| `name` | Stable module identifier |
| `version` | Module version string |
| `supported_target_types()` | Which target kinds this module accepts |
| `supported_profiles()` | Declares supported profile names; see semantics below |
| `validate_target(target, config)` | Pre-flight validation; failures become scan/module errors, not findings |
| `scan(target, config, context) -> ModuleScanResult` | Executes the scan |

Optional:

- `healthcheck() -> status` for diagnostics

### `supported_profiles()` semantics

- **Non-empty list:** plugin runs only for those profile names; core must reject or skip the module when the selected profile is absent (behavior explicit and tested).
- **Empty list:** plugin accepts all V1 platform profiles (`fast`, `balanced`, `deep`).

## ModuleScanResult

Every `scan` invocation returns a **ModuleScanResult** (master spec §9.10.1) containing:

| Field | Content |
|--------|---------|
| **findings** | Normalized findings (unified schema, core fields + typed extensions) |
| **warnings** | Array of `{ code, message, details? }` (non-fatal) |
| **errors** | Array of `{ code, message, details? }` (failures—not findings) |
| **metrics** | Object; include when applicable `duration_ms`, `files_analyzed` (SAST), `requests_sent` (DAST); unknown keys ignored by consumers |

Plugins may use internal models internally; **normalization must occur before** returning results to the core. The core merges into the aggregate JSON envelope (§9.10.3); plugins do not emit the top-level file directly.

## Plugin Rules

Plugins **must**:

- Return normalized findings only via `ModuleScanResult` (no alternative side-channel for findings)
- Avoid direct CLI behavior (no argument parsing, no stdout ownership for machine output)
- Avoid direct output writing for findings (core export layer writes JSON/SARIF)
- Use shared config objects and typed accessors provided by the core
- Use shared logging facilities

The core **must not** depend on module internals beyond this contract.

## Target Validation

- **SAST**: Path exists; is file or directory; contains at least one supported file type (Python in V1).
- **DAST**: URL syntactically valid; scheme allowed; redirects handled per config; host and scope rules satisfied.

Validation failures surface as **errors** on the module or scan result, not as findings.

## SAST Module Obligations (V1)

- Python source only; AST-based analysis.
- V1 does **not** require built-in Flask/Django/FastAPI request sources; optional rule packs may add explicitly named adapters (master spec §11.7.1).
- Bounded **intrafile** interprocedural taint (see master spec “not supported” list).
- Rule-driven sources, sinks, sanitizers, propagators; taint traces where applicable.
- Emit findings with appropriate `location_type`/`evidence_type` (`code`, `code_trace` / `code_match` / `metadata_only` as appropriate).

## DAST Module Obligations (V1)

- HTTP/API-first; discovery phase then audit phase (separate in code architecture).
- Discovery priority: OpenAPI, explicit seeds, target config **over** crawler-driven discovery.
- Crawler (if enabled): same-origin, HTML links/forms only, shallow depth, **no** JavaScript execution; no claim of complete route discovery.
- Passive and active checks per spec; evidence suitable for `http_exchange` and related fields.
- Respect rate limits, timeouts, and scope from config.

## Findings vs Errors (Critical)

| Situation | Where it lives |
|-----------|----------------|
| Vulnerability or policy violation detected | Normalized **finding** (`status` is `open` or `suppressed` after suppression pass) |
| Network timeout, crash, bad config, unsupported target | **Module error** or **scan error** |
| Scanner limitation (“not modeled”) | Typically **no finding**; optional **warning** |

Do **not** add `status: error` on findings.

## Context Object (Implementation)

The `scan(..., context)` context should provide, without coupling modules to CLI:

- Logger
- Abort/cancellation or timeout awareness aligned with `max_scan_duration_seconds`
- Read-only view of effective limits and policies needed for safe scanning
- Paths or handles for temporary storage if specified by implementation

Exact fields are implementation-defined but should not break the “no direct CLI/output” rule.

## Testing Expectations

- Unit tests: validate_target edge cases; normalized finding shape from representative rules/checks.
- Integration tests: plugin registration, combined runs, partial failure, exit codes.
