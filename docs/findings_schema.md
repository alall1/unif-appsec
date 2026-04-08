# Findings Schema

This document describes the normalized finding model required by the Unified AppSec Platform. It restates `master_spec.md` Section 9; the master spec is authoritative.

- **V1 behavior** in this document is **normative** and must remain intact.
- **V2 additions** (SCA and IaC) are called out explicitly and must be **additive**, not widening the schema beyond what the master spec requires.

---

## Purpose (unchanged from V1)

- **Single contract** for all scan modules (SAST, DAST, and future SCA, IaC, IAST).
- V1 **actively uses**:
  - **Code findings** for SAST.
  - **HTTP findings** for DAST.
- Dependency and infrastructure shapes are reserved in the schema for SCA and IaC.

---

## Top-Level Finding Object

### Required Core Fields (unchanged from V1)

Every emitted finding **must** include:

| Field | Description |
|--------|-------------|
| `schema_version` | Version of the finding schema document. |
| `finding_id` | Unique identifier for this emitted finding instance. |
| `fingerprint` | Stable id for near-duplicate matching; normative `fp1:` algorithm in master spec §9.11. |
| `engine` | Scanner family (`sast`, `dast`, `sca`, `iac`, or future `iast`). |
| `module` | Concrete module name (e.g. `python_sast`, `http_dast`). |
| `rule_id` | Stable rule or check identifier. |
| `title` | Short human-readable title. |
| `severity` | One of: `info`, `low`, `medium`, `high`, `critical`. |
| `confidence` | One of: `low`, `medium`, `high`. |
| `category` | Top-level category for the issue class. |
| `status` | One of: `open`, `suppressed` only (**not** `error`; scan failures are not findings). |
| `location_type` | One of: `code`, `http`, `dependency`, `resource`. |
| `evidence_type` | One of: `code_trace`, `code_match`, `http_exchange`, `metadata_only`. |
| `created_at` | RFC 3339 timestamp in UTC with `Z` offset (e.g. `2026-04-03T12:00:00Z`). |
| `suppressed` | Boolean; whether a suppression rule applies (see also `status`). |

### Optional Top-Level Fields (unchanged from V1)

May be present when useful:

- `description`, `subcategory`, `remediation`, `references`, `tags`
- `suppression_reason` (when suppressed)
- `correlation` (structured object; reserved keys per spec)
- `metadata` (generic bag; avoid duplicating typed extension data)

Do **not** widen beyond what the spec requires. Do not add dashboard-, database-, or SaaS-specific fields without a spec change.

---

## Typed Location Objects

A finding may attach one or more location objects according to `location_type`.

### Code location (V1 SAST – unchanged)

- `file_path`, `start_line`, `end_line`, `start_col`, `end_col`, `function_name`

### HTTP location (V1 DAST – unchanged)

- `url`, `method`, `parameter`, `endpoint_signature`

### Dependency location (SCA – reserved in V1, activated in V2)

- `ecosystem`
- `package_name`
- `package_version`
- `dependency_path`

V2 SCA findings **must** use `location_type="dependency"` and populate a dependency location when available.

### Resource location (IaC – reserved in V1, activated in V2)

- `resource_type`
- `resource_id`
- `resource_path`
- `provider`

V2 IaC findings **must** use `location_type="resource"` and populate a resource location when available.

---

## Typed Evidence Objects

Evidence should be structured, not only free text. Use the typed objects that match `evidence_type` and finding class.

### SAST-oriented evidence (V1 – unchanged)

- `code_snippet`
- `matched_sink`
- `matched_source`
- `sanitizer_summary`
- `trace_summary`

SAST findings typically use:
- `location_type="code"`
- `evidence_type="code_trace"` (for taint flows with trace) or `code_match`/`metadata_only` as appropriate.

### DAST-oriented evidence (V1 – unchanged)

- `request_summary`
- `response_summary`
- `matched_payload`
- `observed_behavior`
- `response_markers`
- `baseline_comparison`

DAST findings typically use:
- `location_type="http"`
- `evidence_type="http_exchange"` or `metadata_only`, depending on check behavior and evidence limits.

### SCA evidence (V2 additive)

Per master spec §9.6 and §20.1:

- **Evidence expectations** (minimum for each SCA finding):
  - `source_file` (manifest/lockfile path)
  - `package_identifier` (ecosystem + package + version)
  - `advisory_id` and `advisory_source`
  - `fixed_versions` when known

- **Typical evidence fields** (within an SCA evidence object or inside `sca_details`):
  - `source_file`
  - `package_identifier`
  - `advisory_id`
  - `advisory_source`
  - `fixed_versions`
  - `dependency_path` (when derived from lockfile)

SCA findings typically use:
- `engine="sca"`
- `location_type="dependency"`
- `evidence_type="metadata_only"` unless a richer shape is added by spec.

### IaC evidence (V2 additive)

Per master spec §9.6 and §20.2:

- **Evidence expectations** (minimum for each IaC finding):
  - `config_path` and/or resource address
  - failing check/rule identifier
  - expected vs observed value (or equivalent summary)

- **Typical evidence fields** (within an IaC evidence object or inside `iac_details`):
  - `resource_type`
  - `resource_name`
  - `provider`
  - `config_path`
  - `attribute_path`
  - `expected_vs_actual`
  - `check_inputs`

IaC findings typically use:
- `engine="iac"`
- `location_type="resource"`
- `evidence_type="metadata_only"` unless a richer shape is added by spec.

Low-context heuristics across all modules may use `metadata_only` with structured metadata instead of full traces.

---

## Typed Extension Objects (V2 additive)

The schema uses **typed extension objects** for module-specific details. V1 actively uses:

- `sast_evidence` and `trace` for SAST findings.
- `dast_evidence` for DAST findings.

V2 adds **reserved typed detail objects** for new modules:

- `sca_details` for SCA-specific structured fields.
- `iac_details` for IaC-specific structured fields.

These objects are:
- **Optional** and **module-specific**.
- **Not** part of the normative fingerprint material (per master spec §20.3).
- Expected to be ignored safely by consumers that do not understand them.

### `sca_details` (V2)

When present, `sca_details` should include:

- `ecosystem`
- `package_name`
- `package_version`
- `advisory_id`
- `advisory_source`

and may include:

- `advisory_url`
- `fixed_versions`
- `cvss` (string representation only in V2)
- `cwe_ids`
- `dependency_scope` (e.g. direct/transitive)

The **minimum required when `sca_details` is present** is:
- `ecosystem`
- `package_name`
- `package_version`
- `advisory_id`
- `advisory_source`

### `iac_details` (V2)

When present, `iac_details` should include:

- `provider`
- `resource_type`
- `resource_address`
- `check_id`

and may include:

- `resource_name`
- `expected_value`
- `observed_value`
- `remediation_hint`

The **minimum required when `iac_details` is present** is:
- `provider`
- `resource_type`
- `resource_address`
- `check_id`

---

## Trace Model (Ordered Steps – unchanged from V1)

For SAST (and future IAST), traces are ordered steps:

| Field | Purpose |
|--------|---------|
| `step_index` | Order within the trace |
| `kind` | `source`, `propagation`, `sanitizer`, `sink`, `call`, `return` (V1 set per spec) |
| `label` | Human-readable step label |
| `file_path`, `line`, `column` | Location when applicable |
| `symbol` | Symbol name when applicable |
| `note` | Free-form clarifier |

Future modules may extend trace semantics; consumers should tolerate unknown `kind` values gracefully if introduced later.

---

## Correlation Object (unchanged from V1)

The optional `correlation` object is reserved for cross-module or unified analysis. V1 may populate subsets of:

- `route`
- `sink_type`
- `source_type`
- `parameter_name`
- `function_name`
- `file_path`
- `cwe`
- `host`
- `endpoint`

Future SCA and IaC modules may add correlation keys such as package coordinates or resource addresses, without changing the core schema.

---

## Scan Errors Are Not Findings (unchanged from V1)

- Configuration failures, network errors, module exceptions, and unsupported targets:
  - **Belong in** scan-level or module-level error structures.
  - **Do not** produce findings.
  - **Do not** appear as `status: error` on any finding.

The `Finding.status` field is **strictly**:
- `open` or
- `suppressed`

with a corresponding `suppressed` boolean flag and optional `suppression_reason`.

---

## Module Scan Result and Aggregate JSON (unchanged from V1)

Per master spec §9.10:

- Each plugin returns a **ModuleScanResult**:
  - `findings`
  - `warnings`
  - `errors`
  - `metrics`
- Warning and error entries are objects with at least:
  - `code`
  - `message`
  - optional `details` (unknown keys ignored).
- Metrics may include:
  - `duration_ms`
  - `files_analyzed` (SAST)
  - `requests_sent` (DAST)
  - plus additional module-specific metrics (e.g. SCA manifest counts, IaC file counts) which consumers must ignore if unknown.
- The exported scan document includes:
  - `scan_result_schema_version`
  - a single aggregated `findings` array (after suppression)
  - `module_results` (per-module warnings, errors, metrics only—no per-module finding lists)

The current implementation also includes a top-level `scan_errors` array in the aggregate document for non-module failures; this is consistent with the spec’s “scan result or module result level” language and is treated as an additive field.

---

## Export Semantics (unchanged from V1)

- **JSON**:
  - Complete for emitted findings.
  - Top-level envelope and `module_results` per §9.10.3.
  - `findings` array sorted by `fingerprint` then `finding_id` (§9.12).
- **Evidence**:
  - Subject to size limits and redaction rules (headers, cookies, tokens, truncation).
  - Must respect `max_evidence_bytes` and related limits from config.

---

## Alignment with JSON Schema (unchanged from V1)

`schemas/finding.schema.json` and `schemas/scan_result.schema.json` must match runtime models and this document. Any drift between:

- the master spec,
- these docs, and
- the Pydantic models in `core/findings/models.py`

is a bug unless the master spec is updated. When SCA and IaC modules are implemented in V2, schema and model changes must be kept in lockstep and must not alter any frozen V1 core fields or semantics.


