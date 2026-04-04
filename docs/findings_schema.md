# Findings Schema

This document describes the normalized finding model required by the Unified AppSec Platform V1. It restates [master_spec.md](./master_spec.md) Section 9; the master spec is authoritative.

## Purpose

- Single contract for all scan modules now and future extensions (SCA, IaC, IAST).
- V1 **actively uses** code findings (SAST) and HTTP findings (DAST).
- Dependency and infrastructure shapes are reserved for future modules; fields may appear when those modules exist.

## Top-Level Finding Object

### Required Core Fields

Every emitted finding **must** include:

| Field | Description |
|--------|-------------|
| `schema_version` | Version of the finding schema document. |
| `finding_id` | Unique identifier for this emitted finding instance. |
| `fingerprint` | Stable id for near-duplicate matching; normative `fp1:` algorithm in master spec §9.11. |
| `engine` | Scanner family (e.g. `sast`, `dast`). |
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

### Optional Top-Level Fields

May be present when useful:

- `description`, `subcategory`, `remediation`, `references`, `tags`
- `suppression_reason` (when suppressed)
- `correlation` (structured object; reserved keys per spec)
- `metadata` (generic bag; avoid duplicating typed extension data)

Do **not** widen V1 beyond what the spec requires: optional fields above are those listed in the master spec. Do not add enterprise-only or dashboard-specific fields without a spec update.

## Typed Location Objects

A finding may attach one or more location objects according to `location_type`.

### Code location (V1 SAST)

- `file_path`, `start_line`, `end_line`, `start_col`, `end_col`, `function_name`

### HTTP location (V1 DAST)

- `url`, `method`, `parameter`, `endpoint_signature`

### Dependency location (future SCA)

- `ecosystem`, `package_name`, `package_version`, `dependency_path`

### Resource location (future IaC)

- `resource_type`, `resource_id`, `resource_path`, `provider`

## Typed Evidence Objects

Evidence should be structured, not only free text. Use the extension object that matches `evidence_type` and finding class.

### SAST-oriented evidence (non-exhaustive)

- `code_snippet`, `matched_sink`, `matched_source`, `sanitizer_summary`, `trace_summary`

### DAST-oriented evidence (non-exhaustive)

- `request_summary`, `response_summary`, `matched_payload`, `observed_behavior`, `response_markers`, `baseline_comparison`

Low-context heuristics may use `metadata_only` with structured metadata rather than a full trace.

## Trace Model (Ordered Steps)

For taint-style and future IAST-style findings, traces are ordered steps:

| Field | Purpose |
|--------|---------|
| `step_index` | Order within the trace |
| `kind` | `source`, `propagation`, `sanitizer`, `sink`, `call`, `return` (V1 set per spec) |
| `label` | Human-readable step label |
| `file_path`, `line`, `column` | Location when applicable |
| `symbol` | Symbol name when applicable |
| `note` | Free-form clarifier |

Future modules may extend trace semantics; consumers should tolerate unknown `kind` values gracefully if introduced later.

## Correlation Object

Reserved for cross-module or future unified analysis. V1 may populate subsets of:

- `route`, `sink_type`, `source_type`, `parameter_name`, `function_name`, `file_path`, `cwe`, `host`, `endpoint`

## Scan Errors Are Not Findings

Configuration failures, network errors, module exceptions, and unsupported targets belong in **scan result** or **module result** error structures—not as findings and **not** as `status: error` on a finding.

## Module Scan Result and Aggregate JSON (Non-Finding Envelope)

Per master spec §9.10:

- Each plugin returns a **ModuleScanResult**: `findings`, `warnings`, `errors`, `metrics`.
- **Warning and error entries** are objects with at least `code`, `message`, and optional `details` (unknown keys ignored by consumers).
- **Metrics** may include `duration_ms`, and when applicable `files_analyzed` (SAST) or `requests_sent` (DAST); extra keys are allowed and ignored if unknown.
- The exported scan document includes `scan_result_schema_version`, a single aggregated `findings` array (after suppression), and `module_results` (per-module warnings, errors, metrics only—no duplicate finding lists per module).

## Export Semantics

- JSON: complete for emitted findings; top-level envelope and `module_results` per §9.10.3; `findings` array sorted by `fingerprint` then `finding_id` (§9.12).
- Evidence: subject to size limits and redaction rules (headers, cookies, tokens, truncation).

## Alignment with JSON Schema

`schemas/finding.schema.json` and `schemas/scan_result.schema.json` (per repository layout) should match runtime models; any drift is a bug unless the master spec is updated.
