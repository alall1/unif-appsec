# Implementation Plan (V1)

This plan follows [master_spec.md](./master_spec.md) Section 17 and the must-have list in Section 19. It does not change scope; it orders work for a Python codebase.

## Phase 1 — Core Platform

**Objective:** Runnable CLI, config, orchestration skeleton, and export pipeline without real analysis.

1. **Project scaffold** — Match recommended repo layout (`apps/cli`, `core`, `schemas`, `tests`) as closely as practical; add `schemas/scan_result.schema.json` per spec.
2. **Typed models** — Finding core model + extension slots; `ModuleScanResult` (warnings/errors/metrics shapes in §9.10); aggregate envelope with `scan_result_schema_version`, `findings`, `module_results`.
3. **Config** — Load YAML/JSON/TOML (choice is implementation); validate against versioned schema; merge profile → full config overlay → CLI flags (§8.5); expose `limits` (including `max_response_body_bytes`) and `policies`.
4. **Plugin registry** — Register modules by name; resolve `supported_target_types`, `supported_profiles()` (empty = all profiles), invoke validate/scan.
5. **Orchestration** — Planner selects modules from flags/config; runner enforces per-module timeouts and finding/evidence limits; handles partial failure (record errors, still export safe findings).
6. **Fingerprints** — Implement §9.11 (`fp1:` + SHA-256); required on every finding; document primary-location choice for multi-location findings.
7. **Suppressions** — Post-generation application with precedence and attribution rules (§13.4); never suppress scan errors.
8. **Export** — JSON writer: envelope §9.10.3; sort findings by fingerprint then finding_id (§9.12); redaction hooks; human CLI summary (modules, target, counts, output path, exit reason, module errors).
9. **Exit codes** — Implement 0/1/2 semantics and V1 default “any failure → 2”.
10. **Logging** — Structured logs for scan/module start/end, errors, warnings, output path.

**Exit criterion:** A stub plugin returns synthetic findings and errors; CLI produces valid JSON and correct exit codes in fixture tests.

## Phase 2 — SAST Module

**Objective:** Real Python AST pipeline with bounded intrafile taint and required rule families.

1. **File discovery** — Respect include/exclude; at least one `.py` validation.
2. **Parse and symbol map** — Per-file AST; function/assignment/call graph within file per spec boundaries.
3. **Taint engine** — Sources, sinks, sanitizers, propagators from rule definitions; bounded depth (`max_taint_depth`, profile interaction).
4. **Trace builder** — Ordered steps with V1 `kind` values.
5. **Rule packs** — Command injection, eval/exec, SQLi, path traversal, weak crypto/hash (stretch: deserialization, SSRF-like).
6. **Normalization** — Map internal results to finding schema + code location + evidence/trace extensions.
7. **Fixtures** — Vulnerable, safe, and near-miss Python files; unit tests per rule family and sanitizer discrimination.

**Exit criterion:** Meets SAST acceptance criteria in master spec (fixtures, traces, stable structure, clean plugin integration).

## Phase 3 — DAST Module

**Objective:** HTTP/API-first scanner with explicit discovery/audit split.

1. **Targeting** — `target_url`, optional OpenAPI import, `endpoint_seeds` from config.
2. **Discovery** — Enumerate endpoints/parameters from OpenAPI + seeds + start URL; optional shallow same-origin HTML crawl (no JS).
3. **Audit** — Passive checks (headers, CORS, leaks, cookies, patterns); active checks with baseline comparison where spec requires (XSS/SQLi heuristics not high-confidence on substring alone).
4. **Auth** — Static headers, bearer, cookie jar; document limitations (no SSO/MFA claims).
5. **HTTP client** — Timeouts, rate limits, max body retention, scope checks (no off-host unless allowed).
6. **Normalization** — HTTP locations + `http_exchange` evidence; correlation fields when useful.
7. **Fixtures** — Mocked HTTP, replay responses; optional small local vulnerable service.

**Exit criterion:** Meets DAST acceptance criteria (end-to-end simple target, auth path, structured evidence, discovery/audit separation in code).

## Phase 4 — Integration and Hardening

1. **Combined runs** — Config with both modules; partial failure tests (one module raises, other completes).
2. **SARIF** — Minimal mapping if pursuing should-have; ensure SAST maps cleanly to SARIF concepts per spec.
3. **Docs and schemas** — Keep `finding.schema.json`, `config.schema.json`, and `scan_result.schema.json` in sync with shipped behavior.
4. **Performance guardrails** — Profile tuning for `fast` / `balanced` / `deep`.

## Dependency Order (Strict)

```
Core (models, config, registry, orchestration, export)
  → SAST plugin
  → DAST plugin
  → Integration tests
```

## Out of Scope Reminders (V1)

Do not implement: dashboard, database, RBAC, distributed scanning, multi-tenant SaaS, full SPA/browser automation, blind/OAST, arbitrary JS in DAST, full SCA/IaC/IAST, historical analytics, or cross-module enterprise deduplication beyond fingerprinting.

