# Implementation Plan (V1 with V2 Additions)

This plan follows `master_spec.md` Section 17 and the must-have list in Section 19. It preserves the existing V1 implementation and extends it additively for V2 (SCA and IaC). V1 phases and guarantees remain unchanged; V2 work builds **on top** of the current platform.

---

## Phase 1 — Core Platform (V1 – complete, keep stable)

**Objective (V1):** Runnable CLI, config, orchestration skeleton, and export pipeline without real analysis.

The current repository already implements this phase:

1. **Project scaffold** — Layout under `apps/cli`, `core`, `modules`, `schemas`, `tests` matches the recommended structure.
2. **Typed models** — Core finding model and `ModuleScanResult` are implemented in `core/findings/models.py`; aggregate envelope (`scan_result_schema_version`, `findings`, `module_results`, optional `scan_errors`) is modeled in `core/orchestration/results.py`.
3. **Config** — `core/config/loader.py` and `core/config/models.py` implement versioned configs, merging profile → file → CLI as required, and expose `limits` (including `max_response_body_bytes`) and `policies`.
4. **Plugin registry** — `core/plugins/registry.py` and `core/plugins/base.py` define and register plugins by name, with `supported_target_types` / `supported_profiles`, and `validate_target` / `scan`.
5. **Orchestration** — `core/orchestration/runner.py` selects modules via the planner, enforces per-module timeouts and limits, and handles partial failure (record errors, still export safe findings).
6. **Fingerprints** — Implemented in `core/findings/fingerprints.py` according to §9.11 (`fp1:` + SHA-256) and used across the platform.
7. **Suppressions** — Implemented in `core/policy/suppression.py` with V1 precedence and attribution; they never suppress scan errors.
8. **Export** — JSON writer and SARIF writer live under `core/exports`; JSON uses the aggregate envelope and deterministic finding order; redaction and evidence limits are enforced.
9. **Exit codes** — Implemented by `core/orchestration/exit_code.py` with 0/1/2 semantics and default “any failure → 2”.
10. **Logging** — `core/logging/setup.py` provides structured logging with per-module loggers.

**Plan for V2:** Do not change core behavior. Only extend models and schema minimally to support SCA/IaC typed extensions and config sections, in lockstep with the spec.

---

## Phase 2 — SAST Module (V1 – complete, keep stable)

**Objective (V1):** Real Python AST pipeline with bounded intrafile taint and required rule families.

The current SAST implementation in `modules/sast` already follows the spec:

1. **File discovery** — `modules/sast/files/collector.py` respects include/exclude; validation ensures at least one `.py`.
2. **Parse and symbol map** — `modules/sast/parser/parse.py` and `modules/sast/symbols/map.py` build per-file ASTs and symbol maps.
3. **Taint engine** — `modules/sast/analyzer/engine.py` and `taint.py` implement bounded intrafile taint using rule definitions.
4. **Trace builder** — `modules/sast/traces/builder.py` builds ordered traces with V1 `TraceKind` values.
5. **Rule packs** — `modules/sast/rules/v1_baseline.yaml` and the loader provide rule families (command injection, eval/exec, SQLi, path traversal, weak crypto/hash).
6. **Normalization** — `modules/sast/findings/mapper.py` maps internal results to the normalized finding schema with code locations and SAST evidence.
7. **Fixtures** — Under `modules/sast/fixtures` and `samples/sast`, with corresponding tests in `tests/unit/test_sast_*`.

**Exit criterion (V1):** Already met. For V2, SAST should only receive incremental rule and fixture improvements; the architectural surface and guarantees must stay the same.

---

## Phase 3 — DAST Module (V1 – complete, keep stable)

**Objective (V1):** HTTP/API-first scanner with explicit discovery/audit split.

The current DAST implementation in `modules/dast` already follows the spec:

1. **Targeting** — `modules/dast/targeting/models.py` and helpers build DAST target configs from `target_url`, optional OpenAPI, and endpoint seeds.
2. **Discovery** — `modules/dast/discovery/engine.py` plus `crawl.py` and `openapi.py` enumerate endpoints and parameters from OpenAPI + seeds + start URL, with optional shallow same-origin HTML crawl (no JS).
3. **Audit** — `modules/dast/audit/engine.py` runs passive and active checks (`modules/dast/checks/*`) with baseline comparisons where appropriate.
4. **Auth** — `modules/dast/auth/session.py` supports static headers, bearer tokens, and cookies; reauth hooks are placeholders with clearly limited scope.
5. **HTTP client** — `modules/dast/http/client.py` and `rate_limit.py` implement timeouts, rate limits, evidence size bounds, and scope checks.
6. **Normalization** — `modules/dast/findings/mapper.py` maps raw DAST results to normalized findings with HTTP locations and evidence.
7. **Fixtures** — Under `samples/dast` and DAST unit tests.

**Exit criterion (V1):** Already met. V2 must not expand DAST scope beyond what the spec allows or change its contracts.

---

## Phase 4 — Integration and Hardening (V1 – mostly complete)

**Objective (V1):** Cohesive platform behavior across modules with deterministic outputs.

1. **Combined runs** — Integration tests under `tests/integration` verify combined SAST+DAST runs, partial failure handling, and exit codes.
2. **SARIF** — `core/exports/sarif_writer.py` maps SAST findings into SARIF as a should-have; it must remain optional and in sync with the finding model.
3. **Docs and schemas** — This doc set, plus `schemas/finding.schema.json`, `config.schema.json`, and `scan_result.schema.json`, should remain aligned with the implementation.
4. **Performance guardrails** — Profile tuning and limits are in place; further tuning is incremental.

**Exit criterion (V1):** Integration tests and schema alignment are in place; future changes must preserve these guarantees.

---

## Phase 5 — SCA Module (V2 additive)

**Objective:** Add a narrow Python-only SCA module that plugs into the existing platform without changing any core contracts.

Recommended steps:

1. **Data model updates (minimal)**  
   - Extend the finding model and JSON schema to support:
     - `location_type="dependency"` (already reserved).
     - Optional `sca_details` extension object, as defined in the master spec.
   - Keep fingerprint material **unchanged** (do not include `sca_details` in fingerprint inputs).

2. **Module scaffold**  
   - Create `modules/sca` with:
     - `plugin.py` implementing `AppSecPlugin` with `engine="sca"` and `supported_target_types=("path",)`.
     - Internal helpers for manifest discovery, parsing, and advisory matching.
   - Register the plugin via the existing plugin registry.

3. **Manifest discovery**  
   - Reuse SAST-style target resolution (filesystem root).
   - Search under scan root for:
     - `requirements.txt`
     - `poetry.lock`
     - `Pipfile.lock`
   - Respect optional `scan.include_paths` / `scan.exclude_paths` and `sca.include_manifests` / `exclude_manifests` when present.

4. **Parsing and normalization**  
   - Implement minimal parsers for the three supported file types.
   - Normalize results into package coordinates (ecosystem, package, version, dependency path).

5. **Advisory lookup**  
   - Implement a simple advisory lookup mechanism (e.g. static bundled data file).
   - Match on ecosystem + package + version.
   - Emit normalized findings with:
     - `engine="sca"`, `location_type="dependency"`, `evidence_type="metadata_only"`.
     - Optional `sca_details` per spec.

6. **ModuleScanResult integration**  
   - Return findings, structured warnings (e.g. unsupported file formats), and structured errors (e.g. manifest parse errors) via `ModuleScanResult`.
   - Populate SCA metrics: `manifests_scanned`, `packages_evaluated`, `advisories_matched`.

7. **Tests and fixtures**  
   - Add unit tests for:
     - Manifest discovery.
     - Parsing.
     - Advisory matching.
     - Finding normalization (`location_type`, `sca_details`, evidence expectations).
   - Add integration tests verifying:
     - Combined SAST+SCA and DAST+SCA runs.
     - Suppression behavior for dependency findings (including rule+dependency-coordinate shapes).

**Shippable stopping point:** A working SCA module, with tests and fixtures, integrated into the existing CLI, config, and output flow, but without IaC yet.

---

## Phase 6 — IaC Module (V2 additive, after SCA)

**Objective:** Add a narrow Terraform-only IaC module that plugs into the existing platform without changing any core contracts.

Recommended steps:

1. **Data model updates (minimal)**  
   - Extend the finding model and JSON schema to support:
     - `location_type="resource"` (already reserved).
     - Optional `iac_details` extension object, as defined in the master spec.
   - Keep fingerprint material **unchanged** (do not include `iac_details` in fingerprint inputs).

2. **Module scaffold**  
   - Create `modules/iac` with:
     - `plugin.py` implementing `AppSecPlugin` with `engine="iac"` and `supported_target_types=("path",)`.
     - Internal helpers for Terraform file discovery, parsing, and rule evaluation.
   - Register the plugin via the existing plugin registry.

3. **File discovery**  
   - Reuse SAST-style target resolution (filesystem root).
   - Search under scan root for `.tf` files.
   - Respect optional `iac.include_paths` / `exclude_paths` and `scan.include_paths` / `exclude_paths`.

4. **Parsing and rule evaluation**  
   - Implement a minimal Terraform parser or structured reader suited to the V2 check set (no state/plan support).
   - Define a small, rule-driven check set targeting misconfigurations that can be reliably detected from static `.tf` (e.g. public S3 buckets, missing encryption flags).

5. **Normalization**  
   - Emit normalized findings with:
     - `engine="iac"`, `location_type="resource"`, `evidence_type="metadata_only"`.
     - `iac_details` fields for provider, resource type, resource address, and check ID.

6. **ModuleScanResult integration**  
   - Return findings, warnings (e.g. unparseable files), and errors (e.g. fatal parse failures) via `ModuleScanResult`.
   - Populate IaC metrics: `files_scanned`, `resources_evaluated`, `checks_executed`.

7. **Tests and fixtures**  
   - Add fixtures with minimal Terraform examples (safe/unsafe).
   - Add unit tests for:
     - File discovery.
     - Parsing.
     - Rule evaluation.
     - Finding normalization and `iac_details`.
   - Add integration tests verifying:
     - Combined SAST+IaC and DAST+IaC runs.
     - Suppression behavior for resource-address shapes.

**Note:** SCA should generally be implemented **before** IaC to leverage existing filesystem and normalization patterns and because SCA is structurally closer to SAST’s file-based workflow.

---

## Phase 7 — Cross-Module Integration and Guardrails (V2)

**Objective:** Ensure SCA and IaC are first-class modules without regressing V1.

1. **Module selection and planning**  
   - Update the planner to recognize SCA and IaC module names without changing existing SAST/DAST behavior.
   - Add tests for combinations:
     - SAST + DAST + SCA
     - SAST + IaC
     - All four modules, with partial module failures.

2. **Config schemas**  
   - Extend `config.schema.json` with `sca` and `iac` sections that match the V2 doc, but keep existing keys unchanged.

3. **Finding schemas**  
   - Extend `finding.schema.json` and `scan_result.schema.json` with:
     - Dependency and resource location shapes.
     - `sca_details` and `iac_details` optional objects.
   - Ensure no new required fields are added at the top level.

4. **Suppression behavior**  
   - Implement the additional suppression match shapes for dependency coordinates and resource addresses.
   - Add tests verifying that precedence and attribution behavior remain unchanged for existing SAST/DAST suppressions.

5. **Exit-code regression tests**  
   - Add tests showing:
     - SCA or IaC findings alone can trigger exit code 1 under policies.
     - Any module failure still results in exit code 2.
     - Mixed-module behavior remains consistent with V1.

6. **Documentation synchronization**  
   - Keep this document and the other docs (`architecture.md`, `findings_schema.md`, `config_reference.md`, `module_contracts.md`) synchronized with the master spec and code.

---

## Dependency Order (strict, extended for V2)

```text
Core (models, config, registry, orchestration, export)
  → SAST plugin
  → DAST plugin
  → SCA plugin (V2)
  → IaC plugin (V2)
  → Integration tests (all-module combinations)
```

SCA should be implemented **before** IaC unless the codebase evolves in a way that makes IaC obviously simpler to integrate first. As of the current codebase, SCA is the more natural first V2 module.

---

## Out of Scope Reminders (V1 and V2)

Do not implement in V1 or V2:

- Dashboard or web UI.
- Database persistence.
- User accounts or RBAC.
- Distributed scanning or multi-tenant SaaS deployment.
- Full SPA/browser automation or arbitrary JavaScript execution in DAST.
- Blind/OAST infrastructure.
- Full SCA or IaC coverage beyond the constrained V2 scope.
- IAST runtime behavior (deferred to V3).
- Historical analytics or enterprise-scale deduplication beyond fingerprinting.

---

## Top 10 Implementation Risks (V2)

1. **Accidental changes to V1 contracts** (fingerprints, exit codes, suppression precedence, aggregate envelope shape).
2. **Schema/model drift** between `master_spec.md`, docs, Pydantic models, and JSON schemas.
3. **Overly broad SCA scope** (adding ecosystems or reachability analysis without updating the spec).
4. **Overly broad IaC scope** (adding non-Terraform formats or live cloud calls).
5. **Misuse of findings for errors**, reintroducing implicit `status: error` semantics.
6. **Breaking determinism** in finding order, fingerprints, or output structure.
7. **Insufficient limits enforcement** for new modules (missing duration, findings-per-module, or evidence limits).
8. **Inconsistent suppression behavior** for dependency/resource findings versus code/HTTP findings.
9. **Undertested module combinations** leading to surprising behavior when all four modules run together.
10. **Under-documented extensions**, making it easy for future work to drift from the spec or duplicate architecture concepts.

---

## Top 10 Things to Avoid During V2 Coding

1. Changing or “simplifying” any frozen V1 contract (plugin interface, findings schema, exit codes, suppression rules).
2. Adding new required top-level finding fields for SCA or IaC (use typed extensions instead).
3. Modifying fingerprint inputs to include new module-specific data.
4. Introducing new exit codes or changing the meaning of 0/1/2.
5. Broadening SCA beyond the three specified Python manifest/lockfile types.
6. Broadening IaC beyond Terraform `.tf` files or adding live cloud validation.
7. Encoding module errors as findings, or adding `status: error` anywhere.
8. Adding implicit module-selection behavior that conflicts with existing planner logic.
9. Interweaving module-specific logic into the core orchestration or CLI layers.
10. Changing suppression precedence or attribution behavior to accommodate new match shapes.

---

## Top 10 Ways V1 Could Accidentally Be Regressed in V2

1. **Altering `Finding` fields or enums** (e.g. adding a new `status` value or changing allowed severities/confidences).
2. **Changing fingerprint generation** (inputs, algorithm, or prefix), breaking existing suppressions and deduplication.
3. **Altering exit-code logic** in `compute_exit_code` (e.g. ignoring module errors or changing thresholds).
4. **Modifying suppression logic** such that SAST/DAST suppressions behave differently than before.
5. **Breaking SAST analysis boundaries** by changing intrafile assumptions or removing existing rule coverage.
6. **Breaking DAST boundaries** by silently enabling cross-origin crawling or JavaScript execution.
7. **Changing the aggregate JSON envelope** (removing or renaming `scan_result_schema_version`, `findings`, or `module_results`).
8. **Renaming or repurposing module names** (`SAST_MODULE_NAME`, `DAST_MODULE_NAME`), breaking compatibility with existing configs and tests.
9. **Altering config precedence** (e.g. having CLI or module sections override profiles in new ways).
10. **Introducing undocumented side effects** (e.g. writing extra files, network calls outside DAST, or unstable ordering in exports).


