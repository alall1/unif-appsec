# SCA module (v2) — internal design note

This document is module-internal guidance. `docs/master_spec.md` remains the source of truth.

## Inventory extraction

- **Discovery**: search under `ScanContext.scan_root` for the fixed v2 baseline files:
  - `requirements.txt`
  - `poetry.lock`
  - `Pipfile.lock`
- **Path filtering**: apply `scan.include_paths` / `scan.exclude_paths`, then optional `sca.include_manifests` / `sca.exclude_manifests` (if present in module config).
- **Parsers (deterministic, minimal)**:
  - `requirements.txt`: only `name==version` lines are supported; other line shapes are ignored with warnings.
  - `poetry.lock`: parsed as TOML via stdlib `tomllib`; reads `[[package]]` entries (`name`, `version`).
  - `Pipfile.lock`: parsed as JSON; reads `default` and `develop` package maps and strips leading `==` from versions.
- **Output**: a sorted list of `(ecosystem, package_name, package_version, source_file)` coordinates.

## Advisory matching

- Advisory dataset is a local JSON file with entries keyed by:
  - `ecosystem`, `package_name`, `advisory_id`, `advisory_source`
  - `vulnerable_specifiers` (PEP 440 specifiers)
  - `fixed_versions`
- Matching steps:
  - Filter advisories by `(ecosystem, canonicalized package_name)`.
  - Evaluate the extracted version against each advisory’s `vulnerable_specifiers` using `packaging.specifiers.SpecifierSet`.
  - For each match, emit one finding.

## `sca_details` representation

SCA findings populate the typed extension object `sca_details` with the minimum required keys:
- `ecosystem`
- `package_name`
- `package_version`
- `advisory_id`
- `advisory_source`

Additional optional keys may be present:
- `advisory_url`
- `fixed_versions`
- `cvss` (string in v2)
- `cwe_ids`
- `dependency_scope` (not currently populated in v2 slice)

## Evidence representation

SCA findings use `evidence_type="metadata_only"` and populate `sca_evidence` with structured triage fields:
- `source_file`
- `package_identifier` (`ecosystem:package@version`)
- `advisory_id`
- `advisory_source`
- `fixed_versions`
- `dependency_path` (not currently populated in v2 slice)

## Supported vs not supported (v2 slice)

Supported:
- Python ecosystem only (`ecosystem="pypi"`).
- Inputs: `requirements.txt`, `poetry.lock`, `Pipfile.lock`.
- Version-based matching against a **local** advisory dataset.

Not supported:
- Reachability or exploitability analysis.
- Malicious package / reputation detection.
- VCS/URL/editable requirements in `requirements.txt`.
- Container/image scanning.
- Multi-ecosystem scanning promises.

## How suppressions apply

- Suppressions are applied by the core after SCA findings are normalized and fingerprinted.
- In addition to v1 suppression match shapes, v2 supports **rule + dependency coordinate** matches:
  - `rule_id` + `ecosystem` + `package_name` + `package_version`
- Fingerprinting continues to follow the v1 canonical material and does **not** include `sca_details` or `sca_evidence`.

