# Unified AppSec Platform
### CLI-first modular application security platform (solo engineering project)

## Elevator Pitch
This repository implements a unified, plugin-based AppSec scanner focused on clean architecture and practical security engineering tradeoffs.  
It provides a shared core (config, orchestration, normalized schema, suppression, policy-based exit behavior) with four implemented modules: Python SAST, HTTP/API-first DAST, Python SCA, and Terraform IaC.  
The project is intentionally CLI-first and file-based: no dashboard, no database, no SaaS control plane.  
Its value is in the design quality of the platform boundaries and the implementation discipline around deterministic output, typed contracts, and test coverage.

## Key Highlights
- Plugin-based architecture with stable module contracts (`AppSecPlugin` + `ModuleScanResult`)
- Unified normalized finding schema across code, HTTP, dependency, and resource findings
- Explicit separation between findings and scan/module errors in aggregate output
- Policy-aware suppression system with documented precedence and attribution behavior
- Deterministic export behavior (stable fingerprinting and finding sort order)
- CLI-first workflow with profile/config/flag precedence and machine-readable JSON output
- Implemented modules: Python SAST, HTTP DAST, Python SCA, Terraform IaC

## Why This Project Exists
I built this as a systems-oriented AppSec engineering project: not to maximize scanner breadth, but to demonstrate strong platform design, module boundaries, and implementation rigor.  
It is meant to exercise core security tooling skills end-to-end: static and dynamic analysis concepts, typed schemas, plugin contracts, suppression semantics, export stability, and testing discipline.

## What It Does

### Core Platform
- Provides the `appsec` CLI entrypoint and scan command orchestration
- Loads and resolves config with precedence: profile defaults -> config file -> CLI flags
- Plans module execution, enforces limits/timeouts, aggregates `ModuleScanResult`
- Normalizes findings, applies suppressions, computes exit status, and writes JSON output

### SAST (implemented)
- Python AST-based static analysis with bounded intrafile taint propagation
- Rule pack includes command injection, eval/exec injection, SQL injection, path traversal, weak crypto/hash families
- Emits code findings with trace/evidence when available

### DAST (implemented)
- HTTP/API-first dynamic scanner with explicit discovery and audit phases
- Supports start URL, optional OpenAPI input, endpoint seeds, passive and active checks
- Includes scoped crawling behavior, rate limiting, and structured HTTP evidence

### SCA (implemented, constrained)
- Python dependency scanning for `requirements.txt`, `poetry.lock`, and `Pipfile.lock`
- Parses package coordinates and matches against advisory data
- Emits normalized dependency findings (`location_type=dependency`)

### IaC (implemented, constrained)
- Terraform static misconfiguration scanning for `.tf` files
- Rule-driven checks over parsed Terraform resources
- Emits normalized resource findings (`location_type=resource`)

## Architecture Overview
The platform is organized as a core orchestration engine plus independent scan plugins.

- **CLI-first orchestration:** `appsec scan ...` resolves config, target, and module plan
- **Plugin/module model:** modules implement a shared interface and return `ModuleScanResult`
- **Normalized findings:** every module maps its output into one shared finding schema
- **Separate error channels:** module/scan errors are captured separately from findings
- **Typed extension objects:** module-specific detail fields remain nested (e.g., `sast_evidence`, `dast_evidence`, `sca_details`, `iac_details`)

```text
CLI (appsec scan)
   |
   v
Config resolution (profiles -> file -> CLI)
   |
   v
Planner + Plugin Registry
   |
   +--> python_sast ----\
   +--> http_dast -------+--> AggregateScanResult -> suppressions -> export JSON -> exit code
   +--> python_sca ------/
   +--> terraform_iac ---/
```

## Example Workflow
1. User provides target and options (CLI args and/or config file)  
2. Core resolves effective config and selected modules  
3. Each selected plugin validates target and runs scan logic  
4. Plugins return `ModuleScanResult` (findings + warnings/errors + metrics)  
5. Core normalizes/sorts findings and applies suppression rules  
6. Core evaluates fail thresholds (`severity`, `confidence`, suppression status)  
7. Core writes aggregate JSON output and returns deterministic exit code

## Current Scope

### In Scope (implemented now)
- CLI-driven local/repo scans
- Core orchestration, suppression, policy-based exit behavior
- Python SAST + HTTP DAST + Python SCA + Terraform IaC modules
- JSON machine-readable output with aggregate envelope and per-module summaries
- Unit and integration tests for core/module behavior

### Intentionally Out of Scope
- Dashboard/web UI
- Database persistence
- Multi-user accounts/RBAC
- SaaS/multi-tenant deployment model
- Full browser automation / deep SPA DAST behavior
- IAST runtime instrumentation (explicitly deferred)
- Broad multi-ecosystem SCA or multi-format IaC parity

## Repo Structure
```text
apps/
  cli/                  # CLI entrypoint and command parsing
core/
  config/               # typed config models + loader/merge
  findings/             # normalized finding models + fingerprinting
  orchestration/        # planner, runner, exit code, aggregate results
  plugins/              # plugin contract, registry, built-in registration
  policy/               # suppression matching/precedence
  exports/              # JSON export, redaction, evidence limits
modules/
  sast/                 # Python AST SAST engine + rules
  dast/                 # HTTP/API DAST discovery + checks + audit
  sca/                  # Python dependency SCA
  iac/                  # Terraform IaC scanner
docs/
  master_spec.md        # authoritative architecture/spec document
samples/                # runnable vulnerable/safe sample targets + outputs
tests/
  unit/                 # unit tests across core and modules
  integration/          # end-to-end scan integration tests
```

## Running the Project

### Prerequisites
- Python 3.11+
- `pip` and virtual environment support

### Setup
```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -e ".[dev]"
```

### CLI Basics
```bash
# show help
appsec --help
appsec scan --help

# run SAST only against a local path
appsec scan samples/sast/python_sql_injection --sast --format json --output out/sast.json

# run DAST only against a running local app
appsec scan http://127.0.0.1:5101 --dast --format json --output out/dast.json

# run all built-in modules against a path + DAST URL via config/flags
appsec scan . --all --target-url http://127.0.0.1:5101 --format json --output out/all.json

# run with config file overrides
appsec scan . --config examples/sample_config.yaml --output out/config-run.json
```

### Using Provided Samples
```bash
# run the sample harness (creates timestamped outputs under samples/output/)
python samples/run_all_samples.py
```

## Example Output
Small representative JSON (shape matches the current aggregate output format):

```json
{
  "scan_result_schema_version": "1.0.0",
  "findings": [
    {
      "schema_version": "1",
      "finding_id": "d86445b3-8def-449c-9b62-184f5ccdb67f",
      "fingerprint": "fp1:2f124871ced11b2275aeb950b8f167bbc9524aecbf4a91ab8748ae06c2c083cb",
      "engine": "sast",
      "module": "python_sast",
      "rule_id": "sast.python.command_injection.os_system",
      "severity": "high",
      "confidence": "medium",
      "location_type": "code",
      "evidence_type": "code_trace",
      "status": "open",
      "suppressed": false
    }
  ],
  "module_results": [
    {
      "module": "python_sast",
      "warnings": [],
      "errors": [],
      "metrics": {
        "duration_ms": 8.27,
        "files_analyzed": 1
      }
    }
  ]
}
```

Notes:
- Scan/module errors are intentionally **separate from findings** (`module_results[].errors` and optional top-level `scan_errors`)
- If no scan-level errors occur, `scan_errors` may be omitted in exported JSON

## Technical Design Choices
- **Plugin architecture:** core platform is module-agnostic; scanning engines are independent plugins
- **Normalized schema:** one finding contract supports multiple engines and location types
- **Findings vs errors separation:** avoids overloading finding status with runtime failures
- **Deterministic exports:** stable fingerprint algorithm and deterministic finding ordering
- **Suppression precedence:** fingerprint > exact location/dependency/resource > endpoint > path glob
- **Config precedence discipline:** profile defaults -> config file -> CLI flags

## Testing / Validation
- Unit tests cover config merging, fingerprints, suppression behavior, module logic, CLI flags, and export semantics
- Integration tests validate end-to-end execution, aggregate envelope shape, deterministic ordering, and combined multi-module runs
- Sample apps/fixtures under `samples/` and `modules/*/fixtures` exercise vulnerable and safe paths

Run tests:
```bash
pytest
```

## Limitations
- SAST is intentionally bounded (not whole-program, not full interfile flow modeling)
- DAST focuses on HTTP/API workflows and does not claim full browser/SPA coverage
- SCA scope is Python-only and manifest/lockfile-first
- IaC scope is Terraform `.tf` static checks only
- SARIF support is currently a placeholder/stub in the export layer

## Roadmap
This repository currently includes the intended v2-additive modules (SCA and IaC) within constrained scope.  
There is no commitment to a full v3 implementation; future work is optional and may include selective depth improvements (rule coverage, evidence quality, or additional test fixtures) while preserving the existing core contracts.

## Resume-Style Project Summary
- Designed and implemented a modular AppSec scanning platform with plugin contracts and typed result models.
- Built four integrated scanning modules (Python SAST, HTTP DAST, Python SCA, Terraform IaC) on a shared orchestration core.
- Implemented deterministic finding fingerprinting/sorting, suppression precedence, and policy-based CI-friendly exit behavior.
- Delivered machine-readable aggregate outputs with explicit findings-vs-errors separation and structured evidence.
- Added unit/integration test coverage across config, orchestration, modules, and combined scan workflows.

## Skills / Technologies Used
- Python 3, `argparse`, `pathlib`, `concurrent.futures`
- Pydantic (typed config/findings/contracts), PyYAML (config/rules parsing)
- AST-based static analysis techniques (taint-style flow modeling)
- HTTP/API dynamic scanning patterns (discovery, passive/active checks, rate limiting)
- Dependency and IaC parsing/evaluation (Python manifests, Terraform `.tf`)
- Pytest unit/integration testing, deterministic machine-readable JSON exports

## Closing
For implementation details, start with `docs/master_spec.md`, then inspect `core/`, `modules/`, and `samples/` side by side with `appsec scan --help`.  
This project is intentionally scoped for architectural clarity and technical credibility over feature inflation.
