# Unified AppSec Platform - Master Architecture and Specification

## 1. Project Overview

### 1.1 Project Name
Unified AppSec Platform

### 1.2 V1 Goal
Build a modular, developer-first application security platform with:
- a shared core platform
- a static analysis engine (SAST)
- a dynamic analysis engine (DAST)

The platform must be explicitly designed so that later modules can be added without changing the core architecture:
- IAST
- SCA
- IaC scanning

### 1.3 Product Positioning
This project is not a toy scanner and is not just a bundle of scripts.
It is a unified AppSec platform architecture with:
- a common orchestration layer
- a normalized findings model
- pluggable scan modules
- machine-readable outputs
- developer workflow support
- extension points for future security capabilities

V1 is intentionally limited to a credible, well-architected platform with SAST and DAST only.
It does not attempt enterprise-scale coverage.

### 1.4 Design Philosophy
The platform should feel like a real security tool:
- modular
- typed
- testable
- explainable
- extensible
- CLI-first
- honest about limitations

The priority is architectural credibility and clean design, not maximum scanner coverage.

## 2. V1 Scope

### 2.1 In Scope
V1 includes:
- core platform
- SAST module
- DAST module

### 2.2 Core Platform Responsibilities
The core platform is responsible for:
- CLI entrypoint
- config loading and validation
- scan orchestration
- plugin/module registration
- normalized findings schema
- scan result aggregation
- profile handling
- output writing
- suppression plumbing
- logging
- exit code handling
- resource and evidence limits
- future extension points for IAST, SCA, and IaC

### 2.3 SAST Responsibilities
The SAST module is responsible for:
- static analysis of Python source code
- AST-based parsing
- bounded intrafile interprocedural taint analysis
- rule-driven vulnerability detection
- taint traces from source to sink
- generation of normalized findings through the shared schema

### 2.4 DAST Responsibilities
The DAST module is responsible for:
- HTTP/API-first target scanning
- discovery phase
- audit phase
- passive checks
- active checks
- basic authenticated scanning
- structured evidence capture
- generation of normalized findings through the shared schema

## 3. Explicit Non-Goals for V1

The following are out of scope for V1:
- dashboard or web UI
- database persistence
- user accounts or RBAC
- distributed scanning
- multi-tenant SaaS deployment
- browser-heavy full SPA automation
- complex SSO/MFA handling
- multi-role authorization testing
- enterprise-scale language coverage
- production-grade full IAST agent
- full SCA implementation
- full IaC implementation
- historical trend analytics
- advanced vulnerability deduplication across large datasets
- business-logic vulnerability discovery
- blind/OAST infrastructure
- arbitrary JavaScript execution during DAST

## 4. Supported Targets in V1

### 4.1 SAST Targets
- Python repositories or directories containing Python source files

### 4.2 DAST Targets
- HTTP applications
- REST APIs
- API endpoints supplied from one or more of:
  - start URL
  - provided base URL
  - optional OpenAPI specification
  - explicit endpoint seeds from config

### 4.3 Target Validation Rules
The platform must validate targets before running scans.

SAST target validation must confirm:
- target path exists
- target path is a file or directory
- target contains at least one supported file type

DAST target validation must confirm:
- target URL is syntactically valid
- scheme is allowed by config
- redirects are handled according to config
- host and scope rules are satisfied

V1 defaults:
- same-origin only for crawl expansion
- no automatic scanning of newly discovered hosts unless explicitly allowed

## 5. Architecture Principles

### 5.1 Separation of Concerns
Core platform code must not contain SAST-specific or DAST-specific analysis logic.
Modules must not reimplement core platform responsibilities.

### 5.2 Unified Schema
All findings must conform to one normalized schema.
The schema must support code, HTTP, dependency, and infrastructure findings, but V1 only requires active support for code and HTTP findings.

### 5.3 Extensibility
The architecture must support future modules without requiring a redesign of:
- orchestration
- configuration
- output formats
- findings schema

### 5.4 Explainability
Every finding must include the best available evidence type for its finding class.

Examples:
- SAST taint findings should include a trace when available
- SAST pattern findings should include matched code evidence
- DAST findings should include request/response summaries and check-specific observations
- low-context heuristic findings may include structured metadata rather than a full trace

### 5.5 Machine-Readable Output
All outputs must be suitable for:
- CI pipelines
- IDE/editor integrations
- future GitHub/code scanning interoperability

Deterministic behavior in V1 means:
- stable field names
- stable output structure
- stable sorting rules for exported findings
- stable fingerprint generation under the documented fingerprint algorithm

V1 does not guarantee that DAST runtime behavior is identical across repeated scans against a live target.

### 5.6 Honest Scope
The system must not claim coverage it does not actually implement.

### 5.7 Safety of the Scanner
The scanner must be designed to avoid unsafe behavior.

Examples:
- SAST must not execute target code
- DAST must respect scope boundaries
- DAST must not follow external hosts unless configured
- config and file paths must be resolved safely
- evidence export must redact sensitive data

## 6. High-Level Architecture

### 6.1 Core Components
The platform consists of:

1. CLI Layer
2. Config Layer
3. Orchestration Layer
4. Plugin/Module Registry
5. Findings/Results Layer
6. Export Layer
7. SAST Module
8. DAST Module

### 6.2 Execution Model
A scan request flows through the following stages:

1. CLI command received
2. Config loaded
3. Targets validated
4. Modules selected
5. Profile resolved
6. Module scans executed
7. Findings aggregated
8. Suppressions applied
9. Findings exported
10. Exit code returned

### 6.3 Partial Failure Model
If one module fails and another succeeds:
- successful module findings should still be exportable
- module errors should be recorded in the scan result
- exit code behavior must follow the documented failure policy

V1 default:
- any module/config/runtime failure results in exit code 2
- findings are still exported if safely available

## 7. Repository Structure

Recommended repo structure:

    unif-appsec/
      apps/
        cli/
          main.py
          commands.py
      core/
        config/
          loader.py
          models.py
          defaults.py
        findings/
          models.py
          fingerprints.py
          normalize.py
        orchestration/
          runner.py
          planner.py
          results.py
        plugins/
          base.py
          registry.py
        exports/
          json_writer.py
          sarif_writer.py
        policy/
          profiles.py
          suppression.py
        logging/
          setup.py
      modules/
        sast/
          plugin.py
          parser/
          symbols/
          analyzer/
          traces/
          rules/
          fixtures/
        dast/
          plugin.py
          targeting/
          discovery/
          audit/
          checks/
          auth/
          http/
          fixtures/
      schemas/
        finding.schema.json
        config.schema.json
        scan_result.schema.json
      docs/
        master_spec.md
        findings_schema.md
        config_reference.md
        architecture.md
        module_contracts.md
        implementation_plan.md
      tests/
        unit/
        integration/
        fixtures/

## 8. Core Platform Specification

### 8.1 CLI
Primary command:

appsec scan [target] [flags]

Example supported flows:
- scan repo with SAST
- scan URL/API with DAST
- scan both when config specifies both modules

### 8.2 CLI Requirements
The CLI must support:
- selecting modules
- selecting profile
- specifying config file
- specifying output path
- selecting output format
- severity threshold for exit status
- confidence threshold for exit status
- include/exclude paths
- target URL or OpenAPI path for DAST

Example flags:
- --sast
- --dast
- --all
- --config
- --profile
- --format
- --output
- --fail-on
- --confidence-threshold
- --include
- --exclude
- --target-url
- --openapi

### 8.3 Configuration System
The config system must:
- load from a project file
- validate structure
- support global settings and module-specific settings
- merge defaults with explicit overrides
- support profiles
- support versioned config documents

### 8.4 Profiles
Profiles:
- fast
- balanced
- deep

Profile intent:

fast:
- minimum scan time
- lower analysis depth
- safer/lighter checks
- suitable for local developer loops

balanced:
- default mode
- reasonable detection depth
- reasonable runtime
- suitable for CI

deep:
- more exhaustive analysis
- more DAST requests
- more expensive SAST propagation depth
- suitable for scheduled scans or dedicated testing

### 8.5 Profile and Override Precedence
Configuration precedence must be:

1. profile defaults
2. explicit config file values
3. CLI flags

Merge semantics:
- Begin from the active profile defaults, then overlay the entire config document (global keys and nested objects such as `sast` / `dast`).
- Then overlay CLI-provided settings onto the merged document.

If a module-specific setting conflicts with a profile default for the same key, the explicit value from the config file `sast` or `dast` section wins over the profile default for that key.

CLI flags that correspond to a specific setting (for example `--fail-on` mapping to `policies.fail_on_severity`, or `--profile` selecting the profile) override the merged value for that setting after the config file overlay.

### 8.6 Plugin System
Every module must register through the plugin interface.
The core platform must not know module internals beyond the plugin contract.

### 8.7 Logging
Logging must be structured and clear.
At minimum:
- scan start
- scan end
- module start
- module end
- errors
- warning summaries
- output path summary

### 8.8 Exit Codes
Use deterministic exit codes:
- 0 = scan completed, no unsuppressed findings above threshold
- 1 = scan completed, at least one unsuppressed finding above threshold
- 2 = usage/config/runtime/module failure

A finding contributes to failure only if:
- severity is greater than or equal to fail_on_severity
- confidence is greater than or equal to confidence_threshold
- suppressed is false

### 8.9 Resource Limits
The platform must support resource guardrails.

At minimum:
- max scan duration per module
- max findings per module
- max evidence bytes per finding
- max DAST crawl depth
- max DAST requests per minute
- max response body bytes retained in evidence (config key under `limits`: `max_response_body_bytes`)

## 9. Findings Schema

### 9.1 Purpose
The findings schema is the central contract of the platform.

It must support:
- code findings
- HTTP findings
- dependency findings
- infrastructure findings

V1 will primarily use:
- code findings for SAST
- HTTP findings for DAST

### 9.2 Schema Design
The schema consists of:
- a required core finding object
- optional typed extension objects

This keeps V1 usable for SAST and DAST while preserving extension points for future SCA, IaC, and IAST support.

### 9.3 Required Core Finding Fields
Each finding must contain:

- schema_version
- finding_id
- fingerprint
- engine
- module
- rule_id
- title
- severity
- confidence
- category
- status
- location_type
- evidence_type
- created_at
- suppressed

Optional top-level fields:
- description
- subcategory
- remediation
- references
- tags
- suppression_reason
- correlation
- metadata

### 9.4 Required Semantics

schema_version:
- version of the finding schema

finding_id:
- unique per emitted finding instance

fingerprint:
- stable identifier for near-duplicate matching; V1 algorithm is normative in Section 9.11

engine:
- scanner family, e.g. sast or dast

module:
- concrete module name, e.g. python_sast or http_dast

rule_id:
- stable rule or check identifier

severity:
- one of:
  - info
  - low
  - medium
  - high
  - critical

confidence:
- one of:
  - low
  - medium
  - high

status:
- one of:
  - open
  - suppressed

location_type:
- one of:
  - code
  - http
  - dependency
  - resource

evidence_type:
- one of:
  - code_trace
  - code_match
  - http_exchange
  - metadata_only

suppressed:
- boolean

created_at:
- MUST be an RFC 3339 timestamp in UTC using the `Z` offset designator (example: `2026-04-03T12:00:00Z`)

### 9.5 Typed Location Objects
A finding may include one or more typed location objects depending on the finding class.

#### Code Location
- file_path
- start_line
- end_line
- start_col
- end_col
- function_name

#### HTTP Location
- url
- method
- parameter
- endpoint_signature

#### Future Dependency Location
- ecosystem
- package_name
- package_version
- dependency_path

#### Future Resource Location
- resource_type
- resource_id
- resource_path
- provider

### 9.6 Typed Evidence Objects
Evidence should be structured, not just free text.

#### SAST Evidence
Possible fields:
- code_snippet
- matched_sink
- matched_source
- sanitizer_summary
- trace_summary

#### DAST Evidence
Possible fields:
- request_summary
- response_summary
- matched_payload
- observed_behavior
- response_markers
- baseline_comparison

### 9.7 Trace Model
For SAST and future IAST, trace must support ordered steps.

Trace step fields:
- step_index
- kind
- label
- file_path
- line
- column
- symbol
- note

Trace kinds for V1:
- source
- propagation
- sanitizer
- sink
- call
- return

Future modules may extend trace semantics without breaking existing V1 trace handling.

### 9.8 Correlation Object
Reserve a structured correlation object for future unified analysis.

Possible keys in V1:
- route
- sink_type
- source_type
- parameter_name
- function_name
- file_path
- cwe
- host
- endpoint

Future modules may add additional structured keys such as package identifiers or resource addresses.

### 9.9 Scan Errors
Scan errors are not findings.

They must be represented separately at the scan result or module result level.

Examples:
- config validation failure
- network timeout
- module runtime exception
- unsupported target

### 9.10 Module Scan Result and Aggregate Scan Output

#### 9.10.1 ModuleScanResult shape
Each plugin `scan` return value must map to a structured **ModuleScanResult** with:

- **findings**: array of normalized finding objects (Section 9)
- **warnings**: array of structured warning entries (non-fatal)
- **errors**: array of structured error entries (failures for that module)
- **metrics**: object (Section 9.10.2)

Warning and error entries must be structured objects with at minimum:

- **code**: short stable machine-readable identifier (string)
- **message**: human-readable description (string)
- **details**: optional object for structured context; consumers must ignore unknown keys

#### 9.10.2 Module metrics (minimum optional keys)
Metrics may include additional keys; consumers must ignore unknown keys.

When applicable, modules should populate:

- **duration_ms**: wall-clock time spent in the module scan (number)
- **files_analyzed**: Python files analyzed (integer; SAST)
- **requests_sent**: HTTP requests issued (integer; DAST)

#### 9.10.3 Aggregate machine-readable scan document
The primary JSON scan output must include a stable top-level envelope separate from individual finding rows:

- **scan_result_schema_version**: version of this scan-result envelope (string)
- **findings**: final aggregated list after module aggregation and suppression application
- **module_results**: array of per-module summaries, each containing at minimum:
  - **module**: module name (string; must match finding `module` values from that plugin)
  - **warnings**: as returned by the plugin
  - **errors**: as returned by the plugin
  - **metrics**: as returned by the plugin

`module_results` must not duplicate the full findings list per module; findings appear only in the top-level **findings** array. Each finding carries its own `module` field for attribution.

### 9.11 Fingerprint Algorithm (V1)
Because `fingerprint` is a required finding field (Section 9.3), V1 requires a **normative** fingerprint algorithm so suppressions, deduplication, and exports are stable across runs and implementations.

Fingerprints must **not** depend on: `finding_id`, `created_at`, `suppressed`, `status`, or any free-text description fields.

Fingerprint string format:

- **fp1:** followed by 64 lowercase hexadecimal characters (SHA-256 digest of the canonical material below)

Canonical material (UTF-8 string) is formed by concatenating the following lines in order, each line terminated by a single newline (`\n`), using empty string for optional missing values:

1. `schema_version=<value>`
2. `engine=<value>`
3. `module=<value>`
4. `rule_id=<value>`
5. `location_type=<value>`
6. `evidence_type=<value>`
7. `location_key=<value>` where `location_key` is:
   - **code**: `file_path` normalized to a POSIX relative path from the scan root with `.` and `..` resolved where safe, then `|start_line=<n>|end_line=<n>|function=<name or empty>`
   - **http**: `method` uppercased, then `|url=<canonical_url>|param=<name or empty>|endpoint_sig=<value or empty>` where **canonical_url** is the URL without fragment, with scheme and host lowercased, path left as provided after UTF-8 decoding, and query string parameters sorted lexicographically by parameter name (UTF-8), then by value, using repeated keys in sorted order; parameters URL-encoded in UTF-8 using standard percent-encoding
   - **dependency** or **resource** (future modules): stable pipe-delimited encoding of the primary location fields defined for that location type in Section 9.5, with keys sorted alphabetically

If multiple code locations attach to one finding, use the **primary** location (the narrowest sink or check location as defined by the emitting module; modules must document their primary-location rule).

The SHA-256 digest is computed over UTF-8 bytes of the canonical material string, then encoded as lowercase hex with the `fp1:` prefix.

### 9.12 Exported Findings Sort Order
When findings are exported as an ordered list (JSON array, SARIF ordering, etc.), the order must be deterministic:

1. Sort ascending by `fingerprint` (UTF-8 lexicographic byte order)
2. Tie-break ascending by `finding_id` (UTF-8 lexicographic byte order)

## 10. Plugin Interface Specification

### 10.1 Plugin Contract
Each plugin must implement the following conceptual interface:

- name
- version
- supported_target_types()
- supported_profiles()
- validate_target(target, config)
- scan(target, config, context) -> ModuleScanResult

Optional plugin capabilities:
- healthcheck() -> status

**supported_profiles() semantics:**
- If it returns a **non-empty** list, the plugin declares that it only supports those profile names; the core must reject or skip the module when the selected profile is not in that list (implementation choice, but behavior must be explicit and tested).
- If it returns an **empty** list, the plugin accepts **all** platform-defined V1 profiles (`fast`, `balanced`, `deep`).

### 10.2 ModuleScanResult
Each plugin must return a structured scan result conforming to Section 9.10.1:

- normalized findings
- module warnings
- module errors
- module metrics

Plugins may use internal analysis models, but findings must be normalized before being returned to the core platform.

### 10.3 Plugin Rules
Plugins must:
- return normalized findings through ModuleScanResult
- avoid direct CLI behavior
- avoid direct output writing
- use shared config objects
- use shared logging facilities

## 11. SAST Module Specification

### 11.1 Scope
The SAST module must be a real static analyzer for Python, not a regex-only scanner.

### 11.2 Supported Analysis Model
V1 SAST supports:
- AST parsing
- symbol tracking
- bounded function-aware analysis
- bounded intrafile interprocedural taint propagation
- rule-driven sources/sinks/sanitizers/propagators
- trace generation

### 11.3 Explicit V1 Analysis Boundaries
V1 SAST is intentionally limited.

Supported in V1:
- local variables
- direct assignments
- simple return-value propagation
- direct function calls within the same file
- argument-to-parameter taint transfer
- simple propagation through common expression forms

Not supported in V1:
- complete interfile propagation
- decorators
- closures
- dynamic attribute access
- reflective dispatch
- advanced alias modeling
- exception-sensitive flow
- container element sensitivity
- generator/coroutine flow sensitivity
- whole-program soundness
- custom metaprogramming support

### 11.4 SAST Analysis Pipeline
The SAST pipeline should be:

1. collect Python files
2. parse AST
3. build file-level symbol/function map
4. resolve supported assignments and supported call relationships within file scope
5. identify sources
6. propagate taint through supported constructs
7. detect flows into sinks
8. apply sanitization logic where modeled
9. emit traces
10. convert to normalized findings

### 11.5 Supported Rule Concepts
Each rule definition must support:
- id
- title
- message
- severity
- category
- language
- sources
- sinks
- sanitizers
- propagators
- metadata tags

### 11.6 Initial SAST Rule Families
Required V1 rule families:
- command injection
- eval/exec injection
- SQL injection
- path traversal
- weak crypto or weak hash use

Stretch goals, not required for V1 acceptance:
- unsafe deserialization
- SSRF-like outbound request flow

### 11.7 Source Examples
Possible source types:
- input()
- command line args
- request args for explicitly modeled frameworks only
- request.form for explicitly modeled frameworks only
- request.json for explicitly modeled frameworks only
- environment input if modeled
- file reads only if explicitly marked as untrusted in rules

#### 11.7.1 V1 baseline for framework web request sources
V1 does **not** require any built-in Flask, Django, FastAPI, or other framework-specific request object modeling.

Rules or optional rule packs may introduce **explicitly named** framework adapters (documented alongside the rule). Until such an adapter is present for a given framework, `request.args`, `request.form`, `request.json`, and similar patterns must **not** be treated as automatic taint sources.

### 11.8 Sink Examples
Possible sink types:
- os.system
- subprocess shell execution
- eval
- exec
- raw SQL execution calls
- file open/write path-sensitive usage
- dangerous deserialization calls
- outbound URL fetch calls for SSRF-like rules

### 11.9 Sanitizer Examples
Possible sanitizers:
- allowlist validation wrappers
- explicit path normalization or checks
- parameterized query construction if explicitly modeled
- shell escaping if explicitly modeled

Unmodeled sanitizers must not be assumed to be safe.

### 11.10 SAST Limitations for V1
V1 SAST will not promise:
- perfect framework understanding
- inter-repo analysis
- complete interfile resolution
- advanced alias modeling
- framework-agnostic request object support
- accurate handling of all Python dynamic features

### 11.11 SAST Acceptance Criteria
The SAST module is considered successful when it:
- detects intended flows in test fixtures
- produces traceable findings
- distinguishes safe from unsafe cases in explicitly modeled sanitizer scenarios
- emits stable output structure
- integrates cleanly with the core platform

## 12. DAST Module Specification

### 12.1 Scope
The DAST module must be an HTTP/API-first dynamic scanner.

### 12.2 Supported DAST Model
V1 DAST supports:
- target definition
- optional OpenAPI import
- endpoint discovery
- passive checks
- active checks
- basic authentication handling
- evidence capture
- profile-based scan depth

V1 DAST is API-first.
Discovery from OpenAPI, explicit endpoint seeds, and target configuration takes priority over crawler-driven discovery.

### 12.3 DAST Phases
The DAST pipeline must be split into two primary phases:

1. discovery
2. audit

This separation must exist in code architecture even if some simple flows chain them directly.

### 12.4 Discovery Responsibilities
Discovery should:
- accept start URL or API base URL
- optionally ingest OpenAPI
- ingest explicit endpoint seeds from config if present
- enumerate endpoints and parameters from available inputs
- optionally perform lightweight same-origin link crawling
- identify candidate insertion points

### 12.5 Crawl Limits for V1
If crawling is enabled in V1, it must be limited to:
- same-origin only
- HTML link and form extraction only
- shallow depth as defined by config
- no JavaScript execution
- no claim of complete route discovery

### 12.6 Audit Responsibilities
Audit should:
- run passive response analysis
- run active checks with payloads
- record evidence
- generate findings with confidence/severity
- respect scan policies and rate limits
- compare baseline and modified responses where applicable

### 12.7 Initial Passive Checks
Initial passive checks may include:
- missing security headers
- overly permissive CORS headers
- debug/info leak markers
- framework or server disclosure
- unsafe cookie flags if observable
- insecure response patterns

### 12.8 Initial Active Checks
Initial active checks may include:
- reflected XSS indicators
- SQL injection indicators
- path traversal probes if safely scoped
- debug endpoint or file exposure probes if carefully scoped
- simple response-based misconfiguration checks

A reflected substring alone is not sufficient for a high-confidence XSS finding.
An error message alone is not sufficient for a high-confidence SQL injection finding.
Where practical, active checks should compare baseline and modified responses.

### 12.9 Auth Model
V1 auth support:
- static headers
- bearer token
- cookie persistence
- simple reauth hooks for future expansion

V1 will not claim:
- arbitrary SSO
- MFA navigation
- fully automatic login generation
- deep browser state emulation
- authorization or multi-role testing

### 12.10 DAST Limitations for V1
V1 DAST will not promise:
- complete SPA discovery
- deep JavaScript execution support
- business logic vulnerability discovery
- reliable blind/OAST coverage
- full browser automation
- complete route discovery
- robust testing of undocumented multi-step workflows

### 12.11 DAST Acceptance Criteria
The DAST module is considered successful when it:
- can scan a simple target end to end
- separates discovery from audit in architecture
- supports at least one authenticated path
- emits structured HTTP evidence
- integrates cleanly with the core platform

## 13. Configuration Specification

### 13.1 Config Shape
A single config file should support:
- global settings
- output settings
- profile settings
- module settings
- rule/check control
- suppression settings
- resource limits

### 13.2 Example Structure
Top-level keys:
- config_version
- project
- scan
- output
- policies
- limits
- sast
- dast
- suppressions

### 13.3 Example Concepts

config_version:
- config schema version

project:
- name

scan:
- modules
- profile
- include_paths
- exclude_paths

output:
- format
- path
- pretty
- sarif

policies:
- fail_on_severity
- confidence_threshold

limits:
- max_findings_per_module
- max_evidence_bytes
- max_scan_duration_seconds
- max_requests_per_minute
- max_crawl_depth
- max_response_body_bytes

sast:
- language
- max_taint_depth
- rules_path
- enabled_rules
- disabled_rules

dast:
- target_url
- openapi_path
- endpoint_seeds
- auth
- crawl
- checks
- rate_limit
- timeout

suppressions:
- list of suppressions by fingerprint, rule + path, rule + endpoint, or rule + path glob

### 13.4 Suppression Rules
Suppressions must:
- include a justification
- be applied after findings are generated
- not suppress scan errors

Suppression precedence (highest priority first):
1. fingerprint
2. rule + exact location
3. rule + exact endpoint
4. rule + path glob

Evaluation rule:
- A finding is suppressed if **any** suppression rule matches.
- When attributing `suppression_reason` (or equivalent), use the **highest-priority** matching rule from the list above (fingerprint beats rule+location, and so on).
- Within the **same** precedence tier, if multiple rules match, implementations should use the **first** matching rule in config file order for attribution.

## 14. Testing Strategy

### 14.1 Unit Tests
Each core component and each module subsystem must have unit tests.

### 14.2 Fixture-Based Tests
Use realistic vulnerable and safe fixtures.

SAST fixtures:
- vulnerable Python files
- safe Python files
- near-miss files

DAST fixtures:
- mocked HTTP targets
- small local vulnerable demo service if practical
- response replay fixtures

### 14.3 Integration Tests
Integration tests must verify:
- CLI flow
- config loading
- plugin loading
- combined scan execution
- unified output generation
- aggregate JSON envelope fields (`scan_result_schema_version`, `findings`, `module_results`) and deterministic finding order (Sections 9.10.3 and 9.12)
- exit code behavior
- partial failure behavior

## 15. Output Requirements

### 15.1 JSON Output
JSON output must be:
- stable in structure
- machine-readable
- complete for emitted findings
- deterministically sorted for export

The top-level scan document must follow Section 9.10.3 (envelope with `scan_result_schema_version`, `findings`, and `module_results`). The `findings` array order must follow Section 9.12.

V1 does not guarantee identical DAST runtime observations across repeated live scans.

### 15.2 SARIF Readiness
The export layer must be designed so that SAST findings map cleanly to SARIF concepts even if SARIF support starts minimal.

### 15.3 Evidence Redaction
Evidence must be redacted before export when necessary.

At minimum:
- Authorization headers must be masked
- cookies must be masked
- obvious bearer/session tokens must be masked
- large bodies may be truncated
- response evidence size must respect configured limits

### 15.4 Human Summary
CLI should print a concise summary:
- modules run
- target summary
- findings by severity
- output location
- exit status reason
- module errors if present

## 16. Future Module Extension Points

### 16.1 IAST
The architecture must reserve room for:
- runtime traces
- request-to-code linking
- runtime evidence
- trace enrichment
- sink observation

### 16.2 SCA
The architecture must reserve room for:
- dependency objects
- package metadata
- dependency graph paths
- vulnerability references
- remediation suggestions

### 16.3 IaC
The architecture must reserve room for:
- resource findings
- resource graph relationships
- policy identifiers
- infrastructure locations

## 17. Implementation Guidance

### 17.1 Priorities
Build in this order:
1. core platform
2. SAST module
3. DAST module
4. integration and cleanup

### 17.2 Build Philosophy
Always prioritize:
- stable interfaces
- typed models
- fixtures and tests
- clear boundaries
- deterministic export behavior

Avoid:
- overbuilding
- premature abstractions not used by v1
- claiming unsupported features
- coupling modules to CLI or output logic
- broadening scope without updating the spec

## 18. Success Definition for V1

V1 is successful if:
- there is one coherent platform
- SAST and DAST plug into it cleanly
- findings are normalized
- configuration is consistent
- outputs are usable in developer workflows
- the design clearly supports future IAST, SCA, and IaC additions
- the codebase is understandable and maintainable

## 19. Must-Have vs Should-Have

### 19.1 Must-Have
- modular core platform
- plugin system
- unified findings schema
- stable fingerprinting per Section 9.11 (required because `fingerprint` is a required finding field)
- scan result envelope per Section 9.10.3 and `scan_result.schema.json` in repository schemas
- config system
- JSON output
- CLI
- Python SAST with bounded taint traces
- HTTP/API-first DAST with discovery and audit separation
- tests
- documentation

### 19.2 Should-Have
- SARIF export
- suppression system
- scan profiles
- OpenAPI import
- structured evidence formatting
- integration tests

### 19.3 Future Work
- IAST-lite
- SCA
- IaC
- richer auth handling
- more languages
- better correlation
- richer reporting
