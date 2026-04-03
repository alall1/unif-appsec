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
- profile handling
- output writing
- suppression plumbing
- logging
- exit code handling
- future extension points for IAST, SCA, and IaC

### 2.3 SAST Responsibilities
The SAST module is responsible for:
- static analysis of Python source code
- AST-based parsing
- intrafile interprocedural taint analysis
- rule-driven vulnerability detection
- taint traces from source to sink
- generation of findings in the shared schema

### 2.4 DAST Responsibilities
The DAST module is responsible for:
- HTTP/API-first target scanning
- discovery phase
- audit phase
- passive checks
- active checks
- basic authenticated scanning
- evidence capture
- generation of findings in the shared schema

## 3. Explicit Non-Goals for V1

The following are out of scope for V1:
- dashboard or web UI
- database persistence
- user accounts or RBAC
- distributed scanning
- multi-tenant SaaS deployment
- browser-heavy full SPA automation
- complex SSO/MFA handling
- enterprise-scale language coverage
- production-grade full IAST agent
- full SCA implementation
- full IaC implementation
- historical trend analytics
- advanced vulnerability deduplication across large datasets

## 4. Supported Targets in V1

### 4.1 SAST Targets
- Python repositories or directories containing Python source files

### 4.2 DAST Targets
- HTTP applications
- REST APIs
- API endpoints discoverable from:
  - start URL
  - provided base URL
  - optional OpenAPI specification

## 5. Architecture Principles

### 5.1 Separation of Concerns
Core platform code must not contain SAST-specific or DAST-specific analysis logic.
Modules must not reimplement core platform responsibilities.

### 5.2 Unified Schema
All findings must conform to one normalized schema, even if some fields are unused by a given module.

### 5.3 Extensibility
The architecture must support future modules without requiring a redesign of:
- orchestration
- configuration
- output formats
- findings schema

### 5.4 Explainability
Every finding should include enough evidence to explain why it exists.
For SAST, this usually means a trace.
For DAST, this usually means request/response evidence.

### 5.5 Machine-Readable Output
All outputs must be deterministic and suitable for:
- CI pipelines
- IDE/editor integrations
- future GitHub/code scanning interoperability

### 5.6 Honest Scope
The system must not claim coverage it does not actually implement.

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
7. Findings normalized
8. Suppressions applied
9. Findings exported
10. Exit code returned

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
      docs/
        master_spec.md
        findings_schema.md
        config_reference.md
        architecture.md
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

### 8.4 Profiles
Profiles:
- fast
- balanced
- deep

Profile intent:

fast:
- minimum scan time
- lower depth
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

### 8.5 Plugin System
Every module must register through the plugin interface.
The core platform must not know module internals beyond the plugin contract.

### 8.6 Logging
Logging must be structured and clear.
At minimum:
- scan start
- scan end
- module start
- module end
- errors
- warning summaries
- output path summary

### 8.7 Exit Codes
Use deterministic exit codes:
- 0 = scan completed, no findings above threshold
- 1 = scan completed, findings above threshold
- 2 = usage/config/runtime failure

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

### 9.2 Finding Object
Each finding must contain:

- finding_id
- fingerprint
- engine
- module
- rule_id
- title
- description
- category
- subcategory
- severity
- confidence
- status
- location
- evidence
- trace
- remediation
- references
- tags
- cwe
- cve
- created_at
- correlation_keys
- suppressed
- suppression_reason

### 9.3 Required Semantics

finding_id:
- unique per emitted finding instance

fingerprint:
- stable identifier for near-duplicate matching across runs

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
  - error

### 9.4 Location Model
The schema must support multiple location types.

Code location fields:
- file_path
- start_line
- end_line
- start_col
- end_col
- function_name

HTTP location fields:
- url
- method
- parameter
- endpoint_signature

Resource location fields reserved for future:
- resource_type
- resource_id
- resource_path

### 9.5 Evidence Model
Evidence should be structured, not just free text.

For SAST:
- code snippet
- matched sink
- matched source
- sanitizer summary
- trace summary

For DAST:
- request summary
- response summary
- matched payload
- observed behavior
- response markers

### 9.6 Trace Model
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

Trace kinds:
- source
- propagation
- sanitizer
- sink
- call
- return

### 9.7 Correlation Keys
Reserve correlation keys for future unified analysis:
- route
- sink_type
- source_type
- parameter_name
- function_name
- file_path
- cwe
- host
- endpoint

## 10. Plugin Interface Specification

### 10.1 Plugin Contract
Each plugin must implement the following conceptual interface:

- name
- version
- supported_target_types()
- supported_profiles()
- validate_target(target, config)
- scan(target, config, context) -> findings
- healthcheck() -> status

### 10.2 Plugin Rules
Plugins must:
- return normalized findings or module-native findings that are normalized before export
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
- function-aware analysis
- intrafile interprocedural taint propagation
- rule-driven sources/sinks/sanitizers/propagators
- trace generation

### 11.3 SAST Analysis Pipeline
The SAST pipeline should be:

1. collect Python files
2. parse AST
3. build file-level symbol/function map
4. resolve assignments and call relationships within file scope
5. identify sources
6. propagate taint
7. detect flows into sinks
8. apply sanitization logic
9. emit traces
10. convert to normalized findings

### 11.4 Supported Rule Concepts
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

### 11.5 Initial SAST Rule Families
V1 rule families:
- command injection
- eval/exec injection
- SQL injection
- path traversal
- weak crypto or weak hash use
- unsafe deserialization if practical
- SSRF-like outbound request flow if practical

### 11.6 Source Examples
Possible source types:
- input()
- command line args
- request args
- request.form
- request.json
- environment input if modeled
- file reads only if explicitly marked as untrusted in rules

### 11.7 Sink Examples
Possible sink types:
- os.system
- subprocess shell execution
- eval
- exec
- raw SQL execution calls
- file open/write path-sensitive usage
- dangerous deserialization calls
- outbound URL fetch calls for SSRF-like rules

### 11.8 Sanitizer Examples
Possible sanitizers:
- allowlist validation wrappers
- explicit path normalization or checks
- parameterized query construction if modeled
- shell escaping if modeled

### 11.9 SAST Limitations for V1
V1 SAST will not promise:
- perfect framework understanding
- inter-repo analysis
- whole-program soundness
- complete interfile resolution
- advanced alias modeling
- custom metaprogramming support

### 11.10 SAST Acceptance Criteria
The SAST module is considered successful when it:
- detects intended flows in test fixtures
- produces traceable findings
- distinguishes safe from unsafe cases for at least some sanitizer scenarios
- emits stable output
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

### 12.3 DAST Phases
The DAST pipeline must be split into two primary phases:

1. discovery
2. audit

This separation must exist in code architecture even if some simple flows chain them directly.

### 12.4 Discovery Responsibilities
Discovery should:
- accept start URL or API base URL
- optionally ingest OpenAPI
- enumerate endpoints and parameters
- optionally perform lightweight link crawling
- identify candidate insertion points

### 12.5 Audit Responsibilities
Audit should:
- run passive response analysis
- run active checks with payloads
- record evidence
- generate findings with confidence/severity
- respect scan policies and rate limits

### 12.6 Initial Passive Checks
Initial passive checks may include:
- missing security headers
- overly permissive CORS headers
- debug/info leak markers
- framework or server disclosure
- unsafe cookie flags if observable
- insecure response patterns

### 12.7 Initial Active Checks
Initial active checks may include:
- reflected XSS indicators
- SQL injection indicators
- path traversal probes if safely scoped
- debug endpoint or file exposure probes if carefully scoped
- simple auth and access-control anomalies only if explicitly supported

### 12.8 Auth Model
V1 auth support:
- static headers
- bearer token
- cookie persistence
- simple auth hooks for future expansion

V1 will not claim:
- arbitrary SSO
- MFA navigation
- fully automatic login generation
- deep browser state emulation

### 12.9 DAST Limitations for V1
V1 DAST will not promise:
- complete SPA discovery
- deep JavaScript execution support
- business logic vulnerability discovery
- reliable blind/OAST coverage
- full browser automation

### 12.10 DAST Acceptance Criteria
The DAST module is considered successful when it:
- can scan a simple target end to end
- separates discovery from audit in architecture
- supports at least one authenticated path
- emits structured evidence
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

### 13.2 Example Structure
Top-level keys:
- project
- scan
- output
- policies
- sast
- dast
- suppressions

### 13.3 Example Concepts

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

sast:
- language
- max_taint_depth
- rules_path
- enabled_rules
- disabled_rules

dast:
- target_url
- openapi_path
- auth
- crawl
- checks
- rate_limit
- timeout

suppressions:
- list of suppressions by rule, path, endpoint, or fingerprint

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
- exit code behavior

## 15. Output Requirements

### 15.1 JSON Output
JSON output must be:
- stable
- machine-readable
- complete
- deterministic

### 15.2 SARIF Readiness
The export layer must be designed so that SAST findings map cleanly to SARIF concepts even if SARIF support starts minimal.

### 15.3 Human Summary
CLI should print a concise summary:
- modules run
- target summary
- findings by severity
- output location
- exit status reason

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
- deterministic behavior

Avoid:
- overbuilding
- premature abstractions not used by v1
- claiming unsupported features
- coupling modules to CLI or output logic

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
- config system
- JSON output
- CLI
- Python SAST with taint traces
- HTTP/API-first DAST with discovery and audit separation
- tests
- documentation

### 19.2 Should-Have
- SARIF export
- suppression system
- scan profiles
- OpenAPI import
- stable fingerprinting
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
