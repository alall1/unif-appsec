# Configuration Reference

This document summarizes configuration shape and semantics from `master_spec.md` Sections 8, 13, and 20. The master spec is authoritative.

- **V1 behavior** is described as it exists today in the codebase and must remain intact.
- **V2 additions** (SCA and IaC) are described additively and must not change precedence or existing semantics.

---

## CLI (Primary Command – unchanged from V1)

```bash
appsec scan [target] [flags]
```

### Flags (examples from spec – unchanged)

| Flag | Purpose |
|------|---------|
| `--sast` / `--dast` / `--sca` / `--iac` / `--all` | Module selection |
| `--config` | Path to config file |
| `--profile` | `fast` \| `balanced` \| `deep` |
| `--format` | Output format selection |
| `--output` | Output path |
| `--fail-on` | Severity threshold for exit status |
| `--confidence-threshold` | Confidence threshold for exit status |
| `--include` / `--exclude` | Path filters (SAST-oriented) |
| `--target-url` | DAST target URL |
| `--openapi` | OpenAPI spec path for DAST |

V2 SCA and IaC **do not** add new mandatory CLI flags. They rely on:
- `scan.modules` and the same CLI module-selection flags.
- Target path handling already used for SAST.

Exact flag spelling and parsing are implementation details but must satisfy the spec’s capability list.

---

## Config Precedence (unchanged from V1)

Configuration precedence is **frozen** and must not be changed by V2:

1. **Profile defaults** (`fast`, `balanced`, `deep`)
2. **Explicit config file** values
3. **CLI flags**

Details (per master spec §8.5, implemented in `core/config/loader.py` and `ResolvedConfig`):

- Start from profile defaults (including limits and policies).
- Overlay the entire config document (including nested `scan`, `sast`, `dast`, and future `sca` / `iac` sections).
- Overlay CLI-provided settings for any corresponding config keys (e.g. `--fail-on` → `policies.fail_on_severity`).

If a **module-specific** setting in the config conflicts with a profile default for the same key, the value under that module section in the config file (e.g. `sast`, `dast`) wins for that key.

V2 must follow the same rule for `sca` and `iac` sections.

---

## Profiles (unchanged from V1)

| Profile | Intent |
|---------|--------|
| **fast** | Minimum scan time, lower depth, lighter/safer checks; local dev loops. |
| **balanced** | Default; reasonable depth and runtime; CI. |
| **deep** | More exhaustive analysis, more DAST traffic, deeper SAST taint propagation; scheduled or dedicated testing. |

V2 modules (SCA and IaC) must honor the same profile names. No new profile names are introduced in V2.

---

## Top-Level Config Keys (conceptual – extended for V2)

The config **shape** remains the same; V2 adds module sections but does not change existing keys.

| Key | Role | V1/V2 status |
|-----|------|-------------|
| `config_version` | Config schema version. | **Unchanged** |
| `project` | Project metadata (e.g. `name`). | **Unchanged** |
| `scan` | Which modules to run, profile, include/exclude paths. | **Unchanged** |
| `output` | Output format, path, pretty-printing, SARIF toggle. | **Unchanged** |
| `policies` | `fail_on_severity`, `confidence_threshold`. | **Unchanged** |
| `limits` | Platform-wide resource guardrails. | **Unchanged** |
| `sast` | SAST-specific settings. | **Unchanged** |
| `dast` | DAST-specific settings. | **Unchanged** |
| `sca` | **SCA-specific settings (V2 additive).** | **New in V2** |
| `iac` | **IaC-specific settings (V2 additive).** | **New in V2** |
| `suppressions` | Suppression entries. | **Unchanged** |

The current `ResolvedConfig` model already has stable fields for V1 (`scan`, `output`, `policies`, `limits`, `sast`, `dast`, `suppressions`). SCA and IaC should be added following the same pattern when implemented.

---

## Resource Limits (platform – unchanged from V1)

Minimum required concepts per master spec:

- `max_scan_duration_seconds` (per module)
- `max_findings_per_module`
- `max_evidence_bytes` (per finding)
- `max_crawl_depth` (DAST)
- `max_requests_per_minute` (DAST)
- `max_response_body_bytes` (cap retained response body in evidence)

The current implementation enforces these through `core/config/models.py::LimitsConfig` and the orchestration runner. V2 modules (SCA/IaC) must respect relevant limits (e.g. duration, findings per module, evidence size) but **do not** introduce new global limit concepts in V2.

---

## SAST Module Settings (V1 – unchanged)

SAST uses a free-form `sast` section in config, projected into `ResolvedConfig.sast` (a `dict[str, Any]`). The SAST plugin reads these keys:

- `language` (V1: Python; other values cause warnings and are ignored).
- `max_taint_depth` (integer; interacts with profiles and defaults).
- `rules_path` (path to a rules pack, relative to scan root when not absolute).
- `enabled_rules` / `disabled_rules` (lists of rule IDs).

These semantics must remain unchanged in V2.

---

## DAST Module Settings (V1 – unchanged)

DAST uses a free-form `dast` section in config, projected into `ResolvedConfig.dast`. The DAST plugin and targeting code read keys such as:

- `target_url`
- `base_url`
- `openapi_path`
- `endpoint_seeds`
- `auth` (static headers, bearer token, initial cookies)
- `crawl` settings (enable flag, max depth)
- `allow_cross_origin` / additional origins
- `rate_limit` and `timeout`-like settings (implementation details)

V1 defaults (from target validation and targeting code):
- Same-origin crawl expansion only.
- No automatic scanning of newly discovered hosts unless explicitly allowed.

V2 must not change these defaults.

---

## SCA Module Settings (V2 additive)

SCA configuration is **additive** and should be scoped realistically for a solo project.

Recommended minimal `sca` section:

```yaml
sca:
  enabled: true            # optional; default true when sca module is selected
  include_manifests: []    # optional allowlist of manifest/lockfile globs
  exclude_manifests: []    # optional denylist of manifest/lockfile globs
  advisory_source: "local" # identifier for the advisory dataset
```

Semantics:
- **Inputs**:
  - V2 SCA only supports:
    - `requirements.txt`
    - `poetry.lock`
    - `Pipfile.lock`
  - Config may narrow this via `include_manifests`/`exclude_manifests` but must not introduce new ecosystems.
- **Behavior when no inputs are found**:
  - Return **warnings** and **no findings** rather than failing the full scan, unless an explicit “hard-fail” boolean is added by spec later.
- **Advisory source**:
  - A simple identifier describing the advisory bundle (e.g. `local`, `osv_snapshot`), used only for traceability.

These settings do not change core precedence or module selection; they only influence SCA’s own behavior when that module is run.

---

## IaC Module Settings (V2 additive)

IaC configuration is also **additive** and narrow.

Recommended minimal `iac` section:

```yaml
iac:
  enabled: true           # optional; default true when iac module is selected
  include_paths: []       # optional allowlist of paths/globs for .tf files
  exclude_paths: []       # optional denylist of paths/globs
  providers: []           # optional list of provider identifiers to focus on
```

Semantics:
- **Inputs**:
  - V2 IaC scans only `.tf` Terraform source files.
  - No support is implied for state files, plan files, or other IaC formats.
- **Behavior when no inputs are found**:
  - Return **warnings** and **no findings** rather than failing the full scan, unless an explicit “hard-fail” boolean is added by spec later.
- **Providers**:
  - Optional filter for provider names (e.g. `aws`, `azurerm`) used purely to scope checks, not to imply multi-cloud feature parity.

As with SCA, these options are local to the IaC module and must not change global precedence or exit-code semantics.

---

## Suppressions (unchanged from V1, extended match shapes in V2)

Suppressions:

- Must include a **justification**.
- Apply **after** findings are generated.
- Do **not** suppress **scan errors** (errors are not findings).

**Precedence** (highest priority first; master spec §13.4, implemented in `core/policy/suppression.py`):

1. Fingerprint
2. Rule + exact location
3. Rule + exact endpoint
4. Rule + path glob

A finding is suppressed if **any** rule matches. For `suppression_reason` attribution:
- Use the **highest-priority** matching rule.
- Within the same tier, use the **first** matching rule in config file order.

V2 adds **new match shapes** for SCA and IaC **without changing precedence tiers**:

- **Rule + dependency coordinate** (same tier as “rule + exact location”):
  - `rule_id`
  - `ecosystem`
  - `package_name`
  - `package_version`
- **Rule + resource address** (same tier as “rule + exact location”):
  - `rule_id`
  - `provider`
  - `resource_address`

These shapes are additive; they must not change how existing SAST/DAST suppressions behave.

---

## Policies Affecting Exit Code (unchanged from V1)

A finding contributes to fail (exit **1**) only if:

- `severity` ≥ configured fail-on severity, **and**
- `confidence` ≥ configured confidence threshold, **and**
- `suppressed` is false

Exit **2** applies for usage/config/runtime/module failure per V1 default, independent of finding counts. This behavior is implemented in `core/orchestration/exit_code.py` and must remain unchanged for V2.

V2 modules (SCA, IaC) must:
- Use the same `severity` and `confidence` enums.
- Rely on the same policies for exit-code decisions.
- Not introduce new exit-code meanings.

---

## Versioned Documents (unchanged from V1)

Config must support **versioned** config documents via `config_version` and schema evolution. Implementation should reject, migrate, or clearly error on unknown versions rather than guessing.

V2 changes to config:
- Must be represented as incremental schema versions when needed.
- Must not retroactively change the meaning of existing V1 keys, fields, or precedence.

