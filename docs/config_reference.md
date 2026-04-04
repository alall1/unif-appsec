# Configuration Reference

This document summarizes configuration shape and semantics from [master_spec.md](./master_spec.md) Sections 8 and 13. The master spec is authoritative.

## CLI (Primary Command)

```
appsec scan [target] [flags]
```

### Flags (Examples from Spec)

| Flag | Purpose |
|------|---------|
| `--sast` / `--dast` / `--all` | Module selection |
| `--config` | Path to config file |
| `--profile` | `fast` \| `balanced` \| `deep` |
| `--format` | Output format selection |
| `--output` | Output path |
| `--fail-on` | Severity threshold for exit status |
| `--confidence-threshold` | Confidence threshold for exit status |
| `--include` / `--exclude` | Path filters (SAST-oriented) |
| `--target-url` | DAST target URL |
| `--openapi` | OpenAPI spec path for DAST |

Exact flag spelling and parsing are implementation details but must satisfy the spec’s capability list.

## Precedence

1. **Profile defaults** (`fast`, `balanced`, `deep`)
2. **Explicit config file** values
3. **CLI flags**

If a **module-specific** setting in the config conflicts with a profile default for the same key, the value under `sast` or `dast` in the config file wins over the profile default for that key.

Merge order (master spec §8.5): profile defaults → overlay entire config document → overlay CLI flags for any setting the CLI controls (e.g. `--fail-on` overrides merged `policies.fail_on_severity`).

## Profiles

| Profile | Intent |
|---------|--------|
| **fast** | Minimum scan time, lower depth, lighter/safer checks; local dev loops |
| **balanced** | Default; reasonable depth and runtime; CI |
| **deep** | More exhaustive analysis, more DAST traffic, deeper SAST taint propagation; scheduled or dedicated testing |

## Top-Level Config Keys (Conceptual)

| Key | Role |
|-----|------|
| `config_version` | Config schema version |
| `project` | e.g. `name` |
| `scan` | `modules`, `profile`, `include_paths`, `exclude_paths` |
| `output` | `format`, `path`, `pretty`, `sarif` |
| `policies` | `fail_on_severity`, `confidence_threshold` |
| `limits` | Resource guardrails (see below) |
| `sast` | SAST-specific settings |
| `dast` | DAST-specific settings |
| `suppressions` | Suppression entries |

## Resource Limits (Platform)

Minimum required concepts per master spec:

- `max_scan_duration_seconds` (per module)
- `max_findings_per_module`
- `max_evidence_bytes` (per finding)
- `max_crawl_depth` (DAST)
- `max_requests_per_minute` (DAST)
- `max_response_body_bytes` (cap retained response body in evidence)

## SAST Module Settings (Conceptual)

- `language` (V1: Python)
- `max_taint_depth` (ties to profile + overrides)
- `rules_path`
- `enabled_rules` / `disabled_rules`

## DAST Module Settings (Conceptual)

- `target_url`
- `openapi_path`
- `endpoint_seeds`
- `auth` (static headers, bearer, cookies, simple reauth hooks for future)
- `crawl` (shallow, same-origin, HTML-only when enabled; no JS execution)
- `checks` (passive/active enablement as designed)
- `rate_limit`, `timeout`

V1 defaults (from target validation): same-origin crawl expansion only; do not automatically scan newly discovered hosts unless explicitly allowed.

## Suppressions

Suppressions:

- Must include a **justification**
- Apply **after** findings are generated
- Do **not** suppress **scan errors** (errors are not findings)

**Precedence** (highest priority first; master spec §13.4):

1. Fingerprint
2. Rule + exact location
3. Rule + exact endpoint
4. Rule + path glob

A finding is suppressed if **any** rule matches. For `suppression_reason` attribution, use the **highest-priority** match; within the same tier, use the **first** matching rule in config file order.

## Policies Affecting Exit Code

A finding contributes to fail (exit **1**) only if:

- `severity` ≥ configured fail-on severity, **and**
- `confidence` ≥ configured confidence threshold, **and**
- `suppressed` is false

Exit **2** applies for usage/config/runtime/module failure per V1 default, independent of finding counts.

## Versioned Documents

Config must support **versioned** config documents (`config_version` and schema evolution). Implementation should reject or migrate unknown versions explicitly.
