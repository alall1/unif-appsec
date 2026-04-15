# Samples for Unified AppSec Platform (V1 + additive V2)

This directory contains small, realistic, local-first targets for validating the platform end to end without changing core behavior.

- `sast/`: Python static-analysis fixtures (vulnerable, safe, and near-miss patterns)
- `dast/`: HTTP/API targets for passive and active DAST checks
- `sca/`: Python dependency manifest fixtures for constrained V2 SCA scope
- `iac/`: Terraform `.tf` fixtures for constrained V2 IaC scope
- `combined/`: Flask applications and paired manifests/IaC for multi-engine workflows

These samples intentionally follow `docs/master_spec.md` boundaries:

- SAST: Python AST/taint scope only
- DAST: HTTP/API-first checks only (no browser-heavy SPA assumptions)
- SCA: Python manifest/lockfile-first (`requirements.txt`, `poetry.lock`, `Pipfile.lock`)
- IaC: Terraform `.tf` only
- No advanced auth, SSO, MFA, or unsupported ecosystems/formats

## Quick Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r samples/requirements.txt
```

## Run All Samples Script

Use the bundled script to install required libraries, run each sample through the scanner once, and aggregate outputs under `samples/output/`.

```bash
python3 samples/run_all_samples.py
```

What it does:

- creates/uses repo-local `.venv`
- installs scanner package (`pip install -e .`) and sample runtime deps
- runs one scan per sample target across SAST, DAST, SCA, and IaC-relevant fixtures
- writes per-scan JSON outputs and logs in a timestamped run directory:
  - `samples/output/<timestamp>/results/`
  - `samples/output/<timestamp>/logs/`
  - `samples/output/<timestamp>/summary.json`
  - `samples/output/<timestamp>/summary.md`
- updates `samples/output/LATEST_RUN.txt` with the most recent run path

## Suggested Engine-to-Sample Mapping

### SAST
- `sast/python_command_injection`: command injection (plus shell usage contrast)
- `sast/python_eval_exec_injection`: eval/exec sinks and near-miss static eval
- `sast/python_sql_injection`: string-built SQL vs parameterized query
- `sast/python_path_traversal`: unsafe path join vs normalized boundary check
- `sast/python_weak_crypto`: MD5/SHA1 weak usage vs stronger alternatives
- `sast/python_safe_patterns`: safe allowlist/literal parsing and false-positive resistance

### DAST
- `dast/simple_headers_app`: missing security headers
- `dast/simple_reflection_app`: reflected input behavior
- `dast/simple_error_leak_app`: debug/info leak and SQL-like error signatures
- `dast/simple_cors_app`: permissive CORS headers
- `dast/simple_api_target`: API-first endpoint and parameter coverage (OpenAPI seed included)

### SCA
- `sca/python_vulnerable_deps`: `requests==2.31.0` (expected advisory match in local fixture DB)
- `sca/python_safe_deps`: `requests==2.32.0` (expected clean for the same advisory)

### IaC
- `iac/terraform_public_ingress`: public ingress wildcard CIDR finding
- `iac/terraform_unencrypted_storage`: missing S3 encryption and weak public access block
- `iac/terraform_safe_baseline`: safe baseline for the same check families

### Combined
- `combined/flask_vulnerable_app`: combined SAST + DAST vulnerable target
- `combined/flask_safe_app`: safer mirror routes for reduced findings
- `combined/app_with_vulnerable_requirements`: Flask app + vulnerable `requirements.txt` (SAST/DAST/SCA)
- `combined/app_with_safe_terraform`: Flask app + safe Terraform baseline (SAST/DAST + IaC no-findings baseline)

## What These Samples Intentionally Do Not Cover

- IAST/runtime instrumentation (deferred to V3)
- Browser automation, SPA route execution, or JavaScript-heavy crawling
- Complex SSO/MFA or deep auth workflows
- Non-Python SCA ecosystems and non-Terraform IaC formats
- Reachability/exploitability analysis for SCA
- Live cloud-state validation for IaC
