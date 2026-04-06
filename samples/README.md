# Samples for Unified AppSec Platform (V1)

This directory contains small, realistic, local-first targets for validating the V1 platform end to end:

- `sast/`: Python static-analysis fixtures (vulnerable, safe, and near-miss patterns)
- `dast/`: HTTP/API targets for passive and active DAST checks
- `combined/`: Flask applications that are useful for both SAST and DAST workflows

These samples are intentionally scoped to current V1 capabilities from `docs/master_spec.md`:

- Core + SAST + DAST only
- Python-focused SAST
- HTTP/API-first DAST
- No browser-heavy SPA requirements
- No advanced SSO/MFA flows

## Quick Start

Create one virtual environment at repo root and reuse it for samples:

```bash
python -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r samples/requirements.txt
```

Then run any sample using the commands in that sample's README.

## Suggested V1 Finding Mapping

### SAST Targets

- `sast/python_command_injection`: command injection + eval/exec injection
- `sast/python_eval_exec_injection`: eval/exec injection (focused)
- `sast/python_sql_injection`: SQL injection
- `sast/python_path_traversal`: path traversal
- `sast/python_weak_crypto`: weak hash/crypto usage
- `sast/python_safe_patterns`: false-positive resistance and safe constructions

### DAST Targets

- `dast/simple_headers_app`: missing security headers
- `dast/simple_reflection_app`: reflected input behavior
- `dast/simple_error_leak_app`: debug/info leak markers and SQL-like error signatures
- `dast/simple_cors_app`: overly permissive CORS
- `dast/simple_api_target`: API-first discovery/audit workflows (including OpenAPI seeding)

### Combined Targets

- `combined/flask_vulnerable_app`: intentionally vulnerable routes and unsafe helper code
- `combined/flask_safe_app`: safer equivalents with similar route structure
