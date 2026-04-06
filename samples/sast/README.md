# SAST Samples (Python)

These samples target the V1 Python SAST engine and its required rule families:

- command injection
- eval/exec injection
- SQL injection
- path traversal
- weak crypto / weak hash use

They are intentionally small so traces and findings are easy to inspect.

## How to Scan

From repo root:

```bash
appsec scan samples/sast --sast --format json --output out/sast-samples.json
```

You can also scan each sample folder independently for focused testing.

## Directory Map

- `python_command_injection`: command execution sinks with untrusted input
- `python_eval_exec_injection`: focused eval/exec usage patterns
- `python_sql_injection`: dynamic SQL construction vs parameterized SQL
- `python_path_traversal`: untrusted file path handling vs safe path checks
- `python_weak_crypto`: weak hashes and weak random token patterns
- `python_safe_patterns`: safe and near-miss code to reduce false positives
