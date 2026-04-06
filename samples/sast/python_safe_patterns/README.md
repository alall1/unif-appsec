# python_safe_patterns

## What this sample does

Provides safer constructions and near-miss patterns that should help evaluate false-positive resistance.

## Vulnerable or safe

Primarily safe:

- safe: allowlisted subprocess execution with argument list
- safe: `ast.literal_eval` for structured literal parsing
- near-miss: static `exec` usage to test policy vs taint behavior

## Intended engine(s)

- SAST (primary)

## Expected findings

Should ideally not appear:

- command injection finding on allowlist + list-arg subprocess call
- eval/exec injection finding for `ast.literal_eval`

May appear depending on rule strictness:

- policy-style finding for any `exec` use, even with constant input

## Run

```bash
python samples/sast/python_safe_patterns/app.py
```

## Scan

```bash
appsec scan samples/sast/python_safe_patterns --sast --format json --output out/sast-safe-patterns.json
```
