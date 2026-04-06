# flask_safe_app

## What this sample does

Provides a Flask app with similar structure to the vulnerable variant but using safer patterns.

## Vulnerable or safe

Primarily safe by design.

## Intended engine(s)

- SAST
- DAST

## Expected findings

SAST should ideally not appear for:

- SQL injection (parameterized query in `safe_sql_lookup`)
- weak hash use (SHA-256 only)
- eval/exec injection (uses `ast.literal_eval` instead)
- path traversal (resolved path constrained to base directory)

DAST should ideally show fewer/no findings for:

- missing security headers (explicitly added)
- error/info leak behavior (no debug-style error route)

Potential low-confidence observations may still appear for reflected data at `/reflect` depending on scanner policy.

## Run

```bash
python samples/combined/flask_safe_app/app.py
```

## Scan

SAST:

```bash
appsec scan samples/combined/flask_safe_app --sast --format json --output out/combined-safe-sast.json
```

DAST:

```bash
appsec scan http://127.0.0.1:5202 --dast --format json --output out/combined-safe-dast.json
```
