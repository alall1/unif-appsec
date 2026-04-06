# flask_vulnerable_app

## What this sample does

Runs a small Flask app with intentionally weak HTTP behavior and includes unsafe helper functions in the same codebase for SAST coverage.

## Vulnerable or safe

Intentionally vulnerable.

## Intended engine(s)

- SAST
- DAST

## Expected findings

SAST should appear:

- command injection (`os.system` with `input()`)
- eval injection (`eval` with `input()`)
- SQL injection pattern in `cli_sql_helper`
- path traversal pattern around untrusted file path use

DAST should appear:

- reflected input behavior on `/reflect`
- SQLi-like error/debug leak behavior on `/error`
- potential missing security header findings

## Run

```bash
python samples/combined/flask_vulnerable_app/app.py
```

## Scan

SAST:

```bash
appsec scan samples/combined/flask_vulnerable_app --sast --format json --output out/combined-vuln-sast.json
```

DAST:

```bash
appsec scan http://127.0.0.1:5201 --dast --format json --output out/combined-vuln-dast.json
```

Combined run (if your config enables both):

```bash
appsec scan samples/combined/flask_vulnerable_app --all --target-url http://127.0.0.1:5201 --format json --output out/combined-vuln-all.json
```
