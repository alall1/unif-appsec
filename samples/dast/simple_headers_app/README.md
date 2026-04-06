# simple_headers_app

## What this sample does

Exposes simple endpoints without explicitly setting security headers.

## Vulnerable or safe

Intentionally weak/misconfigured for DAST passive checks.

## Intended engine(s)

- DAST (primary)

## Expected findings

Should appear:

- missing or weak security-header findings (for example CSP, HSTS, X-Frame-Options, X-Content-Type-Options if your checks cover them)

## Run

```bash
python samples/dast/simple_headers_app/app.py
```

## Scan

```bash
appsec scan http://127.0.0.1:5101 --dast --format json --output out/dast-headers.json
```
