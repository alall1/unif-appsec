# simple_cors_app

## What this sample does

Returns deliberately permissive CORS headers on all responses.

## Vulnerable or safe

Intentionally misconfigured.

## Intended engine(s)

- DAST (primary)

## Expected findings

Should appear:

- overly permissive CORS findings (`*` origin, wildcard headers, credential-related issues)

## Run

```bash
python samples/dast/simple_cors_app/app.py
```

## Scan

```bash
appsec scan http://127.0.0.1:5104 --dast --format json --output out/dast-cors.json
```
