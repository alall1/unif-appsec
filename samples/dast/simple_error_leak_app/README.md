# simple_error_leak_app

## What this sample does

Returns explicit debug and SQL-like error markers for controlled DAST testing.

## Vulnerable or safe

Intentionally vulnerable/misconfigured.

## Intended engine(s)

- DAST (primary)

## Expected findings

Should appear:

- debug/info leak markers (traceback-style response)
- SQLi-like error behavior indicators when `'` payloads are tested against `/search`

## Run

```bash
python samples/dast/simple_error_leak_app/app.py
```

## Scan

```bash
appsec scan http://127.0.0.1:5103 --dast --format json --output out/dast-error-leak.json
```
