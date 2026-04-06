# simple_reflection_app

## What this sample does

Reflects request input back in JSON responses.

## Vulnerable or safe

Intentionally reflective for active-check behavior testing.

## Intended engine(s)

- DAST (primary)

## Expected findings

Should appear (depending on check policy/confidence thresholds):

- reflected input indicators
- potential reflected-XSS style indicator findings if payload reflection is detected

Note: reflection alone should generally avoid high-confidence XSS classification unless your engine has stronger confirmation logic.

## Run

```bash
python samples/dast/simple_reflection_app/app.py
```

## Scan

```bash
appsec scan http://127.0.0.1:5102 --dast --format json --output out/dast-reflection.json
```
