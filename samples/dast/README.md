# DAST Samples (HTTP/API-first)

These targets are lightweight HTTP/API applications for V1 DAST checks:

- passive checks (headers, CORS, leak markers)
- active checks (reflected input, SQLi-like response behavior, simple response-based checks)
- API-first endpoint discovery (including OpenAPI for one target)

## Common Setup

From repo root:

```bash
python -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r samples/requirements.txt
```

Run one app at a time on its documented port.

## Scan Example

```bash
appsec scan http://127.0.0.1:5101 --dast --format json --output out/dast-sample.json
```

For the API target, optionally provide OpenAPI input if your CLI/config supports it.
