# simple_api_target

## What this sample does

Provides a small API-first target with explicit query parameters and an OpenAPI document for discovery seeding.

## Vulnerable or safe

Mixed:

- reflective behavior at `/reflect`
- SQLi-like error behavior at `/sql`
- neutral endpoints (`/health`, `/items`)

## Intended engine(s)

- DAST (primary)

## Expected findings

Should appear:

- reflected input indicators on `/reflect`
- SQLi-like error indicators on `/sql` for specific payloads

Should not appear:

- severe findings on `/health` and standard `/items` responses unless your policy flags generic hardening issues

## Run

```bash
uvicorn app:app --app-dir samples/dast/simple_api_target --host 127.0.0.1 --port 5105
```

## Scan

```bash
appsec scan http://127.0.0.1:5105 --dast --format json --output out/dast-api-target.json
```

If your DAST module supports OpenAPI input:

```bash
appsec scan http://127.0.0.1:5105 --dast --openapi samples/dast/simple_api_target/openapi.yaml --format json --output out/dast-api-target-openapi.json
```
