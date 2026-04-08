# app_with_safe_terraform

## What this sample does
Provides a small safe-ish Flask service plus a colocated Terraform file that should pass the implemented IaC baseline checks.

## Vulnerability status
Safe baseline for IaC and mostly safe for DAST passive checks.

## Intended engine(s)
SAST + DAST + IaC.

## Expected findings
- IaC: no findings expected on `main.tf`
- DAST: reduced passive findings due to basic security headers
- SAST: no obvious high-confidence findings expected

## Run target

```bash
source .venv/bin/activate
python samples/combined/app_with_safe_terraform/app.py
```

## Scan examples

```bash
appsec scan samples/combined/app_with_safe_terraform --sast --iac --format json --output out/combined-safe-tf-code.json
appsec scan http://127.0.0.1:5204 --dast --format json --output out/combined-safe-tf-dast.json
```
