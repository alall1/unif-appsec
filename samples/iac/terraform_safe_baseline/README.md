# terraform_safe_baseline

## What this sample does
Provides a minimal Terraform baseline with non-public ingress, full S3 public access block settings, and S3 encryption configured.

## Vulnerability status
Safe baseline.

## Intended engine(s)
IaC only.

## Expected findings
- Should not emit IaC findings for the implemented baseline rules

## Run / scan

```bash
appsec scan samples/iac/terraform_safe_baseline --iac --format json --output out/iac-safe-baseline.json
```
