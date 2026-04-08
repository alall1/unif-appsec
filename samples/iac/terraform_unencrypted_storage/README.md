# terraform_unencrypted_storage

## What this sample does
Defines S3 resources with incomplete public access block settings and a bucket missing server-side encryption configuration.

## Vulnerability status
Vulnerable by design.

## Intended engine(s)
IaC only.

## Expected findings
- S3 public access block not fully enabled
- S3 bucket missing server-side encryption

## Run / scan

```bash
appsec scan samples/iac/terraform_unencrypted_storage --iac --format json --output out/iac-unencrypted-storage.json
```
