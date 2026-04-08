# IaC Samples (Terraform-only V2 scope)

These samples target the implemented Terraform IaC checks:

- public ingress wildcard CIDR
- S3 public access block completeness
- S3 server-side encryption required

## How to Scan

From repo root:

```bash
appsec scan samples/iac --iac --format json --output out/iac-samples.json
```

Or scan each sample folder independently for deterministic assertions.

## Expected Findings

- `terraform_public_ingress`: public ingress finding
- `terraform_unencrypted_storage`: encryption/public access block findings
- `terraform_safe_baseline`: no IaC findings
