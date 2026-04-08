# terraform_public_ingress

## What this sample does
Defines a security group with ingress open to the public internet (`0.0.0.0/0`).

## Vulnerability status
Vulnerable by design.

## Intended engine(s)
IaC only.

## Expected findings
- Public ingress wildcard CIDR finding on `aws_security_group.web_public`

## Run / scan

```bash
appsec scan samples/iac/terraform_public_ingress --iac --format json --output out/iac-public-ingress.json
```
