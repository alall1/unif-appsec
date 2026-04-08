# python_vulnerable_deps

## What this sample does
Provides a minimal Python dependency manifest with a known vulnerable version from the platform's local advisory fixture dataset.

## Vulnerability status
Vulnerable by design.

## Intended engine(s)
SCA only.

## Expected findings
- Should emit one or more SCA findings for `requests==2.31.0`
- Expected advisory id/source should map to the local fixture advisory set

## Run / scan

```bash
appsec scan samples/sca/python_vulnerable_deps --sca --format json --output out/sca-vulnerable.json
```
