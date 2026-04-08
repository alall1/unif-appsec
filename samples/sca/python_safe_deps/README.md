# python_safe_deps

## What this sample does
Provides a minimal Python dependency manifest pinned to the non-vulnerable fixed version used by the local advisory fixture.

## Vulnerability status
Safe baseline for the implemented advisory scope.

## Intended engine(s)
SCA only.

## Expected findings
- Should not emit SCA findings for the included dependency

## Run / scan

```bash
appsec scan samples/sca/python_safe_deps --sca --format json --output out/sca-safe.json
```
