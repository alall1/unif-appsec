# SCA Samples (Python-only V2 scope)

These samples target the implemented V2 SCA slice:

- ecosystem: `pypi`
- supported inputs: `requirements.txt`, `poetry.lock`, `Pipfile.lock`
- deterministic advisory matching against local fixture advisories

## How to Scan

From repo root:

```bash
appsec scan samples/sca --sca --format json --output out/sca-samples.json
```

Or scan one sample directory at a time for focused assertions.

## Expected Findings

- `python_vulnerable_deps`: should report a dependency finding for `requests==2.31.0`
- `python_safe_deps`: should report no SCA findings for the included package/version
