# app_with_vulnerable_requirements

## What this sample does
Provides a small Flask API target and a colocated `requirements.txt` that includes a vulnerable dependency version expected by the local SCA advisory fixture.

## Vulnerability status
Mixed by design:
- App routes are simple and mostly neutral for SAST
- DAST can still exercise reflection behavior
- SCA should report vulnerable dependency findings

## Intended engine(s)
SAST + DAST + SCA.

## Expected findings
- SCA: finding for `requests==2.31.0`
- DAST: possible reflected-input style observations from `/reflect`
- SAST: likely low/no findings (acts as a false-positive resistance target for code)

## Run target

```bash
source .venv/bin/activate
python samples/combined/app_with_vulnerable_requirements/app.py
```

## Scan examples

```bash
appsec scan samples/combined/app_with_vulnerable_requirements --sast --sca --format json --output out/combined-vuln-req-code.json
appsec scan http://127.0.0.1:5203 --dast --format json --output out/combined-vuln-req-dast.json
```
