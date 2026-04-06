# python_path_traversal

## What this sample does

Compares unsafe file path usage against path canonicalization and base-directory enforcement.

## Vulnerable or safe

Mixed:

- vulnerable: `vulnerable_file_read`
- safe comparison: `safe_file_read`

## Intended engine(s)

- SAST (primary)

## Expected findings

Should appear:

- path traversal risk where untrusted filename reaches file read path construction

Should ideally not appear:

- path handling in `safe_file_read` using `resolve()` and base-path check

## Run

```bash
mkdir -p samples/sast/python_path_traversal/data
printf "hello\n" > samples/sast/python_path_traversal/data/hello.txt
python samples/sast/python_path_traversal/app.py
```

## Scan

```bash
appsec scan samples/sast/python_path_traversal --sast --format json --output out/sast-path-traversal.json
```
