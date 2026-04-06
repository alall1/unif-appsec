# python_eval_exec_injection

## What this sample does

Shows direct `eval` and `exec` usage with user-controlled input, plus safer/near-miss cases.

## Vulnerable or safe

Mixed:

- vulnerable: `vulnerable_eval`, `vulnerable_exec`
- safe comparison: `safe_literal_eval`
- near-miss: `near_miss_static_eval` (constant string)

## Intended engine(s)

- SAST (primary)

## Expected findings

Should appear:

- eval/exec injection findings on `eval(expression)` and `exec(code)`

Should ideally not appear:

- `ast.literal_eval(...)` as code-exec injection
- constant-only `eval("1 + 1")` as tainted-flow injection

## Run

```bash
python samples/sast/python_eval_exec_injection/app.py
```

## Scan

```bash
appsec scan samples/sast/python_eval_exec_injection --sast --format json --output out/sast-eval-exec.json
```
