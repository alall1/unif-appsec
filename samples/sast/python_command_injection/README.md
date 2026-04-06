# python_command_injection

## What this sample does

Demonstrates unsafe command execution patterns with user-controlled input.

## Vulnerable or safe

Mixed:

- vulnerable: `vulnerable_os_system`, `vulnerable_subprocess_shell`
- safer comparison: `safe_subprocess_usage`

## Intended engine(s)

- SAST (primary)

## Expected findings

Should appear:

- command injection on `os.system(...)`
- command injection on `subprocess.run(..., shell=True, ...)` with untrusted input

Should ideally not appear (or lower confidence depending on rule modeling):

- false positive on `safe_subprocess_usage` where input is escaped before use

## Run

```bash
python samples/sast/python_command_injection/app.py
```

## Scan

```bash
appsec scan samples/sast/python_command_injection --sast --format json --output out/sast-command-injection.json
```
