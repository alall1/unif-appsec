# python_weak_crypto

## What this sample does

Contains weak hash usage and safer alternatives.

## Vulnerable or safe

Mixed:

- vulnerable: `hashlib.md5`, `hashlib.sha1`
- safer comparisons: `hashlib.sha256`, `secrets.token_urlsafe`

## Intended engine(s)

- SAST (primary)

## Expected findings

Should appear:

- weak crypto/hash findings for MD5 and SHA1 usage

Should ideally not appear:

- SHA-256 usage
- `secrets` token generation

## Run

```bash
python samples/sast/python_weak_crypto/app.py
```

## Scan

```bash
appsec scan samples/sast/python_weak_crypto --sast --format json --output out/sast-weak-crypto.json
```
