# Combined Samples (SAST + DAST)

These apps are designed so the same target can be used in:

- SAST scans against Python source
- DAST scans against a running HTTP service

## Targets

- `flask_vulnerable_app`: intentionally vulnerable and noisy
- `flask_safe_app`: similar route layout with safer implementations

## Why these exist

They provide practical end-to-end demo targets for:

- screenshots and onboarding examples
- regression checks across both modules
- confidence threshold and false-positive tuning
