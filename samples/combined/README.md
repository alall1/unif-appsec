# Combined Samples (SAST + DAST + additive V2 inputs)

These apps are designed so the same target can be used across engines without expanding beyond implemented scope.

## Targets

- `flask_vulnerable_app`: intentionally vulnerable Flask routes for SAST + DAST
- `flask_safe_app`: safer mirror of route structure for SAST + DAST baseline
- `app_with_vulnerable_requirements`: Flask app paired with vulnerable `requirements.txt` for SCA
- `app_with_safe_terraform`: Flask app paired with safe Terraform baseline for IaC

## Why these exist

They provide practical end-to-end demo targets for:

- screenshots and onboarding examples
- regression checks across multiple modules
- sanity checks for false-positive resistance
