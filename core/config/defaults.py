from __future__ import annotations

from typing import Any

PROFILE_NAMES = ("fast", "balanced", "deep")


def _base_profile_shell() -> dict[str, Any]:
    return {
        "config_version": "1",
        "scan": {
            "modules": [],
            "profile": "balanced",
            "include_paths": [],
            "exclude_paths": [],
        },
        "output": {
            "format": "json",
            "path": "appsec-results.json",
            "pretty": False,
            "sarif": {"enabled": False, "path": None},
        },
        "policies": {
            "fail_on_severity": "medium",
            "confidence_threshold": "low",
        },
        "limits": {
            "max_scan_duration_seconds": 600,
            "max_findings_per_module": 5000,
            "max_evidence_bytes": 65536,
            "max_crawl_depth": 2,
            "max_requests_per_minute": 120,
            "max_response_body_bytes": 262144,
        },
        "sast": {},
        "dast": {},
        "suppressions": [],
    }


def profile_defaults(profile: str) -> dict[str, Any]:
    if profile not in PROFILE_NAMES:
        raise ValueError(f"Unknown profile: {profile!r}; expected one of {PROFILE_NAMES}")

    base = _base_profile_shell()

    if profile == "fast":
        base["limits"].update(
            {
                "max_scan_duration_seconds": 120,
                "max_findings_per_module": 1000,
                "max_evidence_bytes": 32768,
                "max_crawl_depth": 1,
                "max_requests_per_minute": 60,
                "max_response_body_bytes": 131072,
            }
        )
        base["sast"] = {"max_taint_depth": 2}
        base["dast"] = {"crawl": {"enabled": False}}
    elif profile == "balanced":
        base["sast"] = {"max_taint_depth": 4}
        base["dast"] = {"crawl": {"enabled": True}}
    else:  # deep
        base["limits"].update(
            {
                "max_scan_duration_seconds": 3600,
                "max_findings_per_module": 20000,
                "max_evidence_bytes": 131072,
                "max_crawl_depth": 4,
                "max_requests_per_minute": 240,
                "max_response_body_bytes": 524288,
            }
        )
        base["sast"] = {"max_taint_depth": 8}
        base["dast"] = {"crawl": {"enabled": True}}

    base["scan"]["profile"] = profile
    return base
