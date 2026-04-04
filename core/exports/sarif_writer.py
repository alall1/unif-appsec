"""
SARIF-ready export design (§15.2).

Mapping (informative, for future implementation):
- Each Finding maps to a SARIF Result.
- rule_id -> reportingDescriptorReference.id
- locations/code -> physicalLocation + region from CodeLocation
- locations/http -> artifactLocation uri for url + webRequest/response where applicable
- fingerprints -> partialFingerprints or fingerprints array using fp1 digest material
- evidence -> codeFlows / relatedLocations for traces; properties bag for DAST summaries

Core keeps SARIF construction out of modules; this module is reserved for a future
minimal SARIF 2.1.0 writer without coupling engines to CLI.
"""

from __future__ import annotations

from typing import Any


def sarif_tool_metadata_stub() -> dict[str, Any]:
    """Placeholder tool/driver block for future SARIF output."""
    return {
        "driver": {
            "name": "unif-appsec",
            "informationUri": "https://example.invalid/unif-appsec",
            "rules": [],
        }
    }
