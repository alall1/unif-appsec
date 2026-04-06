from __future__ import annotations

from typing import Iterator

from core.findings.models import DastEvidence

from modules.dast.checks.base import AuditContext
from modules.dast.discovery.models import DiscoveredEndpoint
from modules.dast.findings.mapper import RawDastFinding
from modules.dast.http.client import HttpResponse


class SecurityHeadersCheck:
    rule_id = "dast.passive.missing_security_headers"

    def analyze(
        self, ctx: AuditContext, ep: DiscoveredEndpoint, baseline: HttpResponse
    ) -> Iterator[RawDastFinding]:
        h = {k.lower(): v for k, v in baseline.headers.items()}
        missing: list[str] = []
        if "x-content-type-options" not in h:
            missing.append("X-Content-Type-Options")
        if "x-frame-options" not in h and "content-security-policy" not in h:
            missing.append("X-Frame-Options or Content-Security-Policy frame-ancestors")
        if "content-security-policy" not in h:
            missing.append("Content-Security-Policy")
        if "strict-transport-security" not in h and baseline.request_url.lower().startswith("https://"):
            missing.append("Strict-Transport-Security")
        if "referrer-policy" not in h:
            missing.append("Referrer-Policy")

        if not missing:
            return
        req_s = f"{baseline.request_method} {baseline.request_url}"
        yield RawDastFinding(
            rule_id=self.rule_id,
            title="Missing recommended HTTP security headers",
            severity="low",
            confidence="medium",
            category="misconfiguration",
            method=baseline.request_method,
            url=baseline.request_url,
            parameter=None,
            endpoint_signature=None,
            description="Response omitted common security headers that reduce browser-level attack surface.",
            remediation="Add the listed headers appropriate to your application.",
            dast_evidence=DastEvidence(
                request_summary=req_s,
                observed_behavior=f"Missing: {', '.join(missing)}",
                response_markers=missing,
                response_summary=f"HTTP {baseline.status_code} without listed headers",
            ),
            correlation={"endpoint": baseline.request_url},
        )
