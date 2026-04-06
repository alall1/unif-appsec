from __future__ import annotations

from typing import Iterator

from core.findings.models import DastEvidence

from modules.dast.checks.base import AuditContext
from modules.dast.discovery.models import DiscoveredEndpoint
from modules.dast.findings.mapper import RawDastFinding
from modules.dast.http.client import HttpResponse


class InsecureCookieFlagsCheck:
    rule_id = "dast.passive.insecure_cookie_flags"

    def analyze(
        self, ctx: AuditContext, ep: DiscoveredEndpoint, baseline: HttpResponse
    ) -> Iterator[RawDastFinding]:
        if not baseline.request_url.lower().startswith("https://"):
            return
        sc = baseline.headers.get("set-cookie")
        if not sc:
            return
        low = sc.lower()
        issues: list[str] = []
        if "secure" not in low:
            issues.append("missing Secure")
        if "httponly" not in low and "session" in low:
            issues.append("session-like cookie without HttpOnly")
        if not issues:
            return
        yield RawDastFinding(
            rule_id=self.rule_id,
            title="Set-Cookie flags may be weak for HTTPS responses",
            severity="low",
            confidence="medium",
            category="misconfiguration",
            method=baseline.request_method,
            url=baseline.request_url,
            parameter=None,
            endpoint_signature=None,
            description="Observed Set-Cookie without recommended flags for HTTPS contexts.",
            dast_evidence=DastEvidence(
                request_summary=f"{baseline.request_method} {baseline.request_url}",
                observed_behavior="; ".join(issues),
                matched_payload=sc[:500],
                response_summary=f"HTTP {baseline.status_code}",
            ),
        )
