from __future__ import annotations

from typing import Iterator

from core.findings.models import DastEvidence

from modules.dast.checks.base import AuditContext
from modules.dast.checks.util import INFO_LEAK_MARKERS, contains_any
from modules.dast.discovery.models import DiscoveredEndpoint
from modules.dast.findings.mapper import RawDastFinding
from modules.dast.http.client import HttpResponse


class InfoLeakCheck:
    rule_id = "dast.passive.info_disclosure"

    def analyze(
        self, ctx: AuditContext, ep: DiscoveredEndpoint, baseline: HttpResponse
    ) -> Iterator[RawDastFinding]:
        hits = contains_any(baseline.body_text, INFO_LEAK_MARKERS)
        if not hits:
            return
        srv = baseline.headers.get("Server") or baseline.headers.get("server")
        markers = list(hits)
        if srv:
            markers.append(f"Server: {srv}")
        yield RawDastFinding(
            rule_id=self.rule_id,
            title="Possible debug or sensitive information in HTTP response",
            severity="low",
            confidence="low",
            category="information_disclosure",
            method=baseline.request_method,
            url=baseline.request_url,
            parameter=None,
            endpoint_signature=None,
            description="Response body or headers matched common debug or secret markers; verify this is not exposed in production.",
            dast_evidence=DastEvidence(
                request_summary=f"{baseline.request_method} {baseline.request_url}",
                observed_behavior=f"Matched markers: {', '.join(hits)}",
                response_markers=markers,
                response_summary=f"HTTP {baseline.status_code}, body length {len(baseline.body_text)}",
            ),
            correlation={"endpoint": baseline.request_url},
        )


class ServerDisclosureCheck:
    rule_id = "dast.passive.server_version_disclosure"

    def analyze(
        self, ctx: AuditContext, ep: DiscoveredEndpoint, baseline: HttpResponse
    ) -> Iterator[RawDastFinding]:
        srv = baseline.headers.get("Server") or baseline.headers.get("server")
        if not srv or "/" not in srv:
            return
        yield RawDastFinding(
            rule_id=self.rule_id,
            title="Server header exposes product version",
            severity="info",
            confidence="high",
            category="information_disclosure",
            method=baseline.request_method,
            url=baseline.request_url,
            parameter=None,
            endpoint_signature=None,
            description="Server header includes a version string that can aid attackers in targeting known issues.",
            remediation="Remove version details from the Server header where practical.",
            dast_evidence=DastEvidence(
                request_summary=f"{baseline.request_method} {baseline.request_url}",
                observed_behavior=f"Server: {srv}",
                response_markers=[srv],
                response_summary=f"HTTP {baseline.status_code}",
            ),
        )
