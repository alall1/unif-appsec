from __future__ import annotations

from typing import Iterator

from core.findings.models import DastEvidence

from modules.dast.checks.base import AuditContext
from modules.dast.discovery.models import DiscoveredEndpoint
from modules.dast.findings.mapper import RawDastFinding
from modules.dast.http.client import HttpResponse


class HttpTraceEnabledCheck:
    rule_id = "dast.active.http_trace_enabled"

    def probe(
        self, ctx: AuditContext, ep: DiscoveredEndpoint, baseline: HttpResponse
    ) -> Iterator[RawDastFinding]:
        if ctx.active_depth() < 2:
            return
        url = baseline.request_url
        resp = ctx.client.request("TRACE", url, headers=ctx.auth.request_headers())
        ctx.auth.absorb_set_cookie(resp)
        if resp.status_code >= 400:
            return
        if baseline.request_method.upper() in resp.body_text.upper():
            yield RawDastFinding(
                rule_id=self.rule_id,
                title="HTTP TRACE may be enabled",
                severity="low",
                confidence="low",
                category="misconfiguration",
                method="TRACE",
                url=url,
                parameter=None,
                endpoint_signature=None,
                description="TRACE echoed request-line-like content; many proxies normalize this — verify server policy.",
                dast_evidence=DastEvidence(
                    request_summary=f"TRACE {url}",
                    response_summary=f"HTTP {resp.status_code}",
                    observed_behavior="TRACE response appeared to echo request data",
                    baseline_comparison=f"baseline_method={baseline.request_method}",
                ),
            )
