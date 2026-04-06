from __future__ import annotations

from typing import Iterator

from core.findings.models import DastEvidence

from modules.dast.checks.base import AuditContext
from modules.dast.discovery.models import DiscoveredEndpoint
from modules.dast.findings.mapper import RawDastFinding
from modules.dast.http.client import HttpResponse


class PermissiveCorsCheck:
    rule_id = "dast.passive.permissive_cors"

    def analyze(
        self, ctx: AuditContext, ep: DiscoveredEndpoint, baseline: HttpResponse
    ) -> Iterator[RawDastFinding]:
        h = {k.lower(): v for k, v in baseline.headers.items()}
        acao = h.get("access-control-allow-origin")
        acc = h.get("access-control-allow-credentials", "").lower()
        if not acao:
            return
        if acao.strip() == "*" and "true" in acc:
            yield RawDastFinding(
                rule_id=self.rule_id,
                title="Permissive CORS with credentials",
                severity="medium",
                confidence="medium",
                category="misconfiguration",
                method=baseline.request_method,
                url=baseline.request_url,
                parameter=None,
                endpoint_signature=None,
                description="Access-Control-Allow-Origin is wildcard while credentials are allowed, which browsers should block — often indicates risky CORS configuration drift.",
                dast_evidence=DastEvidence(
                    request_summary=f"{baseline.request_method} {baseline.request_url}",
                    observed_behavior="ACAO=* with Access-Control-Allow-Credentials: true",
                    response_markers=[acao, acc],
                    response_summary=f"HTTP {baseline.status_code}",
                ),
                correlation={"endpoint": baseline.request_url},
            )
