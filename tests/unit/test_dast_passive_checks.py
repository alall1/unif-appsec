from __future__ import annotations

from email.message import EmailMessage

from core.config.models import LimitsConfig

from modules.dast.checks.base import AuditContext
from modules.dast.checks.passive.headers import SecurityHeadersCheck
from modules.dast.discovery.models import DiscoveredEndpoint
from modules.dast.http.client import HttpResponse
from modules.dast.targeting.models import ScopePolicy


def _resp(url: str) -> HttpResponse:
    h = EmailMessage()
    h["Content-Type"] = "text/html"
    return HttpResponse(
        url=url,
        status_code=200,
        headers={"content-type": "text/html"},
        body_text="<html></html>",
        request_method="GET",
        request_url=url,
        request_headers={},
    )


def test_security_headers_finding_when_absent() -> None:
    ctx = AuditContext(
        profile="fast",
        client=None,  # type: ignore[arg-type]
        auth=None,  # type: ignore[arg-type]
        limits=LimitsConfig(),
        scope=ScopePolicy(frozenset({"https://ex.test"})),
        scan_token="abcd",
        scan_context=None,  # type: ignore[arg-type]
    )
    ep = DiscoveredEndpoint(method="GET", url="https://ex.test/", source="target")
    chk = SecurityHeadersCheck()
    findings = list(chk.analyze(ctx, ep, _resp("https://ex.test/")))
    assert len(findings) == 1
    assert findings[0].rule_id == SecurityHeadersCheck.rule_id
    assert findings[0].dast_evidence.response_markers
