from __future__ import annotations

import urllib.parse
from typing import Iterator

from core.findings.models import DastEvidence

from modules.dast.checks.base import AuditContext
from modules.dast.discovery.models import DiscoveredEndpoint
from modules.dast.findings.mapper import RawDastFinding
from modules.dast.http.client import HttpResponse
from modules.dast.targeting.models import url_is_in_scope


_DEBUG_SUFFIXES = (
    ".env",
    "config.json",
    "debug",
    ".git/HEAD",
    "server-status",
)


class DebugExposureProbeCheck:
    rule_id = "dast.active.debug_or_sensitive_file_probe"

    def probe(
        self, ctx: AuditContext, ep: DiscoveredEndpoint, baseline: HttpResponse
    ) -> Iterator[RawDastFinding]:
        depth = ctx.active_depth()
        parts = urllib.parse.urlsplit(baseline.request_url)
        path = parts.path or "/"
        if path != "/" and not path.endswith("/"):
            path = path.rsplit("/", 1)[0] or "/"
        if not path.endswith("/"):
            path = path + "/"

        base = urllib.parse.urlunsplit((parts.scheme, parts.netloc, path, "", ""))
        max_probes = {1: 2, 2: 4, 3: len(_DEBUG_SUFFIXES)}.get(depth, 4)

        for suf in _DEBUG_SUFFIXES[:max_probes]:
            candidate = urllib.parse.urljoin(base, suf)
            if not url_is_in_scope(candidate, ctx.scope):
                continue
            resp = ctx.client.request("GET", candidate, headers=ctx.auth.request_headers())
            ctx.auth.absorb_set_cookie(resp)
            if resp.status_code not in (200, 203):
                continue
            body_low = resp.body_text.lower()
            suspicious = any(
                x in body_low
                for x in (
                    "aws_secret",
                    "begin rsa private",
                    "ref: refs/heads/",
                    "postgresql://",
                    "mysql://",
                )
            )
            if not suspicious and resp.status_code == 200 and len(resp.body_text) < 4000:
                if suf == ".env" and "=" in resp.body_text and "\n" in resp.body_text:
                    suspicious = True
            if not suspicious:
                continue

            yield RawDastFinding(
                rule_id=self.rule_id,
                title="Sensitive-looking file or debug endpoint may be exposed",
                severity="high",
                confidence="low",
                category="information_disclosure",
                method="GET",
                url=candidate,
                parameter=None,
                endpoint_signature=None,
                description=(
                    "A carefully scoped GET returned content resembling secrets or repository metadata. "
                    "Confirm whether this URL should be public."
                ),
                dast_evidence=DastEvidence(
                    request_summary=f"GET {candidate}",
                    response_summary=f"HTTP {resp.status_code}, len={len(resp.body_text)}",
                    observed_behavior="Heuristic match on response content",
                    baseline_comparison=f"probe_path={suf}",
                ),
            )
