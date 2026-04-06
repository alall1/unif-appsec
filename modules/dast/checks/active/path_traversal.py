from __future__ import annotations

import re
from typing import Iterator

from core.findings.models import DastEvidence

from modules.dast.checks.base import AuditContext
from modules.dast.discovery.models import DiscoveredEndpoint
from modules.dast.findings.mapper import RawDastFinding
from modules.dast.http.client import HttpResponse, replace_path_param, with_query_param


_PARAM_NAME_RE = re.compile(r"(file|path|filepath|document|folder|page|dir)", re.IGNORECASE)


def _endpoint_allows_path_traversal(ep: DiscoveredEndpoint) -> bool:
    low = ep.url.lower()
    if re.search(r"(download|file|path|read)", low):
        return True
    for p in ep.insertion_points:
        if _PARAM_NAME_RE.search(p.name):
            return True
    return False


class PathTraversalProbeCheck:
    rule_id = "dast.active.path_traversal_probe"

    def probe(
        self, ctx: AuditContext, ep: DiscoveredEndpoint, baseline: HttpResponse
    ) -> Iterator[RawDastFinding]:
        if ep.method.upper() != "GET" or not _endpoint_allows_path_traversal(ep):
            return
        payload = "....//....//....//etc/passwd"

        for point in ep.insertion_points:
            if point.location not in ("query", "path"):
                continue
            if not _PARAM_NAME_RE.search(point.name) and point.location == "query":
                continue
            base_url = ep.url
            benign = "index.txt"
            if point.location == "query":
                b_url = with_query_param(base_url, point.name, benign)
                t_url = with_query_param(base_url, point.name, payload)
            else:
                b_url = replace_path_param(base_url, point.name, benign)
                t_url = replace_path_param(base_url, point.name, payload)

            b_resp = ctx.client.request("GET", b_url, headers=ctx.auth.request_headers())
            t_resp = ctx.client.request("GET", t_url, headers=ctx.auth.request_headers())
            ctx.auth.absorb_set_cookie(t_resp)

            passwd_hint = "root:" in t_resp.body_text and "root:" not in b_resp.body_text
            if not passwd_hint:
                continue

            yield RawDastFinding(
                rule_id=self.rule_id,
                title="Possible path traversal — /etc/passwd-like content in response",
                severity="high",
                confidence="low",
                category="path_traversal",
                method="GET",
                url=t_url,
                parameter=point.name,
                endpoint_signature=None,
                description=(
                    "Probe produced passwd-like markers not seen in baseline. "
                    "Many applications echo paths; confirm with manual review."
                ),
                dast_evidence=DastEvidence(
                    request_summary=f"GET {t_url}",
                    response_summary=f"HTTP {t_resp.status_code}, body_len={len(t_resp.body_text)}",
                    matched_payload=payload,
                    observed_behavior="Possible Unix passwd file markers in probe response only",
                    baseline_comparison=(
                        f"baseline_has_root_colon={'root:' in b_resp.body_text} "
                        f"probe_has_root_colon={'root:' in t_resp.body_text}"
                    ),
                ),
            )
