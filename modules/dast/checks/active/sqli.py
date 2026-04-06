from __future__ import annotations

from typing import Iterator

from core.findings.models import DastEvidence

from modules.dast.checks.base import AuditContext
from modules.dast.checks.util import SQL_ERROR_MARKERS, contains_any
from modules.dast.discovery.models import DiscoveredEndpoint
from modules.dast.findings.mapper import RawDastFinding
from modules.dast.http.client import HttpResponse, replace_path_param, with_query_param


class SqlInjectionIndicatorCheck:
    rule_id = "dast.active.sql_injection_indicator"

    def probe(
        self, ctx: AuditContext, ep: DiscoveredEndpoint, baseline: HttpResponse
    ) -> Iterator[RawDastFinding]:
        if ep.method.upper() != "GET":
            return
        depth = ctx.active_depth()
        probes = ["'\"", "1' AND '1'='1"]
        if depth >= 3:
            probes.append("1' OR '1'='1' --")

        for point in ep.insertion_points:
            if point.location not in ("query", "path"):
                continue
            base_url = ep.url
            benign = "1"
            if point.location == "query":
                b_url = with_query_param(base_url, point.name, benign)
            else:
                b_url = replace_path_param(base_url, point.name, benign)
            b_resp = ctx.client.request("GET", b_url, headers=ctx.auth.request_headers())
            ctx.auth.absorb_set_cookie(b_resp)
            b_markers = set(contains_any(b_resp.body_text, SQL_ERROR_MARKERS))

            for payload in probes[:depth]:
                if point.location == "query":
                    t_url = with_query_param(base_url, point.name, payload)
                else:
                    t_url = replace_path_param(base_url, point.name, payload)
                t_resp = ctx.client.request("GET", t_url, headers=ctx.auth.request_headers())
                ctx.auth.absorb_set_cookie(t_resp)
                t_markers = set(contains_any(t_resp.body_text, SQL_ERROR_MARKERS))
                new_markers = sorted(t_markers - b_markers)
                only_in_probe = bool(new_markers)
                status_shift = b_resp.status_code != t_resp.status_code
                len_delta = abs(len(t_resp.body_text) - len(b_resp.body_text))

                if not new_markers and not (status_shift and len_delta > 50):
                    continue

                if only_in_probe and new_markers:
                    confidence = "medium"
                    severity = "medium"
                elif new_markers:
                    confidence = "low"
                    severity = "low"
                else:
                    confidence = "low"
                    severity = "low"

                baseline_comparison = (
                    f"baseline_status={b_resp.status_code} probe_status={t_resp.status_code} "
                    f"baseline_sql_markers={sorted(b_markers)} probe_sql_markers={sorted(t_markers)} "
                    f"new_markers={new_markers} len_delta={len_delta}"
                )

                req_s, _ = ctx.client.summarize_pair(b_resp)
                _, res_s = ctx.client.summarize_pair(t_resp)
                yield RawDastFinding(
                    rule_id=self.rule_id,
                    title="SQL error or differential response suggests possible SQL injection",
                    severity=severity,
                    confidence=confidence,
                    category="injection",
                    method="GET",
                    url=t_url,
                    parameter=point.name,
                    endpoint_signature=None,
                    description=(
                        "Database-style error text or a notable response change was observed compared to baseline. "
                        "Error text alone is treated as low confidence unless it appears only under probing."
                    ),
                    subcategory="sql_injection",
                    dast_evidence=DastEvidence(
                        request_summary=req_s,
                        response_summary=res_s,
                        matched_payload=payload,
                        observed_behavior=f"Markers: {new_markers or sorted(t_markers)}",
                        response_markers=new_markers or sorted(t_markers),
                        baseline_comparison=baseline_comparison,
                    ),
                    correlation={"parameter_name": point.name, "sink_type": "sql"},
                )
