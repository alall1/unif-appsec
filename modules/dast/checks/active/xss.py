from __future__ import annotations

import re
from typing import Iterator

from core.findings.models import DastEvidence

from modules.dast.checks.base import AuditContext
from modules.dast.discovery.models import DiscoveredEndpoint
from modules.dast.findings.mapper import RawDastFinding
from modules.dast.http.client import HttpResponse, with_query_param, replace_path_param


def _xss_context_score(body: str, token: str) -> tuple[int, list[str]]:
    """Higher score => more dangerous reflection context (not normative XSS proof)."""
    markers: list[str] = []
    score = 0
    if token not in body:
        return 0, markers
    idx = body.find(token)
    window = body[max(0, idx - 80) : idx + len(token) + 80]
    if re.search(r"<script[^>]*>", window, re.IGNORECASE):
        score += 3
        markers.append("near_script_tag")
    if re.search(r"on\w+\s*=", window, re.IGNORECASE):
        score += 3
        markers.append("near_event_handler")
    if re.search(r"javascript:", window, re.IGNORECASE):
        score += 2
        markers.append("javascript_url_context")
    if re.search(r"<[^>]+" + re.escape(token), body):
        score += 2
        markers.append("inside_tag_like_context")
    if score == 0:
        score = 1
        markers.append("plain_text_reflection")
    return score, markers


class ReflectedXssCheck:
    rule_id = "dast.active.reflected_xss"

    def probe(
        self, ctx: AuditContext, ep: DiscoveredEndpoint, baseline: HttpResponse
    ) -> Iterator[RawDastFinding]:
        if ep.method.upper() != "GET":
            return
        depth = ctx.active_depth()
        token = f"unifxss_{ctx.scan_token}"
        payloads = [token]
        if depth >= 2:
            payloads.append(f"{token}<svg/onload=alert(1)>")
        if depth >= 3:
            payloads.append(f"\"><script>{token}</script>")

        for point in ep.insertion_points:
            if point.location not in ("query", "path"):
                continue
            base_url = ep.url
            baseline_val = "unif_baseline_marker"
            if point.location == "query":
                b_url = with_query_param(base_url, point.name, baseline_val)
                b_resp = ctx.client.request("GET", b_url, headers=ctx.auth.request_headers())
                ctx.auth.absorb_set_cookie(b_resp)
            else:
                b_url = replace_path_param(base_url, point.name, baseline_val)
                b_resp = ctx.client.request("GET", b_url, headers=ctx.auth.request_headers())
                ctx.auth.absorb_set_cookie(b_resp)

            for payload in payloads[:depth]:
                if point.location == "query":
                    t_url = with_query_param(base_url, point.name, payload)
                else:
                    t_url = replace_path_param(base_url, point.name, payload)
                t_resp = ctx.client.request("GET", t_url, headers=ctx.auth.request_headers())
                ctx.auth.absorb_set_cookie(t_resp)

                if payload not in t_resp.body_text:
                    continue
                base_score, _ = _xss_context_score(b_resp.body_text, baseline_val)
                probe_score, markers = _xss_context_score(t_resp.body_text, payload)
                baseline_comparison = (
                    f"baseline_len={len(b_resp.body_text)} probe_len={len(t_resp.body_text)} "
                    f"baseline_marker_reflected={baseline_val in b_resp.body_text} "
                    f"context_score_probe={probe_score} context_score_baseline={base_score}"
                )
                if probe_score <= base_score and baseline_val in b_resp.body_text:
                    confidence = "low"
                elif probe_score >= 3:
                    confidence = "medium"
                else:
                    confidence = "low"
                severity = "medium" if confidence == "medium" else "low"

                req_a, _ = ctx.client.summarize_pair(b_resp)
                _, res_b = ctx.client.summarize_pair(t_resp)
                yield RawDastFinding(
                    rule_id=self.rule_id,
                    title="Reflected input suggests possible XSS (context-dependent)",
                    severity=severity,
                    confidence=confidence,
                    category="injection",
                    method="GET",
                    url=t_url,
                    parameter=point.name,
                    endpoint_signature=None,
                    description=(
                        "A probe token was reflected in the response. "
                        "This is not proof of exploitable XSS; context and encoding matter."
                    ),
                    subcategory="xss",
                    dast_evidence=DastEvidence(
                        request_summary=req_a,
                        response_summary=res_b,
                        matched_payload=payload[:200],
                        observed_behavior=f"Reflection markers: {', '.join(markers)}",
                        response_markers=markers,
                        baseline_comparison=baseline_comparison,
                    ),
                    correlation={"parameter_name": point.name, "sink_type": "html_response"},
                )
