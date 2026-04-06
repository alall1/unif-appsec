from __future__ import annotations

import secrets
import urllib.parse

from core.findings.models import StructuredDiagnostic
from core.plugins.base import ScanContext

from modules.dast.auth.session import AuthSession, ReauthHookPlaceholder
from modules.dast.checks.base import AuditContext, PassiveCheck, ActiveCheck
from modules.dast.checks.util import materialize_url_template
from modules.dast.discovery.models import DiscoveredEndpoint
from modules.dast.findings.mapper import RawDastFinding
from modules.dast.http.client import HttpClient, with_query_param
from modules.dast.targeting.models import UrlResolution, url_is_in_scope


def _build_request_url(ep: DiscoveredEndpoint) -> str:
    u = materialize_url_template(ep.url)
    if ep.method.upper() == "GET":
        for p in ep.insertion_points:
            if p.location == "query":
                qs = urllib.parse.parse_qsl(urllib.parse.urlsplit(u).query, keep_blank_values=True)
                names = {k for k, _ in qs}
                if p.name not in names:
                    u = with_query_param(u, p.name, "unifneutral")
    return u


class AuditEngine:
    """Audit phase: passive response analysis + active probes with evidence (§12.6)."""

    def __init__(
        self,
        *,
        passive: list[PassiveCheck],
        active: list[ActiveCheck],
        resolution: UrlResolution,
    ) -> None:
        self._passive = passive
        self._active = active
        self._resolution = resolution

    def audit(
        self,
        *,
        endpoints: list[DiscoveredEndpoint],
        client: HttpClient,
        auth: AuthSession,
        scan_context: ScanContext,
        profile: str,
        reauth: ReauthHookPlaceholder | None = None,
    ) -> tuple[list[RawDastFinding], list[StructuredDiagnostic]]:
        warnings: list[StructuredDiagnostic] = []
        if reauth and reauth.configured_path:
            warnings.append(
                StructuredDiagnostic(
                    code="dast_reauth_hook_reserved",
                    message="auth.reauth_hook is configured but not executed in V1 (reserved for future token refresh).",
                    details={"reauth_hook": reauth.configured_path},
                )
            )

        ctx = AuditContext(
            profile=profile,
            client=client,
            auth=auth,
            limits=scan_context.limits,
            scope=self._resolution.scope,
            scan_token=secrets.token_hex(4),
            scan_context=scan_context,
        )

        raw: list[RawDastFinding] = []

        for ep in endpoints:
            if scan_context.timed_out():
                break
            if not url_is_in_scope(ep.url, self._resolution.scope):
                warnings.append(
                    StructuredDiagnostic(
                        code="dast_endpoint_out_of_scope",
                        message=f"Skipping endpoint outside allowed origins: {ep.url}",
                        details={"url": ep.url},
                    )
                )
                continue

            req_url = _build_request_url(ep)
            try:
                baseline = client.request(ep.method, req_url, headers=auth.request_headers())
            except Exception as exc:  # noqa: BLE001
                warnings.append(
                    StructuredDiagnostic(
                        code="dast_baseline_request_failed",
                        message=str(exc),
                        details={"url": req_url, "method": ep.method},
                    )
                )
                continue

            auth.absorb_set_cookie(baseline)

            for chk in self._passive:
                if scan_context.timed_out():
                    break
                try:
                    raw.extend(chk.analyze(ctx, ep, baseline))
                except Exception as exc:  # noqa: BLE001
                    warnings.append(
                        StructuredDiagnostic(
                            code="dast_passive_check_failed",
                            message=f"{chk.rule_id}: {exc}",
                        )
                    )

            if ep.method.upper() == "GET":
                for chk in self._active:
                    if scan_context.timed_out():
                        break
                    try:
                        raw.extend(chk.probe(ctx, ep, baseline))
                    except Exception as exc:  # noqa: BLE001
                        warnings.append(
                            StructuredDiagnostic(
                                code="dast_active_check_failed",
                                message=f"{chk.rule_id}: {exc}",
                            )
                        )

        return raw, warnings
