from __future__ import annotations

import time
from typing import Sequence

from core.config.models import ResolvedConfig, ScanTarget
from core.findings.models import Finding, ModuleMetrics, ModuleScanResult, StructuredDiagnostic
from core.orchestration.constants import DAST_MODULE_NAME
from core.orchestration.runner import resolve_scan_root
from core.plugins.base import AppSecPlugin, ScanContext

from modules.dast.audit.engine import AuditEngine
from modules.dast.auth.session import AuthSession, ReauthHookPlaceholder
from modules.dast.checks.registry import checks_for_config
from modules.dast.discovery.engine import DiscoveryEngine
from modules.dast.findings.mapper import raw_findings_to_normalized
from modules.dast.http.client import HttpClient
from modules.dast.http.rate_limit import RateLimiter
from modules.dast.targeting.models import build_dast_target_config, resolve_urls, validate_dast_target


class HttpDastPlugin(AppSecPlugin):
    """HTTP/API-first DAST: separate discovery and audit phases (master spec §12)."""

    name = DAST_MODULE_NAME
    version = "0.1.0"

    def supported_target_types(self) -> Sequence[str]:
        return ("url",)

    def supported_profiles(self) -> Sequence[str]:
        return ()

    def validate_target(self, target: ScanTarget, config: ResolvedConfig) -> list[StructuredDiagnostic]:
        scan_root = resolve_scan_root(target)
        errors, cfg = validate_dast_target(target, config, scan_root)
        return [
            StructuredDiagnostic(
                code="dast_target_invalid",
                message=msg,
                details={"target_url": cfg.target_url},
            )
            for msg in errors
        ]

    def scan(self, target: ScanTarget, config: ResolvedConfig, context: ScanContext) -> ModuleScanResult:
        t0 = time.perf_counter()
        scan_root = context.scan_root
        errors, dcfg = validate_dast_target(target, config, scan_root)
        if errors:
            return ModuleScanResult(
                errors=[
                    StructuredDiagnostic(
                        code="dast_target_invalid",
                        message=e,
                        details={"target_url": dcfg.target_url},
                    )
                    for e in errors
                ],
                metrics=ModuleMetrics(duration_ms=(time.perf_counter() - t0) * 1000.0, requests_sent=0),
            )

        resolved = resolve_urls(
            target_url=dcfg.target_url,
            base_url=dcfg.base_url,
            allow_cross_origin=dcfg.allow_cross_origin,
            extra_allowed_origins=dcfg.extra_allowed_origins,
        )
        if resolved is None:
            return ModuleScanResult(
                errors=[
                    StructuredDiagnostic(
                        code="dast_scope_resolution_failed",
                        message="Could not resolve target scope.",
                    )
                ],
                metrics=ModuleMetrics(duration_ms=(time.perf_counter() - t0) * 1000.0, requests_sent=0),
            )

        rate = RateLimiter(context.limits.max_requests_per_minute)
        client = HttpClient(
            limits=context.limits,
            rate_limiter=rate,
            timeout=dcfg.timeout_seconds,
            follow_redirects=dcfg.follow_redirects,
            default_headers={},
        )

        auth = AuthSession(
            static_headers=dcfg.auth_headers,
            bearer_token=dcfg.bearer_token,
            cookies=dcfg.initial_cookies,
        )
        reauth = ReauthHookPlaceholder(configured_path=dcfg.reauth_hook)

        warnings: list[StructuredDiagnostic] = []
        findings: list[Finding] = []

        discovery = DiscoveryEngine()
        endpoints, dw = discovery.discover(
            resolution=resolved,
            openapi_path=dcfg.openapi_path,
            endpoint_seeds=dcfg.endpoint_seeds,
            crawl_enabled=dcfg.crawl_enabled,
            crawl_max_depth=dcfg.crawl_max_depth,
            client=client,
            request_headers=auth.request_headers(),
            max_crawl_depth=context.limits.max_crawl_depth,
            context=context,
        )
        warnings.extend(dw)

        passive, active = checks_for_config(dcfg)
        audit = AuditEngine(passive=passive, active=active, resolution=resolved)
        raw, aw = audit.audit(
            endpoints=endpoints,
            client=client,
            auth=auth,
            scan_context=context,
            profile=config.scan.profile,
            reauth=reauth,
        )
        warnings.extend(aw)

        findings = raw_findings_to_normalized(raw)
        duration_ms = (time.perf_counter() - t0) * 1000.0
        return ModuleScanResult(
            findings=findings,
            warnings=warnings,
            errors=[],
            metrics=ModuleMetrics(duration_ms=duration_ms, requests_sent=client.requests_sent),
        )
