from __future__ import annotations

from dataclasses import dataclass
from typing import Iterator, Protocol

from core.config.models import LimitsConfig
from core.plugins.base import ScanContext

from modules.dast.auth.session import AuthSession
from modules.dast.discovery.models import DiscoveredEndpoint
from modules.dast.findings.mapper import RawDastFinding
from modules.dast.http.client import HttpClient, HttpResponse
from modules.dast.targeting.models import ScopePolicy


@dataclass
class AuditContext:
    profile: str
    client: HttpClient
    auth: AuthSession
    limits: LimitsConfig
    scope: ScopePolicy
    scan_token: str
    scan_context: ScanContext

    def active_depth(self) -> int:
        return {"fast": 1, "balanced": 2, "deep": 3}.get(self.profile, 2)


class PassiveCheck(Protocol):
    rule_id: str

    def analyze(
        self, ctx: AuditContext, ep: DiscoveredEndpoint, baseline: HttpResponse
    ) -> Iterator[RawDastFinding]:
        ...


class ActiveCheck(Protocol):
    rule_id: str

    def probe(
        self, ctx: AuditContext, ep: DiscoveredEndpoint, baseline: HttpResponse
    ) -> Iterator[RawDastFinding]:
        ...
