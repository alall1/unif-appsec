from __future__ import annotations

from typing import Iterable

from modules.dast.checks.active import (
    DebugExposureProbeCheck,
    HttpTraceEnabledCheck,
    PathTraversalProbeCheck,
    SqlInjectionIndicatorCheck,
    ReflectedXssCheck,
)
from modules.dast.checks.base import ActiveCheck, PassiveCheck
from modules.dast.checks.passive import (
    InsecureCookieFlagsCheck,
    InfoLeakCheck,
    PermissiveCorsCheck,
    SecurityHeadersCheck,
    ServerDisclosureCheck,
)
from modules.dast.targeting.models import DastTargetConfig


class CheckRegistry:
    """Extensible passive/active check registration (§12 — rule families as discrete checks)."""

    def __init__(self) -> None:
        self._passive: list[PassiveCheck] = []
        self._active: list[ActiveCheck] = []

    def register_passive(self, check: PassiveCheck) -> None:
        self._passive.append(check)

    def register_active(self, check: ActiveCheck) -> None:
        self._active.append(check)

    def passive_checks(self) -> list[PassiveCheck]:
        return list(self._passive)

    def active_checks(self) -> list[ActiveCheck]:
        return list(self._active)

    def extend_passive(self, checks: Iterable[PassiveCheck]) -> None:
        self._passive.extend(checks)

    def extend_active(self, checks: Iterable[ActiveCheck]) -> None:
        self._active.extend(checks)


def default_check_registry() -> CheckRegistry:
    reg = CheckRegistry()
    reg.extend_passive(
        [
            SecurityHeadersCheck(),
            PermissiveCorsCheck(),
            InfoLeakCheck(),
            ServerDisclosureCheck(),
            InsecureCookieFlagsCheck(),
        ]
    )
    reg.extend_active(
        [
            ReflectedXssCheck(),
            SqlInjectionIndicatorCheck(),
            PathTraversalProbeCheck(),
            DebugExposureProbeCheck(),
            HttpTraceEnabledCheck(),
        ]
    )
    return reg


def checks_for_config(cfg: DastTargetConfig, registry: CheckRegistry | None = None) -> tuple[list[PassiveCheck], list[ActiveCheck]]:
    reg = registry or default_check_registry()
    passive = [c for c in reg.passive_checks() if c.rule_id not in cfg.checks_disabled]
    active = [c for c in reg.active_checks() if c.rule_id not in cfg.checks_disabled]
    if not cfg.passive_enabled:
        passive = []
    if not cfg.active_enabled:
        active = []
    return passive, active
