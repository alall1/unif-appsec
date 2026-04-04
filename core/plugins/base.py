from __future__ import annotations

import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Sequence

from core.findings.models import ModuleScanResult, StructuredDiagnostic

if TYPE_CHECKING:
    from core.config.models import ResolvedConfig, ScanTarget


@dataclass(frozen=True)
class ScanContext:
    """Read-only scan execution context passed to plugins (§10 + module_contracts)."""

    logger: logging.Logger
    scan_root: Path
    limits: Any
    policies: Any
    module_config: dict[str, Any]
    deadline_monotonic: float | None

    def timed_out(self) -> bool:
        if self.deadline_monotonic is None:
            return False
        return time.monotonic() >= self.deadline_monotonic


class AppSecPlugin(ABC):
    """Plugin contract (§10.1). Core depends only on this surface."""

    name: str
    version: str

    @abstractmethod
    def supported_target_types(self) -> Sequence[str]:
        """Return target kinds this module accepts, e.g. ('path',) or ('url',)."""

    @abstractmethod
    def supported_profiles(self) -> Sequence[str]:
        """Non-empty: only those profiles; empty tuple: all V1 profiles."""

    @abstractmethod
    def validate_target(self, target: ScanTarget, config: ResolvedConfig) -> list[StructuredDiagnostic]:
        """Return errors (non-empty) if target invalid; empty if OK."""

    @abstractmethod
    def scan(self, target: ScanTarget, config: ResolvedConfig, context: ScanContext) -> ModuleScanResult:
        """Return normalized ModuleScanResult."""
