from __future__ import annotations

from core.config.models import ResolvedConfig


def planned_module_names(config: ResolvedConfig) -> list[str]:
    return list(config.scan.modules)
