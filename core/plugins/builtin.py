from __future__ import annotations

from core.plugins.registry import PluginRegistry


def register_builtin_plugins(registry: PluginRegistry) -> None:
    """Register shipped V1 modules (SAST + DAST)."""
    from modules.dast.plugin import HttpDastPlugin
    from modules.sca.plugin import PythonScaPlugin
    from modules.sast.plugin import PythonSastPlugin

    registry.register(PythonSastPlugin())
    registry.register(HttpDastPlugin())
    registry.register(PythonScaPlugin())
