from __future__ import annotations

from core.plugins.registry import PluginRegistry


def register_builtin_plugins(registry: PluginRegistry) -> None:
    """Register shipped modules (SAST, DAST, SCA, IaC)."""
    from modules.dast.plugin import HttpDastPlugin
    from modules.sca.plugin import PythonScaPlugin
    from modules.sast.plugin import PythonSastPlugin
    from modules.iac.plugin import TerraformIacPlugin

    registry.register(PythonSastPlugin())
    registry.register(HttpDastPlugin())
    registry.register(PythonScaPlugin())
    registry.register(TerraformIacPlugin())
