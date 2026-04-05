from __future__ import annotations

import sys

from apps.cli.commands import execute_scan
from core.plugins.registry import PluginRegistry
from modules.sast.plugin import PythonSastPlugin


def main() -> None:
    """Console entrypoint (`appsec`). Registers built-in scan modules."""
    reg = PluginRegistry()
    reg.register(PythonSastPlugin())
    code = execute_scan(sys.argv[1:], reg)
    raise SystemExit(code)


def run_with_registry(registry: PluginRegistry) -> None:
    """Run CLI with a custom registry (tests); default ``main()`` registers ``PythonSastPlugin``."""
    code = execute_scan(sys.argv[1:], registry)
    raise SystemExit(code)
