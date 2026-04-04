from __future__ import annotations

import sys

from apps.cli.commands import execute_scan
from core.plugins.registry import PluginRegistry


def main() -> None:
    """Console entrypoint (`appsec`). Uses an empty registry unless you call `run_with_registry`."""
    code = execute_scan(sys.argv[1:], PluginRegistry())
    raise SystemExit(code)


def run_with_registry(registry: PluginRegistry) -> None:
    code = execute_scan(sys.argv[1:], registry)
    raise SystemExit(code)
