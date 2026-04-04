from __future__ import annotations

from typing import Iterable

from core.plugins.base import AppSecPlugin


class PluginRegistry:
    def __init__(self) -> None:
        self._by_name: dict[str, AppSecPlugin] = {}

    def register(self, plugin: AppSecPlugin) -> None:
        self._by_name[plugin.name] = plugin

    def get(self, name: str) -> AppSecPlugin | None:
        return self._by_name.get(name)

    def all(self) -> Iterable[AppSecPlugin]:
        return self._by_name.values()
