from __future__ import annotations

from pathlib import Path

import tomllib

from modules.sca.inventory import PackageCoordinate


def parse_poetry_lock(path: Path) -> tuple[list[PackageCoordinate], list[str]]:
    """
    Minimal deterministic parser for Poetry v1-style lock.

    We only extract package name + version from [[package]] entries.
    """
    try:
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        return [], [f"{path.name}: failed to parse poetry.lock as TOML: {exc}"]

    packages = raw.get("package")
    if not isinstance(packages, list):
        return [], [f"{path.name}: missing [[package]] entries"]

    pkgs: list[PackageCoordinate] = []
    for item in packages:
        if not isinstance(item, dict):
            continue
        name = item.get("name")
        version = item.get("version")
        if not name or not version:
            continue
        pkgs.append(
            PackageCoordinate(
                ecosystem="pypi",
                package_name=str(name),
                package_version=str(version),
                source_file=str(path),
            )
        )
    return pkgs, []

