from __future__ import annotations

import json
from pathlib import Path

from modules.sca.inventory import PackageCoordinate


def parse_pipfile_lock(path: Path) -> tuple[list[PackageCoordinate], list[str]]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        return [], [f"{path.name}: invalid Pipfile.lock (expected JSON object)"]

    pkgs: list[PackageCoordinate] = []
    warnings: list[str] = []
    sections = []
    if isinstance(raw.get("default"), dict):
        sections.append(("default", raw["default"]))
    if isinstance(raw.get("develop"), dict):
        sections.append(("develop", raw["develop"]))

    for section_name, section in sections:
        for name, info in section.items():
            if not isinstance(info, dict):
                continue
            v = info.get("version")
            if not v or not isinstance(v, str):
                warnings.append(f"{path.name}: {section_name}.{name}: missing version")
                continue
            version = v.strip()
            if version.startswith("=="):
                version = version[2:]
            if not version:
                warnings.append(f"{path.name}: {section_name}.{name}: empty version")
                continue
            pkgs.append(
                PackageCoordinate(
                    ecosystem="pypi",
                    package_name=name,
                    package_version=version,
                    source_file=str(path),
                )
            )
    return pkgs, warnings

