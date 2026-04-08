from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class PackageCoordinate:
    ecosystem: str
    package_name: str
    package_version: str
    source_file: str

