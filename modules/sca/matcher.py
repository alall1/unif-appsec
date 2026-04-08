from __future__ import annotations

from packaging.specifiers import SpecifierSet
from packaging.utils import canonicalize_name
from packaging.version import Version

from modules.sca.advisories import Advisory
from modules.sca.inventory import PackageCoordinate


def _canon_pkg(name: str) -> str:
    return canonicalize_name(name or "")


def advisories_for_package(advisories: list[Advisory], pkg: PackageCoordinate) -> list[Advisory]:
    p = _canon_pkg(pkg.package_name)
    return [
        a
        for a in advisories
        if (a.ecosystem == pkg.ecosystem and _canon_pkg(a.package_name) == p and a.vulnerable_specifiers)
    ]


def is_vulnerable_version(pkg_version: str, vulnerable_specifiers: list[str]) -> bool:
    v = Version(pkg_version)
    for s in vulnerable_specifiers:
        ss = SpecifierSet(str(s))
        if v in ss:
            return True
    return False

