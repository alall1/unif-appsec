from __future__ import annotations

import re
from pathlib import Path

from modules.sca.inventory import PackageCoordinate

_PIN_RE = re.compile(r"^\s*([A-Za-z0-9_.-]+)\s*==\s*([A-Za-z0-9.+!_-]+)\s*$")


def parse_requirements_txt(path: Path) -> tuple[list[PackageCoordinate], list[str]]:
    """
    Deterministic minimal parser.

    Supported line shape:
      - name==version

    Everything else is ignored with a warning line count.
    """
    pkgs: list[PackageCoordinate] = []
    warnings: list[str] = []
    for i, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if " #" in line:
            line = line.split(" #", 1)[0].strip()
        if line.startswith(("-r", "--requirement", "-c", "--constraint")):
            warnings.append(f"{path.name}:{i}: includes/constraints not supported in v2 SCA slice")
            continue
        if line.startswith(("-e", "--editable")):
            warnings.append(f"{path.name}:{i}: editable requirements not supported in v2 SCA slice")
            continue
        if "@" in line or "://" in line or line.startswith(("git+", "hg+", "svn+", "bzr+")):
            warnings.append(f"{path.name}:{i}: direct URL/VCS requirements not supported in v2 SCA slice")
            continue

        m = _PIN_RE.match(line)
        if not m:
            warnings.append(f"{path.name}:{i}: unsupported requirement line (only name==version supported)")
            continue
        name, version = m.group(1), m.group(2)
        pkgs.append(
            PackageCoordinate(
                ecosystem="pypi",
                package_name=name,
                package_version=version,
                source_file=str(path),
            )
        )
    return pkgs, warnings

