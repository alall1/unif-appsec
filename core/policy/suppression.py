from __future__ import annotations

import fnmatch
from pathlib import Path

from core.config.models import ResolvedConfig, SuppressionEntry
from core.findings.fingerprints import _canonical_url_for_fingerprint, _posix_relative_safe
from core.findings.models import CodeLocation, DependencyLocation, Finding, HttpLocation, ResourceLocation


def _primary_code(f: Finding) -> CodeLocation | None:
    if f.location_type != "code" or not f.locations:
        return None
    for loc in f.locations:
        if isinstance(loc, CodeLocation):
            return loc
    return None


def _primary_http(f: Finding) -> HttpLocation | None:
    if f.location_type != "http" or not f.locations:
        return None
    for loc in f.locations:
        if isinstance(loc, HttpLocation):
            return loc
    return None


def _match_fingerprint(rule_fp: str, finding: Finding) -> bool:
    return finding.fingerprint == rule_fp


def _match_rule_location(
    rule_id: str,
    file_path: str,
    line: int,
    finding: Finding,
    scan_root: Path,
) -> bool:
    if finding.rule_id != rule_id:
        return False
    cl = _primary_code(finding)
    if cl is None:
        return False
    rel = _posix_relative_safe(Path(cl.file_path), scan_root)
    rel_sup = _posix_relative_safe(Path(file_path), scan_root)
    return rel == rel_sup and cl.start_line == line


def _match_rule_endpoint(
    rule_id: str,
    url: str,
    method: str,
    endpoint_signature: str | None,
    finding: Finding,
) -> bool:
    if finding.rule_id != rule_id:
        return False
    hl = _primary_http(finding)
    if hl is None:
        return False
    if hl.method.upper() != method.upper():
        return False
    if _canonical_url_for_fingerprint(hl.url) != _canonical_url_for_fingerprint(url):
        return False
    if endpoint_signature is not None and endpoint_signature != "":
        return (hl.endpoint_signature or "") == endpoint_signature
    return True


def _match_rule_path_glob(rule_id: str, path_glob: str, finding: Finding, scan_root: Path) -> bool:
    if finding.rule_id != rule_id:
        return False
    cl = _primary_code(finding)
    if cl is None:
        return False
    rel = _posix_relative_safe(Path(cl.file_path), scan_root)
    return fnmatch.fnmatch(rel, path_glob)


def _match_rule_dependency_coordinate(
    rule_id: str,
    ecosystem: str,
    package_name: str,
    package_version: str,
    finding: Finding,
) -> bool:
    if finding.rule_id != rule_id:
        return False
    if finding.location_type != "dependency" or not finding.locations:
        return False
    for loc in finding.locations:
        if not isinstance(loc, DependencyLocation):
            continue
        return (
            (loc.ecosystem or "") == ecosystem
            and (loc.package_name or "") == package_name
            and (loc.package_version or "") == package_version
        )
    return False


def _match_rule_resource_address(
    rule_id: str,
    provider: str,
    resource_address: str,
    finding: Finding,
) -> bool:
    if finding.rule_id != rule_id:
        return False
    if finding.location_type != "resource" or not finding.locations:
        return False
    for loc in finding.locations:
        if not isinstance(loc, ResourceLocation):
            continue
        return (loc.provider or "") == provider and (loc.resource_id or "") == resource_address
    return False


def _tier(entry: SuppressionEntry) -> int:
    if entry.kind == "fingerprint":
        return 0
    if entry.kind == "rule_location":
        return 1
    if entry.kind == "rule_dependency_coordinate":
        return 1
    if entry.kind == "rule_resource_address":
        return 1
    if entry.kind == "rule_endpoint":
        return 2
    return 3


def apply_suppressions(findings: list[Finding], config: ResolvedConfig, scan_root: Path) -> list[Finding]:
    """§13.4: any match suppresses; attribution uses highest precedence, first in file within tier."""
    out: list[Finding] = []
    for f in findings:
        best_tier: int | None = None
        best_reason: str | None = None
        for entry in config.suppressions:
            matched = False
            if entry.kind == "fingerprint":
                matched = _match_fingerprint(entry.fingerprint, f)
                reason = entry.justification
            elif entry.kind == "rule_location":
                matched = _match_rule_location(entry.rule_id, entry.file_path, entry.line, f, scan_root)
                reason = entry.justification
            elif entry.kind == "rule_endpoint":
                matched = _match_rule_endpoint(
                    entry.rule_id,
                    entry.url,
                    entry.method,
                    entry.endpoint_signature,
                    f,
                )
                reason = entry.justification
            elif entry.kind == "rule_dependency_coordinate":
                matched = _match_rule_dependency_coordinate(
                    entry.rule_id,
                    entry.ecosystem,
                    entry.package_name,
                    entry.package_version,
                    f,
                )
                reason = entry.justification
            elif entry.kind == "rule_resource_address":
                matched = _match_rule_resource_address(
                    entry.rule_id,
                    entry.provider,
                    entry.resource_address,
                    f,
                )
                reason = entry.justification
            else:
                matched = _match_rule_path_glob(entry.rule_id, entry.path_glob, f, scan_root)
                reason = entry.justification

            if not matched:
                continue
            tier = _tier(entry)
            if best_tier is None or tier < best_tier:
                best_tier = tier
                best_reason = reason
            elif tier == best_tier and best_reason is None:
                best_reason = reason

        if best_reason is not None:
            out.append(
                f.model_copy(
                    update={
                        "suppressed": True,
                        "status": "suppressed",
                        "suppression_reason": best_reason,
                    }
                )
            )
        else:
            out.append(f.model_copy(update={"suppressed": False, "status": "open"}))
    return out
