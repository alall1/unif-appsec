from __future__ import annotations

from pathlib import Path

from core.findings.models import DependencyLocation, Finding, ScaDetails, ScaEvidence
from modules.sca.advisories import Advisory
from modules.sca.inventory import PackageCoordinate


def to_sca_finding(
    *,
    scan_root: Path,
    pkg: PackageCoordinate,
    advisory: Advisory,
) -> Finding:
    loc = DependencyLocation(
        ecosystem=pkg.ecosystem,
        package_name=pkg.package_name,
        package_version=pkg.package_version,
        dependency_path=None,
    )

    pkg_id = f"{pkg.ecosystem}:{pkg.package_name}@{pkg.package_version}"
    fixed = advisory.fixed_versions or []

    return Finding(
        schema_version="1",
        finding_id="",
        fingerprint="fp1:" + "0" * 64,
        engine="sca",
        module="python_sca",
        rule_id=f"sca.vuln.{advisory.advisory_id}",
        title=advisory.title or f"Vulnerable dependency: {pkg.package_name}",
        severity=advisory.severity or "medium",
        confidence="high",
        category="dependency_vulnerability",
        status="open",
        location_type="dependency",
        evidence_type="metadata_only",
        created_at=Finding.utc_now_rfc3339(),
        suppressed=False,
        locations=[loc],
        sca_evidence=ScaEvidence(
            source_file=str(Path(pkg.source_file).resolve()) if pkg.source_file else None,
            package_identifier=pkg_id,
            advisory_id=advisory.advisory_id,
            advisory_source=advisory.advisory_source,
            fixed_versions=fixed or None,
            dependency_path=None,
        ),
        sca_details=ScaDetails(
            ecosystem=pkg.ecosystem,
            package_name=pkg.package_name,
            package_version=pkg.package_version,
            advisory_id=advisory.advisory_id,
            advisory_source=advisory.advisory_source,
            advisory_url=advisory.advisory_url,
            fixed_versions=fixed or None,
            cvss=advisory.cvss,
            cwe_ids=advisory.cwe_ids or None,
            dependency_scope=None,
        ),
    )

