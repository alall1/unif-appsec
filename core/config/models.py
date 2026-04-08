from __future__ import annotations

from pathlib import Path
from typing import Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

Severity = Literal["info", "low", "medium", "high", "critical"]
Confidence = Literal["low", "medium", "high"]
OutputFormat = Literal["json"]


class SarifOutputConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")

    enabled: bool = False
    path: Optional[str] = None


class OutputConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")

    format: OutputFormat = "json"
    path: str = "appsec-results.json"
    pretty: bool = False
    sarif: SarifOutputConfig = Field(default_factory=SarifOutputConfig)


class ScanConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")

    modules: list[str] = Field(default_factory=list)
    profile: str = "balanced"
    include_paths: list[str] = Field(default_factory=list)
    exclude_paths: list[str] = Field(default_factory=list)


class PoliciesConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")

    fail_on_severity: Severity = "medium"
    confidence_threshold: Confidence = "low"


class LimitsConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")

    max_scan_duration_seconds: int = Field(ge=1, default=600)
    max_findings_per_module: int = Field(ge=1, default=5000)
    max_evidence_bytes: int = Field(ge=1, default=65536)
    max_crawl_depth: int = Field(ge=0, default=2)
    max_requests_per_minute: int = Field(ge=1, default=120)
    max_response_body_bytes: int = Field(ge=1, default=262144)


class ProjectConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")

    name: Optional[str] = None


class SuppressionFingerprint(BaseModel):
    model_config = ConfigDict(extra="ignore")

    kind: Literal["fingerprint"] = "fingerprint"
    fingerprint: str
    justification: str


class SuppressionRuleLocation(BaseModel):
    model_config = ConfigDict(extra="ignore")

    kind: Literal["rule_location"] = "rule_location"
    rule_id: str
    file_path: str
    line: int = Field(ge=1)
    justification: str


class SuppressionRuleEndpoint(BaseModel):
    model_config = ConfigDict(extra="ignore")

    kind: Literal["rule_endpoint"] = "rule_endpoint"
    rule_id: str
    url: str
    method: str
    endpoint_signature: Optional[str] = None
    justification: str


class SuppressionRulePathGlob(BaseModel):
    model_config = ConfigDict(extra="ignore")

    kind: Literal["rule_path_glob"] = "rule_path_glob"
    rule_id: str
    path_glob: str
    justification: str


class SuppressionRuleDependencyCoordinate(BaseModel):
    model_config = ConfigDict(extra="ignore")

    kind: Literal["rule_dependency_coordinate"] = "rule_dependency_coordinate"
    rule_id: str
    ecosystem: str
    package_name: str
    package_version: str
    justification: str


SuppressionEntry = (
    SuppressionFingerprint
    | SuppressionRuleLocation
    | SuppressionRuleEndpoint
    | SuppressionRulePathGlob
    | SuppressionRuleDependencyCoordinate
)


class ResolvedConfig(BaseModel):
    """Effective configuration after profile merge, file overlay, and CLI overlay."""

    model_config = ConfigDict(extra="ignore")

    config_version: str
    scan_modules_key_present: bool = Field(
        default=False,
        description="True when merged scan config included a modules key (even if empty).",
    )
    project: ProjectConfig = Field(default_factory=ProjectConfig)
    scan: ScanConfig
    output: OutputConfig = Field(default_factory=OutputConfig)
    policies: PoliciesConfig = Field(default_factory=PoliciesConfig)
    limits: LimitsConfig = Field(default_factory=LimitsConfig)
    sast: dict[str, Any] = Field(default_factory=dict)
    dast: dict[str, Any] = Field(default_factory=dict)
    sca: dict[str, Any] = Field(default_factory=dict)
    suppressions: list[SuppressionEntry] = Field(default_factory=list)

    @field_validator("suppressions", mode="before")
    @classmethod
    def _parse_suppressions(cls, v: Any) -> list[Any]:
        if v is None:
            return []
        if not isinstance(v, list):
            raise ValueError("suppressions must be a list")
        out: list[Any] = []
        for item in v:
            if isinstance(
                item,
                (
                    SuppressionFingerprint,
                    SuppressionRuleLocation,
                    SuppressionRuleEndpoint,
                    SuppressionRulePathGlob,
                    SuppressionRuleDependencyCoordinate,
                ),
            ):
                out.append(item)
                continue
            if not isinstance(item, dict):
                raise ValueError("each suppression must be an object or a typed suppression model")
            kind = item.get("kind")
            if kind == "fingerprint":
                out.append(SuppressionFingerprint.model_validate(item))
            elif kind == "rule_location":
                out.append(SuppressionRuleLocation.model_validate(item))
            elif kind == "rule_endpoint":
                out.append(SuppressionRuleEndpoint.model_validate(item))
            elif kind == "rule_path_glob":
                out.append(SuppressionRulePathGlob.model_validate(item))
            elif kind == "rule_dependency_coordinate":
                out.append(SuppressionRuleDependencyCoordinate.model_validate(item))
            else:
                raise ValueError(f"Unknown suppression kind: {kind!r}")
        return out


class ScanTarget(BaseModel):
    """Targets passed to plugins (core does not interpret paths/URLs for analysis)."""

    model_config = ConfigDict(extra="ignore")

    path: Optional[Path] = None
    url: Optional[str] = None
    openapi_path: Optional[Path] = None

    def model_post_init(self, __context: Any) -> None:
        if self.path is not None and not isinstance(self.path, Path):
            object.__setattr__(self, "path", Path(self.path))
        if self.openapi_path is not None and not isinstance(self.openapi_path, Path):
            object.__setattr__(self, "openapi_path", Path(self.openapi_path))
