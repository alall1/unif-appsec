from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal, Optional, Union

from pydantic import BaseModel, ConfigDict, Field

EngineName = Literal["sast", "dast", "iast", "sca", "iac"]
FindingStatus = Literal["open", "suppressed"]
LocationType = Literal["code", "http", "dependency", "resource"]
EvidenceType = Literal["code_trace", "code_match", "http_exchange", "metadata_only"]
TraceKind = Literal["source", "propagation", "sanitizer", "sink", "call", "return"]


class CodeLocation(BaseModel):
    model_config = ConfigDict(extra="ignore")

    file_path: str
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    start_col: Optional[int] = Field(default=None, ge=1)
    end_col: Optional[int] = Field(default=None, ge=1)
    function_name: Optional[str] = None


class HttpLocation(BaseModel):
    model_config = ConfigDict(extra="ignore")

    url: str
    method: str
    parameter: Optional[str] = None
    endpoint_signature: Optional[str] = None


class DependencyLocation(BaseModel):
    model_config = ConfigDict(extra="ignore")

    ecosystem: Optional[str] = None
    package_name: Optional[str] = None
    package_version: Optional[str] = None
    dependency_path: Optional[str] = None


class ResourceLocation(BaseModel):
    model_config = ConfigDict(extra="ignore")

    resource_type: Optional[str] = None
    resource_id: Optional[str] = None
    resource_path: Optional[str] = None
    provider: Optional[str] = None


LocationExtension = Union[CodeLocation, HttpLocation, DependencyLocation, ResourceLocation]


class SastEvidence(BaseModel):
    model_config = ConfigDict(extra="ignore")

    code_snippet: Optional[str] = None
    matched_sink: Optional[str] = None
    matched_source: Optional[str] = None
    sanitizer_summary: Optional[str] = None
    trace_summary: Optional[str] = None


class DastEvidence(BaseModel):
    model_config = ConfigDict(extra="ignore")

    request_summary: Optional[str] = None
    response_summary: Optional[str] = None
    matched_payload: Optional[str] = None
    observed_behavior: Optional[str] = None
    response_markers: Optional[list[str]] = None
    baseline_comparison: Optional[str] = None


class ScaEvidence(BaseModel):
    model_config = ConfigDict(extra="ignore")

    source_file: Optional[str] = None
    package_identifier: Optional[str] = None
    advisory_id: Optional[str] = None
    advisory_source: Optional[str] = None
    fixed_versions: Optional[list[str]] = None
    dependency_path: Optional[str] = None


class ScaDetails(BaseModel):
    model_config = ConfigDict(extra="ignore")

    ecosystem: str
    package_name: str
    package_version: str
    advisory_id: str
    advisory_source: str

    advisory_url: Optional[str] = None
    fixed_versions: Optional[list[str]] = None
    cvss: Optional[str] = None
    cwe_ids: Optional[list[str]] = None
    dependency_scope: Optional[str] = None


class IacEvidence(BaseModel):
    """IaC structured evidence (V2 additive)."""

    model_config = ConfigDict(extra="ignore")

    # Minimal context for triage
    config_path: Optional[str] = None
    resource_type: Optional[str] = None
    resource_name: Optional[str] = None
    provider: Optional[str] = None

    # Rule/check specific evidence
    attribute_path: Optional[str] = None
    expected_vs_actual: Optional[str] = None
    check_inputs: Optional[dict[str, Any]] = None


class IacDetails(BaseModel):
    """IaC typed extension details (V2 additive)."""

    model_config = ConfigDict(extra="ignore")

    provider: str
    resource_type: str
    resource_address: str
    check_id: str

    # Optional, for explainability and structured triage
    resource_name: Optional[str] = None
    expected_value: Optional[str] = None
    observed_value: Optional[str] = None
    remediation_hint: Optional[str] = None


class TraceStep(BaseModel):
    model_config = ConfigDict(extra="ignore")

    step_index: int = Field(ge=0)
    kind: TraceKind
    label: Optional[str] = None
    file_path: Optional[str] = None
    line: Optional[int] = Field(default=None, ge=1)
    column: Optional[int] = Field(default=None, ge=1)
    symbol: Optional[str] = None
    note: Optional[str] = None


class StructuredDiagnostic(BaseModel):
    model_config = ConfigDict(extra="ignore")

    code: str
    message: str
    details: Optional[dict[str, Any]] = None


class ModuleMetrics(BaseModel):
    model_config = ConfigDict(extra="allow")

    duration_ms: Optional[float] = None
    files_analyzed: Optional[int] = None
    requests_sent: Optional[int] = None


class Finding(BaseModel):
    """Normalized finding: required core fields + optional typed extensions (§9)."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = "1"
    finding_id: str
    fingerprint: str
    engine: EngineName
    module: str
    rule_id: str
    title: str
    severity: Literal["info", "low", "medium", "high", "critical"]
    confidence: Literal["low", "medium", "high"]
    category: str
    status: FindingStatus = "open"
    location_type: LocationType
    evidence_type: EvidenceType
    created_at: str
    suppressed: bool = False

    description: Optional[str] = None
    subcategory: Optional[str] = None
    remediation: Optional[str] = None
    references: Optional[list[str]] = None
    tags: Optional[list[str]] = None
    suppression_reason: Optional[str] = None
    correlation: Optional[dict[str, Any]] = None
    metadata: Optional[dict[str, Any]] = None

    locations: Optional[list[LocationExtension]] = None
    sast_evidence: Optional[SastEvidence] = None
    dast_evidence: Optional[DastEvidence] = None
    sca_evidence: Optional[ScaEvidence] = None
    iac_evidence: Optional[IacEvidence] = None
    trace: Optional[list[TraceStep]] = None
    sca_details: Optional[ScaDetails] = None
    iac_details: Optional[IacDetails] = None

    @staticmethod
    def utc_now_rfc3339() -> str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class ModuleScanResult(BaseModel):
    model_config = ConfigDict(extra="ignore")

    findings: list[Finding] = Field(default_factory=list)
    warnings: list[StructuredDiagnostic] = Field(default_factory=list)
    errors: list[StructuredDiagnostic] = Field(default_factory=list)
    metrics: ModuleMetrics = Field(default_factory=ModuleMetrics)
