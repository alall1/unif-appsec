from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field

from core.findings.models import Finding, ModuleMetrics, StructuredDiagnostic


class ModuleResultSummary(BaseModel):
    model_config = ConfigDict(extra="ignore")

    module: str
    warnings: list[StructuredDiagnostic] = Field(default_factory=list)
    errors: list[StructuredDiagnostic] = Field(default_factory=list)
    metrics: ModuleMetrics = Field(default_factory=ModuleMetrics)


class AggregateScanResult(BaseModel):
    """Machine-readable aggregate document (§9.10.3)."""

    model_config = ConfigDict(extra="ignore")

    scan_result_schema_version: str = "1.0.0"
    findings: list[Finding] = Field(default_factory=list)
    module_results: list[ModuleResultSummary] = Field(default_factory=list)
    scan_errors: list[StructuredDiagnostic] = Field(default_factory=list)

    def to_export_dict(self) -> dict[str, Any]:
        """JSON-ready dict; optional scan_errors omitted when empty."""
        d: dict[str, Any] = {
            "scan_result_schema_version": self.scan_result_schema_version,
            "findings": [f.model_dump(exclude_none=True) for f in self.findings],
            "module_results": [m.model_dump(exclude_none=True) for m in self.module_results],
        }
        if self.scan_errors:
            d["scan_errors"] = [e.model_dump(exclude_none=True) for e in self.scan_errors]
        return d
