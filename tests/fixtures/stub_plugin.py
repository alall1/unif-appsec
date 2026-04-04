from __future__ import annotations

from core.config.models import ResolvedConfig, ScanTarget
from core.findings.models import (
    CodeLocation,
    Finding,
    ModuleMetrics,
    ModuleScanResult,
    SastEvidence,
    StructuredDiagnostic,
)
from core.plugins.base import AppSecPlugin, ScanContext


class StubSastPlugin(AppSecPlugin):
    """Minimal in-repo plugin for exercising core orchestration without real analysis."""

    name = "stub_sast"
    version = "0.0.0"

    def supported_target_types(self):
        return ("path",)

    def supported_profiles(self):
        return ()

    def validate_target(self, target: ScanTarget, config: ResolvedConfig) -> list[StructuredDiagnostic]:
        if target.path is None:
            return [
                StructuredDiagnostic(
                    code="missing_path",
                    message="Stub plugin requires a filesystem target path.",
                )
            ]
        p = target.path
        if not p.exists():
            return [StructuredDiagnostic(code="path_missing", message=f"Path does not exist: {p}")]
        if not p.is_file():
            return [
                StructuredDiagnostic(
                    code="not_a_file",
                    message="Stub plugin expects a single file target for tests.",
                )
            ]
        return []

    def scan(self, target: ScanTarget, config: ResolvedConfig, context: ScanContext) -> ModuleScanResult:
        assert target.path is not None
        code_path = target.path.resolve()
        finding = Finding(
            finding_id="stub-1",
            fingerprint="fp1:" + "0" * 64,
            engine="sast",
            module=self.name,
            rule_id="stub.rule",
            title="Stub finding",
            severity="high",
            confidence="high",
            category="test",
            status="open",
            location_type="code",
            evidence_type="code_match",
            created_at=Finding.utc_now_rfc3339(),
            suppressed=False,
            locations=[CodeLocation(file_path=str(code_path), start_line=1, end_line=1)],
            sast_evidence=SastEvidence(code_snippet="print('hello')"),
        )
        return ModuleScanResult(findings=[finding], warnings=[], errors=[], metrics=ModuleMetrics())


class FailingPlugin(AppSecPlugin):
    name = "failing_stub"
    version = "0.0.0"

    def supported_target_types(self):
        return ("path",)

    def supported_profiles(self):
        return ()

    def validate_target(self, target: ScanTarget, config: ResolvedConfig) -> list[StructuredDiagnostic]:
        return []

    def scan(self, target: ScanTarget, config: ResolvedConfig, context: ScanContext) -> ModuleScanResult:
        raise RuntimeError("boom")
