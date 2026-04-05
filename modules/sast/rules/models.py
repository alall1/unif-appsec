from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal


AnalysisKind = Literal["taint", "sink_only"]


@dataclass
class SourcePattern:
    """Declarative source matcher (loaded from YAML)."""

    type: str
    name: str | None = None
    base: str | None = None
    attr: str | None = None
    module: str | None = None
    function: str | None = None
    qname: str | None = None


@dataclass
class SinkPattern:
    type: str
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class SanitizerPattern:
    type: str
    qname: str | None = None
    module: str | None = None
    function: str | None = None


@dataclass
class PropagatorPattern:
    type: str
    names: list[str] = field(default_factory=list)


@dataclass
class SastRule:
    id: str
    title: str
    message: str
    severity: str
    confidence: str
    category: str
    language: str
    analysis: AnalysisKind
    sources: list[SourcePattern] = field(default_factory=list)
    sinks: list[SinkPattern] = field(default_factory=list)
    sanitizers: list[SanitizerPattern] = field(default_factory=list)
    propagators: list[PropagatorPattern] = field(default_factory=list)
    cwe: str | None = None
    references: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)


@dataclass
class RulesPack:
    schema_version: str
    rules: list[SastRule]
