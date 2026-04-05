from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from modules.sast.rules.models import (
    PropagatorPattern,
    RulesPack,
    SanitizerPattern,
    SinkPattern,
    SastRule,
    SourcePattern,
)


def _src_from_dict(d: dict[str, Any]) -> SourcePattern:
    return SourcePattern(
        type=str(d["type"]),
        name=d.get("name"),
        base=d.get("base"),
        attr=d.get("attr"),
        module=d.get("module"),
        function=d.get("function"),
        qname=d.get("qname"),
    )


def _sink_from_dict(d: dict[str, Any]) -> SinkPattern:
    t = str(d["type"])
    extra = {k: v for k, v in d.items() if k != "type"}
    return SinkPattern(type=t, extra=extra)


def _san_from_dict(d: dict[str, Any]) -> SanitizerPattern:
    return SanitizerPattern(
        type=str(d["type"]),
        qname=d.get("qname"),
        module=d.get("module"),
        function=d.get("function"),
    )


def _prop_from_dict(d: dict[str, Any]) -> PropagatorPattern:
    return PropagatorPattern(type=str(d["type"]), names=list(d.get("names") or []))


def _rule_from_dict(d: dict[str, Any]) -> SastRule:
    analysis = d.get("analysis") or "taint"
    if analysis not in ("taint", "sink_only"):
        raise ValueError(f"Invalid analysis {analysis!r} for rule {d.get('id')!r}")

    return SastRule(
        id=str(d["id"]),
        title=str(d["title"]),
        message=str(d["message"]),
        severity=str(d["severity"]),
        confidence=str(d["confidence"]),
        category=str(d["category"]),
        language=str(d.get("language") or "python"),
        analysis=analysis,  # type: ignore[arg-type]
        sources=[_src_from_dict(x) for x in (d.get("sources") or [])],
        sinks=[_sink_from_dict(x) for x in (d.get("sinks") or [])],
        sanitizers=[_san_from_dict(x) for x in (d.get("sanitizers") or [])],
        propagators=[_prop_from_dict(x) for x in (d.get("propagators") or [])],
        cwe=d.get("cwe"),
        references=list(d.get("references") or []),
        tags=list(d.get("tags") or []),
    )


def load_rules_pack(path: Path) -> RulesPack:
    raw = path.read_text(encoding="utf-8")
    data = yaml.safe_load(raw)
    if not isinstance(data, dict):
        raise ValueError("Rules file must be a mapping at top level")
    sv = str(data.get("schema_version") or "1")
    rules_raw = data.get("rules")
    if not isinstance(rules_raw, list):
        raise ValueError("rules must be a list")
    rules = [_rule_from_dict(r) for r in rules_raw if isinstance(r, dict)]
    return RulesPack(schema_version=sv, rules=rules)


def filter_rules(
    rules: list[SastRule],
    *,
    enabled: list[str] | None,
    disabled: list[str] | None,
) -> list[SastRule]:
    en = set(enabled or [])
    dis = set(disabled or [])
    out: list[SastRule] = []
    for r in rules:
        if dis and r.id in dis:
            continue
        if en and r.id not in en:
            continue
        out.append(r)
    return out
