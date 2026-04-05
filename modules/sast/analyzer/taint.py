from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class TraceEvent:
    """Single ordered trace step (mapped to :class:`core.findings.models.TraceStep`)."""

    kind: str
    line: int
    column: int | None
    symbol: str | None
    label: str | None
    note: str | None


@dataclass(frozen=True)
class TaintParticle:
    """Taint tag with explicit provenance chain (bounded length)."""

    rule_id: str
    events: tuple[TraceEvent, ...]


def empty_taint() -> frozenset[TaintParticle]:
    return frozenset()


def merge_taints(*sets: frozenset[TaintParticle]) -> frozenset[TaintParticle]:
    out: set[TaintParticle] = set()
    for s in sets:
        out |= set(s)
    return frozenset(out)


def filter_rule(taint: frozenset[TaintParticle], rule_id: str) -> frozenset[TaintParticle]:
    return frozenset(p for p in taint if p.rule_id == rule_id)


def strip_rule(taint: frozenset[TaintParticle], rule_id: str) -> frozenset[TaintParticle]:
    return frozenset(p for p in taint if p.rule_id != rule_id)


def append_event(
    particle: TaintParticle,
    event: TraceEvent,
    max_events: int,
) -> TaintParticle:
    if len(particle.events) >= max_events:
        return particle
    return TaintParticle(rule_id=particle.rule_id, events=particle.events + (event,))


def with_propagation_note(
    taint: frozenset[TaintParticle],
    *,
    max_events: int,
    line: int,
    column: int | None,
    label: str,
    symbol: str | None = None,
) -> frozenset[TaintParticle]:
    ev = TraceEvent(
        kind="propagation",
        line=line,
        column=column,
        symbol=symbol,
        label=label,
        note=None,
    )
    return frozenset(append_event(p, ev, max_events) for p in taint)
