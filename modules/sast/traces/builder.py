from __future__ import annotations

from core.findings.models import TraceKind, TraceStep

from modules.sast.analyzer.taint import TaintParticle


def particle_to_trace_steps(particle: TaintParticle, *, file_path: str) -> list[TraceStep]:
    """Map internal trace events to schema :class:`TraceStep` objects (ordered by ``step_index``)."""
    out: list[TraceStep] = []
    for i, ev in enumerate(particle.events):
        kind: TraceKind
        if ev.kind in (
            "source",
            "propagation",
            "sanitizer",
            "sink",
            "call",
            "return",
        ):
            kind = ev.kind  # type: ignore[assignment]
        else:
            kind = "propagation"
        col = (ev.column + 1) if ev.column is not None else None
        out.append(
            TraceStep(
                step_index=i,
                kind=kind,
                label=ev.label,
                file_path=file_path,
                line=ev.line,
                column=col,
                symbol=ev.symbol,
                note=ev.note,
            )
        )
    return out
