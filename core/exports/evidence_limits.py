from __future__ import annotations

import json
from typing import Any

from core.config.models import LimitsConfig


def _json_len(obj: Any) -> int:
    return len(json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))


def _trim_strings(obj: Any, budget: int) -> tuple[Any, int]:
    """Trim longest strings first until serialized size fits budget (best-effort)."""
    if budget <= 0:
        return None, 0
    current = _json_len(obj)
    if current <= budget:
        return obj, budget

    if isinstance(obj, str):
        if len(obj.encode("utf-8")) <= budget:
            return obj, budget - len(obj.encode("utf-8"))
        b = obj.encode("utf-8")[: max(0, budget - 30)]
        return (b.decode("utf-8", errors="ignore") + " ...[trimmed]"), 0

    if isinstance(obj, list):
        out: list[Any] = []
        for item in obj:
            if _json_len(out) >= budget:
                break
            trimmed, _ = _trim_strings(item, max(1, budget - _json_len(out)))
            out.append(trimmed)
        return out, budget - _json_len(out)

    if isinstance(obj, dict):
        out_d: dict[str, Any] = {}
        keys = sorted(obj.keys(), key=lambda k: len(json.dumps(obj[k], ensure_ascii=False)))
        for k in reversed(keys):
            if _json_len(out_d) >= budget:
                break
            trimmed, _ = _trim_strings(obj[k], max(1, budget - _json_len(out_d)))
            out_d[k] = trimmed
        return out_d, budget - _json_len(out_d)

    return obj, budget


def enforce_max_evidence_bytes_on_dict(data: dict[str, Any], limits: LimitsConfig) -> dict[str, Any]:
    """Cap evidence-heavy subtrees to limits.max_evidence_bytes per finding."""
    keys = ("sast_evidence", "dast_evidence", "sca_evidence", "iac_evidence", "trace", "metadata")
    out = dict(data)
    for k in keys:
        if k not in out or out[k] is None:
            continue
        trimmed, _ = _trim_strings(out[k], limits.max_evidence_bytes)
        out[k] = trimmed
    return out
