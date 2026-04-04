from __future__ import annotations

import copy
import re
from typing import Any

from core.config.models import LimitsConfig

_SENSITIVE_HEADER_RE = re.compile(r"(?i)^(authorization|cookie|set-cookie)\s*:")
_BEARER_RE = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9\-._~+/]+=*\b")
_SESSIONISH_RE = re.compile(r"(?i)\b(sessionid|sess|jwt|token)\s*[:=]\s*[^\s,;]+")


def _truncate_str(s: str, max_len: int) -> str:
    if len(s) <= max_len:
        return s
    return s[: max_len - 20] + "\n... [truncated] ..."


def _redact_string(s: str) -> str:
    out = s
    out = _SENSITIVE_HEADER_RE.sub(lambda m: m.group(1) + ": [REDACTED]", out)
    out = _BEARER_RE.sub("Bearer [REDACTED]", out)
    out = _SESSIONISH_RE.sub(lambda m: m.group(1) + "=[REDACTED]", out)
    return out


def redact_value(value: Any, limits: LimitsConfig, in_response_field: bool = False) -> Any:
    """Deep redact and cap string sizes in exported structures (§15.3)."""
    if isinstance(value, str):
        cap = limits.max_response_body_bytes if in_response_field else limits.max_evidence_bytes
        return _truncate_str(_redact_string(value), cap)
    if isinstance(value, list):
        return [redact_value(v, limits, in_response_field=in_response_field) for v in value]
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for k, v in value.items():
            child_in_resp = in_response_field or ("response" in k.lower() and "summary" in k.lower())
            out[k] = redact_value(v, limits, in_response_field=child_in_resp)
        return out
    return value


def redact_finding_dict(data: dict[str, Any], limits: LimitsConfig) -> dict[str, Any]:
    payload = copy.deepcopy(data)
    return redact_value(payload, limits)
