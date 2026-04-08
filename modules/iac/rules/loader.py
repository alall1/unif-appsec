from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from modules.iac.rules.models import IacRule, IacRulePack, RuleCheckKind


def _as_rule_check_kind(v: str) -> RuleCheckKind:
    # Keep mapping strict: if new kinds are added, loader should fail fast.
    allowed = set(
        [
            "public_ingress_any_wildcard_cidr",
            "s3_public_access_block_must_be_true",
            "s3_bucket_encryption_required",
        ]
    )
    if v not in allowed:
        raise ValueError(f"Unsupported IaC rule check kind: {v!r}")
    return v  # type: ignore[return-value]


def load_iac_rules_pack(path: Path) -> IacRulePack:
    raw = path.read_text(encoding="utf-8")
    data: Any = yaml.safe_load(raw)
    if not isinstance(data, dict):
        raise ValueError("IaC rules file must be a mapping at top level.")
    schema_version = str(data.get("schema_version") or "1")
    rules_raw = data.get("rules")
    if not isinstance(rules_raw, list):
        raise ValueError("IaC rules file must contain `rules` as a list.")

    rules: list[IacRule] = []
    for r in rules_raw:
        if not isinstance(r, dict):
            continue
        check_kind = _as_rule_check_kind(str(r.get("check")))
        required_attributes = r.get("required_attributes") or {}
        if required_attributes is None:
            required_attributes = {}
        if not isinstance(required_attributes, dict):
            raise ValueError(f"Rule {r.get('id')!r} required_attributes must be a mapping.")

        allowed_sse_algorithms = r.get("allowed_sse_algorithms") or []
        if allowed_sse_algorithms is None:
            allowed_sse_algorithms = []
        if not isinstance(allowed_sse_algorithms, list):
            raise ValueError(f"Rule {r.get('id')!r} allowed_sse_algorithms must be a list.")

        rules.append(
            IacRule(
                id=str(r["id"]),
                title=str(r["title"]),
                message=str(r["message"]),
                severity=str(r["severity"]),
                confidence=str(r["confidence"]),
                category=str(r["category"]),
                provider=str(r["provider"]),
                resource_type=str(r["resource_type"]),
                check=check_kind,
                required_attributes=dict(required_attributes),
                allowed_sse_algorithms=[str(x) for x in allowed_sse_algorithms],
                remediation_hint=r.get("remediation_hint"),
            )
        )

    return IacRulePack(schema_version=schema_version, rules=rules)

