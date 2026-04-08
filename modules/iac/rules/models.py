from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal, Optional


RuleCheckKind = Literal[
    "public_ingress_any_wildcard_cidr",
    "s3_public_access_block_must_be_true",
    "s3_bucket_encryption_required",
]


@dataclass(frozen=True)
class IacRule:
    id: str
    title: str
    message: str
    severity: str
    confidence: str
    category: str

    provider: str
    resource_type: str

    check: RuleCheckKind

    # Check-specific configuration
    required_attributes: dict[str, Any] = field(default_factory=dict)
    allowed_sse_algorithms: list[str] = field(default_factory=list)
    remediation_hint: Optional[str] = None


@dataclass(frozen=True)
class IacRulePack:
    schema_version: str
    rules: list[IacRule]

