from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from modules.iac.parsing.terraform_parser import TerraformResource
from modules.iac.rules.models import IacRule, RuleCheckKind


@dataclass(frozen=True)
class IacViolation:
    rule: IacRule
    resource: TerraformResource

    attribute_path: Optional[str]
    expected_value: Optional[str]
    observed_value: Optional[str]
    expected_vs_actual: str
    check_inputs: dict[str, Any]


def _strings_from_list(v: Any) -> list[str]:
    if not isinstance(v, list):
        return []
    out: list[str] = []
    for x in v:
        if isinstance(x, str):
            out.append(x)
    return out


def _eval_public_ingress_any_wildcard_cidr(resource: TerraformResource, rule: IacRule) -> list[IacViolation]:
    ingress_blocks = resource.blocks.get("ingress") or []
    wildcards_v4: list[str] = []
    wildcards_v6: list[str] = []
    first_attr_path: Optional[str] = None

    for ing in ingress_blocks:
        cidrs = _strings_from_list(ing.attributes.get("cidr_blocks"))
        if any(c == "0.0.0.0/0" for c in cidrs):
            wildcards_v4.extend([c for c in cidrs if c == "0.0.0.0/0"])
            first_attr_path = first_attr_path or "ingress.cidr_blocks"

        cidrs6 = _strings_from_list(ing.attributes.get("ipv6_cidr_blocks"))
        if any(c == "::/0" for c in cidrs6):
            wildcards_v6.extend([c for c in cidrs6 if c == "::/0"])
            first_attr_path = first_attr_path or "ingress.ipv6_cidr_blocks"

    if not wildcards_v4 and not wildcards_v6:
        return []

    expected = "No wildcard public CIDR in ingress (0.0.0.0/0 or ::/0)"
    observed = []
    if wildcards_v4:
        observed.append("cidr_blocks includes 0.0.0.0/0")
    if wildcards_v6:
        observed.append("ipv6_cidr_blocks includes ::/0")
    observed_s = ", ".join(observed)

    return [
        IacViolation(
            rule=rule,
            resource=resource,
            attribute_path=first_attr_path or "ingress.cidr_blocks",
            expected_value=expected,
            observed_value=observed_s,
            expected_vs_actual=f"{expected}; observed: {observed_s}",
            check_inputs={
                "wildcards_v4": wildcards_v4,
                "wildcards_v6": wildcards_v6,
            },
        )
    ]


def _eval_s3_public_access_block_must_be_true(resource: TerraformResource, rule: IacRule) -> list[IacViolation]:
    if not rule.required_attributes:
        # No configuration: treat as evaluable but no-op.
        return []

    failing: dict[str, Any] = {}
    for attr, expected in rule.required_attributes.items():
        actual = resource.attributes.get(attr)
        if actual != expected:
            failing[attr] = actual

    if not failing:
        return []

    expected_value = f"All required public-access-block attributes must be {True}"
    observed_value = ", ".join([f"{k}={v!r}" for k, v in sorted(failing.items())])

    return [
        IacViolation(
            rule=rule,
            resource=resource,
            attribute_path="public_access_block",
            expected_value=expected_value,
            observed_value=observed_value,
            expected_vs_actual=f"{expected_value}; failing: {observed_value}",
            check_inputs={"failing_attributes": failing},
        )
    ]


def _extract_sse_algorithms(resource: TerraformResource) -> list[str]:
    algorithms: list[str] = []
    enc_confs = resource.blocks.get("server_side_encryption_configuration") or []
    for enc in enc_confs:
        rules = enc.blocks.get("rule") or []
        for r in rules:
            defaults = r.blocks.get("apply_server_side_encryption_by_default") or []
            for d in defaults:
                alg = d.attributes.get("sse_algorithm")
                if isinstance(alg, str):
                    algorithms.append(alg)
    return algorithms


def _eval_s3_bucket_encryption_required(resource: TerraformResource, rule: IacRule) -> list[IacViolation]:
    allowed = rule.allowed_sse_algorithms or []
    algorithms = _extract_sse_algorithms(resource)
    if not algorithms:
        return [
            IacViolation(
                rule=rule,
                resource=resource,
                attribute_path="server_side_encryption_configuration",
                expected_value="Server-side encryption must be configured",
                observed_value="No server_side_encryption_configuration block (or no sse_algorithm literal).",
                expected_vs_actual="Expected encryption configuration; observed missing/unreadable encryption block.",
                check_inputs={"allowed_algorithms": allowed},
            )
        ]

    if allowed:
        if any(a in allowed for a in algorithms):
            return []
    # Either no allowed list configured, or algorithms present but none match allowed set.
    expected_value = f"Encryption algorithm must be one of: {', '.join(allowed) if allowed else '(any configured)'}"
    observed_value = f"Found sse_algorithm values: {', '.join(sorted(set(algorithms)))}"
    return [
        IacViolation(
            rule=rule,
            resource=resource,
            attribute_path="server_side_encryption_configuration.rule.apply_server_side_encryption_by_default.sse_algorithm",
            expected_value=expected_value,
            observed_value=observed_value,
            expected_vs_actual=f"{expected_value}; observed: {observed_value}",
            check_inputs={"found_algorithms": algorithms, "allowed_algorithms": allowed},
        )
    ]


def evaluate_iac_rules(
    resources: list[TerraformResource],
    rules: list[IacRule],
    *,
    provider_filter: Optional[list[str]] = None,
) -> list[IacViolation]:
    provider_allowed = [p.lower() for p in (provider_filter or []) if p]

    violations: list[IacViolation] = []
    for res in resources:
        if provider_allowed and res.provider.lower() not in provider_allowed:
            continue

        for rule in rules:
            if rule.provider.lower() != res.provider.lower():
                continue
            if rule.resource_type != res.terraform_type:
                continue
            check: RuleCheckKind = rule.check
            if check == "public_ingress_any_wildcard_cidr":
                violations.extend(_eval_public_ingress_any_wildcard_cidr(res, rule))
            elif check == "s3_public_access_block_must_be_true":
                violations.extend(_eval_s3_public_access_block_must_be_true(res, rule))
            elif check == "s3_bucket_encryption_required":
                violations.extend(_eval_s3_bucket_encryption_required(res, rule))
            else:
                # loader should prevent this
                continue

    return violations

