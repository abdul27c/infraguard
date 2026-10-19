"""Security rules for Terraform plan resources."""

import json
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    resource: str
    message: str
    remediation: str


def _is_public_cidr(value: Any) -> bool:
    return value in {"0.0.0.0/0", "::/0"}


def check_security_group(resource: dict[str, Any]) -> list[Finding]:
    """Flag public SSH/RDP and unrestricted public ingress."""
    findings = []
    values = resource.get("values") or {}
    ingress_rules = values.get("ingress") or []

    for index, rule in enumerate(ingress_rules):
        if not isinstance(rule, dict):
            continue

        protocol = rule.get("protocol")
        from_port = rule.get("from_port")
        to_port = rule.get("to_port")

        if protocol == "-1":
            risky = True
            reason = "all protocols"
        elif (
            isinstance(from_port, int)
            and isinstance(to_port, int)
            and from_port <= to_port
            and any(from_port <= port <= to_port for port in (22, 3389))
        ):
            risky = True
            reason = "SSH/RDP"
        else:
            risky = False
            reason = ""

        if not risky:
            continue

        public = any(
            _is_public_cidr(cidr)
            for field in ("cidr_blocks", "ipv6_cidr_blocks")
            for cidr in (rule.get(field) or [])
        )

        if public:
            findings.append(
                Finding(
                    rule_id="IG-SG-001",
                    severity="HIGH",
                    resource=resource.get("address", "unknown"),
                    message=(
                        f"Ingress rule {index} exposes {reason} "
                        "to the public internet."
                    ),
                    remediation=(
                        "Restrict ingress to trusted source CIDRs and "
                        "only the ports and protocols required."
                    ),
                )
            )

    return findings


def check_s3_bucket(resource: dict[str, Any]) -> list[Finding]:
    """Flag S3 bucket ACLs that grant public read or write access."""
    values = resource.get("values") or {}
    acl = values.get("acl")

    if acl not in {"public-read", "public-read-write"}:
        return []

    return [
        Finding(
            rule_id="IG-S3-001",
            severity="HIGH",
            resource=resource.get("address", "unknown"),
            message=f"S3 bucket ACL is set to {acl!r}.",
            remediation=(
                "Use a private ACL and review bucket policies and "
                "S3 Block Public Access settings."
            ),
        )
    ]


def check_iam_policy(resource: dict[str, Any]) -> list[Finding]:
    """Flag broad IAM permissions and policies that cannot be parsed."""
    values = resource.get("values") or {}
    policy = values.get("policy")
    address = resource.get("address", "unknown")

    if not isinstance(policy, str):
        return [
            Finding(
                rule_id="IG-IAM-002",
                severity="HIGH",
                resource=address,
                message="IAM policy is missing or is not a JSON string.",
                remediation=(
                    "Provide a valid IAM policy document and verify it "
                    "before deployment."
                ),
            )
        ]

    try:
        document = json.loads(policy)
    except (json.JSONDecodeError, TypeError):
        return [
            Finding(
                rule_id="IG-IAM-002",
                severity="HIGH",
                resource=address,
                message="IAM policy contains invalid JSON.",
                remediation=(
                    "Correct the policy JSON and validate its structure "
                    "before deployment."
                ),
            )
        ]

    if not isinstance(document, dict):
        return [
            Finding(
                rule_id="IG-IAM-002",
                severity="HIGH",
                resource=address,
                message="IAM policy JSON must be an object.",
                remediation="Provide a valid IAM policy document.",
            )
        ]

    statements = document.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    if not isinstance(statements, list):
        return [
            Finding(
                rule_id="IG-IAM-002",
                severity="HIGH",
                resource=address,
                message="IAM policy Statement must be an object or list.",
                remediation="Correct the IAM policy Statement structure.",
            )
        ]

    findings = []

    for statement in statements:
        if not isinstance(statement, dict):
            continue
        if statement.get("Effect") != "Allow":
            continue

        actions = statement.get("Action", [])
        resources = statement.get("Resource", [])

        if isinstance(actions, str):
            actions = [actions]
        if isinstance(resources, str):
            resources = [resources]

        if not isinstance(actions, list) or not isinstance(resources, list):
            continue

        wildcard_action = any(
            isinstance(action, str)
            and (action == "*" or action.endswith(":*"))
            for action in actions
        )
        wildcard_resource = any(
            isinstance(value, str) and value == "*"
            for value in resources
        )

        if wildcard_action and wildcard_resource:
            full_admin = "*" in actions
            findings.append(
                Finding(
                    rule_id="IG-IAM-001",
                    severity="HIGH" if full_admin else "MEDIUM",
                    resource=address,
                    message=(
                        "IAM policy allows all actions on all resources."
                        if full_admin
                        else (
                            "IAM policy grants wildcard service actions "
                            "across all resources."
                        )
                    ),
                    remediation=(
                        "Apply least privilege by restricting actions "
                        "and resources to the minimum required."
                    ),
                )
            )

    return findings
