"""Security rules for Terraform plan resources."""

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
    """Return True for IPv4 or IPv6 addresses that expose all addresses."""
    return value in {"0.0.0.0/0", "::/0"}


def check_security_group(resource: dict[str, Any]) -> list[Finding]:
    """Flag ingress rules open to the internet on sensitive ports."""
    findings = []
    values = resource.get("values") or {}
    ingress_rules = values.get("ingress") or []

    sensitive_ports = {22, 3389}
    address_fields = ("cidr_blocks", "ipv6_cidr_blocks")

    for index, rule in enumerate(ingress_rules):
        if not isinstance(rule, dict):
            continue

        from_port = rule.get("from_port")
        to_port = rule.get("to_port")
        protocol = rule.get("protocol")
        if protocol == "-1":
            sensitive = True
        elif isinstance(from_port, int) and isinstance(to_port, int):
            sensitive = any(
                from_port <= port <= to_port for port in sensitive_ports
            )
        else:
            sensitive = False

        if not sensitive:
            continue

        public = any(
            _is_public_cidr(cidr)
            for field in address_fields
            for cidr in (rule.get(field) or [])
        )
        if public:
            findings.append(
                Finding(
                    rule_id="IG-SG-001",
                    severity="HIGH",
                    resource=resource.get("address", "unknown"),
                    message=(
                        f"Ingress rule {index} exposes SSH/RDP or all "
                        "protocols to the public internet."
                    ),
                    remediation=(
                        "Restrict ingress to trusted source CIDRs and only "
                        "the ports and protocols required."
                    ),
                )
            )

    return findings


def check_s3_bucket(resource: dict[str, Any]) -> list[Finding]:
    """Flag S3 bucket ACLs that explicitly allow public access."""
    values = resource.get("values") or {}
    acl = values.get("acl")

    if acl not in {"public-read", "public-read-write", "authenticated-read"}:
        return []

    return [
        Finding(
            rule_id="IG-S3-001",
            severity="HIGH",
            resource=resource.get("address", "unknown"),
            message=f"S3 bucket ACL is set to {acl!r}.",
            remediation=(
                "Use a private ACL and configure explicit bucket policies "
                "and S3 Block Public Access settings where appropriate."
            ),
        )
    ]


def check_iam_policy(resource: dict[str, Any]) -> list[Finding]:
    """Flag inline IAM policy statements with broad administrative access."""
    values = resource.get("values") or {}
    policy = values.get("policy")

    if not isinstance(policy, str):
        return []

    import json

    try:
        document = json.loads(policy)
    except (json.JSONDecodeError, TypeError):
        return []

    statements = document.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    findings = []
    for statement in statements:
        if not isinstance(statement, dict):
            continue

        actions = statement.get("Action", [])
        resources = statement.get("Resource", [])
        effect = statement.get("Effect")

        if isinstance(actions, str):
            actions = [actions]
        if isinstance(resources, str):
            resources = [resources]

        if (
            effect == "Allow"
            and "*" in actions
            and "*" in resources
        ):
            findings.append(
                Finding(
                    rule_id="IG-IAM-001",
                    severity="HIGH",
                    resource=resource.get("address", "unknown"),
                    message=(
                        "IAM policy allows all actions on all resources."
                    ),
                    remediation=(
                        "Apply least privilege by restricting actions and "
                        "resources to the minimum required."
                    ),
                )
            )
            break

    return findings
