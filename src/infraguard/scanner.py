"""Scan Terraform plan JSON for infrastructure security findings."""

import json
from pathlib import Path
from typing import Any

from infraguard.rules import (
    Finding,
    check_iam_policy,
    check_s3_bucket,
    check_security_group,
)


SUPPORTED_RULES = {
    "aws_security_group": check_security_group,
    "aws_s3_bucket": check_s3_bucket,
    "aws_iam_policy": check_iam_policy,
}


def _scan_resource(resource: dict[str, Any]) -> list[Finding]:
    """Run applicable checks against one Terraform resource."""
    check = SUPPORTED_RULES.get(resource.get("type"))
    if check is None:
        return []
    return check(resource)


def scan_plan(plan: dict[str, Any]) -> list[Finding]:
    """Scan final planned resources and account for resource actions."""
    findings: list[Finding] = []
    planned_values = plan.get("planned_values") or {}
    root_module = planned_values.get("root_module") or {}

    # Record resources explicitly scheduled for deletion. They should not
    # be assessed as though they will remain in the final infrastructure.
    deleted_addresses = set()
    resource_changes = plan.get("resource_changes") or []

    for item in resource_changes:
        if not isinstance(item, dict):
            continue
        change = item.get("change") or {}
        actions = change.get("actions") or []
        after = change.get("after")

        if "delete" in actions and after is None:
            deleted_addresses.add(item.get("address"))

    seen: set[tuple[str, str]] = set()

    def visit_module(module: dict[str, Any]) -> None:
        for resource in module.get("resources") or []:
            if not isinstance(resource, dict):
                continue

            address = resource.get("address", "unknown")
            resource_type = resource.get("type", "unknown")

            if address in deleted_addresses:
                continue

            key = (address, resource_type)
            if key in seen:
                continue
            seen.add(key)
            findings.extend(_scan_resource(resource))

        for child in module.get("child_modules") or []:
            if isinstance(child, dict):
                visit_module(child)

    visit_module(root_module)

    # Also inspect changed resources' after-values. This covers plan JSON
    # where a resource change is present but not represented in planned_values.
    for item in resource_changes:
        if not isinstance(item, dict):
            continue

        change = item.get("change") or {}
        actions = change.get("actions") or []
        after = change.get("after")

        if after is None or not any(
            action in {"create", "update"} for action in actions
        ):
            continue

        address = item.get("address", "unknown")
        resource_type = item.get("type", "unknown")
        key = (address, resource_type)

        if key in seen:
            continue

        resource = {
            "address": address,
            "type": resource_type,
            "values": after,
        }
        seen.add(key)
        findings.extend(_scan_resource(resource))

    return findings


def scan_file(path: str | Path) -> list[Finding]:
    """Load a Terraform plan JSON file and scan it."""
    with Path(path).open(encoding="utf-8") as file:
        plan = json.load(file)

    if not isinstance(plan, dict):
        raise ValueError("Terraform plan JSON must contain an object.")

    return scan_plan(plan)
