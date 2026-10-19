
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


def _require_dict(value: Any, description: str) -> dict[str, Any]:
    """Require a JSON object and provide a clear validation error."""
    if not isinstance(value, dict):
        raise ValueError(f"{description} must be a JSON object.")
    return value


def _scan_resource(resource: dict[str, Any]) -> list[Finding]:
    """Run applicable checks against one Terraform resource."""
    check = SUPPORTED_RULES.get(resource.get("type"))
    if check is None:
        return []
    return check(resource)


def scan_plan(plan: dict[str, Any]) -> list[Finding]:
    """Scan planned resources and changed resource after-values."""
    _require_dict(plan, "Terraform plan")

    planned_values = plan.get("planned_values") or {}
    planned_values = _require_dict(planned_values, "planned_values")

    root_module = planned_values.get("root_module") or {}
    root_module = _require_dict(
        root_module, "planned_values.root_module"
    )

    resource_changes = plan.get("resource_changes") or []
    if not isinstance(resource_changes, list):
        raise ValueError("resource_changes must be a JSON array.")

    deleted_addresses: set[str] = set()

    for index, item in enumerate(resource_changes):
        item = _require_dict(item, f"resource_changes[{index}]")
        change = _require_dict(
            item.get("change") or {},
            f"resource_changes[{index}].change",
        )
        actions = change.get("actions") or []

        if not isinstance(actions, list):
            raise ValueError(
                f"resource_changes[{index}].change.actions "
                "must be a JSON array."
            )

        if "delete" in actions and change.get("after") is None:
            address = item.get("address")
            if isinstance(address, str):
                deleted_addresses.add(address)

    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()

    def visit_module(module: dict[str, Any], description: str) -> None:
        resources = module.get("resources") or []
        children = module.get("child_modules") or []

        if not isinstance(resources, list):
            raise ValueError(f"{description}.resources must be a JSON array.")
        if not isinstance(children, list):
            raise ValueError(
                f"{description}.child_modules must be a JSON array."
            )

        for index, resource in enumerate(resources):
            resource = _require_dict(
                resource, f"{description}.resources[{index}]"
            )
            address = resource.get("address", "unknown")
            resource_type = resource.get("type", "unknown")

            if not isinstance(address, str) or not isinstance(
                resource_type, str
            ):
                raise ValueError(
                    f"{description}.resources[{index}] must have "
                    "string address and type fields."
                )

            if address in deleted_addresses:
                continue

            key = (address, resource_type)
            if key not in seen:
                seen.add(key)
                findings.extend(_scan_resource(resource))

        for index, child in enumerate(children):
            child = _require_dict(
                child, f"{description}.child_modules[{index}]"
            )
            visit_module(child, f"{description}.child_modules[{index}]")

    visit_module(root_module, "planned_values.root_module")

    for index, item in enumerate(resource_changes):
        change = item.get("change") or {}
        actions = change.get("actions") or []
        after = change.get("after")

        if after is None or not any(
            action in {"create", "update"} for action in actions
        ):
            continue

        address = item.get("address", "unknown")
        resource_type = item.get("type", "unknown")

        if not isinstance(address, str) or not isinstance(
            resource_type, str
        ):
            raise ValueError(
                f"resource_changes[{index}] must have "
                "string address and type fields."
            )

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
