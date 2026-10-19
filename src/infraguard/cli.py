"""Command-line interface for InfraGuard."""

import argparse
import json
import sys

from infraguard.scanner import scan_file


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Scan Terraform plan JSON for security risks."
    )
    parser.add_argument("plan", help="Path to a Terraform plan JSON file")
    args = parser.parse_args()

    try:
        findings = scan_file(args.plan)
    except (OSError, json.JSONDecodeError, ValueError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 2

    if not findings:
        print("InfraGuard: no findings from the implemented rules.")
        return 0

    for finding in findings:
        print(f"[{finding.severity}] {finding.rule_id} — {finding.resource}")
        print(f"  Risk: {finding.message}")
        print(f"  Fix:  {finding.remediation}")

    high_findings = sum(
        finding.severity == "HIGH" for finding in findings
    )
    print(f"\nFound {len(findings)} finding(s), including {high_findings} HIGH.")

    return 1 if high_findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
