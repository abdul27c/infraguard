
"""Command-line interface for InfraGuard."""

import argparse
import json
import sys
from dataclasses import asdict

from infraguard.scanner import scan_file


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Scan Terraform plan JSON for security risks."
    )
    parser.add_argument("plan", help="Path to a Terraform plan JSON file")
    parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Output format (default: text)",
    )
    args = parser.parse_args()

    try:
        findings = scan_file(args.plan)
    except (OSError, json.JSONDecodeError, ValueError) as error:
        if args.format == "json":
            print(
                json.dumps({"error": str(error)}, indent=2),
                file=sys.stderr,
            )
        else:
            print(f"Error: {error}", file=sys.stderr)
        return 2

    if args.format == "json":
        output = {
            "findings": [asdict(finding) for finding in findings],
            "summary": {
                "total": len(findings),
                "high": sum(
                    finding.severity == "HIGH" for finding in findings
                ),
                "medium": sum(
                    finding.severity == "MEDIUM" for finding in findings
                ),
            },
        }
        print(json.dumps(output, indent=2))
    elif not findings:
        print("InfraGuard: no findings from the implemented rules.")
    else:
        for finding in findings:
            print(
                f"[{finding.severity}] "
                f"{finding.rule_id} — {finding.resource}"
            )
            print(f"  Risk: {finding.message}")
            print(f"  Fix:  {finding.remediation}")

        high_findings = sum(
            finding.severity == "HIGH" for finding in findings
        )
        print(
            f"\nFound {len(findings)} finding(s), "
            f"including {high_findings} HIGH."
        )

    return 1 if any(
        finding.severity == "HIGH" for finding in findings
    ) else 0


if __name__ == "__main__":
    raise SystemExit(main())
