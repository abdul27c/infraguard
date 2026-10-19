# InfraGuard

**A Python-based Terraform security scanner and CI security gate.**

InfraGuard analyzes Terraform plan JSON to identify selected infrastructure security risks before deployment. It uses rule-based checks to flag risky configurations and returns an exit code that allows CI/CD pipelines to block plans with high-severity findings.

## Why InfraGuard?

Infrastructure misconfigurations can expose services to the public internet, make storage publicly accessible, or grant excessive permissions to IAM identities.

InfraGuard helps catch these issues during infrastructure review rather than relying entirely on manual inspection.

## Security Rules

| Rule ID | Severity | Detection |
|---|---|---|
| `IG-SG-001` | HIGH | Public SSH/RDP access or unrestricted public ingress using all protocols |
| `IG-S3-001` | HIGH | S3 bucket ACLs set to `public-read` or `public-read-write` |
| `IG-IAM-001` | HIGH | IAM policies granting all actions on all resources |
| `IG-IAM-001` | MEDIUM | IAM policies granting wildcard service actions across all resources |
| `IG-IAM-002` | HIGH | Missing, malformed, or structurally invalid IAM policy JSON |

The scanner currently focuses on these specific checks. It is not a complete Terraform, AWS, or IAM security audit.

## How It Works

1. Terraform generates a plan in JSON format.
2. InfraGuard reads the plan and examines supported resources.
3. Security rules evaluate the relevant resource configurations.
4. Findings are printed with a rule ID, severity, affected resource, explanation, and remediation guidance.
5. The CLI returns an exit code that CI/CD workflows can use as a security gate.

## Requirements

- Python 3.10 or later
- Terraform, if you want to generate your own plan
- Git, for cloning the repository

## Installation

Clone the repository:

```bash
git clone https://github.com/abdul27c/infraguard.git
cd infraguard