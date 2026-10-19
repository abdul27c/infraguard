
import unittest
from pathlib import Path

from infraguard.scanner import scan_file, scan_plan

FIXTURES = Path(__file__).parent / "fixtures"


class ScannerTests(unittest.TestCase):
    def test_insecure_plan_finds_three_violations(self):
        findings = scan_file(FIXTURES / "insecure-plan.json")
        self.assertEqual(len(findings), 3)
        self.assertEqual(
            {finding.rule_id for finding in findings},
            {"IG-SG-001", "IG-S3-001", "IG-IAM-001"},
        )

    def test_safe_plan_has_no_findings(self):
        self.assertEqual(scan_file(FIXTURES / "safe-plan.json"), [])

    def test_scans_changed_resource_after_values(self):
        plan = {
            "planned_values": {"root_module": {"resources": []}},
            "resource_changes": [{
                "address": "aws_security_group.changed",
                "type": "aws_security_group",
                "change": {
                    "actions": ["create"],
                    "after": {
                        "ingress": [{
                            "from_port": 22,
                            "to_port": 22,
                            "protocol": "tcp",
                            "cidr_blocks": ["0.0.0.0/0"],
                        }]
                    },
                },
            }],
        }
        findings = scan_plan(plan)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "IG-SG-001")

    def test_does_not_flag_deleted_resource(self):
        plan = {
            "planned_values": {
                "root_module": {
                    "resources": [{
                        "address": "aws_security_group.removed",
                        "type": "aws_security_group",
                        "values": {
                            "ingress": [{
                                "from_port": 22,
                                "to_port": 22,
                                "protocol": "tcp",
                                "cidr_blocks": ["0.0.0.0/0"],
                            }]
                        },
                    }]
                }
            },
            "resource_changes": [{
                "address": "aws_security_group.removed",
                "type": "aws_security_group",
                "change": {
                    "actions": ["delete"],
                    "before": {"ingress": []},
                    "after": None,
                },
            }],
        }
        self.assertEqual(scan_plan(plan), [])

    def test_scans_insecure_resource_in_nested_module(self):
        plan = {
            "planned_values": {
                "root_module": {
                    "resources": [],
                    "child_modules": [{
                        "resources": [{
                            "address": "module.network.aws_security_group.web",
                            "type": "aws_security_group",
                            "values": {
                                "ingress": [{
                                    "from_port": 22,
                                    "to_port": 22,
                                    "protocol": "tcp",
                                    "cidr_blocks": ["0.0.0.0/0"],
                                }]
                            },
                        }]
                    }],
                }
            }
        }
        findings = scan_plan(plan)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "IG-SG-001")

    def test_scans_insecure_replacement_resource(self):
        plan = {
            "planned_values": {"root_module": {"resources": []}},
            "resource_changes": [{
                "address": "aws_security_group.replaced",
                "type": "aws_security_group",
                "change": {
                    "actions": ["delete", "create"],
                    "before": {},
                    "after": {
                        "ingress": [{
                            "from_port": 22,
                            "to_port": 22,
                            "protocol": "tcp",
                            "cidr_blocks": ["0.0.0.0/0"],
                        }]
                    },
                },
            }],
        }
        findings = scan_plan(plan)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "IG-SG-001")

    def test_does_not_duplicate_planned_and_changed_resource(self):
        plan = {
            "planned_values": {
                "root_module": {
                    "resources": [{
                        "address": "aws_security_group.web",
                        "type": "aws_security_group",
                        "values": {
                            "ingress": [{
                                "from_port": 22,
                                "to_port": 22,
                                "protocol": "tcp",
                                "cidr_blocks": ["0.0.0.0/0"],
                            }]
                        },
                    }]
                }
            },
            "resource_changes": [{
                "address": "aws_security_group.web",
                "type": "aws_security_group",
                "change": {
                    "actions": ["update"],
                    "after": {
                        "ingress": [{
                            "from_port": 22,
                            "to_port": 22,
                            "protocol": "tcp",
                            "cidr_blocks": ["0.0.0.0/0"],
                        }]
                    },
                },
            }],
        }
        findings = scan_plan(plan)
        self.assertEqual(len(findings), 1)

    def test_rejects_invalid_planned_values_structure(self):
        with self.assertRaises(ValueError):
            scan_plan({"planned_values": "invalid"})


if __name__ == "__main__":
    unittest.main()
