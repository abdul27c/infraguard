import json
import unittest

from infraguard.rules import (
    check_iam_policy,
    check_s3_bucket,
    check_security_group,
)


class SecurityRuleTests(unittest.TestCase):
    def test_detects_public_ssh(self):
        resource = {
            "address": "aws_security_group.test",
            "values": {"ingress": [{
                "from_port": 22, "to_port": 22,
                "protocol": "tcp", "cidr_blocks": ["0.0.0.0/0"],
            }]},
        }
        findings = check_security_group(resource)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "IG-SG-001")

    def test_allows_restricted_ssh(self):
        resource = {
            "address": "aws_security_group.test",
            "values": {"ingress": [{
                "from_port": 22, "to_port": 22,
                "protocol": "tcp", "cidr_blocks": ["10.0.0.0/8"],
            }]},
        }
        self.assertEqual(check_security_group(resource), [])

    def test_detects_public_s3_acl(self):
        resource = {
            "address": "aws_s3_bucket.test",
            "values": {"acl": "public-read"},
        }
        findings = check_s3_bucket(resource)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "IG-S3-001")

    def test_private_s3_acl_is_not_flagged(self):
        resource = {
            "address": "aws_s3_bucket.test",
            "values": {"acl": "private"},
        }
        self.assertEqual(check_s3_bucket(resource), [])

    def test_detects_admin_iam_policy(self):
        resource = {
            "address": "aws_iam_policy.test",
            "values": {"policy": json.dumps({
                "Statement": {
                    "Effect": "Allow", "Action": "*", "Resource": "*",
                }
            })},
        }
        findings = check_iam_policy(resource)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "IG-IAM-001")

    def test_restricted_iam_policy_is_not_flagged(self):
        resource = {
            "address": "aws_iam_policy.test",
            "values": {"policy": json.dumps({
                "Statement": {
                    "Effect": "Allow",
                    "Action": ["s3:GetObject"],
                    "Resource": ["arn:aws:s3:::example/*"],
                }
            })},
        }
        self.assertEqual(check_iam_policy(resource), [])

    def test_detects_public_ipv6_ssh(self):
        resource = {
            "address": "aws_security_group.ipv6_ssh",
            "values": {"ingress": [{
                "from_port": 22, "to_port": 22,
                "protocol": "tcp", "ipv6_cidr_blocks": ["::/0"],
            }]},
        }
        findings = check_security_group(resource)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "IG-SG-001")

    def test_detects_service_wildcard_iam_actions(self):
        resource = {
            "address": "aws_iam_policy.s3_wildcard",
            "values": {"policy": json.dumps({
                "Statement": {
                    "Effect": "Allow", "Action": "s3:*", "Resource": "*",
                }
            })},
        }
        findings = check_iam_policy(resource)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "MEDIUM")

    def test_malformed_iam_policy_produces_finding(self):
        resource = {
            "address": "aws_iam_policy.invalid",
            "values": {"policy": "{not valid json"},
        }
        findings = check_iam_policy(resource)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "IG-IAM-002")
        self.assertEqual(findings[0].severity, "HIGH")

    def test_authenticated_s3_acl_is_not_public_acl_finding(self):
        resource = {
            "address": "aws_s3_bucket.authenticated",
            "values": {"acl": "authenticated-read"},
        }
        self.assertEqual(check_s3_bucket(resource), [])


if __name__ == "__main__":
    unittest.main()
