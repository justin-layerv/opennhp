from __future__ import annotations

import re
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "terraform/sandbox_fixed_canary.tf"


class SandboxFixedCanaryCustodyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = SOURCE.read_text(encoding="utf-8")

    def test_graph_is_sandbox_only_and_has_exact_fixed_identity_set(self) -> None:
        self.assertRegex(
            self.text,
            r'sandbox_fixed_canary_enabled\s*=\s*var\.environment == "sandbox"',
        )
        self.assertIn('sandbox_fixed_canary_partition = "aws"', self.text)
        self.assertNotIn('data "aws_partition"', self.text)
        self.assertIn(
            'for label in ["direct-a", "direct-b", "relay-c", "relay-d"]',
            self.text,
        )
        self.assertIn('"shared/${label}"', self.text)
        self.assertNotIn("DeployColor", self.text)
        self.assertIn('name        = "/sandbox/nhp/customer-journey/fixed-canary-v1"', self.text)
        self.assertIn("assignment_generation = 1", self.text)
        self.assertNotIn("environment == \"prod\"", self.text)

    def test_custody_has_one_state_table_and_four_encrypted_secret_slots(self) -> None:
        self.assertEqual(
            len(re.findall(r'resource "aws_dynamodb_table" "sandbox_fixed_canary"', self.text)),
            1,
        )
        self.assertEqual(
            len(re.findall(r'resource "aws_secretsmanager_secret" "sandbox_fixed_canary"', self.text)),
            1,
        )
        self.assertIn("server_side_encryption", self.text)
        self.assertIn("kms_key_arn = module.kms.secrets_key_arn", self.text)
        self.assertIn("length(aws_secretsmanager_secret.sandbox_fixed_canary) == 4", self.text)
        self.assertEqual(self.text.count("prevent_destroy = true"), 2)

    def test_role_is_narrow_and_does_not_control_fleets_or_public_routing(self) -> None:
        required_actions = {
            "dynamodb:DeleteItem",
            "dynamodb:GetItem",
            "dynamodb:PutItem",
            "secretsmanager:DescribeSecret",
            "secretsmanager:GetSecretValue",
            "secretsmanager:PutSecretValue",
            "sqs:ChangeMessageVisibility",
            "sqs:DeleteMessage",
            "sqs:ReceiveMessage",
            "s3:GetObject",
            "ssm:GetParameters",
            "autoscaling:DescribeAutoScalingGroups",
            "ec2:DescribeInstances",
            "ec2:DescribeLaunchTemplateVersions",
            "ecs:DescribeServices",
            "ecr:DescribeImages",
        }
        for action in required_actions:
            self.assertIn(f'"{action}"', self.text)
        for forbidden in (
            "autoscaling:SetDesiredCapacity",
            "autoscaling:StartInstanceRefresh",
            "elasticloadbalancing:ModifyListener",
            "elasticloadbalancing:ModifyRule",
            "ec2:AssociateAddress",
            "ec2:DisassociateAddress",
            "ssm:PutParameter",
        ):
            self.assertNotIn(forbidden, self.text)
        self.assertIn("layerv-nhp-sandbox-control-qurl-agent-keys", self.text)
        self.assertIn("max_session_duration = 7200", self.text)
        self.assertNotIn("layerv-nhp-prod", self.text)

    def test_trust_is_existing_nhp_sandbox_environment_only(self) -> None:
        self.assertIn(
            '"token.actions.githubusercontent.com:sub" = "repo:${var.github_org}/${var.github_repo}:environment:sandbox"',
            self.text,
        )
        self.assertNotIn("sandbox-matched-cohort", self.text)

    def test_no_prod_environment_or_workflow_file_changed(self) -> None:
        # This source lives in the shared module and is disabled for every
        # environment except the exact sandbox name. It must never require a
        # production tfvars or workflow edit.
        changed = subprocess.run(
            ["git", "diff", "--name-only", "HEAD"],
            cwd=ROOT,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
        ).stdout.splitlines()
        changed_prod = [path for path in changed if path.startswith("terraform/environments/prod/")]
        self.assertEqual(changed_prod, [])


if __name__ == "__main__":
    unittest.main()
