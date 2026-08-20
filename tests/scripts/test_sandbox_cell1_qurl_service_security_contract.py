#!/usr/bin/env python3
"""Static security contracts for the sandbox-cell1 qurl-service foundation."""

from pathlib import Path
import re
import unittest


REPO_ROOT = Path(__file__).resolve().parents[2]
SOURCE = REPO_ROOT / "terraform/environments/sandbox-cell1/qurl_service.tf"
# Read once — the file is invariant across the suite.
SOURCE_TEXT = SOURCE.read_text(encoding="utf-8")
NORMALIZED = " ".join(SOURCE_TEXT.split())


def terraform_data_body(name: str) -> str:
    match = re.search(
        rf'resource "terraform_data" "{re.escape(name)}" \{{'
        r"(?P<body>.*?)"
        r"\n\}",
        SOURCE_TEXT,
        flags=re.DOTALL,
    )
    if match is None:
        raise AssertionError(f"{name} resource is missing")
    return match.group("body")


class SandboxCell1QurlServiceSecurityContractTest(unittest.TestCase):
    def test_secret_seeds_use_stdin_not_process_argv(self) -> None:
        generated_body = terraform_data_body("qurl_service_secret_seed")
        feedback_body = terraform_data_body("qurl_feedback_slack_webhook_seed")

        self.assertIn('printf \'%s\' "$value" |', generated_body)
        self.assertIn("printf '%s' 'DISABLED' |", feedback_body)
        for body in (generated_body, feedback_body):
            self.assertEqual(
                re.findall(r"--secret-string\s+(\S+)", body),
                ["file:///dev/stdin"],
                "Each secret seed must make AWS CLI read its value from stdin",
            )
            self.assertNotRegex(
                body,
                r"--secret-string\s+[\"']?\$",
                "Secret material must not be interpolated into AWS CLI argv",
            )

    def test_publisher_reads_only_the_cell1_service(self) -> None:
        source = SOURCE_TEXT
        match = re.search(
            r'Sid\s+=\s+"ReadCell1ECS"'
            r"(?P<body>.*?)"
            r'\n\s+\},\n\s+\{\n\s+Sid\s+=\s+"DeployOnlyCell1Service"',
            source,
            flags=re.DOTALL,
        )
        self.assertIsNotNone(match, "ReadCell1ECS policy statement is missing")
        body = match.group("body")

        self.assertIn('Action   = ["ecs:DescribeServices"]', body)
        self.assertIn("Resource = local.qurl_service_service_arn", body)
        self.assertNotIn("ecs:DescribeClusters", source)
        self.assertNotIn("qurl_service_cluster_arn", body)

    def test_publisher_shared_lock_access_is_exact_and_metric_scoped(self) -> None:
        for expected in (
            'qurl_service_live_env_lock_path = "/layerv-nhp-sandbox/qurl-live-env-lock"',
            'qurl_service_live_env_lock_arn = "arn:aws:ssm:${data.aws_region.current.region}:${var.aws_account_id}:parameter${local.qurl_service_live_env_lock_path}"',
            "max_session_duration = 10800",
        ):
            self.assertIn(expected, NORMALIZED)
        self.assertIn(
            'Sid = "CoordinateSharedSandboxMutation" Effect = "Allow" '
            'Action = ["ssm:DeleteParameter", "ssm:GetParameter", '
            '"ssm:PutParameter"] Resource = local.qurl_service_live_env_lock_arn',
            NORMALIZED,
        )
        self.assertIn(
            'Sid = "EmitSandboxLockFailureMetric" Effect = "Allow" '
            'Action = ["cloudwatch:PutMetricData"] Resource = "*" Condition = { '
            'StringEquals = { "cloudwatch:namespace" = "LayerV/QURLServiceCI" } }',
            NORMALIZED,
        )
        self.assertEqual(SOURCE_TEXT.count('"ssm:DeleteParameter"'), 1)
        self.assertEqual(SOURCE_TEXT.count('"cloudwatch:PutMetricData"'), 1)
        self.assertEqual(SOURCE_TEXT.count('"cloudwatch:namespace"'), 1)


if __name__ == "__main__":
    unittest.main()
