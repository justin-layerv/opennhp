"""Permanent source contract for the cell0 qurl-service publisher boundary."""

from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
SOURCE = (
    ROOT
    / "terraform"
    / "environments"
    / "sandbox"
    / "qurl_service_publisher.tf"
).read_text(encoding="utf-8")
NORMALIZED = " ".join(SOURCE.split())


class SandboxCell0QurlServicePublisherContractTest(unittest.TestCase):
    def test_exact_publication_identity_and_targets_are_source_locked(self) -> None:
        for expected in (
            'qurl_service_publisher_source_repository = "layervai/qurl-service"',
            'qurl_service_publisher_repository_name = "layerv/nhp-qurl"',
            'qurl_service_runtime_contract_path = "/${var.environment}/nhp/qurl-service/runtime-contract"',
            'qurl_service_publisher_name = "${local.name_prefix}-${var.cell_id}-qurl-service-publisher"',
            'qurl_service_runtime_name = "${local.name_prefix}-${var.cell_id}-qurl-api"',
            '"token.actions.githubusercontent.com:sub" = "repo:${local.qurl_service_publisher_source_repository}:ref:refs/heads/main"',
        ):
            self.assertIn(expected, NORMALIZED)

    def test_image_and_contract_mutations_are_exact_repository_only(self) -> None:
        for action in (
            '"ecr:CompleteLayerUpload"',
            '"ecr:InitiateLayerUpload"',
            '"ecr:PutImage"',
            '"ecr:UploadLayerPart"',
            '"ssm:GetParameter"',
            '"ssm:PutParameter"',
        ):
            self.assertIn(action, SOURCE)
        self.assertGreaterEqual(
            SOURCE.count("local.qurl_service_publisher_repository_arn"),
            2,
        )
        self.assertIn(
            "Resource = aws_ssm_parameter.qurl_service_runtime_contract.arn",
            SOURCE,
        )
        for forbidden in (
            "secretsmanager:",
            "dynamodb:",
            "lambda:",
            "kms:Decrypt",
            "ecs:Delete",
            "ecr:Delete",
        ):
            self.assertNotIn(forbidden, SOURCE)

    def test_ecs_deployment_is_cell0_shape_and_resource_scoped(self) -> None:
        for expected in (
            "qurl_service_runtime_task_cpu = 512",
            "qurl_service_runtime_task_memory = 1024",
            'Action = ["ecs:DescribeServices"]',
            'Action = ["ecs:UpdateService"]',
            'Action = ["ecs:ListTasks"]',
            'Action = ["ecs:DescribeTasks"]',
            'Action = ["ecs:DescribeTaskDefinition"]',
            'Action = ["ecs:RegisterTaskDefinition"]',
            'Action = ["ecs:TagResource"]',
            '"ecs:CreateAction" = "RegisterTaskDefinition"',
            '"ecs:compute-compatibility" = ["FARGATE"]',
            '"ecs:privileged" = "false"',
            '"iam:PassedToService" = "ecs-tasks.amazonaws.com"',
            'var.environment == "sandbox"',
            'var.cell_id == "cell0"',
            'var.aws_region == "us-east-2"',
            'var.aws_account_id == "767397897469"',
            "var.qurl_grafana_cloud_enabled ? max(var.qurl_container_cpu, 512)",
            "var.qurl_grafana_cloud_enabled ? var.qurl_container_memory + 256",
        ):
            self.assertIn(expected, NORMALIZED)
        self.assertNotIn("ecs:DescribeClusters", SOURCE)

    def test_atomic_sentinel_and_terraform_ownership_are_preserved(self) -> None:
        for expected in (
            "schema_version = 1",
            'status         = "UNPUBLISHED"',
            "ignore_changes = [value]",
            '"aws:RequestTag/SourceRevision" = "false"',
            '"aws:TagKeys" = local.qurl_service_publisher_task_definition_tag_keys',
        ):
            self.assertIn(expected, SOURCE)


if __name__ == "__main__":
    unittest.main()
