#!/usr/bin/env python3

from __future__ import annotations

import re
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = REPO_ROOT / ".github" / "scripts" / "check-terraform-plan-pr-policy-readonly.py"
sys.path.insert(0, str(REPO_ROOT / ".github" / "scripts"))
from _tf_lint_lib import extract_policy_body, iter_resources, parse_tf_files, unquote  # noqa: E402

DEFAULT_SSM_RESOURCES = (
    "arn:aws:ssm:${local.region}:${local.account_id}:parameter/${var.environment}/nhp/*",
    "arn:aws:ssm:${local.region}:${local.account_id}:parameter/${var.environment}/auth0/api-audience",
    "arn:aws:ssm:${local.region}:${local.account_id}:parameter/${var.environment}/auth0/domain",
    "arn:aws:ssm:${local.region}:${local.account_id}:parameter/${var.environment}/auth0/spa-client-id",
    "arn:aws:ssm:${local.region}:${local.account_id}:parameter/layerv/nhp/${var.environment}/*",
    "arn:aws:ssm:${local.region}:${local.account_id}:parameter/${var.name_prefix}/*",
    "arn:aws:ssm:${local.region}:${local.account_id}:parameter/nhp/pool/*",
    "arn:aws:ssm:${local.region}::parameter/aws/service/canonical/ubuntu/*",
)
EXPECTED_DIRECTCONNECT_AUDIT_ACTIONS = {
    "directconnect:DescribeConnections",
    "directconnect:DescribeVirtualInterfaces",
    "directconnect:DescribeDirectConnectGateways",
    "directconnect:DescribeDirectConnectGatewayAssociations",
    "directconnect:DescribeDirectConnectGatewayAssociationProposals",
}


def hcl_string_list(values: tuple[str, ...]) -> str:
    body = ",\n".join(f'            "{value}"' for value in values)
    return f"[\n{body}\n          ]"


def as_list(value: object) -> list[object]:
    if isinstance(value, list):
        return value
    return [value]


def normalized_strings(value: object) -> list[str]:
    return [unquote(item) for item in as_list(value) if isinstance(item, str)]


def directconnect_audit_actions() -> set[str]:
    operations: set[str] = set()
    for relative_path in (
        "scripts/check-control-vpc-cidr-overlap.sh",
        "scripts/check-control-global-routing.sh",
    ):
        source = (REPO_ROOT / relative_path).read_text(encoding="utf-8")
        operations.update(
            re.findall(r"(?m)^\s*aws directconnect ([a-z0-9-]+)\s", source)
        )
    return {
        "directconnect:" + "".join(part.capitalize() for part in operation.split("-"))
        for operation in operations
    }


def find_resource_body(terraform_root: Path, resource_type: str, resource_name: str) -> dict:
    for _file, rtype, name, body in iter_resources(parse_tf_files(terraform_root)):
        if rtype == resource_type and name == resource_name:
            return body
    raise AssertionError(f"{resource_type}.{resource_name} not found")


def find_policy_statement(terraform_root: Path, policy_name: str, sid: str) -> dict:
    body = find_resource_body(terraform_root, "aws_iam_policy", policy_name)
    policy = extract_policy_body(body.get("policy"))
    if policy is None:
        raise AssertionError(f"aws_iam_policy.{policy_name} policy could not be decoded")
    for stmt in policy.get("Statement", []) or []:
        if isinstance(stmt, dict) and unquote(stmt.get("Sid")) == sid:
            return stmt
    raise AssertionError(f"aws_iam_policy.{policy_name} has no Sid={sid}")


def find_policy_expression(terraform_root: Path, policy_name: str) -> str:
    body = find_resource_body(terraform_root, "aws_iam_policy", policy_name)
    policy = body.get("policy")
    if not isinstance(policy, str):
        raise AssertionError(f"aws_iam_policy.{policy_name} policy is not a string expression")
    return " ".join(policy.split())


def policy_fixture(
    *extra_statements: str,
    ssm_resources: tuple[str, ...] = DEFAULT_SSM_RESOURCES,
) -> str:
    statements = [
        """
        {
          Sid    = "SSMParameterRead"
          Effect = "Allow"
          Action = [
            "ssm:GetParameter",
            "ssm:GetParameters",
            "ssm:GetParametersByPath"
          ]
          Resource = __SSM_RESOURCES__
        }
        """.replace("__SSM_RESOURCES__", hcl_string_list(ssm_resources)),
        """
        {
          Sid    = "SSMDocumentRead"
          Effect = "Allow"
          Action = [
            "ssm:GetDocument"
          ]
          Resource = [
            "arn:aws:ssm:${local.region}:${local.account_id}:document/${var.name_prefix}-*",
            "arn:aws:ssm:${local.region}:${local.account_id}:document/traefik-plugins-${var.environment}-*"
          ]
        }
        """,
        """
        {
          Sid    = "SecretsManagerRead"
          Effect = "Allow"
          Action = [
            "secretsmanager:Describe*",
            "secretsmanager:Get*"
          ]
          Resource = "arn:aws:secretsmanager:${local.region}:${local.account_id}:secret:layerv-nhp-*"
        }
        """,
        """
        {
          Sid    = "S3ObjectRead"
          Effect = "Allow"
          Action = [
            "s3:GetObject*"
          ]
          Resource = local.terraform_plan_pr_s3_object_arns
          Condition = {
            StringEquals = {
              "aws:ResourceAccount" = local.account_id
            }
          }
        }
        """,
        """
        {
          Sid    = "KMSDecryptInAccount"
          Effect = "Allow"
          Action = [
            "kms:Decrypt"
          ]
          Resource = "*"
          Condition = {
            StringEquals = {
              "aws:ResourceAccount" = local.account_id
            }
            "ForAnyValue:StringLike" = {
              "kms:ResourceAliases" = [
                "alias/terraform-state",
                "alias/${var.name_prefix}-ebs",
                "alias/${var.name_prefix}-efs",
                "alias/${var.name_prefix}-secrets",
                "alias/${var.name_prefix}-logs",
                "alias/${var.name_prefix}-rds",
                "alias/${var.name_prefix}-cert"
              ]
            }
          }
        }
        """,
        """
        {
          Sid    = "DynamoDBRead"
          Effect = "Allow"
          Action = [
            "dynamodb:DescribeTable",
            "dynamodb:ListTables"
          ]
          Resource = "*"
        }
        """,
        """
        {
          Sid    = "APIGatewayRead"
          Effect = "Allow"
          Action = [
            "apigateway:GET"
          ]
          Resource = "arn:aws:apigateway:${local.region}::/*"
        }
        """,
        """
        {
          Sid      = "RelayIdentityStatusInvoke"
          Effect   = "Allow"
          Action   = ["lambda:InvokeFunction"]
          Resource = ["arn:aws:lambda:${local.region}:${local.account_id}:function:${var.name_prefix}-relay-status:$LATEST"]
        }
        """,
        """
        {
          Sid      = "ComputeServerIdentityValidateInvoke"
          Effect   = "Allow"
          Action   = ["lambda:InvokeFunction"]
          Resource = ["arn:aws:lambda:${local.region}:${local.account_id}:function:${var.name_prefix}-key-validator:$LATEST"]
        }
        """,
        """
        {
          Sid    = "SQSRead"
          Effect = "Allow"
          Action = [
            "sqs:GetQueueAttributes",
            "sqs:GetQueueUrl",
            "sqs:ListQueueTags"
          ]
          Resource = "arn:aws:sqs:${local.region}:${local.account_id}:layerv-nhp-*"
        }
        """,
        """
        {
          Sid    = "ElastiCacheRead"
          Effect = "Allow"
          Action = [
            "elasticache:Describe*",
            "elasticache:List*"
          ]
          Resource = "*"
        }
        """,
        *extra_statements,
    ]
    rendered_statements = ",\n".join(textwrap.dedent(stmt).strip() for stmt in statements)
    return textwrap.dedent(
        f"""
        resource "aws_iam_policy" "terraform_plan_pr_read" {{
          policy = jsonencode({{
            Version = "2012-10-17"
            Statement = [
        {textwrap.indent(rendered_statements, "      ")}
            ]
          }})
        }}
        """
    ).lstrip()


class TerraformPlanPrPolicyReadonlyTests(unittest.TestCase):
    def run_lint(self, terraform_text: str) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as tmpdir:
            terraform_root = Path(tmpdir)
            (terraform_root / "main.tf").write_text(terraform_text, encoding="utf-8")
            return subprocess.run(
                [sys.executable, str(SCRIPT_PATH), str(terraform_root)],
                cwd=REPO_ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

    def run_lint_with_replacement(self, old: str, new: str) -> subprocess.CompletedProcess[str]:
        terraform_text = policy_fixture()
        self.assertIn(old, terraform_text)
        return self.run_lint(terraform_text.replace(old, new))

    def test_fixture_policy_passes(self) -> None:
        result = self.run_lint(policy_fixture())

        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertIn("terraform_plan_pr_read policy actions", result.stdout)

    def test_real_policy_has_plan_time_iam_size_guard(self) -> None:
        body = find_resource_body(
            REPO_ROOT / "terraform" / "modules" / "ecr",
            "aws_iam_policy",
            "terraform_plan_pr_read",
        )
        lifecycle = as_list(body.get("lifecycle"))
        self.assertEqual(len(lifecycle), 1)
        self.assertIsInstance(lifecycle[0], dict)
        postconditions = as_list(lifecycle[0].get("postcondition"))
        self.assertEqual(len(postconditions), 1)
        self.assertIsInstance(postconditions[0], dict)
        self.assertEqual(postconditions[0].get("condition"), "${length(self.policy) <= 6144}")
        self.assertIn("6,144-character", unquote(postconditions[0].get("error_message")))

    def test_dynamodb_getitem_is_rejected(self) -> None:
        result = self.run_lint(
            policy_fixture(
                """
                {
                  Sid    = "DynamoDBGetItem"
                  Effect = "Allow"
                  Action = [
                    "dynamodb:GetItem"
                  ]
                  Resource = "arn:aws:dynamodb:${local.region}:${local.account_id}:table/layerv-nhp-*"
                }
                """
            )
        )

        self.assertEqual(result.returncode, 1, result.stderr + result.stdout)
        self.assertIn("dynamodb:getitem", result.stderr)

    def test_sts_assume_role_is_rejected(self) -> None:
        result = self.run_lint(
            policy_fixture(
                """
                {
                  Sid      = "GeneralAssumeRole"
                  Effect   = "Allow"
                  Action   = "sts:AssumeRole"
                  Resource = "arn:aws:iam::165115313779:role/nhp-cost-analytics-plan-readonly"
                }
                """
            )
        )

        self.assertEqual(result.returncode, 1, result.stderr + result.stdout)
        self.assertIn("sts:assumerole", result.stderr)

    def test_sts_assume_role_inside_scoped_sid_is_rejected(self) -> None:
        result = self.run_lint_with_replacement(
            '"kms:Decrypt"',
            '"kms:Decrypt",\n            "sts:AssumeRole"',
        )

        self.assertEqual(result.returncode, 1, result.stderr + result.stdout)
        self.assertIn("sts:assumerole", result.stderr)

    def test_ssm_document_broad_scope_is_rejected(self) -> None:
        result = self.run_lint_with_replacement(
            '"arn:aws:ssm:${local.region}:${local.account_id}:document/${var.name_prefix}-*"',
            '"arn:aws:ssm:${local.region}:${local.account_id}:document/*"',
        )

        self.assertEqual(result.returncode, 1, result.stderr + result.stdout)
        self.assertIn("SSMDocumentRead resources", result.stderr)

    def test_ssm_document_extra_action_is_rejected(self) -> None:
        result = self.run_lint_with_replacement(
            '"ssm:GetDocument"',
            '"ssm:GetDocument",\n            "ssm:GetParameter"',
        )

        self.assertEqual(result.returncode, 1, result.stderr + result.stdout)
        self.assertIn("SSMDocumentRead must only include", result.stderr)

    def test_apigateway_read_action_is_pinned(self) -> None:
        result = self.run_lint_with_replacement(
            '"apigateway:GET"',
            '"apigateway:GET",\n            "apigateway:List*"',
        )

        self.assertEqual(result.returncode, 1, result.stderr + result.stdout)
        self.assertIn("APIGatewayRead must only include", result.stderr)

    def test_apigateway_read_resource_is_pinned(self) -> None:
        result = self.run_lint_with_replacement(
            '"arn:aws:apigateway:${local.region}::/*"',
            '"*"',
        )

        self.assertEqual(result.returncode, 1, result.stderr + result.stdout)
        self.assertIn("APIGatewayRead resources", result.stderr)

    def test_apigateway_read_sid_is_required(self) -> None:
        result = self.run_lint_with_replacement(
            'Sid    = "APIGatewayRead"',
            'Sid    = "APIGatewayRenamed"',
        )

        self.assertEqual(result.returncode, 1, result.stderr + result.stdout)
        self.assertIn("missing APIGatewayRead", result.stderr)

    def test_relay_status_invoke_resource_is_pinned(self) -> None:
        result = self.run_lint_with_replacement(
            '"arn:aws:lambda:${local.region}:${local.account_id}:function:${var.name_prefix}-relay-status:$LATEST"',
            '"arn:aws:lambda:${local.region}:${local.account_id}:function:*"',
        )

        self.assertEqual(result.returncode, 1, result.stderr + result.stdout)
        self.assertIn("exact read-only relay status Lambda", result.stderr)

    def test_relay_status_invoke_requires_latest_qualifier(self) -> None:
        result = self.run_lint_with_replacement(
            '"arn:aws:lambda:${local.region}:${local.account_id}:function:${var.name_prefix}-relay-status:$LATEST"',
            '"arn:aws:lambda:${local.region}:${local.account_id}:function:${var.name_prefix}-relay-status"',
        )

        self.assertEqual(result.returncode, 1, result.stderr + result.stdout)
        self.assertIn("exact read-only relay status Lambda", result.stderr)

    def test_relay_status_invoke_rejects_qualifier_wildcard(self) -> None:
        result = self.run_lint_with_replacement(
            '"arn:aws:lambda:${local.region}:${local.account_id}:function:${var.name_prefix}-relay-status:$LATEST"',
            '"arn:aws:lambda:${local.region}:${local.account_id}:function:${var.name_prefix}-relay-status:*"',
        )

        self.assertEqual(result.returncode, 1, result.stderr + result.stdout)
        self.assertIn("exact read-only relay status Lambda", result.stderr)

    def test_relay_status_invoke_rejects_alternate_qualifier(self) -> None:
        result = self.run_lint_with_replacement(
            '"arn:aws:lambda:${local.region}:${local.account_id}:function:${var.name_prefix}-relay-status:$LATEST"',
            '"arn:aws:lambda:${local.region}:${local.account_id}:function:${var.name_prefix}-relay-status:prod"',
        )

        self.assertEqual(result.returncode, 1, result.stderr + result.stdout)
        self.assertIn("exact read-only relay status Lambda", result.stderr)

    def test_compute_validator_invoke_resource_is_pinned(self) -> None:
        result = self.run_lint_with_replacement(
            '"arn:aws:lambda:${local.region}:${local.account_id}:function:${var.name_prefix}-key-validator:$LATEST"',
            '"arn:aws:lambda:${local.region}:${local.account_id}:function:*"',
        )

        self.assertEqual(result.returncode, 1, result.stderr + result.stdout)
        self.assertIn("exact read-only compute validator Lambda", result.stderr)

    def test_compute_validator_invoke_requires_latest_qualifier(self) -> None:
        result = self.run_lint_with_replacement(
            '"arn:aws:lambda:${local.region}:${local.account_id}:function:${var.name_prefix}-key-validator:$LATEST"',
            '"arn:aws:lambda:${local.region}:${local.account_id}:function:${var.name_prefix}-key-validator"',
        )

        self.assertEqual(result.returncode, 1, result.stderr + result.stdout)
        self.assertIn("exact read-only compute validator Lambda", result.stderr)

    def test_compute_validator_invoke_rejects_qualifier_wildcard(self) -> None:
        result = self.run_lint_with_replacement(
            '"arn:aws:lambda:${local.region}:${local.account_id}:function:${var.name_prefix}-key-validator:$LATEST"',
            '"arn:aws:lambda:${local.region}:${local.account_id}:function:${var.name_prefix}-key-validator:*"',
        )

        self.assertEqual(result.returncode, 1, result.stderr + result.stdout)
        self.assertIn("exact read-only compute validator Lambda", result.stderr)

    def test_compute_validator_invoke_rejects_stateful_keygen(self) -> None:
        result = self.run_lint_with_replacement(
            '"arn:aws:lambda:${local.region}:${local.account_id}:function:${var.name_prefix}-key-validator:$LATEST"',
            '"arn:aws:lambda:${local.region}:${local.account_id}:function:${var.name_prefix}-keygen:$LATEST"',
        )

        self.assertEqual(result.returncode, 1, result.stderr + result.stdout)
        self.assertIn("exact read-only compute validator Lambda", result.stderr)

    def test_lambda_invoke_outside_relay_status_sid_is_rejected(self) -> None:
        result = self.run_lint(
            policy_fixture(
                """
                {
                  Sid      = "OtherLambdaInvoke"
                  Effect   = "Allow"
                  Action   = ["lambda:InvokeFunction"]
                  Resource = ["arn:aws:lambda:${local.region}:${local.account_id}:function:other"]
                }
                """
            )
        )

        self.assertEqual(result.returncode, 1, result.stderr + result.stdout)
        self.assertIn("outside scoped Sids", result.stderr)

    def test_duplicate_relay_status_sid_cannot_hide_broad_invoke(self) -> None:
        result = self.run_lint(
            policy_fixture(
                """
                {
                  Sid      = "RelayIdentityStatusInvoke"
                  Effect   = "Allow"
                  Action   = ["lambda:InvokeFunction"]
                  Resource = ["arn:aws:lambda:${local.region}:${local.account_id}:function:*"]
                }
                """
            )
        )

        self.assertEqual(result.returncode, 1, result.stderr + result.stdout)
        self.assertIn("duplicate Allow Sid: RelayIdentityStatusInvoke", result.stderr)

    def test_multiple_sidless_metadata_reads_do_not_false_positive(self) -> None:
        result = self.run_lint(
            policy_fixture(
                """
                {
                  Effect   = "Allow"
                  Action   = ["ec2:DescribeInstances"]
                  Resource = "*"
                }
                """,
                """
                {
                  Effect   = "Allow"
                  Action   = ["ec2:DescribeVolumes"]
                  Resource = "*"
                }
                """,
            )
        )

        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)

    def test_sqs_read_action_is_pinned(self) -> None:
        result = self.run_lint_with_replacement(
            '"sqs:ListQueueTags"',
            '"sqs:ListQueueTags",\n            "sqs:ListQueues"',
        )

        self.assertEqual(result.returncode, 1, result.stderr + result.stdout)
        self.assertIn("SQSRead actions", result.stderr)

    def test_sqs_read_resource_is_pinned(self) -> None:
        result = self.run_lint_with_replacement(
            '"arn:aws:sqs:${local.region}:${local.account_id}:layerv-nhp-*"',
            '"arn:aws:sqs:${local.region}:${local.account_id}:*"',
        )

        self.assertEqual(result.returncode, 1, result.stderr + result.stdout)
        self.assertIn("SQSRead resources", result.stderr)

    def test_sqs_read_sid_is_required(self) -> None:
        result = self.run_lint_with_replacement(
            'Sid    = "SQSRead"',
            'Sid    = "SQSRenamed"',
        )

        self.assertEqual(result.returncode, 1, result.stderr + result.stdout)
        self.assertIn("missing SQSRead", result.stderr)

    def test_elasticache_read_action_is_pinned(self) -> None:
        result = self.run_lint_with_replacement(
            '"elasticache:List*"',
            '"elasticache:List*",\n            "elasticache:ListTagsForResource"',
        )

        self.assertEqual(result.returncode, 1, result.stderr + result.stdout)
        self.assertIn("ElastiCacheRead actions", result.stderr)

    def test_elasticache_read_resource_is_pinned(self) -> None:
        result = self.run_lint_with_replacement(
            textwrap.dedent(
                """
                Sid    = "ElastiCacheRead"
                  Effect = "Allow"
                  Action = [
                    "elasticache:Describe*",
                    "elasticache:List*"
                  ]
                  Resource = "*"
                """
            ).strip(),
            textwrap.dedent(
                """
                Sid    = "ElastiCacheRead"
                  Effect = "Allow"
                  Action = [
                    "elasticache:Describe*",
                    "elasticache:List*"
                  ]
                  Resource = "arn:aws:elasticache:${local.region}:${local.account_id}:cluster/*"
                """
            ).strip(),
        )

        self.assertEqual(result.returncode, 1, result.stderr + result.stdout)
        self.assertIn("ElastiCacheRead resource shape changed", result.stderr)

    def test_elasticache_read_sid_is_required(self) -> None:
        result = self.run_lint_with_replacement(
            'Sid    = "ElastiCacheRead"',
            'Sid    = "ElastiCacheRenamed"',
        )

        self.assertEqual(result.returncode, 1, result.stderr + result.stdout)
        self.assertIn("missing ElastiCacheRead", result.stderr)

    def test_sensitive_ec2_get_wildcard_is_rejected(self) -> None:
        result = self.run_lint(
            policy_fixture(
                """
                {
                  Sid    = "EC2GetWildcard"
                  Effect = "Allow"
                  Action = [
                    "ec2:Get*"
                  ]
                  Resource = "*"
                }
                """
            )
        )

        self.assertEqual(result.returncode, 1, result.stderr + result.stdout)
        self.assertIn("ec2:get*", result.stderr)

    def test_sensitive_ec2_console_read_is_rejected(self) -> None:
        result = self.run_lint(
            policy_fixture(
                """
                {
                  Sid      = "EC2ConsoleOutput"
                  Effect   = "Allow"
                  Action   = "ec2:GetConsoleOutput"
                  Resource = "*"
                }
                """
            )
        )

        self.assertEqual(result.returncode, 1, result.stderr + result.stdout)
        self.assertIn("ec2:getconsoleoutput", result.stderr)

    def test_sensitive_ec2_launch_template_data_is_rejected(self) -> None:
        result = self.run_lint(
            policy_fixture(
                """
                {
                  Sid      = "EC2LaunchTemplateData"
                  Effect   = "Allow"
                  Action   = "ec2:GetLaunchTemplateData"
                  Resource = "*"
                }
                """
            )
        )

        self.assertEqual(result.returncode, 1, result.stderr + result.stdout)
        self.assertIn("ec2:getlaunchtemplatedata", result.stderr)

    def test_value_bearing_reads_must_use_scoped_sids(self) -> None:
        result = self.run_lint(
            policy_fixture(
                """
                {
                  Sid    = "AccidentalBroadSecretRead"
                  Effect = "Allow"
                  Action = [
                    "secretsmanager:GetSecretValue"
                  ]
                  Resource = "*"
                }
                """
            )
        )

        self.assertEqual(result.returncode, 1, result.stderr + result.stdout)
        self.assertIn("value-bearing read action", result.stderr)
        self.assertIn("secretsmanager:getsecretvalue", result.stderr)

    def test_duplicate_deny_sid_does_not_override_allow_scope(self) -> None:
        result = self.run_lint(
            policy_fixture(
                """
                {
                  Sid      = "SSMParameterRead"
                  Effect   = "Deny"
                  Action   = "ssm:GetParameter"
                  Resource = "*"
                }
                """
            )
        )

        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)

    def test_iam_passrole_is_rejected(self) -> None:
        result = self.run_lint(
            policy_fixture(
                """
                {
                  Sid      = "PassRole"
                  Effect   = "Allow"
                  Action   = "iam:PassRole"
                  Resource = "*"
                }
                """
            )
        )

        self.assertEqual(result.returncode, 1, result.stderr + result.stdout)
        self.assertIn("iam:passrole", result.stderr)

    def test_broad_ssm_parameter_scope_is_rejected(self) -> None:
        result = self.run_lint(
            policy_fixture(
                ssm_resources=(
                    "arn:aws:ssm:${local.region}:${local.account_id}:parameter/*",
                    "arn:aws:ssm:${local.region}::parameter/aws/service/canonical/ubuntu/*",
                )
            )
        )

        self.assertEqual(result.returncode, 1, result.stderr + result.stdout)
        self.assertIn("SSMParameterRead resources", result.stderr)

    def test_auth0_ssm_parameter_scope_is_required(self) -> None:
        result = self.run_lint(
            policy_fixture(
                ssm_resources=tuple(
                    resource for resource in DEFAULT_SSM_RESOURCES if "/auth0/" not in resource
                )
            )
        )

        self.assertEqual(result.returncode, 1, result.stderr + result.stdout)
        self.assertIn("SSMParameterRead resources", result.stderr)

    def test_auth0_ssm_parameter_wildcard_is_rejected(self) -> None:
        result = self.run_lint(
            policy_fixture(
                ssm_resources=(
                    "arn:aws:ssm:${local.region}:${local.account_id}:parameter/${var.environment}/nhp/*",
                    "arn:aws:ssm:${local.region}:${local.account_id}:parameter/${var.environment}/auth0/*",
                    "arn:aws:ssm:${local.region}:${local.account_id}:parameter/layerv/nhp/${var.environment}/*",
                    "arn:aws:ssm:${local.region}:${local.account_id}:parameter/${var.name_prefix}/*",
                    "arn:aws:ssm:${local.region}:${local.account_id}:parameter/nhp/pool/*",
                    "arn:aws:ssm:${local.region}::parameter/aws/service/canonical/ubuntu/*",
                )
            )
        )

        self.assertEqual(result.returncode, 1, result.stderr + result.stdout)
        self.assertIn("SSMParameterRead resources", result.stderr)

    def test_ssm_parameter_extra_action_is_rejected(self) -> None:
        result = self.run_lint_with_replacement(
            '"ssm:GetParameters"',
            '"ssm:GetParameters",\n            "ssm:GetDocument"',
        )

        self.assertEqual(result.returncode, 1, result.stderr + result.stdout)
        self.assertIn("SSMParameterRead actions", result.stderr)

    def test_s3_resource_account_condition_is_required(self) -> None:
        result = self.run_lint_with_replacement(
            """Condition = {
    StringEquals = {
      "aws:ResourceAccount" = local.account_id
    }
  }""",
            "",
        )

        self.assertEqual(result.returncode, 1, result.stderr + result.stdout)
        self.assertIn("S3ObjectRead must require aws:ResourceAccount", result.stderr)

    def test_broad_secretsmanager_secret_scope_is_rejected(self) -> None:
        result = self.run_lint_with_replacement(
            'Resource = "arn:aws:secretsmanager:${local.region}:${local.account_id}:secret:layerv-nhp-*"',
            'Resource = "*"',
        )

        self.assertEqual(result.returncode, 1, result.stderr + result.stdout)
        self.assertIn("SecretsManagerRead must stay scoped", result.stderr)

    def test_secretsmanager_list_actions_are_rejected(self) -> None:
        result = self.run_lint_with_replacement(
            '"secretsmanager:Get*"',
            '"secretsmanager:Get*",\n            "secretsmanager:ListSecrets"',
        )

        self.assertEqual(result.returncode, 1, result.stderr + result.stdout)
        self.assertIn("SecretsManagerRead actions", result.stderr)

    def test_kms_alias_allowlist_is_enforced(self) -> None:
        result = self.run_lint_with_replacement(
            '"alias/${var.name_prefix}-cert"',
            '"alias/${var.name_prefix}-admin"',
        )

        self.assertEqual(result.returncode, 1, result.stderr + result.stdout)
        self.assertIn("KMSDecryptInAccount aliases", result.stderr)

    def test_allow_notaction_is_rejected(self) -> None:
        result = self.run_lint(
            policy_fixture(
                """
                {
                  Sid       = "NotAction"
                  Effect    = "Allow"
                  NotAction = [
                    "iam:DeleteRole"
                  ]
                  Resource = "*"
                }
                """
            )
        )

        self.assertEqual(result.returncode, 1, result.stderr + result.stdout)
        self.assertIn("Allow statements must not use NotAction", result.stderr)


class TerraformPlanPrBootstrapTests(unittest.TestCase):
    def test_apply_role_can_create_dedicated_plan_pr_role(self) -> None:
        stmt = find_policy_statement(REPO_ROOT / "terraform", "terraform_apply_iam", "IAMRoles")
        resources = set(normalized_strings(stmt.get("Resource")))

        self.assertIn(
            "arn:aws:iam::${local.account_id}:role/nhp-${var.environment}-github-actions-terraform-plan-pr",
            resources,
        )

    def test_apply_role_can_update_role_descriptions(self) -> None:
        stmt = find_policy_statement(REPO_ROOT / "terraform", "terraform_apply_iam", "IAMRoles")
        actions = set(normalized_strings(stmt.get("Action")))

        self.assertIn("iam:UpdateRoleDescription", actions)

    def test_apply_role_does_not_broaden_github_actions_role_scope(self) -> None:
        stmt = find_policy_statement(REPO_ROOT / "terraform", "terraform_apply_iam", "IAMRoles")
        resources = set(normalized_strings(stmt.get("Resource")))

        self.assertNotIn(
            "arn:aws:iam::${local.account_id}:role/nhp-*-github-actions-terraform-plan-pr",
            resources,
        )
        self.assertNotIn("arn:aws:iam::${local.account_id}:role/nhp-*-github-actions*", resources)
        self.assertNotIn("arn:aws:iam::${local.account_id}:role/nhp-*", resources)


class ControlRoutingApplyPolicyTests(unittest.TestCase):
    def test_shared_apply_data_query_is_exact_recovery_partition_union(self) -> None:
        terraform_root = REPO_ROOT / "terraform" / "modules" / "ecr"
        stmt = find_policy_statement(
            terraform_root,
            "terraform_apply_data",
            "DynamoDBSessionControlRecoveryQuery",
        )
        self.assertEqual(normalized_strings(stmt.get("Action")), ["dynamodb:Query"])
        self.assertEqual(
            normalized_strings(stmt.get("Resource")),
            [
                "arn:aws:dynamodb:${local.region}:${local.account_id}:table/"
                "layerv-nhp-sandbox-cell0-nhp-session-control"
            ],
        )
        self.assertNotIn("/index/", normalized_strings(stmt.get("Resource"))[0])
        self.assertEqual(unquote(stmt.get("Effect")), "Allow")
        self.assertEqual(set(stmt), {"Sid", "Effect", "Action", "Resource", "Condition"})

        condition = stmt["Condition"]
        self.assertEqual(
            {unquote(key) for key in condition},
            {"ForAllValues:StringEquals", "StringEquals", "Null"},
        )
        by_name = {unquote(key): value for key, value in condition.items()}
        leading = {
            unquote(key): normalized_strings(value)
            for key, value in by_name["ForAllValues:StringEquals"].items()
        }
        self.assertEqual(
            leading,
            {
                "dynamodb:LeadingKeys": [
                    "AC#c1f4c688a88e7309e89533f7e95343901da66587f3bb03f98539a16fccf33be2",
                    "TARGET#2b6e9d783ef49c0df152d3a640d63b8846bb056b6ed1672fb27829ac340b85b1",
                    "TARGET#71844969e300ec3c25da593e211196c45a03736a57c3850a3bcfab30d5c005f1",
                    "TARGET#a8d6468608a3380b602b53c11365972843f0a4ecde6fd44e9aae6a97509e313b",
                    "TARGETWORK#2e858d866b8756b13117959015df2228a2f9582e24152035b5962b0142aa0420",
                    "TARGETWORK#316b00aa5b86de97fd481b7af9cb1ef1a6a432aba90a9c768c26b4bcd4ea4665",
                    "TARGETWORK#76dc3461739e82e34f454d811b88ac0e90e0bf4e2bdcf77b5f160b018975ac92",
                ]
            },
        )
        principal = {
            unquote(key): unquote(value)
            for key, value in by_name["StringEquals"].items()
        }
        self.assertEqual(
            principal,
            {
                "aws:PrincipalArn": "arn:aws:iam::${local.account_id}:role/"
                "nhp-sandbox-github-actions"
            },
        )
        null = {
            unquote(key): unquote(value) for key, value in by_name["Null"].items()
        }
        self.assertEqual(null, {"dynamodb:LeadingKeys": "false"})

    def test_shared_apply_read_policy_has_exact_relay_status_invoke(self) -> None:
        terraform_root = REPO_ROOT / "terraform" / "modules" / "ecr"
        stmt = find_policy_statement(
            terraform_root,
            "terraform_read",
            "RelayIdentityStatusInvoke",
        )
        self.assertEqual(
            normalized_strings(stmt.get("Action")),
            ["lambda:InvokeFunction"],
        )
        self.assertEqual(
            normalized_strings(stmt.get("Resource")),
            [
                "arn:aws:lambda:${local.region}:${local.account_id}:"
                "function:${var.name_prefix}-relay-status:$LATEST"
            ],
        )
        self.assertEqual(unquote(stmt.get("Effect")), "Allow")
        self.assertEqual(
            set(stmt),
            {"Sid", "Effect", "Action", "Resource"},
        )

        attachment = find_resource_body(
            terraform_root,
            "aws_iam_role_policy_attachment",
            "terraform_read",
        )
        self.assertEqual(
            attachment.get("role"),
            "${aws_iam_role.github_actions.name}",
        )
        self.assertEqual(
            attachment.get("policy_arn"),
            "${aws_iam_policy.terraform_read.arn}",
        )

    def test_shared_apply_data_policy_has_exact_acme_status_invoke(self) -> None:
        # The post-deploy integration test invokes the acme cert-status function
        # under the shared deploy role. The grant lives on terraform_apply_data
        # (a runtime-invoke policy), NOT the refresh-time terraform_read slot,
        # and targets the UNqualified function ARN because the SDK invoke passes
        # no Qualifier.
        terraform_root = REPO_ROOT / "terraform" / "modules" / "ecr"
        stmt = find_policy_statement(
            terraform_root,
            "terraform_apply_data",
            "AcmeCertManagerStatusInvoke",
        )
        self.assertEqual(
            normalized_strings(stmt.get("Action")),
            ["lambda:InvokeFunction"],
        )
        self.assertEqual(
            normalized_strings(stmt.get("Resource")),
            [
                "arn:aws:lambda:${local.region}:${local.account_id}:"
                "function:${var.name_prefix}-acme-cert-manager"
            ],
        )
        self.assertEqual(unquote(stmt.get("Effect")), "Allow")
        self.assertEqual(
            set(stmt),
            {"Sid", "Effect", "Action", "Resource"},
        )

        attachment = find_resource_body(
            terraform_root,
            "aws_iam_role_policy_attachment",
            "terraform_apply_data",
        )
        self.assertEqual(
            attachment.get("role"),
            "${aws_iam_role.github_actions.name}",
        )
        self.assertEqual(
            attachment.get("policy_arn"),
            "${aws_iam_policy.terraform_apply_data.arn}",
        )

    def test_control_first_apply_elasticache_read_is_exact_and_unconditional(
        self,
    ) -> None:
        policy_resource = find_resource_body(
            REPO_ROOT / "terraform" / "modules" / "ecr",
            "aws_iam_policy",
            "terraform_read",
        )
        policy = extract_policy_body(policy_resource.get("policy"))
        self.assertIsNotNone(policy)
        assert policy is not None
        stmt = find_policy_statement(
            REPO_ROOT / "terraform" / "modules" / "ecr",
            "terraform_read",
            "ElastiCacheRead",
        )
        elasticache_actions = {
            action
            for policy_stmt in policy.get("Statement", []) or []
            if isinstance(policy_stmt, dict)
            for action in normalized_strings(policy_stmt.get("Action"))
            if action.startswith("elasticache:")
        }

        self.assertEqual(
            elasticache_actions,
            {"elasticache:Describe*", "elasticache:List*"},
        )
        self.assertEqual(
            normalized_strings(stmt.get("Action")),
            ["elasticache:Describe*", "elasticache:List*"],
        )
        self.assertEqual(normalized_strings(stmt.get("Resource")), ["*"])
        self.assertEqual(unquote(stmt.get("Effect")), "Allow")
        self.assertNotIn("Condition", stmt)
        self.assertNotIn("NotAction", stmt)
        self.assertNotIn("NotResource", stmt)

        attachment = find_resource_body(
            REPO_ROOT / "terraform" / "modules" / "ecr",
            "aws_iam_role_policy_attachment",
            "terraform_read",
        )
        self.assertEqual(
            attachment.get("role"), "${aws_iam_role.github_actions.name}"
        )
        self.assertEqual(
            attachment.get("policy_arn"), "${aws_iam_policy.terraform_read.arn}"
        )

    def test_control_first_apply_simulation_grant_is_retired(self) -> None:
        policy_resource = find_resource_body(
            REPO_ROOT / "terraform" / "modules" / "ecr",
            "aws_iam_policy",
            "terraform_read",
        )
        policy = extract_policy_body(policy_resource.get("policy"))
        self.assertIsNotNone(policy)
        assert policy is not None
        simulation_actions = {
            action
            for policy_stmt in policy.get("Statement", []) or []
            if isinstance(policy_stmt, dict)
            for action in normalized_strings(policy_stmt.get("Action"))
            if action.startswith("iam:Simulate")
        }

        self.assertEqual(simulation_actions, set())
        self.assertFalse(
            any(
                unquote(statement.get("Sid")) == "ControlFirstApplySelfSimulation"
                for statement in policy.get("Statement", []) or []
                if isinstance(statement, dict)
            )
        )

    def test_directconnect_grant_exactly_matches_audit_calls(self) -> None:
        policy_resource = find_resource_body(
            REPO_ROOT / "terraform" / "modules" / "ecr",
            "aws_iam_policy",
            "terraform_read",
        )
        policy = extract_policy_body(policy_resource.get("policy"))
        self.assertIsNotNone(policy)
        assert policy is not None
        stmt = find_policy_statement(
            REPO_ROOT / "terraform" / "modules" / "ecr",
            "terraform_read",
            "DirectConnectRead",
        )
        granted_actions = set(normalized_strings(stmt.get("Action")))
        all_directconnect_actions = {
            action
            for policy_stmt in policy.get("Statement", []) or []
            if isinstance(policy_stmt, dict)
            for action in normalized_strings(policy_stmt.get("Action"))
            if action.startswith("directconnect:")
        }
        audit_actions = directconnect_audit_actions()

        self.assertEqual(audit_actions, EXPECTED_DIRECTCONNECT_AUDIT_ACTIONS)
        self.assertEqual(granted_actions, audit_actions)
        self.assertEqual(all_directconnect_actions, audit_actions)
        self.assertFalse(
            any("*" in action for action in all_directconnect_actions),
            "Control routing audit must not gain wildcard Direct Connect access",
        )
        self.assertEqual(unquote(stmt.get("Effect")), "Allow")
        self.assertEqual(normalized_strings(stmt.get("Resource")), ["*"])
        self.assertNotIn("Condition", stmt)
        self.assertNotIn("NotAction", stmt)

    def test_terraform_read_has_exact_iam_size_guard(self) -> None:
        body = find_resource_body(
            REPO_ROOT / "terraform" / "modules" / "ecr",
            "aws_iam_policy",
            "terraform_read",
        )
        lifecycle = as_list(body.get("lifecycle"))
        self.assertEqual(len(lifecycle), 1)
        self.assertIsInstance(lifecycle[0], dict)
        postconditions = as_list(lifecycle[0].get("postcondition"))
        self.assertEqual(len(postconditions), 1)
        self.assertIsInstance(postconditions[0], dict)
        self.assertEqual(postconditions[0].get("condition"), "${length(self.policy) <= 6144}")
        self.assertIn("6,144-character", unquote(postconditions[0].get("error_message")))


class ConnectorAuthorityApplyPolicyTests(unittest.TestCase):
    def test_existing_apply_role_covers_publisher_role_creation(self) -> None:
        stmt = find_policy_statement(
            REPO_ROOT / "terraform", "terraform_apply_iam", "IAMRoles"
        )
        actions = set(normalized_strings(stmt.get("Action")))
        resources = set(normalized_strings(stmt.get("Resource")))

        self.assertTrue(
            {
                "iam:CreateRole",
                "iam:DeleteRole",
                "iam:PutRolePolicy",
                "iam:DeleteRolePolicy",
                "iam:TagRole",
                "iam:UntagRole",
                "iam:UpdateAssumeRolePolicy",
            }
            <= actions
        )
        self.assertIn(
            "arn:aws:iam::${local.account_id}:role/layerv-nhp-*", resources
        )
        self.assertNotIn("arn:aws:iam::*:role/*", resources)

    def test_apply_data_has_plan_time_iam_size_guard(self) -> None:
        body = find_resource_body(
            REPO_ROOT / "terraform" / "modules" / "ecr",
            "aws_iam_policy",
            "terraform_apply_data",
        )
        lifecycle = as_list(body.get("lifecycle"))
        self.assertEqual(len(lifecycle), 1)
        self.assertIsInstance(lifecycle[0], dict)
        postconditions = as_list(lifecycle[0].get("postcondition"))
        self.assertEqual(len(postconditions), 1)
        self.assertIsInstance(postconditions[0], dict)
        self.assertEqual(postconditions[0].get("condition"), "${length(self.policy) <= 6144}")
        self.assertIn("6,144-character", unquote(postconditions[0].get("error_message")))

    def test_elasticache_rbac_is_control_namespace_only(self) -> None:
        stmt = find_policy_statement(
            REPO_ROOT / "terraform", "terraform_apply_data", "ElastiCacheControlRBAC"
        )

        self.assertEqual(
            set(normalized_strings(stmt.get("Resource"))),
            {
                "arn:aws:elasticache:${local.region}:${local.account_id}:user:layerv-nhp-${var.environment}-control-*",
                "arn:aws:elasticache:${local.region}:${local.account_id}:usergroup:layerv-nhp-${var.environment}-control-*",
            },
        )
        self.assertEqual(
            set(normalized_strings(stmt.get("Action"))),
            {
                "elasticache:CreateUser",
                "elasticache:ModifyUser",
                "elasticache:DeleteUser",
                "elasticache:DescribeUsers",
                "elasticache:CreateUserGroup",
                "elasticache:ModifyUserGroup",
                "elasticache:DeleteUserGroup",
                "elasticache:DescribeUserGroups",
                "elasticache:ListTagsForResource",
                "elasticache:AddTagsToResource",
                "elasticache:RemoveTagsFromResource",
            },
        )

    def test_cache_user_group_dependency_is_exact(self) -> None:
        stmt = find_policy_statement(
            REPO_ROOT / "terraform",
            "terraform_apply_data",
            "ElastiCacheControlCacheUserGroupDependency",
        )

        self.assertEqual(
            normalized_strings(stmt.get("Resource")),
            [
                "arn:aws:elasticache:${local.region}:${local.account_id}:usergroup:layerv-nhp-${var.environment}-control-otp-users"
            ],
        )
        self.assertEqual(
            set(normalized_strings(stmt.get("Action"))),
            {
                "elasticache:CreateServerlessCache",
                "elasticache:ModifyServerlessCache",
            },
        )
        self.assertNotIn(
            "elasticache:DeleteServerlessCache",
            normalized_strings(stmt.get("Action")),
        )
        self.assertFalse(
            any("*" in value for value in normalized_strings(stmt.get("Resource")))
        )


class DynamoDBReadPolicyTests(unittest.TestCase):
    def test_qurl_agent_keys_read_is_narrowly_scoped(self) -> None:
        policy = find_policy_expression(REPO_ROOT / "terraform", "dynamodb_read")
        broad_start = policy.index('Sid = "DynamoDBReadAccess"')
        get_start = policy.index('Sid = "DynamoDBQurlAgentKeysGetItem"')
        query_start = policy.index('Sid = "DynamoDBQurlAgentKeysPubkeyIndexQuery"')
        condition_start = policy.index('Sid = "DynamoDBQurlAgentKeysTransactionCondition"')
        next_start = policy.index("var.kms_key_arn", condition_start)

        broad_stmt = policy[broad_start:get_start]
        self.assertNotIn("qurl_agent_keys", broad_stmt)

        read_conditional = policy[
            policy.rindex("var.deploy_qurl_tables ? [", 0, get_start):condition_start
        ]
        self.assertIn('Action = ["dynamodb:GetItem"]', read_conditional)
        self.assertIn('Action = ["dynamodb:Query"]', read_conditional)
        self.assertNotIn("Resource = []", read_conditional)

        get_stmt = policy[get_start:query_start]
        self.assertIn('Action = ["dynamodb:GetItem"]', get_stmt)
        self.assertIn("Resource = aws_dynamodb_table.qurl_agent_keys[0].arn", get_stmt)
        self.assertNotIn("dynamodb:Query", get_stmt)
        self.assertNotIn("pubkey-index", get_stmt)

        query_stmt = policy[query_start:condition_start]
        self.assertIn('Action = ["dynamodb:Query"]', query_stmt)
        self.assertIn(
            'Resource = "${aws_dynamodb_table.qurl_agent_keys[0].arn}/index/pubkey-index"',
            query_stmt,
        )
        self.assertNotIn("dynamodb:GetItem", query_stmt)
        self.assertNotIn("Resource = aws_dynamodb_table.qurl_agent_keys[0].arn", query_stmt)

        for stmt in (get_stmt, query_stmt):
            self.assertNotIn("dynamodb:Scan", stmt)
            self.assertNotIn("dynamodb:PutItem", stmt)
            self.assertNotIn("dynamodb:UpdateItem", stmt)
            self.assertNotIn("${aws_dynamodb_table.qurl_agent_keys[0].arn}/index/*", stmt)

        condition_stmt = policy[condition_start:next_start]
        self.assertIn('Action = ["dynamodb:ConditionCheckItem"]', condition_stmt)
        self.assertIn("Resource = aws_dynamodb_table.qurl_agent_keys[0].arn", condition_stmt)
        self.assertIn(
            '"dynamodb:EnclosingOperation" = "TransactWriteItems"',
            condition_stmt,
        )
        self.assertNotIn("dynamodb:GetItem", condition_stmt)
        self.assertNotIn("dynamodb:Query", condition_stmt)
        self.assertNotIn("/index/", condition_stmt)


if __name__ == "__main__":
    unittest.main()
