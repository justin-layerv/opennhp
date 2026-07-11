#!/usr/bin/env python3

from __future__ import annotations

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


def hcl_string_list(values: tuple[str, ...]) -> str:
    body = ",\n".join(f'            "{value}"' for value in values)
    return f"[\n{body}\n          ]"


def as_list(value: object) -> list[object]:
    if isinstance(value, list):
        return value
    return [value]


def normalized_strings(value: object) -> list[str]:
    return [unquote(item) for item in as_list(value) if isinstance(item, str)]


def find_policy_statement(terraform_root: Path, policy_name: str, sid: str) -> dict:
    for _file, rtype, name, body in iter_resources(parse_tf_files(terraform_root)):
        if rtype != "aws_iam_policy" or name != policy_name:
            continue
        policy = extract_policy_body(body.get("policy"))
        if policy is None:
            raise AssertionError(f"aws_iam_policy.{policy_name} policy could not be decoded")
        for stmt in policy.get("Statement", []) or []:
            if isinstance(stmt, dict) and unquote(stmt.get("Sid")) == sid:
                return stmt
        raise AssertionError(f"aws_iam_policy.{policy_name} has no Sid={sid}")
    raise AssertionError(f"aws_iam_policy.{policy_name} not found")


def find_policy_expression(terraform_root: Path, policy_name: str) -> str:
    for _file, rtype, name, body in iter_resources(parse_tf_files(terraform_root)):
        if rtype != "aws_iam_policy" or name != policy_name:
            continue
        policy = body.get("policy")
        if not isinstance(policy, str):
            raise AssertionError(f"aws_iam_policy.{policy_name} policy is not a string expression")
        return " ".join(policy.split())
    raise AssertionError(f"aws_iam_policy.{policy_name} not found")


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
          Resource = ["arn:aws:lambda:${local.region}:${local.account_id}:function:${var.name_prefix}-relay-status"]
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
            '"arn:aws:lambda:${local.region}:${local.account_id}:function:${var.name_prefix}-relay-status"',
            '"arn:aws:lambda:${local.region}:${local.account_id}:function:*"',
        )

        self.assertEqual(result.returncode, 1, result.stderr + result.stdout)
        self.assertIn("exact read-only relay status Lambda", result.stderr)

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


class DynamoDBReadPolicyTests(unittest.TestCase):
    def test_qurl_agent_keys_read_is_narrowly_scoped(self) -> None:
        policy = find_policy_expression(REPO_ROOT / "terraform", "dynamodb_read")
        broad_start = policy.index('Sid = "DynamoDBReadAccess"')
        get_start = policy.index('Sid = "DynamoDBQurlAgentKeysGetItem"')
        query_start = policy.index('Sid = "DynamoDBQurlAgentKeysPubkeyIndexQuery"')
        next_start = policy.index("var.kms_key_arn", query_start)

        broad_stmt = policy[broad_start:get_start]
        self.assertNotIn("qurl_agent_keys", broad_stmt)

        agent_conditional = policy[policy.rindex("var.deploy_qurl_tables ? [", 0, get_start):next_start]
        self.assertIn('Action = ["dynamodb:GetItem"]', agent_conditional)
        self.assertIn('Action = ["dynamodb:Query"]', agent_conditional)
        self.assertNotIn("Resource = []", agent_conditional)

        get_stmt = policy[get_start:query_start]
        self.assertIn('Action = ["dynamodb:GetItem"]', get_stmt)
        self.assertIn("Resource = aws_dynamodb_table.qurl_agent_keys[0].arn", get_stmt)
        self.assertNotIn("dynamodb:Query", get_stmt)
        self.assertNotIn("pubkey-index", get_stmt)

        query_stmt = policy[query_start:next_start]
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


if __name__ == "__main__":
    unittest.main()
