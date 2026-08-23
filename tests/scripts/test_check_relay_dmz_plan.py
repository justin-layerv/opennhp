#!/usr/bin/env python3
"""Deterministic positive and mutation fixtures for the relay DMZ plan gate."""

from __future__ import annotations

import base64
import copy
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / ".github" / "scripts" / "check-relay-dmz-plan.py"
REAL_PLAN_SHAPES = (
    REPO_ROOT
    / "tests"
    / "fixtures"
    / "relay-dmz-plan"
    / "sandbox-refresh-false-shapes.json"
)
SANDBOX_PROVIDER_LOCK = (
    REPO_ROOT / "terraform" / "environments" / "sandbox" / ".terraform.lock.hcl"
)
SPEC = importlib.util.spec_from_file_location("check_relay_dmz_plan", SCRIPT)
assert SPEC and SPEC.loader
checker = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = checker
SPEC.loader.exec_module(checker)


FIXTURE_RELAY_SECRET_ARN = (
    "arn:aws:secretsmanager:us-east-2:767397897469:"
    "secret:layerv-nhp-sandbox-relay-abc123"
)
FIXTURE_SECRETS_KMS_ARN = (
    f"arn:aws:kms:us-east-2:{checker.EXPECTED_SANDBOX_ACCOUNT_ID}:key/example"
)
CANONICAL_DEREGISTRATION_DELAY_VALUES = (30, "30")
INVALID_DEREGISTRATION_DELAY_VALUES = (
    29,
    "29",
    30.0,
    "30.0",
    " 30",
    "30 ",
    "+30",
    "030",
    None,
    True,
    False,
)
PROOF_SOURCE_RULE_SUFFIX = (
    f'.server_nlb_udp["{checker.EXPECTED_SANDBOX_PROOF_SOURCE_CIDR}"]'
)
PROOF_SOURCE_RULE_ADDRESS_SUFFIX = (
    "aws_vpc_security_group_ingress_rule" + PROOF_SOURCE_RULE_SUFFIX
)
# The shared migration-plan builder below composes a GREEN-active plan, so it
# must read the green capture. The blue capture is exercised separately.
UDP_SOURCE_FENCE_PROVIDER_FIXTURE = (
    REPO_ROOT
    / "tests"
    / "fixtures"
    / "cell0-udp-source-fence"
    / "active-green-replacement-terraform-1.14.3-aws-6.54.0.json"
)
MANAGED_ACTIVE_COLOR_LISTENER_REFS = (
    "var.enable_blue_green",
    "aws_ssm_parameter.active_color[0].value",
    "aws_ssm_parameter.active_color[0]",
    "aws_ssm_parameter.active_color",
    "aws_lb_target_group.udp[0].arn",
    "aws_lb_target_group.udp[0]",
    "aws_lb_target_group.udp",
    "aws_lb_target_group.udp_green[0].arn",
    "aws_lb_target_group.udp_green[0]",
    "aws_lb_target_group.udp_green",
)


def sandbox_udp_target_group_arn(name: str, suffix: str) -> str:
    return (
        f"arn:aws:elasticloadbalancing:{checker.EXPECTED_SANDBOX_REGION}:"
        f"{checker.EXPECTED_SANDBOX_ACCOUNT_ID}:targetgroup/{name}/{suffix}"
    )


def endpoint_policy(key: str) -> str:
    allows: dict[str, list[dict[str, Any]]] = {
        "ecr-api": [
            {
                "Sid": "RelayAuthorizationToken",
                "Effect": "Allow",
                "Principal": "*",
                "Action": "ecr:GetAuthorizationToken",
                "Resource": "*",
            },
            {
                "Sid": "RelayRepositoryRead",
                "Effect": "Allow",
                "Principal": "*",
                "Action": [
                    "ecr:BatchCheckLayerAvailability",
                    "ecr:BatchGetImage",
                    "ecr:GetDownloadUrlForLayer",
                ],
                "Resource": checker.EXPECTED_SANDBOX_RELAY_REPO_ARN,
            },
        ],
        "ecr-dkr": [
            {
                "Sid": "RelayRepositoryRegistryRead",
                "Effect": "Allow",
                "Principal": "*",
                "Action": [
                    "ecr:BatchCheckLayerAvailability",
                    "ecr:BatchGetImage",
                    "ecr:GetDownloadUrlForLayer",
                ],
                "Resource": checker.EXPECTED_SANDBOX_RELAY_REPO_ARN,
            }
        ],
        "secretsmanager": [
            {
                "Sid": "RelayIdentityRead",
                "Effect": "Allow",
                "Principal": "*",
                "Action": "secretsmanager:GetSecretValue",
                "Resource": FIXTURE_RELAY_SECRET_ARN,
            }
        ],
        "ssm": [
            {
                "Sid": "RelayImageTagRead",
                "Effect": "Allow",
                "Principal": "*",
                "Action": "ssm:GetParameter",
                "Resource": checker.EXPECTED_SANDBOX_IMAGE_TAG_PARAMETER_ARN,
            },
            {
                "Sid": "RelayManagedInstanceCore",
                "Effect": "Allow",
                "Principal": "*",
                "Action": sorted(checker.EXPECTED_RELAY_IAM_SSM_ACTIONS),
                "Resource": "*",
            },
        ],
        "ssmmessages": [
            {
                "Sid": "RelaySessionChannels",
                "Effect": "Allow",
                "Principal": "*",
                "Action": sorted(checker.EXPECTED_INTERFACE_ENDPOINTS["ssmmessages"]),
                "Resource": "*",
            }
        ],
        "logs": [
            {
                "Sid": "RelayLogWrite",
                "Effect": "Allow",
                "Principal": "*",
                "Action": sorted(checker.EXPECTED_INTERFACE_ENDPOINTS["logs"]),
                "Resource": checker.EXPECTED_SANDBOX_RELAY_LOG_GROUP_ARN,
            }
        ],
        "monitoring": [
            {
                "Sid": "RelayMetrics",
                "Effect": "Allow",
                "Principal": "*",
                "Action": "cloudwatch:PutMetricData",
                "Resource": "*",
                "Condition": {
                    "StringEquals": {
                        "cloudwatch:namespace": checker.EXPECTED_METRIC_NAMESPACE
                    }
                },
            }
        ],
        "guardduty-data": [
            {
                "Sid": "RelayRuntimeTelemetry",
                "Effect": "Allow",
                "Principal": "*",
                "Action": "*",
                "Resource": "*",
            }
        ],
    }
    deny = {
        "Sid": "DenyCrossAccountPrincipals",
        "Effect": "Deny",
        "Principal": "*",
        "Action": "*",
        "Resource": "*",
        "Condition": {
            "StringNotEquals": {
                "aws:PrincipalAccount": checker.EXPECTED_SANDBOX_ACCOUNT_ID
            }
        },
    }
    return json.dumps(
        {"Version": "2012-10-17", "Statement": [*allows[key], deny]}, sort_keys=True
    )


def config_resource(
    resource_type: str,
    name: str,
    expressions: dict[str, Any],
    *,
    depends_on: list[str] | None = None,
) -> dict[str, Any]:
    normalized_expressions = copy.deepcopy(expressions)
    result: dict[str, Any] = {
        "type": resource_type,
        "name": name,
        "expressions": normalized_expressions,
    }
    count_expression = normalized_expressions.pop("count", None)
    if count_expression is not None:
        result["count_expression"] = count_expression
    for_each_expression = normalized_expressions.pop("for_each", None)
    if for_each_expression is not None:
        result["for_each_expression"] = for_each_expression
    if depends_on is not None:
        result["depends_on"] = depends_on
    return result


def relay_iam_policy() -> str:
    statements = [
        {
            "Effect": "Allow",
            "Action": ["secretsmanager:GetSecretValue"],
            "Resource": [FIXTURE_RELAY_SECRET_ARN],
        },
        {
            "Effect": "Allow",
            "Action": ["ecr:GetAuthorizationToken"],
            "Resource": "*",
        },
        {
            "Effect": "Allow",
            "Action": [
                "ecr:BatchCheckLayerAvailability",
                "ecr:GetDownloadUrlForLayer",
                "ecr:BatchGetImage",
            ],
            "Resource": checker.EXPECTED_SANDBOX_RELAY_REPO_ARN,
        },
        {
            "Effect": "Allow",
            "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
            "Resource": [checker.EXPECTED_SANDBOX_RELAY_LOG_GROUP_ARN],
        },
        {
            "Effect": "Allow",
            "Action": ["ssm:GetParameter"],
            "Resource": [checker.EXPECTED_SANDBOX_IMAGE_TAG_PARAMETER_ARN],
        },
        {
            "Effect": "Allow",
            "Action": sorted(checker.EXPECTED_RELAY_IAM_SSM_ACTIONS),
            "Resource": "*",
        },
        {
            "Effect": "Allow",
            "Action": sorted(checker.EXPECTED_INTERFACE_ENDPOINTS["ssmmessages"]),
            "Resource": "*",
        },
        {
            "Effect": "Allow",
            "Action": ["s3:GetObject"],
            "Resource": sorted(checker.EXPECTED_RELAY_IAM_S3_RESOURCES),
        },
        {
            "Effect": "Allow",
            "Action": ["cloudwatch:PutMetricData"],
            "Resource": "*",
            "Condition": {
                "StringEquals": {
                    "cloudwatch:namespace": checker.EXPECTED_METRIC_NAMESPACE
                }
            },
        },
        {
            "Effect": "Allow",
            "Action": ["kms:Decrypt"],
            "Resource": [FIXTURE_SECRETS_KMS_ARN],
            "Condition": {
                "StringEquals": {
                    "kms:CallerAccount": checker.EXPECTED_SANDBOX_ACCOUNT_ID,
                    "kms:ViaService": "secretsmanager.us-east-2.amazonaws.com",
                }
            },
        },
    ]
    return json.dumps(
        {"Version": "2012-10-17", "Statement": statements}, sort_keys=True
    )


def policy_statement(policy: dict[str, Any], action: str) -> dict[str, Any]:
    matches = [
        statement
        for statement in policy["Statement"]
        if action in checker.as_strings(statement.get("Action"))
    ]
    if len(matches) != 1:
        raise AssertionError(
            f"fixture expected one statement containing {action!r}; found {len(matches)}"
        )
    return matches[0]


def statement_by_sid(policy: dict[str, Any], sid: str) -> dict[str, Any]:
    matches = [
        statement for statement in policy["Statement"] if statement.get("Sid") == sid
    ]
    if len(matches) != 1:
        raise AssertionError(
            f"fixture expected one statement with Sid {sid!r}; found {len(matches)}"
        )
    return matches[0]


def context_lookups_policy() -> str:
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "ContextLookups",
                    "Effect": "Allow",
                    "Action": ["ec2:DescribeInstances", "ssm:GetParameter"],
                    "Resource": "*",
                },
            ],
        },
        sort_keys=True,
    )


def context_lookups_relay_ssm_policy() -> str:
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "SSMHealthCheckDocument",
                    "Effect": "Allow",
                    "Action": "ssm:SendCommand",
                    "Resource": "arn:aws:ssm:us-east-2::document/AWS-RunShellScript",
                },
                {
                    "Sid": "SSMHealthCheckSandboxInstances",
                    "Effect": "Allow",
                    "Action": "ssm:SendCommand",
                    "Resource": f"arn:aws:ec2:us-east-2:{checker.EXPECTED_SANDBOX_ACCOUNT_ID}:instance/*",
                    "Condition": {
                        "StringEquals": {
                            "ssm:resourceTag/Environment": [
                                "sandbox",
                                "sandbox-cell1",
                            ]
                        }
                    },
                },
                {
                    "Sid": "SSMHealthCheckInvocation",
                    "Effect": "Allow",
                    "Action": "ssm:GetCommandInvocation",
                    "Resource": "*",
                },
            ],
        },
        sort_keys=True,
    )


def logs_kms_policy() -> str:
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "EnableAccountAdministration",
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": f"arn:aws:iam::{checker.EXPECTED_SANDBOX_ACCOUNT_ID}:root"
                    },
                    "Action": "kms:*",
                    "Resource": "*",
                },
                {
                    "Sid": "AllowDmzCloudWatchLogs",
                    "Effect": "Allow",
                    "Principal": {"Service": "logs.us-east-2.amazonaws.com"},
                    "Action": sorted(checker.EXPECTED_LOG_KMS_ACTIONS),
                    "Resource": "*",
                    "Condition": {
                        "ArnEquals": {
                            "kms:EncryptionContext:aws:logs:arn": [
                                f"arn:aws:logs:us-east-2:{checker.EXPECTED_SANDBOX_ACCOUNT_ID}:log-group:/layerv/nhp/sandbox/relay-dmz/flow",
                                f"arn:aws:logs:us-east-2:{checker.EXPECTED_SANDBOX_ACCOUNT_ID}:log-group:/layerv/nhp/sandbox/relay-dmz/resolver",
                            ]
                        },
                    },
                },
            ],
        },
        sort_keys=True,
    )


def flow_logs_policy() -> str:
    group_arn = (
        f"arn:aws:logs:us-east-2:{checker.EXPECTED_SANDBOX_ACCOUNT_ID}:"
        "log-group:/layerv/nhp/sandbox/relay-dmz/flow"
    )
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "DiscoverFlowLogGroup",
                    "Effect": "Allow",
                    "Action": "logs:DescribeLogGroups",
                    "Resource": "*",
                },
                {
                    "Sid": "DescribeFlowLogStreams",
                    "Effect": "Allow",
                    "Action": "logs:DescribeLogStreams",
                    "Resource": group_arn,
                },
                {
                    "Sid": "WriteFlowLogStreams",
                    "Effect": "Allow",
                    "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
                    "Resource": f"{group_arn}:*",
                },
            ],
        },
        sort_keys=True,
    )


def flow_logs_trust_policy() -> str:
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "vpc-flow-logs.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                    "Condition": {
                        "StringEquals": {
                            "aws:SourceAccount": checker.EXPECTED_SANDBOX_ACCOUNT_ID
                        },
                        "ArnLike": {
                            "aws:SourceArn": f"arn:aws:ec2:us-east-2:{checker.EXPECTED_SANDBOX_ACCOUNT_ID}:vpc-flow-log/*"
                        },
                    },
                }
            ],
        },
        sort_keys=True,
    )


def clean_plan() -> dict[str, Any]:
    plan: dict[str, Any] = {
        "format_version": "1.2",
        "resource_changes": [],
        "configuration": {
            "root_module": {
                "module_calls": {
                    "nhp": {
                        "module": {
                            "module_calls": {
                                "relay_network": {
                                    "expressions": {
                                        "apply_role_ready_token": {
                                            "references": [
                                                "time_sleep.relay_dmz_iam_propagation[0].id",
                                                "time_sleep.relay_dmz_iam_propagation[0]",
                                                "time_sleep.relay_dmz_iam_propagation",
                                            ]
                                        },
                                        "main_private_route_table_ids": {
                                            "references": [
                                                "module.networking.private_route_table_ids"
                                            ]
                                        },
                                    },
                                    "module": {
                                        "module_calls": {},
                                        "resources": [
                                            config_resource(
                                                "terraform_data",
                                                "apply_role_ready",
                                                {
                                                    "input": {
                                                        "references": [
                                                            "var.apply_role_ready_token"
                                                        ]
                                                    }
                                                },
                                            ),
                                            config_resource(
                                                "aws_vpc",
                                                "relay",
                                                {},
                                                depends_on=[
                                                    "terraform_data.apply_role_ready"
                                                ],
                                            ),
                                            config_resource(
                                                "aws_iam_role",
                                                "flow",
                                                {},
                                                depends_on=[
                                                    "terraform_data.apply_role_ready"
                                                ],
                                            ),
                                            config_resource(
                                                "aws_route53_resolver_firewall_domain_list",
                                                "allow",
                                                {},
                                                depends_on=[
                                                    "terraform_data.apply_role_ready"
                                                ],
                                            ),
                                            config_resource(
                                                "aws_route53_resolver_firewall_domain_list",
                                                "all",
                                                {},
                                                depends_on=[
                                                    "terraform_data.apply_role_ready"
                                                ],
                                            ),
                                            config_resource(
                                                "aws_route53_resolver_firewall_rule_group",
                                                "relay",
                                                {},
                                                depends_on=[
                                                    "terraform_data.apply_role_ready"
                                                ],
                                            ),
                                            config_resource(
                                                "aws_route_table", "public", {}
                                            ),
                                            config_resource(
                                                "aws_route_table", "relay", {}
                                            ),
                                            config_resource(
                                                "aws_route_table", "endpoint", {}
                                            ),
                                            config_resource(
                                                "aws_security_group",
                                                "endpoints",
                                                {
                                                    "ingress": {"constant_value": []},
                                                    "egress": {"constant_value": []},
                                                },
                                            ),
                                            config_resource(
                                                "aws_route_table_association",
                                                "public",
                                                {
                                                    "subnet_id": {
                                                        "references": [
                                                            "aws_subnet.public",
                                                            "count.index",
                                                        ]
                                                    },
                                                    "route_table_id": {
                                                        "references": [
                                                            "aws_route_table.public.id",
                                                            "aws_route_table.public",
                                                        ]
                                                    },
                                                },
                                            ),
                                            config_resource(
                                                "aws_route_table_association",
                                                "relay",
                                                {
                                                    "subnet_id": {
                                                        "references": [
                                                            "aws_subnet.relay",
                                                            "count.index",
                                                        ]
                                                    },
                                                    "route_table_id": {
                                                        "references": [
                                                            "aws_route_table.relay",
                                                            "count.index",
                                                        ]
                                                    },
                                                },
                                            ),
                                            config_resource(
                                                "aws_route_table_association",
                                                "endpoint",
                                                {
                                                    "subnet_id": {
                                                        "references": [
                                                            "aws_subnet.endpoint",
                                                            "count.index",
                                                        ]
                                                    },
                                                    "route_table_id": {
                                                        "references": [
                                                            "aws_route_table.endpoint",
                                                            "count.index",
                                                        ]
                                                    },
                                                },
                                            ),
                                            config_resource(
                                                "aws_route",
                                                "public_default",
                                                {
                                                    "gateway_id": {
                                                        "references": [
                                                            "aws_internet_gateway.relay.id",
                                                            "aws_internet_gateway.relay",
                                                        ]
                                                    },
                                                    "route_table_id": {
                                                        "references": [
                                                            "aws_route_table.public.id",
                                                            "aws_route_table.public",
                                                        ]
                                                    },
                                                },
                                            ),
                                            config_resource(
                                                "aws_route",
                                                "relay_to_main_private",
                                                {
                                                    "vpc_peering_connection_id": {
                                                        "references": [
                                                            "aws_vpc_peering_connection.main.id",
                                                            "aws_vpc_peering_connection.main",
                                                        ]
                                                    }
                                                },
                                            ),
                                            config_resource(
                                                "aws_route",
                                                "main_private_to_relay",
                                                {
                                                    "vpc_peering_connection_id": {
                                                        "references": [
                                                            "aws_vpc_peering_connection.main.id",
                                                            "aws_vpc_peering_connection.main",
                                                        ]
                                                    },
                                                    "route_table_id": {
                                                        "references": [
                                                            "var.main_private_route_table_ids"
                                                        ]
                                                    },
                                                },
                                            ),
                                            config_resource(
                                                "aws_vpc_endpoint",
                                                "s3",
                                                {
                                                    "route_table_ids": {
                                                        "references": [
                                                            "aws_route_table.relay"
                                                        ]
                                                    }
                                                },
                                            ),
                                            config_resource(
                                                "aws_vpc_endpoint",
                                                "interface",
                                                {
                                                    "policy": {
                                                        "references": [
                                                            "local.endpoint_policies",
                                                            "each.key",
                                                        ]
                                                    },
                                                    "subnet_ids": {
                                                        "references": [
                                                            "aws_subnet.endpoint"
                                                        ]
                                                    },
                                                    "security_group_ids": {
                                                        "references": [
                                                            "aws_security_group.endpoints.id",
                                                            "aws_security_group.endpoints",
                                                        ]
                                                    },
                                                },
                                            ),
                                            config_resource(
                                                "aws_kms_key",
                                                "logs",
                                                {
                                                    "policy": {
                                                        "references": [
                                                            "data.aws_caller_identity.current.account_id",
                                                            "data.aws_caller_identity.current",
                                                            "data.aws_region.current.region",
                                                            "data.aws_region.current",
                                                            "data.aws_partition.current.dns_suffix",
                                                            "data.aws_partition.current.partition",
                                                            "data.aws_partition.current",
                                                            "local.flow_log_group_arn",
                                                            "local.resolver_log_group_arn",
                                                        ]
                                                    },
                                                },
                                                depends_on=[
                                                    "terraform_data.apply_role_ready"
                                                ],
                                            ),
                                            config_resource(
                                                "aws_cloudwatch_log_group",
                                                "flow",
                                                {
                                                    "kms_key_id": {
                                                        "references": [
                                                            "aws_kms_key.logs.arn",
                                                            "aws_kms_key.logs",
                                                        ]
                                                    }
                                                },
                                            ),
                                            config_resource(
                                                "aws_cloudwatch_log_group",
                                                "resolver",
                                                {
                                                    "kms_key_id": {
                                                        "references": [
                                                            "aws_kms_key.logs.arn",
                                                            "aws_kms_key.logs",
                                                        ]
                                                    }
                                                },
                                            ),
                                        ],
                                    },
                                },
                                "networking": {
                                    "expressions": {
                                        "enable_extensible_private_route_tables": {
                                            "references": ["var.deploy_relay"]
                                        },
                                        "extensible_private_route_table_ready_token": {
                                            "references": [
                                                "var.deploy_relay",
                                                "time_sleep.relay_dmz_iam_propagation[0].id",
                                            ]
                                        },
                                    },
                                    "module": {
                                        "module_calls": {},
                                        "outputs": {
                                            "private_route_table_ids": {
                                                "expression": {
                                                    "references": [
                                                        "local.active_private_route_table_ids"
                                                    ]
                                                }
                                            }
                                        },
                                        "resources": [
                                            config_resource(
                                                "aws_route_table",
                                                "private",
                                                {
                                                    "route": {
                                                        "references": [
                                                            "aws_nat_gateway.main"
                                                        ]
                                                    }
                                                },
                                            ),
                                            config_resource(
                                                "aws_route_table",
                                                "private_extensible",
                                                {
                                                    "count": {
                                                        "references": [
                                                            "var.enable_extensible_private_route_tables"
                                                        ]
                                                    }
                                                },
                                            ),
                                            config_resource(
                                                "aws_route",
                                                "private_extensible_default",
                                                {
                                                    "route_table_id": {
                                                        "references": [
                                                            "aws_route_table.private_extensible"
                                                        ]
                                                    },
                                                    "nat_gateway_id": {
                                                        "references": [
                                                            "aws_nat_gateway.main"
                                                        ]
                                                    },
                                                },
                                            ),
                                            config_resource(
                                                "aws_route_table_association",
                                                "private",
                                                {
                                                    "route_table_id": {
                                                        "references": [
                                                            "local.active_private_route_table_ids"
                                                        ]
                                                    }
                                                },
                                                depends_on=[
                                                    "aws_route.private_extensible_default",
                                                    "terraform_data.private_extensible_association_ready",
                                                ],
                                            ),
                                            config_resource(
                                                "terraform_data",
                                                "private_extensible_association_ready",
                                                {
                                                    "input": {
                                                        "references": [
                                                            "var.extensible_private_route_table_ready_token"
                                                        ]
                                                    }
                                                },
                                            ),
                                            config_resource(
                                                "aws_vpc_endpoint",
                                                "s3",
                                                {
                                                    "route_table_ids": {
                                                        "references": [
                                                            "local.all_private_route_table_ids"
                                                        ]
                                                    }
                                                },
                                            ),
                                            config_resource(
                                                "aws_vpc_endpoint",
                                                "dynamodb",
                                                {
                                                    "route_table_ids": {
                                                        "references": [
                                                            "local.all_private_route_table_ids"
                                                        ]
                                                    }
                                                },
                                            ),
                                        ],
                                    },
                                },
                                "ecr": {
                                    "expressions": {
                                        "deploy_relay_network": {
                                            "references": ["var.deploy_relay"]
                                        }
                                    },
                                    "module": {
                                        "module_calls": {},
                                        "resources": [
                                            config_resource(
                                                "aws_iam_role_policy",
                                                "context_lookups",
                                                {
                                                    "policy": {
                                                        "references": [
                                                            "var.deploy_relay_network",
                                                            "var.environment",
                                                            "local.region",
                                                            "local.account_id",
                                                        ]
                                                    }
                                                },
                                            ),
                                            config_resource(
                                                "aws_iam_role_policy",
                                                "context_lookups_relay_ssm",
                                                {
                                                    "count": {
                                                        "references": [
                                                            "var.deploy_relay_network"
                                                        ]
                                                    },
                                                    "policy": {
                                                        "references": [
                                                            "var.environment",
                                                            "local.region",
                                                            "local.account_id",
                                                        ]
                                                    },
                                                },
                                            ),
                                        ],
                                    },
                                },
                                "relay": {
                                    "expressions": {
                                        "vpc_id": {
                                            "references": [
                                                "module.relay_network[0].vpc_id",
                                                "module.relay_network[0]",
                                            ]
                                        },
                                        "public_subnet_ids": {
                                            "references": [
                                                "module.relay_network[0].public_subnet_ids",
                                                "module.relay_network[0]",
                                            ]
                                        },
                                        "relay_subnet_ids": {
                                            "references": [
                                                "module.relay_network[0].relay_subnet_ids",
                                                "module.relay_network[0]",
                                            ]
                                        },
                                        "vpc_endpoint_security_group_id": {
                                            "references": [
                                                "module.relay_network[0].endpoint_security_group_id",
                                                "module.relay_network[0]",
                                            ]
                                        },
                                        "nhp_server_cidr_blocks": {
                                            "references": [
                                                "module.networking.private_subnet_cidr_blocks",
                                                "module.networking",
                                            ]
                                        },
                                        "server_security_group_id": {
                                            "references": [
                                                "module.compute.security_group_id",
                                                "module.compute",
                                            ]
                                        },
                                        "cell_servers": {
                                            "references": [
                                                "terraform_data.relay_cell_routing[0].input",
                                                "terraform_data.relay_cell_routing[0]",
                                                "terraform_data.relay_cell_routing",
                                            ]
                                        },
                                        "network_ready_token": {
                                            "references": [
                                                "terraform_data.relay_network_ready[0].output",
                                                "terraform_data.relay_network_ready[0]",
                                                "terraform_data.relay_network_ready",
                                            ]
                                        },
                                    },
                                    "module": {
                                        "module_calls": {},
                                        "resources": [
                                            config_resource(
                                                "terraform_data",
                                                "network_ready",
                                                {
                                                    "input": {
                                                        "references": [
                                                            "var.network_ready_token"
                                                        ]
                                                    }
                                                },
                                            ),
                                            config_resource(
                                                "terraform_data",
                                                "fleet_security_ready",
                                                {
                                                    "input": {
                                                        "references": [
                                                            "aws_security_group.relay.id",
                                                            "aws_security_group.relay",
                                                        ]
                                                    }
                                                },
                                                depends_on=[
                                                    "aws_vpc_security_group_ingress_rule.alb_https",
                                                    "aws_vpc_security_group_egress_rule.alb_to_relay",
                                                    "aws_vpc_security_group_ingress_rule.relay_http_from_alb",
                                                    "aws_vpc_security_group_ingress_rule.relay_udp_ack_return",
                                                    "aws_vpc_security_group_egress_rule.relay_to_nhp_udp",
                                                    "aws_vpc_security_group_egress_rule.relay_to_vpc_endpoints_https",
                                                    "aws_vpc_security_group_ingress_rule.vpc_endpoints_from_relay",
                                                    "aws_vpc_security_group_egress_rule.relay_to_s3_https",
                                                ],
                                            ),
                                            config_resource(
                                                "aws_security_group",
                                                "alb",
                                                {
                                                    "ingress": {"constant_value": []},
                                                    "egress": {"constant_value": []},
                                                },
                                            ),
                                            config_resource(
                                                "aws_security_group", "relay", {}
                                            ),
                                            config_resource(
                                                "aws_lb",
                                                "relay",
                                                {},
                                                depends_on=[
                                                    "aws_s3_bucket_policy.alb_access_logs",
                                                    "terraform_data.network_ready",
                                                ],
                                            ),
                                            config_resource(
                                                "aws_autoscaling_group",
                                                "relay",
                                                {
                                                    "target_group_arns": {
                                                        "references": [
                                                            "aws_lb_target_group.relay.arn",
                                                            "aws_lb_target_group.relay",
                                                        ]
                                                    },
                                                },
                                                depends_on=[
                                                    "terraform_data.network_ready",
                                                    "terraform_data.fleet_security_ready",
                                                ],
                                            ),
                                            config_resource(
                                                "aws_vpc_security_group_ingress_rule",
                                                "relay_udp_ack_return",
                                                {
                                                    "security_group_id": {
                                                        "references": [
                                                            "aws_security_group.relay.id",
                                                            "aws_security_group.relay",
                                                        ]
                                                    },
                                                    "referenced_security_group_id": {
                                                        "references": [
                                                            "var.server_security_group_id"
                                                        ]
                                                    },
                                                },
                                                depends_on=[
                                                    "terraform_data.network_ready"
                                                ],
                                            ),
                                            config_resource(
                                                "aws_vpc_security_group_ingress_rule",
                                                "relay_http_from_alb",
                                                {
                                                    "security_group_id": {
                                                        "references": [
                                                            "aws_security_group.relay.id",
                                                            "aws_security_group.relay",
                                                        ]
                                                    },
                                                    "referenced_security_group_id": {
                                                        "references": [
                                                            "aws_security_group.alb.id",
                                                            "aws_security_group.alb",
                                                        ]
                                                    },
                                                },
                                            ),
                                            config_resource(
                                                "aws_vpc_security_group_egress_rule",
                                                "alb_to_relay",
                                                {
                                                    "security_group_id": {
                                                        "references": [
                                                            "aws_security_group.alb.id",
                                                            "aws_security_group.alb",
                                                        ]
                                                    },
                                                    "referenced_security_group_id": {
                                                        "references": [
                                                            "aws_security_group.relay.id",
                                                            "aws_security_group.relay",
                                                        ]
                                                    },
                                                },
                                            ),
                                            config_resource(
                                                "aws_vpc_security_group_ingress_rule",
                                                "vpc_endpoints_from_relay",
                                                {
                                                    "security_group_id": {
                                                        "references": [
                                                            "var.vpc_endpoint_security_group_id"
                                                        ]
                                                    },
                                                    "referenced_security_group_id": {
                                                        "references": [
                                                            "aws_security_group.relay.id",
                                                            "aws_security_group.relay",
                                                        ]
                                                    },
                                                },
                                            ),
                                            config_resource(
                                                "aws_vpc_security_group_ingress_rule",
                                                "alb_https",
                                                {
                                                    "security_group_id": {
                                                        "references": [
                                                            "aws_security_group.alb.id",
                                                            "aws_security_group.alb",
                                                        ]
                                                    },
                                                    "cidr_ipv4": {
                                                        "constant_value": "0.0.0.0/0"
                                                    },
                                                },
                                            ),
                                            config_resource(
                                                "aws_vpc_security_group_egress_rule",
                                                "relay_to_vpc_endpoints_https",
                                                {
                                                    "security_group_id": {
                                                        "references": [
                                                            "aws_security_group.relay.id",
                                                            "aws_security_group.relay",
                                                        ]
                                                    },
                                                    "referenced_security_group_id": {
                                                        "references": [
                                                            "var.vpc_endpoint_security_group_id"
                                                        ]
                                                    },
                                                },
                                            ),
                                            config_resource(
                                                "aws_vpc_security_group_egress_rule",
                                                "relay_to_s3_https",
                                                {
                                                    "security_group_id": {
                                                        "references": [
                                                            "aws_security_group.relay.id",
                                                            "aws_security_group.relay",
                                                        ]
                                                    },
                                                    "prefix_list_id": {
                                                        "references": [
                                                            "data.aws_prefix_list.s3.id",
                                                            "data.aws_prefix_list.s3",
                                                        ]
                                                    },
                                                },
                                            ),
                                            config_resource(
                                                "aws_vpc_security_group_egress_rule",
                                                "relay_to_nhp_udp",
                                                {
                                                    "for_each": {
                                                        "references": [
                                                            "local.nhp_server_cidr_blocks"
                                                        ]
                                                    },
                                                    "security_group_id": {
                                                        "references": [
                                                            "aws_security_group.relay.id",
                                                            "aws_security_group.relay",
                                                        ]
                                                    },
                                                    "cidr_ipv4": {
                                                        "references": ["each.value"]
                                                    },
                                                },
                                            ),
                                            config_resource(
                                                "aws_iam_role_policy",
                                                "relay",
                                                {
                                                    "policy": {
                                                        "references": [
                                                            "var.relay_secret_arn",
                                                            "var.relay_repo_arn",
                                                            "aws_cloudwatch_log_group.relay.arn",
                                                            "aws_cloudwatch_log_group.relay",
                                                            "data.aws_region.current.region",
                                                            "data.aws_region.current",
                                                            "data.aws_caller_identity.current.account_id",
                                                            "data.aws_caller_identity.current",
                                                            "var.ssm_image_tag_parameter",
                                                            "data.aws_partition.current.partition",
                                                            "data.aws_partition.current",
                                                            "data.aws_partition.current.dns_suffix",
                                                            "var.secrets_kms_key_arn",
                                                        ]
                                                    }
                                                },
                                            ),
                                        ],
                                    },
                                },
                            },
                            "resources": [],
                        }
                    }
                },
                "resources": [],
            }
        },
    }

    nhp_module = plan["configuration"]["root_module"]["module_calls"]["nhp"]["module"]
    nhp_module["outputs"] = {
        "nlb_dns_name": {
            "expression": {
                "references": ["module.compute.nlb_dns_name", "module.compute"]
            }
        },
    }
    nhp_module["resources"].append(
        config_resource(
            "time_sleep",
            "relay_dmz_iam_propagation",
            {},
            depends_on=["terraform_data.relay_dmz_preconditions"],
        )
    )
    nhp_module["resources"].append(
        config_resource(
            "terraform_data",
            "relay_cell_routing",
            {
                "count": {"references": ["var.deploy_relay"]},
                "input": {
                    "references": [
                        "var.environment",
                        "var.cell_id",
                        "module.compute.server_public_key_b64",
                        "module.compute.internal_nlb_dns_name",
                        "module.compute",
                    ]
                },
            },
        )
    )
    nhp_module["resources"].append(
        config_resource(
            "terraform_data",
            "relay_network_ready",
            {
                "count": {"references": ["var.deploy_relay"]},
                "input": {
                    "references": [
                        "module.relay_network[0].vpc_id",
                        "module.relay_network[0]",
                    ]
                },
            },
            depends_on=["module.relay_network"],
        )
    )
    nhp_module["module_calls"]["dns"] = {
        "expressions": {
            "nlb_dns_name": {
                "references": ["module.compute.nlb_dns_name", "module.compute"]
            },
            "nlb_zone_id": {
                "references": ["module.compute.nlb_zone_id", "module.compute"]
            },
        },
        "module": {"module_calls": {}, "resources": []},
    }
    nhp_module["module_calls"]["compute"] = {
        "expressions": {},
        "module": {
            "module_calls": {},
            "resources": [
                config_resource("aws_lb", "server", {}),
                config_resource(
                    "aws_lb_target_group",
                    "udp",
                    {"preserve_client_ip": {"constant_value": True}},
                ),
                config_resource(
                    "aws_lb_listener",
                    "udp",
                    {
                        "load_balancer_arn": {
                            "references": [
                                "aws_lb.server[0].arn",
                                "aws_lb.server[0]",
                                "aws_lb.server",
                            ]
                        },
                        "default_action": {
                            "references": [
                                "var.enable_blue_green",
                                "aws_ssm_parameter.active_color[0].value",
                                "aws_ssm_parameter.active_color[0]",
                                "aws_ssm_parameter.active_color",
                                "aws_lb_target_group.udp[0].arn",
                                "aws_lb_target_group.udp[0]",
                                "aws_lb_target_group.udp",
                                "aws_lb_target_group.udp_green[0].arn",
                                "aws_lb_target_group.udp_green[0]",
                                "aws_lb_target_group.udp_green",
                            ]
                        },
                    },
                ),
                config_resource(
                    "aws_autoscaling_attachment",
                    "server",
                    {
                        "autoscaling_group_name": {
                            "references": [
                                "aws_autoscaling_group.server.name",
                                "aws_autoscaling_group.server",
                            ]
                        },
                        "lb_target_group_arn": {
                            "references": [
                                "aws_lb_target_group.udp[0].arn",
                                "aws_lb_target_group.udp[0]",
                                "aws_lb_target_group.udp",
                            ]
                        },
                    },
                ),
                config_resource("aws_lb", "server_internal", {}),
                config_resource(
                    "aws_lb_target_group",
                    "udp_internal",
                    {"preserve_client_ip": {"constant_value": True}},
                ),
                config_resource(
                    "aws_lb_target_group",
                    "udp_green",
                    {"preserve_client_ip": {"constant_value": True}},
                ),
                config_resource(
                    "aws_lb_target_group",
                    "udp_internal_green",
                    {"preserve_client_ip": {"constant_value": True}},
                ),
                config_resource(
                    "aws_autoscaling_group",
                    "server_green",
                    {
                        "target_group_arns": {
                            "references": [
                                "aws_lb_target_group.udp_green[0].arn",
                                "aws_lb_target_group.udp_green[0]",
                                "aws_lb_target_group.udp_green",
                                "var.enable_qurl_resolve_endpoint",
                                "aws_lb_target_group.https_green[0].arn",
                                "aws_lb_target_group.https_green[0]",
                                "aws_lb_target_group.https_green",
                                "var.relay_enabled",
                                "aws_lb_target_group.udp_internal_green[0].arn",
                                "aws_lb_target_group.udp_internal_green[0]",
                                "aws_lb_target_group.udp_internal_green",
                            ]
                        }
                    },
                ),
                config_resource(
                    "aws_lb_listener",
                    "udp_internal",
                    {
                        "load_balancer_arn": {
                            "references": [
                                "aws_lb.server_internal[0].arn",
                                "aws_lb.server_internal[0]",
                                "aws_lb.server_internal",
                            ]
                        },
                        "default_action": {
                            "references": [
                                "aws_lb_target_group.udp_internal[0].arn",
                                "aws_lb_target_group.udp_internal[0]",
                                "aws_lb_target_group.udp_internal",
                            ]
                        },
                    },
                ),
                config_resource(
                    "aws_autoscaling_attachment",
                    "server_internal",
                    {
                        "autoscaling_group_name": {
                            "references": [
                                "aws_autoscaling_group.server.name",
                                "aws_autoscaling_group.server",
                            ]
                        },
                        "lb_target_group_arn": {
                            "references": [
                                "aws_lb_target_group.udp_internal[0].arn",
                                "aws_lb_target_group.udp_internal[0]",
                                "aws_lb_target_group.udp_internal",
                            ]
                        },
                    },
                ),
                config_resource("aws_security_group", "server", {}),
                config_resource(
                    "aws_vpc_security_group_ingress_rule",
                    "server_nhp_udp",
                    {
                        "security_group_id": {
                            "references": [
                                "aws_security_group.server.id",
                                "aws_security_group.server",
                            ]
                        }
                    },
                ),
            ],
        },
    }

    def add(
        address: str,
        resource_type: str,
        name: str,
        after: dict[str, Any] | None = None,
        *,
        before: dict[str, Any] | None = None,
        actions: list[str] | None = None,
    ) -> None:
        plan["resource_changes"].append(
            {
                "address": address,
                "mode": "managed",
                "type": resource_type,
                "name": name,
                "change": {
                    "actions": actions or ["create"],
                    "before": before,
                    "after": after or {},
                    "after_unknown": {},
                },
            }
        )

    main_network = "module.nhp.module.networking"
    network = "module.nhp.module.relay_network[0]"
    relay = "module.nhp.module.relay[0]"
    add(
        "module.nhp.terraform_data.relay_cell_routing[0]",
        "terraform_data",
        "relay_cell_routing",
        {
            "input": [
                {
                    "name": "sandbox-cell0",
                    "public_key": f"{'A' * 43}=",
                    "host": "layerv-nhp-sandbox-srv-int-fixture.elb.us-east-2.amazonaws.com",
                    "port": checker.EXPECTED_NHP_SERVER_PORT,
                }
            ]
        },
    )
    for index, cidr in enumerate(
        ["10.100.10.0/24", "10.100.11.0/24", "10.100.12.0/24"]
    ):
        subnet_values = {"cidr_block": cidr}
        add(
            f"{main_network}.aws_subnet.private[{index}]",
            "aws_subnet",
            "private",
            subnet_values,
            before=subnet_values,
            actions=["no-op"],
        )
    add(
        "module.nhp.module.relay_identity[0].aws_secretsmanager_secret.relay",
        "aws_secretsmanager_secret",
        "relay",
        {"arn": FIXTURE_RELAY_SECRET_ARN},
    )
    add(
        "module.nhp.module.kms.aws_kms_key.secrets",
        "aws_kms_key",
        "secrets",
        {"arn": FIXTURE_SECRETS_KMS_ARN},
    )
    add(
        'module.nhp.module.ecr.aws_ecr_repository.main["nhp-relay"]',
        "aws_ecr_repository",
        "main",
        {"arn": checker.EXPECTED_SANDBOX_RELAY_REPO_ARN},
    )
    add(
        "module.nhp.aws_ssm_parameter.relay_image_tag[0]",
        "aws_ssm_parameter",
        "relay_image_tag",
        {"arn": checker.EXPECTED_SANDBOX_IMAGE_TAG_PARAMETER_ARN},
    )
    add(
        f"{network}.aws_vpc.relay",
        "aws_vpc",
        "relay",
        {
            "cidr_block": checker.EXPECTED_SANDBOX_RELAY_VPC_CIDR,
            "enable_dns_hostnames": True,
            "enable_dns_support": True,
            "enable_network_address_usage_metrics": True,
        },
    )
    add(f"{network}.aws_internet_gateway.relay", "aws_internet_gateway", "relay")
    add(
        f"{network}.aws_vpc_peering_connection.main",
        "aws_vpc_peering_connection",
        "main",
        {"auto_accept": True},
    )
    add(
        f"{network}.aws_vpc_peering_connection_options.main",
        "aws_vpc_peering_connection_options",
        "main",
        {
            "requester": [{"allow_remote_vpc_dns_resolution": True}],
            "accepter": [{"allow_remote_vpc_dns_resolution": True}],
        },
    )
    add(
        "module.nhp.module.networking.aws_route_table.private[0]",
        "aws_route_table",
        "private",
        {
            "route": [
                {
                    "cidr_block": "0.0.0.0/0",
                    "nat_gateway_id": "nat-main",
                }
            ]
        },
        before={
            "route": [
                {
                    "cidr_block": "0.0.0.0/0",
                    "nat_gateway_id": "nat-main",
                }
            ]
        },
        actions=["no-op"],
    )
    add(
        "module.nhp.module.networking.aws_route_table.private_extensible[0]",
        "aws_route_table",
        "private_extensible",
        {"route": []},
    )
    add(
        "module.nhp.module.networking.aws_route.private_extensible_default[0]",
        "aws_route",
        "private_extensible_default",
        {
            "destination_cidr_block": "0.0.0.0/0",
            "nat_gateway_id": "nat-main",
        },
    )
    add(
        "module.nhp.module.ecr.aws_iam_role_policy.context_lookups",
        "aws_iam_role_policy",
        "context_lookups",
        {"policy": context_lookups_policy()},
    )
    add(
        "module.nhp.module.ecr.aws_iam_role_policy.context_lookups_relay_ssm[0]",
        "aws_iam_role_policy",
        "context_lookups_relay_ssm",
        {"policy": context_lookups_relay_ssm_policy()},
    )
    add(
        f"{network}.aws_security_group.endpoints",
        "aws_security_group",
        "endpoints",
        {"ingress": [], "egress": []},
    )
    add(
        f"{network}.aws_kms_key.logs",
        "aws_kms_key",
        "logs",
        {"enable_key_rotation": True, "policy": logs_kms_policy()},
    )
    add(
        f"{network}.aws_kms_alias.logs",
        "aws_kms_alias",
        "logs",
        {"name": "alias/layerv-nhp-sandbox-relay-dmz-logs"},
    )
    dedicated_key_arn = "arn:aws:kms:us-east-2:767397897469:key/relay-dmz-logs"
    add(
        f"{network}.aws_cloudwatch_log_group.flow",
        "aws_cloudwatch_log_group",
        "flow",
        {"kms_key_id": dedicated_key_arn},
    )
    add(
        f"{network}.aws_cloudwatch_log_group.resolver",
        "aws_cloudwatch_log_group",
        "resolver",
        {"kms_key_id": dedicated_key_arn},
    )
    add(
        f"{network}.aws_iam_role.flow",
        "aws_iam_role",
        "flow",
        {"assume_role_policy": flow_logs_trust_policy()},
    )
    add(
        f"{network}.aws_iam_role_policy.flow",
        "aws_iam_role_policy",
        "flow",
        {"policy": flow_logs_policy()},
    )
    tier_cidrs = checker.EXPECTED_SANDBOX_RELAY_SUBNET_CIDRS
    for tier, cidrs in tier_cidrs.items():
        for index, cidr in enumerate(cidrs):
            add(
                f"{network}.aws_subnet.{tier}[{index}]",
                "aws_subnet",
                tier,
                {
                    "cidr_block": cidr,
                    "availability_zone": f"us-east-2{chr(ord('a') + index)}",
                    "map_public_ip_on_launch": False,
                },
            )
            add(
                f"{network}.aws_route_table_association.{tier}[{index}]",
                "aws_route_table_association",
                tier,
            )
    for tier, count in (("public", 1), ("relay", 3), ("endpoint", 3)):
        for index in range(count):
            suffix = "" if count == 1 else f"[{index}]"
            add(f"{network}.aws_route_table.{tier}{suffix}", "aws_route_table", tier)
    add(
        f"{network}.aws_route.public_default",
        "aws_route",
        "public_default",
        {
            "destination_cidr_block": checker.EXPECTED_IPV4_DEFAULT_CIDR,
            "nat_gateway_id": None,
        },
    )
    main_cidrs = ["10.100.10.0/24", "10.100.11.0/24", "10.100.12.0/24"]
    for index, cidr in enumerate(main_cidrs * 3):
        add(
            f"{network}.aws_route.relay_to_main_private[{index}]",
            "aws_route",
            "relay_to_main_private",
            {"destination_cidr_block": cidr, "nat_gateway_id": None},
        )
    for index, cidr in enumerate(tier_cidrs["relay"]):
        add(
            f"{network}.aws_route.main_private_to_relay[{index}]",
            "aws_route",
            "main_private_to_relay",
            {"destination_cidr_block": cidr, "nat_gateway_id": None},
        )

    for key in sorted(checker.EXPECTED_INTERFACE_ENDPOINTS):
        add(
            f'{network}.aws_vpc_endpoint.interface["{key}"]',
            "aws_vpc_endpoint",
            "interface",
            {
                "vpc_endpoint_type": "Interface",
                "private_dns_enabled": True,
                "policy": endpoint_policy(key),
            },
        )
    add(
        f"{network}.aws_vpc_endpoint.s3",
        "aws_vpc_endpoint",
        "s3",
        {
            "vpc_endpoint_type": "Gateway",
            "policy": json.dumps(
                {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": "*",
                            "Action": "s3:GetObject",
                            "Resource": sorted(checker.EXPECTED_S3_RESOURCES),
                        }
                    ]
                }
            ),
        },
    )

    add(
        f"{network}.aws_route53_resolver_firewall_domain_list.allow",
        "aws_route53_resolver_firewall_domain_list",
        "allow",
        {"domains": sorted(checker.EXPECTED_ALLOW_DOMAINS)},
    )
    add(
        f"{network}.aws_route53_resolver_firewall_domain_list.all",
        "aws_route53_resolver_firewall_domain_list",
        "all",
        {"domains": ["*."]},
    )
    for key, priority in (
        ("DGA", 100),
        ("DICTIONARY_DGA", 110),
        ("DNS_TUNNELING", 120),
    ):
        add(
            f'{network}.aws_route53_resolver_firewall_rule.advanced["{key}"]',
            "aws_route53_resolver_firewall_rule",
            "advanced",
            {
                "action": "BLOCK",
                "block_response": "NODATA",
                "confidence_threshold": "HIGH",
                "dns_threat_protection": key,
                "priority": priority,
            },
        )
    add(
        f"{network}.aws_route53_resolver_firewall_rule.allow",
        "aws_route53_resolver_firewall_rule",
        "allow",
        {
            "action": "ALLOW",
            "priority": 200,
            "firewall_domain_redirection_action": "TRUST_REDIRECTION_DOMAIN",
        },
    )
    add(
        f"{network}.aws_route53_resolver_firewall_rule.block_all",
        "aws_route53_resolver_firewall_rule",
        "block_all",
        {"action": "BLOCK", "block_response": "NODATA", "priority": 900},
    )
    add(
        f"{network}.aws_route53_resolver_firewall_config.relay",
        "aws_route53_resolver_firewall_config",
        "relay",
        {"firewall_fail_open": "DISABLED"},
    )
    add(
        f"{network}.aws_route53_resolver_firewall_rule_group_association.relay",
        "aws_route53_resolver_firewall_rule_group_association",
        "relay",
        {"mutation_protection": "DISABLED", "priority": 101},
    )
    add(
        f"{network}.aws_route53_resolver_query_log_config.relay",
        "aws_route53_resolver_query_log_config",
        "relay",
    )
    add(
        f"{network}.aws_route53_resolver_query_log_config_association.relay",
        "aws_route53_resolver_query_log_config_association",
        "relay",
    )
    add(
        f"{network}.aws_cloudwatch_log_metric_filter.dns_blocked",
        "aws_cloudwatch_log_metric_filter",
        "dns_blocked",
        {
            "pattern": '{ $.firewall_rule_action = "BLOCK" && $.query_name != %^example\\.com\\.*$% }',
            "metric_transformation": [
                {
                    "name": "RelayDmzDnsBlocked",
                    "namespace": checker.EXPECTED_METRIC_NAMESPACE,
                    "value": "1",
                }
            ],
        },
    )
    add(
        "module.nhp.aws_cloudwatch_metric_alarm.relay_dmz_dns_blocked[0]",
        "aws_cloudwatch_metric_alarm",
        "relay_dmz_dns_blocked",
        {
            "metric_name": "RelayDmzDnsBlocked",
            "namespace": checker.EXPECTED_METRIC_NAMESPACE,
            "statistic": "Sum",
            "period": 60,
            "evaluation_periods": 1,
            "datapoints_to_alarm": 1,
            "threshold": 1,
            "comparison_operator": "GreaterThanOrEqualToThreshold",
            "treat_missing_data": "notBreaching",
            "alarm_actions": ["arn:aws:sns:us-east-2:767397897469:alerts"],
            "ok_actions": ["arn:aws:sns:us-east-2:767397897469:alerts"],
        },
    )
    add(
        f"{network}.aws_flow_log.relay",
        "aws_flow_log",
        "relay",
        {
            "traffic_type": "ALL",
            "max_aggregation_interval": 60,
            "log_format": checker.EXPECTED_FLOW_LOG_FORMAT,
        },
    )

    add(
        f"{relay}.aws_lb_target_group.relay",
        "aws_lb_target_group",
        "relay",
        {
            "protocol": "HTTPS",
            "port": checker.EXPECTED_RELAY_BACKEND_PORT,
            "deregistration_delay": "30",
            "health_check": [
                {
                    "protocol": "HTTPS",
                    "path": checker.EXPECTED_RELAY_HEALTH_PATH,
                }
            ],
        },
    )
    add(
        f"{relay}.aws_lb.relay",
        "aws_lb",
        "relay",
        {
            "internal": False,
            "load_balancer_type": "application",
            "enable_deletion_protection": False,
            "idle_timeout": 30,
            "drop_invalid_header_fields": True,
            "desync_mitigation_mode": "defensive",
            "xff_header_processing_mode": "append",
            "enable_xff_client_port": False,
            "enable_waf_fail_open": False,
            "access_logs": [
                {
                    "enabled": True,
                    "bucket": "layerv-nhp-sandbox-relay-alb-logs-767397897469",
                    "prefix": None,
                }
            ],
        },
    )
    add(
        f"{relay}.aws_lb_listener.https",
        "aws_lb_listener",
        "https",
        {"protocol": "HTTPS", "port": 443},
    )
    add(
        f"{relay}.aws_autoscaling_group.relay",
        "aws_autoscaling_group",
        "relay",
        {
            "name": "layerv-nhp-sandbox-relay-dmz",
            "health_check_type": "ELB",
            "desired_capacity": 3,
            "min_size": 3,
        },
    )
    add(
        f"{relay}.aws_launch_template.relay",
        "aws_launch_template",
        "relay",
        {
            "network_interfaces": [{"associate_public_ip_address": "false"}],
            "metadata_options": [
                {"http_tokens": "required", "http_put_response_hop_limit": 1}
            ],
            "user_data": base64.b64encode(
                (
                    '[[servers]]\nname = "sandbox-cell0"\n'
                    f'public_key = "{"A" * 43}="\n'
                    'host = "layerv-nhp-sandbox-srv-int-fixture.elb.us-east-2.amazonaws.com"\n'
                    f"port = {checker.EXPECTED_NHP_SERVER_PORT}\n"
                ).encode()
            ).decode("ascii"),
        },
    )
    add(
        f"{relay}.aws_cloudwatch_log_group.relay",
        "aws_cloudwatch_log_group",
        "relay",
        {"arn": checker.EXPECTED_SANDBOX_RELAY_LOG_GROUP_ARN.removesuffix(":*")},
    )
    add(
        f"{relay}.aws_iam_role_policy.relay",
        "aws_iam_role_policy",
        "relay",
        {"policy": relay_iam_policy()},
    )
    for resource_type, name, protocol, port, cidr in (
        (
            "aws_vpc_security_group_ingress_rule",
            "alb_https",
            "tcp",
            checker.EXPECTED_HTTPS_PORT,
            checker.EXPECTED_IPV4_DEFAULT_CIDR,
        ),
        (
            "aws_vpc_security_group_egress_rule",
            "alb_to_relay",
            "tcp",
            checker.EXPECTED_RELAY_BACKEND_PORT,
            None,
        ),
        (
            "aws_vpc_security_group_ingress_rule",
            "relay_http_from_alb",
            "tcp",
            checker.EXPECTED_RELAY_BACKEND_PORT,
            None,
        ),
        (
            "aws_vpc_security_group_ingress_rule",
            "relay_udp_ack_return",
            "udp",
            checker.EXPECTED_RELAY_ACK_PORT,
            None,
        ),
        (
            "aws_vpc_security_group_ingress_rule",
            "vpc_endpoints_from_relay",
            "tcp",
            checker.EXPECTED_HTTPS_PORT,
            None,
        ),
        (
            "aws_vpc_security_group_egress_rule",
            "relay_to_vpc_endpoints_https",
            "tcp",
            checker.EXPECTED_HTTPS_PORT,
            None,
        ),
        (
            "aws_vpc_security_group_egress_rule",
            "relay_to_s3_https",
            "tcp",
            checker.EXPECTED_HTTPS_PORT,
            None,
        ),
    ):
        add(
            f"{relay}.{resource_type}.{name}",
            resource_type,
            name,
            {
                "ip_protocol": protocol,
                "from_port": port,
                "to_port": port,
                "cidr_ipv4": cidr,
            },
        )
    for cidr in main_cidrs:
        add(
            f'{relay}.aws_vpc_security_group_egress_rule.relay_to_nhp_udp["{cidr}"]',
            "aws_vpc_security_group_egress_rule",
            "relay_to_nhp_udp",
            {
                "ip_protocol": "udp",
                "from_port": checker.EXPECTED_NHP_SERVER_PORT,
                "to_port": checker.EXPECTED_NHP_SERVER_PORT,
                "cidr_ipv4": cidr,
            },
        )
    add(
        "module.nhp.module.compute.aws_vpc_security_group_ingress_rule.server_nhp_udp",
        "aws_vpc_security_group_ingress_rule",
        "server_nhp_udp",
        {
            "ip_protocol": "udp",
            "from_port": checker.EXPECTED_NHP_SERVER_PORT,
            "to_port": checker.EXPECTED_NHP_SERVER_PORT,
            "cidr_ipv4": checker.EXPECTED_IPV4_DEFAULT_CIDR,
        },
    )
    add(
        "module.nhp.module.compute.aws_lb.server[0]",
        "aws_lb",
        "server",
        {
            "name": checker.EXPECTED_SANDBOX_SERVER_NLB_NAME,
            "internal": False,
            "load_balancer_type": "network",
            "tags": {
                "Environment": "sandbox",
                "Component": "compute",
                "Cell": checker.EXPECTED_SANDBOX_CELL_ID,
                "Name": checker.EXPECTED_SANDBOX_SERVER_NLB_NAME,
            },
        },
    )
    add(
        "module.nhp.module.compute.aws_lb_target_group.udp[0]",
        "aws_lb_target_group",
        "udp",
        {
            "name": checker.EXPECTED_SANDBOX_SERVER_UDP_TG_NAME,
            "protocol": "UDP",
            "port": checker.EXPECTED_NHP_SERVER_PORT,
            "target_type": "instance",
            "preserve_client_ip": "true",
            "tags": {
                "Environment": "sandbox",
                "Component": "compute",
                "Cell": checker.EXPECTED_SANDBOX_CELL_ID,
                "Name": "layerv-nhp-sandbox-tg-udp",
            },
            "health_check": [
                {
                    "enabled": True,
                    "protocol": "HTTP",
                    "port": "8888",
                    "path": "/health/live",
                    "matcher": "200",
                }
            ],
        },
    )
    add(
        "module.nhp.module.compute.aws_lb_target_group.udp_green[0]",
        "aws_lb_target_group",
        "udp_green",
        {
            "arn": "arn:aws:elasticloadbalancing:us-east-2:767397897469:targetgroup/layerv-nhp-sandbox-udp-grn/green",
            "name": checker.EXPECTED_SANDBOX_SERVER_UDP_GREEN_TG_NAME,
            "protocol": "UDP",
            "port": checker.EXPECTED_NHP_SERVER_PORT,
            "target_type": "instance",
            "preserve_client_ip": "true",
            "tags": {
                "Environment": "sandbox",
                "Component": "compute",
                "Cell": checker.EXPECTED_SANDBOX_CELL_ID,
                "Name": "layerv-nhp-sandbox-tg-udp-green",
                "DeployColor": "green",
            },
            "health_check": [
                {
                    "enabled": True,
                    "protocol": "HTTP",
                    "port": "8888",
                    "path": "/health/live",
                    "matcher": "200",
                }
            ],
        },
    )
    add(
        "module.nhp.module.compute.aws_lb_listener.udp[0]",
        "aws_lb_listener",
        "udp",
        {"protocol": "UDP", "port": checker.EXPECTED_NHP_CLIENT_EDGE_PORT},
    )
    add(
        "module.nhp.module.compute.aws_autoscaling_attachment.server[0]",
        "aws_autoscaling_attachment",
        "server",
    )
    add(
        "module.nhp.module.compute.aws_lb.server_internal",
        "aws_lb",
        "server_internal",
        {
            "internal": True,
            "load_balancer_type": "network",
            "dns_name": "layerv-nhp-sandbox-srv-int-fixture.elb.us-east-2.amazonaws.com",
        },
    )
    add(
        "module.nhp.module.compute.aws_lb_listener.udp_internal",
        "aws_lb_listener",
        "udp_internal",
        {"protocol": "UDP", "port": checker.EXPECTED_NHP_SERVER_PORT},
    )
    add(
        "module.nhp.module.compute.aws_lb_target_group.udp_internal",
        "aws_lb_target_group",
        "udp_internal",
        {
            "name": checker.EXPECTED_SANDBOX_INTERNAL_UDP_TG_NAME,
            "protocol": "UDP",
            "port": checker.EXPECTED_NHP_SERVER_PORT,
            "target_type": "instance",
            "preserve_client_ip": "true",
            "tags": {
                "Environment": "sandbox",
                "Component": "compute",
                "Cell": checker.EXPECTED_SANDBOX_CELL_ID,
                "Name": "layerv-nhp-sandbox-tg-srv-int-udp-blue",
                "DeployColor": "blue",
            },
            "health_check": [
                {
                    "enabled": True,
                    "protocol": "HTTP",
                    "port": "8888",
                    "path": "/health/live",
                    "matcher": "200",
                }
            ],
        },
    )
    add(
        "module.nhp.module.compute.aws_lb_target_group.udp_internal_green[0]",
        "aws_lb_target_group",
        "udp_internal_green",
        {
            "arn": "arn:aws:elasticloadbalancing:us-east-2:767397897469:targetgroup/layerv-nhp-sandbox-srv-int-grn/green",
            "name": checker.EXPECTED_SANDBOX_INTERNAL_UDP_GREEN_TG_NAME,
            "protocol": "UDP",
            "port": checker.EXPECTED_NHP_SERVER_PORT,
            "target_type": "instance",
            "preserve_client_ip": "true",
            "tags": {
                "Environment": "sandbox",
                "Component": "compute",
                "Cell": checker.EXPECTED_SANDBOX_CELL_ID,
                "Name": "layerv-nhp-sandbox-tg-srv-int-udp-green",
                "DeployColor": "green",
            },
            "health_check": [
                {
                    "enabled": True,
                    "protocol": "HTTP",
                    "port": "8888",
                    "path": "/health/live",
                    "matcher": "200",
                }
            ],
        },
    )
    add(
        "module.nhp.module.compute.aws_autoscaling_group.server_green[0]",
        "aws_autoscaling_group",
        "server_green",
        {
            "target_group_arns": [
                "arn:aws:elasticloadbalancing:us-east-2:767397897469:targetgroup/layerv-nhp-sandbox-udp-grn/green",
                "arn:aws:elasticloadbalancing:us-east-2:767397897469:targetgroup/layerv-nhp-sandbox-srv-int-grn/green",
            ]
        },
    )
    add(
        "module.nhp.module.compute.aws_autoscaling_attachment.server_internal",
        "aws_autoscaling_attachment",
        "server_internal",
    )
    for cidr in tier_cidrs["relay"]:
        add(
            f'module.nhp.module.compute.aws_vpc_security_group_ingress_rule.server_nhp_udp_additional["{cidr}"]',
            "aws_vpc_security_group_ingress_rule",
            "server_nhp_udp_additional",
            {
                "ip_protocol": "udp",
                "from_port": checker.EXPECTED_NHP_SERVER_PORT,
                "to_port": checker.EXPECTED_NHP_SERVER_PORT,
                "cidr_ipv4": cidr,
            },
        )
    return plan


def source_fenced_plan() -> dict[str, Any]:
    """Return the future cell0 topology admitted only by the migration flag."""
    plan = clean_plan()
    public_listener_config = configured_resource(
        plan, "compute", "aws_lb_listener", "udp"
    )
    public_listener_config["expressions"]["default_action"]["references"] = list(
        MANAGED_ACTIVE_COLOR_LISTENER_REFS
    )
    nhp_module = plan["configuration"]["root_module"]["module_calls"]["nhp"][
        "module"
    ]
    compute_resources = nhp_module["module_calls"]["compute"]["module"]["resources"]
    nhp_module["module_calls"]["ac"] = {
        "module": {
            "resources": [
                config_resource(
                    "aws_vpc_security_group_ingress_rule",
                    "server_nlb_registration",
                    {
                        "for_each": {
                            "references": [
                                "var.server_nlb_source_fenced",
                                "aws_eip.ac",
                            ]
                        },
                        "cidr_ipv4": {"references": ["each.value"]},
                        "description": {"references": ["each.value"]},
                        "from_port": {
                            "constant_value": checker.EXPECTED_NHP_CLIENT_EDGE_PORT
                        },
                        "ip_protocol": {"constant_value": "udp"},
                        "security_group_id": {
                            "references": ["var.server_nlb_security_group_id"]
                        },
                        "to_port": {
                            "constant_value": checker.EXPECTED_NHP_CLIENT_EDGE_PORT
                        },
                    },
                )
            ]
        }
    }

    public_nlb_config = next(
        item
        for item in compute_resources
        if item["type"] == "aws_lb" and item["name"] == "server"
    )
    public_nlb_config["expressions"]["security_groups"] = {
        "references": [
            "var.public_nhp_udp_ingress_cidrs",
            "aws_security_group.server_nlb[0].id",
            "aws_security_group.server_nlb[0]",
            "aws_security_group.server_nlb",
        ]
    }
    legacy_udp_config = next(
        item
        for item in compute_resources
        if item["type"] == "aws_vpc_security_group_ingress_rule"
        and item["name"] == "server_nhp_udp"
    )
    legacy_udp_config["count_expression"] = {
        "references": ["var.public_nhp_udp_ingress_cidrs"]
    }
    legacy_udp_config["expressions"].update(
        {
            "cidr_ipv4": {"constant_value": checker.EXPECTED_IPV4_DEFAULT_CIDR},
            "from_port": {"constant_value": checker.EXPECTED_NHP_SERVER_PORT},
            "ip_protocol": {"constant_value": "udp"},
            "to_port": {"constant_value": checker.EXPECTED_NHP_SERVER_PORT},
        }
    )
    compute_resources.extend(
        [
            config_resource("aws_security_group", "server_nlb", {}),
            config_resource(
                "aws_vpc_security_group_ingress_rule",
                "server_nhp_udp_additional",
                {
                    "for_each": {
                        "references": ["var.additional_nhp_udp_ingress_cidrs"]
                    },
                    "cidr_ipv4": {"references": ["each.value"]},
                    "from_port": {
                        "constant_value": checker.EXPECTED_NHP_SERVER_PORT
                    },
                    "ip_protocol": {"constant_value": "udp"},
                    "security_group_id": {
                        "references": [
                            "aws_security_group.server.id",
                            "aws_security_group.server",
                        ]
                    },
                    "to_port": {
                        "constant_value": checker.EXPECTED_NHP_SERVER_PORT
                    },
                },
            ),
            {
                **config_resource(
                    "aws_vpc_security_group_ingress_rule",
                    "server_nlb_udp",
                    {
                        "cidr_ipv4": {"references": ["each.value"]},
                        "security_group_id": {
                            "references": [
                                "aws_security_group.server_nlb[0].id",
                                "aws_security_group.server_nlb[0]",
                                "aws_security_group.server_nlb",
                            ]
                        },
                    },
                ),
                "for_each_expression": {
                    "references": ["var.public_nhp_udp_ingress_cidrs"]
                },
            },
            config_resource(
                "aws_vpc_security_group_egress_rule",
                "server_nlb_udp",
                {
                    "security_group_id": {
                        "references": [
                            "aws_security_group.server_nlb[0].id",
                            "aws_security_group.server_nlb[0]",
                            "aws_security_group.server_nlb",
                        ]
                    },
                    "referenced_security_group_id": {
                        "references": [
                            "aws_security_group.server.id",
                            "aws_security_group.server",
                        ]
                    },
                },
            ),
            config_resource(
                "aws_vpc_security_group_egress_rule",
                "server_nlb_health",
                {
                    "security_group_id": {
                        "references": [
                            "aws_security_group.server_nlb[0].id",
                            "aws_security_group.server_nlb[0]",
                            "aws_security_group.server_nlb",
                        ]
                    },
                    "referenced_security_group_id": {
                        "references": [
                            "aws_security_group.server.id",
                            "aws_security_group.server",
                        ]
                    },
                },
            ),
            config_resource(
                "aws_vpc_security_group_ingress_rule",
                "server_nhp_udp_nlb",
                {
                    "count": {
                        "references": ["var.public_nhp_udp_ingress_cidrs"]
                    },
                    "from_port": {
                        "constant_value": checker.EXPECTED_NHP_SERVER_PORT
                    },
                    "ip_protocol": {"constant_value": "udp"},
                    "security_group_id": {
                        "references": [
                            "aws_security_group.server.id",
                            "aws_security_group.server",
                        ]
                    },
                    "referenced_security_group_id": {
                        "references": [
                            "aws_security_group.server_nlb[0].id",
                            "aws_security_group.server_nlb[0]",
                            "aws_security_group.server_nlb",
                        ]
                    },
                    "to_port": {
                        "constant_value": checker.EXPECTED_NHP_SERVER_PORT
                    },
                },
            ),
            config_resource(
                "aws_vpc_security_group_ingress_rule",
                "server_nhp_udp_vpc",
                {
                    "count": {
                        "references": ["var.public_nhp_udp_ingress_cidrs"]
                    },
                    "from_port": {
                        "constant_value": checker.EXPECTED_NHP_SERVER_PORT
                    },
                    "ip_protocol": {"constant_value": "udp"},
                    "security_group_id": {
                        "references": [
                            "aws_security_group.server.id",
                            "aws_security_group.server",
                        ]
                    },
                    "cidr_ipv4": {"references": ["var.vpc_cidr"]},
                    "to_port": {
                        "constant_value": checker.EXPECTED_NHP_SERVER_PORT
                    },
                },
            ),
            config_resource(
                "aws_vpc_security_group_ingress_rule",
                "server_nlb_health",
                {
                    "from_port": {
                        "constant_value": checker.EXPECTED_SERVER_HEALTH_PORT
                    },
                    "ip_protocol": {"constant_value": "tcp"},
                    "security_group_id": {
                        "references": [
                            "aws_security_group.server.id",
                            "aws_security_group.server",
                        ]
                    },
                    "referenced_security_group_id": {
                        "references": [
                            "aws_security_group.server_nlb[0].id",
                            "aws_security_group.server_nlb[0]",
                            "aws_security_group.server_nlb",
                        ]
                    },
                    "to_port": {
                        "constant_value": checker.EXPECTED_SERVER_HEALTH_PORT
                    },
                },
            ),
        ]
    )

    plan["resource_changes"] = [
        item
        for item in plan["resource_changes"]
        if not item["address"].endswith(
            "aws_vpc_security_group_ingress_rule.server_nhp_udp"
        )
    ]

    def add(
        address: str,
        resource_type: str,
        name: str,
        after: dict[str, Any],
    ) -> None:
        plan["resource_changes"].append(
            {
                "address": address,
                "mode": "managed",
                "type": resource_type,
                "name": name,
                "change": {
                    "actions": ["create"],
                    "before": None,
                    "after": after,
                    "after_unknown": {},
                },
            }
        )

    add(
        "module.nhp.module.compute.aws_security_group.server",
        "aws_security_group",
        "server",
        {"id": "sg-server"},
    )
    add(
        "module.nhp.module.compute.aws_security_group.server_nlb[0]",
        "aws_security_group",
        "server_nlb",
        {"id": "sg-server-nlb"},
    )
    ac_public_ips = (
        "3.151.137.194",
        "3.151.252.67",
        "3.136.14.164",
        "52.14.228.233",
        "18.225.44.103",
        "52.14.199.249",
        "16.58.119.85",
    )
    for index, public_ip in enumerate(ac_public_ips):
        add(
            f"module.nhp.module.ac[0].aws_eip.ac[{index}]",
            "aws_eip",
            "ac",
            {
                "public_ip": public_ip,
                "tags": {
                    "Environment": "sandbox",
                    "Component": "ac",
                    "Service": "nhp-ac",
                    "EIPPool": "layerv-nhp-sandbox-ac",
                    "ManagedBy": "terraform",
                    "Name": f"layerv-nhp-sandbox-ac-eip-{index}",
                },
            },
        )
        ac_eip = plan["resource_changes"][-1]
        ac_eip["change"]["actions"] = ["no-op"]
        ac_eip["change"]["before"] = copy.deepcopy(ac_eip["change"]["after"])
        add(
            "module.nhp.module.ac[0]."
            "aws_vpc_security_group_ingress_rule."
            f'server_nlb_registration["{index}"]',
            "aws_vpc_security_group_ingress_rule",
            "server_nlb_registration",
            {
                "security_group_id": "sg-server-nlb",
                "ip_protocol": "udp",
                "from_port": checker.EXPECTED_NHP_CLIENT_EDGE_PORT,
                "to_port": checker.EXPECTED_NHP_CLIENT_EDGE_PORT,
                "cidr_ipv4": f"{public_ip}/32",
            },
        )
    for change in plan["resource_changes"]:
        if (
            change.get("name") == "server_nhp_udp_additional"
            and isinstance((change.get("change") or {}).get("after"), dict)
        ):
            change["change"]["after"]["security_group_id"] = "sg-server"
    add(
        "module.nhp.module.compute." + PROOF_SOURCE_RULE_ADDRESS_SUFFIX,
        "aws_vpc_security_group_ingress_rule",
        "server_nlb_udp",
        {
            "security_group_id": "sg-server-nlb",
            "ip_protocol": "udp",
            "from_port": checker.EXPECTED_NHP_CLIENT_EDGE_PORT,
            "to_port": checker.EXPECTED_NHP_CLIENT_EDGE_PORT,
            "cidr_ipv4": checker.EXPECTED_SANDBOX_PROOF_SOURCE_CIDR,
        },
    )
    add(
        "module.nhp.module.compute."
        "aws_vpc_security_group_ingress_rule.server_nhp_udp_nlb[0]",
        "aws_vpc_security_group_ingress_rule",
        "server_nhp_udp_nlb",
        {
            "security_group_id": "sg-server",
            "referenced_security_group_id": "sg-server-nlb",
            "ip_protocol": "udp",
            "from_port": checker.EXPECTED_NHP_SERVER_PORT,
            "to_port": checker.EXPECTED_NHP_SERVER_PORT,
            "cidr_ipv4": None,
        },
    )
    add(
        "module.nhp.module.compute."
        "aws_vpc_security_group_ingress_rule.server_nhp_udp_vpc[0]",
        "aws_vpc_security_group_ingress_rule",
        "server_nhp_udp_vpc",
        {
            "security_group_id": "sg-server",
            "referenced_security_group_id": None,
            "ip_protocol": "udp",
            "from_port": checker.EXPECTED_NHP_SERVER_PORT,
            "to_port": checker.EXPECTED_NHP_SERVER_PORT,
            "cidr_ipv4": "10.100.0.0/16",
        },
    )
    add(
        "module.nhp.module.compute."
        "aws_vpc_security_group_ingress_rule.server_nlb_health[0]",
        "aws_vpc_security_group_ingress_rule",
        "server_nlb_health",
        {
            "security_group_id": "sg-server",
            "referenced_security_group_id": "sg-server-nlb",
            "ip_protocol": "tcp",
            "from_port": checker.EXPECTED_SERVER_HEALTH_PORT,
            "to_port": checker.EXPECTED_SERVER_HEALTH_PORT,
            "cidr_ipv4": None,
        },
    )
    for name, protocol, port in (
        ("server_nlb_udp", "udp", checker.EXPECTED_NHP_SERVER_PORT),
        ("server_nlb_health", "tcp", checker.EXPECTED_SERVER_HEALTH_PORT),
    ):
        add(
            "module.nhp.module.compute."
            f"aws_vpc_security_group_egress_rule.{name}[0]",
            "aws_vpc_security_group_egress_rule",
            name,
            {
                "security_group_id": "sg-server-nlb",
                "referenced_security_group_id": "sg-server",
                "ip_protocol": protocol,
                "from_port": port,
                "to_port": port,
            },
        )

    public_nlb = next(
        item
        for item in plan["resource_changes"]
        if item["address"].endswith("module.compute.aws_lb.server[0]")
    )
    public_nlb["change"]["after"].update(
        {
            "name": checker.EXPECTED_SANDBOX_FENCED_SERVER_NLB_NAME,
            "security_groups": ["sg-server-nlb"],
        }
    )
    public_nlb["change"]["after"]["tags"][
        "Name"
    ] = checker.EXPECTED_SANDBOX_FENCED_SERVER_NLB_NAME
    return plan


def source_fence_migration_plan() -> dict[str, Any]:
    """Return the exact one-time legacy-to-fenced boundary transition."""
    plan = source_fenced_plan()
    provider_changes = json.loads(
        UDP_SOURCE_FENCE_PROVIDER_FIXTURE.read_text(encoding="utf-8")
    )["changes"]
    for change in plan["resource_changes"]:
        if not checker.is_dmz_boundary_address(str(change.get("address", ""))):
            continue
        after = copy.deepcopy((change.get("change") or {}).get("after"))
        change["change"]["actions"] = ["no-op"]
        change["change"]["before"] = after

    exact_create_suffixes = (
        "aws_security_group.server_nlb[0]",
        PROOF_SOURCE_RULE_ADDRESS_SUFFIX,
        "aws_vpc_security_group_ingress_rule.server_nhp_udp_nlb[0]",
        "aws_vpc_security_group_ingress_rule.server_nlb_health[0]",
        "aws_vpc_security_group_egress_rule.server_nlb_udp[0]",
        "aws_vpc_security_group_egress_rule.server_nlb_health[0]",
    ) + tuple(
        "aws_vpc_security_group_ingress_rule."
        f'server_nlb_registration["{index}"]'
        for index in range(checker.EXPECTED_SANDBOX_AC_EIP_COUNT)
    )
    for suffix in exact_create_suffixes:
        change = next(
            item
            for item in plan["resource_changes"]
            if item["address"].endswith(suffix)
        )
        change["change"]["actions"] = ["create"]
        change["change"]["before"] = None

    # Match a real first-apply provider plan: the new NLB SG ID and every
    # dependent SG reference are explicitly unknown until apply.
    nlb_sg = resource(plan, ".aws_security_group.server_nlb[0]")
    nlb_sg["change"]["after"]["id"] = None
    nlb_sg["change"]["after_unknown"]["id"] = True
    for suffix, field in (
        (PROOF_SOURCE_RULE_SUFFIX, "security_group_id"),
        (
            ".aws_vpc_security_group_ingress_rule.server_nhp_udp_nlb[0]",
            "referenced_security_group_id",
        ),
        (
            ".aws_vpc_security_group_ingress_rule.server_nlb_health[0]",
            "referenced_security_group_id",
        ),
        (".aws_vpc_security_group_egress_rule.server_nlb_udp[0]", "security_group_id"),
        (
            ".aws_vpc_security_group_egress_rule.server_nlb_health[0]",
            "security_group_id",
        ),
        *(
            (
                ".aws_vpc_security_group_ingress_rule."
                f'server_nlb_registration["{index}"]',
                "security_group_id",
            )
            for index in range(checker.EXPECTED_SANDBOX_AC_EIP_COUNT)
        ),
    ):
        dependent = resource(plan, suffix)
        dependent["change"]["after"][field] = None
        dependent["change"]["after_unknown"][field] = True

    public_nlb = next(
        item
        for item in plan["resource_changes"]
        if item["address"].endswith("aws_lb.server[0]")
    )
    public_nlb["change"] = copy.deepcopy(provider_changes[public_nlb["address"]])

    udp_listener = next(
        item
        for item in plan["resource_changes"]
        if item["address"].endswith("aws_lb_listener.udp[0]")
    )
    # The captured provider envelope already carries the live green target on
    # both sides with a canonical ARN, so it satisfies the active-color checks
    # from #3466 while also meeting the exact-envelope comparison.
    udp_listener["change"] = copy.deepcopy(provider_changes[udp_listener["address"]])

    plan["resource_changes"].append(
        {
            "address": (
                "module.nhp.module.compute."
                "aws_vpc_security_group_ingress_rule.server_nhp_udp[0]"
            ),
            "mode": "managed",
            "type": "aws_vpc_security_group_ingress_rule",
            "name": "server_nhp_udp",
            "change": {
                "actions": ["delete"],
                "before": {
                    "ip_protocol": "udp",
                    "from_port": checker.EXPECTED_NHP_SERVER_PORT,
                    "to_port": checker.EXPECTED_NHP_SERVER_PORT,
                    "cidr_ipv4": checker.EXPECTED_IPV4_DEFAULT_CIDR,
                },
                "after": None,
                "after_unknown": {},
            },
        }
    )
    return plan


def source_fence_partial_retry_plan(
    pending_keys: set[str],
) -> dict[str, Any]:
    """Return a retry with pending actions plus exact fenced target no-ops."""
    expected_keys = set(checker.UDP_SOURCE_FENCE_MIGRATION_KEYS)
    if not pending_keys or not pending_keys.issubset(expected_keys):
        raise AssertionError("partial retry requires a nonempty reviewed subset")
    plan = source_fence_migration_plan()
    target = source_fenced_plan()
    target_by_key = {
        key: item
        for item in target["resource_changes"]
        if (
            key := checker.udp_source_fence_migration_address_key(item["address"])
        )
        is not None
    }
    for key in expected_keys - pending_keys:
        plan["resource_changes"] = [
            item
            for item in plan["resource_changes"]
            if checker.udp_source_fence_migration_address_key(item["address"]) != key
        ]
        if key == checker.UDP_SOURCE_FENCE_LEGACY_INGRESS_DELETE:
            continue
        target_item = copy.deepcopy(target_by_key[key])
        target_after = copy.deepcopy(target_item["change"]["after"])
        target_item["change"] = {
            "actions": ["no-op"],
            "before": copy.deepcopy(target_after),
            "after": target_after,
            "after_unknown": {},
        }
        plan["resource_changes"].append(target_item)

    if checker.UDP_SOURCE_FENCE_NLB_SG_CREATE not in pending_keys:
        nlb_sg_id = resource(plan, ".aws_security_group.server_nlb[0]")["change"][
            "after"
        ]["id"]
        known_references = (
            (
                checker.UDP_SOURCE_FENCE_NLB_REPLACEMENT,
                ".aws_lb.server[0]",
                "security_groups",
                [nlb_sg_id],
            ),
            (
                checker.UDP_SOURCE_FENCE_PROOF_INGRESS_CREATE,
                PROOF_SOURCE_RULE_SUFFIX,
                "security_group_id",
                nlb_sg_id,
            ),
            (
                checker.UDP_SOURCE_FENCE_TARGET_UDP_CREATE,
                ".aws_vpc_security_group_ingress_rule.server_nhp_udp_nlb[0]",
                "referenced_security_group_id",
                nlb_sg_id,
            ),
            (
                checker.UDP_SOURCE_FENCE_TARGET_HEALTH_CREATE,
                ".aws_vpc_security_group_ingress_rule.server_nlb_health[0]",
                "referenced_security_group_id",
                nlb_sg_id,
            ),
            (
                checker.UDP_SOURCE_FENCE_NLB_UDP_EGRESS_CREATE,
                ".aws_vpc_security_group_egress_rule.server_nlb_udp[0]",
                "security_group_id",
                nlb_sg_id,
            ),
            (
                checker.UDP_SOURCE_FENCE_NLB_HEALTH_EGRESS_CREATE,
                ".aws_vpc_security_group_egress_rule.server_nlb_health[0]",
                "security_group_id",
                nlb_sg_id,
            ),
        )
        for key, suffix, field, value in known_references:
            if key not in pending_keys:
                continue
            pending = resource(plan, suffix)
            pending["change"]["after"][field] = value
            pending["change"]["after_unknown"].pop(field, None)
    return plan


def source_fence_deposed_retry_plan(*, listener_create: bool) -> dict[str, Any]:
    """Return the provider's create-before-destroy interruption shape."""

    plan = source_fence_partial_retry_plan(
        {checker.UDP_SOURCE_FENCE_LISTENER_REPLACEMENT}
    )
    initial = source_fence_migration_plan()
    legacy_nlb = copy.deepcopy(resource(initial, ".aws_lb.server[0]"))
    legacy_nlb["deposed"] = "deadbeef"
    legacy_nlb["change"] = {
        "actions": ["delete"],
        "before": copy.deepcopy(legacy_nlb["change"]["before"]),
        "after": None,
        "after_unknown": {},
    }
    plan["resource_changes"].append(legacy_nlb)

    if listener_create:
        listener = resource(plan, ".aws_lb_listener.udp[0]")
        listener["change"]["actions"] = ["create"]
        listener["change"]["before"] = None
        listener["change"]["after"]["load_balancer_arn"] = (
            f"arn:aws:elasticloadbalancing:{checker.EXPECTED_SANDBOX_REGION}:"
            f"{checker.EXPECTED_SANDBOX_ACCOUNT_ID}:loadbalancer/net/"
            f"{checker.EXPECTED_SANDBOX_FENCED_SERVER_NLB_NAME}/target"
        )
        listener["change"]["after_unknown"].pop("load_balancer_arn", None)
    return plan


def root_level_plan() -> dict[str, Any]:
    plan = clean_plan()
    nested_root = plan["configuration"]["root_module"]
    plan["configuration"]["root_module"] = copy.deepcopy(
        nested_root["module_calls"]["nhp"]["module"]
    )
    for item in plan["resource_changes"]:
        address = item["address"]
        if address.startswith("module.nhp."):
            item["address"] = address.removeprefix("module.nhp.")
    return plan


def counted_parent_plan() -> dict[str, Any]:
    plan = clean_plan()
    root = plan["configuration"]["root_module"]
    nhp_call = copy.deepcopy(root["module_calls"]["nhp"])
    root["module_calls"] = {
        "wrapper": {"module": {"module_calls": {"nhp": nhp_call}, "resources": []}}
    }
    for item in plan["resource_changes"]:
        if item["address"].startswith("module.nhp."):
            item["address"] = item["address"].replace(
                "module.nhp.", "module.wrapper[0].module.nhp.", 1
            )
    return plan


def boundary_noop_plan() -> dict[str, Any]:
    """Return the complete DMZ graph after the automated cutover has converged."""
    plan = clean_plan()
    for change in plan["resource_changes"]:
        if not checker.is_dmz_boundary_address(str(change.get("address", ""))):
            continue
        values = copy.deepcopy((change.get("change") or {}).get("after"))
        change["change"]["actions"] = ["no-op"]
        change["change"]["before"] = values
    return plan


def resource(plan: dict[str, Any], suffix: str) -> dict[str, Any]:
    matches = [
        item
        for item in plan["resource_changes"]
        if item["address"].endswith(suffix)
        or re.search(rf"{re.escape(suffix)}\[[^]]+\]$", item["address"])
    ]
    if len(matches) != 1:
        raise AssertionError(
            f"fixture expected one resource ending {suffix!r}; found {len(matches)}"
        )
    return matches[0]


def raw_changes(
    plan: dict[str, Any], resource_type: str, name: str | None = None
) -> list[dict[str, Any]]:
    return [
        change
        for change in plan["resource_changes"]
        if change["type"] == resource_type and (name is None or change["name"] == name)
    ]


def configured_resource(
    plan: dict[str, Any], module_name: str, resource_type: str, name: str
) -> dict[str, Any]:
    resources = plan["configuration"]["root_module"]["module_calls"]["nhp"]["module"][
        "module_calls"
    ][module_name]["module"]["resources"]
    matches = [
        item
        for item in resources
        if item["type"] == resource_type and item["name"] == name
    ]
    if len(matches) != 1:
        raise AssertionError(
            f"fixture expected one configured {resource_type}.{name} in {module_name}; found {len(matches)}"
        )
    return matches[0]


def run_checker_cli_path(
    plan_path: Path, *options: str
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *options, str(plan_path)],
        check=False,
        capture_output=True,
        text=True,
    )


def run_checker_cli(
    plan: dict[str, Any], *options: str
) -> subprocess.CompletedProcess[str]:
    with tempfile.TemporaryDirectory() as temp_dir:
        plan_path = Path(temp_dir) / "tfplan.json"
        plan_path.write_text(json.dumps(plan), encoding="utf-8")
        return run_checker_cli_path(plan_path, *options)



class OpenEdgeFencedTopologyAcceptanceTests(unittest.TestCase):
    """The full topology fixture must pass in BOTH the fenced and open shapes.

    This is the integration counterpart to the unit cases below. #3701's plan
    gate refused exactly these two assertions against main's checker; this proves
    the same graph is admitted here once the edge is open, and -- just as
    important -- that the fenced graph is still admitted, since the live estate
    stays fenced until the reviewed applies land.
    """

    @staticmethod
    def _open_the_edge(plan: dict[str, Any]) -> dict[str, Any]:
        """Rewrite the fenced fixture's public NLB ingress into the open shape."""
        fenced = checker.EXPECTED_SANDBOX_PROOF_SOURCE_CIDR
        opened = checker.EXPECTED_SANDBOX_OPEN_EDGE_CIDR
        for change in plan["resource_changes"]:
            address = str(change.get("address", ""))
            if f'server_nlb_udp["{fenced}"]' not in address:
                continue
            change["address"] = address.replace(
                f'server_nlb_udp["{fenced}"]', f'server_nlb_udp["{opened}"]'
            )
            for state in ("before", "after"):
                values = (change.get("change") or {}).get(state)
                if isinstance(values, dict) and values.get("cidr_ipv4") == fenced:
                    values["cidr_ipv4"] = opened
        return plan

    def test_fenced_topology_is_still_admitted(self) -> None:
        self.assertEqual(
            [],
            checker.validate_plan(
                source_fenced_plan(), require_udp_source_fenced_topology=True
            ),
        )

    def test_open_topology_is_admitted(self) -> None:
        self.assertEqual(
            [],
            checker.validate_plan(
                self._open_the_edge(source_fenced_plan()),
                require_udp_source_fenced_topology=True,
            ),
        )

    def test_open_topology_still_refuses_an_internet_wide_target_rule(self) -> None:
        """Opening the NLB must not open the instances behind it."""
        plan = self._open_the_edge(source_fenced_plan())
        for change in plan["resource_changes"]:
            if "server_nhp_udp_nlb" in str(change.get("address", "")):
                after = (change.get("change") or {}).get("after")
                if isinstance(after, dict):
                    after["cidr_ipv4"] = checker.EXPECTED_SANDBOX_OPEN_EDGE_CIDR
                    after["referenced_security_group_id"] = None
        errors = checker.validate_plan(
            plan, require_udp_source_fenced_topology=True
        )
        self.assertNotEqual(
            [], errors, "an internet-wide target SG rule must still be refused"
        )


class ASGProcessFencingIAMMigrationTests(unittest.TestCase):
    ADDRESS = checker.EXPECTED_ASG_PROCESS_FENCING_ADDRESS
    RESOURCE = checker.EXPECTED_ASG_PROCESS_FENCING_RESOURCE

    def _policy(
        self,
        actions: tuple[str, ...],
        *,
        resource: str | None = None,
        describe_action: str = "ec2:DescribeInstances",
    ) -> str:
        return json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "ContextLookups",
                        "Effect": "Allow",
                        "Action": [describe_action, "ssm:GetParameter"],
                        "Resource": "*",
                    },
                    {
                        "Sid": "ASGRefreshManage",
                        "Effect": "Allow",
                        "Action": list(actions),
                        "Resource": resource or self.RESOURCE,
                    },
                ],
            },
            sort_keys=True,
        )

    def _change(
        self,
        *,
        after_actions: tuple[str, ...] = checker.ASG_PROCESS_FENCING_AFTER_ACTIONS,
        before_resource: str | None = None,
        after_resource: str | None = None,
        after_describe: str = "ec2:DescribeInstances",
    ) -> dict[str, Any]:
        return {
            "address": self.ADDRESS,
            "mode": "managed",
            "type": "aws_iam_role_policy",
            "name": "context_lookups",
            "change": {
                "actions": ["update"],
                "before": {
                    **checker.EXPECTED_ASG_PROCESS_FENCING_ROW,
                    "policy": self._policy(
                        checker.ASG_PROCESS_FENCING_BEFORE_ACTIONS,
                        resource=before_resource,
                    ),
                },
                "after": {
                    **checker.EXPECTED_ASG_PROCESS_FENCING_ROW,
                    "policy": self._policy(
                        after_actions,
                        resource=after_resource,
                        describe_action=after_describe,
                    ),
                },
                "before_sensitive": {},
                "after_sensitive": {},
                "after_unknown": {},
                "before_identity": checker.EXPECTED_ASG_PROCESS_FENCING_IDENTITY,
                "after_identity": checker.EXPECTED_ASG_PROCESS_FENCING_IDENTITY,
            },
        }

    def test_exact_process_fencing_actions_are_admitted(self) -> None:
        for allow_udp_migration in (False, True):
            with self.subTest(allow_udp_migration=allow_udp_migration):
                self.assertEqual(
                    checker.validate_dmz_boundary_noop(
                        {"resource_changes": [self._change()]},
                        allow_udp_source_fence_replacement=allow_udp_migration,
                    ),
                    [],
                )

    def test_action_mutations_are_refused(self) -> None:
        for actions in (
            checker.ASG_PROCESS_FENCING_BEFORE_ACTIONS,
            checker.ASG_PROCESS_FENCING_AFTER_ACTIONS
            + ("autoscaling:TerminateInstanceInAutoScalingGroup",),
            (
                "autoscaling:StartInstanceRefresh",
                "autoscaling:SuspendProcesses",
                "autoscaling:ResumeProcesses",
            ),
        ):
            with self.subTest(actions=actions):
                self.assertTrue(
                    checker.validate_dmz_boundary_noop(
                        {"resource_changes": [self._change(after_actions=actions)]}
                    )
                )

    def test_resource_or_other_statement_mutation_is_refused(self) -> None:
        for change in (
            self._change(after_resource="*"),
            self._change(before_resource="*", after_resource="*"),
            self._change(after_describe="ec2:DescribeNetworkInterfaces"),
        ):
            with self.subTest(change=change):
                self.assertTrue(
                    checker.validate_dmz_boundary_noop(
                        {"resource_changes": [change]}
                    )
                )

    def test_row_shape_sensitivity_and_unknown_mutations_are_refused(self) -> None:
        changed_row = self._change()
        changed_row["change"]["after"]["role"] = "another-role"
        missing_row_field = self._change()
        del missing_row_field["change"]["before"]["id"]
        extra_row_field = self._change()
        extra_row_field["change"]["after"]["extra"] = "value"
        changed_mask = self._change()
        changed_mask["change"]["after_sensitive"] = {"policy": True}
        matching_masks = self._change()
        matching_masks["change"]["before_sensitive"] = {"policy": True}
        matching_masks["change"]["after_sensitive"] = {"policy": True}
        missing_mask = self._change()
        del missing_mask["change"]["before_sensitive"]
        unknown = self._change()
        unknown["change"]["after_unknown"] = {"policy": True}
        missing_unknown = self._change()
        del missing_unknown["change"]["after_unknown"]
        wrong_identities = self._change()
        wrong_identities["change"]["before_identity"] = {
            **checker.EXPECTED_ASG_PROCESS_FENCING_IDENTITY,
            "role": "other-role",
        }
        wrong_identities["change"]["after_identity"] = {
            **checker.EXPECTED_ASG_PROCESS_FENCING_IDENTITY,
            "role": "other-role",
        }
        missing_identity = self._change()
        del missing_identity["change"]["after_identity"]
        extra_change_field = self._change()
        extra_change_field["change"]["replace_paths"] = []
        replaced = self._change()
        replaced["change"]["actions"] = ["delete", "create"]
        for change in (
            changed_row,
            missing_row_field,
            extra_row_field,
            changed_mask,
            matching_masks,
            missing_mask,
            unknown,
            missing_unknown,
            wrong_identities,
            missing_identity,
            extra_change_field,
            replaced,
        ):
            with self.subTest(change=change):
                self.assertTrue(
                    checker.validate_dmz_boundary_noop(
                        {"resource_changes": [change]}
                    )
                )

    def test_a_second_boundary_mutation_falls_back_to_generic_refusal(self) -> None:
        other = {
            "address": "module.nhp.module.relay[0].aws_lb.relay",
            "mode": "managed",
            "change": {"actions": ["update"], "before": {}, "after": {}},
        }
        errors = checker.validate_dmz_boundary_noop(
            {"resource_changes": [self._change(), other]}
        )
        self.assertTrue(
            any("refuses relay-DMZ boundary change" in error for error in errors)
        )


class OpenEdgeTransitionBoundaryTests(unittest.TestCase):
    """The fence-to-open swap is a third reviewed boundary shape.

    Opening sandbox (qurl-go ADR 0001) replaces the proof-runner /32 ingress
    rule with 0.0.0.0/0 on the same public NLB security group. It is admitted on
    its own exact terms; anything that is not that exact pair falls through to
    the normal refusal.
    """

    COMPUTE = "module.nhp.module.compute"
    RULE = "aws_vpc_security_group_ingress_rule.server_nlb_udp"

    def _delete(self, cidr=checker.EXPECTED_SANDBOX_PROOF_SOURCE_CIDR, **over):
        before = {
            "from_port": 443,
            "to_port": 443,
            "ip_protocol": "udp",
            "cidr_ipv4": cidr,
            "security_group_id": "sg-nlb",
        }
        before.update(over)
        return {
            "address": f'{self.COMPUTE}.{self.RULE}["{cidr}"]',
            "mode": "managed",
            "change": {"actions": ["delete"], "before": before, "after": None},
        }

    def _create(self, cidr=checker.EXPECTED_SANDBOX_OPEN_EDGE_CIDR, **over):
        after = {
            "from_port": 443,
            "to_port": 443,
            "ip_protocol": "udp",
            "cidr_ipv4": cidr,
            "security_group_id": "sg-nlb",
        }
        after.update(over)
        return {
            "address": f'{self.COMPUTE}.{self.RULE}["{cidr}"]',
            "mode": "managed",
            "change": {"actions": ["create"], "before": None, "after": after},
        }

    def test_complete_transition_is_admitted(self) -> None:
        errors = checker.validate_dmz_boundary_noop(
            {"resource_changes": [self._delete(), self._create()]},
            allow_udp_source_fence_replacement=True,
        )
        self.assertEqual([], errors)

    def test_delete_without_create_is_refused(self) -> None:
        """Half the swap would black-hole the edge."""
        errors = checker.validate_dmz_boundary_noop(
            {"resource_changes": [self._delete()]},
            allow_udp_source_fence_replacement=True,
        )
        self.assertNotEqual([], errors)

    def test_create_without_delete_is_refused(self) -> None:
        errors = checker.validate_dmz_boundary_noop(
            {"resource_changes": [self._create()]},
            allow_udp_source_fence_replacement=True,
        )
        self.assertNotEqual([], errors)

    def test_moving_the_rule_to_another_security_group_is_refused(self) -> None:
        """Same fields, different group, would change what is actually exposed."""
        errors = checker.validate_dmz_boundary_noop(
            {
                "resource_changes": [
                    self._delete(),
                    self._create(security_group_id="sg-somewhere-else"),
                ]
            },
            allow_udp_source_fence_replacement=True,
        )
        self.assertTrue(
            any("same public" in error for error in errors),
            f"expected a same-security-group refusal, got {errors}",
        )

    def test_wrong_open_port_is_refused(self) -> None:
        errors = checker.validate_dmz_boundary_noop(
            {
                "resource_changes": [
                    self._delete(),
                    self._create(from_port=62206, to_port=62206),
                ]
            },
            allow_udp_source_fence_replacement=True,
        )
        self.assertNotEqual([], errors)

    def test_an_ordinary_apply_still_requires_a_noop_boundary(self) -> None:
        """The new shape must not become a general boundary-mutation licence."""
        errors = checker.validate_dmz_boundary_noop(
            {
                "resource_changes": [
                    self._delete(),
                    self._create(cidr="198.51.100.7/32"),
                ]
            },
            allow_udp_source_fence_replacement=True,
        )
        self.assertNotEqual([], errors)


class ClientEdgePortMigrationBoundaryTests(unittest.TestCase):
    """The 62206 -> 443 client-edge move is its own reviewed boundary shape.

    The DMZ boundary is frozen for ordinary applies and the source-fence
    replacement was the only previously reviewed mutation. Moving the public
    client edge is a second, different mutation, so it is admitted on its own
    exact terms rather than by loosening the fence contract.
    """

    COMPUTE = "module.nhp.module.compute"
    AC = "module.nhp.module.ac[0]"

    def _listener(self, before_port=62206, after_port=443, **after_over):
        after = {
            "port": after_port,
            "protocol": "UDP",
            "load_balancer_arn": "arn:lb",
            "default_action": [{"target_group_arn": "arn:tg"}],
        }
        after.update(after_over)
        return {
            "address": f"{self.COMPUTE}.aws_lb_listener.udp[0]",
            "mode": "managed",
            "change": {
                "actions": ["update"],
                "before": {
                    "port": before_port,
                    "protocol": "UDP",
                    "load_balancer_arn": "arn:lb",
                    "default_action": [{"target_group_arn": "arn:tg"}],
                },
                "after": after,
            },
        }

    def _rule(self, address, cidr, before_port=62206, after_port=443, **after_over):
        after = {
            "from_port": after_port,
            "to_port": after_port,
            "ip_protocol": "udp",
            "cidr_ipv4": cidr,
            "security_group_id": "sg-nlb",
            "referenced_security_group_id": None,
        }
        after.update(after_over)
        return {
            "address": address,
            "mode": "managed",
            "change": {
                "actions": ["update"],
                "before": {
                    "from_port": before_port,
                    "to_port": before_port,
                    "ip_protocol": "udp",
                    "cidr_ipv4": cidr,
                    "security_group_id": "sg-nlb",
                    "referenced_security_group_id": None,
                },
                "after": after,
            },
        }

    def _complete(self):
        proof = checker.EXPECTED_SANDBOX_PROOF_SOURCE_CIDR
        changes = [
            self._listener(),
            self._rule(
                f"{self.COMPUTE}.aws_vpc_security_group_ingress_rule."
                f'server_nlb_udp["{proof}"]',
                proof,
            ),
        ]
        for index in range(checker.EXPECTED_SANDBOX_AC_EIP_COUNT):
            changes.append(
                self._rule(
                    f"{self.AC}.aws_vpc_security_group_ingress_rule."
                    f'server_nlb_registration["{index}"]',
                    f"198.51.100.{index}/32",
                )
            )
        return changes

    def test_complete_move_is_admitted(self) -> None:
        self.assertEqual(
            checker.validate_dmz_boundary_noop({"resource_changes": self._complete()}),
            [],
        )

    def test_partial_move_is_refused(self) -> None:
        """Half a move black-holes the edge or leaves the old port admitted."""
        for drop in (0, 1, 5):
            with self.subTest(dropped=drop):
                changes = self._complete()
                dropped = changes.pop(drop)
                errors = checker.validate_dmz_boundary_noop(
                    {"resource_changes": changes}
                )
                self.assertTrue(errors)
                self.assertTrue(
                    any("refuses relay-DMZ boundary change" in e for e in errors),
                    f"expected generic refusal after dropping {dropped['address']}",
                )

    def test_wrong_destination_port_is_refused(self) -> None:
        changes = self._complete()
        changes[0] = self._listener(after_port=8443)
        errors = checker.validate_dmz_boundary_noop({"resource_changes": changes})
        self.assertTrue(any("client-edge listener must move" in e for e in errors))

    def test_widened_source_is_refused(self) -> None:
        """The port may move; who is admitted may not."""
        proof = checker.EXPECTED_SANDBOX_PROOF_SOURCE_CIDR
        changes = self._complete()
        changes[1] = self._rule(
            f"{self.COMPUTE}.aws_vpc_security_group_ingress_rule."
            f'server_nlb_udp["{proof}"]',
            proof,
            cidr_ipv4="0.0.0.0/0",
        )
        errors = checker.validate_dmz_boundary_noop({"resource_changes": changes})
        self.assertTrue(any("source and security group unchanged" in e for e in errors))

    def test_retargeted_forward_is_refused(self) -> None:
        changes = self._complete()
        changes[0] = self._listener(
            default_action=[{"target_group_arn": "arn:tg-other"}]
        )
        errors = checker.validate_dmz_boundary_noop({"resource_changes": changes})
        self.assertTrue(any("client-edge listener must move" in e for e in errors))



class RelayDmzPlanCheckerTests(unittest.TestCase):
    def test_runbook_orders_normal_deploy_and_proof(self) -> None:
        runbook = (
            REPO_ROOT / "docs" / "runbooks" / "sandbox-relay-dmz-replacement.md"
        ).read_text()
        anchors = [
            "before applying that exact artifact",
            "gh workflow run build-and-push.yml --ref main",
            "-f force_build=false",
            "There is no standing cutover override.",
            "## Gate 2: structural proof",
            "## Gate 3: relay fleet and HTTPS proof",
            "--mode functional",
            "## Gate 4: direct SDK UDP proof",
        ]
        positions = [runbook.find(anchor) for anchor in anchors]
        self.assertNotIn(-1, positions)
        self.assertEqual(sorted(positions), positions)
        self.assertNotIn("deploy-relay.sh sandbox true", runbook)
        self.assertNotIn("relay_dmz_" "cutover", runbook)
        self.assertIn("assigned-cell server NLB UDP 62206 exactly once", runbook)
        self.assertIn("no internet-facing relay NLB or relay UDP listener", runbook)

    def assert_violation(
        self, plan: dict[str, Any], needle: str, *, require_enabled: bool = True
    ) -> None:
        clean_errors = checker.validate_plan(
            clean_plan(), require_enabled=require_enabled
        )
        self.assertEqual([], clean_errors, "clean baseline unexpectedly failed")
        errors = checker.validate_plan(plan, require_enabled=require_enabled)
        self.assertTrue(errors, "mutation unexpectedly passed")
        self.assertTrue(any(needle in error for error in errors), errors)

    def test_clean_synthetic_plan_passes(self) -> None:
        self.assertEqual([], checker.validate_plan(clean_plan()))

    def test_source_fenced_topology_is_opt_in_and_legacy_remains_default(
        self,
    ) -> None:
        self.assertEqual([], checker.validate_plan(clean_plan()))
        fenced = source_fenced_plan()
        self.assertNotEqual(
            [],
            checker.validate_plan(fenced),
            "legacy topology mode must reject the source-fenced graph",
        )
        self.assertEqual(
            [],
            checker.validate_plan(
                fenced, require_udp_source_fenced_topology=True
            ),
        )

    def test_in_vpc_ac_rule_is_required_by_the_fenced_topology(self) -> None:
        """Dropping the rule reds the contract, so the AC path cannot silently go.

        The public UDP fence removed this path once already, by zeroing
        server_nhp_udp's count -- whose 0.0.0.0/0 source was also the only rule
        admitting in-VPC AC traffic. Requiring the replacement here is what stops
        a future fence change from taking it out again unnoticed.
        """
        plan = source_fenced_plan()
        compute_config = plan["configuration"]["root_module"]["module_calls"]["nhp"][
            "module"
        ]["module_calls"]["compute"]["module"]
        compute_config["resources"] = [
            r
            for r in compute_config["resources"]
            if r.get("name") != "server_nhp_udp_vpc"
        ]
        plan["resource_changes"] = [
            c
            for c in plan["resource_changes"]
            if c.get("name") != "server_nhp_udp_vpc"
        ]
        self.assertNotEqual(
            [],
            checker.validate_plan(
                plan, require_udp_source_fenced_topology=True
            ),
        )

    def test_in_vpc_ac_rule_source_must_be_the_cell_vpc_cidr(self) -> None:
        """Routing it through the operator-supplied relay list is refused.

        var.additional_nhp_udp_ingress_cidrs is an arbitrary caller-supplied
        list; binding this rule to it would let any CIDR reach the servers on
        UDP 62206 under the in-VPC AC rule's name.
        """
        plan = source_fenced_plan()
        compute_config = plan["configuration"]["root_module"]["module_calls"]["nhp"][
            "module"
        ]["module_calls"]["compute"]["module"]
        for resource in compute_config["resources"]:
            if resource.get("name") == "server_nhp_udp_vpc":
                resource["expressions"]["cidr_ipv4"] = {
                    "references": ["var.additional_nhp_udp_ingress_cidrs"]
                }
        errors = checker.validate_plan(
            plan, require_udp_source_fenced_topology=True
        )
        self.assertIn(
            "canonical server SG in-VPC AC rule must bind only the cell VPC"
            " CIDR on UDP 62206",
            errors,
        )


    def test_source_fenced_topology_requires_explicit_unknown_sg_references(
        self,
    ) -> None:
        plan = source_fenced_plan()
        nlb = resource(plan, ".aws_lb.server[0]")
        nlb["change"]["after"].pop("security_groups")
        nlb["change"]["after_unknown"]["security_groups"] = True

        nlb_sg = resource(plan, ".aws_security_group.server_nlb[0]")
        nlb_sg["change"]["after"].pop("id")
        nlb_sg["change"]["after_unknown"]["id"] = True

        unknown_fields = (
            (
                PROOF_SOURCE_RULE_SUFFIX,
                "security_group_id",
            ),
            (".server_nhp_udp_nlb[0]", "referenced_security_group_id"),
            (
                ".aws_vpc_security_group_ingress_rule.server_nlb_health[0]",
                "referenced_security_group_id",
            ),
            (
                ".aws_vpc_security_group_egress_rule.server_nlb_udp[0]",
                "security_group_id",
            ),
            (
                ".aws_vpc_security_group_egress_rule.server_nlb_health[0]",
                "security_group_id",
            ),
            *(
                (
                    ".aws_vpc_security_group_ingress_rule."
                    f'server_nlb_registration["{index}"]',
                    "security_group_id",
                )
                for index in range(checker.EXPECTED_SANDBOX_AC_EIP_COUNT)
            ),
        )
        for suffix, field in unknown_fields:
            change = resource(plan, suffix)["change"]
            change["after"].pop(field)
            change["after_unknown"][field] = True

        self.assertEqual(
            [],
            checker.validate_plan(
                plan, require_udp_source_fenced_topology=True
            ),
        )

        missing_nlb_id = copy.deepcopy(plan)
        missing_nlb_sg = resource(
            missing_nlb_id, ".aws_security_group.server_nlb[0]"
        )
        missing_nlb_sg["change"]["after_unknown"].pop("id")
        errors = checker.validate_plan(
            missing_nlb_id, require_udp_source_fenced_topology=True
        )
        self.assertTrue(
            any("resolved or explicitly unknown planned ID" in error for error in errors),
            errors,
        )

        nlb["change"]["after_unknown"]["security_groups"] = False
        errors = checker.validate_plan(
            plan, require_udp_source_fenced_topology=True
        )
        self.assertTrue(
            any("attach exactly its dedicated security group" in error for error in errors),
            errors,
        )

    def test_source_fenced_topology_requires_existing_canonical_server_sg(
        self,
    ) -> None:
        plan = source_fenced_plan()
        plan["resource_changes"] = [
            change
            for change in plan["resource_changes"]
            if not change["address"].endswith("aws_security_group.server")
        ]
        errors = checker.validate_plan(
            plan, require_udp_source_fenced_topology=True
        )
        self.assertTrue(
            any("existing canonical server SG" in error for error in errors), errors
        )

    def test_source_fenced_topology_requires_complete_exact_ac_registration_pool(
        self,
    ) -> None:
        missing = source_fenced_plan()
        missing["resource_changes"] = [
            change
            for change in missing["resource_changes"]
            if not change["address"].endswith('server_nlb_registration["6"]')
        ]
        errors = checker.validate_plan(
            missing, require_udp_source_fenced_topology=True
        )
        self.assertTrue(
            any("exactly one registration rule" in error for error in errors),
            errors,
        )

        mismatched = source_fenced_plan()
        registration = resource(
            mismatched,
            '.server_nlb_registration["4"]',
        )
        registration["change"]["after"]["cidr_ipv4"] = "198.51.100.4/32"
        errors = checker.validate_plan(
            mismatched, require_udp_source_fenced_topology=True
        )
        self.assertTrue(
            any("matching managed EIP /32" in error for error in errors),
            errors,
        )

        duplicate_ip = source_fenced_plan()
        duplicate_eip = resource(duplicate_ip, ".aws_eip.ac[6]")["change"]
        duplicate_eip["after"]["public_ip"] = "52.14.199.249"
        duplicate_eip["before"]["public_ip"] = "52.14.199.249"
        duplicate_rule = resource(
            duplicate_ip, '.server_nlb_registration["6"]'
        )["change"]
        duplicate_rule["after"]["cidr_ipv4"] = "52.14.199.249/32"
        errors = checker.validate_plan(
            duplicate_ip, require_udp_source_fenced_topology=True
        )
        self.assertTrue(
            any("resolve atomically" in error for error in errors),
            errors,
        )

        partially_known = source_fenced_plan()
        unknown_eip = resource(partially_known, ".aws_eip.ac[6]")["change"]
        unknown_eip["actions"] = ["create"]
        unknown_eip["before"] = None
        unknown_eip["after"]["public_ip"] = None
        unknown_eip["after_unknown"]["public_ip"] = True
        unknown_rule = resource(
            partially_known, '.server_nlb_registration["6"]'
        )["change"]
        unknown_rule["after"]["cidr_ipv4"] = None
        unknown_rule["after_unknown"]["cidr_ipv4"] = True
        errors = checker.validate_plan(
            partially_known, require_udp_source_fenced_topology=True
        )
        self.assertTrue(
            any("resolve atomically" in error for error in errors),
            errors,
        )

        foreign = source_fenced_plan()
        rogue = copy.deepcopy(
            resource(foreign, '.server_nlb_registration["4"]')
        )
        rogue["address"] = rogue["address"].replace(
            'server_nlb_registration["4"]',
            'server_nlb_registration["7"]',
        )
        foreign["resource_changes"].append(rogue)
        errors = checker.validate_plan(
            foreign, require_udp_source_fenced_topology=True
        )
        self.assertTrue(
            any("exactly one registration rule" in error for error in errors),
            errors,
        )

        extra_eip = source_fenced_plan()
        rogue_eip = copy.deepcopy(resource(extra_eip, ".aws_eip.ac[4]"))
        rogue_eip["address"] = rogue_eip["address"].replace(
            "aws_eip.ac[4]",
            'aws_eip.ac["rogue"]',
        )
        extra_eip["resource_changes"].append(rogue_eip)
        errors = checker.validate_plan(
            extra_eip, require_udp_source_fenced_topology=True
        )
        self.assertTrue(
            any("managed EIP pool" in error for error in errors),
            errors,
        )

        nonnumeric = source_fence_migration_plan()
        rogue = copy.deepcopy(
            resource(nonnumeric, '.server_nlb_registration["4"]')
        )
        rogue["address"] = rogue["address"].replace(
            'server_nlb_registration["4"]',
            'server_nlb_registration["rogue"]',
        )
        rogue["change"]["after"]["cidr_ipv4"] = "0.0.0.0/0"
        rogue["change"]["after_unknown"].pop("cidr_ipv4", None)
        nonnumeric["resource_changes"].append(rogue)
        errors = checker.validate_plan(
            nonnumeric, require_udp_source_fenced_topology=True
        )
        self.assertTrue(
            any("exactly one registration rule" in error for error in errors),
            errors,
        )

    def test_source_fenced_topology_rejects_alternate_ac_registration_sources(
        self,
    ) -> None:
        for field, value in (
            ("cidr_ipv6", "::/0"),
            ("prefix_list_id", "pl-0123456789abcdef0"),
            ("referenced_security_group_id", "sg-unreviewed"),
            ("source_security_group_id", "sg-unreviewed"),
        ):
            with self.subTest(field=field):
                plan = source_fenced_plan()
                registration = resource(
                    plan,
                    '.server_nlb_registration["4"]',
                )
                registration["change"]["after"][field] = value
                errors = checker.validate_plan(
                    plan, require_udp_source_fenced_topology=True
                )
                self.assertTrue(
                    any("matching managed EIP /32" in error for error in errors),
                    errors,
                )

        for field, expression in (
            ("cidr_ipv6", {"constant_value": "::/0"}),
            ("prefix_list_id", {"constant_value": "pl-0123456789abcdef0"}),
            (
                "referenced_security_group_id",
                {"references": ["aws_security_group.unreviewed.id"]},
            ),
            (
                "source_security_group_id",
                {"references": ["aws_security_group.unreviewed.id"]},
            ),
        ):
            with self.subTest(authored_field=field):
                plan = source_fenced_plan()
                configured = configured_resource(
                    plan,
                    "ac",
                    "aws_vpc_security_group_ingress_rule",
                    "server_nlb_registration",
                )
                configured["expressions"][field] = expression
                errors = checker.validate_plan(
                    plan, require_udp_source_fenced_topology=True
                )
                self.assertTrue(
                    any(
                        "AC authored NLB SG rule inventory" in error
                        for error in errors
                    ),
                    errors,
                )

    def test_source_fenced_topology_rejects_alternate_ac_registration_for_each(
        self,
    ) -> None:
        plan = source_fenced_plan()
        configured = configured_resource(
            plan,
            "ac",
            "aws_vpc_security_group_ingress_rule",
            "server_nlb_registration",
        )
        configured["for_each_expression"]["references"] = [
            "var.server_nlb_source_fenced",
            "aws_eip.unreviewed",
        ]
        errors = checker.validate_plan(
            plan, require_udp_source_fenced_topology=True
        )
        self.assertTrue(
            any(
                "AC authored NLB SG rule inventory" in error
                for error in errors
            ),
            errors,
        )

    def test_source_fenced_topology_rejects_extra_authored_ac_nlb_rule(
        self,
    ) -> None:
        for target_ref in (
            "var.server_nlb_security_group_id",
            "local.server_nlb_security_group_id",
        ):
            with self.subTest(target_ref=target_ref):
                plan = source_fenced_plan()
                ac_resources = plan["configuration"]["root_module"][
                    "module_calls"
                ]["nhp"]["module"]["module_calls"]["ac"]["module"]["resources"]
                ac_resources.append(
                    config_resource(
                        "aws_vpc_security_group_ingress_rule",
                        "server_nlb_backdoor",
                        {
                            "cidr_ipv4": {"constant_value": "0.0.0.0/0"},
                            "from_port": {
                                "constant_value": checker.EXPECTED_NHP_SERVER_PORT
                            },
                            "ip_protocol": {"constant_value": "udp"},
                            "security_group_id": {
                                "references": [target_ref]
                            },
                            "to_port": {
                                "constant_value": checker.EXPECTED_NHP_SERVER_PORT
                            },
                        },
                    )
                )

                errors = checker.validate_plan(
                    plan, require_udp_source_fenced_topology=True
                )
                self.assertTrue(
                    any(
                        "AC authored NLB SG rule inventory" in error
                        for error in errors
                    ),
                    errors,
                )

    def test_source_fenced_topology_rejects_ac_eip_replacement(self) -> None:
        plan = source_fenced_plan()
        for index in range(checker.EXPECTED_SANDBOX_AC_EIP_COUNT):
            eip_change = resource(plan, f".aws_eip.ac[{index}]")["change"]
            eip_change["actions"] = ["delete", "create"]
            eip_change["after"]["public_ip"] = None
            eip_change["after_unknown"]["public_ip"] = True

            registration_change = resource(
                plan, f'.server_nlb_registration["{index}"]'
            )["change"]
            registration_change["after"]["cidr_ipv4"] = None
            registration_change["after_unknown"]["cidr_ipv4"] = True

        errors = checker.validate_plan(
            plan, require_udp_source_fenced_topology=True
        )
        self.assertEqual(
            checker.EXPECTED_SANDBOX_AC_EIP_COUNT,
            sum(
                "must not be destroyed, replaced, or forgotten" in error
                for error in errors
            ),
            errors,
        )

        impure_create = source_fenced_plan()
        eip_change = resource(impure_create, ".aws_eip.ac[4]")["change"]
        eip_change["actions"] = ["create"]
        errors = checker.validate_plan(
            impure_create, require_udp_source_fenced_topology=True
        )
        self.assertTrue(
            any(
                "must not be destroyed, replaced, or forgotten" in error
                for error in errors
            ),
            errors,
        )

    def test_source_fenced_topology_rejects_unreviewed_server_udp_ingress(
        self,
    ) -> None:
        planned = source_fenced_plan()
        rogue = copy.deepcopy(resource(planned, PROOF_SOURCE_RULE_SUFFIX))
        rogue["address"] = (
            "module.nhp.module.compute."
            'aws_vpc_security_group_ingress_rule.server_backdoor["198.51.100.42/32"]'
        )
        rogue["name"] = "server_backdoor"
        rogue["change"]["after"].update(
            {
                "security_group_id": "sg-server",
                "cidr_ipv4": "198.51.100.42/32",
            }
        )
        planned["resource_changes"].append(rogue)
        errors = checker.validate_plan(
            planned, require_udp_source_fenced_topology=True
        )
        self.assertTrue(
            any("planned UDP-capable ingress" in error for error in errors), errors
        )
        unknown_planned = copy.deepcopy(planned)
        unknown_rogue = resource(
            unknown_planned, '.server_backdoor["198.51.100.42/32"]'
        )
        unknown_rogue["change"]["after"].pop("security_group_id")
        unknown_rogue["change"]["after_unknown"]["security_group_id"] = True
        errors = checker.validate_plan(
            unknown_planned, require_udp_source_fenced_topology=True
        )
        self.assertTrue(
            any(
                "compute planned UDP-capable ingress inventory" in error
                for error in errors
            ),
            errors,
        )

        external_server = source_fenced_plan()
        external_rule = copy.deepcopy(
            resource(
                external_server,
                PROOF_SOURCE_RULE_SUFFIX,
            )
        )
        external_rule["address"] = (
            'aws_vpc_security_group_ingress_rule.external_server_backdoor["198.51.100.42/32"]'
        )
        external_rule["name"] = "external_server_backdoor"
        external_rule["change"]["after"].update(
            {
                "security_group_id": "sg-server",
                "cidr_ipv4": "198.51.100.42/32",
            }
        )
        external_server["resource_changes"].append(external_rule)
        errors = checker.validate_plan(
            external_server, require_udp_source_fenced_topology=True
        )
        self.assertTrue(
            any("canonical server SG planned UDP-capable" in error for error in errors),
            errors,
        )

        external_nlb = source_fenced_plan()
        external_rule = copy.deepcopy(
            resource(external_nlb, PROOF_SOURCE_RULE_SUFFIX)
        )
        external_rule["address"] = (
            'aws_vpc_security_group_ingress_rule.external_nlb_backdoor["0.0.0.0/0"]'
        )
        external_rule["name"] = "external_nlb_backdoor"
        external_rule["change"]["after"]["cidr_ipv4"] = (
            checker.EXPECTED_IPV4_DEFAULT_CIDR
        )
        external_nlb["resource_changes"].append(external_rule)
        errors = checker.validate_plan(
            external_nlb, require_udp_source_fenced_topology=True
        )
        self.assertTrue(
            any("global planned rule inventory" in error for error in errors), errors
        )

        unknown_external = source_fenced_plan()
        external_rule = copy.deepcopy(
            resource(
                unknown_external,
                PROOF_SOURCE_RULE_SUFFIX,
            )
        )
        external_rule["address"] = (
            "module.unrelated."
            'aws_vpc_security_group_ingress_rule.external_unknown["198.51.100.42/32"]'
        )
        external_rule["name"] = "external_unknown"
        external_rule["change"]["after"].pop("security_group_id")
        external_rule["change"]["after_unknown"]["security_group_id"] = True
        unknown_external["resource_changes"].append(external_rule)
        errors = checker.validate_plan(
            unknown_external, require_udp_source_fenced_topology=True
        )
        self.assertTrue(
            any("non-compute changed SG rules" in error for error in errors),
            errors,
        )

        unknown_tcp_surface = source_fenced_plan()
        external_rule = copy.deepcopy(
            resource(
                unknown_tcp_surface,
                PROOF_SOURCE_RULE_SUFFIX,
            )
        )
        external_rule["address"] = (
            "module.unrelated."
            'aws_vpc_security_group_ingress_rule.external_tcp["0.0.0.0/0"]'
        )
        external_rule["name"] = "external_tcp"
        external_rule["change"]["after"].update(
            {
                "cidr_ipv4": checker.EXPECTED_IPV4_DEFAULT_CIDR,
                "ip_protocol": "tcp",
                "from_port": checker.EXPECTED_RELAY_ACK_PORT,
                "to_port": checker.EXPECTED_RELAY_ACK_PORT,
            }
        )
        external_rule["change"]["after"].pop("security_group_id")
        external_rule["change"]["after_unknown"]["security_group_id"] = True
        unknown_tcp_surface["resource_changes"].append(external_rule)
        unknown_tcp_surface["resource_changes"].append(
            {
                "address": "module.unrelated.aws_lb_listener.external_tcp",
                "mode": "managed",
                "type": "aws_lb_listener",
                "name": "external_tcp",
                "change": {
                    "actions": ["create"],
                    "before": None,
                    "after": {
                        "protocol": "TCP",
                        "port": checker.EXPECTED_RELAY_ACK_PORT,
                    },
                    "after_unknown": {"load_balancer_arn": True},
                },
            }
        )
        errors = checker.validate_plan(
            unknown_tcp_surface, require_udp_source_fenced_topology=True
        )
        self.assertTrue(
            any("non-compute changed SG rules" in error for error in errors),
            errors,
        )
        self.assertTrue(
            any("non-compute changed listeners" in error for error in errors),
            errors,
        )

        resolved_external_listener = source_fenced_plan()
        resolved_external_listener["resource_changes"].append(
            {
                "address": "module.unrelated.aws_lb_listener.external_udp",
                "mode": "managed",
                "type": "aws_lb_listener",
                "name": "external_udp",
                "change": {
                    "actions": ["create"],
                    "before": None,
                    "after": {
                        "protocol": "UDP",
                        "port": checker.EXPECTED_NHP_SERVER_PORT,
                        "load_balancer_arn": (
                            "arn:aws:elasticloadbalancing:"
                            f"{checker.EXPECTED_SANDBOX_REGION}:"
                            f"{checker.EXPECTED_SANDBOX_ACCOUNT_ID}:"
                            "loadbalancer/net/external/resolved"
                        ),
                    },
                    "after_unknown": {},
                },
            }
        )
        errors = checker.validate_plan(
            resolved_external_listener,
            require_udp_source_fenced_topology=True,
        )
        self.assertTrue(
            any("non-compute UDP-capable listeners" in error for error in errors),
            errors,
        )

        authored = source_fenced_plan()
        compute_resources = authored["configuration"]["root_module"]["module_calls"][
            "nhp"
        ]["module"]["module_calls"]["compute"]["module"]["resources"]
        compute_resources.append(
            config_resource(
                "aws_vpc_security_group_ingress_rule",
                "server_backdoor",
                {
                    "cidr_ipv4": {"constant_value": "198.51.100.42/32"},
                    "from_port": {
                        "constant_value": checker.EXPECTED_NHP_SERVER_PORT
                    },
                    "ip_protocol": {"constant_value": "udp"},
                    "security_group_id": {
                        "references": [
                            "aws_security_group.server.id",
                            "aws_security_group.server",
                        ]
                    },
                    "to_port": {
                        "constant_value": checker.EXPECTED_NHP_SERVER_PORT
                    },
                },
            )
        )
        errors = checker.validate_plan(
            authored, require_udp_source_fenced_topology=True
        )
        self.assertTrue(
            any("authored UDP-capable ingress" in error for error in errors), errors
        )
        rogue_config = configured_resource(
            authored,
            "compute",
            "aws_vpc_security_group_ingress_rule",
            "server_backdoor",
        )
        rogue_config["expressions"]["security_group_id"] = {
            "references": ["var.runtime_security_group_id"]
        }
        errors = checker.validate_plan(
            authored, require_udp_source_fenced_topology=True
        )
        self.assertTrue(
            any(
                "compute authored UDP-capable ingress inventory" in error
                for error in errors
            ),
            errors,
        )

    def test_source_fence_migration_requires_full_or_exact_remaining_graph(
        self,
    ) -> None:
        plan = source_fence_migration_plan()
        missing_boundary_gate = checker.validate_plan(
            plan,
            allow_udp_source_fence_replacement=True,
        )
        self.assertEqual(
            [
                "allow_udp_source_fence_replacement requires "
                "require_dmz_boundary_noop"
            ],
            missing_boundary_gate,
        )
        self.assertEqual(
            [],
            checker.validate_plan(
                plan,
                require_dmz_boundary_noop=True,
                allow_udp_source_fence_replacement=True,
            ),
        )
        original_actions = checker.UDP_SOURCE_FENCE_MIGRATION_ACTIONS
        try:
            # Declaration order is irrelevant; each address's action ordering is
            # enforced by the sibling replacement-order mutation tests.
            checker.UDP_SOURCE_FENCE_MIGRATION_ACTIONS = tuple(
                reversed(original_actions)
            )
            self.assertEqual(
                [],
                checker.validate_plan(
                    plan,
                    require_dmz_boundary_noop=True,
                    allow_udp_source_fence_replacement=True,
                ),
            )
        finally:
            checker.UDP_SOURCE_FENCE_MIGRATION_ACTIONS = original_actions

        migration_changes = [
            change
            for change in plan["resource_changes"]
            if checker.is_dmz_boundary_address(change["address"])
            and change["change"]["actions"] != ["no-op"]
        ]
        self.assertEqual(
            9 + checker.EXPECTED_SANDBOX_AC_EIP_COUNT,
            len(migration_changes),
        )
        for omitted in migration_changes:
            with self.subTest(omitted=omitted["address"]):
                candidate = copy.deepcopy(plan)
                candidate["resource_changes"] = [
                    change
                    for change in candidate["resource_changes"]
                    if change["address"] != omitted["address"]
                ]
                errors = checker.validate_dmz_boundary_noop(
                    candidate, allow_udp_source_fence_replacement=True
                )
                key = checker.udp_source_fence_migration_address_key(
                    omitted["address"]
                )
                if key == checker.UDP_SOURCE_FENCE_LEGACY_INGRESS_DELETE:
                    self.assertEqual([], errors)
                else:
                    self.assertTrue(
                        any(
                            "bounded remaining subset" in error for error in errors
                        ),
                        errors,
                    )

    def test_source_fence_partial_retry_accepts_only_exact_target_complement(
        self,
    ) -> None:
        cases = (
            {
                checker.UDP_SOURCE_FENCE_NLB_REPLACEMENT,
                checker.UDP_SOURCE_FENCE_LISTENER_REPLACEMENT,
            },
            {
                checker.UDP_SOURCE_FENCE_NLB_REPLACEMENT,
                checker.UDP_SOURCE_FENCE_LISTENER_REPLACEMENT,
                checker.UDP_SOURCE_FENCE_LEGACY_INGRESS_DELETE,
            },
            {checker.UDP_SOURCE_FENCE_PROOF_INGRESS_CREATE},
        )
        for pending in cases:
            with self.subTest(pending=sorted(pending)):
                self.assertEqual(
                    [],
                    checker.validate_plan(
                        source_fence_partial_retry_plan(pending),
                        require_dmz_boundary_noop=True,
                        allow_udp_source_fence_replacement=True,
                    ),
                )

    def test_source_fence_deposed_retry_phases_are_bounded(self) -> None:
        for listener_create in (False, True):
            with self.subTest(listener_create=listener_create):
                self.assertEqual(
                    [],
                    checker.validate_plan(
                        source_fence_deposed_retry_plan(
                            listener_create=listener_create
                        ),
                        require_dmz_boundary_noop=True,
                        allow_udp_source_fence_replacement=True,
                    ),
                )

    def test_source_fence_deposed_retry_rejects_legacy_drift(self) -> None:
        plan = source_fence_deposed_retry_plan(listener_create=False)
        deposed = next(
            item
            for item in plan["resource_changes"]
            if item.get("deposed") == "deadbeef"
        )
        deposed["change"]["before"]["security_groups"] = ["sg-attacker"]
        errors = checker.validate_plan(
            plan,
            require_dmz_boundary_noop=True,
            allow_udp_source_fence_replacement=True,
        )
        self.assertTrue(
            any("deposed NLB delete" in error for error in errors),
            errors,
        )

    def test_source_fence_partial_retry_rejects_unsafe_complement(
        self,
    ) -> None:
        pending = {
            checker.UDP_SOURCE_FENCE_NLB_REPLACEMENT,
            checker.UDP_SOURCE_FENCE_LISTENER_REPLACEMENT,
        }

        unknown = source_fence_partial_retry_plan(pending)
        proof = resource(unknown, PROOF_SOURCE_RULE_SUFFIX)
        proof["change"]["after_unknown"] = {"cidr_ipv4": True}

        mismatched = source_fence_partial_retry_plan(pending)
        proof = resource(mismatched, PROOF_SOURCE_RULE_SUFFIX)
        proof["change"]["before"]["cidr_ipv4"] = "10.0.0.0/8"

        missing = source_fence_partial_retry_plan(pending)
        missing["resource_changes"] = [
            item
            for item in missing["resource_changes"]
            if not item["address"].endswith("aws_security_group.server_nlb[0]")
        ]

        legacy_present = source_fence_partial_retry_plan(pending)
        legacy = resource(
            source_fence_migration_plan(), ".server_nhp_udp[0]"
        )
        legacy["change"] = {
            "actions": ["no-op"],
            "before": copy.deepcopy(legacy["change"]["before"]),
            "after": copy.deepcopy(legacy["change"]["before"]),
            "after_unknown": {},
        }
        legacy_present["resource_changes"].append(legacy)

        for candidate in (unknown, mismatched, missing, legacy_present):
            with self.subTest(candidate=candidate):
                errors = checker.validate_dmz_boundary_noop(
                    candidate, allow_udp_source_fence_replacement=True
                )
                self.assertTrue(
                    any(
                        "bounded remaining subset" in error
                        or "already-applied" in error
                        or "must not retain the legacy" in error
                        for error in errors
                    ),
                    errors,
                )

    def test_source_fence_migration_pins_exact_before_state(self) -> None:
        cases = (
            (".aws_lb.server[0]", "public NLB legacy before-state"),
            (".aws_lb_listener.udp[0]", "listener legacy before-state"),
            (".server_nhp_udp[0]", "legacy server ingress deletion"),
        )
        for suffix, expected_error in cases:
            with self.subTest(suffix=suffix):
                plan = source_fence_migration_plan()
                resource(plan, suffix)["change"]["before"] = {
                    "totally": "unreviewed"
                }
                errors = checker.validate_dmz_boundary_noop(
                    plan, allow_udp_source_fence_replacement=True
                )
                self.assertTrue(
                    any(expected_error in error for error in errors), errors
                )

        plan = source_fence_migration_plan()
        listener = resource(plan, ".aws_lb_listener.udp[0]")
        wrong_account_target = (
            f"arn:aws:elasticloadbalancing:{checker.EXPECTED_SANDBOX_REGION}:"
            "000000000000:targetgroup/"
            f"{checker.EXPECTED_SANDBOX_SERVER_UDP_TG_NAME}/rogue"
        )
        for side in ("before", "after"):
            listener["change"][side]["default_action"] = [
                {"target_group_arn": wrong_account_target}
            ]
        errors = checker.validate_dmz_boundary_noop(
            plan, allow_udp_source_fence_replacement=True
        )
        self.assertTrue(
            any(
                "canonical blue or green public UDP target group" in error
                for error in errors
            ),
            errors,
        )

        for before_name, after_name in (
            (
                checker.EXPECTED_SANDBOX_SERVER_UDP_TG_NAME,
                checker.EXPECTED_SANDBOX_SERVER_UDP_GREEN_TG_NAME,
            ),
            (
                checker.EXPECTED_SANDBOX_SERVER_UDP_GREEN_TG_NAME,
                checker.EXPECTED_SANDBOX_SERVER_UDP_TG_NAME,
            ),
        ):
            with self.subTest(before_name=before_name, after_name=after_name):
                plan = source_fence_migration_plan()
                listener = resource(plan, ".aws_lb_listener.udp[0]")
                for side, target_name in (
                    ("before", before_name),
                    ("after", after_name),
                ):
                    listener["change"][side]["default_action"] = [
                        {
                            "target_group_arn": sandbox_udp_target_group_arn(
                                target_name, side
                            )
                        }
                    ]
                errors = checker.validate_dmz_boundary_noop(
                    plan, allow_udp_source_fence_replacement=True
                )
                self.assertTrue(
                    any(
                        "preserve the exact active public UDP target group" in error
                        for error in errors
                    ),
                    errors,
                )

        plan = source_fence_migration_plan()
        listener = resource(plan, ".aws_lb_listener.udp[0]")
        empty_suffix_target = sandbox_udp_target_group_arn(
            checker.EXPECTED_SANDBOX_SERVER_UDP_TG_NAME, ""
        )
        for side in ("before", "after"):
            listener["change"][side]["default_action"] = [
                {"target_group_arn": empty_suffix_target}
            ]
        errors = checker.validate_dmz_boundary_noop(
            plan, allow_udp_source_fence_replacement=True
        )
        self.assertTrue(
            any(
                "canonical blue or green public UDP target group" in error
                for error in errors
            ),
            errors,
        )

        plan = source_fence_migration_plan()
        nlb_sg = resource(plan, ".aws_security_group.server_nlb[0]")
        nlb_sg["change"]["before"] = {"id": "sg-existing"}
        errors = checker.validate_dmz_boundary_noop(
            plan, allow_udp_source_fence_replacement=True
        )
        self.assertTrue(any("must be a pure create" in error for error in errors), errors)

        plan = source_fence_migration_plan()
        ac_registration = resource(plan, '.server_nlb_registration["4"]')
        ac_registration["change"]["before"] = {
            "security_group_id": "sg-existing",
            "cidr_ipv4": "198.51.100.4/32",
            "ip_protocol": "udp",
            "from_port": checker.EXPECTED_NHP_SERVER_PORT,
            "to_port": checker.EXPECTED_NHP_SERVER_PORT,
        }
        errors = checker.validate_dmz_boundary_noop(
            plan, allow_udp_source_fence_replacement=True
        )
        self.assertTrue(any("must be a pure create" in error for error in errors), errors)

    def test_source_fence_migration_preserves_live_green_target(self) -> None:
        plan = source_fence_migration_plan()
        listener = resource(plan, ".aws_lb_listener.udp[0]")
        # The captured provider envelope is itself the green-preserving shape:
        # both sides already pin the same canonical live green target group.
        # Assert that directly instead of overwriting default_action, which
        # would break the exact-envelope comparison the checker also enforces.
        green_target_prefix = (
            f"arn:aws:elasticloadbalancing:{checker.EXPECTED_SANDBOX_REGION}:"
            f"{checker.EXPECTED_SANDBOX_ACCOUNT_ID}:targetgroup/"
            f"{checker.EXPECTED_SANDBOX_SERVER_UDP_GREEN_TG_NAME}/"
        )
        green_targets = set()
        for side in ("before", "after"):
            target_group_arn = listener["change"][side]["default_action"][0][
                "target_group_arn"
            ]
            self.assertTrue(
                target_group_arn.startswith(green_target_prefix)
                and bool(target_group_arn.rsplit("/", 1)[-1]),
                target_group_arn,
            )
            green_targets.add(target_group_arn)
        self.assertEqual(1, len(green_targets), green_targets)

        self.assertEqual(
            [],
            checker.validate_plan(
                plan,
                require_dmz_boundary_noop=True,
                allow_udp_source_fence_replacement=True,
            ),
        )

    def test_source_fence_migration_rejects_cross_parent_substitution(self) -> None:
        plan = source_fence_migration_plan()
        legacy = resource(plan, ".server_nhp_udp[0]")
        legacy["address"] = legacy["address"].replace(
            "module.nhp.module.compute", "module.unrelated.module.compute"
        )
        errors = checker.validate_dmz_boundary_noop(
            plan, allow_udp_source_fence_replacement=True
        )
        self.assertTrue(
            any("unreviewed UDP source-fence" in error for error in errors), errors
        )

    def test_source_fence_migration_rejects_wrong_listener_order(self) -> None:
        plan = source_fence_migration_plan()
        listener = resource(plan, ".aws_lb_listener.udp[0]")
        listener["change"]["actions"] = ["create", "delete"]
        errors = checker.validate_dmz_boundary_noop(
            plan, allow_udp_source_fence_replacement=True
        )
        self.assertTrue(
            any("unreviewed UDP source-fence" in error for error in errors), errors
        )
        self.assertTrue(
            any("public UDP listener replacement" in error for error in errors),
            errors,
        )

    def test_source_fence_migration_rejects_wrong_nlb_order(self) -> None:
        plan = source_fence_migration_plan()
        nlb = resource(plan, ".aws_lb.server[0]")
        nlb["change"]["actions"] = ["delete", "create"]
        errors = checker.validate_dmz_boundary_noop(
            plan, allow_udp_source_fence_replacement=True
        )
        self.assertTrue(
            any("unreviewed UDP source-fence" in error for error in errors), errors
        )
        self.assertTrue(
            any("public NLB replacement" in error for error in errors), errors
        )

    def test_source_fence_migration_rejects_extra_public_source(self) -> None:
        plan = source_fence_migration_plan()
        extra = copy.deepcopy(resource(plan, PROOF_SOURCE_RULE_SUFFIX))
        extra["address"] = extra["address"].replace(
            f'"{checker.EXPECTED_SANDBOX_PROOF_SOURCE_CIDR}"',
            f'"{checker.EXPECTED_IPV4_DEFAULT_CIDR}"',
        )
        extra["change"]["after"]["cidr_ipv4"] = checker.EXPECTED_IPV4_DEFAULT_CIDR
        plan["resource_changes"].append(extra)
        errors = checker.validate_dmz_boundary_noop(
            plan, allow_udp_source_fence_replacement=True
        )
        self.assertTrue(
            any("unreviewed UDP source-fence" in error for error in errors), errors
        )

    def test_source_fenced_noop_boundary_remains_valid_after_convergence(
        self,
    ) -> None:
        plan = source_fenced_plan()
        for change in plan["resource_changes"]:
            if not checker.is_dmz_boundary_address(change["address"]):
                continue
            change["change"]["actions"] = ["no-op"]
            change["change"]["before"] = copy.deepcopy(change["change"]["after"])
        self.assertEqual(
            [],
            checker.validate_plan(
                plan,
                require_dmz_boundary_noop=True,
                require_udp_source_fenced_topology=True,
            ),
        )

    def test_dns_domain_lists_require_aws_canonical_trailing_dots(self) -> None:
        allow_plan = clean_plan()
        allow = resource(
            allow_plan, ".aws_route53_resolver_firewall_domain_list.allow"
        )
        allow["change"]["after"]["domains"] = [
            domain.removesuffix(".")
            for domain in allow["change"]["after"]["domains"]
        ]
        self.assert_violation(allow_plan, "DNS allowlist changed")

        catch_all_plan = clean_plan()
        catch_all = resource(
            catch_all_plan, ".aws_route53_resolver_firewall_domain_list.all"
        )
        catch_all["change"]["after"]["domains"] = ["*"]
        self.assert_violation(catch_all_plan, "DNS catch-all domain list")

    def test_multiple_independent_violations_are_all_reported(self) -> None:
        plan = clean_plan()
        endpoint = resource(plan, '.aws_vpc_endpoint.interface["logs"]')
        endpoint_policy_json = json.loads(endpoint["change"]["after"]["policy"])
        endpoint_policy_json["Statement"][0]["Action"] = "*"
        endpoint["change"]["after"]["policy"] = json.dumps(endpoint_policy_json)
        flow_policy = resource(plan, ".aws_iam_role_policy.flow")
        flow_policy_json = json.loads(flow_policy["change"]["after"]["policy"])
        flow_policy_json["Statement"][0]["Resource"] = "arn:aws:logs:*"
        flow_policy["change"]["after"]["policy"] = json.dumps(flow_policy_json)

        errors = checker.validate_plan(plan)
        self.assertTrue(any("logs endpoint allow actions changed" in e for e in errors))
        self.assertTrue(
            any("Flow Logs DescribeLogGroups must use Resource=*" in e for e in errors)
        )

    def test_config_module_rejects_ambiguous_suffix(self) -> None:
        duplicate = {"resources": []}
        plan = {
            "configuration": {
                "root_module": {
                    "module_calls": {
                        "first": {
                            "module": {
                                "module_calls": {
                                    "relay_network": {
                                        "module": copy.deepcopy(duplicate)
                                    }
                                }
                            }
                        },
                        "second": {
                            "module": {
                                "module_calls": {
                                    "relay_network": {
                                        "module": copy.deepcopy(duplicate)
                                    }
                                }
                            }
                        },
                    }
                }
            }
        }
        validation = checker.Validation()
        self.assertIsNone(
            checker.config_module(validation, plan, "module.relay_network")
        )
        self.assertEqual(
            [
                "configuration module suffix 'module.relay_network' is ambiguous; found 2 matches"
            ],
            validation.errors,
        )

    def test_policy_parser_rejects_non_object_json_cleanly(self) -> None:
        for value in ([], "policy", 1, None):
            with (
                self.subTest(value=value),
                self.assertRaisesRegex(
                    ValueError, "endpoint policy must be a JSON object"
                ),
            ):
                checker.policy_statements(json.dumps(value))

    def test_cli_reports_non_object_policy_without_traceback(self) -> None:
        plan = clean_plan()
        endpoint = resource(plan, '.aws_vpc_endpoint.interface["logs"]')
        endpoint["change"]["after"]["policy"] = json.dumps([])
        result = run_checker_cli(plan)
        self.assertEqual(1, result.returncode, result.stderr)
        self.assertIn(
            "::error title=Relay DMZ plan contract::logs endpoint: "
            "endpoint policy must be a JSON object",
            result.stderr,
        )
        self.assertNotIn("Traceback", result.stderr)

    def test_cli_input_failures_are_exit_two_without_tracebacks(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            fixture = Path(temp_dir)
            malformed = fixture / "malformed.json"
            malformed.write_text("{", encoding="utf-8")
            invalid_utf8 = fixture / "invalid-utf8.json"
            invalid_utf8.write_bytes(b"\xff")
            invalid_roots = []
            for index, value in enumerate(([], {}, {"resource_changes": {}})):
                path = fixture / f"invalid-root-{index}.json"
                path.write_text(json.dumps(value), encoding="utf-8")
                invalid_roots.append(path)

            cases = [
                (fixture / "absent.json", "cannot read Terraform plan JSON"),
                (malformed, "cannot read Terraform plan JSON"),
                (invalid_utf8, "cannot read Terraform plan JSON"),
                *((path, "has no resource_changes array") for path in invalid_roots),
            ]
            for path, message in cases:
                with self.subTest(path=path.name):
                    result = run_checker_cli_path(path)
                    self.assertEqual(2, result.returncode, result.stderr)
                    self.assertIn(message, result.stderr)
                    self.assertNotIn("Traceback", result.stderr)

    def test_automatic_apply_accepts_only_a_converged_boundary(self) -> None:
        plan = boundary_noop_plan()
        self.assertEqual(
            [], checker.validate_plan(plan, require_dmz_boundary_noop=True)
        )
        plan["resource_changes"].append(
            {
                "address": "module.nhp.module.unrelated.aws_cloudwatch_metric_alarm.example",
                "mode": "managed",
                "type": "aws_cloudwatch_metric_alarm",
                "name": "example",
                "change": {
                    "actions": ["update"],
                    "before": {"threshold": 1},
                    "after": {"threshold": 2},
                    "after_unknown": {},
                },
            }
        )
        self.assertEqual(
            [], checker.validate_plan(plan, require_dmz_boundary_noop=True)
        )

    def test_automatic_apply_rejects_all_boundary_address_classes(self) -> None:
        addresses = (
            "module.relay_network[0].aws_vpc.relay",
            'module.outer[0].module.nhp["sandbox"].module.relay[0].aws_lb.relay',
            "module.outer.module.networking[0].aws_route_table_association.private[2]",
            "module.compute.aws_lb.server[0]",
            "module.compute.aws_lb.server_internal[0]",
            "module.compute.aws_lb_listener.udp[0]",
            "module.compute.aws_lb_listener.udp_internal[0]",
            "module.compute.aws_lb_target_group.udp[0]",
            "module.compute.aws_lb_target_group.udp_green[0]",
            "module.compute.aws_lb_target_group.udp_internal[0]",
            "module.compute.aws_lb_target_group.udp_internal_green[0]",
            "module.compute.aws_autoscaling_attachment.server[0]",
            "module.compute.aws_autoscaling_attachment.server_internal[0]",
            "module.compute.aws_autoscaling_group.server_green[0]",
            "module.compute.aws_vpc_security_group_ingress_rule.server_nhp_udp",
            "module.compute.aws_security_group.server_nlb[0]",
            "module.compute." + PROOF_SOURCE_RULE_ADDRESS_SUFFIX,
            "module.compute.aws_vpc_security_group_ingress_rule.server_nhp_udp_nlb[0]",
            "module.compute.aws_vpc_security_group_ingress_rule.server_nlb_health[0]",
            "module.compute.aws_vpc_security_group_egress_rule.server_nlb_udp[0]",
            "module.compute.aws_vpc_security_group_egress_rule.server_nlb_health[0]",
            'module.compute.aws_vpc_security_group_ingress_rule.server_nhp_udp_additional["10.101.10.0/24"]',
            "module.outer[0].module.ecr[0].aws_iam_role_policy.context_lookups_relay_ssm[0]",
            "module.nhp[0].terraform_data.relay_cell_routing[0]",
            "module.nhp[0].terraform_data.relay_network_ready[0]",
            "module.nhp[0].aws_route53_record.relay_alias[0]",
            (
                "module.security."
                "aws_guardduty_detector_feature.runtime_monitoring[0]"
            ),
            (
                "module.nhp.module.security."
                "aws_guardduty_detector_feature.runtime_monitoring[0]"
            ),
        )
        for address in addresses:
            with self.subTest(address=address):
                plan = {
                    "resource_changes": [
                        {
                            "address": address,
                            "mode": "managed",
                            "change": {"actions": ["update"]},
                        }
                    ]
                }
                errors = checker.validate_dmz_boundary_noop(plan)
                self.assertEqual(1, len(errors), errors)
                self.assertIn(address, errors[0])
                self.assertIn("newly reviewed temporary migration path", errors[0])

    def test_automatic_apply_rejects_partial_cutover_after_vpc_exists(self) -> None:
        plan = boundary_noop_plan()
        route = resource(
            plan,
            ".module.networking.aws_route.private_extensible_default[0]",
        )
        route["change"]["actions"] = ["create"]
        route["change"]["before"] = None
        errors = checker.validate_plan(plan, require_dmz_boundary_noop=True)
        self.assertTrue(
            any("private_extensible_default" in error for error in errors), errors
        )

    def test_boundary_noop_address_matching_has_safe_near_misses(self) -> None:
        for address in (
            "module.relay_identity[0].aws_secretsmanager_secret.relay",
            "module.networking.aws_route_table.private[0]",
            "module.compute.aws_security_group.server",
            "module.ecr.aws_iam_role_policy.unrelated",
            (
                "module.security."
                "aws_guardduty_detector_feature.lambda_network_logs[0]"
            ),
            "aws_route53_record.unrelated",
        ):
            with self.subTest(address=address):
                self.assertFalse(checker.is_dmz_boundary_address(address))

    def test_runtime_monitoring_provider_readback_order_is_pinned(self) -> None:
        security_main = REPO_ROOT / "terraform/modules/security/main.tf"
        source = security_main.read_text(encoding="utf-8")
        match = re.search(
            r'^resource "aws_guardduty_detector_feature" "runtime_monitoring" '
            r"\{.*?^\}\s*$",
            source,
            re.MULTILINE | re.DOTALL,
        )
        self.assertIsNotNone(match, "runtime_monitoring resource block is missing")
        assert match is not None
        resource = match.group(0)

        configurations = re.findall(
            r'additional_configuration\s*\{\s*name\s*=\s*"([^"]+)"\s*'
            r'status\s*=\s*"([^"]+)"\s*\}',
            resource,
        )
        # Completeness is the API requirement; sequence is the provider-version
        # hedge for the order-sensitive read-back behavior tracked in #36400.
        self.assertEqual(
            [
                ("EKS_ADDON_MANAGEMENT", "DISABLED"),
                ("ECS_FARGATE_AGENT_MANAGEMENT", "DISABLED"),
                ("EC2_AGENT_MANAGEMENT", "ENABLED"),
            ],
            configurations,
        )
        self.assertIn(
            "https://github.com/hashicorp/terraform-provider-aws/issues/36400",
            resource,
        )

    def test_production_wrapper_hard_blocks_relay_until_3154(self) -> None:
        terraform = shutil.which("terraform")
        if terraform is None:
            if os.environ.get("REQUIRE_TERRAFORM") == "1":
                self.fail("terraform is required for the CI prod relay hard-stop test")
            self.skipTest("terraform not installed")

        variables = (REPO_ROOT / "terraform/environments/prod/variables.tf").read_text(
            encoding="utf-8"
        )
        match = re.search(
            r'^variable\s+"deploy_relay"\s*\{.*?^\}\s*$',
            variables,
            re.MULTILINE | re.DOTALL,
        )
        self.assertIsNotNone(match, "prod deploy_relay variable block is missing")
        assert match is not None
        deploy_block = match.group(0)

        with tempfile.TemporaryDirectory() as temp_dir:
            fixture = Path(temp_dir)
            (fixture / "main.tf").write_text(
                f'{deploy_block}\n\noutput "deploy_relay" {{\n'
                "  value = var.deploy_relay\n}\n",
                encoding="utf-8",
            )
            init = subprocess.run(
                [terraform, "init", "-backend=false", "-input=false", "-no-color"],
                cwd=fixture,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(0, init.returncode, init.stdout + init.stderr)

            def run_plan(deploy_relay: bool) -> subprocess.CompletedProcess[str]:
                return subprocess.run(
                    [
                        terraform,
                        "plan",
                        "-refresh=false",
                        "-lock=false",
                        "-input=false",
                        "-no-color",
                        f"-var=deploy_relay={str(deploy_relay).lower()}",
                    ],
                    cwd=fixture,
                    check=False,
                    capture_output=True,
                    text=True,
                )

            allowed = run_plan(False)
            self.assertEqual(0, allowed.returncode, allowed.stdout + allowed.stderr)
            blocked = run_plan(True)
            output = blocked.stdout + blocked.stderr
            self.assertNotEqual(0, blocked.returncode, output)
            self.assertIn("Production relay enablement is blocked until #3154", output)

    def test_relay_iam_ssm_actions_stay_lockstep_with_endpoint_policy(self) -> None:
        self.assertEqual(
            checker.EXPECTED_INTERFACE_ENDPOINTS["ssm"] - {"ssm:GetParameter"},
            checker.EXPECTED_RELAY_IAM_SSM_ACTIONS,
        )

    def test_reference_walk_reads_valid_lists_once_and_recovers_nested_malformed_shape(
        self,
    ) -> None:
        class CountingReferences(list[str]):
            iterations = 0

            def __iter__(self) -> Iterator[str]:
                self.iterations += 1
                return super().__iter__()

        direct = CountingReferences(["module.relay_network[0].vpc_id"])
        value = {
            "references": direct,
            "malformed": {"references": {"references": ["module.networking.vpc_id"]}},
        }
        self.assertEqual(
            {"module.relay_network[0].vpc_id", "module.networking.vpc_id"},
            checker.references(value),
        )
        self.assertEqual(1, direct.iterations)

    def test_references_exact_resources_accepts_only_complete_expected_set(
        self,
    ) -> None:
        cases = (
            ("base", {"aws_security_group.relay"}, {"aws_security_group.relay"}, True),
            (
                "attribute",
                {"aws_security_group.relay.id"},
                {"aws_security_group.relay"},
                True,
            ),
            ("index", {"aws_subnet.relay[0].id"}, {"aws_subnet.relay"}, True),
            (
                "two bases",
                {"aws_subnet.relay[0].id", "aws_route_table.relay.id"},
                {"aws_subnet.relay", "aws_route_table.relay"},
                True,
            ),
            (
                "unreviewed metadata rejected",
                {"aws_security_group.relay.id", "var.vpc_id", "local.name"},
                {"aws_security_group.relay"},
                False,
            ),
            (
                "data resource rejected",
                {
                    "aws_security_group.relay.id",
                    "data.aws_security_group.unreviewed.id",
                },
                {"aws_security_group.relay"},
                False,
            ),
            (
                "module output rejected",
                {"aws_security_group.relay.id", "module.unreviewed.security_group_id"},
                {"aws_security_group.relay"},
                False,
            ),
            (
                "other provider resource rejected",
                {
                    "aws_security_group.relay.id",
                    "null_resource.unreviewed.id",
                },
                {"aws_security_group.relay"},
                False,
            ),
            (
                "missing expected",
                {"aws_subnet.relay[0].id"},
                {"aws_subnet.relay", "aws_route_table.relay"},
                False,
            ),
            (
                "extra resource",
                {"aws_subnet.relay[0].id", "aws_vpc.unreviewed.id"},
                {"aws_subnet.relay"},
                False,
            ),
            ("only non-resource", {"var.vpc_id"}, {"aws_vpc.relay"}, False),
        )
        for name, refs, expected, accepted in cases:
            with self.subTest(name=name):
                self.assertEqual(
                    accepted, checker.references_exact_resources(refs, expected)
                )
        self.assertTrue(
            checker.references_exact_resources(
                {"aws_security_group.relay.id", "var.reviewed_gate"},
                {"aws_security_group.relay"},
                allowed_metadata=frozenset({"var.reviewed_gate"}),
            )
        )
        self.assertFalse(
            checker.references_exact_resources(
                {
                    "aws_security_group.relay.id",
                    "var.reviewed_gate",
                    "var.unreviewed_gate",
                },
                {"aws_security_group.relay"},
                allowed_metadata=frozenset({"var.reviewed_gate"}),
            )
        )

    def test_sanitized_fixture_toolchain_provenance_is_current(self) -> None:
        plan = json.loads(REAL_PLAN_SHAPES.read_text(encoding="utf-8"))
        metadata = plan["_fixture"]
        recapture_hint = (
            "See tests/fixtures/relay-dmz-plan/README.md and recapture the "
            "sanitized fixture with the reviewed Terraform/provider pins."
        )
        self.assertEqual(
            metadata["capture_terraform_version"],
            plan["terraform_version"],
            recapture_hint,
        )
        self.assertEqual("1.14.3", metadata["capture_terraform_version"])
        self.assertEqual(
            "4221c9b816bcc6e1a104574f23afa8fcb24dd57f2e33abf38fe4aaf8779f4422",
            metadata["source_sha256"],
        )

        workflow_versions: dict[str, str] = {}
        for workflow in sorted((REPO_ROOT / ".github" / "workflows").glob("*.y*ml")):
            # Exactly two spaces pins this scan to workflow-level env entries;
            # job/step-local TF_VERSION values are unreviewed drift and must not
            # masquerade as the shared toolchain pin.
            matches = re.findall(
                r"^  TF_VERSION:\s*['\"]([^'\"]+)['\"]\s*$",
                workflow.read_text(encoding="utf-8"),
                flags=re.MULTILINE,
            )
            if matches:
                self.assertEqual(1, len(matches), workflow)
                workflow_versions[str(workflow.relative_to(REPO_ROOT))] = matches[0]
        self.assertEqual(
            metadata["workflow_terraform_version_files"],
            sorted(workflow_versions),
        )
        self.assertEqual(
            {metadata["capture_terraform_version"]},
            set(workflow_versions.values()),
            recapture_hint,
        )
        self.assertEqual("1.15.7", metadata["cross_validated_terraform_version"])

        provider_lock = SANDBOX_PROVIDER_LOCK.read_text(encoding="utf-8")
        provider_versions = re.findall(
            r'provider "registry\.terraform\.io/hashicorp/aws"\s*\{\s*'
            r'version\s*=\s*"([^"]+)"',
            provider_lock,
            flags=re.DOTALL,
        )
        self.assertEqual(
            [metadata["aws_provider_version"]], provider_versions, recapture_hint
        )
        self.assertEqual("6.54.0", metadata["aws_provider_version"])
        provider_blocks = re.findall(
            r'provider "([^"]+)"\s*\{(.*?)\n\}', provider_lock, flags=re.DOTALL
        )
        self.assertTrue(provider_blocks, recapture_hint)
        for provider, block in provider_blocks:
            with self.subTest(provider=provider):
                self.assertEqual(
                    4,
                    len(re.findall(r'^\s+"h1:', block, flags=re.MULTILINE)),
                    "sandbox provider lock must cover linux_amd64, darwin_amd64, "
                    "darwin_arm64, and windows_amd64; see the fixture README",
                )

    def test_sanitized_refresh_false_plan_preserves_real_terraform_shapes(
        self,
    ) -> None:
        plan = json.loads(REAL_PLAN_SHAPES.read_text(encoding="utf-8"))
        self.assertEqual("1.2", plan["format_version"])

        resources = checker.active_resources(plan)
        subnets = checker.resources_named(resources, "aws_subnet", "public")
        subnets += checker.resources_named(resources, "aws_subnet", "relay")
        subnets += checker.resources_named(resources, "aws_subnet", "endpoint")
        self.assertEqual(9, len(subnets))
        self.assertTrue(
            all(
                subnet.values.get("map_public_ip_on_launch") is False
                for subnet in subnets
            )
        )

        raw_subnets = raw_changes(plan, "aws_subnet")
        self.assertTrue(
            all(
                change["change"]["after_unknown"].get("map_public_ip_on_launch") is None
                for change in raw_subnets
            )
        )

        interfaces = checker.resources_named(resources, "aws_vpc_endpoint", "interface")
        self.assertEqual(8, len(interfaces))
        self.assertTrue(
            all(
                endpoint.values.get("private_dns_enabled") is True
                for endpoint in interfaces
            )
        )
        self.assertTrue(
            all(
                change["change"]["after_unknown"].get("private_dns_enabled") is None
                for change in raw_changes(plan, "aws_vpc_endpoint", "interface")
            )
        )

        logs_key = checker.resources_named(resources, "aws_kms_key", "logs")
        self.assertEqual(1, len(logs_key))
        self.assertIs(logs_key[0].values.get("enable_key_rotation"), True)
        raw_logs_key = raw_changes(plan, "aws_kms_key", "logs")[0]
        self.assertIsNone(
            raw_logs_key["change"]["after_unknown"].get("enable_key_rotation")
        )

        alb = checker.resources_named(resources, "aws_lb", "relay")
        self.assertEqual(1, len(alb))
        self.assertIs(alb[0].values.get("internal"), False)
        raw_alb = raw_changes(plan, "aws_lb", "relay")[0]
        self.assertIsNone(raw_alb["change"]["after_unknown"].get("internal"))

        asg = checker.resources_named(resources, "aws_autoscaling_group", "relay")
        self.assertEqual(1, len(asg))
        self.assertEqual(
            {"min_size": 3, "desired_capacity": 3, "max_size": 6},
            {
                key: asg[0].values.get(key)
                for key in ("min_size", "desired_capacity", "max_size")
            },
        )
        raw_asg = raw_changes(plan, "aws_autoscaling_group", "relay")[0]
        self.assertTrue(
            all(
                raw_asg["change"]["after_unknown"].get(key) is None
                for key in ("min_size", "desired_capacity", "max_size")
            )
        )

        launch_template = checker.resources_named(
            resources, "aws_launch_template", "relay"
        )
        self.assertEqual(1, len(launch_template))
        self.assertEqual(
            "false",
            launch_template[0].values["network_interfaces"][0][
                "associate_public_ip_address"
            ],
        )
        raw_launch_template = raw_changes(plan, "aws_launch_template", "relay")[0]
        self.assertIsNone(
            raw_launch_template["change"]["after_unknown"]["network_interfaces"][0].get(
                "associate_public_ip_address"
            )
        )

        secret = checker.resources_named(
            resources, "aws_secretsmanager_secret", "relay"
        )
        self.assertEqual(1, len(secret))
        self.assertEqual(("no-op",), secret[0].actions)
        raw_secret = raw_changes(plan, "aws_secretsmanager_secret", "relay")[0]
        self.assertEqual(
            "module.nhp.module.relay[0].aws_secretsmanager_secret.relay",
            raw_secret["previous_address"],
        )

        validation = checker.Validation()
        network_config = checker.config_module(
            validation, plan, "module.nhp.module.relay_network"
        )
        self.assertIsNotNone(network_config)
        self.assertIsNotNone(
            checker.config_module(validation, plan, "module.nhp.module.relay")
        )
        for tier in ("public", "relay", "endpoint"):
            association = checker.config_resource(
                validation,
                network_config,
                "aws_route_table_association",
                tier,
            )
            self.assertIn(
                f"aws_subnet.{tier}",
                checker.expression_refs(association, "subnet_id"),
            )
            self.assertTrue(
                any(
                    ref.startswith(f"aws_route_table.{tier}")
                    for ref in checker.expression_refs(association, "route_table_id")
                )
            )
        self.assertEqual([], validation.errors)

    def test_fixture_only_changes_trigger_workflow_validation(self) -> None:
        workflow = (
            REPO_ROOT / ".github" / "workflows" / "validate-workflows.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("paths: &validate_paths", workflow)
        self.assertIn("paths: *validate_paths", workflow)
        self.assertIn('- "tests/fixtures/relay-dmz-plan/**"', workflow)
        self.assertIn(
            '- "tests/fixtures/cell0-udp-source-fence/**"',
            workflow,
        )
        self.assertIn(
            "python3 -m py_compile .github/scripts/check-relay-dmz-plan.py",
            workflow,
        )

    def test_udp_source_fence_provider_fixture_digest_fails_closed(self) -> None:
        # Every captured colour stays individually digest-pinned.
        for color in sorted(checker.UDP_SOURCE_FENCE_PROVIDER_FIXTURES):
            pins = checker.UDP_SOURCE_FENCE_PROVIDER_FIXTURES[color]
            source = checker._UDP_SOURCE_FENCE_FIXTURE_DIR / pins["filename"]
            with (
                self.subTest(color=color),
                tempfile.TemporaryDirectory() as temp_dir,
            ):
                temp_root = Path(temp_dir)
                (temp_root / pins["filename"]).write_bytes(
                    source.read_bytes() + b"\n"
                )
                with mock.patch.object(
                    checker, "_UDP_SOURCE_FENCE_FIXTURE_DIR", temp_root
                ):
                    with self.assertRaisesRegex(
                        ValueError,
                        "UDP source-fence provider fixture digest changed",
                    ):
                        checker._load_udp_source_fence_provider_fixture(color)

    def test_udp_source_fence_every_captured_colour_loads_exactly(self) -> None:
        # Both captures must load, self-declare their colour, and agree on the
        # colour-independent public NLB envelope.
        for color in sorted(checker.UDP_SOURCE_FENCE_PROVIDER_FIXTURES):
            with self.subTest(color=color):
                fixture = checker._load_udp_source_fence_provider_fixture(color)
                self.assertEqual(fixture["active_color"], color)
        self.assertIsInstance(checker._udp_source_fence_nlb_change(), dict)

    def test_udp_source_fence_unknown_active_colour_fails_closed(self) -> None:
        with self.assertRaisesRegex(ValueError, "no capture for active color"):
            checker._load_udp_source_fence_provider_fixture("teal")

    def test_pr_plan_restores_complete_trusted_checker_family(self) -> None:
        workflow = (
            REPO_ROOT / ".github" / "workflows" / "terraform-plan-pr.yml"
        ).read_text(encoding="utf-8")
        self.assertIn(
            'git ls-tree -r --name-only "$BASE_SHA" -- .github/scripts', workflow
        )
        self.assertIn(".github/scripts/check-relay-dmz-plan*.py)", workflow)
        self.assertIn("if ((trusted_checker_count == 0)); then", workflow)

    def test_root_level_relay_modules_pass_without_leading_dot_prefixes(self) -> None:
        self.assertEqual([], checker.validate_plan(root_level_plan()))

    def test_counted_parent_prefix_maps_to_configuration_path(self) -> None:
        self.assertEqual([], checker.validate_plan(counted_parent_plan()))

    def test_unrelated_same_named_identity_secret_is_ignored(self) -> None:
        for layout, factory in (
            ("root", root_level_plan),
            ("nested", clean_plan),
            ("counted", counted_parent_plan),
        ):
            with self.subTest(layout=layout):
                plan = factory()
                plan["resource_changes"].append(
                    {
                        "address": "module.unrelated.aws_secretsmanager_secret.relay",
                        "mode": "managed",
                        "type": "aws_secretsmanager_secret",
                        "name": "relay",
                        "change": {
                            "actions": ["create"],
                            "before": None,
                            "after": {"arn": "not-the-reviewed-relay-secret"},
                            "after_unknown": {},
                        },
                    }
                )
                self.assertEqual([], checker.validate_plan(plan))

    def test_sandbox_vpc_cidr_is_not_partially_parameterizable(self) -> None:
        plan = clean_plan()
        vpc = resource(plan, ".module.relay_network[0].aws_vpc.relay")
        vpc["change"]["after"]["cidr_block"] = "10.102.0.0/16"
        self.assert_violation(plan, "sandbox relay VPC must use 10.101.0.0/16")

    def test_broad_relay_module_dependencies_are_rejected(self) -> None:
        for module_name in ("relay_network", "relay"):
            with self.subTest(module=module_name):
                plan = clean_plan()
                module_call = plan["configuration"]["root_module"]["module_calls"][
                    "nhp"
                ]["module"]["module_calls"][module_name]
                module_call["depends_on"] = ["module.unreviewed"]
                self.assert_violation(plan, "must not use broad depends_on edges")

    def test_relay_network_apply_role_readiness_chain_is_exact(self) -> None:
        plan = clean_plan()
        network_call = plan["configuration"]["root_module"]["module_calls"]["nhp"][
            "module"
        ]["module_calls"]["relay_network"]
        network_call["expressions"]["apply_role_ready_token"]["references"] = [
            "time_sleep.unreviewed.id"
        ]
        self.assert_violation(plan, "must consume only the IAM propagation token")

        plan = clean_plan()
        gate = configured_resource(
            plan, "relay_network", "terraform_data", "apply_role_ready"
        )
        gate["expressions"]["input"]["references"] = ["var.unreviewed"]
        self.assert_violation(
            plan, "must be driven directly by its root readiness input"
        )

        plan = clean_plan()
        parent = plan["configuration"]["root_module"]["module_calls"]["nhp"]["module"]
        iam_wait = next(
            item
            for item in parent["resources"]
            if item["type"] == "time_sleep"
            and item["name"] == "relay_dmz_iam_propagation"
        )
        iam_wait["depends_on"] = []
        self.assert_violation(
            plan, "must preserve the root CIDR-overlap precondition dependency"
        )

    def test_every_independent_network_dag_root_waits_on_apply_role(self) -> None:
        roots = (
            ("aws_vpc", "relay"),
            ("aws_kms_key", "logs"),
            ("aws_iam_role", "flow"),
            ("aws_route53_resolver_firewall_domain_list", "allow"),
            ("aws_route53_resolver_firewall_domain_list", "all"),
            ("aws_route53_resolver_firewall_rule_group", "relay"),
        )
        for resource_type, name in roots:
            with self.subTest(resource=f"{resource_type}.{name}"):
                plan = clean_plan()
                root = configured_resource(plan, "relay_network", resource_type, name)
                root["depends_on"] = []
                self.assert_violation(
                    plan, f"DAG root {resource_type}.{name} must wait only"
                )

    def test_complete_network_to_fleet_readiness_chain_is_exact(self) -> None:
        plan = clean_plan()
        parent = plan["configuration"]["root_module"]["module_calls"]["nhp"]["module"]
        root_gate = next(
            item
            for item in parent["resources"]
            if item["type"] == "terraform_data"
            and item["name"] == "relay_network_ready"
        )
        root_gate["depends_on"] = []
        self.assert_violation(plan, "must wait for the complete count-gated DMZ")

        plan = clean_plan()
        relay_call = plan["configuration"]["root_module"]["module_calls"]["nhp"][
            "module"
        ]["module_calls"]["relay"]
        relay_call["expressions"]["network_ready_token"]["references"] = [
            "module.relay_network[0].vpc_id"
        ]
        self.assert_violation(
            plan, "must consume only the complete relay-network readiness token"
        )

        plan = clean_plan()
        child_gate = configured_resource(
            plan, "relay", "terraform_data", "network_ready"
        )
        child_gate["expressions"]["input"]["references"] = ["var.unreviewed"]
        self.assert_violation(plan, "must be driven directly by the root network token")

        plan = clean_plan()
        security_gate = configured_resource(
            plan, "relay", "terraform_data", "fleet_security_ready"
        )
        security_gate["expressions"]["input"]["references"] = [
            "aws_security_group.unreviewed.id"
        ]
        self.assert_violation(plan, "must wait for every mandatory standalone SG path")

        required_security_paths = list(security_gate["depends_on"])
        for dependency in required_security_paths:
            with self.subTest(security_path=dependency):
                plan = clean_plan()
                security_gate = configured_resource(
                    plan, "relay", "terraform_data", "fleet_security_ready"
                )
                security_gate["depends_on"].remove(dependency)
                self.assert_violation(
                    plan, "must wait for every mandatory standalone SG path"
                )

        plan = clean_plan()
        lb = configured_resource(plan, "relay", "aws_lb", "relay")
        lb["depends_on"] = [
            dependency
            for dependency in lb["depends_on"]
            if dependency != "terraform_data.network_ready"
        ]
        self.assert_violation(plan, "ALB must wait for complete DMZ network")

        for dependency in (
            "terraform_data.network_ready",
            "terraform_data.fleet_security_ready",
        ):
            with self.subTest(asg_readiness_dependency=dependency):
                plan = clean_plan()
                asg = configured_resource(
                    plan, "relay", "aws_autoscaling_group", "relay"
                )
                asg["depends_on"].remove(dependency)
                self.assert_violation(
                    plan, "must wait for network readiness and the complete fleet"
                )

    def test_dmz_route_tables_cannot_gain_inline_routes(self) -> None:
        for tier in ("public", "relay", "endpoint"):
            with self.subTest(tier=tier):
                plan = clean_plan()
                network = plan["configuration"]["root_module"]["module_calls"]["nhp"][
                    "module"
                ]["module_calls"]["relay_network"]["module"]
                table = next(
                    item
                    for item in network["resources"]
                    if item["type"] == "aws_route_table" and item["name"] == tier
                )
                table["expressions"]["route"] = {
                    "constant_value": [
                        {
                            "cidr_block": "0.0.0.0/0",
                            "gateway_id": "igw-unreviewed",
                        }
                    ]
                }
                self.assert_violation(
                    plan, f"{tier} DMZ route tables must use only reviewed"
                )

    def test_dmz_security_groups_cannot_gain_inline_rules(self) -> None:
        cases = (
            ("relay_network", "endpoints", "ingress", "endpoint SG"),
            ("relay", "alb", "egress", "relay ALB SG"),
            ("relay", "relay", "egress", "relay node SG"),
        )
        for module_name, security_group, direction, needle in cases:
            with self.subTest(security_group=security_group, direction=direction):
                plan = clean_plan()
                module = plan["configuration"]["root_module"]["module_calls"]["nhp"][
                    "module"
                ]["module_calls"][module_name]["module"]
                group = next(
                    item
                    for item in module["resources"]
                    if item["type"] == "aws_security_group"
                    and item["name"] == security_group
                )
                group["expressions"][direction] = {
                    "constant_value": [
                        {
                            "protocol": "-1",
                            "cidr_blocks": ["0.0.0.0/0"],
                        }
                    ]
                }
                self.assert_violation(plan, needle)

    def test_endpoint_sg_accepts_only_exact_standalone_rule_projection(self) -> None:
        plan = clean_plan()
        endpoint_sg = resource(plan, ".aws_security_group.endpoints")
        endpoint_rule = resource(
            plan, ".aws_vpc_security_group_ingress_rule.vpc_endpoints_from_relay"
        )
        endpoint_rule["change"]["after"]["referenced_security_group_id"] = (
            "sg-relay"
        )
        endpoint_sg["change"]["after"]["ingress"] = [
            {
                "description": "HTTPS from relay nodes only",
                "from_port": 443,
                "to_port": 443,
                "protocol": "tcp",
                "security_groups": ["sg-relay"],
                "cidr_blocks": [],
                "ipv6_cidr_blocks": [],
                "prefix_list_ids": [],
                "self": False,
            }
        ]
        self.assertEqual([], checker.validate_plan(plan))

        endpoint_sg["change"]["after"]["ingress"][0]["cidr_blocks"] = [
            "0.0.0.0/0"
        ]
        self.assert_violation(plan, "exactly the standalone relay HTTPS projection")

    def test_root_level_main_egress_replacement_is_rejected(self) -> None:
        plan = clean_plan()
        nested_root = plan["configuration"]["root_module"]
        plan["configuration"]["root_module"] = copy.deepcopy(
            nested_root["module_calls"]["nhp"]["module"]
        )
        for item in plan["resource_changes"]:
            if item["address"].startswith("module.nhp."):
                item["address"] = item["address"].removeprefix("module.nhp.")
        private_subnet = next(
            item
            for item in plan["resource_changes"]
            if item["address"] == "module.networking.aws_subnet.private[0]"
        )
        private_subnet["change"]["actions"] = ["delete", "create"]
        self.assert_violation(plan, "live main-private egress resource")

    def test_unindexed_main_egress_replacement_is_rejected(self) -> None:
        plan = clean_plan()
        private_subnet = resource(plan, ".module.networking.aws_subnet.private[0]")
        private_subnet["address"] = private_subnet["address"].removesuffix("[0]")
        private_subnet["change"]["actions"] = ["delete", "create"]
        self.assert_violation(plan, "live main-private egress resource")

    def test_relay_return_route_cannot_bypass_active_networking_output(self) -> None:
        plan = clean_plan()
        relay_network = plan["configuration"]["root_module"]["module_calls"]["nhp"][
            "module"
        ]["module_calls"]["relay_network"]
        relay_network["expressions"]["main_private_route_table_ids"] = {
            "references": ["module.networking.aws_route_table.private"]
        }
        self.assert_violation(plan, "active private-route-table output")

    def test_extensible_route_tables_must_be_gated_by_relay(self) -> None:
        plan = clean_plan()
        networking = plan["configuration"]["root_module"]["module_calls"]["nhp"][
            "module"
        ]["module_calls"]["networking"]
        networking["expressions"]["enable_extensible_private_route_tables"] = {
            "constant_value": True
        }
        self.assert_violation(plan, "must be gated by deploy_relay")

    def test_relay_return_route_must_use_reviewed_module_input(self) -> None:
        plan = clean_plan()
        resources = plan["configuration"]["root_module"]["module_calls"]["nhp"][
            "module"
        ]["module_calls"]["relay_network"]["module"]["resources"]
        return_route = next(
            item
            for item in resources
            if item["type"] == "aws_route" and item["name"] == "main_private_to_relay"
        )
        return_route["expressions"]["route_table_id"] = {
            "references": ["aws_route_table.private"]
        }
        self.assert_violation(plan, "reviewed active route-table input")

    def test_extensible_table_cannot_gain_inline_routes(self) -> None:
        plan = clean_plan()
        resources = plan["configuration"]["root_module"]["module_calls"]["nhp"][
            "module"
        ]["module_calls"]["networking"]["module"]["resources"]
        table = next(
            item
            for item in resources
            if item["type"] == "aws_route_table"
            and item["name"] == "private_extensible"
        )
        table["expressions"]["route"] = {"references": ["aws_nat_gateway.main"]}
        self.assert_violation(plan, "must not declare inline routes")

    def test_missing_dmz_route_table_config_is_rejected(self) -> None:
        plan = clean_plan()
        resources = plan["configuration"]["root_module"]["module_calls"]["nhp"][
            "module"
        ]["module_calls"]["relay_network"]["module"]["resources"]
        resources[:] = [
            item
            for item in resources
            if not (item["type"] == "aws_route_table" and item["name"] == "relay")
        ]
        self.assert_violation(
            plan, "relay DMZ route tables must use only reviewed standalone"
        )

    def test_missing_relay_security_group_config_is_rejected(self) -> None:
        plan = clean_plan()
        resources = plan["configuration"]["root_module"]["module_calls"]["nhp"][
            "module"
        ]["module_calls"]["relay"]["module"]["resources"]
        resources[:] = [
            item
            for item in resources
            if not (item["type"] == "aws_security_group" and item["name"] == "relay")
        ]
        self.assert_violation(plan, "relay node SG must not declare inline")

    def test_standalone_route_cannot_target_legacy_private_table(self) -> None:
        plan = clean_plan()
        resources = plan["configuration"]["root_module"]["module_calls"]["nhp"][
            "module"
        ]["module_calls"]["networking"]["module"]["resources"]
        route = next(
            item
            for item in resources
            if item["type"] == "aws_route"
            and item["name"] == "private_extensible_default"
        )
        route["expressions"]["route_table_id"] = {
            "references": ["aws_route_table.private[0]"]
        }
        self.assert_violation(plan, "must not have standalone route owners")

    def test_private_association_requires_nat_route_dependency(self) -> None:
        plan = clean_plan()
        resources = plan["configuration"]["root_module"]["module_calls"]["nhp"][
            "module"
        ]["module_calls"]["networking"]["module"]["resources"]
        association = next(
            item
            for item in resources
            if item["type"] == "aws_route_table_association"
            and item["name"] == "private"
        )
        association["depends_on"] = []
        self.assert_violation(plan, "both active-table NAT defaults")

    def test_private_association_requires_iam_propagation_token(self) -> None:
        plan = clean_plan()
        networking = plan["configuration"]["root_module"]["module_calls"]["nhp"][
            "module"
        ]["module_calls"]["networking"]
        networking["expressions"]["extensible_private_route_table_ready_token"] = {
            "constant_value": "not-waited"
        }
        self.assert_violation(plan, "IAM propagation token")

    def test_private_route_table_output_cannot_expose_legacy_tables(self) -> None:
        plan = clean_plan()
        networking = plan["configuration"]["root_module"]["module_calls"]["nhp"][
            "module"
        ]["module_calls"]["networking"]["module"]
        networking["outputs"]["private_route_table_ids"]["expression"] = {
            "references": ["aws_route_table.private"]
        }
        self.assert_violation(plan, "must expose only the active table set")

    def test_gateway_endpoints_must_retain_rollback_tables(self) -> None:
        plan = clean_plan()
        resources = plan["configuration"]["root_module"]["module_calls"]["nhp"][
            "module"
        ]["module_calls"]["networking"]["module"]["resources"]
        s3 = next(
            item
            for item in resources
            if item["type"] == "aws_vpc_endpoint" and item["name"] == "s3"
        )
        s3["expressions"]["route_table_ids"] = {
            "references": ["aws_route_table.private_extensible"]
        }
        self.assert_violation(plan, "retain both legacy and extensible")

    def test_live_legacy_route_table_cannot_be_replaced(self) -> None:
        plan = clean_plan()
        table = resource(plan, ".module.networking.aws_route_table.private[0]")
        table["change"]["actions"] = ["delete", "create"]
        self.assert_violation(plan, "live main-private egress resource")

    def test_nat_gateway_is_rejected(self) -> None:
        plan = clean_plan()
        plan["resource_changes"].append(
            {
                "address": "module.nhp.module.relay_network[0].aws_nat_gateway.bad",
                "mode": "managed",
                "type": "aws_nat_gateway",
                "name": "bad",
                "change": {
                    "actions": ["create"],
                    "before": None,
                    "after": {},
                    "after_unknown": {},
                },
            }
        )
        self.assert_violation(plan, "must not contain NAT")

    def test_nat_or_egress_gateway_is_rejected_in_every_relay_owned_scope(
        self,
    ) -> None:
        for address, resource_type in (
            (
                "module.nhp.module.relay[0].aws_nat_gateway.bad",
                "aws_nat_gateway",
            ),
            (
                "module.nhp.module.relay_identity[0].aws_egress_only_internet_gateway.bad",
                "aws_egress_only_internet_gateway",
            ),
            ("module.nhp.aws_nat_gateway.relay_bad", "aws_nat_gateway"),
        ):
            with self.subTest(address=address):
                plan = clean_plan()
                plan["resource_changes"].append(
                    {
                        "address": address,
                        "mode": "managed",
                        "type": resource_type,
                        "name": "bad",
                        "change": {
                            "actions": ["create"],
                            "before": None,
                            "after": {},
                            "after_unknown": {},
                        },
                    }
                )
                self.assert_violation(plan, "must not contain NAT or egress-only")

    def test_main_network_nat_gateway_is_outside_the_relay_boundary(self) -> None:
        plan = clean_plan()
        plan["resource_changes"].append(
            {
                "address": "module.nhp.module.networking.aws_nat_gateway.main[0]",
                "mode": "managed",
                "type": "aws_nat_gateway",
                "name": "main",
                "change": {
                    "actions": ["no-op"],
                    "before": {"id": "nat-main"},
                    "after": {"id": "nat-main"},
                    "after_unknown": {},
                },
            }
        )
        self.assertEqual([], checker.validate_plan(plan))

    def test_private_default_route_is_rejected(self) -> None:
        plan = clean_plan()
        changed = copy.deepcopy(resource(plan, ".aws_route.relay_to_main_private[0]"))
        changed["address"] = "module.nhp.module.relay_network[0].aws_route.bad_default"
        changed["name"] = "bad_default"
        changed["change"]["after"]["destination_cidr_block"] = "0.0.0.0/0"
        plan["resource_changes"].append(changed)
        self.assert_violation(plan, "only DMZ route table with a default route")

    def test_ipv6_default_route_is_rejected(self) -> None:
        plan = clean_plan()
        changed = copy.deepcopy(resource(plan, ".aws_route.public_default"))
        changed["address"] = (
            "module.nhp.module.relay_network[0].aws_route.bad_ipv6_default"
        )
        changed["name"] = "bad_ipv6_default"
        changed["change"]["after"].pop("destination_cidr_block")
        changed["change"]["after"]["destination_ipv6_cidr_block"] = "::/0"
        plan["resource_changes"].append(changed)
        self.assert_violation(plan, "only DMZ route table with a default route")

    def test_ipv6_main_private_return_default_is_rejected(self) -> None:
        plan = clean_plan()
        changed = copy.deepcopy(resource(plan, ".aws_route.main_private_to_relay[0]"))
        changed["address"] = (
            "module.nhp.module.relay_network[0].aws_route.main_private_to_relay[3]"
        )
        changed["change"]["after"].pop("destination_cidr_block")
        changed["change"]["after"]["destination_ipv6_cidr_block"] = "::/0"
        plan["resource_changes"].append(changed)
        self.assert_violation(plan, "only DMZ route table with a default route")

    def test_destination_prefix_list_route_is_rejected(self) -> None:
        plan = clean_plan()
        changed = copy.deepcopy(resource(plan, ".aws_route.public_default"))
        changed["address"] = (
            "module.nhp.module.relay_network[0].aws_route.bad_prefix_list"
        )
        changed["name"] = "bad_prefix_list"
        changed["change"]["after"].pop("destination_cidr_block")
        changed["change"]["after"]["destination_prefix_list_id"] = "pl-unreviewed"
        plan["resource_changes"].append(changed)
        self.assert_violation(plan, "must not use destination prefix lists")

    def test_unreviewed_route_targets_are_rejected_by_exact_inventory(self) -> None:
        for target_field in (
            "gateway_id",
            "network_interface_id",
            "vpc_endpoint_id",
        ):
            with self.subTest(target_field=target_field):
                plan = clean_plan()
                changed = copy.deepcopy(resource(plan, ".aws_route.public_default"))
                changed["address"] = (
                    f"module.nhp.module.relay_network[0].aws_route.foo_{target_field}"
                )
                changed["name"] = f"foo_{target_field}"
                changed["change"]["after"] = {
                    "destination_cidr_block": "1.2.3.4/32",
                    target_field: "unreviewed-target",
                }
                plan["resource_changes"].append(changed)
                self.assert_violation(plan, "explicit DMZ route inventory changed")

    def test_explicit_dmz_route_inventory_cardinalities_are_exact(self) -> None:
        cases = (
            ("missing relay route", "relay_to_main_private", "remove"),
            ("extra main return", "main_private_to_relay", "duplicate"),
            ("extra public default", "public_default", "duplicate"),
        )
        for case, route_name, mutation in cases:
            with self.subTest(case=case):
                plan = clean_plan()
                route = next(
                    item
                    for item in plan["resource_changes"]
                    if item["type"] == "aws_route" and item["name"] == route_name
                )
                if mutation == "remove":
                    plan["resource_changes"].remove(route)
                else:
                    duplicate = copy.deepcopy(route)
                    duplicate["address"] = f"{duplicate['address']}[review-duplicate]"
                    plan["resource_changes"].append(duplicate)
                self.assert_violation(plan, "explicit DMZ route inventory changed")

    def test_relay_routes_must_match_planned_main_private_subnets(self) -> None:
        plan = clean_plan()
        for item in plan["resource_changes"]:
            if (
                item["name"] == "relay_to_main_private"
                and item["change"]["after"]["destination_cidr_block"]
                == "10.100.12.0/24"
            ):
                item["change"]["after"]["destination_cidr_block"] = "10.100.99.0/24"
        self.assert_violation(plan, "exact planned main-private subnet")

    def test_each_subnet_tier_must_use_its_matching_route_table(self) -> None:
        cases = (
            ("public", "subnet_id", ["aws_subnet.relay", "count.index"]),
            (
                "relay",
                "route_table_id",
                ["aws_route_table.public.id", "aws_route_table.public"],
            ),
            (
                "endpoint",
                "route_table_id",
                ["aws_route_table.relay", "count.index"],
            ),
        )
        for tier, attribute, wrong_references in cases:
            with self.subTest(tier=tier, attribute=attribute):
                plan = clean_plan()
                association = configured_resource(
                    plan,
                    "relay_network",
                    "aws_route_table_association",
                    tier,
                )
                association["expressions"][attribute]["references"] = wrong_references
                self.assert_violation(
                    plan,
                    f"{tier} subnets must attach only to matching {tier} route tables",
                )

    def test_duplicate_main_private_return_route_is_rejected(self) -> None:
        plan = clean_plan()
        duplicate = copy.deepcopy(resource(plan, ".aws_route.main_private_to_relay[0]"))
        duplicate["address"] = (
            "module.nhp.module.relay_network[0].aws_route.main_private_to_relay[3]"
        )
        plan["resource_changes"].append(duplicate)
        self.assert_violation(plan, "each of the three relay /24s exactly once")

    def test_missing_interface_endpoint_is_rejected(self) -> None:
        plan = clean_plan()
        plan["resource_changes"] = [
            item
            for item in plan["resource_changes"]
            if not item["address"].endswith('interface["logs"]')
        ]
        self.assert_violation(plan, "interface endpoint set changed")

    def test_duplicate_interface_endpoint_address_key_is_rejected(self) -> None:
        plan = clean_plan()
        duplicate = copy.deepcopy(resource(plan, '.aws_vpc_endpoint.interface["logs"]'))
        plan["resource_changes"].append(duplicate)
        self.assert_violation(plan, "interface endpoint address keys must be unique")

    def test_address_key_decodes_json_escaped_string_index(self) -> None:
        key = 'quoted"key\\suffix\u2603'
        address = f"aws_vpc_endpoint.interface[{json.dumps(key)}]"
        self.assertEqual(key, checker.address_key(address))
        self.assertIsNone(checker.address_key("aws_subnet.relay[0]"))
        self.assertIsNone(checker.address_key('aws_vpc_endpoint.interface["bad\\q"]'))

    def test_guardduty_wildcard_requires_cross_account_deny(self) -> None:
        plan = clean_plan()
        endpoint = resource(plan, '.aws_vpc_endpoint.interface["guardduty-data"]')
        policy = json.loads(endpoint["change"]["after"]["policy"])
        policy["Statement"] = policy["Statement"][:1]
        endpoint["change"]["after"]["policy"] = json.dumps(policy)
        self.assert_violation(plan, "cross-account deny")

    def test_endpoint_cross_account_deny_pins_sandbox_account(self) -> None:
        plan = clean_plan()
        endpoint = resource(plan, '.aws_vpc_endpoint.interface["logs"]')
        policy = json.loads(endpoint["change"]["after"]["policy"])
        policy["Statement"][1]["Condition"]["StringNotEquals"][
            "aws:PrincipalAccount"
        ] = "000000000000"
        endpoint["change"]["after"]["policy"] = json.dumps(policy)
        self.assert_violation(plan, "cross-account deny")

    def test_endpoint_cross_account_deny_accepts_singleton_action_list(self) -> None:
        plan = clean_plan()
        endpoint = resource(plan, '.aws_vpc_endpoint.interface["logs"]')
        policy = json.loads(endpoint["change"]["after"]["policy"])
        policy["Statement"][1]["Action"] = ["*"]
        endpoint["change"]["after"]["policy"] = json.dumps(policy)
        self.assertEqual([], checker.validate_plan(plan))

    def test_endpoint_cross_account_deny_rejects_extra_action(self) -> None:
        plan = clean_plan()
        endpoint = resource(plan, '.aws_vpc_endpoint.interface["logs"]')
        policy = json.loads(endpoint["change"]["after"]["policy"])
        policy["Statement"][1]["Action"] = ["*", "ec2:DescribeInstances"]
        endpoint["change"]["after"]["policy"] = json.dumps(policy)
        self.assert_violation(plan, "cross-account deny")

    def test_non_guardduty_endpoint_allow_resources_are_pinned(self) -> None:
        resource_statement_sids = {
            "ecr-api": "RelayRepositoryRead",
            "ecr-dkr": "RelayRepositoryRegistryRead",
            "logs": "RelayLogWrite",
            "monitoring": "RelayMetrics",
            "secretsmanager": "RelayIdentityRead",
            "ssm": "RelayImageTagRead",
            "ssmmessages": "RelaySessionChannels",
        }
        for key, sid in resource_statement_sids.items():
            with self.subTest(endpoint=key):
                plan = clean_plan()
                endpoint = resource(plan, f'.aws_vpc_endpoint.interface["{key}"]')
                policy = json.loads(endpoint["change"]["after"]["policy"])
                statement = statement_by_sid(policy, sid)
                statement["Resource"] = (
                    "arn:aws:s3:::unreviewed" if statement["Resource"] == "*" else "*"
                )
                endpoint["change"]["after"]["policy"] = json.dumps(policy)
                self.assert_violation(plan, "allow contract changed")

    def test_non_guardduty_endpoint_allow_principals_are_pinned(self) -> None:
        for key in sorted(
            set(checker.EXPECTED_INTERFACE_ENDPOINTS) - {"guardduty-data"}
        ):
            with self.subTest(endpoint=key):
                plan = clean_plan()
                endpoint = resource(plan, f'.aws_vpc_endpoint.interface["{key}"]')
                policy = json.loads(endpoint["change"]["after"]["policy"])
                statement = next(
                    item
                    for item in policy["Statement"]
                    if item.get("Effect") == "Allow"
                )
                statement["Principal"] = {"AWS": "arn:aws:iam::000000000000:root"}
                endpoint["change"]["after"]["policy"] = json.dumps(policy)
                self.assert_violation(plan, "allow contract changed")

    def test_monitoring_endpoint_namespace_condition_is_pinned(self) -> None:
        plan = clean_plan()
        endpoint = resource(plan, '.aws_vpc_endpoint.interface["monitoring"]')
        policy = json.loads(endpoint["change"]["after"]["policy"])
        policy["Statement"][0]["Condition"]["StringEquals"]["cloudwatch:namespace"] = (
            "Unreviewed"
        )
        endpoint["change"]["after"]["policy"] = json.dumps(policy)
        self.assert_violation(plan, "allow contract changed")

    def test_greenfield_unknown_relay_secret_requires_pr0_apply(self) -> None:
        plan = clean_plan()
        secret = resource(plan, ".aws_secretsmanager_secret.relay")
        secret["change"]["after"]["arn"] = None
        secret["change"]["after_unknown"]["arn"] = True
        errors = checker.validate_plan(plan)
        for expected in (
            "concrete sandbox relay secret created by applied PR0",
            "secretsmanager endpoint RelayIdentityRead allow contract changed",
            "relay IAM Secrets Manager identity read resource allowlist changed",
        ):
            self.assertTrue(
                any(expected in error for error in errors),
                f"missing deliberate primary/secondary fail-closed error {expected!r}: {errors}",
            )

    def test_final_preapply_requires_every_critical_policy_known(self) -> None:
        cases = (
            (
                "interface endpoint",
                '.aws_vpc_endpoint.interface["logs"]',
                "policy",
                "logs interface endpoint policy",
            ),
            (
                "logs KMS",
                ".aws_kms_key.logs",
                "policy",
                "relay telemetry KMS key policy",
            ),
            (
                "Flow Logs role",
                ".aws_iam_role_policy.flow",
                "policy",
                "Flow Logs role policy",
            ),
            (
                "Flow Logs trust",
                ".aws_iam_role.flow",
                "assume_role_policy",
                "Flow Logs role trust policy",
            ),
            (
                "S3 endpoint",
                ".aws_vpc_endpoint.s3",
                "policy",
                "S3 gateway endpoint policy",
            ),
            (
                "relay IAM",
                ".aws_iam_role_policy.relay",
                "policy",
                "relay IAM policy",
            ),
        )
        self.assertEqual(
            [], checker.validate_plan(clean_plan(), require_pr0_applied=True)
        )
        for label, suffix, attribute, needle in cases:
            with self.subTest(policy=label):
                plan = clean_plan()
                policy_resource = resource(plan, suffix)
                policy_resource["change"]["after"][attribute] = None
                policy_resource["change"]["after_unknown"][attribute] = True
                self.assertEqual([], checker.validate_plan(plan))
                errors = checker.validate_plan(plan, require_pr0_applied=True)
                self.assertTrue(
                    any(
                        needle in error
                        and "fully known in the final pre-apply plan" in error
                        for error in errors
                    ),
                    errors,
                )

    def test_unresolved_endpoint_policy_requires_reviewed_config_reference(
        self,
    ) -> None:
        plan = clean_plan()
        endpoint = resource(plan, '.aws_vpc_endpoint.interface["logs"]')
        endpoint["change"]["after"]["policy"] = None
        endpoint["change"]["after_unknown"]["policy"] = True
        endpoint_config = configured_resource(
            plan, "relay_network", "aws_vpc_endpoint", "interface"
        )
        endpoint_config["expressions"]["policy"]["references"].remove(
            "local.endpoint_policies"
        )
        self.assert_violation(
            plan, "interface endpoints must use the reviewed endpoint_policies map"
        )

    def test_unresolved_endpoint_policy_rejects_extra_config_reference(self) -> None:
        plan = clean_plan()
        endpoint = resource(plan, '.aws_vpc_endpoint.interface["logs"]')
        endpoint["change"]["after"]["policy"] = None
        endpoint["change"]["after_unknown"]["policy"] = True
        endpoint_config = configured_resource(
            plan, "relay_network", "aws_vpc_endpoint", "interface"
        )
        endpoint_config["expressions"]["policy"]["references"].append(
            "var.unreviewed_policy"
        )
        self.assert_violation(
            plan, "interface endpoints must use the reviewed endpoint_policies map"
        )

    def test_unresolved_logs_kms_policy_requires_reviewed_config_references(
        self,
    ) -> None:
        plan = clean_plan()
        key = resource(plan, ".aws_kms_key.logs")
        key["change"]["after"]["policy"] = None
        key["change"]["after_unknown"]["policy"] = True
        key_config = configured_resource(plan, "relay_network", "aws_kms_key", "logs")
        key_config["expressions"]["policy"]["references"].remove(
            "local.resolver_log_group_arn"
        )
        self.assert_violation(
            plan,
            "unresolved relay logs KMS policy references changed",
        )

    def test_unresolved_logs_kms_policy_rejects_extra_config_reference(self) -> None:
        plan = clean_plan()
        key = resource(plan, ".aws_kms_key.logs")
        key["change"]["after"]["policy"] = None
        key["change"]["after_unknown"]["policy"] = True
        key_config = configured_resource(plan, "relay_network", "aws_kms_key", "logs")
        key_config["expressions"]["policy"]["references"].append(
            "var.unreviewed_log_context"
        )
        self.assert_violation(
            plan, "unresolved relay logs KMS policy references changed"
        )

    def test_wildcard_action_is_rejected_outside_guardduty(self) -> None:
        plan = clean_plan()
        endpoint = resource(plan, '.aws_vpc_endpoint.interface["logs"]')
        policy = json.loads(endpoint["change"]["after"]["policy"])
        policy["Statement"][0]["Action"] = "*"
        endpoint["change"]["after"]["policy"] = json.dumps(policy)
        self.assert_violation(plan, "logs endpoint allow actions changed")

    def test_endpoint_policy_rejects_extra_deny(self) -> None:
        plan = clean_plan()
        endpoint = resource(plan, '.aws_vpc_endpoint.interface["logs"]')
        policy = json.loads(endpoint["change"]["after"]["policy"])
        policy["Statement"].append(
            {
                "Sid": "ExtraDeny",
                "Effect": "Deny",
                "Principal": "*",
                "Action": "logs:DeleteLogGroup",
                "Resource": "*",
            }
        )
        endpoint["change"]["after"]["policy"] = json.dumps(policy)
        self.assert_violation(
            plan, "must not replace or dilute the reviewed deny shape"
        )

    def test_endpoint_policy_rejects_allow_not_action(self) -> None:
        plan = clean_plan()
        endpoint = resource(plan, '.aws_vpc_endpoint.interface["guardduty-data"]')
        policy = json.loads(endpoint["change"]["after"]["policy"])
        policy["Statement"][0]["NotAction"] = "guardduty:DeleteDetector"
        endpoint["change"]["after"]["policy"] = json.dumps(policy)
        self.assert_violation(plan, "allow statements must not use NotAction")

    def test_endpoint_inventory_and_reviewed_allow_contract_keys_stay_lockstep(
        self,
    ) -> None:
        contracts = checker.endpoint_allow_contracts(FIXTURE_RELAY_SECRET_ARN)
        contracts.pop("logs")
        with mock.patch.object(
            checker, "endpoint_allow_contracts", return_value=contracts
        ):
            errors = checker.validate_plan(clean_plan())
        self.assertTrue(
            any("allow-contract keys must match" in error for error in errors), errors
        )
        self.assertTrue(
            any(
                "logs endpoint has no reviewed allow contract" in error
                for error in errors
            ),
            errors,
        )

    def test_endpoint_policy_helper_rejects_unreviewed_key_legibly(self) -> None:
        validation = checker.Validation()
        checker.check_endpoint_policy(
            validation,
            "unreviewed",
            endpoint_policy("logs"),
            checker.endpoint_allow_contracts(FIXTURE_RELAY_SECRET_ARN),
        )
        self.assertEqual(
            ["unreviewed endpoint has no reviewed action contract"],
            validation.errors,
        )

    def test_endpoint_subnet_reference_drift_is_rejected(self) -> None:
        plan = clean_plan()
        interface = configured_resource(
            plan, "relay_network", "aws_vpc_endpoint", "interface"
        )
        interface["expressions"]["subnet_ids"] = {"references": ["aws_subnet.relay"]}
        self.assert_violation(plan, "only endpoint subnets")

    def test_endpoint_extra_subnet_reference_is_rejected(self) -> None:
        plan = clean_plan()
        interface = configured_resource(
            plan, "relay_network", "aws_vpc_endpoint", "interface"
        )
        interface["expressions"]["subnet_ids"]["references"].append("aws_subnet.relay")
        self.assert_violation(plan, "only endpoint subnets")

    def test_interface_endpoint_extra_security_group_is_rejected(self) -> None:
        plan = clean_plan()
        interface = configured_resource(
            plan, "relay_network", "aws_vpc_endpoint", "interface"
        )
        interface["expressions"]["security_group_ids"]["references"].append(
            "aws_security_group.internet.id"
        )
        self.assert_violation(plan, "only the dedicated endpoint SG")

    def test_ambiguous_configuration_module_suffix_is_rejected(self) -> None:
        plan = clean_plan()
        root = plan["configuration"]["root_module"]
        network_call = root["module_calls"]["nhp"]["module"]["module_calls"][
            "relay_network"
        ]
        root["module_calls"]["duplicate_parent"] = {
            "module": {
                "module_calls": {
                    "nhp": {
                        "module": {
                            "module_calls": {
                                "relay_network": copy.deepcopy(network_call)
                            },
                            "resources": [],
                        }
                    }
                },
                "resources": [],
            }
        }
        self.assert_violation(
            plan,
            "configuration module suffix 'module.nhp.module.relay_network' is ambiguous",
        )

    def test_ambiguous_configuration_resource_is_rejected(self) -> None:
        plan = clean_plan()
        network_resources = plan["configuration"]["root_module"]["module_calls"]["nhp"][
            "module"
        ]["module_calls"]["relay_network"]["module"]["resources"]
        public_default = next(
            item
            for item in network_resources
            if item["type"] == "aws_route" and item["name"] == "public_default"
        )
        network_resources.append(copy.deepcopy(public_default))
        self.assert_violation(
            plan, "configuration resource aws_route.public_default is ambiguous"
        )

    def test_dns_fail_open_is_rejected(self) -> None:
        plan = clean_plan()
        resource(plan, ".aws_route53_resolver_firewall_config.relay")["change"][
            "after"
        ]["firewall_fail_open"] = "ENABLED"
        self.assert_violation(plan, "must fail closed")

    def test_duplicate_advanced_dns_rule_address_key_is_rejected(self) -> None:
        plan = clean_plan()
        duplicate = copy.deepcopy(
            resource(
                plan,
                '.aws_route53_resolver_firewall_rule.advanced["DNS_TUNNELING"]',
            )
        )
        plan["resource_changes"].append(duplicate)
        self.assert_violation(
            plan, "advanced DNS threat rule address keys must be unique"
        )

    def test_advanced_dns_confidence_threshold_is_case_sensitive(self) -> None:
        plan = clean_plan()
        dga = resource(plan, '.aws_route53_resolver_firewall_rule.advanced["DGA"]')
        dga["change"]["after"]["confidence_threshold"] = "high"
        self.assert_violation(plan, "advanced DNS rule DGA changed")

    def test_dns_probe_must_be_excluded_from_paging_metric(self) -> None:
        plan = clean_plan()
        metric = resource(plan, ".aws_cloudwatch_log_metric_filter.dns_blocked")
        metric["change"]["after"]["pattern"] = '{ $.firewall_rule_action = "BLOCK" }'
        self.assert_violation(plan, "non-probe DNS Firewall block")

    def test_dns_alarm_must_have_actions(self) -> None:
        plan = clean_plan()
        alarm = resource(plan, ".aws_cloudwatch_metric_alarm.relay_dmz_dns_blocked[0]")
        alarm["change"]["after"]["alarm_actions"] = []
        self.assert_violation(plan, "first non-probe block")

    def test_flow_log_forensic_field_order_is_exact(self) -> None:
        for mutation in (
            f"{checker.EXPECTED_FLOW_LOG_FORMAT} ${{tcp-flags}}",
            " ".join(reversed(checker.EXPECTED_FLOW_LOG_FORMAT.split())),
        ):
            with self.subTest(mutation=mutation):
                plan = clean_plan()
                flow = resource(plan, ".aws_flow_log.relay")
                flow["change"]["after"]["log_format"] = mutation
                self.assert_violation(
                    plan, "exact ALL-traffic 60s forensic field order"
                )

    def test_dns_mutation_protection_must_remain_rollback_safe(self) -> None:
        plan = clean_plan()
        association = resource(
            plan, ".aws_route53_resolver_firewall_rule_group_association.relay"
        )
        association["change"]["after"]["mutation_protection"] = "ENABLED"
        self.assert_violation(plan, "rollback-safe at non-reserved priority 101")

    def test_dns_association_priority_must_avoid_reserved_boundary(self) -> None:
        plan = clean_plan()
        association = resource(
            plan, ".aws_route53_resolver_firewall_rule_group_association.relay"
        )
        association["change"]["after"]["priority"] = 100
        self.assert_violation(plan, "rollback-safe at non-reserved priority 101")

    def test_backend_port_regression_is_rejected(self) -> None:
        plan = clean_plan()
        resource(plan, ".aws_lb_target_group.relay")["change"]["after"]["port"] = 443
        self.assert_violation(plan, "HTTPS:8080")

    def test_relay_target_group_deregistration_delay_accepts_canonical_types(
        self,
    ) -> None:
        for value in CANONICAL_DEREGISTRATION_DELAY_VALUES:
            with self.subTest(value=value):
                plan = clean_plan()
                target_group = resource(plan, ".aws_lb_target_group.relay")
                target_group["change"]["after"]["deregistration_delay"] = value
                self.assertEqual([], checker.validate_plan(plan))

    def test_relay_target_group_deregistration_delay_is_pinned(self) -> None:
        plan = clean_plan()
        target_group = resource(plan, ".aws_lb_target_group.relay")
        target_group["change"]["after"]["deregistration_delay"] = "60"
        self.assert_violation(plan, "relay target group must use HTTPS:8080")

    def test_public_alb_ingress_cidr_is_pinned(self) -> None:
        plan = clean_plan()
        ingress = resource(plan, ".aws_vpc_security_group_ingress_rule.alb_https")
        ingress["change"]["after"]["cidr_ipv4"] = "10.101.0.0/16"
        self.assert_violation(plan, "IPv4 internet")

    def test_assigned_cell_public_udp_listener_cannot_expose_ack_port(self) -> None:
        plan = clean_plan()
        listener = resource(plan, ".aws_lb_listener.udp[0]")
        listener["change"]["after"]["port"] = 62207
        self.assert_violation(plan, "UDP-capable listener inventory")

    def test_relay_cell_servers_must_use_internal_nlb(self) -> None:
        plan = clean_plan()
        relay_call = plan["configuration"]["root_module"]["module_calls"]["nhp"][
            "module"
        ]["module_calls"]["relay"]
        relay_call["expressions"]["cell_servers"]["references"] = [
            "var.environment",
            "var.cell_id",
            "module.compute.server_public_key_b64",
            "module.compute.nlb_dns_name",
            "module.compute",
        ]
        self.assert_violation(plan, "plan-visible cell-routing contract")

    def test_relay_cell_routing_contract_must_use_internal_nlb(self) -> None:
        plan = clean_plan()
        routing = next(
            item
            for item in plan["configuration"]["root_module"]["module_calls"]["nhp"][
                "module"
            ]["resources"]
            if item["type"] == "terraform_data" and item["name"] == "relay_cell_routing"
        )
        routing["expressions"]["input"] = {
            "references": [
                "var.environment",
                "var.cell_id",
                "module.compute.server_public_key_b64",
                "module.compute.nlb_dns_name",
                "module.compute",
            ]
        }
        self.assert_violation(plan, "canonical compute key and internal server NLB")

    def test_relay_cell_routing_contract_must_share_relay_count_gate(self) -> None:
        plan = clean_plan()
        routing = next(
            item
            for item in plan["configuration"]["root_module"]["module_calls"]["nhp"][
                "module"
            ]["resources"]
            if item["type"] == "terraform_data" and item["name"] == "relay_cell_routing"
        )
        routing["count_expression"] = {"constant_value": 1}
        self.assert_violation(plan, "share the relay fleet gate")

    def test_unknown_relay_cell_routing_input_fails_closed(self) -> None:
        plan = clean_plan()
        routing = resource(plan, ".terraform_data.relay_cell_routing[0]")
        routing["change"]["after"]["input"] = None
        routing["change"]["after_unknown"]["input"] = True
        self.assert_violation(plan, "authoritative server public key")

    def test_assigned_cell_public_udp_listener_must_use_public_server_nlb(self) -> None:
        plan = clean_plan()
        listener = configured_resource(plan, "compute", "aws_lb_listener", "udp")
        listener["expressions"]["load_balancer_arn"] = {
            "references": [
                "aws_lb.server_internal[0].arn",
                "aws_lb.server_internal[0]",
                "aws_lb.server_internal",
            ]
        }
        self.assert_violation(plan, "public UDP listener must forward through")

    def test_assigned_cell_public_udp_listener_must_use_public_udp_tg(self) -> None:
        plan = clean_plan()
        listener = configured_resource(plan, "compute", "aws_lb_listener", "udp")
        listener["expressions"]["default_action"] = {
            "references": [
                "aws_lb_target_group.udp_internal[0].arn",
                "aws_lb_target_group.udp_internal[0]",
                "aws_lb_target_group.udp_internal",
            ]
        }
        self.assert_violation(plan, "public UDP listener must forward through")

    def test_assigned_cell_public_udp_listener_accepts_managed_active_color(
        self,
    ) -> None:
        plan = clean_plan()
        listener = configured_resource(plan, "compute", "aws_lb_listener", "udp")
        listener["expressions"]["default_action"]["references"] = list(
            MANAGED_ACTIVE_COLOR_LISTENER_REFS
        )

        self.assertEqual([], checker.validate_plan(plan))

    def test_assigned_cell_public_udp_listener_managed_selector_is_exact(
        self,
    ) -> None:
        cases = {
            "missing blue-green gate": lambda references: [
                reference
                for reference in references
                if reference != "var.enable_blue_green"
            ],
            "missing active-color record": lambda references: [
                reference
                for reference in references
                if not reference.startswith("aws_ssm_parameter.active_color")
            ],
            "operator target override": lambda references: [
                *references,
                "var.public_udp_listener_target",
            ],
        }
        for name, mutate in cases.items():
            with self.subTest(name=name):
                plan = clean_plan()
                listener = configured_resource(
                    plan, "compute", "aws_lb_listener", "udp"
                )
                listener["expressions"]["default_action"]["references"] = mutate(
                    list(MANAGED_ACTIVE_COLOR_LISTENER_REFS)
                )
                self.assert_violation(
                    plan, "exact managed active-color blue/green selector"
                )

    def test_source_fenced_topology_requires_managed_active_color(
        self,
    ) -> None:
        plan = source_fenced_plan()
        listener = configured_resource(plan, "compute", "aws_lb_listener", "udp")
        listener["expressions"]["default_action"]["references"] = [
            "aws_lb_target_group.udp[0].arn",
            "aws_lb_target_group.udp[0]",
            "aws_lb_target_group.udp",
        ]

        errors = checker.validate_plan(
            plan, require_udp_source_fenced_topology=True
        )
        self.assertTrue(
            any(
                "exact managed active-color blue/green selector" in error
                for error in errors
            ),
            errors,
        )

    def test_assigned_cell_public_udp_tg_must_attach_to_server_asg(self) -> None:
        plan = clean_plan()
        attachment = configured_resource(
            plan, "compute", "aws_autoscaling_attachment", "server"
        )
        attachment["expressions"]["autoscaling_group_name"] = {
            "references": ["aws_autoscaling_group.server_green[0].name"]
        }
        self.assert_violation(plan, "canonical server ASG")

    def test_assigned_cell_server_asg_must_attach_to_public_udp_tg(self) -> None:
        plan = clean_plan()
        attachment = configured_resource(
            plan, "compute", "aws_autoscaling_attachment", "server"
        )
        attachment["expressions"]["lb_target_group_arn"] = {
            "references": [
                "aws_lb_target_group.udp_internal[0].arn",
                "aws_lb_target_group.udp_internal[0]",
                "aws_lb_target_group.udp_internal",
            ]
        }
        self.assert_violation(plan, "canonical server ASG")

    def test_assigned_cell_public_udp_tg_attachment_is_required(self) -> None:
        plan = clean_plan()
        plan["resource_changes"] = [
            item
            for item in plan["resource_changes"]
            if not (
                item["type"] == "aws_autoscaling_attachment"
                and item["name"] == "server"
            )
        ]
        self.assert_violation(plan, "public UDP target-group attachment")

    def test_assigned_cell_public_target_group_is_udp_62206(self) -> None:
        plan = clean_plan()
        target_group = resource(plan, ".aws_lb_target_group.udp[0]")
        target_group["change"]["after"]["target_type"] = "ip"
        self.assert_violation(plan, "instance UDP 62206")

    def test_assigned_cell_public_nlb_identity_and_tags_are_canonical(self) -> None:
        cases = {
            "name": lambda values: values.update({"name": "rogue-cell-nlb"}),
            "cell tag": lambda values: values["tags"].update({"Cell": "cell1"}),
            "component tag": lambda values: values["tags"].update(
                {"Component": "relay"}
            ),
        }
        for name, mutate in cases.items():
            with self.subTest(name=name):
                plan = clean_plan()
                mutate(resource(plan, ".aws_lb.server[0]")["change"]["after"])
                self.assert_violation(plan, "canonically named and tagged")

    def test_assigned_cell_public_target_group_identity_tags_and_health_are_canonical(
        self,
    ) -> None:
        cases = {
            "name": lambda values: values.update({"name": "rogue-cell-udp"}),
            "cell tag": lambda values: values["tags"].update({"Cell": "cell1"}),
            "health protocol": lambda values: values["health_check"][0].update(
                {"protocol": "TCP"}
            ),
            "health port": lambda values: values["health_check"][0].update(
                {"port": "62206"}
            ),
            "health path": lambda values: values["health_check"][0].update(
                {"path": "/health/native-ready"}
            ),
        }
        for name, mutate in cases.items():
            with self.subTest(name=name):
                plan = clean_plan()
                mutate(resource(plan, ".aws_lb_target_group.udp[0]")["change"]["after"])
                self.assert_violation(plan, "canonical identity, tags")

    def test_standby_public_udp_target_group_is_required(self) -> None:
        plan = clean_plan()
        plan["resource_changes"] = [
            item
            for item in plan["resource_changes"]
            if not (
                item["type"] == "aws_lb_target_group" and item["name"] == "udp_green"
            )
        ]
        self.assert_violation(plan, "standby public NHP target group")

    def test_standby_public_udp_target_group_contract_is_exact(self) -> None:
        cases = {
            "name": lambda values: values.update({"name": "rogue-green"}),
            "protocol": lambda values: values.update({"protocol": "TCP_UDP"}),
            "port": lambda values: values.update({"port": 62207}),
            "target type": lambda values: values.update({"target_type": "ip"}),
            "preserve client IP": lambda values: values.update(
                {"preserve_client_ip": "false"}
            ),
            "environment tag": lambda values: values["tags"].update(
                {"Environment": "prod"}
            ),
            "component tag": lambda values: values["tags"].update(
                {"Component": "relay"}
            ),
            "cell tag": lambda values: values["tags"].update({"Cell": "cell1"}),
            "name tag": lambda values: values["tags"].update({"Name": "rogue-green"}),
            "color tag": lambda values: values["tags"].update({"DeployColor": "blue"}),
            "health disabled": lambda values: values["health_check"][0].update(
                {"enabled": False}
            ),
            "health protocol": lambda values: values["health_check"][0].update(
                {"protocol": "TCP"}
            ),
            "health port": lambda values: values["health_check"][0].update(
                {"port": "62206"}
            ),
            "health path": lambda values: values["health_check"][0].update(
                {"path": "/health/native-ready"}
            ),
            "health matcher": lambda values: values["health_check"][0].update(
                {"matcher": "200-399"}
            ),
        }
        for name, mutate in cases.items():
            with self.subTest(name=name):
                plan = clean_plan()
                mutate(
                    resource(plan, ".aws_lb_target_group.udp_green[0]")["change"][
                        "after"
                    ]
                )
                self.assert_violation(plan, "canonical green identity")

    def test_public_udp_preserve_client_ip_must_be_authored_for_both_colors(
        self,
    ) -> None:
        for resource_name in ("udp", "udp_green"):
            with self.subTest(resource=resource_name):
                plan = clean_plan()
                target_group = configured_resource(
                    plan, "compute", "aws_lb_target_group", resource_name
                )
                target_group["expressions"]["preserve_client_ip"] = {
                    "constant_value": False
                }
                self.assert_violation(plan, "preserved client IP")

    def test_exact_int_or_int_string_helper(self) -> None:
        for value in CANONICAL_DEREGISTRATION_DELAY_VALUES:
            with self.subTest(accepted=value):
                self.assertTrue(checker.matches_exact_int_or_int_string(value, 30))
        for value in INVALID_DEREGISTRATION_DELAY_VALUES:
            with self.subTest(rejected=value):
                self.assertFalse(checker.matches_exact_int_or_int_string(value, 30))

    def test_relay_cannot_gain_a_public_udp_listener(self) -> None:
        plan = clean_plan()
        listener = copy.deepcopy(resource(plan, ".aws_lb_listener.udp[0]"))
        listener["address"] = "module.nhp.module.relay[0].aws_lb_listener.udp"
        plan["resource_changes"].append(listener)
        self.assert_violation(plan, "listener inventory must be exactly HTTPS 443")

    def test_compute_cannot_gain_a_tcp_udp_listener(self) -> None:
        plan = clean_plan()
        listener = copy.deepcopy(resource(plan, ".aws_lb_listener.udp[0]"))
        listener["address"] = "module.nhp.module.compute.aws_lb_listener.rogue_tcp_udp"
        listener["name"] = "rogue_tcp_udp"
        listener["change"]["after"].update(
            {"protocol": "TCP_UDP", "port": checker.EXPECTED_RELAY_ACK_PORT}
        )
        plan["resource_changes"].append(listener)
        self.assert_violation(plan, "UDP-capable listener inventory")

    def test_internal_udp_listener_cannot_point_at_public_nlb(self) -> None:
        plan = clean_plan()
        listener = configured_resource(
            plan, "compute", "aws_lb_listener", "udp_internal"
        )
        listener["expressions"]["load_balancer_arn"] = {
            "references": [
                "aws_lb.server[0].arn",
                "aws_lb.server[0]",
                "aws_lb.server",
            ]
        }
        self.assert_violation(plan, "private UDP listener must forward only")

    def test_internal_udp_listener_cannot_point_at_public_tg(self) -> None:
        plan = clean_plan()
        listener = configured_resource(
            plan, "compute", "aws_lb_listener", "udp_internal"
        )
        listener["expressions"]["default_action"] = {
            "references": [
                "aws_lb_target_group.udp[0].arn",
                "aws_lb_target_group.udp[0]",
                "aws_lb_target_group.udp",
            ]
        }
        self.assert_violation(plan, "private UDP listener must forward only")

    def test_internal_udp_target_group_attachment_is_required(self) -> None:
        plan = clean_plan()
        plan["resource_changes"] = [
            item
            for item in plan["resource_changes"]
            if not (
                item["type"] == "aws_autoscaling_attachment"
                and item["name"] == "server_internal"
            )
        ]
        self.assert_violation(plan, "internal server UDP target-group attachment")

    def test_internal_udp_target_group_must_attach_to_server_asg(self) -> None:
        plan = clean_plan()
        attachment = configured_resource(
            plan, "compute", "aws_autoscaling_attachment", "server_internal"
        )
        attachment["expressions"]["autoscaling_group_name"] = {
            "references": ["aws_autoscaling_group.server_green[0].name"]
        }
        self.assert_violation(plan, "canonical server ASG")

    def test_internal_server_asg_must_attach_to_internal_udp_target_group(self) -> None:
        plan = clean_plan()
        attachment = configured_resource(
            plan, "compute", "aws_autoscaling_attachment", "server_internal"
        )
        attachment["expressions"]["lb_target_group_arn"] = {
            "references": [
                "aws_lb_target_group.udp[0].arn",
                "aws_lb_target_group.udp[0]",
                "aws_lb_target_group.udp",
            ]
        }
        self.assert_violation(plan, "canonical server ASG")

    def test_internal_green_udp_target_group_is_required(self) -> None:
        plan = clean_plan()
        plan["resource_changes"] = [
            item
            for item in plan["resource_changes"]
            if not (
                item["type"] == "aws_lb_target_group"
                and item["name"] == "udp_internal_green"
            )
        ]
        self.assert_violation(plan, "internal green server target group")

    def test_internal_udp_target_group_contracts_are_exact_for_both_colors(
        self,
    ) -> None:
        for resource_name in ("udp_internal", "udp_internal_green"):
            cases = {
                "name": lambda values: values.update({"name": "rogue-internal"}),
                "protocol": lambda values: values.update({"protocol": "TCP_UDP"}),
                "port": lambda values: values.update({"port": 62207}),
                "target type": lambda values: values.update({"target_type": "ip"}),
                "preserve client IP": lambda values: values.update(
                    {"preserve_client_ip": "false"}
                ),
                "environment tag": lambda values: values["tags"].update(
                    {"Environment": "prod"}
                ),
                "component tag": lambda values: values["tags"].update(
                    {"Component": "relay"}
                ),
                "cell tag": lambda values: values["tags"].update({"Cell": "cell1"}),
                "name tag": lambda values: values["tags"].update(
                    {"Name": "rogue-internal"}
                ),
                "color tag": lambda values: values["tags"].update(
                    {"DeployColor": "wrong"}
                ),
                "health disabled": lambda values: values["health_check"][0].update(
                    {"enabled": False}
                ),
                "health protocol": lambda values: values["health_check"][0].update(
                    {"protocol": "TCP"}
                ),
                "health port": lambda values: values["health_check"][0].update(
                    {"port": "62206"}
                ),
                "health path": lambda values: values["health_check"][0].update(
                    {"path": "/health/native-ready"}
                ),
                "health matcher": lambda values: values["health_check"][0].update(
                    {"matcher": "200-399"}
                ),
            }
            for name, mutate in cases.items():
                with self.subTest(resource=resource_name, mutation=name):
                    plan = clean_plan()
                    target_group = resource(
                        plan, f".aws_lb_target_group.{resource_name}"
                    )
                    mutate(target_group["change"]["after"])
                    self.assert_violation(
                        plan,
                        f"internal {'green' if resource_name.endswith('_green') else 'blue'} server target group",
                    )

    def test_internal_udp_preserve_client_ip_must_be_authored_for_both_colors(
        self,
    ) -> None:
        for resource_name in ("udp_internal", "udp_internal_green"):
            with self.subTest(resource=resource_name):
                plan = clean_plan()
                target_group = configured_resource(
                    plan, "compute", "aws_lb_target_group", resource_name
                )
                target_group["expressions"]["preserve_client_ip"] = {
                    "constant_value": False
                }
                self.assert_violation(
                    plan,
                    f"internal {'green' if resource_name.endswith('_green') else 'blue'} server target group",
                )

    def test_green_server_asg_is_required(self) -> None:
        plan = clean_plan()
        plan["resource_changes"] = [
            item
            for item in plan["resource_changes"]
            if not (
                item["type"] == "aws_autoscaling_group"
                and item["name"] == "server_green"
            )
        ]
        self.assert_violation(plan, "green server ASG")

    def test_green_server_asg_planned_targets_include_both_udp_colors(self) -> None:
        plan = clean_plan()
        green_asg = resource(plan, ".aws_autoscaling_group.server_green[0]")
        green_asg["change"]["after"]["target_group_arns"] = [
            resource(plan, ".aws_lb_target_group.udp_green[0]")["change"]["after"][
                "arn"
            ]
        ]
        self.assert_violation(plan, "planned values and authored config")

    def test_green_server_asg_planned_targets_reject_extra_literal_arn(self) -> None:
        plan = clean_plan()
        green_asg = resource(plan, ".aws_autoscaling_group.server_green[0]")
        green_asg["change"]["after"]["target_group_arns"].append(
            "arn:aws:elasticloadbalancing:us-east-2:767397897469:targetgroup/rogue/extra"
        )
        self.assert_violation(plan, "planned values and authored config")

    def test_green_server_asg_authored_targets_cannot_omit_internal_udp(self) -> None:
        plan = clean_plan()
        green_asg = configured_resource(
            plan, "compute", "aws_autoscaling_group", "server_green"
        )
        green_asg["expressions"]["target_group_arns"]["references"] = [
            "aws_lb_target_group.udp_green[0].arn",
            "aws_lb_target_group.udp_green[0]",
            "aws_lb_target_group.udp_green",
            "var.enable_qurl_resolve_endpoint",
            "aws_lb_target_group.https_green[0].arn",
            "aws_lb_target_group.https_green[0]",
            "aws_lb_target_group.https_green",
        ]
        self.assert_violation(plan, "planned values and authored config")

    def test_relay_https_backend_rejects_foreign_peer_sg(self) -> None:
        plan = clean_plan()
        ingress = configured_resource(
            plan,
            "relay",
            "aws_vpc_security_group_ingress_rule",
            "relay_http_from_alb",
        )
        ingress["expressions"]["referenced_security_group_id"] = {
            "references": ["aws_security_group.unreviewed_foreign.id"]
        }
        self.assert_violation(
            plan, "relay HTTPS backend ingress must use only the reviewed SG-to-SG path"
        )

    def test_endpoint_ingress_rejects_cidr_source(self) -> None:
        plan = clean_plan()
        ingress = resource(
            plan, ".aws_vpc_security_group_ingress_rule.vpc_endpoints_from_relay"
        )
        ingress["change"]["after"]["cidr_ipv4"] = "10.101.0.0/16"
        self.assert_violation(
            plan, "VPC endpoint HTTPS ingress must use only the reviewed SG-to-SG path"
        )

    def test_relay_backend_rejects_configured_cidr_branch(self) -> None:
        plan = clean_plan()
        ingress = configured_resource(
            plan,
            "relay",
            "aws_vpc_security_group_ingress_rule",
            "relay_http_from_alb",
        )
        ingress["expressions"]["cidr_ipv4"] = {"constant_value": "10.101.0.0/16"}
        self.assert_violation(
            plan, "relay HTTPS backend ingress must use only the reviewed SG-to-SG path"
        )

    def test_alb_backend_egress_rejects_wrong_owner_sg(self) -> None:
        plan = clean_plan()
        egress = configured_resource(
            plan,
            "relay",
            "aws_vpc_security_group_egress_rule",
            "alb_to_relay",
        )
        egress["expressions"]["security_group_id"] = {
            "references": ["aws_security_group.relay.id"]
        }
        self.assert_violation(
            plan, "ALB HTTPS backend egress must use only the reviewed SG-to-SG path"
        )

    def test_standalone_rule_config_rejects_every_alternate_selector(self) -> None:
        cases = (
            (
                "aws_vpc_security_group_egress_rule",
                "relay_to_vpc_endpoints_https",
                "security_group_id",
                {"references": ["aws_security_group.unreviewed.id"]},
                "relay endpoint HTTPS egress must use only the reviewed SG-to-SG path",
            ),
            (
                "aws_vpc_security_group_egress_rule",
                "relay_to_vpc_endpoints_https",
                "cidr_ipv4",
                {"references": ["var.unreviewed_endpoint_cidr"]},
                "relay endpoint HTTPS egress must use only the reviewed SG-to-SG path",
            ),
            (
                "aws_vpc_security_group_egress_rule",
                "relay_to_s3_https",
                "security_group_id",
                {"references": ["aws_security_group.unreviewed.id"]},
                "relay S3 HTTPS egress must target only the regional S3 prefix list",
            ),
            (
                "aws_vpc_security_group_egress_rule",
                "relay_to_s3_https",
                "referenced_security_group_id",
                {"references": ["aws_security_group.unreviewed.id"]},
                "relay S3 HTTPS egress must target only the regional S3 prefix list",
            ),
            (
                "aws_vpc_security_group_egress_rule",
                "relay_to_nhp_udp",
                "security_group_id",
                {"references": ["aws_security_group.unreviewed.id"]},
                "relay server UDP egress must use only the relay SG",
            ),
            (
                "aws_vpc_security_group_egress_rule",
                "relay_to_nhp_udp",
                "prefix_list_id",
                {"references": ["aws_ec2_managed_prefix_list.unreviewed.id"]},
                "relay server UDP egress must use only the relay SG",
            ),
        )
        for resource_type, name, field, expression, error in cases:
            with self.subTest(name=name, field=field):
                plan = clean_plan()
                rule_config = configured_resource(plan, "relay", resource_type, name)
                rule_config["expressions"][field] = expression
                self.assert_violation(plan, error)

        plan = clean_plan()
        server_egress = configured_resource(
            plan, "relay", "aws_vpc_security_group_egress_rule", "relay_to_nhp_udp"
        )
        server_egress["for_each_expression"] = {
            "references": ["var.unreviewed_gate", "local.nhp_server_cidr_blocks"]
        }
        self.assert_violation(
            plan, "relay server UDP egress must use only the relay SG"
        )

    def test_private_ack_ingress_cannot_become_public(self) -> None:
        plan = clean_plan()
        ingress = resource(
            plan, ".aws_vpc_security_group_ingress_rule.relay_udp_ack_return"
        )
        ingress["change"]["after"]["cidr_ipv4"] = "0.0.0.0/0"
        self.assert_violation(plan, "must not use any public or CIDR source")

    def test_private_ack_ingress_must_wait_for_active_peering(self) -> None:
        plan = clean_plan()
        ingress = configured_resource(
            plan,
            "relay",
            "aws_vpc_security_group_ingress_rule",
            "relay_udp_ack_return",
        )
        ingress["depends_on"] = []
        self.assert_violation(plan, "active cross-VPC peering barrier")

    def test_private_ack_ingress_rejects_configured_cidr_branch(self) -> None:
        plan = clean_plan()
        ingress = configured_resource(
            plan,
            "relay",
            "aws_vpc_security_group_ingress_rule",
            "relay_udp_ack_return",
        )
        ingress["expressions"]["cidr_ipv4"] = {
            "references": ["var.unreviewed_ack_source_cidr"]
        }
        self.assert_violation(
            plan,
            "relay UDP 62207 ACK ingress must use only the reviewed SG-to-SG path",
        )

    def test_private_ack_ingress_rejects_wrong_owner_sg(self) -> None:
        plan = clean_plan()
        ingress = configured_resource(
            plan,
            "relay",
            "aws_vpc_security_group_ingress_rule",
            "relay_udp_ack_return",
        )
        ingress["expressions"]["security_group_id"] = {
            "references": ["aws_security_group.unreviewed_foreign.id"]
        }
        self.assert_violation(
            plan,
            "relay UDP 62207 ACK ingress must use only the reviewed SG-to-SG path",
        )

    def test_private_ack_ingress_must_reference_only_server_sg(self) -> None:
        plan = clean_plan()
        relay_resources = plan["configuration"]["root_module"]["module_calls"]["nhp"][
            "module"
        ]["module_calls"]["relay"]["module"]["resources"]
        ingress = next(
            item
            for item in relay_resources
            if item["type"] == "aws_vpc_security_group_ingress_rule"
            and item["name"] == "relay_udp_ack_return"
        )
        ingress["expressions"]["referenced_security_group_id"] = {
            "references": ["aws_security_group.unreviewed_foreign.id"]
        }
        self.assert_violation(
            plan,
            "relay UDP 62207 ACK ingress must use only the reviewed SG-to-SG path",
        )

    def test_private_ack_module_input_must_come_from_canonical_server_sg(
        self,
    ) -> None:
        plan = clean_plan()
        relay_call = plan["configuration"]["root_module"]["module_calls"]["nhp"]
        relay_call = relay_call["module"]["module_calls"]["relay"]
        relay_call["expressions"]["server_security_group_id"] = {
            "references": ["aws_security_group.unreviewed.id"]
        }
        self.assert_violation(
            plan, "must come from the canonical server security group"
        )

    def test_relay_user_data_must_contain_plaintext_relay_toml_markers(self) -> None:
        plan = clean_plan()
        launch_template = resource(plan, ".aws_launch_template.relay")
        launch_template["change"]["after"]["user_data"] = base64.b64encode(
            b"#!/bin/bash\necho bootstrap without relay config\n"
        ).decode("ascii")
        self.assert_violation(
            plan,
            "must remain base64-encoded UTF-8 plaintext containing [[servers]] relay TOML markers",
        )

    def test_relay_user_data_rejects_extra_literal_cell_host(self) -> None:
        plan = clean_plan()
        launch_template = resource(plan, ".aws_launch_template.relay")
        rendered = base64.b64decode(launch_template["change"]["after"]["user_data"])
        rendered += (
            b'\n[[servers]]\nname = "sandbox-cell1"\n'
            + f'public_key = "{"B" * 43}="\n'.encode()
            + b'host = "evil.example"\nport = 62206\n'
        )
        launch_template["change"]["after"]["user_data"] = base64.b64encode(
            rendered
        ).decode("ascii")
        self.assert_violation(
            plan,
            "exactly match the plan-visible sandbox-cell0 route",
        )

    def test_relay_user_data_rejects_missing_cell_host(self) -> None:
        plan = clean_plan()
        launch_template = resource(plan, ".aws_launch_template.relay")
        rendered = base64.b64decode(
            launch_template["change"]["after"]["user_data"]
        ).decode()
        rendered = re.sub(r'(?m)^host = "[^"]+"\n', "", rendered)
        launch_template["change"]["after"]["user_data"] = base64.b64encode(
            rendered.encode()
        ).decode("ascii")
        self.assert_violation(plan, "containing [[servers]] relay TOML markers")

    def test_relay_user_data_rejects_wrong_internal_cell_host(self) -> None:
        plan = clean_plan()
        launch_template = resource(plan, ".aws_launch_template.relay")
        rendered = base64.b64decode(
            launch_template["change"]["after"]["user_data"]
        ).decode()
        rendered = re.sub(r'(?m)^host = "[^"]+"$', 'host = "evil.example"', rendered)
        launch_template["change"]["after"]["user_data"] = base64.b64encode(
            rendered.encode()
        ).decode("ascii")
        self.assert_violation(
            plan,
            "exactly match the plan-visible sandbox-cell0 route",
        )

    def test_relay_user_data_rejects_well_shaped_wrong_server_key(self) -> None:
        plan = clean_plan()
        launch_template = resource(plan, ".aws_launch_template.relay")
        rendered = base64.b64decode(
            launch_template["change"]["after"]["user_data"]
        ).decode()
        rendered = re.sub(
            r'(?m)^public_key = "[^"]+"$',
            f'public_key = "{"B" * 43}="',
            rendered,
        )
        launch_template["change"]["after"]["user_data"] = base64.b64encode(
            rendered.encode()
        ).decode("ascii")
        self.assert_violation(
            plan,
            "authoritative server public key",
        )

    def test_relay_user_data_rejects_gzipped_payload_with_clear_diagnostic(
        self,
    ) -> None:
        plan = clean_plan()
        launch_template = resource(plan, ".aws_launch_template.relay")
        launch_template["change"]["after"]["user_data"] = base64.b64encode(
            b"\x1f\x8b\x08\x00compressed"
        ).decode("ascii")
        self.assert_violation(
            plan,
            "gzip or multipart user_data requires an explicitly reviewed parser update",
        )

    def test_public_nhp_dns_must_target_assigned_cell_nlb(self) -> None:
        plan = clean_plan()
        nhp_module = plan["configuration"]["root_module"]["module_calls"]["nhp"][
            "module"
        ]
        nhp_module["module_calls"]["dns"]["expressions"]["nlb_dns_name"] = {
            "references": ["module.relay[0].dns_name"]
        }
        self.assert_violation(plan, "assigned cell's server NLB directly")

    def test_public_nhp_dns_and_output_accept_terraform_dual_references(self) -> None:
        plan = clean_plan()
        nhp_module = plan["configuration"]["root_module"]["module_calls"]["nhp"][
            "module"
        ]
        self.assertEqual(
            ["module.compute.nlb_dns_name", "module.compute"],
            nhp_module["module_calls"]["dns"]["expressions"]["nlb_dns_name"][
                "references"
            ],
        )
        self.assertEqual(
            ["module.compute.nlb_dns_name", "module.compute"],
            nhp_module["outputs"]["nlb_dns_name"]["expression"]["references"],
        )
        self.assertEqual([], checker.validate_plan(plan))

    def test_public_nhp_dns_rejects_incomplete_leaf_only_reference(self) -> None:
        plan = clean_plan()
        nhp_module = plan["configuration"]["root_module"]["module_calls"]["nhp"][
            "module"
        ]
        nhp_module["module_calls"]["dns"]["expressions"]["nlb_dns_name"] = {
            "references": ["module.compute.nlb_dns_name"]
        }
        self.assert_violation(plan, "assigned cell's server NLB directly")

    def test_public_nlb_output_must_expose_assigned_cell_nlb(self) -> None:
        plan = clean_plan()
        nhp_module = plan["configuration"]["root_module"]["module_calls"]["nhp"][
            "module"
        ]
        nhp_module["outputs"]["nlb_dns_name"] = {
            "expression": {"references": ["module.relay[0].dns_name"]}
        }
        self.assert_violation(plan, "public nlb_dns_name output")

    def test_public_nlb_output_rejects_incomplete_leaf_only_reference(self) -> None:
        plan = clean_plan()
        nhp_module = plan["configuration"]["root_module"]["module_calls"]["nhp"][
            "module"
        ]
        nhp_module["outputs"]["nlb_dns_name"] = {
            "expression": {"references": ["module.compute.nlb_dns_name"]}
        }
        self.assert_violation(plan, "public nlb_dns_name output")

    def test_s3_egress_must_use_prefix_list(self) -> None:
        plan = clean_plan()
        relay_resources = plan["configuration"]["root_module"]["module_calls"]["nhp"][
            "module"
        ]["module_calls"]["relay"]["module"]["resources"]
        s3_egress = next(
            item for item in relay_resources if item["name"] == "relay_to_s3_https"
        )
        s3_egress["expressions"]["prefix_list_id"] = {"constant_value": "pl-unreviewed"}
        self.assert_violation(plan, "regional S3 prefix list")

    def test_s3_endpoint_accepts_singleton_get_object_action_list(self) -> None:
        plan = clean_plan()
        endpoint = resource(plan, ".aws_vpc_endpoint.s3")
        policy = json.loads(endpoint["change"]["after"]["policy"])
        policy["Statement"][0]["Action"] = ["s3:GetObject"]
        endpoint["change"]["after"]["policy"] = json.dumps(policy)
        self.assertEqual([], checker.validate_plan(plan))

    def test_s3_endpoint_rejects_extra_action(self) -> None:
        plan = clean_plan()
        endpoint = resource(plan, ".aws_vpc_endpoint.s3")
        policy = json.loads(endpoint["change"]["after"]["policy"])
        policy["Statement"][0]["Action"] = ["s3:GetObject", "s3:PutObject"]
        endpoint["change"]["after"]["policy"] = json.dumps(policy)
        self.assert_violation(plan, "S3 endpoint may allow only GetObject")

    def test_initial_dmz_move_requires_existing_alb_replacement(self) -> None:
        plan = clean_plan()
        alb = resource(plan, ".module.relay[0].aws_lb.relay")
        alb["change"]["before"] = {"vpc_id": "vpc-old-main"}
        alb["change"]["actions"] = ["update"]
        self.assert_violation(plan, "must be replaced")

    def test_relay_alb_hardening_and_log_destination_are_exact(self) -> None:
        cases = {
            "client port": lambda alb: alb.update({"enable_xff_client_port": True}),
            "WAF fail open": lambda alb: alb.update({"enable_waf_fail_open": True}),
            "redirected logs": lambda alb: alb["access_logs"][0].update(
                {"bucket": "attacker-controlled-bucket"}
            ),
            "log prefix": lambda alb: alb["access_logs"][0].update(
                {"prefix": "redirected"}
            ),
        }
        for name, mutate in cases.items():
            with self.subTest(name=name):
                plan = clean_plan()
                alb = resource(plan, ".module.relay[0].aws_lb.relay")
                mutate(alb["change"]["after"])
                self.assert_violation(
                    plan,
                    "exact deletion protection, WAF/XFF/HTTP hardening, and access-log destination",
                )

    def test_broad_server_return_ingress_is_rejected(self) -> None:
        plan = clean_plan()
        rule = resource(plan, '.server_nhp_udp_additional["10.101.10.0/24"]')
        rule["change"]["after"]["cidr_ipv4"] = "10.101.0.0/16"
        self.assert_violation(plan, "exactly the three relay /24s")

    def test_assigned_cell_public_server_nlb_surface_is_required(self) -> None:
        plan = clean_plan()
        plan["resource_changes"] = [
            item
            for item in plan["resource_changes"]
            if not (
                ".module.compute." in item["address"]
                and (item["type"], item["name"])
                in {
                    ("aws_lb", "server"),
                    ("aws_lb_target_group", "udp"),
                    ("aws_lb_listener", "udp"),
                }
            )
        ]
        self.assert_violation(
            plan, "canonically named and tagged internet-facing server NLB"
        )

    def test_renamed_public_compute_nlb_is_rejected(self) -> None:
        plan = clean_plan()
        public_nlb = copy.deepcopy(resource(plan, ".aws_lb.server_internal"))
        public_nlb["address"] = "module.nhp.module.compute.aws_lb.renamed_public"
        public_nlb["name"] = "renamed_public"
        public_nlb["change"]["after"]["internal"] = False
        plan["resource_changes"].append(public_nlb)
        self.assert_violation(plan, "only internet-facing compute NLB")

    def test_base_server_udp_ingress_must_remain_public(self) -> None:
        plan = clean_plan()
        rule = resource(plan, ".server_nhp_udp")
        rule["change"]["after"]["cidr_ipv4"] = "10.100.0.0/16"
        self.assert_violation(plan, "accept public NHP UDP 62206")

    def test_base_server_udp_ingress_must_belong_to_server_sg(self) -> None:
        plan = clean_plan()
        rule = configured_resource(
            plan,
            "compute",
            "aws_vpc_security_group_ingress_rule",
            "server_nhp_udp",
        )
        rule["expressions"]["security_group_id"] = {
            "references": ["aws_security_group.unreviewed.id"]
        }
        self.assert_violation(plan, "canonical server SG")

    def test_server_sg_rejects_inline_public_udp_ack_ingress(self) -> None:
        plan = clean_plan()
        server_sg = configured_resource(plan, "compute", "aws_security_group", "server")
        server_sg["expressions"]["ingress"] = {
            "constant_value": [
                {
                    "protocol": "udp",
                    "from_port": 62207,
                    "to_port": 62207,
                    "cidr_blocks": ["0.0.0.0/0"],
                }
            ]
        }
        self.assert_violation(plan, "declare no inline ingress or egress")

    def test_compute_rejects_legacy_public_udp_security_group_rule(self) -> None:
        plan = clean_plan()
        plan["resource_changes"].append(
            {
                "address": (
                    "module.nhp.module.compute.aws_security_group_rule.rogue_public_ack"
                ),
                "mode": "managed",
                "type": "aws_security_group_rule",
                "name": "rogue_public_ack",
                "change": {
                    "actions": ["create"],
                    "before": None,
                    "after": {
                        "type": "ingress",
                        "security_group_id": "sg-server",
                        "protocol": "udp",
                        "from_port": 62207,
                        "to_port": 62207,
                        "cidr_blocks": ["0.0.0.0/0"],
                        "ipv6_cidr_blocks": [],
                    },
                    "after_unknown": {},
                },
            }
        )
        self.assert_violation(plan, "legacy aws_security_group_rule resources")

    def test_server_sg_rejects_second_public_udp_range_covering_nhp(self) -> None:
        plan = clean_plan()
        rule = copy.deepcopy(resource(plan, ".server_nhp_udp"))
        rule["address"] = (
            "module.nhp.module.compute."
            "aws_vpc_security_group_ingress_rule.rogue_public_udp_range"
        )
        rule["name"] = "rogue_public_udp_range"
        rule["change"]["after"].update({"from_port": 62000, "to_port": 63000})
        plan["resource_changes"].append(rule)
        self.assert_violation(plan, "public UDP-capable ingress")

    def test_server_sg_rejects_public_all_protocol_rule_covering_nhp(self) -> None:
        plan = clean_plan()
        rule = copy.deepcopy(resource(plan, ".server_nhp_udp"))
        rule["address"] = (
            "module.nhp.module.compute."
            "aws_vpc_security_group_ingress_rule.rogue_public_all"
        )
        rule["name"] = "rogue_public_all"
        rule["change"]["after"].update(
            {"ip_protocol": "-1", "from_port": None, "to_port": None}
        )
        plan["resource_changes"].append(rule)
        self.assert_violation(plan, "public UDP-capable ingress")

    def test_public_udp_scan_handles_case_and_fails_closed_on_ambiguity(self) -> None:
        for protocol_values in (
            {},
            {"ip_protocol": None},
            {"ip_protocol": ""},
            {"ip_protocol": "gre"},
            {"ip_protocol": "UDP"},
            {"ip_protocol": "17"},
            {"ip_protocol": "6"},
        ):
            with self.subTest(protocol_values=protocol_values):
                candidate = checker.PlannedResource(
                    address="aws_vpc_security_group_ingress_rule.unreviewed",
                    resource_type="aws_vpc_security_group_ingress_rule",
                    name="unreviewed",
                    values={
                        "cidr_ipv4": checker.EXPECTED_IPV4_DEFAULT_CIDR,
                        **protocol_values,
                    },
                    after_unknown=None,
                    before=None,
                    actions=("create",),
                )
                self.assertTrue(checker.public_udp_capable_rule(candidate))
                self.assertTrue(checker.planned_udp_capable_sg_rule(candidate))

    def test_server_sg_rejects_public_udp_ack_port(self) -> None:
        plan = clean_plan()
        rule = copy.deepcopy(resource(plan, ".server_nhp_udp"))
        rule["address"] = (
            "module.nhp.module.compute."
            "aws_vpc_security_group_ingress_rule.rogue_public_ack"
        )
        rule["name"] = "rogue_public_ack"
        rule["change"]["after"].update({"from_port": 62207, "to_port": 62207})
        plan["resource_changes"].append(rule)
        self.assert_violation(plan, "public UDP-capable ingress")

    def test_ipv6_internet_wide_security_group_egress_is_rejected(self) -> None:
        plan = clean_plan()
        rule = resource(plan, ".aws_vpc_security_group_egress_rule.relay_to_s3_https")
        rule["change"]["after"]["cidr_ipv6"] = "::/0"
        self.assert_violation(plan, "IPv4 or IPv6 internet-wide egress")

    def test_peering_routes_reject_an_alternative_target_reference(self) -> None:
        for route_name in ("relay_to_main_private", "main_private_to_relay"):
            with self.subTest(route=route_name):
                plan = clean_plan()
                route_config = configured_resource(
                    plan, "relay_network", "aws_route", route_name
                )
                route_config["expressions"] = {
                    "transit_gateway_id": {
                        "references": ["aws_ec2_transit_gateway.main.id"]
                    }
                }
                self.assert_violation(
                    plan, "must target only the reviewed main VPC peering connection"
                )

    def test_peering_routes_reject_a_concrete_alternative_target(self) -> None:
        for route_name in ("relay_to_main_private", "main_private_to_relay"):
            with self.subTest(route=route_name):
                plan = clean_plan()
                route = resource(plan, f".aws_route.{route_name}[0]")
                route["change"]["after"]["transit_gateway_id"] = "tgw-unreviewed"
                self.assert_violation(plan, "must not use an alternative next-hop")

    def test_relay_iam_ec2messages_is_rejected(self) -> None:
        plan = clean_plan()
        iam = resource(plan, ".aws_iam_role_policy.relay")
        policy = json.loads(iam["change"]["after"]["policy"])
        policy_statement(policy, "ssm:DescribeAssociation")["Action"].append(
            "ec2messages:GetMessages"
        )
        iam["change"]["after"]["policy"] = json.dumps(policy)
        self.assert_violation(plan, "relay IAM action set changed")

    def test_ssm_document_grant_cannot_include_account_owned_document(self) -> None:
        plan = clean_plan()
        iam = resource(plan, ".aws_iam_role_policy.context_lookups_relay_ssm[0]")
        policy = json.loads(iam["change"]["after"]["policy"])
        statement = statement_by_sid(policy, "SSMHealthCheckDocument")
        statement["Resource"] = [
            statement["Resource"],
            f"arn:aws:ssm:us-east-2:{checker.EXPECTED_SANDBOX_ACCOUNT_ID}:document/AWS-RunShellScript",
        ]
        iam["change"]["after"]["policy"] = json.dumps(policy)
        self.assert_violation(plan, "commercial AWS-owned AWS-RunShellScript")

    def test_ssm_instance_grant_accepts_only_sandbox_cells(self) -> None:
        plan = clean_plan()
        iam = resource(plan, ".aws_iam_role_policy.context_lookups_relay_ssm[0]")
        policy = json.loads(iam["change"]["after"]["policy"])
        statement = statement_by_sid(policy, "SSMHealthCheckSandboxInstances")
        environments = statement["Condition"]["StringEquals"][
            "ssm:resourceTag/Environment"
        ]
        self.assertEqual(["sandbox", "sandbox-cell1"], environments)
        self.assertEqual([], checker.validate_plan(plan))

        environments.append("prod")
        iam["change"]["after"]["policy"] = json.dumps(policy)
        self.assert_violation(
            plan, "require exactly Environment=sandbox or sandbox-cell1"
        )

    def test_ssm_instance_grant_cannot_cross_accounts(self) -> None:
        plan = clean_plan()
        iam = resource(plan, ".aws_iam_role_policy.context_lookups_relay_ssm[0]")
        policy = json.loads(iam["change"]["after"]["policy"])
        statement = statement_by_sid(policy, "SSMHealthCheckSandboxInstances")
        statement["Resource"] = "arn:aws:ec2:us-east-2:*:instance/*"
        iam["change"]["after"]["policy"] = json.dumps(policy)
        self.assert_violation(plan, "same-account")

    def test_ssm_get_invocation_requires_action_only_wildcard(self) -> None:
        plan = clean_plan()
        iam = resource(plan, ".aws_iam_role_policy.context_lookups_relay_ssm[0]")
        policy = json.loads(iam["change"]["after"]["policy"])
        statement = statement_by_sid(policy, "SSMHealthCheckInvocation")
        statement["Resource"] = (
            f"arn:aws:ec2:us-east-2:{checker.EXPECTED_SANDBOX_ACCOUNT_ID}:instance/*"
        )
        iam["change"]["after"]["policy"] = json.dumps(policy)
        self.assert_violation(plan, "AWS exposes no resource type")

    def test_ssm_command_statement_set_cannot_expand(self) -> None:
        plan = clean_plan()
        iam = resource(plan, ".aws_iam_role_policy.context_lookups_relay_ssm[0]")
        policy = json.loads(iam["change"]["after"]["policy"])
        policy["Statement"].append(
            {
                "Sid": "BroadCommand",
                "Effect": "Allow",
                "Action": "ssm:SendCommand",
                "Resource": "*",
            }
        )
        iam["change"]["after"]["policy"] = json.dumps(policy)
        self.assert_violation(plan, "exactly document, sandbox-instance")

    def test_ssm_action_case_variant_cannot_bypass_checker(self) -> None:
        plan = clean_plan()
        iam = resource(plan, ".aws_iam_role_policy.context_lookups_relay_ssm[0]")
        policy = json.loads(iam["change"]["after"]["policy"])
        policy["Statement"].append(
            {
                "Sid": "CaseVariantCommand",
                "Effect": "Allow",
                "Action": "SSM:SendCommand",
                "Resource": "*",
            }
        )
        iam["change"]["after"]["policy"] = json.dumps(policy)
        self.assert_violation(plan, "case-normalized SSM action envelope")

    def test_ssm_service_wildcard_cannot_bypass_checker(self) -> None:
        for action in ("ssm:*", "ssm*"):
            with self.subTest(action=action):
                plan = clean_plan()
                iam = resource(
                    plan, ".aws_iam_role_policy.context_lookups_relay_ssm[0]"
                )
                policy = json.loads(iam["change"]["after"]["policy"])
                policy["Statement"].append(
                    {
                        "Sid": "SSMWildcard",
                        "Effect": "Allow",
                        "Action": action,
                        "Resource": "*",
                    }
                )
                iam["change"]["after"]["policy"] = json.dumps(policy)
                self.assert_violation(
                    plan, "wildcard actions that include Systems Manager"
                )

    def test_global_action_wildcard_cannot_bypass_checker(self) -> None:
        plan = clean_plan()
        iam = resource(plan, ".aws_iam_role_policy.context_lookups_relay_ssm[0]")
        policy = json.loads(iam["change"]["after"]["policy"])
        policy["Statement"].append(
            {
                "Sid": "GlobalWildcard",
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*",
            }
        )
        iam["change"]["after"]["policy"] = json.dumps(policy)
        self.assert_violation(plan, "wildcard actions that include Systems Manager")

    def test_not_action_cannot_bypass_ssm_checker(self) -> None:
        plan = clean_plan()
        iam = resource(plan, ".aws_iam_role_policy.context_lookups_relay_ssm[0]")
        policy = json.loads(iam["change"]["after"]["policy"])
        policy["Statement"].append(
            {
                "Sid": "NotActionGrant",
                "Effect": "Allow",
                "NotAction": "s3:DeleteObject",
                "Resource": "*",
            }
        )
        iam["change"]["after"]["policy"] = json.dumps(policy)
        self.assert_violation(plan, "must not use NotAction")

    def test_ssm_context_policy_must_remain_relay_gated(self) -> None:
        plan = clean_plan()
        ecr = plan["configuration"]["root_module"]["module_calls"]["nhp"]["module"][
            "module_calls"
        ]["ecr"]
        ecr["expressions"]["deploy_relay_network"] = {"constant_value": True}
        self.assert_violation(plan, "must be gated by deploy_relay")

    def test_relay_ssm_policy_count_must_remain_relay_gated(self) -> None:
        plan = clean_plan()
        ecr = plan["configuration"]["root_module"]["module_calls"]["nhp"]["module"][
            "module_calls"
        ]["ecr"]["module"]
        relay_ssm = next(
            item
            for item in ecr["resources"]
            if item["name"] == "context_lookups_relay_ssm"
        )
        relay_ssm["count_expression"] = {"constant_value": 1}
        self.assert_violation(plan, "gated directly by deploy_relay_network")

    def test_context_policy_cannot_regain_send_command(self) -> None:
        plan = clean_plan()
        iam = resource(plan, ".aws_iam_role_policy.context_lookups")
        policy = json.loads(iam["change"]["after"]["policy"])
        policy["Statement"].append(
            {
                "Sid": "BroadCommand",
                "Effect": "Allow",
                "Action": "ssm:SendCommand",
                "Resource": "*",
            }
        )
        iam["change"]["after"]["policy"] = json.dumps(policy)
        self.assert_violation(plan, "case-normalized SSM action envelope")

    def test_relay_iam_s3_expansion_is_rejected(self) -> None:
        plan = clean_plan()
        iam = resource(plan, ".aws_iam_role_policy.relay")
        policy = json.loads(iam["change"]["after"]["policy"])
        policy_statement(policy, "s3:GetObject")["Resource"].append(
            "arn:aws:s3:::aws-ssm-document-attachments-us-east-2/*"
        )
        iam["change"]["after"]["policy"] = json.dumps(policy)
        self.assert_violation(plan, "S3 bucket allowlist changed")

    def test_relay_iam_resource_partition_is_exact_for_every_action_group(
        self,
    ) -> None:
        cases = (
            ("secretsmanager:GetSecretValue", "*", "Secrets Manager identity read"),
            (
                "ecr:GetAuthorizationToken",
                checker.EXPECTED_SANDBOX_RELAY_REPO_ARN,
                "ECR authorization token",
            ),
            ("ecr:BatchGetImage", "*", "ECR repository read"),
            ("logs:PutLogEvents", "*", "relay log write"),
            ("ssm:GetParameter", "*", "relay image-tag read"),
            (
                "ssm:DescribeAssociation",
                "arn:aws:ssm:us-east-2:123:bad",
                "SSM Agent core",
            ),
            (
                "ssmmessages:OpenControlChannel",
                "arn:aws:ssmmessages:us-east-2:123:bad",
                "SSM message channels",
            ),
            ("s3:GetObject", "*", "SSM regional bucket read"),
            (
                "cloudwatch:PutMetricData",
                "arn:aws:cloudwatch:us-east-2:123:bad",
                "bootstrap metric write",
            ),
        )
        for action, bad_resource, label in cases:
            with self.subTest(action=action):
                plan = clean_plan()
                iam = resource(plan, ".aws_iam_role_policy.relay")
                policy = json.loads(iam["change"]["after"]["policy"])
                policy_statement(policy, action)["Resource"] = bad_resource
                iam["change"]["after"]["policy"] = json.dumps(policy)
                self.assert_violation(
                    plan, f"relay IAM {label} resource allowlist changed"
                )

    def test_relay_iam_unreviewed_conditions_are_rejected_for_every_group(
        self,
    ) -> None:
        actions = (
            ("secretsmanager:GetSecretValue", "Secrets Manager identity read"),
            ("ecr:GetAuthorizationToken", "ECR authorization token"),
            ("ecr:BatchGetImage", "ECR repository read"),
            ("logs:PutLogEvents", "relay log write"),
            ("ssm:GetParameter", "relay image-tag read"),
            ("ssm:DescribeAssociation", "SSM Agent core"),
            ("ssmmessages:OpenControlChannel", "SSM message channels"),
            ("s3:GetObject", "SSM regional bucket read"),
        )
        for action, label in actions:
            with self.subTest(action=action):
                plan = clean_plan()
                iam = resource(plan, ".aws_iam_role_policy.relay")
                policy = json.loads(iam["change"]["after"]["policy"])
                policy_statement(policy, action)["Condition"] = {
                    "StringEquals": {"aws:SourceAccount": "000000000000"}
                }
                iam["change"]["after"]["policy"] = json.dumps(policy)
                self.assert_violation(plan, f"relay IAM {label} condition changed")

    def test_relay_iam_cloudwatch_namespace_is_pinned(self) -> None:
        plan = clean_plan()
        iam = resource(plan, ".aws_iam_role_policy.relay")
        policy = json.loads(iam["change"]["after"]["policy"])
        policy_statement(policy, "cloudwatch:PutMetricData")["Condition"][
            "StringEquals"
        ]["cloudwatch:namespace"] = "Unreviewed"
        iam["change"]["after"]["policy"] = json.dumps(policy)
        self.assert_violation(plan, "bootstrap metric write condition changed")

    def test_relay_iam_statement_keys_are_exact(self) -> None:
        for key, value in (
            ("Principal", "*"),
            ("NotResource", "arn:aws:secretsmanager:*:*:secret:unreviewed"),
            ("Sid", "UnreviewedMetadata"),
        ):
            with self.subTest(key=key):
                plan = clean_plan()
                iam = resource(plan, ".aws_iam_role_policy.relay")
                policy = json.loads(iam["change"]["after"]["policy"])
                policy_statement(policy, "secretsmanager:GetSecretValue")[key] = value
                iam["change"]["after"]["policy"] = json.dumps(policy)
                self.assert_violation(
                    plan,
                    "relay IAM Secrets Manager identity read statement shape changed",
                )

    def test_relay_iam_resources_follow_the_exact_planned_arns(self) -> None:
        for suffix, label in (
            (
                '.module.ecr.aws_ecr_repository.main["nhp-relay"]',
                "ECR repository read",
            ),
            (".aws_cloudwatch_log_group.relay", "relay log write"),
            (".aws_ssm_parameter.relay_image_tag[0]", "relay image-tag read"),
        ):
            with self.subTest(resource=suffix):
                plan = clean_plan()
                resource(plan, suffix)["change"]["after"]["arn"] = (
                    "arn:aws:service:us-east-2:767397897469:unreviewed"
                )
                self.assert_violation(
                    plan, f"relay IAM {label} resource allowlist changed"
                )

    def test_relay_iam_action_groups_cannot_be_bundled_or_duplicated(self) -> None:
        for mutation in ("bundle", "duplicate"):
            with self.subTest(mutation=mutation):
                plan = clean_plan()
                iam = resource(plan, ".aws_iam_role_policy.relay")
                policy = json.loads(iam["change"]["after"]["policy"])
                auth = policy_statement(policy, "ecr:GetAuthorizationToken")
                if mutation == "bundle":
                    repository = policy_statement(policy, "ecr:BatchGetImage")
                    auth["Action"] = checker.as_strings(
                        auth["Action"]
                    ) + checker.as_strings(repository["Action"])
                    policy["Statement"].remove(repository)
                else:
                    policy["Statement"].append(copy.deepcopy(auth))
                iam["change"]["after"]["policy"] = json.dumps(policy)
                self.assert_violation(
                    plan, "relay IAM statement action partitions changed"
                )

    def test_relay_kms_viaservice_condition_is_required(self) -> None:
        plan = clean_plan()
        iam = resource(plan, ".aws_iam_role_policy.relay")
        policy = json.loads(iam["change"]["after"]["policy"])
        del policy_statement(policy, "kms:Decrypt")["Condition"]["StringEquals"][
            "kms:ViaService"
        ]
        iam["change"]["after"]["policy"] = json.dumps(policy)
        self.assert_violation(
            plan, "CallerAccount and the regional Secrets Manager ViaService"
        )

    def test_relay_kms_caller_account_is_pinned(self) -> None:
        plan = clean_plan()
        iam = resource(plan, ".aws_iam_role_policy.relay")
        policy = json.loads(iam["change"]["after"]["policy"])
        policy_statement(policy, "kms:Decrypt")["Condition"]["StringEquals"][
            "kms:CallerAccount"
        ] = "000000000000"
        iam["change"]["after"]["policy"] = json.dumps(policy)
        self.assert_violation(plan, "sandbox CallerAccount")

    def test_relay_kms_decrypt_cannot_be_bundled_with_another_statement(self) -> None:
        plan = clean_plan()
        iam = resource(plan, ".aws_iam_role_policy.relay")
        policy = json.loads(iam["change"]["after"]["policy"])
        kms_statement = policy_statement(policy, "kms:Decrypt")
        policy_statement(policy, "secretsmanager:GetSecretValue")["Action"].append(
            "kms:Decrypt"
        )
        policy["Statement"].remove(kms_statement)
        iam["change"]["after"]["policy"] = json.dumps(policy)
        self.assert_violation(plan, "KMS decrypt must be isolated")

    def test_relay_kms_decrypt_rejects_an_extra_action(self) -> None:
        plan = clean_plan()
        iam = resource(plan, ".aws_iam_role_policy.relay")
        policy = json.loads(iam["change"]["after"]["policy"])
        policy_statement(policy, "kms:Decrypt")["Action"].append("kms:DescribeKey")
        iam["change"]["after"]["policy"] = json.dumps(policy)
        self.assert_violation(plan, "KMS decrypt must be isolated")

    def test_relay_kms_decrypt_rejects_an_extra_resource(self) -> None:
        plan = clean_plan()
        iam = resource(plan, ".aws_iam_role_policy.relay")
        policy = json.loads(iam["change"]["after"]["policy"])
        policy_statement(policy, "kms:Decrypt")["Resource"].append(
            f"arn:aws:kms:us-east-2:{checker.EXPECTED_SANDBOX_ACCOUNT_ID}:key/other"
        )
        iam["change"]["after"]["policy"] = json.dumps(policy)
        self.assert_violation(
            plan, "exactly the planned sandbox Secrets Manager KMS key"
        )

    def test_relay_kms_decrypt_rejects_the_wrong_resource(self) -> None:
        plan = clean_plan()
        iam = resource(plan, ".aws_iam_role_policy.relay")
        policy = json.loads(iam["change"]["after"]["policy"])
        policy_statement(policy, "kms:Decrypt")["Resource"] = [
            f"arn:aws:kms:us-east-2:{checker.EXPECTED_SANDBOX_ACCOUNT_ID}:key/other"
        ]
        iam["change"]["after"]["policy"] = json.dumps(policy)
        self.assert_violation(
            plan, "exactly the planned sandbox Secrets Manager KMS key"
        )

    def test_relay_kms_decrypt_must_match_the_planned_key(self) -> None:
        plan = clean_plan()
        key = resource(plan, ".module.kms.aws_kms_key.secrets")
        key["change"]["after"]["arn"] = (
            f"arn:aws:kms:us-east-2:{checker.EXPECTED_SANDBOX_ACCOUNT_ID}:key/other"
        )
        self.assert_violation(
            plan, "exactly the planned sandbox Secrets Manager KMS key"
        )

    def test_relay_kms_decrypt_rejects_duplicate_statements(self) -> None:
        plan = clean_plan()
        iam = resource(plan, ".aws_iam_role_policy.relay")
        policy = json.loads(iam["change"]["after"]["policy"])
        policy["Statement"].append(
            copy.deepcopy(policy_statement(policy, "kms:Decrypt"))
        )
        iam["change"]["after"]["policy"] = json.dumps(policy)
        self.assert_violation(plan, "at most one KMS decrypt statement")

    def test_relay_kms_decrypt_statement_is_optional(self) -> None:
        plan = clean_plan()
        iam = resource(plan, ".aws_iam_role_policy.relay")
        policy = json.loads(iam["change"]["after"]["policy"])
        policy["Statement"].remove(policy_statement(policy, "kms:Decrypt"))
        iam["change"]["after"]["policy"] = json.dumps(policy)
        self.assertEqual([], checker.validate_plan(plan))

    def test_relay_kms_viaservice_condition_is_pinned(self) -> None:
        plan = clean_plan()
        iam = resource(plan, ".aws_iam_role_policy.relay")
        policy = json.loads(iam["change"]["after"]["policy"])
        policy_statement(policy, "kms:Decrypt")["Condition"]["StringEquals"][
            "kms:ViaService"
        ] = "ec2.us-east-2.amazonaws.com"
        iam["change"]["after"]["policy"] = json.dumps(policy)
        self.assert_violation(plan, "regional Secrets Manager ViaService")

    def test_unresolved_relay_iam_policy_uses_config_reference_fallback(self) -> None:
        plan = clean_plan()
        iam = resource(plan, ".aws_iam_role_policy.relay")
        iam["change"]["after"]["policy"] = None
        iam["change"]["after_unknown"]["policy"] = True
        self.assertEqual([], checker.validate_plan(plan))

    def test_unresolved_relay_iam_policy_requires_all_reviewed_inputs(self) -> None:
        for required_ref in checker.EXPECTED_RELAY_IAM_POLICY_REFS:
            with self.subTest(reference=required_ref):
                plan = clean_plan()
                iam = resource(plan, ".aws_iam_role_policy.relay")
                iam["change"]["after"]["policy"] = None
                iam["change"]["after_unknown"]["policy"] = True
                iam_config = configured_resource(
                    plan, "relay", "aws_iam_role_policy", "relay"
                )
                iam_config["expressions"]["policy"]["references"].remove(required_ref)
                self.assert_violation(
                    plan,
                    "unresolved relay IAM policy references changed",
                )

    def test_unresolved_relay_iam_policy_rejects_extra_config_reference(self) -> None:
        plan = clean_plan()
        iam = resource(plan, ".aws_iam_role_policy.relay")
        iam["change"]["after"]["policy"] = None
        iam["change"]["after_unknown"]["policy"] = True
        iam_config = configured_resource(plan, "relay", "aws_iam_role_policy", "relay")
        iam_config["expressions"]["policy"]["references"].append(
            "var.unreviewed_resource_arn"
        )
        self.assert_violation(plan, "unresolved relay IAM policy references changed")

    def test_logs_kms_context_cannot_expand(self) -> None:
        plan = clean_plan()
        key = resource(plan, ".aws_kms_key.logs")
        policy = json.loads(key["change"]["after"]["policy"])
        contexts = policy["Statement"][1]["Condition"]["ArnEquals"][
            "kms:EncryptionContext:aws:logs:arn"
        ]
        contexts.append("arn:aws:logs:us-east-2:767397897469:log-group:*")
        key["change"]["after"]["policy"] = json.dumps(policy)
        self.assert_violation(plan, "exactly the flow and Resolver log groups")

    def test_logs_kms_rejects_unsupported_viaservice_condition(self) -> None:
        plan = clean_plan()
        key = resource(plan, ".aws_kms_key.logs")
        policy = json.loads(key["change"]["after"]["policy"])
        policy["Statement"][1]["Condition"]["StringEquals"] = {
            "kms:ViaService": "logs.us-east-2.amazonaws.com"
        }
        key["change"]["after"]["policy"] = json.dumps(policy)
        self.assert_violation(plan, "only the exact Logs encryption-context")

    def test_logs_kms_administration_is_pinned_to_sandbox_root(self) -> None:
        plan = clean_plan()
        key = resource(plan, ".aws_kms_key.logs")
        policy = json.loads(key["change"]["after"]["policy"])
        policy["Statement"][0]["Principal"] = {"AWS": "arn:aws:iam::000000000000:root"}
        key["change"]["after"]["policy"] = json.dumps(policy)
        self.assert_violation(plan, "pinned to the sandbox account root")

    def test_logs_kms_alias_is_pinned_to_full_sandbox_name(self) -> None:
        plan = clean_plan()
        alias = resource(plan, ".aws_kms_alias.logs")
        alias["change"]["after"]["name"] = "alias/attacker-relay-dmz-logs"
        self.assert_violation(plan, "relay telemetry KMS alias name changed")

    def test_log_group_must_use_dedicated_key(self) -> None:
        for name in ("flow", "resolver"):
            with self.subTest(log_group=name):
                plan = clean_plan()
                log_group = resource(plan, f".aws_cloudwatch_log_group.{name}")
                log_group["change"]["after"]["kms_key_id"] = (
                    "arn:aws:kms:us-east-2:767397897469:key/shared"
                )
                self.assert_violation(plan, "same dedicated KMS key")

    def test_final_preapply_allows_new_log_key_arn_to_remain_unknown(self) -> None:
        plan = clean_plan()
        resolver = resource(plan, ".aws_cloudwatch_log_group.resolver")
        resolver["change"]["after"]["kms_key_id"] = None
        resolver["change"]["after_unknown"]["kms_key_id"] = True

        self.assertEqual([], checker.validate_plan(plan))
        self.assertEqual([], checker.validate_plan(plan, require_pr0_applied=True))

    def test_concrete_null_log_group_kms_key_is_rejected_in_every_mode(
        self,
    ) -> None:
        for name in ("flow", "resolver"):
            for require_pr0_applied in (False, True):
                with self.subTest(
                    log_group=name, require_pr0_applied=require_pr0_applied
                ):
                    plan = clean_plan()
                    log_group = resource(plan, f".aws_cloudwatch_log_group.{name}")
                    log_group["change"]["after"]["kms_key_id"] = None
                    log_group["change"]["after_unknown"].pop("kms_key_id", None)

                    errors = checker.validate_plan(
                        plan, require_pr0_applied=require_pr0_applied
                    )
                    self.assertTrue(
                        any(
                            f"{name} log-group KMS key ID must be concrete or explicitly apply-time unknown"
                            in error
                            for error in errors
                        ),
                        errors,
                    )

    def test_malformed_log_group_after_unknown_shape_fails_closed(self) -> None:
        for name in ("flow", "resolver"):
            for after_unknown in (True, False, "unexpected", [], None):
                with self.subTest(log_group=name, after_unknown=after_unknown):
                    plan = clean_plan()
                    log_group = resource(plan, f".aws_cloudwatch_log_group.{name}")
                    log_group["change"]["after"]["kms_key_id"] = None
                    log_group["change"]["after_unknown"] = after_unknown

                    self.assert_violation(
                        plan,
                        f"{name} log-group KMS key ID must be concrete or explicitly apply-time unknown",
                    )

    def test_both_unknown_log_group_keys_require_exact_config_references(
        self,
    ) -> None:
        for redirected_name in ("flow", "resolver"):
            with self.subTest(redirected_log_group=redirected_name):
                plan = clean_plan()
                for name in ("flow", "resolver"):
                    log_group = resource(plan, f".aws_cloudwatch_log_group.{name}")
                    log_group["change"]["after"]["kms_key_id"] = None
                    log_group["change"]["after_unknown"]["kms_key_id"] = True

                self.assertEqual([], checker.validate_plan(plan))
                self.assertEqual(
                    [], checker.validate_plan(plan, require_pr0_applied=True)
                )

                log_group_config = configured_resource(
                    plan,
                    "relay_network",
                    "aws_cloudwatch_log_group",
                    redirected_name,
                )
                log_group_config["expressions"]["kms_key_id"]["references"] = [
                    "aws_kms_key.unreviewed.arn"
                ]
                expected = f"{redirected_name} log group must use the dedicated relay logs KMS key"
                self.assert_violation(plan, expected)
                errors = checker.validate_plan(plan, require_pr0_applied=True)
                self.assertTrue(
                    any(expected in error for error in errors),
                    errors,
                )

    def test_flow_logs_describe_groups_must_use_wildcard_resource(self) -> None:
        plan = clean_plan()
        role_policy = resource(plan, ".aws_iam_role_policy.flow")
        policy = json.loads(role_policy["change"]["after"]["policy"])
        policy["Statement"][0]["Resource"] = (
            "arn:aws:logs:us-east-2:767397897469:log-group:/layerv/nhp/sandbox/relay-dmz/flow"
        )
        role_policy["change"]["after"]["policy"] = json.dumps(policy)
        self.assert_violation(plan, "DescribeLogGroups must use Resource=*")

    def test_flow_logs_policy_rejects_extra_statement(self) -> None:
        plan = clean_plan()
        role_policy = resource(plan, ".aws_iam_role_policy.flow")
        policy = json.loads(role_policy["change"]["after"]["policy"])
        policy["Statement"].append(
            {
                "Sid": "ExtraFlowAccess",
                "Effect": "Allow",
                "Action": "logs:GetLogEvents",
                "Resource": "*",
            }
        )
        role_policy["change"]["after"]["policy"] = json.dumps(policy)
        self.assert_violation(plan, "exactly the three action-scoped statements")

    def test_flow_logs_policy_rejects_duplicate_reviewed_sid(self) -> None:
        plan = clean_plan()
        role_policy = resource(plan, ".aws_iam_role_policy.flow")
        policy = json.loads(role_policy["change"]["after"]["policy"])
        # Insert before the canonical statement: index_by_sid then retains the
        # safe final value, proving the separate raw-cardinality guard is what
        # rejects this broad duplicate-Sid grant.
        policy["Statement"].insert(
            2,
            {
                "Sid": "WriteFlowLogStreams",
                "Effect": "Allow",
                "Action": "logs:*",
                "Resource": "*",
            },
        )
        role_policy["change"]["after"]["policy"] = json.dumps(policy)
        self.assert_violation(plan, "exactly the three action-scoped statements")

    def test_flow_logs_describe_streams_requires_exact_group_arn(self) -> None:
        plan = clean_plan()
        role_policy = resource(plan, ".aws_iam_role_policy.flow")
        policy = json.loads(role_policy["change"]["after"]["policy"])
        group_arn = checker.EXPECTED_SANDBOX_DMZ_FLOW_LOG_GROUP_ARN
        policy["Statement"][1]["Resource"] = f"{group_arn}:*"
        role_policy["change"]["after"]["policy"] = json.dumps(policy)
        self.assert_violation(
            plan, "DescribeLogStreams must use the exact log-group ARN"
        )

    def test_flow_logs_write_streams_requires_stream_arn(self) -> None:
        plan = clean_plan()
        role_policy = resource(plan, ".aws_iam_role_policy.flow")
        policy = json.loads(role_policy["change"]["after"]["policy"])
        policy["Statement"][2]["Resource"] = (
            checker.EXPECTED_SANDBOX_DMZ_FLOW_LOG_GROUP_ARN
        )
        role_policy["change"]["after"]["policy"] = json.dumps(policy)
        self.assert_violation(
            plan, "stream writes must use only the dedicated log-stream ARN wildcard"
        )

    def test_flow_log_format_order_is_exact(self) -> None:
        plan = clean_plan()
        flow = resource(plan, ".aws_flow_log.relay")
        fields = flow["change"]["after"]["log_format"].split()
        fields[0], fields[1] = fields[1], fields[0]
        flow["change"]["after"]["log_format"] = " ".join(fields)
        self.assert_violation(plan, "exact ALL-traffic 60s forensic field order")

    def test_flow_logs_trust_requires_source_account_and_arn(self) -> None:
        plan = clean_plan()
        role = resource(plan, ".aws_iam_role.flow")
        policy = json.loads(role["change"]["after"]["assume_role_policy"])
        del policy["Statement"][0]["Condition"]["ArnLike"]
        role["change"]["after"]["assume_role_policy"] = json.dumps(policy)
        self.assert_violation(plan, "trust must be scoped")

    def test_extra_legacy_security_group_rule_is_rejected(self) -> None:
        plan = clean_plan()
        plan["resource_changes"].append(
            {
                "address": "module.nhp.module.relay[0].aws_security_group_rule.internet_egress",
                "mode": "managed",
                "type": "aws_security_group_rule",
                "name": "internet_egress",
                "change": {
                    "actions": ["create"],
                    "before": None,
                    "after": {"type": "egress", "cidr_blocks": ["0.0.0.0/0"]},
                    "after_unknown": {},
                },
            }
        )
        self.assert_violation(plan, "legacy standalone")

    def test_every_relay_root_route53_record_is_registered_durable(self) -> None:
        """Every relay DNS record in the root must be in the durable registry.

        test_durable_relay_resources_cannot_be_destroyed_or_replaced iterates
        DURABLE_RELAY_RESOURCES, so it cannot notice a resource that was never
        added — deleting an entry there just yields one fewer subtest and still
        passes. This asserts the other direction: the registry is derived from
        the Terraform, so a new relay route53 record (for instance a
        cross-account twin) fails here until it is registered, rather than
        silently becoming an unguarded participant the contract will reject at
        plan time in whichever environment happens to instantiate it.
        """
        control_plane = (
            REPO_ROOT / "terraform" / "relay_control_plane.tf"
        ).read_text(encoding="utf-8")
        declared = set(
            re.findall(
                r'resource\s+"aws_route53_record"\s+"([a-z0-9_]+)"', control_plane
            )
        )
        self.assertTrue(declared, "no relay route53 records found in the root")

        registered = {
            name
            for (resource_type, name) in checker.DURABLE_RELAY_RESOURCES
            if resource_type == "aws_route53_record"
        }
        self.assertEqual(
            declared - registered,
            set(),
            "relay route53 records declared in relay_control_plane.tf but absent "
            "from DURABLE_RELAY_RESOURCES",
        )

    def test_durable_relay_resources_cannot_be_destroyed_or_replaced(self) -> None:
        for index, ((resource_type, name), relative_parent) in enumerate(
            checker.DURABLE_RELAY_RESOURCES.items()
        ):
            with self.subTest(resource_type=resource_type, name=name):
                plan = clean_plan()
                actions = (
                    ["forget"]
                    if index % 3 == 2
                    else (["delete"] if index % 2 else ["delete", "create"])
                )
                instance_key = "[0]" if index % 2 else ""
                parent = checker.child_module_prefix("module.nhp", relative_parent)
                plan["resource_changes"].append(
                    {
                        "address": f"{parent}.{resource_type}.{name}{instance_key}",
                        "mode": "managed",
                        "type": resource_type,
                        "name": name,
                        "change": {
                            "actions": actions,
                            "before": {"id": "durable"},
                            "after": {"id": "replacement"}
                            if "create" in actions
                            else None,
                            "after_unknown": {},
                        },
                    }
                )
                self.assert_violation(
                    plan, "must not be destroyed, replaced, or forgotten"
                )

    def test_durable_guards_follow_root_nested_and_counted_topologies(self) -> None:
        layouts = (
            ("root", root_level_plan),
            ("nested", clean_plan),
            ("counted", counted_parent_plan),
        )
        for layout, factory in layouts:
            for action in ("delete", "forget"):
                with self.subTest(layout=layout, action=action):
                    plan = factory()
                    secret = resource(plan, ".aws_secretsmanager_secret.relay")
                    secret["change"].update(
                        {
                            "actions": [action],
                            "before": {"id": "durable"},
                            "after": None,
                        }
                    )
                    self.assert_violation(
                        plan, "must not be destroyed, replaced, or forgotten"
                    )

    def test_allow_disabled_still_guards_every_durable_resource(self) -> None:
        layouts = ("", "module.nhp", "module.wrapper[0].module.nhp")
        guarded = list(checker.DURABLE_RELAY_RESOURCES.items())
        for parent in layouts:
            for index, ((resource_type, name), relative_parent) in enumerate(guarded):
                with self.subTest(
                    parent=parent or "root", resource=f"{resource_type}.{name}"
                ):
                    identity_parent = checker.child_module_prefix(
                        parent, checker.DURABLE_RELAY_IDENTITY_PARENT
                    )
                    durable_parent = checker.child_module_prefix(
                        parent, relative_parent
                    )
                    plan: dict[str, Any] = {
                        "configuration": {"root_module": {}},
                        "resource_changes": [],
                    }
                    if relative_parent == checker.DURABLE_RELAY_ROOT_PARENT and parent:
                        plan["resource_changes"].append(
                            {
                                "address": f"{identity_parent}.aws_secretsmanager_secret.relay",
                                "mode": "managed",
                                "type": "aws_secretsmanager_secret",
                                "name": "relay",
                                "change": {
                                    "actions": ["no-op"],
                                    "before": {"id": "identity-anchor"},
                                    "after": {"id": "identity-anchor"},
                                    "after_unknown": {},
                                },
                            }
                        )
                    resource_address = (
                        f"{durable_parent}.{resource_type}.{name}"
                        if durable_parent
                        else f"{resource_type}.{name}"
                    )
                    plan["resource_changes"].append(
                        {
                            "address": resource_address,
                            "mode": "managed",
                            "type": resource_type,
                            "name": name,
                            "change": {
                                # Alternate across the inventory so both destructive
                                # action paths stay covered without duplicating cases.
                                "actions": ["forget" if index % 2 else "delete"],
                                "before": {"id": "durable"},
                                "after": None,
                                "after_unknown": {},
                            },
                        }
                    )
                    self.assert_violation(
                        plan,
                        "must not be destroyed, replaced, or forgotten",
                        require_enabled=False,
                    )

    def test_allow_disabled_ignores_unrelated_same_named_resource(self) -> None:
        plan = {
            "configuration": {"root_module": {}},
            "resource_changes": [
                {
                    "address": "module.unrelated.aws_secretsmanager_secret.relay",
                    "mode": "managed",
                    "type": "aws_secretsmanager_secret",
                    "name": "relay",
                    "change": {
                        "actions": ["delete"],
                        "before": {"id": "unrelated"},
                        "after": None,
                        "after_unknown": {},
                    },
                }
            ],
        }
        self.assertEqual([], checker.validate_plan(plan, require_enabled=False))

    def test_unrelated_same_named_resource_is_not_treated_as_relay_durable(
        self,
    ) -> None:
        layouts = (
            ("root", "", root_level_plan),
            ("nested", "module.nhp", clean_plan),
            ("counted", "module.wrapper[0].module.nhp", counted_parent_plan),
        )
        for layout, parent, factory in layouts:
            with self.subTest(layout=layout):
                plan = factory()
                bootstrap_parent = checker.child_module_prefix(
                    parent, "module.bootstrap_alb[0]"
                )
                plan["resource_changes"].append(
                    {
                        "address": f"{bootstrap_parent}.aws_s3_bucket.alb_access_logs",
                        "mode": "managed",
                        "type": "aws_s3_bucket",
                        "name": "alb_access_logs",
                        "change": {
                            "actions": ["delete"],
                            "before": {"id": "unrelated"},
                            "after": None,
                            "after_unknown": {},
                        },
                    }
                )
                self.assertEqual([], checker.validate_plan(plan))

    def test_preapply_gate_rejects_pending_pr0_state_moves(self) -> None:
        plan = clean_plan()
        image_tag = resource(plan, ".aws_ssm_parameter.relay_image_tag[0]")
        image_tag["previous_address"] = (
            "module.nhp.module.relay[0].aws_ssm_parameter.image_tag"
        )
        image_tag["change"]["actions"] = ["no-op"]
        image_tag["change"]["before"] = copy.deepcopy(image_tag["change"]["after"])
        self.assertEqual([], checker.validate_plan(plan))
        errors = checker.validate_plan(plan, require_pr0_applied=True)
        self.assertTrue(
            any("PR 0 state move" in error for error in errors),
            errors,
        )

    def test_pr0_relay_moves_all_originate_in_old_relay_module(self) -> None:
        # Deliberate cross-PR fence: PR0 owns this file, but any move count or
        # source change must update the DMZ replacement contract in this stack.
        source = (REPO_ROOT / "terraform" / "relay_control_plane.tf").read_text(
            encoding="utf-8"
        )
        moved_sources = re.findall(r"(?m)^\s*from = ([^\n]+)$", source)
        self.assertEqual(13, len(moved_sources), moved_sources)
        self.assertEqual(13, source.count("moved {"))
        self.assertTrue(
            all(item.startswith("module.relay[0].") for item in moved_sources),
            moved_sources,
        )

        drifted_source = source.replace(
            "from = module.relay[0].",
            "from = module.relay_network[0].",
            1,
        )
        drifted_sources = re.findall(r"(?m)^\s*from = ([^\n]+)$", drifted_source)
        self.assertFalse(
            all(item.startswith("module.relay[0].") for item in drifted_sources)
        )

    def test_disabled_plan_can_be_explicitly_allowed(self) -> None:
        plan = {"resource_changes": [], "configuration": {"root_module": {}}}
        self.assertEqual([], checker.validate_plan(plan, require_enabled=False))
        self.assertTrue(checker.validate_plan(plan, require_enabled=True))

    def test_allow_disabled_still_validates_an_enabled_https_relay(self) -> None:
        plan = clean_plan()
        self.assertEqual([], checker.validate_plan(plan, require_enabled=False))
        result = run_checker_cli(plan, "--allow-disabled")
        self.assertEqual(0, result.returncode, result.stderr)

    def test_cli_requires_integrated_dmz_unless_caller_is_explicitly_relay_dark(
        self,
    ) -> None:
        plan = {"resource_changes": [], "configuration": {"root_module": {}}}
        required = run_checker_cli(plan)
        self.assertEqual(1, required.returncode, required.stderr)
        self.assertIn("relay DMZ is not present", required.stderr)

        relay_dark = run_checker_cli(plan, "--allow-disabled")
        self.assertEqual(0, relay_dark.returncode, relay_dark.stderr)

    def test_cli_rejects_partial_sandbox_contract_overrides(self) -> None:
        for flag, value in (
            ("--expected-account-id", "000000000000"),
            ("--expected-region", "us-west-2"),
            ("--expected-vpc-cidr", "10.102.0.0/16"),
        ):
            with self.subTest(flag=flag):
                result = run_checker_cli(clean_plan(), flag, value)
                self.assertEqual(2, result.returncode, result.stderr)
                self.assertIn("unrecognized arguments", result.stderr)

    def test_cli_rejects_disabled_final_preapply_mode(self) -> None:
        result = run_checker_cli(
            {"resource_changes": [], "configuration": {"root_module": {}}},
            "--allow-disabled",
            "--require-pr0-applied",
        )
        self.assertEqual(2, result.returncode, result.stderr)
        self.assertIn(
            "--allow-disabled and --require-pr0-applied are mutually exclusive",
            result.stderr,
        )
        self.assertNotIn("Traceback", result.stderr)

    def test_cli_reserves_pr0_convergence_for_final_preapply_mode(self) -> None:
        plan = clean_plan()
        image_tag = resource(plan, ".aws_ssm_parameter.relay_image_tag[0]")
        image_tag["previous_address"] = (
            "module.nhp.module.relay[0].aws_ssm_parameter.image_tag"
        )
        image_tag["change"]["actions"] = ["no-op"]
        image_tag["change"]["before"] = copy.deepcopy(image_tag["change"]["after"])
        pr_time = run_checker_cli(plan)
        self.assertEqual(0, pr_time.returncode, pr_time.stderr)

        preapply = run_checker_cli(plan, "--require-pr0-applied")
        self.assertEqual(1, preapply.returncode, preapply.stderr)
        self.assertIn("PR 0 state move", preapply.stderr)

    def test_cli_reserves_boundary_changes_for_new_migration_path(self) -> None:
        plan = boundary_noop_plan()
        converged = run_checker_cli(
            plan, "--require-pr0-applied", "--require-dmz-boundary-noop"
        )
        self.assertEqual(0, converged.returncode, converged.stderr)

        vpc = resource(plan, ".module.relay_network[0].aws_vpc.relay")
        vpc["change"]["actions"] = ["update"]
        blocked = run_checker_cli(
            plan, "--require-pr0-applied", "--require-dmz-boundary-noop"
        )
        self.assertEqual(1, blocked.returncode, blocked.stderr)
        self.assertIn("automatic apply refuses", blocked.stderr)
        self.assertIn("newly reviewed temporary migration path", blocked.stderr)

    def test_cli_boundary_noop_gate_operates_without_pr0_convergence_gate(self) -> None:
        plan = boundary_noop_plan()
        vpc = resource(plan, ".module.relay_network[0].aws_vpc.relay")
        vpc["change"]["actions"] = ["update"]

        blocked = run_checker_cli(plan, "--require-dmz-boundary-noop")

        self.assertEqual(1, blocked.returncode, blocked.stderr)
        self.assertIn("automatic apply refuses", blocked.stderr)
        self.assertIn("newly reviewed temporary migration path", blocked.stderr)
        self.assertNotIn("PR 0 state move", blocked.stderr)

    def test_cli_source_fence_allowance_requires_boundary_gate(self) -> None:
        result = run_checker_cli(
            source_fenced_plan(), "--allow-udp-source-fence-replacement"
        )
        self.assertEqual(2, result.returncode, result.stderr)
        self.assertIn(
            "--allow-udp-source-fence-replacement requires "
            "--require-dmz-boundary-noop",
            result.stderr,
        )
        self.assertNotIn("Traceback", result.stderr)

    def test_cli_fenced_topology_gate_is_steady_state_only(self) -> None:
        converged = source_fenced_plan()
        for change in converged["resource_changes"]:
            if not checker.is_dmz_boundary_address(change["address"]):
                continue
            change["change"]["actions"] = ["no-op"]
            change["change"]["before"] = copy.deepcopy(change["change"]["after"])

        result = run_checker_cli(
            converged,
            "--require-dmz-boundary-noop",
            "--require-udp-source-fenced-topology",
        )
        self.assertEqual(0, result.returncode, result.stderr)

        legacy_mode = run_checker_cli(
            converged,
            "--require-dmz-boundary-noop",
        )
        self.assertEqual(1, legacy_mode.returncode, legacy_mode.stderr)

        migration_without_allowance = run_checker_cli(
            source_fence_migration_plan(),
            "--require-dmz-boundary-noop",
            "--require-udp-source-fenced-topology",
        )
        self.assertEqual(
            1, migration_without_allowance.returncode, migration_without_allowance.stderr
        )
        self.assertIn("automatic apply refuses", migration_without_allowance.stderr)

    def test_cli_source_fence_allowance_accepts_only_complete_migration(
        self,
    ) -> None:
        plan = source_fence_migration_plan()
        result = run_checker_cli(
            plan,
            "--require-dmz-boundary-noop",
            "--allow-udp-source-fence-replacement",
        )
        self.assertEqual(0, result.returncode, result.stderr)

        listener = resource(plan, ".aws_lb_listener.udp[0]")
        listener["change"]["actions"] = ["create", "delete"]
        blocked = run_checker_cli(
            plan,
            "--require-dmz-boundary-noop",
            "--allow-udp-source-fence-replacement",
        )
        self.assertEqual(1, blocked.returncode, blocked.stderr)
        self.assertIn("unreviewed UDP source-fence", blocked.stderr)
        self.assertIn("bounded remaining subset", blocked.stderr)


if __name__ == "__main__":
    unittest.main()
