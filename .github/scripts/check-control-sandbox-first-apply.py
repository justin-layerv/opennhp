#!/usr/bin/env python3
"""Fail-closed contracts for the sandbox Connector Control first apply."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
import sys
import time
from pathlib import Path
from typing import Any, Callable, Iterable


ACCOUNT_ID = "767397897469"
AWS_REGION = "us-east-2"
REPOSITORY = "layervai/nhp"
ROLE_NAME = "nhp-sandbox-github-actions"
ROLE_ARN = f"arn:aws:iam::{ACCOUNT_ID}:role/{ROLE_NAME}"
POLICY_ARN = (
    f"arn:aws:iam::{ACCOUNT_ID}:policy/nhp-sandbox-github-actions-terraform-apply-data"
)
STATE_BUCKET = f"layerv-terraform-state-{ACCOUNT_ID}"
STATE_KEY = "nhp/sandbox/control/terraform.tfstate"
STATE_LOCK_KEY = f"{STATE_KEY}.tflock"
STATE_KMS_KEY_ARN = (
    "arn:aws:kms:us-east-2:767397897469:key/289dbe35-ab5a-4752-8564-4c96c607c9f4"
)
# Locked to the first-apply workflow by the boundary regression test.
TF_VERSION = "1.14.3"
WORKFLOW_PATH = ".github/workflows/control-sandbox-first-apply.yml"
WORKFLOW_NAME = "Control Sandbox First Apply"
TRUSTED_ACTOR = "justin-layerv"
PLAN_MAX_AGE_SECONDS = 2 * 24 * 60 * 60
CONTROL_PREFIX = "layerv-nhp-sandbox-control"
FAILED_APPLY_RUN_ID = "29673343567"
FAILED_APPLY_COMMIT = "09cc08eba8a481a49423baa422bfd131f0b11c89"
PARTIAL_STATE_LINEAGE = "e6aaf0d7-f880-87a6-1dbd-2fe4f819ff7f"
PARTIAL_STATE_SERIAL = 3
PARTIAL_STATE_SHA256 = (
    "00cfe940ad381cd0902d1ce9065bbe7bf0eaba829f8da05a7f388e511241d414"
)
PARTIAL_STATE_VERSION_ID = "Pm51vLOThwP.wQw.3U.VDisYbUOulo09"
PARTIAL_STATE_ETAG = '"6076f9d3bcaa993869612a2a57d59517"'
PARTIAL_STATE_CONTENT_LENGTH = 134776
_DYNAMODB_TABLES = (
    "agent_keys",
    "api_key_idempotency",
    "api_keys",
    "connector_authority",
    "customers",
)

EXPECTED_RESOURCES = {
    "module.control.aws_cloudwatch_log_group.flow_logs": "aws_cloudwatch_log_group",
    "module.control.aws_default_security_group.control": "aws_default_security_group",
    "module.control.aws_dynamodb_table.agent_keys": "aws_dynamodb_table",
    "module.control.aws_dynamodb_table.api_key_idempotency": "aws_dynamodb_table",
    "module.control.aws_dynamodb_table.api_keys": "aws_dynamodb_table",
    "module.control.aws_dynamodb_table.connector_authority": "aws_dynamodb_table",
    "module.control.aws_dynamodb_table.customers": "aws_dynamodb_table",
    "module.control.aws_ecr_repository.authority": "aws_ecr_repository",
    "module.control.aws_elasticache_serverless_cache.otp": "aws_elasticache_serverless_cache",
    "module.control.aws_elasticache_user.otp_authority": "aws_elasticache_user",
    "module.control.aws_elasticache_user.otp_disabled_default": "aws_elasticache_user",
    "module.control.aws_elasticache_user_group.otp": "aws_elasticache_user_group",
    "module.control.aws_flow_log.control": "aws_flow_log",
    "module.control.aws_iam_role.flow_logs": "aws_iam_role",
    "module.control.aws_iam_role_policy.flow_logs": "aws_iam_role_policy",
    "module.control.aws_kms_alias.authority_data": "aws_kms_alias",
    "module.control.aws_kms_alias.qat1_signing": "aws_kms_alias",
    "module.control.aws_kms_key.authority_data": "aws_kms_key",
    "module.control.aws_kms_key.qat1_signing": "aws_kms_key",
    "module.control.aws_route_table.isolated[0]": "aws_route_table",
    "module.control.aws_route_table.isolated[1]": "aws_route_table",
    "module.control.aws_route_table.isolated[2]": "aws_route_table",
    "module.control.aws_route_table_association.isolated[0]": "aws_route_table_association",
    "module.control.aws_route_table_association.isolated[1]": "aws_route_table_association",
    "module.control.aws_route_table_association.isolated[2]": "aws_route_table_association",
    "module.control.aws_secretsmanager_secret.otp_pepper": "aws_secretsmanager_secret",
    "module.control.aws_security_group.interface_endpoints": "aws_security_group",
    "module.control.aws_security_group.otp_redis": "aws_security_group",
    "module.control.aws_ssm_parameter.authority_image_digest": "aws_ssm_parameter",
    "module.control.aws_subnet.isolated[0]": "aws_subnet",
    "module.control.aws_subnet.isolated[1]": "aws_subnet",
    "module.control.aws_subnet.isolated[2]": "aws_subnet",
    "module.control.aws_vpc.control": "aws_vpc",
    "module.control.aws_vpc_endpoint.dynamodb": "aws_vpc_endpoint",
    'module.control.aws_vpc_endpoint.interface["email"]': "aws_vpc_endpoint",
    'module.control.aws_vpc_endpoint.interface["kms"]': "aws_vpc_endpoint",
    'module.control.aws_vpc_endpoint.interface["lambda"]': "aws_vpc_endpoint",
    'module.control.aws_vpc_endpoint.interface["logs"]': "aws_vpc_endpoint",
    'module.control.aws_vpc_endpoint.interface["monitoring"]': "aws_vpc_endpoint",
    'module.control.aws_vpc_endpoint.interface["secretsmanager"]': "aws_vpc_endpoint",
    "module.control.terraform_data.foundation_contract": "terraform_data",
}

CONTROL_ACTIONS = (
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
)
# The shared Terraform read policy intentionally grants ElastiCache Describe*
# and List* account-wide so Terraform can refresh all managed cache resources.
# The Control boundary is therefore write confinement, not read concealment:
# cell-scoped writes must remain denied while these three reads remain allowed.
# The exact read allow is operational too: Terraform refresh needs this reviewed
# visibility, so a future narrowing must be reviewed instead of silently passing.
CONTROL_READ_ACTIONS = (
    "elasticache:DescribeUsers",
    "elasticache:DescribeUserGroups",
    "elasticache:ListTagsForResource",
)
CONTROL_WRITE_ACTIONS = tuple(
    action for action in CONTROL_ACTIONS if action not in CONTROL_READ_ACTIONS
)
CONTROL_RESOURCES = (
    f"arn:aws:elasticache:{AWS_REGION}:{ACCOUNT_ID}:user:{CONTROL_PREFIX}-otp-auth",
    f"arn:aws:elasticache:{AWS_REGION}:{ACCOUNT_ID}:usergroup:{CONTROL_PREFIX}-otp-users",
)
SERVERLESS_CACHE_ACTIONS = (
    "elasticache:CreateServerlessCache",
    "elasticache:DeleteServerlessCache",
    "elasticache:ModifyServerlessCache",
    "elasticache:DescribeServerlessCaches",
    "elasticache:ListTagsForResource",
    "elasticache:AddTagsToResource",
    "elasticache:RemoveTagsFromResource",
    "elasticache:CreateCacheSubnetGroup",
    "elasticache:DeleteCacheSubnetGroup",
    "elasticache:ModifyCacheSubnetGroup",
    "elasticache:DescribeCacheSubnetGroups",
)
CACHE_DEPENDENCY_ACTIONS = (
    "elasticache:CreateServerlessCache",
    "elasticache:ModifyServerlessCache",
)
CONTROL_CACHE_RESOURCE = (
    f"arn:aws:elasticache:{AWS_REGION}:{ACCOUNT_ID}:serverlesscache:{CONTROL_PREFIX}-otp"
)
CONTROL_CACHE_USER_GROUP_RESOURCE = (
    f"arn:aws:elasticache:{AWS_REGION}:{ACCOUNT_ID}:usergroup:{CONTROL_PREFIX}-otp-users"
)
CELL_CACHE_USER_GROUP_RESOURCE = (
    f"arn:aws:elasticache:{AWS_REGION}:{ACCOUNT_ID}:usergroup:layerv-nhp-sandbox-cell0-forbidden"
)
CELL_RESOURCES = (
    f"arn:aws:elasticache:{AWS_REGION}:{ACCOUNT_ID}:user:layerv-nhp-sandbox-cell0-forbidden",
    f"arn:aws:elasticache:{AWS_REGION}:{ACCOUNT_ID}:usergroup:layerv-nhp-sandbox-cell0-forbidden",
)
INTERFACE_ENDPOINT_SERVICES = (
    "email",
    "kms",
    "lambda",
    "logs",
    "monitoring",
    "secretsmanager",
)
EXPECTED_CONTROL_STATEMENT = {
    "Sid": "ElastiCacheControlRBAC",
    "Effect": "Allow",
    "Action": list(CONTROL_ACTIONS),
    "Resource": [
        f"arn:aws:elasticache:{AWS_REGION}:{ACCOUNT_ID}:user:{CONTROL_PREFIX}-*",
        f"arn:aws:elasticache:{AWS_REGION}:{ACCOUNT_ID}:usergroup:{CONTROL_PREFIX}-*",
    ],
}
EXPECTED_SERVERLESS_CACHE_STATEMENT = {
    "Sid": "ElastiCache",
    "Effect": "Allow",
    "Action": list(SERVERLESS_CACHE_ACTIONS),
    "Resource": [
        f"arn:aws:elasticache:{AWS_REGION}:{ACCOUNT_ID}:serverlesscache:layerv-nhp-*",
        f"arn:aws:elasticache:{AWS_REGION}:{ACCOUNT_ID}:subnetgroup:layerv-nhp-*",
    ],
}
EXPECTED_CACHE_DEPENDENCY_STATEMENT = {
    "Sid": "ElastiCacheControlCacheUserGroupDependency",
    "Effect": "Allow",
    "Action": [
        "elasticache:CreateServerlessCache",
        "elasticache:ModifyServerlessCache",
    ],
    "Resource": [
        f"arn:aws:elasticache:{AWS_REGION}:{ACCOUNT_ID}:usergroup:{CONTROL_PREFIX}-otp-users"
    ],
}

ARTIFACT_KEYS = {
    "account_id",
    "backend_bucket",
    "backend_key",
    "commit_sha",
    "contract_sha256",
    "plan_json_sha256",
    "plan_sha256",
    "planned_at_epoch",
    "repository",
    "run_attempt",
    "run_id",
    "state_kms_key_arn",
    "terraform_version",
    "workflow_ref",
}
RECOVERY_ARTIFACT_KEYS = ARTIFACT_KEYS | {
    "failed_apply_commit",
    "failed_apply_run_id",
    "plan_mode",
    "state_content_length",
    "state_etag",
    "state_lineage",
    "state_serial",
    "state_sha256",
    "state_version_id",
}
EXPECTED_DATA_RESOURCES = {
    "module.control.data.aws_availability_zones.available": "aws_availability_zones",
    "module.control.data.aws_caller_identity.current": "aws_caller_identity",
    "module.control.data.aws_partition.current": "aws_partition",
    "module.control.data.aws_region.current": "aws_region",
}

DENY_ENDPOINT_POLICY = {
    "Statement": [
        {
            "Action": "*",
            "Effect": "Deny",
            "Principal": "*",
            "Resource": "*",
            "Sid": "DenyUntilAuthorityRuntimeExists",
        }
    ],
    "Version": "2012-10-17",
}
FLOW_LOG_INLINE_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "DiscoverFlowLogGroups",
            "Effect": "Allow",
            "Action": "logs:DescribeLogGroups",
            "Resource": "*",
        },
        {
            "Sid": "DescribeFlowLogStreams",
            "Effect": "Allow",
            "Action": "logs:DescribeLogStreams",
            "Resource": f"arn:aws:logs:{AWS_REGION}:{ACCOUNT_ID}:log-group:/layerv/nhp/sandbox/control/vpc-flow-logs:*",
        },
        {
            "Sid": "WriteFlowLogStreams",
            "Effect": "Allow",
            "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
            "Resource": f"arn:aws:logs:{AWS_REGION}:{ACCOUNT_ID}:log-group:/layerv/nhp/sandbox/control/vpc-flow-logs:*",
        },
    ],
}
ACCOUNT_KMS_STATEMENT = {
    "Action": "kms:*",
    "Effect": "Allow",
    "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT_ID}:root"},
    "Resource": "*",
    "Sid": "EnableAccountIAM",
}
AUTHORITY_DATA_KMS_POLICY = {
    "Statement": [
        ACCOUNT_KMS_STATEMENT,
        {
            "Action": [
                "kms:Decrypt",
                "kms:DescribeKey",
                "kms:Encrypt",
                "kms:GenerateDataKey*",
                "kms:ReEncrypt*",
            ],
            "Condition": {
                "ArnEquals": {
                    "kms:EncryptionContext:aws:logs:arn": (
                        f"arn:aws:logs:{AWS_REGION}:{ACCOUNT_ID}:"
                        "log-group:/layerv/nhp/sandbox/control/vpc-flow-logs"
                    )
                }
            },
            "Effect": "Allow",
            "Principal": {"Service": f"logs.{AWS_REGION}.amazonaws.com"},
            "Resource": "*",
            "Sid": "AllowControlFlowLogs",
        },
    ],
    "Version": "2012-10-17",
}
QAT1_SIGNING_KMS_POLICY = {
    "Statement": [ACCOUNT_KMS_STATEMENT],
    "Version": "2012-10-17",
}

EXPECTED_CONFIGURATION_RESOURCES: dict[str, tuple[str, str, str]] = {}
for _address, _resource_type in EXPECTED_RESOURCES.items():
    _configuration_address = re.sub(r"\[[^]]+\]", "", _address)
    _provider_config_key = (
        "module.control:terraform" if _resource_type == "terraform_data" else "aws"
    )
    _existing = EXPECTED_CONFIGURATION_RESOURCES.setdefault(
        _configuration_address,
        ("managed", _resource_type, _provider_config_key),
    )
    if _existing != ("managed", _resource_type, _provider_config_key):
        raise RuntimeError(
            f"inconsistent configuration resource type for {_configuration_address}"
        )
EXPECTED_CONFIGURATION_RESOURCES.update(
    {
        "module.control.data.aws_availability_zones.available": (
            "data",
            "aws_availability_zones",
            "aws",
        ),
        "module.control.data.aws_caller_identity.current": (
            "data",
            "aws_caller_identity",
            "aws",
        ),
        "module.control.data.aws_partition.current": (
            "data",
            "aws_partition",
            "aws",
        ),
        "module.control.data.aws_region.current": ("data", "aws_region", "aws"),
    }
)

ExpressionPath = tuple[str | int, ...]
CONFIG_REFERENCE_CONTRACT: dict[str, dict[ExpressionPath, list[str]]] = {
    "module.control.aws_vpc.control": {
        ("cidr_block",): ["var.vpc_cidr"],
    },
    "module.control.aws_default_security_group.control": {
        ("vpc_id",): ["aws_vpc.control.id", "aws_vpc.control"],
    },
    "module.control.aws_security_group.interface_endpoints": {
        ("vpc_id",): ["aws_vpc.control.id", "aws_vpc.control"],
    },
    "module.control.aws_security_group.otp_redis": {
        ("vpc_id",): ["aws_vpc.control.id", "aws_vpc.control"],
    },
    "module.control.aws_subnet.isolated": {
        ("availability_zone",): ["local.availability_zones", "count.index"],
        ("cidr_block",): ["var.vpc_cidr", "count.index"],
        ("vpc_id",): ["aws_vpc.control.id", "aws_vpc.control"],
    },
    "module.control.aws_route_table.isolated": {
        ("vpc_id",): ["aws_vpc.control.id", "aws_vpc.control"],
    },
    "module.control.aws_route_table_association.isolated": {
        ("route_table_id",): ["aws_route_table.isolated", "count.index"],
        ("subnet_id",): ["aws_subnet.isolated", "count.index"],
    },
    "module.control.aws_vpc_endpoint.dynamodb": {
        ("route_table_ids",): ["aws_route_table.isolated"],
        ("vpc_id",): ["aws_vpc.control.id", "aws_vpc.control"],
    },
    "module.control.aws_vpc_endpoint.interface": {
        ("security_group_ids",): [
            "aws_security_group.interface_endpoints.id",
            "aws_security_group.interface_endpoints",
        ],
        ("subnet_ids",): ["aws_subnet.isolated"],
        ("vpc_id",): ["aws_vpc.control.id", "aws_vpc.control"],
    },
    "module.control.aws_elasticache_serverless_cache.otp": {
        ("kms_key_id",): [
            "aws_kms_key.authority_data.arn",
            "aws_kms_key.authority_data",
        ],
        ("security_group_ids",): [
            "aws_security_group.otp_redis.id",
            "aws_security_group.otp_redis",
        ],
        ("subnet_ids",): ["aws_subnet.isolated"],
        ("user_group_id",): [
            "aws_elasticache_user_group.otp.user_group_id",
            "aws_elasticache_user_group.otp",
        ],
    },
    "module.control.aws_elasticache_user_group.otp": {
        ("user_ids",): [
            "aws_elasticache_user.otp_disabled_default.user_id",
            "aws_elasticache_user.otp_disabled_default",
            "aws_elasticache_user.otp_authority.user_id",
            "aws_elasticache_user.otp_authority",
        ],
    },
    "module.control.aws_flow_log.control": {
        ("iam_role_arn",): ["aws_iam_role.flow_logs.arn", "aws_iam_role.flow_logs"],
        ("log_destination",): [
            "aws_cloudwatch_log_group.flow_logs.arn",
            "aws_cloudwatch_log_group.flow_logs",
        ],
        ("vpc_id",): ["aws_vpc.control.id", "aws_vpc.control"],
    },
    "module.control.aws_iam_role_policy.flow_logs": {
        ("policy",): ["local.flow_log_group_arn", "local.flow_log_group_arn"],
        ("role",): ["aws_iam_role.flow_logs.id", "aws_iam_role.flow_logs"],
    },
    "module.control.aws_cloudwatch_log_group.flow_logs": {
        ("kms_key_id",): [
            "aws_kms_key.authority_data.arn",
            "aws_kms_key.authority_data",
        ],
    },
    "module.control.aws_secretsmanager_secret.otp_pepper": {
        ("kms_key_id",): [
            "aws_kms_key.authority_data.arn",
            "aws_kms_key.authority_data",
        ],
    },
    "module.control.aws_ecr_repository.authority": {
        ("encryption_configuration", 0, "kms_key"): [
            "aws_kms_key.authority_data.arn",
            "aws_kms_key.authority_data",
        ],
    },
    "module.control.aws_kms_alias.authority_data": {
        ("target_key_id",): [
            "aws_kms_key.authority_data.key_id",
            "aws_kms_key.authority_data",
        ],
    },
    "module.control.aws_kms_alias.qat1_signing": {
        ("target_key_id",): [
            "aws_kms_key.qat1_signing.key_id",
            "aws_kms_key.qat1_signing",
        ],
    },
}
for _table in _DYNAMODB_TABLES:
    CONFIG_REFERENCE_CONTRACT[f"module.control.aws_dynamodb_table.{_table}"] = {
        ("server_side_encryption", 0, "kms_key_arn"): [
            "aws_kms_key.authority_data.arn",
            "aws_kms_key.authority_data",
        ]
    }

CONFIG_CONSTANT_CONTRACT: dict[str, dict[ExpressionPath, Any]] = {
    "module.control.aws_vpc.control": {
        ("enable_dns_hostnames",): True,
        ("enable_dns_support",): True,
    },
    "module.control.aws_default_security_group.control": {
        ("egress",): [],
        ("ingress",): [],
    },
    "module.control.aws_security_group.interface_endpoints": {
        ("egress",): [],
        ("ingress",): [],
    },
    "module.control.aws_security_group.otp_redis": {
        ("egress",): [],
        ("ingress",): [],
    },
    "module.control.aws_subnet.isolated": {
        ("map_public_ip_on_launch",): False,
    },
    "module.control.aws_vpc_endpoint.dynamodb": {
        ("vpc_endpoint_type",): "Gateway",
    },
    "module.control.aws_vpc_endpoint.interface": {
        ("private_dns_enabled",): True,
        ("vpc_endpoint_type",): "Interface",
    },
    "module.control.aws_ecr_repository.authority": {
        ("encryption_configuration", 0, "encryption_type"): "KMS",
        ("image_scanning_configuration", 0, "scan_on_push"): True,
        ("image_tag_mutability",): "IMMUTABLE",
    },
    "module.control.aws_elasticache_user.otp_authority": {
        ("authentication_mode", 0, "type"): "iam",
    },
    "module.control.aws_elasticache_user.otp_disabled_default": {
        ("authentication_mode", 0, "type"): "no-password-required",
    },
}
for _table in _DYNAMODB_TABLES:
    CONFIG_CONSTANT_CONTRACT[f"module.control.aws_dynamodb_table.{_table}"] = {
        ("server_side_encryption", 0, "enabled"): True
    }

CONFIG_ABSENT_PATHS: dict[str, tuple[ExpressionPath, ...]] = {
    "module.control.aws_vpc.control": tuple(
        (field,)
        for field in (
            "assign_generated_ipv6_cidr_block",
            "ipv4_ipam_pool_id",
            "ipv4_netmask_length",
            "ipv6_cidr_block",
            "ipv6_ipam_pool_id",
            "ipv6_netmask_length",
        )
    ),
    "module.control.aws_subnet.isolated": tuple(
        (field,)
        for field in (
            "assign_ipv6_address_on_creation",
            "customer_owned_ipv4_pool",
            "enable_dns64",
            "ipv6_cidr_block",
            "ipv6_ipam_pool_id",
            "ipv6_native",
            "ipv6_netmask_length",
            "map_customer_owned_ip_on_launch",
        )
    ),
    "module.control.aws_route_table.isolated": (("route",),),
    "module.control.aws_vpc_endpoint.dynamodb": (
        ("security_group_ids",),
        ("subnet_ids",),
    ),
    "module.control.aws_vpc_endpoint.interface": (("route_table_ids",),),
    "module.control.aws_elasticache_serverless_cache.otp": (
        ("daily_snapshot_time",),
        ("snapshot_arns_to_restore",),
    ),
    "module.control.aws_elasticache_user.otp_authority": (
        ("authentication_mode", 0, "passwords"),
        ("no_password_required",),
        ("passwords",),
        ("passwords_wo",),
        ("passwords_wo_version",),
    ),
    "module.control.aws_elasticache_user.otp_disabled_default": (
        ("authentication_mode", 0, "passwords"),
        ("no_password_required",),
        ("passwords",),
        ("passwords_wo",),
        ("passwords_wo_version",),
    ),
}


class ContractError(ValueError):
    """Raised when live or artifact evidence violates the reviewed contract."""


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ContractError(f"cannot read JSON {path}: {exc}") from exc


def write_json(path: Path, value: Any) -> None:
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise ContractError(f"cannot hash {path}: {exc}") from exc
    return digest.hexdigest()


def contract_sha256() -> str:
    """Bind artifact metadata to the reviewed resource-address/type inventory."""
    payload = json.dumps(
        EXPECTED_RESOURCES, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _non_noop(items: Any, label: str) -> list[dict[str, Any]]:
    if items is None:
        return []
    if not isinstance(items, list):
        raise ContractError(f"{label} must be an array")
    return [
        item for item in items if item.get("change", {}).get("actions") != ["no-op"]
    ]


def _iter_configuration_modules(
    module: Any, prefix: str = ""
) -> Iterable[tuple[str, dict[str, Any]]]:
    if not isinstance(module, dict):
        raise ContractError("Terraform configuration module must be an object")
    yield prefix, module
    calls = module.get("module_calls", {})
    if not isinstance(calls, dict):
        raise ContractError("Terraform configuration module_calls must be an object")
    for name, call in calls.items():
        if not isinstance(call, dict) or not isinstance(call.get("module"), dict):
            raise ContractError(
                f"Terraform configuration module call is malformed: {name}"
            )
        child_prefix = f"{prefix}.module.{name}" if prefix else f"module.{name}"
        yield from _iter_configuration_modules(call["module"], child_prefix)


def _configuration_resource_map(plan: dict[str, Any]) -> dict[str, dict[str, Any]]:
    configuration = plan.get("configuration")
    if not isinstance(configuration, dict) or not isinstance(
        configuration.get("root_module"), dict
    ):
        raise ContractError("Terraform plan configuration root_module is missing")
    provider_config = configuration.get("provider_config")
    if not isinstance(provider_config, dict) or set(provider_config) != {
        "aws",
        "module.control:terraform",
    }:
        raise ContractError("Terraform provider configuration map is not exact")
    aws_provider = provider_config["aws"]
    terraform_provider = provider_config["module.control:terraform"]
    if (
        not isinstance(aws_provider, dict)
        or set(aws_provider)
        != {"name", "full_name", "version_constraint", "expressions"}
        or aws_provider.get("name") != "aws"
        or aws_provider.get("full_name") != "registry.terraform.io/hashicorp/aws"
        or aws_provider.get("version_constraint") != "~> 6.27"
        or not isinstance(aws_provider.get("expressions"), dict)
        or set(aws_provider.get("expressions", {})) != {"default_tags", "region"}
        or aws_provider.get("expressions", {}).get("region")
        != {"references": ["var.aws_region"]}
        or not isinstance(terraform_provider, dict)
        or terraform_provider
        != {
            "name": "terraform",
            "full_name": "terraform.io/builtin/terraform",
            "module_address": "module.control",
        }
    ):
        raise ContractError("Terraform provider configuration identity drifted")

    by_address: dict[str, dict[str, Any]] = {}
    for prefix, module in _iter_configuration_modules(configuration["root_module"]):
        resources = module.get("resources", [])
        if not isinstance(resources, list):
            raise ContractError("Terraform configuration resources must be an array")
        for resource in resources:
            if not isinstance(resource, dict) or not isinstance(
                resource.get("address"), str
            ):
                raise ContractError("Terraform configuration resource is malformed")
            address = (
                f"{prefix}.{resource['address']}" if prefix else resource["address"]
            )
            if address in by_address:
                raise ContractError(
                    f"duplicate Terraform configuration resource: {address}"
                )
            if resource.get("provisioners") not in (None, []):
                raise ContractError(
                    f"Terraform configuration resource has provisioners: {address}"
                )
            by_address[address] = resource
    actual = {
        address: (
            resource.get("mode"),
            resource.get("type"),
            resource.get("provider_config_key"),
        )
        for address, resource in by_address.items()
    }
    if actual != EXPECTED_CONFIGURATION_RESOURCES:
        missing = sorted(set(EXPECTED_CONFIGURATION_RESOURCES) - set(actual))
        extra = sorted(set(actual) - set(EXPECTED_CONFIGURATION_RESOURCES))
        mismatched = sorted(
            address
            for address in set(actual) & set(EXPECTED_CONFIGURATION_RESOURCES)
            if actual[address] != EXPECTED_CONFIGURATION_RESOURCES[address]
        )
        raise ContractError(
            "Terraform configuration resource map differs; "
            f"missing={missing}, extra={extra}, mode_type_provider={mismatched}"
        )
    return by_address


_MISSING = object()


def _expression_at(expressions: Any, path: ExpressionPath) -> Any:
    current = expressions
    for part in path:
        if isinstance(part, str):
            if not isinstance(current, dict) or part not in current:
                return _MISSING
            current = current[part]
        else:
            if not isinstance(current, list) or part >= len(current):
                return _MISSING
            current = current[part]
    return current


def _check_configuration_security(
    resources: dict[str, dict[str, Any]],
) -> None:
    def expressions_of(address: str) -> dict[str, Any]:
        expressions = resources[address].get("expressions")
        if not isinstance(expressions, dict):
            raise ContractError(
                f"Terraform configuration expressions missing: {address}"
            )
        return expressions

    for address, paths in CONFIG_REFERENCE_CONTRACT.items():
        expressions = expressions_of(address)
        for path, references in paths.items():
            actual = _expression_at(expressions, path)
            if actual != {"references": references}:
                raise ContractError(
                    f"Terraform configuration reference differs: {address} {path}"
                )
    for address, paths in CONFIG_CONSTANT_CONTRACT.items():
        expressions = expressions_of(address)
        for path, constant in paths.items():
            actual = _expression_at(expressions, path)
            if actual != {"constant_value": constant}:
                raise ContractError(
                    f"Terraform configuration constant differs: {address} {path}"
                )
    for address, paths in CONFIG_ABSENT_PATHS.items():
        expressions = expressions_of(address)
        for path in paths:
            if _expression_at(expressions, path) is not _MISSING:
                raise ContractError(
                    f"forbidden Terraform configuration input exists: {address} {path}"
                )


def _check_no_embedded_actions(plan: dict[str, Any]) -> None:
    action_invocations = plan.get("action_invocations")
    if action_invocations not in (None, []):
        raise ContractError("Terraform plan contains action_invocations")
    _check_configuration_security(_configuration_resource_map(plan))


def _require_fields(
    values: Any, expected: dict[str, Any], address: str, label: str = "planned"
) -> None:
    if not isinstance(values, dict):
        raise ContractError(f"{address} {label} values must be an object")
    mismatches = [key for key, value in expected.items() if values.get(key) != value]
    if mismatches:
        raise ContractError(
            f"{address} {label} security fields differ: {sorted(mismatches)}"
        )


def _require_json_field(
    values: dict[str, Any], field: str, expected: Any, address: str
) -> None:
    raw = values.get(field)
    if not isinstance(raw, str):
        raise ContractError(f"{address} {field} must be JSON text")
    try:
        decoded = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ContractError(f"{address} {field} is malformed JSON: {exc}") from exc
    if decoded != expected:
        raise ContractError(f"{address} {field} differs from the dark contract")


def _check_planned_security(
    by_address: dict[str, dict[str, Any]], expected_action: str
) -> None:
    def values(address: str) -> tuple[dict[str, Any], dict[str, Any]]:
        change = by_address[address].get("change", {})
        after = change.get("after")
        unknown = change.get("after_unknown", {})
        if not isinstance(after, dict) or not isinstance(unknown, dict):
            raise ContractError(f"{address} planned values are malformed")
        return after, unknown

    vpc, _ = values("module.control.aws_vpc.control")
    # `recover-config` captured the partial-recovery state's provider shape:
    # refreshed resource values plus pre-convergence `passwords = null`. The
    # converged PR lane now uses no-op and reads `passwords = []` even with
    # -refresh=false. Recovery modes remain only until the tracked one-shot
    # cleanup removes them. Keep each complete provider-specific shape visible.
    live_values, password_value = {
        "create": (False, None),
        "recover": (True, []),
        "recover-config": (True, None),
        "no-op": (True, []),
    }[expected_action]
    _require_fields(
        vpc,
        {
            "cidr_block": "10.102.0.0/16",
            "enable_dns_hostnames": True,
            "enable_dns_support": True,
            "instance_tenancy": "default",
            "ipv4_ipam_pool_id": None,
            "ipv4_netmask_length": None,
            "ipv6_ipam_pool_id": "" if live_values else None,
            "ipv6_netmask_length": 0 if live_values else None,
            "region": AWS_REGION,
        },
        "module.control.aws_vpc.control",
    )
    if vpc.get("assign_generated_ipv6_cidr_block") not in (None, False):
        raise ContractError(
            "module.control.aws_vpc.control must not request generated IPv6"
        )

    for address in (
        "module.control.aws_default_security_group.control",
        "module.control.aws_security_group.interface_endpoints",
        "module.control.aws_security_group.otp_redis",
    ):
        after, unknown = values(address)
        _require_fields(after, {"ingress": [], "egress": []}, address)
        if unknown.get("ingress", []) != [] or unknown.get("egress", []) != []:
            raise ContractError(f"{address} has unknown planned traffic rules")

    for index, availability_zone in enumerate(
        ("us-east-2a", "us-east-2b", "us-east-2c")
    ):
        address = f"module.control.aws_subnet.isolated[{index}]"
        after, _ = values(address)
        _require_fields(
            after,
            {
                "assign_ipv6_address_on_creation": False,
                "availability_zone": availability_zone,
                "cidr_block": f"10.102.{index}.0/24",
                "enable_dns64": False,
                "ipv4_ipam_pool_id": None,
                "ipv4_netmask_length": None,
                "ipv6_ipam_pool_id": None,
                "ipv6_native": False,
                "ipv6_netmask_length": None,
                "map_public_ip_on_launch": False,
                "region": AWS_REGION,
            },
            address,
        )

    kms_contracts = {
        "module.control.aws_kms_key.authority_data": (
            {
                "bypass_policy_lockout_safety_check": False,
                "customer_master_key_spec": "SYMMETRIC_DEFAULT",
                "deletion_window_in_days": 7,
                "enable_key_rotation": True,
                "is_enabled": True,
                "key_usage": "ENCRYPT_DECRYPT",
                "region": AWS_REGION,
            },
            AUTHORITY_DATA_KMS_POLICY,
        ),
        "module.control.aws_kms_key.qat1_signing": (
            {
                "bypass_policy_lockout_safety_check": False,
                "customer_master_key_spec": "ECC_NIST_P256",
                "deletion_window_in_days": 7,
                "enable_key_rotation": False,
                "is_enabled": True,
                "key_usage": "SIGN_VERIFY",
                "region": AWS_REGION,
            },
            QAT1_SIGNING_KMS_POLICY,
        ),
    }
    for address, (expected, policy) in kms_contracts.items():
        after, _ = values(address)
        _require_fields(after, expected, address)
        _require_json_field(after, "policy", policy, address)

    endpoint_contracts = {"dynamodb": "Gateway"}
    endpoint_contracts.update(
        {service: "Interface" for service in INTERFACE_ENDPOINT_SERVICES}
    )
    for service, endpoint_type in endpoint_contracts.items():
        address = (
            "module.control.aws_vpc_endpoint.dynamodb"
            if service == "dynamodb"
            else f'module.control.aws_vpc_endpoint.interface["{service}"]'
        )
        after, _ = values(address)
        expected = {
            "region": AWS_REGION,
            "service_name": f"com.amazonaws.{AWS_REGION}.{service}",
            "vpc_endpoint_type": endpoint_type,
        }
        if endpoint_type == "Interface":
            expected["private_dns_enabled"] = True
        _require_fields(after, expected, address)
        _require_json_field(after, "policy", DENY_ENDPOINT_POLICY, address)

    redis_contracts = {
        "module.control.aws_elasticache_user.otp_authority": {
            "access_string": "on ~connector:* -@all +@connection +@read +@write +@scripting",
            "engine": "redis",
            "region": AWS_REGION,
            "user_id": f"{CONTROL_PREFIX}-otp-auth",
            "user_name": f"{CONTROL_PREFIX}-otp-auth",
        },
        "module.control.aws_elasticache_user.otp_disabled_default": {
            "access_string": "off ~* -@all",
            "engine": "redis",
            "region": AWS_REGION,
            "user_id": f"{CONTROL_PREFIX}-otp-default",
            "user_name": "default",
        },
        "module.control.aws_elasticache_user_group.otp": {
            "engine": "redis",
            "region": AWS_REGION,
            "user_group_id": f"{CONTROL_PREFIX}-otp-users",
        },
        "module.control.aws_elasticache_serverless_cache.otp": {
            "engine": "redis",
            "major_engine_version": "7",
            "name": f"{CONTROL_PREFIX}-otp",
            "region": AWS_REGION,
            "snapshot_arns_to_restore": None,
            "snapshot_retention_limit": 0,
            "user_group_id": f"{CONTROL_PREFIX}-otp-users",
        },
    }
    for address, expected in redis_contracts.items():
        after, _ = values(address)
        _require_fields(after, expected, address)

    # These shapes are exact for the locked AWS provider version; any provider
    # upgrade must regenerate and re-review both recovery plan fixtures before
    # changing this split (including the analogous IPv6 null/empty shapes).
    for address, auth_type in (
        ("module.control.aws_elasticache_user.otp_authority", "iam"),
        (
            "module.control.aws_elasticache_user.otp_disabled_default",
            "no-password" if live_values else "no-password-required",
        ),
    ):
        after, _ = values(address)
        auth = after.get("authentication_mode")
        if (
            not isinstance(auth, list)
            or len(auth) != 1
            or not isinstance(auth[0], dict)
            or auth[0].get("type") != auth_type
            or auth[0].get("passwords") != password_value
            or auth[0].get("password_count") not in (None, 0)
        ):
            raise ContractError(f"{address} authentication mode is not fail closed")

    group, _ = values("module.control.aws_elasticache_user_group.otp")
    expected_users = {
        f"{CONTROL_PREFIX}-otp-auth",
        f"{CONTROL_PREFIX}-otp-default",
    }
    users = group.get("user_ids")
    if not isinstance(users, list) or len(users) != 2 or set(users) != expected_users:
        raise ContractError("planned OTP Redis user-group membership drifted")

    cache, _ = values("module.control.aws_elasticache_serverless_cache.otp")
    usage = cache.get("cache_usage_limits")
    if not isinstance(usage, list) or len(usage) != 1 or not isinstance(usage[0], dict):
        raise ContractError("planned OTP Redis usage limits are malformed")
    data_storage = usage[0].get("data_storage")
    ecpu = usage[0].get("ecpu_per_second")
    if (
        not isinstance(data_storage, list)
        or len(data_storage) != 1
        or not isinstance(data_storage[0], dict)
        or data_storage[0].get("maximum") != 1
        or data_storage[0].get("unit") != "GB"
        or not isinstance(ecpu, list)
        or len(ecpu) != 1
        or not isinstance(ecpu[0], dict)
        or ecpu[0].get("maximum") != 1000
    ):
        raise ContractError("planned OTP Redis usage limits drifted")


def _check_recovery_drift(resource_drift: Any) -> None:
    if not isinstance(resource_drift, list):
        raise ContractError("Terraform recovery resource_drift must be an array")
    by_address: dict[str, dict[str, Any]] = {}
    for item in resource_drift:
        if not isinstance(item, dict) or not isinstance(item.get("address"), str):
            raise ContractError("Terraform recovery drift item is malformed")
        if item["address"] in by_address:
            raise ContractError("Terraform recovery drift contains a duplicate")
        by_address[item["address"]] = item

    expected = {
        "module.control.aws_elasticache_user.otp_authority",
        "module.control.aws_elasticache_user.otp_disabled_default",
        "module.control.aws_iam_role.flow_logs",
    }
    if set(by_address) != expected:
        raise ContractError("Terraform recovery drift inventory is not exact")

    for address, auth_type in (
        ("module.control.aws_elasticache_user.otp_authority", "iam"),
        ("module.control.aws_elasticache_user.otp_disabled_default", "no-password"),
    ):
        item = by_address[address]
        if item.get("mode") != "managed" or item.get("type") != "aws_elasticache_user":
            raise ContractError(f"{address} recovery drift identity differs")
        change = item.get("change")
        if not isinstance(change, dict) or change.get("actions") != ["update"]:
            raise ContractError(f"{address} recovery drift action is not exact")
        before = copy.deepcopy(change.get("before"))
        after = copy.deepcopy(change.get("after"))
        if not isinstance(before, dict) or not isinstance(after, dict):
            raise ContractError(f"{address} recovery drift values are malformed")
        expected_before_auth = [
            {"password_count": 0, "passwords": None, "type": auth_type}
        ]
        expected_after_auth = [
            {"password_count": 0, "passwords": [], "type": auth_type}
        ]
        if (
            before.get("authentication_mode") != expected_before_auth
            or after.get("authentication_mode") != expected_after_auth
        ):
            raise ContractError(f"{address} recovery authentication drift differs")
        before["authentication_mode"] = expected_after_auth
        if before != after:
            raise ContractError(f"{address} has additional recovery drift")
        if (
            change.get("after_unknown") != {}
            or change.get("before_sensitive") != change.get("after_sensitive")
        ):
            raise ContractError(f"{address} recovery drift metadata differs")

    role_item = by_address["module.control.aws_iam_role.flow_logs"]
    if role_item.get("mode") != "managed" or role_item.get("type") != "aws_iam_role":
        raise ContractError("Flow Log role recovery drift identity differs")
    role_change = role_item.get("change")
    if not isinstance(role_change, dict) or role_change.get("actions") != ["update"]:
        raise ContractError("Flow Log role recovery drift action is not exact")
    before = copy.deepcopy(role_change.get("before"))
    after = copy.deepcopy(role_change.get("after"))
    if not isinstance(before, dict) or not isinstance(after, dict):
        raise ContractError("Flow Log role recovery drift values are malformed")
    inline_after = after.get("inline_policy")
    if before.get("inline_policy") != [] or not isinstance(inline_after, list) or len(
        inline_after
    ) != 1:
        raise ContractError("Flow Log role inline-policy recovery drift differs")
    inline = inline_after[0]
    if (
        not isinstance(inline, dict)
        or inline.get("name") != "flow-logs"
        or not isinstance(inline.get("policy"), str)
    ):
        raise ContractError("Flow Log role inline-policy recovery drift is malformed")
    try:
        inline_policy = json.loads(inline["policy"])
    except json.JSONDecodeError as exc:
        raise ContractError("Flow Log role inline-policy JSON is malformed") from exc
    if inline_policy != FLOW_LOG_INLINE_POLICY:
        raise ContractError("Flow Log role inline-policy recovery drift differs")
    before["inline_policy"] = inline_after
    if before != after or role_change.get("after_unknown") != {}:
        raise ContractError("Flow Log role has additional recovery drift")
    before_sensitive = copy.deepcopy(role_change.get("before_sensitive"))
    after_sensitive = copy.deepcopy(role_change.get("after_sensitive"))
    if not isinstance(before_sensitive, dict) or not isinstance(after_sensitive, dict):
        raise ContractError("Flow Log role recovery sensitivity is malformed")
    if (
        before_sensitive.get("inline_policy") != []
        or after_sensitive.get("inline_policy") != [{}]
    ):
        raise ContractError("Flow Log role recovery sensitivity differs")
    before_sensitive["inline_policy"] = [{}]
    if before_sensitive != after_sensitive:
        raise ContractError("Flow Log role has additional sensitive drift")


def check_plan(plan: Any, expected_action: str) -> dict[str, str | int]:
    if not isinstance(plan, dict):
        raise ContractError("Terraform plan must be an object")
    if plan.get("format_version") != "1.2":
        raise ContractError("Terraform plan format_version must be 1.2")
    if plan.get("terraform_version") != TF_VERSION:
        raise ContractError(f"Terraform plan must use exact {TF_VERSION}")
    if plan.get("complete") is not True or plan.get("errored") is not False:
        raise ContractError("Terraform plan must be complete and non-errored")
    if expected_action == "recover":
        _check_recovery_drift(plan.get("resource_drift"))
    elif _non_noop(plan.get("resource_drift"), "resource_drift"):
        raise ContractError("Terraform plan contains live resource drift")
    _check_no_embedded_actions(plan)

    changes = plan.get("resource_changes")
    if not isinstance(changes, list):
        raise ContractError("Terraform plan resource_changes must be an array")
    by_address: dict[str, dict[str, Any]] = {}
    for item in changes:
        if not isinstance(item, dict) or not isinstance(item.get("address"), str):
            raise ContractError("Terraform resource change is malformed")
        address = item["address"]
        if address in by_address:
            raise ContractError(f"duplicate Terraform resource change: {address}")
        by_address[address] = item

    missing = sorted(set(EXPECTED_RESOURCES) - set(by_address))
    extra = sorted(set(by_address) - set(EXPECTED_RESOURCES))
    if missing or extra:
        raise ContractError(
            f"Terraform resource inventory mismatch; missing={missing}, extra={extra}"
        )

    recovery_action = expected_action in {"recover", "recover-config"}
    for address, expected_type in EXPECTED_RESOURCES.items():
        item = by_address[address]
        if item.get("mode") != "managed" or item.get("type") != expected_type:
            raise ContractError(f"unexpected mode/type for {address}")
        if recovery_action:
            action = (
                "create"
                if address == "module.control.aws_elasticache_serverless_cache.otp"
                else "no-op"
            )
        else:
            action = expected_action
        expected_actions = [action]
        change = item.get("change")
        if not isinstance(change, dict) or change.get("actions") != expected_actions:
            raise ContractError(
                f"{address} must have exact actions {expected_actions!r}"
            )
        if action == "create":
            if change.get("before") is not None or not isinstance(
                change.get("after"), dict
            ):
                raise ContractError(f"{address} is not a pure first create")
        elif action == "no-op":
            if change.get("before") != change.get("after"):
                raise ContractError(f"{address} no-op before and after differ")
        else:
            raise ContractError(f"unsupported expected action: {action}")

    _check_planned_security(by_address, expected_action)

    expected_applyable = expected_action in {"create", "recover", "recover-config"}
    if plan.get("applyable") is not expected_applyable:
        raise ContractError(
            f"Terraform applyable must be {expected_applyable} for {expected_action}"
        )
    # The counts are returned so the contract tests assert the exact action
    # inventory in addition to this function's per-resource validation.
    return {
        "contract_sha256": contract_sha256(),
        "create_count": {
            "create": 41,
            "recover": 1,
            "recover-config": 1,
            "no-op": 0,
        }[expected_action],
        "resource_count": len(EXPECTED_RESOURCES),
    }


def check_state_list(path: Path) -> dict[str, int]:
    try:
        addresses = {
            line.strip() for line in path.read_text().splitlines() if line.strip()
        }
    except OSError as exc:
        raise ContractError(f"cannot read Terraform state list: {exc}") from exc

    # `terraform state list` includes both managed resources and cached data
    # sources. Require the reviewed union here; the subsequent JSON state check
    # remains mode-aware and independently enforces the exact 41 managed
    # resources plus their types and security-sensitive values.
    expected = set(EXPECTED_RESOURCES) | set(EXPECTED_DATA_RESOURCES)
    missing = sorted(expected - addresses)
    extra = sorted(addresses - expected)
    if missing or extra:
        raise ContractError(
            f"Terraform state inventory mismatch; missing={missing}, extra={extra}"
        )
    return {
        "data_resource_count": len(EXPECTED_DATA_RESOURCES),
        "managed_resource_count": len(EXPECTED_RESOURCES),
    }


def _normalized_statement(statement: Any) -> dict[str, Any]:
    if not isinstance(statement, dict):
        raise ContractError("IAM statement must be an object")
    normalized = dict(statement)
    for field in ("Action", "Resource"):
        value = normalized.get(field)
        if isinstance(value, str):
            normalized[field] = [value]
        if not isinstance(normalized.get(field), list):
            raise ContractError(f"IAM statement {field} must be a list")
        normalized[field] = sorted(normalized[field])
    return normalized


# The IAM simulator reports missing values from unrelated statements attached
# to the shared apply role. These service-specific keys cannot exist on an
# ElastiCache write request. Keep global aws:* keys out of this exception: they
# can affect real authorization and must either be supplied or fail closed.
CELL_WRITE_IMPOSSIBLE_CONTEXT_KEYS = frozenset(
    {
        "cloudwatch:namespace",
        "iam:AWSServiceName",
        "iam:PassedToService",
        "route53:ChangeResourceRecordSetsNormalizedRecordNames",
        "ssm:resourceTag/Environment",
    }
)


def _check_simulation(
    payload: Any,
    actions: Iterable[str],
    resources: Iterable[str],
    decision: str,
    label: str,
    allowed_missing_context_keys: frozenset[str] = frozenset(),
) -> None:
    if not isinstance(payload, dict) or not isinstance(
        payload.get("EvaluationResults"), list
    ):
        raise ContractError(f"{label} simulation is malformed")
    expected = {
        (action.lower(), resource) for action in actions for resource in resources
    }
    actual: dict[tuple[str, str], str] = {}
    missing_context_keys: set[str] = set()
    for result in payload["EvaluationResults"]:
        if not isinstance(result, dict):
            raise ContractError(f"{label} simulation result is malformed")
        key = (
            str(result.get("EvalActionName", "")).lower(),
            str(result.get("EvalResourceName", "")),
        )
        if key in actual:
            raise ContractError(f"{label} simulation contains a duplicate result")
        missing = result.get("MissingContextValues")
        if missing is not None and not isinstance(missing, list):
            raise ContractError(
                f"{label} simulation has malformed missing-context metadata"
            )
        if isinstance(missing, list):
            if any(
                not isinstance(key_name, str) or not key_name for key_name in missing
            ):
                raise ContractError(
                    f"{label} simulation has malformed missing-context metadata"
                )
            missing_context_keys.update(missing)
        actual[key] = result.get("EvalDecision")
    unexpected_missing_context_keys = (
        missing_context_keys - allowed_missing_context_keys
    )
    if unexpected_missing_context_keys:
        # Context key names are safe diagnostics, but JSON-encode them so a
        # provider-controlled name cannot inject terminal or workflow syntax.
        names = json.dumps(
            sorted(unexpected_missing_context_keys), separators=(",", ":")
        )
        raise ContractError(f"{label} simulation has missing context keys: {names}")
    if set(actual) != expected or set(actual.values()) != {decision}:
        raise ContractError(
            f"{label} simulation does not match exact {decision} matrix"
        )


def _check_cache_dependency_simulation(
    payload: Any,
    user_group_resource: str,
    user_group_decision: str,
    label: str,
) -> None:
    """Validate IAM's composite cache/user-group authorization result.

    ElastiCache evaluates both resources for each cache lifecycle action. The
    outer result alone can hide which dependent resource caused a denial, so
    require the exact nested ResourceSpecificResults matrix as well.
    """
    if not isinstance(payload, dict) or not isinstance(
        payload.get("EvaluationResults"), list
    ):
        raise ContractError(f"{label} simulation is malformed")

    resources = (CONTROL_CACHE_RESOURCE, user_group_resource)
    expected_outer = {
        (action.lower(), resource)
        for action in CACHE_DEPENDENCY_ACTIONS
        for resource in resources
    }
    expected_outer_decision = (
        "allowed" if user_group_decision == "allowed" else "implicitDeny"
    )
    actual_outer: dict[tuple[str, str], str] = {}
    for result in payload["EvaluationResults"]:
        if not isinstance(result, dict):
            raise ContractError(f"{label} simulation result is malformed")
        action = str(result.get("EvalActionName", "")).lower()
        resource = str(result.get("EvalResourceName", ""))
        key = (action, resource)
        if key in actual_outer:
            raise ContractError(f"{label} simulation contains a duplicate result")
        actual_outer[key] = result.get("EvalDecision")

        nested = result.get("ResourceSpecificResults")
        if not isinstance(nested, list):
            raise ContractError(f"{label} simulation lacks composite results")
        actual_nested: dict[str, str] = {}
        for item in nested:
            if not isinstance(item, dict):
                raise ContractError(f"{label} composite result is malformed")
            nested_resource = str(item.get("EvalResourceName", ""))
            if nested_resource in actual_nested:
                raise ContractError(f"{label} composite result is duplicated")
            actual_nested[nested_resource] = item.get("EvalResourceDecision")
            missing = item.get("MissingContextValues", [])
            if not isinstance(missing, list) or any(
                not isinstance(name, str) or not name for name in missing
            ):
                raise ContractError(
                    f"{label} composite missing-context metadata is malformed"
                )
            expected_missing = (
                CELL_WRITE_IMPOSSIBLE_CONTEXT_KEYS
                if nested_resource == user_group_resource
                and user_group_decision == "implicitDeny"
                else frozenset()
            )
            if set(missing) != expected_missing:
                names = json.dumps(sorted(set(missing)), separators=(",", ":"))
                raise ContractError(
                    f"{label} composite missing-context keys differ: {names}"
                )
        expected_nested = {
            CONTROL_CACHE_RESOURCE: "allowed",
            user_group_resource: user_group_decision,
        }
        if actual_nested != expected_nested:
            raise ContractError(f"{label} composite authorization matrix drifted")
    if set(actual_outer) != expected_outer or set(actual_outer.values()) != {
        expected_outer_decision
    }:
        raise ContractError(
            f"{label} simulation does not match exact {expected_outer_decision} matrix"
        )


def check_preflight(
    evidence_dir: Path, expected_state: str = "absent"
) -> dict[str, Any]:
    caller = load_json(evidence_dir / "caller.json")
    if caller.get("Account") != ACCOUNT_ID or not re.fullmatch(
        rf"arn:aws:sts::{ACCOUNT_ID}:assumed-role/{ROLE_NAME}/[^/]+",
        str(caller.get("Arn", "")),
    ):
        raise ContractError("preflight did not run under the sandbox apply role")

    state = load_json(evidence_dir / "state-status.json")
    if expected_state not in {"absent", "present"}:
        raise ContractError("preflight expected state mode is invalid")
    expected_state_status = {
        "bucket": STATE_BUCKET,
        "lock_exists": False,
        "lock_key": STATE_LOCK_KEY,
        "state_exists": expected_state == "present",
        "state_key": STATE_KEY,
    }
    if state != expected_state_status:
        raise ContractError(
            f"Control state/lock does not match exact {expected_state} contract"
        )
    if expected_state == "present":
        state_head = load_json(evidence_dir / "state-head.json")
        if (
            state_head.get("ServerSideEncryption") != "aws:kms"
            or state_head.get("SSEKMSKeyId") != STATE_KMS_KEY_ARN
            or not isinstance(state_head.get("VersionId"), str)
            or not state_head["VersionId"]
            or state_head["VersionId"] == "null"
            or not isinstance(state_head.get("ContentLength"), int)
            or state_head["ContentLength"] <= 0
        ):
            raise ContractError(
                "existing Control state is not versioned under the exact KMS key"
            )
        secret_versions = load_json(evidence_dir / "otp-secret-versions.json")
        if secret_versions.get("Versions") != []:
            raise ContractError("OTP pepper was seeded before recovery verification")
        if load_json(evidence_dir / "otp-cache.json") != {"exists": False}:
            raise ContractError("Control OTP cache is not exactly absent")

    bucket_versioning = load_json(evidence_dir / "bucket-versioning.json")
    if (
        not isinstance(bucket_versioning, dict)
        or bucket_versioning.get("Status") != "Enabled"
    ):
        raise ContractError("sandbox Terraform-state bucket versioning is not enabled")

    policy = load_json(evidence_dir / "policy.json").get("Policy", {})
    if policy.get("Arn") != POLICY_ARN or policy.get("AttachmentCount") != 1:
        raise ContractError("sandbox apply-data policy identity/attachment drifted")
    version_id = policy.get("DefaultVersionId")
    if not isinstance(version_id, str) or not re.fullmatch(r"v[1-9][0-9]*", version_id):
        raise ContractError("sandbox apply-data default version is malformed")
    version = load_json(evidence_dir / "policy-version.json").get("PolicyVersion", {})
    if (
        version.get("VersionId") != version_id
        or version.get("IsDefaultVersion") is not True
    ):
        raise ContractError("sandbox apply-data version evidence is stale")
    document = version.get("Document", {})
    statements = document.get("Statement") if isinstance(document, dict) else None
    if not isinstance(statements, list):
        raise ContractError("sandbox apply-data policy document is malformed")
    for sid, expected in (
        ("ElastiCache", EXPECTED_SERVERLESS_CACHE_STATEMENT),
        (
            "ElastiCacheControlCacheUserGroupDependency",
            EXPECTED_CACHE_DEPENDENCY_STATEMENT,
        ),
        ("ElastiCacheControlRBAC", EXPECTED_CONTROL_STATEMENT),
    ):
        matching = [item for item in statements if item.get("Sid") == sid]
        if len(matching) != 1 or _normalized_statement(
            matching[0]
        ) != _normalized_statement(expected):
            raise ContractError(f"sandbox {sid} statement is not exact")

    # This preflight owns POLICY_ARN identity, attachment count/quota, and the
    # Control-allow and cell write-deny/read-allow simulations below. The other
    # shared-role policy identities remain the normal Terraform/IAM review
    # surface; this attended one-time workflow does not duplicate that inventory.
    attached = load_json(evidence_dir / "attached-policies.json").get(
        "AttachedPolicies"
    )
    if not isinstance(attached, list) or len(attached) != 10:
        raise ContractError("sandbox apply role attachment count is not exactly 10")
    if [item.get("PolicyArn") for item in attached].count(POLICY_ARN) != 1:
        raise ContractError("sandbox apply-data policy is not attached exactly once")
    quota = (
        load_json(evidence_dir / "account-summary.json")
        .get("SummaryMap", {})
        .get("AttachedPoliciesPerRoleQuota")
    )
    if quota != 10:
        raise ContractError("sandbox attached-policy quota changed from 10")

    _check_simulation(
        load_json(evidence_dir / "control-simulation.json"),
        CONTROL_ACTIONS,
        CONTROL_RESOURCES,
        "allowed",
        "Control",
    )
    _check_simulation(
        load_json(evidence_dir / "cell-write-simulation.json"),
        CONTROL_WRITE_ACTIONS,
        CELL_RESOURCES,
        "implicitDeny",
        "cell write",
        CELL_WRITE_IMPOSSIBLE_CONTEXT_KEYS,
    )
    _check_simulation(
        load_json(evidence_dir / "cell-read-simulation.json"),
        CONTROL_READ_ACTIONS,
        CELL_RESOURCES,
        "allowed",
        "cell read",
    )
    _check_cache_dependency_simulation(
        load_json(evidence_dir / "cache-control-dependency-simulation.json"),
        CONTROL_CACHE_USER_GROUP_RESOURCE,
        "allowed",
        "Control cache dependent user group",
    )
    _check_cache_dependency_simulation(
        load_json(evidence_dir / "cache-cell-dependency-simulation.json"),
        CELL_CACHE_USER_GROUP_RESOURCE,
        "implicitDeny",
        "cell cache dependent user group",
    )

    details = load_json(evidence_dir / "endpoint-service.json").get("ServiceDetails")
    if not isinstance(details, list) or len(details) != 1:
        raise ContractError("SES API PrivateLink service evidence is not singular")
    service = details[0]
    service_types = {item.get("ServiceType") for item in service.get("ServiceType", [])}
    if (
        service.get("ServiceName") != f"com.amazonaws.{AWS_REGION}.email"
        or service_types != {"Interface"}
        or set(service.get("AvailabilityZones", []))
        != {"us-east-2a", "us-east-2b", "us-east-2c"}
    ):
        raise ContractError("SES API PrivateLink service/AZ contract drifted")

    key = load_json(evidence_dir / "state-kms.json").get("KeyMetadata", {})
    if (
        key.get("Arn") != STATE_KMS_KEY_ARN
        or key.get("Enabled") is not True
        or key.get("KeyState") != "Enabled"
        or key.get("KeyUsage") != "ENCRYPT_DECRYPT"
    ):
        raise ContractError("sandbox Terraform-state KMS alias target drifted")

    return {
        "account_id": ACCOUNT_ID,
        "attachment_count": len(attached),
        "attachment_quota": quota,
        "state_bucket_versioning": "Enabled",
        "state_kms_key_arn": STATE_KMS_KEY_ARN,
    }


def _raw_state_address(resource: dict[str, Any], instance: dict[str, Any]) -> str:
    module = resource.get("module")
    resource_type = resource.get("type")
    name = resource.get("name")
    if module != "module.control" or not all(
        isinstance(value, str) and value for value in (resource_type, name)
    ):
        raise ContractError("partial state resource identity is malformed")
    prefix = f"{module}.data" if resource.get("mode") == "data" else module
    address = f"{prefix}.{resource_type}.{name}"
    if "index_key" in instance:
        index = instance["index_key"]
        if isinstance(index, str):
            address += f"[{json.dumps(index, separators=(',', ':'))}]"
        elif isinstance(index, int) and not isinstance(index, bool):
            address += f"[{index}]"
        else:
            raise ContractError("partial state resource index is malformed")
    return address


def check_partial_state(state_path: Path, head_path: Path) -> dict[str, Any]:
    if sha256_file(state_path) != PARTIAL_STATE_SHA256:
        raise ContractError("partial state raw digest is not exact")
    state = load_json(state_path)
    if not isinstance(state, dict) or (
        state.get("version") != 4
        or state.get("terraform_version") != TF_VERSION
        or state.get("lineage") != PARTIAL_STATE_LINEAGE
        or state.get("serial") != PARTIAL_STATE_SERIAL
    ):
        raise ContractError("partial state header is not exact")

    head = load_json(head_path)
    if (
        not isinstance(head, dict)
        or head.get("ContentLength") != PARTIAL_STATE_CONTENT_LENGTH
        or head.get("ETag") != PARTIAL_STATE_ETAG
        or head.get("VersionId") != PARTIAL_STATE_VERSION_ID
        or head.get("ServerSideEncryption") != "aws:kms"
        or head.get("SSEKMSKeyId") != STATE_KMS_KEY_ARN
    ):
        raise ContractError("partial state S3 identity is not exact")

    raw_resources = state.get("resources")
    if not isinstance(raw_resources, list):
        raise ContractError("partial state resources are malformed")
    actual: dict[str, tuple[str, str]] = {}
    for resource in raw_resources:
        if not isinstance(resource, dict):
            raise ContractError("partial state resource is malformed")
        mode = resource.get("mode")
        if mode not in {"managed", "data"}:
            raise ContractError("partial state resource mode is unexpected")
        instances = resource.get("instances")
        if not isinstance(instances, list) or not instances:
            raise ContractError("partial state resource has no instances")
        for instance in instances:
            if not isinstance(instance, dict):
                raise ContractError("partial state instance is malformed")
            if "status" in instance or "deposed" in instance:
                raise ContractError("partial state contains tainted/deposed state")
            address = _raw_state_address(resource, instance)
            if address in actual:
                raise ContractError("partial state contains a duplicate address")
            actual[address] = (mode, str(resource.get("type", "")))

    expected_managed = dict(EXPECTED_RESOURCES)
    missing_cache = "module.control.aws_elasticache_serverless_cache.otp"
    expected_managed.pop(missing_cache)
    expected = {
        **{address: ("managed", kind) for address, kind in expected_managed.items()},
        **{
            address: ("data", kind)
            for address, kind in EXPECTED_DATA_RESOURCES.items()
        },
    }
    if actual != expected:
        missing = sorted(set(expected) - set(actual))
        extra = sorted(set(actual) - set(expected))
        mismatched = sorted(
            address
            for address in set(actual) & set(expected)
            if actual[address] != expected[address]
        )
        raise ContractError(
            "partial state inventory is not exact; "
            f"missing={missing}, extra={extra}, mismatched={mismatched}"
        )
    return {
        "data_resource_count": len(EXPECTED_DATA_RESOURCES),
        "managed_resource_count": len(expected_managed),
        "missing_managed_resource": missing_cache,
        "state_content_length": PARTIAL_STATE_CONTENT_LENGTH,
        "state_etag": PARTIAL_STATE_ETAG,
        "state_lineage": PARTIAL_STATE_LINEAGE,
        "state_serial": PARTIAL_STATE_SERIAL,
        "state_sha256": PARTIAL_STATE_SHA256,
        "state_version_id": PARTIAL_STATE_VERSION_ID,
    }


def _artifact_values(
    args: argparse.Namespace, expected_action: str = "create"
) -> dict[str, Any]:
    for field in ("commit_sha", "plan_sha256"):
        if not re.fullmatch(
            r"[0-9a-f]{40}" if field == "commit_sha" else r"[0-9a-f]{64}",
            str(getattr(args, field)),
        ):
            raise ContractError(f"{field} is malformed")
    for field in ("run_id", "run_attempt", "planned_at_epoch"):
        if not re.fullmatch(r"[1-9][0-9]*", str(getattr(args, field))):
            raise ContractError(f"{field} is malformed")
    if args.repository != REPOSITORY or args.terraform_version != TF_VERSION:
        raise ContractError("artifact repository or Terraform version is wrong")
    expected_workflow_ref = f"{REPOSITORY}/{WORKFLOW_PATH}@refs/heads/main"
    if args.workflow_ref != expected_workflow_ref:
        raise ContractError("artifact workflow_ref is not exact main workflow")
    if sha256_file(args.plan) != args.plan_sha256:
        raise ContractError("saved plan digest does not match supplied digest")
    plan = load_json(args.plan_json)
    check_plan(plan, expected_action)
    return {
        "account_id": ACCOUNT_ID,
        "backend_bucket": STATE_BUCKET,
        "backend_key": STATE_KEY,
        "commit_sha": args.commit_sha,
        "contract_sha256": contract_sha256(),
        "plan_json_sha256": sha256_file(args.plan_json),
        "plan_sha256": args.plan_sha256,
        "planned_at_epoch": str(args.planned_at_epoch),
        "repository": REPOSITORY,
        "run_attempt": str(args.run_attempt),
        "run_id": str(args.run_id),
        "state_kms_key_arn": STATE_KMS_KEY_ARN,
        "terraform_version": TF_VERSION,
        "workflow_ref": expected_workflow_ref,
    }


def create_artifact(args: argparse.Namespace) -> dict[str, Any]:
    values = _artifact_values(args)
    write_json(args.output, values)
    return values


def _verify_artifact(
    args: argparse.Namespace,
    keys: set[str],
    values: Callable[[argparse.Namespace], dict[str, Any]],
    label: str,
    plan_label: str,
) -> dict[str, Any]:
    metadata = load_json(args.metadata)
    if not isinstance(metadata, dict) or set(metadata) != keys:
        raise ContractError(f"{label} metadata keys are not exact")
    expected = values(args)
    if metadata != expected:
        mismatches = sorted(
            key for key in keys if metadata.get(key) != expected.get(key)
        )
        raise ContractError(f"{label} metadata mismatch: " + ", ".join(mismatches))
    now = int(args.now_epoch) if args.now_epoch is not None else int(time.time())
    age = now - int(metadata["planned_at_epoch"])
    if age < 0 or age > PLAN_MAX_AGE_SECONDS:
        raise ContractError(
            f"saved {plan_label} is outside the two-day approval window"
        )
    return metadata


def verify_artifact(args: argparse.Namespace) -> dict[str, Any]:
    return _verify_artifact(args, ARTIFACT_KEYS, _artifact_values, "artifact", "plan")


def _recovery_artifact_values(args: argparse.Namespace) -> dict[str, Any]:
    return {
        **_artifact_values(args, "recover"),
        "failed_apply_commit": FAILED_APPLY_COMMIT,
        "failed_apply_run_id": FAILED_APPLY_RUN_ID,
        "plan_mode": "partial-recovery",
        "state_content_length": PARTIAL_STATE_CONTENT_LENGTH,
        "state_etag": PARTIAL_STATE_ETAG,
        "state_lineage": PARTIAL_STATE_LINEAGE,
        "state_serial": PARTIAL_STATE_SERIAL,
        "state_sha256": PARTIAL_STATE_SHA256,
        "state_version_id": PARTIAL_STATE_VERSION_ID,
    }


def create_recovery_artifact(args: argparse.Namespace) -> dict[str, Any]:
    values = _recovery_artifact_values(args)
    write_json(args.output, values)
    return values


def verify_recovery_artifact(args: argparse.Namespace) -> dict[str, Any]:
    return _verify_artifact(
        args,
        RECOVERY_ARTIFACT_KEYS,
        _recovery_artifact_values,
        "recovery artifact",
        "recovery plan",
    )


def _check_workflow_run(
    run: Any, expected: dict[str, Any], label: str
) -> None:
    if not isinstance(run, dict):
        raise ContractError(f"{label} workflow run is malformed")
    for key, value in expected.items():
        if run.get(key) != value:
            raise ContractError(f"{label} workflow run {key} is not exact")
    for actor_field in ("actor", "triggering_actor"):
        actor = run.get(actor_field)
        if not isinstance(actor, dict) or actor.get("login") != TRUSTED_ACTOR:
            raise ContractError(f"{label} workflow run {actor_field} is not exact")
    if run.get("repository", {}).get("full_name") != REPOSITORY:
        raise ContractError(f"{label} workflow run repository is not exact")


def check_source_run(args: argparse.Namespace) -> None:
    run = load_json(args.run_json)
    expected = {
        "id": int(args.run_id),
        "event": "workflow_dispatch",
        "status": "completed",
        "conclusion": "success",
        "head_branch": "main",
        "head_sha": args.commit_sha,
        "name": WORKFLOW_NAME,
        "path": WORKFLOW_PATH,
    }
    _check_workflow_run(run, expected, "source")


def check_failed_run(run_path: Path) -> None:
    run = load_json(run_path)
    expected = {
        "id": int(FAILED_APPLY_RUN_ID),
        "event": "workflow_dispatch",
        "status": "completed",
        "conclusion": "failure",
        "head_branch": "main",
        "head_sha": FAILED_APPLY_COMMIT,
        "name": WORKFLOW_NAME,
        "path": WORKFLOW_PATH,
    }
    _check_workflow_run(run, expected, "failed apply")


def _iter_resources(module: Any) -> Iterable[dict[str, Any]]:
    if not isinstance(module, dict):
        return
    for resource in module.get("resources", []):
        yield resource
    for child in module.get("child_modules", []):
        yield from _iter_resources(child)


def check_state(state: Any) -> dict[str, Any]:
    # Accept both `terraform show -json` state and plan shapes so this contract
    # remains reusable for direct state evidence as well as refreshed plans.
    values_root = state.get("values") if isinstance(state, dict) else None
    prior_state = state.get("prior_state") if isinstance(state, dict) else None
    if not isinstance(values_root, dict) and isinstance(prior_state, dict):
        values_root = prior_state.get("values")
    root = values_root.get("root_module") if isinstance(values_root, dict) else None
    resources = [
        item for item in _iter_resources(root) if item.get("mode") == "managed"
    ]
    by_address = {item.get("address"): item for item in resources}
    if len(by_address) != len(resources):
        raise ContractError("refreshed state contains duplicate managed addresses")
    missing = sorted(set(EXPECTED_RESOURCES) - set(by_address))
    extra = sorted(set(by_address) - set(EXPECTED_RESOURCES))
    if missing or extra:
        raise ContractError(
            f"refreshed state inventory mismatch; missing={missing}, extra={extra}"
        )
    for address, expected_type in EXPECTED_RESOURCES.items():
        resource = by_address[address]
        if resource.get("mode") != "managed" or resource.get("type") != expected_type:
            raise ContractError(f"refreshed state mode/type mismatch for {address}")
        if not isinstance(resource.get("values"), dict):
            raise ContractError(f"refreshed state values missing for {address}")

    values = {address: item["values"] for address, item in by_address.items()}
    vpc_id = values["module.control.aws_vpc.control"].get("id")
    if (
        not re.fullmatch(r"vpc-[0-9a-f]+", str(vpc_id))
        or values["module.control.aws_vpc.control"].get("cidr_block") != "10.102.0.0/16"
    ):
        raise ContractError("Control VPC identity/CIDR is invalid")
    for address in (
        "module.control.aws_default_security_group.control",
        "module.control.aws_security_group.interface_endpoints",
        "module.control.aws_security_group.otp_redis",
    ):
        item = values[address]
        if item.get("ingress") not in ([], None) or item.get("egress") not in (
            [],
            None,
        ):
            raise ContractError(f"dark security group has traffic rules: {address}")

    data_key = values["module.control.aws_kms_key.authority_data"]
    signer = values["module.control.aws_kms_key.qat1_signing"]
    if (
        data_key.get("key_usage") != "ENCRYPT_DECRYPT"
        or data_key.get("is_enabled") is not True
    ):
        raise ContractError("authority data KMS key is not enabled ENCRYPT_DECRYPT")
    if (
        signer.get("key_usage") != "SIGN_VERIFY"
        or signer.get("customer_master_key_spec") != "ECC_NIST_P256"
        or signer.get("is_enabled") is not True
    ):
        raise ContractError("qat1 KMS signer is not enabled P-256 SIGN_VERIFY")

    flow = values["module.control.aws_flow_log.control"]
    log_group = values["module.control.aws_cloudwatch_log_group.flow_logs"]
    if log_group.get("kms_key_id") != data_key.get("arn"):
        raise ContractError(
            "Control Flow Log group is not encrypted by authority data KMS"
        )
    if (
        flow.get("traffic_type") != "ALL"
        or flow.get("max_aggregation_interval") != 60
        or flow.get("log_destination_type") != "cloud-watch-logs"
        or flow.get("log_destination") != log_group.get("arn")
        or flow.get("iam_role_arn")
        != values["module.control.aws_iam_role.flow_logs"].get("arn")
    ):
        raise ContractError("Control Flow Log state contract drifted")

    interface_sg = values["module.control.aws_security_group.interface_endpoints"].get(
        "id"
    )
    subnet_ids = {
        values[f"module.control.aws_subnet.isolated[{index}]"].get("id")
        for index in range(3)
    }
    route_table_ids = {
        values[f"module.control.aws_route_table.isolated[{index}]"].get("id")
        for index in range(3)
    }
    deny_policy = DENY_ENDPOINT_POLICY
    for service in INTERFACE_ENDPOINT_SERVICES:
        item = values[f'module.control.aws_vpc_endpoint.interface["{service}"]']
        if (
            item.get("state") != "available"
            or item.get("vpc_endpoint_type") != "Interface"
            or item.get("service_name") != f"com.amazonaws.{AWS_REGION}.{service}"
            or item.get("private_dns_enabled") is not True
            or item.get("vpc_id") != vpc_id
            or set(item.get("subnet_ids", [])) != subnet_ids
            or set(item.get("security_group_ids", [])) != {interface_sg}
            or json.loads(item.get("policy", "{}")) != deny_policy
        ):
            raise ContractError(
                f"dark interface endpoint contract failed for {service}"
            )
    dynamodb = values["module.control.aws_vpc_endpoint.dynamodb"]
    if (
        dynamodb.get("state") != "available"
        or dynamodb.get("vpc_endpoint_type") != "Gateway"
        or dynamodb.get("service_name") != f"com.amazonaws.{AWS_REGION}.dynamodb"
        or dynamodb.get("vpc_id") != vpc_id
        or set(dynamodb.get("route_table_ids", [])) != route_table_ids
        or json.loads(dynamodb.get("policy", "{}")) != deny_policy
    ):
        raise ContractError("dark DynamoDB endpoint contract failed")

    cache = values["module.control.aws_elasticache_serverless_cache.otp"]
    if (
        cache.get("status") != "available"
        or cache.get("engine") != "redis"
        or cache.get("major_engine_version") != "7"
        or cache.get("user_group_id") != f"{CONTROL_PREFIX}-otp-users"
        or cache.get("kms_key_id") != data_key.get("arn")
        or cache.get("snapshot_retention_limit") != 0
        or set(cache.get("security_group_ids", []))
        != {values["module.control.aws_security_group.otp_redis"].get("id")}
        or set(cache.get("subnet_ids", [])) != subnet_ids
    ):
        raise ContractError("OTP Redis cache contract failed")
    disabled = values["module.control.aws_elasticache_user.otp_disabled_default"]
    authority = values["module.control.aws_elasticache_user.otp_authority"]
    group = values["module.control.aws_elasticache_user_group.otp"]
    disabled_auth = disabled.get("authentication_mode", [])
    authority_auth = authority.get("authentication_mode", [])
    if (
        disabled.get("user_name") != "default"
        or disabled.get("access_string") != "off ~* -@all"
        or [item.get("type") for item in disabled_auth] != ["no-password"]
        or [item.get("password_count") for item in disabled_auth] != [0]
    ):
        raise ContractError("Redis default user is not disabled")
    if (
        authority.get("user_name") != f"{CONTROL_PREFIX}-otp-auth"
        or authority.get("user_id") != f"{CONTROL_PREFIX}-otp-auth"
        or authority.get("access_string")
        != "on ~connector:* -@all +@connection +@read +@write +@scripting"
        or [item.get("type") for item in authority_auth] != ["iam"]
        or [item.get("password_count") for item in authority_auth] != [0]
    ):
        raise ContractError("Redis authority ACL drifted")
    if group.get("user_group_id") != f"{CONTROL_PREFIX}-otp-users" or set(
        group.get("user_ids", [])
    ) != {disabled.get("user_id"), authority.get("user_id")}:
        raise ContractError("Redis user-group membership drifted")

    return {"resource_count": len(resources), "vpc_id": vpc_id}


def check_live(evidence_dir: Path) -> dict[str, Any]:
    expected = load_json(evidence_dir / "expected-live.json")
    required_expected = {
        "dynamodb_endpoint_id",
        "flow_log_destination",
        "flow_log_id",
        "flow_log_role_arn",
        "isolated_route_table_ids",
        "vpc_id",
    }
    if not isinstance(expected, dict) or set(expected) != required_expected:
        raise ContractError("live expected-ID manifest is not exact")
    vpc_id = expected["vpc_id"]
    if not re.fullmatch(r"vpc-[0-9a-f]+", str(vpc_id)):
        raise ContractError("live VPC ID is malformed")
    isolated = set(expected["isolated_route_table_ids"])
    if len(isolated) != 3 or not all(
        re.fullmatch(r"rtb-[0-9a-f]+", str(value)) for value in isolated
    ):
        raise ContractError("live isolated route-table IDs are malformed")

    route_tables = load_json(evidence_dir / "route-tables.json").get("RouteTables")
    if not isinstance(route_tables, list) or len(route_tables) != 4:
        raise ContractError("Control VPC must have exactly four route tables")
    by_id = {item.get("RouteTableId"): item for item in route_tables}
    if not isolated.issubset(by_id):
        raise ContractError("isolated route tables are absent from live VPC")
    main = [
        item
        for item in route_tables
        if any(
            association.get("Main") is True
            for association in item.get("Associations", [])
        )
    ]
    if len(main) != 1 or main[0].get("RouteTableId") in isolated:
        raise ContractError("Control VPC main route table is not singular/unmanaged")
    for route_table_id, route_table in by_id.items():
        routes = route_table.get("Routes")
        if not isinstance(routes, list):
            raise ContractError(f"live routes missing for {route_table_id}")
        local_routes = [
            route
            for route in routes
            if route.get("GatewayId") == "local"
            and route.get("DestinationCidrBlock") == "10.102.0.0/16"
            and route.get("State") == "active"
        ]
        dynamodb_routes = [
            route
            for route in routes
            if route.get("GatewayId") == expected["dynamodb_endpoint_id"]
            and re.fullmatch(
                r"pl-[0-9a-f]+", str(route.get("DestinationPrefixListId", ""))
            )
            and route.get("State") == "active"
        ]
        allowed = [*local_routes, *dynamodb_routes]
        expected_count = 2 if route_table_id in isolated else 1
        if len(local_routes) != 1 or len(dynamodb_routes) != expected_count - 1:
            raise ContractError(f"live route ownership drifted for {route_table_id}")
        if len(routes) != len(allowed):
            raise ContractError(
                f"live route table has an internet/remote route: {route_table_id}"
            )

    empty_arrays = {
        "internet-gateways.json": "InternetGateways",
        "egress-only-internet-gateways.json": "EgressOnlyInternetGateways",
        "vpc-peerings.json": "VpcPeeringConnections",
        "transit-gateway-attachments.json": "TransitGatewayAttachments",
    }
    for filename, key in empty_arrays.items():
        value = load_json(evidence_dir / filename).get(key)
        if value != []:
            raise ContractError(
                f"Control VPC has forbidden live resources in {filename}"
            )
    nat_gateways = load_json(evidence_dir / "nat-gateways.json").get("NatGateways")
    if not isinstance(nat_gateways, list) or any(
        item.get("State") != "deleted" for item in nat_gateways
    ):
        raise ContractError("Control VPC has a nondeleted NAT gateway")

    flows = load_json(evidence_dir / "flow-logs.json").get("FlowLogs")
    if not isinstance(flows, list) or len(flows) != 1:
        raise ContractError("Control VPC must have exactly one Flow Log")
    flow = flows[0]
    if (
        flow.get("FlowLogId") != expected["flow_log_id"]
        or flow.get("FlowLogStatus") != "ACTIVE"
        or flow.get("DeliverLogsStatus") != "SUCCESS"
        or flow.get("DeliverLogsErrorMessage") not in (None, "")
        or flow.get("TrafficType") != "ALL"
        or flow.get("MaxAggregationInterval") != 60
        or flow.get("LogDestinationType") != "cloud-watch-logs"
        or flow.get("LogDestination") != expected["flow_log_destination"]
        or flow.get("DeliverLogsPermissionArn") != expected["flow_log_role_arn"]
    ):
        raise ContractError("Control Flow Log live delivery contract failed")

    state_head = load_json(evidence_dir / "state-head.json")
    if (
        state_head.get("ServerSideEncryption") != "aws:kms"
        or state_head.get("SSEKMSKeyId") != STATE_KMS_KEY_ARN
        or not isinstance(state_head.get("VersionId"), str)
        or not state_head["VersionId"]
        or state_head["VersionId"] == "null"
    ):
        raise ContractError(
            "Control state object is not versioned under the exact KMS key"
        )

    if load_json(evidence_dir / "control-lambdas.json") != []:
        raise ContractError("Control prefix unexpectedly owns a Lambda function")
    if load_json(evidence_dir / "control-load-balancers.json") != []:
        raise ContractError("Control prefix unexpectedly owns a load balancer")
    return {"flow_log_id": flow["FlowLogId"], "vpc_id": vpc_id}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)

    plan = sub.add_parser("plan")
    plan.add_argument("plan_json", type=Path)
    plan.add_argument(
        "--expected-action",
        choices=("create", "no-op", "recover", "recover-config"),
        required=True,
    )

    state_list = sub.add_parser("state-list")
    state_list.add_argument("path", type=Path)

    preflight = sub.add_parser("preflight")
    preflight.add_argument("evidence_dir", type=Path)
    preflight.add_argument(
        "--expected-state", choices=("absent", "present"), default="absent"
    )

    for name in (
        "artifact-create",
        "artifact-verify",
        "recovery-artifact-create",
        "recovery-artifact-verify",
    ):
        artifact = sub.add_parser(name)
        artifact.add_argument("--plan", type=Path, required=True)
        artifact.add_argument("--plan-json", type=Path, required=True)
        artifact.add_argument("--metadata", type=Path)
        artifact.add_argument("--output", type=Path)
        artifact.add_argument("--repository", required=True)
        artifact.add_argument("--commit-sha", required=True)
        artifact.add_argument("--plan-sha256", required=True)
        artifact.add_argument("--run-id", required=True)
        artifact.add_argument("--run-attempt", required=True)
        artifact.add_argument("--planned-at-epoch", required=True)
        artifact.add_argument("--workflow-ref", required=True)
        artifact.add_argument("--terraform-version", required=True)
        artifact.add_argument("--now-epoch")

    source_run = sub.add_parser("source-run")
    source_run.add_argument("run_json", type=Path)
    source_run.add_argument("--run-id", required=True)
    source_run.add_argument("--commit-sha", required=True)

    failed_run = sub.add_parser("failed-run")
    failed_run.add_argument("run_json", type=Path)

    partial_state = sub.add_parser("partial-state")
    partial_state.add_argument("state_json", type=Path)
    partial_state.add_argument("state_head_json", type=Path)

    state = sub.add_parser("state")
    state.add_argument("state_json", type=Path)
    live = sub.add_parser("live")
    live.add_argument("evidence_dir", type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        if args.command == "plan":
            result = check_plan(load_json(args.plan_json), args.expected_action)
        elif args.command == "state-list":
            result = check_state_list(args.path)
        elif args.command == "preflight":
            result = check_preflight(args.evidence_dir, args.expected_state)
        elif args.command == "artifact-create":
            if args.output is None:
                raise ContractError("artifact-create requires --output")
            result = create_artifact(args)
        elif args.command == "artifact-verify":
            if args.metadata is None:
                raise ContractError("artifact-verify requires --metadata")
            result = verify_artifact(args)
        elif args.command == "recovery-artifact-create":
            if args.output is None:
                raise ContractError("recovery-artifact-create requires --output")
            result = create_recovery_artifact(args)
        elif args.command == "recovery-artifact-verify":
            if args.metadata is None:
                raise ContractError("recovery-artifact-verify requires --metadata")
            result = verify_recovery_artifact(args)
        elif args.command == "source-run":
            check_source_run(args)
            result = {"run_id": str(args.run_id)}
        elif args.command == "failed-run":
            check_failed_run(args.run_json)
            result = {"failed_apply_run_id": FAILED_APPLY_RUN_ID}
        elif args.command == "partial-state":
            result = check_partial_state(args.state_json, args.state_head_json)
        elif args.command == "state":
            result = check_state(load_json(args.state_json))
        elif args.command == "live":
            result = check_live(args.evidence_dir)
        else:
            raise AssertionError(args.command)
    except ContractError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
