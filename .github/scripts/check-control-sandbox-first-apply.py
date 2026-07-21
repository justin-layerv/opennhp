#!/usr/bin/env python3
"""Fail-closed contracts for the sandbox Connector Control foundation."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any, Iterable


ACCOUNT_ID = "767397897469"
AWS_REGION = "us-east-2"
STATE_KMS_KEY_ARN = (
    "arn:aws:kms:us-east-2:767397897469:key/289dbe35-ab5a-4752-8564-4c96c607c9f4"
)
# Locked by the active no-op plan contract and permanent live-state verifier.
TF_VERSION = "1.14.3"
CONTROL_PREFIX = "layerv-nhp-sandbox-control"
AUTHORITY_PUBLISHER_ROLE_NAME = (
    "layerv-nhp-sandbox-control-connector-authority-publisher"
)
AUTHORITY_PUBLISHER_ECR_ARN = (
    f"arn:aws:ecr:{AWS_REGION}:{ACCOUNT_ID}:repository/"
    "layerv/qurl-connector-authority"
)
AUTHORITY_PUBLISHER_DIGEST_PARAMETER_ARN = (
    f"arn:aws:ssm:{AWS_REGION}:{ACCOUNT_ID}:parameter/"
    "sandbox/nhp/control/connector-authority/image-digest"
)
AUTHORITY_PUBLISHER_TRUST_POLICY = {
    "Statement": [
        {
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {
                "StringEquals": {
                    "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
                    "token.actions.githubusercontent.com:sub": (
                        "repo:layervai/qurl-service:environment:sandbox"
                    ),
                }
            },
            "Effect": "Allow",
            "Principal": {
                "Federated": (
                    f"arn:aws:iam::{ACCOUNT_ID}:oidc-provider/"
                    "token.actions.githubusercontent.com"
                )
            },
            "Sid": "GitHubEnvironmentPublisher",
        }
    ],
    "Version": "2012-10-17",
}
AUTHORITY_PUBLISHER_POLICY = {
    "Statement": [
        {
            "Action": "ecr:GetAuthorizationToken",
            "Effect": "Allow",
            "Resource": "*",
            "Sid": "ECRAuthorization",
        },
        {
            "Action": [
                "ecr:BatchCheckLayerAvailability",
                "ecr:BatchGetImage",
                "ecr:CompleteLayerUpload",
                "ecr:DescribeImages",
                "ecr:GetDownloadUrlForLayer",
                "ecr:InitiateLayerUpload",
                "ecr:PutImage",
                "ecr:UploadLayerPart",
            ],
            "Effect": "Allow",
            "Resource": AUTHORITY_PUBLISHER_ECR_ARN,
            "Sid": "AuthorityRepository",
        },
        {
            "Action": ["ssm:GetParameter", "ssm:PutParameter"],
            "Effect": "Allow",
            "Resource": AUTHORITY_PUBLISHER_DIGEST_PARAMETER_ARN,
            "Sid": "AuthorityDigestPin",
        },
    ],
    "Version": "2012-10-17",
}
_DYNAMODB_TABLES = (
    "agent_keys",
    "api_key_idempotency",
    "api_keys",
    "connector_authority",
    "customers",
)
# Keep this reviewed inventory synchronized with sandbox/outputs.tf. The
# refresh-only output-contract test parses that file and fails on either drift.
EXPECTED_CONTROL_OUTPUTS = frozenset(
    {
        "authority_data_kms_key_arn",
        "authority_ecr_repository_url",
        "authority_image_digest_parameter_name",
        "authority_publisher_github_environment",
        "authority_publisher_role_arn",
        "authority_publisher_role_name",
        "control_table_names",
        "control_table_prefix",
        "interface_endpoint_ids",
        "isolated_subnet_ids",
        "otp_pepper_secret_arn",
        "otp_redis_authority_user_arn",
        "otp_redis_endpoint",
        "otp_redis_user_group_id",
        "qat1_signing_kms_key_arn",
        "ses_identity_arn",
        "vpc_id",
    }
)
_OUTPUT_ENTRY_KEYS = frozenset({"sensitive", "type", "value"})
_OUTPUT_CHANGE_KEYS = frozenset(
    {
        "actions",
        "after",
        "after_sensitive",
        "after_unknown",
        "before",
        "before_sensitive",
    }
)
_PUBLISHER_REFRESH_BEFORE_SENSITIVE = {
    "inline_policy": [],
    "managed_policy_arns": [],
    "tags": {},
    "tags_all": {},
}
_PUBLISHER_REFRESH_AFTER_SENSITIVE = {
    "inline_policy": [{}],
    "managed_policy_arns": [],
    "tags": {},
    "tags_all": {},
}

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
    "module.control.aws_iam_role.authority_publisher": "aws_iam_role",
    "module.control.aws_iam_role_policy.authority_publisher": "aws_iam_role_policy",
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

PUBLISHER_BOOTSTRAP_RESOURCES = frozenset(
    {
        "module.control.aws_iam_role.authority_publisher",
        "module.control.aws_iam_role_policy.authority_publisher",
    }
)

INTERFACE_ENDPOINT_SERVICES = (
    "email",
    "kms",
    "lambda",
    "logs",
    "monitoring",
    "secretsmanager",
)
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
    "module.control.aws_iam_role_policy.authority_publisher": {
        ("role",): [
            "aws_iam_role.authority_publisher.id",
            "aws_iam_role.authority_publisher",
        ],
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
    "module.control.aws_iam_role.authority_publisher": {
        ("max_session_duration",): 3600,
    },
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
    "module.control.aws_iam_role.authority_publisher": (
        ("inline_policy",),
        ("managed_policy_arns",),
        ("permissions_boundary",),
    ),
}


class ContractError(ValueError):
    """Raised when plan or live evidence violates the reviewed contract."""


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ContractError(f"cannot read JSON {path}: {exc}") from exc


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _json_sha256(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _json_equal(left: Any, right: Any) -> bool:
    """Compare JSON values without Python's ``False == 0`` coercion."""
    return _canonical_json(left) == _canonical_json(right)


def _refresh_only_value_shape(value: Any) -> str:
    """Return a bounded, value-free diagnostic for Terraform value-tree drift."""
    if not isinstance(value, dict):
        return f"planned={type(value).__name__}"
    root = value.get("root_module")
    outputs = value.get("outputs")
    entries = list(outputs.values()) if isinstance(outputs, dict) else []
    object_entries = [entry for entry in entries if isinstance(entry, dict)]
    return ";".join(
        (
            f"planned=dict:{len(value)}",
            f"root={type(root).__name__}:"
            f"{len(root) if isinstance(root, dict) else '-'}",
            f"outputs={type(outputs).__name__}:"
            f"{len(outputs) if isinstance(outputs, dict) else '-'}",
            f"entry_objects={len(object_entries)}",
            "entry_sensitive_false="
            f"{sum(entry.get('sensitive') is False for entry in object_entries)}",
            f"entry_type_present={sum('type' in entry for entry in object_entries)}",
            f"entry_value_present={sum('value' in entry for entry in object_entries)}",
        )
    )


def _is_exact_nonsensitive_output_entry(value: Any) -> bool:
    """Require Terraform's exact non-sensitive root-output entry shape."""
    return (
        isinstance(value, dict)
        and set(value) == _OUTPUT_ENTRY_KEYS
        and value.get("sensitive") is False
    )


def contract_sha256() -> str:
    """Fingerprint the reviewed resource-address/type inventory."""
    return _json_sha256(EXPECTED_RESOURCES)


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


def _require_publisher_identity(
    role: dict[str, Any],
    policy: dict[str, Any],
    *,
    reflected_inline_policy: bool | None,
) -> None:
    role_address = "module.control.aws_iam_role.authority_publisher"
    policy_address = "module.control.aws_iam_role_policy.authority_publisher"
    _require_fields(
        role,
        {
            "max_session_duration": 3600,
            "name": AUTHORITY_PUBLISHER_ROLE_NAME,
        },
        role_address,
    )
    _require_json_field(
        role,
        "assume_role_policy",
        AUTHORITY_PUBLISHER_TRUST_POLICY,
        role_address,
    )
    if role.get("managed_policy_arns") not in (None, []):
        raise ContractError("authority publisher may not attach managed policies")
    # The locked AWS provider renders an absent permissions boundary as null on
    # create and as an empty string after refresh. Configuration validation
    # independently forbids the input; reject every nonempty live ARN here.
    if role.get("permissions_boundary") not in (None, ""):
        raise ContractError("authority publisher may not use a permissions boundary")
    inline_policies = role.get("inline_policy")
    if inline_policies in (None, []):
        if reflected_inline_policy is True:
            raise ContractError(
                "authority publisher role must reflect its separately managed inline policy"
            )
    else:
        if reflected_inline_policy is False:
            raise ContractError(
                "authority publisher role reflected an inline policy before its separate policy exists"
            )
        if (
            not isinstance(inline_policies, list)
            or len(inline_policies) != 1
            or not isinstance(inline_policies[0], dict)
            or set(inline_policies[0]) != {"name", "policy"}
        ):
            raise ContractError(
                "authority publisher role must reflect exactly its separately managed inline policy"
            )
        _require_fields(
            inline_policies[0],
            {"name": "publish-connector-authority"},
            role_address,
        )
        _require_json_field(
            inline_policies[0],
            "policy",
            AUTHORITY_PUBLISHER_POLICY,
            role_address,
        )
    _require_fields(
        policy,
        {"name": "publish-connector-authority"},
        policy_address,
    )
    _require_json_field(
        policy,
        "policy",
        AUTHORITY_PUBLISHER_POLICY,
        policy_address,
    )


def _check_planned_security(by_address: dict[str, dict[str, Any]]) -> None:
    def values(address: str) -> tuple[dict[str, Any], dict[str, Any]]:
        change = by_address[address].get("change", {})
        after = change.get("after")
        unknown = change.get("after_unknown", {})
        if not isinstance(after, dict) or not isinstance(unknown, dict):
            raise ContractError(f"{address} planned values are malformed")
        return after, unknown

    vpc, _ = values("module.control.aws_vpc.control")
    # Keep the complete provider-version-specific no-op shape visible here as
    # literals rather than deriving its dimensions independently. The empty-
    # string / zero IPv6 values below are the exact no-op shape emitted by the
    # locked AWS provider version (see the authentication-mode note below
    # before changing them).
    _require_fields(
        vpc,
        {
            "cidr_block": "10.102.0.0/16",
            "enable_dns_hostnames": True,
            "enable_dns_support": True,
            "instance_tenancy": "default",
            "ipv4_ipam_pool_id": None,
            "ipv4_netmask_length": None,
            "ipv6_ipam_pool_id": "",
            "ipv6_netmask_length": 0,
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
    # upgrade must regenerate and re-review the plan fixtures before changing
    # this split (including the analogous IPv6 null/empty shapes).
    for address, auth_type in (
        ("module.control.aws_elasticache_user.otp_authority", "iam"),
        (
            "module.control.aws_elasticache_user.otp_disabled_default",
            "no-password",
        ),
    ):
        after, _ = values(address)
        auth = after.get("authentication_mode")
        if (
            not isinstance(auth, list)
            or len(auth) != 1
            or not isinstance(auth[0], dict)
            or auth[0].get("type") != auth_type
            or auth[0].get("passwords") != []
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

    publisher_role_address = "module.control.aws_iam_role.authority_publisher"
    publisher_role, publisher_role_unknown = values(publisher_role_address)
    publisher_policy_address = (
        "module.control.aws_iam_role_policy.authority_publisher"
    )
    publisher_policy, publisher_policy_unknown = values(publisher_policy_address)
    publisher_role_is_create = (
        by_address[publisher_role_address].get("change", {}).get("actions")
        == ["create"]
    )
    allowed_managed_policy_unknown = (
        (None, [], False, True)
        if publisher_role_is_create
        else (None, [], False)
    )
    if (
        publisher_role_unknown.get("managed_policy_arns")
        not in allowed_managed_policy_unknown
    ):
        raise ContractError("authority publisher managed policies may not be unknown")

    publisher_policy_is_create = (
        by_address[publisher_policy_address].get("change", {}).get("actions")
        == ["create"]
    )
    _require_publisher_identity(
        publisher_role,
        publisher_policy,
        # The refresh-disabled PR plan sees the pre-normalization empty
        # computed field; a refreshed plan sees the exact reflected policy.
        # Both are safe no-op representations, while create/partial-retry must
        # remain empty until the separate policy exists.
        reflected_inline_policy=(
            False if publisher_role_is_create or publisher_policy_is_create else None
        ),
    )
    _require_fields(
        publisher_role,
        {"path": "/"},
        publisher_role_address,
    )
    if publisher_policy_is_create and publisher_role_is_create:
        if (
            publisher_policy.get("role") is not None
            or publisher_policy_unknown.get("role") is not True
        ):
            raise ContractError("authority publisher create must derive its role")
    elif publisher_policy.get("role") != AUTHORITY_PUBLISHER_ROLE_NAME:
        raise ContractError("authority publisher policy role drifted")


def _check_publisher_state_normalization_drift(
    drift: list[dict[str, Any]],
    by_address: dict[str, dict[str, Any]],
) -> int:
    """Admit only the provider's exact state-only inline-policy reflection.

    Terraform marks that delta applyable for ``-refresh-only``. An ordinary
    refresh-enabled plan with no configuration changes is not applyable and is
    rejected by ``check_plan`` below, independent of the workflow operation.
    """
    if not drift:
        return 0
    role_address = "module.control.aws_iam_role.authority_publisher"
    if len(drift) != 1:
        raise ContractError("refresh-only plan must normalize exactly one resource")
    item = drift[0]
    if (
        item.get("address") != role_address
        or item.get("mode") != "managed"
        or item.get("type") != "aws_iam_role"
    ):
        raise ContractError("refresh-only plan may normalize only the publisher role")
    change = item.get("change")
    if not isinstance(change, dict) or change.get("actions") != ["update"]:
        raise ContractError("publisher role normalization must be an in-state update")
    before = change.get("before")
    after = change.get("after")
    if not isinstance(before, dict) or not isinstance(after, dict):
        raise ContractError("publisher role normalization values are malformed")
    changed_fields = {
        field
        for field in set(before) | set(after)
        if field not in before or field not in after or before[field] != after[field]
    }
    if changed_fields != {"inline_policy"} or before.get("inline_policy") not in (
        None,
        [],
    ):
        raise ContractError(
            "publisher role normalization may only reflect its separately managed inline policy; "
            f"changed_fields={sorted(changed_fields)}"
        )
    planned_role = by_address[role_address].get("change", {})
    if planned_role.get("actions") != ["no-op"] or planned_role.get("after") != after:
        raise ContractError(
            "publisher role normalization must match the refresh-only no-op state"
        )
    publisher_policy = by_address[
        "module.control.aws_iam_role_policy.authority_publisher"
    ].get("change", {}).get("after")
    if not isinstance(publisher_policy, dict):
        raise ContractError("publisher policy normalization values are malformed")
    _require_publisher_identity(
        after,
        publisher_policy,
        reflected_inline_policy=True,
    )
    return 1


def _check_refresh_only_outputs(
    plan: dict[str, Any], prior_state: dict[str, Any]
) -> None:
    """Bind Terraform's value-only refresh envelope to captured state.

    Terraform 1.14.3 omits unchanged resources from a refresh-only plan, but
    still serializes all root outputs. Keep the resource/module tree exactly
    empty and require those outputs, plus their changes, to be exact
    non-sensitive no-ops against the version-bound pre-plan state.
    """
    planned_values = plan.get("planned_values")
    if (
        not isinstance(planned_values, dict)
        or set(planned_values) != {"outputs", "root_module"}
        or planned_values.get("root_module") != {}
    ):
        raise ContractError(
            f"refresh-only Terraform {TF_VERSION} value tree is malformed; "
            f"{_refresh_only_value_shape(planned_values)}"
        )

    planned_outputs = planned_values.get("outputs")
    state_values = prior_state.get("values")
    state_outputs = (
        state_values.get("outputs") if isinstance(state_values, dict) else None
    )
    if (
        not isinstance(planned_outputs, dict)
        or set(planned_outputs) != EXPECTED_CONTROL_OUTPUTS
        or not isinstance(state_outputs, dict)
        or set(state_outputs) != EXPECTED_CONTROL_OUTPUTS
    ):
        raise ContractError(
            f"refresh-only Terraform {TF_VERSION} output inventory is malformed; "
            f"{_refresh_only_value_shape(planned_values)}"
        )

    for output_name in EXPECTED_CONTROL_OUTPUTS:
        planned_output = planned_outputs[output_name]
        state_output = state_outputs[output_name]
        # Terraform 1.14.3 collapses non-sensitive scalar and complex root
        # outputs to the literal false; the version-pinned fixture covers both
        # object and tuple values so a representation change fails closed.
        if (
            not _is_exact_nonsensitive_output_entry(planned_output)
            or not _is_exact_nonsensitive_output_entry(state_output)
            or not _json_equal(planned_output, state_output)
        ):
            raise ContractError(
                f"refresh-only Terraform {TF_VERSION} outputs do not match captured state; "
                f"{_refresh_only_value_shape(planned_values)}"
            )

    output_changes = plan.get("output_changes")
    if (
        not isinstance(output_changes, dict)
        or set(output_changes) != EXPECTED_CONTROL_OUTPUTS
    ):
        raise ContractError(
            f"refresh-only Terraform {TF_VERSION} output changes are malformed; "
            f"{_refresh_only_value_shape(planned_values)}"
        )
    for output_name in EXPECTED_CONTROL_OUTPUTS:
        change = output_changes[output_name]
        output_value = planned_outputs[output_name]["value"]
        if (
            not isinstance(change, dict)
            or set(change) != _OUTPUT_CHANGE_KEYS
            or change.get("actions") != ["no-op"]
            or change.get("after_unknown") is not False
            or change.get("before_sensitive") is not False
            or change.get("after_sensitive") is not False
            or not _json_equal(change.get("before"), output_value)
            or not _json_equal(change.get("after"), output_value)
        ):
            raise ContractError(
                f"refresh-only Terraform {TF_VERSION} outputs must be exact no-ops; "
                f"{_refresh_only_value_shape(planned_values)}"
            )


def _plan_resource_changes(
    plan: dict[str, Any],
    drift: list[dict[str, Any]],
    prior_state: Any,
) -> list[dict[str, Any]]:
    """Return ordinary changes or reconstruct Terraform's refresh-only shape.

    Terraform 1.14 omits ``resource_changes`` when ``-refresh-only`` has no
    configuration changes, and its ``planned_values`` may omit every unchanged
    resource. Preserve the exact-inventory and planned-value checks by using the
    separately captured, version-bound pre-plan state for the unchanged
    inventory and overlaying only the admitted refresh drift. The workflow
    proves that state object did not move while planning and re-captures the
    identical object before apply.
    """
    if "resource_changes" in plan:
        changes = plan["resource_changes"]
        if not isinstance(changes, list):
            raise ContractError("Terraform plan resource_changes must be an array")
        return changes
    if not drift:
        raise ContractError("Terraform plan resource_changes must be an array")

    if (
        not isinstance(prior_state, dict)
        or prior_state.get("format_version") != "1.0"
        or prior_state.get("terraform_version") != TF_VERSION
    ):
        raise ContractError(
            f"refresh-only compatibility requires exact Terraform {TF_VERSION} state JSON"
        )
    _check_refresh_only_outputs(plan, prior_state)

    state_values = prior_state.get("values")
    root = (
        state_values.get("root_module") if isinstance(state_values, dict) else None
    )
    resources = [
        item for item in _iter_resources(root) if item.get("mode") == "managed"
    ]
    if not resources:
        raise ContractError(
            "refresh-only plan requires the captured pre-plan state inventory"
        )

    drift_by_address: dict[str, dict[str, Any]] = {}
    for item in drift:
        address = item.get("address") if isinstance(item, dict) else None
        if not isinstance(address, str):
            raise ContractError("Terraform resource drift is malformed")
        if address in drift_by_address:
            raise ContractError(f"duplicate Terraform resource drift: {address}")
        drift_by_address[address] = item

    changes: list[dict[str, Any]] = []
    matched_drift_addresses: set[str] = set()
    for item in resources:
        address = item.get("address")
        resource_values = item.get("values")
        if not isinstance(address, str) or not isinstance(resource_values, dict):
            raise ContractError("Terraform prior-state resource is malformed")
        resolved_values = resource_values
        drift_item = drift_by_address.get(address)
        if drift_item is not None:
            matched_drift_addresses.add(address)
            change = drift_item.get("change")
            if not isinstance(change, dict):
                raise ContractError("Terraform resource drift change is malformed")
            if change.get("after_unknown") != {}:
                raise ContractError(
                    "refresh-only publisher drift contains unknown values"
                )
            if (
                "before_sensitive" not in change
                or "after_sensitive" not in change
                or not _json_equal(
                    change["before_sensitive"],
                    _PUBLISHER_REFRESH_BEFORE_SENSITIVE,
                )
                or not _json_equal(
                    change["after_sensitive"],
                    _PUBLISHER_REFRESH_AFTER_SENSITIVE,
                )
            ):
                raise ContractError(
                    "refresh-only publisher drift has unexpected sensitive-value metadata"
                )
            # Terraform 1.14.3 renders the same resource values in the captured
            # state and drift.before. Keep that equality exact: a provider or
            # Terraform representation change must abort rather than weaken the
            # state-to-plan binding.
            if change.get("before") != resource_values:
                raise ContractError(
                    f"refresh drift before value does not match captured state: {address}"
                )
            resolved_values = change.get("after")
            if not isinstance(resolved_values, dict):
                raise ContractError("Terraform resource drift after value is malformed")
        changes.append(
            {
                "address": address,
                "mode": item.get("mode"),
                "type": item.get("type"),
                "change": {
                    "actions": ["no-op"],
                    "after": resolved_values,
                    "after_unknown": {},
                    "before": resolved_values,
                },
            }
        )
    unmatched_drift = sorted(set(drift_by_address) - matched_drift_addresses)
    if unmatched_drift:
        raise ContractError(
            f"refresh drift is absent from captured state: {unmatched_drift}"
        )
    return changes


def check_plan(plan: Any, prior_state: Any = None) -> dict[str, str | int]:
    """Validate one exact reviewed plan shape.

    ``prior_state`` is required only when Terraform omits ``resource_changes``
    for the reviewed refresh-only compatibility shape. Ordinary callers, such
    as the refresh-disabled PR plan lane, may omit it; if their plan shape ever
    loses ``resource_changes``, this checker deliberately fails closed.
    """
    if not isinstance(plan, dict):
        raise ContractError("Terraform plan must be an object")
    if plan.get("format_version") != "1.2":
        raise ContractError("Terraform plan format_version must be 1.2")
    if plan.get("terraform_version") != TF_VERSION:
        raise ContractError(f"Terraform plan must use exact {TF_VERSION}")
    if plan.get("complete") is not True or plan.get("errored") is not False:
        raise ContractError("Terraform plan must be complete and non-errored")
    drift = _non_noop(plan.get("resource_drift"), "resource_drift")
    _check_no_embedded_actions(plan)

    changes = _plan_resource_changes(plan, drift, prior_state)
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

    bootstrap_creates: set[str] = set()
    for address, expected_type in EXPECTED_RESOURCES.items():
        item = by_address[address]
        if item.get("mode") != "managed" or item.get("type") != expected_type:
            raise ContractError(f"unexpected mode/type for {address}")
        change = item.get("change")
        if not isinstance(change, dict):
            raise ContractError(f"{address} change is malformed")
        actions = change.get("actions")
        if actions == ["no-op"]:
            if change.get("before") != change.get("after"):
                raise ContractError(f"{address} no-op before and after differ")
            continue
        if address in PUBLISHER_BOOTSTRAP_RESOURCES and actions == ["create"]:
            if change.get("before") is not None or not isinstance(
                change.get("after"), dict
            ):
                raise ContractError(f"{address} create shape is malformed")
            bootstrap_creates.add(address)
            continue
        raise ContractError(
            f"{address} must be no-op or an exact publisher bootstrap create"
        )

    publisher_role_address = "module.control.aws_iam_role.authority_publisher"
    publisher_policy_address = (
        "module.control.aws_iam_role_policy.authority_publisher"
    )
    if (
        publisher_role_address in bootstrap_creates
        and publisher_policy_address not in bootstrap_creates
    ):
        raise ContractError(
            "authority publisher role create requires its inline policy create"
        )

    _check_planned_security(by_address)

    normalization_drift_count = _check_publisher_state_normalization_drift(
        drift, by_address
    )

    expected_applyable = bool(bootstrap_creates or normalization_drift_count)
    if plan.get("applyable") is not expected_applyable:
        raise ContractError(
            "Terraform applyability must match exact publisher bootstrap creates "
            "or the exact refresh-only state normalization"
        )
    # Bind the complete admitted drift across the review-time and immediate
    # pre-apply plans. Canonical object-key ordering removes JSON presentation
    # noise, while any value or list-order change intentionally aborts apply.
    return {
        "bootstrap_create_count": len(bootstrap_creates),
        "contract_sha256": contract_sha256(),
        "normalization_drift_sha256": _json_sha256(drift),
        "normalization_drift_count": normalization_drift_count,
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
    # remains mode-aware and independently enforces the exact 43 managed
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

    publisher_role = values["module.control.aws_iam_role.authority_publisher"]
    publisher_policy = values[
        "module.control.aws_iam_role_policy.authority_publisher"
    ]
    _require_publisher_identity(
        publisher_role,
        publisher_policy,
        reflected_inline_policy=True,
    )
    if publisher_policy.get("role") != AUTHORITY_PUBLISHER_ROLE_NAME:
        raise ContractError("authority publisher inline policy identity drifted")

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
    plan.add_argument("prior_state_json", nargs="?", type=Path)

    state_list = sub.add_parser("state-list")
    state_list.add_argument("path", type=Path)

    state = sub.add_parser("state")
    state.add_argument("state_json", type=Path)
    live = sub.add_parser("live")
    live.add_argument("evidence_dir", type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        if args.command == "plan":
            prior_state = (
                load_json(args.prior_state_json) if args.prior_state_json else None
            )
            result = check_plan(load_json(args.plan_json), prior_state)
        elif args.command == "state-list":
            result = check_state_list(args.path)
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
