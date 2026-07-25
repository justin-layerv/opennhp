#!/usr/bin/env python3
"""Hermetic fail-closed tests for the sandbox Control foundation boundary."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CHECKER_PATH = ROOT / ".github/scripts/check-control-sandbox-first-apply.py"
VALIDATE_WORKFLOW_PATH = ROOT / ".github/workflows/validate-workflows.yml"
TERRAFORM_PLAN_WORKFLOW_PATH = ROOT / ".github/workflows/terraform-plan-pr.yml"
MAKEFILE_PATH = ROOT / "Makefile"
SECRET_SEED_SCRIPT_PATH = ROOT / "scripts/ensure-control-otp-pepper.sh"
REDIS_TF_PATH = (
    ROOT / "terraform/modules/connector-authority-foundation/redis.tf"
)
AUTHORITY_ECR_TF_PATH = (
    ROOT / "terraform/modules/connector-authority-foundation/ecr.tf"
)
HUB_ARTIFACT_TF_PATH = (
    ROOT / "terraform/modules/connector-authority-foundation/hub_artifact.tf"
)
PUBLISHER_TF_PATH = (
    ROOT / "terraform/modules/connector-authority-foundation/publisher.tf"
)
CONTROL_README_PATH = ROOT / "terraform/control/README.md"
HUB_ROLLOUT_LEDGER_PATH = (
    ROOT
    / "docs/runbooks/prod-rollout-ledger/"
    "2026-07-23-issue-3227-hub-artifact-foundation.md"
)
CONTROL_LOCKFILE_PATH = (
    ROOT / "terraform/control/environments/sandbox/.terraform.lock.hcl"
)
EXPECTED_AWS_PROVIDER_VERSION = "6.55.0"
REAL_TERRAFORM_NOOP_FIXTURE_PATH = (
    ROOT / "tests/fixtures/qurl-agent-transact-iam/no-op-terraform-1.14.3.json"
)
REAL_REDIS_IAM_CREATE_FIXTURE_PATH = (
    ROOT
    / "tests/fixtures/control-elasticache-user/"
    "create-authentication-mode-terraform-1.14.3-aws-6.55.0.json"
)
REAL_REDIS_PASSWORD_REFRESH_FIXTURE_PATH = (
    ROOT
    / "tests/fixtures/control-elasticache-user/"
    "refresh-passwords-null-to-empty-terraform-1.14.3-aws-6.55.0.json"
)
SPEC = importlib.util.spec_from_file_location("control_first_apply", CHECKER_PATH)
assert SPEC and SPEC.loader
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)


def planned_security_fixture() -> dict[str, tuple[dict, dict]]:
    data_key_arn = (
        f"arn:aws:kms:{CHECKER.AWS_REGION}:{CHECKER.ACCOUNT_ID}:"
        "key/data123"
    )
    result: dict[str, tuple[dict, dict]] = {
        "module.control.aws_vpc.control": (
            {
                "assign_generated_ipv6_cidr_block": None,
                "cidr_block": "10.102.0.0/16",
                "enable_dns_hostnames": True,
                "enable_dns_support": True,
                "instance_tenancy": "default",
                "ipv4_ipam_pool_id": None,
                "ipv4_netmask_length": None,
                "ipv6_ipam_pool_id": None,
                "ipv6_netmask_length": None,
                "region": CHECKER.AWS_REGION,
            },
            {},
        ),
        "module.control.terraform_data.foundation_contract": (
            {
                "input": {
                    "account_id": CHECKER.ACCOUNT_ID,
                    "control_table_prefix": CHECKER.CONTROL_PREFIX,
                    "region": CHECKER.AWS_REGION,
                },
                "output": {
                    "account_id": CHECKER.ACCOUNT_ID,
                    "control_table_prefix": CHECKER.CONTROL_PREFIX,
                    "region": CHECKER.AWS_REGION,
                },
            },
            {},
        ),
        "module.control.aws_kms_key.authority_data": (
            {
                "bypass_policy_lockout_safety_check": False,
                "customer_master_key_spec": "SYMMETRIC_DEFAULT",
                "deletion_window_in_days": 7,
                "enable_key_rotation": True,
                "is_enabled": True,
                "key_usage": "ENCRYPT_DECRYPT",
                "arn": data_key_arn,
                "policy": json.dumps(CHECKER.AUTHORITY_DATA_KMS_POLICY),
                "region": CHECKER.AWS_REGION,
            },
            {},
        ),
        "module.control.aws_kms_key.qat1_signing": (
            {
                "bypass_policy_lockout_safety_check": False,
                "customer_master_key_spec": "ECC_NIST_P256",
                "deletion_window_in_days": 7,
                "enable_key_rotation": False,
                "is_enabled": True,
                "key_usage": "SIGN_VERIFY",
                "policy": json.dumps(CHECKER.QAT1_SIGNING_KMS_POLICY),
                "region": CHECKER.AWS_REGION,
            },
            {},
        ),
        "module.control.aws_iam_role.authority_publisher": (
            {
                "assume_role_policy": json.dumps(
                    CHECKER.AUTHORITY_PUBLISHER_TRUST_POLICY
                ),
                "inline_policy": [
                    {
                        "name": "publish-connector-authority",
                        "policy": json.dumps(CHECKER.AUTHORITY_PUBLISHER_POLICY),
                    }
                ],
                "managed_policy_arns": [],
                "max_session_duration": 3600,
                "name": CHECKER.AUTHORITY_PUBLISHER_ROLE_NAME,
                "path": "/",
                "permissions_boundary": "",
                "tags": {"Component": "connector-authority"},
                "tags_all": {"Component": "connector-authority"},
            },
            {"managed_policy_arns": []},
        ),
        "module.control.aws_iam_role_policy.authority_publisher": (
            {
                "name": "publish-connector-authority",
                "policy": json.dumps(CHECKER.AUTHORITY_PUBLISHER_POLICY),
                "role": CHECKER.AUTHORITY_PUBLISHER_ROLE_NAME,
            },
            {},
        ),
        "module.control.aws_ecr_repository.hub": (
            {
                "arn": CHECKER.HUB_ECR_REPOSITORY_ARN,
                "encryption_configuration": [
                    {"encryption_type": "KMS", "kms_key": data_key_arn}
                ],
                "force_delete": False,
                "image_scanning_configuration": [{"scan_on_push": True}],
                "image_tag_mutability": "IMMUTABLE",
                "name": CHECKER.HUB_ECR_REPOSITORY_NAME,
                "region": CHECKER.AWS_REGION,
                "repository_url": (
                    f"{CHECKER.ACCOUNT_ID}.dkr.ecr.{CHECKER.AWS_REGION}."
                    "amazonaws.com/layerv/nhp-hub"
                ),
            },
            {},
        ),
        "module.control.aws_ecr_lifecycle_policy.hub": (
            {
                "policy": json.dumps(CHECKER.HUB_ECR_LIFECYCLE_POLICY),
                "region": CHECKER.AWS_REGION,
                "repository": CHECKER.HUB_ECR_REPOSITORY_NAME,
            },
            {},
        ),
        "module.control.aws_ssm_parameter.hub_image_digest": (
            {
                "allowed_pattern": "",
                "data_type": "text",
                "description": (
                    "Immutable sha256 digest for the separately published "
                    "Connector Hub image"
                ),
                "has_value_wo": False,
                "insecure_value": None,
                "key_id": "",
                "name": CHECKER.HUB_IMAGE_DIGEST_PARAMETER_NAME,
                "overwrite": None,
                "region": CHECKER.AWS_REGION,
                "tier": "Standard",
                "type": "String",
                "value": "UNPUBLISHED",
                "value_wo": None,
                "value_wo_version": None,
            },
            {},
        ),
        "module.control.aws_iam_role.hub_publisher": (
            {
                "assume_role_policy": json.dumps(
                    CHECKER.HUB_PUBLISHER_TRUST_POLICY
                ),
                "inline_policy": [
                    {
                        "name": "publish-connector-hub",
                        "policy": json.dumps(CHECKER.HUB_PUBLISHER_POLICY),
                    }
                ],
                "managed_policy_arns": [],
                "max_session_duration": 3600,
                "name": CHECKER.HUB_PUBLISHER_ROLE_NAME,
                "path": "/",
                "permissions_boundary": "",
                "tags": {"Component": "connector-hub"},
                "tags_all": {"Component": "connector-hub"},
            },
            {"managed_policy_arns": []},
        ),
        "module.control.aws_iam_role_policy.hub_publisher": (
            {
                "name": "publish-connector-hub",
                "policy": json.dumps(CHECKER.HUB_PUBLISHER_POLICY),
                "role": CHECKER.HUB_PUBLISHER_ROLE_NAME,
            },
            {},
        ),
        "module.control.aws_elasticache_user.otp_authority": (
            {
                "access_string": CHECKER.OTP_REDIS_LEGACY_ACCESS,
                "authentication_mode": [{"passwords": None, "type": "iam"}],
                "engine": "redis",
                "region": CHECKER.AWS_REGION,
                "user_id": f"{CHECKER.CONTROL_PREFIX}-otp-auth",
                "user_name": f"{CHECKER.CONTROL_PREFIX}-otp-auth",
            },
            {},
        ),
        "module.control.aws_elasticache_user.otp_issuer": (
            {
                "access_string": CHECKER.OTP_REDIS_ISSUER_ACCESS,
                "authentication_mode": [{"passwords": None, "type": "iam"}],
                "engine": "redis",
                "region": CHECKER.AWS_REGION,
                "user_id": f"{CHECKER.CONTROL_PREFIX}-otp-issuer",
                "user_name": f"{CHECKER.CONTROL_PREFIX}-otp-issuer",
            },
            {},
        ),
        "module.control.aws_elasticache_user.otp_activator": (
            {
                "access_string": CHECKER.OTP_REDIS_ACTIVATOR_ACCESS,
                "authentication_mode": [{"passwords": None, "type": "iam"}],
                "engine": "redis",
                "region": CHECKER.AWS_REGION,
                "user_id": f"{CHECKER.CONTROL_PREFIX}-otp-activator",
                "user_name": f"{CHECKER.CONTROL_PREFIX}-otp-activator",
            },
            {},
        ),
        "module.control.aws_elasticache_user.otp_disabled_default": (
            {
                "access_string": "off ~* -@all",
                "authentication_mode": [
                    {"passwords": None, "type": "no-password-required"}
                ],
                "engine": "redis",
                "region": CHECKER.AWS_REGION,
                "user_id": f"{CHECKER.CONTROL_PREFIX}-otp-default",
                "user_name": "default",
            },
            {},
        ),
        "module.control.aws_elasticache_user_group.otp": (
            {
                "engine": "redis",
                "region": CHECKER.AWS_REGION,
                "user_group_id": f"{CHECKER.CONTROL_PREFIX}-otp-users",
                "user_ids": [
                    f"{CHECKER.CONTROL_PREFIX}-otp-activator",
                    f"{CHECKER.CONTROL_PREFIX}-otp-default",
                    f"{CHECKER.CONTROL_PREFIX}-otp-issuer",
                ],
            },
            {},
        ),
        "module.control.aws_elasticache_serverless_cache.otp": (
            {
                "cache_usage_limits": [
                    {
                        "data_storage": [{"maximum": 1, "unit": "GB"}],
                        "ecpu_per_second": [{"maximum": 1000}],
                    }
                ],
                "engine": "redis",
                "major_engine_version": "7",
                "name": f"{CHECKER.CONTROL_PREFIX}-otp",
                "region": CHECKER.AWS_REGION,
                "snapshot_arns_to_restore": None,
                "snapshot_retention_limit": 0,
                "user_group_id": f"{CHECKER.CONTROL_PREFIX}-otp-users",
            },
            {},
        ),
    }
    for address in (
        "module.control.aws_default_security_group.control",
        "module.control.aws_security_group.interface_endpoints",
        "module.control.aws_security_group.otp_redis",
    ):
        result[address] = ({"ingress": [], "egress": []}, {"ingress": [], "egress": []})
    for index, availability_zone in enumerate(
        ("us-east-2a", "us-east-2b", "us-east-2c")
    ):
        result[f"module.control.aws_subnet.isolated[{index}]"] = (
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
                "region": CHECKER.AWS_REGION,
            },
            {},
        )
    for service in (
        "dynamodb",
        "email",
        "kms",
        "lambda",
        "logs",
        "monitoring",
        "secretsmanager",
    ):
        address = (
            "module.control.aws_vpc_endpoint.dynamodb"
            if service == "dynamodb"
            else f'module.control.aws_vpc_endpoint.interface["{service}"]'
        )
        after = {
            "policy": json.dumps(CHECKER.DENY_ENDPOINT_POLICY),
            "region": CHECKER.AWS_REGION,
            "service_name": f"com.amazonaws.{CHECKER.AWS_REGION}.{service}",
            "vpc_endpoint_type": "Gateway" if service == "dynamodb" else "Interface",
        }
        if service != "dynamodb":
            after["private_dns_enabled"] = True
        result[address] = (after, {})
    return result


def authority_runtime_input_fixture() -> dict:
    evidence = {
        "repository": "layervai/nhp",
        "source_commit": "a" * 40,
        "path": (
            "docs/evidence/connector-authority/v1/"
            "sandbox-measurement-basis.json"
        ),
        "sha256": "b" * 64,
        "schema_version": 1,
    }
    digest = "sha256:" + "1" * 64
    repository = (
        f"{CHECKER.ACCOUNT_ID}.dkr.ecr.{CHECKER.AWS_REGION}.amazonaws.com/"
        "layerv/qurl-connector-authority"
    )
    functions = {
        name: {
            "basis_evidence": copy.deepcopy(evidence),
            "result_evidence": None,
        }
        for name in (
            "layerv-nhp-sandbox-ca-ia",
            "layerv-nhp-sandbox-ca-ra",
            "layerv-nhp-sandbox-ca-icr",
        )
    }
    return {
        "account_id": CHECKER.ACCOUNT_ID,
        "control_table_prefix": CHECKER.CONTROL_PREFIX,
        "region": CHECKER.AWS_REGION,
        "authority_image_uri": f"{repository}@{digest}",
        "authority_runtime_contract": {
            "schema_version": 1,
            "phase": "measurement",
            "selected_authority_color": "blue",
            "provisioned_cells": {"cell0": {"caller_role_arn": "fixture"}},
            "provisioned_cells_evidence": copy.deepcopy(evidence),
            "global": {
                "authority_repository_url": repository,
                "authority_image_digest": digest,
                "basis_evidence": copy.deepcopy(evidence),
                "result_evidence": None,
            },
            "functions": functions,
        },
    }


def set_expression_path(
    expressions: dict, path: tuple[str | int, ...], value: object
) -> None:
    current: object = expressions
    for index, part in enumerate(path):
        last = index == len(path) - 1
        next_part = None if last else path[index + 1]
        if isinstance(part, str):
            assert isinstance(current, dict)
            if last:
                current[part] = copy.deepcopy(value)
            else:
                current = current.setdefault(
                    part, [] if isinstance(next_part, int) else {}
                )
        else:
            assert isinstance(current, list)
            while len(current) <= part:
                current.append(None)
            if last:
                current[part] = copy.deepcopy(value)
            else:
                if current[part] is None:
                    current[part] = [] if isinstance(next_part, int) else {}
                current = current[part]


def delete_expression_path(expressions: dict, path: tuple[str | int, ...]) -> None:
    current: object = expressions
    for part in path[:-1]:
        if isinstance(part, str):
            assert isinstance(current, dict)
        else:
            assert isinstance(current, list)
        current = current[part]
    last = path[-1]
    if isinstance(last, str):
        assert isinstance(current, dict)
        del current[last]
    else:
        assert isinstance(current, list)
        del current[last]


def configuration_fixture() -> dict:
    resources = []
    by_address = {}
    prefix = "module.control."
    for address, (
        mode,
        resource_type,
        provider_config_key,
    ) in CHECKER.EXPECTED_CONFIGURATION_RESOURCES.items():
        assert address.startswith(prefix)
        resource = {
            "address": address.removeprefix(prefix),
            "mode": mode,
            "provider_config_key": provider_config_key,
            "type": resource_type,
            "expressions": {},
        }
        resources.append(resource)
        by_address[address] = resource
    for address, paths in CHECKER.CONFIG_REFERENCE_CONTRACT.items():
        for path, references in paths.items():
            if path == ("count",):
                by_address[address]["count_expression"] = {
                    "references": references
                }
                continue
            set_expression_path(
                by_address[address]["expressions"],
                path,
                {"references": references},
            )
    for address, paths in CHECKER.CONFIG_CONSTANT_CONTRACT.items():
        for path, constant in paths.items():
            set_expression_path(
                by_address[address]["expressions"],
                path,
                {"constant_value": constant},
            )
    return {
        "provider_config": {
            "aws": {
                "name": "aws",
                "full_name": "registry.terraform.io/hashicorp/aws",
                "version_constraint": "~> 6.27",
                "expressions": {
                    "default_tags": [{"tags": {"references": ["var.environment"]}}],
                    "region": {"references": ["var.aws_region"]},
                },
            },
            "module.control:terraform": {
                "name": "terraform",
                "full_name": "terraform.io/builtin/terraform",
                "module_address": "module.control",
            },
            "module.control:archive": {
                "name": "archive",
                "full_name": "registry.terraform.io/hashicorp/archive",
                "module_address": "module.control",
                "version_constraint": "~> 2.7",
            },
        },
        "root_module": {
            "resources": [],
            "module_calls": {
                "control": {"module": {"resources": resources, "module_calls": {}}}
            },
        },
    }


def plan_fixture() -> dict:
    security = planned_security_fixture()
    vpc = security["module.control.aws_vpc.control"][0]
    vpc["assign_generated_ipv6_cidr_block"] = False
    vpc["ipv6_ipam_pool_id"] = ""
    vpc["ipv6_netmask_length"] = 0
    for address, auth_type in (
        ("module.control.aws_elasticache_user.otp_activator", "iam"),
        ("module.control.aws_elasticache_user.otp_authority", "iam"),
        (
            "module.control.aws_elasticache_user.otp_disabled_default",
            "no-password",
        ),
        ("module.control.aws_elasticache_user.otp_issuer", "iam"),
    ):
        security[address][0]["authentication_mode"] = [
            {
                "password_count": 0,
                "passwords": [],
                "type": auth_type,
            }
        ]
    changes = []
    for address, resource_type in CHECKER.EXPECTED_RESOURCES.items():
        after, after_unknown = copy.deepcopy(
            security.get(address, ({"id": address}, {}))
        )
        before = copy.deepcopy(after)
        changes.append(
            {
                "address": address,
                "mode": "managed",
                "type": resource_type,
                "change": {
                    "actions": ["no-op"],
                    "before": before,
                    "after": after,
                    "after_unknown": after_unknown,
                },
            }
        )
    return {
        "format_version": "1.2",
        "terraform_version": CHECKER.TF_VERSION,
        "complete": True,
        "errored": False,
        "applyable": False,
        "action_invocations": [],
        "configuration": configuration_fixture(),
        "resource_drift": [],
        "resource_changes": changes,
    }


def authority_enablement_drift_pair(candidate: dict) -> list[dict]:
    """Build the exact benign ``resource_drift`` pair the live Step-3 Connector
    Authority enablement plan carries, and align the planned no-op digest state
    the digest drift refreshes to.

    The enablement plan's refresh phase always observes TWO independent,
    externally driven state normalizations at once, so the real plan carries this
    pair (not a single entry). Each item mirrors the exact single-drift shape
    proven benign elsewhere:

    * the Hub publisher inline-policy reflection -- see
      ``test_exact_hub_publisher_refresh_only_normalization_passes`` and
      ``publisher_refresh_candidate(hub=True)``;
    * the externally rolled Authority image digest -- see
      ``test_exact_authority_digest_refresh_only_normalization_passes`` and
      ``authority_digest_refresh_candidate()``.

    Returned address-sorted; the checker admits either serialization order (see
    ``test_authority_enablement_drift_pair_is_order_insensitive``).
    """
    changes = {
        item["address"]: item["change"] for item in candidate["resource_changes"]
    }

    # Hub publisher inline-policy reflection. ``after`` is the planned no-op role
    # state; ``before`` is that state before the separately managed inline policy
    # was reflected into role state.
    role_address = "module.control.aws_iam_role.hub_publisher"
    role_after = copy.deepcopy(changes[role_address]["after"])
    role_drift = {
        "address": role_address,
        "mode": "managed",
        "module_address": "module.control",
        "name": "hub_publisher",
        "provider_name": "registry.terraform.io/hashicorp/aws",
        "type": "aws_iam_role",
        "change": {
            "actions": ["update"],
            "after_sensitive": {
                "inline_policy": [{}],
                "managed_policy_arns": [],
                "tags": {},
                "tags_all": {},
            },
            "after_unknown": {},
            "before": {**copy.deepcopy(role_after), "inline_policy": []},
            "before_sensitive": {
                "inline_policy": [],
                "managed_policy_arns": [],
                "tags": {},
                "tags_all": {},
            },
            "after": copy.deepcopy(role_after),
        },
    }

    # Authority image-digest roll. Terraform owns the parameter and ignores its
    # value; the external publisher rolls value+version. Bind the planned no-op
    # state to the refreshed (new) digest the drift lands on so the digest drift's
    # ``after`` matches the planned state, exactly as the live refresh does.
    spec = CHECKER._AUTHORITY_DIGEST_SPEC
    digest_address = spec["address"]
    parameter_name = spec["parameter_name"]
    old_digest = f"sha256:{'1' * 64}"
    new_digest = f"sha256:{'2' * 64}"
    digest_after = {
        "allowed_pattern": "",
        "arn": spec["parameter_arn"],
        "data_type": "text",
        "description": spec["description"],
        "has_value_wo": False,
        "id": parameter_name,
        "insecure_value": None,
        "key_id": "",
        "name": parameter_name,
        "overwrite": None,
        "region": CHECKER.AWS_REGION,
        "tags": {},
        "tags_all": {},
        "tier": "Standard",
        "type": "String",
        "value": new_digest,
        "value_wo": None,
        "value_wo_version": None,
        "version": 8,
    }
    changes[digest_address]["before"] = copy.deepcopy(digest_after)
    changes[digest_address]["after"] = copy.deepcopy(digest_after)
    digest_drift = {
        "address": digest_address,
        "mode": "managed",
        "module_address": "module.control",
        "name": spec["name"],
        "provider_name": "registry.terraform.io/hashicorp/aws",
        "type": "aws_ssm_parameter",
        "change": {
            "actions": ["update"],
            "after_sensitive": copy.deepcopy(CHECKER._DIGEST_REFRESH_SENSITIVE),
            "after_unknown": {},
            "before": {
                **copy.deepcopy(digest_after),
                "value": old_digest,
                "version": 7,
            },
            "before_sensitive": copy.deepcopy(CHECKER._DIGEST_REFRESH_SENSITIVE),
            "after": copy.deepcopy(digest_after),
        },
    }

    # aws_iam_role.hub_publisher sorts before aws_ssm_parameter.authority_...
    return [role_drift, digest_drift]


def authority_contract_transition_fixture() -> dict:
    result = plan_fixture()
    result["applyable"] = True
    change = next(
        item["change"]
        for item in result["resource_changes"]
        if item["address"]
        == "module.control.terraform_data.foundation_contract"
    )
    change["actions"] = ["update"]
    change["after"]["input"] = authority_runtime_input_fixture()
    change["after"]["output"] = None
    # Model the REAL enablement plan shape: main.tf builds the input with
    # merge(base, jsondecode(jsonencode(...))), so Terraform marks the two
    # jsondecode-derived keys unknown in after_unknown.input even though
    # after.input holds their exact concrete values. The static merge-base keys
    # stay known. (Previously this fixture used only {"output": True}, which did
    # not exercise _require_foundation_input_known — the gap the live plan hit.)
    change["after_unknown"] = {
        "output": True,
        "input": {
            "authority_image_uri": True,
            "authority_runtime_contract": True,
        },
    }
    # Model the REAL Step-3 enablement plan's refresh phase: it always observes
    # TWO benign, externally driven state normalizations in the same plan, so
    # resource_drift carries this exact pair (Hub publisher inline-policy
    # reflection + Authority image-digest roll), not a single entry. (Previously
    # this fixture left resource_drift empty, which never exercised the 2-drift
    # combination -- the gap the live plan hit; the #3411 terminal review's
    # Finding 2.)
    result["resource_drift"] = authority_enablement_drift_pair(result)
    return result


def redis_split_transition_fixture(create_addresses: set[str] | None = None) -> dict:
    result = plan_fixture()
    result["applyable"] = True
    changes = {item["address"]: item["change"] for item in result["resource_changes"]}
    golden = json.loads(
        REAL_REDIS_IAM_CREATE_FIXTURE_PATH.read_text(encoding="utf-8")
    )["change"]
    if create_addresses is None:
        create_addresses = {
            "module.control.aws_elasticache_user.otp_activator",
            "module.control.aws_elasticache_user.otp_issuer",
        }
    for address in create_addresses:
        changes[address]["actions"] = ["create"]
        changes[address]["before"] = None
        changes[address]["after"]["authentication_mode"] = copy.deepcopy(
            golden["after"]["authentication_mode"]
        )
        changes[address]["after_unknown"]["authentication_mode"] = copy.deepcopy(
            golden["after_unknown"]["authentication_mode"]
        )
        changes[address]["after_sensitive"] = copy.deepcopy(
            golden["after_sensitive"]
        )
    group = changes["module.control.aws_elasticache_user_group.otp"]
    group["actions"] = ["update"]
    group["before"] = {
        **group["after"],
        "user_ids": [
            f"{CHECKER.CONTROL_PREFIX}-otp-auth",
            f"{CHECKER.CONTROL_PREFIX}-otp-default",
        ],
    }
    return result


def hub_artifact_transition_fixture(
    create_addresses: frozenset[str] | None = None,
) -> dict:
    result = plan_fixture()
    result["applyable"] = True
    if create_addresses is None:
        create_addresses = CHECKER.HUB_ARTIFACT_BOOTSTRAP_RESOURCES
    changes = {item["address"]: item["change"] for item in result["resource_changes"]}

    role_address = "module.control.aws_iam_role.hub_publisher"
    policy_address = "module.control.aws_iam_role_policy.hub_publisher"
    digest_address = "module.control.aws_ssm_parameter.hub_image_digest"
    if policy_address in create_addresses:
        changes[role_address]["before"]["inline_policy"] = []
        changes[role_address]["after"]["inline_policy"] = []
    for address in create_addresses:
        change = changes[address]
        change["actions"] = ["create"]
        change["before"] = None
        if address == role_address:
            change["after"]["permissions_boundary"] = None
            change["after_unknown"]["managed_policy_arns"] = True
        if address == policy_address and role_address in create_addresses:
            change["after"]["role"] = None
            change["after_unknown"]["role"] = True
        if address == digest_address:
            change["after"]["allowed_pattern"] = None
            for field in (
                "data_type",
                "has_value_wo",
                "insecure_value",
                "key_id",
                "tier",
            ):
                change["after"][field] = None
                change["after_unknown"][field] = True
    return result


RUNTIME_QAT1_KEY_ARN = (
    f"arn:aws:kms:{CHECKER.AWS_REGION}:{CHECKER.ACCOUNT_ID}:"
    "key/00000000-0000-0000-0000-000000000001"
)
RUNTIME_LAMBDA_SG_ID = "sg-runtimefn0000000"


def authority_runtime_input_with_concurrency() -> dict:
    payload = authority_runtime_input_fixture()
    for spec in payload["authority_runtime_contract"]["functions"].values():
        spec.update(
            {
                "steady_provisioned_concurrency": 2,
                "steady_reserved_concurrency": 2,
                "rollout_active_provisioned_concurrency": 2,
                "rollout_standby_provisioned_concurrency": 2,
                "rollout_reserved_concurrency": 4,
                "max_caller_in_flight": 2,
                "max_caller_requests_per_second": 4,
                "rollback_retention_seconds": 3600,
            }
        )
    return payload


def runtime_scoped_endpoint_policies() -> tuple[str, str]:
    # VPC endpoint policies do not match an assumed-role session against a
    # role-ARN Principal, so the runtime grants use Principal "*" scoped by an
    # exact aws:PrincipalArn condition. Keep this fixture in that shape.
    roles = sorted(CHECKER.AUTHORITY_RUNTIME_EXEC_ROLE_ARNS)
    dynamodb = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AuthorityFunctionsData",
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": sorted(CHECKER.AUTHORITY_RUNTIME_DYNAMODB_ACTIONS),
                    "Resource": sorted(CHECKER.AUTHORITY_RUNTIME_DYNAMODB_RESOURCES),
                    "Condition": {"StringEquals": {"aws:PrincipalArn": roles}},
                }
            ],
        }
    )
    kms = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AuthorityFunctionsQat1",
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": ["kms:GetPublicKey", "kms:Sign"],
                    "Resource": [RUNTIME_QAT1_KEY_ARN],
                    "Condition": {
                        "StringEquals": {
                            "aws:PrincipalArn": sorted(
                                CHECKER.AUTHORITY_RUNTIME_SIGN_ROLE_ARNS
                            )
                        }
                    },
                }
            ],
        }
    )
    return dynamodb, kms


def runtime_exec_policy(fn: str, operation: str) -> str:
    """Build the per-operation execution (identity) policy the checker expects.

    Derived from the checker constants so the fixture stays in lockstep with the
    reviewed IAM; every referenced ARN is a known literal.
    """
    spec = CHECKER.AUTHORITY_RUNTIME_OPERATION_IAM[operation]
    read_resources = sorted(
        set().union(
            *(
                CHECKER.AUTHORITY_RUNTIME_TABLE_RESOURCES[table]
                for table in spec["read_tables"]
            )
        )
    )
    statements = [
        {
            "Sid": "LambdaVpcEni",
            "Effect": "Allow",
            "Action": sorted(CHECKER.AUTHORITY_RUNTIME_ENI_ACTIONS),
            "Resource": "*",
        },
        {
            "Sid": "OwnLogStream",
            "Effect": "Allow",
            "Action": sorted(CHECKER.AUTHORITY_RUNTIME_LOG_ACTIONS),
            "Resource": [
                f"arn:aws:logs:{CHECKER.AWS_REGION}:{CHECKER.ACCOUNT_ID}:"
                f"log-group:/aws/lambda/{fn}:*"
            ],
        },
        {
            "Sid": "AuthorityReads",
            "Effect": "Allow",
            "Action": sorted(CHECKER.AUTHORITY_RUNTIME_DYNAMODB_READ_ACTIONS),
            "Resource": read_resources,
        },
        {
            "Sid": spec["write_sid"],
            "Effect": "Allow",
            "Action": sorted(spec["write_actions"]),
            "Resource": sorted(
                CHECKER.AUTHORITY_RUNTIME_TABLE_RESOURCES["connector_authority"]
            ),
        },
    ]
    if spec["signs"]:
        statements.append(
            {
                "Sid": "Qat1Sign",
                "Effect": "Allow",
                "Action": ["kms:GetPublicKey", "kms:Sign"],
                "Resource": [RUNTIME_QAT1_KEY_ARN],
            }
        )
    return json.dumps({"Version": "2012-10-17", "Statement": statements})


def runtime_exec_trust(fn: str) -> str:
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "LambdaAssume",
                    "Effect": "Allow",
                    "Principal": {"Service": "lambda.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )


def runtime_interface_ingress_rule() -> dict:
    return {
        "description": "HTTPS from Connector Authority function ENIs",
        "from_port": 443,
        "to_port": 443,
        "protocol": "tcp",
        "security_groups": [RUNTIME_LAMBDA_SG_ID],
        "cidr_blocks": [],
        "ipv6_cidr_blocks": [],
        "prefix_list_ids": [],
        "self": False,
    }


def _runtime_create(after: dict) -> dict:
    return {
        "actions": ["create"],
        "before": None,
        "after": after,
        "after_unknown": {},
    }


def _runtime_resource_changes() -> list[dict]:
    payload = authority_runtime_input_with_concurrency()
    image_uri = payload["authority_image_uri"]
    functions = payload["authority_runtime_contract"]["functions"]
    changes: list[dict] = []
    for fn, spec in functions.items():
        changes.append(
            {
                "address": f'module.control.aws_lambda_function.authority["{fn}"]',
                "mode": "managed",
                "type": "aws_lambda_function",
                "change": _runtime_create(
                    {
                        "function_name": fn,
                        "package_type": "Image",
                        "image_uri": image_uri,
                        "reserved_concurrent_executions": spec[
                            "steady_reserved_concurrency"
                        ],
                        "vpc_config": [
                            {"subnet_ids": [], "security_group_ids": []}
                        ],
                    }
                ),
            }
        )
        for color in ("blue", "green"):
            changes.append(
                {
                    "address": (
                        f'module.control.aws_lambda_alias.authority["{fn}:{color}"]'
                    ),
                    "mode": "managed",
                    "type": "aws_lambda_alias",
                    "change": _runtime_create({"name": color}),
                }
            )
        changes.append(
            {
                "address": (
                    "module.control.aws_lambda_provisioned_concurrency_config."
                    f'authority["{fn}"]'
                ),
                "mode": "managed",
                "type": "aws_lambda_provisioned_concurrency_config",
                "change": _runtime_create(
                    {
                        "provisioned_concurrent_executions": spec[
                            "steady_provisioned_concurrency"
                        ],
                        "qualifier": "blue",
                    }
                ),
            }
        )
        changes.append(
            {
                "address": f'module.control.aws_iam_role.authority_exec["{fn}"]',
                "mode": "managed",
                "type": "aws_iam_role",
                "change": _runtime_create(
                    {
                        "assume_role_policy": runtime_exec_trust(fn),
                        "managed_policy_arns": [],
                        "max_session_duration": 3600,
                        "permissions_boundary": None,
                    }
                ),
            }
        )
        operation = CHECKER.AUTHORITY_RUNTIME_HUB_FUNCTIONS[fn]
        changes.append(
            {
                "address": (
                    f'module.control.aws_iam_role_policy.authority_exec["{fn}"]'
                ),
                "mode": "managed",
                "type": "aws_iam_role_policy",
                "change": _runtime_create(
                    {
                        "name": f"connector-authority-{operation}",
                        "policy": runtime_exec_policy(fn, operation),
                    }
                ),
            }
        )
        changes.append(
            {
                "address": (
                    f'module.control.aws_cloudwatch_log_group.authority["{fn}"]'
                ),
                "mode": "managed",
                "type": "aws_cloudwatch_log_group",
                "change": _runtime_create({"name": f"/aws/lambda/{fn}"}),
            }
        )
        changes.append(
            {
                "address": (
                    "module.control.aws_cloudwatch_metric_alarm."
                    f'authority_spillover["{fn}"]'
                ),
                "mode": "managed",
                "type": "aws_cloudwatch_metric_alarm",
                "change": _runtime_create(
                    {"alarm_name": f"{fn}-provisioned-concurrency-spillover"}
                ),
            }
        )
    changes.append(
        {
            "address": CHECKER.AUTHORITY_RUNTIME_LAMBDA_SG_ADDRESS,
            "mode": "managed",
            "type": "aws_security_group",
            "change": _runtime_create(
                {"ingress": [], "egress": [{"from_port": 443, "to_port": 443}]}
            ),
        }
    )
    return changes


def authority_runtime_transition_fixture() -> dict:
    """The runtime slice: 25 pure creates plus the exact three endpoint/SG opens."""
    result = plan_fixture()
    result["applyable"] = True
    changes = {item["address"]: item for item in result["resource_changes"]}
    payload = authority_runtime_input_with_concurrency()

    foundation = changes["module.control.terraform_data.foundation_contract"]["change"]
    foundation["actions"] = ["no-op"]
    foundation["before"] = {"input": payload, "output": payload}
    foundation["after"] = {"input": payload, "output": payload}
    foundation["after_unknown"] = {}

    dynamodb_policy, kms_policy = runtime_scoped_endpoint_policies()
    ddb = changes[CHECKER.AUTHORITY_RUNTIME_DYNAMODB_ADDRESS]["change"]
    ddb["actions"] = ["update"]
    ddb["after"] = {**ddb["after"], "policy": dynamodb_policy}
    kms = changes[CHECKER.AUTHORITY_RUNTIME_KMS_ENDPOINT_ADDRESS]["change"]
    kms["actions"] = ["update"]
    kms["after"] = {**kms["after"], "policy": kms_policy}
    sg = changes[CHECKER.AUTHORITY_RUNTIME_INTERFACE_SG_ADDRESS]["change"]
    sg["actions"] = ["update"]
    sg["after"] = {
        **sg["after"],
        "ingress": [runtime_interface_ingress_rule()],
        "egress": [],
    }

    result["resource_changes"].extend(_runtime_resource_changes())
    return result


def authority_runtime_steady_fixture() -> dict:
    """Runtime inventory, every change a no-op: the steady post-slice state."""
    result = authority_runtime_transition_fixture()
    result["applyable"] = False
    for item in result["resource_changes"]:
        change = item["change"]
        if change["actions"] == ["no-op"]:
            continue
        change["actions"] = ["no-op"]
        # Steady state: the applied value is both before and after.
        change["before"] = copy.deepcopy(change["after"])
        change["after_unknown"] = {}
    return result


def authority_runtime_partial_retry_fixture(applied_addresses: set[str]) -> dict:
    """A partial-apply RETRY of the runtime slice: every address in
    ``applied_addresses`` already applied on an earlier attempt and now replans
    as a validated no-op (before==after); the remaining slice creates plus all
    three endpoint/SG opens stay pending. Models the real failure where the exec
    roles/policies/spillover alarms/log groups applied before the DynamoDB
    gateway-endpoint open was rejected and the run aborted."""
    result = authority_runtime_transition_fixture()
    for item in result["resource_changes"]:
        change = item["change"]
        if item["address"] in applied_addresses and change["actions"] == ["create"]:
            change["actions"] = ["no-op"]
            change["before"] = copy.deepcopy(change["after"])
            change["after_unknown"] = {}
    return result


def _slice_refresh_drift(address: str, resource_type: str) -> dict:
    """A minimal benign refresh re-projection ``resource_drift`` entry. The
    runtime-slice normalization admits by address (confined to the slice + its
    opens), so trivial projected values suffice for coverage."""
    return {
        "address": address,
        "mode": "managed",
        "type": resource_type,
        "change": {
            "actions": ["update"],
            "before": {"tags_all": {}},
            "after": {"tags_all": {"reviewed": "yes"}},
            "after_unknown": {},
        },
    }


def authority_runtime_retry_fixture() -> dict:
    """A recovery re-plan after a partial apply left the 3 hub functions Failed:
    Terraform auto-taints them (replace = ["delete","create"]) and the exec-role
    trust is normalized (the confused-deputy Condition removed -> in-place
    update). The spillover alarms / log groups / function SG already applied
    (no-op); the aliases + provisioned-concurrency are still pending creates; the
    three opens are updates."""
    result = authority_runtime_transition_fixture()
    for item in result["resource_changes"]:
        change = item["change"]
        if change["actions"] != ["create"]:
            continue
        if item["type"] == "aws_lambda_function":
            change["actions"] = ["delete", "create"]
            change["before"] = copy.deepcopy(change["after"])
        elif item["type"] == "aws_iam_role":
            change["actions"] = ["update"]
            change["before"] = copy.deepcopy(change["after"])
        elif item["type"] in (
            "aws_cloudwatch_metric_alarm",
            "aws_cloudwatch_log_group",
            "aws_security_group",
        ):
            change["actions"] = ["no-op"]
            change["before"] = copy.deepcopy(change["after"])
            change["after_unknown"] = {}
    return result


def _hub_edge_resource_changes() -> list[dict]:
    return [
        {
            "address": address,
            "mode": "managed",
            "type": resource_type,
            "change": _runtime_create({"id": address}),
        }
        for address, resource_type in CHECKER.HUB_EDGE_RESOURCES.items()
    ]


def hub_edge_transition_fixture() -> dict:
    """The Hub public edge slice: the exact edge resources as pure creates."""
    result = plan_fixture()
    result["applyable"] = True
    result["resource_changes"].extend(_hub_edge_resource_changes())
    return result


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value), encoding="utf-8")


def terraform_resource_source(path: Path, resource_type: str, name: str) -> str:
    """Return one exact top-level resource block from a small module source."""
    marker = f'resource "{resource_type}" "{name}" {{'
    source = path.read_text(encoding="utf-8")
    _, found, remainder = source.partition(marker)
    if not found or marker in remainder:
        raise AssertionError(f"expected exactly one Terraform resource: {marker}")
    return marker + remainder.split('\nresource "', 1)[0]


def control_outputs_fixture() -> dict[str, dict]:
    outputs = {
        name: {
            "sensitive": False,
            "type": "string",
            "value": f"fixture-{index}",
        }
        for index, name in enumerate(sorted(CHECKER.EXPECTED_CONTROL_OUTPUTS))
    }
    outputs["control_table_names"] = {
        "sensitive": False,
        "type": ["object", {"agents": "string", "customers": "string"}],
        "value": {"agents": "fixture-agents", "customers": "fixture-customers"},
    }
    outputs["isolated_subnet_ids"] = {
        "sensitive": False,
        "type": ["tuple", ["string", "string"]],
        "value": ["subnet-fixture-a", "subnet-fixture-b"],
    }
    return outputs


def terraform_1_14_refresh_only_golden(candidate: dict) -> dict:
    """Build the version-pinned Terraform 1.14 refresh plan/state shape.

    The Control values remain the complete synthetic security fixture so every
    field can be mutated hermetically. The JSON envelope follows the 1.14.3
    source and local output-bearing reproduction: no ``resource_changes``, all
    all reviewed root outputs, an empty ``planned_values.root_module``, and a separate
    format-1.0 state containing the unchanged inventory and output values.
    """
    resources = []
    for item in candidate.pop("resource_changes"):
        resources.append(
            {
                "address": item["address"],
                "mode": item["mode"],
                "type": item["type"],
                "values": copy.deepcopy(item["change"]["after"]),
            }
        )
    outputs = control_outputs_fixture()
    candidate["planned_values"] = {
        "outputs": copy.deepcopy(outputs),
        "root_module": {},
    }
    candidate["output_changes"] = {
        name: {
            "actions": ["no-op"],
            "after": copy.deepcopy(output["value"]),
            "after_sensitive": False,
            "after_unknown": False,
            "before": copy.deepcopy(output["value"]),
            "before_sensitive": False,
        }
        for name, output in outputs.items()
    }
    return {
        "format_version": "1.0",
        "terraform_version": CHECKER.TF_VERSION,
        "values": {
            "outputs": copy.deepcopy(outputs),
            "root_module": {
                "child_modules": [
                    {"address": "module.control", "resources": resources}
                ]
            }
        },
    }


def state_resource(state: dict, address: str) -> dict:
    """Return the resource at ``address`` from a prior-state tree."""
    return next(
        item
        for item in state["values"]["root_module"]["child_modules"][0][
            "resources"
        ]
        if item["address"] == address
    )


def state_publisher_role(state: dict) -> dict:
    return state_resource(
        state, "module.control.aws_iam_role.authority_publisher"
    )


def publisher_refresh_candidate(*, hub: bool = False) -> tuple[dict, dict]:
    candidate = plan_fixture()
    candidate["applyable"] = True
    role_address = (
        "module.control.aws_iam_role.hub_publisher"
        if hub
        else "module.control.aws_iam_role.authority_publisher"
    )
    role_change = next(
        item["change"]
        for item in candidate["resource_changes"]
        if item["address"] == role_address
    )
    candidate["resource_drift"] = [
        {
            "address": role_address,
            "mode": "managed",
            "type": "aws_iam_role",
            "change": {
                "actions": ["update"],
                "after_sensitive": {
                    "inline_policy": [{}],
                    "managed_policy_arns": [],
                    "tags": {},
                    "tags_all": {},
                },
                "after_unknown": {},
                "before": {
                    **copy.deepcopy(role_change["after"]),
                    "inline_policy": [],
                },
                "before_sensitive": {
                    "inline_policy": [],
                    "managed_policy_arns": [],
                    "tags": {},
                    "tags_all": {},
                },
                "after": copy.deepcopy(role_change["after"]),
            },
        }
    ]
    prior_state = terraform_1_14_refresh_only_golden(candidate)
    prior_role = state_resource(prior_state, role_address)
    prior_role["values"] = copy.deepcopy(
        candidate["resource_drift"][0]["change"]["before"]
    )
    return candidate, prior_state


def authority_digest_refresh_candidate(*, hub: bool = False) -> tuple[dict, dict]:
    candidate = plan_fixture()
    candidate["applyable"] = True
    spec = CHECKER._HUB_DIGEST_SPEC if hub else CHECKER._AUTHORITY_DIGEST_SPEC
    parameter_change = next(
        item["change"]
        for item in candidate["resource_changes"]
        if item["address"] == spec["address"]
    )
    parameter_name = spec["parameter_name"]
    old_digest = f"sha256:{'1' * 64}"
    new_digest = f"sha256:{'2' * 64}"
    parameter_change["before"] = {
        "allowed_pattern": "",
        "arn": spec["parameter_arn"],
        "data_type": "text",
        "description": spec["description"],
        "has_value_wo": False,
        "id": parameter_name,
        "insecure_value": None,
        "key_id": "",
        "name": parameter_name,
        "overwrite": None,
        "region": CHECKER.AWS_REGION,
        "tags": {},
        "tags_all": {},
        "tier": "Standard",
        "type": "String",
        "value": new_digest,
        "value_wo": None,
        "value_wo_version": None,
        "version": 8,
    }
    parameter_change["after"] = copy.deepcopy(parameter_change["before"])
    candidate["resource_drift"] = [
        {
            "address": spec["address"],
            "mode": "managed",
            "module_address": "module.control",
            "name": spec["name"],
            "provider_name": "registry.terraform.io/hashicorp/aws",
            "type": "aws_ssm_parameter",
            "change": {
                "actions": ["update"],
                "after_sensitive": copy.deepcopy(
                    CHECKER._DIGEST_REFRESH_SENSITIVE
                ),
                "after_unknown": {},
                "before": {
                    **copy.deepcopy(parameter_change["after"]),
                    "value": old_digest,
                    "version": 7,
                },
                "before_sensitive": copy.deepcopy(
                    CHECKER._DIGEST_REFRESH_SENSITIVE
                ),
                "after": copy.deepcopy(parameter_change["after"]),
            },
        }
    ]
    prior_state = terraform_1_14_refresh_only_golden(candidate)
    prior_parameter = state_resource(prior_state, spec["address"])
    prior_parameter["values"] = copy.deepcopy(
        candidate["resource_drift"][0]["change"]["before"]
    )
    return candidate, prior_state


def redis_password_refresh_candidate() -> tuple[dict, dict]:
    candidate = plan_fixture()
    candidate["applyable"] = True
    changes = {
        item["address"]: item["change"] for item in candidate["resource_changes"]
    }
    golden = json.loads(
        REAL_REDIS_PASSWORD_REFRESH_FIXTURE_PATH.read_text(encoding="utf-8")
    )
    drift = copy.deepcopy(golden["resource_drift"])
    for item in drift:
        address = item["address"]
        projected = item["change"]
        after = copy.deepcopy(changes[address]["after"])
        before = copy.deepcopy(after)
        before["authentication_mode"] = copy.deepcopy(
            projected["before"]["authentication_mode"]
        )
        after["authentication_mode"] = copy.deepcopy(
            projected["after"]["authentication_mode"]
        )
        projected["before"] = before
        projected["after"] = after
    candidate["resource_drift"] = drift

    prior_state = terraform_1_14_refresh_only_golden(candidate)
    for item in drift:
        state_resource(prior_state, item["address"])["values"] = copy.deepcopy(
            item["change"]["before"]
        )
    return candidate, prior_state


def authority_enablement_refresh_candidate() -> tuple[dict, dict]:
    """Live pre-apply refresh-only observation carrying the benign enablement pair.

    This is the ``op=apply`` / ``op=verify`` counterpart to
    ``authority_contract_transition_fixture``: the same benign pair (Hub-publisher
    inline-policy reflection + Authority image-digest roll), but observed by a
    ``terraform plan -refresh-only`` (no ``resource_changes``, empty planned
    root_module) and bound to the captured pre-plan state, exactly the shape the
    workflow feeds to ``check_normalization_drift``.
    """
    candidate = plan_fixture()
    candidate["applyable"] = True
    drift = authority_enablement_drift_pair(candidate)
    candidate["resource_drift"] = drift
    prior_state = terraform_1_14_refresh_only_golden(candidate)
    for item in drift:
        state_resource(prior_state, item["address"])["values"] = copy.deepcopy(
            item["change"]["before"]
        )
    return candidate, prior_state


class PlanContractTests(unittest.TestCase):
    def test_real_terraform_1_14_3_noop_status_contract(self) -> None:
        real_noop = json.loads(
            REAL_TERRAFORM_NOOP_FIXTURE_PATH.read_text(encoding="utf-8")
        )
        self.assertEqual(real_noop["terraform_version"], CHECKER.TF_VERSION)

        candidate = plan_fixture()
        for field in ("format_version", "complete", "errored", "applyable"):
            candidate[field] = real_noop[field]
        self.assertEqual(CHECKER.check_plan(candidate)["resource_count"], 50)

    def test_exact_noop_passes(self) -> None:
        summary = CHECKER.check_plan(plan_fixture())
        self.assertEqual(summary["resource_count"], 50)
        self.assertEqual(summary["plan_mode"], "no-op")
        unrefreshed = plan_fixture()
        unrefreshed_role = self.change(
            unrefreshed, "module.control.aws_iam_role.authority_publisher"
        )
        unrefreshed_role["before"]["inline_policy"] = []
        unrefreshed_role["after"]["inline_policy"] = []
        self.assertEqual(CHECKER.check_plan(unrefreshed)["resource_count"], 50)

    def test_foundation_input_jsondecode_unknown_tolerance_boundary(self) -> None:
        # The enablement fixture carries the real after_unknown.input jsondecode
        # artifact ({authority_image_uri, authority_runtime_contract}); it must
        # be accepted because after.input is the exact validated binding.
        CHECKER.check_plan(authority_contract_transition_fixture())

        # An unknown marker on any static merge-base key (or any unexpected key)
        # is a genuine non-determinism and must fail closed.
        for stray_key in ("account_id", "control_table_prefix", "region", "surprise"):
            with self.subTest(stray_key=stray_key):
                candidate = authority_contract_transition_fixture()
                self.change(
                    candidate,
                    "module.control.terraform_data.foundation_contract",
                )["after_unknown"]["input"][stray_key] = True
                self.assert_rejected(candidate)

        # A wholesale-unknown input (not the bounded jsondecode dict) is rejected.
        candidate = authority_contract_transition_fixture()
        self.change(
            candidate,
            "module.control.terraform_data.foundation_contract",
        )["after_unknown"]["input"] = True
        self.assert_rejected(candidate)

    def test_exact_authority_contract_binding_passes_and_drift_fails(self) -> None:
        candidate = authority_contract_transition_fixture()
        summary = CHECKER.check_plan(candidate)
        self.assertEqual(summary["plan_mode"], "authority-contract-binding")
        self.assertEqual(summary["bootstrap_create_count"], 0)

        mutations = (
            lambda payload: payload.__setitem__(
                "authority_image_uri", "repository.example/authority:latest"
            ),
            lambda payload: payload["authority_runtime_contract"][
                "provisioned_cells_evidence"
            ].__setitem__("sha256", "0" * 64),
            lambda payload: payload["authority_runtime_contract"][
                "functions"
            ].pop("layerv-nhp-sandbox-ca-icr"),
        )
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                changed = authority_contract_transition_fixture()
                foundation = self.change(
                    changed,
                    "module.control.terraform_data.foundation_contract",
                )["after"]["input"]
                mutate(foundation)
                self.assert_rejected(changed)

        normalized = plan_fixture()
        normalized_changes = {
            item["address"]: item["change"] for item in normalized["resource_changes"]
        }
        normalized_changes["module.control.aws_vpc.control"]["after"][
            "assign_generated_ipv6_cidr_block"
        ] = False
        for address, auth_type in (
            ("module.control.aws_elasticache_user.otp_activator", "iam"),
            ("module.control.aws_elasticache_user.otp_authority", "iam"),
            (
                "module.control.aws_elasticache_user.otp_disabled_default",
                "no-password",
            ),
            ("module.control.aws_elasticache_user.otp_issuer", "iam"),
        ):
            normalized_changes[address]["after"]["authentication_mode"] = [
                {"password_count": 0, "passwords": [], "type": auth_type}
            ]
        normalized_changes["module.control.aws_elasticache_user_group.otp"]["after"][
            "user_ids"
        ].reverse()
        usage = normalized_changes[
            "module.control.aws_elasticache_serverless_cache.otp"
        ]["after"]["cache_usage_limits"][0]
        usage["data_storage"][0]["minimum"] = 1
        usage["ecpu_per_second"][0]["minimum"] = 1000
        for change in normalized_changes.values():
            change["before"] = copy.deepcopy(change["after"])
        for address in (
            "module.control.aws_default_security_group.control",
            "module.control.aws_security_group.interface_endpoints",
            "module.control.aws_security_group.otp_redis",
        ):
            normalized_changes[address]["after_unknown"] = {}
        self.assertEqual(CHECKER.check_plan(normalized)["resource_count"], 50)

    def test_authority_enablement_benign_drift_pair_passes(self) -> None:
        # The REAL Step-3 enablement plan carries exactly two benign refresh-phase
        # drifts (Hub-publisher inline-policy reflection + Authority image-digest
        # roll). The pair is admitted as one combined kind, with each item still
        # validated by its own exact single-drift validator.
        candidate = authority_contract_transition_fixture()
        self.assertEqual(
            {item["address"] for item in candidate["resource_drift"]},
            {
                "module.control.aws_iam_role.hub_publisher",
                CHECKER._AUTHORITY_DIGEST_ADDRESS,
            },
        )
        summary = CHECKER.check_plan(candidate)
        self.assertEqual(summary["plan_mode"], "authority-contract-binding")
        self.assertEqual(
            summary["normalization_drift_kind"],
            "authority-enablement-normalization",
        )
        self.assertEqual(summary["normalization_drift_count"], 2)
        self.assertEqual(summary["bootstrap_create_count"], 0)
        self.assertRegex(summary["normalization_drift_sha256"], r"^[0-9a-f]{64}$")

    def test_authority_enablement_drift_pair_is_order_insensitive(self) -> None:
        # Terraform's resource_drift ordering is not observable locally, so
        # admission must not depend on it -- each item is validated by address.
        forward = authority_contract_transition_fixture()
        reverse = authority_contract_transition_fixture()
        reverse["resource_drift"].reverse()
        for label, candidate in (("forward", forward), ("reverse", reverse)):
            with self.subTest(order=label):
                summary = CHECKER.check_plan(candidate)
                self.assertEqual(
                    summary["normalization_drift_kind"],
                    "authority-enablement-normalization",
                )
                self.assertEqual(summary["normalization_drift_count"], 2)

    def test_authority_enablement_single_benign_drift_still_passes(self) -> None:
        # The 2-drift branch must not hijack the exact single-drift admissions:
        # each benign drift on its own keeps its own single-drift kind.
        role_candidate, role_state = publisher_refresh_candidate(hub=True)
        self.assertEqual(
            CHECKER.check_plan(role_candidate, role_state)[
                "normalization_drift_kind"
            ],
            "hub-publisher-role",
        )
        digest_candidate, digest_state = authority_digest_refresh_candidate()
        self.assertEqual(
            CHECKER.check_plan(digest_candidate, digest_state)[
                "normalization_drift_kind"
            ],
            "authority-digest",
        )
        # The digest rolls permanently, so a lone digest drift is also admissible
        # in the enablement config-change plan (still kept as "authority-digest").
        digest_only = authority_contract_transition_fixture()
        digest_only["resource_drift"] = [
            self.drift(digest_only, CHECKER._AUTHORITY_DIGEST_ADDRESS)
        ]
        summary = CHECKER.check_plan(digest_only)
        self.assertEqual(summary["plan_mode"], "authority-contract-binding")
        self.assertEqual(summary["normalization_drift_kind"], "authority-digest")
        self.assertEqual(summary["normalization_drift_count"], 1)

    def test_authority_enablement_drift_pair_other_combinations_fail(self) -> None:
        role_address = "module.control.aws_iam_role.hub_publisher"
        digest_address = CHECKER._AUTHORITY_DIGEST_ADDRESS

        # A different address in either slot is not the exact reviewed pair.
        swapped_role = authority_contract_transition_fixture()
        self.drift(swapped_role, role_address)["address"] = (
            "module.control.aws_iam_role.authority_publisher"
        )
        self.assert_rejected(swapped_role)

        swapped_digest = authority_contract_transition_fixture()
        self.drift(swapped_digest, digest_address)["address"] = (
            CHECKER._HUB_DIGEST_ADDRESS
        )
        self.assert_rejected(swapped_digest)

        # A duplicated benign address (len 2, but only one distinct address).
        duplicated = authority_contract_transition_fixture()
        role_item = self.drift(duplicated, role_address)
        duplicated["resource_drift"] = [
            copy.deepcopy(role_item),
            copy.deepcopy(role_item),
        ]
        self.assert_rejected(duplicated)

        # A third drift beyond the exact pair.
        extra = authority_contract_transition_fixture()
        extra["resource_drift"].append(
            copy.deepcopy(self.drift(extra, digest_address))
        )
        self.assert_rejected(extra)

    def test_authority_enablement_drift_pair_each_item_is_validated(self) -> None:
        role_address = "module.control.aws_iam_role.hub_publisher"
        digest_address = CHECKER._AUTHORITY_DIGEST_ADDRESS

        # Corrupting the Hub-publisher-role drift beyond a pure inline-policy
        # reflection must fail: _check_publisher_role_normalization is not
        # weakened by the pair admission.
        bad_role = authority_contract_transition_fixture()
        self.drift(bad_role, role_address)["change"]["after"][
            "max_session_duration"
        ] = 7200
        self.assert_rejected(bad_role)

        # A digest drift whose value did not actually roll must fail: the
        # _check_digest_normalization immutability proof is not weakened either.
        bad_digest = authority_contract_transition_fixture()
        digest_change = self.drift(bad_digest, digest_address)["change"]
        digest_change["before"]["value"] = digest_change["after"]["value"]
        self.assert_rejected(bad_digest)

    def test_authority_enablement_drift_pair_admitted_only_for_enablement(
        self,
    ) -> None:
        # The exact same benign pair carries no admission outside the reviewed
        # enablement transition: a no-op or another transition stays fail-closed.
        noop = plan_fixture()
        noop["resource_drift"] = authority_enablement_drift_pair(noop)
        with self.assertRaisesRegex(
            CHECKER.ContractError,
            "admitted only for the Authority contract enablement transition",
        ):
            CHECKER.check_plan(noop)

        redis = redis_split_transition_fixture()
        redis["resource_drift"] = authority_enablement_drift_pair(redis)
        with self.assertRaisesRegex(
            CHECKER.ContractError,
            "admitted only for the Authority contract enablement transition",
        ):
            CHECKER.check_plan(redis)

    def test_authority_enablement_tolerates_config_change_plan_metadata(
        self,
    ) -> None:
        # The live Step-3 enablement plan (op=plan, NOT -refresh-only) also
        # carries the config-change plan metadata the current fixtures omit:
        # output_changes ("Changes to Outputs: authority_image_uri"),
        # planned_values, a top-level variables block, and it is checked WITH the
        # captured prior state (`check_plan plan.json state.json`). check_plan
        # reconstructs from prior_state and validates outputs/planned_values ONLY
        # for the refresh-only shape (resource_changes absent); for a
        # config-change plan those fields are ignored, so the authority_image_uri
        # output roll must not perturb admission. Lock that tolerance against a
        # realistic shape so a future output check would have to reckon with it.
        candidate = authority_contract_transition_fixture()
        candidate["output_changes"] = {
            "authority_image_uri": {
                "actions": ["update"],
                "before": None,
                "after": (
                    f"{CHECKER.ACCOUNT_ID}.dkr.ecr.{CHECKER.AWS_REGION}"
                    ".amazonaws.com/layerv/nhp-authority@sha256:" + "2" * 64
                ),
                "after_unknown": False,
                "before_sensitive": False,
                "after_sensitive": False,
            }
        }
        candidate["planned_values"] = {
            "outputs": {},
            "root_module": {
                "child_modules": [{"address": "module.control", "resources": []}]
            },
        }
        candidate["variables"] = {
            "authority_runtime_contract_evidence_verified": {"value": True}
        }
        prior_state = {
            "format_version": "1.0",
            "terraform_version": CHECKER.TF_VERSION,
            "values": {"outputs": {}, "root_module": {}},
        }
        summary = CHECKER.check_plan(candidate, prior_state)
        self.assertEqual(summary["plan_mode"], "authority-contract-binding")
        self.assertEqual(
            summary["normalization_drift_kind"],
            "authority-enablement-normalization",
        )
        self.assertEqual(summary["normalization_drift_count"], 2)

    def test_exact_refresh_disabled_password_omission_passes(self) -> None:
        candidate = plan_fixture()
        for address in (
            "module.control.aws_elasticache_user.otp_activator",
            "module.control.aws_elasticache_user.otp_authority",
            "module.control.aws_elasticache_user.otp_disabled_default",
            "module.control.aws_elasticache_user.otp_issuer",
        ):
            change = self.change(candidate, address)
            for side in ("before", "after"):
                del change[side]["authentication_mode"][0]["passwords"]

        summary = CHECKER.check_plan(candidate)
        self.assertEqual(summary["resource_count"], 50)
        self.assertEqual(summary["plan_mode"], "no-op")

    def test_exact_refresh_disabled_password_null_passes(self) -> None:
        candidate = plan_fixture()
        for address in (
            "module.control.aws_elasticache_user.otp_activator",
            "module.control.aws_elasticache_user.otp_issuer",
        ):
            change = self.change(candidate, address)
            for side in ("before", "after"):
                change[side]["authentication_mode"][0]["passwords"] = None

        summary = CHECKER.check_plan(candidate)
        self.assertEqual(summary["resource_count"], 50)
        self.assertEqual(summary["plan_mode"], "no-op")

    def test_passwordless_authentication_mode_boundary_is_exact(self) -> None:
        for label, mode in (
            ("passwords-omitted", {"password_count": 0, "type": "iam"}),
            (
                "passwords-null",
                {"password_count": 0, "passwords": None, "type": "iam"},
            ),
            (
                "passwords-empty",
                {"password_count": 0, "passwords": [], "type": "iam"},
            ),
        ):
            with self.subTest(label=label):
                self.assertTrue(
                    CHECKER._is_exact_passwordless_authentication_mode(
                        [mode],
                        "iam",
                    )
                )

        for label, mode in (
            ("extra-field", {"extra": None, "password_count": 0, "type": "iam"}),
            ("missing-count", {"passwords": [], "type": "iam"}),
            ("boolean-count", {"password_count": False, "type": "iam"}),
            ("nonzero-count", {"password_count": 1, "type": "iam"}),
            ("missing-type", {"password_count": 0}),
            ("wrong-type", {"password_count": 0, "type": "password"}),
            (
                "passwords-object",
                {"password_count": 0, "passwords": {}, "type": "iam"},
            ),
            (
                "passwords-nonempty",
                {
                    "password_count": 0,
                    "passwords": ["must-not-appear"],
                    "type": "iam",
                },
            ),
        ):
            with self.subTest(label=label):
                self.assertFalse(
                    CHECKER._is_exact_passwordless_authentication_mode(
                        [mode],
                        "iam",
                    )
                )

    def test_noop_redis_auth_rejects_unsafe_password_projections(self) -> None:
        address = "module.control.aws_elasticache_user.otp_activator"
        for label, passwords in (
            ("non-empty", ["must-not-appear"]),
            ("wrong-type", {}),
        ):
            with self.subTest(label=label):
                candidate = plan_fixture()
                change = self.change(candidate, address)
                for side in ("before", "after"):
                    change[side]["authentication_mode"][0]["passwords"] = passwords
                self.assert_rejected(candidate)

        boolean_count = plan_fixture()
        change = self.change(boolean_count, address)
        for side in ("before", "after"):
            change[side]["authentication_mode"][0]["password_count"] = False
        self.assert_rejected(boolean_count)

    def test_exact_publisher_first_create_and_partial_retry_pass(self) -> None:
        for create_addresses in (
            CHECKER.PUBLISHER_BOOTSTRAP_RESOURCES,
            frozenset({"module.control.aws_iam_role_policy.authority_publisher"}),
        ):
            with self.subTest(create_addresses=create_addresses):
                candidate = plan_fixture()
                candidate["applyable"] = True
                # Before the separately managed policy exists, the provider has
                # nothing to reflect onto the role's computed inline_policy.
                if (
                    "module.control.aws_iam_role_policy.authority_publisher"
                    in create_addresses
                ):
                    role_change = self.change(
                        candidate,
                        "module.control.aws_iam_role.authority_publisher",
                    )
                    role_change["before"]["inline_policy"] = []
                    role_change["after"]["inline_policy"] = []
                for address in create_addresses:
                    change = self.change(candidate, address)
                    change["actions"] = ["create"]
                    change["before"] = None
                    if address == "module.control.aws_iam_role.authority_publisher":
                        change["after"]["permissions_boundary"] = None
                        change["after_unknown"]["managed_policy_arns"] = True
                    if (
                        address
                        == "module.control.aws_iam_role_policy.authority_publisher"
                        and "module.control.aws_iam_role.authority_publisher"
                        in create_addresses
                    ):
                        change["after"]["role"] = None
                        change["after_unknown"]["role"] = True
                result = CHECKER.check_plan(candidate)
                self.assertEqual(
                    result["bootstrap_create_count"], len(create_addresses)
                )
                self.assertEqual(result["plan_mode"], "publisher-bootstrap")

    def test_exact_hub_artifact_create_and_partial_retry_pass(self) -> None:
        self.assertEqual(
            CHECKER.HUB_ARTIFACT_BOOTSTRAP_RESOURCES,
            frozenset(
                {
                    "module.control.aws_ecr_lifecycle_policy.hub",
                    "module.control.aws_ecr_repository.hub",
                    "module.control.aws_iam_role.hub_publisher",
                    "module.control.aws_iam_role_policy.hub_publisher",
                    "module.control.aws_ssm_parameter.hub_image_digest",
                }
            ),
        )
        for create_addresses in (
            CHECKER.HUB_ARTIFACT_BOOTSTRAP_RESOURCES,
            frozenset(
                {
                    "module.control.aws_ecr_lifecycle_policy.hub",
                    "module.control.aws_iam_role_policy.hub_publisher",
                    "module.control.aws_ssm_parameter.hub_image_digest",
                }
            ),
        ):
            with self.subTest(create_addresses=create_addresses):
                result = CHECKER.check_plan(
                    hub_artifact_transition_fixture(create_addresses)
                )
                self.assertEqual(
                    result["bootstrap_create_count"], len(create_addresses)
                )
                self.assertEqual(result["plan_mode"], "hub-artifact-bootstrap")

    def test_hub_artifact_transition_fails_closed(self) -> None:
        role_without_policy = hub_artifact_transition_fixture(
            frozenset({"module.control.aws_iam_role.hub_publisher"})
        )
        self.assert_rejected(role_without_policy)

        repository_without_lifecycle = hub_artifact_transition_fixture(
            frozenset({"module.control.aws_ecr_repository.hub"})
        )
        self.assert_rejected(repository_without_lifecycle)

        wrong_pin = hub_artifact_transition_fixture()
        self.change(
            wrong_pin,
            "module.control.aws_ssm_parameter.hub_image_digest",
        )["after"]["value"] = f"sha256:{'a' * 64}"
        self.assert_rejected(wrong_pin)

        mutable_tags = hub_artifact_transition_fixture()
        self.change(
            mutable_tags,
            "module.control.aws_ecr_repository.hub",
        )["after"]["image_tag_mutability"] = "MUTABLE"
        self.assert_rejected(mutable_tags)

        unknown_repository = hub_artifact_transition_fixture()
        lifecycle = self.change(
            unknown_repository,
            "module.control.aws_ecr_lifecycle_policy.hub",
        )
        lifecycle["after"]["repository"] = None
        lifecycle["after_unknown"]["repository"] = True
        self.assert_rejected(unknown_repository)

        provider_defaults = {
            "allowed_pattern": "",
            "data_type": "text",
            "has_value_wo": False,
            "insecure_value": None,
            "key_id": "",
            "tier": "Standard",
        }
        for field, value in provider_defaults.items():
            if value is not None:
                with self.subTest(provider_default_known_on_create=field):
                    concrete_default = hub_artifact_transition_fixture()
                    digest = self.change(
                        concrete_default,
                        "module.control.aws_ssm_parameter.hub_image_digest",
                    )
                    digest["after"][field] = value
                    self.assert_rejected(concrete_default)

            with self.subTest(provider_default_not_unknown_on_create=field):
                missing_unknown = hub_artifact_transition_fixture()
                digest = self.change(
                    missing_unknown,
                    "module.control.aws_ssm_parameter.hub_image_digest",
                )
                if field == "allowed_pattern":
                    digest["after_unknown"][field] = True
                else:
                    digest["after_unknown"].pop(field)
                self.assert_rejected(missing_unknown)

        for shared_environment in ("sandbox", "production"):
            with self.subTest(shared_environment=shared_environment):
                shared_trust = hub_artifact_transition_fixture()
                role = self.change(
                    shared_trust,
                    "module.control.aws_iam_role.hub_publisher",
                )["after"]
                trust = json.loads(role["assume_role_policy"])
                trust["Statement"][0]["Condition"]["StringEquals"][
                    "token.actions.githubusercontent.com:sub"
                ] = f"repo:layervai/nhp:environment:{shared_environment}"
                role["assume_role_policy"] = json.dumps(trust)
                self.assert_rejected(shared_trust)

    def test_exact_publisher_refresh_only_normalization_passes(self) -> None:
        candidate, prior_state = publisher_refresh_candidate()
        role_drift = candidate["resource_drift"][0]["change"]

        # This is the value-free sensitivity envelope emitted by the exact
        # Terraform/provider pair used by the live Control workflow.
        self.assertEqual(
            role_drift["before_sensitive"],
            {
                "inline_policy": [],
                "managed_policy_arns": [],
                "tags": {},
                "tags_all": {},
            },
        )
        self.assertEqual(
            role_drift["after_sensitive"],
            {
                "inline_policy": [{}],
                "managed_policy_arns": [],
                "tags": {},
                "tags_all": {},
            },
        )
        self.assertRegex(
            CONTROL_LOCKFILE_PATH.read_text(encoding="utf-8"),
            rf'provider "registry\.terraform\.io/hashicorp/aws"\s*\{{\s*'
            rf'version\s*=\s*"{re.escape(EXPECTED_AWS_PROVIDER_VERSION)}"',
        )

        summary = CHECKER.check_plan(candidate, prior_state)

        self.assertEqual(summary["bootstrap_create_count"], 0)
        self.assertEqual(summary["normalization_drift_count"], 1)
        self.assertEqual(summary["normalization_drift_kind"], "publisher-role")
        self.assertEqual(summary["plan_mode"], "no-op")
        self.assertRegex(summary["normalization_drift_sha256"], r"^[0-9a-f]{64}$")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plan_path = root / "plan.json"
            state_path = root / "state.json"
            write_json(plan_path, candidate)
            write_json(state_path, prior_state)
            result = subprocess.run(
                [str(CHECKER_PATH), "plan", str(plan_path), str(state_path)],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(
                json.loads(result.stdout)["normalization_drift_count"], 1
            )

            missing_state = subprocess.run(
                [str(CHECKER_PATH), "plan", str(plan_path)],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(missing_state.returncode, 0)
            self.assertIn(
                f"exact Terraform {CHECKER.TF_VERSION} state JSON",
                missing_state.stderr,
            )

    def test_exact_hub_publisher_refresh_only_normalization_passes(self) -> None:
        candidate, prior_state = publisher_refresh_candidate(hub=True)
        summary = CHECKER.check_plan(candidate, prior_state)

        self.assertEqual(summary["normalization_drift_count"], 1)
        self.assertEqual(
            summary["normalization_drift_kind"], "hub-publisher-role"
        )
        self.assertEqual(summary["plan_mode"], "no-op")

    def test_exact_hub_digest_refresh_only_normalization_passes(self) -> None:
        candidate, prior_state = authority_digest_refresh_candidate(hub=True)
        summary = CHECKER.check_plan(candidate, prior_state)
        observation = CHECKER.check_normalization_drift(candidate, prior_state)

        self.assertEqual(summary["normalization_drift_count"], 1)
        self.assertEqual(summary["normalization_drift_kind"], "hub-digest")
        self.assertEqual(summary["plan_mode"], "no-op")
        self.assertEqual(observation["normalization_drift_kind"], "hub-digest")

        ordinary = plan_fixture()
        ordinary["resource_drift"] = copy.deepcopy(candidate["resource_drift"])
        refreshed = ordinary["resource_drift"][0]["change"]["after"]
        ordinary_hub_digest = next(
            item["change"]
            for item in ordinary["resource_changes"]
            if item["address"] == CHECKER._HUB_DIGEST_ADDRESS
        )
        ordinary_hub_digest["before"] = copy.deepcopy(refreshed)
        ordinary_hub_digest["after"] = copy.deepcopy(refreshed)
        with self.assertRaisesRegex(
            CHECKER.ContractError,
            "Hub digest state normalization requires a refresh-only plan",
        ):
            CHECKER.check_plan(ordinary)

    def test_exact_authority_digest_refresh_only_normalization_passes(self) -> None:
        candidate, prior_state = authority_digest_refresh_candidate()

        summary = CHECKER.check_plan(candidate, prior_state)

        self.assertEqual(summary["bootstrap_create_count"], 0)
        self.assertEqual(summary["normalization_drift_count"], 1)
        self.assertEqual(summary["normalization_drift_kind"], "authority-digest")
        self.assertEqual(summary["plan_mode"], "no-op")
        self.assertRegex(summary["normalization_drift_sha256"], r"^[0-9a-f]{64}$")

        live_summary = CHECKER.check_normalization_drift(candidate, prior_state)
        self.assertEqual(
            live_summary,
            {
                "normalization_drift_count": 1,
                "normalization_drift_kind": "authority-digest",
                "normalization_drift_sha256": summary[
                    "normalization_drift_sha256"
                ],
            },
        )

        first_publication, first_publication_state = (
            authority_digest_refresh_candidate()
        )
        first_publication_before = first_publication["resource_drift"][0][
            "change"
        ]["before"]
        first_publication_before["value"] = "UNPUBLISHED"
        first_publication_before["version"] = 1
        state_resource(
            first_publication_state, CHECKER._AUTHORITY_DIGEST_ADDRESS
        )["values"] = copy.deepcopy(first_publication_before)
        CHECKER.check_normalization_drift(
            first_publication, first_publication_state
        )

    def test_authority_enablement_pair_normalization_drift_reproof_passes(
        self,
    ) -> None:
        # The op=apply / op=verify live-refresh lane re-proves the SAME benign
        # pair via check_normalization_drift (the output-ignoring narrow mode);
        # its {count, kind, sha256} must equal the plan lane's summary so the
        # workflow's plan-vs-live cmp matches.
        candidate, prior_state = authority_enablement_refresh_candidate()
        observation = CHECKER.check_normalization_drift(candidate, prior_state)
        self.assertEqual(observation["normalization_drift_count"], 2)
        self.assertEqual(
            observation["normalization_drift_kind"],
            "authority-enablement-normalization",
        )
        self.assertRegex(
            observation["normalization_drift_sha256"], r"^[0-9a-f]{64}$"
        )
        # check_normalization_drift returns exactly the three fields the workflow
        # compares (jq '{count, kind, sha256}').
        self.assertEqual(
            set(observation),
            {
                "normalization_drift_count",
                "normalization_drift_kind",
                "normalization_drift_sha256",
            },
        )

        plan_summary = CHECKER.check_plan(authority_contract_transition_fixture())
        for field in (
            "normalization_drift_count",
            "normalization_drift_kind",
            "normalization_drift_sha256",
        ):
            with self.subTest(field=field):
                self.assertEqual(observation[field], plan_summary[field])

    def test_authority_runtime_slice_normalization_reproof_matches_plan(
        self,
    ) -> None:
        # The op=apply pre-apply re-prove lane re-observes the benign slice
        # completion drift via check_normalization_drift (output-ignoring narrow
        # mode, which skips the full inventory contract). Its {count, kind,
        # sha256} must equal the plan lane's for the identical drift, so the
        # workflow's plan-vs-live cmp matches and the completion apply proceeds.
        exec_roles = sorted(
            address
            for address, resource_type in CHECKER.AUTHORITY_RUNTIME_RESOURCES.items()
            if resource_type == "aws_iam_role"
        )
        drift = [
            _slice_refresh_drift(exec_roles[0], "aws_iam_role"),
            _slice_refresh_drift(exec_roles[1], "aws_iam_role"),
            _slice_refresh_drift(
                CHECKER.AUTHORITY_RUNTIME_DYNAMODB_ADDRESS, "aws_vpc_endpoint"
            ),
        ]
        refresh = plan_fixture()
        refresh["applyable"] = True
        refresh["resource_drift"] = copy.deepcopy(drift)
        prior_state = terraform_1_14_refresh_only_golden(refresh)
        observation = CHECKER.check_normalization_drift(refresh, prior_state)
        self.assertEqual(
            observation["normalization_drift_kind"],
            "authority-runtime-slice-normalization",
        )
        self.assertEqual(observation["normalization_drift_count"], 3)
        self.assertEqual(
            set(observation),
            {
                "normalization_drift_count",
                "normalization_drift_kind",
                "normalization_drift_sha256",
            },
        )
        completion = authority_runtime_partial_retry_fixture(set(exec_roles))
        completion["resource_drift"] = copy.deepcopy(drift)
        plan_summary = CHECKER.check_plan(completion)
        for field in (
            "normalization_drift_count",
            "normalization_drift_kind",
            "normalization_drift_sha256",
        ):
            with self.subTest(field=field):
                self.assertEqual(observation[field], plan_summary[field])

    def test_authority_runtime_slice_normalization_reproof_rejects_outside_slice(
        self,
    ) -> None:
        # A re-prove observation whose drift reaches outside the slice must fail
        # closed in the narrow lane too (not just check_plan).
        exec_role = next(
            address
            for address, resource_type in CHECKER.AUTHORITY_RUNTIME_RESOURCES.items()
            if resource_type == "aws_iam_role"
        )
        refresh = plan_fixture()
        refresh["applyable"] = True
        refresh["resource_drift"] = [
            _slice_refresh_drift(exec_role, "aws_iam_role"),
            _slice_refresh_drift(
                "module.control.aws_kms_key.authority_data", "aws_kms_key"
            ),
        ]
        prior_state = terraform_1_14_refresh_only_golden(refresh)
        with self.assertRaises(CHECKER.ContractError):
            CHECKER.check_normalization_drift(refresh, prior_state)

    def test_authority_enablement_pair_normalization_drift_is_order_insensitive(
        self,
    ) -> None:
        # Terraform may serialize the live-refresh pair in a different order than
        # the reviewed plan; the canonical sha256 must still match so the pair is
        # not spuriously rejected as "moved".
        plan_sha = CHECKER.check_plan(
            authority_contract_transition_fixture()
        )["normalization_drift_sha256"]
        for label in ("forward", "reverse"):
            with self.subTest(order=label):
                candidate, prior_state = authority_enablement_refresh_candidate()
                if label == "reverse":
                    candidate["resource_drift"].reverse()
                observation = CHECKER.check_normalization_drift(
                    candidate, prior_state
                )
                self.assertEqual(observation["normalization_drift_count"], 2)
                self.assertEqual(
                    observation["normalization_drift_kind"],
                    "authority-enablement-normalization",
                )
                self.assertEqual(
                    observation["normalization_drift_sha256"], plan_sha
                )

    def test_authority_enablement_pair_normalization_drift_fails_closed(
        self,
    ) -> None:
        role_address = "module.control.aws_iam_role.hub_publisher"
        digest_address = CHECKER._AUTHORITY_DIGEST_ADDRESS

        def assert_rejected(mutate) -> None:
            candidate, prior_state = authority_enablement_refresh_candidate()
            mutate(candidate, prior_state)
            with self.assertRaises(CHECKER.ContractError):
                CHECKER.check_normalization_drift(candidate, prior_state)

        def swap_role(candidate, _prior) -> None:
            # A different second address is not the reviewed pair.
            next(
                d for d in candidate["resource_drift"] if d["address"] == role_address
            )["address"] = "module.control.aws_iam_role.authority_publisher"

        def corrupt_role(candidate, _prior) -> None:
            # The Hub-publisher-role validator is not weakened by the pair path.
            next(
                d for d in candidate["resource_drift"] if d["address"] == role_address
            )["change"]["after"]["max_session_duration"] = 7200

        def move_state(_candidate, prior) -> None:
            # A moved live observation (drift.before != captured state) must fail
            # closed so the enablement is re-planned, not applied against a stale
            # review.
            state_resource(prior, digest_address)["values"]["version"] = 999

        def drop_policy(_candidate, prior) -> None:
            # The Hub publisher inline policy proves the role identity.
            module = prior["values"]["root_module"]["child_modules"][0]
            module["resources"] = [
                item
                for item in module["resources"]
                if item["address"]
                != "module.control.aws_iam_role_policy.hub_publisher"
            ]

        def extra_third(candidate, _prior) -> None:
            candidate["resource_drift"].append(
                copy.deepcopy(
                    next(
                        d
                        for d in candidate["resource_drift"]
                        if d["address"] == digest_address
                    )
                )
            )

        def not_refresh_only(candidate, _prior) -> None:
            # A config-change plan is not a valid normalization observation.
            candidate["resource_changes"] = []

        for name, mutate in (
            ("swap_role", swap_role),
            ("corrupt_role", corrupt_role),
            ("move_state", move_state),
            ("drop_policy", drop_policy),
            ("extra_third", extra_third),
            ("not_refresh_only", not_refresh_only),
        ):
            with self.subTest(mutation=name):
                assert_rejected(mutate)

    def test_exact_redis_password_refresh_only_normalization_passes(self) -> None:
        golden = json.loads(
            REAL_REDIS_PASSWORD_REFRESH_FIXTURE_PATH.read_text(encoding="utf-8")
        )
        self.assertEqual(golden["terraform_version"], CHECKER.TF_VERSION)
        self.assertEqual(
            golden["aws_provider_version"],
            EXPECTED_AWS_PROVIDER_VERSION,
        )
        self.assertEqual(
            golden["provenance"],
            {
                "source": (
                    "local read-only terraform show -json of the sandbox "
                    "Control refresh-only plan using the exact workflow "
                    "Terraform and provider versions"
                ),
                "corroborating_run_id": "30030853799",
                "state_version_id": "32gMsDv0qisFvqpwtlenhmuLED54Zfry",
                "state_sha256": (
                    "746fd9ae24a6fe78e403bf5f90e3dae2c27fb0aeb1724e00a7c501a6c1e7f9c8"
                ),
                "source_resource_drift_sha256": (
                    "739af817895f15bb81479053537bfb076d753b6530ecd56d905f3bf0e51df2b9"
                ),
                "projection": (
                    "resource identity plus authentication_mode values, "
                    "unknown mask, and sensitive masks"
                ),
                "captured_on": "2026-07-23",
                "contains_sensitive_values": False,
            },
        )
        self.assertEqual(
            tuple(item["address"] for item in golden["resource_drift"]),
            CHECKER._REDIS_PASSWORD_NORMALIZATION_ADDRESSES,
        )
        for item in golden["resource_drift"]:
            change = item["change"]
            self.assertEqual(
                change["before"]["authentication_mode"],
                [{"password_count": 0, "passwords": None, "type": "iam"}],
            )
            self.assertEqual(
                change["after"]["authentication_mode"],
                [{"password_count": 0, "passwords": [], "type": "iam"}],
            )
            self.assertEqual(change["after_unknown"], {})
            self.assertEqual(
                change["before_sensitive"],
                CHECKER._REDIS_PASSWORD_NORMALIZATION_SENSITIVE,
            )
            self.assertEqual(
                change["after_sensitive"],
                CHECKER._REDIS_PASSWORD_NORMALIZATION_SENSITIVE,
            )

        candidate, prior_state = redis_password_refresh_candidate()
        summary = CHECKER.check_plan(candidate, prior_state)

        self.assertEqual(summary["bootstrap_create_count"], 0)
        self.assertEqual(summary["normalization_drift_count"], 2)
        self.assertEqual(
            summary["normalization_drift_kind"],
            "redis-passwords",
        )
        self.assertEqual(summary["plan_mode"], "no-op")
        self.assertEqual(
            summary["normalization_drift_sha256"],
            CHECKER._json_sha256(candidate["resource_drift"]),
        )

    def test_redis_password_refresh_only_normalization_is_exact(self) -> None:
        candidate, prior_state = redis_password_refresh_candidate()
        candidate["resource_drift"].pop()
        self.assert_rejected(candidate, prior_state)

        candidate, prior_state = redis_password_refresh_candidate()
        candidate["resource_drift"].append(
            copy.deepcopy(candidate["resource_drift"][0])
        )
        self.assert_rejected(candidate, prior_state)

        candidate, prior_state = redis_password_refresh_candidate()
        candidate["resource_drift"].reverse()
        self.assert_rejected(candidate, prior_state)

        candidate, prior_state = redis_password_refresh_candidate()
        change = candidate["resource_drift"][0]["change"]
        change["before"]["authentication_mode"], change["after"][
            "authentication_mode"
        ] = (
            change["after"]["authentication_mode"],
            change["before"]["authentication_mode"],
        )
        state_resource(
            prior_state,
            candidate["resource_drift"][0]["address"],
        )["values"] = copy.deepcopy(change["before"])
        self.assert_rejected(candidate, prior_state)

        candidate, prior_state = redis_password_refresh_candidate()
        candidate["resource_drift"][0]["change"]["after"][
            "authentication_mode"
        ][0]["passwords"] = ["must-not-appear"]
        self.assert_rejected(candidate, prior_state)

        candidate, prior_state = redis_password_refresh_candidate()
        candidate["resource_drift"][0]["change"]["after_unknown"] = {
            "authentication_mode": [{"passwords": True}]
        }
        self.assert_rejected(candidate, prior_state)

        candidate, prior_state = redis_password_refresh_candidate()
        candidate["resource_drift"][0]["change"]["after"]["engine"] = "valkey"
        self.assert_rejected(candidate, prior_state)

        candidate, prior_state = redis_password_refresh_candidate()
        candidate["resource_drift"][0]["change"]["after_sensitive"] = {}
        self.assert_rejected(candidate, prior_state)

        candidate, prior_state = redis_password_refresh_candidate()
        change = candidate["resource_drift"][0]["change"]
        for side in ("before", "after"):
            change[side]["authentication_mode"][0]["password_count"] = False
        state_resource(
            prior_state,
            candidate["resource_drift"][0]["address"],
        )["values"] = copy.deepcopy(change["before"])
        self.assert_rejected(candidate, prior_state)

        candidate, prior_state = redis_password_refresh_candidate()
        candidate["resource_drift"][0]["change"]["before_sensitive"][
            "authentication_mode"
        ][0]["passwords"] = 1
        self.assert_rejected(candidate, prior_state)

        candidate, prior_state = redis_password_refresh_candidate()
        change = candidate["resource_drift"][0]["change"]
        change["before"]["opaque_projection"] = False
        change["after"]["opaque_projection"] = 0
        state_resource(
            prior_state,
            candidate["resource_drift"][0]["address"],
        )["values"] = copy.deepcopy(change["before"])
        self.assert_rejected(candidate, prior_state)

        candidate, prior_state = redis_password_refresh_candidate()
        candidate["resource_drift"][0]["provider_name"] = "example.invalid/aws"
        self.assert_rejected(candidate, prior_state)

        candidate, prior_state = redis_password_refresh_candidate()
        candidate["applyable"] = False
        self.assert_rejected(candidate, prior_state)

        candidate, prior_state = redis_password_refresh_candidate()
        digest, _ = authority_digest_refresh_candidate()
        candidate["resource_drift"].append(
            copy.deepcopy(digest["resource_drift"][0])
        )
        self.assert_rejected(candidate, prior_state)

        normalization, prior_state = redis_password_refresh_candidate()
        ordinary = plan_fixture()
        ordinary["resource_drift"] = copy.deepcopy(
            normalization["resource_drift"]
        )
        self.assert_rejected(ordinary, prior_state)

    def test_authority_digest_refresh_only_normalization_is_exact(self) -> None:
        for mutation in (
            lambda change: change["after"].__setitem__("description", "piggyback"),
            lambda change: change["after"].__setitem__("value", "latest"),
            lambda change: change["after"].__setitem__("version", 7),
            lambda change: change["before"].__setitem__("version", 0),
            lambda change: change.__setitem__("replace_paths", []),
            lambda change: change.__setitem__("after_sensitive", {}),
            lambda change: change.__setitem__("after_unknown", {"version": True}),
        ):
            candidate, prior_state = authority_digest_refresh_candidate()
            mutation(candidate["resource_drift"][0]["change"])
            self.assert_rejected(candidate, prior_state)

        for mutation in (
            lambda item: item.__setitem__("provider_name", "example.invalid/aws"),
            lambda item: item.__setitem__("unexpected", "metadata"),
        ):
            candidate, prior_state = authority_digest_refresh_candidate()
            mutation(candidate["resource_drift"][0])
            self.assert_rejected(candidate, prior_state)

        candidate, prior_state = authority_digest_refresh_candidate()
        drift_change = candidate["resource_drift"][0]["change"]
        drift_change["before"]["unexpected"] = "stable"
        drift_change["after"]["unexpected"] = "stable"
        state_resource(
            prior_state, CHECKER._AUTHORITY_DIGEST_ADDRESS
        )["values"]["unexpected"] = "stable"
        self.assert_rejected(candidate, prior_state)

        candidate, prior_state = authority_digest_refresh_candidate()
        parameter = state_resource(
            prior_state, CHECKER._AUTHORITY_DIGEST_ADDRESS
        )
        parameter["values"]["version"] = 6
        self.assert_rejected(candidate, prior_state)

    def test_live_authority_digest_normalization_guards_are_exact(self) -> None:
        cases = []

        candidate, prior_state = authority_digest_refresh_candidate()
        candidate["resource_changes"] = []
        cases.append((candidate, prior_state))

        candidate, prior_state = authority_digest_refresh_candidate()
        candidate["planned_values"]["root_module"] = {"unexpected": True}
        cases.append((candidate, prior_state))

        candidate, prior_state = authority_digest_refresh_candidate()
        prior_state["format_version"] = "1.1"
        cases.append((candidate, prior_state))

        candidate, prior_state = authority_digest_refresh_candidate()
        state_resource(
            prior_state, CHECKER._AUTHORITY_DIGEST_ADDRESS
        )["values"]["version"] = 6
        cases.append((candidate, prior_state))

        candidate, prior_state = authority_digest_refresh_candidate()
        prior_state["values"]["root_module"]["child_modules"][0][
            "resources"
        ] = [
            item
            for item in prior_state["values"]["root_module"]["child_modules"][
                0
            ]["resources"]
            if item["address"] != CHECKER._AUTHORITY_DIGEST_ADDRESS
        ]
        cases.append((candidate, prior_state))

        for candidate, prior_state in cases:
            with self.subTest(candidate=candidate, prior_state=prior_state):
                with self.assertRaises(CHECKER.ContractError):
                    CHECKER.check_normalization_drift(candidate, prior_state)

    def test_authority_digest_only_ordinary_plan_requires_refresh_only(self) -> None:
        normalization, prior_state = authority_digest_refresh_candidate()
        candidate = plan_fixture()
        candidate["resource_drift"] = copy.deepcopy(normalization["resource_drift"])
        parameter = self.change(candidate, CHECKER._AUTHORITY_DIGEST_ADDRESS)
        parameter["before"] = copy.deepcopy(
            normalization["resource_drift"][0]["change"]["after"]
        )
        parameter["after"] = copy.deepcopy(parameter["before"])

        self.assert_rejected(candidate, prior_state)

    def test_refresh_only_output_contract_is_exact_and_secret_safe(self) -> None:
        declared_outputs = set(
            re.findall(
                r'^output\s+"([^"]+)"',
                (ROOT / "terraform/control/environments/sandbox/outputs.tf").read_text(
                    encoding="utf-8"
                ),
                flags=re.MULTILINE,
            )
        )
        self.assertEqual(declared_outputs, CHECKER.EXPECTED_CONTROL_OUTPUTS)
        output_name = min(CHECKER.EXPECTED_CONTROL_OUTPUTS)

        missing_output, missing_output_state = publisher_refresh_candidate()
        del missing_output["planned_values"]["outputs"][output_name]
        self.assert_rejected(missing_output, missing_output_state)

        sensitive_output, sensitive_output_state = publisher_refresh_candidate()
        sensitive_output["planned_values"]["outputs"][output_name]["sensitive"] = True
        self.assert_rejected(sensitive_output, sensitive_output_state)

        missing_value, missing_value_state = publisher_refresh_candidate()
        del missing_value["planned_values"]["outputs"][output_name]["value"]
        self.assert_rejected(missing_value, missing_value_state)

        state_mismatch, state_mismatch_state = publisher_refresh_candidate()
        state_mismatch["planned_values"]["outputs"][output_name]["value"] = False
        state_mismatch_state["values"]["outputs"][output_name]["value"] = 0
        self.assert_rejected(state_mismatch, state_mismatch_state)

        root_resource, root_resource_state = publisher_refresh_candidate()
        root_resource["planned_values"]["root_module"] = {
            "resources": [{"address": "redacted"}]
        }
        self.assert_rejected(root_resource, root_resource_state)

        extra_top_key, extra_top_key_state = publisher_refresh_candidate()
        extra_top_key["planned_values"]["unexpected"] = {}
        self.assert_rejected(extra_top_key, extra_top_key_state)

        missing_change, missing_change_state = publisher_refresh_candidate()
        del missing_change["output_changes"][output_name]
        self.assert_rejected(missing_change, missing_change_state)

        changed_output, changed_output_state = publisher_refresh_candidate()
        changed_output["output_changes"][output_name]["actions"] = ["update"]
        self.assert_rejected(changed_output, changed_output_state)

        unknown_output, unknown_output_state = publisher_refresh_candidate()
        unknown_output["output_changes"][output_name]["after_unknown"] = True
        self.assert_rejected(unknown_output, unknown_output_state)

        integer_sensitivity, integer_sensitivity_state = publisher_refresh_candidate()
        integer_sensitivity["output_changes"][output_name]["before_sensitive"] = 0
        self.assert_rejected(integer_sensitivity, integer_sensitivity_state)

        wrong_before, wrong_before_state = publisher_refresh_candidate()
        wrong_before["output_changes"][output_name]["before"] = "different"
        self.assert_rejected(wrong_before, wrong_before_state)

        sentinel = "super-secret-output-value-7f510f845f8e"
        extra_output, extra_output_state = publisher_refresh_candidate()
        extra_output["planned_values"]["outputs"][sentinel] = {
            "sensitive": False,
            "type": "string",
            "value": sentinel,
        }
        with self.assertRaises(CHECKER.ContractError) as error:
            CHECKER.check_plan(extra_output, extra_output_state)
        self.assertNotIn(sentinel, str(error.exception))

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plan_path = root / "plan.json"
            state_path = root / "state.json"
            write_json(plan_path, extra_output)
            write_json(state_path, extra_output_state)
            result = subprocess.run(
                [str(CHECKER_PATH), "plan", str(plan_path), str(state_path)],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, "")
            self.assertNotIn(sentinel, result.stderr)

    def test_publisher_refresh_only_normalization_is_exact(self) -> None:
        refresh_candidate = publisher_refresh_candidate

        wrong_address, wrong_address_state = refresh_candidate()
        wrong_address["resource_drift"][0]["address"] = (
            "module.control.aws_iam_role.flow_logs"
        )
        self.assert_rejected(wrong_address, wrong_address_state)

        orphan_drift, orphan_drift_state = refresh_candidate()
        orphan_drift["resource_drift"][0]["address"] = (
            "module.control.aws_iam_role.missing"
        )
        self.assert_rejected(orphan_drift, orphan_drift_state)

        extra_drift, extra_drift_state = refresh_candidate()
        extra_drift["resource_drift"].append(
            {
                "address": "module.control.aws_vpc.control",
                "mode": "managed",
                "type": "aws_vpc",
                "change": {"actions": ["update"], "before": {}, "after": {}},
            }
        )
        self.assert_rejected(extra_drift, extra_drift_state)

        other_field, other_field_state = refresh_candidate()
        other_field["resource_drift"][0]["change"]["before"][
            "max_session_duration"
        ] = 7200
        self.assert_rejected(other_field, other_field_state)

        missing_null_field, missing_null_field_state = refresh_candidate()
        del missing_null_field["resource_drift"][0]["change"]["before"][
            "permissions_boundary"
        ]
        self.assert_rejected(missing_null_field, missing_null_field_state)

        wrong_policy, wrong_policy_state = refresh_candidate()
        wrong_policy["resource_drift"][0]["change"]["after"]["inline_policy"][0][
            "policy"
        ] = "{}"
        self.assert_rejected(wrong_policy, wrong_policy_state)

        ordinary_plan, ordinary_plan_state = refresh_candidate()
        ordinary_plan["applyable"] = False
        self.assert_rejected(ordinary_plan, ordinary_plan_state)

        unknown_value, unknown_value_state = refresh_candidate()
        unknown_value["resource_drift"][0]["change"]["after_unknown"] = {
            "assume_role_policy": True
        }
        self.assert_rejected(unknown_value, unknown_value_state)

        sensitive_value, sensitive_value_state = refresh_candidate()
        sensitive_value["resource_drift"][0]["change"]["after_sensitive"][
            "inline_policy"
        ][0]["policy"] = True
        self.assert_rejected(sensitive_value, sensitive_value_state)

        scalar_masks, scalar_masks_state = refresh_candidate()
        scalar_masks["resource_drift"][0]["change"]["before_sensitive"] = False
        scalar_masks["resource_drift"][0]["change"]["after_sensitive"] = False
        self.assert_rejected(scalar_masks, scalar_masks_state)

        swapped_masks, swapped_masks_state = refresh_candidate()
        swapped_change = swapped_masks["resource_drift"][0]["change"]
        (
            swapped_change["before_sensitive"],
            swapped_change["after_sensitive"],
        ) = (
            swapped_change["after_sensitive"],
            swapped_change["before_sensitive"],
        )
        self.assert_rejected(swapped_masks, swapped_masks_state)

        missing_collection, missing_collection_state = refresh_candidate()
        missing_collection["resource_drift"][0]["change"]["after_sensitive"] = {}
        self.assert_rejected(missing_collection, missing_collection_state)

        wrong_collection_length, wrong_collection_length_state = refresh_candidate()
        wrong_collection_length["resource_drift"][0]["change"][
            "after_sensitive"
        ]["inline_policy"] = []
        self.assert_rejected(wrong_collection_length, wrong_collection_length_state)

        wrong_collection_type, wrong_collection_type_state = refresh_candidate()
        wrong_collection_type["resource_drift"][0]["change"][
            "after_sensitive"
        ]["inline_policy"] = {}
        self.assert_rejected(wrong_collection_type, wrong_collection_type_state)

        extra_sensitive_key, extra_sensitive_key_state = refresh_candidate()
        extra_sensitive_key["resource_drift"][0]["change"]["after_sensitive"][
            "permissions_boundary"
        ] = False
        self.assert_rejected(extra_sensitive_key, extra_sensitive_key_state)

        extra_collection, extra_collection_state = refresh_candidate()
        extra_collection_change = extra_collection["resource_drift"][0]["change"]
        extra_collection_change["before"]["unexpected_collection"] = []
        extra_collection_change["after"]["unexpected_collection"] = []
        extra_collection_change["before_sensitive"]["unexpected_collection"] = []
        extra_collection_change["after_sensitive"]["unexpected_collection"] = []
        extra_collection_state_role = state_publisher_role(extra_collection_state)
        extra_collection_state_role["values"]["unexpected_collection"] = []
        self.assert_rejected(extra_collection, extra_collection_state)

        integer_sensitive, integer_sensitive_state = refresh_candidate()
        integer_sensitive["resource_drift"][0]["change"]["before_sensitive"] = 0
        self.assert_rejected(integer_sensitive, integer_sensitive_state)

        sentinel = "publisher-secret-sentinel-79c17e31"
        secret_safe, secret_safe_state = refresh_candidate()
        secret_change = secret_safe["resource_drift"][0]["change"]
        secret_change["before"]["permissions_boundary"] = sentinel
        secret_change["after"]["permissions_boundary"] = sentinel
        secret_state_role = state_publisher_role(secret_safe_state)
        secret_state_role["values"]["permissions_boundary"] = sentinel
        secret_change["after_sensitive"] = {"permissions_boundary": True}
        with self.assertRaises(CHECKER.ContractError) as error:
            CHECKER.check_plan(secret_safe, secret_safe_state)
        self.assertNotIn(sentinel, str(error.exception))

        missing_sensitive, missing_sensitive_state = refresh_candidate()
        del missing_sensitive["resource_drift"][0]["change"]["before_sensitive"]
        del missing_sensitive["resource_drift"][0]["change"]["after_sensitive"]
        self.assert_rejected(missing_sensitive, missing_sensitive_state)

        unexpected_planned_values, unexpected_planned_state = refresh_candidate()
        unexpected_planned_values["planned_values"] = {
            "root_module": {"child_modules": []}
        }
        self.assert_rejected(unexpected_planned_values, unexpected_planned_state)

        missing_prior_state, _ = refresh_candidate()
        self.assert_rejected(missing_prior_state)

        wrong_state_format, wrong_state_format_state = refresh_candidate()
        wrong_state_format_state["format_version"] = "1.1"
        self.assert_rejected(wrong_state_format, wrong_state_format_state)

        wrong_state_version, wrong_state_version_state = refresh_candidate()
        wrong_state_version_state["terraform_version"] = "1.15.0"
        self.assert_rejected(wrong_state_version, wrong_state_version_state)

        mismatched_prior, mismatched_prior_state = refresh_candidate()
        mismatched_role = state_publisher_role(mismatched_prior_state)
        mismatched_role["values"]["max_session_duration"] = 7200
        self.assert_rejected(mismatched_prior, mismatched_prior_state)

        state_security, state_security_prior = refresh_candidate()
        kms_endpoint = state_resource(
            state_security_prior,
            'module.control.aws_vpc_endpoint.interface["kms"]',
        )
        kms_endpoint["values"]["private_dns_enabled"] = False
        self.assert_rejected(state_security, state_security_prior)

        malformed_resource_changes, malformed_state = refresh_candidate()
        malformed_resource_changes["resource_changes"] = None
        self.assert_rejected(malformed_resource_changes, malformed_state)

    def test_unexpected_resource_drift_diagnostic_is_value_free(self) -> None:
        sentinel = "drift-secret-sentinel-598d5135"
        candidate = plan_fixture()
        candidate["resource_drift"] = [
            {
                "address": "module.control.aws_iam_role.flow_logs",
                "mode": "managed",
                "type": "aws_iam_role",
                "change": {
                    "actions": ["update"],
                    "before": {"secret": sentinel},
                    "after": {"secret": sentinel},
                },
            }
        ]

        with self.assertRaises(CHECKER.ContractError) as error:
            CHECKER.check_plan(candidate)

        message = str(error.exception)
        self.assertIn(
            'resource_drift_identity={"count":1,"identities":['
            '{"address":"module.control.aws_iam_role.flow_logs",'
            '"mode":"managed","type":"aws_iam_role"}],"truncated":false}',
            message,
        )
        self.assertNotIn(sentinel, message)

    def test_unexpected_resource_drift_diagnostic_is_bounded(self) -> None:
        hidden_suffix = "hidden-drift-suffix-2a282d43"
        long_field = "x" * (CHECKER._DRIFT_IDENTITY_FIELD_MAX_CHARS + 1) + hidden_suffix
        candidate = plan_fixture()
        candidate["resource_drift"] = [
            {
                "address": long_field,
                "mode": long_field,
                "type": long_field,
                "change": {
                    "actions": ["update"],
                    "before": {"secret": hidden_suffix},
                    "after": {"secret": hidden_suffix},
                },
            }
            for _ in range(CHECKER._DRIFT_IDENTITY_LIMIT + 2)
        ]

        with self.assertRaises(CHECKER.ContractError) as error:
            CHECKER.check_plan(candidate)

        message = str(error.exception)
        self.assertIn(
            f'resource_drift_identity={{"count":{CHECKER._DRIFT_IDENTITY_LIMIT + 2},',
            message,
        )
        self.assertIn('"truncated":true', message)
        self.assertEqual(message.count('"address"'), CHECKER._DRIFT_IDENTITY_LIMIT)
        self.assertEqual(
            message.count("<truncated>"), CHECKER._DRIFT_IDENTITY_LIMIT * 3
        )
        self.assertNotIn(hidden_suffix, message)
        self.assertLess(len(message), 8_000)

    def test_unexpected_resource_drift_diagnostic_redacts_instance_keys(
        self,
    ) -> None:
        sentinel = "sensitive-instance-key-85bb4441"
        candidate = plan_fixture()
        candidate["resource_drift"] = [
            {
                "address": f'module.control.aws_iam_role.publisher["{sentinel}"]',
                "mode": "managed",
                "type": "aws_iam_role",
                "change": {"actions": ["update"]},
            }
        ]

        with self.assertRaises(CHECKER.ContractError) as error:
            CHECKER.check_plan(candidate)

        diagnostic = str(error.exception).split("resource_drift_identity=", 1)[1]
        decoded = json.loads(diagnostic)
        self.assertEqual(decoded["identities"][0]["address"], "<indexed-address>")
        self.assertTrue(decoded["truncated"])
        self.assertNotIn(sentinel, diagnostic)

    def test_unexpected_resource_drift_diagnostic_bounds_json_escape_expansion(
        self,
    ) -> None:
        hidden_suffix = "hidden-unicode-suffix-c0268e7f"
        long_field = (
            "\N{GRINNING FACE}" * (CHECKER._DRIFT_IDENTITY_FIELD_MAX_CHARS + 1)
            + hidden_suffix
        )
        candidate = plan_fixture()
        candidate["resource_drift"] = [
            {
                "address": long_field,
                "mode": long_field,
                "type": long_field,
                "change": {"actions": ["update"]},
            }
            for _ in range(CHECKER._DRIFT_IDENTITY_LIMIT + 2)
        ]

        with self.assertRaises(CHECKER.ContractError) as error:
            CHECKER.check_plan(candidate)

        message = str(error.exception)
        diagnostic = message.split("resource_drift_identity=", 1)[1]
        self.assertLessEqual(len(diagnostic), CHECKER._DRIFT_DIAGNOSTIC_MAX_CHARS)
        self.assertTrue(json.loads(diagnostic)["truncated"])
        self.assertNotIn(hidden_suffix, diagnostic)

    def test_unexpected_resource_drift_diagnostic_keeps_one_unicode_identity(
        self,
    ) -> None:
        hidden_suffix = "hidden-unicode-suffix-7125ad55"
        long_field = (
            "\N{GRINNING FACE}" * (CHECKER._DRIFT_IDENTITY_FIELD_MAX_CHARS + 1)
            + hidden_suffix
        )
        candidate = plan_fixture()
        candidate["resource_drift"] = [
            {
                "address": long_field,
                "mode": long_field,
                "type": long_field,
                "change": {"actions": ["update"]},
            }
        ]

        with self.assertRaises(CHECKER.ContractError) as error:
            CHECKER.check_plan(candidate)

        diagnostic = str(error.exception).split("resource_drift_identity=", 1)[1]
        decoded = json.loads(diagnostic)
        self.assertEqual(len(decoded["identities"]), 1)
        self.assertTrue(decoded["truncated"])
        self.assertTrue(
            all(
                value.endswith("<truncated>")
                for value in decoded["identities"][0].values()
            )
        )
        self.assertLessEqual(len(diagnostic), CHECKER._DRIFT_DIAGNOSTIC_MAX_CHARS)
        self.assertNotIn(hidden_suffix, diagnostic)

    def test_resource_drift_rejects_non_object_entries(self) -> None:
        candidate = plan_fixture()
        candidate["resource_drift"] = ["malformed-resource-drift"]

        with self.assertRaisesRegex(
            CHECKER.ContractError, "resource_drift entries must be objects"
        ):
            CHECKER.check_plan(candidate)

        candidate["resource_drift"] = [{"change": "malformed-change"}]
        with self.assertRaisesRegex(
            CHECKER.ContractError, "resource_drift change entries must be objects"
        ):
            CHECKER.check_plan(candidate)

    def test_unexpected_resource_drift_diagnostic_masks_malformed_identity(
        self,
    ) -> None:
        sentinel = "malformed-drift-sentinel-b7f7555e"
        candidate = plan_fixture()
        candidate["resource_drift"] = [
            {
                "address": {"secret": sentinel},
                "mode": [sentinel],
                "type": None,
                "change": {"actions": ["update"]},
            }
        ]

        with self.assertRaises(CHECKER.ContractError) as error:
            CHECKER.check_plan(candidate)

        message = str(error.exception)
        self.assertIn(
            'resource_drift_identity={"count":1,"identities":['
            '{"address":"<malformed>","mode":"<malformed>",'
            '"type":"<malformed>"}],"truncated":true}',
            message,
        )
        self.assertNotIn(sentinel, message)

    def test_publisher_updates_and_malformed_create_fail(self) -> None:
        update = plan_fixture()
        change = self.change(
            update, "module.control.aws_iam_role.authority_publisher"
        )
        change["actions"] = ["update"]
        change["after"]["max_session_duration"] = 7200
        update["applyable"] = True
        self.assert_rejected(update)

        malformed_create = plan_fixture()
        change = self.change(
            malformed_create,
            "module.control.aws_iam_role_policy.authority_publisher",
        )
        change["actions"] = ["create"]
        change["before"] = None
        change["after"]["policy"] = json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "ssm:*",
                        "Resource": "*",
                    }
                ],
            }
        )
        malformed_create["applyable"] = True
        self.assert_rejected(malformed_create)

        permissions_boundary = plan_fixture()
        self.change(
            permissions_boundary,
            "module.control.aws_iam_role.authority_publisher",
        )["after"]["permissions_boundary"] = "arn:aws:iam::123456789012:policy/broad"
        self.assert_rejected(permissions_boundary)

        malformed_reflection = plan_fixture()
        reflected_role = self.change(
            malformed_reflection,
            "module.control.aws_iam_role.authority_publisher",
        )
        reflected_role["after"]["inline_policy"][0]["policy"] = "{}"
        reflected_role["before"] = copy.deepcopy(reflected_role["after"])
        self.assert_rejected(malformed_reflection)

    def test_publisher_role_create_without_policy_create_fails(self) -> None:
        candidate = plan_fixture()
        candidate["applyable"] = True
        change = self.change(
            candidate, "module.control.aws_iam_role.authority_publisher"
        )
        change["actions"] = ["create"]
        change["before"] = None
        change["after_unknown"]["managed_policy_arns"] = True

        self.assert_rejected(candidate)

    def test_exact_redis_split_and_partial_retry_transitions_pass(self) -> None:
        all_users = {
            "module.control.aws_elasticache_user.otp_activator",
            "module.control.aws_elasticache_user.otp_issuer",
        }
        for create_addresses in (
            all_users,
            {"module.control.aws_elasticache_user.otp_activator"},
            {"module.control.aws_elasticache_user.otp_issuer"},
            set(),
        ):
            with self.subTest(create_addresses=create_addresses):
                result = CHECKER.check_plan(
                    redis_split_transition_fixture(create_addresses)
                )
                self.assertEqual(result["resource_count"], 50)
                self.assertEqual(result["plan_mode"], "redis-split-transition")

    def test_redis_iam_create_authentication_mode_matches_real_golden(self) -> None:
        golden = json.loads(
            REAL_REDIS_IAM_CREATE_FIXTURE_PATH.read_text(encoding="utf-8")
        )
        self.assertEqual(golden["terraform_version"], CHECKER.TF_VERSION)
        self.assertEqual(
            golden["aws_provider_version"], EXPECTED_AWS_PROVIDER_VERSION
        )
        self.assertEqual(
            golden["provenance"],
            {
                "source": (
                    "terraform show -json for a create-only "
                    "aws_elasticache_user plan"
                ),
                "projection": (
                    "change actions plus authentication_mode value, unknown, "
                    "and sensitive masks"
                ),
                "captured_on": "2026-07-21",
                "contains_sensitive_values": False,
            },
        )
        self.assertEqual(golden["change"]["actions"], ["create"])
        self.assertIsNone(golden["change"]["before"])
        self.assertEqual(
            golden["change"]["after"]["authentication_mode"],
            CHECKER._REDIS_IAM_CREATE_AUTHENTICATION_MODE,
        )
        self.assertEqual(
            golden["change"]["after_unknown"]["authentication_mode"],
            CHECKER._REDIS_IAM_CREATE_AUTHENTICATION_MODE_UNKNOWN,
        )
        self.assertEqual(
            golden["change"]["after_sensitive"]["authentication_mode"],
            CHECKER._REDIS_IAM_CREATE_AUTHENTICATION_MODE_SENSITIVE,
        )
        self.assertEqual(
            CHECKER.check_plan(redis_split_transition_fixture())["plan_mode"],
            "redis-split-transition",
        )
        no_op = plan_fixture()
        no_op_auth = self.change(
            no_op, "module.control.aws_elasticache_user.otp_activator"
        )["after"]["authentication_mode"]
        self.assertEqual(
            no_op_auth,
            [{"password_count": 0, "passwords": [], "type": "iam"}],
        )
        self.assertEqual(CHECKER.check_plan(no_op)["plan_mode"], "no-op")

    def test_redis_iam_create_authentication_mode_rejects_shape_drift(self) -> None:
        for label, path, value, delete in (
            ("after-null", ("after", "authentication_mode"), None, False),
            (
                "after-passwords-known",
                ("after", "authentication_mode", 0, "passwords"),
                [],
                False,
            ),
            (
                "unknown-null",
                ("after_unknown", "authentication_mode"),
                None,
                False,
            ),
            (
                "unknown-missing",
                ("after_unknown", "authentication_mode"),
                None,
                True,
            ),
            (
                "unknown-false",
                ("after_unknown", "authentication_mode"),
                [{"password_count": False}],
                False,
            ),
            (
                "unknown-extra",
                ("after_unknown", "authentication_mode"),
                [{"password_count": True, "passwords": True}],
                False,
            ),
            (
                "sensitive-null",
                ("after_sensitive", "authentication_mode"),
                None,
                False,
            ),
            (
                "sensitive-missing",
                ("after_sensitive", "authentication_mode"),
                None,
                True,
            ),
            (
                "sensitive-false",
                ("after_sensitive", "authentication_mode"),
                [{"passwords": False}],
                False,
            ),
        ):
            with self.subTest(label=label):
                candidate = redis_split_transition_fixture()
                change = self.change(
                    candidate,
                    "module.control.aws_elasticache_user.otp_activator",
                )
                if delete:
                    delete_expression_path(change, path)
                else:
                    set_expression_path(change, path, value)
                self.assert_rejected(candidate)

    def test_redis_iam_create_envelope_requires_create_with_null_before(self) -> None:
        update = redis_split_transition_fixture()
        update_change = self.change(
            update, "module.control.aws_elasticache_user.otp_activator"
        )
        update_change["actions"] = ["update"]
        update_change["before"] = copy.deepcopy(update_change["after"])
        self.assert_rejected(update)

        non_null_before = redis_split_transition_fixture()
        create_change = self.change(
            non_null_before, "module.control.aws_elasticache_user.otp_activator"
        )
        create_change["before"] = copy.deepcopy(create_change["after"])
        self.assert_rejected(non_null_before)

    def test_non_create_redis_auth_and_group_values_must_be_fully_known(self) -> None:
        activator = "module.control.aws_elasticache_user.otp_activator"
        issuer = "module.control.aws_elasticache_user.otp_issuer"
        group = "module.control.aws_elasticache_user_group.otp"
        scenarios = (
            ("full-noop", plan_fixture, activator, "no-op"),
            (
                "partial-retry",
                lambda: redis_split_transition_fixture({activator}),
                issuer,
                "redis-split-transition",
            ),
        )
        for scenario, candidate_factory, existing_user, plan_mode in scenarios:
            with self.subTest(scenario=scenario, shape="baseline"):
                self.assertEqual(
                    CHECKER.check_plan(candidate_factory())["plan_mode"], plan_mode
                )

            for shape in (
                "whole-auth-unknown",
                "auth-mask-none",
                "auth-mask-false",
                "password-count-unknown",
                "password-count-none",
                "passwords-unknown",
            ):
                with self.subTest(scenario=scenario, shape=shape):
                    candidate = candidate_factory()
                    change = self.change(candidate, existing_user)
                    if shape == "whole-auth-unknown":
                        change["after_unknown"]["authentication_mode"] = True
                    elif shape == "auth-mask-none":
                        change["after_unknown"]["authentication_mode"] = None
                    elif shape == "auth-mask-false":
                        change["after_unknown"]["authentication_mode"] = False
                    elif shape == "password-count-unknown":
                        change["after_unknown"]["authentication_mode"] = [
                            {"password_count": True}
                        ]
                    elif shape == "password-count-none":
                        for side in ("before", "after"):
                            set_expression_path(
                                change,
                                (
                                    side,
                                    "authentication_mode",
                                    0,
                                    "password_count",
                                ),
                                None,
                            )
                    else:
                        change["after_unknown"]["authentication_mode"] = [
                            {"passwords": True}
                        ]
                    self.assert_rejected(candidate)

            with self.subTest(scenario=scenario, shape="group-users-unknown"):
                candidate = candidate_factory()
                self.change(candidate, group)["after_unknown"]["user_ids"] = True
                self.assert_rejected(candidate)

    def test_missing_password_count_counterexample_fails_closed(self) -> None:
        activator = "module.control.aws_elasticache_user.otp_activator"
        issuer = "module.control.aws_elasticache_user.otp_issuer"
        for scenario, candidate_factory, existing_user, plan_mode in (
            ("full-noop", plan_fixture, activator, "no-op"),
            (
                "partial-retry",
                lambda: redis_split_transition_fixture({activator}),
                issuer,
                "redis-split-transition",
            ),
        ):
            with self.subTest(scenario=scenario):
                candidate = candidate_factory()
                self.assertEqual(
                    CHECKER.check_plan(candidate)["plan_mode"], plan_mode
                )
                change = self.change(candidate, existing_user)
                for side in ("before", "after"):
                    delete_expression_path(
                        change,
                        (side, "authentication_mode", 0, "password_count"),
                    )
                auth = change["after"]["authentication_mode"]
                self.assertEqual(auth, [{"passwords": [], "type": "iam"}])
                # The prior predicate read this missing field as None and
                # incorrectly treated it as equivalent to a proven zero.
                self.assertIsNone(auth[0].get("password_count"))
                self.assert_rejected(candidate)

    def test_redis_split_transition_requires_exact_legacy_membership(self) -> None:
        for user_ids in (
            [f"{CHECKER.CONTROL_PREFIX}-otp-default"],
            [
                f"{CHECKER.CONTROL_PREFIX}-otp-auth",
                f"{CHECKER.CONTROL_PREFIX}-otp-default",
                f"{CHECKER.CONTROL_PREFIX}-otp-default",
            ],
            None,
            "malformed",
        ):
            with self.subTest(user_ids=user_ids):
                candidate = redis_split_transition_fixture()
                self.change(
                    candidate, "module.control.aws_elasticache_user_group.otp"
                )["before"]["user_ids"] = user_ids
                self.assert_rejected(candidate)

    def test_redis_split_rejects_group_piggyback_and_missing_group_update(self) -> None:
        piggyback = redis_split_transition_fixture()
        self.change(piggyback, "module.control.aws_elasticache_user_group.otp")[
            "after"
        ]["engine"] = "valkey"
        self.assert_rejected(piggyback)

        missing_group = redis_split_transition_fixture()
        group = self.change(
            missing_group, "module.control.aws_elasticache_user_group.otp"
        )
        group["actions"] = ["no-op"]
        group["before"] = copy.deepcopy(group["after"])
        self.assert_rejected(missing_group)

    def test_publisher_and_redis_transitions_cannot_be_combined(self) -> None:
        candidate = redis_split_transition_fixture()
        for address in CHECKER.PUBLISHER_BOOTSTRAP_RESOURCES:
            change = self.change(candidate, address)
            change["actions"] = ["create"]
            change["before"] = None
            if address == "module.control.aws_iam_role.authority_publisher":
                change["after_unknown"]["managed_policy_arns"] = True
            else:
                change["after"]["role"] = None
                change["after_unknown"]["role"] = True
        self.assert_rejected(candidate)

    def test_redis_and_publisher_normalization_cannot_be_combined(self) -> None:
        normalization, prior_state = publisher_refresh_candidate()
        candidate = redis_split_transition_fixture()
        candidate["resource_drift"] = copy.deepcopy(normalization["resource_drift"])

        self.assert_rejected(candidate, prior_state)

    def test_redis_may_carry_exact_authority_digest_normalization(self) -> None:
        normalization, prior_state = authority_digest_refresh_candidate()
        candidate = redis_split_transition_fixture()
        candidate["resource_drift"] = copy.deepcopy(normalization["resource_drift"])
        parameter = self.change(candidate, CHECKER._AUTHORITY_DIGEST_ADDRESS)
        parameter["before"] = copy.deepcopy(
            normalization["resource_drift"][0]["change"]["after"]
        )
        parameter["after"] = copy.deepcopy(parameter["before"])

        summary = CHECKER.check_plan(candidate, prior_state)
        self.assertEqual(summary["plan_mode"], "redis-split-transition")
        self.assertEqual(summary["normalization_drift_kind"], "authority-digest")
        live_summary = CHECKER.check_normalization_drift(
            normalization, prior_state
        )
        self.assertEqual(
            summary["normalization_drift_sha256"],
            live_summary["normalization_drift_sha256"],
        )

        piggyback = copy.deepcopy(candidate)
        piggyback["resource_drift"][0]["change"]["after"]["description"] = "changed"
        self.assert_rejected(piggyback, prior_state)

    # --- Connector Authority runtime slice (Step 4) ---------------------------

    def test_exact_authority_runtime_slice_passes(self) -> None:
        summary = CHECKER.check_plan(authority_runtime_transition_fixture())
        self.assertEqual(summary["plan_mode"], "authority-runtime-slice")
        self.assertEqual(
            summary["resource_count"],
            len(CHECKER.EXPECTED_RESOURCES) + len(CHECKER.AUTHORITY_RUNTIME_RESOURCES),
        )
        self.assertEqual(summary["bootstrap_create_count"], 0)

    def test_authority_runtime_steady_state_noop_passes(self) -> None:
        summary = CHECKER.check_plan(authority_runtime_steady_fixture())
        self.assertEqual(summary["plan_mode"], "no-op")
        self.assertEqual(
            summary["resource_count"],
            len(CHECKER.EXPECTED_RESOURCES) + len(CHECKER.AUTHORITY_RUNTIME_RESOURCES),
        )

    def test_authority_runtime_slice_partial_retry_passes(self) -> None:
        """After a partial apply (e.g. the DynamoDB gateway open was rejected
        mid-run) the already-created slice resources replan as no-ops and only
        the remaining creates plus the three opens stay pending. The slice
        transition must still be accepted across the full-slice (``set()``),
        one-applied, and real 12-applied boundaries."""
        full = authority_runtime_transition_fixture()
        early_applied = {
            item["address"]
            for item in full["resource_changes"]
            if item["change"]["actions"] == ["create"]
            and item["type"]
            in {
                "aws_iam_role",
                "aws_iam_role_policy",
                "aws_cloudwatch_metric_alarm",
                "aws_cloudwatch_log_group",
            }
        }
        # 3 hub functions x {exec role, exec policy, spillover alarm, log group}.
        self.assertEqual(len(early_applied), 12)
        for applied in (set(), {next(iter(early_applied))}, early_applied):
            with self.subTest(applied=len(applied)):
                summary = CHECKER.check_plan(
                    authority_runtime_partial_retry_fixture(applied)
                )
                self.assertEqual(summary["plan_mode"], "authority-runtime-slice")
                self.assertEqual(
                    summary["resource_count"],
                    len(CHECKER.EXPECTED_RESOURCES)
                    + len(CHECKER.AUTHORITY_RUNTIME_RESOURCES),
                )

    def test_authority_runtime_partial_retry_rejects_drifted_applied_resource(
        self,
    ) -> None:
        """A slice resource that already applied but now replans as an in-place
        update (drift), not a no-op, fails closed: a retry may only complete
        still-pending creates and the three opens, never mutate applied state."""
        applied = {
            item["address"]
            for item in authority_runtime_transition_fixture()["resource_changes"]
            if item["change"]["actions"] == ["create"]
            and item["type"] == "aws_iam_role"
        }
        candidate = authority_runtime_partial_retry_fixture(applied)
        drifted = self.change(candidate, next(iter(applied)))
        drifted["actions"] = ["update"]
        self.assert_rejected(candidate)

    def test_authority_runtime_slice_completion_admits_confined_refresh_drift(
        self,
    ) -> None:
        """A partial-apply completion refreshes its already-applied slice
        resources and the endpoints it opens, recording benign provider
        re-projections in resource_drift. Drift whose addresses are CONFINED to
        the slice's own resources + its three opens is admitted alongside the
        runtime-slice transition (the load-bearing fields are still validated on
        the after-state)."""
        full = authority_runtime_transition_fixture()
        roles = sorted(
            item["address"]
            for item in full["resource_changes"]
            if item["type"] == "aws_iam_role"
            and item["change"]["actions"] == ["create"]
        )
        candidate = authority_runtime_partial_retry_fixture(set(roles))
        candidate["resource_drift"] = [
            _slice_refresh_drift(roles[0], "aws_iam_role"),
            _slice_refresh_drift(roles[1], "aws_iam_role"),
            _slice_refresh_drift(
                CHECKER.AUTHORITY_RUNTIME_DYNAMODB_ADDRESS, "aws_vpc_endpoint"
            ),
        ]
        summary = CHECKER.check_plan(candidate)
        self.assertEqual(summary["plan_mode"], "authority-runtime-slice")
        self.assertEqual(summary["normalization_drift_count"], 3)

    def test_authority_runtime_slice_completion_rejects_drift_outside_slice(
        self,
    ) -> None:
        """Refresh drift that reaches ANY address outside the slice ∪ its opens
        is NOT admitted by the slice normalization — it falls through to the exact
        single-drift handling and fails closed (a base resource must never drift
        silently during a slice completion)."""
        role = next(
            item["address"]
            for item in authority_runtime_transition_fixture()["resource_changes"]
            if item["type"] == "aws_iam_role"
            and item["change"]["actions"] == ["create"]
        )
        candidate = authority_runtime_partial_retry_fixture({role})
        candidate["resource_drift"] = [
            _slice_refresh_drift(role, "aws_iam_role"),
            _slice_refresh_drift(
                "module.control.aws_kms_key.authority_data", "aws_kms_key"
            ),
        ]
        self.assert_rejected(candidate)

    def test_authority_runtime_slice_retry_transition_passes(self) -> None:
        """A recovery re-plan after a partial apply left the hub functions Failed
        (Terraform auto-tainted -> replace) and normalized the exec-role trust
        (confused-deputy Condition removed -> in-place update) is admitted as the
        distinct authority-runtime-slice-retry transition (the strict clean
        completion stays creates-only)."""
        summary = CHECKER.check_plan(authority_runtime_retry_fixture())
        self.assertEqual(summary["plan_mode"], "authority-runtime-slice-retry")
        self.assertEqual(
            summary["resource_count"],
            len(CHECKER.EXPECTED_RESOURCES)
            + len(CHECKER.AUTHORITY_RUNTIME_RESOURCES),
        )

    def test_authority_runtime_retry_requires_a_tainted_function(self) -> None:
        """The retry transition is admitted ONLY when >=1 function is actually
        being replaced. Un-tainting the functions (leaving trust updates + creates
        with no replace) is neither the strict completion nor a retry, so it fails
        closed."""
        candidate = authority_runtime_retry_fixture()
        for item in candidate["resource_changes"]:
            if (
                item["type"] == "aws_lambda_function"
                and item["change"]["actions"] == ["delete", "create"]
            ):
                item["change"]["actions"] = ["no-op"]
                item["change"]["after_unknown"] = {}
        self.assert_rejected(candidate)

    def test_authority_runtime_rejects_index_arn_in_ddb_endpoint(self) -> None:
        """Gateway VPC-endpoint policies are table-granular; a /index/* resource
        is InvalidPolicyDocument at apply (the real failure this fix resolves).
        The endpoint policy must carry only base-table ARNs, so an index ARN
        here fails the contract; the finer /index/* grant lives on the exec-role
        identity policies, which are checked separately."""
        candidate = authority_runtime_transition_fixture()
        ddb = self.change(candidate, CHECKER.AUTHORITY_RUNTIME_DYNAMODB_ADDRESS)
        policy = json.loads(ddb["after"]["policy"])
        policy["Statement"][0]["Resource"].append(
            f"{CHECKER.AUTHORITY_RUNTIME_TABLE_ARNS['agent_keys']}/index/*"
        )
        ddb["after"]["policy"] = json.dumps(policy)
        self.assert_rejected(candidate)

    def test_authority_runtime_rejects_broadened_dynamodb_principal(self) -> None:
        candidate = authority_runtime_transition_fixture()
        ddb = self.change(candidate, CHECKER.AUTHORITY_RUNTIME_DYNAMODB_ADDRESS)
        policy = json.loads(ddb["after"]["policy"])
        # Principal "*" is required, so broadening now means dropping the
        # aws:PrincipalArn condition that scopes it to the three exec roles.
        policy["Statement"][0].pop("Condition", None)
        ddb["after"]["policy"] = json.dumps(policy)
        self.assert_rejected(candidate)

    def test_authority_runtime_rejects_extra_dynamodb_resource(self) -> None:
        candidate = authority_runtime_transition_fixture()
        ddb = self.change(candidate, CHECKER.AUTHORITY_RUNTIME_DYNAMODB_ADDRESS)
        policy = json.loads(ddb["after"]["policy"])
        policy["Statement"][0]["Resource"].append(
            f"arn:aws:dynamodb:{CHECKER.AWS_REGION}:{CHECKER.ACCOUNT_ID}:table/"
            f"{CHECKER.CONTROL_PREFIX}-qurl-customers"
        )
        ddb["after"]["policy"] = json.dumps(policy)
        self.assert_rejected(candidate)

    def test_authority_runtime_rejects_kms_non_qat1_key(self) -> None:
        candidate = authority_runtime_transition_fixture()
        kms = self.change(candidate, CHECKER.AUTHORITY_RUNTIME_KMS_ENDPOINT_ADDRESS)
        policy = json.loads(kms["after"]["policy"])
        policy["Statement"][0]["Resource"] = [
            f"arn:aws:kms:{CHECKER.AWS_REGION}:{CHECKER.ACCOUNT_ID}:key/not-a-uuid"
        ]
        kms["after"]["policy"] = json.dumps(policy)
        self.assert_rejected(candidate)

    def test_authority_runtime_rejects_kms_wildcard_action(self) -> None:
        candidate = authority_runtime_transition_fixture()
        kms = self.change(candidate, CHECKER.AUTHORITY_RUNTIME_KMS_ENDPOINT_ADDRESS)
        policy = json.loads(kms["after"]["policy"])
        policy["Statement"][0]["Action"] = ["kms:*"]
        kms["after"]["policy"] = json.dumps(policy)
        self.assert_rejected(candidate)

    def test_authority_runtime_rejects_opening_caller_lambda_endpoint(self) -> None:
        candidate = authority_runtime_transition_fixture()
        lam = self.change(
            candidate, 'module.control.aws_vpc_endpoint.interface["lambda"]'
        )
        lam["actions"] = ["update"]
        lam["after"] = {
            **lam["after"],
            "policy": runtime_scoped_endpoint_policies()[1],
        }
        self.assert_rejected(candidate)

    def test_authority_runtime_rejects_opening_redis_sg(self) -> None:
        candidate = authority_runtime_transition_fixture()
        redis_sg = self.change(candidate, "module.control.aws_security_group.otp_redis")
        redis_sg["actions"] = ["update"]
        redis_sg["after"] = {
            **redis_sg["after"],
            "ingress": [runtime_interface_ingress_rule()],
        }
        self.assert_rejected(candidate)

    def test_authority_runtime_rejects_world_interface_ingress(self) -> None:
        candidate = authority_runtime_transition_fixture()
        sg = self.change(candidate, CHECKER.AUTHORITY_RUNTIME_INTERFACE_SG_ADDRESS)
        sg["after"]["ingress"][0]["cidr_blocks"] = ["0.0.0.0/0"]
        sg["after"]["ingress"][0]["security_groups"] = []
        self.assert_rejected(candidate)

    def test_authority_runtime_rejects_wrong_reserved_concurrency(self) -> None:
        candidate = authority_runtime_transition_fixture()
        fn = self.change(
            candidate,
            'module.control.aws_lambda_function.authority'
            '["layerv-nhp-sandbox-ca-ia"]',
        )
        fn["after"]["reserved_concurrent_executions"] = 1
        self.assert_rejected(candidate)

    def test_authority_runtime_rejects_unpinned_image(self) -> None:
        candidate = authority_runtime_transition_fixture()
        fn = self.change(
            candidate,
            'module.control.aws_lambda_function.authority'
            '["layerv-nhp-sandbox-ca-ra"]',
        )
        fn["after"]["image_uri"] = "public.ecr.aws/rogue/authority:latest"
        self.assert_rejected(candidate)

    def test_authority_runtime_rejects_wildcard_exec_trust(self) -> None:
        candidate = authority_runtime_transition_fixture()
        role = self.change(
            candidate,
            'module.control.aws_iam_role.authority_exec["layerv-nhp-sandbox-ca-ia"]',
        )
        trust = json.loads(role["after"]["assume_role_policy"])
        trust["Statement"][0]["Principal"] = {"AWS": "*"}
        role["after"]["assume_role_policy"] = json.dumps(trust)
        self.assert_rejected(candidate)

    def test_authority_runtime_rejects_confused_deputy_exec_trust(self) -> None:
        # A per-function aws:SourceArn/aws:SourceAccount confused-deputy Condition
        # on the EXECUTION role trust breaks VPC ENI creation
        # (InsufficientRolePermissions on first apply), so it must be rejected;
        # the bare lambda-principal trust is the only one that lets the function
        # initialize.
        candidate = authority_runtime_transition_fixture()
        role = self.change(
            candidate,
            'module.control.aws_iam_role.authority_exec["layerv-nhp-sandbox-ca-ia"]',
        )
        trust = json.loads(role["after"]["assume_role_policy"])
        trust["Statement"][0]["Condition"] = {
            "StringEquals": {"aws:SourceAccount": CHECKER.ACCOUNT_ID}
        }
        role["after"]["assume_role_policy"] = json.dumps(trust)
        self.assert_rejected(candidate)

    def test_authority_runtime_rejects_managed_policy_on_exec_role(self) -> None:
        candidate = authority_runtime_transition_fixture()
        role = self.change(
            candidate,
            'module.control.aws_iam_role.authority_exec["layerv-nhp-sandbox-ca-icr"]',
        )
        role["after"]["managed_policy_arns"] = ["arn:aws:iam::aws:policy/AdministratorAccess"]
        self.assert_rejected(candidate)

    def test_authority_runtime_rejects_ddb_endpoint_missing_describe_table(self) -> None:
        candidate = authority_runtime_transition_fixture()
        ddb = self.change(candidate, CHECKER.AUTHORITY_RUNTIME_DYNAMODB_ADDRESS)
        policy = json.loads(ddb["after"]["policy"])
        policy["Statement"][0]["Action"] = [
            action
            for action in policy["Statement"][0]["Action"]
            if action != "dynamodb:DescribeTable"
        ]
        ddb["after"]["policy"] = json.dumps(policy)
        self.assert_rejected(candidate)

    def test_authority_runtime_rejects_kms_endpoint_verify_action(self) -> None:
        candidate = authority_runtime_transition_fixture()
        kms = self.change(candidate, CHECKER.AUTHORITY_RUNTIME_KMS_ENDPOINT_ADDRESS)
        policy = json.loads(kms["after"]["policy"])
        policy["Statement"][0]["Action"] = [
            "kms:GetPublicKey",
            "kms:Sign",
            "kms:Verify",
        ]
        kms["after"]["policy"] = json.dumps(policy)
        self.assert_rejected(candidate)

    def test_authority_runtime_rejects_broadened_kms_endpoint_principal(self) -> None:
        candidate = authority_runtime_transition_fixture()
        kms = self.change(candidate, CHECKER.AUTHORITY_RUNTIME_KMS_ENDPOINT_ADDRESS)
        policy = json.loads(kms["after"]["policy"])
        # Widening the qat1 endpoint back to all three roles must fail: only the
        # IssueAssignment role builds a KMS client. Scoping now lives in the
        # aws:PrincipalArn condition (Principal is the required "*").
        policy["Statement"][0]["Condition"]["StringEquals"]["aws:PrincipalArn"] = sorted(
            CHECKER.AUTHORITY_RUNTIME_EXEC_ROLE_ARNS
        )
        kms["after"]["policy"] = json.dumps(policy)
        self.assert_rejected(candidate)

    def _exec_policy_change(self, candidate: dict, operation: str) -> dict:
        fn = next(
            name
            for name, op in CHECKER.AUTHORITY_RUNTIME_HUB_FUNCTIONS.items()
            if op == operation
        )
        return self.change(
            candidate, f'module.control.aws_iam_role_policy.authority_exec["{fn}"]'
        )

    def test_authority_runtime_rejects_exec_reads_missing_describe_table(self) -> None:
        candidate = authority_runtime_transition_fixture()
        change = self._exec_policy_change(candidate, "issue_assignment")
        policy = json.loads(change["after"]["policy"])
        reads = next(s for s in policy["Statement"] if s["Sid"] == "AuthorityReads")
        reads["Action"] = [
            action for action in reads["Action"] if action != "dynamodb:DescribeTable"
        ]
        change["after"]["policy"] = json.dumps(policy)
        self.assert_rejected(candidate)

    def test_authority_runtime_rejects_refresh_exec_kms_statement(self) -> None:
        # RefreshAssignment builds no KMS client; a Sign statement must be rejected.
        candidate = authority_runtime_transition_fixture()
        change = self._exec_policy_change(candidate, "refresh_assignment")
        policy = json.loads(change["after"]["policy"])
        policy["Statement"].append(
            {
                "Sid": "Qat1Sign",
                "Effect": "Allow",
                "Action": ["kms:GetPublicKey", "kms:Sign"],
                "Resource": [RUNTIME_QAT1_KEY_ARN],
            }
        )
        change["after"]["policy"] = json.dumps(policy)
        self.assert_rejected(candidate)

    def test_authority_runtime_rejects_recovery_exec_writes_api_keys(self) -> None:
        # IssueCredentialRecovery writes connector_authority ONLY; api_keys is a
        # ConditionCheck-only (read-set) table.
        candidate = authority_runtime_transition_fixture()
        change = self._exec_policy_change(candidate, "issue_credential_recovery")
        policy = json.loads(change["after"]["policy"])
        write = next(
            s for s in policy["Statement"] if s["Sid"] == "AuthorityRecoveryWrite"
        )
        write["Resource"] = sorted(
            set(write["Resource"])
            | CHECKER.AUTHORITY_RUNTIME_TABLE_RESOURCES["api_keys"]
        )
        change["after"]["policy"] = json.dumps(policy)
        self.assert_rejected(candidate)

    def test_authority_runtime_rejects_exec_non_eni_wildcard_resource(self) -> None:
        candidate = authority_runtime_transition_fixture()
        change = self._exec_policy_change(candidate, "issue_assignment")
        policy = json.loads(change["after"]["policy"])
        write = next(
            s for s in policy["Statement"] if s["Sid"] == "AuthorityReplayWrite"
        )
        write["Resource"] = ["*"]
        change["after"]["policy"] = json.dumps(policy)
        self.assert_rejected(candidate)

    def test_authority_runtime_rejects_replay_write_update_over_grant(self) -> None:
        # IssueAssignment/RefreshAssignment write only the replay Put; adding
        # UpdateItem is an over-grant and must be rejected.
        candidate = authority_runtime_transition_fixture()
        change = self._exec_policy_change(candidate, "refresh_assignment")
        policy = json.loads(change["after"]["policy"])
        write = next(
            s for s in policy["Statement"] if s["Sid"] == "AuthorityReplayWrite"
        )
        write["Action"] = ["dynamodb:PutItem", "dynamodb:UpdateItem"]
        change["after"]["policy"] = json.dumps(policy)
        self.assert_rejected(candidate)

    def test_authority_runtime_rejects_partial_inventory(self) -> None:
        candidate = authority_runtime_transition_fixture()
        candidate["resource_changes"] = [
            item
            for item in candidate["resource_changes"]
            if item["address"] != CHECKER.AUTHORITY_RUNTIME_LAMBDA_SG_ADDRESS
        ]
        self.assert_rejected(candidate)

    def test_authority_runtime_rejects_stray_extra_resource(self) -> None:
        candidate = authority_runtime_transition_fixture()
        candidate["resource_changes"].append(
            {
                "address": 'module.control.aws_lambda_function.rogue',
                "mode": "managed",
                "type": "aws_lambda_function",
                "change": {
                    "actions": ["create"],
                    "before": None,
                    "after": {"function_name": "rogue"},
                    "after_unknown": {},
                },
            }
        )
        self.assert_rejected(candidate)

    def test_base_plan_rejects_stray_runtime_resource(self) -> None:
        candidate = plan_fixture()
        candidate["resource_changes"].append(
            {
                "address": CHECKER.AUTHORITY_RUNTIME_LAMBDA_SG_ADDRESS,
                "mode": "managed",
                "type": "aws_security_group",
                "change": {
                    "actions": ["create"],
                    "before": None,
                    "after": {"ingress": [], "egress": []},
                    "after_unknown": {},
                },
            }
        )
        self.assert_rejected(candidate)

    def test_authority_runtime_rejects_create_without_endpoint_open(self) -> None:
        # Creating the functions while leaving the dependency endpoints deny-all
        # is not the admitted transition (they must open in lockstep).
        candidate = authority_runtime_transition_fixture()
        ddb = self.change(candidate, CHECKER.AUTHORITY_RUNTIME_DYNAMODB_ADDRESS)
        ddb["actions"] = ["no-op"]
        ddb["after"] = {**ddb["after"], "policy": json.dumps(CHECKER.DENY_ENDPOINT_POLICY)}
        ddb["before"] = ddb["after"]
        self.assert_rejected(candidate)

    def assert_rejected(self, plan: dict, prior_state: object = None) -> None:
        with self.assertRaises(CHECKER.ContractError):
            CHECKER.check_plan(plan, prior_state)

    def change(self, plan: dict, address: str) -> dict:
        return next(
            item["change"]
            for item in plan["resource_changes"]
            if item["address"] == address
        )

    def drift(self, plan: dict, address: str) -> dict:
        return next(
            item
            for item in plan["resource_drift"]
            if item["address"] == address
        )

    def configuration_resource(self, plan: dict, address: str) -> dict:
        prefix = "module.control."
        self.assertTrue(address.startswith(prefix))
        resources = plan["configuration"]["root_module"]["module_calls"]["control"][
            "module"
        ]["resources"]
        return next(
            item
            for item in resources
            if item["address"] == address.removeprefix(prefix)
        )

    def test_inventory_and_destructive_changes_fail(self) -> None:
        missing = plan_fixture()
        missing["resource_changes"].pop()
        self.assert_rejected(missing)

        extra = plan_fixture()
        extra["resource_changes"].append(
            {
                "address": "aws_lambda_function.forbidden",
                "mode": "managed",
                "type": "aws_lambda_function",
                "change": {"actions": ["no-op"], "before": {}, "after": {}},
            }
        )
        self.assert_rejected(extra)

        for actions in (["delete"], ["delete", "create"], ["create", "delete"]):
            destructive = plan_fixture()
            destructive["resource_changes"][0]["change"]["actions"] = actions
            self.assert_rejected(destructive)

    def test_version_drift_and_applyability_fail(self) -> None:
        for field, value in (
            ("terraform_version", "1.15.0"),
            ("format_version", "1.3"),
            ("complete", False),
            ("errored", True),
            ("applyable", True),
        ):
            candidate = plan_fixture()
            candidate[field] = value
            self.assert_rejected(candidate)

        drift = plan_fixture()
        drift["resource_drift"] = [
            {"change": {"actions": ["update"]}, "address": "forbidden"}
        ]
        self.assert_rejected(drift)

        unequal_noop = plan_fixture()
        unequal_noop["resource_changes"][0]["change"]["after"] = {"id": "changed"}
        self.assert_rejected(unequal_noop)

    def test_configuration_actions_and_provisioners_fail(self) -> None:
        action = plan_fixture()
        action["action_invocations"] = [{"action": "aws_lambda_invoke.forbidden"}]
        self.assert_rejected(action)

        local_exec = plan_fixture()
        self.configuration_resource(
            local_exec, "module.control.terraform_data.foundation_contract"
        )["provisioners"] = [
            {
                "type": "local-exec",
                "expressions": {
                    "command": {"constant_value": "curl https://example.invalid"}
                },
            }
        ]
        self.assert_rejected(local_exec)

    def test_external_topology_and_key_reference_substitutions_fail(self) -> None:
        mutations = (
            (
                "external-subnets",
                "module.control.aws_elasticache_serverless_cache.otp",
                ("subnet_ids",),
                ["data.aws_subnets.external.ids", "data.aws_subnets.external"],
            ),
            (
                "external-security-group",
                "module.control.aws_vpc_endpoint.interface",
                ("security_group_ids",),
                [
                    "data.aws_security_group.external.id",
                    "data.aws_security_group.external",
                ],
            ),
            (
                "external-kms-key",
                "module.control.aws_dynamodb_table.connector_authority",
                ("server_side_encryption", 0, "kms_key_arn"),
                ["data.aws_kms_key.external.arn", "data.aws_kms_key.external"],
            ),
            (
                "external-vpc",
                "module.control.aws_subnet.isolated",
                ("vpc_id",),
                ["data.aws_vpc.external.id", "data.aws_vpc.external"],
            ),
            (
                "flow-log-destination-substitution",
                "module.control.aws_flow_log.control",
                ("log_destination",),
                [
                    "aws_cloudwatch_log_group.external.arn",
                    "aws_cloudwatch_log_group.external",
                ],
            ),
            (
                "route-table-association-substitution",
                "module.control.aws_route_table_association.isolated",
                ("route_table_id",),
                ["data.aws_route_table.external.id", "count.index"],
            ),
            (
                "kms-alias-target-substitution",
                "module.control.aws_kms_alias.qat1_signing",
                ("target_key_id",),
                ["data.aws_kms_key.external.key_id", "data.aws_kms_key.external"],
            ),
        )
        for label, address, path, references in mutations:
            with self.subTest(label=label):
                candidate = plan_fixture()
                resource = self.configuration_resource(candidate, address)
                set_expression_path(
                    resource["expressions"], path, {"references": references}
                )
                self.assert_rejected(candidate)

    def test_external_provider_substitution_fails(self) -> None:
        alias = plan_fixture()
        self.configuration_resource(alias, "module.control.aws_subnet.isolated")[
            "provider_config_key"
        ] = "aws.external"
        self.assert_rejected(alias)

        assume_role = plan_fixture()
        assume_role["configuration"]["provider_config"]["aws"]["expressions"][
            "assume_role"
        ] = [{"role_arn": {"constant_value": "arn:aws:iam::111122223333:role/other"}}]
        self.assert_rejected(assume_role)

    def test_forbidden_ipv6_snapshot_and_password_inputs_fail(self) -> None:
        mutations = (
            (
                "vpc-ipv6",
                "module.control.aws_vpc.control",
                ("assign_generated_ipv6_cidr_block",),
                {"constant_value": True},
            ),
            (
                "subnet-ipv6",
                "module.control.aws_subnet.isolated",
                ("ipv6_cidr_block",),
                {"constant_value": "2600:1f00::/64"},
            ),
            (
                "snapshot-restore",
                "module.control.aws_elasticache_serverless_cache.otp",
                ("snapshot_arns_to_restore",),
                {"constant_value": ["arn:aws:s3:::external/snapshot.rdb"]},
            ),
            (
                "hub-digest-provider-default",
                "module.control.aws_ssm_parameter.hub_image_digest",
                ("tier",),
                {"references": ["var.untrusted_tier"]},
            ),
            (
                "hub-digest-write-only-value",
                "module.control.aws_ssm_parameter.hub_image_digest",
                ("value_wo",),
                {"references": ["var.untrusted_digest"]},
            ),
            (
                "authority-password",
                "module.control.aws_elasticache_user.otp_authority",
                ("authentication_mode", 0, "passwords"),
                {"constant_value": ["forbidden-password"]},
            ),
            (
                "issuer-password",
                "module.control.aws_elasticache_user.otp_issuer",
                ("authentication_mode", 0, "passwords"),
                {"constant_value": ["forbidden-password"]},
            ),
            (
                "activator-password",
                "module.control.aws_elasticache_user.otp_activator",
                ("authentication_mode", 0, "passwords"),
                {"constant_value": ["forbidden-password"]},
            ),
            (
                "default-password",
                "module.control.aws_elasticache_user.otp_disabled_default",
                ("passwords",),
                {"constant_value": ["forbidden-password"]},
            ),
        )
        for label, address, path, expression in mutations:
            with self.subTest(label=label):
                candidate = plan_fixture()
                resource = self.configuration_resource(candidate, address)
                set_expression_path(resource["expressions"], path, expression)
                self.assert_rejected(candidate)

    def test_missing_encryption_references_fail(self) -> None:
        targets = [
            (
                "module.control.aws_cloudwatch_log_group.flow_logs",
                ("kms_key_id",),
            ),
            (
                "module.control.aws_secretsmanager_secret.otp_pepper",
                ("kms_key_id",),
            ),
            (
                "module.control.aws_ecr_repository.authority",
                ("encryption_configuration", 0, "kms_key"),
            ),
            (
                "module.control.aws_ecr_repository.hub",
                ("encryption_configuration", 0, "kms_key"),
            ),
            *(
                (
                    f"module.control.aws_dynamodb_table.{table}",
                    ("server_side_encryption", 0, "kms_key_arn"),
                )
                for table in (
                    "agent_keys",
                    "api_key_idempotency",
                    "api_keys",
                    "connector_authority",
                    "customers",
                )
            ),
        ]
        for address, path in targets:
            with self.subTest(address=address):
                candidate = plan_fixture()
                resource = self.configuration_resource(candidate, address)
                delete_expression_path(resource["expressions"], path)
                self.assert_rejected(candidate)

    def test_ecr_scanning_and_immutability_drift_fail(self) -> None:
        mutations = (
            (("image_scanning_configuration", 0, "scan_on_push"), False),
            (("image_tag_mutability",), "MUTABLE"),
        )
        for address in (
            "module.control.aws_ecr_repository.authority",
            "module.control.aws_ecr_repository.hub",
        ):
            for path, value in mutations:
                with self.subTest(address=address, path=path):
                    candidate = plan_fixture()
                    resource = self.configuration_resource(candidate, address)
                    set_expression_path(
                        resource["expressions"], path, {"constant_value": value}
                    )
                    self.assert_rejected(candidate)

    def test_dark_network_bypass_fields_fail(self) -> None:
        public_ingress = plan_fixture()
        self.change(
            public_ingress, "module.control.aws_security_group.interface_endpoints"
        )["after"]["ingress"] = [
            {
                "cidr_blocks": ["0.0.0.0/0"],
                "from_port": 443,
                "protocol": "tcp",
                "to_port": 443,
            }
        ]
        self.assert_rejected(public_ingress)

        unknown_ingress = plan_fixture()
        self.change(unknown_ingress, "module.control.aws_security_group.otp_redis")[
            "after_unknown"
        ]["ingress"] = True
        self.assert_rejected(unknown_ingress)

        public_subnet = plan_fixture()
        self.change(public_subnet, "module.control.aws_subnet.isolated[0]")["after"][
            "map_public_ip_on_launch"
        ] = True
        self.assert_rejected(public_subnet)

    def test_kms_endpoint_and_redis_policy_drift_fail(self) -> None:
        mutations = (
            ("module.control.aws_vpc.control", "enable_dns_support", False),
            (
                "module.control.aws_kms_key.authority_data",
                "policy",
                json.dumps({"Statement": [], "Version": "2012-10-17"}),
            ),
            (
                'module.control.aws_vpc_endpoint.interface["kms"]',
                "private_dns_enabled",
                False,
            ),
            (
                "module.control.aws_elasticache_user.otp_issuer",
                "access_string",
                "on ~* +@all",
            ),
            (
                "module.control.aws_elasticache_user.otp_activator",
                "access_string",
                "on ~* +@all",
            ),
            (
                "module.control.aws_elasticache_user.otp_activator",
                "access_string",
                CHECKER.OTP_REDIS_ACTIVATOR_ACCESS.replace(
                    "+hello +auth +ping +command", "+@connection"
                ),
            ),
            (
                "module.control.aws_elasticache_serverless_cache.otp",
                "snapshot_retention_limit",
                7,
            ),
        )
        for address, field, value in mutations:
            with self.subTest(address=address, field=field):
                candidate = plan_fixture()
                self.change(candidate, address)["after"][field] = value
                self.assert_rejected(candidate)


class StateListTests(unittest.TestCase):
    def check(self, addresses: list[str]) -> dict[str, int]:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state-list.txt"
            path.write_text("\n".join(addresses) + "\n", encoding="utf-8")
            return CHECKER.check_state_list(path)

    def expected_addresses(self) -> list[str]:
        return [
            *CHECKER.EXPECTED_RESOURCES,
            *CHECKER.EXPECTED_DATA_RESOURCES,
        ]

    def test_exact_managed_and_data_inventory_passes(self) -> None:
        self.assertEqual(
            self.check(self.expected_addresses()),
            {"data_resource_count": 6, "managed_resource_count": 50},
        )

    def test_missing_managed_or_data_address_fails(self) -> None:
        for address in (
            "module.control.aws_vpc.control",
            "module.control.data.aws_region.current",
        ):
            with self.subTest(address=address):
                addresses = self.expected_addresses()
                addresses.remove(address)
                with self.assertRaisesRegex(CHECKER.ContractError, re.escape(address)):
                    self.check(addresses)

    def test_extra_managed_or_data_address_fails(self) -> None:
        for address in (
            "module.control.aws_s3_bucket.forbidden",
            "module.control.data.aws_vpc.forbidden",
        ):
            with self.subTest(address=address):
                with self.assertRaisesRegex(CHECKER.ContractError, re.escape(address)):
                    self.check([*self.expected_addresses(), address])

    def test_runtime_inventory_passes_and_partial_fails(self) -> None:
        runtime = [*self.expected_addresses(), *CHECKER.AUTHORITY_RUNTIME_RESOURCES]
        self.assertEqual(
            self.check(runtime),
            {"data_resource_count": 6, "managed_resource_count": 75},
        )
        # A partial runtime inventory (missing one runtime resource) fails closed.
        partial = [
            address
            for address in runtime
            if address != CHECKER.AUTHORITY_RUNTIME_LAMBDA_SG_ADDRESS
        ]
        with self.assertRaises(CHECKER.ContractError):
            self.check(partial)

    def test_hub_worker_inventory_requires_edge_and_runtime(self) -> None:
        worker_managed = list(CHECKER.HUB_WORKER_RESOURCES)
        worker_data = list(CHECKER.HUB_WORKER_DATA_RESOURCES)
        full = [
            *self.expected_addresses(),
            *CHECKER.AUTHORITY_RUNTIME_RESOURCES,
            *CHECKER.HUB_EDGE_RESOURCES,
            *worker_managed,
            *worker_data,
        ]
        self.assertEqual(
            self.check(full),
            {
                "data_resource_count": 6 + len(worker_data),
                "managed_resource_count": (
                    50
                    + len(CHECKER.AUTHORITY_RUNTIME_RESOURCES)
                    + len(CHECKER.HUB_EDGE_RESOURCES)
                    + len(worker_managed)
                ),
            },
        )
        # The worker without the edge slice fails closed (dependency).
        without_edge = [
            address
            for address in full
            if address not in set(CHECKER.HUB_EDGE_RESOURCES)
        ]
        with self.assertRaisesRegex(
            CHECKER.ContractError, "requires both the Hub edge"
        ):
            self.check(without_edge)
        # A partial worker inventory (missing one managed resource) fails closed.
        partial = [address for address in full if address != worker_managed[0]]
        with self.assertRaises(CHECKER.ContractError):
            self.check(partial)


def state_fixture() -> dict:
    resources = [
        {
            "address": address,
            "mode": "managed",
            "type": resource_type,
            "values": {"id": "placeholder"},
        }
        for address, resource_type in CHECKER.EXPECTED_RESOURCES.items()
    ]
    by_address = {item["address"]: item["values"] for item in resources}
    runtime_input = authority_runtime_input_fixture()
    by_address["module.control.terraform_data.foundation_contract"].clear()
    by_address["module.control.terraform_data.foundation_contract"].update(
        {
            "input": copy.deepcopy(runtime_input),
            "output": copy.deepcopy(runtime_input),
        }
    )
    by_address["module.control.aws_vpc.control"].update(
        {"id": "vpc-abc123", "cidr_block": "10.102.0.0/16"}
    )
    for address in (
        "module.control.aws_default_security_group.control",
        "module.control.aws_security_group.interface_endpoints",
        "module.control.aws_security_group.otp_redis",
    ):
        by_address[address].update({"ingress": [], "egress": []})
    by_address["module.control.aws_security_group.interface_endpoints"]["id"] = "sg-111"
    by_address["module.control.aws_security_group.otp_redis"]["id"] = "sg-222"
    data_key_arn = f"arn:aws:kms:{CHECKER.AWS_REGION}:{CHECKER.ACCOUNT_ID}:key/data123"
    by_address["module.control.aws_kms_key.authority_data"].update(
        {
            "arn": data_key_arn,
            "key_usage": "ENCRYPT_DECRYPT",
            "is_enabled": True,
        }
    )
    by_address["module.control.aws_kms_key.qat1_signing"].update(
        {
            "key_usage": "SIGN_VERIFY",
            "customer_master_key_spec": "ECC_NIST_P256",
            "is_enabled": True,
        }
    )
    by_address["module.control.aws_cloudwatch_log_group.flow_logs"].update(
        {"arn": "arn:aws:logs:flow-group", "kms_key_id": data_key_arn}
    )
    by_address["module.control.aws_iam_role.flow_logs"]["arn"] = (
        "arn:aws:iam::role/flow"
    )
    by_address["module.control.aws_flow_log.control"].update(
        {
            "traffic_type": "ALL",
            "max_aggregation_interval": 60,
            "log_destination_type": "cloud-watch-logs",
            "log_destination": "arn:aws:logs:flow-group",
            "iam_role_arn": "arn:aws:iam::role/flow",
        }
    )
    by_address["module.control.aws_iam_role.authority_publisher"].update(
        {
            "assume_role_policy": json.dumps(
                CHECKER.AUTHORITY_PUBLISHER_TRUST_POLICY
            ),
            "inline_policy": [
                {
                    "name": "publish-connector-authority",
                    "policy": json.dumps(CHECKER.AUTHORITY_PUBLISHER_POLICY),
                }
            ],
            "managed_policy_arns": [],
            "max_session_duration": 3600,
            "name": CHECKER.AUTHORITY_PUBLISHER_ROLE_NAME,
            "path": "/",
            "permissions_boundary": "",
        }
    )
    by_address["module.control.aws_iam_role_policy.authority_publisher"].update(
        {
            "name": "publish-connector-authority",
            "policy": json.dumps(CHECKER.AUTHORITY_PUBLISHER_POLICY),
            "role": CHECKER.AUTHORITY_PUBLISHER_ROLE_NAME,
        }
    )
    by_address["module.control.aws_ecr_repository.hub"].update(
        {
            "arn": CHECKER.HUB_ECR_REPOSITORY_ARN,
            "encryption_configuration": [
                {"encryption_type": "KMS", "kms_key": data_key_arn}
            ],
            "force_delete": False,
            "image_scanning_configuration": [{"scan_on_push": True}],
            "image_tag_mutability": "IMMUTABLE",
            "name": CHECKER.HUB_ECR_REPOSITORY_NAME,
        }
    )
    by_address["module.control.aws_ecr_lifecycle_policy.hub"].update(
        {
            "policy": json.dumps(CHECKER.HUB_ECR_LIFECYCLE_POLICY),
            "repository": CHECKER.HUB_ECR_REPOSITORY_NAME,
        }
    )
    by_address["module.control.aws_ssm_parameter.hub_image_digest"].update(
        {
            "arn": CHECKER.HUB_IMAGE_DIGEST_PARAMETER_ARN,
            "data_type": "text",
            "description": (
                "Immutable sha256 digest for the separately published "
                "Connector Hub image"
            ),
            "name": CHECKER.HUB_IMAGE_DIGEST_PARAMETER_NAME,
            "tier": "Standard",
            "type": "String",
            "value": "UNPUBLISHED",
        }
    )
    by_address["module.control.aws_iam_role.hub_publisher"].update(
        {
            "assume_role_policy": json.dumps(CHECKER.HUB_PUBLISHER_TRUST_POLICY),
            "inline_policy": [
                {
                    "name": "publish-connector-hub",
                    "policy": json.dumps(CHECKER.HUB_PUBLISHER_POLICY),
                }
            ],
            "managed_policy_arns": [],
            "max_session_duration": 3600,
            "name": CHECKER.HUB_PUBLISHER_ROLE_NAME,
            "path": "/",
            "permissions_boundary": "",
        }
    )
    by_address["module.control.aws_iam_role_policy.hub_publisher"].update(
        {
            "name": "publish-connector-hub",
            "policy": json.dumps(CHECKER.HUB_PUBLISHER_POLICY),
            "role": CHECKER.HUB_PUBLISHER_ROLE_NAME,
        }
    )
    subnet_ids = []
    route_table_ids = []
    for index in range(3):
        subnet_id = f"subnet-{index}abc"
        route_table_id = f"rtb-{index}abc"
        subnet_ids.append(subnet_id)
        route_table_ids.append(route_table_id)
        by_address[f"module.control.aws_subnet.isolated[{index}]"]["id"] = subnet_id
        by_address[f"module.control.aws_route_table.isolated[{index}]"]["id"] = (
            route_table_id
        )
    deny_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "DenyUntilAuthorityRuntimeExists",
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": "*",
                    "Resource": "*",
                }
            ],
        }
    )
    for service in ("email", "kms", "lambda", "logs", "monitoring", "secretsmanager"):
        by_address[f'module.control.aws_vpc_endpoint.interface["{service}"]'].update(
            {
                "state": "available",
                "vpc_endpoint_type": "Interface",
                "service_name": f"com.amazonaws.{CHECKER.AWS_REGION}.{service}",
                "private_dns_enabled": True,
                "vpc_id": "vpc-abc123",
                "subnet_ids": subnet_ids,
                "security_group_ids": ["sg-111"],
                "policy": deny_policy,
            }
        )
    by_address["module.control.aws_vpc_endpoint.dynamodb"].update(
        {
            "state": "available",
            "vpc_endpoint_type": "Gateway",
            "service_name": f"com.amazonaws.{CHECKER.AWS_REGION}.dynamodb",
            "vpc_id": "vpc-abc123",
            "route_table_ids": route_table_ids,
            "policy": deny_policy,
        }
    )
    by_address["module.control.aws_elasticache_serverless_cache.otp"].update(
        {
            "status": "available",
            "engine": "redis",
            "major_engine_version": "7",
            "user_group_id": f"{CHECKER.CONTROL_PREFIX}-otp-users",
            "kms_key_id": data_key_arn,
            "snapshot_retention_limit": 0,
            "security_group_ids": ["sg-222"],
            "subnet_ids": subnet_ids,
        }
    )
    default_id = f"{CHECKER.CONTROL_PREFIX}-otp-default"
    legacy_id = f"{CHECKER.CONTROL_PREFIX}-otp-auth"
    issuer_id = f"{CHECKER.CONTROL_PREFIX}-otp-issuer"
    activator_id = f"{CHECKER.CONTROL_PREFIX}-otp-activator"
    by_address["module.control.aws_elasticache_user.otp_disabled_default"].update(
        {
            "user_id": default_id,
            "user_name": "default",
            "access_string": "off ~* -@all",
            "authentication_mode": [
                {"password_count": 0, "type": "no-password"}
            ],
        }
    )
    by_address["module.control.aws_elasticache_user.otp_authority"].update(
        {
            "user_id": legacy_id,
            "user_name": legacy_id,
            "access_string": CHECKER.OTP_REDIS_LEGACY_ACCESS,
            "authentication_mode": [{"password_count": 0, "type": "iam"}],
        }
    )
    by_address["module.control.aws_elasticache_user.otp_issuer"].update(
        {
            "user_id": issuer_id,
            "user_name": issuer_id,
            "access_string": CHECKER.OTP_REDIS_ISSUER_ACCESS,
            "authentication_mode": [{"password_count": 0, "type": "iam"}],
        }
    )
    by_address["module.control.aws_elasticache_user.otp_activator"].update(
        {
            "user_id": activator_id,
            "user_name": activator_id,
            "access_string": CHECKER.OTP_REDIS_ACTIVATOR_ACCESS,
            "authentication_mode": [{"password_count": 0, "type": "iam"}],
        }
    )
    by_address["module.control.aws_elasticache_user_group.otp"].update(
        {
            "user_group_id": f"{CHECKER.CONTROL_PREFIX}-otp-users",
            "user_ids": [default_id, issuer_id, activator_id],
        }
    )
    return {
        "values": {
            "outputs": {
                "authority_image_uri": {
                    "sensitive": False,
                    "type": "string",
                    "value": runtime_input["authority_image_uri"],
                }
            },
            "root_module": {"resources": resources},
        }
    }


def state_fixture_runtime() -> dict:
    """The dark state plus the applied runtime slice (scoped endpoints, function SG
    ingress, and the 25 runtime resources)."""
    state = state_fixture()
    resources = state["values"]["root_module"]["resources"]
    by_address = {item["address"]: item["values"] for item in resources}
    dynamodb_policy, kms_policy = runtime_scoped_endpoint_policies()
    by_address["module.control.aws_vpc_endpoint.dynamodb"]["policy"] = dynamodb_policy
    by_address['module.control.aws_vpc_endpoint.interface["kms"]']["policy"] = kms_policy
    interface_sg = by_address["module.control.aws_security_group.interface_endpoints"]
    interface_sg["ingress"] = [runtime_interface_ingress_rule()]
    interface_sg["egress"] = []
    for address, resource_type in CHECKER.AUTHORITY_RUNTIME_RESOURCES.items():
        resources.append(
            {
                "address": address,
                "mode": "managed",
                "type": resource_type,
                "values": {"id": "runtime-placeholder"},
            }
        )
    return state


class StateContractTests(unittest.TestCase):
    def test_resource_inventory_contract_hash_is_reviewed(self) -> None:
        # Update only with an intentional, reviewed address/type inventory change.
        self.assertEqual(
            CHECKER.contract_sha256(),
            "193c698ff4ff5a1c8192c87581493021b015e1d84630d0b7af0defec261507ac",
        )

    def test_exact_state_passes(self) -> None:
        self.assertEqual(CHECKER.check_state(state_fixture())["resource_count"], 50)

    def test_exact_runtime_state_passes(self) -> None:
        self.assertEqual(
            CHECKER.check_state(state_fixture_runtime())["resource_count"], 75
        )

    def test_runtime_state_rejects_still_dark_dependency_endpoint(self) -> None:
        state = state_fixture_runtime()
        resources = state["values"]["root_module"]["resources"]
        by_address = {item["address"]: item["values"] for item in resources}
        by_address["module.control.aws_vpc_endpoint.dynamodb"]["policy"] = json.dumps(
            CHECKER.DENY_ENDPOINT_POLICY
        )
        with self.assertRaises(CHECKER.ContractError):
            CHECKER.check_state(state)

    def test_runtime_state_rejects_open_caller_lambda_endpoint(self) -> None:
        state = state_fixture_runtime()
        resources = state["values"]["root_module"]["resources"]
        by_address = {item["address"]: item["values"] for item in resources}
        by_address['module.control.aws_vpc_endpoint.interface["lambda"]']["policy"] = (
            runtime_scoped_endpoint_policies()[1]
        )
        with self.assertRaises(CHECKER.ContractError):
            CHECKER.check_state(state)

    def test_publisher_trust_and_permissions_drift_fail(self) -> None:
        mutations = (
            (
                "module.control.aws_iam_role.authority_publisher",
                "assume_role_policy",
                json.dumps(
                    {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": "sts:AssumeRoleWithWebIdentity",
                                "Principal": {"Federated": "*"},
                            }
                        ],
                    }
                ),
            ),
            (
                "module.control.aws_iam_role.authority_publisher",
                "permissions_boundary",
                "arn:aws:iam::123456789012:policy/broad",
            ),
            (
                "module.control.aws_iam_role_policy.authority_publisher",
                "policy",
                json.dumps(
                    {
                        "Version": "2012-10-17",
                        "Statement": [
                            {"Effect": "Allow", "Action": "ssm:*", "Resource": "*"}
                        ],
                    }
                ),
            ),
            (
                "module.control.aws_iam_role.hub_publisher",
                "assume_role_policy",
                json.dumps(
                    {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": "sts:AssumeRoleWithWebIdentity",
                                "Principal": {"Federated": "*"},
                            }
                        ],
                    }
                ),
            ),
            (
                "module.control.aws_iam_role_policy.hub_publisher",
                "policy",
                json.dumps(
                    {
                        "Version": "2012-10-17",
                        "Statement": [
                            {"Effect": "Allow", "Action": "ecr:*", "Resource": "*"}
                        ],
                    }
                ),
            ),
            (
                "module.control.aws_ecr_repository.hub",
                "image_tag_mutability",
                "MUTABLE",
            ),
            (
                "module.control.aws_ecr_lifecycle_policy.hub",
                "policy",
                json.dumps(
                    {
                        "rules": [
                            {
                                "rulePriority": 1,
                                "selection": {
                                    "tagStatus": "any",
                                    "countType": "imageCountMoreThan",
                                    "countNumber": 1,
                                },
                                "action": {"type": "expire"},
                            }
                        ]
                    }
                ),
            ),
            (
                "module.control.aws_ssm_parameter.hub_image_digest",
                "value",
                "latest",
            ),
        )
        for address, field, value in mutations:
            with self.subTest(address=address):
                state = state_fixture()
                resource = next(
                    item
                    for item in state["values"]["root_module"]["resources"]
                    if item["address"] == address
                )
                resource["values"][field] = value
                with self.assertRaises(CHECKER.ContractError):
                    CHECKER.check_state(state)

    def test_malformed_prior_state_shapes_fail_with_contract_error(self) -> None:
        for malformed_prior_state in (None, [], "invalid"):
            with self.subTest(prior_state=malformed_prior_state):
                with self.assertRaises(CHECKER.ContractError):
                    CHECKER.check_state(
                        {"values": None, "prior_state": malformed_prior_state}
                    )

    def test_security_endpoint_kms_and_redis_drift_fail(self) -> None:
        mutations = (
            (
                "module.control.aws_security_group.interface_endpoints",
                "ingress",
                [{"from_port": 443}],
            ),
            (
                'module.control.aws_vpc_endpoint.interface["lambda"]',
                "policy",
                "{}",
            ),
            ("module.control.aws_kms_key.qat1_signing", "key_usage", "ENCRYPT_DECRYPT"),
            (
                "module.control.aws_elasticache_user.otp_issuer",
                "access_string",
                "on ~* +@all",
            ),
            (
                "module.control.aws_elasticache_user.otp_activator",
                "access_string",
                "on ~* +@all",
            ),
            (
                "module.control.aws_elasticache_user.otp_issuer",
                "access_string",
                CHECKER.OTP_REDIS_ISSUER_ACCESS.replace(
                    "+hello +auth +ping +command", "+@connection"
                ),
            ),
        )
        for address, field, value in mutations:
            with self.subTest(address=address, field=field):
                state = state_fixture()
                resource = next(
                    item
                    for item in state["values"]["root_module"]["resources"]
                    if item["address"] == address
                )
                resource["values"][field] = value
                with self.assertRaises(CHECKER.ContractError):
                    CHECKER.check_state(state)

    def test_state_redis_major_engine_version_is_exact(self) -> None:
        for version in ("70", "7x"):
            with self.subTest(version=version):
                state = state_fixture()
                resource = next(
                    item
                    for item in state["values"]["root_module"]["resources"]
                    if item["address"]
                    == "module.control.aws_elasticache_serverless_cache.otp"
                )
                resource["values"]["major_engine_version"] = version
                with self.assertRaises(CHECKER.ContractError):
                    CHECKER.check_state(state)

    def test_state_redis_users_must_have_zero_passwords(self) -> None:
        for address in (
            "module.control.aws_elasticache_user.otp_activator",
            "module.control.aws_elasticache_user.otp_authority",
            "module.control.aws_elasticache_user.otp_disabled_default",
            "module.control.aws_elasticache_user.otp_issuer",
        ):
            with self.subTest(address=address):
                state = state_fixture()
                resource = next(
                    item
                    for item in state["values"]["root_module"]["resources"]
                    if item["address"] == address
                )
                resource["values"]["authentication_mode"][0]["password_count"] = 1
                with self.assertRaises(CHECKER.ContractError):
                    CHECKER.check_state(state)

    def test_state_redis_group_rejects_duplicate_membership(self) -> None:
        state = state_fixture()
        group = next(
            item
            for item in state["values"]["root_module"]["resources"]
            if item["address"]
            == "module.control.aws_elasticache_user_group.otp"
        )
        group["values"]["user_ids"].append(group["values"]["user_ids"][0])
        with self.assertRaises(CHECKER.ContractError):
            CHECKER.check_state(state)

    def test_disabled_user_lifecycle_ignore_is_narrow_and_fail_closed(self) -> None:
        redis = REDIS_TF_PATH.read_text(encoding="utf-8")
        self.assertEqual(
            redis.count("ignore_changes = [authentication_mode[0].type]"), 1
        )
        self.assertNotIn("ignore_changes = [authentication_mode]", redis)
        self.assertIn('["no-password-required", "no-password"]', redis)
        self.assertIn("self.authentication_mode[0].password_count == 0", redis)
        self.assertIn("%W~connector:registration-otp:v2:{*}:challenge", redis)
        self.assertIn("%R~connector:registration-otp:v2:{*}:challenge", redis)
        self.assertEqual(redis.count('"resetchannels"'), 2)
        self.assertNotIn('"allchannels"', redis)
        self.assertNotIn('"&*"', redis)
        self.assertEqual(redis.count('"+cluster|slots"'), 2)
        for command in ("hello", "auth", "ping", "command"):
            self.assertEqual(redis.count(f'"+{command}"'), 2)
        self.assertNotIn('"+asking"', redis)
        # The one remaining broad connection category belongs only to the
        # detached legacy user retained for non-destructive state rollout.
        self.assertEqual(redis.count("+@connection"), 1)
        self.assertNotIn('"+client"', redis)
        self.assertNotIn("+hincrby", redis)
        self.assertNotIn('"+hget"', redis)
        self.assertIn("major_engine_version     = \"7\"", redis)

    def test_artifact_lifecycle_meta_contracts_are_pinned(self) -> None:
        # Terraform plan/state JSON omits lifecycle meta-arguments, so keep the
        # destroy fence and external digest ownership under a direct source
        # contract. Strip comments before matching so prose cannot satisfy it.
        for label, path, resource_type, name, expected in (
            (
                "Authority repository",
                AUTHORITY_ECR_TF_PATH,
                "aws_ecr_repository",
                "authority",
                r"lifecycle\s*\{\s*prevent_destroy\s*=\s*true\s*\}",
            ),
            (
                "Authority digest",
                AUTHORITY_ECR_TF_PATH,
                "aws_ssm_parameter",
                "authority_image_digest",
                r"lifecycle\s*\{\s*ignore_changes\s*=\s*\[value\]\s*\}",
            ),
            (
                "Hub repository",
                HUB_ARTIFACT_TF_PATH,
                "aws_ecr_repository",
                "hub",
                r"lifecycle\s*\{\s*prevent_destroy\s*=\s*true\s*\}",
            ),
            (
                "Hub digest",
                HUB_ARTIFACT_TF_PATH,
                "aws_ssm_parameter",
                "hub_image_digest",
                r"lifecycle\s*\{\s*ignore_changes\s*=\s*\[value\]\s*\}",
            ),
        ):
            with self.subTest(resource=label):
                block = terraform_resource_source(path, resource_type, name)
                uncommented = re.sub(r"(?m)#.*$", "", block)
                self.assertRegex(uncommented, re.compile(expected, re.DOTALL))

    def test_hub_publisher_source_requires_dedicated_environments(self) -> None:
        # Environment protection is enforced by GitHub rather than Terraform,
        # so pin the exact OIDC-subject construction here. Shared deployment
        # environments must never regain permission through a prose-only check.
        source = PUBLISHER_TF_PATH.read_text(encoding="utf-8")
        uncommented = re.sub(r"(?m)#.*$", "", source)
        self.assertRegex(
            uncommented,
            re.compile(
                r'hub_publisher_github_environment\s*=\s*local\.is_prod\s*'
                r'\?\s*"hub-publish-production"\s*:\s*"hub-publish-sandbox"'
            ),
        )
        self.assertRegex(
            uncommented,
            re.compile(
                r'hub_publisher_github_subject\s*=\s*'
                r'"repo:layervai/nhp:environment:'
                r'\$\{local\.hub_publisher_github_environment\}"'
            ),
        )
        for shared_subject in (
            "repo:layervai/nhp:environment:sandbox",
            "repo:layervai/nhp:environment:production",
        ):
            with self.subTest(shared_subject=shared_subject):
                self.assertNotIn(shared_subject, uncommented)

        self.assertEqual(
            CHECKER.HUB_PUBLISHER_GITHUB_ENVIRONMENT,
            "hub-publish-sandbox",
        )
        self.assertEqual(
            CHECKER.HUB_PUBLISHER_GITHUB_SUBJECT,
            "repo:layervai/nhp:environment:hub-publish-sandbox",
        )

    def test_hub_carrier_transition_requires_live_protection_preflight(self) -> None:
        for path in (CONTROL_README_PATH, HUB_ROLLOUT_LEDGER_PATH):
            with self.subTest(path=path):
                contract = path.read_text(encoding="utf-8")
                self.assertIn("hub-publish-sandbox", contract)
                self.assertIn("hub-publish-production", contract)
                self.assertIn("178750268", contract)
                normalized = " ".join(contract.split())
                self.assertIn(
                    "before every publication attempt", normalized.lower()
                )
                self.assertRegex(normalized, re.compile(r"(live-read|readback)"))
                self.assertIn("required reviewer Justin", normalized)
                self.assertRegex(
                    normalized,
                    re.compile(
                        r"(sole custom `main`|"
                        r"only deployment branch policy is custom `main`)"
                    ),
                )


def live_fixture(root: Path) -> None:
    expected = {
        "vpc_id": "vpc-abc123",
        "dynamodb_endpoint_id": "vpce-abc123",
        "flow_log_id": "fl-abc123",
        "flow_log_destination": "arn:aws:logs:flow-group",
        "flow_log_role_arn": "arn:aws:iam::role/flow",
        "isolated_route_table_ids": ["rtb-0abc", "rtb-1abc", "rtb-2abc"],
        # Dark by default: the Hub worker S3 gateway endpoint is absent, so the
        # manifest carries a null id and the isolated tables stay local+DynamoDB.
        "s3_endpoint_id": None,
    }
    local_route = {
        "GatewayId": "local",
        "DestinationCidrBlock": "10.102.0.0/16",
        "State": "active",
    }
    route_tables = [
        {
            "RouteTableId": "rtb-main",
            "Associations": [{"Main": True}],
            "Routes": [local_route],
        }
    ]
    for route_table_id in expected["isolated_route_table_ids"]:
        route_tables.append(
            {
                "RouteTableId": route_table_id,
                "Associations": [{"Main": False}],
                "Routes": [
                    local_route,
                    {
                        "GatewayId": expected["dynamodb_endpoint_id"],
                        "DestinationPrefixListId": "pl-abc123",
                        "State": "active",
                    },
                ],
            }
        )
    fixtures = {
        "expected-live.json": expected,
        "route-tables.json": {"RouteTables": route_tables},
        "internet-gateways.json": {"InternetGateways": []},
        "egress-only-internet-gateways.json": {"EgressOnlyInternetGateways": []},
        "nat-gateways.json": {"NatGateways": []},
        "vpc-peerings.json": {"VpcPeeringConnections": []},
        "transit-gateway-attachments.json": {"TransitGatewayAttachments": []},
        "flow-logs.json": {
            "FlowLogs": [
                {
                    "FlowLogId": expected["flow_log_id"],
                    "FlowLogStatus": "ACTIVE",
                    "DeliverLogsStatus": "SUCCESS",
                    "TrafficType": "ALL",
                    "MaxAggregationInterval": 60,
                    "LogDestinationType": "cloud-watch-logs",
                    "LogDestination": expected["flow_log_destination"],
                    "DeliverLogsPermissionArn": expected["flow_log_role_arn"],
                }
            ]
        },
        "state-head.json": {
            "ServerSideEncryption": "aws:kms",
            "SSEKMSKeyId": CHECKER.STATE_KMS_KEY_ARN,
            "VersionId": "state-version-1",
        },
        "control-lambdas.json": [],
        "control-load-balancers.json": [],
    }
    for filename, value in fixtures.items():
        write_json(root / filename, value)


def hub_nlb_evidence() -> dict:
    return {
        "LoadBalancerName": CHECKER.HUB_EDGE_LOAD_BALANCER_NAME,
        "Type": "network",
        "Scheme": "internet-facing",
        "VpcId": "vpc-abc123",
        "State": {"Code": "active"},
    }


def live_edge_fixture(root: Path) -> None:
    """The dark live boundary plus the Step-5 Hub public UDP edge: one tagged
    public-edge route table carrying the sole internet route, exactly one
    internet gateway, and the single internet-facing Hub NLB."""
    live_fixture(root)
    route_payload = json.loads((root / "route-tables.json").read_text())
    route_payload["RouteTables"].append(
        {
            "RouteTableId": "rtb-edge",
            "Associations": [{"Main": False}],
            "Tags": [{"Key": "Type", "Value": "public-edge"}],
            "Routes": [
                {
                    "GatewayId": "local",
                    "DestinationCidrBlock": "10.102.0.0/16",
                    "State": "active",
                },
                {
                    "GatewayId": "igw-abc123",
                    "DestinationCidrBlock": "0.0.0.0/0",
                    "State": "active",
                },
            ],
        }
    )
    write_json(root / "route-tables.json", route_payload)
    write_json(
        root / "internet-gateways.json",
        {"InternetGateways": [{"InternetGatewayId": "igw-abc123"}]},
    )
    write_json(root / "control-load-balancers.json", [hub_nlb_evidence()])


def live_worker_fixture(root: Path) -> None:
    """The live Hub public edge PLUS the Step-5 Hub Fargate worker: the S3 gateway
    endpoint injects one prefix-list route into EACH isolated route table, and the
    manifest carries the endpoint id (null while the worker is dark)."""
    live_edge_fixture(root)
    expected = json.loads((root / "expected-live.json").read_text())
    expected["s3_endpoint_id"] = "vpce-0a1b2c3"
    write_json(root / "expected-live.json", expected)
    isolated = set(expected["isolated_route_table_ids"])
    route_payload = json.loads((root / "route-tables.json").read_text())
    for table in route_payload["RouteTables"]:
        if table.get("RouteTableId") in isolated:
            table["Routes"].append(
                {
                    "GatewayId": "vpce-0a1b2c3",
                    "DestinationPrefixListId": "pl-0abc123",
                    "State": "active",
                }
            )
    write_json(root / "route-tables.json", route_payload)


class LiveHubWorkerBoundaryTests(unittest.TestCase):
    def test_live_worker_admits_the_s3_gateway_route(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            live_worker_fixture(root)
            self.assertEqual(CHECKER.check_live(root)["vpc_id"], "vpc-abc123")

    def test_live_worker_missing_s3_route_on_an_isolated_table_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            live_worker_fixture(root)
            payload = json.loads((root / "route-tables.json").read_text())
            expected = json.loads((root / "expected-live.json").read_text())
            isolated = set(expected["isolated_route_table_ids"])
            for table in payload["RouteTables"]:
                if table.get("RouteTableId") in isolated:
                    table["Routes"] = [
                        route
                        for route in table["Routes"]
                        if route.get("GatewayId") != "vpce-0a1b2c3"
                    ]
                    break  # drop the S3 route from exactly one isolated table
            write_json(root / "route-tables.json", payload)
            with self.assertRaises(CHECKER.ContractError):
                CHECKER.check_live(root)

    def test_stray_s3_route_while_worker_dark_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            live_edge_fixture(root)  # worker dark: s3_endpoint_id stays null
            payload = json.loads((root / "route-tables.json").read_text())
            expected = json.loads((root / "expected-live.json").read_text())
            isolated = set(expected["isolated_route_table_ids"])
            for table in payload["RouteTables"]:
                if table.get("RouteTableId") in isolated:
                    table["Routes"].append(
                        {
                            "GatewayId": "vpce-0a1b2c3",
                            "DestinationPrefixListId": "pl-0abc123",
                            "State": "active",
                        }
                    )
                    break
            write_json(root / "route-tables.json", payload)
            with self.assertRaises(CHECKER.ContractError):
                CHECKER.check_live(root)

    def test_malformed_s3_endpoint_id_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            live_worker_fixture(root)
            expected = json.loads((root / "expected-live.json").read_text())
            expected["s3_endpoint_id"] = "not-a-vpce-id"
            write_json(root / "expected-live.json", expected)
            with self.assertRaises(CHECKER.ContractError):
                CHECKER.check_live(root)

    def test_live_worker_admits_the_keygen_lambda(self) -> None:
        # The persisted keygen function is admitted ONLY alongside the 3 authority
        # functions (the worker requires the live runtime).
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            live_worker_fixture(root)
            write_json(
                root / "control-lambdas.json",
                [
                    {"FunctionName": name}
                    for name in [
                        *CHECKER.AUTHORITY_RUNTIME_HUB_FUNCTIONS,
                        CHECKER.HUB_KEYGEN_FUNCTION_NAME,
                    ]
                ],
            )
            self.assertEqual(CHECKER.check_live(root)["hub_load_balancer_count"], 1)

    def test_live_worker_rejects_extra_lambda_beyond_keygen(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            live_worker_fixture(root)
            write_json(
                root / "control-lambdas.json",
                [
                    {"FunctionName": name}
                    for name in [
                        *CHECKER.AUTHORITY_RUNTIME_HUB_FUNCTIONS,
                        CHECKER.HUB_KEYGEN_FUNCTION_NAME,
                        "layerv-nhp-sandbox-control-rogue",
                    ]
                ],
            )
            with self.assertRaises(CHECKER.ContractError):
                CHECKER.check_live(root)


class HubSecretsmanagerEndpointPolicyTests(unittest.TestCase):
    def _after(self, **overrides) -> dict:
        stmt = {
            "Sid": "HubWorkerReadKeyMaterial",
            "Effect": "Allow",
            "Principal": "*",
            "Action": "secretsmanager:GetSecretValue",
            "Resource": [
                f"arn:aws:secretsmanager:{CHECKER.AWS_REGION}:{CHECKER.ACCOUNT_ID}"
                f":secret:{CHECKER.CONTROL_PREFIX}-hub-key-material-Ab3xYz"
            ],
            "Condition": {
                "StringEquals": {"aws:PrincipalArn": [CHECKER.HUB_EXECUTION_ROLE_ARN]}
            },
        }
        stmt.update(overrides)
        return {"policy": json.dumps({"Version": "2012-10-17", "Statement": [stmt]})}

    def test_exact_policy_passes(self) -> None:
        CHECKER._check_hub_secretsmanager_endpoint_policy(self._after(), "sm")

    def test_wrong_principal_fails(self) -> None:
        after = self._after(
            Condition={"StringEquals": {"aws:PrincipalArn": [CHECKER.HUB_TASK_ROLE_ARN]}}
        )
        with self.assertRaises(CHECKER.ContractError):
            CHECKER._check_hub_secretsmanager_endpoint_policy(after, "sm")

    def test_wrong_action_fails(self) -> None:
        with self.assertRaises(CHECKER.ContractError):
            CHECKER._check_hub_secretsmanager_endpoint_policy(
                self._after(Action="secretsmanager:PutSecretValue"), "sm"
            )

    def test_wrong_resource_shape_fails(self) -> None:
        after = self._after(
            Resource=[
                f"arn:aws:secretsmanager:{CHECKER.AWS_REGION}:{CHECKER.ACCOUNT_ID}"
                ":secret:some-other-secret-Ab3xYz"
            ]
        )
        with self.assertRaises(CHECKER.ContractError):
            CHECKER._check_hub_secretsmanager_endpoint_policy(after, "sm")


class HubLogsEndpointPolicyTests(unittest.TestCase):
    def _after(self, **overrides) -> dict:
        stmt = {
            "Sid": "HubWorkerContainerLogs",
            "Effect": "Allow",
            "Principal": "*",
            "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
            "Resource": [CHECKER.HUB_LOG_GROUP_ARN],
            "Condition": {
                "StringEquals": {"aws:PrincipalArn": [CHECKER.HUB_EXECUTION_ROLE_ARN]}
            },
        }
        stmt.update(overrides)
        return {"policy": json.dumps({"Version": "2012-10-17", "Statement": [stmt]})}

    def test_exact_passes(self) -> None:
        CHECKER._check_hub_logs_endpoint_policy(self._after(), "logs")

    def test_wrong_principal_fails(self) -> None:
        after = self._after(
            Condition={"StringEquals": {"aws:PrincipalArn": [CHECKER.HUB_TASK_ROLE_ARN]}}
        )
        with self.assertRaises(CHECKER.ContractError):
            CHECKER._check_hub_logs_endpoint_policy(after, "logs")

    def test_extra_action_fails(self) -> None:
        after = self._after(
            Action=["logs:CreateLogStream", "logs:PutLogEvents", "logs:CreateLogGroup"]
        )
        with self.assertRaises(CHECKER.ContractError):
            CHECKER._check_hub_logs_endpoint_policy(after, "logs")

    def test_wrong_log_group_fails(self) -> None:
        after = self._after(
            Resource=[
                f"arn:aws:logs:{CHECKER.AWS_REGION}:{CHECKER.ACCOUNT_ID}"
                ":log-group:/layerv/nhp/sandbox/control/other:*"
            ]
        )
        with self.assertRaises(CHECKER.ContractError):
            CHECKER._check_hub_logs_endpoint_policy(after, "logs")


class HubMonitoringEndpointPolicyTests(unittest.TestCase):
    def _after(self, **overrides) -> dict:
        stmt = {
            "Sid": "HubWorkerPublishMetrics",
            "Effect": "Allow",
            "Principal": "*",
            "Action": "cloudwatch:PutMetricData",
            "Resource": "*",
            "Condition": {
                "StringEquals": {
                    "aws:PrincipalArn": [CHECKER.HUB_TASK_ROLE_ARN],
                    "cloudwatch:namespace": "LayerV/NHP",
                }
            },
        }
        stmt.update(overrides)
        return {"policy": json.dumps({"Version": "2012-10-17", "Statement": [stmt]})}

    def test_exact_passes(self) -> None:
        CHECKER._check_hub_monitoring_endpoint_policy(self._after(), "mon")

    def test_wrong_principal_fails(self) -> None:
        after = self._after(
            Condition={
                "StringEquals": {
                    "aws:PrincipalArn": [CHECKER.HUB_EXECUTION_ROLE_ARN],
                    "cloudwatch:namespace": "LayerV/NHP",
                }
            }
        )
        with self.assertRaises(CHECKER.ContractError):
            CHECKER._check_hub_monitoring_endpoint_policy(after, "mon")

    def test_missing_namespace_condition_fails(self) -> None:
        after = self._after(
            Condition={
                "StringEquals": {"aws:PrincipalArn": [CHECKER.HUB_TASK_ROLE_ARN]}
            }
        )
        with self.assertRaises(CHECKER.ContractError):
            CHECKER._check_hub_monitoring_endpoint_policy(after, "mon")

    def test_wrong_namespace_fails(self) -> None:
        after = self._after(
            Condition={
                "StringEquals": {
                    "aws:PrincipalArn": [CHECKER.HUB_TASK_ROLE_ARN],
                    "cloudwatch:namespace": "Other/NS",
                }
            }
        )
        with self.assertRaises(CHECKER.ContractError):
            CHECKER._check_hub_monitoring_endpoint_policy(after, "mon")

    def test_non_wildcard_resource_fails(self) -> None:
        after = self._after(
            Resource=[f"arn:aws:cloudwatch:{CHECKER.AWS_REGION}:{CHECKER.ACCOUNT_ID}:*"]
        )
        with self.assertRaises(CHECKER.ContractError):
            CHECKER._check_hub_monitoring_endpoint_policy(after, "mon")

    def test_wrong_action_fails(self) -> None:
        with self.assertRaises(CHECKER.ContractError):
            CHECKER._check_hub_monitoring_endpoint_policy(
                self._after(Action="cloudwatch:PutMetricStream"), "mon"
            )


class LiveContractTests(unittest.TestCase):
    def test_exact_live_boundary_passes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            live_fixture(root)
            self.assertEqual(CHECKER.check_live(root)["vpc_id"], "vpc-abc123")

    def test_remote_route_flow_failure_and_state_version_drift_fail(self) -> None:
        for mutation in ("route", "flow", "kms", "version-null"):
            with (
                self.subTest(mutation=mutation),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory)
                live_fixture(root)
                if mutation == "route":
                    payload = json.loads((root / "route-tables.json").read_text())
                    payload["RouteTables"][1]["Routes"].append(
                        {"GatewayId": "igw-bad", "DestinationCidrBlock": "0.0.0.0/0"}
                    )
                    write_json(root / "route-tables.json", payload)
                elif mutation == "flow":
                    payload = json.loads((root / "flow-logs.json").read_text())
                    payload["FlowLogs"][0]["DeliverLogsStatus"] = "FAILED"
                    write_json(root / "flow-logs.json", payload)
                elif mutation == "kms":
                    payload = json.loads((root / "state-head.json").read_text())
                    payload["SSEKMSKeyId"] = "alias/wrong"
                    write_json(root / "state-head.json", payload)
                else:
                    payload = json.loads((root / "state-head.json").read_text())
                    payload["VersionId"] = "null"
                    write_json(root / "state-head.json", payload)
                with self.assertRaises(CHECKER.ContractError):
                    CHECKER.check_live(root)

    def test_live_boundary_admits_exactly_the_three_authority_functions(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            live_fixture(root)
            write_json(
                root / "control-lambdas.json",
                [
                    {"FunctionName": name, "Runtime": None}
                    for name in CHECKER.AUTHORITY_RUNTIME_HUB_FUNCTIONS
                ],
            )
            self.assertEqual(
                CHECKER.check_live(root)["authority_function_count"], 3
            )

    def test_live_boundary_rejects_unexpected_or_malformed_lambdas(self) -> None:
        for payload in (
            [{"FunctionName": "layerv-nhp-sandbox-ca-rogue"}],
            [{"FunctionName": name} for name in CHECKER.AUTHORITY_RUNTIME_HUB_FUNCTIONS]
            + [{"FunctionName": "layerv-nhp-sandbox-ca-ia-extra"}],
            ["layerv-nhp-sandbox-ca-ia"],
        ):
            with (
                self.subTest(payload=payload),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory)
                live_fixture(root)
                write_json(root / "control-lambdas.json", payload)
                with self.assertRaises(CHECKER.ContractError):
                    CHECKER.check_live(root)


class LiveHubEdgeBoundaryTests(unittest.TestCase):
    def test_live_public_edge_admits_exactly_the_hub_nlb(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            live_edge_fixture(root)
            summary = CHECKER.check_live(root)
            self.assertEqual(summary["hub_load_balancer_count"], 1)
            self.assertEqual(summary["vpc_id"], "vpc-abc123")

    def test_dark_boundary_reports_no_load_balancer(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            live_fixture(root)
            self.assertEqual(CHECKER.check_live(root)["hub_load_balancer_count"], 0)

    def test_load_balancer_while_edge_dark_fails(self) -> None:
        # A load balancer without the tagged public-edge route table proving the
        # edge is live is a boundary breach and must fail closed.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            live_fixture(root)
            write_json(root / "control-load-balancers.json", [hub_nlb_evidence()])
            with self.assertRaises(CHECKER.ContractError):
                CHECKER.check_live(root)

    def test_live_public_edge_without_load_balancer_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            live_edge_fixture(root)
            write_json(root / "control-load-balancers.json", [])
            with self.assertRaises(CHECKER.ContractError):
                CHECKER.check_live(root)

    def test_live_public_edge_rejects_wrong_or_extra_load_balancer(self) -> None:
        base = hub_nlb_evidence()
        mutations = (
            [{**base, "LoadBalancerName": "layerv-nhp-sandbox-control-rogue"}],
            [{**base, "Type": "application"}],
            [{**base, "Scheme": "internal"}],
            [{**base, "VpcId": "vpc-other"}],
            [{**base, "State": {"Code": "provisioning"}}],
            [base, base],
            ["not-an-object"],
            "not-a-list",
        )
        for payload in mutations:
            with (
                self.subTest(payload=payload),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory)
                live_edge_fixture(root)
                write_json(root / "control-load-balancers.json", payload)
                with self.assertRaises(CHECKER.ContractError):
                    CHECKER.check_live(root)


class SecretSeedOrchestrationTests(unittest.TestCase):
    secret_arn = (
        "arn:aws:secretsmanager:us-east-2:767397897469:secret:"
        "layerv-nhp-sandbox-control-otp-pepper-AbCdEf"
    )
    kms_arn = "arn:aws:kms:us-east-2:767397897469:key/data123"

    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.bin_dir = self.root / "bin"
        self.bin_dir.mkdir()
        self.state_path = self.root / "state.json"
        self.log_path = self.root / "aws.log"
        fake_aws = self.bin_dir / "aws"
        fake_aws.write_text(
            """#!/usr/bin/env python3
import json
import os
import sys
from pathlib import Path

state_path = Path(os.environ["FAKE_AWS_STATE"])
log_path = Path(os.environ["FAKE_AWS_LOG"])
state = json.loads(state_path.read_text())
args = sys.argv[1:]
with log_path.open("a") as log:
    log.write(" ".join(args) + "\\n")

operation = tuple(args[:2])
if operation == ("secretsmanager", "describe-secret"):
    print(json.dumps({"KmsKeyId": state["kms_key_id"]}))
elif operation == ("secretsmanager", "list-secret-version-ids"):
    print(json.dumps({"Versions": state["versions"]}))
elif operation == ("secretsmanager", "get-random-password"):
    print("R" * 48)
elif operation == ("secretsmanager", "put-secret-value"):
    token = args[args.index("--client-request-token") + 1]
    secret_arg = args[args.index("--secret-string") + 1]
    if not secret_arg.startswith("file://"):
        raise SystemExit("secret was not passed through a file")
    if len(Path(secret_arg.removeprefix("file://")).read_bytes()) != 48:
        raise SystemExit("secret payload length is not 48")
    state["versions"].append(
        {"VersionId": token, "VersionStages": ["AWSCURRENT"]}
    )
    state_path.write_text(json.dumps(state))
    print(json.dumps({"VersionId": token}))
else:
    raise SystemExit(f"unexpected fake AWS operation: {args}")
""",
            encoding="utf-8",
        )
        fake_aws.chmod(0o755)
        self.env = dict(os.environ)
        self.env.update(
            {
                "FAKE_AWS_LOG": str(self.log_path),
                "FAKE_AWS_STATE": str(self.state_path),
                "PATH": f"{self.bin_dir}:{self.env['PATH']}",
            }
        )

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def write_state(self, versions: list[dict]) -> None:
        write_json(self.state_path, {"kms_key_id": self.kms_arn, "versions": versions})

    def run_seed(self, evidence_name: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                str(SECRET_SEED_SCRIPT_PATH),
                self.secret_arn,
                self.kms_arn,
                CHECKER.AWS_REGION,
                str(self.root / evidence_name),
            ],
            check=False,
            capture_output=True,
            env=self.env,
            text=True,
        )

    def test_absent_secret_is_seeded_once_and_then_is_idempotent(self) -> None:
        self.write_state([])
        first = self.run_seed("first")
        self.assertEqual(first.returncode, 0, first.stderr)
        token = hashlib.sha256(self.secret_arn.encode()).hexdigest()
        state = json.loads(self.state_path.read_text())
        self.assertEqual(
            state["versions"],
            [{"VersionId": token, "VersionStages": ["AWSCURRENT"]}],
        )
        summary = json.loads((self.root / "first/secret-seed-summary.json").read_text())
        self.assertTrue(summary["seeded_this_run"])

        second = self.run_seed("second")
        self.assertEqual(second.returncode, 0, second.stderr)
        summary = json.loads(
            (self.root / "second/secret-seed-summary.json").read_text()
        )
        self.assertFalse(summary["seeded_this_run"])
        self.assertEqual(self.log_path.read_text().count("put-secret-value"), 1)

    def test_ambiguous_or_missing_current_history_fails_without_mutation(self) -> None:
        token = hashlib.sha256(self.secret_arn.encode()).hexdigest()
        histories = (
            [{"VersionId": "prior", "VersionStages": ["AWSCURRENT"]}],
            [{"VersionId": token, "VersionStages": ["AWSPREVIOUS"]}],
            [
                {"VersionId": token, "VersionStages": ["AWSCURRENT"]},
                {"VersionId": "prior", "VersionStages": ["AWSPREVIOUS"]},
            ],
        )
        for index, versions in enumerate(histories):
            with self.subTest(versions=versions):
                self.write_state(versions)
                self.log_path.write_text("")
                result = self.run_seed(f"ambiguous-{index}")
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("ambiguous or missing AWSCURRENT", result.stderr)
                self.assertNotIn("put-secret-value", self.log_path.read_text())


class WorkflowContractTests(unittest.TestCase):
    def test_temporary_first_apply_workflow_is_retired(self) -> None:
        for path in (
            ROOT / ".github/workflows/control-sandbox-first-apply.yml",
            ROOT / "scripts/capture-control-sandbox-first-apply-preflight.sh",
            ROOT / "scripts/capture-control-sandbox-partial-recovery-state.sh",
        ):
            self.assertFalse(path.exists(), path)
        checker = CHECKER_PATH.read_text(encoding="utf-8")
        for retired_token in (
            'sub.add_parser("preflight")',
            '"artifact-create"',
            '"artifact-verify"',
            'sub.add_parser("source-run")',
            'choices=("create", "no-op")',
            "--expected-action",
            "recover-config",
            "recovery-artifact-create",
            "recovery-artifact-verify",
            "FAILED_APPLY_",
            "PARTIAL_STATE_",
        ):
            self.assertNotIn(retired_token, checker)

    def test_security_helpers_remain_in_workflow_lint_boundary(self) -> None:
        validate_workflow = VALIDATE_WORKFLOW_PATH.read_text(encoding="utf-8")
        makefile = MAKEFILE_PATH.read_text(encoding="utf-8")
        boundary_step = validate_workflow.split(
            "      - name: Test sandbox Control foundation boundary\n", 1
        )[1].split("\n      - name:", 1)[0]
        make_shellcheck = next(
            line
            for line in makefile.splitlines()
            if line.startswith("\t@shellcheck ")
            and "verify-control-sandbox-first-apply.sh" in line
        )

        for helper in (
            "scripts/check-control-global-routing.sh",
            "scripts/check-control-vpc-cidr-overlap.sh",
            "scripts/ensure-control-otp-pepper.sh",
            "scripts/verify-control-sandbox-first-apply.sh",
        ):
            self.assertIn(f'- "{helper}"', validate_workflow)
            self.assertIn(helper, boundary_step)
            self.assertIn(helper, make_shellcheck)
        self.assertIn(
            '- "tests/scripts/**"',
            validate_workflow,
        )

    def test_real_pr_plan_runs_convergence_contract(self) -> None:
        plan_workflow = TERRAFORM_PLAN_WORKFLOW_PATH.read_text(encoding="utf-8")
        foundation_check = plan_workflow.index(
            "      - name: Check Terraform Control Plan Contract\n"
        )
        convergence_check = plan_workflow.index(
            "      - name: Check Terraform Control Convergence Plan Contract\n"
        )
        summary = plan_workflow.index(
            "      - name: Summarize Terraform Control Plan\n"
        )

        self.assertLess(foundation_check, convergence_check)
        self.assertLess(convergence_check, summary)
        self.assertIn(
            "python3 .github/scripts/check-control-sandbox-first-apply.py plan "
            "terraform/control/environments/sandbox/control.tfplan.json",
            plan_workflow,
        )
        self.assertNotIn("--expected-action", plan_workflow)
        self.assertIn(
            "Fail closed on any unreviewed Control mutation",
            plan_workflow,
        )


class HubEdgeSliceTests(unittest.TestCase):
    """Step 5 slice 5a: the Hub public UDP edge admission + plan_mode."""

    def test_hub_edge_slice_admitted(self) -> None:
        summary = CHECKER.check_plan(hub_edge_transition_fixture())
        self.assertEqual(summary["plan_mode"], "hub-edge-slice")

    def test_hub_edge_partial_slice_rejected(self) -> None:
        candidate = hub_edge_transition_fixture()
        candidate["resource_changes"] = [
            change
            for change in candidate["resource_changes"]
            if change["address"] != "module.control.aws_lb.hub[0]"
        ]
        with self.assertRaises(CHECKER.ContractError):
            CHECKER.check_plan(candidate)

    def test_hub_edge_foreign_resource_rejected(self) -> None:
        candidate = hub_edge_transition_fixture()
        candidate["resource_changes"].append(
            {
                "address": "module.control.aws_lb.rogue[0]",
                "mode": "managed",
                "type": "aws_lb",
                "change": _runtime_create({"id": "rogue"}),
            }
        )
        with self.assertRaises(CHECKER.ContractError):
            CHECKER.check_plan(candidate)

    def test_hub_edge_update_rejected(self) -> None:
        candidate = hub_edge_transition_fixture()
        for change in candidate["resource_changes"]:
            if change["address"] == "module.control.aws_lb_listener.hub[0]":
                change["change"]["actions"] = ["update"]
                change["change"]["before"] = copy.deepcopy(change["change"]["after"])
        with self.assertRaises(CHECKER.ContractError):
            CHECKER.check_plan(candidate)

    def test_hub_edge_created_over_steady_runtime(self) -> None:
        # The edge slice applies independently while the runtime slice is already
        # steady (every runtime change a no-op): still exactly hub-edge-slice.
        result = authority_runtime_steady_fixture()
        result["applyable"] = True
        result["resource_changes"].extend(_hub_edge_resource_changes())
        summary = CHECKER.check_plan(result)
        self.assertEqual(summary["plan_mode"], "hub-edge-slice")

    def test_both_slices_steady_is_noop(self) -> None:
        # Both slices already applied (all no-op) is a valid steady inventory.
        result = authority_runtime_steady_fixture()
        for change in _hub_edge_resource_changes():
            change["change"]["actions"] = ["no-op"]
            change["change"]["before"] = copy.deepcopy(change["change"]["after"])
            result["resource_changes"].append(change)
        summary = CHECKER.check_plan(result)
        self.assertEqual(summary["plan_mode"], "no-op")


if __name__ == "__main__":
    unittest.main(verbosity=2)
