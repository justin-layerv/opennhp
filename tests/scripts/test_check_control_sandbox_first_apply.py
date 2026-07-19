#!/usr/bin/env python3
"""Hermetic fail-closed tests for the sandbox Control first-apply boundary."""

from __future__ import annotations

import argparse
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
WORKFLOW_PATH = ROOT / ".github/workflows/control-sandbox-first-apply.yml"
VALIDATE_WORKFLOW_PATH = ROOT / ".github/workflows/validate-workflows.yml"
TERRAFORM_PLAN_WORKFLOW_PATH = ROOT / ".github/workflows/terraform-plan-pr.yml"
MAKEFILE_PATH = ROOT / "Makefile"
VERIFY_SCRIPT_PATH = ROOT / "scripts/verify-control-sandbox-first-apply.sh"
PREFLIGHT_SCRIPT_PATH = (
    ROOT / "scripts/capture-control-sandbox-first-apply-preflight.sh"
)
LIVE_MAIN_SCRIPT_PATH = ROOT / "scripts/check-live-main-ref.sh"
NO_CHECKOUT_CREDENTIALS_SCRIPT_PATH = (
    ROOT / "scripts/check-no-checkout-credentials.sh"
)
SECRET_SEED_SCRIPT_PATH = ROOT / "scripts/ensure-control-otp-pepper.sh"
REDIS_TF_PATH = (
    ROOT / "terraform/modules/connector-authority-foundation/redis.tf"
)
REAL_TERRAFORM_NOOP_FIXTURE_PATH = (
    ROOT / "tests/fixtures/qurl-agent-transact-iam/no-op-terraform-1.14.3.json"
)
LEDGER_PATH = (
    ROOT
    / "docs/runbooks/prod-rollout-ledger/2026-07-16-issue-3227-connector-authority-foundation.md"
)
SPEC = importlib.util.spec_from_file_location("control_first_apply", CHECKER_PATH)
assert SPEC and SPEC.loader
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)


def planned_security_fixture() -> dict[str, tuple[dict, dict]]:
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
        "module.control.aws_kms_key.authority_data": (
            {
                "bypass_policy_lockout_safety_check": False,
                "customer_master_key_spec": "SYMMETRIC_DEFAULT",
                "deletion_window_in_days": 7,
                "enable_key_rotation": True,
                "is_enabled": True,
                "key_usage": "ENCRYPT_DECRYPT",
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
        "module.control.aws_elasticache_user.otp_authority": (
            {
                "access_string": "on ~connector:* -@all +@connection +@read +@write +@scripting",
                "authentication_mode": [{"passwords": None, "type": "iam"}],
                "engine": "redis",
                "region": CHECKER.AWS_REGION,
                "user_id": f"{CHECKER.CONTROL_PREFIX}-otp-auth",
                "user_name": f"{CHECKER.CONTROL_PREFIX}-otp-auth",
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
                    f"{CHECKER.CONTROL_PREFIX}-otp-auth",
                    f"{CHECKER.CONTROL_PREFIX}-otp-default",
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
        },
        "root_module": {
            "resources": [],
            "module_calls": {
                "control": {"module": {"resources": resources, "module_calls": {}}}
            },
        },
    }


def recovery_drift_fixture() -> list[dict]:
    result = []
    for address, auth_type in (
        ("module.control.aws_elasticache_user.otp_authority", "iam"),
        ("module.control.aws_elasticache_user.otp_disabled_default", "no-password"),
    ):
        before = {
            "id": address,
            "authentication_mode": [
                {"password_count": 0, "passwords": None, "type": auth_type}
            ],
        }
        after = copy.deepcopy(before)
        after["authentication_mode"][0]["passwords"] = []
        result.append(
            {
                "address": address,
                "mode": "managed",
                "type": "aws_elasticache_user",
                "change": {
                    "actions": ["update"],
                    "before": before,
                    "after": after,
                    "after_unknown": {},
                    "before_sensitive": {"authentication_mode": [{"passwords": True}]},
                    "after_sensitive": {"authentication_mode": [{"passwords": True}]},
                },
            }
        )
    policy = json.dumps(CHECKER.FLOW_LOG_INLINE_POLICY, separators=(",", ":"))
    result.append(
        {
            "address": "module.control.aws_iam_role.flow_logs",
            "mode": "managed",
            "type": "aws_iam_role",
            "change": {
                "actions": ["update"],
                "before": {"id": "flow-logs", "inline_policy": []},
                "after": {
                    "id": "flow-logs",
                    "inline_policy": [{"name": "flow-logs", "policy": policy}],
                },
                "after_unknown": {},
                "before_sensitive": {"inline_policy": []},
                "after_sensitive": {"inline_policy": [{}]},
            },
        }
    )
    return result


def plan_fixture(action: str = "create") -> dict:
    if action not in {"create", "no-op", "recover", "recover-config"}:
        raise ValueError(f"unsupported fixture action: {action}")
    security = planned_security_fixture()
    if action != "create":
        vpc = security["module.control.aws_vpc.control"][0]
        vpc["assign_generated_ipv6_cidr_block"] = False
        vpc["ipv6_ipam_pool_id"] = ""
        vpc["ipv6_netmask_length"] = 0
        for address, auth_type in (
            ("module.control.aws_elasticache_user.otp_authority", "iam"),
            (
                "module.control.aws_elasticache_user.otp_disabled_default",
                "no-password",
            ),
        ):
            security[address][0]["authentication_mode"] = [
                {
                    "password_count": 0,
                    "passwords": None if action == "recover-config" else [],
                    "type": auth_type,
                }
            ]
    changes = []
    for address, resource_type in CHECKER.EXPECTED_RESOURCES.items():
        after, after_unknown = copy.deepcopy(
            security.get(address, ({"id": address}, {}))
        )
        resource_action = (
            "create"
            if action in {"recover", "recover-config"}
            and address == "module.control.aws_elasticache_serverless_cache.otp"
            else "no-op"
            if action in {"recover", "recover-config"}
            else action
        )
        before = None if resource_action == "create" else copy.deepcopy(after)
        changes.append(
            {
                "address": address,
                "mode": "managed",
                "type": resource_type,
                "change": {
                    "actions": [resource_action],
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
        "applyable": action in {"create", "recover", "recover-config"},
        "action_invocations": [],
        "configuration": configuration_fixture(),
        "resource_drift": (
            recovery_drift_fixture()
            if action == "recover"
            else None
            if action == "recover-config"
            else []
        ),
        "resource_changes": changes,
    }


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value), encoding="utf-8")


class PlanContractTests(unittest.TestCase):
    def test_real_terraform_1_14_3_noop_status_contract(self) -> None:
        real_noop = json.loads(
            REAL_TERRAFORM_NOOP_FIXTURE_PATH.read_text(encoding="utf-8")
        )
        self.assertEqual(real_noop["terraform_version"], CHECKER.TF_VERSION)

        candidate = plan_fixture("no-op")
        for field in ("format_version", "complete", "errored", "applyable"):
            candidate[field] = real_noop[field]
        self.assertEqual(CHECKER.check_plan(candidate, "no-op")["resource_count"], 41)

    def test_exact_create_and_noop_pass(self) -> None:
        self.assertEqual(
            CHECKER.check_plan(plan_fixture(), "create")["resource_count"], 41
        )
        self.assertEqual(
            CHECKER.check_plan(plan_fixture("no-op"), "no-op")["resource_count"],
            41,
        )
        recovery = CHECKER.check_plan(plan_fixture("recover"), "recover")
        self.assertEqual(recovery["resource_count"], 41)
        self.assertEqual(recovery["create_count"], 1)
        recovery_config = CHECKER.check_plan(
            plan_fixture("recover-config"), "recover-config"
        )
        self.assertEqual(recovery_config["resource_count"], 41)
        self.assertEqual(recovery_config["create_count"], 1)

        normalized = plan_fixture("no-op")
        normalized_changes = {
            item["address"]: item["change"] for item in normalized["resource_changes"]
        }
        normalized_changes["module.control.aws_vpc.control"]["after"][
            "assign_generated_ipv6_cidr_block"
        ] = False
        for address, auth_type in (
            ("module.control.aws_elasticache_user.otp_authority", "iam"),
            (
                "module.control.aws_elasticache_user.otp_disabled_default",
                "no-password",
            ),
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
        self.assertEqual(CHECKER.check_plan(normalized, "no-op")["resource_count"], 41)

    def assert_rejected(self, plan: dict, action: str = "create") -> None:
        with self.assertRaises(CHECKER.ContractError):
            CHECKER.check_plan(plan, action)

    def change(self, plan: dict, address: str) -> dict:
        return next(
            item["change"]
            for item in plan["resource_changes"]
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
                "change": {"actions": ["create"], "before": None, "after": {}},
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
            ("applyable", False),
        ):
            candidate = plan_fixture()
            candidate[field] = value
            self.assert_rejected(candidate)

        drift = plan_fixture()
        drift["resource_drift"] = [
            {"change": {"actions": ["update"]}, "address": "forbidden"}
        ]
        self.assert_rejected(drift)

        unequal_noop = plan_fixture("no-op")
        unequal_noop["resource_changes"][0]["change"]["after"] = {"id": "changed"}
        self.assert_rejected(unequal_noop, "no-op")

    def test_recovery_rejects_any_extra_change_or_drift(self) -> None:
        for label, mutation in (
            (
                "managed-update",
                lambda plan: plan["resource_changes"][0]["change"].__setitem__(
                    "actions", ["update"]
                ),
            ),
            (
                "cache-replacement",
                lambda plan: self.change(
                    plan, "module.control.aws_elasticache_serverless_cache.otp"
                ).__setitem__("actions", ["delete", "create"]),
            ),
            (
                "extra-drift",
                lambda plan: plan["resource_drift"].append(
                    {
                        "address": "module.control.aws_vpc.control",
                        "mode": "managed",
                        "type": "aws_vpc",
                        "change": {"actions": ["update"]},
                    }
                ),
            ),
            (
                "drift-type",
                lambda plan: plan["resource_drift"][0].__setitem__(
                    "type", "aws_iam_role"
                ),
            ),
            (
                "missing-exact-drift",
                lambda plan: plan.__setitem__("resource_drift", []),
            ),
        ):
            with self.subTest(label=label):
                candidate = plan_fixture("recover")
                mutation(candidate)
                self.assert_rejected(candidate, "recover")

    def test_recovery_config_rejects_any_live_drift(self) -> None:
        candidate = plan_fixture("recover-config")
        candidate["resource_drift"] = recovery_drift_fixture()
        self.assert_rejected(candidate, "recover-config")

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
                "authority-password",
                "module.control.aws_elasticache_user.otp_authority",
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
        for path, value in mutations:
            with self.subTest(path=path):
                candidate = plan_fixture()
                resource = self.configuration_resource(
                    candidate, "module.control.aws_ecr_repository.authority"
                )
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
                "module.control.aws_elasticache_user.otp_authority",
                "access_string",
                "on ~* +@all",
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
            {"data_resource_count": 4, "managed_resource_count": 41},
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


class ArtifactTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.plan = self.root / "tfplan"
        self.plan_json = self.root / "tfplan.json"
        self.metadata = self.root / "plan-metadata.json"
        self.plan.write_bytes(b"immutable terraform plan")
        write_json(self.plan_json, plan_fixture())
        self.base = {
            "plan": self.plan,
            "plan_json": self.plan_json,
            "metadata": self.metadata,
            "output": self.metadata,
            "repository": CHECKER.REPOSITORY,
            "commit_sha": "a" * 40,
            "plan_sha256": CHECKER.sha256_file(self.plan),
            "run_id": "12345",
            "run_attempt": "1",
            "planned_at_epoch": "200000",
            "workflow_ref": (
                f"{CHECKER.REPOSITORY}/{CHECKER.WORKFLOW_PATH}@refs/heads/main"
            ),
            "terraform_version": CHECKER.TF_VERSION,
            "now_epoch": "200001",
        }

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def args(self, **changes: object) -> argparse.Namespace:
        values = dict(self.base)
        values.update(changes)
        return argparse.Namespace(**values)

    def test_artifact_round_trip(self) -> None:
        created = CHECKER.create_artifact(self.args())
        self.assertEqual(created["plan_sha256"], self.base["plan_sha256"])
        self.assertNotIn("state_was_absent", created)
        self.assertNotIn("lock_was_absent", created)
        verified = CHECKER.verify_artifact(self.args())
        self.assertEqual(verified, created)

    def test_tamper_and_stale_artifact_fail(self) -> None:
        CHECKER.create_artifact(self.args())
        self.plan.write_bytes(b"tampered")
        with self.assertRaises(CHECKER.ContractError):
            CHECKER.verify_artifact(self.args())

        self.plan.write_bytes(b"immutable terraform plan")
        with self.assertRaises(CHECKER.ContractError):
            CHECKER.verify_artifact(
                self.args(now_epoch=str(200000 + CHECKER.PLAN_MAX_AGE_SECONDS + 1))
            )

    def test_wrong_source_binding_fails(self) -> None:
        for field, value in (
            ("repository", "layervai/not-nhp"),
            ("commit_sha", "A" * 40),
            ("run_id", "0"),
            ("terraform_version", "1.15.0"),
        ):
            with self.assertRaises(CHECKER.ContractError):
                CHECKER.create_artifact(self.args(**{field: value}))

    def test_recovery_artifact_round_trip_and_state_binding(self) -> None:
        write_json(self.plan_json, plan_fixture("recover"))
        created = CHECKER.create_recovery_artifact(self.args())
        self.assertEqual(created["plan_mode"], "partial-recovery")
        self.assertEqual(created["failed_apply_run_id"], CHECKER.FAILED_APPLY_RUN_ID)
        self.assertEqual(created["state_sha256"], CHECKER.PARTIAL_STATE_SHA256)
        self.assertEqual(CHECKER.verify_recovery_artifact(self.args()), created)

        metadata = json.loads(self.metadata.read_text(encoding="utf-8"))
        metadata["state_version_id"] = "stale-version"
        write_json(self.metadata, metadata)
        with self.assertRaisesRegex(CHECKER.ContractError, "state_version_id"):
            CHECKER.verify_recovery_artifact(self.args())


class PartialStateTests(unittest.TestCase):
    def raw_state(self) -> dict:
        resources = []
        expected = {
            **{
                address: ("managed", kind)
                for address, kind in CHECKER.EXPECTED_RESOURCES.items()
                if address
                != "module.control.aws_elasticache_serverless_cache.otp"
            },
            **{
                address: ("data", kind)
                for address, kind in CHECKER.EXPECTED_DATA_RESOURCES.items()
            },
        }
        pattern = re.compile(
            r"^module\.control\.(?:data\.)?([^.]+)\.([^\[]+)(?:\[(.+)\])?$"
        )
        for address, (mode, resource_type) in expected.items():
            match = pattern.fullmatch(address)
            self.assertIsNotNone(match, address)
            _, name, raw_index = match.groups()
            instance = {"schema_version": 0, "attributes": {"id": address}}
            if raw_index is not None:
                instance["index_key"] = json.loads(raw_index)
            resources.append(
                {
                    "module": "module.control",
                    "mode": mode,
                    "type": resource_type,
                    "name": name,
                    "instances": [instance],
                }
            )
        return {
            "version": 4,
            "terraform_version": CHECKER.TF_VERSION,
            "serial": CHECKER.PARTIAL_STATE_SERIAL,
            "lineage": CHECKER.PARTIAL_STATE_LINEAGE,
            "resources": resources,
        }

    def check(self, state: dict) -> dict:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state_path = root / "state.tfstate"
            head_path = root / "state-head.json"
            write_json(state_path, state)
            write_json(
                head_path,
                {
                    "ContentLength": CHECKER.PARTIAL_STATE_CONTENT_LENGTH,
                    "ETag": CHECKER.PARTIAL_STATE_ETAG,
                    "VersionId": CHECKER.PARTIAL_STATE_VERSION_ID,
                    "ServerSideEncryption": "aws:kms",
                    "SSEKMSKeyId": CHECKER.STATE_KMS_KEY_ARN,
                },
            )
            old_digest = CHECKER.PARTIAL_STATE_SHA256
            CHECKER.PARTIAL_STATE_SHA256 = CHECKER.sha256_file(state_path)
            try:
                return CHECKER.check_partial_state(state_path, head_path)
            finally:
                CHECKER.PARTIAL_STATE_SHA256 = old_digest

    def test_exact_partial_state_passes(self) -> None:
        result = self.check(self.raw_state())
        self.assertEqual(result["managed_resource_count"], 40)
        self.assertEqual(result["data_resource_count"], 4)

    def test_extra_missing_and_deposed_state_fail(self) -> None:
        for label, mutation in (
            ("missing", lambda state: state["resources"].pop()),
            (
                "deposed",
                lambda state: state["resources"][0]["instances"][0].__setitem__(
                    "deposed", "deadbeef"
                ),
            ),
        ):
            with self.subTest(label=label):
                state = self.raw_state()
                mutation(state)
                with self.assertRaises(CHECKER.ContractError):
                    self.check(state)


def simulation(
    actions: tuple[str, ...], resources: tuple[str, ...], decision: str
) -> dict:
    return {
        "EvaluationResults": [
            {
                "EvalActionName": action.lower(),
                "EvalResourceName": resource,
                "EvalDecision": decision,
                "MissingContextValues": [],
            }
            for action in actions
            for resource in resources
        ]
    }


def cache_dependency_simulation(
    user_group_resource: str, user_group_decision: str
) -> dict:
    resources = (CHECKER.CONTROL_CACHE_RESOURCE, user_group_resource)
    outer_decision = (
        "allowed" if user_group_decision == "allowed" else "implicitDeny"
    )
    return {
        "EvaluationResults": [
            {
                "EvalActionName": action.lower(),
                "EvalResourceName": resource,
                "EvalDecision": outer_decision,
                "ResourceSpecificResults": [
                    {
                        "EvalResourceName": nested_resource,
                        "EvalResourceDecision": (
                            "allowed"
                            if nested_resource == CHECKER.CONTROL_CACHE_RESOURCE
                            else user_group_decision
                        ),
                        "MissingContextValues": (
                            sorted(CHECKER.CELL_WRITE_IMPOSSIBLE_CONTEXT_KEYS)
                            if nested_resource == user_group_resource
                            and user_group_decision == "implicitDeny"
                            else []
                        ),
                    }
                    for nested_resource in resources
                ],
            }
            for action in CHECKER.CACHE_DEPENDENCY_ACTIONS
            for resource in resources
        ]
    }


def preflight_fixture(root: Path) -> None:
    policy_version = "v14"
    fixtures = {
        "caller.json": {
            "Account": CHECKER.ACCOUNT_ID,
            "Arn": (
                f"arn:aws:sts::{CHECKER.ACCOUNT_ID}:assumed-role/"
                f"{CHECKER.ROLE_NAME}/control-plan"
            ),
        },
        "state-status.json": {
            "bucket": CHECKER.STATE_BUCKET,
            "state_key": CHECKER.STATE_KEY,
            "lock_key": CHECKER.STATE_LOCK_KEY,
            "state_exists": False,
            "lock_exists": False,
        },
        "bucket-versioning.json": {"Status": "Enabled"},
        "policy.json": {
            "Policy": {
                "Arn": CHECKER.POLICY_ARN,
                "AttachmentCount": 1,
                "DefaultVersionId": policy_version,
            }
        },
        "policy-version.json": {
            "PolicyVersion": {
                "VersionId": policy_version,
                "IsDefaultVersion": True,
                "Document": {
                    "Statement": [
                        CHECKER.EXPECTED_SERVERLESS_CACHE_STATEMENT,
                        CHECKER.EXPECTED_CACHE_DEPENDENCY_STATEMENT,
                        CHECKER.EXPECTED_CONTROL_STATEMENT,
                    ]
                },
            }
        },
        "attached-policies.json": {
            "AttachedPolicies": [
                {"PolicyArn": CHECKER.POLICY_ARN},
                *(
                    {"PolicyArn": f"arn:aws:iam::aws:policy/Fake{index}"}
                    for index in range(9)
                ),
            ]
        },
        "account-summary.json": {"SummaryMap": {"AttachedPoliciesPerRoleQuota": 10}},
        "control-simulation.json": simulation(
            CHECKER.CONTROL_ACTIONS, CHECKER.CONTROL_RESOURCES, "allowed"
        ),
        "cell-write-simulation.json": simulation(
            CHECKER.CONTROL_WRITE_ACTIONS,
            CHECKER.CELL_RESOURCES,
            "implicitDeny",
        ),
        "cell-read-simulation.json": simulation(
            CHECKER.CONTROL_READ_ACTIONS, CHECKER.CELL_RESOURCES, "allowed"
        ),
        "cache-control-dependency-simulation.json": cache_dependency_simulation(
            CHECKER.CONTROL_CACHE_USER_GROUP_RESOURCE,
            "allowed",
        ),
        "cache-cell-dependency-simulation.json": cache_dependency_simulation(
            CHECKER.CELL_CACHE_USER_GROUP_RESOURCE,
            "implicitDeny",
        ),
        "endpoint-service.json": {
            "ServiceDetails": [
                {
                    "ServiceName": f"com.amazonaws.{CHECKER.AWS_REGION}.email",
                    "ServiceType": [{"ServiceType": "Interface"}],
                    "AvailabilityZones": ["us-east-2a", "us-east-2b", "us-east-2c"],
                }
            ]
        },
        "state-kms.json": {
            "KeyMetadata": {
                "Arn": CHECKER.STATE_KMS_KEY_ARN,
                "Enabled": True,
                "KeyState": "Enabled",
                "KeyUsage": "ENCRYPT_DECRYPT",
            }
        },
    }
    for filename, value in fixtures.items():
        write_json(root / filename, value)


class PreflightTests(unittest.TestCase):
    def test_preflight_script_preserves_exact_cell_simulation_boundaries(self) -> None:
        preflight = PREFLIGHT_SCRIPT_PATH.read_text(encoding="utf-8")

        def shell_array(name: str) -> tuple[str, ...]:
            match = re.search(
                rf"^{name}=\(\n(?P<body>(?:  [^\n]+\n)+)\)$", preflight, re.M
            )
            self.assertIsNotNone(match)
            assert match is not None
            return tuple(line.strip() for line in match.group("body").splitlines())

        self.assertEqual(
            shell_array("control_write_actions"), CHECKER.CONTROL_WRITE_ACTIONS
        )
        self.assertEqual(
            shell_array("control_read_actions"), CHECKER.CONTROL_READ_ACTIONS
        )
        self.assertIn('control_actions=("${control_write_actions[@]}"', preflight)
        self.assertIn('"${control_read_actions[@]}")', preflight)
        self.assertIn(
            '--action-names "${control_write_actions[@]}"', preflight
        )
        self.assertIn('--action-names "${control_read_actions[@]}"', preflight)
        self.assertIn("cell-write-simulation.json", preflight)
        self.assertIn("cell-read-simulation.json", preflight)
        self.assertNotIn('"$evidence_dir/cell-simulation.json"', preflight)
        self.assertEqual(
            preflight.count(
                "ContextKeyName=aws:ResourceAccount,"
                "ContextKeyValues=${account_id},ContextKeyType=string"
            ),
            3,
        )
        self.assertEqual(
            preflight.count(
                "ContextKeyName=aws:RequestedRegion,"
                "ContextKeyValues=${region},ContextKeyType=string"
            ),
            3,
        )
        cell_write_command = preflight[
            preflight.rfind(
                "aws iam simulate-principal-policy",
                0,
                preflight.index('>"$evidence_dir/cell-write-simulation.json"'),
            ) : preflight.index('>"$evidence_dir/cell-write-simulation.json"')
        ]
        self.assertIn(
            "ContextKeyName=aws:RequestedRegion,"
            "ContextKeyValues=${region},ContextKeyType=string",
            cell_write_command,
        )
        self.assertIn(
            "ContextKeyName=aws:ResourceAccount,"
            "ContextKeyValues=${account_id},ContextKeyType=string",
            cell_write_command,
        )

    def test_exact_preflight_passes_and_drift_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            preflight_fixture(root)
            self.assertEqual(CHECKER.check_preflight(root)["attachment_count"], 10)

            state = json.loads((root / "state-status.json").read_text())
            state["state_exists"] = True
            write_json(root / "state-status.json", state)
            with self.assertRaises(CHECKER.ContractError):
                CHECKER.check_preflight(root)

    def test_present_state_mode_requires_exact_encrypted_versioned_object(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            preflight_fixture(root)
            state = json.loads((root / "state-status.json").read_text())
            state["state_exists"] = True
            write_json(root / "state-status.json", state)
            state_head = {
                "ContentLength": 123,
                "ServerSideEncryption": "aws:kms",
                "SSEKMSKeyId": CHECKER.STATE_KMS_KEY_ARN,
                "VersionId": "state-version",
            }
            write_json(root / "state-head.json", state_head)
            write_json(root / "otp-secret-versions.json", {"Versions": []})
            write_json(root / "otp-cache.json", {"exists": False})
            self.assertEqual(
                CHECKER.check_preflight(root, "present")["attachment_count"], 10
            )

            for key, value in (
                ("ContentLength", 0),
                ("ServerSideEncryption", "AES256"),
                ("SSEKMSKeyId", "wrong"),
                ("VersionId", "null"),
            ):
                with self.subTest(key=key):
                    broken = dict(state_head)
                    broken[key] = value
                    write_json(root / "state-head.json", broken)
                    with self.assertRaises(CHECKER.ContractError):
                        CHECKER.check_preflight(root, "present")

            write_json(root / "state-head.json", state_head)
            for filename, value in (
                ("otp-secret-versions.json", {"Versions": [{"VersionId": "seeded"}]}),
                ("otp-cache.json", {"exists": True}),
            ):
                with self.subTest(filename=filename):
                    preflight_fixture(root)
                    state = json.loads((root / "state-status.json").read_text())
                    state["state_exists"] = True
                    write_json(root / "state-status.json", state)
                    write_json(root / "state-head.json", state_head)
                    write_json(root / "otp-secret-versions.json", {"Versions": []})
                    write_json(root / "otp-cache.json", {"exists": False})
                    write_json(root / filename, value)
                    with self.assertRaises(CHECKER.ContractError):
                        CHECKER.check_preflight(root, "present")

    def test_cell_grant_and_quota_drift_fail(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            preflight_fixture(root)
            write_json(
                root / "cell-write-simulation.json",
                simulation(
                    CHECKER.CONTROL_WRITE_ACTIONS,
                    CHECKER.CELL_RESOURCES,
                    "allowed",
                ),
            )
            with self.assertRaises(CHECKER.ContractError):
                CHECKER.check_preflight(root)

    def test_cache_create_dependent_user_group_is_exactly_confined(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            preflight_fixture(root)
            write_json(
                root / "cache-control-dependency-simulation.json",
                cache_dependency_simulation(
                    CHECKER.CONTROL_CACHE_USER_GROUP_RESOURCE,
                    "implicitDeny",
                ),
            )
            with self.assertRaisesRegex(
                CHECKER.ContractError,
                "Control cache dependent user group composite",
            ):
                CHECKER.check_preflight(root)

            preflight_fixture(root)
            write_json(
                root / "cache-cell-dependency-simulation.json",
                cache_dependency_simulation(
                    CHECKER.CELL_CACHE_USER_GROUP_RESOURCE,
                    "allowed",
                ),
            )
            with self.assertRaisesRegex(
                CHECKER.ContractError,
                "cell cache dependent user group composite",
            ):
                CHECKER.check_preflight(root)

            preflight_fixture(root)
            malformed = cache_dependency_simulation(
                CHECKER.CONTROL_CACHE_USER_GROUP_RESOURCE, "allowed"
            )
            malformed["EvaluationResults"][0]["ResourceSpecificResults"].pop()
            write_json(root / "cache-control-dependency-simulation.json", malformed)
            with self.assertRaisesRegex(
                CHECKER.ContractError, "composite authorization matrix drifted"
            ):
                CHECKER.check_preflight(root)

            preflight_fixture(root)
            write_json(
                root / "account-summary.json",
                {"SummaryMap": {"AttachedPoliciesPerRoleQuota": 20}},
            )
            with self.assertRaises(CHECKER.ContractError):
                CHECKER.check_preflight(root)

    def test_cell_read_and_write_decisions_are_checked_separately(self) -> None:
        self.assertEqual(
            set(CHECKER.CONTROL_READ_ACTIONS),
            {
                "elasticache:DescribeUsers",
                "elasticache:DescribeUserGroups",
                "elasticache:ListTagsForResource",
            },
        )
        self.assertEqual(
            set(CHECKER.CONTROL_WRITE_ACTIONS)
            | set(CHECKER.CONTROL_READ_ACTIONS),
            set(CHECKER.CONTROL_ACTIONS),
        )
        self.assertFalse(
            set(CHECKER.CONTROL_WRITE_ACTIONS)
            & set(CHECKER.CONTROL_READ_ACTIONS)
        )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            preflight_fixture(root)
            write_json(
                root / "cell-read-simulation.json",
                simulation(
                    CHECKER.CONTROL_READ_ACTIONS,
                    CHECKER.CELL_RESOURCES,
                    "implicitDeny",
                ),
            )
            with self.assertRaisesRegex(
                CHECKER.ContractError,
                "cell read simulation does not match exact allowed matrix",
            ):
                CHECKER.check_preflight(root)

    def test_cell_write_tolerates_only_exact_impossible_service_context_keys(
        self,
    ) -> None:
        self.assertEqual(
            CHECKER.CELL_WRITE_IMPOSSIBLE_CONTEXT_KEYS,
            {
                "cloudwatch:namespace",
                "iam:AWSServiceName",
                "iam:PassedToService",
                "route53:ChangeResourceRecordSetsNormalizedRecordNames",
                "ssm:resourceTag/Environment",
            },
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            preflight_fixture(root)
            payload = json.loads(
                (root / "cell-write-simulation.json").read_text(encoding="utf-8")
            )
            payload["EvaluationResults"][0]["MissingContextValues"] = sorted(
                CHECKER.CELL_WRITE_IMPOSSIBLE_CONTEXT_KEYS
            )
            write_json(root / "cell-write-simulation.json", payload)
            self.assertEqual(CHECKER.check_preflight(root)["attachment_count"], 10)

            payload = simulation(
                CHECKER.CONTROL_WRITE_ACTIONS,
                CHECKER.CELL_RESOURCES,
                "allowed",
            )
            payload["EvaluationResults"][0]["MissingContextValues"] = sorted(
                CHECKER.CELL_WRITE_IMPOSSIBLE_CONTEXT_KEYS
            )
            write_json(root / "cell-write-simulation.json", payload)
            with self.assertRaisesRegex(
                CHECKER.ContractError,
                "cell write simulation does not match exact implicitDeny matrix",
            ):
                CHECKER.check_preflight(root)

            preflight_fixture(root)
            payload = json.loads(
                (root / "cell-write-simulation.json").read_text(encoding="utf-8")
            )

            for key_name in (
                "aws:ResourceAccount",
                "aws:RequestedRegion",
                "aws:RequestTag/Owner\n::error::injected",
                "iam:NewServiceContextKey",
            ):
                with self.subTest(key_name=key_name):
                    payload["EvaluationResults"][0]["MissingContextValues"] = [
                        *sorted(CHECKER.CELL_WRITE_IMPOSSIBLE_CONTEXT_KEYS),
                        key_name,
                    ]
                    write_json(root / "cell-write-simulation.json", payload)
                    with self.assertRaises(CHECKER.ContractError) as raised:
                        CHECKER.check_preflight(root)
                    self.assertEqual(
                        str(raised.exception),
                        "cell write simulation has missing context keys: "
                        + json.dumps([key_name], separators=(",", ":")),
                    )

    def test_other_simulations_reject_cell_write_context_exceptions(self) -> None:
        for filename in ("control-simulation.json", "cell-read-simulation.json"):
            with (
                self.subTest(filename=filename),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory)
                preflight_fixture(root)
                payload = json.loads((root / filename).read_text(encoding="utf-8"))
                payload["EvaluationResults"][0]["MissingContextValues"] = [
                    "iam:PassedToService"
                ]
                write_json(root / filename, payload)
                with self.assertRaisesRegex(
                    CHECKER.ContractError,
                    "simulation has missing context keys",
                ):
                    CHECKER.check_preflight(root)

    def test_bucket_versioning_must_be_enabled(self) -> None:
        for value in ({}, {"Status": "Suspended"}):
            with (
                self.subTest(value=value),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory)
                preflight_fixture(root)
                write_json(root / "bucket-versioning.json", value)
                with self.assertRaises(CHECKER.ContractError):
                    CHECKER.check_preflight(root)


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
    authority_id = f"{CHECKER.CONTROL_PREFIX}-otp-auth"
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
            "user_id": authority_id,
            "user_name": authority_id,
            "access_string": "on ~connector:* -@all +@connection +@read +@write +@scripting",
            "authentication_mode": [{"password_count": 0, "type": "iam"}],
        }
    )
    by_address["module.control.aws_elasticache_user_group.otp"].update(
        {
            "user_group_id": f"{CHECKER.CONTROL_PREFIX}-otp-users",
            "user_ids": [default_id, authority_id],
        }
    )
    return {"values": {"root_module": {"resources": resources}}}


class StateContractTests(unittest.TestCase):
    def test_resource_inventory_contract_hash_is_reviewed(self) -> None:
        # Update only with an intentional, reviewed address/type inventory change.
        self.assertEqual(
            CHECKER.contract_sha256(),
            "a97f65c62d1a4c5a6e26f60ef95995b2bd31f24c8d7d5f18fa732fad1e9b4140",
        )

    def test_exact_state_passes(self) -> None:
        self.assertEqual(CHECKER.check_state(state_fixture())["resource_count"], 41)

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
                "module.control.aws_elasticache_user.otp_authority",
                "access_string",
                "on ~* +@all",
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
            "module.control.aws_elasticache_user.otp_authority",
            "module.control.aws_elasticache_user.otp_disabled_default",
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

    def test_disabled_user_lifecycle_ignore_is_narrow_and_fail_closed(self) -> None:
        redis = REDIS_TF_PATH.read_text(encoding="utf-8")
        self.assertEqual(
            redis.count("ignore_changes = [authentication_mode[0].type]"), 1
        )
        self.assertNotIn("ignore_changes = [authentication_mode]", redis)
        self.assertIn('["no-password-required", "no-password"]', redis)
        self.assertIn("self.authentication_mode[0].password_count == 0", redis)
        self.assertIn(
            'access_string = "on ~connector:* -@all +@connection +@read +@write +@scripting"',
            redis,
        )


def live_fixture(root: Path) -> None:
    expected = {
        "vpc_id": "vpc-abc123",
        "dynamodb_endpoint_id": "vpce-abc123",
        "flow_log_id": "fl-abc123",
        "flow_log_destination": "arn:aws:logs:flow-group",
        "flow_log_role_arn": "arn:aws:iam::role/flow",
        "isolated_route_table_ids": ["rtb-0abc", "rtb-1abc", "rtb-2abc"],
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


class SourceRunAndWorkflowTests(unittest.TestCase):
    def test_plain_run_scalars_cannot_hide_shell_continuations(self) -> None:
        workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
        offenders = [
            f"{line_number}: {line.strip()}"
            for line_number, line in enumerate(workflow.splitlines(), start=1)
            if re.match(r"^\s*run:\s+.*\\\s*$", line)
        ]
        self.assertEqual([], offenders)

    @staticmethod
    def initialize_checkout_repository(root: Path) -> Path:
        repository = root / "repository"
        subprocess.run(["git", "init", "--quiet", repository], check=True, text=True)
        subprocess.run(
            [
                "git",
                "-C",
                repository,
                "remote",
                "add",
                "origin",
                "https://github.com/layervai/nhp",
            ],
            check=True,
            text=True,
        )
        return repository

    @staticmethod
    def run_checkout_credential_check(
        repository: Path,
    ) -> subprocess.CompletedProcess[str]:
        env = dict(os.environ)
        env.pop("GH_TOKEN", None)
        env.pop("GITHUB_TOKEN", None)
        env["GITHUB_REPOSITORY"] = "layervai/nhp"
        return subprocess.run(
            [str(NO_CHECKOUT_CREDENTIALS_SCRIPT_PATH)],
            cwd=repository,
            env=env,
            check=False,
            capture_output=True,
            text=True,
        )

    def test_checkout_v7_include_credential_indirection_is_rejected(self) -> None:
        key = "http.https://github.com/.extraheader"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            repository = self.initialize_checkout_repository(root)
            credentials = root / "git-credentials.config"
            subprocess.run(
                [
                    "git",
                    "config",
                    "--file",
                    credentials,
                    key,
                    "AUTHORIZATION: basic checkout-v7-token",
                ],
                check=True,
                text=True,
            )
            subprocess.run(
                [
                    "git",
                    "-C",
                    repository,
                    "config",
                    "--local",
                    f"includeIf.gitdir:{repository}/.git.path",
                    str(credentials),
                ],
                check=True,
                text=True,
            )

            # This is the exact false-negative that motivated the fix: the
            # header is absent from .git/config but active through includeIf.
            local_only = subprocess.run(
                ["git", "config", "--local", "--get-regexp", "extraheader$"],
                cwd=repository,
                check=False,
                capture_output=True,
                text=True,
            )
            effective = subprocess.run(
                ["git", "config", "--get-regexp", "extraheader$"],
                cwd=repository,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(local_only.returncode, 1, local_only.stdout)
            self.assertEqual(effective.returncode, 0, effective.stderr)

            result = self.run_checkout_credential_check(repository)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("effective git config", result.stdout)

    def test_checkout_credential_boundary_accepts_nonpersistent_checkout(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = self.initialize_checkout_repository(
                Path(directory).resolve()
            )

            result = self.run_checkout_credential_check(repository)
            self.assertEqual(result.returncode, 0, result.stderr)

            leaked_env = dict(os.environ)
            leaked_env.pop("GITHUB_TOKEN", None)
            leaked_env.update(
                {
                    "GH_TOKEN": "leaked-step-token",
                    "GITHUB_REPOSITORY": "layervai/nhp",
                }
            )
            leaked = subprocess.run(
                [str(NO_CHECKOUT_CREDENTIALS_SCRIPT_PATH)],
                cwd=repository,
                env=leaked_env,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(leaked.returncode, 0)
            self.assertIn("Terraform step environment", leaked.stdout)

    def test_checkout_credential_boundary_rejects_dangling_include_and_url(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = self.initialize_checkout_repository(
                Path(directory).resolve()
            )
            subprocess.run(
                [
                    "git",
                    "-C",
                    repository,
                    "config",
                    "--local",
                    "includeIf.gitdir:/unmatched/worktree/.git.path",
                    "/tmp/git-credentials.config",
                ],
                check=True,
                text=True,
            )
            dangling = self.run_checkout_credential_check(repository)
            self.assertNotEqual(dangling.returncode, 0)
            self.assertIn("credential include", dangling.stdout)

            subprocess.run(
                [
                    "git",
                    "-C",
                    repository,
                    "config",
                    "--local",
                    "--unset-all",
                    "includeIf.gitdir:/unmatched/worktree/.git.path",
                ],
                check=True,
                text=True,
            )
            subprocess.run(
                [
                    "git",
                    "-C",
                    repository,
                    "remote",
                    "set-url",
                    "origin",
                    "https://token@github.com/layervai/nhp",
                ],
                check=True,
                text=True,
            )
            embedded_url = self.run_checkout_credential_check(repository)
            self.assertNotEqual(embedded_url.returncode, 0)
            self.assertIn("origin URL", embedded_url.stdout)

    def test_live_main_check_uses_authenticated_github_api(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            log_path = root / "gh.log"
            fake_gh = fake_bin / "gh"
            fake_gh.write_text(
                "#!/usr/bin/env bash\n"
                "set -euo pipefail\n"
                'printf \'%s\\n\' "$*" >"$FAKE_GH_LOG"\n'
                "printf "
                "'{\"ref\":\"%s\",\"object\":{\"type\":\"%s\",\"sha\":\"%s\"}}\\n' "
                '"${FAKE_GH_REF:-refs/heads/main}" '
                '"${FAKE_GH_TYPE:-commit}" "$FAKE_GH_SHA"\n',
                encoding="utf-8",
            )
            fake_gh.chmod(0o755)
            expected_sha = "a" * 40
            env = {
                **os.environ,
                "PATH": f"{fake_bin}:{os.environ['PATH']}",
                "FAKE_GH_LOG": str(log_path),
                "FAKE_GH_SHA": expected_sha,
                "GH_TOKEN": "step-scoped-token",
                "GITHUB_REPOSITORY": "layervai/nhp",
            }
            success = subprocess.run(
                [str(LIVE_MAIN_SCRIPT_PATH), expected_sha],
                env=env,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(success.returncode, 0, success.stderr)
            self.assertEqual(
                log_path.read_text().strip(),
                "api repos/layervai/nhp/git/ref/heads/main",
            )

            mismatch = subprocess.run(
                [str(LIVE_MAIN_SCRIPT_PATH), "b" * 40],
                env=env,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(mismatch.returncode, 0)
            self.assertIn("does not exactly match", mismatch.stderr)

    def test_source_run_binding(self) -> None:
        run = {
            "id": 12345,
            "event": "workflow_dispatch",
            "status": "completed",
            "conclusion": "success",
            "head_branch": "main",
            "head_sha": "a" * 40,
            "name": CHECKER.WORKFLOW_NAME,
            "path": CHECKER.WORKFLOW_PATH,
            "repository": {"full_name": CHECKER.REPOSITORY},
            "actor": {"login": CHECKER.TRUSTED_ACTOR},
            "triggering_actor": {"login": CHECKER.TRUSTED_ACTOR},
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "run.json"
            write_json(path, run)
            args = argparse.Namespace(
                run_json=path, run_id="12345", commit_sha="a" * 40
            )
            CHECKER.check_source_run(args)
            run["conclusion"] = "failure"
            write_json(path, run)
            with self.assertRaises(CHECKER.ContractError):
                CHECKER.check_source_run(args)
            run["conclusion"] = "success"
            for actor_field in ("actor", "triggering_actor"):
                with self.subTest(actor_field=actor_field):
                    run[actor_field]["login"] = "different-operator"
                    write_json(path, run)
                    with self.assertRaises(CHECKER.ContractError):
                        CHECKER.check_source_run(args)
                    run[actor_field]["login"] = CHECKER.TRUSTED_ACTOR

    def test_failed_apply_binding_is_exact(self) -> None:
        run = {
            "id": int(CHECKER.FAILED_APPLY_RUN_ID),
            "event": "workflow_dispatch",
            "status": "completed",
            "conclusion": "failure",
            "head_branch": "main",
            "head_sha": CHECKER.FAILED_APPLY_COMMIT,
            "name": CHECKER.WORKFLOW_NAME,
            "path": CHECKER.WORKFLOW_PATH,
            "repository": {"full_name": CHECKER.REPOSITORY},
            "actor": {"login": CHECKER.TRUSTED_ACTOR},
            "triggering_actor": {"login": CHECKER.TRUSTED_ACTOR},
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "failed-run.json"
            write_json(path, run)
            CHECKER.check_failed_run(path)
            for field, value in (
                ("id", 1),
                ("conclusion", "success"),
                ("head_sha", "a" * 40),
            ):
                with self.subTest(field=field):
                    broken = copy.deepcopy(run)
                    broken[field] = value
                    write_json(path, broken)
                    with self.assertRaises(CHECKER.ContractError):
                        CHECKER.check_failed_run(path)

    def test_workflow_and_ledger_fence_sandbox_only_two_dispatch(self) -> None:
        workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
        verifier = VERIFY_SCRIPT_PATH.read_text(encoding="utf-8")
        secret_seed = SECRET_SEED_SCRIPT_PATH.read_text(encoding="utf-8")
        preflight = PREFLIGHT_SCRIPT_PATH.read_text(encoding="utf-8")
        live_main = LIVE_MAIN_SCRIPT_PATH.read_text(encoding="utf-8")
        ledger = LEDGER_PATH.read_text(encoding="utf-8")
        for token in (
            "source_plan_run_id",
            "planned_commit_sha",
            "plan_sha256",
            "ACCEPT_SANDBOX_CONTROL_STANDING_COST",
            "APPLY_SANDBOX_CONTROL_FOUNDATION",
            "group: deploy-sandbox-infra",
            "actions/download-artifact@",
            "run-id: ${{ inputs.source_plan_run_id }}",
            "secrets.AWS_ROLE_ARN",
            "terraform apply -input=false",
            "verify-control-sandbox-first-apply.sh",
            "ORIGINAL_ACTOR: ${{ github.actor }}",
            "TRIGGERING_ACTOR: ${{ github.triggering_actor }}",
            "Only justin-layerv may originate and trigger",
        ):
            self.assertIn(token, workflow)
        self.assertEqual(workflow.count("TF_VERSION:"), 1)
        self.assertIn(f"TF_VERSION: '{CHECKER.TF_VERSION}'", workflow)
        self.assertEqual(workflow.count("environment: sandbox"), 5)
        self.assertEqual(workflow.count("Re-read live main before AWS access"), 5)
        self.assertEqual(workflow.count("scripts/check-live-main-ref.sh"), 7)
        self.assertEqual(
            workflow.count("scripts/check-no-checkout-credentials.sh"), 7
        )
        self.assertEqual(workflow.count("GH_TOKEN: ${{ github.token }}"), 10)
        for recovery_token in (
            "recover-plan",
            "recover-apply",
            "RECOVER_PLAN_ONLY",
            "RECOVER_APPLY_SANDBOX_CONTROL_FOUNDATION",
            "recovery-artifact-create",
            "recovery-artifact-verify",
            "capture-control-sandbox-partial-recovery-state.sh",
            "--expected-action recover",
            "29673343567",
        ):
            self.assertIn(recovery_token, workflow)
        self.assertIn('gh api "repos/$repository/git/ref/heads/main"', live_main)
        self.assertNotIn("git ls-remote", live_main)
        terraform_apply = workflow.index("terraform apply -input=false")
        final_ref_check = workflow.rfind(
            "scripts/check-live-main-ref.sh", 0, terraform_apply
        )
        final_credential_check = workflow.rfind(
            "scripts/check-no-checkout-credentials.sh", 0, terraform_apply
        )
        self.assertGreater(final_ref_check, -1)
        self.assertGreater(final_credential_check, -1)
        self.assertLess(final_ref_check, terraform_apply)
        self.assertLess(final_ref_check, final_credential_check)
        self.assertLess(final_credential_check, terraform_apply)
        self.assertIn(
            "      - name: Re-read live main immediately before exact apply\n"
            "        working-directory: ${{ env.CONTROL_ROOT }}\n"
            "        env:\n"
            "          GH_TOKEN: ${{ github.token }}\n"
            "          PLANNED_COMMIT_SHA: ${{ inputs.planned_commit_sha }}\n"
            '        run: ../../../../scripts/check-live-main-ref.sh '
            '"$PLANNED_COMMIT_SHA"\n\n'
            "      - name: Apply exact saved plan without GitHub credentials\n"
            "        working-directory: ${{ env.CONTROL_ROOT }}\n"
            "        run: |\n"
            "          ../../../../scripts/check-no-checkout-credentials.sh\n"
            "          terraform apply -input=false",
            workflow,
        )
        for forbidden in (
            "AWS_PROD_ROLE_ARN",
            "terraform/control/environments/prod",
            "environment: production",
            "get-secret-value",
        ):
            self.assertNotIn(forbidden, workflow)
        self.assertIn('[[ "${#generated_secret}" -ne 48 ]]', secret_seed)
        self.assertIn("printf '%s' \"$generated_secret\"", secret_seed)
        self.assertIn(
            'client_request_token="$(printf \'%s\' "$secret_arn" | sha256sum',
            secret_seed,
        )
        self.assertIn('--client-request-token "$client_request_token"', secret_seed)
        self.assertNotIn("get-secret-value", verifier)
        self.assertNotIn("get-secret-value", secret_seed)
        self.assertIn("aws s3api get-bucket-versioning", preflight)
        self.assertIn("Control Sandbox First Apply", ledger)
        self.assertIn("separate apply dispatch", ledger)
        self.assertIn("plan assumes the apply-capable sandbox role", ledger)
        self.assertIn("newly enabled region blocks the routing audit", ledger)
        self.assertIn("cannot target production", ledger)
        self.assertIn(
            "#3349 advances the read-only PR-plan gate from the completed "
            "`recover-config` shape to an exact 41-resource no-op",
            ledger,
        )
        self.assertIn(
            "Never rerun the original apply, recovery plan, or recovery apply",
            ledger,
        )

    def test_security_helpers_remain_in_workflow_lint_boundary(self) -> None:
        validate_workflow = VALIDATE_WORKFLOW_PATH.read_text(encoding="utf-8")
        makefile = MAKEFILE_PATH.read_text(encoding="utf-8")
        boundary_step = validate_workflow.split(
            "      - name: Test sandbox Control first-apply boundary\n", 1
        )[1].split("\n      - name:", 1)[0]
        make_shellcheck = next(
            line
            for line in makefile.splitlines()
            if line.startswith("\t@shellcheck ")
            and "capture-control-sandbox-first-apply-preflight.sh" in line
        )

        for helper in (
            "scripts/capture-control-sandbox-partial-recovery-state.sh",
            "scripts/check-live-main-ref.sh",
            "scripts/check-no-checkout-credentials.sh",
            "scripts/ensure-control-otp-pepper.sh",
        ):
            self.assertIn(f'- "{helper}"', validate_workflow)
            self.assertIn(helper, boundary_step)
            self.assertIn(helper, make_shellcheck)
        self.assertIn(
            '- "tests/scripts/**"',
            validate_workflow,
        )

    def test_real_pr_plan_runs_strict_noop_contract(self) -> None:
        workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
        plan_workflow = TERRAFORM_PLAN_WORKFLOW_PATH.read_text(encoding="utf-8")
        foundation_check = plan_workflow.index(
            "      - name: Check Terraform Control Plan Contract\n"
        )
        strict_check = plan_workflow.index(
            "      - name: Check Terraform Control No-Op Plan Contract\n"
        )
        summary = plan_workflow.index(
            "      - name: Summarize Terraform Control Plan\n"
        )

        self.assertLess(foundation_check, strict_check)
        self.assertLess(strict_check, summary)
        self.assertIn(
            "python3 .github/scripts/check-control-sandbox-first-apply.py plan "
            "terraform/control/environments/sandbox/control.tfplan.json "
            "--expected-action no-op",
            plan_workflow,
        )
        self.assertIn(
            "recovered foundation must remain an exact",
            plan_workflow,
        )
        self.assertNotIn("--expected-action recover-config", plan_workflow)
        self.assertNotIn("Partial-Recovery Plan Contract", plan_workflow)
        self.assertEqual(workflow.count("persist-credentials: false"), 5)
        self.assertNotIn("persist-credentials: true", workflow)
        self.assertNotIn("--unset-all http.https://github.com/.extraheader", workflow)


if __name__ == "__main__":
    unittest.main(verbosity=2)
