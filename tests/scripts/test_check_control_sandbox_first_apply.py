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
REAL_TERRAFORM_NOOP_FIXTURE_PATH = (
    ROOT / "tests/fixtures/qurl-agent-transact-iam/no-op-terraform-1.14.3.json"
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


def plan_fixture() -> dict:
    security = planned_security_fixture()
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


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value), encoding="utf-8")


def terraform_1_14_refresh_only_golden(candidate: dict) -> dict:
    """Build the exact empirically observed Terraform 1.14 plan/state shape.

    The Control values remain the complete synthetic security fixture so every
    field can be mutated hermetically. The JSON envelope is the real 1.14.3
    shape: no ``resource_changes``, empty ``planned_values.root_module``, and a
    separate format-1.0 state containing the unchanged inventory.
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
    candidate["planned_values"] = {"root_module": {}}
    return {
        "format_version": "1.0",
        "terraform_version": CHECKER.TF_VERSION,
        "values": {
            "root_module": {
                "child_modules": [
                    {"address": "module.control", "resources": resources}
                ]
            }
        },
    }


class PlanContractTests(unittest.TestCase):
    def test_real_terraform_1_14_3_noop_status_contract(self) -> None:
        real_noop = json.loads(
            REAL_TERRAFORM_NOOP_FIXTURE_PATH.read_text(encoding="utf-8")
        )
        self.assertEqual(real_noop["terraform_version"], CHECKER.TF_VERSION)

        candidate = plan_fixture()
        for field in ("format_version", "complete", "errored", "applyable"):
            candidate[field] = real_noop[field]
        self.assertEqual(CHECKER.check_plan(candidate)["resource_count"], 43)

    def test_exact_noop_passes(self) -> None:
        self.assertEqual(CHECKER.check_plan(plan_fixture())["resource_count"], 43)
        unrefreshed = plan_fixture()
        unrefreshed_role = self.change(
            unrefreshed, "module.control.aws_iam_role.authority_publisher"
        )
        unrefreshed_role["before"]["inline_policy"] = []
        unrefreshed_role["after"]["inline_policy"] = []
        self.assertEqual(CHECKER.check_plan(unrefreshed)["resource_count"], 43)

        normalized = plan_fixture()
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
        self.assertEqual(CHECKER.check_plan(normalized)["resource_count"], 43)

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
                self.assertEqual(
                    CHECKER.check_plan(candidate)["bootstrap_create_count"],
                    len(create_addresses),
                )

    def test_exact_publisher_refresh_only_normalization_passes(self) -> None:
        candidate = plan_fixture()
        candidate["applyable"] = True
        role_change = self.change(
            candidate, "module.control.aws_iam_role.authority_publisher"
        )
        candidate["resource_drift"] = [
            {
                "address": "module.control.aws_iam_role.authority_publisher",
                "mode": "managed",
                "type": "aws_iam_role",
                "change": {
                    "actions": ["update"],
                    "after_sensitive": False,
                    "after_unknown": {},
                    "before": {
                        **copy.deepcopy(role_change["after"]),
                        "inline_policy": [],
                    },
                    "before_sensitive": False,
                    "after": copy.deepcopy(role_change["after"]),
                },
            }
        ]
        prior_state = terraform_1_14_refresh_only_golden(candidate)
        prior_role = next(
            item
            for item in prior_state["values"]["root_module"]["child_modules"][0][
                "resources"
            ]
            if item["address"]
            == "module.control.aws_iam_role.authority_publisher"
        )
        prior_role["values"] = copy.deepcopy(
            candidate["resource_drift"][0]["change"]["before"]
        )

        summary = CHECKER.check_plan(candidate, prior_state)

        self.assertEqual(summary["bootstrap_create_count"], 0)
        self.assertEqual(summary["normalization_drift_count"], 1)
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

    def test_publisher_refresh_only_normalization_is_exact(self) -> None:
        def refresh_candidate() -> tuple[dict, dict]:
            candidate = plan_fixture()
            candidate["applyable"] = True
            role_change = self.change(
                candidate, "module.control.aws_iam_role.authority_publisher"
            )
            candidate["resource_drift"] = [
                {
                    "address": "module.control.aws_iam_role.authority_publisher",
                    "mode": "managed",
                    "type": "aws_iam_role",
                    "change": {
                        "actions": ["update"],
                        "after_sensitive": False,
                        "after_unknown": {},
                        "before": {
                            **copy.deepcopy(role_change["after"]),
                            "inline_policy": [],
                        },
                        "before_sensitive": False,
                        "after": copy.deepcopy(role_change["after"]),
                    },
                }
            ]
            prior_state = terraform_1_14_refresh_only_golden(candidate)
            prior_role = next(
                item
                for item in prior_state["values"]["root_module"]["child_modules"][0][
                    "resources"
                ]
                if item["address"]
                == "module.control.aws_iam_role.authority_publisher"
            )
            prior_role["values"] = copy.deepcopy(
                candidate["resource_drift"][0]["change"]["before"]
            )
            return candidate, prior_state

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
        sensitive_value["resource_drift"][0]["change"]["after_sensitive"] = {
            "permissions_boundary": True
        }
        self.assert_rejected(sensitive_value, sensitive_value_state)

        nonempty_sensitive, nonempty_sensitive_state = refresh_candidate()
        nonempty_sensitive["resource_drift"][0]["change"]["before_sensitive"] = {
            "permissions_boundary": True
        }
        nonempty_sensitive["resource_drift"][0]["change"]["after_sensitive"] = {
            "permissions_boundary": True
        }
        self.assert_rejected(nonempty_sensitive, nonempty_sensitive_state)

        integer_sensitive, integer_sensitive_state = refresh_candidate()
        integer_sensitive["resource_drift"][0]["change"]["before_sensitive"] = 0
        integer_sensitive["resource_drift"][0]["change"]["after_sensitive"] = 0
        self.assert_rejected(integer_sensitive, integer_sensitive_state)

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
        mismatched_role = next(
            item
            for item in mismatched_prior_state["values"]["root_module"][
                "child_modules"
            ][0]["resources"]
            if item["address"]
            == "module.control.aws_iam_role.authority_publisher"
        )
        mismatched_role["values"]["max_session_duration"] = 7200
        self.assert_rejected(mismatched_prior, mismatched_prior_state)

        state_security, state_security_prior = refresh_candidate()
        kms_endpoint = next(
            item
            for item in state_security_prior["values"]["root_module"][
                "child_modules"
            ][0]["resources"]
            if item["address"]
            == 'module.control.aws_vpc_endpoint.interface["kms"]'
        )
        kms_endpoint["values"]["private_dns_enabled"] = False
        self.assert_rejected(state_security, state_security_prior)

        malformed_resource_changes, malformed_state = refresh_candidate()
        malformed_resource_changes["resource_changes"] = None
        self.assert_rejected(malformed_resource_changes, malformed_state)

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

    def assert_rejected(self, plan: dict, prior_state: object = None) -> None:
        with self.assertRaises(CHECKER.ContractError):
            CHECKER.check_plan(plan, prior_state)

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
            {"data_resource_count": 4, "managed_resource_count": 43},
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
            "54b15989ec63a4d15b019fb8c4ee2e65e8fccdb5ac71bbc735ac38edea24913a",
        )

    def test_exact_state_passes(self) -> None:
        self.assertEqual(CHECKER.check_state(state_fixture())["resource_count"], 43)

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


if __name__ == "__main__":
    unittest.main(verbosity=2)
