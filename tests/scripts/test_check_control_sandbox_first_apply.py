#!/usr/bin/env python3
"""Hermetic fail-closed tests for the sandbox Control foundation boundary."""

from __future__ import annotations

import copy
import base64
import hashlib
import importlib.util
import json
import os
import re
import subprocess
import tempfile
import pathlib
import unittest
from unittest import mock
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CHECKER_PATH = ROOT / ".github/scripts/check-control-sandbox-first-apply.py"
VALIDATE_WORKFLOW_PATH = ROOT / ".github/workflows/validate-workflows.yml"
TERRAFORM_PLAN_WORKFLOW_PATH = ROOT / ".github/workflows/terraform-plan-pr.yml"
GATES_READER_PATH = ROOT / ".github/scripts/control-sandbox-runtime-gates.py"
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
HUB_WORKER_TF_PATH = (
    ROOT / "terraform/modules/connector-authority-foundation/hub_worker.tf"
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
PROD_CONTROL_VARIABLES_PATH = (
    ROOT / "terraform/control/environments/prod/variables.tf"
)
EXPECTED_AWS_PROVIDER_VERSION = "6.55.0"
REAL_TERRAFORM_NOOP_FIXTURE_PATH = (
    ROOT / "tests/fixtures/terraform/no-op-envelope-1.14.3.json"
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
REAL_HUB_SOURCE_FENCE_ENVELOPES_PATH = (
    ROOT
    / "tests/fixtures/control-hub-source-fence/"
    "hub-replacement-terraform-1.14.3-aws-6.55.0.json"
)
SPEC = importlib.util.spec_from_file_location("control_first_apply", CHECKER_PATH)
assert SPEC and SPEC.loader
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)


class AuthorityProofRolloutTransitionTests(unittest.TestCase):
    @staticmethod
    def foundation(selected=None, prepared=None):
        value = {
            "input": {
                "authority_runtime_contract": {"selected_authority_color": "blue"},
            }
        }
        if selected is not None or prepared is not None:
            value["input"].update(
                {
                    "authority_proof_policy_consumers_staged": True,
                    "authority_proof_policy_selected_color": selected,
                    "authority_proof_policy_prepared_color": prepared,
                }
            )
        return value

    def test_prepare_promote_rollback_sequence_is_closed(self):
        self.assertEqual(
            CHECKER._authority_proof_rollout_transition(
                self.foundation(), self.foundation("blue", "green")
            ),
            "prepare",
        )
        self.assertEqual(
            CHECKER._authority_proof_rollout_transition(
                self.foundation("blue", "green"),
                self.foundation("green", "green"),
            ),
            "selector",
        )
        self.assertEqual(
            CHECKER._authority_proof_rollout_transition(
                self.foundation("green", "green"),
                self.foundation("green", "blue"),
            ),
            "prepare",
        )
        self.assertEqual(
            CHECKER._authority_proof_rollout_transition(
                self.foundation("green", "blue"),
                self.foundation("blue", "blue"),
            ),
            "selector",
        )

    def test_selector_cannot_skip_prepare_or_move_both_fields(self):
        self.assertIsNone(
            CHECKER._authority_proof_rollout_transition(
                self.foundation(), self.foundation("green", "green")
            )
        )
        self.assertIsNone(
            CHECKER._authority_proof_rollout_transition(
                self.foundation("blue", "green"),
                self.foundation("green", "blue"),
            )
        )

    def test_selected_colors_keep_recovery_on_contract_basis(self):
        self.assertEqual(
            CHECKER._authority_proof_selected_colors(
                self.foundation("green", "green")
            ),
            {
                CHECKER.AUTHORITY_PROOF_FUNCTION_NAME: "green",
                CHECKER.AUTHORITY_PROOF_RECOVERY_FUNCTION_NAME: "blue",
            },
        )

    def test_plan_tracks_rollout_resources_and_service_revision(self):
        checker_source = CHECKER_PATH.read_text()
        self.assertRegex(
            checker_source,
            re.compile(
                r"if proof_rollout_mode:\s+"
                r"expected_resources\.update"
                r"\(AUTHORITY_PROOF_ROLLOUT_RESOURCES\)"
            ),
        )

        hub_worker_source = HUB_WORKER_TF_PATH.read_text()
        service = hub_worker_source.split(
            'resource "aws_ecs_service" "hub" {', 1
        )[1]
        lifecycle = service.split("lifecycle {", 1)[1].split("}", 1)[0]
        self.assertRegex(lifecycle, r"ignore_changes\s*=\s*\[desired_count\]")
        self.assertNotIn("task_definition", lifecycle)

    def test_initial_prepare_reconciles_only_to_planned_hub_revision(self):
        service_before = {
            "name": "layerv-nhp-sandbox-control-hub",
            "desired_count": 2,
            "task_definition": "arn:aws:ecs:us-east-2:767397897469:task-definition/hub:6",
        }
        planned_arn = (
            "arn:aws:ecs:us-east-2:767397897469:task-definition/hub:7"
        )
        by_address = {
            CHECKER.HUB_WORKER_TASK_DEFINITION_ADDRESS: {
                "change": {"after": {"arn": planned_arn}}
            },
            CHECKER.HUB_WORKER_SERVICE_ADDRESS: {
                "change": {
                    "actions": ["update"],
                    "before": service_before,
                    "after": {
                        **service_before,
                        "task_definition": planned_arn,
                    },
                    "after_unknown": {},
                }
            },
        }

        CHECKER._check_hub_service_task_revision_update(
            by_address, require_planned_target=True
        )

        wrong_target = copy.deepcopy(by_address)
        wrong_target[CHECKER.HUB_WORKER_SERVICE_ADDRESS]["change"]["after"][
            "task_definition"
        ] = f"{planned_arn.rsplit(':', 1)[0]}:8"
        with self.assertRaisesRegex(CHECKER.ContractError, "planned task revision"):
            CHECKER._check_hub_service_task_revision_update(
                wrong_target, require_planned_target=True
            )

        widened = copy.deepcopy(by_address)
        widened[CHECKER.HUB_WORKER_SERVICE_ADDRESS]["change"]["after"][
            "desired_count"
        ] = 3
        with self.assertRaisesRegex(CHECKER.ContractError, "only the Hub task revision"):
            CHECKER._check_hub_service_task_revision_update(
                widened, require_planned_target=True
            )

    def test_runtime_normalization_is_scoped_to_proof_rollout_modes(self):
        self.assertTrue(
            {
                "authority-proof-rollout-prepare",
                "authority-proof-rollout-selector",
            }
            <= CHECKER._AUTHORITY_RUNTIME_NORMALIZATION_PLAN_MODES
        )
        self.assertNotIn(
            "authority-proof-enable",
            CHECKER._AUTHORITY_RUNTIME_NORMALIZATION_PLAN_MODES,
        )

    def test_partial_prepare_recovery_is_exact_and_includes_pm(self):
        actions = {}
        for function_name in CHECKER.AUTHORITY_PROOF_ROLLOUT_FUNCTIONS:
            actions[
                f'module.control.aws_lambda_function.authority["{function_name}"]'
            ] = ["update"]
            actions[
                f'module.control.aws_lambda_alias.authority["{function_name}:green"]'
            ] = ["update"]
            actions[
                "module.control.aws_lambda_provisioned_concurrency_config."
                f'authority_proof_standby["{function_name}"]'
            ] = (
                ["create"]
                if function_name == CHECKER.AUTHORITY_PROOF_FUNCTION_NAME
                else ["delete", "create"]
            )

        self.assertEqual(len(actions), 12)
        self.assertTrue(
            CHECKER._is_exact_authority_proof_rollout_prepare_recovery(
                actions,
                self.foundation("blue", "green"),
            )
        )
        self.assertIn(
            (
                "module.control.aws_lambda_alias.authority"
                f'["{CHECKER.AUTHORITY_PROOF_FUNCTION_NAME}:green"]'
            ),
            actions,
        )

        for label, mutate in {
            "missing": lambda candidate: candidate.pop(next(iter(candidate))),
            "extra": lambda candidate: candidate.update(
                {'module.control.aws_lambda_function.authority["foreign"]': ["update"]}
            ),
            "wrong action": lambda candidate: candidate.update(
                {
                    "module.control.aws_lambda_provisioned_concurrency_config."
                    f'authority_proof_standby["{CHECKER.AUTHORITY_PROOF_FUNCTION_NAME}"]': [
                        "delete",
                        "create",
                    ]
                }
            ),
        }.items():
            with self.subTest(label=label):
                malformed = copy.deepcopy(actions)
                mutate(malformed)
                self.assertFalse(
                    CHECKER._is_exact_authority_proof_rollout_prepare_recovery(
                        malformed,
                        self.foundation("blue", "green"),
                    )
                )

        self.assertFalse(
            CHECKER._is_exact_authority_proof_rollout_prepare_recovery(
                actions,
                self.foundation("green", "green"),
            )
        )

    @staticmethod
    def partial_prepare_recovery_resources():
        resources = {}
        descriptions = {
            function_name: (
                f"Connector Authority {operation} (sandbox)"
            )
            for function_name, operation in (
                CHECKER.AUTHORITY_RUNTIME_FUNCTIONS_WITH_PROOF.items()
            )
        }
        base_proof_variables = {
            "CONNECTOR_AUTHORITY_PROOF_OWNER_ID": CHECKER.AUTHORITY_PROOF_OWNER_ID,
            "CONNECTOR_AUTHORITY_PROOF_AGENT_ID_PREFIX": "qurl-go-sandbox-",
        }
        added_proof_variables = {
            "CONNECTOR_AUTHORITY_PROOF_DIRECTIVE_TTL": "5400",
            "CONNECTOR_AUTHORITY_PROOF_MIN_LEASE_SECONDS": "30",
        }
        for function_name in CHECKER.AUTHORITY_PROOF_ROLLOUT_FUNCTIONS:
            previous_version = (
                "2"
                if function_name == CHECKER.AUTHORITY_PROOF_FUNCTION_NAME
                else "8"
            )
            before_variables = dict(base_proof_variables)
            if function_name == CHECKER.AUTHORITY_PROOF_FUNCTION_NAME:
                before_variables.update(added_proof_variables)
            before = {
                "function_name": function_name,
                "description": descriptions[function_name],
                "environment": [{"variables": before_variables}],
                "architectures": ["x86_64"],
                "memory_size": 512,
                "timeout": 10,
                "package_type": "Image",
                "publish": True,
                "region": CHECKER.AWS_REGION,
                "role": (
                    f"arn:aws:iam::{CHECKER.ACCOUNT_ID}:role/{function_name}-exec"
                ),
                "qualified_arn": f"qualified:{function_name}:{previous_version}",
                "qualified_invoke_arn": (
                    f"qualified-invoke:{function_name}:{previous_version}"
                ),
                "version": previous_version,
            }
            after = copy.deepcopy(before)
            for field in ("qualified_arn", "qualified_invoke_arn", "version"):
                after.pop(field)
            if function_name == CHECKER.AUTHORITY_PROOF_FUNCTION_NAME:
                after["description"] = (
                    "Connector Authority mutate_proof_agent "
                    "(sandbox; proof-policy-prepared=green)"
                )
            else:
                after["environment"][0]["variables"].update(added_proof_variables)
            function_address = (
                f'module.control.aws_lambda_function.authority["{function_name}"]'
            )
            resources[function_address] = {
                "address": function_address,
                "mode": "managed",
                "module_address": "module.control",
                "name": "authority",
                "type": "aws_lambda_function",
                "index": function_name,
                "change": {
                    "actions": ["update"],
                    "before": before,
                    "after": after,
                    "after_unknown": {
                        "qualified_arn": True,
                        "qualified_invoke_arn": True,
                        "version": True,
                    },
                    "before_sensitive": {},
                    "after_sensitive": {},
                    "before_identity": CHECKER._authority_function_identity(
                        function_name
                    ),
                    "after_identity": CHECKER._authority_function_identity(
                        function_name
                    ),
                },
            }

            alias_address = (
                "module.control.aws_lambda_alias.authority"
                f'["{function_name}:green"]'
            )
            alias_before = {
                "function_name": function_name,
                "function_version": previous_version,
                "name": "green",
                "description": "Closed green deployment qualifier",
                "routing_config": [],
            }
            alias_after = copy.deepcopy(alias_before)
            alias_after.pop("function_version")
            resources[alias_address] = {
                "address": alias_address,
                "mode": "managed",
                "module_address": "module.control",
                "name": "authority",
                "type": "aws_lambda_alias",
                "index": f"{function_name}:green",
                "change": {
                    "actions": ["update"],
                    "before": alias_before,
                    "after": alias_after,
                    "after_unknown": {"function_version": True},
                    "before_sensitive": {},
                    "after_sensitive": {},
                },
            }

            pool_address = (
                "module.control.aws_lambda_provisioned_concurrency_config."
                f'authority_proof_standby["{function_name}"]'
            )
            pool_after = {
                "function_name": function_name,
                "provisioned_concurrent_executions": (
                    1
                    if function_name == CHECKER.AUTHORITY_PROOF_FUNCTION_NAME
                    else 2
                ),
                "qualifier": "green",
                "region": CHECKER.AWS_REGION,
                "skip_destroy": False,
                "timeouts": None,
            }
            is_pm = function_name == CHECKER.AUTHORITY_PROOF_FUNCTION_NAME
            resources[pool_address] = {
                "address": pool_address,
                "mode": "managed",
                "module_address": "module.control",
                "name": "authority_proof_standby",
                "type": "aws_lambda_provisioned_concurrency_config",
                "index": function_name,
                **({} if is_pm else {"action_reason": "replace_because_tainted"}),
                "change": {
                    "actions": ["create"] if is_pm else ["delete", "create"],
                    "before": (
                        None
                        if is_pm
                        else {
                            **pool_after,
                            "id": f"{function_name},green",
                            "provisioned_concurrent_executions": 0,
                        }
                    ),
                    "after": pool_after,
                    "after_unknown": {"id": True},
                    "before_sensitive": False if is_pm else {},
                    "after_sensitive": {},
                },
            }
        return resources

    def test_partial_prepare_recovery_rejects_field_level_bypasses(self):
        exact = self.partial_prepare_recovery_resources()
        CHECKER._check_authority_proof_rollout_prepare_recovery(
            exact,
            refresh_disabled=False,
        )
        refresh_disabled = copy.deepcopy(exact)
        for function_name in CHECKER.AUTHORITY_PROOF_CONSUMER_FUNCTIONS:
            address = (
                "module.control.aws_lambda_provisioned_concurrency_config."
                f'authority_proof_standby["{function_name}"]'
            )
            refresh_disabled[address]["change"]["before"][
                "provisioned_concurrent_executions"
            ] = 2
        CHECKER._check_authority_proof_rollout_prepare_recovery(
            refresh_disabled,
            refresh_disabled=True,
        )
        with self.assertRaises(CHECKER.ContractError):
            CHECKER._check_authority_proof_rollout_prepare_recovery(
                refresh_disabled,
                refresh_disabled=False,
            )

        ia_function = (
            'module.control.aws_lambda_function.authority["'
            'layerv-nhp-sandbox-ca-ia"]'
        )
        ia_alias = (
            'module.control.aws_lambda_alias.authority["'
            'layerv-nhp-sandbox-ca-ia:green"]'
        )
        ia_pool = (
            "module.control.aws_lambda_provisioned_concurrency_config."
            'authority_proof_standby["layerv-nhp-sandbox-ca-ia"]'
        )
        mutations = {
            "weighted alias routing": (
                ia_alias,
                ("change", "after", "routing_config"),
                [{"additional_version_weights": {"6": 0.5}}],
            ),
            "foreign function role": (
                ia_function,
                ("change", "after", "role"),
                f"arn:aws:iam::{CHECKER.ACCOUNT_ID}:role/foreign",
            ),
            "widened timeout": (
                ia_function,
                ("change", "after", "timeout"),
                900,
            ),
            "changed architecture": (
                ia_function,
                ("change", "after", "architectures"),
                ["arm64"],
            ),
            "fabricated pool before-state": (
                ia_pool,
                (
                    "change",
                    "before",
                    "provisioned_concurrent_executions",
                ),
                99,
            ),
        }
        for label, (address, path, value) in mutations.items():
            with self.subTest(label=label):
                candidate = copy.deepcopy(exact)
                target = candidate[address]
                for key in path[:-1]:
                    target = target[key]
                target[path[-1]] = value
                with self.assertRaises(CHECKER.ContractError):
                    CHECKER._check_authority_proof_rollout_prepare_recovery(
                        candidate,
                        refresh_disabled=False,
                    )


def applied_provisioned_cell_item(cell_id: str) -> str:
    """Render a catalog row the way a refreshed read renders it.

    The create plan carries the configuration's `jsonencode` text, but the
    provider re-renders `item` from the live AttributeValue map through Go's
    `json.Encoder`, which terminates the document with a newline. Steady-state
    fixtures must carry that applied spelling, not the create-time one.
    """
    return CHECKER.PROVISIONED_CELL_EXPECTED_ITEM_JSON[cell_id] + "\n"


def planned_security_fixture() -> dict[str, tuple[dict, dict]]:
    data_key_arn = (
        f"arn:aws:kms:{CHECKER.AWS_REGION}:{CHECKER.ACCOUNT_ID}:"
        "key/00000000-0000-0000-0000-000000000002"
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
    for address in CHECKER.PROVISIONED_CELL_RESOURCES:
        cell_id = address.rsplit('"', 2)[1]
        result[address] = (
            {
                "hash_key": "pk",
                "hash_key_value": "REGISTRY",
                "id": (
                    f"{CHECKER.PROVISIONED_CELL_TABLE_NAME}"
                    f",REGISTRY,CELL#{cell_id}"
                ),
                "item": applied_provisioned_cell_item(cell_id),
                "range_key": "sk",
                "range_key_value": f"CELL#{cell_id}",
                "region": CHECKER.AWS_REGION,
                "table_name": CHECKER.PROVISIONED_CELL_TABLE_NAME,
            },
            {},
        )
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
        for name in CHECKER.AUTHORITY_RUNTIME_FUNCTIONS
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
            "provisioned_cells": copy.deepcopy(
                CHECKER.AUTHORITY_CONNECTOR_RESOURCE_CELLS
            ),
            "provisioned_cells_evidence": copy.deepcopy(evidence),
            "global": {
                "authority_repository_url": repository,
                # These fixtures exercise the pinned path, which is still a
                # supported source and is what prod uses. Publish tracking has
                # its own cases below.
                "authority_image_source": "pinned_digest",
                "authority_image_digest": digest,
                "basis_evidence": copy.deepcopy(evidence),
                "result_evidence": None,
                "caller_capacity": {
                    "cell_workers": {
                        cell_id: {
                            "max_replicas": 2,
                            "preinvoke_limits": {
                                operation: 1
                                for operation in (
                                    CHECKER.AUTHORITY_CELL_OPERATION_SUFFIXES.values()
                                )
                            },
                            "preinvoke_rate_limits": {
                                operation: {
                                    "burst": 1,
                                    "refill_per_second": 1,
                                }
                                for operation in (
                                    CHECKER.AUTHORITY_CELL_OPERATION_SUFFIXES.values()
                                )
                            },
                        }
                        for cell_id in CHECKER.AUTHORITY_CELLS
                    },
                    "hub_workers": {
                        "max_replicas": 2,
                        "preinvoke_limits": {
                            operation: 1
                            for operation in (
                                CHECKER.AUTHORITY_RUNTIME_HUB_FUNCTIONS.values()
                            )
                        },
                        "preinvoke_rate_limits": {
                            operation: {
                                "burst": 1,
                                "refill_per_second": 1,
                            }
                            for operation in (
                                CHECKER.AUTHORITY_RUNTIME_HUB_FUNCTIONS.values()
                            )
                        },
                    },
                },
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
            if path == ("for_each",):
                by_address[address]["for_each_expression"] = {
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
            if (
                address in CHECKER.STANDALONE_RULE_SECURITY_GROUPS
                and path in CHECKER.STANDALONE_RULE_EMPTY_PATHS
            ):
                continue
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
        "planned_values": {
            "outputs": {
                "provisioned_cells": {
                    "sensitive": False,
                    "type": ["object", {}],
                    "value": copy.deepcopy(CHECKER.PROVISIONED_CELL_CATALOG),
                }
            }
        },
        "resource_drift": [],
        "resource_changes": changes,
    }


def provisioned_cell_catalog_holdback_fixture() -> dict:
    result = plan_fixture()
    result["resource_changes"] = [
        item
        for item in result["resource_changes"]
        if item["address"] not in CHECKER.PROVISIONED_CELL_RESOURCES
    ]
    result["planned_values"]["outputs"]["provisioned_cells"]["value"] = {}
    return result


def provisioned_cell_catalog_transition_fixture() -> dict:
    result = plan_fixture()
    result["applyable"] = True
    by_address = {
        item["address"]: item["change"] for item in result["resource_changes"]
    }
    for address in CHECKER.PROVISIONED_CELL_RESOURCES:
        cell_id = address.rsplit('"', 2)[1]
        change = by_address[address]
        change.update(
            {
                "actions": ["create"],
                "before": None,
                "after": {
                    "hash_key": "pk",
                    "item": CHECKER.PROVISIONED_CELL_EXPECTED_ITEM_JSON[cell_id],
                    "range_key": "sk",
                    "region": CHECKER.AWS_REGION,
                    "table_name": CHECKER.PROVISIONED_CELL_TABLE_NAME,
                },
                "after_unknown": {
                    "hash_key_value": True,
                    "id": True,
                    "range_key_value": True,
                },
                "before_sensitive": False,
                "after_sensitive": {},
                "after_identity": {
                    "account_id": None,
                    "hash_key_value": None,
                    "range_key_value": None,
                    "region": None,
                    "table_name": None,
                },
            }
        )
    result["planned_values"] = {
        "outputs": {
            "provisioned_cells": {
                "sensitive": False,
                "type": ["object", {}],
                "value": copy.deepcopy(CHECKER.PROVISIONED_CELL_CATALOG),
            }
        }
    }
    result["output_changes"] = {
        "provisioned_cells": {
            "actions": ["create"],
            "before": None,
            "after": copy.deepcopy(CHECKER.PROVISIONED_CELL_CATALOG),
            "after_unknown": False,
            "before_sensitive": False,
            "after_sensitive": False,
        }
    }
    return result


def with_provisioned_cell_catalog_transition(candidate: dict) -> dict:
    """Overlay the exact two-row catalog create onto another reviewed plan."""
    result = copy.deepcopy(candidate)
    catalog = provisioned_cell_catalog_transition_fixture()
    by_address = {
        item["address"]: item for item in result["resource_changes"]
    }
    catalog_by_address = {
        item["address"]: item for item in catalog["resource_changes"]
    }
    for address in CHECKER.PROVISIONED_CELL_RESOURCES:
        by_address[address]["change"] = copy.deepcopy(
            catalog_by_address[address]["change"]
        )
    result["planned_values"] = copy.deepcopy(catalog["planned_values"])
    result["output_changes"] = copy.deepcopy(catalog["output_changes"])
    result["applyable"] = True
    return result


def provisioned_cell_general_assignable_flip_fixture(
    cell_id: str = "cell1", value: bool = False
) -> dict:
    """A plan whose ONLY resource change is `cell_id` gaining an explicit
    general_assignable Boolean.

    Reuses the reviewed no-op catalog row as the steady before-state and adds
    only the general_assignable attribute to the after-item, so every other
    field -- status, weight, endpoint, keys, updated_at -- stays byte-identical.
    The public output surfaces general_assignable as a resolved Boolean for every
    cell (an assignable cell shows true even though its stored item omits it).
    """
    result = plan_fixture()
    result["applyable"] = True
    address = (
        f'module.control.aws_dynamodb_table_item.provisioned_cell["{cell_id}"]'
    )
    change = next(
        item["change"]
        for item in result["resource_changes"]
        if item["address"] == address
    )
    before_item = json.loads(change["before"]["item"])
    after_item = {**before_item, "general_assignable": {"BOOL": value}}
    change["actions"] = ["update"]
    change["after"] = copy.deepcopy(change["before"])
    change["after"]["item"] = json.dumps(after_item, sort_keys=True)
    change["after_unknown"] = {}
    out = result["planned_values"]["outputs"]["provisioned_cells"]["value"]
    for cid in out:
        out[cid] = {
            **out[cid],
            "general_assignable": (value if cid == cell_id else True),
        }
    return result


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


def legacy_otp_user_before() -> dict:
    """The exact pre-cleanup state of the detached legacy OTP Redis user."""
    return {
        "access_string": CHECKER.OTP_REDIS_LEGACY_ACCESS,
        "authentication_mode": [
            {"password_count": 0, "passwords": [], "type": "iam"}
        ],
        "engine": "redis",
        "id": CHECKER.LEGACY_OTP_REDIS_USER_ID,
        "region": CHECKER.AWS_REGION,
        "user_group_ids": [],
        "user_id": CHECKER.LEGACY_OTP_REDIS_USER_ID,
        "user_name": CHECKER.LEGACY_OTP_REDIS_USER_ID,
    }


def legacy_otp_user_delete_fixture() -> dict:
    """A no-op Control plan carrying only the reviewed legacy-user delete."""
    result = plan_fixture()
    result["applyable"] = True
    result["resource_changes"].append(
        {
            "address": CHECKER.LEGACY_OTP_REDIS_USER_ADDRESS,
            "mode": "managed",
            "type": CHECKER.LEGACY_OTP_REDIS_USER_TYPE,
            "change": {
                "actions": ["delete"],
                "before": legacy_otp_user_before(),
                "after": None,
            },
        }
    )
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
RUNTIME_AUTHORITY_DATA_KEY_ARN = (
    f"arn:aws:kms:{CHECKER.AWS_REGION}:{CHECKER.ACCOUNT_ID}:"
    "key/00000000-0000-0000-0000-000000000002"
)
RUNTIME_OTP_SECRET_ARN = (
    f"arn:aws:secretsmanager:{CHECKER.AWS_REGION}:{CHECKER.ACCOUNT_ID}:"
    f"secret:{CHECKER.CONTROL_PREFIX}-otp-pepper-ABCDEF"
)
RUNTIME_LAMBDA_SG_ID = "sg-0a110000000000000"
# The reviewed sandbox operator destination every Authority alarm routes to.
OPERATOR_ALARM_TOPIC_ARN = (
    "arn:aws:sns:us-east-2:767397897469:layerv-nhp-sandbox-cell0-alerts"
)
RUNTIME_INTERFACE_SG_ID = "sg-1face00000000000"
RUNTIME_OTP_REDIS_SG_ID = "sg-0a7ed150000000000"
RUNTIME_DYNAMODB_PREFIX_LIST_ID = "pl-0123456789abcdef0"


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


def authority_runtime_input_with_proof() -> dict:
    payload = authority_runtime_input_with_concurrency()
    contract = payload["authority_runtime_contract"]
    evidence = copy.deepcopy(contract["global"]["basis_evidence"])
    contract["global"]["caller_capacity"]["proof_controller"] = {
        "max_replicas": 1,
        "preinvoke_limits": {
            operation: 1 for operation in CHECKER.AUTHORITY_PROOF_FUNCTIONS.values()
        },
        "preinvoke_rate_limits": {
            operation: {
                "burst": 1,
                "refill_per_second": 1,
            }
            for operation in CHECKER.AUTHORITY_PROOF_FUNCTIONS.values()
        },
    }
    proof_function = {
        "basis_evidence": evidence,
        "max_caller_in_flight": 1,
        "max_caller_requests_per_second": 2,
        "result_evidence": None,
        "rollback_retention_seconds": 3600,
        "rollout_active_provisioned_concurrency": 1,
        "rollout_reserved_concurrency": 2,
        "rollout_standby_provisioned_concurrency": 1,
        "steady_provisioned_concurrency": 1,
        "steady_reserved_concurrency": 1,
    }
    for function_name in CHECKER.AUTHORITY_PROOF_FUNCTIONS:
        contract["functions"][function_name] = copy.deepcopy(proof_function)
    return payload


def runtime_scoped_endpoint_policies(
    *, proof_enabled: bool = False, legacy_recovery_resources: bool = False
) -> tuple[str, str, str, str]:
    # VPC endpoint policies do not match an assumed-role session against a
    # role-ARN Principal, so the runtime grants use Principal "*" scoped by an
    # exact aws:PrincipalArn condition. Keep this fixture in that shape.
    roles = sorted(CHECKER.AUTHORITY_RUNTIME_EXEC_ROLE_ARNS)
    if proof_enabled:
        roles.extend(sorted(CHECKER.AUTHORITY_PROOF_EXEC_ROLE_ARNS))
    dynamodb = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AuthorityFunctionsData",
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": sorted(CHECKER.AUTHORITY_RUNTIME_DYNAMODB_ACTIONS),
                    "Resource": sorted(
                        CHECKER.AUTHORITY_RUNTIME_DYNAMODB_LEGACY_RESOURCES
                        if legacy_recovery_resources
                        else CHECKER.AUTHORITY_RUNTIME_DYNAMODB_RESOURCES
                    ),
                    "Condition": {"StringEquals": {"aws:PrincipalArn": roles}},
                },
                {
                    "Sid": "ConnectorResourceCellData",
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": [
                        "dynamodb:DeleteItem",
                        "dynamodb:DescribeTable",
                        "dynamodb:GetItem",
                        "dynamodb:PutItem",
                        "dynamodb:UpdateItem",
                    ],
                    "Resource": sorted(
                        CHECKER.AUTHORITY_CONNECTOR_RESOURCE_CELL_TABLE_ARNS
                    ),
                    "Condition": {
                        "StringEquals": {
                            "aws:PrincipalArn": sorted(
                                CHECKER.AUTHORITY_CONNECTOR_RESOURCE_ROLE_ARNS
                            )
                        }
                    },
                },
            ],
        }
    )
    kms = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AuthorityFunctionsQat1PublicKey",
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": ["kms:GetPublicKey"],
                    "Resource": [RUNTIME_QAT1_KEY_ARN],
                    "Condition": {
                        "StringEquals": {
                            "aws:PrincipalArn": sorted(
                                CHECKER.AUTHORITY_RUNTIME_PUBLIC_KEY_ROLE_ARNS
                            )
                        }
                    },
                },
                {
                    "Sid": "IssueAssignmentQat1Sign",
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": ["kms:Sign"],
                    "Resource": [RUNTIME_QAT1_KEY_ARN],
                    "Condition": {
                        "StringEquals": {
                            "aws:PrincipalArn": sorted(
                                CHECKER.AUTHORITY_RUNTIME_SIGN_ROLE_ARNS
                            )
                        }
                    },
                },
                {
                    "Sid": "ConnectorResourceGenerateEnvelopeDataKey",
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": ["kms:GenerateDataKey"],
                    "Resource": sorted(
                        CHECKER.AUTHORITY_CONNECTOR_RESOURCE_ENVELOPE_KEY_ARNS
                    ),
                    "Condition": {
                        "StringEquals": {
                            "aws:PrincipalArn": sorted(
                                CHECKER.AUTHORITY_CONNECTOR_RESOURCE_ROLE_ARNS
                            ),
                            "kms:EncryptionContext:purpose": (
                                "qurl-v2-resource-software-key"
                            ),
                        }
                    },
                },
            ],
        }
    )
    secrets = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AuthorityOTPSecret",
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "secretsmanager:GetSecretValue",
                    "Resource": [RUNTIME_OTP_SECRET_ARN],
                    "Condition": {
                        "StringEquals": {
                            "aws:PrincipalArn": sorted(
                                CHECKER.AUTHORITY_RUNTIME_OTP_ROLE_ARNS
                            )
                        }
                    },
                }
            ],
        }
    )
    email = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AuthorityOTPSendEmail",
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "ses:SendEmail",
                    "Resource": sorted(CHECKER.AUTHORITY_RUNTIME_SES_RESOURCES),
                    "Condition": {
                        "StringEquals": {
                            "aws:PrincipalArn": sorted(
                                CHECKER.AUTHORITY_RUNTIME_SES_ROLE_ARNS
                            )
                        }
                    },
                }
            ],
        }
    )
    return dynamodb, kms, secrets, email


def hub_lambda_endpoint_policy(
    *, rollout: bool = True, selected: str = "blue"
) -> dict[str, str]:
    return {
        "policy": json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "HubWorkersInvokeAuthority",
                        "Effect": "Allow",
                        "Principal": "*",
                        "Action": "lambda:InvokeFunction",
                        "Resource": sorted(
                            CHECKER._hub_authority_alias_arns(rollout, selected)
                        ),
                        "Condition": {
                            "StringEquals": {
                                "aws:PrincipalArn": [CHECKER.HUB_TASK_ROLE_ARN]
                            }
                        },
                    }
                ],
            }
        )
    }


def runtime_exec_policy(fn: str, operation: str) -> str:
    """Build the per-operation execution (identity) policy the checker expects.

    Derived from the checker constants so the fixture stays in lockstep with the
    reviewed IAM; every referenced ARN is a known literal.
    """
    if operation == "resolve_connector_resource":
        cell = CHECKER.AUTHORITY_CONNECTOR_RESOURCE_CELLS[fn.rsplit("-", 1)[-1]]
        control_resources = sorted(
            CHECKER.AUTHORITY_RUNTIME_TABLE_ARNS[table]
            for table in ("agent_keys", "connector_authority", "customers")
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
                "Sid": "ConnectorResourceControlDescribe",
                "Effect": "Allow",
                "Action": ["dynamodb:DescribeTable"],
                "Resource": control_resources,
            },
            {
                "Sid": "ConnectorResourceControlDynamoDBDecrypt",
                "Effect": "Allow",
                "Action": ["kms:Decrypt"],
                "Resource": [RUNTIME_AUTHORITY_DATA_KEY_ARN],
                "Condition": {
                    "StringEquals": {
                        "kms:ViaService": (
                            f"dynamodb.{CHECKER.AWS_REGION}.amazonaws.com"
                        ),
                        "kms:EncryptionContext:aws:dynamodb:subscriberId": (
                            CHECKER.ACCOUNT_ID
                        ),
                        "kms:EncryptionContext:aws:dynamodb:tableName": [
                            CHECKER.AUTHORITY_RUNTIME_TABLE_ARNS[table].rsplit(
                                "/", 1
                            )[-1]
                            for table in (
                                "agent_keys",
                                "connector_authority",
                                "customers",
                            )
                        ],
                    }
                },
            },
            {
                "Sid": "ConnectorResourceControlRead",
                "Effect": "Allow",
                "Action": ["dynamodb:GetItem"],
                "Resource": control_resources,
            },
            {
                "Sid": "ConnectorResourceCellDescribe",
                "Effect": "Allow",
                "Action": ["dynamodb:DescribeTable"],
                "Resource": [
                    cell["qurl_resources_table_arn"],
                    cell["qurl_resource_key_material_table_arn"],
                ],
            },
            {
                "Sid": "ConnectorResourceCellResourceData",
                "Effect": "Allow",
                "Action": [
                    "dynamodb:GetItem",
                    "dynamodb:PutItem",
                    "dynamodb:UpdateItem",
                ],
                "Resource": [cell["qurl_resources_table_arn"]],
            },
            {
                "Sid": "ConnectorResourceCellKeyMaterial",
                "Effect": "Allow",
                "Action": ["dynamodb:DeleteItem", "dynamodb:PutItem"],
                "Resource": [cell["qurl_resource_key_material_table_arn"]],
            },
            {
                "Sid": "ConnectorResourceCellDynamoDBDecrypt",
                "Effect": "Allow",
                "Action": ["kms:Decrypt"],
                "Resource": [cell["cell_data_kms_key_arn"]],
                "Condition": {
                    "StringEquals": {
                        "kms:ViaService": (
                            f"dynamodb.{CHECKER.AWS_REGION}.amazonaws.com"
                        ),
                        "kms:EncryptionContext:aws:dynamodb:subscriberId": (
                            CHECKER.ACCOUNT_ID
                        ),
                        "kms:EncryptionContext:aws:dynamodb:tableName": [
                            cell["qurl_resources_table_arn"].rsplit("/", 1)[-1],
                            cell["qurl_resource_key_material_table_arn"].rsplit(
                                "/", 1
                            )[-1],
                        ],
                    }
                },
            },
            {
                "Sid": "ConnectorResourceGenerateEnvelopeDataKey",
                "Effect": "Allow",
                "Action": ["kms:GenerateDataKey"],
                "Resource": [cell["resource_key_envelope_kms_key_arn"]],
                "Condition": {
                    "StringEquals": {
                        "kms:EncryptionContext:purpose": (
                            "qurl-v2-resource-software-key"
                        )
                    }
                },
            },
        ]
        return json.dumps({"Version": "2012-10-17", "Statement": statements})

    spec = (
        CHECKER.AUTHORITY_RUNTIME_OPERATION_IAM.get(operation)
        or CHECKER.AUTHORITY_RUNTIME_CELL_OPERATION_IAM[operation]
    )
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
            "Sid": "AuthorityDynamoDBDecrypt",
            "Effect": "Allow",
            "Action": ["kms:Decrypt"],
            "Resource": [RUNTIME_AUTHORITY_DATA_KEY_ARN],
            "Condition": {
                "StringEquals": {
                    "kms:ViaService": (
                        f"dynamodb.{CHECKER.AWS_REGION}.amazonaws.com"
                    )
                }
            },
        },
        {
            "Sid": "AuthorityReads",
            "Effect": "Allow",
            "Action": sorted(CHECKER.AUTHORITY_RUNTIME_DYNAMODB_READ_ACTIONS),
            "Resource": read_resources,
        },
    ]
    if operation in CHECKER.AUTHORITY_RUNTIME_OPERATION_IAM:
        expected_write_keys = {
            "issue_assignment": ["HUB_REQUEST#IssueAssignment#*"],
            "refresh_assignment": ["HUB_REQUEST#RefreshAssignment#*"],
            "issue_credential_recovery": [
                "CREDENTIAL_RECOVERY_GRANT#*",
                "CREDENTIAL_RECOVERY_ISSUE#*",
                "HUB_REQUEST#IssueCredentialRecovery#*",
                "OWNER#*",
            ],
        }[operation]
        statements.append(
            {
                "Sid": spec["write_sid"],
                "Effect": "Allow",
                "Action": sorted(spec["write_actions"]),
                "Resource": sorted(
                    CHECKER.AUTHORITY_RUNTIME_TABLE_RESOURCES[
                        "connector_authority"
                    ]
                ),
                "Condition": {
                    "ForAllValues:StringLike": {
                        "dynamodb:LeadingKeys": expected_write_keys,
                    },
                    "Null": {"dynamodb:LeadingKeys": "false"},
                },
            }
        )
    else:
        for sid, (actions, resources) in spec["writes"].items():
            statements.append(
                {
                    "Sid": sid,
                    "Effect": "Allow",
                    "Action": sorted(actions),
                    "Resource": sorted(resources),
                }
            )
    if spec.get("ticket_handle_write"):
        statements.append(
            {
                "Sid": "AuthorityTicketHandleWrite",
                "Effect": "Allow",
                # The handle spec, NOT the replay action list. Sourcing it from
                # the replay list reintroduced in the fixture exactly the
                # coupling the Terraform split removes: widening replay would
                # make this fixture emit the wider set for the handle write and
                # surface as a confusing "ticket-handle write actions drifted"
                # failure caused by an unrelated change.
                "Action": sorted(spec["ticket_handle_write_actions"]),
                "Resource": sorted(
                    CHECKER.AUTHORITY_RUNTIME_TABLE_RESOURCES["connector_authority"]
                ),
                "Condition": {
                    "ForAllValues:StringLike": {
                        "dynamodb:LeadingKeys": ["ASSIGNMENT_TICKET#*"],
                    },
                    "Null": {"dynamodb:LeadingKeys": "false"},
                },
            }
        )
    if spec.get("ticket_handle_read"):
        statements.append(
            {
                "Sid": "AuthorityTicketHandleRead",
                "Effect": "Allow",
                "Action": ["dynamodb:GetItem"],
                "Resource": sorted(
                    CHECKER.AUTHORITY_RUNTIME_TABLE_RESOURCES["connector_authority"]
                ),
                "Condition": {
                    "ForAllValues:StringLike": {
                        "dynamodb:LeadingKeys": ["ASSIGNMENT_TICKET#*"],
                    },
                    "Null": {"dynamodb:LeadingKeys": "false"},
                },
            }
        )
    if spec.get("signs"):
        statements.append(
            {
                "Sid": "Qat1Sign",
                "Effect": "Allow",
                "Action": ["kms:GetPublicKey", "kms:Sign"],
                "Resource": [RUNTIME_QAT1_KEY_ARN],
            }
        )
    if spec.get("public_key"):
        statements.append(
            {
                "Sid": "Qat1PublicKey",
                "Effect": "Allow",
                "Action": ["kms:GetPublicKey"],
                "Resource": [RUNTIME_QAT1_KEY_ARN],
            }
        )
    otp_user = spec.get("otp_user")
    if otp_user is not None:
        statements.extend(
            [
                {
                    "Sid": "OTPSecretRead",
                    "Effect": "Allow",
                    "Action": ["secretsmanager:GetSecretValue"],
                    "Resource": [RUNTIME_OTP_SECRET_ARN],
                },
                {
                    "Sid": "OTPSecretDecrypt",
                    "Effect": "Allow",
                    "Action": ["kms:Decrypt"],
                    "Resource": [RUNTIME_AUTHORITY_DATA_KEY_ARN],
                    "Condition": {
                        "StringEquals": {
                            "kms:ViaService": (
                                f"secretsmanager.{CHECKER.AWS_REGION}.amazonaws.com"
                            ),
                            "kms:EncryptionContext:SecretARN": RUNTIME_OTP_SECRET_ARN,
                        }
                    },
                },
                {
                    "Sid": "OTPRedisConnect",
                    "Effect": "Allow",
                    "Action": ["elasticache:Connect"],
                    "Resource": [
                        CHECKER.AUTHORITY_RUNTIME_REDIS_CACHE_ARN,
                        CHECKER.AUTHORITY_RUNTIME_REDIS_USER_ARNS[otp_user],
                    ],
                },
            ]
        )
    if spec.get("sends_email"):
        statements.append(
            {
                "Sid": "OTPSendEmail",
                "Effect": "Allow",
                "Action": ["ses:SendEmail"],
                "Resource": sorted(CHECKER.AUTHORITY_RUNTIME_SES_RESOURCES),
            }
        )
    return json.dumps({"Version": "2012-10-17", "Statement": statements})


def proof_runtime_exec_policy() -> str:
    fn = CHECKER.AUTHORITY_PROOF_FUNCTION_NAME
    table = sorted(
        CHECKER.AUTHORITY_RUNTIME_TABLE_RESOURCES["connector_authority"]
    )
    owner_partition = (
        "OWNER#"
        + __import__("hashlib")
        .sha256(CHECKER.AUTHORITY_PROOF_OWNER_ID.encode("utf-8"))
        .hexdigest()
    )
    read_actions = sorted(
        set(CHECKER.AUTHORITY_RUNTIME_DYNAMODB_READ_ACTIONS)
        - {"dynamodb:DescribeTable"}
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
            "Sid": "ProofVerifyTableEncryption",
            "Effect": "Allow",
            "Action": ["dynamodb:DescribeTable"],
            "Resource": table,
        },
        {
            "Sid": "ProofDynamoDBDecrypt",
            "Effect": "Allow",
            "Action": ["kms:Decrypt"],
            "Resource": [RUNTIME_AUTHORITY_DATA_KEY_ARN],
            "Condition": {
                "StringEquals": {
                    "kms:ViaService": (
                        f"dynamodb.{CHECKER.AWS_REGION}.amazonaws.com"
                    )
                }
            },
        },
        {
            "Sid": "ProofFencedPlacementRead",
            "Effect": "Allow",
            "Action": read_actions,
            "Resource": table,
            "Condition": {
                "ForAllValues:StringEquals": {
                    "dynamodb:LeadingKeys": [owner_partition, "PROOF"]
                },
                "Null": {"dynamodb:LeadingKeys": "false"},
            },
        },
        {
            "Sid": "ProofRegistryRead",
            "Effect": "Allow",
            "Action": read_actions,
            "Resource": table,
            "Condition": {
                "ForAllValues:StringEquals": {
                    "dynamodb:LeadingKeys": ["REGISTRY"]
                },
                "Null": {"dynamodb:LeadingKeys": "false"},
            },
        },
        {
            "Sid": "ProofFencedPlacementWrite",
            "Effect": "Allow",
            "Action": ["dynamodb:PutItem", "dynamodb:UpdateItem"],
            "Resource": table,
            "Condition": {
                "ForAllValues:StringEquals": {
                    "dynamodb:LeadingKeys": [owner_partition, "PROOF"]
                },
                "Null": {"dynamodb:LeadingKeys": "false"},
            },
        },
        {
            "Sid": "ProofReplayReadWrite",
            "Effect": "Allow",
            "Action": [
                "dynamodb:GetItem",
                "dynamodb:PutItem",
                "dynamodb:UpdateItem",
            ],
            "Resource": table,
            "Condition": {
                "ForAllValues:StringLike": {
                    "dynamodb:LeadingKeys": [
                        "HUB_REQUEST#MutateProofAgent#*"
                    ]
                },
                "Null": {"dynamodb:LeadingKeys": "false"},
            },
        },
    ]
    return json.dumps({"Version": "2012-10-17", "Statement": statements})


def proof_recovery_runtime_exec_policy() -> str:
    fn = CHECKER.AUTHORITY_PROOF_RECOVERY_FUNCTION_NAME
    table = CHECKER.AUTHORITY_RUNTIME_TABLE_RESOURCES
    owner_partition = (
        "OWNER#"
        + __import__("hashlib")
        .sha256(CHECKER.AUTHORITY_PROOF_OWNER_ID.encode("utf-8"))
        .hexdigest()
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
            "Sid": "AuthorityDynamoDBDecrypt",
            "Effect": "Allow",
            "Action": ["kms:Decrypt"],
            "Resource": [RUNTIME_AUTHORITY_DATA_KEY_ARN],
            "Condition": {
                "StringEquals": {
                    "kms:ViaService": (
                        f"dynamodb.{CHECKER.AWS_REGION}.amazonaws.com"
                    )
                }
            },
        },
        {
            "Sid": "ProofRecoveryVerifyTableEncryption",
            "Effect": "Allow",
            "Action": ["dynamodb:DescribeTable"],
            "Resource": sorted(
                set().union(
                    table["api_keys"],
                    table["api_key_idempotency"],
                    table["customers"],
                    table["connector_authority"],
                )
            ),
        },
        {
            "Sid": "ProofRecoveryCredentialReadWrite",
            "Effect": "Allow",
            "Action": [
                "dynamodb:ConditionCheckItem",
                "dynamodb:GetItem",
                "dynamodb:PutItem",
                "dynamodb:Query",
                "dynamodb:UpdateItem",
            ],
            "Resource": sorted(
                {
                    *table["api_keys"],
                    f"{CHECKER.AUTHORITY_RUNTIME_TABLE_ARNS['api_keys']}/index/*",
                }
            ),
        },
        {
            "Sid": "ProofRecoveryReplayReadWrite",
            "Effect": "Allow",
            "Action": ["dynamodb:GetItem", "dynamodb:PutItem"],
            "Resource": sorted(table["api_key_idempotency"]),
        },
        {
            "Sid": "ProofRecoveryOwnerRead",
            "Effect": "Allow",
            "Action": ["dynamodb:ConditionCheckItem", "dynamodb:GetItem"],
            "Resource": sorted(table["customers"]),
            "Condition": {
                "ForAllValues:StringEquals": {
                    "dynamodb:LeadingKeys": [CHECKER.AUTHORITY_PROOF_OWNER_ID]
                }
            },
        },
        {
            "Sid": "ProofRecoveryAssignmentReadWrite",
            "Effect": "Allow",
            "Action": [
                "dynamodb:GetItem",
                "dynamodb:PutItem",
                "dynamodb:UpdateItem",
            ],
            "Resource": sorted(table["connector_authority"]),
            "Condition": {
                "ForAllValues:StringEquals": {
                    "dynamodb:LeadingKeys": [owner_partition]
                }
            },
        },
    ]
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


def redis_tls_ingress_rule() -> dict:
    """The one standalone SG-to-SG rule the runtime slice attaches to the OTP
    Redis SG, as a refreshed plan renders it."""
    return {
        "description": "Redis TLS from Connector Authority OTP functions",
        "from_port": 6379,
        "to_port": 6379,
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


def _authority_alarm_after(address: str, functions: dict) -> dict:
    """Reviewed after-state for one Authority alarm address (NHP #3455).

    Derived from the checker's own expected dimension/threshold tables so the
    fixture cannot drift from the contract it is exercising; the tests that must
    prove a regression fails mutate this after-state deliberately.
    """
    after: dict = {"alarm_actions": [OPERATOR_ALARM_TOPIC_ARN]}
    dimensions = CHECKER.AUTHORITY_ALARM_DIMENSIONS.get(address)
    if dimensions is None:
        # Composite alarm: selects its children by name, carries no dimension.
        fn = address.rsplit('["', 1)[1].removesuffix('"]')
        after["alarm_rule"] = (
            f'ALARM("{fn}-provisioned-concurrency-spillover") '
            f'AND ALARM("{fn}-errors")'
        )
        return after
    after["dimensions"] = dict(dimensions)
    after["treat_missing_data"] = "notBreaching"
    after["namespace"] = (
        CHECKER.AUTHORITY_ALARM_NAMESPACE_LAMBDA
        if set(dimensions) == {"FunctionName"}
        else CHECKER.AUTHORITY_ALARM_NAMESPACE_CUSTOM
    )
    if "authority_spillover[" in address:
        after.update(
            {
                "metric_name": "ProvisionedConcurrencySpilloverInvocations",
                "statistic": "Sum",
                "comparison_operator": "GreaterThanThreshold",
                "threshold": 0,
            }
        )
        return after
    if "authority_runtime[" in address:
        fn, family = address.rsplit('["', 1)[1].removesuffix('"]').split(":")
        (
            metric_name,
            statistic,
            extended_statistic,
            comparison,
            threshold,
        ) = CHECKER.AUTHORITY_ALARM_LAMBDA_FAMILIES[family]
        after.update(
            {
                "metric_name": metric_name,
                "statistic": statistic,
                "extended_statistic": extended_statistic,
                "comparison_operator": comparison,
                "threshold": (
                    threshold
                    if threshold is not None
                    else functions[fn]["steady_reserved_concurrency"]
                ),
            }
        )
        return after
    # Custom EMF alarms are uniform zero-tolerance Sum counters.
    after.update(
        {
            "statistic": "Sum",
            "comparison_operator": "GreaterThanThreshold",
            "threshold": 0,
        }
    )
    return after


def _authority_alarm_changes(functions: dict) -> list[dict]:
    changes: list[dict] = []
    for address, resource_type in CHECKER.AUTHORITY_ALARM_RESOURCES.items():
        changes.append(
            {
                "address": address,
                "mode": "managed",
                "type": resource_type,
                "change": _runtime_create(
                    _authority_alarm_after(address, functions)
                ),
            }
        )
    return changes


def _runtime_resource_changes() -> list[dict]:
    payload = authority_runtime_input_with_concurrency()
    image_uri = payload["authority_image_uri"]
    functions = payload["authority_runtime_contract"]["functions"]
    changes: list[dict] = _authority_alarm_changes(functions)
    changes.append(
        {
            "address": CHECKER.AUTHORITY_ACTIVE_COLOR_PARAMETER_ADDRESS,
            "mode": "managed",
            "type": "aws_ssm_parameter",
            "change": _runtime_create(
                {
                    "name": CHECKER.AUTHORITY_ACTIVE_COLOR_PARAMETER_NAME,
                    "type": "String",
                    "value": payload["authority_runtime_contract"][
                        "selected_authority_color"
                    ],
                    "tier": "Standard",
                }
            ),
        }
    )
    for fn, spec in functions.items():
        operation = CHECKER.AUTHORITY_RUNTIME_FUNCTIONS[fn]
        function_after = {
            "function_name": fn,
            "description": f"Connector Authority {operation} (sandbox)",
            "package_type": "Image",
            "image_uri": image_uri,
            "reserved_concurrent_executions": spec[
                "steady_reserved_concurrency"
            ],
            "vpc_config": [
                {"subnet_ids": [], "security_group_ids": []}
            ],
        }
        if operation == "resolve_connector_resource":
            cell_id = fn.rsplit("-", 1)[-1]
            cell = CHECKER.AUTHORITY_CONNECTOR_RESOURCE_CELLS[cell_id]
            function_after["environment"] = [{
                "variables": {
                    "CONNECTOR_AUTHORITY_OPERATION": "ResolveConnectorResource",
                    "CONNECTOR_AUTHORITY_ENVIRONMENT_ID": "sandbox",
                    "CONNECTOR_AUTHORITY_ACCOUNT_ID": CHECKER.ACCOUNT_ID,
                    "CONNECTOR_AUTHORITY_HOME_REGION": CHECKER.AWS_REGION,
                    "CONNECTOR_AUTHORITY_DATA_KMS_KEY_ARN": (
                        RUNTIME_AUTHORITY_DATA_KEY_ARN
                    ),
                    "CONNECTOR_AUTHORITY_CELL_ID": cell_id,
                    "CONNECTOR_AUTHORITY_CELL_DNS_SUFFIX": ".nhp.layerv.xyz",
                    "CONNECTOR_AUTHORITY_CELL_TABLE_PREFIX": (
                        cell["cell_table_prefix"]
                    ),
                    "CONNECTOR_AUTHORITY_CELL_DATA_KMS_KEY_ARN": (
                        cell["cell_data_kms_key_arn"]
                    ),
                    "CONNECTOR_AUTHORITY_RESOURCE_KEY_SERVICE_ROLE_ARN": (
                        f"arn:aws:iam::{CHECKER.ACCOUNT_ID}:role/{fn}-exec"
                    ),
                    "CONNECTOR_AUTHORITY_RESOURCE_KEY_ENVELOPE_KMS_KEY_ARN": (
                        cell["resource_key_envelope_kms_key_arn"]
                    ),
                    "CONNECTOR_AUTHORITY_RESOURCE_KEY_SOFTWARE_CUSTODY_ENABLED": (
                        "true"
                    ),
                }
            }]
        changes.append(
            {
                "address": f'module.control.aws_lambda_function.authority["{fn}"]',
                "mode": "managed",
                "type": "aws_lambda_function",
                "change": _runtime_create(function_after),
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
        spillover_address = (
            "module.control.aws_cloudwatch_metric_alarm."
            f'authority_spillover["{fn}"]'
        )
        changes.append(
            {
                "address": spillover_address,
                "mode": "managed",
                "type": "aws_cloudwatch_metric_alarm",
                "change": _runtime_create(
                    {
                        "alarm_name": f"{fn}-provisioned-concurrency-spillover",
                        **_authority_alarm_after(spillover_address, functions),
                    }
                ),
            }
        )
    changes.append(
        {
            "address": CHECKER.AUTHORITY_RUNTIME_LAMBDA_SG_ADDRESS,
            "mode": "managed",
            "type": "aws_security_group",
            "change": _runtime_create(
                {
                    "name_prefix": f"{CHECKER.CONTROL_PREFIX}-ca-fn-v2-",
                    "description": (
                        "Connector Authority function ENIs; egress to Control "
                        "dependency endpoints only"
                    ),
                    "vpc_id": "vpc-abc123",
                    "id": RUNTIME_LAMBDA_SG_ID,
                    "ingress": [],
                    "egress": [],
                }
            ),
        }
    )
    for address, destination in (
        (
            "module.control.aws_vpc_security_group_egress_rule."
            "authority_interface_endpoints[0]",
            {
                "description": "HTTPS to Control interface endpoints",
                "referenced_security_group_id": RUNTIME_INTERFACE_SG_ID,
            },
        ),
        (
            "module.control.aws_vpc_security_group_egress_rule."
            "authority_dynamodb[0]",
            {
                "description": "HTTPS to the DynamoDB gateway endpoint",
                "prefix_list_id": RUNTIME_DYNAMODB_PREFIX_LIST_ID,
            },
        ),
    ):
        changes.append(
            {
                "address": address,
                "mode": "managed",
                "type": "aws_vpc_security_group_egress_rule",
                "change": _runtime_create(
                    {
                        "from_port": 443,
                        "to_port": 443,
                        "ip_protocol": "tcp",
                        "security_group_id": RUNTIME_LAMBDA_SG_ID,
                        **destination,
                    }
                ),
            }
        )
    for address, resource_type, security_group_id, referenced_security_group_id in (
        (
            "module.control.aws_vpc_security_group_egress_rule.authority_otp_redis[0]",
            "aws_vpc_security_group_egress_rule",
            RUNTIME_LAMBDA_SG_ID,
            RUNTIME_OTP_REDIS_SG_ID,
        ),
        (
            "module.control.aws_vpc_security_group_ingress_rule.otp_redis_authority[0]",
            "aws_vpc_security_group_ingress_rule",
            RUNTIME_OTP_REDIS_SG_ID,
            RUNTIME_LAMBDA_SG_ID,
        ),
    ):
        changes.append(
            {
                "address": address,
                "mode": "managed",
                "type": resource_type,
                "change": _runtime_create(
                    {
                        "description": (
                            "TLS to Connector OTP Redis"
                            if resource_type == "aws_vpc_security_group_egress_rule"
                            else "TLS from Connector Authority OTP functions"
                        ),
                        "from_port": 6379,
                        "to_port": 6379,
                        "ip_protocol": "tcp",
                        "security_group_id": security_group_id,
                        "referenced_security_group_id": referenced_security_group_id,
                    }
                ),
            }
        )
    return changes


def _proof_environment(function_name: str = CHECKER.AUTHORITY_PROOF_FUNCTION_NAME) -> dict[str, str]:
    environment = {
        "CONNECTOR_AUTHORITY_PROOF_OWNER_ID": CHECKER.AUTHORITY_PROOF_OWNER_ID,
        "CONNECTOR_AUTHORITY_PROOF_AGENT_ID_PREFIX": "qurl-go-sandbox-",
    }
    if function_name != CHECKER.AUTHORITY_PROOF_RECOVERY_FUNCTION_NAME:
        environment.update(
            {
                "CONNECTOR_AUTHORITY_PROOF_DIRECTIVE_TTL": "5400",
                "CONNECTOR_AUTHORITY_PROOF_MIN_LEASE_SECONDS": "30",
            }
        )
    return environment


def _proof_resource_changes(payload: dict) -> list[dict]:
    functions = payload["authority_runtime_contract"]["functions"]
    changes = [
        {
            "address": address,
            "mode": "managed",
            "type": resource_type,
            "change": _runtime_create(_authority_alarm_after(address, functions)),
        }
        for address, resource_type in CHECKER.AUTHORITY_PROOF_ALARM_RESOURCES.items()
    ]
    for fn, operation in CHECKER.AUTHORITY_PROOF_FUNCTIONS.items():
        spec = functions[fn]
        policy = (
            proof_runtime_exec_policy()
            if fn == CHECKER.AUTHORITY_PROOF_FUNCTION_NAME
            else proof_recovery_runtime_exec_policy()
        )
        changes.extend(
            [
                {
                    "address": f'module.control.aws_lambda_function.authority["{fn}"]',
                    "mode": "managed",
                    "type": "aws_lambda_function",
                    "change": _runtime_create(
                        {
                            "function_name": fn,
                            "description": (
                                "Connector Authority "
                                f"{CHECKER.AUTHORITY_RUNTIME_FUNCTIONS_WITH_PROOF[fn]} "
                                "(sandbox)"
                            ),
                            "package_type": "Image",
                            "image_uri": payload["authority_image_uri"],
                            "reserved_concurrent_executions": spec[
                                "steady_reserved_concurrency"
                            ],
                            "vpc_config": [
                                {"subnet_ids": [], "security_group_ids": []}
                            ],
                            "environment": [
                                {"variables": _proof_environment(fn)}
                            ],
                        }
                    ),
                },
                *[
                    {
                        "address": (
                            f'module.control.aws_lambda_alias.authority["{fn}:{color}"]'
                        ),
                        "mode": "managed",
                        "type": "aws_lambda_alias",
                        "change": _runtime_create(
                            {
                                "function_name": fn,
                                "name": color,
                                "routing_config": [],
                            }
                        ),
                    }
                    for color in ("blue", "green")
                ],
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
                },
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
                },
                {
                    "address": (
                        f'module.control.aws_iam_role_policy.authority_exec["{fn}"]'
                    ),
                    "mode": "managed",
                    "type": "aws_iam_role_policy",
                    "change": _runtime_create(
                        {
                            "name": f"connector-authority-{operation}",
                            "policy": policy,
                        }
                    ),
                },
                {
                    "address": (
                        f'module.control.aws_cloudwatch_log_group.authority["{fn}"]'
                    ),
                    "mode": "managed",
                    "type": "aws_cloudwatch_log_group",
                    "change": _runtime_create({"name": f"/aws/lambda/{fn}"}),
                },
            ]
        )
        spillover_address = (
            "module.control.aws_cloudwatch_metric_alarm."
            f'authority_spillover["{fn}"]'
        )
        changes.append(
            {
                "address": spillover_address,
                "mode": "managed",
                "type": "aws_cloudwatch_metric_alarm",
                "change": _runtime_create(
                    {
                        "alarm_name": f"{fn}-provisioned-concurrency-spillover",
                        **_authority_alarm_after(spillover_address, functions),
                    }
                ),
            }
        )
    assert {item["address"] for item in changes} == set(
        CHECKER.AUTHORITY_PROOF_RESOURCES
    )
    return changes


def authority_runtime_transition_fixture() -> dict:
    """The full runtime graph plus its exact dependency endpoint/SG opens."""
    result = plan_fixture()
    result["applyable"] = True
    changes = {item["address"]: item for item in result["resource_changes"]}
    payload = authority_runtime_input_with_concurrency()

    foundation = changes["module.control.terraform_data.foundation_contract"]["change"]
    foundation["actions"] = ["no-op"]
    foundation["before"] = {"input": payload, "output": payload}
    foundation["after"] = {"input": payload, "output": payload}
    foundation["after_unknown"] = {}

    dynamodb_policy, kms_policy, secrets_policy, email_policy = (
        runtime_scoped_endpoint_policies()
    )
    ddb = changes[CHECKER.AUTHORITY_RUNTIME_DYNAMODB_ADDRESS]["change"]
    ddb["actions"] = ["update"]
    ddb["after"] = {**ddb["after"], "policy": dynamodb_policy}
    kms = changes[CHECKER.AUTHORITY_RUNTIME_KMS_ENDPOINT_ADDRESS]["change"]
    kms["actions"] = ["update"]
    kms["after"] = {**kms["after"], "policy": kms_policy}
    secrets = changes[CHECKER.AUTHORITY_RUNTIME_SECRETS_ENDPOINT_ADDRESS]["change"]
    secrets["actions"] = ["update"]
    secrets["after"] = {**secrets["after"], "policy": secrets_policy}
    email = changes[CHECKER.AUTHORITY_RUNTIME_EMAIL_ENDPOINT_ADDRESS]["change"]
    email["actions"] = ["update"]
    email["after"] = {**email["after"], "policy": email_policy}
    sg = changes[CHECKER.AUTHORITY_RUNTIME_INTERFACE_SG_ADDRESS]["change"]
    sg["actions"] = ["update"]
    sg["after"] = {
        **sg["after"],
        "id": RUNTIME_INTERFACE_SG_ID,
        "ingress": [runtime_interface_ingress_rule()],
        "egress": [],
    }
    otp_sg = changes["module.control.aws_security_group.otp_redis"]["change"]
    otp_sg["after"] = {
        **otp_sg["after"],
        "id": RUNTIME_OTP_REDIS_SG_ID,
    }
    otp_sg["before"] = copy.deepcopy(otp_sg["after"])

    result["resource_changes"].extend(_runtime_resource_changes())
    return result


def legacy_authority_runtime_payload() -> dict:
    payload = copy.deepcopy(authority_runtime_input_with_concurrency())
    contract = payload["authority_runtime_contract"]
    evidence = copy.deepcopy(CHECKER.AUTHORITY_RUNTIME_LEGACY_HUB_EVIDENCE)
    contract["global"]["basis_evidence"] = evidence
    contract["global"]["caller_capacity"]["cell_workers"].pop("cell1")
    contract["functions"] = {
        function_name: {
            **contract["functions"][function_name],
            "basis_evidence": copy.deepcopy(evidence),
        }
        for function_name in CHECKER.AUTHORITY_RUNTIME_HUB_FUNCTIONS
    }
    contract["provisioned_cells"].pop("cell1")
    contract["provisioned_cells_evidence"] = copy.deepcopy(evidence)
    return payload


def connector_resource_predecessor_payload() -> dict:
    """The exact live 11-function contract before creso is introduced."""
    payload = copy.deepcopy(authority_runtime_input_with_concurrency())
    contract = payload["authority_runtime_contract"]
    evidence = copy.deepcopy(
        CHECKER.AUTHORITY_CONNECTOR_RESOURCE_PREDECESSOR_EVIDENCE
    )
    contract["global"]["basis_evidence"] = evidence
    contract["provisioned_cells_evidence"] = copy.deepcopy(evidence)
    for function_name in CHECKER.AUTHORITY_CONNECTOR_RESOURCE_FUNCTIONS:
        contract["functions"].pop(function_name)
    for function in contract["functions"].values():
        function["basis_evidence"] = copy.deepcopy(evidence)
    for cell_id in CHECKER.AUTHORITY_CELLS:
        worker = contract["global"]["caller_capacity"]["cell_workers"][cell_id]
        worker["preinvoke_limits"].pop("resolve_connector_resource")
        worker["preinvoke_rate_limits"].pop("resolve_connector_resource")
        contract["provisioned_cells"][cell_id] = {
            "caller_role_arn": contract["provisioned_cells"][cell_id][
                "caller_role_arn"
            ]
        }
    return payload


def authority_connector_resource_expansion_fixture(
    applied_addresses: set[str] | None = None,
) -> dict:
    """Exact live 11-function -> 13-function connector-resource migration."""
    applied = applied_addresses or set()
    result = authority_runtime_transition_fixture()
    result["applyable"] = True
    changes = {item["address"]: item for item in result["resource_changes"]}
    create_addresses = set(
        CHECKER.AUTHORITY_CONNECTOR_RESOURCE_EXPANSION_CREATE_ADDRESSES
    )
    update_addresses = set(
        CHECKER.AUTHORITY_CONNECTOR_RESOURCE_EXPANSION_UPDATE_ADDRESSES
    )

    for address, item in changes.items():
        if address in create_addresses or address in update_addresses:
            continue
        change = item["change"]
        change["actions"] = ["no-op"]
        change["before"] = copy.deepcopy(change["after"])
        change["after_unknown"] = {}

    foundation = changes[
        "module.control.terraform_data.foundation_contract"
    ]["change"]
    before_payload = connector_resource_predecessor_payload()
    after_payload = authority_runtime_input_with_concurrency()
    foundation["actions"] = ["update"]
    foundation["before"] = {
        "input": copy.deepcopy(before_payload),
        "output": copy.deepcopy(before_payload),
    }
    foundation["after"] = {
        "input": copy.deepcopy(after_payload),
        "output": copy.deepcopy(after_payload),
    }
    foundation["after_unknown"] = {}

    for address in applied:
        change = changes[address]["change"]
        change["actions"] = ["no-op"]
        change["before"] = copy.deepcopy(change["after"])
        change["after_unknown"] = {}

    return result


def legacy_authority_lambda_sg_before() -> dict:
    return {
        "name_prefix": f"{CHECKER.CONTROL_PREFIX}-ca-fn-",
        "description": (
            "Connector Authority function ENIs; egress to Control dependency "
            "endpoints only"
        ),
        "vpc_id": "vpc-abc123",
        "ingress": [],
        "egress": [
            {
                "cidr_blocks": [CHECKER.CONTROL_VPC_CIDR],
                "description": ("HTTPS to Control interface endpoints (KMS) in-VPC"),
                "from_port": 443,
                "ipv6_cidr_blocks": [],
                "prefix_list_ids": [],
                "protocol": "tcp",
                "security_groups": [],
                "self": False,
                "to_port": 443,
            },
            {
                "cidr_blocks": [],
                "description": ("HTTPS to the DynamoDB gateway endpoint prefix list"),
                "from_port": 443,
                "ipv6_cidr_blocks": [],
                "prefix_list_ids": [RUNTIME_DYNAMODB_PREFIX_LIST_ID],
                "protocol": "tcp",
                "security_groups": [],
                "self": False,
                "to_port": 443,
            },
        ],
    }


def authority_runtime_legacy_expansion_fixture(
    applied_addresses: set[str] | None = None,
) -> dict:
    """Observed live three-Hub-function -> complete two-cell transition."""
    applied = applied_addresses or set()
    result = authority_runtime_transition_fixture()
    changes = {item["address"]: item for item in result["resource_changes"]}
    full_payload = authority_runtime_input_with_concurrency()
    foundation_address = "module.control.terraform_data.foundation_contract"

    # The alarm-routing addresses post-date this transition entirely, so they are
    # settled no-ops throughout it. The legacy expansion moves only the missing
    # cell graph; admitting an alarm create here would widen a historical shape.
    for address in (
        set(CHECKER.AUTHORITY_RUNTIME_LEGACY_HUB_RESOURCE_ADDRESSES)
        | set(CHECKER.AUTHORITY_ALARM_RESOURCES)
    ):
        change = changes[address]["change"]
        change["actions"] = ["no-op"]
        change["before"] = copy.deepcopy(change["after"])
        change["after_unknown"] = {}

    for address in CHECKER.AUTHORITY_RUNTIME_LEGACY_EXPANSION_UPDATE_ADDRESSES:
        change = changes[address]["change"]
        change["actions"] = ["update"]
        change["before"] = copy.deepcopy(change["after"])

    foundation = changes[foundation_address]["change"]
    legacy_payload = legacy_authority_runtime_payload()
    foundation["before"] = {"input": legacy_payload, "output": legacy_payload}
    foundation["after"] = {"input": full_payload, "output": full_payload}
    foundation["after_unknown"] = {}

    lambda_sg = changes[CHECKER.AUTHORITY_RUNTIME_LAMBDA_SG_ADDRESS]["change"]
    lambda_sg["actions"] = ["create", "delete"]
    lambda_sg["before"] = legacy_authority_lambda_sg_before()
    lambda_sg["after"] = {
        "name_prefix": f"{CHECKER.CONTROL_PREFIX}-ca-fn-v2-",
        "description": lambda_sg["before"]["description"],
        "vpc_id": lambda_sg["before"]["vpc_id"],
    }
    lambda_sg["after_unknown"] = {
        "arn": True,
        "egress": True,
        "id": True,
        "ingress": True,
        "name": True,
        "owner_id": True,
    }
    lambda_sg["replace_paths"] = [["name_prefix"]]

    # The replacement SG id is create-time unknown. Every dependent standalone
    # rule and the interface-endpoint SG ingress must carry the same unknown
    # projection; configuration-reference checks bind each field to the exact
    # SG resource expression.
    for address in (
        "module.control.aws_vpc_security_group_egress_rule."
        "authority_interface_endpoints[0]",
        "module.control.aws_vpc_security_group_egress_rule.authority_dynamodb[0]",
        "module.control.aws_vpc_security_group_egress_rule.authority_otp_redis[0]",
    ):
        change = changes[address]["change"]
        change["after"].pop("security_group_id")
        change["after_unknown"] = {"security_group_id": True}
    redis_ingress = changes[
        "module.control.aws_vpc_security_group_ingress_rule.otp_redis_authority[0]"
    ]["change"]
    redis_ingress["after"].pop("referenced_security_group_id")
    redis_ingress["after_unknown"] = {"referenced_security_group_id": True}
    interface_sg = changes[CHECKER.AUTHORITY_RUNTIME_INTERFACE_SG_ADDRESS]["change"]
    interface_sg["after"]["ingress"][0].pop("security_groups")
    interface_sg["after_unknown"] = {
        "ingress": [
            {
                "cidr_blocks": [],
                "ipv6_cidr_blocks": [],
                "prefix_list_ids": [],
                "security_groups": True,
            }
        ]
    }

    for address in applied:
        change = changes[address]["change"]
        if address == CHECKER.AUTHORITY_RUNTIME_LAMBDA_SG_ADDRESS:
            change["after"] = {
                "id": RUNTIME_LAMBDA_SG_ID,
                "name_prefix": f"{CHECKER.CONTROL_PREFIX}-ca-fn-v2-",
                "description": (
                    "Connector Authority function ENIs; egress to Control "
                    "dependency endpoints only"
                ),
                "vpc_id": "vpc-abc123",
                "ingress": [],
                "egress": [],
            }
        change["actions"] = ["no-op"]
        change["before"] = copy.deepcopy(change["after"])
        change["after_unknown"] = {}

    if CHECKER.AUTHORITY_RUNTIME_LAMBDA_SG_ADDRESS in applied:
        for address in (
            "module.control.aws_vpc_security_group_egress_rule."
            "authority_interface_endpoints[0]",
            "module.control.aws_vpc_security_group_egress_rule.authority_dynamodb[0]",
            "module.control.aws_vpc_security_group_egress_rule.authority_otp_redis[0]",
        ):
            change = changes[address]["change"]
            change["after"]["security_group_id"] = RUNTIME_LAMBDA_SG_ID
            change["after_unknown"].pop("security_group_id", None)
        redis_ingress["after"]["referenced_security_group_id"] = RUNTIME_LAMBDA_SG_ID
        redis_ingress["after_unknown"].pop("referenced_security_group_id", None)
        interface_sg["after"]["ingress"][0]["security_groups"] = [RUNTIME_LAMBDA_SG_ID]
        interface_sg["after_unknown"] = {}

    # The known replacement id may have changed pending dependent values above;
    # re-synchronize every already-applied address to its exact no-op state.
    for address in applied:
        change = changes[address]["change"]
        change["before"] = copy.deepcopy(change["after"])
        change["after_unknown"] = {}

    return result


def with_legacy_authority_digest_roll(candidate: dict) -> dict:
    """Model an exact-main Authority publish racing the one-time expansion."""
    result = copy.deepcopy(candidate)
    changes = {item["address"]: item for item in result["resource_changes"]}
    foundation = changes[
        "module.control.terraform_data.foundation_contract"
    ]["change"]
    previous_digest = "sha256:" + "2" * 64
    repository = foundation["after"]["input"]["authority_runtime_contract"][
        "global"
    ]["authority_repository_url"]
    previous_uri = f"{repository}@{previous_digest}"
    for projection in ("input", "output"):
        foundation["before"][projection]["authority_image_uri"] = previous_uri
        foundation["before"][projection]["authority_runtime_contract"]["global"][
            "authority_image_digest"
        ] = previous_digest
    for function_name in CHECKER.AUTHORITY_RUNTIME_HUB_FUNCTIONS:
        changes[
            f'module.control.aws_lambda_function.authority["{function_name}"]'
        ]["change"]["before"]["image_uri"] = previous_uri
    return result


def legacy_expansion_evidence_slots(candidate: dict) -> list[dict]:
    """Every basis-evidence object in the expansion's live predecessor.

    The predecessor binds its basis in four independent places -- the global
    contract, the provisioned-cell catalog, and each retained Hub function -- so
    a test can advance them together or leave a subset behind to prove a mixed
    predecessor is still rejected.
    """
    foundation = next(
        item["change"]
        for item in candidate["resource_changes"]
        if item["address"] == "module.control.terraform_data.foundation_contract"
    )
    slots = []
    for projection in ("input", "output"):
        contract = foundation["before"][projection]["authority_runtime_contract"]
        slots.append(contract["global"]["basis_evidence"])
        slots.append(contract["provisioned_cells_evidence"])
        slots.extend(
            contract["functions"][function_name]["basis_evidence"]
            for function_name in CHECKER.AUTHORITY_RUNTIME_HUB_FUNCTIONS
        )
    return slots


def with_legacy_predecessor_at_image_update_basis(candidate: dict) -> dict:
    """Model the reviewed image update having ALREADY applied its contract.

    The observed sandbox state: the admitted ``authority-image-update`` apply
    converged the foundation contract and every Hub function's $LATEST, then
    failed on ``lambda:PublishVersion``. The live predecessor the expansion now
    plans from therefore sits at that transition's reviewed TO basis, not at its
    FROM basis.
    """
    result = copy.deepcopy(candidate)
    historical_target = CHECKER.AUTHORITY_RUNTIME_LEGACY_HUB_EVIDENCE_CANDIDATES[1]
    for evidence in legacy_expansion_evidence_slots(result):
        evidence["sha256"] = historical_target["sha256"]
        evidence["source_commit"] = historical_target["source_commit"]
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


def authority_proof_enable_fixture() -> dict:
    """Exact attended gate-off -> proof-on Control plan."""
    result = authority_runtime_steady_fixture()
    result["applyable"] = True
    changes = {
        item["address"]: item["change"] for item in result["resource_changes"]
    }
    before_payload = authority_runtime_input_with_concurrency()
    after_payload = authority_runtime_input_with_proof()

    foundation = changes["module.control.terraform_data.foundation_contract"]
    foundation["actions"] = ["update"]
    foundation["before"] = {
        "input": copy.deepcopy(before_payload),
        "output": copy.deepcopy(before_payload),
    }
    foundation["after"] = {
        "input": copy.deepcopy(after_payload),
        "output": copy.deepcopy(after_payload),
    }
    foundation["after_unknown"] = {}

    ddb = changes[CHECKER.AUTHORITY_RUNTIME_DYNAMODB_ADDRESS]
    dark_ddb, _, _, _ = runtime_scoped_endpoint_policies(
        legacy_recovery_resources=True
    )
    proof_ddb, _, _, _ = runtime_scoped_endpoint_policies(proof_enabled=True)
    ddb["actions"] = ["update"]
    ddb["before"] = {**copy.deepcopy(ddb["after"]), "policy": dark_ddb}
    ddb["after"] = {**copy.deepcopy(ddb["after"]), "policy": proof_ddb}

    result["resource_changes"].extend(_proof_resource_changes(after_payload))

    outputs = control_outputs_fixture()
    for function_name, output_name in CHECKER.AUTHORITY_PROOF_ALIAS_OUTPUTS.items():
        selected_alias = (
            f"arn:aws:lambda:{CHECKER.AWS_REGION}:{CHECKER.ACCOUNT_ID}:function:"
            f"{function_name}:blue"
        )
        outputs[output_name] = {
            "sensitive": False,
            "type": "string",
            "value": selected_alias,
        }
    result["planned_values"]["outputs"] = copy.deepcopy(outputs)
    result["output_changes"] = {
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
    for output_name in CHECKER.AUTHORITY_PROOF_ALIAS_OUTPUTS.values():
        result["output_changes"][output_name].update(
            {"actions": ["create"], "before": None}
        )
    return result


def authority_proof_disable_fixture() -> dict:
    """Exact attended proof-on -> gate-off Control rollback plan."""
    result = authority_proof_enable_fixture()
    changes = {
        item["address"]: item["change"] for item in result["resource_changes"]
    }

    foundation = changes["module.control.terraform_data.foundation_contract"]
    foundation["before"], foundation["after"] = (
        copy.deepcopy(foundation["after"]),
        copy.deepcopy(foundation["before"]),
    )

    ddb = changes[CHECKER.AUTHORITY_RUNTIME_DYNAMODB_ADDRESS]
    proof_ddb = copy.deepcopy(ddb["after"])
    dark_ddb, _, _, _ = runtime_scoped_endpoint_policies()
    ddb["before"] = proof_ddb
    ddb["after"] = {**copy.deepcopy(proof_ddb), "policy": dark_ddb}

    for address in CHECKER.AUTHORITY_PROOF_RESOURCES:
        change = changes[address]
        change.update(
            {
                "actions": ["delete"],
                "before": copy.deepcopy(change["after"]),
                "after": None,
                "after_unknown": {},
            }
        )

    for output_name in CHECKER.AUTHORITY_PROOF_ALIAS_OUTPUTS.values():
        selected_alias = result["output_changes"][output_name]["after"]
        del result["planned_values"]["outputs"][output_name]
        result["output_changes"][output_name].update(
            {
                "actions": ["delete"],
                "before": selected_alias,
                "after": None,
            }
        )
    return result


def authority_proof_steady_fixture() -> dict:
    result = authority_proof_enable_fixture()
    result["applyable"] = False
    for item in result["resource_changes"]:
        change = item["change"]
        if change["actions"] == ["no-op"]:
            continue
        change["actions"] = ["no-op"]
        change["before"] = copy.deepcopy(change["after"])
        change["after_unknown"] = {}
    for output_name in CHECKER.AUTHORITY_PROOF_ALIAS_OUTPUTS.values():
        proof_output = result["output_changes"][output_name]
        proof_output["actions"] = ["no-op"]
        proof_output["before"] = copy.deepcopy(proof_output["after"])
    return result


def authority_alarm_routing_fixture() -> dict:
    """The real NHP #3455 rollout shape, on top of the applied runtime slice.

    Every function, alias, role, endpoint, and SG is a settled no-op; the 11
    already-live spillover alarms take an in-place ``alarm_actions`` update and
    the remaining alarm addresses are pending creates. This is the plan the
    sandbox apply actually produces, distinct from the full-slice fixture the
    other alarm mutation tests build on.
    """
    result = authority_runtime_steady_fixture()
    result["applyable"] = True
    changes = {item["address"]: item for item in result["resource_changes"]}
    for address in CHECKER.AUTHORITY_ALARM_RESOURCES:
        change = changes[address]["change"]
        change["actions"] = ["create"]
        change["before"] = None
        change["after_unknown"] = {}
    for address in CHECKER.AUTHORITY_ALARM_UPDATE_ADDRESSES:
        change = changes[address]["change"]
        change["actions"] = ["update"]
        # The pre-#3455 live state: the alarm exists with no operator action.
        change["before"] = {**copy.deepcopy(change["after"]), "alarm_actions": []}
        change["after_unknown"] = {}
    return result


def authority_image_update_fixture(
    pending_addresses: set[str] | None = None,
    *,
    foundation_pending: bool | None = None,
    recovery_replaces: set[str] | None = None,
    refresh_disabled: bool = False,
) -> dict:
    """Exact full-graph 65421e-to-e147b2 image migration.

    ``pending_addresses`` models a partial-apply completion: already-applied
    function/alias addresses are exact no-ops at the new version, while the
    supplied subset remains update-only. By default the full migration includes
    the foundation update; an explicit subset defaults to foundation-applied.
    ``recovery_replaces`` models the proof pools tainted by the stale-image
    failed apply.
    """
    result = authority_proof_steady_fixture()
    result["applyable"] = True
    changes = {item["address"]: item["change"] for item in result["resource_changes"]}

    image_addresses = set(CHECKER.AUTHORITY_IMAGE_UPDATE_RESOURCES)
    if pending_addresses is None:
        pending_addresses = image_addresses
        if foundation_pending is None:
            foundation_pending = True
    elif foundation_pending is None:
        foundation_pending = False
    assert pending_addresses <= image_addresses
    recovery_replaces = recovery_replaces or set()
    assert recovery_replaces <= set(
        CHECKER.AUTHORITY_IMAGE_UPDATE_RECOVERY_REPLACES
    )
    assert pending_addresses or foundation_pending or recovery_replaces

    foundation = changes["module.control.terraform_data.foundation_contract"]
    new_input = copy.deepcopy(foundation["after"]["input"])
    new_input["authority_image_uri"] = CHECKER.AUTHORITY_IMAGE_UPDATE_TO_URI
    new_contract = new_input["authority_runtime_contract"]
    new_contract["global"]["authority_image_digest"] = (
        CHECKER.AUTHORITY_IMAGE_UPDATE_TO_URI.rsplit("@", 1)[1]
    )
    new_source = CHECKER.AUTHORITY_IMAGE_UPDATE_TO_EVIDENCE_SOURCE
    for evidence in CHECKER._authority_basis_evidence(new_input):
        evidence["sha256"] = CHECKER.AUTHORITY_IMAGE_UPDATE_TO_EVIDENCE_SHA256
        evidence["source_commit"] = new_source

    if foundation_pending:
        old_input = copy.deepcopy(new_input)
        old_input["authority_image_uri"] = CHECKER.AUTHORITY_IMAGE_UPDATE_FROM_URI
        old_input["authority_runtime_contract"]["global"][
            "authority_image_digest"
        ] = CHECKER.AUTHORITY_IMAGE_UPDATE_FROM_URI.rsplit("@", 1)[1]
        for evidence in CHECKER._authority_basis_evidence(old_input):
            evidence["sha256"] = CHECKER.AUTHORITY_IMAGE_UPDATE_FROM_EVIDENCE_SHA256
            evidence["source_commit"] = (
                CHECKER.AUTHORITY_IMAGE_UPDATE_FROM_EVIDENCE_SOURCE
            )
        contract_shape = CHECKER._mapping_shape(new_contract)
        foundation.clear()
        foundation.update(
            {
                "actions": ["update"],
                "before": {
                    "id": "6cdf8fea-de09-e404-1191-338120049d2e",
                    "input": old_input,
                    "output": copy.deepcopy(old_input),
                    "triggers_replace": None,
                },
                "after": {
                    "id": "6cdf8fea-de09-e404-1191-338120049d2e",
                    "input": new_input,
                    "triggers_replace": None,
                },
                "after_unknown": {
                    "input": {"authority_runtime_contract": contract_shape},
                    "output": True,
                },
                "before_sensitive": {
                    "input": {"authority_runtime_contract": contract_shape},
                    "output": {"authority_runtime_contract": contract_shape},
                },
                "after_sensitive": {
                    "input": {"authority_runtime_contract": contract_shape},
                    "output": {},
                },
            }
        )
    else:
        contract_shape = CHECKER._mapping_shape(new_contract)
        target_value = {
            "id": "6cdf8fea-de09-e404-1191-338120049d2e",
            "input": copy.deepcopy(new_input),
            "output": copy.deepcopy(new_input),
            "triggers_replace": None,
        }
        target_sensitive = {
            "input": {"authority_runtime_contract": contract_shape},
            "output": {"authority_runtime_contract": contract_shape},
        }
        foundation.clear()
        foundation.update(
            {
                "actions": ["no-op"],
                "before": copy.deepcopy(target_value),
                "after": copy.deepcopy(target_value),
                "after_unknown": {},
                "before_sensitive": copy.deepcopy(target_sensitive),
                "after_sensitive": copy.deepcopy(target_sensitive),
            }
        )

    # Every function the contract carries must sit at the contract-pinned image.
    for fn in CHECKER.AUTHORITY_RUNTIME_FUNCTIONS_WITH_PROOF:
        function_address = (
            f'module.control.aws_lambda_function.authority["{fn}"]'
        )
        function = changes[function_address]
        function["after"].update(
            {
                "image_uri": CHECKER.AUTHORITY_IMAGE_UPDATE_TO_URI,
                "last_modified": "2026-07-25T05:00:00.000+0000",
                "qualified_arn": (
                    f"arn:aws:lambda:{CHECKER.AWS_REGION}:{CHECKER.ACCOUNT_ID}:"
                    f"function:{fn}:6"
                ),
                "qualified_invoke_arn": (
                    f"arn:aws:apigateway:{CHECKER.AWS_REGION}:lambda:path/"
                    "2015-03-31/functions/"
                    f"arn:aws:lambda:{CHECKER.AWS_REGION}:{CHECKER.ACCOUNT_ID}:"
                    f"function:{fn}:6/invocations"
                ),
                "version": "6",
            }
        )
        function["before"] = copy.deepcopy(function["after"])
        function["before_sensitive"] = {}
        function["after_sensitive"] = {}
        function["before_identity"] = {
            "account_id": CHECKER.ACCOUNT_ID,
            "function_name": fn,
            "region": CHECKER.AWS_REGION,
        }
        function["after_identity"] = copy.deepcopy(function["before_identity"])
        if function_address in pending_addresses:
            function["actions"] = ["update"]
            function["before"].update(
                {
                    "image_uri": CHECKER.AUTHORITY_IMAGE_UPDATE_FROM_URI,
                    "last_modified": "2026-07-25T04:44:39.000+0000",
                    "qualified_arn": (
                        f"arn:aws:lambda:{CHECKER.AWS_REGION}:"
                        f"{CHECKER.ACCOUNT_ID}:function:{fn}:5"
                    ),
                    "qualified_invoke_arn": (
                        f"arn:aws:apigateway:{CHECKER.AWS_REGION}:lambda:path/"
                        "2015-03-31/functions/"
                        f"arn:aws:lambda:{CHECKER.AWS_REGION}:"
                        f"{CHECKER.ACCOUNT_ID}:function:{fn}:5/invocations"
                    ),
                    "version": "5",
                }
            )
            for field in CHECKER._AUTHORITY_FUNCTION_UPDATE_COMPUTED_FIELDS:
                function["after"].pop(field)
            function["after_unknown"] = {
                field: True
                for field in CHECKER._AUTHORITY_FUNCTION_UPDATE_COMPUTED_FIELDS
            }

        for color in ("blue", "green"):
            alias_address = (
                f'module.control.aws_lambda_alias.authority["{fn}:{color}"]'
            )
            alias = changes[alias_address]
            alias["after"].update(
                {
                    "function_name": fn,
                    "function_version": "6",
                    "routing_config": [],
                }
            )
            alias["before"] = copy.deepcopy(alias["after"])
            alias["before_sensitive"] = {}
            alias["after_sensitive"] = {}
            if alias_address in pending_addresses:
                alias["actions"] = ["update"]
                alias["before"]["function_version"] = "5"
                alias["after"].pop("function_version")
                alias["after_unknown"] = {"function_version": True}

    for address in recovery_replaces:
        change = changes[address]
        function_name = address.rsplit('["', 1)[1][:-2]
        change["actions"] = ["delete", "create"]
        change["before"] = {
            "function_name": function_name,
            "id": f"{function_name},blue",
            "provisioned_concurrent_executions": 1 if refresh_disabled else 0,
            "qualifier": "blue",
            "skip_destroy": False,
            "timeouts": None,
        }
        change["after"] = {
            "function_name": function_name,
            "provisioned_concurrent_executions": 1,
            "qualifier": "blue",
            "skip_destroy": False,
            "timeouts": None,
        }
        change["after_unknown"] = {"id": True}
        change["before_sensitive"] = {}
        change["after_sensitive"] = {}

    outputs = copy.deepcopy(result["planned_values"]["outputs"])
    result["output_changes"] = {
        name: {
            "actions": ["no-op"],
            "before": copy.deepcopy(output["value"]),
            "after": copy.deepcopy(output["value"]),
            "after_unknown": False,
            "before_sensitive": False,
            "after_sensitive": False,
        }
        for name, output in outputs.items()
    }
    if foundation_pending and pending_addresses == image_addresses:
        result["output_changes"]["authority_image_uri"].update(
            {
                "actions": ["update"],
                "before": CHECKER.AUTHORITY_IMAGE_UPDATE_FROM_URI,
                "after": CHECKER.AUTHORITY_IMAGE_UPDATE_TO_URI,
            }
        )
    else:
        result["output_changes"]["authority_image_uri"].update(
            {
                "before": CHECKER.AUTHORITY_IMAGE_UPDATE_TO_URI,
                "after": CHECKER.AUTHORITY_IMAGE_UPDATE_TO_URI,
            }
        )

    return result


def authority_proof_concurrency_recovery_drift(
    addresses: set[str] | None = None,
) -> list[dict]:
    """Exact stored-one to live-zero PM/PCR failure observation."""
    selected = (
        set(CHECKER.AUTHORITY_IMAGE_UPDATE_RECOVERY_REPLACES)
        if addresses is None
        else addresses
    )
    assert selected
    assert selected <= set(CHECKER.AUTHORITY_IMAGE_UPDATE_RECOVERY_REPLACES)
    result = []
    for address in sorted(selected):
        function_name = address.rsplit('["', 1)[1][:-2]
        before = {
            "function_name": function_name,
            "id": f"{function_name},blue",
            "provisioned_concurrent_executions": 1,
            "qualifier": "blue",
            "region": CHECKER.AWS_REGION,
            "skip_destroy": False,
            "timeouts": None,
        }
        result.append(
            {
                "address": address,
                "index": function_name,
                "mode": "managed",
                "module_address": "module.control",
                "name": "authority",
                "provider_name": "registry.terraform.io/hashicorp/aws",
                "type": "aws_lambda_provisioned_concurrency_config",
                "change": {
                    "actions": ["update"],
                    "after": {
                        **copy.deepcopy(before),
                        "provisioned_concurrent_executions": 0,
                    },
                    "after_sensitive": {},
                    "after_unknown": {},
                    "before": before,
                    "before_sensitive": {},
                },
            }
        )
    return result


def authority_proof_concurrency_recovery_normalization_fixture(
    addresses: set[str] | None = None,
) -> tuple[dict, dict]:
    """Build the pre-apply refresh-only observation and captured state."""
    selected = (
        set(CHECKER.AUTHORITY_IMAGE_UPDATE_RECOVERY_REPLACES)
        if addresses is None
        else addresses
    )
    candidate = authority_image_update_fixture(recovery_replaces=selected)
    candidate["resource_drift"] = authority_proof_concurrency_recovery_drift(
        selected
    )
    prior_state = terraform_1_14_refresh_only_golden(candidate)
    for item in candidate["resource_drift"]:
        state_resource(prior_state, item["address"])["values"] = copy.deepcopy(
            item["change"]["before"]
        )
    return candidate, prior_state


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
    """A minimal benign refresh re-projection ``resource_drift`` entry.

    ``before`` holds an EMPTY collection, so this is a pure first projection:
    state recorded no prior value, nothing changed out of band, and
    ``_drift_is_first_projection_only`` classifies it benign.
    """
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


def _substantive_refresh_drift(address: str, resource_type: str) -> dict:
    """A refresh drift entry that carries a REAL out-of-band value change.

    Same address/shape as ``_slice_refresh_drift``, but ``before`` holds a
    RECORDED value that the refresh read back differently. That is the signal the
    checker exists to catch, so it must never be filtered as a first projection
    and must still be rejected unless it matches an exact reviewed normalization.
    """
    return {
        "address": address,
        "mode": "managed",
        "type": resource_type,
        "change": {
            "actions": ["update"],
            "before": {"tags_all": {"reviewed": "yes"}},
            "after": {"tags_all": {"reviewed": "tampered"}},
            "after_unknown": {},
        },
    }


def add_runtime_role_state_normalization(candidate: dict) -> None:
    """Attach a substantive, configuration-converged runtime-role refresh."""
    item = next(
        resource
        for resource in candidate["resource_changes"]
        if resource["type"] == "aws_iam_role"
        and resource["address"] in CHECKER.AUTHORITY_RUNTIME_RESOURCES
    )
    after = copy.deepcopy(item["change"]["after"])
    before = copy.deepcopy(after)
    before["max_session_duration"] = 7200
    candidate["resource_drift"] = [
        {
            "address": item["address"],
            "mode": "managed",
            "type": item["type"],
            "change": {
                "actions": ["update"],
                "before": before,
                "after": after,
                "after_unknown": {},
            },
        }
    ]


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
    changes = []
    for address, resource_type in CHECKER.HUB_EDGE_RESOURCES.items():
        after = {"id": address}
        if address == "module.control.aws_security_group.hub_nlb[0]":
            after.update({"ingress": [], "egress": []})
        elif address.endswith(
            'aws_vpc_security_group_ingress_rule.hub_nlb_udp["0.0.0.0/0"]'
        ):
            after.update(
                {
                    "cidr_ipv4": CHECKER.HUB_PUBLIC_UDP_INGRESS_CIDR,
                    "cidr_ipv6": None,
                    "from_port": 443,
                    "ip_protocol": "udp",
                    "to_port": 443,
                }
            )
        elif address == "module.control.aws_lb.hub[0]":
            after.update(
                {
                    "internal": False,
                    "load_balancer_type": "network",
                    "name": CHECKER.HUB_EDGE_LOAD_BALANCER_NAME,
                    "security_groups": ["sg-hub-nlb"],
                }
            )
        changes.append(
            {
                "address": address,
                "mode": "managed",
                "type": resource_type,
                "change": _runtime_create(after),
            }
        )
    return changes


def hub_identity_migration_fixture(*, converged: bool = False) -> dict[str, dict]:
    secret_arn = (
        f"arn:aws:secretsmanager:{CHECKER.AWS_REGION}:{CHECKER.ACCOUNT_ID}:"
        f"secret:{CHECKER.CONTROL_PREFIX}-hub-key-material-Ab3xYz"
    )
    key_arn = (
        f"arn:aws:kms:{CHECKER.AWS_REGION}:{CHECKER.ACCOUNT_ID}:"
        "key/00000000-0000-0000-0000-000000000002"
    )
    source_hash = base64.b64encode(hashlib.sha256(b"hub-keygen").digest()).decode()
    public_key = base64.b64encode(bytes(range(1, 33))).decode()
    kms_condition = {
        "StringEquals": {
            "kms:EncryptionContext:SecretARN": secret_arn,
            "kms:ViaService": CHECKER.HUB_SECRETSMANAGER_KMS_VIA_SERVICE,
        }
    }
    keygen_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Action": [
                    "secretsmanager:DescribeSecret",
                    "secretsmanager:GetSecretValue",
                    "secretsmanager:PutSecretValue",
                ],
                "Effect": "Allow",
                "Resource": secret_arn,
                "Sid": "SeedHubKeyMaterial",
            },
            {
                "Action": ["ssm:GetParameter", "ssm:PutParameter"],
                "Effect": "Allow",
                "Resource": CHECKER.HUB_PUBLIC_KEY_PARAMETER_ARN,
                "Sid": "PublishHubPublicIdentity",
            },
            {
                "Action": ["kms:GenerateDataKey", "kms:Decrypt"],
                "Condition": copy.deepcopy(kms_condition),
                "Effect": "Allow",
                "Resource": key_arn,
                "Sid": "WrapHubKeyMaterial",
            },
            {
                "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
                "Effect": "Allow",
                "Resource": CHECKER.HUB_KEYGEN_LOG_GROUP_ARN,
                "Sid": "OwnLogStream",
            },
        ],
    }
    execution_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Action": "secretsmanager:GetSecretValue",
                "Effect": "Allow",
                "Resource": secret_arn,
                "Sid": "ReadHubKeyMaterial",
            },
            {
                "Action": "kms:Decrypt",
                "Condition": copy.deepcopy(kms_condition),
                "Effect": "Allow",
                "Resource": key_arn,
                "Sid": "DecryptHubKeyMaterial",
            },
        ],
    }

    def item(
        after: dict,
        *,
        actions: list[str] | None = None,
        unknown: dict | None = None,
        replace_paths: list[list[str]] | None = None,
    ) -> dict:
        selected_actions = actions or ["no-op"]
        change = {
            "actions": selected_actions,
            "before": (
                None if selected_actions == ["create"] else copy.deepcopy(after)
            ),
            "after": after,
            "after_unknown": unknown or {},
        }
        if replace_paths is not None:
            change["replace_paths"] = replace_paths
        return {"change": change}

    publication_invocation = {
        "function_name": CHECKER.HUB_KEYGEN_FUNCTION_NAME,
        "input": "{}",
        "lifecycle_scope": "CREATE_ONLY",
        "qualifier": "$LATEST",
        "region": CHECKER.AWS_REGION,
        "tenant_id": None,
        "terraform_key": "tf",
        "triggers": None,
    }
    public = {
        "description": (
            "Connector Hub X25519 public identity; private key remains in "
            "Secrets Manager"
        ),
        "name": CHECKER.HUB_PUBLIC_KEY_PARAMETER_NAME,
        "region": CHECKER.AWS_REGION,
        "type": "String",
        "value": public_key if converged else "pending-keygen",
        "value_wo": None,
        "value_wo_version": None,
    }
    if converged:
        publication_invocation["result"] = '{"seeded": true}'
        invocation_actions = ["no-op"]
        invocation_unknown = {}
        public_actions = ["no-op"]
    else:
        invocation_actions = ["create"]
        invocation_unknown = {"id": True, "result": True}
        public_actions = ["create"]

    return {
        "module.control.aws_kms_key.authority_data": item({"arn": key_arn}),
        "module.control.aws_secretsmanager_secret.hub_key_material[0]": item(
            {
                "arn": secret_arn,
                "description": (
                    "Connector Hub private key and cookie keys; seeded once by "
                    "the keygen Lambda, never via Terraform state"
                ),
                "kms_key_id": key_arn,
                "name": CHECKER.HUB_KEY_MATERIAL_SECRET_NAME,
                "policy": "",
                "recovery_window_in_days": 7,
                "region": CHECKER.AWS_REGION,
            }
        ),
        "module.control.aws_iam_role.hub_keygen[0]": item(
            {
                "arn": CHECKER.HUB_KEYGEN_ROLE_ARN,
                "assume_role_policy": json.dumps(
                    {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Action": "sts:AssumeRole",
                                "Effect": "Allow",
                                "Principal": {"Service": "lambda.amazonaws.com"},
                                "Sid": "LambdaAssume",
                            }
                        ],
                    }
                ),
                "managed_policy_arns": [],
                "max_session_duration": 3600,
                "name": f"{CHECKER.CONTROL_PREFIX}-hub-keygen",
                "path": "/",
                "permissions_boundary": "",
            }
        ),
        "module.control.aws_iam_role_policy.hub_keygen[0]": item(
            {
                "name": "hub-keygen",
                "policy": json.dumps(keygen_policy),
                "role": f"{CHECKER.CONTROL_PREFIX}-hub-keygen",
            },
            actions=["no-op"] if converged else ["update"],
        ),
        "module.control.aws_iam_role_policy.hub_execution[0]": item(
            {
                "name": "hub-execution",
                "policy": json.dumps(execution_policy),
                "role": f"{CHECKER.CONTROL_PREFIX}-hub-exec",
            },
            actions=["no-op"] if converged else ["update"],
        ),
        "module.control.aws_ssm_parameter.hub_public_key[0]": item(
            public,
            actions=public_actions,
        ),
        "module.control.aws_lambda_function.hub_keygen[0]": item(
            {
                "description": (
                    "Seeds or repairs the Connector Hub identity and publishes "
                    "its public key at worker create (sandbox)"
                ),
                "environment": [
                    {
                        "variables": {
                            "ENVIRONMENT": "sandbox",
                            "PUBLIC_KEY_PARAMETER": (
                                CHECKER.HUB_PUBLIC_KEY_PARAMETER_NAME
                            ),
                            "SECRET_ID": secret_arn,
                        }
                    }
                ],
                "filename": (
                    "../../../modules/connector-authority-foundation/lambda/"
                    "hub-keygen.zip"
                ),
                "function_name": CHECKER.HUB_KEYGEN_FUNCTION_NAME,
                "handler": "keygen.handler",
                "package_type": "Zip",
                "reserved_concurrent_executions": 1,
                "role": CHECKER.HUB_KEYGEN_ROLE_ARN,
                "runtime": "nodejs22.x",
                "source_code_hash": source_hash,
                "timeout": 30,
                "vpc_config": [],
            },
            actions=["no-op"] if converged else ["update"],
            unknown=(
                {}
                if converged
                else {"environment": [{"variables": {}}], "vpc_config": []}
            ),
        ),
        "module.control.aws_lambda_invocation.hub_keygen[0]": item(
            {
                "function_name": CHECKER.HUB_KEYGEN_FUNCTION_NAME,
                "input": "{}",
                "lifecycle_scope": "CREATE_ONLY",
                "qualifier": "$LATEST",
                "region": CHECKER.AWS_REGION,
                "tenant_id": None,
                "terraform_key": "tf",
                "triggers": None,
            },
        ),
        "module.control.aws_lambda_invocation.hub_identity_publication[0]": item(
            publication_invocation,
            actions=invocation_actions,
            unknown=invocation_unknown,
        ),
    }


def hub_edge_transition_fixture() -> dict:
    """The Hub public edge slice: the exact edge resources as pure creates."""
    result = plan_fixture()
    result["applyable"] = True
    result["resource_changes"].extend(_hub_edge_resource_changes())
    return result


def hub_source_fence_transition_changes_fixture() -> dict[str, dict]:
    """Exact carrier graph from the reviewed Terraform 1.14.3 plan envelope."""

    payload = REAL_HUB_SOURCE_FENCE_ENVELOPES_PATH.read_bytes()
    if (
        hashlib.sha256(payload).hexdigest()
        != CHECKER.HUB_SOURCE_FENCE_PROVIDER_FIXTURE_SHA256
    ):
        raise AssertionError("Hub source-fence provider fixture digest drift")
    provider_changes = CHECKER._load_hub_source_fence_provider_changes()
    by_address: dict[str, dict] = {
        address: {
            "address": address,
            "mode": "managed",
            "type": "fixture",
            "change": {
                "actions": copy.deepcopy(actions),
                "before": None,
                "after": {"id": address},
                "after_unknown": {},
            },
        }
        for address, actions in CHECKER.HUB_SOURCE_FENCE_ACTIONS.items()
    }
    captured_types = {
        "module.control.aws_lb.hub[0]": "aws_lb",
        "module.control.aws_lb_listener.hub[0]": "aws_lb_listener",
        "module.control.aws_lb_target_group.hub[0]": "aws_lb_target_group",
        "module.control.aws_security_group.hub_worker[0]": "aws_security_group",
        "module.control.aws_ssm_parameter.hub_udp_listener_arn[0]": (
            "aws_ssm_parameter"
        ),
    }
    for address, captured_change in provider_changes.items():
        by_address[address] = {
            "address": address,
            "mode": "managed",
            "type": captured_types[address],
            "change": copy.deepcopy(captured_change),
        }
    return by_address


def _make_exact_noop(item: dict, after: dict) -> None:
    item["change"] = {
        "actions": ["no-op"],
        "before": copy.deepcopy(after),
        "after": copy.deepcopy(after),
        "after_unknown": {},
    }


def hub_source_fence_partial_retry_fixture() -> dict[str, dict]:
    """Retry after the NLB SG and one proof rule already applied."""

    candidate = hub_source_fence_transition_changes_fixture()
    sg_id = "sg-0123456789abcdef0"
    sg_address = "module.control.aws_security_group.hub_nlb[0]"
    rule_address = (
        'module.control.aws_vpc_security_group_ingress_rule.'
        'hub_nlb_udp["0.0.0.0/0"]'
    )
    _make_exact_noop(candidate[sg_address], {"id": sg_id})
    _make_exact_noop(
        candidate[rule_address],
        {
            "id": "sgr-0123456789abcdef0",
            "security_group_id": sg_id,
            "cidr_ipv4": CHECKER.HUB_PUBLIC_UDP_INGRESS_CIDR,
            "ip_protocol": "udp",
            "from_port": 443,
            "to_port": 443,
        },
    )
    nlb_change = candidate["module.control.aws_lb.hub[0]"]["change"]
    nlb_change["after"]["security_groups"] = [sg_id]
    nlb_change["after_unknown"]["security_groups"] = False
    worker_change = candidate[
        "module.control.aws_security_group.hub_worker[0]"
    ]["change"]
    for rule, unknown in zip(
        worker_change["after"]["ingress"],
        worker_change["after_unknown"]["ingress"],
        strict=True,
    ):
        rule["security_groups"] = [sg_id]
        unknown["security_groups"] = False
    return candidate


def hub_source_fence_deposed_retry_fixture(
    *, listener_create: bool,
) -> tuple[dict[str, dict], dict[str, list[dict]]]:
    """Retry after the fenced NLB exists and its legacy instance is deposed."""

    candidate = hub_source_fence_transition_changes_fixture()
    provider = CHECKER._load_hub_source_fence_provider_changes()
    lb_address = "module.control.aws_lb.hub[0]"
    listener_address = "module.control.aws_lb_listener.hub[0]"
    target_address = "module.control.aws_lb_target_group.hub[0]"
    sg_address = "module.control.aws_security_group.hub_nlb[0]"
    sg_id = "sg-0123456789abcdef0"
    target_lb_arn = (
        "arn:aws:elasticloadbalancing:us-east-2:767397897469:"
        "loadbalancer/net/layerv-nhp-sandbox-hub-edge/0123456789abcdef"
    )

    target_lb = copy.deepcopy(provider[lb_address]["before"])
    target_lb.update(
        {
            "arn": target_lb_arn,
            "id": target_lb_arn,
            "arn_suffix": (
                "net/layerv-nhp-sandbox-hub-edge/0123456789abcdef"
            ),
            "dns_name": (
                "layerv-nhp-sandbox-hub-edge-0123456789abcdef."
                "elb.us-east-2.amazonaws.com"
            ),
            "name": CHECKER.HUB_EDGE_LOAD_BALANCER_NAME,
            "security_groups": [sg_id],
        }
    )
    target_lb["tags"]["Name"] = CHECKER.HUB_EDGE_LOAD_BALANCER_NAME
    target_lb["tags_all"]["Name"] = CHECKER.HUB_EDGE_LOAD_BALANCER_NAME
    _make_exact_noop(candidate[lb_address], target_lb)
    _make_exact_noop(candidate[sg_address], {"id": sg_id})

    target_group = copy.deepcopy(provider[target_address]["after"])
    target_group["load_balancer_arns"] = [target_lb_arn]
    _make_exact_noop(candidate[target_address], target_group)

    listener = candidate[listener_address]["change"]
    listener["after"]["load_balancer_arn"] = target_lb_arn
    listener["after_unknown"]["load_balancer_arn"] = False
    if listener_create:
        listener["actions"] = ["create"]
        listener["before"] = None
        listener.pop("replace_paths", None)
        listener.pop("before_sensitive", None)
        listener.pop("before_identity", None)
        listener["after_identity"] = {}

    worker = candidate["module.control.aws_security_group.hub_worker[0]"][
        "change"
    ]
    for rule, unknown in zip(
        worker["after"]["ingress"],
        worker["after_unknown"]["ingress"],
        strict=True,
    ):
        rule["security_groups"] = [sg_id]
        unknown["security_groups"] = False

    deposed = {
        "address": lb_address,
        "deposed": "deadbeef",
        "mode": "managed",
        "type": "aws_lb",
        "name": "hub",
        "change": {
            "actions": ["delete"],
            "before": copy.deepcopy(provider[lb_address]["before"]),
            "after": None,
            "after_unknown": {},
        },
    }
    return candidate, {lb_address: [deposed]}


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
    outputs["provisioned_cells"] = {
        "sensitive": False,
        "type": ["object", {}],
        "value": copy.deepcopy(CHECKER.PROVISIONED_CELL_CATALOG),
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


def dual_digest_refresh_candidate() -> tuple[dict, dict]:
    candidate, prior_state = authority_digest_refresh_candidate()
    hub_candidate, _ = authority_digest_refresh_candidate(hub=True)
    hub_drift = copy.deepcopy(hub_candidate["resource_drift"][0])
    candidate["resource_drift"].append(hub_drift)
    state_resource(
        prior_state, CHECKER._HUB_DIGEST_ADDRESS
    )["values"] = copy.deepcopy(hub_drift["change"]["before"])
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
    def test_prod_catalog_is_pinned_to_the_reviewed_row(self) -> None:
        """Production ships one cell, and its identity is review-pinned.

        The catalog is no longer locked empty — production runs the Authority,
        so it carries a live row. What must not drift is the row's *content*:
        the endpoint identity is pinned from live production readback, and a
        dispatch cannot substitute a different host, port, or server key
        without editing this validation under review.
        """
        variables = PROD_CONTROL_VARIABLES_PATH.read_text(encoding="utf-8")
        start = variables.index('variable "provisioned_cells" {')
        end = variables.index(
            'variable "authority_runtime_contract" {',
            start,
        )
        catalog_block = variables[start:end]

        # Exactly one cell, and it must take general placement: production has
        # no second cell to fall back to, so a non-assignable cell0 would
        # strand every weight-placed agent.
        self.assertIn("cell_id               = \"cell0\"", catalog_block)
        self.assertNotIn("cell1", catalog_block)
        self.assertIn("general_assignable    = true", catalog_block)
        self.assertIn("status                = \"active\"", catalog_block)

        # Endpoint identity pinned from live production readback. Port 443 is
        # the post-#3649 client edge; a row advertising it against a 62206
        # listener places agents on a dead port.
        self.assertIn("nhp_host              = \"cell0.nhp.layerv.ai\"", catalog_block)
        self.assertIn("nhp_port              = 443", catalog_block)

        # The validation must pin the whole row by value, not merely constrain
        # its shape, so any endpoint or lifecycle revision is a reviewed edit.
        self.assertIn(
            "condition = jsonencode(var.provisioned_cells) == jsonencode({",
            catalog_block,
        )

    def test_prod_runtime_gates_default_closed(self) -> None:
        """A plan that does not explicitly open production must stay dark.

        Production Control accepts a real runtime contract now, so the
        protection is no longer a validation that rejects every non-null value.
        It is that each gate DEFAULTS closed: only the reviewed production
        dispatch supplies the open value, and an unreviewed or accidental plan
        creates no functions and no public listener.
        """
        variables = PROD_CONTROL_VARIABLES_PATH.read_text(encoding="utf-8")
        for name, expected_default in (
            ("authority_runtime_contract", "default     = null"),
            ("authority_runtime_contract_evidence_verified", "default     = false"),
            ("authority_runtime_functions_enabled", "default     = false"),
            ("hub_edge_enabled", "default     = false"),
            ("hub_worker_enabled", "default     = false"),
        ):
            with self.subTest(variable=name):
                start = variables.index(f'variable "{name}" {{')
                end = variables.index("\n}\n", start)
                self.assertIn(expected_default, variables[start:end])

    def test_real_terraform_1_14_3_noop_status_contract(self) -> None:
        real_noop = json.loads(
            REAL_TERRAFORM_NOOP_FIXTURE_PATH.read_text(encoding="utf-8")
        )
        self.assertEqual(real_noop["terraform_version"], CHECKER.TF_VERSION)

        candidate = plan_fixture()
        for field in ("format_version", "complete", "errored", "applyable"):
            candidate[field] = real_noop[field]
        self.assertEqual(CHECKER.check_plan(candidate)["resource_count"], 51)

    def test_exact_noop_passes(self) -> None:
        summary = CHECKER.check_plan(plan_fixture())
        self.assertEqual(summary["resource_count"], 51)
        self.assertEqual(summary["plan_mode"], "no-op")
        unrefreshed = plan_fixture()
        unrefreshed_role = self.change(
            unrefreshed, "module.control.aws_iam_role.authority_publisher"
        )
        unrefreshed_role["before"]["inline_policy"] = []
        unrefreshed_role["after"]["inline_policy"] = []
        self.assertEqual(CHECKER.check_plan(unrefreshed)["resource_count"], 51)

    def test_provisioned_cell_catalog_transition_is_exact_and_atomic(self) -> None:
        exact = provisioned_cell_catalog_transition_fixture()
        summary = CHECKER.check_plan(exact)
        self.assertEqual(summary["plan_mode"], "provisioned-cell-catalog")
        self.assertEqual(summary["resource_count"], 51)

        cell0 = (
            'module.control.aws_dynamodb_table_item.provisioned_cell["cell0"]'
        )
        cell1 = (
            'module.control.aws_dynamodb_table_item.provisioned_cell["cell1"]'
        )

        partial = provisioned_cell_catalog_transition_fixture()
        partial_change = self.change(partial, cell1)
        partial_change["actions"] = ["no-op"]
        partial_change["after"] = copy.deepcopy(
            planned_security_fixture()[cell1][0]
        )
        partial_change["before"] = copy.deepcopy(partial_change["after"])
        partial_change["after_unknown"] = {}
        self.assert_rejected(partial)

        wrong_endpoint = provisioned_cell_catalog_transition_fixture()
        wrong_item = json.loads(self.change(wrong_endpoint, cell0)["after"]["item"])
        wrong_item["nhp_host"] = {"S": "attacker.example"}
        self.change(wrong_endpoint, cell0)["after"]["item"] = json.dumps(
            wrong_item, separators=(",", ":"), sort_keys=True
        )
        self.assert_rejected(wrong_endpoint)

        unknown_key = provisioned_cell_catalog_transition_fixture()
        self.change(unknown_key, cell0)["after_unknown"]["item"] = True
        self.assert_rejected(unknown_key)

        wrong_output = provisioned_cell_catalog_transition_fixture()
        wrong_output["planned_values"]["outputs"]["provisioned_cells"]["value"][
            "cell0"
        ]["nhp_port"] = 62206
        self.assert_rejected(wrong_output)

        combined = provisioned_cell_catalog_transition_fixture()
        vpc = self.change(combined, "module.control.aws_vpc.control")
        vpc["actions"] = ["update"]
        vpc["before"] = copy.deepcopy(vpc["after"])
        vpc["after"]["enable_dns_support"] = False
        self.assert_rejected(combined)

        destructive = provisioned_cell_catalog_transition_fixture()
        self.change(destructive, cell0)["actions"] = ["delete"]
        self.assert_rejected(destructive)

    def test_catalog_create_output_admits_optional_general_assignable(
        self,
    ) -> None:
        """The catalog-create output binding admits the resolved
        general_assignable Boolean per cell (absent ⇒ true) and still pins every
        other projected field exactly."""
        # A create whose public output surfaces general_assignable is admitted.
        with_ga = provisioned_cell_catalog_transition_fixture()
        for surface in (
            with_ga["planned_values"]["outputs"]["provisioned_cells"]["value"],
            with_ga["output_changes"]["provisioned_cells"]["after"],
        ):
            surface["cell0"]["general_assignable"] = True
            surface["cell1"]["general_assignable"] = False
        self.assertEqual(
            CHECKER.check_plan(with_ga)["plan_mode"], "provisioned-cell-catalog"
        )

        # A drifted field alongside a valid general_assignable still fails closed.
        drifted = provisioned_cell_catalog_transition_fixture()
        for surface in (
            drifted["planned_values"]["outputs"]["provisioned_cells"]["value"],
            drifted["output_changes"]["provisioned_cells"]["after"],
        ):
            surface["cell0"]["general_assignable"] = True
            surface["cell1"]["general_assignable"] = False
        drifted["output_changes"]["provisioned_cells"]["after"]["cell0"][
            "nhp_port"
        ] = 62206
        self.assert_rejected(drifted)

    def test_catalog_item_admits_rendering_and_still_pins_every_value(
        self,
    ) -> None:
        """Tolerate the provider's serialisation of `item`, nothing else.

        A refreshed read re-renders the row through the provider's Go
        `json.Encoder`, so the applied text is the create-time `jsonencode`
        spelling plus a trailing newline. That difference must be admitted --
        it blocked every PR and the Control Sandbox Update lane on main -- but
        no attribute, type tag or value may move with it.
        """
        cell0 = (
            'module.control.aws_dynamodb_table_item.provisioned_cell["cell0"]'
        )
        canonical = json.loads(
            CHECKER.PROVISIONED_CELL_EXPECTED_ITEM_JSON["cell0"]
        )

        def plan_with_item(rendered: object) -> dict:
            plan = plan_fixture()
            change = self.change(plan, cell0)
            change["after"]["item"] = rendered
            change["before"]["item"] = rendered
            return plan

        # The same object, spelled differently, is the same contract.
        for label, rendered in (
            (
                "create-time jsonencode",
                CHECKER.PROVISIONED_CELL_EXPECTED_ITEM_JSON["cell0"],
            ),
            ("applied trailing newline", applied_provisioned_cell_item("cell0")),
            (
                "reordered keys",
                json.dumps(
                    dict(reversed(list(canonical.items()))),
                    separators=(",", ":"),
                ),
            ),
            ("expanded whitespace", json.dumps(canonical, indent=2)),
        ):
            with self.subTest(rendering=label):
                self.assertEqual(
                    CHECKER.check_plan(plan_with_item(rendered))["plan_mode"],
                    "no-op",
                )

        # One real change per attribute must still fail closed, and must name
        # the attribute that moved rather than the opaque `item` blob.
        for attribute, value in (
            ("status", {"S": "revoked"}),
            ("nhp_host", {"S": "attacker.example"}),
            ("nhp_port", {"N": "62206"}),
            (
                "server_public_key_b64",
                {"S": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},
            ),
            ("selection_weight", {"N": "2"}),
            ("updated_at", {"S": "2026-07-26T00:00:00Z"}),
            ("cell_id", {"S": "cell1"}),
            ("endpoint_revision", {"N": "3"}),
            ("pk", {"S": "REGISTRY-SHADOW"}),
            ("sk", {"S": "CELL#cell1"}),
            # Decoding must not launder DynamoDB's numeric spelling: N values
            # travel as JSON strings, so "1" and "1.0" stay distinct.
            ("selection_weight-respelled", {"N": "1.0"}),
            # Nor may a type tag be swapped under an unchanged value.
            ("selection_weight-retyped", {"S": "1"}),
        ):
            with self.subTest(attribute=attribute):
                name = attribute.split("-")[0]
                drifted = copy.deepcopy(canonical)
                drifted[name] = value
                with self.assertRaisesRegex(
                    CHECKER.ContractError,
                    rf"provisioned-cell item attributes differ: \['{name}'\]",
                ):
                    CHECKER.check_plan(
                        plan_with_item(
                            json.dumps(
                                drifted, separators=(",", ":"), sort_keys=True
                            )
                        )
                    )

        # Added and removed attributes are value differences, not renderings.
        added = copy.deepcopy(canonical)
        added["ttl"] = {"N": "1"}
        with self.assertRaisesRegex(
            CHECKER.ContractError,
            r"provisioned-cell item attributes differ: \['ttl'\]",
        ):
            CHECKER.check_plan(plan_with_item(json.dumps(added)))

        removed = copy.deepcopy(canonical)
        del removed["status"]
        with self.assertRaisesRegex(
            CHECKER.ContractError,
            r"provisioned-cell item attributes differ: \['status'\]",
        ):
            CHECKER.check_plan(plan_with_item(json.dumps(removed)))

        # Decoding may never become a way in: the text must be a JSON object,
        # and a repeated key must not hide a real value behind an admitted one.
        for label, rendered, pattern in (
            ("not JSON", "{not json", r"item is malformed JSON"),
            ("not a string", None, r"item must be JSON text"),
            ("not an object", '"REGISTRY"', r"item is not a JSON object"),
            (
                "repeated key",
                CHECKER.PROVISIONED_CELL_EXPECTED_ITEM_JSON["cell0"].replace(
                    '{"cell_id"',
                    '{"status":{"S":"revoked"},"cell_id"',
                    1,
                ),
                r"item is malformed JSON: object repeats a key",
            ),
        ):
            with self.subTest(rejection=label):
                with self.assertRaisesRegex(CHECKER.ContractError, pattern):
                    CHECKER.check_plan(plan_with_item(rendered))

    def test_general_assignable_is_an_optional_item_attribute(self) -> None:
        """B6: general_assignable is admitted absent / {BOOL:true} / {BOOL:false}
        and nothing else may ride in on that key."""
        address = (
            'module.control.aws_dynamodb_table_item.provisioned_cell["cell1"]'
        )
        frozen = dict(CHECKER.PROVISIONED_CELL_DYNAMODB_ITEMS["cell1"])

        # (i) absent (pre-B6), (ii) explicit true, (iii) explicit false all pass.
        for ga in (None, {"BOOL": True}, {"BOOL": False}):
            item = dict(frozen)
            if ga is not None:
                item["general_assignable"] = ga
            CHECKER._require_provisioned_cell_item(
                {"item": json.dumps(item)}, "cell1", address
            )

        # Any non-Boolean spelling of the attribute is rejected.
        for bad in ({"BOOL": "false"}, {"N": "0"}, {"S": "false"}, True, "true"):
            item = {**frozen, "general_assignable": bad}
            with self.assertRaisesRegex(
                CHECKER.ContractError,
                r"general_assignable must be an absent or Boolean",
            ):
                CHECKER._require_provisioned_cell_item(
                    {"item": json.dumps(item)}, "cell1", address
                )

        # A real change to any OTHER field still fails closed and names it, even
        # with a valid general_assignable present.
        item = {
            **frozen,
            "status": {"S": "revoked"},
            "general_assignable": {"BOOL": False},
        }
        with self.assertRaisesRegex(
            CHECKER.ContractError,
            r"provisioned-cell item attributes differ: \['status'\]",
        ):
            CHECKER._require_provisioned_cell_item(
                {"item": json.dumps(item)}, "cell1", address
            )

    def test_general_assignable_flip_is_its_own_admitted_lane(self) -> None:
        """Setting general_assignable=false on cell1 is admitted as its own plan
        mode, leaving every other catalog field byte-identical (B6)."""
        summary = CHECKER.check_plan(
            provisioned_cell_general_assignable_flip_fixture("cell1", False)
        )
        self.assertEqual(
            summary["plan_mode"], "provisioned-cell-general-assignable-update"
        )
        # Restoring assignability (true) rides the same lane.
        summary_true = CHECKER.check_plan(
            provisioned_cell_general_assignable_flip_fixture("cell1", True)
        )
        self.assertEqual(
            summary_true["plan_mode"],
            "provisioned-cell-general-assignable-update",
        )

    def test_already_flipped_cell_reads_back_as_no_op(self) -> None:
        """A cell whose stored row already carries {BOOL:false} is a steady
        no-op, and an assignable cell that still omits the attribute stays valid
        alongside it (back-compat)."""
        plan = plan_fixture()
        address = (
            'module.control.aws_dynamodb_table_item.provisioned_cell["cell1"]'
        )
        change = self.change(plan, address)
        flipped = {
            **json.loads(change["before"]["item"]),
            "general_assignable": {"BOOL": False},
        }
        change["before"]["item"] = json.dumps(flipped, sort_keys=True)
        change["after"]["item"] = json.dumps(flipped, sort_keys=True)
        plan["planned_values"]["outputs"]["provisioned_cells"]["value"][
            "cell1"
        ]["general_assignable"] = False
        self.assertEqual(CHECKER.check_plan(plan)["plan_mode"], "no-op")

    def test_general_assignable_flip_admits_no_other_edit(self) -> None:
        """Tightness: a plan that moves status, weight, endpoint, key, or
        updated_at alongside general_assignable, or writes a non-Boolean, is
        rejected -- the lane owns only the assignability flag."""
        address = (
            'module.control.aws_dynamodb_table_item.provisioned_cell["cell1"]'
        )
        for field, value in (
            ("status", {"S": "draining"}),
            ("selection_weight", {"N": "2"}),
            ("cell_id", {"S": "cell9"}),
            ("nhp_host", {"S": "attacker.example"}),
            ("updated_at", {"S": "2026-09-01T00:00:00Z"}),
        ):
            with self.subTest(smuggled=field):
                flip = provisioned_cell_general_assignable_flip_fixture(
                    "cell1", False
                )
                change = self.change(flip, address)
                after_item = json.loads(change["after"]["item"])
                after_item[field] = value
                change["after"]["item"] = json.dumps(after_item, sort_keys=True)
                self.assert_rejected(flip)

        # A non-Boolean general_assignable in the item is rejected outright.
        bad_item = provisioned_cell_general_assignable_flip_fixture("cell1", False)
        change = self.change(bad_item, address)
        after_item = json.loads(change["after"]["item"])
        after_item["general_assignable"] = {"N": "0"}
        change["after"]["item"] = json.dumps(after_item, sort_keys=True)
        self.assert_rejected(bad_item)

    def test_general_assignable_output_inventory_is_optional_and_pinned(
        self,
    ) -> None:
        """The public catalog output admits the resolved Boolean but still pins
        every other projected field exactly."""
        # A non-Boolean general_assignable in the output is rejected.
        bad_type = provisioned_cell_general_assignable_flip_fixture("cell1", False)
        bad_type["planned_values"]["outputs"]["provisioned_cells"]["value"][
            "cell1"
        ]["general_assignable"] = "false"
        self.assert_rejected(bad_type)

        # A drifted non-assignability field in the output still fails closed even
        # though general_assignable is present and valid.
        drifted = provisioned_cell_general_assignable_flip_fixture("cell1", False)
        drifted["planned_values"]["outputs"]["provisioned_cells"]["value"][
            "cell0"
        ]["nhp_port"] = 62206
        self.assert_rejected(drifted)

    def test_catalog_row_resource_id_matches_the_applied_provider_spelling(
        self,
    ) -> None:
        """The composite id is the pinned components, provider-separated.

        #3458 calibrated it as "|"-joined from the create plan, where `id` is
        unknown and so was never observed. Every applied row renders it
        ","-joined. Exactly one spelling stays admitted; the unobserved one
        must now fail closed.
        """
        cell0 = (
            'module.control.aws_dynamodb_table_item.provisioned_cell["cell0"]'
        )
        table = CHECKER.PROVISIONED_CELL_TABLE_NAME
        self.assertEqual(
            CHECKER._provisioned_cell_resource_id("cell0"),
            f"{table},REGISTRY,CELL#cell0",
        )
        self.assertEqual(CHECKER.check_plan(plan_fixture())["plan_mode"], "no-op")

        for label, resource_id in (
            ("unobserved pipe spelling", f"{table}|REGISTRY|CELL#cell0"),
            ("other cell", f"{table},REGISTRY,CELL#cell1"),
            ("other table", f"{table}-shadow,REGISTRY,CELL#cell0"),
            ("unseparated", f"{table}REGISTRYCELL#cell0"),
        ):
            with self.subTest(resource_id=label):
                drifted = plan_fixture()
                change = self.change(drifted, cell0)
                change["after"]["id"] = resource_id
                change["before"]["id"] = resource_id
                with self.assertRaisesRegex(
                    CHECKER.ContractError, "steady key identity is not exact"
                ):
                    CHECKER.check_plan(drifted)

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
        self.assertEqual(CHECKER.check_plan(normalized)["resource_count"], 51)

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
            "outputs": {
                "provisioned_cells": {
                    "sensitive": False,
                    "type": ["object", {}],
                    "value": copy.deepcopy(CHECKER.PROVISIONED_CELL_CATALOG),
                }
            },
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
            "module.control.aws_elasticache_user.otp_disabled_default",
            "module.control.aws_elasticache_user.otp_issuer",
        ):
            change = self.change(candidate, address)
            for side in ("before", "after"):
                del change[side]["authentication_mode"][0]["passwords"]

        summary = CHECKER.check_plan(candidate)
        self.assertEqual(summary["resource_count"], 51)
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
        self.assertEqual(summary["resource_count"], 51)
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

    def test_provider_reprojection_admits_the_observed_live_drift(self) -> None:
        """The live sandbox Control root reports 27 drift entries over six
        addresses, every one the provider recording an Optional+Computed
        collection that was absent from state, plus the OTP Redis standalone
        TLS/6379 ingress read-back. Nothing changed in AWS out of band.
        """
        drift = [
            {
                "address": 'module.control.aws_lambda_function.authority["x"]',
                "change": {"before": {"function_name": "x"},
                           "after": {"function_name": "x", "layers": []}},
            },
            {
                "address": "module.control.aws_iam_role.hub_keygen[0]",
                "change": {"before": {"name": "k"},
                           "after": {"name": "k", "managed_policy_arns": []}},
            },
            {
                "address": "module.control.aws_iam_role.hub_execution[0]",
                "change": {"before": {"name": "e"},
                           "after": {"name": "e", "managed_policy_arns": []}},
            },
            {
                "address": CHECKER._OTP_REDIS_SG_ADDRESS,
                "change": {
                    "before": {"ingress": []},
                    "after": {"ingress": [redis_tls_ingress_rule()]},
                },
            },
        ]
        CHECKER._check_provider_reprojection_drift(drift)

    def test_provider_reprojection_admits_inline_policy_readback(self) -> None:
        """`inline_policy` is a deprecated Optional+Computed read-back of the
        separately managed aws_iam_role_policy, so a refreshed plan re-projects
        it even though the role block declares none. Includes the Lambda VPC ENI
        statement, whose `Resource: "*"` is required by AWS because those ec2
        actions do not support resource-level permissions -- an earlier revision
        of this gate rejected exactly that and was wrong.
        """
        policy = json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "LambdaVpcEni",
                        "Effect": "Allow",
                        "Action": ["ec2:CreateNetworkInterface"],
                        "Resource": "*",
                    }
                ],
            }
        )
        CHECKER._check_provider_reprojection_drift(
            [
                {
                    "address": 'module.control.aws_iam_role.authority_exec["z"]',
                    "change": {
                        "before": {"inline_policy": []},
                        "after": {
                            "inline_policy": [
                                {"name": "connector-authority-x", "policy": policy}
                            ]
                        },
                    },
                }
            ]
        )

    def test_provider_reprojection_rejects_malformed_inline_policy(self) -> None:
        """Shape is asserted even though content deliberately is not."""
        cases = {
            "scalar": "not-a-list",
            "empty": [],
            "unparseable": [{"name": "n", "policy": "{not json"}],
            "extra key": [
                {"name": "n", "policy": '{"Statement":[{"Effect":"Allow"}]}', "x": 1}
            ],
            "no statements": [{"name": "n", "policy": '{"Statement":[]}'}],
            "blank name": [
                {"name": "", "policy": '{"Statement":[{"Effect":"Allow"}]}'}
            ],
        }
        for label, value in cases.items():
            with self.subTest(label):
                with self.assertRaises(CHECKER.ContractError):
                    CHECKER._check_provider_reprojection_drift(
                        [
                            {
                                "address": 'module.control.aws_iam_role.hub_keygen[0]',
                                "change": {
                                    "before": {},
                                    "after": {"inline_policy": value},
                                },
                            }
                        ]
                    )

    def test_provider_reprojection_rejects_anything_but_normalization(self) -> None:
        """The address allowlist alone would admit ANY change to these
        resources. The delta itself is what is pinned."""
        cases = {
            "real value change": {
                "address": "module.control.aws_iam_role.hub_keygen[0]",
                "change": {"before": {"name": "k"}, "after": {"name": "attacker"}},
            },
            "non-empty collection appears": {
                "address": "module.control.aws_iam_role.hub_execution[0]",
                "change": {
                    "before": {"name": "e"},
                    "after": {"name": "e", "managed_policy_arns": ["arn:aws:iam::aws:policy/AdministratorAccess"]},
                },
            },
            "widened redis ingress": {
                "address": CHECKER._OTP_REDIS_SG_ADDRESS,
                "change": {
                    "before": {"ingress": []},
                    "after": {
                        "ingress": [
                            {**redis_tls_ingress_rule(), "cidr_blocks": ["0.0.0.0/0"]}
                        ]
                    },
                },
            },
            "second redis rule": {
                "address": CHECKER._OTP_REDIS_SG_ADDRESS,
                "change": {
                    "before": {"ingress": []},
                    "after": {
                        "ingress": [redis_tls_ingress_rule(), redis_tls_ingress_rule()]
                    },
                },
            },
            "empty collection becomes populated": {
                "address": 'module.control.aws_lambda_function.authority["x"]',
                "change": {
                    "before": {"layers": []},
                    "after": {"layers": ["arn:aws:lambda:::layer:evil:1"]},
                },
            },
        }
        for label, item in cases.items():
            with self.subTest(label):
                with self.assertRaises(CHECKER.ContractError):
                    CHECKER._check_provider_reprojection_drift([item])

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

    def test_dual_digest_normalization_reproof_matches_plan(self) -> None:
        candidate, prior_state = dual_digest_refresh_candidate()
        plan_summary = CHECKER.check_plan(candidate, prior_state)

        for order in ("forward", "reverse"):
            with self.subTest(order=order):
                live_candidate = copy.deepcopy(candidate)
                if order == "reverse":
                    live_candidate["resource_drift"].reverse()
                observation = CHECKER.check_normalization_drift(
                    live_candidate, prior_state
                )
                self.assertEqual(
                    observation,
                    {
                        "normalization_drift_count": 2,
                        "normalization_drift_kind": "authority-and-hub-digest",
                        "normalization_drift_sha256": plan_summary[
                            "normalization_drift_sha256"
                        ],
                    },
                )

    def test_dual_digest_normalization_reproof_fails_closed(self) -> None:
        candidate, prior_state = dual_digest_refresh_candidate()
        for missing_address in (
            CHECKER._AUTHORITY_DIGEST_ADDRESS,
            CHECKER._HUB_DIGEST_ADDRESS,
        ):
            with self.subTest(missing_address=missing_address):
                incomplete = [
                    item
                    for item in candidate["resource_drift"]
                    if item["address"] != missing_address
                ]
                with self.assertRaises(CHECKER.ContractError):
                    CHECKER._check_dual_digest_normalization_drift(
                        incomplete, prior_state
                    )

        def assert_rejected(mutate) -> None:
            candidate, prior_state = dual_digest_refresh_candidate()
            mutate(candidate, prior_state)
            with self.assertRaises(CHECKER.ContractError):
                CHECKER.check_normalization_drift(candidate, prior_state)

        def mix_extra(candidate, _prior_state) -> None:
            candidate["resource_drift"].append(
                _substantive_refresh_drift(
                    "module.control.aws_kms_key.authority_data",
                    "aws_kms_key",
                )
            )

        def replace_hub(candidate, _prior_state) -> None:
            candidate["resource_drift"][1] = _substantive_refresh_drift(
                "module.control.aws_kms_key.authority_data",
                "aws_kms_key",
            )

        def wrong_mode(candidate, _prior_state) -> None:
            candidate["resource_changes"] = []

        def moved_state(_candidate, prior_state) -> None:
            state_resource(
                prior_state, CHECKER._HUB_DIGEST_ADDRESS
            )["values"]["version"] = 999

        def wrong_state_type(_candidate, prior_state) -> None:
            state_resource(
                prior_state, CHECKER._HUB_DIGEST_ADDRESS
            )["type"] = "aws_secretsmanager_secret"

        for name, mutate in (
            ("mixed_extra", mix_extra),
            ("missing_hub", replace_hub),
            ("wrong_mode", wrong_mode),
            ("moved_state", moved_state),
            ("wrong_state_type", wrong_state_type),
        ):
            with self.subTest(case=name):
                assert_rejected(mutate)

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
        #
        # These entries are pure first projections, so BOTH lanes now classify
        # them "first-projection" ahead of any reviewed-kind match. The agreement
        # this test exists to prove is what matters and is unchanged; only the
        # kind string moved. Lane agreement is load-bearing: if only one lane
        # filtered, a benign projection would abort the apply as "moved".
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
            "first-projection",
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
        # A re-prove observation carrying a REAL out-of-band value change outside
        # the slice must fail closed in the narrow lane too (not just check_plan).
        # As above, the out-of-slice entry is substantive; a pure first projection
        # there is admitted by design in both lanes.
        exec_role = next(
            address
            for address, resource_type in CHECKER.AUTHORITY_RUNTIME_RESOURCES.items()
            if resource_type == "aws_iam_role"
        )
        refresh = plan_fixture()
        refresh["applyable"] = True
        refresh["resource_drift"] = [
            _slice_refresh_drift(exec_role, "aws_iam_role"),
            _substantive_refresh_drift(
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

        dark_proof, dark_proof_state = publisher_refresh_candidate()
        for proof_output in CHECKER.AUTHORITY_PROOF_ALIAS_OUTPUTS.values():
            dark_proof["planned_values"]["outputs"][proof_output] = {
                "sensitive": False,
                "type": "dynamic",
                "value": None,
            }
            dark_proof["output_changes"][proof_output].update(
                {"before": None, "after": None}
            )
            del dark_proof_state["values"]["outputs"][proof_output]
        self.assertEqual(
            CHECKER.check_plan(dark_proof, dark_proof_state)["plan_mode"],
            "no-op",
        )

        omitted_live, omitted_live_state = publisher_refresh_candidate()
        del omitted_live_state["values"]["outputs"][
            CHECKER.AUTHORITY_PROOF_ALIAS_OUTPUT
        ]
        self.assert_rejected(omitted_live, omitted_live_state)

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
            '"mode":"managed","type":"aws_iam_role"}],'
            '"resources":{"module.control.aws_iam_role.flow_logs":1},'
            '"truncated":false}',
            message,
        )
        self.assertNotIn(sentinel, message)

    def test_unexpected_resource_drift_diagnostic_names_the_resources(self) -> None:
        """A bulk rejection must say WHAT drifted, not just how many.

        Every address carrying a for_each key renders as `<indexed-address>`, so
        a 27-entry rejection over two resources showed eight identical rows and
        nothing else. Diagnosing one took a state download and a
        resource-by-resource diff against live AWS.

        The un-indexed address is a static identifier that already appears in
        this checker's own constants -- no instance key, no attribute, no value
        -- so naming it costs nothing the per-row redaction protects.
        """
        drift = [
            {
                "address": f'module.control.aws_iam_role.authority_exec["fn{index}"]',
                "mode": "managed",
                "type": "aws_iam_role",
            }
            for index in range(20)
        ] + [
            {
                "address": "module.control.aws_iam_role.hub_publisher",
                "mode": "managed",
                "type": "aws_iam_role",
            }
        ]
        decoded = json.loads(CHECKER._drift_identity_diagnostic(drift))
        self.assertEqual(decoded["count"], 21)
        self.assertEqual(
            decoded["resources"],
            {
                "module.control.aws_iam_role.authority_exec": 20,
                "module.control.aws_iam_role.hub_publisher": 1,
            },
            "the histogram must separate the bulk group from the one outlier -- "
            "that outlier is the whole reason a rejection is unexplained",
        )
        # Still value-free: no instance key survives anywhere in the message.
        self.assertNotIn("fn0", json.dumps(decoded))
        self.assertNotIn("[", json.dumps(decoded["resources"]))

    def test_unexpected_resource_drift_histogram_is_bounded(self) -> None:
        """The histogram must not be able to squeeze out an identity row."""
        drift = [
            {
                "address": f"module.control.aws_iam_role.role_{index}",
                "mode": "managed",
                "type": "aws_iam_role",
            }
            for index in range(CHECKER._DRIFT_RESOURCE_HISTOGRAM_LIMIT + 5)
        ]
        decoded = json.loads(CHECKER._drift_identity_diagnostic(drift))
        self.assertLessEqual(
            len(decoded["resources"]), CHECKER._DRIFT_RESOURCE_HISTOGRAM_LIMIT + 1
        )
        self.assertIn("<other-resources>", decoded["resources"])
        self.assertEqual(sum(decoded["resources"].values()), len(drift))

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
        # Count WITHIN the identity rows. The resource histogram now shares the
        # message and caps its own keys with the same marker, so a whole-message
        # count no longer isolates what this assertion is about: that every one
        # of the three fields on every emitted identity was truncated.
        decoded = json.loads(message.split("resource_drift_identity=", 1)[1])
        self.assertEqual(
            json.dumps(decoded["identities"]).count("<truncated>"),
            CHECKER._DRIFT_IDENTITY_LIMIT * 3,
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
            '"type":"<malformed>"}],"resources":{"<malformed>":1},'
            '"truncated":true}',
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
                self.assertEqual(result["resource_count"], 51)
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

    # --- Detached legacy OTP Redis user cleanup (NHP #3362) -------------------

    def test_exact_legacy_otp_user_delete_passes(self) -> None:
        summary = CHECKER.check_plan(legacy_otp_user_delete_fixture())
        self.assertEqual(summary["plan_mode"], "legacy-otp-user-delete")
        # The delete address is retired before the inventory equality check, so
        # the count is the then-current inventory the apply converges on.
        self.assertEqual(summary["resource_count"], 51)
        self.assertEqual(summary["bootstrap_create_count"], 0)
        self.assertNotIn(
            CHECKER.LEGACY_OTP_REDIS_USER_ADDRESS, CHECKER.EXPECTED_RESOURCES
        )

    def test_legacy_otp_user_delete_requires_the_exact_reviewed_before(self) -> None:
        for label, mutate in (
            # A widened or otherwise drifted ACL must be reviewed, not destroyed.
            ("acl", lambda b: b.update({"access_string": "on ~* +@all"})),
            ("user_id", lambda b: b.update({"user_id": "layerv-nhp-sandbox-other"})),
            ("user_name", lambda b: b.update({"user_name": "default"})),
            ("engine", lambda b: b.update({"engine": "valkey"})),
            # A password-backed identity means a long-lived Redis credential
            # exists somewhere; fail closed rather than silently dropping it.
            (
                "password-backed",
                lambda b: b.update(
                    {
                        "authentication_mode": [
                            {"password_count": 1, "passwords": [], "type": "password"}
                        ]
                    }
                ),
            ),
            (
                "password-count",
                lambda b: b.update(
                    {
                        "authentication_mode": [
                            {"password_count": 2, "passwords": [], "type": "iam"}
                        ]
                    }
                ),
            ),
            # Still attached to a user group means it is not the detached user
            # this cleanup reviewed.
            (
                "attached",
                lambda b: b.update(
                    {"user_group_ids": [f"{CHECKER.CONTROL_PREFIX}-otp-users"]}
                ),
            ),
        ):
            with self.subTest(label=label):
                candidate = legacy_otp_user_delete_fixture()
                mutate(self.change(candidate, CHECKER.LEGACY_OTP_REDIS_USER_ADDRESS)["before"])
                self.assert_rejected(candidate)

    def test_legacy_otp_user_address_admits_only_a_delete(self) -> None:
        for actions, after in (
            (["no-op"], legacy_otp_user_before()),
            (["update"], legacy_otp_user_before()),
            (["create"], legacy_otp_user_before()),
            (["create", "delete"], legacy_otp_user_before()),
            # A delete that still plans an after-state is not a removal.
            (["delete"], {"user_id": CHECKER.LEGACY_OTP_REDIS_USER_ID}),
        ):
            with self.subTest(actions=actions):
                candidate = legacy_otp_user_delete_fixture()
                change = self.change(
                    candidate, CHECKER.LEGACY_OTP_REDIS_USER_ADDRESS
                )
                change["actions"] = actions
                change["after"] = after
                self.assert_rejected(candidate)

        # A deposed object at this address is never the reviewed delete.
        deposed = legacy_otp_user_delete_fixture()
        next(
            item
            for item in deposed["resource_changes"]
            if item["address"] == CHECKER.LEGACY_OTP_REDIS_USER_ADDRESS
        )["deposed"] = "4a2844f4"
        self.assert_rejected(deposed)

    def test_legacy_otp_user_delete_cannot_be_combined(self) -> None:
        # The guardrail: no publisher bootstrap, no split-user creation, no
        # runtime activation, and no unrelated Control change may ride along.
        publisher = legacy_otp_user_delete_fixture()
        for address in CHECKER.PUBLISHER_BOOTSTRAP_RESOURCES:
            change = self.change(publisher, address)
            change["actions"] = ["create"]
            change["before"] = None
            if address == "module.control.aws_iam_role.authority_publisher":
                change["after_unknown"]["managed_policy_arns"] = True
            else:
                change["after"]["role"] = None
                change["after_unknown"]["role"] = True
        self.assert_rejected(publisher)

        split = redis_split_transition_fixture()
        split["resource_changes"].append(
            {
                "address": CHECKER.LEGACY_OTP_REDIS_USER_ADDRESS,
                "mode": "managed",
                "type": CHECKER.LEGACY_OTP_REDIS_USER_TYPE,
                "change": {
                    "actions": ["delete"],
                    "before": legacy_otp_user_before(),
                    "after": None,
                },
            }
        )
        self.assert_rejected(split)

        unrelated = legacy_otp_user_delete_fixture()
        group = self.change(
            unrelated, "module.control.aws_elasticache_user_group.otp"
        )
        group["actions"] = ["update"]
        group["before"] = {**group["after"], "user_ids": []}
        self.assert_rejected(unrelated)

    def test_legacy_otp_user_delete_may_carry_authority_digest_normalization(
        self,
    ) -> None:
        # The publisher owns the digest parameter and may have written since the
        # last apply; that inherent refresh noise must not block the cleanup.
        normalization, prior_state = authority_digest_refresh_candidate()
        candidate = legacy_otp_user_delete_fixture()
        candidate["resource_drift"] = copy.deepcopy(normalization["resource_drift"])
        parameter = self.change(candidate, CHECKER._AUTHORITY_DIGEST_ADDRESS)
        parameter["before"] = copy.deepcopy(
            normalization["resource_drift"][0]["change"]["after"]
        )
        parameter["after"] = copy.deepcopy(parameter["before"])

        summary = CHECKER.check_plan(candidate, prior_state)
        self.assertEqual(summary["plan_mode"], "legacy-otp-user-delete")
        self.assertEqual(summary["normalization_drift_kind"], "authority-digest")

    def test_legacy_otp_user_delete_rejects_publisher_role_normalization(self) -> None:
        # Publisher-role normalization stays confined to an exact no-op plan.
        normalization, prior_state = publisher_refresh_candidate()
        candidate = legacy_otp_user_delete_fixture()
        candidate["resource_drift"] = copy.deepcopy(normalization["resource_drift"])
        self.assert_rejected(candidate, prior_state)

    # --- Connector Authority runtime slice (Step 4) ---------------------------

    def test_exact_authority_runtime_slice_passes(self) -> None:
        summary = CHECKER.check_plan(authority_runtime_transition_fixture())
        self.assertEqual(summary["plan_mode"], "authority-runtime-slice")
        self.assertEqual(
            summary["resource_count"],
            len(CHECKER.EXPECTED_RESOURCES) + len(CHECKER.AUTHORITY_RUNTIME_RESOURCES),
        )
        self.assertEqual(summary["bootstrap_create_count"], 0)

    def test_exact_authority_proof_enablement_passes(self) -> None:
        candidate = authority_proof_enable_fixture()
        summary = CHECKER.check_plan(candidate)
        self.assertEqual(summary["plan_mode"], "authority-proof-enable")
        self.assertEqual(
            summary["resource_count"],
            len(CHECKER.EXPECTED_RESOURCES)
            + len(CHECKER.AUTHORITY_RUNTIME_RESOURCES)
            + len(CHECKER.AUTHORITY_PROOF_RESOURCES),
        )
        self.assertEqual(
            {
                item["address"]
                for item in candidate["resource_changes"]
                if item["change"]["actions"] != ["no-op"]
            },
            set(CHECKER.AUTHORITY_PROOF_ENABLE_ALL_CHANGES),
        )
        actions = [
            item["change"]["actions"]
            for item in candidate["resource_changes"]
            if item["change"]["actions"] != ["no-op"]
        ]
        # 32, not 33: the proof-controller invoke grant is no longer created
        # here. It managed an inline policy on a role the udp-proof-runner root
        # owned, and destroying that root (#3804) left it pointing at nothing,
        # so the module released it through a `removed` block.
        self.assertEqual(actions.count(["create"]), 32)
        self.assertEqual(actions.count(["update"]), 2)
        self.assertEqual(
            len(
                {
                    address
                    for address in CHECKER.AUTHORITY_PROOF_RESOURCES
                    if CHECKER.AUTHORITY_PROOF_RECOVERY_FUNCTION_NAME in address
                }
            ),
            16,
        )
        self.assertEqual(
            CHECKER.check_plan(authority_proof_steady_fixture())["plan_mode"],
            "no-op",
        )

    def test_exact_authority_proof_disable_passes_and_dark_remains_noop(
        self,
    ) -> None:
        summary = CHECKER.check_plan(authority_proof_disable_fixture())
        self.assertEqual(summary["plan_mode"], "authority-proof-disable")
        self.assertEqual(
            CHECKER.check_plan(authority_runtime_steady_fixture())["plan_mode"],
            "no-op",
        )

    def test_authority_proof_disable_rejects_partial_foreign_or_extra_graph(
        self,
    ) -> None:
        partial = authority_proof_disable_fixture()
        removed = next(iter(CHECKER.AUTHORITY_PROOF_RESOURCES))
        partial["resource_changes"] = [
            item for item in partial["resource_changes"]
            if item["address"] != removed
        ]
        self.assert_rejected(partial)

        foreign = authority_proof_disable_fixture()
        foundation = self.change(
            foreign, "module.control.terraform_data.foundation_contract"
        )
        foundation["after"]["input"]["authority_image_uri"] = (
            "public.ecr.aws/foreign/authority@sha256:" + "f" * 64
        )
        foundation["after"]["output"] = copy.deepcopy(
            foundation["after"]["input"]
        )
        self.assert_rejected(foreign)

        extra = authority_proof_disable_fixture()
        unrelated = self.change(
            extra, "module.control.aws_security_group.interface_endpoints"
        )
        unrelated["actions"] = ["update"]
        unrelated["before"] = {
            **copy.deepcopy(unrelated["after"]),
            "description": "foreign drift",
        }
        self.assert_rejected(extra)

    def test_authority_proof_disable_rejects_output_env_or_iam_drift(
        self,
    ) -> None:
        output = authority_proof_disable_fixture()
        output["planned_values"]["outputs"][
            CHECKER.AUTHORITY_PROOF_ALIAS_OUTPUT
        ] = {
            "sensitive": False,
            "type": "dynamic",
            "value": None,
        }
        self.assert_rejected(output)

        environment = authority_proof_disable_fixture()
        function_change = self.change(
            environment,
            (
                "module.control.aws_lambda_function.authority"
                f'["{next(iter(CHECKER.AUTHORITY_RUNTIME_HUB_FUNCTIONS))}"]'
            ),
        )
        function_change["actions"] = ["update"]
        function_change["before"] = copy.deepcopy(function_change["after"])
        function_change["after"] = {
            **copy.deepcopy(function_change["after"]),
            "environment": [{"variables": _proof_environment()}],
        }
        self.assert_rejected(environment)

        endpoint = authority_proof_disable_fixture()
        ddb = self.change(endpoint, CHECKER.AUTHORITY_RUNTIME_DYNAMODB_ADDRESS)
        proof_policy = json.loads(ddb["before"]["policy"])
        ddb["after"]["policy"] = json.dumps(proof_policy)
        self.assert_rejected(endpoint)

        replay = authority_proof_disable_fixture()
        policy_change = self.change(
            replay,
            (
                "module.control.aws_iam_role_policy.authority_exec"
                f'["{CHECKER.AUTHORITY_PROOF_FUNCTION_NAME}"]'
            ),
        )
        policy = json.loads(policy_change["before"]["policy"])
        replay_statement = next(
            statement
            for statement in policy["Statement"]
            if statement["Sid"] == "ProofReplayReadWrite"
        )
        replay_statement["Condition"]["ForAllValues:StringLike"][
            "dynamodb:LeadingKeys"
        ] = ["HUB_REQUEST#*"]
        policy_change["before"]["policy"] = json.dumps(policy)
        self.assert_rejected(replay)


    def test_authority_proof_enablement_rejects_partial_or_foreign_graph(
        self,
    ) -> None:
        partial = authority_proof_enable_fixture()
        removed = next(iter(CHECKER.AUTHORITY_PROOF_RESOURCES))
        partial["resource_changes"] = [
            item for item in partial["resource_changes"]
            if item["address"] != removed
        ]
        self.assert_rejected(partial)

        foreign = authority_proof_enable_fixture()
        foundation = self.change(
            foreign, "module.control.terraform_data.foundation_contract"
        )
        functions = foundation["after"]["input"]["authority_runtime_contract"][
            "functions"
        ]
        functions["layerv-nhp-sandbox-ca-pm-foreign"] = functions.pop(
            CHECKER.AUTHORITY_PROOF_FUNCTION_NAME
        )
        self.assert_rejected(foreign)

        extra = authority_proof_enable_fixture()
        extra["resource_changes"].append(
            {
                "address": (
                    "module.control.aws_cloudwatch_log_group.authority"
                    '["layerv-nhp-sandbox-ca-pcr-foreign"]'
                ),
                "mode": "managed",
                "type": "aws_cloudwatch_log_group",
                "change": _runtime_create(
                    {"name": "/aws/lambda/layerv-nhp-sandbox-ca-pcr-foreign"}
                ),
            }
        )
        self.assert_rejected(extra)

    def test_authority_proof_enablement_rejects_security_or_output_drift(
        self,
    ) -> None:
        replay = authority_proof_enable_fixture()
        policy_change = self.change(
            replay,
            (
                "module.control.aws_iam_role_policy.authority_exec"
                f'["{CHECKER.AUTHORITY_PROOF_FUNCTION_NAME}"]'
            ),
        )
        policy = json.loads(policy_change["after"]["policy"])
        replay_statement = next(
            statement
            for statement in policy["Statement"]
            if statement["Sid"] == "ProofReplayReadWrite"
        )
        replay_statement["Condition"]["ForAllValues:StringLike"][
            "dynamodb:LeadingKeys"
        ] = ["HUB_REQUEST#*"]
        policy_change["after"]["policy"] = json.dumps(policy)
        self.assert_rejected(replay)

        recovery = authority_proof_enable_fixture()
        recovery_policy_change = self.change(
            recovery,
            (
                "module.control.aws_iam_role_policy.authority_exec"
                f'["{CHECKER.AUTHORITY_PROOF_RECOVERY_FUNCTION_NAME}"]'
            ),
        )
        recovery_policy = json.loads(recovery_policy_change["after"]["policy"])
        recovery_replay = next(
            statement
            for statement in recovery_policy["Statement"]
            if statement["Sid"] == "ProofRecoveryReplayReadWrite"
        )
        recovery_replay["Resource"] = ["*"]
        recovery_policy_change["after"]["policy"] = json.dumps(recovery_policy)
        self.assert_rejected(recovery)

        environment = authority_proof_enable_fixture()
        function_change = self.change(
            environment,
            (
                "module.control.aws_lambda_function.authority"
                f'["{next(iter(CHECKER.AUTHORITY_RUNTIME_HUB_FUNCTIONS))}"]'
            ),
        )
        function_change["actions"] = ["update"]
        function_change["before"] = copy.deepcopy(function_change["after"])
        function_change["after"] = {
            **copy.deepcopy(function_change["after"]),
            "environment": [{"variables": _proof_environment()}],
        }
        self.assert_rejected(environment)


        output = authority_proof_enable_fixture()
        output["output_changes"][CHECKER.AUTHORITY_PROOF_ALIAS_OUTPUT][
            "after"
        ] = (
            f"arn:aws:lambda:{CHECKER.AWS_REGION}:{CHECKER.ACCOUNT_ID}:"
            f"function:{CHECKER.AUTHORITY_PROOF_FUNCTION_NAME}:green"
        )
        self.assert_rejected(output)

    def test_proof_policy_consumer_pins_read_and_deny_set_operators(
        self,
    ) -> None:
        operation = "issue_assignment"
        fn = next(
            function_name
            for function_name, function_operation in (
                CHECKER.AUTHORITY_RUNTIME_FUNCTIONS.items()
            )
            if function_operation == operation
        )
        table_resources = sorted(
            CHECKER.AUTHORITY_RUNTIME_TABLE_RESOURCES["connector_authority"]
        )
        policy = json.loads(runtime_exec_policy(fn, operation))
        policy["Statement"].extend(
            [
                {
                    "Sid": "ProofPolicyRead",
                    "Effect": "Allow",
                    "Action": ["dynamodb:GetItem"],
                    "Resource": table_resources,
                    "Condition": {
                        "ForAllValues:StringEquals": {
                            "dynamodb:LeadingKeys": ["PROOF"],
                        },
                        "Null": {"dynamodb:LeadingKeys": "false"},
                    },
                },
                {
                    "Sid": "DenyProofPolicyWrite",
                    "Effect": "Deny",
                    "Action": [
                        "dynamodb:DeleteItem",
                        "dynamodb:PutItem",
                        "dynamodb:UpdateItem",
                    ],
                    "Resource": table_resources,
                    "Condition": {
                        "ForAnyValue:StringEquals": {
                            "dynamodb:LeadingKeys": ["PROOF"],
                        },
                        "Null": {"dynamodb:LeadingKeys": "false"},
                    },
                },
            ]
        )
        after = {"policy": json.dumps(policy)}
        CHECKER._check_authority_exec_role_policy(
            after,
            fn,
            operation,
            proof_policy_consumer=True,
        )

        for sid, current_operator, wrong_operator in (
            ("ProofPolicyRead", "ForAllValues:StringEquals", "ForAnyValue:StringEquals"),
            ("DenyProofPolicyWrite", "ForAnyValue:StringEquals", "ForAllValues:StringEquals"),
        ):
            with self.subTest(sid=sid):
                malformed = copy.deepcopy(policy)
                statement = next(
                    candidate
                    for candidate in malformed["Statement"]
                    if candidate["Sid"] == sid
                )
                statement["Condition"][wrong_operator] = statement[
                    "Condition"
                ].pop(current_operator)
                with self.assertRaisesRegex(
                    CHECKER.ContractError,
                    "proof policy must be exact",
                ):
                    CHECKER._check_authority_exec_role_policy(
                        {"policy": json.dumps(malformed)},
                        fn,
                        operation,
                        proof_policy_consumer=True,
                    )

    def test_exact_connector_resource_runtime_expansion_passes(self) -> None:
        candidate = authority_connector_resource_expansion_fixture()
        summary = CHECKER.check_plan(candidate)
        self.assertEqual(
            summary["plan_mode"], "authority-connector-resource-expansion"
        )
        changed = {
            item["address"]
            for item in candidate["resource_changes"]
            if item["change"]["actions"] != ["no-op"]
        }
        self.assertEqual(len(CHECKER.AUTHORITY_CONNECTOR_RESOURCE_FUNCTIONS), 2)
        self.assertEqual(
            len(CHECKER.AUTHORITY_CONNECTOR_RESOURCE_EXPANSION_CREATE_ADDRESSES),
            32,
        )
        self.assertEqual(
            changed,
            set(CHECKER.AUTHORITY_CONNECTOR_RESOURCE_EXPANSION_CREATE_ADDRESSES)
            | set(CHECKER.AUTHORITY_CONNECTOR_RESOURCE_EXPANSION_UPDATE_ADDRESSES),
        )

    def test_connector_resource_expansion_partial_retry_passes(self) -> None:
        creates = set(
            CHECKER.AUTHORITY_CONNECTOR_RESOURCE_EXPANSION_CREATE_ADDRESSES
        )
        updates = set(
            CHECKER.AUTHORITY_CONNECTOR_RESOURCE_EXPANSION_UPDATE_ADDRESSES
        )
        complete = creates | updates
        foundation_address = (
            "module.control.terraform_data.foundation_contract"
        )
        last_nonfoundation = sorted(complete - {foundation_address})[-1]
        progressions = {
            # Terraform may fail before or after writing the contract record;
            # neither ordering may broaden the exact missing-resource set.
            "foundation-only": {
                foundation_address
            },
            "one-create-only": {sorted(creates)[0]},
            "one-update-only": {sorted(updates)[0]},
            "all-creates": creates,
            "all-updates": updates,
            "one-resource-remaining": complete - {last_nonfoundation},
        }

        for state, applied in progressions.items():
            with self.subTest(state=state):
                summary = CHECKER.check_plan(
                    authority_connector_resource_expansion_fixture(applied)
                )
                self.assertEqual(
                    summary["plan_mode"],
                    "authority-connector-resource-expansion",
                )

        # Once every exact member has applied, the retry must collapse to a
        # true no-op. This is the state that releases the downstream workflow's
        # fresh cell-plan authorization without accepting an extra mutation.
        converged = authority_connector_resource_expansion_fixture(complete)
        converged["applyable"] = False
        summary = CHECKER.check_plan(converged)
        self.assertEqual(
            summary["plan_mode"], "no-op"
        )

    def test_connector_resource_expansion_rejects_predecessor_drift(self) -> None:
        mutations = (
            lambda contract: contract["global"]["basis_evidence"].__setitem__(
                "sha256", "f" * 64
            ),
            lambda contract: contract["global"]["caller_capacity"][
                "cell_workers"
            ]["cell0"]["preinvoke_limits"].__setitem__(
                "resolve_connector_resource", 1
            ),
            lambda contract: contract["provisioned_cells"]["cell1"].__setitem__(
                "cell_table_prefix", "layerv-nhp-sandbox-cell1-cell1"
            ),
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                candidate = authority_connector_resource_expansion_fixture()
                foundation = self.change(
                    candidate, "module.control.terraform_data.foundation_contract"
                )
                mutation(
                    foundation["before"]["input"]["authority_runtime_contract"]
                )
                self.assert_rejected(candidate)

    def test_connector_resource_expansion_rejects_foreign_change(self) -> None:
        candidate = authority_connector_resource_expansion_fixture()
        foreign = self.change(
            candidate, CHECKER.AUTHORITY_RUNTIME_SECRETS_ENDPOINT_ADDRESS
        )
        foreign["actions"] = ["update"]
        self.assert_rejected(candidate)

    def test_exact_legacy_hub_runtime_expansion_passes(self) -> None:
        candidate = authority_runtime_legacy_expansion_fixture()
        summary = CHECKER.check_plan(candidate)
        self.assertEqual(
            summary["plan_mode"], "authority-runtime-legacy-expansion"
        )
        changed = {
            item["address"]
            for item in candidate["resource_changes"]
            if item["change"]["actions"] != ["no-op"]
        }
        self.assertEqual(
            changed,
            set(CHECKER.AUTHORITY_RUNTIME_LEGACY_EXPANSION_CREATE_ADDRESSES)
            | set(CHECKER.AUTHORITY_RUNTIME_LEGACY_EXPANSION_UPDATE_ADDRESSES)
            | set(CHECKER.AUTHORITY_RUNTIME_LEGACY_EXPANSION_REPLACE_ADDRESSES),
        )

    def test_legacy_expansion_may_roll_only_the_exact_authority_digest(
        self,
    ) -> None:
        candidate = with_legacy_authority_digest_roll(
            authority_runtime_legacy_expansion_fixture()
        )
        summary = CHECKER.check_plan(candidate)
        self.assertEqual(
            summary["plan_mode"], "authority-runtime-legacy-expansion"
        )

        for mutation in (
            lambda before: before.__setitem__(
                "authority_image_uri", "repository.example/authority:latest"
            ),
            lambda before: before["authority_runtime_contract"]["global"].__setitem__(
                "authority_image_digest", "sha256:" + "3" * 64
            ),
            lambda before: before["authority_runtime_contract"]["global"].__setitem__(
                "authority_repository_url", "public.ecr.aws/attacker/authority"
            ),
        ):
            malformed = copy.deepcopy(candidate)
            foundation = self.change(
                malformed, "module.control.terraform_data.foundation_contract"
            )
            mutation(foundation["before"]["input"])
            self.assert_rejected(malformed)

        mixed_predecessor = copy.deepcopy(candidate)
        first_hub_function = next(
            iter(CHECKER.AUTHORITY_RUNTIME_HUB_FUNCTIONS)
        )
        self.change(
            mixed_predecessor,
            (
                'module.control.aws_lambda_function.authority["'
                f'{first_hub_function}"]'
            ),
        )["before"]["image_uri"] = (
            "public.ecr.aws/attacker/authority@sha256:" + "4" * 64
        )
        self.assert_rejected(mixed_predecessor)

    def test_legacy_hub_runtime_expansion_partial_retry_passes(self) -> None:
        applied = {
            "module.control.terraform_data.foundation_contract",
            CHECKER.AUTHORITY_RUNTIME_LAMBDA_SG_ADDRESS,
            CHECKER.AUTHORITY_RUNTIME_INTERFACE_SG_ADDRESS,
            next(
                iter(CHECKER.AUTHORITY_RUNTIME_LEGACY_EXPANSION_CREATE_ADDRESSES)
            ),
            CHECKER.AUTHORITY_RUNTIME_KMS_ENDPOINT_ADDRESS,
        }
        summary = CHECKER.check_plan(
            authority_runtime_legacy_expansion_fixture(applied)
        )
        self.assertEqual(
            summary["plan_mode"], "authority-runtime-legacy-expansion"
        )

    def test_legacy_expansion_may_carry_only_the_complete_cell_catalog(
        self,
    ) -> None:
        candidate = with_provisioned_cell_catalog_transition(
            authority_runtime_legacy_expansion_fixture()
        )
        summary = CHECKER.check_plan(candidate)
        self.assertEqual(
            summary["plan_mode"],
            (
                "authority-runtime-legacy-expansion-"
                "provisioned-cell-catalog"
            ),
        )

        partial = copy.deepcopy(candidate)
        cell1 = (
            'module.control.aws_dynamodb_table_item.provisioned_cell["cell1"]'
        )
        partial_change = self.change(partial, cell1)
        partial_change["actions"] = ["no-op"]
        partial_change["before"] = copy.deepcopy(partial_change["after"])
        partial_change["after_unknown"] = {}
        self.assert_rejected(partial)

        wrong_output = copy.deepcopy(candidate)
        wrong_output["planned_values"]["outputs"]["provisioned_cells"]["value"][
            "cell0"
        ]["nhp_host"] = "attacker.example"
        self.assert_rejected(wrong_output)

    def test_legacy_hub_runtime_expansion_rejects_predecessor_drift(self) -> None:
        candidate = authority_runtime_legacy_expansion_fixture()
        foundation = self.change(
            candidate, "module.control.terraform_data.foundation_contract"
        )
        foundation["before"]["input"]["authority_runtime_contract"]["global"][
            "basis_evidence"
        ]["sha256"] = "f" * 64
        self.assert_rejected(candidate)

    def test_legacy_expansion_predecessor_bases_are_exactly_two_reviewed(
        self,
    ) -> None:
        """Pin the admitted predecessor set to the image transition's endpoints.

        The live legacy Hub predecessor is either the basis the expansion was
        reviewed against or -- once the reviewed image update applied its
        contract -- that transition's own after-basis. Enumerating a third entry
        would admit a predecessor no reviewed transition produces.
        """
        candidates = CHECKER.AUTHORITY_RUNTIME_LEGACY_HUB_EVIDENCE_CANDIDATES
        self.assertEqual(len(candidates), 2)
        shared = {
            "path": "docs/evidence/connector-authority/v1/"
            "sandbox-measurement-basis.json",
            "repository": "layervai/nhp",
            "schema_version": 1,
        }
        self.assertEqual(
            list(candidates),
            [
                {
                    **shared,
                    "sha256": "d535970977ba3b31da2b224c01897c535786ff802a91edbe8319884c23924eff",
                    "source_commit": "388a22f7a5333a246e623a19dd5ca3793bd89f60",
                },
                {
                    **shared,
                    "sha256": "b44ee0ca10d555db931713f2809b1e45c149c0382d5aaee2a5bf1cf252b55056",
                    "source_commit": "38c11ec130f7443339581eb42692f3577812f904",
                },
            ],
        )

    def test_legacy_expansion_accepts_the_applied_image_update_predecessor(
        self,
    ) -> None:
        """The expansion may plan from the already-applied image-update basis.

        The reviewed image update converged the foundation contract and each Hub
        function's $LATEST before failing on ``lambda:PublishVersion``, so the
        expansion's live predecessor now carries that transition's TO basis while
        the pending alias rebind remains in the expansion's update envelope.
        """
        candidate = with_legacy_predecessor_at_image_update_basis(
            authority_runtime_legacy_expansion_fixture()
        )
        summary = CHECKER.check_plan(candidate)
        self.assertEqual(summary["plan_mode"], "authority-runtime-legacy-expansion")

    def test_legacy_expansion_rejects_unreviewed_or_mixed_predecessor_bases(
        self,
    ) -> None:
        """Neither endpoint may be forged, blended, or partially applied."""
        from_basis, to_basis = (
            CHECKER.AUTHORITY_RUNTIME_LEGACY_HUB_EVIDENCE_CANDIDATES
        )
        from_sha = from_basis["sha256"]
        from_source = from_basis["source_commit"]
        to_sha = to_basis["sha256"]
        to_source = to_basis["source_commit"]

        def unreviewed_third_basis(candidate: dict) -> None:
            for evidence in legacy_expansion_evidence_slots(candidate):
                evidence["sha256"] = "f" * 64
                evidence["source_commit"] = "a" * 40

        def blended_sha_and_commit(candidate: dict) -> None:
            for evidence in legacy_expansion_evidence_slots(candidate):
                evidence["sha256"] = to_sha
                evidence["source_commit"] = from_source

        def only_global_advanced(candidate: dict) -> None:
            for evidence in legacy_expansion_evidence_slots(candidate)[:1]:
                evidence["sha256"] = to_sha
                evidence["source_commit"] = to_source

        def catalog_left_behind(candidate: dict) -> None:
            slots = legacy_expansion_evidence_slots(candidate)
            for evidence in slots:
                evidence["sha256"] = to_sha
                evidence["source_commit"] = to_source
            for evidence in slots[1::5]:
                evidence["sha256"] = from_sha
                evidence["source_commit"] = from_source

        def tampered_repository(candidate: dict) -> None:
            for evidence in legacy_expansion_evidence_slots(candidate):
                evidence["sha256"] = to_sha
                evidence["source_commit"] = to_source
                evidence["repository"] = "attacker/nhp"

        for mutation in (
            unreviewed_third_basis,
            blended_sha_and_commit,
            only_global_advanced,
            catalog_left_behind,
            tampered_repository,
        ):
            with self.subTest(mutation=mutation.__name__):
                candidate = authority_runtime_legacy_expansion_fixture()
                mutation(candidate)
                self.assert_rejected(candidate)

    def test_runtime_slice_may_not_absorb_the_provisioned_cell_catalog(
        self,
    ) -> None:
        """The narrowing subtractions must not shrink the global change set.

        Only the legacy expansion composes with the two-row catalog, and only
        under a plan_mode that names it. Aliasing the candidate set to ``changed``
        instead of copying it let the catalog rows be subtracted out from under
        every later transition test, admitting this pair as a bare
        ``authority-runtime-slice`` -- and, when a subtraction emptied the set
        entirely, as plan_mode "no-op".
        """
        candidate = with_provisioned_cell_catalog_transition(
            authority_runtime_transition_fixture()
        )
        self.assert_rejected(candidate)

    def test_legacy_hub_runtime_expansion_rejects_caller_catalog_drift(
        self,
    ) -> None:
        candidate = authority_runtime_legacy_expansion_fixture()
        foundation = self.change(
            candidate, "module.control.terraform_data.foundation_contract"
        )
        foundation["after"]["input"]["authority_runtime_contract"]["global"][
            "caller_capacity"
        ]["cell_workers"]["cell2"] = {"max_replicas": 2}
        self.assert_rejected(candidate)

    def test_legacy_hub_runtime_expansion_rejects_extra_update(self) -> None:
        candidate = authority_runtime_legacy_expansion_fixture()
        ia_role = (
            'module.control.aws_iam_role.authority_exec["'
            f'{CHECKER.CONTROL_PREFIX.removesuffix("-control")}-ca-ia"]'
        )
        self.change(candidate, ia_role)["actions"] = ["update"]
        self.assert_rejected(candidate)

    def test_legacy_hub_runtime_expansion_rejects_retained_sg_cidr(
        self,
    ) -> None:
        candidate = authority_runtime_legacy_expansion_fixture()
        lambda_sg = self.change(candidate, CHECKER.AUTHORITY_RUNTIME_LAMBDA_SG_ADDRESS)
        lambda_sg["after"]["egress"] = copy.deepcopy(lambda_sg["before"]["egress"])
        self.assert_rejected(candidate)

    def test_legacy_hub_runtime_expansion_rejects_wrong_sg_predecessor(
        self,
    ) -> None:
        candidate = authority_runtime_legacy_expansion_fixture()
        lambda_sg = self.change(candidate, CHECKER.AUTHORITY_RUNTIME_LAMBDA_SG_ADDRESS)
        lambda_sg["before"]["egress"][0]["cidr_blocks"] = ["0.0.0.0/0"]
        self.assert_rejected(candidate)

    def test_legacy_hub_runtime_expansion_rejects_noncreate_cell_resource(
        self,
    ) -> None:
        candidate = authority_runtime_legacy_expansion_fixture()
        address = next(
            iter(CHECKER.AUTHORITY_RUNTIME_LEGACY_EXPANSION_CREATE_ADDRESSES)
        )
        self.change(candidate, address)["actions"] = ["update"]
        self.assert_rejected(candidate)
    def test_authority_image_update_admits_exactly_the_full_function_graph(
        self,
    ) -> None:
        """Pin the migration to every function and its two closed aliases."""
        functions = set(CHECKER.AUTHORITY_RUNTIME_FUNCTIONS_WITH_PROOF)
        expected = {
            f'module.control.aws_lambda_function.authority["{fn}"]':
                "aws_lambda_function"
            for fn in functions
        }
        expected.update({
            f'module.control.aws_lambda_alias.authority["{fn}:{color}"]':
                "aws_lambda_alias"
            for fn in functions
            for color in ("blue", "green")
        })
        self.assertEqual(CHECKER.AUTHORITY_IMAGE_UPDATE_RESOURCES, expected)
        self.assertEqual(len(CHECKER.AUTHORITY_IMAGE_UPDATE_RESOURCES), 45)

    def test_authority_image_update_rejects_non_image_runtime_movement(
        self,
    ) -> None:
        role_address = next(
            address
            for address, resource_type in {
                **CHECKER.AUTHORITY_RUNTIME_RESOURCES,
                **CHECKER.AUTHORITY_PROOF_RESOURCES,
            }.items()
            if resource_type == "aws_iam_role"
        )
        candidate = authority_image_update_fixture()
        self.change(candidate, role_address)["actions"] = ["update"]
        self.assert_rejected(candidate)

    def test_exact_authority_image_update_and_partial_completion_pass(self) -> None:
        exact = authority_image_update_fixture()
        summary = CHECKER.check_plan(exact)
        self.assertEqual(summary["plan_mode"], "authority-image-update")
        self.assertEqual(
            summary["resource_count"],
            len(exact["resource_changes"]),
        )

        alias_only = {
            next(
                address
                for address, resource_type in CHECKER.AUTHORITY_IMAGE_UPDATE_RESOURCES.items()
                if resource_type == "aws_lambda_alias"
            )
        }
        partial = authority_image_update_fixture(alias_only)
        self.assertEqual(
            CHECKER.check_plan(partial)["plan_mode"],
            "authority-image-update",
        )

        foundation_only = authority_image_update_fixture(
            set(), foundation_pending=True
        )
        self.assertEqual(
            CHECKER.check_plan(foundation_only)["plan_mode"],
            "authority-image-update",
        )

        recovery = authority_image_update_fixture(
            recovery_replaces=set(CHECKER.AUTHORITY_IMAGE_UPDATE_RECOVERY_REPLACES),
        )
        self.assertEqual(
            CHECKER.check_plan(recovery)["plan_mode"],
            "authority-image-update",
        )
        pr_recovery = authority_image_update_fixture(
            recovery_replaces=set(CHECKER.AUTHORITY_IMAGE_UPDATE_RECOVERY_REPLACES),
            refresh_disabled=True,
        )
        self.assertEqual(
            CHECKER.check_plan(
                pr_recovery,
                refresh_disabled=True,
            )["plan_mode"],
            "authority-image-update",
        )

    def test_authority_image_update_rejects_unobserved_concurrency_recovery(
        self,
    ) -> None:
        recovery_addresses = set(
            CHECKER.AUTHORITY_IMAGE_UPDATE_RECOVERY_REPLACES
        )
        for actions in (["create"], ["update"]):
            with self.subTest(actions=actions):
                candidate = authority_image_update_fixture(
                    recovery_replaces=recovery_addresses,
                )
                address = next(iter(recovery_addresses))
                change = self.change(candidate, address)
                change["actions"] = actions
                self.assert_rejected(candidate)

        singleton = authority_image_update_fixture(
            recovery_replaces=recovery_addresses,
        )
        settled_address = next(iter(recovery_addresses))
        settled = self.change(singleton, settled_address)
        settled["actions"] = ["no-op"]
        settled["before"] = copy.deepcopy(settled["after"])
        settled["after_unknown"] = {}
        settled["before_sensitive"] = {}
        settled["after_sensitive"] = {}
        self.assertEqual(
            CHECKER.check_plan(singleton)["plan_mode"],
            "authority-image-update",
        )

        foreign = authority_image_update_fixture()
        foreign_address = next(
            address
            for address, resource_type in CHECKER.AUTHORITY_RUNTIME_RESOURCES.items()
            if resource_type == "aws_lambda_provisioned_concurrency_config"
        )
        function_name = foreign_address.rsplit('["', 1)[1][:-2]
        change = self.change(foreign, foreign_address)
        change.update(
            {
                "actions": ["delete", "create"],
                "before": {
                    "function_name": function_name,
                    "id": f"{function_name},blue",
                    "provisioned_concurrent_executions": 0,
                    "qualifier": "blue",
                    "skip_destroy": False,
                    "timeouts": None,
                },
                "after": {
                    "function_name": function_name,
                    "provisioned_concurrent_executions": 1,
                    "qualifier": "blue",
                    "skip_destroy": False,
                    "timeouts": None,
                },
                "after_unknown": {"id": True},
                "before_sensitive": {},
                "after_sensitive": {},
            }
        )
        self.assert_rejected(foreign)

    def test_authority_image_recovery_admits_exact_proof_concurrency_drift(
        self,
    ) -> None:
        recovery_addresses = set(
            CHECKER.AUTHORITY_IMAGE_UPDATE_RECOVERY_REPLACES
        )
        candidate = authority_image_update_fixture(
            recovery_replaces=recovery_addresses,
        )
        candidate["resource_drift"] = (
            authority_proof_concurrency_recovery_drift(recovery_addresses)
        )
        summary = CHECKER.check_plan(candidate)
        self.assertEqual(summary["plan_mode"], "authority-image-update")
        self.assertEqual(summary["normalization_drift_count"], 2)
        self.assertEqual(
            summary["normalization_drift_kind"],
            CHECKER.AUTHORITY_PROOF_CONCURRENCY_RECOVERY_NORMALIZATION_KIND,
        )

        singleton = {next(iter(recovery_addresses))}
        partial = authority_image_update_fixture(
            pending_addresses=set(),
            foundation_pending=False,
            recovery_replaces=singleton,
        )
        partial["resource_drift"] = (
            authority_proof_concurrency_recovery_drift(singleton)
        )
        self.assertEqual(
            CHECKER.check_plan(partial)["normalization_drift_count"],
            1,
        )

        reversed_candidate = copy.deepcopy(candidate)
        reversed_candidate["resource_drift"].reverse()
        self.assertEqual(
            CHECKER.check_plan(reversed_candidate)[
                "normalization_drift_sha256"
            ],
            summary["normalization_drift_sha256"],
        )

    def test_proof_concurrency_drift_requires_exact_recovery_pairing(
        self,
    ) -> None:
        recovery_addresses = set(
            CHECKER.AUTHORITY_IMAGE_UPDATE_RECOVERY_REPLACES
        )
        missing = authority_image_update_fixture(
            recovery_replaces=recovery_addresses,
        )
        missing["resource_drift"] = (
            authority_proof_concurrency_recovery_drift(
                {next(iter(recovery_addresses))}
            )
        )
        self.assert_rejected(missing)

        no_replacement = authority_image_update_fixture()
        no_replacement["resource_drift"] = (
            authority_proof_concurrency_recovery_drift(recovery_addresses)
        )
        self.assert_rejected(no_replacement)

        steady = authority_proof_steady_fixture()
        steady["resource_drift"] = (
            authority_proof_concurrency_recovery_drift(recovery_addresses)
        )
        self.assert_rejected(steady)

    def test_proof_concurrency_recovery_drift_is_exact(self) -> None:
        recovery_addresses = set(
            CHECKER.AUTHORITY_IMAGE_UPDATE_RECOVERY_REPLACES
        )

        def assert_rejected(mutate) -> None:
            candidate = authority_image_update_fixture(
                recovery_replaces=recovery_addresses,
            )
            candidate["resource_drift"] = (
                authority_proof_concurrency_recovery_drift(recovery_addresses)
            )
            mutate(candidate["resource_drift"][0])
            self.assert_rejected(candidate)

        mutations = {
            "wrong address": lambda item: item.update(
                {
                    "address": (
                        "module.control."
                        'aws_lambda_provisioned_concurrency_config.authority["foreign"]'
                    )
                }
            ),
            "unhashable address": lambda item: item.update(
                {"address": {"malformed": True}}
            ),
            "wrong id": lambda item: item["change"]["after"].update(
                {"id": "wrong,blue"}
            ),
            "wrong qualifier": lambda item: item["change"]["after"].update(
                {"qualifier": "green"}
            ),
            "wrong before count": lambda item: item["change"]["before"].update(
                {"provisioned_concurrent_executions": 2}
            ),
            "wrong after count": lambda item: item["change"]["after"].update(
                {"provisioned_concurrent_executions": 1}
            ),
            "wrong action": lambda item: item["change"].update(
                {"actions": ["delete", "create"]}
            ),
            "wrong type": lambda item: item.update(
                {"type": "aws_lambda_function"}
            ),
            "wrong mode": lambda item: item.update({"mode": "data"}),
            "wrong provider": lambda item: item.update(
                {"provider_name": "example.invalid/aws"}
            ),
            "deposed": lambda item: item.update({"deposed": "deadbeef"}),
            "unknown": lambda item: item["change"].update(
                {"after_unknown": {"id": True}}
            ),
            "sensitive": lambda item: item["change"].update(
                {"after_sensitive": {"id": True}}
            ),
            "wrong region": lambda item: item["change"]["after"].update(
                {"region": "us-west-2"}
            ),
            "extra state field": lambda item: item["change"]["after"].update(
                {"unexpected": "value"}
            ),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                assert_rejected(mutate)

    def test_proof_concurrency_recovery_live_reproof_binds_captured_state(
        self,
    ) -> None:
        candidate, prior_state = (
            authority_proof_concurrency_recovery_normalization_fixture()
        )
        summary = CHECKER.check_normalization_drift(candidate, prior_state)
        self.assertEqual(
            summary["normalization_drift_kind"],
            CHECKER.AUTHORITY_PROOF_CONCURRENCY_RECOVERY_NORMALIZATION_KIND,
        )
        self.assertEqual(summary["normalization_drift_count"], 2)

        moved, moved_state = (
            authority_proof_concurrency_recovery_normalization_fixture()
        )
        address = moved["resource_drift"][0]["address"]
        state_resource(moved_state, address)["values"][
            "provisioned_concurrent_executions"
        ] = 2
        with self.assertRaises(CHECKER.ContractError):
            CHECKER.check_normalization_drift(moved, moved_state)

    def test_proof_concurrency_recovery_live_reproof_keeps_full_mixed_drift(
        self,
    ) -> None:
        recovery_addresses = set(
            CHECKER.AUTHORITY_IMAGE_UPDATE_RECOVERY_REPLACES
        )
        recovery = authority_proof_concurrency_recovery_drift(
            recovery_addresses
        )
        # Captured sandbox shape: 22 alarm first projections plus the two
        # substantive PM/PCR state-1 -> live-0 observations.
        projections = [
            _slice_refresh_drift(
                f'module.control.aws_cloudwatch_metric_alarm.captured["{index}"]',
                "aws_cloudwatch_metric_alarm",
            )
            for index in range(22)
        ]
        full_drift = [*projections, *recovery]

        saved = authority_image_update_fixture(
            recovery_replaces=recovery_addresses,
        )
        saved["resource_drift"] = copy.deepcopy(full_drift)
        saved_summary = CHECKER.check_plan(saved)

        live, prior_state = (
            authority_proof_concurrency_recovery_normalization_fixture()
        )
        live["resource_drift"] = copy.deepcopy(full_drift)
        observation = CHECKER.check_normalization_drift(live, prior_state)
        self.assertEqual(observation["normalization_drift_count"], 24)
        self.assertEqual(
            observation["normalization_drift_kind"],
            CHECKER.AUTHORITY_PROOF_CONCURRENCY_RECOVERY_NORMALIZATION_KIND,
        )
        self.assertEqual(observation, {
            field: saved_summary[field]
            for field in (
                "normalization_drift_count",
                "normalization_drift_kind",
                "normalization_drift_sha256",
            )
        })

        live["resource_drift"].reverse()
        self.assertEqual(
            CHECKER.check_normalization_drift(live, prior_state),
            observation,
        )

    def test_proof_concurrency_recovery_mixed_reproof_rejects_signal(
        self,
    ) -> None:
        substantive = _substantive_refresh_drift(
            "module.control.aws_kms_key.authority_data",
            "aws_kms_key",
        )
        malformed = _slice_refresh_drift(
            "module.control.aws_cloudwatch_metric_alarm.malformed",
            "aws_cloudwatch_metric_alarm",
        )
        malformed["address"] = {"malformed": True}
        for label, extra in (
            ("substantive", substantive),
            ("malformed", malformed),
        ):
            with self.subTest(label=label):
                candidate, prior_state = (
                    authority_proof_concurrency_recovery_normalization_fixture()
                )
                candidate["resource_drift"].insert(0, extra)
                with self.assertRaises(CHECKER.ContractError):
                    CHECKER.check_normalization_drift(candidate, prior_state)

    def test_authority_image_update_rejects_unpinned_source_and_alias_drift(
        self,
    ) -> None:
        function_address = next(
            address
            for address, resource_type in CHECKER.AUTHORITY_IMAGE_UPDATE_RESOURCES.items()
            if resource_type == "aws_lambda_function"
        )
        for invalid_uri in (
            CHECKER.AUTHORITY_IMAGE_UPDATE_FROM_URI.replace(
                "layerv/qurl-connector-authority", "layerv/other"
            ),
            (
                f"{CHECKER.ACCOUNT_ID}.dkr.ecr.{CHECKER.AWS_REGION}.amazonaws.com/"
                "layerv/qurl-connector-authority:latest"
            ),
            CHECKER.AUTHORITY_IMAGE_UPDATE_FROM_URI.replace(
                CHECKER.AUTHORITY_IMAGE_UPDATE_FROM_URI.rsplit("@sha256:", 1)[1],
                "0" * 64,
            ),
        ):
            with self.subTest(invalid_uri=invalid_uri):
                candidate = authority_image_update_fixture()
                self.change(candidate, function_address)["before"]["image_uri"] = (
                    invalid_uri
                )
                self.assert_rejected(candidate)

        alternate_target = authority_image_update_fixture()
        # Derive the alternate digest from the pinned URI itself. Hardcoding the
        # reviewed digest here turned this into a silent no-op assertion the
        # moment the pin advanced.
        self.change(alternate_target, function_address)["after"]["image_uri"] = (
            f"{CHECKER.AUTHORITY_IMAGE_UPDATE_TO_URI.rsplit('@', 1)[0]}@sha256:"
            + "f" * 64
        )
        self.assert_rejected(alternate_target)

        alias_address = next(
            address
            for address, resource_type in CHECKER.AUTHORITY_IMAGE_UPDATE_RESOURCES.items()
            if resource_type == "aws_lambda_alias"
        )
        routing = authority_image_update_fixture()
        self.change(routing, alias_address)["after"]["routing_config"] = [
            {"additional_version_weights": {"4": 0.1}}
        ]
        self.assert_rejected(routing)

        mixed = authority_image_update_fixture()
        role_address = next(
            address
            for address, resource_type in CHECKER.AUTHORITY_RUNTIME_RESOURCES.items()
            if resource_type == "aws_iam_role"
        )
        self.change(mixed, role_address)["actions"] = ["update"]
        self.assert_rejected(mixed)

    def test_authority_image_update_rejects_foundation_and_output_drift(
        self,
    ) -> None:
        foundation_address = CHECKER.AUTHORITY_IMAGE_UPDATE_FOUNDATION_ADDRESS

        unrelated_contract = authority_image_update_fixture()
        self.change(unrelated_contract, foundation_address)["after"]["input"][
            "authority_runtime_contract"
        ]["selected_authority_color"] = "green"
        self.assert_rejected(unrelated_contract)

        mismatched_output = authority_image_update_fixture()
        self.change(mismatched_output, foundation_address)["before"]["output"][
            "authority_runtime_contract"
        ]["selected_authority_color"] = "green"
        self.assert_rejected(mismatched_output)

        wrong_old_uri = authority_image_update_fixture()
        self.change(wrong_old_uri, foundation_address)["before"]["input"][
            "authority_image_uri"
        ] = CHECKER.AUTHORITY_IMAGE_UPDATE_TO_URI
        self.assert_rejected(wrong_old_uri)

        wrong_new_digest = authority_image_update_fixture()
        self.change(wrong_new_digest, foundation_address)["after"]["input"][
            "authority_runtime_contract"
        ]["global"]["authority_image_digest"] = "sha256:" + "f" * 64
        self.assert_rejected(wrong_new_digest)

        evidence_drift = authority_image_update_fixture()
        self.change(evidence_drift, foundation_address)["after"]["input"][
            "authority_runtime_contract"
        ]["functions"]["layerv-nhp-sandbox-ca-ia"]["basis_evidence"][
            "sha256"
        ] = "f" * 64
        self.assert_rejected(evidence_drift)

        wrong_target_source = authority_image_update_fixture()
        self.change(wrong_target_source, foundation_address)["after"]["input"][
            "authority_runtime_contract"
        ]["global"]["basis_evidence"]["source_commit"] = "f" * 40
        self.assert_rejected(wrong_target_source)

        trigger_drift = authority_image_update_fixture()
        self.change(trigger_drift, foundation_address)["after"][
            "triggers_replace"
        ] = ["unexpected"]
        self.assert_rejected(trigger_drift)

        unknown_drift = authority_image_update_fixture()
        self.change(unknown_drift, foundation_address)["after_unknown"][
            "triggers_replace"
        ] = True
        self.assert_rejected(unknown_drift)

        sensitive_drift = authority_image_update_fixture()
        self.change(sensitive_drift, foundation_address)["after_sensitive"][
            "output"
        ] = {"unexpected": {}}
        self.assert_rejected(sensitive_drift)

        unrelated_output = authority_image_update_fixture()
        unrelated_output["output_changes"]["authority_data_kms_key_arn"][
            "after"
        ] = "drift"
        self.assert_rejected(unrelated_output)

        wrong_image_output = authority_image_update_fixture()
        wrong_image_output["output_changes"]["authority_image_uri"]["after"] = (
            CHECKER.AUTHORITY_IMAGE_UPDATE_FROM_URI
        )
        self.assert_rejected(wrong_image_output)

    def test_authority_image_recovery_requires_exact_new_noops(self) -> None:
        candidate = authority_image_update_fixture(set(), foundation_pending=True)
        function_address = next(
            address
            for address, resource_type in CHECKER.AUTHORITY_IMAGE_UPDATE_RESOURCES.items()
            if resource_type == "aws_lambda_function"
        )
        change = self.change(candidate, function_address)
        for side in ("before", "after"):
            change[side]["image_uri"] = CHECKER.AUTHORITY_IMAGE_UPDATE_FROM_URI
        self.assert_rejected(candidate)

        alias_address = next(
            address
            for address, resource_type in CHECKER.AUTHORITY_IMAGE_UPDATE_RESOURCES.items()
            if resource_type == "aws_lambda_alias"
        )
        old_foundation = authority_image_update_fixture({alias_address})
        foundation = self.change(
            old_foundation, CHECKER.AUTHORITY_IMAGE_UPDATE_FOUNDATION_ADDRESS
        )
        for side in ("before", "after"):
            foundation[side]["input"]["authority_image_uri"] = (
                CHECKER.AUTHORITY_IMAGE_UPDATE_FROM_URI
            )
            foundation[side]["output"]["authority_image_uri"] = (
                CHECKER.AUTHORITY_IMAGE_UPDATE_FROM_URI
            )
        self.assert_rejected(old_foundation)

        malformed_complement = authority_image_update_fixture({alias_address})
        complement_address = next(
            address
            for address, resource_type in CHECKER.AUTHORITY_IMAGE_UPDATE_RESOURCES.items()
            if resource_type == "aws_lambda_function"
        )
        complement = self.change(malformed_complement, complement_address)
        for side in ("before", "after"):
            complement[side]["version"] = "0"
        self.assert_rejected(malformed_complement)

        unknown_complement = authority_image_update_fixture({alias_address})
        self.change(unknown_complement, complement_address)["after_unknown"][
            "unexpected"
        ] = True
        self.assert_rejected(unknown_complement)

        sensitive_complement = authority_image_update_fixture({alias_address})
        sensitive_change = self.change(sensitive_complement, complement_address)
        sensitive_change["before_sensitive"] = {"unexpected": True}
        sensitive_change["after_sensitive"] = {"unexpected": True}
        self.assert_rejected(sensitive_complement)

        identity_complement = authority_image_update_fixture({alias_address})
        self.change(identity_complement, complement_address)["after_identity"][
            "account_id"
        ] = "000000000000"
        self.assert_rejected(identity_complement)

        extra_envelope = authority_image_update_fixture()
        self.change(extra_envelope, alias_address)["unexpected"] = False
        self.assert_rejected(extra_envelope)

    def test_authority_runtime_steady_state_noop_passes(self) -> None:
        summary = CHECKER.check_plan(authority_runtime_steady_fixture())
        self.assertEqual(summary["plan_mode"], "no-op")
        self.assertEqual(
            summary["resource_count"],
            len(CHECKER.EXPECTED_RESOURCES) + len(CHECKER.AUTHORITY_RUNTIME_RESOURCES),
        )

    def test_authority_runtime_steady_noop_admits_confined_state_normalization(
        self,
    ) -> None:
        """The post-apply lane is an ordinary refresh-enabled no-op plan."""
        candidate = authority_runtime_steady_fixture()
        add_runtime_role_state_normalization(candidate)

        summary = CHECKER.check_plan(candidate)

        self.assertEqual(summary["plan_mode"], "no-op")
        self.assertEqual(
            summary["normalization_drift_kind"],
            "authority-runtime-slice-normalization",
        )
        self.assertEqual(summary["normalization_drift_count"], 1)

    def test_authority_runtime_state_normalization_rejects_unrelated_transition(
        self,
    ) -> None:
        candidate = authority_proof_enable_fixture()
        add_runtime_role_state_normalization(candidate)

        with self.assertRaisesRegex(
            CHECKER.ContractError,
            "runtime-slice state normalization is admitted only",
        ):
            CHECKER.check_plan(candidate)

    def test_authority_runtime_steady_state_admits_applied_standalone_egress(
        self,
    ) -> None:
        """A REFRESHED steady-state plan reports the egress rules AWS actually
        holds, because `egress` is Optional+Computed and the generation-2 group
        declares no inline block. Live sandbox state carries exactly this: an
        empty `ingress` and a populated `egress`.

        The steady fixture used to copy `after` into `before` with both empty,
        so no test ever modeled the refreshed shape -- which is how a contract
        that only admitted the creating plan reached main and then failed every
        subsequent plan.
        """
        fixture = authority_runtime_steady_fixture()
        applied_egress = legacy_authority_lambda_sg_before()["egress"]
        for item in fixture["resource_changes"]:
            if item["address"] == CHECKER.AUTHORITY_RUNTIME_LAMBDA_SG_ADDRESS:
                item["change"]["before"]["egress"] = copy.deepcopy(applied_egress)
                item["change"]["after"]["egress"] = copy.deepcopy(applied_egress)
                break
        else:  # pragma: no cover - fixture drift
            self.fail("steady fixture is missing the Authority function SG")
        summary = CHECKER.check_plan(fixture)
        self.assertEqual(summary["plan_mode"], "no-op")

    def test_authority_runtime_steady_state_rejects_any_group_rule_rewrite(
        self,
    ) -> None:
        """Admitting the applied egress must not admit the group MUTATING it.

        An inline block (even `egress = []`) without `ignore_changes` surfaces
        as a revoking diff -- the first-apply-vs-refresh trap documented on
        modules/bootstrap-alb's SG. Both directions fail closed. On a steady
        plan the generic no-op guard is what fires, which is deliberately
        stricter than the rule-set comparison: on a no-op resource NOTHING may
        differ, so this asserts the address rather than a specific message.
        """
        applied_egress = legacy_authority_lambda_sg_before()["egress"]
        mutations = {
            # The group revokes every standalone rule it does not declare.
            "egress revoked": ("egress", copy.deepcopy(applied_egress), []),
            # Nothing dials the functions on the network path, so a populated
            # ingress is a real posture change in every state -- never drift.
            "ingress opened": ("ingress", [], copy.deepcopy(applied_egress[:1])),
        }
        for label, (field, before, after) in mutations.items():
            with self.subTest(label):
                fixture = authority_runtime_steady_fixture()
                for item in fixture["resource_changes"]:
                    if item["address"] == CHECKER.AUTHORITY_RUNTIME_LAMBDA_SG_ADDRESS:
                        item["change"]["before"][field] = before
                        item["change"]["after"][field] = after
                        break
                else:  # pragma: no cover - fixture drift
                    self.fail("steady fixture is missing the Authority function SG")
                with self.assertRaises(CHECKER.ContractError) as caught:
                    CHECKER.check_plan(fixture)
                self.assertIn(
                    CHECKER.AUTHORITY_RUNTIME_LAMBDA_SG_ADDRESS,
                    str(caught.exception),
                )

    def test_authority_runtime_slice_partial_retry_passes(self) -> None:
        """After a partial apply (e.g. the DynamoDB gateway open was rejected
        mid-run) the already-created slice resources replan as no-ops and only
        the remaining creates plus the dependency opens stay pending. The slice
        transition must still be accepted across the full-slice (``set()``),
        one-applied, and complete early-resource boundaries."""
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
            # The spillover alarm is the only alarm that belongs to the original
            # runtime slice; the rest of the alarm set is NHP #3455's own slice.
            and item["address"] not in CHECKER.AUTHORITY_ALARM_RESOURCES
        }
        # 13 functions x {exec role, exec policy, spillover alarm, log group}.
        self.assertEqual(
            len(early_applied), 4 * len(CHECKER.AUTHORITY_RUNTIME_FUNCTIONS)
        )
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
        """A REAL value change on an address outside the slice ∪ its opens is NOT
        admitted by the slice normalization — it falls through to the exact
        single-drift handling and fails closed (a base resource must never change
        out of band during a slice completion).

        The out-of-slice entry carries a SUBSTANTIVE before-value. A pure first
        projection on a base resource is now admitted by design and is covered by
        ``test_first_projection_outside_the_slice_is_admitted``: state that never
        recorded a value cannot evidence an out-of-band change, and the live
        sandbox emits 122 such alarm projections (109 metric + 13 composite) on
        base resources. What must stay rejected is a recorded value that changed,
        which is what this asserts."""
        role = next(
            item["address"]
            for item in authority_runtime_transition_fixture()["resource_changes"]
            if item["type"] == "aws_iam_role"
            and item["change"]["actions"] == ["create"]
        )
        candidate = authority_runtime_partial_retry_fixture({role})
        candidate["resource_drift"] = [
            _slice_refresh_drift(role, "aws_iam_role"),
            _substantive_refresh_drift(
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
            f"{CHECKER.CONTROL_PREFIX}-qurl-foreign-idempotency"
        )
        ddb["after"]["policy"] = json.dumps(policy)
        self.assert_rejected(candidate)

    def test_authority_runtime_accepts_actual_api_key_idempotency_table_name(
        self,
    ) -> None:
        candidate = authority_runtime_transition_fixture()
        ddb = self.change(candidate, CHECKER.AUTHORITY_RUNTIME_DYNAMODB_ADDRESS)
        actual_arn = (
            f"arn:aws:dynamodb:{CHECKER.AWS_REGION}:{CHECKER.ACCOUNT_ID}:table/"
            f"{CHECKER.CONTROL_PREFIX}-qurl-apikey-idempotency"
        )
        self.assertIn(actual_arn, json.loads(ddb["after"]["policy"])["Statement"][0]["Resource"])
        CHECKER.check_plan(candidate)

    def test_authority_runtime_rejects_hyphenated_api_key_idempotency_table_name(
        self,
    ) -> None:
        candidate = authority_runtime_transition_fixture()
        ddb = self.change(candidate, CHECKER.AUTHORITY_RUNTIME_DYNAMODB_ADDRESS)
        policy = json.loads(ddb["after"]["policy"])
        actual_arn = CHECKER.AUTHORITY_RUNTIME_TABLE_ARNS["api_key_idempotency"]
        wrong_arn = (
            f"arn:aws:dynamodb:{CHECKER.AWS_REGION}:{CHECKER.ACCOUNT_ID}:table/"
            f"{CHECKER.CONTROL_PREFIX}-qurl-api-key-idempotency"
        )
        policy["Statement"][0]["Resource"] = [
            wrong_arn if resource == actual_arn else resource
            for resource in policy["Statement"][0]["Resource"]
        ]
        ddb["after"]["policy"] = json.dumps(policy)
        self.assert_rejected(candidate)

    def test_authority_runtime_rejects_missing_dynamodb_resource(self) -> None:
        candidate = authority_runtime_transition_fixture()
        ddb = self.change(candidate, CHECKER.AUTHORITY_RUNTIME_DYNAMODB_ADDRESS)
        policy = json.loads(ddb["after"]["policy"])
        policy["Statement"][0]["Resource"].remove(
            CHECKER.AUTHORITY_RUNTIME_TABLE_ARNS["customers"]
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

    def test_authority_runtime_admits_the_applied_redis_tls_ingress(self) -> None:
        """Post-slice, the OTP Redis SG legitimately carries the ONE standalone
        SG-to-SG TLS/6379 rule that aws_vpc_security_group_ingress_rule
        .otp_redis_authority attaches. `ingress` is Optional+Computed, so a
        refreshed plan reports it -- live sg-081a26fbcf3d14ca6 carries exactly
        this. Demanding an empty list admitted only the pre-slice state and so
        failed every plan after the slice applied.
        """
        candidate = authority_runtime_transition_fixture()
        redis_sg = self.change(candidate, "module.control.aws_security_group.otp_redis")
        redis_sg["actions"] = ["no-op"]
        redis_sg["after"] = {
            **redis_sg["after"],
            "ingress": [redis_tls_ingress_rule()],
        }
        redis_sg["before"] = copy.deepcopy(redis_sg["after"])
        CHECKER.check_plan(candidate)

    def test_authority_runtime_rejects_unlawful_redis_ingress_shapes(self) -> None:
        """Admitting the applied rule must not admit a broader one."""
        cidr_reachable = {**redis_tls_ingress_rule(), "cidr_blocks": ["0.0.0.0/0"]}
        wrong_port = {**redis_tls_ingress_rule(), "from_port": 6380, "to_port": 6380}
        self_reachable = {**redis_tls_ingress_rule(), "self": True}
        cases = {
            "cidr reachable": [cidr_reachable],
            "wrong port": [wrong_port],
            "self reachable": [self_reachable],
            "two rules": [redis_tls_ingress_rule(), redis_tls_ingress_rule()],
            "multi-SG rule": [
                {
                    **redis_tls_ingress_rule(),
                    "security_groups": [RUNTIME_LAMBDA_SG_ID, "sg-0deadbeef"],
                }
            ],
        }
        for label, ingress in cases.items():
            with self.subTest(label):
                candidate = authority_runtime_transition_fixture()
                redis_sg = self.change(
                    candidate, "module.control.aws_security_group.otp_redis"
                )
                redis_sg["actions"] = ["no-op"]
                redis_sg["after"] = {**redis_sg["after"], "ingress": ingress}
                redis_sg["before"] = copy.deepcopy(redis_sg["after"])
                self.assert_rejected(candidate)

    def test_authority_runtime_rejects_world_interface_endpoint_egress(self) -> None:
        candidate = authority_runtime_transition_fixture()
        egress = self.change(
            candidate,
            "module.control.aws_vpc_security_group_egress_rule."
            "authority_interface_endpoints[0]",
        )
        egress["after"]["referenced_security_group_id"] = None
        egress["after"]["cidr_ipv4"] = "0.0.0.0/0"
        self.assert_rejected(candidate)

    def test_authority_runtime_rejects_wrong_function_sg_source(self) -> None:
        candidate = authority_runtime_transition_fixture()
        egress = self.change(
            candidate,
            "module.control.aws_vpc_security_group_egress_rule."
            "authority_interface_endpoints[0]",
        )
        egress["after"]["security_group_id"] = "sg-0bad0000000000000"
        self.assert_rejected(candidate)

    def test_authority_runtime_rejects_standalone_rule_reference_rewire(
        self,
    ) -> None:
        candidate = authority_runtime_transition_fixture()
        resource = self.configuration_resource(
            candidate,
            "module.control.aws_vpc_security_group_egress_rule.authority_otp_redis",
        )
        resource["expressions"]["referenced_security_group_id"] = {
            "references": [
                "aws_security_group.interface_endpoints.id",
                "aws_security_group.interface_endpoints",
            ]
        }
        self.assert_rejected(candidate)

    def test_authority_runtime_rejects_world_dynamodb_egress(self) -> None:
        candidate = authority_runtime_transition_fixture()
        egress = self.change(
            candidate,
            "module.control.aws_vpc_security_group_egress_rule."
            "authority_dynamodb[0]",
        )
        egress["after"]["prefix_list_id"] = None
        egress["after"]["cidr_ipv4"] = "0.0.0.0/0"
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

    def test_authority_runtime_rejects_exec_dynamodb_decrypt_without_via_service(
        self,
    ) -> None:
        candidate = authority_runtime_transition_fixture()
        change = self._exec_policy_change(candidate, "issue_assignment")
        policy = json.loads(change["after"]["policy"])
        decrypt = next(
            s
            for s in policy["Statement"]
            if s["Sid"] == "AuthorityDynamoDBDecrypt"
        )
        decrypt.pop("Condition")
        change["after"]["policy"] = json.dumps(policy)
        self.assert_rejected(candidate)

    def test_connector_resource_runtime_rejects_control_query_grant(self) -> None:
        candidate = authority_runtime_transition_fixture()
        fn = "layerv-nhp-sandbox-ca-creso-cell0"
        change = self.change(
            candidate,
            f'module.control.aws_iam_role_policy.authority_exec["{fn}"]',
        )
        policy = json.loads(change["after"]["policy"])
        read = next(
            statement
            for statement in policy["Statement"]
            if statement["Sid"] == "ConnectorResourceControlRead"
        )
        read["Action"].append("dynamodb:Query")
        change["after"]["policy"] = json.dumps(policy)
        self.assert_rejected(candidate)

    def test_connector_resource_runtime_requires_both_table_sse_decrypt_grants(
        self,
    ) -> None:
        for sid in (
            "ConnectorResourceControlDynamoDBDecrypt",
            "ConnectorResourceCellDynamoDBDecrypt",
        ):
            with self.subTest(sid=sid):
                candidate = authority_runtime_transition_fixture()
                fn = "layerv-nhp-sandbox-ca-creso-cell0"
                change = self.change(
                    candidate,
                    f'module.control.aws_iam_role_policy.authority_exec["{fn}"]',
                )
                policy = json.loads(change["after"]["policy"])
                policy["Statement"] = [
                    statement
                    for statement in policy["Statement"]
                    if statement["Sid"] != sid
                ]
                change["after"]["policy"] = json.dumps(policy)
                self.assert_rejected(candidate)

    def test_connector_resource_runtime_rejects_decrypt_scope_drift(self) -> None:
        mutations = {
            "direct without ViaService": lambda statement: statement.pop(
                "Condition"
            ),
            "wrong service": lambda statement: statement["Condition"][
                "StringEquals"
            ].__setitem__("kms:ViaService", "lambda.us-east-2.amazonaws.com"),
            "wrong subscriber": lambda statement: statement["Condition"][
                "StringEquals"
            ].__setitem__(
                "kms:EncryptionContext:aws:dynamodb:subscriberId",
                "000000000000",
            ),
            "cross-cell key": lambda statement: statement.__setitem__(
                "Resource",
                [
                    CHECKER.AUTHORITY_CONNECTOR_RESOURCE_CELLS["cell1"][
                        "cell_data_kms_key_arn"
                    ]
                ],
            ),
            "envelope key": lambda statement: statement.__setitem__(
                "Resource",
                [
                    CHECKER.AUTHORITY_CONNECTOR_RESOURCE_CELLS["cell0"][
                        "resource_key_envelope_kms_key_arn"
                    ]
                ],
            ),
            "unrelated table": lambda statement: statement["Condition"][
                "StringEquals"
            ].__setitem__(
                "kms:EncryptionContext:aws:dynamodb:tableName",
                ["layerv-nhp-sandbox-cell0-unrelated"],
            ),
        }
        for sid in (
            "ConnectorResourceControlDynamoDBDecrypt",
            "ConnectorResourceCellDynamoDBDecrypt",
        ):
            for name, mutate in mutations.items():
                with self.subTest(sid=sid, name=name):
                    candidate = authority_runtime_transition_fixture()
                    fn = "layerv-nhp-sandbox-ca-creso-cell0"
                    change = self.change(
                        candidate,
                        f'module.control.aws_iam_role_policy.authority_exec["{fn}"]',
                    )
                    policy = json.loads(change["after"]["policy"])
                    decrypt = next(
                        statement
                        for statement in policy["Statement"]
                        if statement["Sid"] == sid
                    )
                    mutate(decrypt)
                    change["after"]["policy"] = json.dumps(policy)
                    self.assert_rejected(candidate)

    def test_connector_resource_runtime_rejects_control_decrypt_key_mismatch(
        self,
    ) -> None:
        candidate = authority_runtime_transition_fixture()
        fn = "layerv-nhp-sandbox-ca-creso-cell0"
        change = self.change(
            candidate,
            f'module.control.aws_iam_role_policy.authority_exec["{fn}"]',
        )
        policy = json.loads(change["after"]["policy"])
        decrypt = next(
            statement
            for statement in policy["Statement"]
            if statement["Sid"] == "ConnectorResourceControlDynamoDBDecrypt"
        )
        decrypt["Resource"] = [
            CHECKER.AUTHORITY_CONNECTOR_RESOURCE_CELLS["cell0"][
                "cell_data_kms_key_arn"
            ]
        ]
        change["after"]["policy"] = json.dumps(policy)
        self.assert_rejected(candidate)

    def test_connector_resource_runtime_rejects_coupled_control_key_drift(
        self,
    ) -> None:
        candidate = authority_runtime_transition_fixture()
        fn = "layerv-nhp-sandbox-ca-creso-cell0"
        alternate_key_arn = (
            f"arn:aws:kms:{CHECKER.AWS_REGION}:{CHECKER.ACCOUNT_ID}:"
            "key/00000000-0000-0000-0000-000000000099"
        )
        function = self.change(
            candidate,
            f'module.control.aws_lambda_function.authority["{fn}"]',
        )
        function["after"]["environment"][0]["variables"][
            "CONNECTOR_AUTHORITY_DATA_KMS_KEY_ARN"
        ] = alternate_key_arn
        policy_change = self.change(
            candidate,
            f'module.control.aws_iam_role_policy.authority_exec["{fn}"]',
        )
        policy = json.loads(policy_change["after"]["policy"])
        decrypt = next(
            statement
            for statement in policy["Statement"]
            if statement["Sid"] == "ConnectorResourceControlDynamoDBDecrypt"
        )
        decrypt["Resource"] = [alternate_key_arn]
        policy_change["after"]["policy"] = json.dumps(policy)
        self.assert_rejected(candidate)

    def test_connector_resource_runtime_rejects_cell_prefix_drift(self) -> None:
        candidate = authority_runtime_transition_fixture()
        fn = "layerv-nhp-sandbox-ca-creso-cell1"
        change = self.change(
            candidate,
            f'module.control.aws_lambda_function.authority["{fn}"]',
        )
        change["after"]["environment"][0]["variables"][
            "CONNECTOR_AUTHORITY_CELL_TABLE_PREFIX"
        ] = "layerv-nhp-sandbox-cell1"
        self.assert_rejected(candidate)

    def test_connector_resource_runtime_rejects_endpoint_widening(self) -> None:
        candidate = authority_runtime_transition_fixture()
        endpoint = self.change(
            candidate, CHECKER.AUTHORITY_RUNTIME_DYNAMODB_ADDRESS
        )
        policy = json.loads(endpoint["after"]["policy"])
        cell = next(
            statement
            for statement in policy["Statement"]
            if statement["Sid"] == "ConnectorResourceCellData"
        )
        cell["Resource"].append("*")
        endpoint["after"]["policy"] = json.dumps(policy)
        self.assert_rejected(candidate)

    def test_connector_resource_runtime_rejects_envelope_context_drift(self) -> None:
        candidate = authority_runtime_transition_fixture()
        endpoint = self.change(
            candidate, CHECKER.AUTHORITY_RUNTIME_KMS_ENDPOINT_ADDRESS
        )
        policy = json.loads(endpoint["after"]["policy"])
        envelope = next(
            statement
            for statement in policy["Statement"]
            if statement["Sid"] == "ConnectorResourceGenerateEnvelopeDataKey"
        )
        envelope["Condition"]["StringEquals"].pop(
            "kms:EncryptionContext:purpose"
        )
        endpoint["after"]["policy"] = json.dumps(policy)
        self.assert_rejected(candidate)

    def test_connector_resource_runtime_contract_rejects_live_prefix_rename(
        self,
    ) -> None:
        candidate = authority_runtime_transition_fixture()
        foundation = self.change(
            candidate, "module.control.terraform_data.foundation_contract"
        )
        foundation["after"]["input"]["authority_runtime_contract"][
            "provisioned_cells"
        ]["cell1"]["cell_table_prefix"] = "layerv-nhp-sandbox-cell1"
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

    # -----------------------------------------------------------------------
    # Operator alert routing and the full runtime alarm set (NHP #3455). Each
    # test below is one of the four regressions the issue names, plus the
    # dimension-set rule from terraform/CLAUDE.md.
    # -----------------------------------------------------------------------
    ALARM_SAMPLE = (
        "module.control.aws_cloudwatch_metric_alarm."
        'authority_runtime["layerv-nhp-sandbox-ca-ia:errors"]'
    )
    ALARM_CUSTOM_SAMPLE = (
        "module.control.aws_cloudwatch_metric_alarm."
        'authority_admission_rejected["layerv-nhp-sandbox-ca-ar-cell0:limited"]'
    )

    def test_exact_authority_alarm_routing_slice_passes(self) -> None:
        """The transition this rollout actually uses: functions settled, alarms
        moving. 122 creates plus the 13 spillover alarms gaining actions, and
        nothing else."""
        candidate = authority_alarm_routing_fixture()
        summary = CHECKER.check_plan(candidate)
        self.assertEqual(summary["plan_mode"], "authority-alarm-routing")
        changed = {
            item["address"]: item["change"]["actions"]
            for item in candidate["resource_changes"]
            if item["change"]["actions"] != ["no-op"]
        }
        self.assertEqual(
            sum(1 for actions in changed.values() if actions == ["create"]), 122
        )
        self.assertEqual(
            sum(1 for actions in changed.values() if actions == ["update"]), 13
        )
        self.assertEqual(len(changed), 135)

    def test_alarm_routing_slice_still_validates_alarm_contents(self) -> None:
        """The dispatch proof for the mode above.

        ``_check_authority_runtime_resources`` (and therefore
        ``_check_authority_alarm_routing``) is gated on ``runtime_mode``, which
        is INVENTORY-derived, not transition-derived — so the dim-set, routing,
        threshold, and missing-data checks run even when every function is a
        no-op. Without this test the alarm-routing branch's inline claim that
        the spillover updates' after-state is validated would be unproven, and a
        regression during this specific rollout would reach apply.
        """
        for mutate, pattern in (
            (
                lambda after: after.__setitem__("alarm_actions", []),
                "at least one operator alarm action",
            ),
            (
                lambda after: after.__setitem__(
                    "alarm_actions", ["arn:aws:sns:us-east-2:767397897469:*"]
                ),
                "exact in-account, in-region SNS topic ARN",
            ),
            (
                lambda after: after.__setitem__(
                    "dimensions", {"FunctionName": "layerv-nhp-sandbox-ca-ia", "Resource": "x"}
                ),
                "must key on exactly",
            ),
            (
                lambda after: after.__setitem__("threshold", 1),
                "threshold must be exactly",
            ),
            (
                lambda after: after.__setitem__("treat_missing_data", "breaching"),
                "notBreaching",
            ),
        ):
            with self.subTest(pattern=pattern):
                candidate = authority_alarm_routing_fixture()
                mutate(self.change(candidate, self.ALARM_SAMPLE)["after"])
                with self.assertRaisesRegex(CHECKER.ContractError, pattern):
                    CHECKER.check_plan(candidate)

        # The same holds for the in-place spillover updates, whose after-state
        # is the whole point of this transition.
        spillover = (
            "module.control.aws_cloudwatch_metric_alarm."
            'authority_spillover["layerv-nhp-sandbox-ca-ia"]'
        )
        candidate = authority_alarm_routing_fixture()
        self.change(candidate, spillover)["after"]["alarm_actions"] = []
        with self.assertRaisesRegex(
            CHECKER.ContractError, "at least one operator alarm action"
        ):
            CHECKER.check_plan(candidate)

    def test_alarm_routing_slice_admits_no_other_movement(self) -> None:
        """Observability-only by construction: a function, role, or endpoint
        moving alongside the alarms means the plan is not what it claims."""
        for address, actions in (
            (
                'module.control.aws_lambda_function.authority["layerv-nhp-sandbox-ca-ia"]',
                ["update"],
            ),
            (
                'module.control.aws_iam_role.authority_exec["layerv-nhp-sandbox-ca-ia"]',
                ["update"],
            ),
            ("module.control.aws_vpc_endpoint.dynamodb", ["update"]),
        ):
            with self.subTest(address=address):
                candidate = authority_alarm_routing_fixture()
                change = self.change(candidate, address)
                change["actions"] = actions
                self.assert_rejected(candidate)

    def test_alarm_missing_operator_action_fails_closed(self) -> None:
        for empty in ([], None):
            with self.subTest(actions=empty):
                candidate = authority_runtime_transition_fixture()
                self.change(candidate, self.ALARM_SAMPLE)["after"][
                    "alarm_actions"
                ] = empty
                with self.assertRaisesRegex(
                    CHECKER.ContractError, "at least one operator alarm action"
                ):
                    CHECKER.check_plan(candidate)

    def test_alarm_wildcard_destination_fails_closed(self) -> None:
        for action in (
            "arn:aws:sns:us-east-2:767397897469:*",
            "*",
            "arn:aws:sns:*:*:layerv-nhp-sandbox-cell0-alerts",
            # Right shape, wrong account: not a destination this account can
            # publish to, so it is silence dressed as coverage.
            "arn:aws:sns:us-east-2:000000000000:layerv-nhp-sandbox-cell0-alerts",
            "arn:aws:sns:us-west-2:767397897469:layerv-nhp-sandbox-cell0-alerts",
        ):
            with self.subTest(action=action):
                candidate = authority_runtime_transition_fixture()
                self.change(candidate, self.ALARM_SAMPLE)["after"][
                    "alarm_actions"
                ] = [action]
                with self.assertRaisesRegex(
                    CHECKER.ContractError, "exact in-account, in-region SNS topic ARN"
                ):
                    CHECKER.check_plan(candidate)

    def test_alarm_split_routing_fails_closed(self) -> None:
        """One family quietly pointed somewhere else is still 'every alarm has
        an action', which is why sameness is checked, not just non-emptiness."""
        candidate = authority_runtime_transition_fixture()
        self.change(candidate, self.ALARM_SAMPLE)["after"]["alarm_actions"] = [
            "arn:aws:sns:us-east-2:767397897469:some-other-topic"
        ]
        with self.assertRaisesRegex(
            CHECKER.ContractError, "identical\n?\\s*reviewed operator destination"
        ):
            CHECKER.check_plan(candidate)

    def test_alarm_omitted_function_fails_closed(self) -> None:
        for omitted in (
            self.ALARM_SAMPLE,
            (
                "module.control.aws_cloudwatch_composite_alarm."
                'authority_non_provisioned_initialization["layerv-nhp-sandbox-ca-ra"]'
            ),
            (
                "module.control.aws_cloudwatch_metric_alarm."
                'authority_terminal_outcome["layerv-nhp-sandbox-ca-ccr-cell1:internal"]'
            ),
        ):
            with self.subTest(omitted=omitted):
                candidate = authority_runtime_transition_fixture()
                candidate["resource_changes"] = [
                    item
                    for item in candidate["resource_changes"]
                    if item["address"] != omitted
                ]
                # The inventory equality catches it first; either way the plan
                # is rejected rather than reported as complete coverage.
                self.assert_rejected(candidate)

    def test_alarm_weakened_threshold_fails_closed(self) -> None:
        for address, threshold in (
            (self.ALARM_SAMPLE, 1),
            (
                "module.control.aws_cloudwatch_metric_alarm."
                'authority_runtime["layerv-nhp-sandbox-ca-ia:duration"]',
                9500,
            ),
            (
                "module.control.aws_cloudwatch_metric_alarm."
                'authority_runtime["layerv-nhp-sandbox-ca-ia:concurrency_exhaustion"]',
                10,
            ),
            (
                "module.control.aws_cloudwatch_metric_alarm."
                'authority_spillover["layerv-nhp-sandbox-ca-ia"]',
                1,
            ),
            (self.ALARM_CUSTOM_SAMPLE, 5),
        ):
            with self.subTest(address=address):
                candidate = authority_runtime_transition_fixture()
                self.change(candidate, address)["after"]["threshold"] = threshold
                self.assert_rejected(candidate)

    def test_alarm_partial_dimension_set_fails_closed(self) -> None:
        """The exact failure terraform/CLAUDE.md records: a dim set the
        publisher never emits selects a stream nothing writes to, and the alarm
        sits green forever while the fault it names goes unpaged."""
        for address, dimensions in (
            # Dropping CellID from a cell operation's custom alarm.
            (
                self.ALARM_CUSTOM_SAMPLE,
                {
                    "EnvironmentID": "sandbox",
                    "AuthorityOperation": "ActivateRegistration",
                    "Outcome": "limited",
                },
            ),
            # snake_case terraform key instead of the PascalCase conformance
            # name the handler actually reports.
            (
                self.ALARM_CUSTOM_SAMPLE,
                {
                    "EnvironmentID": "sandbox",
                    "AuthorityOperation": "activate_registration",
                    "CellID": "cell0",
                    "Outcome": "limited",
                },
            ),
            # An extra dimension is just as fatal as a missing one.
            (
                self.ALARM_SAMPLE,
                {
                    "FunctionName": "layerv-nhp-sandbox-ca-ia",
                    "Resource": "layerv-nhp-sandbox-ca-ia:blue",
                },
            ),
        ):
            with self.subTest(address=address, dimensions=sorted(dimensions)):
                candidate = authority_runtime_transition_fixture()
                self.change(candidate, address)["after"]["dimensions"] = dimensions
                with self.assertRaisesRegex(
                    CHECKER.ContractError, "must key on exactly"
                ):
                    CHECKER.check_plan(candidate)

    def test_alarm_breaching_missing_data_fails_closed(self) -> None:
        candidate = authority_runtime_transition_fixture()
        self.change(candidate, self.ALARM_SAMPLE)["after"][
            "treat_missing_data"
        ] = "breaching"
        with self.assertRaisesRegex(CHECKER.ContractError, "notBreaching"):
            CHECKER.check_plan(candidate)

    def test_non_provisioned_initialization_rule_is_exact(self) -> None:
        candidate = authority_runtime_transition_fixture()
        composite = (
            "module.control.aws_cloudwatch_composite_alarm."
            'authority_non_provisioned_initialization["layerv-nhp-sandbox-ca-ia"]'
        )
        # OR instead of AND stops naming the security event and starts
        # duplicating the two child pages.
        self.change(candidate, composite)["after"]["alarm_rule"] = (
            'ALARM("layerv-nhp-sandbox-ca-ia-provisioned-concurrency-spillover") '
            'OR ALARM("layerv-nhp-sandbox-ca-ia-errors")'
        )
        with self.assertRaisesRegex(
            CHECKER.ContractError, "exactly the conjunction"
        ):
            CHECKER.check_plan(candidate)

    def test_authority_function_may_not_declare_a_dead_letter_queue(self) -> None:
        candidate = authority_runtime_transition_fixture()
        self.change(
            candidate,
            'module.control.aws_lambda_function.authority["layerv-nhp-sandbox-ca-ia"]',
        )["after"]["dead_letter_config"] = [
            {"target_arn": "arn:aws:sqs:us-east-2:767397897469:authority-dlq"}
        ]
        with self.assertRaisesRegex(
            CHECKER.ContractError, "may not declare a dead_letter_config"
        ):
            CHECKER.check_plan(candidate)

    def test_alarm_metric_name_drift_fails_closed(self) -> None:
        """Metric names must stay inside what AWS actually publishes; an
        invented name can never select a stream."""
        candidate = authority_runtime_transition_fixture()
        self.change(candidate, self.ALARM_SAMPLE)["after"]["metric_name"] = (
            "FunctionErrors"
        )
        with self.assertRaisesRegex(
            CHECKER.ContractError, "reviewed Errors alarm shape"
        ):
            CHECKER.check_plan(candidate)

    # The unset statistic field as the AWS provider actually reads it back:
    # `""`, not the `null` a creation plan renders straight from config. Pinned
    # from the applied sandbox control state (serial 56) after the #3492 apply.
    APPLIED_UNSET_STATISTIC = ""

    def test_alarm_applied_unset_statistic_rendering_passes(self) -> None:
        """The steady-state rendering this checker rejected after #3492 applied.

        ``statistic`` and ``extended_statistic`` are mutually exclusive: each
        family sets one and leaves the other unset. A CREATION plan renders the
        unset one as ``null``, but once applied, the provider reads an absent
        optional string back as ``""`` — so every steady-state plan carries
        ``""`` and the verify lane rejected all 65 live alarms (13 functions x 5
        families) as shape drift when the alarms were in fact exactly correct.

        The other alarm fixtures build ``after`` from
        ``AUTHORITY_ALARM_LAMBDA_FAMILIES`` itself, so they render the checker's
        own expectation back at it and can never observe this divergence. This
        test pins the applied rendering instead.
        """
        candidate = authority_runtime_transition_fixture()
        rewritten = 0
        for item in candidate["resource_changes"]:
            if ".authority_runtime[" not in item["address"]:
                continue
            if item["type"] != "aws_cloudwatch_metric_alarm":
                continue
            after = item["change"]["after"]
            for field in ("statistic", "extended_statistic"):
                if after.get(field) is None:
                    after[field] = self.APPLIED_UNSET_STATISTIC
                    rewritten += 1
        # Every family leaves exactly one of the two fields unset.
        self.assertEqual(
            rewritten,
            len(CHECKER.AUTHORITY_RUNTIME_FUNCTIONS)
            * len(CHECKER.AUTHORITY_ALARM_LAMBDA_FAMILIES),
        )
        CHECKER.check_plan(candidate)

    def test_alarm_statistic_drift_still_fails_closed(self) -> None:
        """Admitting the applied ``""`` must not admit a real statistic change.

        Each case is a genuine loss of the reviewed shape, not a rendering
        difference: a populated field where the family requires none, a wrong
        populated value, and an unset field where the family requires a value.
        """
        duration = (
            "module.control.aws_cloudwatch_metric_alarm."
            'authority_runtime["layerv-nhp-sandbox-ca-ia:duration"]'
        )
        for address, field, value in (
            # An extended statistic on a plain Sum counter.
            (self.ALARM_SAMPLE, "extended_statistic", "p99"),
            # The wrong aggregation entirely: Average hides a single fault.
            (self.ALARM_SAMPLE, "statistic", "Average"),
            # Errors must not silently become an unaggregated alarm.
            (self.ALARM_SAMPLE, "statistic", self.APPLIED_UNSET_STATISTIC),
            # A looser percentile than the reviewed p99.
            (duration, "extended_statistic", "p50"),
            # Duration losing its percentile is a real coverage change.
            (duration, "extended_statistic", self.APPLIED_UNSET_STATISTIC),
            (duration, "statistic", "Average"),
        ):
            with self.subTest(address=address, field=field, value=value):
                candidate = authority_runtime_transition_fixture()
                self.change(candidate, address)["after"][field] = value
                with self.assertRaisesRegex(
                    CHECKER.ContractError, "reviewed .* alarm shape"
                ):
                    CHECKER.check_plan(candidate)

    def orphan_forget_fixture(self) -> dict:
        """A converged proof plan whose only work is releasing the orphan.

        The proof-controller grant is gone from the module but still in state
        until its `removed` block applies, so it presents as a state-only
        `forget`. See _validate_authority_proof_controller_orphan_forget.
        """
        candidate = authority_proof_steady_fixture()
        candidate["applyable"] = True
        candidate["resource_changes"].append(
            {
                "address": CHECKER.AUTHORITY_PROOF_CONTROLLER_POLICY_ADDRESS,
                "mode": "managed",
                "type": "aws_iam_role_policy",
                "index": 0,
                "provider_name": "registry.terraform.io/hashicorp/aws",
                "action_reason": "delete_because_no_resource_config",
                "change": {
                    "actions": ["forget"],
                    "before": {
                        "name": CHECKER.AUTHORITY_PROOF_CONTROLLER_POLICY_NAME,
                        "role": CHECKER.AUTHORITY_PROOF_CONTROLLER_ROLE_NAME,
                        "policy": "{}",
                    },
                    "after": None,
                    "after_unknown": {},
                    "before_sensitive": False,
                    "after_sensitive": False,
                },
            }
        )
        return candidate

    def test_orphaned_proof_controller_grant_may_be_forgotten(self) -> None:
        CHECKER.check_plan(self.orphan_forget_fixture())

    def test_orphaned_proof_controller_grant_may_not_be_deleted(self) -> None:
        """A real destroy is not this lane.

        Tearing the grant down while a live controller depends on it is the
        `authority-proof-disable` transition's job, and it carries the alias
        ordering this lane deliberately has no opinion about.
        """
        candidate = self.orphan_forget_fixture()
        self.change(
            candidate, CHECKER.AUTHORITY_PROOF_CONTROLLER_POLICY_ADDRESS
        )["actions"] = ["delete"]
        self.assert_rejected(candidate)

    def test_forgotten_proof_controller_grant_may_not_plan_an_after_state(
        self,
    ) -> None:
        candidate = self.orphan_forget_fixture()
        self.change(
            candidate, CHECKER.AUTHORITY_PROOF_CONTROLLER_POLICY_ADDRESS
        )["after"] = {"name": CHECKER.AUTHORITY_PROOF_CONTROLLER_POLICY_NAME}
        self.assert_rejected(candidate)

    def test_forgotten_grant_must_be_the_proof_controller_grant(self) -> None:
        for field, value in (
            ("role", "layerv-nhp-sandbox-some-other-role"),
            ("name", "some-other-policy"),
        ):
            with self.subTest(field=field):
                candidate = self.orphan_forget_fixture()
                self.change(
                    candidate, CHECKER.AUTHORITY_PROOF_CONTROLLER_POLICY_ADDRESS
                )["before"][field] = value
                self.assert_rejected(candidate)

    def test_forgotten_proof_controller_grant_must_carry_prior_state(self) -> None:
        candidate = self.orphan_forget_fixture()
        self.change(
            candidate, CHECKER.AUTHORITY_PROOF_CONTROLLER_POLICY_ADDRESS
        )["before"] = None
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

    def test_catalog_holdback_is_exact_all_or_nothing(self) -> None:
        holdback = provisioned_cell_catalog_holdback_fixture()
        summary = CHECKER.check_plan(holdback)
        self.assertEqual(summary["resource_count"], 49)
        self.assertEqual(summary["plan_mode"], "no-op")

        partial = provisioned_cell_catalog_holdback_fixture()
        partial["resource_changes"].append(
            copy.deepcopy(
                next(
                    item
                    for item in plan_fixture()["resource_changes"]
                    if item["address"]
                    == CHECKER.PROVISIONED_CELL_ADDRESSES["cell0"]
                )
            )
        )
        self.assert_rejected(partial)

        full_output_without_rows = provisioned_cell_catalog_holdback_fixture()
        full_output_without_rows["planned_values"]["outputs"][
            "provisioned_cells"
        ]["value"] = copy.deepcopy(CHECKER.PROVISIONED_CELL_CATALOG)
        self.assert_rejected(full_output_without_rows)

        empty_output_with_rows = plan_fixture()
        empty_output_with_rows["planned_values"]["outputs"]["provisioned_cells"][
            "value"
        ] = {}
        self.assert_rejected(empty_output_with_rows)

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

        external_catalog = plan_fixture()
        catalog_resource = self.configuration_resource(
            external_catalog,
            "module.control.aws_dynamodb_table_item.provisioned_cell",
        )
        catalog_resource["for_each_expression"] = {
            "references": ["var.unreviewed_cells"]
        }
        self.assert_rejected(external_catalog)

        derived_item = plan_fixture()
        catalog_resource = self.configuration_resource(
            derived_item,
            "module.control.aws_dynamodb_table_item.provisioned_cell",
        )
        catalog_resource["expressions"]["item"] = {
            "references": ["local.derived_endpoint"]
        }
        self.assert_rejected(derived_item)

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
            (
                "hub-worker-ingress-security-group-substitution",
                "module.control.aws_security_group.hub_worker",
                ("ingress",),
                [
                    "local.hub_edge_enabled",
                    "aws_security_group.external.id",
                    "aws_security_group.external",
                    "local.hub_edge_enabled",
                    "aws_security_group.external.id",
                    "aws_security_group.external",
                ],
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

    def test_standalone_security_groups_omit_inline_rule_configuration(self) -> None:
        candidate = plan_fixture()
        for address in CHECKER.STANDALONE_RULE_SECURITY_GROUPS:
            expressions = self.configuration_resource(candidate, address)[
                "expressions"
            ]
            self.assertNotIn("ingress", expressions)
            self.assertNotIn("egress", expressions)
        CHECKER.check_plan(candidate)

    def test_standalone_security_groups_reject_nonempty_inline_rules(self) -> None:
        inline_rule = {
            "constant_value": [
                {
                    "cidr_blocks": ["10.102.0.0/16"],
                    "from_port": 443,
                    "protocol": "tcp",
                    "to_port": 443,
                }
            ]
        }
        for address in CHECKER.STANDALONE_RULE_SECURITY_GROUPS:
            for field in ("ingress", "egress"):
                with self.subTest(address=address, field=field):
                    candidate = plan_fixture()
                    expressions = self.configuration_resource(candidate, address)[
                        "expressions"
                    ]
                    expressions[field] = copy.deepcopy(inline_rule)
                    self.assert_rejected(candidate)

    def test_missing_inline_rule_constant_remains_strict_for_other_sgs(self) -> None:
        candidate = plan_fixture()
        expressions = self.configuration_resource(
            candidate, "module.control.aws_default_security_group.control"
        )["expressions"]
        del expressions["egress"]
        self.assert_rejected(candidate)

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
            {"data_resource_count": len(CHECKER.EXPECTED_DATA_RESOURCES), "managed_resource_count": 51},
        )

    def test_catalog_holdback_inventory_is_exact_all_or_nothing(self) -> None:
        held_back = [
            address
            for address in self.expected_addresses()
            if address not in CHECKER.PROVISIONED_CELL_RESOURCES
        ]
        self.assertEqual(
            self.check(held_back),
            {"data_resource_count": len(CHECKER.EXPECTED_DATA_RESOURCES), "managed_resource_count": 49},
        )

        partial = [
            address
            for address in self.expected_addresses()
            if address != CHECKER.PROVISIONED_CELL_ADDRESSES["cell0"]
        ]
        with self.assertRaises(CHECKER.ContractError):
            self.check(partial)

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
            {
                "data_resource_count": len(CHECKER.EXPECTED_DATA_RESOURCES),
                "managed_resource_count": (
                    len(CHECKER.EXPECTED_RESOURCES)
                    + len(CHECKER.AUTHORITY_RUNTIME_RESOURCES)
                ),
            },
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
                "data_resource_count": len(CHECKER.EXPECTED_DATA_RESOURCES) + len(worker_data),
                "managed_resource_count": (
                    51
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
    planned_security = planned_security_fixture()
    for address in CHECKER.PROVISIONED_CELL_RESOURCES:
        by_address[address].clear()
        by_address[address].update(copy.deepcopy(planned_security[address][0]))
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
    by_address["module.control.aws_security_group.interface_endpoints"]["id"] = (
        RUNTIME_INTERFACE_SG_ID
    )
    by_address["module.control.aws_security_group.otp_redis"]["id"] = (
        RUNTIME_OTP_REDIS_SG_ID
    )
    data_key_arn = RUNTIME_AUTHORITY_DATA_KEY_ARN
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
                "security_group_ids": [RUNTIME_INTERFACE_SG_ID],
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
            "prefix_list_id": RUNTIME_DYNAMODB_PREFIX_LIST_ID,
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
            "security_group_ids": [RUNTIME_OTP_REDIS_SG_ID],
            "subnet_ids": subnet_ids,
        }
    )
    default_id = f"{CHECKER.CONTROL_PREFIX}-otp-default"
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
                },
                "provisioned_cells": {
                    "sensitive": False,
                    "type": ["object", {}],
                    "value": copy.deepcopy(CHECKER.PROVISIONED_CELL_CATALOG),
                },
            },
            "root_module": {"resources": resources},
        }
    }


def state_fixture_runtime() -> dict:
    """The dark state plus the applied complete runtime graph."""
    state = state_fixture()
    resources = state["values"]["root_module"]["resources"]
    by_address = {item["address"]: item["values"] for item in resources}
    dynamodb_policy, kms_policy, secrets_policy, email_policy = (
        runtime_scoped_endpoint_policies()
    )
    by_address["module.control.aws_vpc_endpoint.dynamodb"]["policy"] = dynamodb_policy
    by_address['module.control.aws_vpc_endpoint.interface["kms"]']["policy"] = kms_policy
    by_address['module.control.aws_vpc_endpoint.interface["secretsmanager"]'][
        "policy"
    ] = secrets_policy
    by_address['module.control.aws_vpc_endpoint.interface["email"]'][
        "policy"
    ] = email_policy
    interface_sg = by_address["module.control.aws_security_group.interface_endpoints"]
    interface_sg["ingress"] = [runtime_interface_ingress_rule()]
    interface_sg["egress"] = []
    runtime_security_values = {
        CHECKER.AUTHORITY_RUNTIME_LAMBDA_SG_ADDRESS: {
            "id": RUNTIME_LAMBDA_SG_ID,
            "name_prefix": f"{CHECKER.CONTROL_PREFIX}-ca-fn-v2-",
            "description": (
                "Connector Authority function ENIs; egress to Control dependency "
                "endpoints only"
            ),
            "vpc_id": "vpc-abc123",
            "ingress": [],
            "egress": [],
        },
        (
            "module.control.aws_vpc_security_group_egress_rule."
            "authority_interface_endpoints[0]"
        ): {
            "description": "HTTPS to Control interface endpoints",
            "from_port": 443,
            "to_port": 443,
            "ip_protocol": "tcp",
            "security_group_id": RUNTIME_LAMBDA_SG_ID,
            "referenced_security_group_id": RUNTIME_INTERFACE_SG_ID,
            "cidr_ipv4": None,
            "cidr_ipv6": None,
            "prefix_list_id": None,
        },
        ("module.control.aws_vpc_security_group_egress_rule.authority_dynamodb[0]"): {
            "description": "HTTPS to the DynamoDB gateway endpoint",
            "from_port": 443,
            "to_port": 443,
            "ip_protocol": "tcp",
            "security_group_id": RUNTIME_LAMBDA_SG_ID,
            "referenced_security_group_id": None,
            "cidr_ipv4": None,
            "cidr_ipv6": None,
            "prefix_list_id": RUNTIME_DYNAMODB_PREFIX_LIST_ID,
        },
        ("module.control.aws_vpc_security_group_egress_rule.authority_otp_redis[0]"): {
            "description": "TLS to Connector OTP Redis",
            "from_port": 6379,
            "to_port": 6379,
            "ip_protocol": "tcp",
            "security_group_id": RUNTIME_LAMBDA_SG_ID,
            "referenced_security_group_id": RUNTIME_OTP_REDIS_SG_ID,
            "cidr_ipv4": None,
            "cidr_ipv6": None,
            "prefix_list_id": None,
        },
        ("module.control.aws_vpc_security_group_ingress_rule.otp_redis_authority[0]"): {
            "description": "TLS from Connector Authority OTP functions",
            "from_port": 6379,
            "to_port": 6379,
            "ip_protocol": "tcp",
            "security_group_id": RUNTIME_OTP_REDIS_SG_ID,
            "referenced_security_group_id": RUNTIME_LAMBDA_SG_ID,
            "cidr_ipv4": None,
            "cidr_ipv6": None,
            "prefix_list_id": None,
        },
    }
    for address, resource_type in CHECKER.AUTHORITY_RUNTIME_RESOURCES.items():
        resources.append(
            {
                "address": address,
                "mode": "managed",
                "type": resource_type,
                "values": copy.deepcopy(
                    runtime_security_values.get(address, {"id": "runtime-placeholder"})
                ),
            }
        )
    return state


class StateContractTests(unittest.TestCase):
    def test_resource_inventory_contract_hash_is_reviewed(self) -> None:
        # Update only with an intentional, reviewed address/type inventory change.
        self.assertEqual(
            CHECKER.contract_sha256(),
            "0163ea49dd8a060b4f46c6af2310e83b644719f508b3298626ad047f4cd91d35",
        )

    def test_exact_state_passes(self) -> None:
        self.assertEqual(CHECKER.check_state(state_fixture())["resource_count"], 51)

    def test_catalog_holdback_state_is_exact_and_output_bound(self) -> None:
        holdback = state_fixture()
        holdback["values"]["root_module"]["resources"] = [
            item
            for item in holdback["values"]["root_module"]["resources"]
            if item["address"] not in CHECKER.PROVISIONED_CELL_RESOURCES
        ]
        holdback["values"]["outputs"]["provisioned_cells"]["value"] = {}
        self.assertEqual(CHECKER.check_state(holdback)["resource_count"], 49)

        full_output = copy.deepcopy(holdback)
        full_output["values"]["outputs"]["provisioned_cells"]["value"] = (
            copy.deepcopy(CHECKER.PROVISIONED_CELL_CATALOG)
        )
        with self.assertRaises(CHECKER.ContractError):
            CHECKER.check_state(full_output)

        empty_output_with_rows = state_fixture()
        empty_output_with_rows["values"]["outputs"]["provisioned_cells"][
            "value"
        ] = {}
        with self.assertRaises(CHECKER.ContractError):
            CHECKER.check_state(empty_output_with_rows)

    def test_state_rejects_catalog_row_or_public_output_drift(self) -> None:
        missing_row = state_fixture()
        missing_row["values"]["root_module"]["resources"] = [
            item
            for item in missing_row["values"]["root_module"]["resources"]
            if item["address"]
            != 'module.control.aws_dynamodb_table_item.provisioned_cell["cell0"]'
        ]
        with self.assertRaisesRegex(
            CHECKER.ContractError, "refreshed state inventory mismatch"
        ):
            CHECKER.check_state(missing_row)

        row_drift = state_fixture()
        resources = row_drift["values"]["root_module"]["resources"]
        by_address = {item["address"]: item["values"] for item in resources}
        cell0 = (
            'module.control.aws_dynamodb_table_item.provisioned_cell["cell0"]'
        )
        item = json.loads(by_address[cell0]["item"])
        item["server_public_key_b64"] = {
            "S": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        }
        by_address[cell0]["item"] = json.dumps(
            item, separators=(",", ":"), sort_keys=True
        )
        with self.assertRaises(CHECKER.ContractError):
            CHECKER.check_state(row_drift)

        output_drift = state_fixture()
        output_drift["values"]["outputs"]["provisioned_cells"]["value"]["cell1"][
            "nhp_host"
        ] = "cell0.nhp.layerv.xyz"
        with self.assertRaises(CHECKER.ContractError):
            CHECKER.check_state(output_drift)

        identity_drift = state_fixture()
        resources = identity_drift["values"]["root_module"]["resources"]
        by_address = {item["address"]: item["values"] for item in resources}
        by_address[cell0]["id"] = (
            f"{CHECKER.PROVISIONED_CELL_TABLE_NAME},REGISTRY,CELL#cell1"
        )
        with self.assertRaises(CHECKER.ContractError):
            CHECKER.check_state(identity_drift)

    def test_state_catalog_item_admits_rendering_and_pins_every_value(
        self,
    ) -> None:
        """The refreshed-state lane tolerates the same serialisation, only it.

        `check_state` reads the applied rows, so it sees the provider's
        re-rendered `item` on every run. It must accept that spelling and
        still reject any moved value.
        """
        cell0 = (
            'module.control.aws_dynamodb_table_item.provisioned_cell["cell0"]'
        )
        canonical = json.loads(
            CHECKER.PROVISIONED_CELL_EXPECTED_ITEM_JSON["cell0"]
        )

        def state_with_item(rendered: object) -> dict:
            state = state_fixture()
            by_address = {
                item["address"]: item["values"]
                for item in state["values"]["root_module"]["resources"]
            }
            by_address[cell0]["item"] = rendered
            return state

        for label, rendered in (
            (
                "create-time jsonencode",
                CHECKER.PROVISIONED_CELL_EXPECTED_ITEM_JSON["cell0"],
            ),
            ("applied trailing newline", applied_provisioned_cell_item("cell0")),
            ("expanded whitespace", json.dumps(canonical, indent=2)),
        ):
            with self.subTest(rendering=label):
                CHECKER.check_state(state_with_item(rendered))

        for attribute, value in (
            ("status", {"S": "revoked"}),
            ("nhp_host", {"S": "attacker.example"}),
            ("nhp_port", {"N": "62206"}),
            (
                "server_public_key_b64",
                {"S": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},
            ),
            ("selection_weight", {"N": "2"}),
            ("updated_at", {"S": "2026-07-26T00:00:00Z"}),
        ):
            with self.subTest(attribute=attribute):
                drifted = copy.deepcopy(canonical)
                drifted[attribute] = value
                with self.assertRaisesRegex(
                    CHECKER.ContractError,
                    rf"provisioned-cell item attributes differ: \['{attribute}'\]",
                ):
                    CHECKER.check_state(
                        state_with_item(
                            json.dumps(
                                drifted, separators=(",", ":"), sort_keys=True
                            )
                        )
                    )

        with self.assertRaisesRegex(
            CHECKER.ContractError, "item is malformed JSON"
        ):
            CHECKER.check_state(state_with_item("{not json"))

        # The unobserved "|"-joined resource id must fail closed here too.
        pipe_id = state_fixture()
        by_address = {
            item["address"]: item["values"]
            for item in pipe_id["values"]["root_module"]["resources"]
        }
        by_address[cell0]["id"] = (
            f"{CHECKER.PROVISIONED_CELL_TABLE_NAME}|REGISTRY|CELL#cell0"
        )
        with self.assertRaisesRegex(
            CHECKER.ContractError, "steady key identity is not exact"
        ):
            CHECKER.check_state(pipe_id)

    def test_state_admits_the_general_assignable_flip(self) -> None:
        """The refreshed-state (post-apply / `verify`) lane admits the B6 flip:
        cell1's applied row carries {BOOL:false}, the public output surfaces the
        resolved Boolean per cell, and every other field stays pinned."""
        cell1 = (
            'module.control.aws_dynamodb_table_item.provisioned_cell["cell1"]'
        )

        def flipped_state(cell1_value: bool = False) -> dict:
            state = state_fixture()
            by_address = {
                item["address"]: item["values"]
                for item in state["values"]["root_module"]["resources"]
            }
            flipped = {
                **json.loads(by_address[cell1]["item"]),
                "general_assignable": {"BOOL": cell1_value},
            }
            by_address[cell1]["item"] = json.dumps(flipped, sort_keys=True)
            out = state["values"]["outputs"]["provisioned_cells"]["value"]
            out["cell0"]["general_assignable"] = True
            out["cell1"]["general_assignable"] = cell1_value
            return state

        # The applied flip (and its restore) verify cleanly.
        CHECKER.check_state(flipped_state(False))
        CHECKER.check_state(flipped_state(True))

        # A non-Boolean general_assignable in the refreshed output fails closed.
        bad_type = flipped_state(False)
        bad_type["values"]["outputs"]["provisioned_cells"]["value"]["cell1"][
            "general_assignable"
        ] = "false"
        with self.assertRaisesRegex(
            CHECKER.ContractError,
            "refreshed state provisioned-cell catalog output is not exact",
        ):
            CHECKER.check_state(bad_type)

        # A drifted non-assignability output field still fails closed even with a
        # valid general_assignable present.
        drifted = flipped_state(False)
        drifted["values"]["outputs"]["provisioned_cells"]["value"]["cell0"][
            "nhp_port"
        ] = 62206
        with self.assertRaisesRegex(
            CHECKER.ContractError,
            "refreshed state provisioned-cell catalog output is not exact",
        ):
            CHECKER.check_state(drifted)

    def test_exact_runtime_state_passes(self) -> None:
        self.assertEqual(
            CHECKER.check_state(state_fixture_runtime())["resource_count"],
            len(CHECKER.EXPECTED_RESOURCES) + len(CHECKER.AUTHORITY_RUNTIME_RESOURCES),
        )

    def test_closed_proof_window_admits_permanent_hub_alias_overlap(self) -> None:
        state = state_fixture_runtime()
        resources = state["values"]["root_module"]["resources"]
        by_address = {item["address"]: item["values"] for item in resources}
        self.assertFalse(
            set(by_address) & set(CHECKER.AUTHORITY_PROOF_ROLLOUT_RESOURCES)
        )
        hub_edge_address = "module.control.aws_subnet.hub_public[0]"
        hub_worker_address = "module.control.aws_security_group.hub_worker[0]"
        hub_worker_sg_id = "sg-a11a5"
        resources.extend(
            [
                {
                    "address": hub_edge_address,
                    "mode": "managed",
                    "type": "aws_subnet",
                    "values": {"id": "subnet-hub"},
                },
                {
                    "address": hub_worker_address,
                    "mode": "managed",
                    "type": "aws_security_group",
                    "values": {"id": hub_worker_sg_id},
                },
            ]
        )
        hub_ingress = runtime_interface_ingress_rule()
        hub_ingress.update(
            {
                "description": "HTTPS from Hub worker ENIs",
                "security_groups": [hub_worker_sg_id],
            }
        )
        by_address[CHECKER.AUTHORITY_RUNTIME_INTERFACE_SG_ADDRESS]["ingress"].append(
            hub_ingress
        )
        by_address[CHECKER.HUB_WORKER_LAMBDA_ENDPOINT_ADDRESS]["policy"] = (
            hub_lambda_endpoint_policy()["policy"]
        )

        class ReachedHubEndpointPolicy(Exception):
            pass

        check_endpoint_policy = CHECKER._check_hub_lambda_endpoint_policy

        def check_endpoint_policy_and_stop(after: dict, address: str) -> None:
            check_endpoint_policy(after, address)
            raise ReachedHubEndpointPolicy

        # Narrow the optional Hub inventories to isolate check_state's policy
        # routing. The full Hub inventory and each resource contract are covered
        # separately; this regression must prove that a closed proof-rollout
        # window still routes the live six-alias endpoint policy to the steady
        # validator without deriving a selected-color-only expectation.
        with (
            mock.patch.object(
                CHECKER, "HUB_EDGE_RESOURCES", {hub_edge_address: "aws_subnet"}
            ),
            mock.patch.object(
                CHECKER,
                "HUB_WORKER_RESOURCES",
                {hub_worker_address: "aws_security_group"},
            ),
            mock.patch.object(
                CHECKER,
                "_check_hub_lambda_endpoint_policy",
                check_endpoint_policy_and_stop,
            ),
            self.assertRaises(ReachedHubEndpointPolicy),
        ):
            CHECKER.check_state(state)

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

    def test_runtime_state_rejects_function_sg_inline_cidr(self) -> None:
        state = state_fixture_runtime()
        function_sg = next(
            item["values"]
            for item in state["values"]["root_module"]["resources"]
            if item["address"] == CHECKER.AUTHORITY_RUNTIME_LAMBDA_SG_ADDRESS
        )
        function_sg["egress"] = [
            {
                "cidr_blocks": ["10.102.0.0/16"],
                "from_port": 443,
                "to_port": 443,
                "protocol": "tcp",
            }
        ]
        with self.assertRaises(CHECKER.ContractError):
            CHECKER.check_state(state)

    def test_runtime_state_rejects_cidr_substitute_for_sg_edge(self) -> None:
        state = state_fixture_runtime()
        address = (
            "module.control.aws_vpc_security_group_egress_rule."
            "authority_interface_endpoints[0]"
        )
        rule = next(
            item["values"]
            for item in state["values"]["root_module"]["resources"]
            if item["address"] == address
        )
        rule["referenced_security_group_id"] = None
        rule["cidr_ipv4"] = "10.102.0.0/16"
        with self.assertRaises(CHECKER.ContractError):
            CHECKER.check_state(state)

    def test_runtime_state_rejects_wrong_inline_ingress_source(self) -> None:
        state = state_fixture_runtime()
        interface_sg = next(
            item["values"]
            for item in state["values"]["root_module"]["resources"]
            if item["address"] == CHECKER.AUTHORITY_RUNTIME_INTERFACE_SG_ADDRESS
        )
        interface_sg["ingress"][0]["security_groups"] = ["sg-0bad0000000000000"]
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
        # NHP #3362 removed the detached legacy user that held the last broad
        # category grant, so no command category survives anywhere in the file.
        for category in ("+@connection", "+@read", "+@write", "+@scripting"):
            self.assertNotIn(category, redis)
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
        "control-security-groups.json": {"SecurityGroups": []},
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
        "SecurityGroups": ["sg-a1b2c3"],
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
    write_json(
        root / "control-security-groups.json",
        {
            "SecurityGroups": [
                {
                    "GroupId": "sg-a1b2c3",
                    "Tags": [
                        {"Key": "Component", "Value": "connector-hub-edge"},
                        {
                            "Key": "Name",
                            "Value": f"{CHECKER.CONTROL_PREFIX}-hub-nlb",
                        },
                    ],
                    "IpPermissions": [
                        {
                            "IpProtocol": "udp",
                            "FromPort": 443,
                            "ToPort": 443,
                            "IpRanges": [{"CidrIp": CHECKER.HUB_PUBLIC_UDP_INGRESS_CIDR}],
                        }
                    ],
                    "IpPermissionsEgress": [],
                }
            ]
        },
    )


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
    security = json.loads((root / "control-security-groups.json").read_text())
    nlb_group = security["SecurityGroups"][0]
    nlb_group["IpPermissionsEgress"] = [
        {
            "IpProtocol": "udp",
            "FromPort": 62206,
            "ToPort": 62206,
            "UserIdGroupPairs": [{"GroupId": "sg-d4e5f6"}],
        },
        {
            "IpProtocol": "tcp",
            "FromPort": 62207,
            "ToPort": 62207,
            "UserIdGroupPairs": [{"GroupId": "sg-d4e5f6"}],
        },
    ]
    security["SecurityGroups"].append(
        {
            "GroupId": "sg-d4e5f6",
            "Tags": [
                {"Key": "Component", "Value": "connector-hub"},
                {"Key": "Name", "Value": f"{CHECKER.CONTROL_PREFIX}-hub"},
            ],
            "IpPermissions": [
                {
                    "IpProtocol": "udp",
                    "FromPort": 62206,
                    "ToPort": 62206,
                    "UserIdGroupPairs": [{"GroupId": "sg-a1b2c3"}],
                },
                {
                    "IpProtocol": "tcp",
                    "FromPort": 62207,
                    "ToPort": 62207,
                    "UserIdGroupPairs": [{"GroupId": "sg-a1b2c3"}],
                },
            ],
            # Worker HTTPS egress is validated by Terraform state/plan; live
            # edge validation only normalizes ingress and the NLB's inverse.
            "IpPermissionsEgress": [],
        }
    )
    write_json(root / "control-security-groups.json", security)


class LiveHubEdgePhaseTests(unittest.TestCase):
    """Pre-apply asserts invariants; post-apply asserts the exact target.

    Pinning the target pre-apply gates the apply on its own outcome. That is
    structural, not incidental: it deadlocked the 62206 -> 443 port migration
    and again when the Hub edge source opened to 0.0.0.0/0.
    """

    def _with_hub_ingress(self, root: Path, *, port: int, cidr: str) -> None:
        payload = json.loads((root / "control-security-groups.json").read_text())
        for group in payload["SecurityGroups"]:
            if group["GroupId"] != "sg-a1b2c3":
                continue
            group["IpPermissions"] = [
                {
                    "IpProtocol": "udp",
                    "FromPort": port,
                    "ToPort": port,
                    "IpRanges": [{"CidrIp": cidr}],
                }
            ]
        write_json(root / "control-security-groups.json", payload)

    def test_pre_apply_admits_the_source_the_apply_replaces(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            live_edge_fixture(root)
            self._with_hub_ingress(root, port=443, cidr="3.141.109.76/32")
            # Post-apply refuses it: the edge is not open yet.
            with self.assertRaises(CHECKER.ContractError):
                CHECKER.check_live(root)
            # Pre-apply admits it, which is what lets the opening apply run.
            self.assertEqual(
                CHECKER.check_live(root, pre_apply=True)["vpc_id"], "vpc-abc123"
            )

    def test_pre_apply_still_refuses_what_no_apply_may_do(self) -> None:
        for label, mutate in (
            (
                "two rules",
                lambda payload: payload["IpPermissions"].append(
                    {
                        "IpProtocol": "udp",
                        "FromPort": 443,
                        "ToPort": 443,
                        "IpRanges": [{"CidrIp": "10.0.0.0/8"}],
                    }
                ),
            ),
            (
                "non-UDP",
                lambda payload: payload["IpPermissions"][0].update(IpProtocol="tcp"),
            ),
            (
                "port range",
                lambda payload: payload["IpPermissions"][0].update(ToPort=9999),
            ),
            (
                "security-group source",
                lambda payload: payload["IpPermissions"][0].update(
                    IpRanges=[], UserIdGroupPairs=[{"GroupId": "sg-a1b2c3"}]
                ),
            ),
        ):
            with self.subTest(case=label):
                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    live_edge_fixture(root)
                    payload = json.loads(
                        (root / "control-security-groups.json").read_text()
                    )
                    for group in payload["SecurityGroups"]:
                        if group["GroupId"] == "sg-a1b2c3":
                            mutate(group)
                    write_json(root / "control-security-groups.json", payload)
                    with self.assertRaises(CHECKER.ContractError):
                        CHECKER.check_live(root, pre_apply=True)

    def test_post_apply_requires_the_open_edge_on_the_current_port(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            live_edge_fixture(root)
            self._with_hub_ingress(root, port=443, cidr="0.0.0.0/0")
            self.assertEqual(CHECKER.check_live(root)["vpc_id"], "vpc-abc123")
            # The legacy port is no longer tolerated: that migration is complete,
            # and accepting both only weakened the steady-state assertion.
            self._with_hub_ingress(root, port=62206, cidr="0.0.0.0/0")
            with self.assertRaises(CHECKER.ContractError):
                CHECKER.check_live(root)


class LiveHubWorkerBoundaryTests(unittest.TestCase):
    def test_live_worker_admits_the_s3_gateway_route(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            live_worker_fixture(root)
            self.assertEqual(CHECKER.check_live(root)["vpc_id"], "vpc-abc123")

    def test_live_edge_rejects_an_unreviewed_ingress_source(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            live_edge_fixture(root)
            payload = json.loads(
                (root / "control-security-groups.json").read_text()
            )
            payload["SecurityGroups"][0]["IpPermissions"][0]["IpRanges"][0][
                "CidrIp"
            ] = "198.51.100.7/32"
            write_json(root / "control-security-groups.json", payload)
            with self.assertRaisesRegex(
                CHECKER.ContractError, "the open sandbox edge UDP 443"
            ):
                CHECKER.check_live(root)

    def test_live_edge_rejects_nlb_without_attached_sg(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            live_edge_fixture(root)
            payload = json.loads((root / "control-load-balancers.json").read_text())
            payload[0]["SecurityGroups"] = []
            write_json(root / "control-load-balancers.json", payload)
            with self.assertRaisesRegex(
                CHECKER.ContractError, "attach exactly the reviewed NLB SG"
            ):
                CHECKER.check_live(root)

    def test_live_worker_rejects_cidr_target_ingress(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            live_worker_fixture(root)
            payload = json.loads(
                (root / "control-security-groups.json").read_text()
            )
            worker = next(
                group
                for group in payload["SecurityGroups"]
                if group["GroupId"] == "sg-d4e5f6"
            )
            worker["IpPermissions"][0].pop("UserIdGroupPairs")
            worker["IpPermissions"][0]["IpRanges"] = [{"CidrIp": "0.0.0.0/0"}]
            write_json(root / "control-security-groups.json", payload)
            with self.assertRaisesRegex(
                CHECKER.ContractError, "exactly from the Hub NLB SG"
            ):
                CHECKER.check_live(root)

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
                        *CHECKER.AUTHORITY_RUNTIME_FUNCTIONS,
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
                        *CHECKER.AUTHORITY_RUNTIME_FUNCTIONS,
                        CHECKER.HUB_KEYGEN_FUNCTION_NAME,
                        "layerv-nhp-sandbox-control-rogue",
                    ]
                ],
            )
            with self.assertRaises(CHECKER.ContractError):
                CHECKER.check_live(root)


class HubIdentityMigrationTests(unittest.TestCase):
    def test_exact_migration_and_converged_identity_pass(self) -> None:
        CHECKER._check_hub_identity_resources(hub_identity_migration_fixture())
        CHECKER._check_hub_identity_resources(
            hub_identity_migration_fixture(converged=True)
        )

    def test_transition_action_boundary_is_exact(self) -> None:
        actions = {
            **{
                address: ["create"]
                for address in CHECKER.HUB_IDENTITY_CREATE_ADDRESSES
            },
            **{
                address: ["update"]
                for address in CHECKER.HUB_IDENTITY_UPDATE_ADDRESSES
            },
        }
        exact, creates, updates = (
            CHECKER._hub_identity_transition_pending(actions)
        )
        self.assertTrue(exact)
        self.assertEqual(creates, set(CHECKER.HUB_IDENTITY_CREATE_ADDRESSES))
        self.assertEqual(updates, set(CHECKER.HUB_IDENTITY_UPDATE_ADDRESSES))

        publication_address = (
            "module.control.aws_lambda_invocation.hub_identity_publication[0]"
        )
        partial, partial_creates, _ = (
            CHECKER._hub_identity_transition_pending(
                {publication_address: ["create"]}
            )
        )
        self.assertTrue(partial)
        self.assertEqual(partial_creates, {publication_address})

        wrong = copy.deepcopy(actions)
        wrong[publication_address] = ["delete", "create"]
        self.assertFalse(CHECKER._hub_identity_transition_pending(wrong)[0])

    def test_kms_conditions_are_required_on_both_consumers(self) -> None:
        for address in (
            "module.control.aws_iam_role_policy.hub_keygen[0]",
            "module.control.aws_iam_role_policy.hub_execution[0]",
        ):
            candidate = hub_identity_migration_fixture()
            policy = json.loads(candidate[address]["change"]["after"]["policy"])
            kms_statement = next(
                statement
                for statement in policy["Statement"]
                if statement["Sid"]
                in {"WrapHubKeyMaterial", "DecryptHubKeyMaterial"}
            )
            del kms_statement["Condition"]
            candidate[address]["change"]["after"]["policy"] = json.dumps(policy)
            with self.assertRaises(CHECKER.ContractError):
                CHECKER._check_hub_identity_resources(candidate)

    def test_public_parameter_permission_cannot_broaden(self) -> None:
        candidate = hub_identity_migration_fixture()
        address = "module.control.aws_iam_role_policy.hub_keygen[0]"
        policy = json.loads(candidate[address]["change"]["after"]["policy"])
        publish = next(
            statement
            for statement in policy["Statement"]
            if statement["Sid"] == "PublishHubPublicIdentity"
        )
        publish["Resource"] = "*"
        candidate[address]["change"]["after"]["policy"] = json.dumps(policy)
        with self.assertRaises(CHECKER.ContractError):
            CHECKER._check_hub_identity_resources(candidate)

    def test_keygen_runtime_and_serialization_are_exact(self) -> None:
        for field, value in (
            ("runtime", "python3.13"),
            ("reserved_concurrent_executions", -1),
            ("vpc_config", [{"subnet_ids": ["subnet-bypass"]}]),
        ):
            candidate = hub_identity_migration_fixture()
            candidate[
                "module.control.aws_lambda_function.hub_keygen[0]"
            ]["change"]["after"][field] = value
            with self.assertRaises(CHECKER.ContractError):
                CHECKER._check_hub_identity_resources(candidate)

    def test_publication_invocation_is_additive_and_triggerless(self) -> None:
        address = (
            "module.control.aws_lambda_invocation.hub_identity_publication[0]"
        )
        for mutation in ("trigger", "replacement", "replace_path"):
            candidate = hub_identity_migration_fixture()
            change = candidate[address]["change"]
            if mutation == "trigger":
                change["after"]["triggers"] = {"rerun": "unsafe"}
            elif mutation == "replacement":
                change["actions"] = ["delete", "create"]
                change["before"] = copy.deepcopy(change["after"])
            else:
                change["replace_paths"] = [["function_name"]]
            with self.assertRaises(CHECKER.ContractError):
                CHECKER._check_hub_identity_resources(candidate)

    def test_invocation_create_retry_is_exact(self) -> None:
        candidate = hub_identity_migration_fixture()
        CHECKER._check_hub_identity_resources(candidate)

        for mutation in ("unexpected-before", "replacement-path"):
            malformed = copy.deepcopy(candidate)
            malformed_change = malformed[
                "module.control.aws_lambda_invocation.hub_identity_publication[0]"
            ]["change"]
            if mutation == "unexpected-before":
                malformed_change["before"] = {}
            else:
                malformed_change["replace_paths"] = [["triggers"]]
            with self.assertRaises(CHECKER.ContractError):
                CHECKER._check_hub_identity_resources(malformed)

    def test_placeholder_cannot_be_a_converged_noop(self) -> None:
        candidate = hub_identity_migration_fixture(converged=True)
        candidate[
            "module.control.aws_ssm_parameter.hub_public_key[0]"
        ]["change"]["after"]["value"] = "pending-keygen"
        with self.assertRaises(CHECKER.ContractError):
            CHECKER._check_hub_identity_resources(candidate)

    def test_noncanonical_or_zero_public_key_fails(self) -> None:
        for value in (
            base64.b64encode(b"\x00" * 32).decode(),
            base64.b64encode(b"x" * 31).decode(),
            base64.b64encode(b"x" * 32).decode().rstrip("="),
        ):
            candidate = hub_identity_migration_fixture(converged=True)
            candidate[
                "module.control.aws_ssm_parameter.hub_public_key[0]"
            ]["change"]["after"]["value"] = value
            with self.assertRaises(CHECKER.ContractError):
                CHECKER._check_hub_identity_resources(candidate)


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


class HubS3EndpointPolicyTests(unittest.TestCase):
    def _after(self, **overrides) -> dict:
        stmt = {
            "Sid": "HubPullLayers",
            "Effect": "Allow",
            "Principal": "*",
            "Action": "s3:GetObject",
            "Resource": [CHECKER.HUB_S3_LAYER_BUCKET_ARN],
        }
        stmt.update(overrides)
        return {"policy": json.dumps({"Version": "2012-10-17", "Statement": [stmt]})}

    def test_exact_passes(self) -> None:
        CHECKER._check_hub_s3_endpoint_policy(self._after(), "s3")

    def test_principal_condition_rejected(self) -> None:
        # A principal condition 403s ECR presigned-URL layer GETs, so it is banned.
        after = self._after(
            Condition={
                "StringEquals": {"aws:PrincipalArn": [CHECKER.HUB_EXECUTION_ROLE_ARN]}
            }
        )
        with self.assertRaises(CHECKER.ContractError):
            CHECKER._check_hub_s3_endpoint_policy(after, "s3")

    def test_wrong_bucket_fails(self) -> None:
        with self.assertRaises(CHECKER.ContractError):
            CHECKER._check_hub_s3_endpoint_policy(
                self._after(Resource=["arn:aws:s3:::some-other-bucket/*"]), "s3"
            )

    def test_wrong_action_fails(self) -> None:
        with self.assertRaises(CHECKER.ContractError):
            CHECKER._check_hub_s3_endpoint_policy(
                self._after(Action="s3:PutObject"), "s3"
            )


class HubAuthorityAliasOverlapPolicyTests(unittest.TestCase):
    def test_exact_two_resource_update_is_the_only_admitted_shape(self) -> None:
        exact = {
            CHECKER.HUB_WORKER_LAMBDA_ENDPOINT_ADDRESS: ["update"],
            CHECKER.HUB_WORKER_TASK_POLICY_ADDRESS: ["update"],
        }
        self.assertTrue(
            CHECKER._is_exact_hub_authority_alias_overlap_policy_update(
                hub_worker_mode=True,
                changed=set(exact),
                actual_non_noop=exact,
                deposed_by_address={},
            )
        )

        for label, worker_mode, actions, deposed in (
            ("worker dark", False, exact, {}),
            (
                "extra resource",
                True,
                {**exact, "module.control.aws_iam_role_policy.rogue": ["update"]},
                {},
            ),
            (
                "destructive action",
                True,
                {**exact, CHECKER.HUB_WORKER_TASK_POLICY_ADDRESS: ["delete"]},
                {},
            ),
            ("deposed object", True, exact, {"rogue": [{}]}),
        ):
            with self.subTest(label=label):
                self.assertFalse(
                    CHECKER._is_exact_hub_authority_alias_overlap_policy_update(
                        hub_worker_mode=worker_mode,
                        changed=set(actions),
                        actual_non_noop=actions,
                        deposed_by_address=deposed,
                    )
                )

    def test_steady_policies_require_both_closed_aliases(self) -> None:
        endpoint = hub_lambda_endpoint_policy()
        task_policy = {
            "name": "hub-task",
            "role": f"{CHECKER.CONTROL_PREFIX}-hub-task",
            "policy": json.dumps(
                CHECKER._expected_hub_task_inline_policy(
                    rollout=True, selected="blue"
                )
            ),
        }

        CHECKER._check_hub_lambda_endpoint_policy(
            endpoint,
            CHECKER.HUB_WORKER_LAMBDA_ENDPOINT_ADDRESS,
        )
        CHECKER._check_hub_task_policy(
            task_policy, CHECKER.HUB_WORKER_TASK_POLICY_ADDRESS
        )

        selected_only = copy.deepcopy(task_policy)
        selected_only["policy"] = json.dumps(
            CHECKER._expected_hub_task_inline_policy(
                rollout=False, selected="blue"
            )
        )
        with self.assertRaises(CHECKER.ContractError):
            CHECKER._check_hub_task_policy(
                selected_only, CHECKER.HUB_WORKER_TASK_POLICY_ADDRESS
            )

        selected_only_endpoint = hub_lambda_endpoint_policy(rollout=False)
        with self.assertRaises(CHECKER.ContractError):
            CHECKER._check_hub_lambda_endpoint_policy(
                selected_only_endpoint,
                CHECKER.HUB_WORKER_LAMBDA_ENDPOINT_ADDRESS,
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

    def test_live_boundary_admits_exact_complete_authority_graph(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            live_fixture(root)
            write_json(
                root / "control-lambdas.json",
                [
                    {"FunctionName": name, "Runtime": None}
                    for name in CHECKER.AUTHORITY_RUNTIME_FUNCTIONS
                ],
            )
            self.assertEqual(
                CHECKER.check_live(root)["authority_function_count"],
                len(CHECKER.AUTHORITY_RUNTIME_FUNCTIONS),
            )

    def test_live_boundary_admits_the_legacy_hub_predecessor(self) -> None:
        # This proof runs BEFORE the expansion apply, so the live set is still
        # the legacy Hub trio. Admitting only the complete 13 made the expansion
        # unappliable -- the gate demanded the functions the apply creates.
        # Observed on control-update-apply run 30220568057.
        for extra in ((), (CHECKER.HUB_KEYGEN_FUNCTION_NAME,)):
            with (
                self.subTest(hub_keygen=bool(extra)),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory)
                live_fixture(root)
                write_json(
                    root / "control-lambdas.json",
                    [
                        {"FunctionName": name, "Runtime": None}
                        for name in (
                            *CHECKER.AUTHORITY_RUNTIME_HUB_FUNCTIONS,
                            *extra,
                        )
                    ],
                )
                self.assertEqual(
                    CHECKER.check_live(root)["authority_function_count"],
                    len(CHECKER.AUTHORITY_RUNTIME_HUB_FUNCTIONS) + len(extra),
                )

    def test_live_boundary_admits_the_exact_pre_creso_predecessor(self) -> None:
        # This is the live shape between the original 3 -> 11 cell-runtime
        # expansion and the one-time 11 -> 13 creso expansion. Freeze both its
        # membership and cardinality so a future cell/operation cannot silently
        # widen this historical predecessor.
        self.assertEqual(len(CHECKER.AUTHORITY_RUNTIME_PRE_CRESO_FUNCTIONS), 11)
        self.assertEqual(
            set(CHECKER.AUTHORITY_RUNTIME_PRE_CRESO_FUNCTIONS),
            set(CHECKER.AUTHORITY_RUNTIME_FUNCTIONS)
            - set(CHECKER.AUTHORITY_CONNECTOR_RESOURCE_FUNCTIONS),
        )
        for extra in ((), (CHECKER.HUB_KEYGEN_FUNCTION_NAME,)):
            with (
                self.subTest(hub_keygen=bool(extra)),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory)
                live_fixture(root)
                write_json(
                    root / "control-lambdas.json",
                    [
                        {"FunctionName": name, "Runtime": None}
                        for name in (
                            *CHECKER.AUTHORITY_RUNTIME_PRE_CRESO_FUNCTIONS,
                            *extra,
                        )
                    ],
                )
                self.assertEqual(
                    CHECKER.check_live(root)["authority_function_count"],
                    len(CHECKER.AUTHORITY_RUNTIME_PRE_CRESO_FUNCTIONS)
                    + len(extra),
                )

    def test_live_boundary_rejects_partial_expansion_shapes(self) -> None:
        # Only exact historical endpoints are admitted. Anything part-way
        # through either 3 -> 11 or 11 -> 13, or any set missing a member,
        # fails closed.
        complete = list(CHECKER.AUTHORITY_RUNTIME_FUNCTIONS)
        legacy = list(CHECKER.AUTHORITY_RUNTIME_HUB_FUNCTIONS)
        pre_creso = list(CHECKER.AUTHORITY_RUNTIME_PRE_CRESO_FUNCTIONS)
        partial_cell_runtime = legacy + [n for n in pre_creso if n not in legacy][:1]
        partial_creso = pre_creso + [
            n for n in complete if n not in pre_creso
        ][:1]
        for payload in (
            partial_cell_runtime,
            partial_creso,
            complete[:-1],
            pre_creso[:-1],
            legacy[:-1],
        ):
            with (
                self.subTest(names=len(payload)),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory)
                live_fixture(root)
                write_json(
                    root / "control-lambdas.json",
                    [{"FunctionName": n, "Runtime": None} for n in payload],
                )
                with self.assertRaisesRegex(
                    CHECKER.ContractError, "11-function pre-creso predecessor"
                ):
                    CHECKER.check_live(root)

    def test_live_boundary_rejects_unexpected_or_malformed_lambdas(self) -> None:
        for payload in (
            [{"FunctionName": "layerv-nhp-sandbox-ca-rogue"}],
            [{"FunctionName": name} for name in CHECKER.AUTHORITY_RUNTIME_FUNCTIONS]
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


class OutputsOnlyApplyabilityTests(unittest.TestCase):
    """An outputs-only Control change is a no-op plan that IS applyable.

    Adding a root output touches no resource, so `changed` is empty and the
    plan classifies as "no-op" -- but the apply still rewrites state outputs and
    Terraform reports applyable=true. The gate previously expected a no-op plan
    to be unapplyable unless it was a refresh-only normalization, so every
    outputs-only Control change was unmergeable.
    """

    def plan(self, *, applyable, output_actions, with_resource_changes=True):
        plan = {
            "output_changes": {
                "some_output": {"actions": output_actions},
            },
            "applyable": applyable,
        }
        if with_resource_changes:
            plan["resource_changes"] = []
        return plan

    def expected(self, plan, plan_mode="no-op", drift=0):
        output_only_change = any(
            isinstance(change, dict) and change.get("actions") != ["no-op"]
            for change in (plan.get("output_changes") or {}).values()
        )
        return (
            plan_mode != "no-op"
            or (drift > 0 and "resource_changes" not in plan)
            or output_only_change
        )

    def test_a_changed_output_makes_a_no_op_plan_applyable(self) -> None:
        plan = self.plan(applyable=True, output_actions=["update"])
        self.assertTrue(self.expected(plan))

    def test_a_created_output_makes_a_no_op_plan_applyable(self) -> None:
        plan = self.plan(applyable=True, output_actions=["create"])
        self.assertTrue(self.expected(plan))

    def test_an_unchanged_output_leaves_a_no_op_plan_unapplyable(self) -> None:
        """The fence: no-op outputs must NOT excuse an applyable no-op plan."""
        plan = self.plan(applyable=False, output_actions=["no-op"])
        self.assertFalse(self.expected(plan))

    def test_a_resource_transition_is_unaffected(self) -> None:
        plan = self.plan(applyable=True, output_actions=["no-op"])
        self.assertTrue(self.expected(plan, plan_mode="hub-worker-image-update"))

    def test_refresh_only_normalization_is_unaffected(self) -> None:
        plan = self.plan(
            applyable=True, output_actions=["no-op"], with_resource_changes=False
        )
        self.assertTrue(self.expected(plan, drift=1))


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
        self.assertIn(
            '- "tests/fixtures/control-hub-source-fence/**"',
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
        # This lane plans with -refresh=false, so it MUST declare that to the
        # checker. Without the flag the checker assumes a refreshed plan and
        # demands values that an out-of-band writer (the keygen Lambda) makes
        # unobservable here. Pinned so the two cannot drift apart silently.
        self.assertIn("-refresh=false", plan_workflow)
        self.assertIn(
            "control.tfplan.json --refresh-disabled",
            plan_workflow,
        )
        # The Authority runtime flags are DERIVED from
        # .github/control-sandbox-runtime-gates.json, never written out here.
        # This assertion used to pin the literal flag list, which made the gate
        # file and this lane two sources of truth: a PR retiring a gate that
        # forgot this workflow planned to re-create what it was retiring, and
        # the pin held the stale list in place. Pin the reader instead.
        self.assertIn(
            'gate_flag_text="$(.github/scripts/control-sandbox-runtime-gates.py flags)"',
            plan_workflow,
        )
        # Same reasoning as the C6 fence in check-control-leg-surfaced.sh, which
        # covers only build-and-push.yml: reading the gates is necessary but not
        # sufficient, because process substitution discards the reader's exit
        # status. This is the PR lane's only coverage of that.
        self.assertNotRegex(
            plan_workflow, r"< *<\(.*control-sandbox-runtime-gates\.py"
        )
        # The receipt: bind the generated tfvars back to the gate file, so a
        # generator rename cannot make this lane plan a shape nobody chose.
        self.assertIn(
            ".github/scripts/control-sandbox-runtime-gates.py verify-tfvars",
            plan_workflow,
        )
        # The regression guard proper: any generator gate flag appearing
        # literally in this workflow means the hard-coded list is back.
        #
        # The flag names are DERIVED from the reader's own tables, not copied
        # here. Copying them would reintroduce this PR's own defect one level
        # down — a silent one, at that: an eighth gate added to the reader
        # would go uncovered forever with this test still green, where the
        # stale workflow list at least produced a visibly wrong plan.
        spec = importlib.util.spec_from_file_location(
            "control_sandbox_runtime_gates", GATES_READER_PATH
        )
        assert spec and spec.loader
        gates_reader = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(gates_reader)
        gate_flags = [
            flag
            for _, flag in gates_reader.BOOLEAN_GATES + gates_reader.COLOR_GATES
        ]
        # Not a count pin — the point is that an eighth gate is covered without
        # touching this test. Only guard the vacuous pass: renamed or emptied
        # tables would loop over nothing and stay green.
        self.assertTrue(gate_flags, "gate reader exposed no flags to deny")
        for flag in gate_flags:
            self.assertNotIn(flag, plan_workflow)
        self.assertNotIn("--expected-action", plan_workflow)
        self.assertIn(
            "Fail closed on any unreviewed Control mutation",
            plan_workflow,
        )


class AlarmRefreshSensitiveTests(unittest.TestCase):
    """Alarm re-projection is validated structurally, not against a literal."""

    def test_placeholder_maps_are_admitted(self) -> None:
        # Terraform renders these structurally: False for a non-sensitive
        # scalar, empty collections for lists/maps. This is the real shape the
        # applied sandbox alarms carry.
        for value in (
            {"alarm_actions": [False], "dimensions": {}, "tags": {}},
            {"actions_suppressor": [], "alarm_actions": [False], "tags_all": {}},
            {},
            [],
            False,
            None,
        ):
            with self.subTest(repr(value)[:40]):
                self.assertTrue(CHECKER._is_placeholder_sensitive(value))

    def test_any_real_sensitive_value_is_refused(self) -> None:
        # A True anywhere means an actual sensitive value is present. Admitting
        # one as "normalization" would let a secret ride in on a drift entry.
        for value in (
            True,
            {"alarm_actions": [False], "leaked": True},
            {"nested": {"deeper": [True]}},
            [False, [True]],
            "a-string-is-not-a-placeholder",
        ):
            with self.subTest(repr(value)[:40]):
                self.assertFalse(CHECKER._is_placeholder_sensitive(value))

    def test_only_the_reviewed_alarm_families_take_the_structural_path(self) -> None:
        for address in CHECKER._ALARM_REFRESH_NORMALIZATION_PREFIXES:
            with self.subTest(address):
                self.assertEqual(
                    CHECKER._refresh_sensitive_contract(f'{address}["x"]'),
                    (None, None),
                )
        with self.assertRaises(CHECKER.ContractError):
            CHECKER._refresh_sensitive_contract(
                "module.control.aws_cloudwatch_metric_alarm.not_reviewed"
            )


class HubSourceFenceTransitionTests(unittest.TestCase):
    """One-time Hub carrier replacement must bind its exact legacy state."""

    def test_exact_hub_source_fence_transition_passes(self) -> None:
        CHECKER._check_hub_source_fence_transition(
            hub_source_fence_transition_changes_fixture()
        )

    def test_exact_partial_retry_with_target_noops_passes(self) -> None:
        CHECKER._check_hub_source_fence_transition(
            hub_source_fence_partial_retry_fixture()
        )

    def test_exact_deposed_nlb_retry_phases_pass(self) -> None:
        for listener_create in (False, True):
            candidate, deposed = hub_source_fence_deposed_retry_fixture(
                listener_create=listener_create
            )
            with self.subTest(listener_create=listener_create):
                CHECKER._check_hub_source_fence_transition(candidate, deposed)

    def test_partial_retry_rejects_unsafe_target_noop(self) -> None:
        candidate = hub_source_fence_partial_retry_fixture()
        sg_address = "module.control.aws_security_group.hub_nlb[0]"
        candidate[sg_address]["change"]["after"]["id"] = "sg-attacker"
        with self.assertRaisesRegex(
            CHECKER.ContractError, "exact target no-op"
        ):
            CHECKER._check_hub_source_fence_transition(candidate)

    def test_deposed_retry_rejects_legacy_envelope_drift(self) -> None:
        candidate, deposed = hub_source_fence_deposed_retry_fixture(
            listener_create=False
        )
        deposed["module.control.aws_lb.hub[0]"][0]["change"]["before"][
            "dns_record_client_routing_policy"
        ] = "availability_zone_affinity"
        with self.assertRaisesRegex(
            CHECKER.ContractError, "exact captured SG-less legacy"
        ):
            CHECKER._check_hub_source_fence_transition(candidate, deposed)

    def test_identity_and_fence_address_sets_are_disjoint(self) -> None:
        """The invariant that lets the fence branch withhold identity addresses.

        ``check_plan`` filters the Hub identity addresses out of the map it hands
        to the fence validator. That is only safe while the two sets share no
        address -- otherwise a fence resource could be hidden from its own deep
        validation.
        """
        self.assertEqual(
            CHECKER.HUB_IDENTITY_MIGRATION_ADDRESSES
            & frozenset(CHECKER.HUB_SOURCE_FENCE_ACTIONS),
            frozenset(),
        )

    def test_fence_validator_still_rejects_an_identity_address(self) -> None:
        """The composition is the call-site filter, not a loosened validator.

        A co-occurring Hub identity create is admitted by ``check_plan`` only
        after ``_hub_identity_transition_pending`` proves its exact shape. The
        fence validator itself must stay strict, so that an identity address
        reaching it directly is still an unreviewed action subset.
        """
        candidate = hub_source_fence_transition_changes_fixture()
        candidate[
            "module.control.aws_lambda_invocation.hub_identity_publication[0]"
        ] = {"change": {"actions": ["create"], "before": None, "after": {}}}
        with self.assertRaisesRegex(
            CHECKER.ContractError, "exact reviewed remaining action subset"
        ):
            CHECKER._check_hub_source_fence_transition(candidate)

    def test_alarm_and_fence_address_sets_are_disjoint(self) -> None:
        """The invariant that lets the fence branch withhold alarm addresses.

        ``check_plan`` filters the NHP #3455 alarm addresses out of the map it
        hands to the fence validator when the two transitions co-occur. That is
        only safe while the two sets share no address -- otherwise a fence
        resource could be hidden from its own deep validation.
        """
        alarm_scope = frozenset(CHECKER.AUTHORITY_ALARM_RESOURCES) | frozenset(
            CHECKER.AUTHORITY_ALARM_UPDATE_ADDRESSES
        )
        self.assertEqual(
            alarm_scope & frozenset(CHECKER.HUB_SOURCE_FENCE_ACTIONS),
            frozenset(),
        )
        # And disjoint from the Hub identity set, so the two co-occurring
        # slices cannot mask each other either.
        self.assertEqual(
            alarm_scope & CHECKER.HUB_IDENTITY_MIGRATION_ADDRESSES,
            frozenset(),
        )

    def test_observed_fence_plus_alarm_change_set_composes(self) -> None:
        """The exact 144-address change set the sandbox Control plan produces.

        Reconstructed from the observed failure class: the 122 pending alarm
        creates, the 13 in-place spillover updates, the 8 pending Hub
        source-fence actions, and the still-pending Hub identity publication.
        Before the alarm subtraction the fence candidate is not a subset of the
        reviewed fence actions (which is exactly why the plan was rejected);
        after it, it is. Guards against a future edit dropping the composition
        and silently re-blocking every Control-root PR.
        """
        alarm_slice_changed = set(CHECKER.AUTHORITY_ALARM_RESOURCES) | set(
            CHECKER.AUTHORITY_ALARM_UPDATE_ADDRESSES
        )
        identity = "module.control.aws_lambda_invocation.hub_identity_publication[0]"
        observed = (
            alarm_slice_changed | set(CHECKER.HUB_SOURCE_FENCE_ACTIONS) | {identity}
        )
        self.assertEqual(len(observed), 144)

        candidate = observed - {identity}
        self.assertFalse(
            candidate.issubset(CHECKER.HUB_SOURCE_FENCE_ACTIONS),
            "without the alarm subtraction the fence subset test must fail",
        )
        self.assertTrue(
            (candidate - alarm_slice_changed).issubset(
                CHECKER.HUB_SOURCE_FENCE_ACTIONS
            ),
            "with the alarm subtraction the fence candidate must be exactly the "
            "reviewed fence actions",
        )

    def test_fence_validator_still_rejects_an_alarm_address(self) -> None:
        """The alarm composition is the call-site filter, not a loosened
        validator.

        A co-occurring alarm slice is admitted by ``check_plan`` only after
        ``authority_alarm_slice_exact`` proves its exact shape. The fence
        validator itself must stay strict, so an alarm address reaching it
        directly is still an unreviewed action subset.
        """
        for address, actions in (
            (
                "module.control.aws_cloudwatch_metric_alarm."
                'authority_runtime["layerv-nhp-sandbox-ca-ia:errors"]',
                ["create"],
            ),
            (
                "module.control.aws_cloudwatch_metric_alarm."
                'authority_spillover["layerv-nhp-sandbox-ca-ia"]',
                ["update"],
            ),
        ):
            with self.subTest(address=address):
                candidate = hub_source_fence_transition_changes_fixture()
                candidate[address] = {
                    "change": {"actions": actions, "before": None, "after": {}}
                }
                with self.assertRaisesRegex(
                    CHECKER.ContractError, "exact reviewed remaining action subset"
                ):
                    CHECKER._check_hub_source_fence_transition(candidate)

    def test_unrelated_drift_is_rejected(self) -> None:
        candidate = hub_source_fence_transition_changes_fixture()
        candidate["module.control.aws_vpc.control"] = {
            "change": {
                "actions": ["update"],
                "before": {"enable_dns_support": True},
                "after": {"enable_dns_support": False},
            }
        }
        with self.assertRaisesRegex(
            CHECKER.ContractError, "exact reviewed remaining action subset"
        ):
            CHECKER._check_hub_source_fence_transition(candidate)

    def test_wrong_legacy_source_fence_is_rejected(self) -> None:
        candidate = hub_source_fence_transition_changes_fixture()
        candidate["module.control.aws_lb.hub[0]"]["change"]["before"][
            "security_groups"
        ] = ["sg-unreviewed"]
        with self.assertRaisesRegex(CHECKER.ContractError, "replacement before"):
            CHECKER._check_hub_source_fence_transition(candidate)

    def test_nlb_dns_routing_policy_injection_is_rejected(self) -> None:
        candidate = hub_source_fence_transition_changes_fixture()
        candidate["module.control.aws_lb.hub[0]"]["change"]["after"][
            "dns_record_client_routing_policy"
        ] = "availability_zone_affinity"
        with self.assertRaisesRegex(CHECKER.ContractError, "replacement after"):
            CHECKER._check_hub_source_fence_transition(candidate)

    def _privatelink_enforcement_plan(
        self, *, before: str = "", after: str = "on"
    ) -> dict:
        """A steady post-fence plan carrying only the exact PrivateLink flip."""
        plan = hub_edge_transition_fixture()
        # The edge is already applied: every edge resource settles to a no-op so
        # the only non-no-op left is the attribute flip under test.
        for entry in plan["resource_changes"]:
            change = entry["change"]
            if change.get("actions") == ["create"]:
                change["actions"] = ["no-op"]
                change["before"] = copy.deepcopy(change["after"])
        item = next(
            entry
            for entry in plan["resource_changes"]
            if entry["address"] == CHECKER.HUB_EDGE_LOAD_BALANCER_ADDRESS
        )
        change = item["change"]
        change["actions"] = ["update"]
        change["before"] = copy.deepcopy(change["after"])
        change["after"] = copy.deepcopy(change["after"])
        change["before"].update(
            {
                "internal": False,
                "load_balancer_type": "network",
                "name": CHECKER.HUB_EDGE_LOAD_BALANCER_NAME,
                CHECKER.PRIVATELINK_ENFORCEMENT_ATTRIBUTE: before,
            }
        )
        change["after"].update(
            {
                "internal": False,
                "load_balancer_type": "network",
                "name": CHECKER.HUB_EDGE_LOAD_BALANCER_NAME,
                CHECKER.PRIVATELINK_ENFORCEMENT_ATTRIBUTE: after,
            }
        )
        change["after_unknown"] = {}
        return plan

    def test_privatelink_enforcement_is_its_own_bounded_plan_mode(self) -> None:
        for before in ("", "off"):
            with self.subTest(before=before):
                self.assertEqual(
                    "hub-privatelink-enforcement",
                    CHECKER.check_plan(
                        self._privatelink_enforcement_plan(before=before)
                    )["plan_mode"],
                )

    def test_privatelink_enforcement_lane_is_exactly_bounded(self) -> None:
        # Each mutation is a way the lane could be widened into a general Hub-edge
        # mutation escape; every one must fall through to the fail-closed
        # fallback rather than being admitted.
        def refused(plan: dict) -> None:
            with self.assertRaises(CHECKER.ContractError):
                CHECKER.check_plan(plan)

        with self.subTest("a second attribute may not ride along"):
            plan = self._privatelink_enforcement_plan()
            next(
                entry
                for entry in plan["resource_changes"]
                if entry["address"] == CHECKER.HUB_EDGE_LOAD_BALANCER_ADDRESS
            )["change"]["after"]["security_groups"] = ["sg-rogue"]
            refused(plan)

        with self.subTest("the target value must be exactly on"):
            for after in ("off", "", "ON", "true"):
                refused(self._privatelink_enforcement_plan(after=after))

        with self.subTest("an already-on predecessor is not a correction"):
            refused(self._privatelink_enforcement_plan(before="on"))

        with self.subTest("nothing may be deferred to apply time"):
            plan = self._privatelink_enforcement_plan()
            next(
                entry
                for entry in plan["resource_changes"]
                if entry["address"] == CHECKER.HUB_EDGE_LOAD_BALANCER_ADDRESS
            )["change"]["after_unknown"] = {"subnets": True}
            refused(plan)

        with self.subTest("a forced replacement must fail closed"):
            plan = self._privatelink_enforcement_plan()
            next(
                entry
                for entry in plan["resource_changes"]
                if entry["address"] == CHECKER.HUB_EDGE_LOAD_BALANCER_ADDRESS
            )["change"]["replace_paths"] = [["security_groups"]]
            refused(plan)

        with self.subTest("the edge identity must be the reviewed one"):
            plan = self._privatelink_enforcement_plan()
            change = next(
                entry
                for entry in plan["resource_changes"]
                if entry["address"] == CHECKER.HUB_EDGE_LOAD_BALANCER_ADDRESS
            )["change"]
            change["before"]["name"] = "layerv-nhp-sandbox-hub-rogue"
            change["after"]["name"] = "layerv-nhp-sandbox-hub-rogue"
            refused(plan)

        with self.subTest("the lane admits no co-travelling change"):
            plan = self._privatelink_enforcement_plan()
            other = next(
                entry
                for entry in plan["resource_changes"]
                if entry["address"]
                == "module.control.aws_lb_listener.hub[0]"
            )
            other["change"]["actions"] = ["update"]
            other["change"]["after"] = {"rogue": True}
            refused(plan)

    def test_privatelink_enforcement_does_not_mask_a_pending_fence(self) -> None:
        # The replacement lane's own NLB action is create/delete, never update,
        # and a pending fence necessarily carries more than this singleton.
        plan = self._privatelink_enforcement_plan()
        next(
            entry
            for entry in plan["resource_changes"]
            if entry["address"] == CHECKER.HUB_EDGE_LOAD_BALANCER_ADDRESS
        )["change"]["actions"] = ["create", "delete"]
        with self.assertRaises(CHECKER.ContractError):
            CHECKER.check_plan(plan)

    def test_listener_certificate_injection_is_rejected(self) -> None:
        candidate = hub_source_fence_transition_changes_fixture()
        candidate["module.control.aws_lb_listener.hub[0]"]["change"]["after"][
            "certificate_arn"
        ] = (
            "arn:aws:acm:us-east-2:767397897469:"
            "certificate/00000000-0000-0000-0000-000000000000"
        )
        with self.assertRaisesRegex(CHECKER.ContractError, "replacement after"):
            CHECKER._check_hub_source_fence_transition(candidate)

    def test_persisted_provider_envelope_drift_is_rejected(self) -> None:
        cases = {
            "nlb-before-derived-identity": (
                "module.control.aws_lb.hub[0]",
                "before",
                lambda envelope: envelope.__setitem__(
                    "dns_name", "unreviewed.elb.us-east-2.amazonaws.com"
                ),
            ),
            "nlb-unknown-security-groups": (
                "module.control.aws_lb.hub[0]",
                "after_unknown",
                lambda envelope: envelope.__setitem__("security_groups", False),
            ),
            "nlb-sensitive-subnet-shape": (
                "module.control.aws_lb.hub[0]",
                "after_sensitive",
                lambda envelope: envelope["subnet_mapping"].append({}),
            ),
            "nlb-identity-drift": (
                "module.control.aws_lb.hub[0]",
                "after_identity",
                lambda envelope: envelope.__setitem__(
                    "arn", envelope["arn"].replace("651df21ec4f8f904", "0" * 16)
                ),
            ),
            "listener-unknown-ssl-policy": (
                "module.control.aws_lb_listener.hub[0]",
                "after_unknown",
                lambda envelope: envelope.__setitem__("ssl_policy", False),
            ),
            "listener-sensitive-tags-shape": (
                "module.control.aws_lb_listener.hub[0]",
                "before_sensitive",
                lambda envelope: envelope.pop("tags"),
            ),
            "listener-identity-drift": (
                "module.control.aws_lb_listener.hub[0]",
                "after_identity",
                lambda envelope: envelope.__setitem__(
                    "arn", envelope["arn"].replace("b4f22dd284158770", "f" * 16)
                ),
            ),
            "target-unknown-protocol": (
                "module.control.aws_lb_target_group.hub[0]",
                "after_unknown",
                lambda envelope: envelope.__setitem__("protocol", True),
            ),
            "target-before-sensitive-health-check": (
                "module.control.aws_lb_target_group.hub[0]",
                "before_sensitive",
                lambda envelope: envelope.__setitem__("health_check", True),
            ),
            "target-after-sensitive-health-check": (
                "module.control.aws_lb_target_group.hub[0]",
                "after_sensitive",
                lambda envelope: envelope.__setitem__("health_check", True),
            ),
            "target-before-identity": (
                "module.control.aws_lb_target_group.hub[0]",
                "before_identity",
                lambda envelope: envelope.__setitem__("arn", "target-attacker"),
            ),
            "target-after-identity": (
                "module.control.aws_lb_target_group.hub[0]",
                "after_identity",
                lambda envelope: envelope.__setitem__("arn", "target-attacker"),
            ),
            "worker-unknown-ingress": (
                "module.control.aws_security_group.hub_worker[0]",
                "after_unknown",
                lambda envelope: envelope.__setitem__("ingress", True),
            ),
            "worker-before-sensitive-ingress": (
                "module.control.aws_security_group.hub_worker[0]",
                "before_sensitive",
                lambda envelope: envelope.__setitem__("ingress", True),
            ),
            "worker-after-sensitive-ingress": (
                "module.control.aws_security_group.hub_worker[0]",
                "after_sensitive",
                lambda envelope: envelope.__setitem__("ingress", True),
            ),
            "worker-before-identity": (
                "module.control.aws_security_group.hub_worker[0]",
                "before_identity",
                lambda envelope: envelope.__setitem__("id", "sg-attacker"),
            ),
            "worker-after-identity": (
                "module.control.aws_security_group.hub_worker[0]",
                "after_identity",
                lambda envelope: envelope.__setitem__("id", "sg-attacker"),
            ),
            "parameter-unknown-version": (
                "module.control.aws_ssm_parameter.hub_udp_listener_arn[0]",
                "after_unknown",
                lambda envelope: envelope.__setitem__("version", False),
            ),
            "parameter-before-sensitive-value": (
                "module.control.aws_ssm_parameter.hub_udp_listener_arn[0]",
                "before_sensitive",
                lambda envelope: envelope.__setitem__("value", False),
            ),
            "parameter-after-sensitive-value": (
                "module.control.aws_ssm_parameter.hub_udp_listener_arn[0]",
                "after_sensitive",
                lambda envelope: envelope.__setitem__("value", False),
            ),
            "parameter-before-identity": (
                "module.control.aws_ssm_parameter.hub_udp_listener_arn[0]",
                "before_identity",
                lambda envelope: envelope.__setitem__("name", "/attacker"),
            ),
            "parameter-after-identity": (
                "module.control.aws_ssm_parameter.hub_udp_listener_arn[0]",
                "after_identity",
                lambda envelope: envelope.__setitem__("name", "/attacker"),
            ),
        }
        for name, (address, side, mutate) in cases.items():
            candidate = hub_source_fence_transition_changes_fixture()
            mutate(candidate[address]["change"][side])
            with (
                self.subTest(case=name),
                self.assertRaisesRegex(
                    CHECKER.ContractError, rf"replacement {side}"
                ),
            ):
                CHECKER._check_hub_source_fence_transition(candidate)

    def test_extra_provider_envelope_field_is_rejected(self) -> None:
        for address in CHECKER.HUB_SOURCE_FENCE_PROVIDER_ADDRESSES:
            candidate = hub_source_fence_transition_changes_fixture()
            candidate[address]["change"]["generated_config"] = {}
            with (
                self.subTest(address=address),
                self.assertRaisesRegex(
                    CHECKER.ContractError, "replacement envelope fields"
                ),
            ):
                CHECKER._check_hub_source_fence_transition(candidate)

    def test_wrong_action_order_is_rejected(self) -> None:
        candidate = hub_source_fence_transition_changes_fixture()
        candidate["module.control.aws_lb_listener.hub[0]"]["change"]["actions"] = [
            "create",
            "delete",
        ]
        with self.assertRaisesRegex(
            CHECKER.ContractError, "exact reviewed remaining action subset"
        ):
            CHECKER._check_hub_source_fence_transition(candidate)

    def test_partial_and_mixed_replacement_are_rejected(self) -> None:
        partial = hub_source_fence_transition_changes_fixture()
        partial.pop(
            "module.control.aws_vpc_security_group_egress_rule.hub_nlb_health[0]"
        )
        mixed = hub_source_fence_transition_changes_fixture()
        mixed["module.control.aws_lb_target_group.hub[0]"]["change"]["actions"] = [
            "update"
        ]
        for candidate in (partial, mixed):
            with (
                self.subTest(candidate=candidate),
                self.assertRaises(CHECKER.ContractError),
            ):
                CHECKER._check_hub_source_fence_transition(candidate)

    def test_target_and_backend_sg_changes_are_bounded(self) -> None:
        target_drift = hub_source_fence_transition_changes_fixture()
        target_drift["module.control.aws_lb_target_group.hub[0]"]["change"]["after"][
            "health_check"
        ][0]["port"] = "443"
        worker_drift = hub_source_fence_transition_changes_fixture()
        worker_drift["module.control.aws_security_group.hub_worker[0]"]["change"][
            "after"
        ]["tags"]["Name"] = "unreviewed"
        for candidate in (target_drift, worker_drift):
            with (
                self.subTest(candidate=candidate),
                self.assertRaises(CHECKER.ContractError),
            ):
                CHECKER._check_hub_source_fence_transition(candidate)

    def test_listener_parameter_change_is_value_only(self) -> None:
        candidate = hub_source_fence_transition_changes_fixture()
        candidate["module.control.aws_ssm_parameter.hub_udp_listener_arn[0]"]["change"][
            "after"
        ]["tier"] = "Advanced"
        with self.assertRaisesRegex(
            CHECKER.ContractError, "replacement after"
        ):
            CHECKER._check_hub_source_fence_transition(candidate)

    def test_dns_root_pins_replacement_nlb_names(self) -> None:
        variables = (
            ROOT / "terraform" / "environments" / "sandbox-hub-dns" / "variables.tf"
        ).read_text(encoding="utf-8")
        for variable, expected in (
            ("hub_nlb_name", "layerv-nhp-sandbox-hub-edge"),
            ("cell0_nlb_name", "layerv-nhp-sandbox-edge"),
        ):
            marker = f'variable "{variable}" {{'
            _, found, remainder = variables.partition(marker)
            self.assertEqual(found, marker)
            block = marker + remainder.split('\nvariable "', 1)[0]
            self.assertIn(f'condition     = var.{variable} == "{expected}"', block)
        self.assertNotIn("0.0.0.0/0", variables)


def authority_sg_deposed_delete_fixture() -> dict[str, object]:
    """The exact deposed generation-1 Authority function SG pending delete."""

    return {
        "address": CHECKER.AUTHORITY_FUNCTION_SG_ADDRESS,
        "type": "aws_security_group",
        "mode": "managed",
        "deposed": CHECKER.AUTHORITY_FUNCTION_SG_DEPOSED_KEY,
        "change": {
            "actions": ["delete"],
            "after": None,
            "before": {
                "id": CHECKER.AUTHORITY_FUNCTION_SG_DEPOSED_ID,
                "name_prefix": f"{CHECKER.CONTROL_PREFIX}-ca-fn-",
                "description": (
                    "Connector Authority function ENIs; egress to Control "
                    "dependency endpoints only"
                ),
                "vpc_id": "vpc-0d911f0d4b6cb7176",
                "ingress": [],
                "egress": [
                    {
                        "cidr_blocks": [CHECKER.CONTROL_VPC_CIDR],
                        "description": (
                            "HTTPS to Control interface endpoints (KMS) in-VPC"
                        ),
                        "from_port": 443,
                        "ipv6_cidr_blocks": [],
                        "prefix_list_ids": [],
                        "protocol": "tcp",
                        "security_groups": [],
                        "self": False,
                        "to_port": 443,
                    },
                    {
                        "cidr_blocks": [],
                        "description": (
                            "HTTPS to the DynamoDB gateway endpoint prefix list"
                        ),
                        "from_port": 443,
                        "ipv6_cidr_blocks": [],
                        "prefix_list_ids": ["pl-4ca54025"],
                        "protocol": "tcp",
                        "security_groups": [],
                        "self": False,
                        "to_port": 443,
                    },
                ],
            },
        },
    }


class AuthorityFunctionSgDeposedDeleteTests(unittest.TestCase):
    """The one reviewed deposed object: exact, and admitted only as itself."""

    def test_exact_captured_deposed_delete_is_admitted(self) -> None:
        self.assertTrue(
            CHECKER._is_exact_legacy_authority_sg_deposed_delete(
                authority_sg_deposed_delete_fixture()
            )
        )

    def test_identity_must_match_the_reviewed_object(self) -> None:
        for field, value in (
            ("deposed", "deadbeef"),
            ("address", "module.control.aws_security_group.interface_endpoints"),
            ("type", "aws_vpc"),
            ("mode", "data"),
        ):
            item = authority_sg_deposed_delete_fixture()
            item[field] = value
            with self.subTest(field=field):
                self.assertFalse(
                    CHECKER._is_exact_legacy_authority_sg_deposed_delete(item)
                )

    def test_rejects_foreign_group_id(self) -> None:
        item = authority_sg_deposed_delete_fixture()
        item["change"]["before"]["id"] = "sg-0000000000000000f"
        self.assertFalse(CHECKER._is_exact_legacy_authority_sg_deposed_delete(item))

    def test_only_a_pure_delete_of_the_object_is_admitted(self) -> None:
        for actions, after in (
            (["delete", "create"], None),
            (["create", "delete"], None),
            (["delete"], {"name_prefix": f"{CHECKER.CONTROL_PREFIX}-ca-fn-v2-"}),
        ):
            item = authority_sg_deposed_delete_fixture()
            item["change"]["actions"] = actions
            item["change"]["after"] = after
            with self.subTest(actions=actions):
                self.assertFalse(
                    CHECKER._is_exact_legacy_authority_sg_deposed_delete(item)
                )

    def test_rejects_generation_one_before_state_drift(self) -> None:
        widened = authority_sg_deposed_delete_fixture()
        widened["change"]["before"]["egress"][0]["cidr_blocks"] = ["0.0.0.0/0"]
        extra = authority_sg_deposed_delete_fixture()
        extra["change"]["before"]["egress"].append(
            dict(extra["change"]["before"]["egress"][0], description="extra")
        )
        retained_ingress = authority_sg_deposed_delete_fixture()
        retained_ingress["change"]["before"]["ingress"] = [
            dict(retained_ingress["change"]["before"]["egress"][0])
        ]
        generation_two = authority_sg_deposed_delete_fixture()
        generation_two["change"]["before"]["name_prefix"] = (
            f"{CHECKER.CONTROL_PREFIX}-ca-fn-v2-"
        )
        for label, item in (
            ("widened_cidr", widened),
            ("extra_rule", extra),
            ("retained_ingress", retained_ingress),
            ("generation_two", generation_two),
        ):
            with self.subTest(label=label):
                self.assertFalse(
                    CHECKER._is_exact_legacy_authority_sg_deposed_delete(item)
                )

    def test_foreign_deposed_objects_still_fail_closed(self) -> None:
        """The admission must not weaken the unreviewed-deposed guard."""

        candidate = hub_source_fence_transition_changes_fixture()
        foreign = authority_sg_deposed_delete_fixture()
        foreign["address"] = "module.control.aws_vpc.control"
        with self.assertRaisesRegex(
            CHECKER.ContractError, "unreviewed deposed resources"
        ):
            CHECKER._check_hub_source_fence_transition(
                candidate, {"module.control.aws_vpc.control": [foreign]}
            )


class HubEdgeSliceTests(unittest.TestCase):
    """Step 5 slice 5a: the Hub public UDP edge admission + plan_mode."""

    def test_hub_edge_slice_admitted(self) -> None:
        summary = CHECKER.check_plan(hub_edge_transition_fixture())
        self.assertEqual(summary["plan_mode"], "hub-edge-slice")

    def test_hub_edge_new_sg_accepts_provider_unknown_empty_collections(
        self,
    ) -> None:
        candidate = hub_edge_transition_fixture()
        nlb_sg = next(
            item
            for item in candidate["resource_changes"]
            if item["address"] == "module.control.aws_security_group.hub_nlb[0]"
        )["change"]
        del nlb_sg["after"]["ingress"]
        del nlb_sg["after"]["egress"]
        nlb_sg["after_unknown"].update({"ingress": True, "egress": True})

        summary = CHECKER.check_plan(candidate)
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


class FirstProjectionDriftTests(unittest.TestCase):
    """The before-value discriminator that filters signal-free refresh drift.

    State that held NO prior value cannot evidence an out-of-band change, so
    such drift is admitted ahead of the reviewed-kind matching. State that held
    a value which then differs is the signal this checker exists to catch and
    must still match an exact reviewed normalization.
    """

    @staticmethod
    def _entry(before: object, after: object, address: str = "m.a") -> dict:
        return {
            "address": address,
            "mode": "managed",
            "type": "aws_iam_role",
            "change": {"actions": ["update"], "before": before, "after": after},
        }

    def assert_rejected(self, plan: dict, prior_state: object = None) -> None:
        with self.assertRaises(CHECKER.ContractError):
            CHECKER.check_plan(plan, prior_state)

    # --- the discriminator itself -------------------------------------------

    def test_unrecorded_before_values_are_first_projections(self) -> None:
        for label, before in (
            ("absent", {"other": 1}),
            ("null", {"other": 1, "k": None}),
            ("empty-list", {"other": 1, "k": []}),
            ("empty-dict", {"other": 1, "k": {}}),
        ):
            with self.subTest(label=label):
                entry = self._entry({**before}, {**before, "k": ["populated"]})
                self.assertTrue(CHECKER._drift_is_first_projection_only(entry))

    def test_recorded_before_value_is_never_a_first_projection(self) -> None:
        # A recorded value that changed is the signal. Scalars count as recorded
        # even when falsy: "" / 0 / False are real provider settings, and a
        # boolean flip is exactly the posture change that must not slip through.
        for label, before_value, after_value in (
            ("populated-list", ["a"], ["a", "b"]),
            ("populated-dict", {"a": 1}, {"a": 2}),
            ("empty-string", "", "arn:aws:kms:::key/real"),
            ("zero", 0, 3),
            ("false", False, True),
            ("list-emptied", ["a"], []),
            ("string-changed", "old", "new"),
        ):
            with self.subTest(label=label):
                entry = self._entry({"k": before_value}, {"k": after_value})
                self.assertFalse(CHECKER._drift_is_first_projection_only(entry))

    def test_mixed_entry_needs_every_differing_key_unrecorded(self) -> None:
        # One recorded key that changed taints the whole entry, even alongside
        # any number of genuine projections.
        entry = self._entry(
            {"ok_actions": None, "tags": {}, "description": "reviewed"},
            {"ok_actions": [], "tags": {"a": "b"}, "description": "tampered"},
        )
        self.assertFalse(CHECKER._drift_is_first_projection_only(entry))

    def test_empty_before_object_is_not_a_first_projection(self) -> None:
        # An empty before object is a CREATE (or a malformed entry), not a
        # re-projection onto an object state already tracked.
        self.assertFalse(
            CHECKER._drift_is_first_projection_only(self._entry({}, {"k": ["v"]}))
        )

    def test_nothing_differing_is_not_a_first_projection(self) -> None:
        # Must not be vacuously true: that would admit malformed entries whose
        # before/after are identical, bypassing the bounded rejection diagnostic.
        self.assertFalse(
            CHECKER._drift_is_first_projection_only(
                self._entry({"k": "v"}, {"k": "v"})
            )
        )

    def test_malformed_change_envelopes_fail_closed(self) -> None:
        for label, entry in (
            ("no-change", {"address": "m.a"}),
            ("change-not-object", {"address": "m.a", "change": "x"}),
            ("before-not-object", self._entry("x", {"k": []})),
            ("after-not-object", self._entry({"k": None}, "x")),
            ("before-null", self._entry(None, {"k": []})),
            ("item-not-object", "x"),
        ):
            with self.subTest(label=label):
                self.assertFalse(CHECKER._drift_is_first_projection_only(entry))

    def test_discriminator_is_not_the_attribute_name(self) -> None:
        # Noise and signal arrive in the SAME attributes. `ingress` from an empty
        # state is the Hub NLB read-back; `ingress` from a recorded rule set is a
        # widened security group and must not be filtered.
        rule = {"from_port": 62206, "to_port": 62206, "protocol": "udp"}
        self.assertTrue(
            CHECKER._drift_is_first_projection_only(
                self._entry({"ingress": []}, {"ingress": [rule]})
            )
        )
        self.assertFalse(
            CHECKER._drift_is_first_projection_only(
                self._entry(
                    {"ingress": [rule]},
                    {"ingress": [rule, {**rule, "cidr_blocks": ["0.0.0.0/0"]}]},
                )
            )
        )

    # --- end-to-end through check_plan --------------------------------------

    def test_first_projection_outside_the_slice_is_admitted(self) -> None:
        # The counterpart to
        # test_authority_runtime_slice_completion_rejects_drift_outside_slice:
        # base-resource drift that never held a prior value is admitted without
        # any reviewed kind. This is the sandbox shape (122 alarm
        # projections on base resources during a slice completion).
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
            _slice_refresh_drift(
                "module.control.aws_cloudwatch_metric_alarm.hub_target_health",
                "aws_cloudwatch_metric_alarm",
            ),
        ]
        summary = CHECKER.check_plan(candidate)
        self.assertEqual(summary["normalization_drift_kind"], "first-projection")
        self.assertEqual(summary["normalization_drift_count"], 3)

    def test_one_substantive_entry_among_many_benign_is_rejected(self) -> None:
        # The live shape with a tampered needle: 20 pure projections plus one
        # recorded value that changed. The filter must not let the volume of
        # benign entries carry the substantive one through.
        candidate = plan_fixture()
        candidate["resource_drift"] = [
            _slice_refresh_drift(
                f"module.control.aws_cloudwatch_metric_alarm.a{index}",
                "aws_cloudwatch_metric_alarm",
            )
            for index in range(20)
        ] + [
            _substantive_refresh_drift(
                "module.control.aws_kms_key.authority_data", "aws_kms_key"
            )
        ]
        self.assert_rejected(candidate)

    def test_rejection_diagnostic_names_only_substantive_entries(self) -> None:
        # Filtering happens before the diagnostic, so the operator sees the one
        # entry that actually carries a signal rather than the noise around it.
        candidate = plan_fixture()
        candidate["resource_drift"] = [
            _slice_refresh_drift(
                f"module.control.aws_cloudwatch_metric_alarm.a{index}",
                "aws_cloudwatch_metric_alarm",
            )
            for index in range(20)
        ] + [
            _substantive_refresh_drift(
                "module.control.aws_kms_key.authority_data", "aws_kms_key"
            )
        ]
        with self.assertRaises(CHECKER.ContractError) as error:
            CHECKER.check_plan(candidate)
        decoded = json.loads(
            str(error.exception).split("resource_drift_identity=", 1)[1]
        )
        self.assertEqual(decoded["count"], 1)
        self.assertEqual(
            [identity["address"] for identity in decoded["identities"]],
            ["module.control.aws_kms_key.authority_data"],
        )

    def test_publisher_roles_stay_on_the_strict_path(self) -> None:
        # Their reviewed normalization is BY DEFINITION a first projection
        # (before inline_policy is null or []), so filtering them would make
        # _check_publisher_role_normalization unreachable and drop both the role
        # identity proof and the no-op-plan binding. They must stay strict.
        for address in (
            "module.control.aws_iam_role.authority_publisher",
            "module.control.aws_iam_role.hub_publisher",
        ):
            with self.subTest(address=address):
                entry = self._entry({"inline_policy": []}, {"inline_policy": [{}]})
                entry["address"] = address
                self.assertTrue(CHECKER._drift_is_first_projection_only(entry))
                benign, substantive = CHECKER._partition_first_projection_drift(
                    [entry]
                )
                self.assertEqual(benign, [])
                self.assertEqual(substantive, [entry])

    def test_publisher_role_projection_still_requires_a_noop_plan(self) -> None:
        # The invariant the strict-path exemption exists to preserve: this
        # projection may not ride along with a resource transition.
        normalization, prior_state = publisher_refresh_candidate()
        candidate = redis_split_transition_fixture()
        candidate["resource_drift"] = copy.deepcopy(normalization["resource_drift"])
        self.assert_rejected(candidate, prior_state)

    def test_malformed_unhashable_address_reaches_the_diagnostic(self) -> None:
        # The strict-address membership test must not raise TypeError on an
        # unhashable address before the bounded, value-free diagnostic runs.
        candidate = plan_fixture()
        candidate["resource_drift"] = [
            {
                "address": {"unhashable": True},
                "mode": "managed",
                "type": "aws_iam_role",
                "change": {
                    "actions": ["update"],
                    "before": {"k": "recorded"},
                    "after": {"k": "changed"},
                },
            }
        ]
        with self.assertRaises(CHECKER.ContractError) as error:
            CHECKER.check_plan(candidate)
        self.assertIn("resource_drift_identity=", str(error.exception))

    def test_both_lanes_agree_on_a_substantive_rejection(self) -> None:
        # Lane agreement must hold for rejection too, not just admission.
        refresh = plan_fixture()
        refresh["applyable"] = True
        refresh["resource_drift"] = [
            _substantive_refresh_drift(
                "module.control.aws_kms_key.authority_data", "aws_kms_key"
            )
        ]
        prior_state = terraform_1_14_refresh_only_golden(refresh)
        with self.assertRaises(CHECKER.ContractError):
            CHECKER.check_normalization_drift(refresh, prior_state)
        self.assert_rejected(refresh, prior_state)


class HubWorkerImageUpdateLaneTest(unittest.TestCase):
    """Shipping a reviewed Hub image was not expressible before this lane.

    ECS task definitions are immutable, so the deploy can only ever present as
    delete+create. The allow-list carried a lane for the Authority runtime's
    image update and none for the Hub worker, so the plan was rejected as an
    unreviewed transition -- the same create-time-only shape seen repeatedly.
    """

    HUB_REPO = "767397897469.dkr.ecr.us-east-2.amazonaws.com/layerv/nhp-hub"
    OLD_IMAGE = f"{HUB_REPO}@sha256:{'7' * 64}"
    NEW_IMAGE = f"{HUB_REPO}@sha256:{'c' * 64}"

    def containers(self, image):
        return json.dumps(
            [
                {
                    "name": "hub",
                    "image": image,
                    "cpu": 512,
                    "memory": 1024,
                    "essential": True,
                    "portMappings": [{"containerPort": 62206}],
                },
                {
                    "name": "hub-init",
                    "image": image,
                    "essential": False,
                },
            ]
        )

    def state(self, image, **overrides):
        base = {
            "family": "hub",
            "cpu": "512",
            "memory": "1024",
            "execution_role_arn": "arn:aws:iam::767397897469:role/hub-exec",
            "task_role_arn": "arn:aws:iam::767397897469:role/hub-task",
            "container_definitions": self.containers(image),
            "enable_fault_injection": False,
            "ipc_mode": "",
            "pid_mode": "",
            "volume": [
                {
                    "name": "hub-etc",
                    "configure_at_launch": False,
                    "docker_volume_configuration": [],
                    "efs_volume_configuration": [],
                    "fsx_windows_file_server_volume_configuration": [],
                    "host_path": "",
                    "s3files_volume_configuration": [],
                }
            ],
            "arn": "arn:aws:ecs:us-east-2:767397897469:task-definition/hub:1",
            "arn_without_revision": (
                "arn:aws:ecs:us-east-2:767397897469:task-definition/hub"
            ),
            "id": "hub",
            "revision": 1,
            "tags_all": {},
        }
        base.update(overrides)
        return base

    def by_address(self, before, after, actions=("delete", "create"), unknown=None):
        after = copy.deepcopy(after)
        for key in (
            "arn",
            "arn_without_revision",
            "enable_fault_injection",
            "id",
            "revision",
        ):
            after.pop(key, None)
        after["ipc_mode"] = None
        after["pid_mode"] = None
        after["volume"][0].pop("configure_at_launch")
        return {
            CHECKER.HUB_WORKER_TASK_DEFINITION_ADDRESS: {
                "address": CHECKER.HUB_WORKER_TASK_DEFINITION_ADDRESS,
                "type": "aws_ecs_task_definition",
                "mode": "managed",
                "change": {
                    "actions": list(actions),
                    "replace_paths": [["container_definitions"]],
                    "before": before,
                    "after": after,
                    "after_unknown": {
                        "arn": True,
                        "arn_without_revision": True,
                        "id": True,
                        "revision": True,
                        "enable_fault_injection": True,
                        "volume": [
                            {
                                "configure_at_launch": True,
                                "docker_volume_configuration": [],
                                "efs_volume_configuration": [],
                                "fsx_windows_file_server_volume_configuration": [],
                                "s3files_volume_configuration": [],
                            }
                        ],
                    }
                    if unknown is None
                    else unknown,
                },
            }
        }

    def test_an_image_only_replacement_is_admitted(self) -> None:
        CHECKER._check_hub_worker_image_update(
            self.by_address(self.state(self.OLD_IMAGE), self.state(self.NEW_IMAGE))
        )

    def test_a_replacement_that_moves_no_image_is_rejected(self) -> None:
        with self.assertRaisesRegex(CHECKER.ContractError, "both container images"):
            CHECKER._check_hub_worker_image_update(
                self.by_address(self.state(self.OLD_IMAGE), self.state(self.OLD_IMAGE))
            )

    def test_a_smuggled_task_role_change_is_rejected(self) -> None:
        with self.assertRaisesRegex(CHECKER.ContractError, "task_role_arn"):
            CHECKER._check_hub_worker_image_update(
                self.by_address(
                    self.state(self.OLD_IMAGE),
                    self.state(self.NEW_IMAGE, task_role_arn="arn:aws:iam::1:role/evil"),
                )
            )

    def test_a_smuggled_sizing_change_is_rejected(self) -> None:
        with self.assertRaisesRegex(CHECKER.ContractError, "'cpu'"):
            CHECKER._check_hub_worker_image_update(
                self.by_address(
                    self.state(self.OLD_IMAGE), self.state(self.NEW_IMAGE, cpu="1024")
                )
            )

    def test_a_smuggled_container_field_change_is_rejected(self) -> None:
        """Every non-image key inside the container definition is pinned too."""
        after = self.state(self.NEW_IMAGE)
        containers = json.loads(after["container_definitions"])
        containers[0]["portMappings"] = [{"containerPort": 9999}]
        after["container_definitions"] = json.dumps(containers)
        with self.assertRaisesRegex(CHECKER.ContractError, "portMappings"):
            CHECKER._check_hub_worker_image_update(
                self.by_address(self.state(self.OLD_IMAGE), after)
            )

    def test_only_the_live_provider_container_defaults_are_normalized(self) -> None:
        before = self.state(self.OLD_IMAGE)
        containers = json.loads(before["container_definitions"])
        containers[0].update(
            {"environment": [], "systemControls": [], "volumesFrom": []}
        )
        containers[0]["portMappings"][0]["hostPort"] = 62206
        containers[1].update(
            {"portMappings": [], "systemControls": [], "volumesFrom": []}
        )
        before["container_definitions"] = json.dumps(containers)
        CHECKER._check_hub_worker_image_update(
            self.by_address(before, self.state(self.NEW_IMAGE))
        )

        containers[0]["portMappings"][0]["hostPort"] = 62207
        before["container_definitions"] = json.dumps(containers)
        with self.assertRaisesRegex(CHECKER.ContractError, "key set|portMappings"):
            CHECKER._check_hub_worker_image_update(
                self.by_address(before, self.state(self.NEW_IMAGE))
            )

    def test_a_floating_tag_is_rejected(self) -> None:
        """The lane must not be usable to float the worker onto a mutable ref."""
        with self.assertRaisesRegex(CHECKER.ContractError, "pinned by digest"):
            CHECKER._check_hub_worker_image_update(
                self.by_address(
                    self.state(self.OLD_IMAGE), self.state(f"{self.HUB_REPO}:latest")
                )
            )

    def test_a_foreign_repository_is_rejected(self) -> None:
        foreign = (
            "767397897469.dkr.ecr.us-east-2.amazonaws.com/layerv/evil"
            f"@sha256:{'c' * 64}"
        )
        with self.assertRaisesRegex(CHECKER.ContractError, "pinned by digest"):
            CHECKER._check_hub_worker_image_update(
                self.by_address(self.state(self.OLD_IMAGE), self.state(foreign))
            )

    def test_a_foreign_account_or_region_is_rejected(self) -> None:
        for foreign in (
            self.NEW_IMAGE.replace("767397897469", "000000000000", 1),
            self.NEW_IMAGE.replace("us-east-2", "us-west-2", 1),
        ):
            with self.subTest(foreign=foreign):
                with self.assertRaisesRegex(
                    CHECKER.ContractError, "pinned by digest"
                ):
                    CHECKER._check_hub_worker_image_update(
                        self.by_address(
                            self.state(self.OLD_IMAGE), self.state(foreign)
                        )
                    )

    def test_missing_or_empty_unknown_revision_is_rejected(self) -> None:
        for unknown in ({}, None):
            with self.subTest(unknown=unknown):
                by_address = self.by_address(
                    self.state(self.OLD_IMAGE),
                    self.state(self.NEW_IMAGE),
                    unknown=unknown,
                )
                if unknown is None:
                    del by_address[
                        CHECKER.HUB_WORKER_TASK_DEFINITION_ADDRESS
                    ]["change"]["after_unknown"]
                with self.assertRaisesRegex(
                    CHECKER.ContractError, "defer its computed revision"
                ):
                    CHECKER._check_hub_worker_image_update(by_address)

    def test_reverse_replacement_order_is_rejected(self) -> None:
        with self.assertRaisesRegex(
            CHECKER.ContractError, "destroy-then-create"
        ):
            CHECKER._check_hub_worker_image_update(
                self.by_address(
                    self.state(self.OLD_IMAGE),
                    self.state(self.NEW_IMAGE),
                    actions=("create", "delete"),
                )
            )

    def test_partial_or_divergent_container_roll_is_rejected(self) -> None:
        for mode in ("partial", "divergent"):
            with self.subTest(mode=mode):
                after = self.state(self.NEW_IMAGE)
                containers = json.loads(after["container_definitions"])
                containers[0]["image"] = (
                    self.OLD_IMAGE
                    if mode == "partial"
                    else self.NEW_IMAGE.replace("c" * 64, "d" * 64)
                )
                after["container_definitions"] = json.dumps(containers)
                with self.assertRaisesRegex(
                    CHECKER.ContractError,
                    "both container images|move together",
                ):
                    CHECKER._check_hub_worker_image_update(
                        self.by_address(self.state(self.OLD_IMAGE), after)
                    )

    def test_unreviewed_provider_projection_is_rejected(self) -> None:
        by_address = self.by_address(
            self.state(self.OLD_IMAGE), self.state(self.NEW_IMAGE)
        )
        by_address[CHECKER.HUB_WORKER_TASK_DEFINITION_ADDRESS]["change"][
            "after_unknown"
        ]["task_role_arn"] = True
        with self.assertRaisesRegex(CHECKER.ContractError, "not exact"):
            CHECKER._check_hub_worker_image_update(by_address)

    def test_attribute_or_container_key_set_change_is_rejected(self) -> None:
        after = self.state(self.NEW_IMAGE)
        after["smuggled"] = True
        with self.assertRaisesRegex(CHECKER.ContractError, "attribute set"):
            CHECKER._check_hub_worker_image_update(
                self.by_address(self.state(self.OLD_IMAGE), after)
            )

        after = self.state(self.NEW_IMAGE)
        containers = json.loads(after["container_definitions"])
        containers[0]["smuggled"] = True
        after["container_definitions"] = json.dumps(containers)
        with self.assertRaisesRegex(CHECKER.ContractError, "key set"):
            CHECKER._check_hub_worker_image_update(
                self.by_address(self.state(self.OLD_IMAGE), after)
            )

    def test_non_json_or_empty_containers_are_rejected(self) -> None:
        for raw in ("not-json", "[]"):
            with self.subTest(raw=raw):
                after = self.state(self.NEW_IMAGE)
                after["container_definitions"] = raw
                with self.assertRaises(CHECKER.ContractError):
                    CHECKER._check_hub_worker_image_update(
                        self.by_address(self.state(self.OLD_IMAGE), after)
                    )

    def test_an_in_place_update_is_rejected(self) -> None:
        with self.assertRaisesRegex(CHECKER.ContractError, "task-definition replacement"):
            CHECKER._check_hub_worker_image_update(
                self.by_address(
                    self.state(self.OLD_IMAGE),
                    self.state(self.NEW_IMAGE),
                    actions=("update",),
                )
            )

    def test_a_container_count_change_is_rejected(self) -> None:
        after = self.state(self.NEW_IMAGE)
        containers = json.loads(after["container_definitions"])
        containers.append({"name": "sidecar", "image": self.NEW_IMAGE})
        after["container_definitions"] = json.dumps(containers)
        with self.assertRaisesRegex(CHECKER.ContractError, "containers must remain"):
            CHECKER._check_hub_worker_image_update(
                self.by_address(self.state(self.OLD_IMAGE), after)
            )




class ComposedTransitionTest(unittest.TestCase):
    """Composition must PARTITION the change set, never widen it.

    Every transition in the dispatch matches `changed == <its exact set>`. That
    is right for one transition and wrong the moment two legitimately land in
    one plan -- enabling attended proof while a reviewed Hub image deploy is
    pending -- which rejects a plan whose halves are each already admitted.

    These pin the ALGEBRA against a synthetic registry, so they keep testing the
    partitioning rules no matter which lanes are registered; the real lanes keep
    their own validators and tests.
    """

    A, B, C = "addr.a", "addr.b", "addr.c"
    SHARED = "module.control.terraform_data.foundation_contract"

    def registry(self, *, a_raises=None, claim_shared=False):
        def claim_a(changed, actual, by_address):
            want = {self.A} | ({self.SHARED} if claim_shared else set())
            return frozenset(want) if want <= changed else None

        def claim_b(changed, actual, by_address):
            want = {self.B} | ({self.SHARED} if claim_shared else set())
            return frozenset(want) if want <= changed else None

        def validate_a(claimed, by_address, plan):
            if a_raises:
                raise CHECKER.ContractError(a_raises)

        def validate_b(claimed, by_address, plan):
            return None

        return (("lane-a", claim_a, validate_a), ("lane-b", claim_b, validate_b))

    def compose(self, changed, deposed=None, **kw):
        by = {a: {"change": {"actions": ["update"]}} for a in changed}
        with mock.patch.object(CHECKER, "_COMPOSABLE_TRANSITIONS", self.registry(**kw)):
            return CHECKER._compose_admitted_transitions(
                set(changed), {}, by, deposed or {}, {}
            )

    def test_two_reviewed_transitions_compose(self) -> None:
        mode = self.compose({self.A, self.B})
        self.assertEqual(mode, "composed-lane-a-with-lane-b")

    def test_a_single_transition_does_not_compose(self) -> None:
        """One claim must fall through to the stricter dispatch above."""
        self.assertIsNone(self.compose({self.A}))

    def test_an_unclaimed_address_refuses_composition(self) -> None:
        """One stray change and the whole plan falls through to rejection."""
        self.assertIsNone(self.compose({self.A, self.B, self.C}))

    def test_deposed_objects_never_compose(self) -> None:
        self.assertIsNone(
            self.compose({self.A, self.B}, deposed={"x": {"actions": ["delete"]}})
        )

    def test_each_slice_still_runs_its_own_validator(self) -> None:
        with self.assertRaisesRegex(CHECKER.ContractError, "slice rejected"):
            self.compose({self.A, self.B}, a_raises="slice rejected")

    def test_overlapping_claims_refuse(self) -> None:
        """Two lanes claiming one ordinary address is ambiguous ownership."""

        def claim_both(changed, actual, by_address):
            return frozenset({self.A, self.B})

        registry = (
            ("lane-a", claim_both, lambda c, b, p: None),
            ("lane-b", claim_both, lambda c, b, p: None),
        )
        by = {a: {"change": {"actions": ["update"]}} for a in (self.A, self.B)}
        with mock.patch.object(CHECKER, "_COMPOSABLE_TRANSITIONS", registry):
            self.assertIsNone(
                CHECKER._compose_admitted_transitions(
                    {self.A, self.B}, {}, by, {}, {}
                )
            )

    def test_the_foundation_contract_may_be_shared(self) -> None:
        """Every config-changing transition updates it by construction.

        Requiring it to belong to exactly one claim would make any two
        config-changing transitions permanently uncomposable.
        """
        mode = self.compose({self.A, self.B, self.SHARED}, claim_shared=True)
        self.assertEqual(mode, "composed-lane-a-with-lane-b")

    def test_only_the_allowlisted_address_may_be_shared(self) -> None:
        self.assertEqual(
            CHECKER._COMPOSABLE_SHARED_ADDRESSES,
            frozenset({"module.control.terraform_data.foundation_contract"}),
        )

    def image_roll_fixture(self) -> dict:
        """The live sandbox Authority image roll, reduced to its shape."""
        target = (
            "767397897469.dkr.ecr.us-east-2.amazonaws.com/"
            "layerv/qurl-connector-authority@sha256:" + "a" * 64
        )
        by = {}
        for fn in ("layerv-nhp-sandbox-ca-ia", "layerv-nhp-sandbox-ca-ra"):
            by[f'module.control.aws_lambda_function.authority["{fn}"]'] = {
                "change": {"actions": ["update"], "after": {"image_uri": target}}
            }
            by[f'module.control.aws_lambda_alias.authority["{fn}:green"]'] = {
                "change": {"actions": ["update"], "after": {}}
            }
        by[CHECKER.AUTHORITY_IMAGE_UPDATE_FOUNDATION_ADDRESS] = {
            "change": {
                "actions": ["update"],
                "after": {"input": {"authority_image_uri": target}},
            }
        }
        return by

    @staticmethod
    def transaction_action_correction_fixture() -> dict:
        """The closed two-role-plus-endpoint policy correction."""
        role_statement = {
            "Action": [
                "dynamodb:GetItem",
                "dynamodb:TransactWriteItems",
                "dynamodb:UpdateItem",
            ],
            "Effect": "Allow",
            "Resource": ["arn:aws:dynamodb:us-east-2:767397897469:table/resources"],
            "Sid": "ConnectorResourceCellResourceData",
        }
        endpoint_statement = {
            "Action": [
                "dynamodb:GetItem",
                "dynamodb:PutItem",
                "dynamodb:TransactWriteItems",
                "dynamodb:UpdateItem",
            ],
            "Effect": "Allow",
            "Principal": "*",
            "Resource": ["arn:aws:dynamodb:us-east-2:767397897469:table/resources"],
            "Sid": "ConnectorResourceCellData",
        }
        fixture = {}
        for address in sorted(
            CHECKER.AUTHORITY_DYNAMODB_TRANSACTION_ACTION_CORRECTION_ADDRESSES
        ):
            statement = (
                endpoint_statement
                if address == "module.control.aws_vpc_endpoint.dynamodb"
                else role_statement
            )
            before = {
                "id": address,
                "policy": json.dumps(
                    {"Statement": [statement], "Version": "2012-10-17"},
                    separators=(",", ":"),
                ),
            }
            expected_policy = CHECKER._dynamodb_transaction_action_correction_after(
                before, address
            )
            after = copy.deepcopy(before)
            after["policy"] = json.dumps(expected_policy, separators=(",", ":"))
            fixture[address] = {
                "change": {
                    "actions": ["update"],
                    "before": before,
                    "after": after,
                }
            }
        return fixture

    def test_transaction_action_correction_claims_and_validates_all_policies(self) -> None:
        by = self.transaction_action_correction_fixture()
        changed = set(by)
        actions = {address: ["update"] for address in changed}
        claimed = CHECKER._claim_dynamodb_transaction_action_correction(
            changed, actions, by
        )
        self.assertEqual(set(claimed), changed)
        CHECKER._validate_dynamodb_transaction_action_correction(claimed, by, {})

    def test_transaction_action_correction_admits_partial_apply_retry(self) -> None:
        by = self.transaction_action_correction_fixture()
        address = next(iter(by))
        claimed = CHECKER._claim_dynamodb_transaction_action_correction(
            {address}, {address: ["update"]}, by
        )
        self.assertEqual(claimed, frozenset({address}))

    def test_transaction_action_correction_refuses_a_second_policy_change(self) -> None:
        by = self.transaction_action_correction_fixture()
        address = next(
            item
            for item in by
            if item != "module.control.aws_vpc_endpoint.dynamodb"
        )
        after_policy = json.loads(by[address]["change"]["after"]["policy"])
        after_policy["Statement"][0]["Resource"].append("arn:aws:dynamodb:::table/extra")
        by[address]["change"]["after"]["policy"] = json.dumps(after_policy)
        changed = set(by)
        actions = {item: ["update"] for item in changed}
        self.assertEqual(
            CHECKER._claim_dynamodb_transaction_action_correction(
                changed, actions, by
            ),
            frozenset(),
        )

    def test_transaction_action_correction_refuses_non_update_shape(self) -> None:
        by = self.transaction_action_correction_fixture()
        address = next(iter(by))
        by[address]["change"]["actions"] = ["delete", "create"]
        actions = {item: by[item]["change"]["actions"] for item in by}
        self.assertEqual(
            CHECKER._claim_dynamodb_transaction_action_correction(
                set(by), actions, by
            ),
            frozenset(),
        )

    def test_transaction_action_correction_composes_with_image_roll(self) -> None:
        by = self.image_roll_fixture()
        by.update(self.transaction_action_correction_fixture())
        changed = set(by)
        actions = {address: by[address]["change"]["actions"] for address in changed}
        self.assertEqual(
            CHECKER._compose_admitted_transitions(changed, actions, by, {}, {}),
            "composed-authority-image-roll-with-dynamodb-transaction-action-correction",
        )

    def test_image_roll_claims_functions_aliases_and_contract(self) -> None:
        by = self.image_roll_fixture()
        changed = set(by)
        actions = {a: by[a]["change"]["actions"] for a in changed}
        claimed = CHECKER._claim_authority_image_roll(changed, actions, by)
        self.assertEqual(set(claimed), changed)
        CHECKER._validate_authority_image_roll(claimed, by, {})

    def test_image_roll_refuses_a_split_fleet(self) -> None:
        """A function left on a stale digest is the real hazard."""
        by = self.image_roll_fixture()
        by['module.control.aws_lambda_function.authority["layerv-nhp-sandbox-ca-ra"]'][
            "change"
        ]["after"]["image_uri"] = "stale"
        changed = set(by)
        actions = {a: by[a]["change"]["actions"] for a in changed}
        self.assertEqual(
            CHECKER._claim_authority_image_roll(changed, actions, by), frozenset()
        )

    def test_image_roll_refuses_a_no_op_function_on_a_stale_digest(self) -> None:
        """Convergence is checked across every function, not just changed ones."""
        by = self.image_roll_fixture()
        by['module.control.aws_lambda_function.authority["layerv-nhp-sandbox-ca-pm"]'] = {
            "change": {"actions": ["no-op"], "after": {"image_uri": "stale"}}
        }
        changed = {a for a in by if by[a]["change"]["actions"] != ["no-op"]}
        actions = {a: by[a]["change"]["actions"] for a in changed}
        self.assertEqual(
            CHECKER._claim_authority_image_roll(changed, actions, by), frozenset()
        )

    def test_image_roll_is_update_only(self) -> None:
        by = self.image_roll_fixture()
        by['module.control.aws_lambda_alias.authority["layerv-nhp-sandbox-ca-ia:green"]'][
            "change"
        ]["actions"] = ["delete"]
        changed = set(by)
        actions = {a: by[a]["change"]["actions"] for a in changed}
        self.assertEqual(
            CHECKER._claim_authority_image_roll(changed, actions, by), frozenset()
        )

    def test_image_roll_requires_a_contract_bound_digest(self) -> None:
        by = self.image_roll_fixture()
        del by[CHECKER.AUTHORITY_IMAGE_UPDATE_FOUNDATION_ADDRESS]
        changed = set(by)
        actions = {a: by[a]["change"]["actions"] for a in changed}
        self.assertEqual(
            CHECKER._claim_authority_image_roll(changed, actions, by), frozenset()
        )

    def test_plan_resource_changes_keeps_no_op_entries(self) -> None:
        """by_address must see no-op resources, or the split-fleet check is blind.

        _claim/_validate_authority_image_roll prove convergence by walking every
        Authority function in by_address, including ones planned no-op. That is
        the whole point: a function stranded on the previous digest is the
        hazard. by_address is built from _plan_resource_changes, so if that ever
        started filtering no-ops the stranded function would simply be absent
        and the split fleet would be ADMITTED. Pinned here against the real
        function rather than a synthetic map, because a hand-built fixture
        passes regardless of what the production path does.
        """
        plan = {
            "resource_changes": [
                {"address": "quiet", "change": {"actions": ["no-op"]}},
                {"address": "moving", "change": {"actions": ["update"]}},
            ]
        }
        changes = CHECKER._plan_resource_changes(plan, [], None)
        self.assertEqual(
            {item["address"] for item in changes}, {"quiet", "moving"}
        )

    def test_image_roll_validator_requires_a_contract_bound_digest(self) -> None:
        by = self.image_roll_fixture()
        claimed = frozenset(by)
        del by[CHECKER.AUTHORITY_IMAGE_UPDATE_FOUNDATION_ADDRESS]
        with self.assertRaises(CHECKER.ContractError):
            CHECKER._validate_authority_image_roll(claimed, by, {})

    def test_image_roll_validator_refuses_a_non_convergent_function(self) -> None:
        by = self.image_roll_fixture()
        by['module.control.aws_lambda_function.authority["layerv-nhp-sandbox-ca-ra"]'][
            "change"
        ]["after"]["image_uri"] = "stale"
        with self.assertRaises(CHECKER.ContractError):
            CHECKER._validate_authority_image_roll(frozenset(by), by, {})

    def test_image_roll_validator_refuses_a_stale_no_op_function(self) -> None:
        by = self.image_roll_fixture()
        claimed = frozenset(by)
        by['module.control.aws_lambda_function.authority["layerv-nhp-sandbox-ca-pm"]'] = {
            "change": {"actions": ["no-op"], "after": {"image_uri": "stale"}}
        }
        with self.assertRaises(CHECKER.ContractError):
            CHECKER._validate_authority_image_roll(claimed, by, {})

    def test_image_roll_validator_refuses_malformed_planned_values(self) -> None:
        by = self.image_roll_fixture()
        by['module.control.aws_lambda_function.authority["layerv-nhp-sandbox-ca-ra"]'][
            "change"
        ]["after"] = None
        with self.assertRaises(CHECKER.ContractError):
            CHECKER._validate_authority_image_roll(frozenset(by), by, {})

    def test_image_roll_validator_is_update_only(self) -> None:
        by = self.image_roll_fixture()
        by['module.control.aws_lambda_alias.authority["layerv-nhp-sandbox-ca-ia:green"]'][
            "change"
        ]["actions"] = ["delete"]
        with self.assertRaises(CHECKER.ContractError):
            CHECKER._validate_authority_image_roll(frozenset(by), by, {})

    def test_image_roll_validator_refuses_an_alias_with_no_owner(self) -> None:
        by = self.image_roll_fixture()
        orphan = 'module.control.aws_lambda_alias.authority["layerv-nhp-sandbox-ca-ghost:green"]'
        by[orphan] = {"change": {"actions": ["update"], "after": {}}}
        with self.assertRaises(CHECKER.ContractError):
            CHECKER._validate_authority_image_roll(frozenset(by), by, {})

    def test_image_roll_validator_requires_at_least_one_function(self) -> None:
        by = self.image_roll_fixture()
        aliases = frozenset(
            a
            for a in by
            if a.startswith(CHECKER.AUTHORITY_ALIAS_ADDRESS_PREFIX)
        )
        with self.assertRaises(CHECKER.ContractError):
            CHECKER._validate_authority_image_roll(aliases, by, {})

    def test_plan_mode_parts_splits_a_composed_mode(self) -> None:
        self.assertEqual(
            CHECKER._plan_mode_parts("composed-authority-image-roll-with-hub-worker-image-update"),
            {"authority-image-roll", "hub-worker-image-update"},
        )

    def test_plan_mode_parts_passes_an_atomic_mode_through(self) -> None:
        for mode in ("no-op", "authority-image-roll", "authority-proof-disable"):
            with self.subTest(mode=mode):
                self.assertEqual(CHECKER._plan_mode_parts(mode), {mode})

    def test_plan_mode_parts_round_trips_the_composer_rendering(self) -> None:
        """The parser and the renderer must agree on the separator."""
        names = sorted({name for name, _, _ in CHECKER._COMPOSABLE_TRANSITIONS})[:3]
        rendered = CHECKER._COMPOSED_PLAN_MODE_PREFIX + (
            CHECKER._COMPOSED_PLAN_MODE_SEPARATOR.join(names)
        )
        self.assertEqual(CHECKER._plan_mode_parts(rendered), set(names))

    def test_the_deploy_gate_refuses_the_real_rollout_plan_modes(self) -> None:
        """Bind build-and-push.yml's refusal literals to the producer vocabulary.

        The unattended deploy gate refuses a proof rollout apply by matching
        plan_mode strings out of plan-contract-summary.json. Its safety is
        entirely in those literals: if the checker ever renames a rollout mode,
        or joins composed modes with a different token, the `case` arms stop
        matching, the loop falls through, and the step prints "Not a proof
        rollout apply ... proceeding." The fail-CLOSED refusal silently becomes
        fail-OPEN, which is the one outcome that step exists to prevent.

        That is the same producer/consumer drift the retired CONTROL_* `env`
        publisher had, so it gets the same treatment: assert the equality across
        the seam rather than pinning either side alone.
        """
        workflow = (
            ROOT / ".github" / "workflows" / "build-and-push.yml"
        ).read_text(encoding="utf-8")
        checker = (
            ROOT / ".github" / "scripts" / "check-control-sandbox-first-apply.py"
        ).read_text(encoding="utf-8")

        refused = ("authority-proof-rollout-selector", "authority-proof-rollout-prepare")
        for mode in refused:
            with self.subTest(mode=mode):
                # The consumer still names it...
                self.assertIn(mode, workflow, f"{mode} is not refused by the deploy gate")
                # ...and the producer can still emit it.
                self.assertIn(
                    f'plan_mode = "{mode}"',
                    checker,
                    f"{mode} is refused by the deploy gate but no longer produced",
                )

        # The composed-mode split must agree with how the composer renders.
        self.assertIn(
            f'parts="${{mode#{CHECKER._COMPOSED_PLAN_MODE_PREFIX}}}"',
            workflow,
            "the deploy gate strips a different composed prefix than the composer writes",
        )
        self.assertIn(
            f'parts="${{parts//{CHECKER._COMPOSED_PLAN_MODE_SEPARATOR}/ }}"',
            workflow,
            "the deploy gate splits on a different separator than the composer writes",
        )

    def test_no_registered_lane_name_contains_the_composition_separator(self) -> None:
        """_plan_mode_parts splits on "-with-", so no lane name may contain it.

        A lane named with the separator inside it would be mis-split into
        phantom parts, and a phantom part could collide with an allowlisted
        name -- silently granting an allowance nobody reviewed.
        """
        for name, _, _ in CHECKER._COMPOSABLE_TRANSITIONS:
            with self.subTest(lane=name):
                self.assertNotIn(CHECKER._COMPOSED_PLAN_MODE_SEPARATOR, name)
                # The prefix strip is the other half of the parse: a lane named
                # "composed-..." would have its own name mangled into parts.
                self.assertFalse(
                    name.startswith(CHECKER._COMPOSED_PLAN_MODE_PREFIX)
                )

    def retirement_fixture(self) -> dict:
        """Closing the rollout window, reduced to its shape."""
        pool = (
            CHECKER.AUTHORITY_PROOF_STANDBY_PREFIX
            + '"layerv-nhp-sandbox-ca-ia"]'
        )
        return {
            CHECKER.AUTHORITY_IMAGE_UPDATE_FOUNDATION_ADDRESS: {
                "change": {
                    "actions": ["update"],
                    "before": {
                        "input": {
                            "authority_proof_policy_selected_color": "green",
                            "authority_proof_policy_prepared_color": "green",
                        }
                    },
                    "after": {
                        "input": {
                            "authority_proof_policy_selected_color": None,
                            "authority_proof_policy_prepared_color": None,
                        }
                    },
                }
            },
            pool: {"change": {"actions": ["delete"]}},
            CHECKER.AUTHORITY_PROOF_RETIREMENT_TASK_DEFINITION: {
                "change": {
                    "actions": ["delete", "create"],
                    # Identical but for the alias colour, and carrying a
                    # provider-normalised empty on one side only -- both of
                    # which the content proof must see through.
                    "before": {
                        "container_definitions": json.dumps(
                            [
                                {
                                    "name": "hub-init",
                                    "environment": [
                                        {
                                            "name": "NHP_HUB_PUBLIC_CONFIG_JSON",
                                            "value": json.dumps(
                                                {
                                                    "issue_assignment_alias_arn": (
                                                        "arn:aws:lambda:us-east-2:"
                                                        "767397897469:function:"
                                                        "layerv-nhp-sandbox-ca-ia:green"
                                                    )
                                                }
                                            ),
                                        }
                                    ],
                                    "portMappings": [],
                                }
                            ]
                        )
                    },
                    "after": {
                        "container_definitions": json.dumps(
                            [
                                {
                                    "name": "hub-init",
                                    "environment": [
                                        {
                                            "name": "NHP_HUB_PUBLIC_CONFIG_JSON",
                                            "value": json.dumps(
                                                {
                                                    "issue_assignment_alias_arn": (
                                                        "arn:aws:lambda:us-east-2:"
                                                        "767397897469:function:"
                                                        "layerv-nhp-sandbox-ca-ia:blue"
                                                    )
                                                }
                                            ),
                                        }
                                    ],
                                }
                            ]
                        )
                    },
                }
            },
        }

    def test_retirement_claims_pools_contract_and_task_definition(self) -> None:
        by = self.retirement_fixture()
        changed = set(by)
        actions = {a: by[a]["change"]["actions"] for a in changed}
        claimed = CHECKER._claim_authority_proof_rollout_retirement(changed, actions, by)
        self.assertEqual(set(claimed), changed)
        CHECKER._validate_authority_proof_rollout_retirement(claimed, by, {})

    def test_retirement_requires_the_window_to_close(self) -> None:
        """Colours must go set -> null; anything else is not a retirement."""
        by = self.retirement_fixture()
        by[CHECKER.AUTHORITY_IMAGE_UPDATE_FOUNDATION_ADDRESS]["change"]["after"][
            "input"
        ]["authority_proof_policy_selected_color"] = "green"
        changed = set(by)
        actions = {a: by[a]["change"]["actions"] for a in changed}
        self.assertEqual(
            CHECKER._claim_authority_proof_rollout_retirement(changed, actions, by),
            frozenset(),
        )

    def test_retirement_defers_alias_moves_to_the_image_roll(self) -> None:
        """Alias/function movement is authority-image-roll's to prove.

        Claiming it in both would overlap, and overlapping claims fail
        composition's disjointness -- so this lane stands down entirely when an
        alias moves without a roll to own it.
        """
        by = self.retirement_fixture()
        by[
            CHECKER.AUTHORITY_ALIAS_ADDRESS_PREFIX + 'layerv-nhp-sandbox-ca-ia:green"]'
        ] = {"change": {"actions": ["update"]}}
        changed = set(by)
        actions = {a: by[a]["change"]["actions"] for a in changed}
        self.assertEqual(
            CHECKER._claim_authority_proof_rollout_retirement(changed, actions, by),
            frozenset(),
        )

    def test_retirement_requires_plain_pool_deletes(self) -> None:
        by = self.retirement_fixture()
        pool = CHECKER.AUTHORITY_PROOF_STANDBY_PREFIX + '"layerv-nhp-sandbox-ca-ia"]'
        by[pool]["change"]["actions"] = ["delete", "create"]
        changed = set(by)
        actions = {a: by[a]["change"]["actions"] for a in changed}
        self.assertEqual(
            CHECKER._claim_authority_proof_rollout_retirement(changed, actions, by),
            frozenset(),
        )

    def test_retirement_refuses_a_non_colour_hub_delta(self) -> None:
        """Admitting a bare "hub-init environment changed" would be the widening
        this lane exists to avoid, so any delta beyond the alias colour fails.
        """
        by = self.retirement_fixture()
        change = by[CHECKER.AUTHORITY_PROOF_RETIREMENT_TASK_DEFINITION]["change"]
        containers = json.loads(change["after"]["container_definitions"])
        containers[0]["environment"].append({"name": "SNUCK_IN", "value": "1"})
        change["after"]["container_definitions"] = json.dumps(containers)
        with self.assertRaises(CHECKER.ContractError):
            CHECKER._validate_authority_proof_rollout_retirement(
                frozenset(by), by, {}
            )

    def test_retirement_composes_with_an_image_roll(self) -> None:
        """The shape this lane is actually built for.

        Main publishes a new Authority image on merge, so a roll rides along
        with the retirement rather than the retirement landing alone. The whole
        disjointness design -- ceding functions/aliases to authority-image-roll,
        sharing foundation_contract, standing down when an alias moves with no
        roll to own it -- exists for this path, so assert it directly instead of
        inferring it from the standalone case.
        """
        roll = self.image_roll_fixture()
        by = self.retirement_fixture()
        target = roll[CHECKER.AUTHORITY_IMAGE_UPDATE_FOUNDATION_ADDRESS]["change"][
            "after"
        ]["input"]["authority_image_uri"]
        by.update(
            {a: v for a, v in roll.items()
             if a != CHECKER.AUTHORITY_IMAGE_UPDATE_FOUNDATION_ADDRESS}
        )
        # One contract entry carrying BOTH halves: the image the fleet converges
        # on, and the colour transition that closes the window.
        by[CHECKER.AUTHORITY_IMAGE_UPDATE_FOUNDATION_ADDRESS] = {
            "change": {
                "actions": ["update"],
                "before": {
                    "input": {
                        "authority_image_uri": target,
                        "authority_proof_policy_selected_color": "green",
                        "authority_proof_policy_prepared_color": "green",
                    }
                },
                "after": {
                    "input": {
                        "authority_image_uri": target,
                        "authority_proof_policy_selected_color": None,
                        "authority_proof_policy_prepared_color": None,
                    }
                },
            }
        }
        changed = {a for a in by if by[a]["change"]["actions"] != ["no-op"]}
        actions = {a: by[a]["change"]["actions"] for a in changed}

        retirement = CHECKER._claim_authority_proof_rollout_retirement(
            changed, actions, by
        )
        roll_claim = CHECKER._claim_authority_image_roll(changed, actions, by)
        self.assertTrue(retirement, "retirement must claim alongside a roll")
        self.assertTrue(roll_claim, "the roll must still claim its own addresses")

        # Disjoint except for the deliberately shared contract address, and
        # between them they must account for every changed address.
        overlap = set(retirement) & set(roll_claim)
        self.assertEqual(overlap - CHECKER._COMPOSABLE_SHARED_ADDRESSES, set())
        self.assertEqual(set(retirement) | set(roll_claim), changed)

    def test_image_roll_claims_the_shared_contract_address(self) -> None:
        """Both lanes claim foundation_contract; that is why it is shared.

        If it ever stopped being in _COMPOSABLE_SHARED_ADDRESSES, the overlap
        would fail composition's disjointness and the retirement-plus-roll plan
        would be rejected -- the normal merge shape. Pin the dependency.
        """
        by = self.image_roll_fixture()
        changed = set(by)
        actions = {a: by[a]["change"]["actions"] for a in changed}
        claimed = CHECKER._claim_authority_image_roll(changed, actions, by)
        self.assertIn(CHECKER.AUTHORITY_IMAGE_UPDATE_FOUNDATION_ADDRESS, claimed)
        self.assertIn(
            CHECKER.AUTHORITY_IMAGE_UPDATE_FOUNDATION_ADDRESS,
            CHECKER._COMPOSABLE_SHARED_ADDRESSES,
        )

    def test_opening_the_window_is_not_a_selector_transition(self) -> None:
        """null -> set is opening, and must not match the transition predicate.

        The same predicate gates the stand-downs in hub-worker-image-update and
        authority-image-uri-move, so a false match there would silently disarm
        two unrelated lanes during a window-opening plan.
        """
        by = self.retirement_fixture()
        contract = by[CHECKER.AUTHORITY_IMAGE_UPDATE_FOUNDATION_ADDRESS]["change"]
        contract["before"]["input"]["authority_proof_policy_selected_color"] = None
        contract["before"]["input"]["authority_proof_policy_prepared_color"] = None
        contract["after"]["input"]["authority_proof_policy_selected_color"] = "green"
        contract["after"]["input"]["authority_proof_policy_prepared_color"] = "green"
        self.assertFalse(
            CHECKER._authority_proof_retirement_closes_the_window(by)
        )

    def alias_refresh_drift(self, planned: str = "no-op") -> tuple[list, dict]:
        address = (
            'module.control.aws_lambda_alias.authority["layerv-nhp-sandbox-ca-ia:blue"]'
        )
        drift = [{"address": address, "change": {"actions": ["update"]}}]
        by = {address: {"change": {"actions": [planned]}}}
        return drift, by

    def test_absorbed_alias_refresh_drift_is_a_reviewed_kind(self) -> None:
        """A failed apply's partial success reconciles as pure state catch-up."""
        drift, by = self.alias_refresh_drift()
        self.assertEqual(
            CHECKER._check_state_normalization_drift(drift, by, refresh_only=False),
            "authority-alias-refresh",
        )

    def test_alias_refresh_drift_with_a_pending_change_is_not_catch_up(self) -> None:
        """The no-op requirement is the confinement.

        A drifted alias with a pending change must NOT classify as the
        catch-up kind -- it falls through to the slice-normalization kind,
        whose downstream gate binds it to reviewed slice transitions (and the
        terminal rejection otherwise, as the end-to-end negative proves).
        """
        drift, by = self.alias_refresh_drift(planned="update")
        self.assertNotEqual(
            CHECKER._check_state_normalization_drift(drift, by, refresh_only=False),
            "authority-alias-refresh",
        )

    def test_function_drift_is_also_catch_up(self) -> None:
        address = (
            'module.control.aws_lambda_function.authority["layerv-nhp-sandbox-ca-pm"]'
        )
        drift = [{"address": address, "change": {"actions": ["update"]}}]
        by = {address: {"change": {"actions": ["no-op"]}}}
        self.assertEqual(
            CHECKER._check_state_normalization_drift(drift, by, refresh_only=False),
            "authority-alias-refresh",
        )

    def test_mixed_drift_with_a_foreign_address_is_not_catch_up(self) -> None:
        """One non-Authority address in the set defeats the whole kind."""
        drift, by = self.alias_refresh_drift()
        foreign = "module.control.aws_vpc.control"
        drift.append({"address": foreign, "change": {"actions": ["update"]}})
        by[foreign] = {"change": {"actions": ["no-op"]}}
        with self.assertRaises(CHECKER.ContractError):
            CHECKER._check_state_normalization_drift(drift, by, refresh_only=False)

    def test_switch_pointer_reads_the_contract(self) -> None:
        for color in ("blue", "green"):
            with self.subTest(color=color):
                self.assertEqual(
                    CHECKER._selected_authority_color_from_contract(
                        {"authority_runtime_contract": {"selected_authority_color": color}}
                    ),
                    color,
                )

    def test_switch_pointer_defaults_blue_only_without_a_contract(self) -> None:
        for payload in (None, {}, {"authority_runtime_contract": None}):
            with self.subTest(payload=payload):
                self.assertEqual(
                    CHECKER._selected_authority_color_from_contract(payload), "blue"
                )

    def test_switch_pointer_raises_on_a_contract_missing_the_colour(self) -> None:
        """Schema drift must surface as itself, not as a phantom blue."""
        for contract in ({}, {"selected_authority_color": "purple"}):
            with self.subTest(contract=contract):
                with self.assertRaises(CHECKER.ContractError):
                    CHECKER._selected_authority_color_from_contract(
                        {"authority_runtime_contract": contract}
                    )

    def test_blue_green_hold_data_slice_membership(self) -> None:
        """26 reads: 15 functions minus two creso bootstraps, x both colours."""
        slice_ = CHECKER.AUTHORITY_BLUE_GREEN_LIVE_ALIAS_DATA_RESOURCES
        self.assertEqual(len(slice_), 26)
        self.assertEqual(
            len(CHECKER.AUTHORITY_RUNTIME_FUNCTIONS_WITH_PROOF), 15
        )
        for fn in CHECKER.AUTHORITY_RUNTIME_FUNCTIONS_WITH_PROOF:
            for color in ("blue", "green"):
                address = (
                    "module.control.data.aws_lambda_alias."
                    f'authority_live["{fn}:{color}"]'
                )
                if fn in CHECKER.AUTHORITY_ALIAS_HOLD_BOOTSTRAP_FUNCTIONS:
                    self.assertNotIn(address, slice_)
                else:
                    self.assertIn(address, slice_)

    def rehome_fixture(self) -> dict:
        """A window-close carrying one steady-PC re-home blue -> green."""
        by = self.retirement_fixture()
        contract = by[CHECKER.AUTHORITY_IMAGE_UPDATE_FOUNDATION_ADDRESS]["change"]
        contract["before"]["input"]["authority_runtime_contract"] = {
            "selected_authority_color": "blue"
        }
        contract["after"]["input"]["authority_runtime_contract"] = {
            "selected_authority_color": "green"
        }
        by[
            CHECKER.AUTHORITY_STEADY_PC_PREFIX + '"layerv-nhp-sandbox-ca-ia"]'
        ] = {
            "change": {
                "actions": ["delete", "create"],
                "before": {"qualifier": "blue", "provisioned_concurrent_executions": 2},
                "after": {"qualifier": "green", "provisioned_concurrent_executions": 2},
            }
        }
        return by

    def test_rehome_rides_the_window_close(self) -> None:
        by = self.rehome_fixture()
        changed = set(by)
        actions = {a: by[a]["change"]["actions"] for a in changed}
        claimed = CHECKER._claim_authority_proof_rollout_retirement(changed, actions, by)
        self.assertEqual(set(claimed), changed)
        CHECKER._validate_authority_proof_rollout_retirement(claimed, by, {})

    def test_rehome_must_follow_the_selector_direction(self) -> None:
        """green -> blue while the selector moves blue -> green is refused."""
        by = self.rehome_fixture()
        pc = by[CHECKER.AUTHORITY_STEADY_PC_PREFIX + '"layerv-nhp-sandbox-ca-ia"]']
        pc["change"]["before"]["qualifier"] = "green"
        pc["change"]["after"]["qualifier"] = "blue"
        with self.assertRaises(CHECKER.ContractError):
            CHECKER._validate_authority_proof_rollout_retirement(
                frozenset(by), by, {}
            )

    def test_rehome_must_keep_its_allocation(self) -> None:
        by = self.rehome_fixture()
        by[CHECKER.AUTHORITY_STEADY_PC_PREFIX + '"layerv-nhp-sandbox-ca-ia"]'][
            "change"
        ]["after"]["provisioned_concurrent_executions"] = 99
        with self.assertRaises(CHECKER.ContractError):
            CHECKER._validate_authority_proof_rollout_retirement(
                frozenset(by), by, {}
            )

    def test_rehome_is_delete_before_create_only(self) -> None:
        """Parity with the shell fence is exact, not incidental."""
        by = self.rehome_fixture()
        pc_addr = CHECKER.AUTHORITY_STEADY_PC_PREFIX + '"layerv-nhp-sandbox-ca-ia"]'
        by[pc_addr]["change"]["actions"] = ["create", "delete"]
        changed = set(by)
        actions = {a: by[a]["change"]["actions"] for a in changed}
        self.assertEqual(
            CHECKER._claim_authority_proof_rollout_retirement(changed, actions, by),
            frozenset(),
        )

    def steady_pc_completion_by(self, qualifier="green", alloc=1, fn="ca-pm"):
        return {
            CHECKER.AUTHORITY_IMAGE_UPDATE_FOUNDATION_ADDRESS: {
                "change": {
                    "actions": ["no-op"],
                    "after": {
                        "input": {
                            "authority_runtime_contract": {
                                "selected_authority_color": "green"
                            }
                        }
                    },
                }
            },
            CHECKER.AUTHORITY_STEADY_PC_PREFIX
            + f'"layerv-nhp-sandbox-{fn}"]': {
                "change": {
                    "actions": ["create"],
                    "before": None,
                    "after": {
                        "qualifier": qualifier,
                        "provisioned_concurrent_executions": alloc,
                    },
                }
            },
        }

    def test_steady_pc_completion_admits_the_selected_colour(self) -> None:
        """The real validator runs: pm at 1 on green, a runtime fn at 2."""
        for fn, alloc in (("ca-pm", 1), ("ca-ar-cell0", 2)):
            with self.subTest(fn=fn):
                by = self.steady_pc_completion_by(alloc=alloc, fn=fn)
                changed = {
                    a for a, v in by.items()
                    if v["change"]["actions"] != ["no-op"]
                }
                CHECKER._check_authority_steady_pc_completion(changed, by)

    def test_steady_pc_completion_refuses_the_standby_colour(self) -> None:
        by = self.steady_pc_completion_by(qualifier="blue")
        changed = {a for a, v in by.items() if v["change"]["actions"] != ["no-op"]}
        with self.assertRaises(CHECKER.ContractError):
            CHECKER._check_authority_steady_pc_completion(changed, by)

    def test_steady_pc_completion_pins_the_exact_allocation(self) -> None:
        """0/2/3 for pm and 1/3 for a runtime fn are all refused."""
        for fn, bad in (("ca-pm", 0), ("ca-pm", 2), ("ca-pm", 3),
                        ("ca-ar-cell0", 1), ("ca-ar-cell0", 3)):
            with self.subTest(fn=fn, alloc=bad):
                by = self.steady_pc_completion_by(alloc=bad, fn=fn)
                changed = {
                    a for a, v in by.items()
                    if v["change"]["actions"] != ["no-op"]
                }
                with self.assertRaises(CHECKER.ContractError):
                    CHECKER._check_authority_steady_pc_completion(changed, by)

    def hub_projection_item(self) -> dict:
        def role(policy):
            return {
                "inline_policy": [{"name": "hub-task", "policy": policy}],
                "arn": "arn:aws:iam::767397897469:role/hub-task",
            }
        import json as _json
        before = role(_json.dumps(
            CHECKER._expected_hub_task_inline_policy(rollout=True, selected="blue")
        ))
        after = role(_json.dumps(
            CHECKER._expected_hub_task_inline_policy(rollout=False, selected="green")
        ))
        return {
            "address": CHECKER.AUTHORITY_PROOF_PREPARE_RECOVERY_HUB_ROLE_ADDRESS,
            "change": {"actions": ["update"], "before": before, "after": after},
        }

    def test_hub_projection_drift_is_the_reviewed_kind(self) -> None:
        item = self.hub_projection_item()
        by = {item["address"]: {"change": {"actions": ["no-op"]}}}
        self.assertEqual(
            CHECKER._check_state_normalization_drift([item], by, refresh_only=False),
            "hub-task-selected-projection",
        )

    def test_hub_projection_drift_refuses_an_arbitrary_role_edit(self) -> None:
        import json as _json
        item = self.hub_projection_item()
        doc = _json.loads(item["change"]["after"]["inline_policy"][0]["policy"])
        doc["Statement"].append({"Action": "s3:*", "Effect": "Allow", "Resource": "*"})
        item["change"]["after"]["inline_policy"][0]["policy"] = _json.dumps(doc)
        by = {item["address"]: {"change": {"actions": ["no-op"]}}}
        with self.assertRaises(CHECKER.ContractError):
            CHECKER._check_state_normalization_drift([item], by, refresh_only=False)

    def test_pm_pc_tolerance_requires_the_pm_delete(self) -> None:
        """The never-created pm PC is tolerated ONLY while pm is being deleted.

        Groundwork for teardown step 2, tested before it executes against live
        state: with pm planned delete and its PC absent everywhere, the
        expected sets drop the PC address; with pm NOT being deleted, they do
        not, and the exact inventory still applies.
        """
        pm_fn = (
            'module.control.aws_lambda_function.authority'
            '["layerv-nhp-sandbox-ca-pm"]'
        )
        pm_pc = (
            'module.control.aws_lambda_provisioned_concurrency_config.authority'
            '["layerv-nhp-sandbox-ca-pm"]'
        )
        deleting = {pm_fn: {"change": {"actions": ["delete"]}}}
        not_deleting = {pm_fn: {"change": {"actions": ["update"]}}}
        for by, tolerated in ((deleting, True), (not_deleting, False)):
            with self.subTest(tolerated=tolerated):
                delete = (
                    by.get(pm_fn, {}).get("change", {}).get("actions")
                    == ["delete"]
                )
                self.assertEqual(delete and pm_pc not in by, tolerated)

    def standby_advance_by(self, contract=True, selected="green"):
        by = {}
        if contract:
            by[CHECKER.AUTHORITY_IMAGE_UPDATE_FOUNDATION_ADDRESS] = {
                "change": {
                    "actions": ["no-op"],
                    "after": {
                        "input": {
                            "authority_runtime_contract": {
                                "selected_authority_color": selected
                            }
                        }
                    },
                }
            }
        by[
            CHECKER.AUTHORITY_ALIAS_ADDRESS_PREFIX
            + 'layerv-nhp-sandbox-ca-ar-cell0:blue"]'
        ] = {"change": {"actions": ["update"]}}
        return by

    def test_standby_advance_claims_the_catch_up(self) -> None:
        by = self.standby_advance_by()
        changed = {a for a, v in by.items() if v["change"]["actions"] != ["no-op"]}
        acts = {a: by[a]["change"]["actions"] for a in changed}
        self.assertEqual(
            set(CHECKER._claim_authority_standby_alias_advance(changed, acts, by)),
            changed,
        )

    def test_standby_advance_fails_closed_without_a_contract(self) -> None:
        """Cannot prove which colour is serving -> do not claim (review #1).

        With no contract entry the old code defaulted the serving colour and
        the retarget guard could never fire; a serving-alias retarget would
        have been claimed as a benign catch-up.
        """
        by = self.standby_advance_by(contract=False)
        changed = set(by)
        acts = {a: by[a]["change"]["actions"] for a in changed}
        self.assertEqual(
            CHECKER._claim_authority_standby_alias_advance(changed, acts, by),
            frozenset(),
        )

    def test_standby_advance_refuses_a_serving_retarget(self) -> None:
        by = self.standby_advance_by()
        by[
            CHECKER.AUTHORITY_ALIAS_ADDRESS_PREFIX
            + 'layerv-nhp-sandbox-ca-ar-cell0:green"]'
        ] = {"change": {"actions": ["update"]}}
        changed = {a for a, v in by.items() if v["change"]["actions"] != ["no-op"]}
        acts = {a: by[a]["change"]["actions"] for a in changed}
        self.assertEqual(
            CHECKER._claim_authority_standby_alias_advance(changed, acts, by),
            frozenset(),
        )

    def test_retired_pair_slice_subtraction_matches_the_population_format(self) -> None:
        """The 26 -> 22 arithmetic, format-locked (review on #3850).

        The subtraction is a silent no-op if its f-string ever drifts from how
        the slice constant is populated, so pin byte-for-byte membership: the
        pair's four instances are IN the constant, the remainder is 22, and the
        proof set is exactly the retired pair.
        """
        self.assertEqual(sorted(CHECKER.AUTHORITY_PROOF_FUNCTIONS), [
            "layerv-nhp-sandbox-ca-pcr", "layerv-nhp-sandbox-ca-pm",
        ])
        pair_instances = {
            f'module.control.data.aws_lambda_alias.authority_live["{fn}:{color}"]'
            for fn in CHECKER.AUTHORITY_PROOF_FUNCTIONS
            for color in ("blue", "green")
        }
        slice_ = CHECKER.AUTHORITY_BLUE_GREEN_LIVE_ALIAS_DATA_RESOURCES
        self.assertEqual(len(pair_instances), 4)
        self.assertTrue(pair_instances <= slice_)
        self.assertEqual(len(slice_ - pair_instances), 22)

    def flip_by(self) -> dict:
        import copy as _copy
        target_pc = {
            "change": {
                "actions": ["create", "delete"],
                "before": {"qualifier": "green", "provisioned_concurrent_executions": 2},
                "after": {"qualifier": "blue", "provisioned_concurrent_executions": 2},
            }
        }
        by = {
            CHECKER.AUTHORITY_IMAGE_UPDATE_FOUNDATION_ADDRESS: {
                "change": {
                    "actions": ["update"],
                    "before": {"input": {"authority_runtime_contract": {"selected_authority_color": "green"}}},
                    "after": {"input": {"authority_runtime_contract": {"selected_authority_color": "blue"}}},
                }
            },
        }
        # Completeness: the claim requires the WHOLE fleet, so the fixture
        # carries every runtime function's steady pool.
        for fn in CHECKER.AUTHORITY_RUNTIME_FUNCTIONS:
            by[CHECKER.AUTHORITY_STEADY_PC_PREFIX + f'"{fn}"]'] = _copy.deepcopy(
                target_pc
            )
        return by

    def test_selector_flip_claims_and_validates(self) -> None:
        by = self.flip_by()
        changed = set(by)
        acts = {a: by[a]["change"]["actions"] for a in changed}
        claimed = CHECKER._claim_authority_selector_flip(changed, acts, by)
        self.assertEqual(set(claimed), changed)
        CHECKER._validate_authority_selector_flip(claimed, by, {})

    def degenerate_flip_by(self) -> dict:
        """The pointer-unwind recovery (run 31644720148): the contract flips
        back to the colour every pool already sits on; zero re-homes, the
        task definition resurrects from lost state as a pure create."""
        import copy as _copy
        by = {
            CHECKER.AUTHORITY_IMAGE_UPDATE_FOUNDATION_ADDRESS: {
                "change": {
                    "actions": ["update"],
                    "before": {"input": {"authority_runtime_contract": {"selected_authority_color": "green"}}},
                    "after": {"input": {"authority_runtime_contract": {"selected_authority_color": "blue"}}},
                }
            },
            CHECKER.AUTHORITY_PROOF_RETIREMENT_TASK_DEFINITION: {
                "change": {
                    "actions": ["create"],
                    "before": None,
                    "after": {"container_definitions": json.dumps([
                        {"environment": [{"name": "X", "value":
                            "arn:aws:lambda:us-east-2:1:function:layerv-nhp-sandbox-ca-ia:blue"}]}
                    ])},
                }
            },
        }
        for fn in CHECKER.AUTHORITY_RUNTIME_FUNCTIONS:
            by[CHECKER.AUTHORITY_STEADY_PC_PREFIX + f'"{fn}"]'] = {
                "change": {
                    "actions": ["no-op"],
                    "before": {"qualifier": "blue", "provisioned_concurrent_executions": 2},
                    "after": {"qualifier": "blue", "provisioned_concurrent_executions": 2},
                }
            }
        return by

    def test_pointer_and_projection_drift_pair_classifies(self) -> None:
        """A flip plan carries exactly this drift pair (run 31644720148's
        recovery): the hub_task projection re-read plus the pointer's benign
        value re-read, each planned no-op."""
        import json as _j
        def role(sel):
            return {"inline_policy": [{"name": "hub-task", "policy": _j.dumps(
                CHECKER._expected_hub_task_inline_policy(rollout=False, selected=sel))}]}
        drift = [
            {
                "address": CHECKER.AUTHORITY_PROOF_PREPARE_RECOVERY_HUB_ROLE_ADDRESS,
                "change": {"actions": ["update"], "before": role("green"), "after": role("blue")},
            },
            {
                "address": CHECKER.AUTHORITY_ACTIVE_COLOR_PARAMETER_ADDRESS,
                "change": {"actions": ["update"], "before": {"value": "green"}, "after": {"value": "blue"}},
            },
        ]
        by = {
            item["address"]: {"change": {"actions": ["no-op"]}} for item in drift
        }
        self.assertEqual(
            CHECKER._check_state_normalization_drift(drift, by, refresh_only=False),
            "hub-task-selected-projection",
        )

    def test_drift_pair_with_a_pending_pointer_change_stays_strict(self) -> None:
        """The pair is only the benign re-read when BOTH halves are planned
        no-op; a pointer with a pending change must fall to the strict path."""
        import json as _j
        def role(sel):
            return {"inline_policy": [{"name": "hub-task", "policy": _j.dumps(
                CHECKER._expected_hub_task_inline_policy(rollout=False, selected=sel))}]}
        drift = [
            {
                "address": CHECKER.AUTHORITY_PROOF_PREPARE_RECOVERY_HUB_ROLE_ADDRESS,
                "change": {"actions": ["update"], "before": role("green"), "after": role("blue")},
            },
            {
                "address": CHECKER.AUTHORITY_ACTIVE_COLOR_PARAMETER_ADDRESS,
                "change": {"actions": ["update"], "before": {"value": "green"}, "after": {"value": "blue"}},
            },
        ]
        by = {
            CHECKER.AUTHORITY_PROOF_PREPARE_RECOVERY_HUB_ROLE_ADDRESS: {"change": {"actions": ["no-op"]}},
            CHECKER.AUTHORITY_ACTIVE_COLOR_PARAMETER_ADDRESS: {"change": {"actions": ["update"]}},
        }
        with self.assertRaises(CHECKER.ContractError):
            CHECKER._check_state_normalization_drift(drift, by, refresh_only=False)

    def test_pointer_peel_survives_any_drift_combination(self) -> None:
        """The triple from run 31648474705: projection + pointer + digest.
        The pointer peels (planned no-op), and the remaining pair classifies
        with each half's own validator."""
        def role(sel):
            return {"inline_policy": [{"name": "hub-task", "policy": json.dumps(
                CHECKER._expected_hub_task_inline_policy(rollout=False, selected=sel))}]}
        digest_before = "sha256:" + "1" * 64
        digest_after = "sha256:" + "2" * 64
        drift = [
            {
                "address": CHECKER.AUTHORITY_PROOF_PREPARE_RECOVERY_HUB_ROLE_ADDRESS,
                "change": {"actions": ["update"], "before": role("green"), "after": role("blue")},
            },
            {
                "address": CHECKER.AUTHORITY_ACTIVE_COLOR_PARAMETER_ADDRESS,
                "change": {"actions": ["update"], "before": {"value": "green"}, "after": {"value": "blue"}},
            },
            {
                "address": "module.control.aws_ssm_parameter.authority_image_digest",
                "change": {"actions": ["update"], "before": {
                    "name": "/sandbox/nhp/control/connector-authority/image-digest",
                    "type": "String", "value": digest_before,
                }, "after": {
                    "name": "/sandbox/nhp/control/connector-authority/image-digest",
                    "type": "String", "value": digest_after,
                }},
            },
        ]
        # A shape-exact digest item, borrowed from the enablement fixture the
        # digest validator already accepts.
        binding = authority_contract_transition_fixture()
        digest_item = next(
            item
            for item in binding["resource_drift"]
            if item["address"]
            == "module.control.aws_ssm_parameter.authority_image_digest"
        )
        drift[2] = digest_item
        by = {item["address"]: {"change": {"actions": ["no-op"],
            "after": item["change"]["after"]}} for item in drift}
        kind = CHECKER._check_state_normalization_drift(drift, by, refresh_only=False)
        self.assertEqual(kind, "hub-task-selected-projection-with-authority-digest")

    def test_degenerate_flip_claims_and_validates(self) -> None:
        by = self.degenerate_flip_by()
        changed = {a for a, v in by.items() if v["change"]["actions"] != ["no-op"]}
        acts = {a: by[a]["change"]["actions"] for a in changed}
        claimed = CHECKER._claim_authority_selector_flip(changed, acts, by)
        self.assertEqual(set(claimed), changed)
        CHECKER._validate_authority_selector_flip(claimed, by, {})

    def test_degenerate_flip_refuses_a_pool_on_the_old_colour(self) -> None:
        """Zero re-homes is only admissible when EVERY pool already sits on
        the new selected colour; one still on the old colour is the mid-flip
        hazard and must refuse."""
        by = self.degenerate_flip_by()
        by[CHECKER.AUTHORITY_STEADY_PC_PREFIX + '"layerv-nhp-sandbox-ca-ra"]'][
            "change"
        ]["after"]["qualifier"] = "green"
        changed = {a for a, v in by.items() if v["change"]["actions"] != ["no-op"]}
        acts = {a: by[a]["change"]["actions"] for a in changed}
        self.assertEqual(
            CHECKER._claim_authority_selector_flip(changed, acts, by), frozenset()
        )

    def test_resurrected_task_definition_pins_the_new_colour(self) -> None:
        """A pure-create task definition (lost state) cannot smuggle the old
        colour into the container environment."""
        by = self.degenerate_flip_by()
        by[CHECKER.AUTHORITY_PROOF_RETIREMENT_TASK_DEFINITION]["change"][
            "after"
        ]["container_definitions"] = json.dumps([
            {"environment": [{"name": "X", "value":
                "arn:aws:lambda:us-east-2:1:function:layerv-nhp-sandbox-ca-ia:green"}]}
        ])
        changed = {a for a, v in by.items() if v["change"]["actions"] != ["no-op"]}
        acts = {a: by[a]["change"]["actions"] for a in changed}
        claimed = CHECKER._claim_authority_selector_flip(changed, acts, by)
        with self.assertRaisesRegex(
            CHECKER.ContractError, "resurrected Hub task definition"
        ):
            CHECKER._validate_authority_selector_flip(claimed, by, {})

    def test_selector_flip_refuses_a_partial_fleet(self) -> None:
        """Some pools flipped and some not is itself the hazardous state."""
        by = self.flip_by()
        del by[
            CHECKER.AUTHORITY_STEADY_PC_PREFIX + '"layerv-nhp-sandbox-ca-ra"]'
        ]
        changed = set(by)
        acts = {a: by[a]["change"]["actions"] for a in changed}
        self.assertEqual(
            CHECKER._claim_authority_selector_flip(changed, acts, by), frozenset()
        )

    def test_selector_flip_refuses_allocation_tamper(self) -> None:
        by = self.flip_by()
        by[CHECKER.AUTHORITY_STEADY_PC_PREFIX + '"layerv-nhp-sandbox-ca-ia"]'][
            "change"
        ]["after"]["provisioned_concurrent_executions"] = 99
        with self.assertRaises(CHECKER.ContractError):
            CHECKER._validate_authority_selector_flip(frozenset(by), by, {})

    def test_selector_flip_refuses_a_non_colour_policy_edit(self) -> None:
        """A riding hub_task update must be a colour move, nothing else."""
        import json as _json
        by = self.flip_by()
        addr = "module.control.aws_iam_role_policy.hub_task[0]"
        by[addr] = {
            "change": {
                "actions": ["update"],
                "before": {"policy": _json.dumps({"Resource": [
                    "arn:aws:lambda:us-east-2:1:function:layerv-nhp-sandbox-ca-ia:green"
                ]})},
                "after": {"policy": _json.dumps({"Resource": [
                    "arn:aws:lambda:us-east-2:1:function:layerv-nhp-sandbox-ca-ia:blue",
                    "s3:*",
                ]})},
            }
        }
        with self.assertRaises(CHECKER.ContractError):
            CHECKER._validate_authority_selector_flip(
                frozenset(by), by, {}
            )

    def test_selector_flip_pins_rehome_direction(self) -> None:
        by = self.flip_by()
        pc = by[CHECKER.AUTHORITY_STEADY_PC_PREFIX + '"layerv-nhp-sandbox-ca-ia"]']
        pc["change"]["before"]["qualifier"] = "blue"
        pc["change"]["after"]["qualifier"] = "green"
        with self.assertRaises(CHECKER.ContractError):
            CHECKER._validate_authority_selector_flip(frozenset(by), by, {})

    def test_selector_flip_requires_the_pointer_to_move(self) -> None:
        by = self.flip_by()
        by[CHECKER.AUTHORITY_IMAGE_UPDATE_FOUNDATION_ADDRESS]["change"]["after"][
            "input"
        ]["authority_runtime_contract"]["selected_authority_color"] = "green"
        changed = set(by)
        acts = {a: by[a]["change"]["actions"] for a in changed}
        self.assertEqual(
            CHECKER._claim_authority_selector_flip(changed, acts, by), frozenset()
        )

    def test_steady_pc_completion_admits_delete_create_rehome(self) -> None:
        """The 2026-08-12 cutover recovery: stuck pools re-home delete-first."""
        by = {
            CHECKER.AUTHORITY_IMAGE_UPDATE_FOUNDATION_ADDRESS: {
                "change": {
                    "actions": ["no-op"],
                    "after": {"input": {"authority_runtime_contract": {
                        "selected_authority_color": "blue"}}},
                }
            },
            CHECKER.AUTHORITY_STEADY_PC_PREFIX + '"layerv-nhp-sandbox-ca-ia"]': {
                "change": {
                    "actions": ["delete", "create"],
                    "before": {"qualifier": "green", "provisioned_concurrent_executions": 2},
                    "after": {"qualifier": "blue", "provisioned_concurrent_executions": 2},
                }
            },
        }
        # End-to-end through check_plan (not just the validator): the full
        # runtime fleet re-homing delete,create classifies as the completion.
        for fn in CHECKER.AUTHORITY_RUNTIME_FUNCTIONS:
            by[CHECKER.AUTHORITY_STEADY_PC_PREFIX + f'"{fn}"]'] = {
                "change": {
                    "actions": ["delete", "create"],
                    "before": {"qualifier": "green", "provisioned_concurrent_executions": 2},
                    "after": {"qualifier": "blue", "provisioned_concurrent_executions": 2},
                }
            }
        changed = {a for a, v in by.items() if v["change"]["actions"] != ["no-op"]}
        CHECKER._check_authority_steady_pc_completion(changed, by)

    def widen_plan(self) -> dict:
        """The steady inventory mutated into the one-time envelope widen: the
        contract's steady reserved algebra moves provisioned -> 2x, every
        function's reserved_concurrent_executions follows, and every
        concurrency-exhaustion alarm threshold follows (it derives from the
        reserved envelope)."""
        plan = authority_runtime_steady_fixture()
        plan["applyable"] = True
        changes = {
            item["address"]: item["change"] for item in plan["resource_changes"]
        }
        foundation = changes[CHECKER.AUTHORITY_IMAGE_UPDATE_FOUNDATION_ADDRESS]
        foundation["actions"] = ["update"]
        after_payload = copy.deepcopy(foundation["after"]["input"])
        for spec in after_payload["authority_runtime_contract"][
            "functions"
        ].values():
            spec["steady_reserved_concurrency"] = (
                2 * spec["steady_provisioned_concurrency"]
            )
        foundation["after"] = {
            "input": after_payload,
            "output": copy.deepcopy(after_payload),
        }
        for fn in CHECKER.AUTHORITY_RUNTIME_FUNCTIONS:
            change = changes[f'{CHECKER.AUTHORITY_FUNCTION_ADDRESS_PREFIX}{fn}"]']
            change["actions"] = ["update"]
            change["after"] = {
                **copy.deepcopy(change["before"]),
                "reserved_concurrent_executions": 4,
            }
            alarm = changes[
                CHECKER.AUTHORITY_EXHAUSTION_ALARM_TEMPLATE.format(fn=fn)
            ]
            alarm["actions"] = ["update"]
            alarm["after"] = {**copy.deepcopy(alarm["before"]), "threshold": 4}
        return plan

    def test_reserved_envelope_widen_classifies_end_to_end(self) -> None:
        summary = CHECKER.check_plan(self.widen_plan())
        self.assertEqual(summary["plan_mode"], "authority-reserved-envelope-widen")

    def test_reserved_envelope_widen_absorbs_a_riding_image_publish(self) -> None:
        """A routine publish landing in the same plan stays admitted.

        Under publish tracking (the live sandbox source), the resolved digest
        moves in the payload's image URI alone -- the contract itself is
        byte-identical -- so the delta helper still recognizes the widen, and
        the validator's full-inventory pass re-proves the uniform convergence
        the image-roll lane (stood down to keep claims disjoint) would have.
        """
        plan = self.widen_plan()
        changes = {
            item["address"]: item["change"] for item in plan["resource_changes"]
        }
        foundation = changes[CHECKER.AUTHORITY_IMAGE_UPDATE_FOUNDATION_ADDRESS]
        for side in ("before", "after"):
            for view in ("input", "output"):
                global_contract = foundation[side][view][
                    "authority_runtime_contract"
                ]["global"]
                global_contract["authority_image_source"] = "publish_parameter"
                global_contract.pop("authority_image_digest", None)
        old_uri = foundation["after"]["input"]["authority_image_uri"]
        new_uri = old_uri.split("@sha256:")[0] + "@sha256:" + 64 * "f"
        self.assertNotEqual(new_uri, old_uri)
        for view in ("input", "output"):
            foundation["after"][view]["authority_image_uri"] = new_uri
        for fn in CHECKER.AUTHORITY_RUNTIME_FUNCTIONS:
            change = changes[f'{CHECKER.AUTHORITY_FUNCTION_ADDRESS_PREFIX}{fn}"]']
            change["after"]["image_uri"] = new_uri
        self._advance_standby_aliases(changes)
        summary = CHECKER.check_plan(plan)
        self.assertEqual(summary["plan_mode"], "authority-reserved-envelope-widen")

    def _advance_standby_aliases(self, changes: dict) -> None:
        """The republish's organic companion: every standby (green — the
        fixture's contract selects blue) alias advances to the new version,
        deferred to apply."""
        for fn in CHECKER.AUTHORITY_RUNTIME_FUNCTIONS:
            alias = changes[
                f'{CHECKER.AUTHORITY_ALIAS_ADDRESS_PREFIX}{fn}:green"]'
            ]
            alias["actions"] = ["update"]
            alias["after"] = {
                **copy.deepcopy(alias["before"]),
                "function_version": None,
            }
            alias["after_unknown"] = {"function_version": True}

    def test_reserved_envelope_widen_refuses_an_alias_ride_without_a_publish(
        self,
    ) -> None:
        """Standby aliases moving with NO image move is not the organic
        republish shape -- the claim leaves them unclaimed and the plan
        cannot be fully accounted for."""
        plan = self.widen_plan()
        changes = {
            item["address"]: item["change"] for item in plan["resource_changes"]
        }
        self._advance_standby_aliases(changes)
        with self.assertRaises(CHECKER.ContractError):
            CHECKER.check_plan(plan)

    def test_reserved_envelope_widen_refuses_a_partial_standby_ride(self) -> None:
        """Image moved but only SOME standby aliases advancing is not the
        organic republish (which republishes every function): refused."""
        plan = self.widen_plan()
        changes = {
            item["address"]: item["change"] for item in plan["resource_changes"]
        }
        foundation = changes[CHECKER.AUTHORITY_IMAGE_UPDATE_FOUNDATION_ADDRESS]
        for side in ("before", "after"):
            for view in ("input", "output"):
                global_contract = foundation[side][view][
                    "authority_runtime_contract"
                ]["global"]
                global_contract["authority_image_source"] = "publish_parameter"
                global_contract.pop("authority_image_digest", None)
        old_uri = foundation["after"]["input"]["authority_image_uri"]
        new_uri = old_uri.split("@sha256:")[0] + "@sha256:" + 64 * "f"
        for view in ("input", "output"):
            foundation["after"][view]["authority_image_uri"] = new_uri
        for fn in CHECKER.AUTHORITY_RUNTIME_FUNCTIONS:
            changes[f'{CHECKER.AUTHORITY_FUNCTION_ADDRESS_PREFIX}{fn}"]'][
                "after"
            ]["image_uri"] = new_uri
        self._advance_standby_aliases(changes)
        stale = sorted(CHECKER.AUTHORITY_RUNTIME_FUNCTIONS)[0]
        alias = changes[
            f'{CHECKER.AUTHORITY_ALIAS_ADDRESS_PREFIX}{stale}:green"]'
        ]
        alias["actions"] = ["no-op"]
        alias["after"] = copy.deepcopy(alias["before"])
        alias["after_unknown"] = {}
        by = {item["address"]: item for item in plan["resource_changes"]}
        changed = {
            a for a, i in by.items() if i["change"]["actions"] != ["no-op"]
        }
        acts = {a: by[a]["change"]["actions"] for a in changed}
        self.assertEqual(
            CHECKER._claim_authority_reserved_envelope_widen(changed, acts, by),
            frozenset(),
        )

    def test_reserved_envelope_widen_refuses_a_standby_alias_replace(self) -> None:
        """A standby alias REPLACING (rather than updating in place) is not
        the hold's advance shape: refused."""
        plan = self.widen_plan()
        changes = {
            item["address"]: item["change"] for item in plan["resource_changes"]
        }
        foundation = changes[CHECKER.AUTHORITY_IMAGE_UPDATE_FOUNDATION_ADDRESS]
        for side in ("before", "after"):
            for view in ("input", "output"):
                global_contract = foundation[side][view][
                    "authority_runtime_contract"
                ]["global"]
                global_contract["authority_image_source"] = "publish_parameter"
                global_contract.pop("authority_image_digest", None)
        old_uri = foundation["after"]["input"]["authority_image_uri"]
        new_uri = old_uri.split("@sha256:")[0] + "@sha256:" + 64 * "f"
        for view in ("input", "output"):
            foundation["after"][view]["authority_image_uri"] = new_uri
        for fn in CHECKER.AUTHORITY_RUNTIME_FUNCTIONS:
            changes[f'{CHECKER.AUTHORITY_FUNCTION_ADDRESS_PREFIX}{fn}"]'][
                "after"
            ]["image_uri"] = new_uri
        self._advance_standby_aliases(changes)
        changes[
            f'{CHECKER.AUTHORITY_ALIAS_ADDRESS_PREFIX}'
            f'{sorted(CHECKER.AUTHORITY_RUNTIME_FUNCTIONS)[0]}:green"]'
        ]["actions"] = ["delete", "create"]
        by = {item["address"]: item for item in plan["resource_changes"]}
        changed = {
            a for a, i in by.items() if i["change"]["actions"] != ["no-op"]
        }
        acts = {a: by[a]["change"]["actions"] for a in changed}
        self.assertEqual(
            CHECKER._claim_authority_reserved_envelope_widen(changed, acts, by),
            frozenset(),
        )

    def test_reserved_envelope_widen_validator_rejects_a_doctored_claim(self) -> None:
        """The validator's standby-only recheck is defense-in-depth against a
        future claim bug: drive it directly with a claimed set that smuggles a
        selected-colour alias (review #3856)."""
        plan = self.widen_plan()
        by = {item["address"]: item for item in plan["resource_changes"]}
        doctored = frozenset(
            {
                CHECKER.AUTHORITY_IMAGE_UPDATE_FOUNDATION_ADDRESS,
                f'{CHECKER.AUTHORITY_ALIAS_ADDRESS_PREFIX}'
                'layerv-nhp-sandbox-ca-ia:blue"]',
            }
        )
        with self.assertRaisesRegex(
            CHECKER.ContractError, "is not the standby colour"
        ):
            CHECKER._validate_authority_reserved_envelope_widen(
                doctored, by, plan
            )

    def test_reserved_envelope_widen_refuses_a_serving_alias_retarget(self) -> None:
        """A selected-colour alias update is a traffic move; the widen claim
        refuses outright rather than leaving it to composition."""
        plan = self.widen_plan()
        by = {item["address"]: item for item in plan["resource_changes"]}
        by[
            f'{CHECKER.AUTHORITY_ALIAS_ADDRESS_PREFIX}layerv-nhp-sandbox-ca-ia:blue"]'
        ]["change"]["actions"] = ["update"]
        changed = {
            a for a, i in by.items() if i["change"]["actions"] != ["no-op"]
        }
        acts = {a: by[a]["change"]["actions"] for a in changed}
        self.assertEqual(
            CHECKER._claim_authority_reserved_envelope_widen(changed, acts, by),
            frozenset(),
        )

    def test_reserved_envelope_widen_rejects_a_split_fleet_image_ride(self) -> None:
        """A non-uniform image ride is rejected INSIDE this lane: the claim
        excludes the image URI from its own comparison, so the split-fleet
        refusal rests on the delegated full-inventory pass pinning every
        function to the contract's URI (review #3855 round 4)."""
        plan = self.widen_plan()
        changes = {
            item["address"]: item["change"] for item in plan["resource_changes"]
        }
        foundation = changes[CHECKER.AUTHORITY_IMAGE_UPDATE_FOUNDATION_ADDRESS]
        for side in ("before", "after"):
            for view in ("input", "output"):
                global_contract = foundation[side][view][
                    "authority_runtime_contract"
                ]["global"]
                global_contract["authority_image_source"] = "publish_parameter"
                global_contract.pop("authority_image_digest", None)
        old_uri = foundation["after"]["input"]["authority_image_uri"]
        new_uri = old_uri.split("@sha256:")[0] + "@sha256:" + 64 * "f"
        for view in ("input", "output"):
            foundation["after"][view]["authority_image_uri"] = new_uri
        stale = sorted(CHECKER.AUTHORITY_RUNTIME_FUNCTIONS)[0]
        for fn in CHECKER.AUTHORITY_RUNTIME_FUNCTIONS:
            if fn == stale:
                continue
            changes[f'{CHECKER.AUTHORITY_FUNCTION_ADDRESS_PREFIX}{fn}"]'][
                "after"
            ]["image_uri"] = new_uri
        self._advance_standby_aliases(changes)
        with self.assertRaisesRegex(
            CHECKER.ContractError, "contract-pinned repository@digest"
        ):
            CHECKER.check_plan(plan)

    def test_reserved_envelope_widen_refuses_a_partial_fleet(self) -> None:
        """One function left on the old algebra fails the contract delta."""
        plan = self.widen_plan()
        by = {item["address"]: item for item in plan["resource_changes"]}
        foundation = by[CHECKER.AUTHORITY_IMAGE_UPDATE_FOUNDATION_ADDRESS]
        foundation["change"]["after"]["input"]["authority_runtime_contract"][
            "functions"
        ]["layerv-nhp-sandbox-ca-ra"]["steady_reserved_concurrency"] = 2
        self.assertIsNone(
            CHECKER._authority_reserved_envelope_widen_functions(by)
        )

    def test_reserved_envelope_widen_refuses_a_wrong_multiple(self) -> None:
        plan = self.widen_plan()
        by = {item["address"]: item for item in plan["resource_changes"]}
        foundation = by[CHECKER.AUTHORITY_IMAGE_UPDATE_FOUNDATION_ADDRESS]
        for spec in foundation["change"]["after"]["input"][
            "authority_runtime_contract"
        ]["functions"].values():
            spec["steady_reserved_concurrency"] = 5
        self.assertIsNone(
            CHECKER._authority_reserved_envelope_widen_functions(by)
        )

    def test_reserved_envelope_widen_refuses_a_riding_contract_edit(self) -> None:
        """Any other spec field moving with the widen is not this lane."""
        plan = self.widen_plan()
        by = {item["address"]: item for item in plan["resource_changes"]}
        foundation = by[CHECKER.AUTHORITY_IMAGE_UPDATE_FOUNDATION_ADDRESS]
        foundation["change"]["after"]["input"]["authority_runtime_contract"][
            "functions"
        ]["layerv-nhp-sandbox-ca-ia"]["max_caller_requests_per_second"] = 6
        self.assertIsNone(
            CHECKER._authority_reserved_envelope_widen_functions(by)
        )

    def test_reserved_envelope_widen_refuses_a_riding_global_edit(self) -> None:
        """Evidence stamps may move with the widen; anything else in the
        contract's global block may not."""
        plan = self.widen_plan()
        by = {item["address"]: item for item in plan["resource_changes"]}
        foundation = by[CHECKER.AUTHORITY_IMAGE_UPDATE_FOUNDATION_ADDRESS]
        foundation["change"]["after"]["input"]["authority_runtime_contract"][
            "global"
        ]["caller_capacity"]["hub_workers"]["max_replicas"] = 99
        self.assertIsNone(
            CHECKER._authority_reserved_envelope_widen_functions(by)
        )

    def test_reserved_envelope_widen_tolerates_fresh_evidence_stamps(self) -> None:
        """The generator stamps the checkout commit + manifest hash into every
        evidence block, and the widen edits the manifest -- so a real widen
        plan always carries fresh stamps. The delta must admit them."""
        plan = self.widen_plan()
        by = {item["address"]: item for item in plan["resource_changes"]}
        foundation = by[CHECKER.AUTHORITY_IMAGE_UPDATE_FOUNDATION_ADDRESS]
        contract = foundation["change"]["after"]["input"][
            "authority_runtime_contract"
        ]
        fresh = {
            "repository": "layervai/nhp",
            "source_commit": "c" * 40,
            "path": (
                "docs/evidence/connector-authority/v1/"
                "sandbox-measurement-basis.json"
            ),
            "sha256": "d" * 64,
            "schema_version": 1,
        }
        contract["global"]["basis_evidence"] = dict(fresh)
        contract["provisioned_cells_evidence"] = dict(fresh)
        for spec in contract["functions"].values():
            spec["basis_evidence"] = dict(fresh)
        self.assertEqual(
            CHECKER._authority_reserved_envelope_widen_functions(by),
            set(contract["functions"]),
        )

    def test_reserved_envelope_widen_rejects_an_alarm_threshold_tamper(self) -> None:
        """The claim admits the shape; the full-inventory validator pins the
        threshold to the widened envelope exactly."""
        plan = self.widen_plan()
        changes = {
            item["address"]: item["change"] for item in plan["resource_changes"]
        }
        changes[
            CHECKER.AUTHORITY_EXHAUSTION_ALARM_TEMPLATE.format(
                fn="layerv-nhp-sandbox-ca-ia"
            )
        ]["after"]["threshold"] = 3
        with self.assertRaisesRegex(
            CHECKER.ContractError, "threshold must be exactly"
        ):
            CHECKER.check_plan(plan)

    def test_reserved_envelope_widen_rejects_a_function_field_smuggle(self) -> None:
        """A function update carrying more than the envelope (and a uniform
        image move) is caught by the full-inventory after-state check."""
        plan = self.widen_plan()
        changes = {
            item["address"]: item["change"] for item in plan["resource_changes"]
        }
        changes[
            f'{CHECKER.AUTHORITY_FUNCTION_ADDRESS_PREFIX}layerv-nhp-sandbox-ca-ia"]'
        ]["after"]["description"] = "not the reviewed description"
        with self.assertRaises(CHECKER.ContractError):
            CHECKER.check_plan(plan)

    def _append_hub_service_wait_flip(self, plan: dict, extra: dict) -> None:
        """The runtime fixture carries no Hub worker slice, so append the
        service update the real widen plan carries (wait_for_steady_state
        turning on) with any extra after-field tamper the test wants."""
        before = {
            "name": "layerv-nhp-sandbox-hub",
            "launch_type": "FARGATE",
            "desired_count": 2,
            "task_definition": "arn:aws:ecs:us-east-2:767397897469:task-definition/layerv-nhp-sandbox-control-hub:5",
            "wait_for_steady_state": False,
        }
        plan["resource_changes"].append(
            {
                "address": CHECKER.HUB_WORKER_SERVICE_ADDRESS,
                "mode": "managed",
                "type": "aws_ecs_service",
                "change": {
                    "actions": ["update"],
                    "before": copy.deepcopy(before),
                    "after": {
                        **copy.deepcopy(before),
                        "wait_for_steady_state": True,
                        **extra,
                    },
                    "after_unknown": {},
                },
            }
        )

    def test_reserved_envelope_widen_admits_the_steady_state_wait_flip(self) -> None:
        """The service's wait_for_steady_state enablement rides the widen
        apply exactly once (the drain half of warm-before-switch).

        Claim-level rather than check_plan: the runtime fixture carries no Hub
        worker inventory, and appending a lone service trips the slice
        coexistence rule. The end-to-end admission is proven against the real
        live-state plan (which carries the full Hub inventory) in the PR.
        """
        plan = self.widen_plan()
        self._append_hub_service_wait_flip(plan, {})
        by = {item["address"]: item for item in plan["resource_changes"]}
        changed = {
            a for a, i in by.items() if i["change"]["actions"] != ["no-op"]
        }
        acts = {a: by[a]["change"]["actions"] for a in changed}
        claimed = CHECKER._claim_authority_reserved_envelope_widen(
            changed, acts, by
        )
        self.assertIn(CHECKER.HUB_WORKER_SERVICE_ADDRESS, claimed)
        self.assertEqual(set(claimed), changed)
        CHECKER._validate_authority_reserved_envelope_widen(claimed, by, plan)

    def test_reserved_envelope_widen_refuses_a_wider_service_edit(self) -> None:
        """A service update carrying anything beyond the wait flag is not
        claimable by the widen, so the plan cannot be fully claimed."""
        plan = self.widen_plan()
        self._append_hub_service_wait_flip(plan, {"desired_count": 9})
        by = {item["address"]: item for item in plan["resource_changes"]}
        changed = {
            a for a, i in by.items() if i["change"]["actions"] != ["no-op"]
        }
        acts = {a: by[a]["change"]["actions"] for a in changed}
        self.assertEqual(
            CHECKER._claim_authority_reserved_envelope_widen(changed, acts, by),
            frozenset(),
        )

    def completion_recovery_plan(self, function_count: int) -> dict:
        """The steady inventory with the first function_count steady pools
        re-homing delete,create to the selected colour."""
        plan = authority_runtime_steady_fixture()
        plan["applyable"] = True
        changes = {
            item["address"]: item["change"] for item in plan["resource_changes"]
        }
        for fn in sorted(CHECKER.AUTHORITY_RUNTIME_FUNCTIONS)[:function_count]:
            change = changes[CHECKER.AUTHORITY_STEADY_PC_PREFIX + f'"{fn}"]']
            change["actions"] = ["delete", "create"]
            change["before"] = {
                **copy.deepcopy(change["after"]),
                "qualifier": "green",
            }
        return plan

    def test_full_delete_create_completion_classifies_end_to_end(self) -> None:
        summary = CHECKER.check_plan(
            self.completion_recovery_plan(len(CHECKER.AUTHORITY_RUNTIME_FUNCTIONS))
        )
        self.assertEqual(summary["plan_mode"], "authority-steady-pc-completion")

    def test_partial_delete_create_completion_falls_to_the_terminal_reject(
        self,
    ) -> None:
        """A partial delete-first re-home set IS the mid-flip hazard; only the
        complete 13-function recovery classifies (review #3855, aligning the
        Python elif with the shell fence's exactly-the-13 witness)."""
        with self.assertRaisesRegex(
            CHECKER.ContractError, "must be an exact no-op"
        ):
            CHECKER.check_plan(self.completion_recovery_plan(3))

    def test_image_roll_stands_down_for_the_widen(self) -> None:
        """Two claims on one function address would fail composition."""
        plan = self.widen_plan()
        by = {item["address"]: item for item in plan["resource_changes"]}
        changed = {
            a for a, item in by.items() if item["change"]["actions"] != ["no-op"]
        }
        acts = {a: by[a]["change"]["actions"] for a in changed}
        self.assertEqual(
            CHECKER._claim_authority_image_roll(changed, acts, by), frozenset()
        )

    def pointer_create_plan(self) -> dict:
        """The steady inventory with the switch-pointer parameter appearing:
        the B1 shape (module change merged, gate dark, one create)."""
        plan = authority_runtime_steady_fixture()
        plan["applyable"] = True
        changes = {
            item["address"]: item["change"] for item in plan["resource_changes"]
        }
        change = changes[CHECKER.AUTHORITY_ACTIVE_COLOR_PARAMETER_ADDRESS]
        change["actions"] = ["create"]
        change["before"] = None
        return plan

    def test_pointer_create_classifies_as_the_legacy_expansion(self) -> None:
        """Standing alone, the pointer create is a runtime resource appearing
        with the contract already bound -- the expansion branch owns it, and
        the config-reference contract pins its seed to the contract colour."""
        summary = CHECKER.check_plan(self.pointer_create_plan())
        self.assertEqual(
            summary["plan_mode"], "authority-runtime-legacy-expansion"
        )

    def test_pointer_create_claim_admits_the_exact_seed(self) -> None:
        plan = self.pointer_create_plan()
        by = {item["address"]: item for item in plan["resource_changes"]}
        changed = {
            a for a, i in by.items() if i["change"]["actions"] != ["no-op"]
        }
        acts = {a: by[a]["change"]["actions"] for a in changed}
        self.assertEqual(
            CHECKER._claim_authority_selector_pointer_create(changed, acts, by),
            frozenset({CHECKER.AUTHORITY_ACTIVE_COLOR_PARAMETER_ADDRESS}),
        )

    def test_pointer_create_claim_refuses_a_disagreeing_seed(self) -> None:
        """A seed that disagrees with the bound contract's selected colour is
        not the reviewed transition."""
        plan = self.pointer_create_plan()
        by = {item["address"]: item for item in plan["resource_changes"]}
        by[CHECKER.AUTHORITY_ACTIVE_COLOR_PARAMETER_ADDRESS]["change"]["after"][
            "value"
        ] = "green"
        changed = {
            a for a, i in by.items() if i["change"]["actions"] != ["no-op"]
        }
        acts = {a: by[a]["change"]["actions"] for a in changed}
        self.assertEqual(
            CHECKER._claim_authority_selector_pointer_create(changed, acts, by),
            frozenset(),
        )

    def test_pointer_create_claim_refuses_a_foreign_name(self) -> None:
        plan = self.pointer_create_plan()
        by = {item["address"]: item for item in plan["resource_changes"]}
        by[CHECKER.AUTHORITY_ACTIVE_COLOR_PARAMETER_ADDRESS]["change"]["after"][
            "name"
        ] = "/sandbox/nhp/somewhere/else"
        changed = {
            a for a, i in by.items() if i["change"]["actions"] != ["no-op"]
        }
        acts = {a: by[a]["change"]["actions"] for a in changed}
        self.assertEqual(
            CHECKER._claim_authority_selector_pointer_create(changed, acts, by),
            frozenset(),
        )

    def test_pointer_value_drift_is_the_permanent_refresh_kind(self) -> None:
        """The deploy pipeline writes the pointer on every promotion and state
        keeps the seed forever, so this drift rides every subsequent plan --
        including the promotion's own flip plan (run 31641110788 was refused
        exactly here) and every steady no-op after it. It classifies with the
        alias-refresh kind, which is deliberately not plan-mode-gated."""
        item = {
            "address": CHECKER.AUTHORITY_ACTIVE_COLOR_PARAMETER_ADDRESS,
            "change": {
                "actions": ["update"],
                "before": {"value": "blue"},
                "after": {"value": "green"},
            },
        }
        by = {
            CHECKER.AUTHORITY_ACTIVE_COLOR_PARAMETER_ADDRESS: {
                "change": {"actions": ["no-op"]}
            }
        }
        self.assertEqual(
            CHECKER._check_state_normalization_drift(
                [item], by, refresh_only=False
            ),
            "authority-alias-refresh",
        )

    def test_pointer_drift_with_a_pending_change_stays_strict(self) -> None:
        """A drifted pointer whose plan is NOT a no-op is not the benign
        re-read; it must fall through to the stricter matchers."""
        item = {
            "address": CHECKER.AUTHORITY_ACTIVE_COLOR_PARAMETER_ADDRESS,
            "change": {
                "actions": ["update"],
                "before": {"value": "blue"},
                "after": {"value": "green"},
            },
        }
        by = {
            CHECKER.AUTHORITY_ACTIVE_COLOR_PARAMETER_ADDRESS: {
                "change": {"actions": ["update"]}
            }
        }
        self.assertNotEqual(
            CHECKER._check_state_normalization_drift(
                [item], by, refresh_only=False
            ),
            "authority-alias-refresh",
        )

    def test_flip_projection_drift_admits_either_direction(self) -> None:
        """hub_task projection drift is accepted for a green->blue flip too."""
        import json as _json
        def role(sel):
            return {"inline_policy": [{"name": "hub-task", "policy": _json.dumps(
                CHECKER._expected_hub_task_inline_policy(rollout=False, selected=sel))}]}
        item = {
            "address": CHECKER.AUTHORITY_PROOF_PREPARE_RECOVERY_HUB_ROLE_ADDRESS,
            "change": {"actions": ["update"], "before": role("green"), "after": role("blue")},
        }
        by = {item["address"]: {"change": {"actions": ["no-op"]}}}
        self.assertEqual(
            CHECKER._check_state_normalization_drift([item], by, refresh_only=False),
            "hub-task-selected-projection",
        )

    def test_hub_task_overlap_projection_admits_either_selected_predecessor(
        self,
    ) -> None:
        """The permanent six-alias policy re-projects after its first apply."""
        import json as _json

        def role(*, rollout, selected="blue"):
            return {
                "inline_policy": [
                    {
                        "name": "hub-task",
                        "policy": _json.dumps(
                            CHECKER._expected_hub_task_inline_policy(
                                rollout=rollout, selected=selected
                            )
                        ),
                    }
                ]
            }

        address = CHECKER.AUTHORITY_PROOF_PREPARE_RECOVERY_HUB_ROLE_ADDRESS
        by = {address: {"change": {"actions": ["no-op"]}}}
        for selected in ("blue", "green"):
            with self.subTest(selected=selected):
                item = {
                    "address": address,
                    "change": {
                        "actions": ["update"],
                        "before": role(rollout=False, selected=selected),
                        "after": role(rollout=True),
                    },
                }
                self.assertEqual(
                    CHECKER._check_state_normalization_drift(
                        [item], by, refresh_only=False
                    ),
                    "hub-task-selected-projection",
                )

    def test_hub_task_overlap_projection_rejects_an_unreviewed_policy(
        self,
    ) -> None:
        """An expansion is not a wildcard for arbitrary inline-policy drift."""
        import copy as _copy
        import json as _json

        def role(policy):
            return {
                "inline_policy": [
                    {"name": "hub-task", "policy": _json.dumps(policy)}
                ]
            }

        before = CHECKER._expected_hub_task_inline_policy(
            rollout=False, selected="blue"
        )
        after = _copy.deepcopy(
            CHECKER._expected_hub_task_inline_policy(rollout=True)
        )
        after["Statement"][0]["Resource"].append("*")
        address = CHECKER.AUTHORITY_PROOF_PREPARE_RECOVERY_HUB_ROLE_ADDRESS
        item = {
            "address": address,
            "change": {
                "actions": ["update"],
                "before": role(before),
                "after": role(after),
            },
        }
        by = {address: {"change": {"actions": ["no-op"]}}}
        with self.assertRaises(CHECKER.ContractError):
            CHECKER._check_state_normalization_drift(
                [item], by, refresh_only=False
            )

    def test_composed_plan_mode_vocabulary_is_pinned(self) -> None:
        """The auto-promote deploy step greps the composed label format
        (build-and-push.yml: `composed-*authority-selector-flip*`); a silent
        rename here would make it reject a legitimate flip with the pointer
        already written. Pin the vocabulary so a rename breaks HERE first."""
        self.assertEqual(CHECKER._COMPOSED_PLAN_MODE_PREFIX, "composed-")
        self.assertEqual(CHECKER._COMPOSED_PLAN_MODE_SEPARATOR, "-with-")
        self.assertIn(
            ("authority-selector-flip"),
            {name for name, _, _ in CHECKER._COMPOSABLE_TRANSITIONS},
        )

    def test_the_real_registry_carries_the_expected_lanes(self) -> None:
        names = {name for name, _, _ in CHECKER._COMPOSABLE_TRANSITIONS}
        self.assertEqual(
            names,
            {
                "provisioned-cell-status-update",
                "provisioned-cell-general-assignable-update",
                "hub-worker-image-update",
                "authority-proof-enable",
                "authority-proof-consumer-staging",
                "authority-hub-exec-policy-update",
                "dynamodb-transaction-action-correction",
                "hub-client-edge-port-migration",
                # Publish tracking makes the resolved digest move on its own, so
                # the foundation contract now lands alongside whatever else a
                # Control PR changes. Without this lane every such plan falls
                # through to the terminal reject.
                "authority-image-uri-move",
                # The routine Authority image roll. Validated structurally --
                # every function must converge on the digest the foundation
                # contract binds -- because a literal FROM->TO digest pin can
                # only ever admit one migration and cannot keep up with a
                # stream of merges to main.
                "authority-image-roll",
                # Closing the attended-proof rollout window: the live-first half
                # of the retirement, where live state goes dark before the
                # Terraform removal follows.
                "authority-proof-rollout-retirement",
                # The consumer-staging rollback and the steady-PC completion as
                # composable claims: the elif chain keeps their standalone
                # forms, and these let them ride together (the 2026-08-12
                # step-1 shape: consumers off + pm's pending capacity create).
                "authority-proof-consumers-disable",
                "authority-steady-pc-completion",
                # Step 2 of the teardown as a composable claim, and the hold's
                # permanent steady-state lane: standby aliases catching up to
                # the newest published version while selected holds.
                "authority-proof-disable",
                "authority-standby-alias-advance",
                # The blue/green cutover: one reviewed pointer moves, capacity
                # follows create-before-destroy, and the Hub repoints by
                # colour with the delta content-proved.
                "authority-selector-flip",
                # The one-time steady-algebra migration behind warm flips:
                # every function's reserved envelope widens to 2x provisioned
                # so both colours' pools fit inside it, with the exhaustion
                # alarm thresholds following.
                "authority-reserved-envelope-widen",
                # The switch-pointer parameter's one-time creation as a
                # composable rider (standing alone, the legacy-expansion
                # branch classifies it): a publish's standby alias advance in
                # the same push would otherwise leave the create unclaimed.
                "authority-selector-pointer-create",
            },
        )


class LiveBoundaryPortToleranceTest(unittest.TestCase):
    """check_live runs BEFORE the apply that moves the ingress port.

    Pinning only the post-migration value made the check demand the state its
    own apply produces, so the Control apply refused with

      Control Hub NLB SG ingress is not exactly proof-runner /32 UDP 443

    while live was still 62206 and the plan in hand was the very change that
    moves it. That is the same mistake the NLB-SG-absence branch beside it
    already documents.
    """

    def ingress(self, port):
        return {("udp", port, port, "cidr_ipv4", CHECKER.HUB_PUBLIC_UDP_INGRESS_CIDR)}

    def test_both_migration_ports_are_admitted(self) -> None:
        for port in (
            CHECKER.HUB_CLIENT_EDGE_PORT,
            CHECKER.HUB_CLIENT_EDGE_PORT_LEGACY,
        ):
            with self.subTest(port=port):
                self.assertIn(
                    self.ingress(port),
                    (
                        self.ingress(CHECKER.HUB_CLIENT_EDGE_PORT),
                        self.ingress(CHECKER.HUB_CLIENT_EDGE_PORT_LEGACY),
                    ),
                )

    def test_live_boundary_admits_only_the_two_migration_ports(self) -> None:
        """The tolerance is a PAIR, not a range.

        Delete HUB_CLIENT_EDGE_PORT_LEGACY once every environment's ingress is
        on 443 -- this test is where that decision is recorded.
        """
        self.assertEqual(CHECKER.HUB_CLIENT_EDGE_PORT, 443)
        self.assertEqual(CHECKER.HUB_CLIENT_EDGE_PORT_LEGACY, 62206)
        source = pathlib.Path(CHECKER.__file__).read_text(encoding="utf-8")
        self.assertNotIn(
            '("udp", 443, 443, "cidr_ipv4", HUB_PUBLIC_UDP_INGRESS_CIDR)',
            source,
            "the ingress assertion must not re-pin a single port",
        )

    def test_the_worker_egress_stays_on_the_backend_port(self) -> None:
        """The edge translates; it does not renumber the backend.

        62206 on the NLB->worker egress is permanent and must not be swept up
        by the client-edge migration.
        """
        source = pathlib.Path(CHECKER.__file__).read_text(encoding="utf-8")
        self.assertIn(
            '("udp", 62206, 62206, "security_group", worker_group_id)',
            source,
            "the worker egress must stay pinned to the backend bind port",
        )


class HubClientEdgePortMigrationLaneTest(unittest.TestCase):
    """The public Hub UDP edge may move to 443, and only in that exact shape."""

    LISTENER = "module.control.aws_lb_listener.hub[0]"
    RULE = (
        "module.control.aws_vpc_security_group_ingress_rule."
        f'hub_nlb_udp["{CHECKER.HUB_PUBLIC_UDP_INGRESS_CIDR}"]'
    )

    def _by_address(self, listener=None, rule=None):
        listener_change = {
            "actions": ["update"],
            "before": {
                "port": 62206,
                "protocol": "UDP",
                "load_balancer_arn": "arn:lb",
                "default_action": [{"type": "forward", "target_group_arn": "arn:tg"}],
            },
            "after": {
                "port": 443,
                "protocol": "UDP",
                "load_balancer_arn": "arn:lb",
                "default_action": [{"type": "forward", "target_group_arn": "arn:tg"}],
            },
        }
        rule_change = {
            "actions": ["update"],
            "before": {
                "from_port": 62206,
                "to_port": 62206,
                "ip_protocol": "udp",
                "cidr_ipv4": CHECKER.HUB_PUBLIC_UDP_INGRESS_CIDR,
                "security_group_id": "sg-hub-nlb",
            },
            "after": {
                "from_port": 443,
                "to_port": 443,
                "ip_protocol": "udp",
                "cidr_ipv4": CHECKER.HUB_PUBLIC_UDP_INGRESS_CIDR,
                "security_group_id": "sg-hub-nlb",
            },
        }
        if listener:
            listener_change["after"].update(listener)
        if rule:
            rule_change["after"].update(rule)
        return {
            self.LISTENER: {"change": listener_change},
            self.RULE: {"change": rule_change},
        }

    def _claim(self, by_address, changed=None):
        changed = changed if changed is not None else set(by_address)
        actual = {address: ["update"] for address in changed}
        return CHECKER._claim_hub_client_edge_port_migration(
            changed, actual, by_address
        )

    def test_exact_move_is_claimed_and_validates(self) -> None:
        by_address = self._by_address()
        claimed = self._claim(by_address)
        self.assertEqual(claimed, CHECKER.HUB_CLIENT_EDGE_PORT_ADDRESSES)
        CHECKER._validate_hub_client_edge_port_migration(claimed, by_address, {})

    def test_partial_move_is_not_claimable(self) -> None:
        # The listener alone would black-hole the edge; the rule alone would
        # leave the old port reachable. Neither composes.
        by_address = self._by_address()
        for address in (self.LISTENER, self.RULE):
            with self.subTest(only=address):
                self.assertIsNone(self._claim(by_address, {address}))

    def test_wrong_destination_port_is_rejected(self) -> None:
        by_address = self._by_address(listener={"port": 8443})
        claimed = self._claim(by_address)
        with self.assertRaisesRegex(CHECKER.ContractError, "UDP 62206 -> 443"):
            CHECKER._validate_hub_client_edge_port_migration(claimed, by_address, {})

    def test_changed_source_is_rejected(self) -> None:
        by_address = self._by_address(rule={"cidr_ipv4": "198.51.100.7/32"})
        claimed = self._claim(by_address)
        with self.assertRaisesRegex(CHECKER.ContractError, "admitted source"):
            CHECKER._validate_hub_client_edge_port_migration(claimed, by_address, {})

    def test_retargeted_forward_is_rejected(self) -> None:
        # The port may move; where it forwards may not.
        by_address = self._by_address(
            listener={
                "default_action": [
                    {"type": "forward", "target_group_arn": "arn:tg-other"}
                ]
            }
        )
        claimed = self._claim(by_address)
        with self.assertRaisesRegex(CHECKER.ContractError, "target group"):
            CHECKER._validate_hub_client_edge_port_migration(claimed, by_address, {})


class HubWorkerServiceClaimTest(unittest.TestCase):
    """A Hub image deploy is two addresses, so the lane must claim two.

    An ECS task definition is immutable: a new image is delete+create, and the
    service must then be updated to point at the new revision. The lane claimed
    only the task definition, so the service was left unclaimed -- and since
    composition requires the union of claims to equal the changed set exactly,
    ONE unclaimed address refuses the whole plan. No composite plan containing a
    Hub deploy could ever be admitted.
    """

    TD = CHECKER.HUB_WORKER_TASK_DEFINITION_ADDRESS
    SVC = CHECKER.HUB_WORKER_SERVICE_ADDRESS

    def claim(self, actual):
        by = {
            address: {
                "address": address,
                "change": {"actions": actions, "before": {}, "after": {}},
            }
            for address, actions in actual.items()
        }
        return CHECKER._claim_hub_worker_image_update(set(actual), actual, by)

    def test_a_deploy_claims_the_task_definition_and_the_service(self) -> None:
        self.assertEqual(
            self.claim({self.TD: ["create", "delete"], self.SVC: ["update"]}),
            frozenset({self.TD, self.SVC}),
        )

    def test_the_standalone_branch_admits_the_shape_a_real_deploy_produces(self) -> None:
        """The dispatch predicate must be the CLAIM, not `changed == {TD}`.

        Replacing the task definition a live ECS service references always
        updates that service too, so `changed` on a real Hub image deploy is
        {TD, SVC} -- never the single-address literal the branch used to
        require. It therefore fell through to the terminal reject, and the
        composer could not rescue it either: composition needs two or more
        claims and a Hub deploy is one. The Hub image was undeployable through
        the governed lane, which is why sandbox sat on a pre-1.1 image while
        every other component rolled forward.
        """
        actual = {self.TD: ["delete", "create"], self.SVC: ["update"]}
        changed = set(actual)
        claimed = self.claim(actual)

        # The new predicate matches.
        self.assertIsNotNone(claimed)
        self.assertEqual(set(claimed), changed)
        # The old one did not -- this is the exact regression.
        self.assertNotEqual(changed, {self.TD})

    def test_a_lone_service_update_is_never_claimed(self) -> None:
        """The service rides along with a replacement or not at all.

        Otherwise this lane becomes a route for editing the Hub service --
        desired count, role, network -- with no immutable replacement forcing
        the deeper validation.
        """
        self.assertIsNone(self.claim({self.SVC: ["update"]}))

    def test_a_task_definition_replacement_alone_still_claims(self) -> None:
        """Terraform can plan the revision without the service following yet."""
        self.assertEqual(
            self.claim({self.TD: ["create", "delete"]}), frozenset({self.TD})
        )

    def test_a_destructive_service_change_is_left_unclaimed(self) -> None:
        """Only an in-place update rides along; a delete must fail closed.

        Leaving it unclaimed is the fail-closed outcome: the union check then
        refuses the composite rather than admitting a service teardown.
        """
        claimed = self.claim({self.TD: ["create", "delete"], self.SVC: ["delete"]})
        self.assertEqual(claimed, frozenset({self.TD}))
        self.assertNotIn(self.SVC, claimed)

    def test_a_non_replacement_task_definition_claims_nothing(self) -> None:
        self.assertIsNone(self.claim({self.TD: ["update"], self.SVC: ["update"]}))

    def test_claiming_the_service_also_validates_it(self) -> None:
        """Claiming without validating would be widening, not fixing."""
        calls = []

        def spy(by_address, *, require_planned_target=False):
            calls.append(require_planned_target)

        with mock.patch.object(
            CHECKER, "_check_hub_worker_image_update", lambda by: None
        ), mock.patch.object(
            CHECKER, "_check_hub_service_task_revision_update", spy
        ):
            CHECKER._validate_hub_worker_image_update(
                frozenset({self.TD, self.SVC}), {}, {}
            )
        self.assertEqual(
            calls,
            [True],
            "the service slice must be validated, and bound to the revision "
            "this same plan creates",
        )

    def test_the_real_service_validator_runs_end_to_end(self) -> None:
        """Drive the REAL collaborator, not a spy.

        Every other validation test here mocks
        `_check_hub_service_task_revision_update`, so they assert the
        interaction and never exercise the real call. A signature or
        planned-target-resolution mismatch would keep the unit suite green and
        fail only in CI against a live hub-deploy plan. Only
        `_check_hub_worker_image_update` stays stubbed -- its field contract
        needs a full task-definition fixture and is covered on its own.
        """
        new_arn = "arn:aws:ecs:us-east-2:767397897469:task-definition/hub:4"
        by_address = {
            self.TD: {
                "address": self.TD,
                "change": {"actions": ["create", "delete"], "after": {"arn": new_arn}},
            },
            self.SVC: {
                "address": self.SVC,
                "change": {
                    "actions": ["update"],
                    "before": {"task_definition": "…/hub:3", "desired_count": 2},
                    "after": {"task_definition": new_arn, "desired_count": 2},
                },
            },
        }
        with mock.patch.object(
            CHECKER, "_check_hub_worker_image_update", lambda by: None
        ):
            CHECKER._validate_hub_worker_image_update(
                frozenset({self.TD, self.SVC}), by_address, {}
            )

            # A service pointed at some OTHER revision must be refused by the
            # real check -- this is the "revision this same plan creates" bind.
            by_address[self.SVC]["change"]["after"]["task_definition"] = "…/hub:9"
            with self.assertRaises(CHECKER.ContractError):
                CHECKER._validate_hub_worker_image_update(
                    frozenset({self.TD, self.SVC}), by_address, {}
                )

            # A second field moving alongside the revision must also be refused.
            by_address[self.SVC]["change"]["after"]["task_definition"] = new_arn
            by_address[self.SVC]["change"]["after"]["desired_count"] = 5
            with self.assertRaises(CHECKER.ContractError):
                CHECKER._validate_hub_worker_image_update(
                    frozenset({self.TD, self.SVC}), by_address, {}
                )

    def test_the_service_validator_is_not_run_when_unclaimed(self) -> None:
        """A task-definition-only slice has no service to validate."""
        calls = []
        with mock.patch.object(
            CHECKER, "_check_hub_worker_image_update", lambda by: None
        ), mock.patch.object(
            CHECKER,
            "_check_hub_service_task_revision_update",
            lambda by, **kw: calls.append(kw),
        ):
            CHECKER._validate_hub_worker_image_update(frozenset({self.TD}), {}, {})
        self.assertEqual(calls, [])


class ExecPolicyLanePrecedenceTest(unittest.TestCase):
    """The exec-policy lane must stand down when staging claims the same rows.

    Consumer staging resolves the SAME exec policies as part of a strictly
    larger, more deeply validated slice. Two lanes claiming one address is
    ambiguous ownership, which fails composition closed -- so precedence is
    explicit rather than incidental.
    """

    POLICIES = frozenset(
        f'module.control.aws_iam_role_policy.authority_exec["layerv-nhp-sandbox-ca-{s}"]'
        for s in ("ia", "ra", "icr")
    )

    def claim(self, changed, staged):
        actual = {a: ["update"] for a in changed}
        with mock.patch.object(
            CHECKER,
            "_claim_authority_proof_consumer_staging",
            lambda *a, **k: frozenset(staged) if staged else None,
        ):
            return CHECKER._claim_authority_hub_exec_policy_update(
                set(changed), actual, {}
            )

    def test_claims_the_policies_when_staging_is_absent(self) -> None:
        claimed = self.claim(self.POLICIES, staged=None)
        self.assertEqual(claimed, self.POLICIES)

    def test_stands_down_when_staging_claims_them(self) -> None:
        self.assertIsNone(self.claim(self.POLICIES, staged=self.POLICIES))

    def test_ignores_exec_policies_outside_the_reviewed_set(self) -> None:
        foreign = 'module.control.aws_iam_role_policy.authority_exec["other-fn"]'
        self.assertIsNone(self.claim({foreign}, staged=None))

    def test_ignores_non_update_actions(self) -> None:
        changed = set(self.POLICIES)
        with mock.patch.object(
            CHECKER, "_claim_authority_proof_consumer_staging", lambda *a, **k: None
        ):
            self.assertIsNone(
                CHECKER._claim_authority_hub_exec_policy_update(
                    changed, {a: ["create"] for a in changed}, {}
                )
            )

    def test_claims_every_known_authority_function_not_just_the_hub_three(self) -> None:
        """The runtime grew; the claim must track it.

        The hub trio was the whole runtime when this lane was written. Per-cell
        and proof functions were added later and their exec policies move in the
        same plan, so scoping the claim to the hub subset left a real plan
        unadmittable while its shape was identical -- the failure a live PR hit
        with all thirteen policies present.
        """
        every = frozenset(
            f'module.control.aws_iam_role_policy.authority_exec["{fn}"]'
            for fn in CHECKER.AUTHORITY_RUNTIME_FUNCTIONS_WITH_PROOF
        )
        # Guard the premise: this is only meaningful while the runtime really is
        # wider than the hub trio.
        self.assertGreater(len(every), len(self.POLICIES))
        self.assertEqual(self.claim(every, staged=None), every)

    def test_still_refuses_an_exec_policy_for_an_unknown_function(self) -> None:
        """Widening tracks the function map; it does not open the lane up."""
        unknown = 'module.control.aws_iam_role_policy.authority_exec["layerv-nhp-sandbox-ca-nope"]'
        self.assertIsNone(self.claim({unknown}, staged=None))
        # A known policy alongside an unknown one claims only the known address,
        # so the unknown one falls through to the terminal rejection rather than
        # riding along.
        known = next(iter(self.POLICIES))
        self.assertEqual(self.claim({known, unknown}, staged=None), frozenset({known}))


class StandaloneExecPolicyLaneTest(unittest.TestCase):
    """The exec policies moving alone must be admissible too.

    Composition requires two or more claims by design, so a plan whose entire
    pending work is the three reviewed exec-policy updates would otherwise be
    rejected -- even though the identical claim and validator are already
    trusted inside a composed plan.
    """

    POLICIES = tuple(
        f'module.control.aws_iam_role_policy.authority_exec["layerv-nhp-sandbox-ca-{s}"]'
        for s in ("ia", "ra", "icr")
    )

    def by_address(self, moved_role=False, actions=("update",)):
        return {
            address: {
                "address": address,
                "mode": "managed",
                "deposed": None,
                "type": "aws_iam_role_policy",
                "change": {
                    "actions": list(actions),
                    "before": {"name": "p", "role": "r1", "policy": "{}"},
                    "after": {
                        "name": "p",
                        "role": "r2" if moved_role else "r1",
                        "policy": '{"a":1}',
                    },
                },
            }
            for address in self.POLICIES
        }

    def test_the_standalone_shape_validates(self) -> None:
        by = self.by_address()
        CHECKER._validate_authority_hub_exec_policy_update(
            frozenset(self.POLICIES), by, {}
        )

    def test_a_moved_role_still_fails_closed(self) -> None:
        with self.assertRaisesRegex(CHECKER.ContractError, "moved 'role'"):
            CHECKER._validate_authority_hub_exec_policy_update(
                frozenset(self.POLICIES), self.by_address(moved_role=True), {}
            )

    def test_a_non_update_action_still_fails_closed(self) -> None:
        with self.assertRaisesRegex(CHECKER.ContractError, "is not an update"):
            CHECKER._validate_authority_hub_exec_policy_update(
                frozenset(self.POLICIES), self.by_address(actions=("create",)), {}
            )


class ProofMutationDecryptUpdateTest(unittest.TestCase):
    """The one-off ca-pm policy lane admits only the exact decrypt addition."""

    def by_address(self):
        after_policy = json.loads(proof_runtime_exec_policy())
        before_policy = copy.deepcopy(after_policy)
        before_policy["Statement"] = [
            statement
            for statement in before_policy["Statement"]
            if statement["Sid"] != "ProofDynamoDBDecrypt"
        ]
        address = CHECKER.AUTHORITY_PROOF_EXEC_POLICY_ADDRESS
        return {
            address: {
                "address": address,
                "mode": "managed",
                "deposed": None,
                "type": "aws_iam_role_policy",
                "change": {
                    "actions": ["update"],
                    "before": {
                        "name": "ca-pm",
                        "role": "ca-pm",
                        "policy": json.dumps(before_policy),
                    },
                    "after": {
                        "name": "ca-pm",
                        "role": "ca-pm",
                        "policy": json.dumps(after_policy),
                    },
                    "before_sensitive": {},
                    "after_sensitive": {},
                    "after_unknown": {},
                },
            }
        }

    def test_exact_decrypt_addition_passes(self) -> None:
        CHECKER._check_authority_proof_mutation_decrypt_update(self.by_address())

    def test_extra_policy_change_fails_closed(self) -> None:
        by_address = self.by_address()
        change = by_address[CHECKER.AUTHORITY_PROOF_EXEC_POLICY_ADDRESS]["change"]
        policy = json.loads(change["after"]["policy"])
        policy["Statement"][0]["Action"].append("ec2:DescribeInstances")
        change["after"]["policy"] = json.dumps(policy)
        with self.assertRaisesRegex(
            CHECKER.ContractError, "changed more than the reviewed statement"
        ):
            CHECKER._check_authority_proof_mutation_decrypt_update(by_address)

    def test_decrypt_condition_drift_fails_closed(self) -> None:
        by_address = self.by_address()
        change = by_address[CHECKER.AUTHORITY_PROOF_EXEC_POLICY_ADDRESS]["change"]
        policy = json.loads(change["after"]["policy"])
        decrypt = next(
            statement
            for statement in policy["Statement"]
            if statement["Sid"] == "ProofDynamoDBDecrypt"
        )
        decrypt["Condition"]["StringEquals"]["kms:ViaService"] = (
            "secretsmanager.us-east-2.amazonaws.com"
        )
        change["after"]["policy"] = json.dumps(policy)
        with self.assertRaisesRegex(
            CHECKER.ContractError, "decrypt statement drifted"
        ):
            CHECKER._check_authority_proof_mutation_decrypt_update(by_address)


class SliceAndAuthorityDigestDriftCompositionTest(unittest.TestCase):
    """The runtime-slice re-projection and the image digest, in one plan.

    Each already has a reviewed kind; neither matched their UNION, so a plan
    carrying both fell to the terminal rejection. They arrive together by
    construction -- the digest rolls on every upstream publish while the slice
    re-projects on every partial-apply retry -- and the result was a 27-entry
    rejection that blocked every Control plan, including the ones that would
    have fixed it.
    """

    DIGEST = CHECKER._AUTHORITY_DIGEST_ADDRESS
    SLICE = sorted(CHECKER.AUTHORITY_RUNTIME_RESOURCES)[0]

    def entry(self, address):
        return {
            "address": address,
            "mode": "managed",
            "type": "x",
            "change": {"actions": ["no-op"], "before": {"a": 1}, "after": {"a": 2}},
        }

    def compose(self, addresses, digest_raises=None):
        drift = [self.entry(a) for a in addresses]
        def digest_check(item, by_address, *, spec):
            if digest_raises:
                raise CHECKER.ContractError(digest_raises)
        with mock.patch.object(CHECKER, "_check_digest_normalization", digest_check), \
             mock.patch.object(CHECKER, "_drift_is_first_projection_only", lambda item: False):
            return CHECKER._check_state_normalization_drift(drift, {}, refresh_only=True)

    def test_the_real_sandbox_shape_is_admitted(self) -> None:
        """The exact 27-entry drift that blocked every Control plan.

        22 runtime-slice + 4 proof-function exec identities + 1 digest.
        AUTHORITY_RUNTIME_RESOURCES covers only the THIRTEEN runtime functions, so
        the two proof functions (ca-pcr, ca-pm) sit outside the slice and their
        exec role and policy broke the subset test -- even though their drift is
        the same benign re-projection as the other thirteen.

        Built from the constants rather than a literal list, so it keeps
        describing reality if the function set changes.
        """
        drift = []
        for function in sorted(CHECKER.AUTHORITY_RUNTIME_FUNCTIONS_WITH_PROOF):
            for template in (
                'module.control.aws_iam_role.authority_exec["{}"]',
                'module.control.aws_iam_role_policy.authority_exec["{}"]',
            ):
                drift.append(self.entry(template.format(function)))
        drift.append(self.entry(CHECKER._AUTHORITY_DIGEST_ADDRESS))
        self.assertEqual(len(drift), 31)
        with mock.patch.object(
            CHECKER, "_check_digest_normalization", lambda *a, **k: None
        ), mock.patch.object(
            CHECKER, "_drift_is_first_projection_only", lambda item: False
        ):
            self.assertEqual(
                CHECKER._check_state_normalization_drift(drift, {}, refresh_only=False),
                CHECKER._SLICE_AND_AUTHORITY_DIGEST_NORMALIZATION_KIND,
            )

    def test_the_extension_is_exec_identities_not_all_proof_resources(self) -> None:
        """Scope guard: admitting all 33 proof resources would be a widening.

        Only the exec role and its inline policy are added, because policy
        CONTENT is validated for every plan by _check_planned_security outside
        this dispatch. A proof lambda, alias or concurrency config drifting is
        not covered by that and must keep failing closed.
        """
        self.assertTrue(
            CHECKER._AUTHORITY_EXEC_IDENTITY_ADDRESSES
            < set(CHECKER.AUTHORITY_PROOF_RESOURCES)
            | set(CHECKER.AUTHORITY_RUNTIME_RESOURCES),
            "exec identities must be a strict subset, never the whole proof set",
        )
        for address in sorted(CHECKER._AUTHORITY_EXEC_IDENTITY_ADDRESSES):
            with self.subTest(address=address):
                self.assertRegex(
                    address,
                    r"^module\.control\.aws_iam_role(_policy)?\.authority_exec\[",
                )
        # A proof resource that is NOT an exec identity must still fail closed.
        other = sorted(
            set(CHECKER.AUTHORITY_PROOF_RESOURCES)
            - CHECKER._AUTHORITY_EXEC_IDENTITY_ADDRESSES
            - set(CHECKER.AUTHORITY_RUNTIME_RESOURCES)
        )
        self.assertTrue(other, "fixture assumption: proof set has non-exec members")
        with mock.patch.object(
            CHECKER, "_check_digest_normalization", lambda *a, **k: None
        ), mock.patch.object(
            CHECKER, "_drift_is_first_projection_only", lambda item: False
        ):
            with self.assertRaises(CHECKER.ContractError):
                CHECKER._check_state_normalization_drift(
                    [
                        self.entry(sorted(CHECKER._AUTHORITY_EXEC_IDENTITY_ADDRESSES)[0]),
                        self.entry(CHECKER._AUTHORITY_DIGEST_ADDRESS),
                        self.entry(other[0]),
                    ],
                    {},
                    refresh_only=False,
                )

    def test_the_pair_composes(self) -> None:
        self.assertEqual(
            self.compose([self.SLICE, self.DIGEST]),
            CHECKER._SLICE_AND_AUTHORITY_DIGEST_NORMALIZATION_KIND,
        )

    def test_the_digest_half_still_runs_its_own_validator(self) -> None:
        """Composition must not skip either half's checks."""
        with self.assertRaisesRegex(CHECKER.ContractError, "digest rejected"):
            self.compose([self.SLICE, self.DIGEST], digest_raises="digest rejected")

    def test_the_digest_alone_does_not_take_the_composed_route(self) -> None:
        """One kind must keep being judged by the stricter single-kind chain."""
        self.assertNotEqual(
            self.compose([self.DIGEST]),
            CHECKER._SLICE_AND_AUTHORITY_DIGEST_NORMALIZATION_KIND,
        )

    def test_the_slice_alone_does_not_take_the_composed_route(self) -> None:
        self.assertEqual(
            self.compose([self.SLICE]), "authority-runtime-slice-normalization"
        )

    def test_a_third_address_refuses_the_composition(self) -> None:
        """One unaccounted address and the whole plan must fail closed."""
        with self.assertRaises(CHECKER.ContractError):
            self.compose(
                [self.SLICE, self.DIGEST, "module.control.aws_iam_role.flow_logs"]
            )

    def test_the_pair_is_gated_to_the_stricter_half_plan_modes(self) -> None:
        """Composing must not widen the plan surface beyond the slice half.

        Behavioural on purpose. The first version of this asserted the error
        STRING appeared in the source, which survived replacing the condition
        with `if False` -- it reported the gate as covered when it was gone.
        """
        kind = CHECKER._SLICE_AND_AUTHORITY_DIGEST_NORMALIZATION_KIND
        allowed = sorted(CHECKER._AUTHORITY_RUNTIME_NORMALIZATION_PLAN_MODES)[0]
        CHECKER._require_slice_and_digest_plan_mode(kind, allowed)

        rejected = "authority-image-update"
        self.assertNotIn(
            rejected,
            CHECKER._AUTHORITY_RUNTIME_NORMALIZATION_PLAN_MODES,
            "fixture assumption: pick a mode the slice half rejects",
        )
        with self.assertRaisesRegex(
            CHECKER.ContractError, "runtime-slice state normalization"
        ):
            CHECKER._require_slice_and_digest_plan_mode(kind, rejected)

        # Other kinds must pass straight through this gate untouched.
        CHECKER._require_slice_and_digest_plan_mode("no-op", rejected)

    def test_the_composed_drift_kind_may_ride_a_composed_plan(self) -> None:
        """A widening, and the one it is scoped to.

        `composed-` is the strongest shape guarantee this checker produces:
        every changed address belongs to a reviewed transition, the transitions
        are pairwise disjoint, their union is exactly the change set, and each
        ran its own deep validator. Several single modes already allowed carry a
        weaker guarantee.
        """
        composed = "composed-authority-hub-exec-policy-update-with-provisioned-cell-status-update"
        CHECKER._require_slice_and_digest_plan_mode(
            CHECKER._SLICE_AND_AUTHORITY_DIGEST_NORMALIZATION_KIND, composed
        )

    def test_the_slice_only_kind_is_not_widened(self) -> None:
        """The pre-existing kind keeps its narrower binding."""
        composed = "composed-authority-hub-exec-policy-update-with-provisioned-cell-status-update"
        with self.assertRaises(CHECKER.ContractError):
            CHECKER._require_slice_and_digest_plan_mode(
                "authority-runtime-slice-normalization", composed
            )

    def test_an_uncomposed_transition_is_still_refused(self) -> None:
        """The widening is to composed plans, not to plans in general."""
        for mode in ("authority-image-update", "redis-split-transition", "hub-worker-image-update"):
            with self.subTest(mode=mode):
                self.assertNotIn(mode, CHECKER._AUTHORITY_RUNTIME_NORMALIZATION_PLAN_MODES)
                with self.assertRaises(CHECKER.ContractError):
                    CHECKER._require_slice_and_digest_plan_mode(
                        CHECKER._SLICE_AND_AUTHORITY_DIGEST_NORMALIZATION_KIND, mode
                    )

    def test_one_gate_covers_the_slice_kind_and_the_composed_pair(self) -> None:
        """A duplicated gate is a gate that drifts.

        Code review flagged the risk directly: the composed kind originally
        carried a private copy of the slice kind's plan-mode rule, so anything a
        future change added under the slice kind would silently not apply to the
        composed one -- and the composed one is the shape the sandbox actually
        produces. Both now go through the same function, keyed on one set.
        """
        self.assertEqual(
            CHECKER._RUNTIME_SLICE_NORMALIZATION_KINDS,
            frozenset(
                {
                    "authority-runtime-slice-normalization",
                    CHECKER._SLICE_AND_AUTHORITY_DIGEST_NORMALIZATION_KIND,
                }
            ),
        )
        rejected = "authority-image-update"
        for kind in sorted(CHECKER._RUNTIME_SLICE_NORMALIZATION_KINDS):
            with self.subTest(kind=kind):
                with self.assertRaises(CHECKER.ContractError):
                    CHECKER._require_slice_and_digest_plan_mode(kind, rejected)

        source = pathlib.Path(CHECKER.__file__).read_text(encoding="utf-8")
        self.assertNotIn(
            'if normalization_drift_kind == "authority-runtime-slice-normalization":',
            source,
            "the slice kind must not regain a second, private gate",
        )

    def test_the_gate_is_actually_wired_into_check_plan(self) -> None:
        """A gate nothing calls is a gate that does not exist.

        The behavioural test above proves the function refuses; this proves
        check_plan still invokes it. Deleting the call site passed every other
        assertion in this class.
        """
        import ast

        source = pathlib.Path(CHECKER.__file__).read_text(encoding="utf-8")
        tree = ast.parse(source)
        check_plan = next(
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef) and node.name == "check_plan"
        )
        called = {
            node.func.id
            for node in ast.walk(check_plan)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        }
        self.assertIn(
            "_require_slice_and_digest_plan_mode",
            called,
            "check_plan no longer gates the composed normalization kind",
        )


class DualDigestNormalizationTest(unittest.TestCase):
    """Both publisher-owned digests may drift at once, and must be absorbable.

    Each is already an admitted normalization alone, and they are independent --
    the Authority and Hub publishers advance their own parameter. Handling one
    at a time deadlocks: reducing two drifts to one needs an apply to absorb the
    other, and the apply is what this check gates. Any SSM write also bumps the
    version, so rewriting a value back to what is deployed re-drifts it.
    """

    AUTH = "module.control.aws_ssm_parameter.authority_image_digest"
    HUB = "module.control.aws_ssm_parameter.hub_image_digest"

    def drift(self, addresses):
        return [{"address": a, "change": {"before": {}, "after": {}}} for a in addresses]

    def test_both_digests_are_admitted_together(self) -> None:
        seen = []
        with (
            mock.patch.object(
                CHECKER, "_partition_first_projection_drift",
                lambda d: ([], d),
            ),
            mock.patch.object(
                CHECKER, "_check_digest_normalization",
                lambda item, by, spec: seen.append(item["address"]),
            ),
        ):
            kind = CHECKER._check_state_normalization_drift(
                self.drift([self.AUTH, self.HUB]), {}, refresh_only=True
            )
        self.assertEqual(kind, "authority-and-hub-digest")
        # Each drift is still validated against its OWN spec.
        self.assertEqual(sorted(seen), sorted([self.AUTH, self.HUB]))

    def test_an_unrelated_second_drift_still_fails_closed(self) -> None:
        with mock.patch.object(
            CHECKER, "_partition_first_projection_drift", lambda d: ([], d)
        ):
            with self.assertRaises(CHECKER.ContractError):
                CHECKER._check_state_normalization_drift(
                    self.drift([self.AUTH, "module.control.aws_s3_bucket.stray"]),
                    {},
                    refresh_only=True,
                )

    def test_a_failing_digest_still_fails_closed(self) -> None:
        def boom(item, by, spec):
            raise CHECKER.ContractError("digest identity is wrong")

        with (
            mock.patch.object(
                CHECKER, "_partition_first_projection_drift", lambda d: ([], d)
            ),
            mock.patch.object(CHECKER, "_check_digest_normalization", boom),
        ):
            with self.assertRaisesRegex(CHECKER.ContractError, "digest identity"):
                CHECKER._check_state_normalization_drift(
                    self.drift([self.AUTH, self.HUB]), {}, refresh_only=True
                )


class DualDigestPlanModeGateTest(unittest.TestCase):
    """The pair may ride the Hub image update it causes -- and nothing else."""

    def gate(self, plan_mode, plan=None):
        return CHECKER._require_normalization_plan_mode(
            "authority-and-hub-digest", plan_mode, plan if plan is not None else {}
        )

    def test_refresh_only_no_op_is_allowed(self) -> None:
        self.gate("no-op")

    def test_the_hub_image_update_is_allowed(self) -> None:
        self.gate("hub-worker-image-update", {"resource_changes": []})

    def test_a_composed_plan_carrying_it_is_allowed(self) -> None:
        self.gate(
            "composed-authority-hub-exec-policy-update-with-hub-worker-image-update",
            {"resource_changes": []},
        )

    def test_an_unrelated_transition_is_rejected(self) -> None:
        for mode in ("redis-split-transition", "authority-image-update",
                     "composed-authority-proof-enable-with-authority-proof-consumer-staging"):
            with self.subTest(mode=mode):
                with self.assertRaisesRegex(CHECKER.ContractError, "may accompany only"):
                    self.gate(mode, {"resource_changes": []})

    def test_a_no_op_with_resource_changes_still_requires_refresh_only(self) -> None:
        with self.assertRaisesRegex(CHECKER.ContractError, "refresh-only"):
            self.gate("no-op", {"resource_changes": []})


class ProvisionedCellStatusUpdateTest(unittest.TestCase):
    """The reviewed cell-lifecycle transition, and what it must NOT admit.

    Draining a cell stops the Authority placing new agents on it. That is a
    legitimate reviewed change, but the same plan shape must never be able to
    carry an endpoint, server-key, or weight edit: those decide where an agent
    is sent and which server identity it trusts.
    """

    def _plan(self, cell, overrides=None):
        # `overrides` is a dict rather than **kwargs: one of the fields under
        # test is literally named cell_id, which collides with the parameter.
        expected = dict(CHECKER.PROVISIONED_CELL_DYNAMODB_ITEMS[cell])
        expected.update(overrides or {})
        address = CHECKER.PROVISIONED_CELL_ADDRESSES[cell]
        return {address: {"change": {"after": {"item": json.dumps(expected)}}}}

    def test_status_only_update_is_admitted(self):
        cell_id = "cell1"
        address = CHECKER.PROVISIONED_CELL_ADDRESSES[cell_id]
        by_address = self._plan(cell_id)
        self.assertTrue(
            CHECKER._claim_provisioned_cell_status_update(
                {address}, {address: ["update"]}, by_address
            ),
            "a status/updated_at-only catalog update must be admitted",
        )

    def test_endpoint_or_key_edit_is_rejected(self):
        cell_id = "cell1"
        address = CHECKER.PROVISIONED_CELL_ADDRESSES[cell_id]
        # DynamoDB-typed values, matching the real catalog item shape; a raw
        # value would be rejected for the wrong reason and prove nothing.
        for field, value in (
            ("nhp_host", {"S": "attacker.example"}),
            ("server_public_key_b64", {"S": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}),
            ("nhp_port", {"N": "1"}),
            ("selection_weight", {"N": "9"}),
            ("cell_id", {"S": "cell0"}),
        ):
            with self.subTest(field=field):
                self.assertFalse(
                    CHECKER._claim_provisioned_cell_status_update(
                        {address}, {address: ["update"]}, self._plan(cell_id, {field: value})
                    ),
                    f"a {field} edit must not ride the status-update lane",
                )

    def test_replace_is_rejected(self):
        """Only in-place updates. A replace would re-create the row."""
        cell_id = "cell1"
        address = CHECKER.PROVISIONED_CELL_ADDRESSES[cell_id]
        self.assertFalse(
            CHECKER._claim_provisioned_cell_status_update(
                {address}, {address: ["delete", "create"]}, self._plan(cell_id)
            )
        )

    def test_claims_only_catalog_addresses(self):
        """The lane never claims an address outside the cell catalog.

        It is composable, so it takes only what it owns; a plan carrying an
        address that NO lane claims is rejected by composition, whose union
        must equal `changed` exactly. Claiming the stray here instead would be
        precisely the "widen a plan by absorbing a stray change" failure the
        composition contract exists to prevent.
        """
        address = CHECKER.PROVISIONED_CELL_ADDRESSES["cell1"]
        foreign = "module.control.aws_iam_role.something_else"
        by_address = self._plan("cell1")
        by_address[foreign] = {"change": {"after": {}}}
        claimed = CHECKER._claim_provisioned_cell_status_update(
            {address, foreign}, {address: ["update"], foreign: ["update"]}, by_address
        )
        self.assertEqual(claimed, frozenset({address}))
        self.assertNotIn(foreign, claimed or frozenset())


def _legacy_pre_key_runtime_input() -> dict:
    """The contract as it exists in APPLIED state: no authority_image_source.

    Every fixture in this file describes the world under the current schema, so
    a schema transition -- where the "before" side is the previously applied
    shape -- was untested by construction. That is not hypothetical: the
    pinned-to-publish change failed the live plan five separate times, each on
    an assertion no local fixture could reach, because nothing here could
    express the state being migrated FROM. This is the missing half.
    """
    payload = authority_runtime_input_fixture()
    payload["authority_runtime_contract"]["global"].pop("authority_image_source")
    return payload


def _authority_foundation_change(before: dict, after: dict) -> dict:
    """A realistic foundation_contract update between two runtime inputs.

    Modelled on what Terraform actually emits for this resource, so the
    envelope assertions in _check_authority_image_foundation_update are
    exercised rather than bypassed: output mirrors input on the before side,
    after carries no output, the id is stable, and the unknown/sensitive masks
    are the value-free object shapes.
    """
    identifier = "8f14e45f-ceea-467a-9c1d-2b0aa0a1a1a1"
    contract_shape = CHECKER._mapping_shape(
        after["authority_runtime_contract"]
    )
    return {
        "actions": ["update"],
        "before": {
            "id": identifier,
            "input": copy.deepcopy(before),
            "output": copy.deepcopy(before),
            "triggers_replace": None,
        },
        "after": {
            "id": identifier,
            "input": copy.deepcopy(after),
            "triggers_replace": None,
        },
        "after_unknown": {
            "input": {"authority_runtime_contract": contract_shape},
            "output": True,
        },
        "before_sensitive": {
            "input": {"authority_runtime_contract": contract_shape},
            "output": {"authority_runtime_contract": contract_shape},
        },
        "after_sensitive": {
            "input": {"authority_runtime_contract": contract_shape},
            "output": {},
        },
    }


def _foundation_by_address(change: dict) -> dict:
    return {
        CHECKER.AUTHORITY_IMAGE_UPDATE_FOUNDATION_ADDRESS: {
            "mode": "managed",
            "type": "terraform_data",
            "change": change,
        }
    }


def _migrated_publish_input(before: dict, image_uri: str | None = None) -> dict:
    """Apply exactly the pinned-to-publish migration to a runtime input."""
    after = copy.deepcopy(before)
    global_contract = after["authority_runtime_contract"]["global"]
    global_contract.pop("authority_image_digest", None)
    global_contract["authority_image_source"] = "publish_parameter"
    if image_uri is not None:
        after["authority_image_uri"] = image_uri
    for evidence in CHECKER._authority_basis_evidence(after):
        # The migration edits the basis manifest, so its identity moves.
        evidence["sha256"] = "d" * 64
        evidence["source_commit"] = "e" * 40
    return after


def _publish_tracking_runtime_input() -> dict:
    """The fixture as a publish-tracking contract: source switched, digest gone."""
    payload = authority_runtime_input_fixture()
    global_contract = payload["authority_runtime_contract"]["global"]
    global_contract["authority_image_source"] = "publish_parameter"
    global_contract.pop("authority_image_digest", None)
    return payload


class AuthorityImageSourceTests(unittest.TestCase):
    """The image source the deploy path resolves through.

    The invariant that survives both sources is that the Lambdas run an
    immutable repository@sha256 reference. What differs is where the digest
    comes from, and a contract must not be ambiguous about which applies.
    """

    def test_publish_tracking_binding_is_admitted(self) -> None:
        payload = _publish_tracking_runtime_input()
        self.assertTrue(
            CHECKER._require_authority_runtime_binding({"input": payload})
        )

    def test_pinned_binding_is_still_admitted(self) -> None:
        payload = authority_runtime_input_fixture()
        self.assertTrue(
            CHECKER._require_authority_runtime_binding({"input": payload})
        )

    def test_publish_tracking_must_not_also_name_a_digest(self) -> None:
        payload = _publish_tracking_runtime_input()
        payload["authority_runtime_contract"]["global"][
            "authority_image_digest"
        ] = "sha256:" + "1" * 64
        with self.assertRaises(CHECKER.ContractError):
            CHECKER._require_authority_runtime_binding({"input": payload})

    def test_pinned_uri_must_match_the_named_digest(self) -> None:
        payload = authority_runtime_input_fixture()
        repository = payload["authority_runtime_contract"]["global"][
            "authority_repository_url"
        ]
        payload["authority_image_uri"] = f"{repository}@sha256:" + "2" * 64
        with self.assertRaises(CHECKER.ContractError):
            CHECKER._require_authority_runtime_binding({"input": payload})

    def test_absent_source_is_the_legacy_pinned_shape(self) -> None:
        """The currently-applied state predates the key and must still validate.

        It is the "before" side of every plan until the first apply carrying
        the new schema lands, so refusing it would make the change unappliable.
        """
        payload = authority_runtime_input_fixture()
        payload["authority_runtime_contract"]["global"].pop(
            "authority_image_source"
        )
        self.assertTrue(
            CHECKER._require_authority_runtime_binding({"input": payload})
        )

    def test_absent_source_still_requires_a_matching_digest(self) -> None:
        """Absent means pinned, not unconstrained -- it cannot track publishes."""
        payload = authority_runtime_input_fixture()
        global_contract = payload["authority_runtime_contract"]["global"]
        global_contract.pop("authority_image_source")
        global_contract["authority_image_digest"] = "sha256:" + "9" * 64
        with self.assertRaises(CHECKER.ContractError):
            CHECKER._require_authority_runtime_binding({"input": payload})

    def test_migration_from_pinned_to_publish_is_admitted(self) -> None:
        """The one-time schema change this checker had to be taught.

        Exactly two things move: the basis digest goes and the source arrives.
        """
        before = authority_runtime_input_fixture()
        after = _publish_tracking_runtime_input()
        expected = copy.deepcopy(before)
        expected["authority_image_uri"] = after["authority_image_uri"]
        expected_global = expected["authority_runtime_contract"]["global"]
        expected_global.pop("authority_image_digest", None)
        expected_global["authority_image_source"] = "publish_parameter"
        self.assertEqual(expected, after)

    def test_migration_must_not_move_anything_else(self) -> None:
        before = authority_runtime_input_fixture()
        after = _publish_tracking_runtime_input()
        after["authority_runtime_contract"]["global"][
            "regional_lambda_concurrency_quota"
        ] = 999
        expected = copy.deepcopy(before)
        expected["authority_image_uri"] = after["authority_image_uri"]
        expected_global = expected["authority_runtime_contract"]["global"]
        expected_global.pop("authority_image_digest", None)
        expected_global["authority_image_source"] = "publish_parameter"
        self.assertNotEqual(expected, after)

    def test_migration_evidence_must_be_uniform(self) -> None:
        """Evidence may move with the manifest edit, but only in lockstep.

        The migration edits the basis file, so its sha256 and blob-owning
        commit necessarily change. Admitting that must not admit a contract
        whose objects disagree about which basis they came from.
        """
        payload = _publish_tracking_runtime_input()
        objects = CHECKER._authority_basis_evidence(payload)
        self.assertGreater(len(objects), 1)
        uniform = {
            (evidence["sha256"], evidence["source_commit"])
            for evidence in objects
        }
        self.assertEqual(len(uniform), 1)
        objects[-1]["sha256"] = "c" * 64
        divergent = {
            (evidence["sha256"], evidence["source_commit"])
            for evidence in CHECKER._authority_basis_evidence(payload)
        }
        self.assertEqual(len(divergent), 2)

    def test_pinned_plan_uris_are_the_enumerated_constants(self) -> None:
        """The pinned scenario must be byte-for-byte what it was.

        Everything downstream now compares against this pair instead of the
        constants directly, so if the resolver ever stopped returning them the
        enumerated migration would silently start accepting other images.
        """
        by_address = {
            CHECKER.AUTHORITY_IMAGE_UPDATE_FOUNDATION_ADDRESS: {
                "change": {
                    "before": {"input": authority_runtime_input_fixture()},
                    "after": {"input": authority_runtime_input_fixture()},
                }
            }
        }
        self.assertEqual(
            CHECKER._authority_image_plan_uris(by_address),
            (
                CHECKER.AUTHORITY_IMAGE_UPDATE_FROM_URI,
                CHECKER.AUTHORITY_IMAGE_UPDATE_TO_URI,
            ),
        )

    def test_publish_plan_uris_come_from_the_foundation(self) -> None:
        before = _publish_tracking_runtime_input()
        after = _publish_tracking_runtime_input()
        repository = after["authority_runtime_contract"]["global"][
            "authority_repository_url"
        ]
        after["authority_image_uri"] = f"{repository}@sha256:" + "7" * 64
        by_address = {
            CHECKER.AUTHORITY_IMAGE_UPDATE_FOUNDATION_ADDRESS: {
                "change": {"before": {"input": before}, "after": {"input": after}}
            }
        }
        self.assertEqual(
            CHECKER._authority_image_plan_uris(by_address),
            (before["authority_image_uri"], after["authority_image_uri"]),
        )

    def test_publish_plan_uris_refuse_a_mutable_tag(self) -> None:
        before = _publish_tracking_runtime_input()
        after = _publish_tracking_runtime_input()
        repository = after["authority_runtime_contract"]["global"][
            "authority_repository_url"
        ]
        after["authority_image_uri"] = f"{repository}:latest"
        by_address = {
            CHECKER.AUTHORITY_IMAGE_UPDATE_FOUNDATION_ADDRESS: {
                "change": {"before": {"input": before}, "after": {"input": after}}
            }
        }
        with self.assertRaises(CHECKER.ContractError):
            CHECKER._authority_image_plan_uris(by_address)

    def test_unknown_source_is_refused(self) -> None:
        payload = _publish_tracking_runtime_input()
        payload["authority_runtime_contract"]["global"][
            "authority_image_source"
        ] = "latest"
        with self.assertRaises(CHECKER.ContractError):
            CHECKER._require_authority_runtime_binding({"input": payload})

    def test_a_mutable_tag_is_refused_under_publish_tracking(self) -> None:
        """The whole point of tracking a digest parameter rather than a tag."""
        payload = _publish_tracking_runtime_input()
        repository = payload["authority_runtime_contract"]["global"][
            "authority_repository_url"
        ]
        payload["authority_image_uri"] = f"{repository}:latest"
        with self.assertRaises(CHECKER.ContractError):
            CHECKER._require_authority_runtime_binding({"input": payload})


class AuthorityImageSchemaTransitionTests(unittest.TestCase):
    """Drive the checker through a schema transition, not just steady state.

    Every one of the five live-plan failures on the pinned-to-publish change
    was an assertion reachable only when the BEFORE side carries the previously
    applied shape. These cases reach all of them locally.
    """

    def test_legacy_to_publish_foundation_update_is_admitted(self) -> None:
        before = _legacy_pre_key_runtime_input()
        after = _migrated_publish_input(before)
        change = _authority_foundation_change(before, after)
        CHECKER._check_authority_image_foundation_update(
            _foundation_by_address(change)
        )

    def test_pinned_to_publish_foundation_update_is_admitted(self) -> None:
        before = authority_runtime_input_fixture()
        after = _migrated_publish_input(before)
        change = _authority_foundation_change(before, after)
        CHECKER._check_authority_image_foundation_update(
            _foundation_by_address(change)
        )

    def test_migration_may_also_move_the_image(self) -> None:
        """Schema and image can move together; neither ordering is required."""
        before = authority_runtime_input_fixture()
        repository = before["authority_runtime_contract"]["global"][
            "authority_repository_url"
        ]
        after = _migrated_publish_input(
            before, image_uri=f"{repository}@sha256:" + "4" * 64
        )
        change = _authority_foundation_change(before, after)
        CHECKER._check_authority_image_foundation_update(
            _foundation_by_address(change)
        )

    def test_migration_may_not_move_an_unrelated_field(self) -> None:
        before = authority_runtime_input_fixture()
        after = _migrated_publish_input(before)
        after["authority_runtime_contract"]["global"][
            "regional_lambda_concurrency_quota"
        ] = 999
        change = _authority_foundation_change(before, after)
        with self.assertRaises(CHECKER.ContractError):
            CHECKER._check_authority_image_foundation_update(
                _foundation_by_address(change)
            )

    def test_migration_may_not_leave_a_basis_digest_behind(self) -> None:
        before = authority_runtime_input_fixture()
        after = _migrated_publish_input(before)
        after["authority_runtime_contract"]["global"][
            "authority_image_digest"
        ] = "sha256:" + "1" * 64
        change = _authority_foundation_change(before, after)
        with self.assertRaises(CHECKER.ContractError):
            CHECKER._check_authority_image_foundation_update(
                _foundation_by_address(change)
            )

    def test_migration_may_not_desynchronize_basis_evidence(self) -> None:
        before = authority_runtime_input_fixture()
        after = _migrated_publish_input(before)
        CHECKER._authority_basis_evidence(after)[-1]["sha256"] = "f" * 64
        change = _authority_foundation_change(before, after)
        with self.assertRaises(CHECKER.ContractError):
            CHECKER._check_authority_image_foundation_update(
                _foundation_by_address(change)
            )

    def test_migration_may_not_deploy_a_mutable_tag(self) -> None:
        before = authority_runtime_input_fixture()
        repository = before["authority_runtime_contract"]["global"][
            "authority_repository_url"
        ]
        after = _migrated_publish_input(before, image_uri=f"{repository}:latest")
        change = _authority_foundation_change(before, after)
        with self.assertRaises(CHECKER.ContractError):
            CHECKER._check_authority_image_foundation_update(
                _foundation_by_address(change)
            )

    def test_steady_state_publish_update_moves_only_the_image(self) -> None:
        before = _publish_tracking_runtime_input()
        repository = before["authority_runtime_contract"]["global"][
            "authority_repository_url"
        ]
        after = copy.deepcopy(before)
        after["authority_image_uri"] = f"{repository}@sha256:" + "5" * 64
        change = _authority_foundation_change(before, after)
        CHECKER._check_authority_image_foundation_update(
            _foundation_by_address(change)
        )

    def test_steady_state_publish_update_refuses_other_movement(self) -> None:
        before = _publish_tracking_runtime_input()
        after = copy.deepcopy(before)
        after["authority_runtime_contract"]["global"]["qat1_kid"] = "moved"
        change = _authority_foundation_change(before, after)
        with self.assertRaises(CHECKER.ContractError):
            CHECKER._check_authority_image_foundation_update(
                _foundation_by_address(change)
            )

    def test_pinned_migration_is_still_the_enumerated_one(self) -> None:
        """The pinned scenario keeps its exact reviewed migration.

        Teaching the checker a second source must not turn the pinned path into
        "any image may replace any other".
        """
        before = authority_runtime_input_fixture()
        after = copy.deepcopy(before)
        repository = after["authority_runtime_contract"]["global"][
            "authority_repository_url"
        ]
        after["authority_image_uri"] = f"{repository}@sha256:" + "6" * 64
        after["authority_runtime_contract"]["global"]["authority_image_digest"] = (
            "sha256:" + "6" * 64
        )
        change = _authority_foundation_change(before, after)
        with self.assertRaises(CHECKER.ContractError):
            CHECKER._check_authority_image_foundation_update(
                _foundation_by_address(change)
            )


class AuthorityImageUriMoveLaneTests(unittest.TestCase):
    """The lane that lets a floating digest coexist with other changes."""

    def _foundation(self, before: dict, after: dict) -> dict:
        return _foundation_by_address(_authority_foundation_change(before, after))

    def test_claims_a_pure_image_move(self) -> None:
        before = _publish_tracking_runtime_input()
        after = copy.deepcopy(before)
        repository = after["authority_runtime_contract"]["global"][
            "authority_repository_url"
        ]
        after["authority_image_uri"] = f"{repository}@sha256:" + "8" * 64
        by_address = self._foundation(before, after)
        claimed = CHECKER._claim_authority_image_uri_move(
            set(by_address), {a: ["update"] for a in by_address}, by_address
        )
        self.assertEqual(
            claimed, frozenset({CHECKER.AUTHORITY_IMAGE_UPDATE_FOUNDATION_ADDRESS})
        )

    def test_claims_the_migration_and_image_move_together(self) -> None:
        """The shape the live plan actually produced.

        The recorded state can still predate the schema change, so the first
        Control plan after it carries the pinned-to-publish migration AND an
        image move in one foundation update. A claim that recognised only a
        pure image move left that plan unadmittable -- which is exactly what
        CI rejected.
        """
        before = _legacy_pre_key_runtime_input()
        repository = before["authority_runtime_contract"]["global"][
            "authority_repository_url"
        ]
        after = _migrated_publish_input(
            before, image_uri=f"{repository}@sha256:" + "9" * 64
        )
        by_address = self._foundation(before, after)
        claimed = CHECKER._claim_authority_image_uri_move(
            set(by_address), {a: ["update"] for a in by_address}, by_address
        )
        self.assertEqual(
            claimed, frozenset({CHECKER.AUTHORITY_IMAGE_UPDATE_FOUNDATION_ADDRESS})
        )

    def test_rejects_when_something_else_moved(self) -> None:
        """Claimed, then REFUSED with a specific error -- not silently unclaimed.

        A claim that declined here sent the plan to the generic "unadmittable
        shape" reject, which says nothing about what was wrong. The lane owns
        this address; the validator is what enforces the rule.
        """
        before = _publish_tracking_runtime_input()
        after = copy.deepcopy(before)
        repository = after["authority_runtime_contract"]["global"][
            "authority_repository_url"
        ]
        after["authority_image_uri"] = f"{repository}@sha256:" + "8" * 64
        after["authority_runtime_contract"]["global"]["qat1_kid"] = "moved"
        by_address = self._foundation(before, after)
        self.assertIsNotNone(
            CHECKER._claim_authority_image_uri_move(
                set(by_address), {a: ["update"] for a in by_address}, by_address
            )
        )
        with self.assertRaises(CHECKER.ContractError):
            CHECKER._validate_authority_image_uri_move(
                frozenset(by_address), by_address, {}
            )

    def test_delegated_validation_covers_every_field_not_just_one(self) -> None:
        """The lane claims structurally, so its safety IS the validator.

        Review asked whether the delegation is airtight or rests on the single
        field the earlier case happened to mutate. It is a byte-equality
        reconstruction, so it covers all of them -- demonstrated rather than
        asserted, across a nested global value, a top-level contract value, a
        per-function value and an added key.
        """
        repository_change = lambda c: c["authority_runtime_contract"]["global"].update(
            {"authority_repository_url": "123456789012.dkr.ecr.us-east-2.amazonaws.com/layerv/other"}
        )
        quota_change = lambda c: c["authority_runtime_contract"]["global"].update(
            {"regional_lambda_concurrency_quota": 4242}
        )
        color_change = lambda c: c["authority_runtime_contract"].update(
            {"selected_authority_color": "green"}
        )
        function_change = lambda c: next(
            iter(c["authority_runtime_contract"]["functions"].values())
        ).update({"steady_reserved_concurrency": 99})
        added_key = lambda c: c["authority_runtime_contract"]["global"].update(
            {"unexpected_new_key": "x"}
        )

        for name, mutate in (
            ("repository url", repository_change),
            ("concurrency quota", quota_change),
            ("selected color", color_change),
            ("per-function concurrency", function_change),
            ("an added global key", added_key),
        ):
            with self.subTest(name):
                before = _publish_tracking_runtime_input()
                after = copy.deepcopy(before)
                repository = after["authority_runtime_contract"]["global"][
                    "authority_repository_url"
                ]
                after["authority_image_uri"] = f"{repository}@sha256:" + "a" * 64
                mutate(after)
                by_address = self._foundation(before, after)
                # Claimed on the structural signal ...
                self.assertIsNotNone(
                    CHECKER._claim_authority_image_uri_move(
                        set(by_address),
                        {a: ["update"] for a in by_address},
                        by_address,
                    )
                )
                # ... and then refused by the validator, which is where the
                # safety of this lane actually lives.
                with self.assertRaises(CHECKER.ContractError):
                    CHECKER._validate_authority_image_uri_move(
                        frozenset(by_address), by_address, {}
                    )

    def test_does_not_claim_a_pinned_contract(self) -> None:
        """A pinned digest cannot move on its own, so this lane must not apply."""
        before = authority_runtime_input_fixture()
        after = copy.deepcopy(before)
        repository = after["authority_runtime_contract"]["global"][
            "authority_repository_url"
        ]
        after["authority_image_uri"] = f"{repository}@sha256:" + "8" * 64
        by_address = self._foundation(before, after)
        self.assertIsNone(
            CHECKER._claim_authority_image_uri_move(
                set(by_address), {a: ["update"] for a in by_address}, by_address
            )
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
