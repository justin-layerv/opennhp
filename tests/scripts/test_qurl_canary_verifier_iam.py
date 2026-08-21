#!/usr/bin/env python3
"""Source and plan contracts for qurl-service's canary binding verifier."""

from __future__ import annotations

import copy
import importlib.util
import json
import re
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SOURCE = (ROOT / "terraform" / "modules" / "ecr" / "main.tf").read_text(
    encoding="utf-8"
)
SCRIPT = ROOT / ".github" / "scripts" / "check-qurl-canary-verifier-iam-plan.py"
SPEC = importlib.util.spec_from_file_location("qurl_canary_verifier_plan", SCRIPT)
assert SPEC and SPEC.loader
CHECKER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CHECKER
SPEC.loader.exec_module(CHECKER)


def _block(kind: str, name: str) -> str:
    marker = f'resource "{kind}" "{name}" {{'
    start = SOURCE.index(marker)
    depth = 0
    for index in range(start, len(SOURCE)):
        if SOURCE[index] == "{":
            depth += 1
        elif SOURCE[index] == "}":
            depth -= 1
            if depth == 0:
                return SOURCE[start : index + 1]
    raise AssertionError(f"unterminated Terraform block: {marker}")


def _document(value: dict) -> str:
    return json.dumps(value, separators=(",", ":"))


def _plan() -> dict:
    before = {
        "id": f"{CHECKER.ROLE_NAME}:{CHECKER.POLICY_NAME}",
        "name": CHECKER.POLICY_NAME,
        "name_prefix": None,
        "policy": _document(CHECKER.EXPECTED_BEFORE_POLICY),
        "role": CHECKER.ROLE_NAME,
    }
    after = copy.deepcopy(before)
    after["policy"] = _document(CHECKER.EXPECTED_AFTER_POLICY)
    return {
        "format_version": "1.2",
        "terraform_version": "1.14.3",
        "resource_changes": [
            {
                "address": CHECKER.POLICY_ADDRESS,
                "module_address": "module.nhp.module.ecr",
                "mode": "managed",
                "type": "aws_iam_role_policy",
                "name": "qurl_agent_key_inventory",
                "provider_name": "registry.terraform.io/hashicorp/aws",
                "change": {
                    "actions": ["update"],
                    "before": before,
                    "after": after,
                    "after_unknown": {},
                    "before_sensitive": {"policy": True},
                    "after_sensitive": {"policy": True},
                    "replace_paths": [],
                },
            }
        ],
        "output_changes": {},
    }


class SourceContract(unittest.TestCase):
    def test_grant_is_exact_read_only_sandbox_table(self) -> None:
        policy = _block("aws_iam_role_policy", "qurl_agent_key_inventory")
        verifier = policy[policy.index("DynamoDBQurlCanaryBindingVerifier") :]
        actions = re.findall(r'"(dynamodb:[A-Za-z*]+)"', verifier)
        self.assertEqual(actions, ["dynamodb:Scan"])
        self.assertRegex(
            policy,
            r'var\.environment == "sandbox" \? \[\{\s*'
            r'Sid\s*=\s*"DynamoDBQurlCanaryBindingVerifier"',
        )
        self.assertIn(
            "table/layerv-nhp-sandbox-control-connector-authority", verifier
        )
        self.assertNotIn("connector-authority*", verifier)
        for forbidden in ("PutItem", "UpdateItem", "DeleteItem", "InvokeFunction"):
            self.assertNotIn(forbidden, verifier)


class PlanContract(unittest.TestCase):
    def test_exact_policy_only_update_passes(self) -> None:
        summary = CHECKER.check_plan(_plan())
        self.assertEqual(summary["added_action"], "dynamodb:Scan")
        self.assertEqual(summary["added_resource"], CHECKER.AUTHORITY_RESOURCE)

    def test_permission_or_resource_expansion_fails(self) -> None:
        mutations = (
            ("Action", ["dynamodb:Scan", "dynamodb:GetItem"]),
            ("Action", ["dynamodb:*"]),
            ("Resource", [CHECKER.AUTHORITY_RESOURCE + "*"]),
            ("Resource", ["*"]),
        )
        for field, value in mutations:
            plan = _plan()
            document = copy.deepcopy(CHECKER.EXPECTED_AFTER_POLICY)
            document["Statement"][1][field] = value
            plan["resource_changes"][0]["change"]["after"]["policy"] = _document(
                document
            )
            with self.subTest(field=field, value=value):
                with self.assertRaises(CHECKER.ContractError):
                    CHECKER.check_plan(plan)

    def test_existing_inventory_grant_change_fails(self) -> None:
        plan = _plan()
        document = copy.deepcopy(CHECKER.EXPECTED_AFTER_POLICY)
        document["Statement"][0]["Resource"].pop()
        plan["resource_changes"][0]["change"]["after"]["policy"] = _document(
            document
        )
        with self.assertRaises(CHECKER.ContractError):
            CHECKER.check_plan(plan)

    def test_identity_unknown_and_replacement_fail(self) -> None:
        for mutation in ("identity", "unknown", "replacement"):
            plan = _plan()
            change = plan["resource_changes"][0]["change"]
            if mutation == "identity":
                change["after"]["role"] = "other"
            elif mutation == "unknown":
                change["after_unknown"] = {"policy": True}
            else:
                change["actions"] = ["delete", "create"]
            with self.subTest(mutation=mutation):
                with self.assertRaises(CHECKER.ContractError):
                    CHECKER.check_plan(plan)

    def test_other_material_change_fails(self) -> None:
        plan = _plan()
        extra = copy.deepcopy(plan["resource_changes"][0])
        extra["address"] = "module.nhp.aws_lambda_function.other"
        extra["type"] = "aws_lambda_function"
        extra["name"] = "other"
        plan["resource_changes"].append(extra)
        with self.assertRaisesRegex(CHECKER.ContractError, "exactly one non-no-op"):
            CHECKER.check_plan(plan)

    def test_version_drift_and_output_changes_fail(self) -> None:
        for mutation in ("version", "drift", "output"):
            plan = _plan()
            if mutation == "version":
                plan["terraform_version"] = "1.15.8"
            elif mutation == "drift":
                plan["resource_drift"] = [copy.deepcopy(plan["resource_changes"][0])]
            else:
                plan["output_changes"] = {"changed": {"actions": ["update"]}}
            with self.subTest(mutation=mutation):
                with self.assertRaises(CHECKER.ContractError):
                    CHECKER.check_plan(plan)


if __name__ == "__main__":
    unittest.main()
