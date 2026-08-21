#!/usr/bin/env python3
"""Source and plan contracts for qurl-go's sandbox OTP mailbox role."""

from __future__ import annotations

import copy
import importlib.util
import json
import re
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SOURCE = (ROOT / "terraform" / "agent_otp_ci_mailbox.tf").read_text(
    encoding="utf-8"
)
SCRIPT = ROOT / ".github" / "scripts" / "check-qurl-go-otp-mailbox-gate-plan.py"
SPEC = importlib.util.spec_from_file_location("qurl_go_otp_plan", SCRIPT)
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
    role_before = {
        "arn": "arn:aws:iam::767397897469:role/" + CHECKER.ROLE_NAME,
        "assume_role_policy": _document(CHECKER.EXPECTED_BEFORE_TRUST),
        "create_date": "2026-08-01T00:00:00Z",
        "description": "Per-PR OTP registration gate",
        "force_detach_policies": False,
        "id": CHECKER.ROLE_NAME,
        "managed_policy_arns": [],
        "max_session_duration": 3600,
        "name": CHECKER.ROLE_NAME,
        "name_prefix": None,
        "path": "/",
        "permissions_boundary": None,
        "tags": {"Environment": "sandbox"},
        "tags_all": {"Environment": "sandbox"},
        "unique_id": "AROAEXAMPLE",
    }
    role_after = copy.deepcopy(role_before)
    role_after["assume_role_policy"] = _document(CHECKER.EXPECTED_AFTER_TRUST)
    permission = {
        "id": CHECKER.ROLE_NAME + ":agent-otp-ci-mailbox-read",
        "name": "agent-otp-ci-mailbox-read",
        "name_prefix": None,
        "policy": _document(CHECKER.EXPECTED_MAILBOX_POLICY),
        "role": CHECKER.ROLE_NAME,
    }
    return {
        "format_version": "1.2",
        "terraform_version": "1.14.3",
        "resource_changes": [
            {
                "address": CHECKER.ROLE_ADDRESS,
                "module_address": "module.nhp",
                "mode": "managed",
                "type": "aws_iam_role",
                "name": "qurl_go_otp_mailbox_gate",
                "provider_name": "registry.terraform.io/hashicorp/aws",
                "change": {
                    "actions": ["update"],
                    "before": role_before,
                    "after": role_after,
                    "after_unknown": {},
                    "before_sensitive": {},
                    "after_sensitive": {},
                    "replace_paths": [],
                },
            },
            {
                "address": CHECKER.POLICY_ADDRESS,
                "module_address": "module.nhp",
                "mode": "managed",
                "type": "aws_iam_role_policy",
                "name": "qurl_go_otp_mailbox_gate",
                "provider_name": "registry.terraform.io/hashicorp/aws",
                "change": {
                    "actions": ["no-op"],
                    "before": permission,
                    "after": copy.deepcopy(permission),
                    "after_unknown": {},
                    "before_sensitive": {"policy": True},
                    "after_sensitive": {"policy": True},
                    "replace_paths": [],
                },
            },
        ],
        "output_changes": {},
    }


class SourceContract(unittest.TestCase):
    def test_trust_is_exact_two_subject_string_equals(self) -> None:
        role = _block("aws_iam_role", "qurl_go_otp_mailbox_gate")
        subjects = re.findall(
            r'"repo:\$\{var\.github_org\}/\$\{var\.qurl_go_github_repo\}:[^"]+"',
            role,
        )
        self.assertEqual(
            subjects,
            [
                '"repo:${var.github_org}/${var.qurl_go_github_repo}:pull_request"',
                '"repo:${var.github_org}/${var.qurl_go_github_repo}:ref:refs/heads/main"',
            ],
        )
        self.assertIn("StringEquals", role)
        self.assertNotIn("StringLike", role)
        self.assertNotIn(":environment:", role)
        self.assertNotIn("*", "".join(subjects))

    def test_permission_policy_remains_mailbox_read_only(self) -> None:
        policy = _block("aws_iam_role_policy", "qurl_go_otp_mailbox_gate")
        policy_without_comments = "\n".join(
            line for line in policy.splitlines() if not line.lstrip().startswith("#")
        )
        actions = re.findall(
            r'"([a-z][a-z0-9-]*:[A-Za-z*]+)"', policy_without_comments
        )
        self.assertEqual(
            actions,
            [
                "sqs:ReceiveMessage",
                "sqs:DeleteMessage",
                "sqs:GetQueueAttributes",
                "s3:GetObject",
            ],
        )
        self.assertIn(
            "Resource = [aws_sqs_queue.agent_otp_ci_mailbox[0].arn]", policy
        )
        self.assertIn(
            'Resource = ["${aws_s3_bucket.agent_otp_ci_mailbox[0].arn}/'
            '${local.agent_otp_ci_mailbox_prefix}*"]',
            policy,
        )


class PlanContract(unittest.TestCase):
    def test_exact_trust_only_update_passes(self) -> None:
        summary = CHECKER.check_plan(_plan())
        self.assertEqual(summary["added_subject"], CHECKER.MAIN_SUBJECT)
        self.assertEqual(summary["permission_policy"], "no-op")

    def test_subject_weakening_fails(self) -> None:
        mutations = (
            [CHECKER.MAIN_SUBJECT],
            [
                CHECKER.PULL_REQUEST_SUBJECT,
                "repo:layervai/qurl-go:ref:refs/heads/*",
            ],
            [
                CHECKER.PULL_REQUEST_SUBJECT,
                "repo:layervai/qurl-go:environment:sandbox",
            ],
        )
        for subjects in mutations:
            plan = _plan()
            trust = copy.deepcopy(CHECKER.EXPECTED_AFTER_TRUST)
            trust["Statement"][0]["Condition"]["StringEquals"][
                "token.actions.githubusercontent.com:sub"
            ] = subjects
            plan["resource_changes"][0]["change"]["after"][
                "assume_role_policy"
            ] = _document(trust)
            with self.subTest(subjects=subjects):
                with self.assertRaises(CHECKER.ContractError):
                    CHECKER.check_plan(plan)

    def test_non_trust_role_change_fails(self) -> None:
        plan = _plan()
        plan["resource_changes"][0]["change"]["after"]["description"] = "changed"
        with self.assertRaisesRegex(CHECKER.ContractError, "other than trust"):
            CHECKER.check_plan(plan)

    def test_plan_and_role_identity_drift_fail(self) -> None:
        for mutation in ("terraform-version", "role-arn", "role-path"):
            plan = _plan()
            if mutation == "terraform-version":
                plan["terraform_version"] = "1.15.8"
            elif mutation == "role-arn":
                plan["resource_changes"][0]["change"]["before"]["arn"] = (
                    "arn:aws:iam::767397897469:role/other"
                )
            else:
                plan["resource_changes"][0]["change"]["after"]["path"] = "/other/"
            with self.subTest(mutation=mutation):
                with self.assertRaises(CHECKER.ContractError):
                    CHECKER.check_plan(plan)

    def test_permission_expansion_fails(self) -> None:
        plan = _plan()
        permission = plan["resource_changes"][1]
        permission["change"]["actions"] = ["update"]
        expanded = copy.deepcopy(CHECKER.EXPECTED_MAILBOX_POLICY)
        expanded["Statement"][1]["Action"].append("s3:ListBucket")
        permission["change"]["after"]["policy"] = _document(expanded)
        with self.assertRaises(CHECKER.ContractError):
            CHECKER.check_plan(plan)

    def test_missing_permission_noop_fails(self) -> None:
        plan = _plan()
        plan["resource_changes"].pop()
        with self.assertRaisesRegex(CHECKER.ContractError, "exactly one"):
            CHECKER.check_plan(plan)

    def test_permission_identity_or_unknown_value_fails(self) -> None:
        for mutation in ("identity", "unknown"):
            plan = _plan()
            permission = plan["resource_changes"][1]
            if mutation == "identity":
                permission["change"]["after"]["role"] = "other"
            else:
                permission["change"]["after_unknown"] = {"policy": True}
            with self.subTest(mutation=mutation):
                with self.assertRaises(CHECKER.ContractError):
                    CHECKER.check_plan(plan)

    def test_any_other_material_change_fails(self) -> None:
        plan = _plan()
        extra = copy.deepcopy(plan["resource_changes"][1])
        extra["address"] = "module.nhp.aws_s3_bucket.unrelated"
        extra["type"] = "aws_s3_bucket"
        extra["name"] = "unrelated"
        extra["change"]["actions"] = ["update"]
        plan["resource_changes"].append(extra)
        with self.assertRaisesRegex(CHECKER.ContractError, "exactly one non-no-op"):
            CHECKER.check_plan(plan)

    def test_drift_unknown_and_output_changes_fail(self) -> None:
        for mutation in ("drift", "unknown", "output"):
            plan = _plan()
            if mutation == "drift":
                plan["resource_drift"] = [copy.deepcopy(plan["resource_changes"][0])]
            elif mutation == "unknown":
                plan["resource_changes"][0]["change"]["after_unknown"] = {
                    "assume_role_policy": True
                }
            else:
                plan["output_changes"]["changed"] = {"actions": ["update"]}
            with self.subTest(mutation=mutation):
                with self.assertRaises(CHECKER.ContractError):
                    CHECKER.check_plan(plan)


if __name__ == "__main__":
    unittest.main()
