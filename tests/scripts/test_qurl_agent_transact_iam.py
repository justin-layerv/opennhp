#!/usr/bin/env python3
"""Regression tests for the staged qURL agent transaction IAM boundary."""

from __future__ import annotations

import copy
import importlib.util
import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CHECKER_PATH = ROOT / "scripts/check-qurl-agent-transact-iam.py"
ROOT_MAIN = ROOT / "terraform/staged/qurl-agent-transact-iam/main.tf"
ROOT_BACKEND = ROOT / "terraform/staged/qurl-agent-transact-iam/backend.tf"
ROOT_README = ROOT / "terraform/staged/qurl-agent-transact-iam/README.md"
WORKFLOW = ROOT / ".github/workflows/qurl-agent-transact-iam.yml"
BUILD_WORKFLOW = ROOT / ".github/workflows/build-and-push.yml"
PROMOTE = ROOT / ".github/workflows/promote-to-prod.yml"
PLAN_FIXTURES = ROOT / "tests/fixtures/qurl-agent-transact-iam"
PLAN_FIXTURES_README = PLAN_FIXTURES / "README.md"
LEDGER = (
    ROOT
    / "docs/runbooks/prod-rollout-ledger/2026-07-17-issue-1952-qurl-agent-transact-iam.md"
)

SPEC = importlib.util.spec_from_file_location("qurl_agent_transact_checker", CHECKER_PATH)
assert SPEC and SPEC.loader
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)


def folded_yaml_values(document: str, key: str) -> list[str]:
    """Extract folded block-scalar values without requiring a YAML dependency."""
    lines = document.splitlines()
    values: list[str] = []
    marker = f"{key}: >-"
    for index, line in enumerate(lines):
        if line.lstrip() != marker:
            continue
        base_indent = len(line) - len(line.lstrip())
        block: list[str] = []
        for candidate in lines[index + 1 :]:
            if not candidate.strip():
                continue
            indent = len(candidate) - len(candidate.lstrip())
            if indent <= base_indent:
                break
            block.append(candidate.strip())
        values.append(" ".join(block))
    return values


def plan_fixture(*, actions: list[str], policy: dict | None = None) -> dict:
    after = {
        "id": None,
        "name": CHECKER.POLICY_NAME,
        "policy": json.dumps(policy or CHECKER.EXPECTED_POLICY),
        "role": CHECKER.ROLE_NAME,
    }
    return {
        "applyable": actions != ["no-op"],
        "complete": True,
        "errored": False,
        "resource_changes": [
            {
                "address": CHECKER.RESOURCE_ADDRESS,
                "mode": "managed",
                "type": "aws_iam_role_policy",
                "name": "qurl_agent_keys_transact",
                "change": {
                    "actions": actions,
                    "before": None if actions == ["create"] else after,
                    "after": after,
                },
            }
        ],
    }


class ContractTests(unittest.TestCase):
    def test_create_and_noop_plans_are_accepted(self) -> None:
        self.assertEqual(
            CHECKER.check_plan(plan_fixture(actions=["create"]), "create"),
            CHECKER.policy_sha256(CHECKER.EXPECTED_POLICY),
        )
        self.assertEqual(
            CHECKER.check_plan(plan_fixture(actions=["no-op"]), "no-op"),
            CHECKER.policy_sha256(CHECKER.EXPECTED_POLICY),
        )

    def test_real_terraform_1_14_3_plan_shapes_pass_cli_contract(self) -> None:
        for filename, expected_action, expected_applyable in (
            ("create-terraform-1.14.3.json", "create", True),
            ("no-op-terraform-1.14.3.json", "no-op", False),
        ):
            with self.subTest(filename=filename):
                fixture = PLAN_FIXTURES / filename
                plan = json.loads(fixture.read_text(encoding="utf-8"))
                self.assertEqual(plan["format_version"], "1.2")
                self.assertEqual(plan["terraform_version"], "1.14.3")
                self.assertIs(plan["applyable"], expected_applyable)
                self.assertIs(plan["complete"], True)
                self.assertIs(plan["errored"], False)

                completed = subprocess.run(
                    [
                        sys.executable,
                        str(CHECKER_PATH),
                        "plan",
                        str(fixture),
                        "--expected-action",
                        expected_action,
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertEqual(
                    json.loads(completed.stdout),
                    {
                        "policy_sha256": CHECKER.policy_sha256(
                            CHECKER.EXPECTED_POLICY
                        )
                    },
                )

    def test_scope_broadening_is_rejected(self) -> None:
        for mutation in (
            {"Action": ["dynamodb:*"]},
            {"Resource": [CHECKER.TABLE_ARN, f"{CHECKER.TABLE_ARN}/index/*"]},
            {"Effect": "Deny"},
        ):
            with self.subTest(mutation=mutation):
                policy = copy.deepcopy(CHECKER.EXPECTED_POLICY)
                policy["Statement"][0].update(mutation)
                with self.assertRaises(CHECKER.ContractError):
                    CHECKER.check_plan(plan_fixture(actions=["create"], policy=policy), "create")

    def test_extra_resource_and_delete_are_rejected(self) -> None:
        extra = plan_fixture(actions=["create"])
        extra["resource_changes"].append(extra["resource_changes"][0])
        with self.assertRaises(CHECKER.ContractError):
            CHECKER.check_plan(extra, "create")
        with self.assertRaises(CHECKER.ContractError):
            CHECKER.check_plan(plan_fixture(actions=["delete"]), "create")

    def test_plan_metadata_mode_and_noop_before_are_fail_closed(self) -> None:
        for field, value in (
            ("complete", None),
            ("errored", None),
            ("applyable", None),
        ):
            with self.subTest(field=field):
                plan = plan_fixture(actions=["create"])
                plan[field] = value
                with self.assertRaises(CHECKER.ContractError):
                    CHECKER.check_plan(plan, "create")

        unmanaged = plan_fixture(actions=["create"])
        unmanaged["resource_changes"][0]["mode"] = "data"
        with self.assertRaisesRegex(CHECKER.ContractError, "resource mode"):
            CHECKER.check_plan(unmanaged, "create")

        changed_noop = plan_fixture(actions=["no-op"])
        changed_noop["resource_changes"][0]["change"]["before"] = None
        with self.assertRaisesRegex(CHECKER.ContractError, "before and after"):
            CHECKER.check_plan(changed_noop, "no-op")

    def test_policy_subcommand_reads_exact_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            policy_path = Path(directory) / "live-policy.json"
            policy_path.write_text(
                json.dumps(CHECKER.EXPECTED_POLICY), encoding="utf-8"
            )
            completed = subprocess.run(
                [sys.executable, str(CHECKER_PATH), "policy", str(policy_path)],
                check=False,
                capture_output=True,
                text=True,
            )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(
            json.loads(completed.stdout),
            {"policy_sha256": CHECKER.policy_sha256(CHECKER.EXPECTED_POLICY)},
        )

    def test_root_is_fixed_to_prod_and_prevent_destroy(self) -> None:
        main = ROOT_MAIN.read_text(encoding="utf-8")
        backend = ROOT_BACKEND.read_text(encoding="utf-8")
        readme = ROOT_README.read_text(encoding="utf-8")
        readme_flat = " ".join(readme.split())
        self.assertIn(CHECKER.ROLE_NAME, main)
        self.assertIn(CHECKER.TABLE_ARN, main)
        self.assertIn("Keep this document in lockstep with EXPECTED_POLICY", main)
        self.assertIn("Keep this contract in lockstep", CHECKER_PATH.read_text())
        self.assertIn("prevent_destroy = true", main)
        self.assertNotIn('Resource = ["*"]', main)
        self.assertNotIn("/index/", main)
        self.assertIn('allowed_account_ids = ["235500187906"]', backend)
        self.assertIn(
            'key          = "nhp/prod/staged/qurl-agent-transact-iam/terraform.tfstate"',
            backend,
        )
        self.assertIn('required_version = "= 1.14.3"', backend)
        self.assertIn("key/00a0e673-cef4-41f0-bfc0-5116a9ab3aa0", backend)
        self.assertIn("approval window is two days", readme_flat)
        self.assertIn("retained for three days", readme_flat)
        self.assertIn("re-dispatch the workflow", readme_flat)
        self.assertIn("queues regular production promotions", readme_flat)
        self.assertIn("Do not retry apply", readme_flat)
        self.assertIn("separately reviewed read-only convergence plan", readme_flat)
        self.assertIn("Markdown remains documentation-only", readme_flat)

    def test_rollout_links_issue_and_atomic_writer_pr(self) -> None:
        ledger = LEDGER.read_text(encoding="utf-8")
        self.assertIn("qurl-service/issues/1036", ledger)
        self.assertIn("qurl-service/pull/1037", ledger)
        self.assertNotIn("qurl-service/pull/1036", ledger)
        self.assertIn("enforced two-day window", ledger)
        self.assertIn("retained for three days", ledger)
        self.assertIn("queues regular production promotions", ledger)
        self.assertIn("first end-to-end exercise", ledger)
        self.assertIn("If any write is denied", ledger)
        self.assertIn("do not retry apply", ledger)
        self.assertIn("separately reviewed read-only convergence plan", ledger)

        fixtures_readme = PLAN_FIXTURES_README.read_text(encoding="utf-8")
        self.assertIn("revalidate the exact plan", fixtures_readme)
        self.assertIn("S3 list/native-lock behavior", fixtures_readme)
        self.assertIn("KMS", fixtures_readme)

    def test_workflow_is_main_only_saved_plan_and_never_deploys_writer(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        for marker in (
            'if [[ "$GITHUB_REF" != \'refs/heads/main\' ]]',
            "qurl-agent-keys-transact-write",
            "terraform plan",
            "terraform apply -input=false -lock-timeout=5m -no-color tfplan",
            "environment: production",
            "group: promote-to-prod",
            "cancel-in-progress: false",
            "IAM scopes PutRolePolicy to the role, not an inline-policy name",
            "same shell immediately before apply",
            "Approve the protected apply within two days of plan creation",
            "Enforce two-day approval window",
            "planned_at_epoch",
            "plan_age_seconds > 172800",
            "pending approval holds the shared \\`promote-to-prod\\` concurrency slot",
            "Policy installed; effective-permission simulation pending",
            "transactional writer NOT authorized for rollout",
            "qurl-service/pull/1037",
        ):
            self.assertIn(marker, workflow)
        self.assertNotIn("DeleteRolePolicy", workflow)
        self.assertNotIn("deploy-qurl", workflow)
        guard_start = workflow.index("  guard:")
        plan_start = workflow.index("  plan:")
        apply_start = workflow.index("  apply:")
        self.assertNotIn("id-token: write", workflow[guard_start:plan_start])
        self.assertEqual(workflow.count("id-token: write"), 2)
        self.assertIn("id-token: write", workflow[plan_start:apply_start])
        self.assertIn("id-token: write", workflow[apply_start:])
        plan_upload_start = workflow.index(
            "- name: Upload saved plan for protected apply"
        )
        plan_upload_end = workflow.index(
            "- name: Summarize approval boundary", plan_upload_start
        )
        plan_upload_step = workflow[plan_upload_start:plan_upload_end]
        self.assertIn("retention-days: 3", plan_upload_step)
        self.assertIn("The binary plan is hash-pinned", workflow)
        self.assertLess(
            workflow.index("- name: Enforce two-day approval window"),
            workflow.index("- name: Configure narrowly-scoped production apply session"),
        )
        self.assertEqual(workflow.count("- name: Cache Terraform plugins"), 2)
        self.assertEqual(
            workflow.count(
                'export TF_PLUGIN_CACHE_DIR="$HOME/.terraform.d/plugin-cache"'
            ),
            2,
        )

        build_workflow = BUILD_WORKFLOW.read_text(encoding="utf-8")
        staged_init_start = build_workflow.index(
            "- name: Terraform staged qURL agent transaction IAM init (no backend)"
        )
        staged_init_end = build_workflow.index(
            "- name: Terraform staged qURL agent transaction IAM validate",
            staged_init_start,
        )
        self.assertIn(
            'export TF_PLUGIN_CACHE_DIR="$HOME/.terraform.d/plugin-cache"',
            build_workflow[staged_init_start:staged_init_end],
        )

        apply_step_start = workflow.index(
            "- name: Re-prove policy is absent and apply exact saved plan"
        )
        apply_step_end = workflow.index(
            "- name: Verify live policy, state ownership, and convergence",
            apply_step_start,
        )
        apply_step = workflow[apply_step_start:apply_step_end]
        apply_index = apply_step.index("terraform apply")
        for marker in (
            'role_arn=$(aws iam get-role --role-name "$ROLE_NAME"',
            '[[ "$role_arn" == "$ROLE_ARN" ]]',
            "aws dynamodb describe-table",
            '[[ "$table_status" == "ACTIVE" && "$table_arn" == "$TABLE_ARN" ]]',
            'aws iam get-role-policy --role-name "$ROLE_NAME"',
        ):
            self.assertIn(marker, apply_step)
            self.assertLess(apply_step.index(marker), apply_index)

        summary_start = workflow.index("- name: Summarize remaining hard gate")
        summary = workflow[summary_start:]
        self.assertIn('printf -- "- Policy: \\`%s\\`', summary)
        self.assertIn('"$POLICY_NAME"', summary)
        self.assertIn('"$ROLE_ARN"', summary)
        self.assertIn('"$TABLE_ARN"', summary)
        self.assertNotIn("${{ secrets.", summary)

        session_policy_texts = folded_yaml_values(workflow, "inline-session-policy")
        self.assertEqual(len(session_policy_texts), 2)
        session_policies = [json.loads(value) for value in session_policy_texts]
        self.assertIn("STS inline session policies are limited to 2,048", workflow)
        self.assertTrue(all(len(value) <= 2048 for value in session_policy_texts))

        def actions(policy: dict) -> set[str]:
            return {
                action
                for statement in policy["Statement"]
                for action in statement["Action"]
            }

        plan_actions, apply_actions = map(actions, session_policies)
        self.assertEqual(
            plan_actions,
            {
                "dynamodb:DescribeTable",
                "iam:GetRole",
                "iam:GetRolePolicy",
                "iam:ListRolePolicies",
                "kms:Decrypt",
                "kms:DescribeKey",
                "s3:GetBucketLocation",
                "s3:GetObject",
                "sts:GetCallerIdentity",
            },
        )
        self.assertEqual(
            apply_actions,
            plan_actions
            | {
                "iam:PutRolePolicy",
                "kms:Encrypt",
                "kms:GenerateDataKey",
                "s3:DeleteObject",
                "s3:PutObject",
            },
        )
        for policy in session_policies:
            for statement in policy["Statement"]:
                if statement["Resource"] == "*":
                    self.assertEqual(statement["Action"], ["sts:GetCallerIdentity"])

        self.assertNotIn('"s3:ListBucket"', "\n".join(session_policy_texts))
        self.assertNotIn("StateBucketList", workflow)
        self.assertIn("explicitly treats AccessDenied as default-workspace", workflow)

        serialized = json.dumps(session_policies, sort_keys=True)
        self.assertIn(CHECKER.ROLE_NAME, serialized)
        self.assertIn(CHECKER.TABLE_ARN, serialized)
        self.assertNotIn(f"{CHECKER.TABLE_ARN}/index", serialized)
        self.assertIn(
            "nhp/prod/staged/qurl-agent-transact-iam/terraform.tfstate.tflock",
            serialized,
        )

    def test_staged_root_is_outside_legacy_prod_stale_diff_scope(self) -> None:
        promote = PROMOTE.read_text(encoding="utf-8")
        match = re.search(
            r"TF_DIFF=\$\(git diff --name-only[\s\S]{0,300}?\)", promote
        )
        self.assertIsNotNone(match)
        scope = match.group(0)
        self.assertIn("terraform/environments/prod/", scope)
        self.assertIn("terraform/modules/", scope)
        self.assertNotIn("terraform/staged/", scope)


if __name__ == "__main__":
    unittest.main()
