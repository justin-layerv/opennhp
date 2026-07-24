#!/usr/bin/env python3

from __future__ import annotations

import copy
import importlib.util
import json
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPT = REPO_ROOT / ".github" / "scripts" / "check-sandbox-terraform-read-recovery.py"
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "recover-sandbox-terraform-read.yml"


def _load():
    spec = importlib.util.spec_from_file_location("sandbox_read_recovery", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


RECOVERY = _load()


def _policy(statements):
    return json.dumps(
        {"Version": "2012-10-17", "Statement": statements},
        separators=(",", ":"),
    )


def _plan():
    statements = [
        {
            "Sid": f"Existing{index}",
            "Effect": "Allow",
            "Action": [f"service{index}:Read"],
            "Resource": ["*"],
        }
        for index in range(10)
    ]
    after_statements = list(statements)
    after_statements.insert(8, copy.deepcopy(RECOVERY.EXPECTED_STATEMENT))
    before = {
        "arn": RECOVERY.TARGET_POLICY_ARN,
        "description": "Read-only permissions",
        "id": RECOVERY.TARGET_POLICY_ARN,
        "name": RECOVERY.TARGET_POLICY_NAME,
        "path": "/",
        "policy": _policy(statements),
        "policy_id": "ANPAEXAMPLE",
        "tags": {},
        "tags_all": {"Environment": "sandbox"},
    }
    after = copy.deepcopy(before)
    after["policy"] = _policy(after_statements)
    return {
        "format_version": "1.2",
        "terraform_version": "1.14.3",
        "resource_changes": [
            {
                "address": RECOVERY.TARGET_ADDRESS,
                "module_address": "module.nhp.module.ecr",
                "mode": "managed",
                "type": "aws_iam_policy",
                "name": "terraform_read",
                "provider_name": "registry.terraform.io/hashicorp/aws",
                "change": {
                    "actions": ["update"],
                    "before": before,
                    "after": after,
                    "after_unknown": {},
                    "before_sensitive": {},
                    "after_sensitive": {},
                    "replace_paths": [],
                },
            }
        ],
        "output_changes": {},
    }


def _live_metadata(version_id="v7", **overrides):
    policy = {
        "PolicyName": RECOVERY.TARGET_POLICY_NAME,
        "PolicyId": "ANPAEXAMPLE",
        "Arn": RECOVERY.TARGET_POLICY_ARN,
        "Path": "/",
        "DefaultVersionId": version_id,
        "IsAttachable": True,
    }
    policy.update(overrides)
    return {"Policy": policy}


def _live_version(plan, phase, version_id, **overrides):
    document = json.loads(plan["resource_changes"][0]["change"][phase]["policy"])
    policy_version = {
        "Document": document,
        "VersionId": version_id,
        "IsDefaultVersion": True,
    }
    policy_version.update(overrides)
    return {"PolicyVersion": policy_version}


class RecoveryPlanContract(unittest.TestCase):
    def test_exact_plan_passes(self):
        summary = RECOVERY.check_plan(_plan())
        self.assertEqual(summary["resource_change_count"], 1)
        self.assertEqual(summary["added_statement"], RECOVERY.EXPECTED_STATEMENT)

    def test_only_exact_target_may_change(self):
        for mutation in ("wrong-address", "extra-change", "create"):
            plan = _plan()
            if mutation == "wrong-address":
                plan["resource_changes"][0]["address"] += "_other"
            elif mutation == "extra-change":
                plan["resource_changes"].append(
                    copy.deepcopy(plan["resource_changes"][0])
                )
            else:
                plan["resource_changes"][0]["change"]["actions"] = ["create"]
            with self.subTest(mutation=mutation):
                with self.assertRaises(RECOVERY.ContractError):
                    RECOVERY.check_plan(plan)

    def test_unrelated_noop_resource_is_accepted(self):
        plan = _plan()
        noop = copy.deepcopy(plan["resource_changes"][0])
        noop["address"] = "module.nhp.aws_s3_bucket.example"
        noop["type"] = "aws_s3_bucket"
        noop["name"] = "example"
        noop["change"]["actions"] = ["no-op"]
        noop["change"]["after"] = copy.deepcopy(noop["change"]["before"])
        plan["resource_changes"].append(noop)
        self.assertEqual(RECOVERY.check_plan(plan)["resource_change_count"], 1)

    def test_non_policy_attribute_change_fails(self):
        plan = _plan()
        plan["resource_changes"][0]["change"]["after"]["description"] = "broader"
        with self.assertRaisesRegex(
            RECOVERY.ContractError, "attribute other than policy"
        ):
            RECOVERY.check_plan(plan)

    def test_target_policy_identity_is_exact(self):
        for attribute, value in (
            ("arn", "arn:aws:iam::767397897469:policy/other"),
            ("id", "arn:aws:iam::767397897469:policy/other"),
            ("name", "other"),
            ("path", "/other/"),
            ("policy_id", ""),
        ):
            plan = _plan()
            change = plan["resource_changes"][0]["change"]
            change["before"][attribute] = value
            change["after"][attribute] = value
            with self.subTest(attribute=attribute):
                with self.assertRaises(RECOVERY.ContractError):
                    RECOVERY.check_plan(plan)

    def test_only_exact_qualified_statement_may_be_added(self):
        for mutation in ("unqualified", "broad-action", "extra-condition"):
            plan = _plan()
            after = json.loads(plan["resource_changes"][0]["change"]["after"]["policy"])
            statement = after["Statement"][8]
            if mutation == "unqualified":
                statement["Resource"][0] = statement["Resource"][0].removesuffix(
                    ":$LATEST"
                )
            elif mutation == "broad-action":
                statement["Action"] = ["lambda:Invoke*"]
            else:
                statement["Condition"] = {}
            plan["resource_changes"][0]["change"]["after"]["policy"] = json.dumps(after)
            with self.subTest(mutation=mutation):
                with self.assertRaisesRegex(
                    RECOVERY.ContractError, "exact qualified|policy delta"
                ):
                    RECOVERY.check_plan(plan)

    def test_existing_or_reordered_statement_fails(self):
        for mutation in ("already-existed", "reordered"):
            plan = _plan()
            change = plan["resource_changes"][0]["change"]
            if mutation == "already-existed":
                before = json.loads(change["before"]["policy"])
                before["Statement"].insert(
                    8, copy.deepcopy(RECOVERY.EXPECTED_STATEMENT)
                )
                change["before"]["policy"] = json.dumps(before)
            else:
                after = json.loads(change["after"]["policy"])
                after["Statement"][0], after["Statement"][1] = (
                    after["Statement"][1],
                    after["Statement"][0],
                )
                change["after"]["policy"] = json.dumps(after)
            with self.subTest(mutation=mutation):
                with self.assertRaises(RECOVERY.ContractError):
                    RECOVERY.check_plan(plan)

    def test_unknown_or_output_change_fails(self):
        for mutation in ("unknown", "output", "drift", "deferred"):
            plan = _plan()
            if mutation == "unknown":
                plan["resource_changes"][0]["change"]["after_unknown"] = {
                    "policy": True
                }
            elif mutation == "output":
                plan["output_changes"]["changed"] = {"actions": ["update"]}
            elif mutation == "drift":
                plan["resource_drift"] = [copy.deepcopy(plan["resource_changes"][0])]
            else:
                plan["deferred_changes"] = [{"reason": "provider_config_unknown"}]
            with self.subTest(mutation=mutation):
                with self.assertRaises(RECOVERY.ContractError):
                    RECOVERY.check_plan(plan)


class RecoveryLivePolicyContract(unittest.TestCase):
    def test_exact_before_and_advanced_after_pass(self):
        plan = _plan()
        before = RECOVERY.check_live_policy(
            plan,
            phase="before",
            metadata=_live_metadata("v7"),
            version=_live_version(plan, "before", "v7"),
            confirmed_metadata=_live_metadata("v7"),
        )
        after = RECOVERY.check_live_policy(
            plan,
            phase="after",
            metadata=_live_metadata("v8"),
            version=_live_version(plan, "after", "v8"),
            confirmed_metadata=_live_metadata("v8"),
            previous_default_version="v7",
        )
        self.assertTrue(before["live_policy_matches"])
        self.assertTrue(after["live_default_version_matches"])

    def test_live_document_mismatch_fails(self):
        plan = _plan()
        live_version = _live_version(plan, "before", "v7")
        live_version["PolicyVersion"]["Document"]["Statement"].append(
            {
                "Sid": "Unreviewed",
                "Effect": "Allow",
                "Action": ["lambda:InvokeFunction"],
                "Resource": ["*"],
            }
        )
        with self.assertRaisesRegex(
            RECOVERY.ContractError,
            "does not equal the planned before",
        ):
            RECOVERY.check_live_policy(
                plan,
                phase="before",
                metadata=_live_metadata("v7"),
                version=live_version,
                confirmed_metadata=_live_metadata("v7"),
            )

    def test_live_default_version_race_fails(self):
        plan = _plan()
        with self.assertRaisesRegex(
            RECOVERY.ContractError,
            "changed during live readback",
        ):
            RECOVERY.check_live_policy(
                plan,
                phase="before",
                metadata=_live_metadata("v7"),
                version=_live_version(plan, "before", "v7"),
                confirmed_metadata=_live_metadata("v8"),
            )

    def test_live_version_document_and_identity_must_be_exact(self):
        plan = _plan()
        cases = (
            (
                _live_metadata("v7", Arn="arn:aws:iam::767397897469:policy/other"),
                _live_version(plan, "before", "v7"),
            ),
            (
                _live_metadata("v7"),
                _live_version(plan, "before", "v8"),
            ),
            (
                _live_metadata("v7"),
                _live_version(plan, "before", "v7", IsDefaultVersion=False),
            ),
        )
        for metadata, version in cases:
            with self.subTest(metadata=metadata, version=version):
                with self.assertRaises(RECOVERY.ContractError):
                    RECOVERY.check_live_policy(
                        plan,
                        phase="before",
                        metadata=metadata,
                        version=version,
                        confirmed_metadata=_live_metadata("v7"),
                    )

    def test_after_default_version_must_advance(self):
        plan = _plan()
        for current, previous in (("v7", "v7"), ("v7", "v8")):
            with self.subTest(current=current, previous=previous):
                with self.assertRaisesRegex(
                    RECOVERY.ContractError,
                    "did not advance",
                ):
                    RECOVERY.check_live_policy(
                        plan,
                        phase="after",
                        metadata=_live_metadata(current),
                        version=_live_version(plan, "after", current),
                        confirmed_metadata=_live_metadata(current),
                        previous_default_version=previous,
                    )


class RecoveryWorkflowContract(unittest.TestCase):
    def test_credentialed_job_rejects_reruns_in_its_first_step(self):
        workflow = WORKFLOW.read_text(encoding="utf-8")
        recover_job = workflow.index("\n  recover:\n")
        first_step = workflow.index(
            "      - name: Reject recover job reruns before any action or AWS access",
            recover_job,
        )
        checkout = workflow.index(
            "      - name: Checkout exact confirmed main", recover_job
        )
        self.assertLess(first_step, checkout)
        first_step_body = workflow[first_step:checkout]
        self.assertIn("[[ \"$GITHUB_RUN_ATTEMPT\" == '1' ]]", first_step_body)
        self.assertNotIn("uses:", first_step_body)

    def test_workflow_pins_exact_recovery_contract(self):
        workflow = WORKFLOW.read_text(encoding="utf-8")
        for literal in (
            "group: deploy-sandbox-infra",
            "TF_VERSION: '1.14.3'",
            f"TARGET_ADDRESS: {RECOVERY.TARGET_ADDRESS}",
            f"TARGET_POLICY_ARN: {RECOVERY.TARGET_POLICY_ARN}",
            f"QUALIFIED_RELAY_STATUS_ARN: {RECOVERY.RELAY_STATUS_ARN}",
            "-refresh=false",
            '-target="$TARGET_ADDRESS"',
            "APPLY_EXACT_SANDBOX_TERRAFORM_READ_RECOVERY",
            "--invocation-type DryRun",
            "--query StatusCode",
            "[[ \"$status_code\" == '204' ]]",
        ):
            with self.subTest(literal=literal):
                self.assertIn(literal, workflow)

    def test_stale_lock_recovery_is_exact_guarded_and_pre_plan(self):
        workflow = WORKFLOW.read_text(encoding="utf-8")
        plan_step = workflow.index(
            "      - name: Build and mechanically review exact saved recovery plan"
        )
        apply_step = workflow.index(
            "      - name: Apply the mechanically reviewed saved plan",
            plan_step,
        )
        body = workflow[plan_step:apply_step]
        live_main = body.index(
            '../../../scripts/check-live-main-ref.sh "$EXPECTED_MAIN_SHA"'
        )
        lock_read = body.index("aws s3api get-object")
        lock_list_before = body.index(
            'lock_count_before="$(list_lock_key)"',
            lock_read,
        )
        evidence_check = body.index(
            "check-sandbox-stale-state-lock.py",
            lock_list_before,
        )
        lock_id_check = body.index(
            "'.lock_id == $lock_id'",
            evidence_check,
        )
        force_unlock = body.index(
            'terraform force-unlock -force "$STALE_LOCK_ID"',
            lock_id_check,
        )
        lock_list_after = body.index(
            'lock_count_after="$(list_lock_key)"',
            force_unlock,
        )
        plan = body.index("terraform plan", lock_list_after)
        self.assertLess(live_main, lock_read)
        self.assertLess(lock_read, lock_list_before)
        self.assertLess(lock_list_before, evidence_check)
        self.assertLess(evidence_check, lock_id_check)
        self.assertLess(lock_id_check, force_unlock)
        self.assertLess(force_unlock, lock_list_after)
        self.assertLess(lock_list_after, plan)
        self.assertIn(
            "FORCE_UNLOCK_EXACT_REVIEWED_SANDBOX_PLAN_LOCK",
            workflow,
        )
        self.assertIn("STALE_LOCK_SOURCE_RUN_ID: '30051956048'", workflow)
        self.assertIn("STALE_LOCK_SOURCE_JOB_ID: '89356869295'", workflow)
        self.assertIn("actions: read", workflow)
        self.assertIn("aws s3api list-objects-v2", body)
        self.assertNotIn("s3api delete-object", workflow)
        self.assertNotIn("aws s3api head-object", body)
        self.assertNotIn("-lock=false", workflow)

    def test_apply_binds_live_policy_before_and_after_saved_plan(self):
        workflow = WORKFLOW.read_text(encoding="utf-8")
        apply_step = workflow.index(
            "      - name: Apply the mechanically reviewed saved plan"
        )
        wait_step = workflow.index(
            "      - name: Wait for exact qualified DryRun authorization",
            apply_step,
        )
        body = workflow[apply_step:wait_step]
        before_fetch = body.index("fetch_live_policy live-before")
        before_check = body.index("--live-phase before")
        apply = body.index("terraform apply")
        after_fetch = body.index("fetch_live_policy live-after")
        after_check = body.index("--live-phase after")
        cleanup = body.index("rm -f")
        self.assertLess(before_fetch, before_check)
        self.assertLess(before_check, apply)
        self.assertLess(apply, after_fetch)
        self.assertLess(after_fetch, after_check)
        self.assertLess(after_check, cleanup)
        self.assertIn(
            "--previous-default-version \"$before_default_version\"",
            body,
        )
        self.assertIn("post_apply_verified=false", body)
        self.assertIn("for attempt in {1..24}", body)
        self.assertGreaterEqual(body.count("aws iam get-policy \\"), 2)
        self.assertIn("aws iam get-policy-version \\", body)
        # A function called from an `if` condition does not inherit reliable
        # errexit behavior; every AWS/jq read must fail the retry explicitly.
        self.assertGreaterEqual(body.count("|| return"), 4)
        self.assertNotIn("cat live-", body)


if __name__ == "__main__":
    unittest.main()
