#!/usr/bin/env python3

from __future__ import annotations

import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "udp-proof-runner-sandbox-update.yml"
CAPTURE = ROOT / "scripts" / "capture-sandbox-udp-proof-runner-state.sh"


class UDPProofRunnerUpdateWorkflowTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.raw = WORKFLOW.read_text(encoding="utf-8")
        cls.workflow = yaml.load(cls.raw, Loader=yaml.BaseLoader)
        cls.capture = CAPTURE.read_text(encoding="utf-8")

    def test_dispatch_is_closed_to_plan_apply_verify(self) -> None:
        self.assertEqual(set(self.workflow["on"]), {"workflow_dispatch"})
        inputs = self.workflow["on"]["workflow_dispatch"]["inputs"]
        self.assertEqual(
            set(inputs),
            {
                "operation",
                "source_plan_run_id",
                "planned_commit_sha",
                "plan_sha256",
                "planned_state_version_id",
                "planned_state_serial",
                "planned_state_sha256",
                "confirmation",
            },
        )
        self.assertEqual(
            inputs["operation"]["options"],
            ["plan", "apply", "verify"],
        )
        for phrase in (
            "PLAN_SANDBOX_UDP_PROOF_RUNNER",
            "APPLY_SANDBOX_UDP_PROOF_RUNNER",
            "VERIFY_SANDBOX_UDP_PROOF_RUNNER",
        ):
            self.assertIn(phrase, self.raw)

    def test_current_signed_main_and_source_run_are_authenticated(self) -> None:
        self.assertIn('test "$GITHUB_REF" = refs/heads/main', self.raw)
        self.assertIn("commit.verification", self.raw)
        self.assertIn('.verified == true and .reason == "valid"', self.raw)
        self.assertIn('.path == ".github/workflows/udp-proof-runner-sandbox-update.yml"', self.raw)
        self.assertIn('.conclusion == "success"', self.raw)
        self.assertIn('.head_branch == "main"', self.raw)
        self.assertIn('test "$GITHUB_SHA" = "$PLANNED_COMMIT_SHA"', self.raw)

    def test_saved_plan_binds_unchanged_versioned_state(self) -> None:
        self.assertEqual(
            self.workflow["concurrency"],
            {
                "group": "deploy-sandbox-infra",
                "cancel-in-progress": "false",
            },
        )
        self.assertEqual(
            self.raw.count("capture-sandbox-udp-proof-runner-state.sh"),
            3,
        )
        self.assertIn('cmp "$RUNNER_TEMP/state-before/state-summary.json"', self.raw)
        for field in (
            "planned_state_version_id",
            "planned_state_serial",
            "planned_state_sha256",
        ):
            self.assertIn(field, self.workflow["on"]["workflow_dispatch"]["inputs"])
        self.assertIn('terraform apply -input=false -auto-approve "$RUNNER_TEMP/saved-plan/tfplan"', self.raw)
        self.assertIn("digest-mismatch: error", self.raw)
        self.assertIn("broker_zip_sha256", self.raw)
        self.assertIn("artifact/broker.zip", self.raw)

    def test_proof_account_hash_is_rebound_not_operator_supplied(self) -> None:
        inputs = self.workflow["on"]["workflow_dispatch"]["inputs"]
        self.assertNotIn("proof_account", inputs)
        self.assertIn(
            "PROOF_ACCOUNT_SHA_PARAMETER: /sandbox/nhp/udp-proof/account-credential-sha256",
            self.raw,
        )
        self.assertEqual(
            self.raw.count("aws ssm get-parameter"),
            3,
        )
        self.assertIn("TF_VAR_proof_account_credential_sha256", self.raw)

    def test_state_capture_pins_account_object_and_kms_identity(self) -> None:
        for exact in (
            "expected_account=767397897469",
            "bucket=layerv-terraform-state-767397897469",
            "key=nhp/sandbox-udp-proof-runner/terraform.tfstate",
            "expected_kms_key_arn=arn:aws:kms:us-east-2:767397897469:key/289dbe35-ab5a-4752-8564-4c96c607c9f4",
            "--version-id",
            ".tflock",
            "state-summary.json",
        ):
            self.assertIn(exact, self.capture)

    def test_apply_and_verify_require_post_plan_convergence(self) -> None:
        self.assertEqual(self.raw.count("select(.change.actions != [\"no-op\"])"), 3)
        self.assertEqual(self.raw.count("scripts/check-live-main-ref.sh"), 3)
        for job_name in ("plan", "apply", "verify"):
            job = self.workflow["jobs"][job_name]
            self.assertEqual(job["environment"], "sandbox")
            self.assertEqual(job["permissions"]["id-token"], "write")


if __name__ == "__main__":
    unittest.main()
