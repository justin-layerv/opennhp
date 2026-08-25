from __future__ import annotations

import copy
import json
import subprocess
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/nhp-smoke-tests.yml"
BUILD_WORKFLOW = ROOT / ".github/workflows/build-and-push.yml"


class SandboxQURLCustomerWorkflowTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = WORKFLOW.read_text(encoding="utf-8")
        cls.workflow = yaml.safe_load(cls.text)
        cls.job = cls.workflow["jobs"]["qurl-customer-journey"]
        cls.steps = {step["name"]: step for step in cls.job["steps"]}

    def test_customer_job_uses_only_narrow_fixed_canary_role(self) -> None:
        self.assertEqual(self.job["timeout-minutes"], 75)
        self.assertEqual(
            self.steps["Configure exact sandbox AWS role"]["with"]["role-to-assume"],
            "arn:aws:iam::767397897469:role/layerv-nhp-sandbox-fixed-canary",
        )
        self.assertEqual(self.steps["Configure exact sandbox AWS role"]["with"]["role-duration-seconds"], 7200)
        self.assertNotIn("secrets.AWS_ROLE_ARN", str(self.job))
        runtime = self.steps["Build stable sandbox runtime authority"]["run"]
        self.assertIn("assumed-role/layerv-nhp-sandbox-fixed-canary/", runtime)
        self.assertEqual(self.job["concurrency"]["group"], "sandbox-fixed-canary-journey")
        self.assertFalse(self.job["concurrency"]["cancel-in-progress"])

    def test_artifact_and_caller_authority_are_fail_closed(self) -> None:
        step = self.steps["Download and verify exact qURL artifacts"]["run"]
        for flag in (
            "--binary-artifact-metadata-file",
            "--source-receipt-artifact-metadata-file",
            "--binary-artifact-zip",
            "--source-receipt-artifact-zip",
        ):
            self.assertIn(flag, step)
        self.assertIn(".head_repository.full_name", step)
        self.assertNotIn("7a1b0613d527de8924c59f72aed91fc8a08fb190", step)
        self.assertIn("CALLER_EVENT=$EVENT", step)
        self.assertIn('/tmp/layerv-sandbox-qurl-${CALLER_RUN_ID}-${CALLER_HEAD_SHA}', step)
        self.assertIn(
            "qurl-integrations/compare/78b025404be1d52e9fe9144a28812b71dcd80b96...$CALLER_HEAD_SHA",
            step,
        )
        self.assertIn("compare/95b33ab9fe89b9fcc7bc7d16b92892c9d526c9a3", step)
        self.assertIn('HELPER_SHA=$(sha256sum "$PRIVATE_ROOT/prod-matched-cohort-key.py"', step)
        self.assertIn("qurl_infra_helper_sha256:$helper_sha", step)
        self.assertIn('verify_signed_commit "$CALLER_REPOSITORY" "$CALLER_HEAD_SHA"', step)
        self.assertIn('verify_signed_commit layervai/qurl-go "$QURL_GO_SOURCE_SHA"', step)
        self.assertIn('verify_signed_commit layervai/qurl-integrations-infra "$QURL_INFRA_SOURCE_SHA"', step)

    def test_shared_runtime_capability_ancestry_gate_rejects_mutations(self) -> None:
        step = self.steps["Download and verify exact qURL artifacts"]["run"]
        minimum = "78b025404be1d52e9fe9144a28812b71dcd80b96"

        def has_closed_gate(value: str) -> bool:
            return (
                f"qurl-integrations/compare/{minimum}...$CALLER_HEAD_SHA" in value
                and 'QURL_INTEGRATIONS_MINIMUM=$(gh api ' in value
                and "<<<\"$QURL_INTEGRATIONS_MINIMUM\"" in value
                and '.status == "ahead" or .status == "identical"' in value
            )

        self.assertTrue(has_closed_gate(step))
        for mutation in (
            step.replace(minimum, "0" * 40),
            step.replace('QURL_INTEGRATIONS_MINIMUM=$(gh api ', 'QURL_INTEGRATIONS_MINIMUM=$(printf '),
            step.replace('<<<"$QURL_INTEGRATIONS_MINIMUM"', '<<<"{\\"status\\":\\"ahead\\"}"'),
            step.replace('.status == "ahead" or .status == "identical"', '.status == "behind"'),
        ):
            self.assertFalse(has_closed_gate(mutation))

    def test_signed_commit_filter_rejects_unsigned_reason_and_commit_drift(self) -> None:
        step = self.steps["Download and verify exact qURL artifacts"]["run"]
        signed_filter = '.sha == $sha and .commit.verification.verified == true and .commit.verification.reason == "valid"'
        self.assertIn(signed_filter, step)
        expected = "a" * 40
        valid = {
            "sha": expected,
            "commit": {"verification": {"verified": True, "reason": "valid"}},
        }

        def accepted(value: dict) -> bool:
            result = subprocess.run(
                ["jq", "-e", "--arg", "sha", expected, signed_filter],
                input=json.dumps(value),
                text=True,
                capture_output=True,
                check=False,
            )
            return result.returncode == 0

        self.assertTrue(accepted(valid))
        mutations = []
        for field, replacement in (("verified", False), ("reason", "unsigned")):
            changed = copy.deepcopy(valid)
            changed["commit"]["verification"][field] = replacement
            mutations.append(changed)
        changed = copy.deepcopy(valid)
        changed["sha"] = "b" * 40
        mutations.append(changed)
        for mutation in mutations:
            self.assertFalse(accepted(mutation))

    def test_cleanup_starts_only_after_journey_starts(self) -> None:
        reconcile = self.steps["Reconcile customer authority on every exit"]
        self.assertEqual(reconcile["if"], "always() && steps.journey.outcome != 'skipped'")
        for flag in (
            "--runtime-file",
            "--source-authority-file",
            "--key-helper-file",
            "--caller-event",
            "--terminal-receipt",
        ):
            self.assertIn(flag, reconcile["run"])

    def test_journey_passes_exact_caller_event_to_terminal_builder(self) -> None:
        journey = self.steps["Run protected direct relay and recovery customer journey"]["run"]
        self.assertIn('--caller-event "$CALLER_EVENT"', journey)

    def test_runtime_and_provenance_are_bracketed_before_credential_mint(self) -> None:
        nhp = self.steps["Verify active NHP image provenance and operation ancestry"]["run"]
        self.assertIn("compare/a70e5d66dda604459b0a37ed7c634da8c8e46c3d", nhp)
        self.assertIn("gh attestation verify", nhp)
        self.assertIn("--source-digest", nhp)
        self.assertIn('ACTIVE_SERVER=$(jq -er', nhp)
        self.assertIn('ACTIVE_AC=$(jq -er', nhp)
        self.assertIn('cmp "$PRIVATE_ROOT/server-source-sha" "$PRIVATE_ROOT/ac-source-sha"', nhp)
        self.assertIn('cmp "$PRIVATE_ROOT/server-source-sha" "$PRIVATE_ROOT/relay-source-sha"', nhp)
        qurl = self.steps["Verify deployed qurl-service SLSA source and build run"]["run"]
        self.assertIn("--image-index-digest", qurl)
        self.assertIn("qurl-service/compare/$SOURCE_SHA...$MAIN_SHA", qurl)
        self.assertIn("qurl-service/attestations/$IMAGE_DIGEST", qurl)
        self.assertIn("gh attestation verify", qurl)
        self.assertIn("--signer-workflow layervai/qurl-service/.github/workflows/build-and-deploy.yml", qurl)
        reread = self.steps["Re-read exact sandbox runtime before credential mint"]["run"]
        self.assertIn('cmp "$PRIVATE_ROOT/runtime.json" "$PRIVATE_ROOT/runtime-before-mint.json"', reread)
        self.assertLess(
            list(self.steps).index("Re-read exact sandbox runtime before credential mint"),
            list(self.steps).index("Run protected direct relay and recovery customer journey"),
        )

    def test_caller_modes_and_runtime_reader_argv_are_closed(self) -> None:
        download = self.steps["Download and verify exact qURL artifacts"]["run"]
        self.assertIn('if [[ "$CALLER_MODE" == active ]]', download)
        self.assertIn('[[ "$CALLER_MODE" == postdeploy ]]', download)
        terminal_verify = self.steps["Verify caller remained exact through terminal outcome"]
        self.assertEqual(terminal_verify["env"]["CALLER_MODE"], "${{ inputs.caller_mode }}")
        self.assertIn('if [[ "$CALLER_MODE" == active ]]', terminal_verify["run"])
        reread = self.steps["Re-read exact sandbox runtime before credential mint"]["run"]
        self.assertEqual(reread.count("--region us-east-2"), 1)


class SandboxQURLPostDeployWorkflowTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = yaml.safe_load(BUILD_WORKFLOW.read_text(encoding="utf-8"))

    def test_existing_main_deploy_path_requires_completed_current_qurl_artifacts(self) -> None:
        resolve = self.workflow["jobs"]["resolve-qurl-customer-artifacts"]
        script = resolve["steps"][1]["run"]
        self.assertIn("qurl-integrations/git/ref/heads/main", script)
        self.assertIn('[[ "$CANDIDATE_HEAD" == "$HEAD" ]]', script)
        self.assertNotIn('compare/$CANDIDATE_HEAD...$HEAD', script)
        self.assertIn('commits/$CALLER_HEAD', script)
        self.assertIn('.commit.verification.verified == true', script)
        self.assertIn('.commit.verification.reason == "valid"', script)
        self.assertIn('.status == "completed"', script)
        self.assertIn('.conclusion == "success"', script)
        self.assertIn("sandbox-matched-cohort-binaries", script)
        self.assertIn("sandbox-matched-cohort-source-receipt.json", script)
        self.assertIn("qurl-integrations-infra/git/ref/heads/main", script)

    def test_postdeploy_stale_ancestor_cannot_select_or_start_a_journey(self) -> None:
        script = self.workflow["jobs"]["resolve-qurl-customer-artifacts"]["steps"][1]["run"]
        journey = self.workflow["jobs"]["qurl-customer-journey-sandbox"]
        self.assertEqual(journey["needs"], ["resolve-qurl-customer-artifacts"])
        self.assertEqual(journey["if"], "needs.resolve-qurl-customer-artifacts.result == 'success'")

        def exact_head_only(value: str) -> bool:
            return (
                'CANDIDATE_HEAD=$(jq -er .head_sha <<<"$CANDIDATE")' in value
                and '[[ "$CANDIDATE_HEAD" == "$HEAD" ]]' in value
                and 'compare/$CANDIDATE_HEAD...$HEAD' not in value
            )

        self.assertTrue(exact_head_only(script))
        for mutation in (
            script.replace('[[ "$CANDIDATE_HEAD" == "$HEAD" ]]', '[[ -n "$CANDIDATE_HEAD" ]]'),
            script.replace('[[ "$CANDIDATE_HEAD" == "$HEAD" ]]', 'gh api "repos/layervai/qurl-integrations/compare/$CANDIDATE_HEAD...$HEAD"'),
            script.replace('CANDIDATE_HEAD=$(jq -er .head_sha <<<"$CANDIDATE")', 'CANDIDATE_HEAD="$HEAD"'),
        ):
            self.assertFalse(exact_head_only(mutation))

    def test_postdeploy_rechecks_immutable_sources_as_current_main_ancestors(self) -> None:
        download = SandboxQURLCustomerWorkflowTest.steps["Download and verify exact qURL artifacts"]["run"]
        self.assertIn('compare/$CALLER_HEAD_SHA...$CALLER_MAIN', download)
        self.assertIn('compare/$QURL_INFRA_SOURCE_SHA...$QURL_INFRA_MAIN', download)
        self.assertNotIn('[[ "$QURL_INFRA_SOURCE_SHA" == "$QURL_INFRA_MAIN" ]]', download)
        terminal = SandboxQURLCustomerWorkflowTest.steps["Verify caller remained exact through terminal outcome"]["run"]
        self.assertIn('compare/$CALLER_HEAD_SHA...$CALLER_MAIN', terminal)
        journey = self.workflow["jobs"]["qurl-customer-journey-sandbox"]
        self.assertEqual(journey["with"]["caller_mode"], "postdeploy")
        self.assertEqual(journey["with"]["operation"], "qurl-customer-journey")


if __name__ == "__main__":
    unittest.main()
