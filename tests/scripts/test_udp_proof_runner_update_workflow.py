#!/usr/bin/env python3

from __future__ import annotations

import json
import hashlib
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "udp-proof-runner-sandbox-update.yml"
CAPTURE = ROOT / "scripts" / "capture-sandbox-udp-proof-runner-state.sh"
BINDING_CAPTURE = (
    ROOT / "scripts" / "capture-sandbox-udp-proof-account-binding.sh"
)


class UDPProofRunnerUpdateWorkflowTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.raw = WORKFLOW.read_text(encoding="utf-8")
        cls.workflow = yaml.load(cls.raw, Loader=yaml.BaseLoader)
        cls.capture = CAPTURE.read_text(encoding="utf-8")
        cls.binding_capture = BINDING_CAPTURE.read_text(encoding="utf-8")

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
        self.assertNotIn("Seed the proof account", inputs["operation"]["description"])
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
            "PROOF_ACCOUNT_SOURCE_SECRET: layerv-nhp-sandbox/udp-proof-account/credential",
            self.raw,
        )
        self.assertIn(
            "PROOF_ACCOUNT_SHA_PARAMETER: /sandbox/nhp/udp-proof/account-credential-sha256",
            self.raw,
        )
        self.assertEqual(
            self.raw.count("capture-sandbox-udp-proof-account-binding.sh"),
            3,
        )
        self.assertNotIn("TF_VAR_proof_account_credential_sha256", self.raw)
        self.assertIn("aws secretsmanager get-secret-value", self.binding_capture)
        self.assertIn("ResourceNotFoundException", self.binding_capture)
        self.assertIn("aws ssm get-parameter", self.binding_capture)
        self.assertIn("ParameterNotFound", self.binding_capture)
        self.assertIn('state:\"unconfigured\"', self.binding_capture)
        self.assertIn(
            '{proof_account_credential_sha256:$sha256}',
            self.binding_capture,
        )
        self.assertIn('"proof_account_binding"', self.raw)
        self.assertIn(".schema_version == 2", self.raw)

    def test_proof_account_capture_has_exact_bootstrap_states(self) -> None:
        credential = f"lv_test_{'A' * 43}"
        digest = hashlib.sha256(credential.encode()).hexdigest()
        secret_version = "proof-secret-version-1"
        cases = (
            (
                "configured",
                0,
                {
                    "parameter_state": "configured",
                    "parameter_version": 1,
                    "secret_version_id": secret_version,
                    "sha256": digest,
                    "state": "configured",
                },
                {"proof_account_credential_sha256": digest},
            ),
            (
                "seeded_without_parameter",
                0,
                {
                    "parameter_state": "missing",
                    "parameter_version": None,
                    "secret_version_id": secret_version,
                    "sha256": digest,
                    "state": "configured",
                },
                {"proof_account_credential_sha256": digest},
            ),
            (
                "both_missing",
                0,
                {
                    "parameter_state": "missing",
                    "parameter_version": None,
                    "secret_version_id": None,
                    "sha256": None,
                    "state": "unconfigured",
                },
                {},
            ),
            ("mismatch", 1, None, None),
            ("denied_secret", 1, None, None),
            ("malformed_secret", 1, None, None),
            ("parameter_without_secret", 1, None, None),
        )
        for mode, expected_code, expected_binding, expected_tfvars in cases:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp:
                tmp_path = Path(tmp)
                fake_bin = tmp_path / "bin"
                fake_bin.mkdir()
                fake_aws = fake_bin / "aws"
                fake_aws.write_text(
                    f"""#!/usr/bin/env bash
set -euo pipefail
if [[ "$1" == "secretsmanager" ]]; then
  case "${{FAKE_AWS_MODE}}" in
    configured|seeded_without_parameter|mismatch)
      printf '%s\\n' '{{"SecretString":"{credential}","VersionId":"{secret_version}"}}'
      ;;
    malformed_secret) printf '%s\\n' '{{"SecretString":"wrong"}}' ;;
    denied_secret)
      echo 'An error occurred (AccessDeniedException) when calling GetSecretValue' >&2
      exit 254
      ;;
    both_missing|parameter_without_secret)
      echo 'An error occurred (ResourceNotFoundException) when calling GetSecretValue' >&2
      exit 254
      ;;
  esac
elif [[ "$1" == "ssm" ]]; then
  case "${{FAKE_AWS_MODE}}" in
    configured|parameter_without_secret)
      printf '%s\\n' '{{"Parameter":{{"Value":"{digest}","Version":1}}}}'
      ;;
    mismatch)
      printf '%s\\n' '{{"Parameter":{{"Value":"{"b" * 64}","Version":2}}}}'
      ;;
    seeded_without_parameter|both_missing|malformed_secret)
      echo 'An error occurred (ParameterNotFound) when calling GetParameter' >&2
      exit 254
      ;;
  esac
fi
""",
                    encoding="utf-8",
                )
                fake_aws.chmod(0o755)
                output = tmp_path / "capture"
                result = subprocess.run(
                    [str(BINDING_CAPTURE), str(output)],
                    check=False,
                    capture_output=True,
                    text=True,
                    env={
                        **os.environ,
                        "AWS_REGION": "us-east-2",
                        "PROOF_ACCOUNT_SOURCE_SECRET": "test/proof-account",
                        "PROOF_ACCOUNT_SHA_PARAMETER": "/test/proof-account",
                        "FAKE_AWS_MODE": mode,
                        "PATH": f"{fake_bin}:{os.environ['PATH']}",
                    },
                )
                self.assertEqual(expected_code, result.returncode, result.stderr)
                if expected_code == 0:
                    self.assertEqual(
                        expected_binding,
                        json.loads((output / "binding.json").read_text()),
                    )
                    self.assertEqual(
                        expected_tfvars,
                        json.loads(
                            (output / "terraform.tfvars.json").read_text()
                        ),
                    )
                else:
                    self.assertFalse((output / "binding.json").exists())

    def test_first_binding_plan_allows_only_digest_and_iam_updates(self) -> None:
        for exact in (
            '$binding.state == "configured"',
            '$binding.parameter_state == "missing"',
            'address: "module.udp_proof_runner.aws_iam_role_policy.controller"',
            'address: "module.udp_proof_runner.aws_ssm_parameter.'
            'proof_account_credential_sha256[0]"',
            'actions: ["update"]',
            'actions: ["create"]',
        ):
            self.assertIn(exact, self.raw)
        self.assertIn('select(.mode == "managed")', self.raw)

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
