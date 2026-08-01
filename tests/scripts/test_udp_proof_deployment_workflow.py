#!/usr/bin/env python3

from __future__ import annotations

import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "udp-proof-deployment-manifest.yml"


class DeploymentManifestWorkflowTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.raw = WORKFLOW.read_text(encoding="utf-8")
        cls.workflow = yaml.load(cls.raw, Loader=yaml.BaseLoader)

    def test_dispatch_surface_contains_only_non_authoritative_selectors(self) -> None:
        self.assertEqual(
            set(self.workflow["on"]),
            {"workflow_dispatch"},
        )
        inputs = self.workflow["on"]["workflow_dispatch"]["inputs"]
        self.assertEqual(
            set(inputs),
            # No client selector inputs by design: main is the bible. The
            # producer resolves each client's main at run time, so there is
            # nothing for a dispatcher to choose -- and therefore nothing to
            # keep in sync with the client repositories.
            {
                "proof_phase",
                "connector_canary_run_id",
                "terraform_apply_run_id",
            },
        )
        self.assertEqual(
            inputs["proof_phase"]["options"],
            ["pre_removal", "post_removal"],
        )
        forbidden = (
            "sha",
            "digest",
            "host",
            "port",
            "key",
            "cell",
            "topology",
            "ref",
            "image",
        )
        self.assertFalse(
            any(token in input_name for input_name in inputs for token in forbidden)
        )

    def test_workflow_is_trusted_main_read_only_and_headless(self) -> None:
        # packages:read is required and is still read-only. GHCR authorizes
        # container packages per repository via the package's "Manage Actions
        # access" list, which grants a repository's GITHUB_TOKEN rather than a
        # third-party App installation token, so the private canary pull cannot
        # use the evidence App's token no matter what it is granted.
        self.assertEqual(
            self.workflow["permissions"],
            {"contents": "read", "id-token": "write", "packages": "read"},
        )
        # Nothing in this workflow may acquire a write permission.
        self.assertEqual(
            {
                scope
                for scope, level in self.workflow["permissions"].items()
                if level != "read"
            },
            {"id-token"},
        )
        jobs = self.workflow["jobs"]
        self.assertEqual(set(jobs), {"produce"})
        self.assertEqual(
            jobs["produce"]["environment"],
            "udp-proof-manifest-sandbox",
        )
        lowered = self.raw.lower()
        for forbidden in (
            "electron",
            "react",
            "vite",
            "npm ",
            "qurl-desktop",
        ):
            self.assertNotIn(forbidden, lowered)
        self.assertIn("refs/heads/main", self.raw)
        self.assertIn("commit.verification.verified == true", self.raw)
        self.assertIn('python-version: "3.12"', self.raw)

    def test_orchestrator_evidence_is_observed_into_the_same_artifact(self) -> None:
        steps = self.workflow["jobs"]["produce"]["steps"]
        names = [step.get("name") for step in steps]
        render = names.index("Render exactly three canonical proof inputs")
        observe = names.index("Observe the orchestrator-owned scenario evidence")
        upload = next(
            index
            for index, step in enumerate(steps)
            if str(step.get("uses", "")).startswith("actions/upload-artifact@")
        )
        # The fourth file must land in the same artifact directory, after the
        # triplet exists and before the single upload.
        self.assertLess(render, observe)
        self.assertLess(observe, upload)
        step = steps[observe]
        self.assertEqual(
            set(step["env"]),
            {"GH_TOKEN", "PROOF_PHASE", "TERRAFORM_APPLY_RUN_ID"},
        )
        self.assertIn("collect_udp_proof_orchestrator_evidence.py", step["run"])
        self.assertIn("--output artifact/orchestrator-evidence.json", step["run"])
        self.assertIn(
            '--terraform-apply-run-id "${TERRAFORM_APPLY_RUN_ID}"',
            step["run"],
        )
        self.assertIn(
            "pre_removal forbids terraform_apply_run_id",
            step["run"],
        )
        # The producer reads only the deployed revisions, so it needs no AWS
        # credential and must not acquire one.
        self.assertNotIn("aws ", step["run"])
        self.assertIn('[[ "${count}" = "4" && -z "${nonfiles}" ]]', self.raw)

    def test_retirement_target_collector_receives_the_read_only_app_token(
        self,
    ) -> None:
        steps = self.workflow["jobs"]["produce"]["steps"]
        step = next(
            step
            for step in steps
            if step.get("name") == "Observe exact HTTP and relay retirement targets"
        )
        self.assertEqual(set(step["env"]), {"GH_TOKEN", "PROOF_PHASE"})
        self.assertEqual(
            step["env"]["GH_TOKEN"],
            "${{ steps.app.outputs.token }}",
        )
        self.assertIn("collect_udp_proof_retirement_targets.py", step["run"])

    def test_artifact_is_one_exact_three_file_handoff(self) -> None:
        steps = self.workflow["jobs"]["produce"]["steps"]
        uploads = [
            step
            for step in steps
            if str(step.get("uses", "")).startswith("actions/upload-artifact@")
        ]
        self.assertEqual(len(uploads), 1)
        self.assertEqual(
            uploads[0]["with"]["name"],
            "udp-proof-deployment-manifest-${{ github.run_id }}-${{ github.run_attempt }}",
        )
        self.assertEqual(uploads[0]["with"]["path"], "artifact")
        self.assertIn('[[ "${count}" = "3" && -z "${nonfiles}" ]]', self.raw)
        for filename in (
            "deployment-manifest.json",
            "deployment-runtime-inputs.json",
            "deployment-provenance.json",
        ):
            self.assertIn(
                filename,
                (
                    ROOT
                    / ".github"
                    / "scripts"
                    / "produce_udp_proof_deployment_manifest.py"
                ).read_text(encoding="utf-8"),
            )

    def test_private_canary_is_signature_and_predicate_verified(self) -> None:
        self.assertIn("cosign verify ", self.raw)
        self.assertIn("cosign verify-attestation ", self.raw)
        self.assertIn(
            "https://layerv.ai/attestations/qurl-connector-canary/v1",
            self.raw,
        )
        self.assertIn(".predicate == $expected[0]", self.raw)
        self.assertIn("permission-packages: read", self.raw)
        self.assertIn('cosign-release: "v3.0.6"', self.raw)
        self.assertEqual(
            self.raw.count(
                '--certificate-github-workflow-name "Connector Canary Publish"'
            ),
            2,
        )
        for exact_pin in (
            '--certificate-github-workflow-ref "refs/heads/main"',
            '--certificate-github-workflow-repository "layervai/qurl-connector"',
            '--certificate-github-workflow-sha "${CANARY_WORKFLOW_SHA}"',
        ):
            self.assertEqual(self.raw.count(exact_pin), 2)
        self.assertIn(
            "CANARY_WORKFLOW_SHA: ${{ steps.metadata.outputs.canary_head_sha }}",
            self.raw,
        )

    def test_qurl_runtime_is_independently_attested(self) -> None:
        collector = (
            ROOT / ".github" / "scripts" / "collect_udp_proof_deployment_evidence.py"
        ).read_text(encoding="utf-8")
        self.assertIn("permission-attestations: read", self.raw)
        self.assertIn(
            "layervai/qurl-service/.github/workflows/publish-cell-runtime.yml",
            collector,
        )
        self.assertIn("--deny-self-hosted-runners", collector)
        self.assertIn("--source-digest", collector)
        self.assertIn("--source-ref", collector)
        self.assertIn("aws ecr get-login-password", self.raw)
        self.assertIn(
            "767397897469.dkr.ecr.us-east-2.amazonaws.com",
            self.raw,
        )
        self.assertIn("docker logout", self.raw)
        self.assertIn("GH_TOKEN: ${{ steps.app.outputs.token }}", self.raw)


if __name__ == "__main__":
    unittest.main()
