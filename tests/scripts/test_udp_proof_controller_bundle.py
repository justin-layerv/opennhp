#!/usr/bin/env python3

from __future__ import annotations

import copy
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / ".github" / "scripts"
sys.path.insert(0, str(SCRIPTS))

import udp_proof_deployment_contract as deployment  # noqa: E402
import validate_udp_proof_controller_bundle as validator  # noqa: E402
from tests.scripts import test_udp_proof_runtime_evidence as fixtures  # noqa: E402


RUN_ID = 7001
RUN_ATTEMPT = 2
HEAD_SHA = "a" * 40
ARTIFACT_ID = 9001
ARTIFACT_DIGEST = "sha256:" + "b" * 64


def run_document() -> dict[str, object]:
    return {
        "conclusion": "success",
        "event": "workflow_dispatch",
        "head_branch": "main",
        "head_sha": HEAD_SHA,
        "id": RUN_ID,
        "path": ".github/workflows/udp-proof-controller.yml",
        "repository": {"full_name": "layervai/nhp"},
        "run_attempt": RUN_ATTEMPT,
        "status": "completed",
    }


def artifact_document() -> dict[str, object]:
    return {
        "digest": ARTIFACT_DIGEST,
        "expired": False,
        "id": ARTIFACT_ID,
        "name": (
            "udp-proof-controller-attestation-connector-pre_removal-"
            f"{RUN_ID}-{RUN_ATTEMPT}"
        ),
        "workflow_run": {"id": RUN_ID},
    }


class ControllerBundleTest(unittest.TestCase):
    def test_metadata_authenticates_exact_successful_main_attempt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run_path = root / "run.json"
            artifacts_path = root / "artifacts.json"
            run_path.write_text(json.dumps(run_document()))
            artifacts_path.write_text(
                json.dumps({"artifacts": [artifact_document()], "total_count": 1})
            )
            self.assertEqual(
                validator.metadata(
                    run_path=run_path,
                    artifacts_path=artifacts_path,
                    client="connector",
                    proof_phase="pre_removal",
                    run_id=str(RUN_ID),
                ),
                {
                    "artifact_digest": ARTIFACT_DIGEST,
                    "artifact_id": str(ARTIFACT_ID),
                    "head_sha": HEAD_SHA,
                    "run_attempt": str(RUN_ATTEMPT),
                    "run_id": str(RUN_ID),
                },
            )

            stale = artifact_document()
            stale["name"] = stale["name"].replace(
                f"-{RUN_ATTEMPT}", f"-{RUN_ATTEMPT - 1}"
            )
            artifacts_path.write_text(
                json.dumps({"artifacts": [stale], "total_count": 1})
            )
            with self.assertRaisesRegex(
                deployment.ContractError, "one exact current-attempt bundle"
            ):
                validator.metadata(
                    run_path=run_path,
                    artifacts_path=artifacts_path,
                    client="connector",
                    proof_phase="pre_removal",
                    run_id=str(RUN_ID),
                )

    def test_files_bind_attestation_to_exact_embedded_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifact_dir = root / "client-artifact"
            artifact_dir.mkdir()
            evidence_raw = b'{"proof":true}\n'
            inventory_raw = b'{"scenarios":[]}\n'
            (artifact_dir / "strict-sandbox-proof.evidence.json").write_bytes(
                evidence_raw
            )
            (artifact_dir / "strict-proof-scenarios.json").write_bytes(
                inventory_raw
            )
            attestation = copy.deepcopy(fixtures.attestation("connector"))
            attestation["controller"].update(
                {
                    "head_sha": HEAD_SHA,
                    "run_attempt": RUN_ATTEMPT,
                    "run_id": RUN_ID,
                }
            )
            attestation["client_artifact"]["evidence_sha256"] = hashlib.sha256(
                evidence_raw
            ).hexdigest()
            (root / "controller-attestation.json").write_bytes(
                deployment.canonical_bytes(
                    attestation,
                    maximum=128 * 1024,
                    name="connector controller attestation",
                )
            )

            outputs = validator.files(
                directory=root,
                client="connector",
                proof_phase="pre_removal",
                run_id=str(RUN_ID),
                run_attempt=str(RUN_ATTEMPT),
                head_sha=HEAD_SHA,
            )
            self.assertEqual(
                outputs["evidence_sha256"],
                hashlib.sha256(evidence_raw).hexdigest(),
            )

            (artifact_dir / "strict-sandbox-proof.evidence.json").write_bytes(
                b'{"proof":false}\n'
            )
            with self.assertRaisesRegex(
                deployment.ContractError, "client evidence digest drift"
            ):
                validator.files(
                    directory=root,
                    client="connector",
                    proof_phase="pre_removal",
                    run_id=str(RUN_ID),
                    run_attempt=str(RUN_ATTEMPT),
                    head_sha=HEAD_SHA,
                )


if __name__ == "__main__":
    unittest.main()
