#!/usr/bin/env python3

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / ".github" / "scripts"
TESTS = ROOT / "tests" / "scripts"
sys.path.insert(0, str(SCRIPTS))
sys.path.insert(0, str(TESTS))

import collect_udp_proof_controller_attestation as collector  # noqa: E402
import test_udp_proof_deployment_contract as producer_fixture  # noqa: E402
import udp_proof_deployment_contract as deployment  # noqa: E402
import udp_proof_runtime_evidence_contract as runtime  # noqa: E402
from tests.scripts import test_udp_proof_runtime_evidence as fixtures  # noqa: E402


class ControllerAttestationTest(unittest.TestCase):
    def test_collects_observation_derived_qurl_go_attestation(self) -> None:
        source = fixtures.attestation("qurl_go")
        snapshot = producer_fixture.valid_snapshot()
        artifact = source["client_artifact"]
        controller = source["controller"]
        producer = snapshot["provenance"]["producer"]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            producer_dir = root / "producer"
            client_dir = root / "client"
            producer_dir.mkdir()
            client_dir.mkdir()
            for name, value, maximum in (
                (
                    "deployment-manifest.json",
                    snapshot["manifest"],
                    deployment.MAX_MANIFEST_BYTES,
                ),
                (
                    "deployment-runtime-inputs.json",
                    snapshot["runtime"],
                    deployment.MAX_RUNTIME_BYTES,
                ),
                (
                    "deployment-provenance.json",
                    snapshot["provenance"],
                    deployment.MAX_PROVENANCE_BYTES,
                ),
            ):
                (producer_dir / name).write_bytes(
                    deployment.canonical_bytes(
                        value, maximum=maximum, name=name
                    )
                )
            paths: dict[str, Path] = {}
            for name, value in (
                ("assignment", source["assignment_receipt"]),
                ("transport", source["transport_receipt"]),
                ("probe", source["runtime_probe"]),
                ("server", source["server_receipt"]),
            ):
                path = root / f"{name}.json"
                path.write_bytes(
                    deployment.canonical_bytes(
                        value, maximum=256 * 1024, name=name
                    )
                )
                paths[name] = path
            # The qurl-go workflow canonicalizes the reviewed repository file
            # into the uploaded artifact. The collector must hash those exact
            # authenticated artifact bytes without another re-encoding.
            surface = deployment.canonical_bytes(
                {"public_http_operations": [], "schema_version": 1},
                maximum=256 * 1024,
                name="retired lifecycle surface",
            )
            (client_dir / "retired_lifecycle_surface.json").write_bytes(surface)
            args = argparse.Namespace(
                assignment_receipt=paths["assignment"],
                client="qurl_go",
                client_artifact_digest=artifact["artifact_digest"],
                client_artifact_id=str(artifact["artifact_id"]),
                client_directory=client_dir,
                client_evidence_sha256=artifact["evidence_sha256"],
                client_head_sha=artifact["head_sha"],
                client_run_attempt=str(artifact["run_attempt"]),
                client_run_id=str(artifact["run_id"]),
                client_typed_evidence_sha256=artifact[
                    "typed_evidence_sha256"
                ],
                controller_head_sha=controller["head_sha"],
                controller_run_attempt=str(controller["run_attempt"]),
                controller_run_id=str(controller["run_id"]),
                packet_capture_sha256=source["transport_receipt"][
                    "capture_sha256"
                ],
                producer_artifact_digest="sha256:" + "1" * 64,
                producer_artifact_id="1001",
                producer_directory=producer_dir,
                producer_head_sha=producer["head_sha"],
                producer_run_attempt=str(producer["run_attempt"]),
                producer_run_id=str(producer["run_id"]),
                proof_phase="pre_removal",
                runner_instance_id="i-0fedcba9876543210",
                runtime_probe=paths["probe"],
                server_receipt=paths["server"],
                transport_receipt=paths["transport"],
            )
            raw = collector.collect(args, observed_at=fixtures.NOW)
            document = json.loads(raw)
            self.assertEqual(set(document["rows"]), set(runtime.ROW_VALIDATORS))
            self.assertEqual(
                document["runner"]["packet_capture_sha256"],
                source["transport_receipt"]["capture_sha256"],
            )
            self.assertEqual(
                document["server_receipt"], source["server_receipt"]
            )
            self.assertEqual(
                document["surface_contract_sha256"],
                hashlib.sha256(surface).hexdigest(),
            )


if __name__ == "__main__":
    unittest.main()
