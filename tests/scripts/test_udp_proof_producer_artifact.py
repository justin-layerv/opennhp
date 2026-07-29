#!/usr/bin/env python3

from __future__ import annotations

import base64
import copy
import hashlib
import importlib.util
import json
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / ".github" / "scripts"
TESTS = ROOT / "tests" / "scripts"
sys.path.insert(0, str(SCRIPTS))
sys.path.insert(0, str(TESTS))

import test_udp_proof_deployment_contract as producer_fixture  # noqa: E402
import test_udp_proof_orchestrator_contract as orchestrator_fixture  # noqa: E402
import udp_proof_deployment_contract as contract  # noqa: E402
import udp_proof_orchestrator_contract as orchestrator  # noqa: E402
import udp_proof_retirement_targets_contract as retirement_targets  # noqa: E402


VALIDATOR_PATH = SCRIPTS / "validate_udp_proof_producer_artifact.py"
SPEC = importlib.util.spec_from_file_location(
    "producer_artifact_validator", VALIDATOR_PATH
)
assert SPEC is not None and SPEC.loader is not None
validator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(validator)

RUN_ID = 999
RUN_ATTEMPT = 1
HEAD_SHA = producer_fixture.PRODUCER_SHA
REPOSITORY_ID = 67890
ARTIFACT_ID = 24680
VALIDATION_TIME = datetime(2026, 7, 25, 12, 0, tzinfo=timezone.utc)


def valid_run() -> dict[str, object]:
    return {
        "conclusion": "success",
        "event": "workflow_dispatch",
        "head_branch": "main",
        "head_repository": {
            "full_name": "layervai/nhp",
            "id": REPOSITORY_ID,
        },
        "head_sha": HEAD_SHA,
        "id": RUN_ID,
        "path": ".github/workflows/udp-proof-deployment-manifest.yml",
        "repository": {"full_name": "layervai/nhp", "id": REPOSITORY_ID},
        "run_attempt": RUN_ATTEMPT,
        "status": "completed",
    }


def artifact(
    *,
    artifact_id: int = ARTIFACT_ID,
    name: str | None = None,
    expired: bool = False,
    created_at: str = "2026-07-25T11:59:00Z",
) -> dict[str, object]:
    return {
        "created_at": created_at,
        "digest": "sha256:" + "d" * 64,
        "expired": expired,
        "id": artifact_id,
        "name": name or f"udp-proof-deployment-manifest-{RUN_ID}-{RUN_ATTEMPT}",
        "size_in_bytes": 4096,
        "workflow_run": {
            "head_branch": "main",
            "head_repository_id": REPOSITORY_ID,
            "head_sha": HEAD_SHA,
            "id": RUN_ID,
            "repository_id": REPOSITORY_ID,
        },
    }


def valid_artifacts_response() -> dict[str, object]:
    # Older rerun artifacts may remain attached to one run. The current
    # attempt must still select exactly one unexpired canonical artifact.
    artifacts = [
        artifact(
            artifact_id=ARTIFACT_ID - 1,
            name=f"udp-proof-deployment-manifest-{RUN_ID}-2",
            expired=True,
            created_at="2026-07-25T11:58:00Z",
        ),
        artifact(),
    ]
    return {"artifacts": artifacts, "total_count": len(artifacts)}


def write_valid_triplet(directory: Path) -> dict[str, object]:
    snapshot = producer_fixture.valid_snapshot()
    manifest_raw, runtime_raw, provenance_raw = contract.validate_triplet(
        snapshot["manifest"],
        snapshot["runtime"],
        snapshot["provenance"],
        proof_phase="pre_removal",
        producer_run_id=RUN_ID,
        producer_run_attempt=RUN_ATTEMPT,
        producer_head_sha=HEAD_SHA,
        validation_time=VALIDATION_TIME,
    )
    for name, raw in (
        ("deployment-manifest.json", manifest_raw),
        ("deployment-runtime-inputs.json", runtime_raw),
        ("deployment-provenance.json", provenance_raw),
    ):
        (directory / name).write_bytes(raw)
    write_orchestrator_evidence(directory)
    write_retirement_targets(directory)
    return snapshot


def write_orchestrator_evidence(directory: Path) -> None:
    """Add the fourth canonical file the producer artifact must now carry."""

    document, *_ = orchestrator_fixture.build_document()
    (directory / contract.ORCHESTRATOR_EVIDENCE_FILE).write_bytes(
        orchestrator.canonical_bytes(document)
    )


def write_retirement_targets(directory: Path) -> None:
    provenance_raw = (directory / "deployment-provenance.json").read_bytes()
    route53 = lambda host, zone: {  # noqa: E731
        "alias_dns_name": f"dualstack.{host}",
        "record_name": host,
        "zone_id": zone,
    }
    document = {
        "gate": retirement_targets.GATE,
        "http_operations": [
            {
                "host": host,
                "method": method,
                "path": path,
                "route53": route53(host, zone),
            }
            for host, method, path, zone in retirement_targets.HTTP_OPERATIONS
        ],
        "observed_at": VALIDATION_TIME.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "phase": "pre_removal",
        "producer": {
            "deployment_provenance_sha256": hashlib.sha256(
                provenance_raw
            ).hexdigest(),
            "head_sha": HEAD_SHA,
            "run_attempt": RUN_ATTEMPT,
            "run_id": RUN_ID,
            "surface_contract_sha256": "a" * 64,
        },
        "relay": {
            "aliases": [
                {"cell_id": "cell0", "server_id": "AAAAAAAAAAA"},
                {"cell_id": "cell1", "server_id": "BBBBBBBBBBB"},
            ],
            "base_url": retirement_targets.RELAY_BASE_URL,
            "route53": route53(
                "relay.qurl.link.layerv.xyz",
                retirement_targets.PUBLIC_ZONE_ID,
            ),
            "ssm": {
                "name": retirement_targets.RELAY_PARAMETER,
                "value_sha256": hashlib.sha256(
                    retirement_targets.RELAY_BASE_URL.encode("ascii")
                ).hexdigest(),
                "version": 2,
            },
        },
        "schema_version": 1,
    }
    (directory / retirement_targets.ARTIFACT_FILE_NAME).write_bytes(
        retirement_targets.canonical_bytes(document)
    )


def rewrite_snapshot(directory: Path, snapshot: dict[str, object]) -> None:
    manifest_raw = contract.canonical_bytes(
        snapshot["manifest"],
        maximum=contract.MAX_MANIFEST_BYTES,
        name="deployment-manifest.json",
    )
    runtime_raw = contract.canonical_bytes(
        snapshot["runtime"],
        maximum=contract.MAX_RUNTIME_BYTES,
        name="deployment-runtime-inputs.json",
    )
    provenance = snapshot["provenance"]
    provenance["files"] = {  # type: ignore[index]
        "deployment-manifest.json": (
            "sha256:" + hashlib.sha256(manifest_raw).hexdigest()
        ),
        "deployment-runtime-inputs.json": (
            "sha256:" + hashlib.sha256(runtime_raw).hexdigest()
        ),
    }
    (directory / "deployment-manifest.json").write_bytes(manifest_raw)
    (directory / "deployment-runtime-inputs.json").write_bytes(runtime_raw)
    (directory / "deployment-provenance.json").write_bytes(
        contract.canonical_bytes(
            provenance,
            maximum=contract.MAX_PROVENANCE_BYTES,
            name="deployment-provenance.json",
        )
    )
    write_retirement_targets(directory)


class MetadataTest(unittest.TestCase):
    def test_accepts_exact_run_and_current_attempt_artifact(self) -> None:
        outputs = validator.validate_metadata(
            valid_run(),
            valid_artifacts_response(),
            str(RUN_ID),
            current_time=VALIDATION_TIME,
        )
        self.assertEqual(outputs["producer_artifact_id"], str(ARTIFACT_ID))
        self.assertEqual(outputs["producer_run_attempt"], str(RUN_ATTEMPT))
        self.assertEqual(outputs["producer_head_sha"], HEAD_SHA)

    def test_rejects_run_identity_drift(self) -> None:
        for field, value in (
            ("id", RUN_ID + 1),
            ("path", ".github/workflows/other.yml"),
            ("event", "pull_request"),
            ("head_branch", "feature"),
            ("head_sha", "f" * 40),
            ("conclusion", "failure"),
            ("status", "in_progress"),
            ("run_attempt", True),
        ):
            with self.subTest(field=field):
                run = valid_run()
                run[field] = value
                with self.assertRaises(validator.ArtifactValidationError):
                    validator.validate_metadata(
                        run,
                        valid_artifacts_response(),
                        str(RUN_ID),
                        current_time=VALIDATION_TIME,
                    )

    def test_rejects_repository_identity_drift(self) -> None:
        for container, field, value in (
            ("repository", "full_name", "attacker/nhp"),
            ("repository", "id", True),
            ("repository", "id", REPOSITORY_ID + 1),
            ("head_repository", "full_name", "attacker/nhp"),
            ("head_repository", "id", REPOSITORY_ID + 1),
        ):
            with self.subTest(container=container, field=field, value=value):
                run = valid_run()
                run[container][field] = value  # type: ignore[index]
                with self.assertRaises(validator.ArtifactValidationError):
                    validator.validate_metadata(
                        run,
                        valid_artifacts_response(),
                        str(RUN_ID),
                        current_time=VALIDATION_TIME,
                    )

    def test_rejects_missing_repository_identity(self) -> None:
        for field in ("repository", "head_repository"):
            with self.subTest(field=field):
                run = valid_run()
                del run[field]
                with self.assertRaises(validator.ArtifactValidationError):
                    validator.validate_metadata(
                        run,
                        valid_artifacts_response(),
                        str(RUN_ID),
                        current_time=VALIDATION_TIME,
                    )

    def test_rejects_incomplete_or_mismatched_artifact_listing(self) -> None:
        incomplete = valid_artifacts_response()
        incomplete["total_count"] = 3
        wrong_run = valid_artifacts_response()
        wrong_run["artifacts"][1]["workflow_run"]["head_sha"] = "f" * 40  # type: ignore[index]
        future = valid_artifacts_response()
        future["artifacts"][1]["created_at"] = "2026-07-25T12:01:00Z"  # type: ignore[index]
        duplicate = valid_artifacts_response()
        duplicate["artifacts"].append(copy.deepcopy(duplicate["artifacts"][1]))  # type: ignore[union-attr]
        duplicate["total_count"] = 3
        for response in (incomplete, wrong_run, future, duplicate):
            with self.subTest(response=response):
                with self.assertRaises(validator.ArtifactValidationError):
                    validator.validate_metadata(
                        valid_run(),
                        response,
                        str(RUN_ID),
                        current_time=VALIDATION_TIME,
                    )

    def test_rejects_current_artifact_identity_or_integrity_drift(self) -> None:
        responses: list[dict[str, object]] = []
        for field, value in (
            ("name", "operator-manifest"),
            ("digest", "sha256:not-a-digest"),
            ("size_in_bytes", contract.MAX_PRODUCER_ARTIFACT_BYTES + 1),
            ("expired", True),
            ("id", True),
        ):
            response = valid_artifacts_response()
            response["artifacts"][1][field] = value  # type: ignore[index]
            responses.append(response)
        for field, value in (
            ("id", RUN_ID + 1),
            ("repository_id", REPOSITORY_ID + 1),
            ("head_repository_id", REPOSITORY_ID + 1),
            ("head_branch", "feature"),
        ):
            response = valid_artifacts_response()
            response["artifacts"][1]["workflow_run"][field] = value  # type: ignore[index]
            responses.append(response)
        for response in responses:
            with self.subTest(response=response):
                with self.assertRaises(validator.ArtifactValidationError):
                    validator.validate_metadata(
                        valid_run(),
                        response,
                        str(RUN_ID),
                        current_time=VALIDATION_TIME,
                    )


class FilesTest(unittest.TestCase):
    def validate(self, directory: Path, **overrides: object) -> dict[str, str]:
        values: dict[str, object] = {
            "client": "connector",
            "pre_removal_run_id": "",
            "producer_head_sha": HEAD_SHA,
            "producer_run_attempt": str(RUN_ATTEMPT),
            "producer_run_id": str(RUN_ID),
            "proof_phase": "pre_removal",
            "validation_time": VALIDATION_TIME,
        }
        values.update(overrides)
        return validator.validate_files(directory, **values)

    def test_accepts_complete_shared_contract_and_derives_dispatch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            snapshot = write_valid_triplet(directory)
            outputs = self.validate(directory)
            self.assertEqual(
                outputs["client_ref"],
                snapshot["provenance"]["candidates"]["qurl_connector"]["head_ref"],  # type: ignore[index]
            )
            self.assertEqual(
                base64.b64decode(outputs["deployment_manifest_b64"]),
                (directory / "deployment-manifest.json").read_bytes(),
            )
            self.assertEqual(
                base64.b64decode(outputs["deployment_runtime_inputs_b64"]),
                (directory / "deployment-runtime-inputs.json").read_bytes(),
            )
            self.assertEqual(
                outputs["deployment_manifest_sha256"],
                hashlib.sha256(
                    (directory / "deployment-manifest.json").read_bytes()
                ).hexdigest(),
            )
            self.assertEqual(
                outputs["deployment_runtime_inputs_sha256"],
                hashlib.sha256(
                    (directory / "deployment-runtime-inputs.json").read_bytes()
                ).hexdigest(),
            )
            self.assertEqual(
                outputs["proof_recovery_alias_arn"],
                "arn:aws:lambda:us-east-2:767397897469:"
                "function:layerv-nhp-sandbox-ca-pcr:blue",
            )
            self.assertNotIn("connector_ref", outputs)
            self.assertNotIn("qurl_go_ref", outputs)

    def test_rejects_missing_or_ambiguous_recovery_alias(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            snapshot = write_valid_triplet(directory)
            authority = snapshot["provenance"]["evidence"]["workloads"][  # type: ignore[index]
                "qurl_service_authority"
            ]
            functions = authority["functions"]
            pcr = functions.pop()
            rewrite_snapshot(directory, snapshot)
            with self.assertRaisesRegex(
                validator.ArtifactValidationError,
                "orchestrator evidence is not bound",
            ):
                self.validate(directory)

            functions.append(pcr)
            duplicate = copy.deepcopy(pcr)
            duplicate["alias_arn"] = (
                duplicate["alias_arn"].removesuffix(":blue") + ":green"
            )
            functions.append(duplicate)
            functions.sort(key=lambda item: (item["alias_arn"], item["version_arn"]))
            rewrite_snapshot(directory, snapshot)
            with self.assertRaisesRegex(
                validator.ArtifactValidationError,
                "orchestrator evidence is not bound",
            ):
                self.validate(directory)

    def test_selects_qurl_go_ref_only_from_authenticated_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            snapshot = write_valid_triplet(directory)
            outputs = self.validate(
                directory,
                client="qurl_go",
            )
            self.assertEqual(
                outputs["client_ref"],
                snapshot["provenance"]["candidates"]["qurl_go"]["head_ref"],  # type: ignore[index]
            )
            self.assertEqual(
                outputs["client_sha"],
                snapshot["manifest"]["repositories"]["qurl_go"],  # type: ignore[index]
            )

    def test_rejects_any_complete_evidence_or_candidate_drift(self) -> None:
        for mutation in ("account", "candidate", "file_digest"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as tmp:
                directory = Path(tmp)
                snapshot = write_valid_triplet(directory)
                if mutation == "account":
                    snapshot["provenance"]["evidence"]["aws"]["account_id"] = (
                        "000000000000"  # type: ignore[index]
                    )
                    rewrite_snapshot(directory, snapshot)
                elif mutation == "candidate":
                    snapshot["provenance"]["candidates"]["qurl_go"]["head_sha"] = (
                        "0" * 40
                    )  # type: ignore[index]
                    rewrite_snapshot(directory, snapshot)
                else:
                    provenance_path = directory / "deployment-provenance.json"
                    provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
                    provenance["files"]["deployment-manifest.json"] = (
                        "sha256:" + "f" * 64
                    )
                    provenance_path.write_bytes(
                        contract.canonical_bytes(
                            provenance,
                            maximum=contract.MAX_PROVENANCE_BYTES,
                            name="deployment-provenance.json",
                        )
                    )
                with self.assertRaises(validator.ArtifactValidationError):
                    self.validate(directory)

    def test_rejects_extra_nonregular_and_stale_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            write_valid_triplet(directory)
            (directory / "extra").write_text("x", encoding="utf-8")
            with self.assertRaises(validator.ArtifactValidationError):
                self.validate(directory)
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            write_valid_triplet(directory)
            manifest_path = directory / "deployment-manifest.json"
            manifest_bytes = manifest_path.read_bytes()
            manifest_path.unlink()
            target = directory / "manifest-target"
            target.write_bytes(manifest_bytes)
            manifest_path.symlink_to(target)
            with self.assertRaises(validator.ArtifactValidationError):
                self.validate(directory)
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            write_valid_triplet(directory)
            with self.assertRaisesRegex(
                validator.ArtifactValidationError, "no more than 10 minutes old"
            ):
                self.validate(
                    directory,
                    validation_time=datetime(2026, 7, 25, 12, 20, tzinfo=timezone.utc),
                )

    def test_requires_valid_orchestrator_evidence_in_the_same_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            write_valid_triplet(directory)
            outputs = self.validate(directory)
            self.assertEqual(
                outputs["orchestrator_evidence_sha256"],
                hashlib.sha256(
                    (directory / contract.ORCHESTRATOR_EVIDENCE_FILE).read_bytes()
                ).hexdigest(),
            )
        # Missing entirely.
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            write_valid_triplet(directory)
            (directory / contract.ORCHESTRATOR_EVIDENCE_FILE).unlink()
            with self.assertRaises(validator.ArtifactValidationError):
                self.validate(directory)
        # Present but bound to a different deployment observation.
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            write_valid_triplet(directory)
            document, *_ = orchestrator_fixture.build_document()
            document["bindings"]["deployment_manifest_sha256"] = "0" * 64
            (directory / contract.ORCHESTRATOR_EVIDENCE_FILE).write_bytes(
                orchestrator.canonical_bytes(document)
            )
            with self.assertRaises(validator.ArtifactValidationError):
                self.validate(directory)

    def test_rejects_phase_or_authenticated_producer_mismatch(self) -> None:
        for overrides in (
            {"proof_phase": "post_removal", "pre_removal_run_id": "12345"},
            {"producer_run_id": str(RUN_ID + 1)},
            {"producer_run_attempt": str(RUN_ATTEMPT + 1)},
            {"producer_head_sha": "f" * 40},
        ):
            with (
                self.subTest(overrides=overrides),
                tempfile.TemporaryDirectory() as tmp,
            ):
                directory = Path(tmp)
                write_valid_triplet(directory)
                with self.assertRaises(validator.ArtifactValidationError):
                    self.validate(directory, **overrides)


if __name__ == "__main__":
    unittest.main()
