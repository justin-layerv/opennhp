#!/usr/bin/env python3

from __future__ import annotations

import copy
import hashlib
import importlib.util
import io
import json
import stat
import sys
import tempfile
import unittest
import warnings
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / ".github" / "scripts"
TESTS = ROOT / "tests" / "scripts"
sys.path.insert(0, str(SCRIPTS))
sys.path.insert(0, str(TESTS))

import test_udp_proof_deployment_contract as producer_fixture  # noqa: E402
import udp_proof_deployment_contract as contract  # noqa: E402


VALIDATOR_PATH = SCRIPTS / "validate_udp_proof_client_artifact.py"
SPEC = importlib.util.spec_from_file_location(
    "client_artifact_validator", VALIDATOR_PATH
)
assert SPEC is not None and SPEC.loader is not None
validator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(validator)

CLIENT_RUN_ID = 12345
CLIENT_RUN_ATTEMPT = 1
CONTROLLER_RUN_ID = 54321
CONTROLLER_RUN_ATTEMPT = 2
PRODUCER_RUN_ID = 999
PRODUCER_RUN_ATTEMPT = 1
PRODUCER_ARTIFACT_ID = 24680
PRODUCER_ARTIFACT_DIGEST = "sha256:" + "d" * 64
PRODUCER_HEAD_SHA = producer_fixture.PRODUCER_SHA
REPOSITORY_ID = 67890
CLIENT_ARTIFACT_ID = 13579


def target(client: str) -> dict[str, str]:
    snapshot = producer_fixture.valid_snapshot()
    if client == "connector":
        return {
            "repository": "layervai/qurl-connector",
            "ref": snapshot["provenance"]["candidates"]["qurl_connector"]["head_ref"],
            "sha": snapshot["manifest"]["repositories"]["qurl_connector"],
            "workflow": ".github/workflows/sandbox-smoke.yml",
            "prefix": "strict-sandbox-proof",
        }
    return {
        "repository": "layervai/qurl-go",
        "ref": snapshot["provenance"]["candidates"]["qurl_go"]["head_ref"],
        "sha": snapshot["manifest"]["repositories"]["qurl_go"],
        "workflow": ".github/workflows/native-udp-sandbox.yml",
        "prefix": "native-udp-sandbox",
    }


def correlation(client: str, phase: str) -> str:
    return (
        f"nhp-{CONTROLLER_RUN_ID}-{CONTROLLER_RUN_ATTEMPT}-{client}-{phase}-"
        + "a" * 32
    )


def valid_run(client: str, phase: str = "pre_removal") -> dict[str, object]:
    selected = target(client)
    return {
        "conclusion": "success",
        "display_title": f"UDP proof [corr:{correlation(client, phase)}]",
        "event": "workflow_dispatch",
        "head_branch": selected["ref"],
        "head_repository": {
            "full_name": selected["repository"],
            "id": REPOSITORY_ID,
        },
        "head_sha": selected["sha"],
        "id": CLIENT_RUN_ID,
        "path": selected["workflow"],
        "repository": {
            "full_name": selected["repository"],
            "id": REPOSITORY_ID,
        },
        "run_attempt": CLIENT_RUN_ATTEMPT,
        "status": "completed",
    }


def artifact(client: str, phase: str = "pre_removal") -> dict[str, object]:
    selected = target(client)
    return {
        "digest": "sha256:" + "e" * 64,
        "expired": False,
        "id": CLIENT_ARTIFACT_ID,
        "name": (
            f"{selected['prefix']}-{phase}-{selected['sha']}-"
            f"{CLIENT_RUN_ATTEMPT}"
        ),
        "size_in_bytes": 4096,
        "workflow_run": {
            "head_branch": selected["ref"],
            "head_repository_id": REPOSITORY_ID,
            "head_sha": selected["sha"],
            "id": CLIENT_RUN_ID,
            "repository_id": REPOSITORY_ID,
        },
    }


def artifacts_response(
    client: str, phase: str = "pre_removal"
) -> dict[str, object]:
    artifacts = [artifact(client, phase)]
    return {"artifacts": artifacts, "total_count": len(artifacts)}


def producer_object() -> dict[str, str]:
    return {
        "artifact_digest": PRODUCER_ARTIFACT_DIGEST,
        "artifact_id": str(PRODUCER_ARTIFACT_ID),
        "head_sha": PRODUCER_HEAD_SHA,
        "repository": "layervai/nhp",
        "run_attempt": str(PRODUCER_RUN_ATTEMPT),
        "run_id": str(PRODUCER_RUN_ID),
        "workflow_path": ".github/workflows/udp-proof-deployment-manifest.yml",
    }


def evidence(
    client: str,
    manifest_raw: bytes,
    runtime_raw: bytes,
    *,
    phase: str = "pre_removal",
    pre_removal_run_id: str = "",
    connector_proof_run_id: str = "777",
) -> dict[str, object]:
    selected = target(client)
    value: dict[str, object] = {
        "commit_sha": selected["sha"],
        "counts": {
            "blocking": 0,
            "exact_passes": 1,
            "failures": 0,
            "implemented": 1,
            "skips": 0,
        },
        "deployment_manifest_sha256": hashlib.sha256(manifest_raw).hexdigest(),
        "deployment_producer": producer_object(),
        "deployment_runtime_inputs_sha256": hashlib.sha256(runtime_raw).hexdigest(),
        "dispatch_correlation_id": correlation(client, phase),
        "enforcement_outcome": "success",
        "gate_passed": True,
        "inputs_unchanged": True,
        "inventory_sha256": "1" * 64,
        "nhp_controller_run_attempt": str(CONTROLLER_RUN_ATTEMPT),
        "nhp_controller_run_id": str(CONTROLLER_RUN_ID),
        "phase": phase,
        "pre_removal_deployment_sha256": None,
        "pre_removal_evidence_sha256": None,
        "pre_removal_run_id": None,
        "proof_harness_sha256": "2" * 64,
        "provenance": {},
        "provenance_valid": True,
        "repository": selected["repository"],
        "run_attempt": str(CLIENT_RUN_ATTEMPT),
        "run_id": str(CLIENT_RUN_ID),
        "scenario_contract_sha256": "3" * 64,
        "scenario_results": [
            {"action": "pass", "elapsed_seconds": 1, "test_name": "TestProof"}
        ],
        "schema_version": 1,
        "two_cell_provenance": True,
        "typed_evidence": [
            {
                "evidence": [
                    {
                        "kind": "wire_trace",
                        "observation": {"verified": True},
                        "observation_sha256": "4" * 64,
                    }
                ],
                "scenario_key": "proof",
            }
        ],
        "typed_evidence_complete": True,
        "typed_evidence_contract_sha256": "5" * 64,
    }
    if phase == "post_removal":
        value["pre_removal_run_id"] = pre_removal_run_id
        value["pre_removal_evidence_sha256"] = "6" * 64
        value["pre_removal_deployment_sha256"] = "7" * 64
    if client == "connector":
        value["input_outcome"] = "success"
    else:
        value.update(
            {
                "connector_attestation_sha256": "8" * 64,
                "connector_proof_run_id": connector_proof_run_id,
                "inventory_mapping_sha256": "9" * 64,
                "retired_lifecycle_surface_sha256": "a" * 64,
                "strict_outcome": "success",
            }
        )
    return value


def canonical(value: object, maximum: int, name: str) -> bytes:
    return contract.canonical_bytes(value, maximum=maximum, name=name)


def write_client_files(
    directory: Path,
    client: str,
    *,
    phase: str = "pre_removal",
    pre_removal_run_id: str = "",
    connector_proof_run_id: str = "777",
) -> tuple[bytes, bytes]:
    snapshot = producer_fixture.valid_snapshot()
    snapshot["manifest"]["phase"] = phase
    snapshot["manifest"]["retirement_state"] = (
        "http_lifecycle_present"
        if phase == "pre_removal"
        else "http_lifecycle_removed"
    )
    manifest_raw = canonical(
        snapshot["manifest"],
        contract.MAX_MANIFEST_BYTES,
        "sandbox-deployment-manifest.json",
    )
    runtime_raw = canonical(
        snapshot["runtime"],
        contract.MAX_RUNTIME_BYTES,
        "deployment-runtime-inputs.json",
    )
    documents: dict[str, bytes] = {
        "deployment-runtime-inputs.json": runtime_raw,
        "sandbox-deployment-manifest.json": manifest_raw,
    }
    if client == "connector":
        documents["strict-proof-scenarios.json"] = b"{}"
        documents["strict-sandbox-proof.evidence.json"] = canonical(
            evidence(
                client,
                manifest_raw,
                runtime_raw,
                phase=phase,
                pre_removal_run_id=pre_removal_run_id,
            ),
            validator.MAX_EVIDENCE_BYTES,
            "strict-sandbox-proof.evidence.json",
        )
    else:
        documents["pre_retirement_scenarios.json"] = b"{}"
        documents["retired_lifecycle_surface.json"] = b"{}"
        documents["native-udp-sandbox.evidence.json"] = canonical(
            evidence(
                client,
                manifest_raw,
                runtime_raw,
                phase=phase,
                pre_removal_run_id=pre_removal_run_id,
                connector_proof_run_id=connector_proof_run_id,
            ),
            validator.MAX_EVIDENCE_BYTES,
            "native-udp-sandbox.evidence.json",
        )
    for name, raw in documents.items():
        (directory / name).write_bytes(raw)
    return manifest_raw, runtime_raw


def validate_files(
    directory: Path,
    client: str,
    manifest_raw: bytes,
    runtime_raw: bytes,
    *,
    phase: str = "pre_removal",
    pre_removal_run_id: str = "",
    connector_proof_run_id: str = "777",
) -> dict[str, str]:
    selected = target(client)
    return validator.validate_files(
        directory,
        client=client,
        proof_phase=phase,
        client_repository=selected["repository"],
        client_sha=selected["sha"],
        client_run_id=str(CLIENT_RUN_ID),
        client_run_attempt=str(CLIENT_RUN_ATTEMPT),
        dispatch_correlation_id=correlation(client, phase),
        controller_run_id=str(CONTROLLER_RUN_ID),
        controller_run_attempt=str(CONTROLLER_RUN_ATTEMPT),
        deployment_manifest_sha256=hashlib.sha256(manifest_raw).hexdigest(),
        deployment_runtime_inputs_sha256=hashlib.sha256(runtime_raw).hexdigest(),
        producer_run_id=str(PRODUCER_RUN_ID),
        producer_run_attempt=str(PRODUCER_RUN_ATTEMPT),
        producer_head_sha=PRODUCER_HEAD_SHA,
        producer_artifact_id=str(PRODUCER_ARTIFACT_ID),
        producer_artifact_digest=PRODUCER_ARTIFACT_DIGEST,
        connector_proof_run_id=(
            connector_proof_run_id if client == "qurl_go" else ""
        ),
        pre_removal_run_id=pre_removal_run_id,
    )


class MetadataTest(unittest.TestCase):
    def validate(
        self,
        client: str,
        *,
        phase: str = "pre_removal",
        run: dict[str, object] | None = None,
        artifacts: dict[str, object] | None = None,
    ) -> dict[str, str]:
        selected = target(client)
        return validator.validate_metadata(
            run or valid_run(client, phase),
            artifacts or artifacts_response(client, phase),
            client=client,
            proof_phase=phase,
            client_run_id=str(CLIENT_RUN_ID),
            client_repository=selected["repository"],
            client_ref=selected["ref"],
            client_sha=selected["sha"],
            client_run_title=f"UDP proof [corr:{correlation(client, phase)}]",
        )

    def test_selects_exact_artifact_for_each_client(self) -> None:
        for client in ("connector", "qurl_go"):
            with self.subTest(client=client):
                outputs = self.validate(client)
                self.assertEqual(
                    outputs["client_artifact_id"], str(CLIENT_ARTIFACT_ID)
                )
                self.assertEqual(outputs["client_run_attempt"], "1")

    def test_rejects_run_candidate_or_correlation_drift(self) -> None:
        for field, value in (
            ("run_attempt", True),
            ("head_branch", "other"),
            ("head_sha", "f" * 40),
            ("display_title", "UDP proof [corr:wrong]"),
            ("path", ".github/workflows/other.yml"),
            ("conclusion", "failure"),
        ):
            with self.subTest(field=field):
                run = valid_run("connector")
                run[field] = value
                with self.assertRaises(validator.ClientArtifactError):
                    self.validate("connector", run=run)

    def test_rejects_missing_duplicate_or_cross_run_artifact(self) -> None:
        missing = {"artifacts": [], "total_count": 0}
        duplicate = artifacts_response("connector")
        duplicate["artifacts"].append(copy.deepcopy(duplicate["artifacts"][0]))  # type: ignore[union-attr]
        duplicate["total_count"] = 2
        wrong_run = artifacts_response("connector")
        wrong_run["artifacts"][0]["workflow_run"]["id"] = CLIENT_RUN_ID + 1  # type: ignore[index]
        for artifacts in (missing, duplicate, wrong_run):
            with self.subTest(artifacts=artifacts):
                with self.assertRaises(validator.ClientArtifactError):
                    self.validate("connector", artifacts=artifacts)


class ArchiveTest(unittest.TestCase):
    def archive(
        self,
        client: str,
        *,
        duplicate: bool = False,
        symlink: bool = False,
        extra: bool = False,
    ) -> bytes:
        expected = validator.CLIENTS[client]["files"]
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as bundle:
            for name in expected:
                if symlink and name == next(iter(expected)):
                    info = zipfile.ZipInfo(name)
                    info.create_system = 3
                    info.external_attr = (stat.S_IFLNK | 0o777) << 16
                    bundle.writestr(info, b"target")
                else:
                    bundle.writestr(name, b"{}")
            if duplicate:
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", UserWarning)
                    bundle.writestr(next(iter(expected)), b"{}")
            if extra:
                bundle.writestr("extra.json", b"{}")
        return output.getvalue()

    def extract(self, client: str, archive_raw: bytes, *, digest: str | None = None):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        archive = root / "artifact.zip"
        destination = root / "artifact"
        archive.write_bytes(archive_raw)
        validator.extract_archive(
            archive,
            destination,
            client=client,
            expected_digest=(
                digest
                or "sha256:" + hashlib.sha256(archive_raw).hexdigest()
            ),
        )
        return destination

    def test_extracts_exact_regular_files(self) -> None:
        for client in ("connector", "qurl_go"):
            with self.subTest(client=client):
                destination = self.extract(client, self.archive(client))
                self.assertEqual(
                    {path.name for path in destination.iterdir()},
                    set(validator.CLIENTS[client]["files"]),
                )

    def test_rejects_digest_extra_duplicate_and_symlink(self) -> None:
        cases = (
            (self.archive("connector"), "sha256:" + "0" * 64),
            (self.archive("connector", extra=True), None),
            (self.archive("connector", duplicate=True), None),
            (self.archive("connector", symlink=True), None),
        )
        for archive_raw, digest in cases:
            with self.subTest(digest=digest, size=len(archive_raw)):
                with self.assertRaises(validator.ClientArtifactError):
                    self.extract("connector", archive_raw, digest=digest)


class FilesTest(unittest.TestCase):
    def test_accepts_exact_connector_and_qurl_go_results(self) -> None:
        cases = (
            ("connector", "pre_removal", "", "777"),
            ("connector", "post_removal", "111", "777"),
            ("qurl_go", "pre_removal", "", "777"),
            ("qurl_go", "post_removal", "222", "777"),
        )
        for client, phase, pre_run, connector_run in cases:
            with self.subTest(client=client, phase=phase), tempfile.TemporaryDirectory() as tmp:
                directory = Path(tmp)
                manifest_raw, runtime_raw = write_client_files(
                    directory,
                    client,
                    phase=phase,
                    pre_removal_run_id=pre_run,
                    connector_proof_run_id=connector_run,
                )
                outputs = validate_files(
                    directory,
                    client,
                    manifest_raw,
                    runtime_raw,
                    phase=phase,
                    pre_removal_run_id=pre_run,
                    connector_proof_run_id=connector_run,
                )
                self.assertEqual(
                    outputs["client_manifest_sha256"],
                    hashlib.sha256(manifest_raw).hexdigest(),
                )

    def test_rejects_every_result_lineage_drift(self) -> None:
        mutations = {
            "correlation": ("dispatch_correlation_id", "wrong"),
            "phase": ("phase", "post_removal"),
            "candidate": ("commit_sha", "f" * 40),
            "producer artifact": (
                "deployment_producer",
                {**producer_object(), "artifact_id": "1"},
            ),
            "runtime digest": ("deployment_runtime_inputs_sha256", "f" * 64),
            "extra evidence": ("unexpected", True),
        }
        for name, (field, value) in mutations.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                directory = Path(tmp)
                manifest_raw, runtime_raw = write_client_files(
                    directory, "connector"
                )
                path = directory / "strict-sandbox-proof.evidence.json"
                document = json.loads(path.read_text(encoding="utf-8"))
                document[field] = value
                path.write_bytes(
                    canonical(
                        document,
                        validator.MAX_EVIDENCE_BYTES,
                        path.name,
                    )
                )
                with self.assertRaises(validator.ClientArtifactError):
                    validate_files(
                        directory,
                        "connector",
                        manifest_raw,
                        runtime_raw,
                    )

    def test_rejects_manifest_bytes_and_qurl_go_connector_lineage_drift(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            manifest_raw, runtime_raw = write_client_files(directory, "connector")
            with self.assertRaises(validator.ClientArtifactError):
                validate_files(
                    directory,
                    "connector",
                    b"{}",
                    runtime_raw,
                )

        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            manifest_raw, runtime_raw = write_client_files(directory, "qurl_go")
            with self.assertRaises(validator.ClientArtifactError):
                validate_files(
                    directory,
                    "qurl_go",
                    manifest_raw,
                    runtime_raw,
                    connector_proof_run_id="778",
                )

    def test_rejects_missing_extra_and_noncanonical_files(self) -> None:
        for mutation in ("missing", "extra", "noncanonical"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as tmp:
                directory = Path(tmp)
                manifest_raw, runtime_raw = write_client_files(
                    directory, "connector"
                )
                if mutation == "missing":
                    (directory / "strict-proof-scenarios.json").unlink()
                elif mutation == "extra":
                    (directory / "extra.json").write_text("{}", encoding="utf-8")
                else:
                    (directory / "strict-proof-scenarios.json").write_text(
                        "{}\n", encoding="utf-8"
                    )
                with self.assertRaises(validator.ClientArtifactError):
                    validate_files(
                        directory,
                        "connector",
                        manifest_raw,
                        runtime_raw,
                    )


if __name__ == "__main__":
    unittest.main()
