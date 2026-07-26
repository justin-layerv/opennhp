#!/usr/bin/env python3
"""Authenticate and validate one attended UDP client proof artifact.

The controller uses metadata mode to bind the completed workflow run to one
immutable artifact, archive mode to reject unsafe or ambiguous ZIP contents,
and files mode to reconcile the client's canonical evidence with the exact
producer snapshot and controller dispatch.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import zipfile
from pathlib import Path
from typing import Any

import udp_proof_deployment_contract as deployment


MAX_CLIENT_ARTIFACT_BYTES = 5 * 1024 * 1024
MAX_EVIDENCE_BYTES = 4 * 1024 * 1024
MAX_INVENTORY_BYTES = 256 * 1024
MAX_RETIRED_SURFACE_BYTES = 64 * 1024
RUN_ID_RE = re.compile(r"^[1-9][0-9]{0,19}$")

CLIENTS = {
    "connector": {
        "repository": "layervai/qurl-connector",
        "workflow_path": ".github/workflows/sandbox-smoke.yml",
        "artifact_prefix": "strict-sandbox-proof",
        "files": {
            "deployment-runtime-inputs.json": deployment.MAX_RUNTIME_BYTES,
            "sandbox-deployment-manifest.json": deployment.MAX_MANIFEST_BYTES,
            "strict-proof-scenarios.json": MAX_INVENTORY_BYTES,
            "strict-sandbox-proof.evidence.json": MAX_EVIDENCE_BYTES,
        },
        "evidence_file": "strict-sandbox-proof.evidence.json",
    },
    "qurl_go": {
        "repository": "layervai/qurl-go",
        "workflow_path": ".github/workflows/native-udp-sandbox.yml",
        "artifact_prefix": "native-udp-sandbox",
        "files": {
            "deployment-runtime-inputs.json": deployment.MAX_RUNTIME_BYTES,
            "native-udp-sandbox.evidence.json": MAX_EVIDENCE_BYTES,
            "pre_retirement_scenarios.json": MAX_INVENTORY_BYTES,
            "retired_lifecycle_surface.json": MAX_RETIRED_SURFACE_BYTES,
            "sandbox-deployment-manifest.json": deployment.MAX_MANIFEST_BYTES,
        },
        "evidence_file": "native-udp-sandbox.evidence.json",
    },
}

COMMON_EVIDENCE_KEYS = {
    "commit_sha",
    "counts",
    "deployment_manifest_sha256",
    "deployment_producer",
    "deployment_runtime_inputs_sha256",
    "dispatch_correlation_id",
    "enforcement_outcome",
    "gate_passed",
    "inputs_unchanged",
    "inventory_sha256",
    "nhp_controller_run_attempt",
    "nhp_controller_run_id",
    "phase",
    "pre_removal_deployment_sha256",
    "pre_removal_evidence_sha256",
    "pre_removal_run_id",
    "proof_harness_sha256",
    "provenance",
    "provenance_valid",
    "repository",
    "run_attempt",
    "run_id",
    "scenario_contract_sha256",
    "scenario_results",
    "schema_version",
    "two_cell_provenance",
    "typed_evidence",
    "typed_evidence_complete",
    "typed_evidence_contract_sha256",
}
CONNECTOR_EVIDENCE_KEYS = COMMON_EVIDENCE_KEYS | {"input_outcome"}
QURL_GO_EVIDENCE_KEYS = COMMON_EVIDENCE_KEYS | {
    "connector_attestation_sha256",
    "connector_proof_run_id",
    "inventory_mapping_sha256",
    "retired_lifecycle_surface_sha256",
    "strict_outcome",
}


class ClientArtifactError(ValueError):
    """A completed client result is not the exact dispatched proof."""


def _client(client: str) -> dict[str, Any]:
    if client not in CLIENTS:
        raise ClientArtifactError("client must be connector or qurl_go")
    return CLIENTS[client]


def _positive_int_string(value: str, name: str) -> int:
    if not isinstance(value, str) or not RUN_ID_RE.fullmatch(value):
        raise ClientArtifactError(f"{name} must be a positive integer")
    return int(value)


def _required_object(value: Any, required: set[str], name: str) -> dict[str, Any]:
    if not isinstance(value, dict) or not required.issubset(value):
        raise ClientArtifactError(f"{name} is missing required fields")
    return value


def _exact_object(value: Any, keys: set[str], name: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise ClientArtifactError(f"{name} must contain exactly {sorted(keys)}")
    return value


def _sha(value: Any, name: str) -> str:
    if not isinstance(value, str) or not deployment.SHA_RE.fullmatch(value):
        raise ClientArtifactError(f"{name} must be a lowercase Git SHA")
    return value


def _sha256(value: Any, name: str) -> str:
    if not isinstance(value, str) or not deployment.SHA256_RE.fullmatch(value):
        raise ClientArtifactError(f"{name} must be a lowercase SHA-256")
    return value


def _digest(value: Any, name: str) -> str:
    if not isinstance(value, str) or not deployment.DIGEST_RE.fullmatch(value):
        raise ClientArtifactError(f"{name} must be a lowercase sha256 digest")
    return value


def _load_json(path: Path) -> Any:
    try:
        return json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=deployment._reject_duplicate_keys,
            parse_constant=deployment._reject_nonfinite,
            parse_float=deployment._parse_finite_float,
        )
    except (
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        deployment.ContractError,
    ) as exc:
        raise ClientArtifactError(f"could not read JSON input {path}") from exc


def validate_metadata(
    run: Any,
    artifacts_response: Any,
    *,
    client: str,
    proof_phase: str,
    client_run_id: str,
    client_repository: str,
    client_ref: str,
    client_sha: str,
    client_run_title: str,
) -> dict[str, str]:
    """Bind the exact completed candidate run to one current-attempt artifact."""

    target = _client(client)
    run_id = _positive_int_string(client_run_id, "client run ID")
    if proof_phase not in {"pre_removal", "post_removal"}:
        raise ClientArtifactError("proof phase must be pre_removal or post_removal")
    _sha(client_sha, "client SHA")
    if client_repository != target["repository"]:
        raise ClientArtifactError("client repository does not match client")

    run_object = _required_object(
        run,
        {
            "id",
            "run_attempt",
            "repository",
            "head_repository",
            "path",
            "event",
            "status",
            "conclusion",
            "head_branch",
            "head_sha",
            "display_title",
        },
        "client run",
    )
    repository = _required_object(
        run_object["repository"], {"id", "full_name"}, "client repository"
    )
    head_repository = _required_object(
        run_object["head_repository"],
        {"id", "full_name"},
        "client head repository",
    )
    repository_id = repository["id"]
    if (
        type(repository_id) is not int
        or repository_id <= 0
        or type(head_repository["id"]) is not int
        or type(run_object["id"]) is not int
        or type(run_object["run_attempt"]) is not int
    ):
        raise ClientArtifactError("client repository id must be a positive integer")
    if (
        head_repository["id"] != repository_id
        or head_repository["full_name"] != client_repository
    ):
        raise ClientArtifactError(
            "client head repository differs from the authenticated repository"
        )
    expected_run = {
        "id": run_id,
        "run_attempt": 1,
        "repository": client_repository,
        "workflow_path": target["workflow_path"],
        "event": "workflow_dispatch",
        "status": "completed",
        "conclusion": "success",
        "head_branch": client_ref,
        "head_sha": client_sha,
        "display_title": client_run_title,
    }
    normalized_run = {
        "id": run_object["id"],
        "run_attempt": run_object["run_attempt"],
        "repository": repository["full_name"],
        "workflow_path": run_object["path"],
        "event": run_object["event"],
        "status": run_object["status"],
        "conclusion": run_object["conclusion"],
        "head_branch": run_object["head_branch"],
        "head_sha": run_object["head_sha"],
        "display_title": run_object["display_title"],
    }
    if normalized_run != expected_run:
        raise ClientArtifactError("client workflow run identity drift")

    envelope = _required_object(
        artifacts_response, {"total_count", "artifacts"}, "client artifacts response"
    )
    artifacts = envelope["artifacts"]
    if (
        type(envelope["total_count"]) is not int
        or not isinstance(artifacts, list)
        or envelope["total_count"] != len(artifacts)
        or not 1 <= len(artifacts) <= 100
    ):
        raise ClientArtifactError(
            "client artifact response must contain the complete bounded 1..100 list"
        )
    expected_name = (
        f"{target['artifact_prefix']}-{proof_phase}-{client_sha}-"
        f"{run_object['run_attempt']}"
    )
    matches: list[dict[str, Any]] = []
    for index, raw in enumerate(artifacts):
        artifact = _required_object(
            raw,
            {
                "id",
                "name",
                "digest",
                "size_in_bytes",
                "expired",
                "workflow_run",
            },
            f"client artifact {index}",
        )
        artifact_run = _required_object(
            artifact["workflow_run"],
            {
                "id",
                "repository_id",
                "head_repository_id",
                "head_branch",
                "head_sha",
            },
            f"client artifact {index} workflow run",
        )
        if (
            type(artifact_run["id"]) is not int
            or type(artifact_run["repository_id"]) is not int
            or type(artifact_run["head_repository_id"]) is not int
            or artifact_run["id"] != run_id
            or artifact_run["repository_id"] != repository_id
            or artifact_run["head_repository_id"] != repository_id
            or artifact_run["head_branch"] != client_ref
            or artifact_run["head_sha"] != client_sha
        ):
            raise ClientArtifactError(
                f"client artifact {index} does not belong to the exact candidate run"
            )
        if (
            type(artifact["id"]) is not int
            or artifact["id"] <= 0
            or not isinstance(artifact["name"], str)
            or not artifact["name"]
            or type(artifact["size_in_bytes"]) is not int
            or not 1 <= artifact["size_in_bytes"] <= MAX_CLIENT_ARTIFACT_BYTES
            or not isinstance(artifact["expired"], bool)
        ):
            raise ClientArtifactError(
                f"client artifact {index} has invalid bounded metadata"
            )
        _digest(artifact["digest"], f"client artifact {index} digest")
        if artifact["name"] == expected_name:
            matches.append(artifact)
    if len(matches) != 1 or matches[0]["expired"]:
        raise ClientArtifactError(
            "expected exactly one unexpired exact client proof artifact"
        )
    selected = matches[0]
    return {
        "client_artifact_id": str(selected["id"]),
        "client_artifact_name": selected["name"],
        "client_artifact_digest": selected["digest"],
        "client_run_attempt": str(run_object["run_attempt"]),
    }


def extract_archive(
    archive: Path,
    directory: Path,
    *,
    client: str,
    expected_digest: str,
) -> None:
    """Verify and safely extract exactly the client's allowlisted root files."""

    target = _client(client)
    _digest(expected_digest, "client artifact digest")
    try:
        metadata = archive.lstat()
        raw_size = metadata.st_size
    except OSError as exc:
        raise ClientArtifactError("cannot read client artifact archive") from exc
    if (
        archive.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or not 1 <= raw_size <= MAX_CLIENT_ARTIFACT_BYTES
    ):
        raise ClientArtifactError("client artifact archive is not a bounded file")
    actual_digest = "sha256:" + hashlib.sha256(archive.read_bytes()).hexdigest()
    if actual_digest != expected_digest:
        raise ClientArtifactError("client artifact archive digest mismatch")
    if directory.exists() or directory.is_symlink():
        raise ClientArtifactError("client artifact destination already exists")

    expected_files: dict[str, int] = target["files"]
    try:
        with zipfile.ZipFile(archive) as bundle:
            entries = bundle.infolist()
            names = [entry.filename for entry in entries]
            if (
                len(entries) != len(expected_files)
                or len(names) != len(set(names))
                or set(names) != set(expected_files)
            ):
                raise ClientArtifactError(
                    "client artifact must contain exactly the allowlisted files once"
                )
            total_expanded = 0
            for entry in entries:
                mode = entry.external_attr >> 16
                limit = expected_files[entry.filename]
                if (
                    entry.is_dir()
                    or "/" in entry.filename
                    or "\\" in entry.filename
                    or stat.S_ISLNK(mode)
                    or (stat.S_IFMT(mode) not in {0, stat.S_IFREG})
                    or entry.flag_bits & 0x1
                    or not 1 <= entry.file_size <= limit
                    or entry.compress_size > MAX_CLIENT_ARTIFACT_BYTES
                ):
                    raise ClientArtifactError(
                        f"unsafe or oversized client artifact entry: {entry.filename}"
                    )
                total_expanded += entry.file_size
            if total_expanded > MAX_CLIENT_ARTIFACT_BYTES:
                raise ClientArtifactError(
                    "client artifact expanded size exceeds the bound"
                )

            directory.mkdir(mode=0o700)
            for entry in entries:
                body = bundle.read(entry)
                if len(body) != entry.file_size:
                    raise ClientArtifactError(
                        f"client artifact entry size drift: {entry.filename}"
                    )
                descriptor = os.open(
                    directory / entry.filename,
                    os.O_CREAT | os.O_EXCL | os.O_WRONLY,
                    0o600,
                )
                with os.fdopen(descriptor, "wb") as handle:
                    handle.write(body)
    except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
        raise ClientArtifactError("could not safely extract client artifact") from exc


def _validate_counts(value: Any) -> int:
    counts = _exact_object(
        value,
        {"implemented", "blocking", "failures", "skips", "exact_passes"},
        "client evidence counts",
    )
    for name, count in counts.items():
        if type(count) is not int or count < 0:
            raise ClientArtifactError(f"client evidence counts.{name} is invalid")
    implemented = counts["implemented"]
    if (
        implemented <= 0
        or counts["blocking"] != 0
        or counts["failures"] != 0
        or counts["skips"] != 0
        or counts["exact_passes"] != implemented
    ):
        raise ClientArtifactError("client evidence counts do not prove a complete gate")
    return implemented


def validate_files(
    directory: Path,
    *,
    client: str,
    proof_phase: str,
    client_repository: str,
    client_sha: str,
    client_run_id: str,
    client_run_attempt: str,
    dispatch_correlation_id: str,
    controller_run_id: str,
    controller_run_attempt: str,
    deployment_manifest_sha256: str,
    deployment_runtime_inputs_sha256: str,
    producer_run_id: str,
    producer_run_attempt: str,
    producer_head_sha: str,
    producer_artifact_id: str,
    producer_artifact_digest: str,
    connector_proof_run_id: str,
    pre_removal_run_id: str,
) -> dict[str, str]:
    """Reconcile canonical client evidence with the exact controller dispatch."""

    target = _client(client)
    expected_files: dict[str, int] = target["files"]
    try:
        metadata = directory.lstat()
        entries = {entry.name for entry in directory.iterdir()}
    except OSError as exc:
        raise ClientArtifactError("cannot read client artifact directory") from exc
    if (
        directory.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or entries != set(expected_files)
    ):
        raise ClientArtifactError(
            "client artifact directory does not contain the exact file set"
        )

    parsed: dict[str, dict[str, Any]] = {}
    raw: dict[str, bytes] = {}
    for name, maximum in expected_files.items():
        path = directory / name
        try:
            file_metadata = path.lstat()
            body = path.read_bytes()
        except OSError as exc:
            raise ClientArtifactError(f"cannot read client artifact file {name}") from exc
        if path.is_symlink() or not stat.S_ISREG(file_metadata.st_mode):
            raise ClientArtifactError(f"client artifact file {name} is not regular")
        try:
            parsed[name] = deployment.parse_canonical_bytes(
                body, maximum=maximum, name=name
            )
        except deployment.ContractError as exc:
            raise ClientArtifactError(str(exc)) from exc
        raw[name] = body

    manifest = parsed["sandbox-deployment-manifest.json"]
    runtime = parsed["deployment-runtime-inputs.json"]
    try:
        deployment.validate_manifest(manifest, proof_phase)
        deployment.validate_runtime_inputs(runtime, manifest)
    except deployment.ContractError as exc:
        raise ClientArtifactError(str(exc)) from exc

    expected_manifest_sha = _sha256(
        deployment_manifest_sha256, "deployment manifest SHA-256"
    )
    expected_runtime_sha = _sha256(
        deployment_runtime_inputs_sha256, "deployment runtime SHA-256"
    )
    actual_manifest_sha = hashlib.sha256(
        raw["sandbox-deployment-manifest.json"]
    ).hexdigest()
    actual_runtime_sha = hashlib.sha256(
        raw["deployment-runtime-inputs.json"]
    ).hexdigest()
    if (
        actual_manifest_sha != expected_manifest_sha
        or actual_runtime_sha != expected_runtime_sha
    ):
        raise ClientArtifactError(
            "client artifact deployment bytes differ from the producer snapshot"
        )

    evidence = parsed[target["evidence_file"]]
    expected_evidence_keys = (
        CONNECTOR_EVIDENCE_KEYS if client == "connector" else QURL_GO_EVIDENCE_KEYS
    )
    _exact_object(evidence, expected_evidence_keys, "client evidence")
    run_id = _positive_int_string(client_run_id, "client run ID")
    run_attempt = _positive_int_string(client_run_attempt, "client run attempt")
    controller_id = _positive_int_string(controller_run_id, "controller run ID")
    controller_attempt = _positive_int_string(
        controller_run_attempt, "controller run attempt"
    )
    producer_id = _positive_int_string(producer_run_id, "producer run ID")
    producer_attempt = _positive_int_string(
        producer_run_attempt, "producer run attempt"
    )
    producer_artifact = _positive_int_string(
        producer_artifact_id, "producer artifact ID"
    )
    _sha(client_sha, "client SHA")
    _sha(producer_head_sha, "producer head SHA")
    _digest(producer_artifact_digest, "producer artifact digest")
    expected_producer = {
        "repository": "layervai/nhp",
        "workflow_path": ".github/workflows/udp-proof-deployment-manifest.yml",
        "run_id": str(producer_id),
        "run_attempt": str(producer_attempt),
        "head_sha": producer_head_sha,
        "artifact_id": str(producer_artifact),
        "artifact_digest": producer_artifact_digest,
    }
    expected_common = {
        "schema_version": 1,
        "phase": proof_phase,
        "repository": client_repository,
        "commit_sha": client_sha,
        "run_id": str(run_id),
        "run_attempt": str(run_attempt),
        "dispatch_correlation_id": dispatch_correlation_id,
        "nhp_controller_run_id": str(controller_id),
        "nhp_controller_run_attempt": str(controller_attempt),
        "deployment_producer": expected_producer,
        "deployment_manifest_sha256": actual_manifest_sha,
        "deployment_runtime_inputs_sha256": actual_runtime_sha,
        "enforcement_outcome": "success",
        "inputs_unchanged": True,
        "gate_passed": True,
        "provenance_valid": True,
        "two_cell_provenance": True,
        "typed_evidence_complete": True,
    }
    for key, expected in expected_common.items():
        if evidence[key] != expected:
            raise ClientArtifactError(f"client evidence {key} does not match dispatch")
    if type(evidence["schema_version"]) is not int or any(
        type(evidence[key]) is not bool
        for key in (
            "gate_passed",
            "inputs_unchanged",
            "provenance_valid",
            "two_cell_provenance",
            "typed_evidence_complete",
        )
    ):
        raise ClientArtifactError("client evidence scalar types are not exact")
    if client_repository != target["repository"]:
        raise ClientArtifactError("client evidence repository does not match client")
    if proof_phase not in {"pre_removal", "post_removal"}:
        raise ClientArtifactError("proof phase must be pre_removal or post_removal")
    correlation = (
        f"nhp-{controller_id}-{controller_attempt}-{client}-{proof_phase}-"
    )
    if (
        not isinstance(dispatch_correlation_id, str)
        or not re.fullmatch(re.escape(correlation) + r"[0-9a-f]{32}", dispatch_correlation_id)
    ):
        raise ClientArtifactError("dispatch correlation ID is not canonical")

    implemented = _validate_counts(evidence["counts"])
    digest_fields = [
        "inventory_sha256",
        "scenario_contract_sha256",
        "proof_harness_sha256",
        "typed_evidence_contract_sha256",
    ]
    if client == "qurl_go":
        digest_fields.extend(
            ["inventory_mapping_sha256", "retired_lifecycle_surface_sha256"]
        )
    for name in digest_fields:
        _sha256(evidence[name], f"client evidence {name}")
    if (
        not isinstance(evidence["typed_evidence"], list)
        or len(evidence["typed_evidence"]) != implemented
        or not isinstance(evidence["scenario_results"], list)
        or len(evidence["scenario_results"]) != implemented
        or not isinstance(evidence["provenance"], dict)
    ):
        raise ClientArtifactError("client evidence proof collections are incomplete")

    if proof_phase == "pre_removal":
        if (
            pre_removal_run_id
            or evidence["pre_removal_run_id"] is not None
            or evidence["pre_removal_evidence_sha256"] is not None
            or evidence["pre_removal_deployment_sha256"] is not None
        ):
            raise ClientArtifactError("pre-removal client evidence has prior lineage")
    else:
        _positive_int_string(pre_removal_run_id, "pre-removal run ID")
        if evidence["pre_removal_run_id"] != pre_removal_run_id:
            raise ClientArtifactError("post-removal client evidence run lineage drift")
        _sha256(
            evidence["pre_removal_evidence_sha256"],
            "pre-removal evidence SHA-256",
        )
        _sha256(
            evidence["pre_removal_deployment_sha256"],
            "pre-removal deployment SHA-256",
        )

    if client == "connector":
        if connector_proof_run_id:
            raise ClientArtifactError(
                "Connector result cannot carry qurl-go Connector-proof lineage"
            )
        if (
            evidence["input_outcome"] != "success"
            or not isinstance(evidence["typed_evidence_contract_sha256"], str)
        ):
            raise ClientArtifactError("Connector evidence outcome is incomplete")
    else:
        _positive_int_string(
            connector_proof_run_id, "same-phase Connector proof run ID"
        )
        if evidence["connector_proof_run_id"] != connector_proof_run_id:
            raise ClientArtifactError(
                "qurl-go evidence same-phase Connector lineage drift"
            )
        if (
            evidence["strict_outcome"] != "success"
            or not isinstance(evidence["connector_attestation_sha256"], str)
        ):
            raise ClientArtifactError("qurl-go evidence outcome is incomplete")
        _sha256(
            evidence["connector_attestation_sha256"],
            "Connector attestation SHA-256",
        )

    return {
        "client_evidence_sha256": hashlib.sha256(
            raw[target["evidence_file"]]
        ).hexdigest(),
        "client_manifest_sha256": actual_manifest_sha,
        "client_runtime_inputs_sha256": actual_runtime_sha,
    }


def _write_outputs(path: Path, outputs: dict[str, str]) -> None:
    with path.open("a", encoding="utf-8") as handle:
        for name, value in outputs.items():
            if "\n" in value or "\r" in value:
                raise ClientArtifactError(f"output {name} contains a newline")
            handle.write(f"{name}={value}\n")


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    metadata = subparsers.add_parser("metadata")
    metadata.add_argument("--run-json", type=Path, required=True)
    metadata.add_argument("--artifacts-json", type=Path, required=True)
    metadata.add_argument("--client", required=True)
    metadata.add_argument("--proof-phase", required=True)
    metadata.add_argument("--client-run-id", required=True)
    metadata.add_argument("--client-repository", required=True)
    metadata.add_argument("--client-ref", required=True)
    metadata.add_argument("--client-sha", required=True)
    metadata.add_argument("--client-run-title", required=True)
    metadata.add_argument("--github-output", type=Path, required=True)

    archive = subparsers.add_parser("archive")
    archive.add_argument("--archive", type=Path, required=True)
    archive.add_argument("--directory", type=Path, required=True)
    archive.add_argument("--client", required=True)
    archive.add_argument("--expected-digest", required=True)

    files = subparsers.add_parser("files")
    files.add_argument("--directory", type=Path, required=True)
    files.add_argument("--client", required=True)
    files.add_argument("--proof-phase", required=True)
    files.add_argument("--client-repository", required=True)
    files.add_argument("--client-sha", required=True)
    files.add_argument("--client-run-id", required=True)
    files.add_argument("--client-run-attempt", required=True)
    files.add_argument("--dispatch-correlation-id", required=True)
    files.add_argument("--controller-run-id", required=True)
    files.add_argument("--controller-run-attempt", required=True)
    files.add_argument("--deployment-manifest-sha256", required=True)
    files.add_argument("--deployment-runtime-inputs-sha256", required=True)
    files.add_argument("--producer-run-id", required=True)
    files.add_argument("--producer-run-attempt", required=True)
    files.add_argument("--producer-head-sha", required=True)
    files.add_argument("--producer-artifact-id", required=True)
    files.add_argument("--producer-artifact-digest", required=True)
    files.add_argument("--connector-proof-run-id", default="")
    files.add_argument("--pre-removal-run-id", default="")
    files.add_argument("--github-output", type=Path, required=True)
    args = parser.parse_args()

    try:
        if args.command == "metadata":
            outputs = validate_metadata(
                _load_json(args.run_json),
                _load_json(args.artifacts_json),
                client=args.client,
                proof_phase=args.proof_phase,
                client_run_id=args.client_run_id,
                client_repository=args.client_repository,
                client_ref=args.client_ref,
                client_sha=args.client_sha,
                client_run_title=args.client_run_title,
            )
            _write_outputs(args.github_output, outputs)
        elif args.command == "archive":
            extract_archive(
                args.archive,
                args.directory,
                client=args.client,
                expected_digest=args.expected_digest,
            )
        else:
            outputs = validate_files(
                args.directory,
                client=args.client,
                proof_phase=args.proof_phase,
                client_repository=args.client_repository,
                client_sha=args.client_sha,
                client_run_id=args.client_run_id,
                client_run_attempt=args.client_run_attempt,
                dispatch_correlation_id=args.dispatch_correlation_id,
                controller_run_id=args.controller_run_id,
                controller_run_attempt=args.controller_run_attempt,
                deployment_manifest_sha256=args.deployment_manifest_sha256,
                deployment_runtime_inputs_sha256=(
                    args.deployment_runtime_inputs_sha256
                ),
                producer_run_id=args.producer_run_id,
                producer_run_attempt=args.producer_run_attempt,
                producer_head_sha=args.producer_head_sha,
                producer_artifact_id=args.producer_artifact_id,
                producer_artifact_digest=args.producer_artifact_digest,
                connector_proof_run_id=args.connector_proof_run_id,
                pre_removal_run_id=args.pre_removal_run_id,
            )
            _write_outputs(args.github_output, outputs)
    except (ClientArtifactError, OSError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
