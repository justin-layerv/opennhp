#!/usr/bin/env python3
"""Build one current-attempt controller attestation from authenticated artifacts."""

from __future__ import annotations

import argparse
import hashlib
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import udp_proof_deployment_contract as deployment
import udp_proof_runtime_evidence_contract as runtime


MAX_INPUT_BYTES = 5 * 1024 * 1024


def _load(path: Path, name: str, *, maximum: int = MAX_INPUT_BYTES) -> tuple[Any, bytes]:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise runtime.RuntimeEvidenceError(f"could not read {name}") from exc
    try:
        value = deployment.parse_canonical_bytes(raw, maximum=maximum, name=name)
    except deployment.ContractError as exc:
        raise runtime.RuntimeEvidenceError(str(exc)) from exc
    return value, raw


def _positive(value: str, name: str) -> int:
    if (
        not isinstance(value, str)
        or not value.isascii()
        or not value.isdigit()
        or value.startswith("0")
    ):
        raise runtime.RuntimeEvidenceError(f"{name} must be a positive integer")
    parsed = int(value)
    if parsed <= 0 or parsed > 9_007_199_254_740_991:
        raise runtime.RuntimeEvidenceError(f"{name} must be a positive safe integer")
    return parsed


def _write_once(path: Path, raw: bytes) -> None:
    if not path.is_absolute() or path != path.resolve(strict=False):
        raise runtime.RuntimeEvidenceError("output must be one canonical absolute path")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = -1
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            descriptor = -1
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    except OSError as exc:
        raise runtime.RuntimeEvidenceError(
            "could not publish immutable controller attestation"
        ) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def collect(args: argparse.Namespace, *, observed_at: datetime | None = None) -> bytes:
    if args.client not in runtime.CLIENT_REPOSITORIES:
        raise runtime.RuntimeEvidenceError("client must be connector or qurl_go")
    if args.proof_phase not in {"pre_removal", "post_removal"}:
        raise runtime.RuntimeEvidenceError("proof phase is invalid")
    controller_run_id = _positive(args.controller_run_id, "controller run ID")
    controller_run_attempt = _positive(
        args.controller_run_attempt, "controller run attempt"
    )
    producer_run_id = _positive(args.producer_run_id, "producer run ID")
    producer_run_attempt = _positive(
        args.producer_run_attempt, "producer run attempt"
    )
    producer_artifact_id = _positive(
        args.producer_artifact_id, "producer artifact ID"
    )
    client_run_id = _positive(args.client_run_id, "client run ID")
    client_run_attempt = _positive(args.client_run_attempt, "client run attempt")
    client_artifact_id = _positive(args.client_artifact_id, "client artifact ID")
    runtime._sha(args.controller_head_sha, "controller head SHA")
    runtime._sha(args.producer_head_sha, "producer head SHA")
    runtime._sha(args.client_head_sha, "client head SHA")
    runtime._digest(args.producer_artifact_digest, "producer artifact digest")
    runtime._digest(args.client_artifact_digest, "client artifact digest")
    runtime._sha256(args.client_evidence_sha256, "client evidence SHA-256")
    runtime._sha256(
        args.client_typed_evidence_sha256, "client typed evidence SHA-256"
    )
    runtime._sha256(args.packet_capture_sha256, "client packet capture SHA-256")

    manifest, manifest_raw = _load(
        args.producer_directory / "deployment-manifest.json",
        "deployment manifest",
        maximum=deployment.MAX_MANIFEST_BYTES,
    )
    runtime_inputs, runtime_raw = _load(
        args.producer_directory / "deployment-runtime-inputs.json",
        "deployment runtime inputs",
        maximum=deployment.MAX_RUNTIME_BYTES,
    )
    provenance, provenance_raw = _load(
        args.producer_directory / "deployment-provenance.json",
        "deployment provenance",
        maximum=deployment.MAX_PROVENANCE_BYTES,
    )
    deployment.validate_manifest(manifest, args.proof_phase)
    deployment.validate_runtime_inputs(runtime_inputs, manifest)
    expected_producer_identity = {
        "head_sha": args.producer_head_sha,
        "repository": "layervai/nhp",
        "run_attempt": producer_run_attempt,
        "run_id": producer_run_id,
        "workflow_path": ".github/workflows/udp-proof-deployment-manifest.yml",
    }
    if provenance.get("producer") != expected_producer_identity:
        raise runtime.RuntimeEvidenceError("producer provenance identity drift")
    producer = {
        "artifact_digest": args.producer_artifact_digest,
        "artifact_id": producer_artifact_id,
        "head_sha": args.producer_head_sha,
        "manifest_sha256": hashlib.sha256(manifest_raw).hexdigest(),
        "provenance_sha256": hashlib.sha256(provenance_raw).hexdigest(),
        "run_attempt": producer_run_attempt,
        "run_id": producer_run_id,
        "runtime_inputs_sha256": hashlib.sha256(runtime_raw).hexdigest(),
    }
    client_artifact = {
        "artifact_digest": args.client_artifact_digest,
        "artifact_id": client_artifact_id,
        "evidence_sha256": args.client_evidence_sha256,
        "head_sha": args.client_head_sha,
        "repository": runtime.CLIENT_REPOSITORIES[args.client],
        "run_attempt": client_run_attempt,
        "run_id": client_run_id,
        "typed_evidence_sha256": args.client_typed_evidence_sha256,
        "workflow_path": runtime.CLIENT_WORKFLOWS[args.client],
    }
    proof_source = provenance.get("evidence", {}).get("aws", {}).get("proof_source")
    if not isinstance(proof_source, dict):
        raise runtime.RuntimeEvidenceError("producer proof-source evidence is absent")
    labels = [
        "Linux",
        "X64",
        "sandbox",
        "self-hosted",
        "udp-proof",
        f"run-{controller_run_id}-attempt-{controller_run_attempt}",
    ]
    runner = {
        "capabilities": list(runtime.RUNNER_CAPABILITIES),
        "egress_ip": proof_source.get("public_ip"),
        "instance_id": args.runner_instance_id,
        "packet_capture_sha256": args.packet_capture_sha256,
        "reviewed_source_cidr": proof_source.get("cidr"),
        "runner_group": "udp-proof-sandbox",
        "runner_labels_sha256": hashlib.sha256(
            deployment.canonical_bytes(
                labels, maximum=4096, name="controller runner labels"
            )
        ).hexdigest(),
    }
    now = (observed_at or datetime.now(timezone.utc)).astimezone(timezone.utc)
    now = now.replace(microsecond=0)
    document: dict[str, Any] = {
        "assignment_receipt": None,
        "client": args.client,
        "client_artifact": client_artifact,
        "controller": {
            "head_sha": args.controller_head_sha,
            "repository": "layervai/nhp",
            "run_attempt": controller_run_attempt,
            "run_id": controller_run_id,
            "workflow_path": runtime.CONTROLLER_WORKFLOW,
        },
        "gate": runtime.GATE,
        "observed_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "phase": args.proof_phase,
        "producer_artifact": producer,
        "rows": {},
        "runner": runner,
        "runtime_probe": None,
        "schema_version": runtime.SCHEMA_VERSION,
        "server_authority": None,
        "server_receipt": None,
        "surface_contract_sha256": None,
        "transport_receipt": None,
    }
    if args.client == "qurl_go":
        required = (
            args.assignment_receipt,
            args.transport_receipt,
            args.runtime_probe,
            args.server_receipt,
        )
        if any(value is None for value in required):
            raise runtime.RuntimeEvidenceError(
                "qurl-go attestation requires all runtime receipt inputs"
            )
        assignment, _ = _load(
            args.assignment_receipt,
            "assignment receipt",
            maximum=64 * 1024,
        )
        transport, _ = _load(
            args.transport_receipt,
            "transport receipt",
            maximum=64 * 1024,
        )
        if transport.get("capture_sha256") != args.packet_capture_sha256:
            raise runtime.RuntimeEvidenceError(
                "qurl-go runner capture differs from the transport receipt"
            )
        probe, _ = _load(
            args.runtime_probe,
            "runtime probe",
            maximum=256 * 1024,
        )
        server_receipt, _ = _load(
            args.server_receipt,
            "server receipt",
            maximum=128 * 1024,
        )
        surface_path = args.client_directory / "retired_lifecycle_surface.json"
        _, surface_raw = _load(
            surface_path,
            "retired lifecycle surface",
            maximum=256 * 1024,
        )
        surface_sha256 = hashlib.sha256(surface_raw).hexdigest()
        server_authority = {
            "proof_source_ip": server_receipt.get("proof_source_ip"),
            "qurl_service_log_groups": server_receipt.get("http", {}).get(
                "log_groups"
            ),
            "relay_log_group": server_receipt.get("relay", {}).get("log_group"),
        }
        document.update(
            {
                "assignment_receipt": assignment,
                "runtime_probe": probe,
                "server_authority": server_authority,
                "server_receipt": server_receipt,
                "surface_contract_sha256": surface_sha256,
                "transport_receipt": transport,
                "rows": runtime.rows_from_runtime_observations(
                    runtime_probe=probe,
                    server_receipt=server_receipt,
                    transport_receipt=transport,
                    surface_contract_sha256=surface_sha256,
                    proof_phase=args.proof_phase,
                ),
            }
        )
    runtime.validate_controller_attestation(
        document,
        client=args.client,
        proof_phase=args.proof_phase,
        producer_artifact=producer,
        client_artifact=client_artifact,
        validation_time=now,
    )
    return runtime.canonical_attestation_bytes(document, args.client)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    result.add_argument("--client", choices=("connector", "qurl_go"), required=True)
    result.add_argument(
        "--proof-phase",
        choices=("pre_removal", "post_removal"),
        required=True,
    )
    result.add_argument("--producer-directory", required=True, type=Path)
    result.add_argument("--client-directory", required=True, type=Path)
    result.add_argument("--controller-run-id", required=True)
    result.add_argument("--controller-run-attempt", required=True)
    result.add_argument("--controller-head-sha", required=True)
    result.add_argument("--producer-run-id", required=True)
    result.add_argument("--producer-run-attempt", required=True)
    result.add_argument("--producer-head-sha", required=True)
    result.add_argument("--producer-artifact-id", required=True)
    result.add_argument("--producer-artifact-digest", required=True)
    result.add_argument("--client-run-id", required=True)
    result.add_argument("--client-run-attempt", required=True)
    result.add_argument("--client-head-sha", required=True)
    result.add_argument("--client-artifact-id", required=True)
    result.add_argument("--client-artifact-digest", required=True)
    result.add_argument("--client-evidence-sha256", required=True)
    result.add_argument("--client-typed-evidence-sha256", required=True)
    result.add_argument("--packet-capture-sha256", required=True)
    result.add_argument("--runner-instance-id", required=True)
    result.add_argument("--assignment-receipt", type=Path)
    result.add_argument("--transport-receipt", type=Path)
    result.add_argument("--runtime-probe", type=Path)
    result.add_argument("--server-receipt", type=Path)
    result.add_argument("--output", type=Path, required=True)
    return result


def main() -> int:
    args = parser().parse_args()
    try:
        _write_once(args.output, collect(args))
    except runtime.RuntimeEvidenceError as exc:
        parser().error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
