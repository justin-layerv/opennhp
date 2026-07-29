#!/usr/bin/env python3
"""Assemble the seven attended NHP runtime rows from controller attestations."""

from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import udp_proof_deployment_contract as deployment
import udp_proof_runtime_evidence_contract as runtime


MAX_BINDING_BYTES = 64 * 1024


def _load_canonical(path: Path, *, maximum: int, name: str) -> Any:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise runtime.RuntimeEvidenceError(f"could not read {name}") from exc
    try:
        return deployment.parse_canonical_bytes(raw, maximum=maximum, name=name)
    except deployment.ContractError as exc:
        raise runtime.RuntimeEvidenceError(str(exc)) from exc


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
            "could not publish immutable runtime evidence"
        ) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def collect(
    *,
    connector_attestation_path: Path,
    qurl_go_attestation_path: Path,
    producer_artifact_path: Path | None = None,
    connector_artifact_path: Path | None = None,
    qurl_go_artifact_path: Path | None = None,
    proof_phase: str,
    observed_at: datetime | None = None,
) -> bytes:
    """Validate authoritative inputs and return canonical runtime evidence."""

    connector_attestation = _load_canonical(
        connector_attestation_path,
        maximum=runtime.MAX_CONTROLLER_ATTESTATION_BYTES,
        name="connector controller attestation",
    )
    qurl_go_attestation = _load_canonical(
        qurl_go_attestation_path,
        maximum=runtime.MAX_CONTROLLER_ATTESTATION_BYTES,
        name="qurl-go controller attestation",
    )
    producer_artifact = connector_attestation.get("producer_artifact")
    connector_artifact = connector_attestation.get("client_artifact")
    qurl_go_artifact = qurl_go_attestation.get("client_artifact")
    if producer_artifact != qurl_go_attestation.get("producer_artifact"):
        raise runtime.RuntimeEvidenceError(
            "controller attestations use different producer artifacts"
        )
    for path, expected, name in (
        (producer_artifact_path, producer_artifact, "producer artifact binding"),
        (
            connector_artifact_path,
            connector_artifact,
            "connector artifact binding",
        ),
        (qurl_go_artifact_path, qurl_go_artifact, "qurl-go artifact binding"),
    ):
        if path is not None and _load_canonical(
            path,
            maximum=MAX_BINDING_BYTES,
            name=name,
        ) != expected:
            raise runtime.RuntimeEvidenceError(f"{name} differs from attestation")
    if observed_at is None:
        observed_at = datetime.now(timezone.utc)
    now = observed_at.astimezone(timezone.utc)
    now = now.replace(microsecond=0)
    document = runtime.build_runtime_evidence(
        connector_attestation,
        qurl_go_attestation,
        proof_phase=proof_phase,
        producer_artifact=producer_artifact,
        connector_artifact=connector_artifact,
        qurl_go_artifact=qurl_go_artifact,
        observed_at=now,
    )
    return runtime.canonical_bytes(document)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--connector-attestation", required=True, type=Path)
    parser.add_argument("--qurl-go-attestation", required=True, type=Path)
    parser.add_argument("--producer-artifact", type=Path)
    parser.add_argument("--connector-artifact", type=Path)
    parser.add_argument("--qurl-go-artifact", type=Path)
    parser.add_argument(
        "--proof-phase",
        choices=("pre_removal", "post_removal"),
        required=True,
    )
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        raw = collect(
            connector_attestation_path=args.connector_attestation,
            qurl_go_attestation_path=args.qurl_go_attestation,
            producer_artifact_path=args.producer_artifact,
            connector_artifact_path=args.connector_artifact,
            qurl_go_artifact_path=args.qurl_go_artifact,
            proof_phase=args.proof_phase,
        )
        _write_once(args.output, raw)
    except (runtime.RuntimeEvidenceError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
