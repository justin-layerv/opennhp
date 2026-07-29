#!/usr/bin/env python3
"""Revalidate the seven-row runtime artifact and both source attestations."""

from __future__ import annotations

import argparse
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import udp_proof_deployment_contract as deployment
import udp_proof_runtime_evidence_contract as runtime


MAX_BINDING_BYTES = 64 * 1024


def _load(path: Path, *, maximum: int, name: str) -> tuple[Any, bytes]:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise runtime.RuntimeEvidenceError(f"could not read {name}") from exc
    try:
        value = deployment.parse_canonical_bytes(raw, maximum=maximum, name=name)
    except deployment.ContractError as exc:
        raise runtime.RuntimeEvidenceError(str(exc)) from exc
    return value, raw


def validate(
    *,
    evidence_path: Path,
    connector_attestation_path: Path,
    qurl_go_attestation_path: Path,
    producer_artifact_path: Path,
    connector_artifact_path: Path,
    qurl_go_artifact_path: Path,
    proof_phase: str,
    validation_time: datetime | None = None,
) -> dict[str, Any]:
    evidence, evidence_raw = _load(
        evidence_path,
        maximum=runtime.MAX_RUNTIME_EVIDENCE_BYTES,
        name=runtime.ARTIFACT_FILE_NAME,
    )
    connector_attestation, connector_attestation_raw = _load(
        connector_attestation_path,
        maximum=runtime.MAX_CONTROLLER_ATTESTATION_BYTES,
        name="connector controller attestation",
    )
    qurl_go_attestation, qurl_go_attestation_raw = _load(
        qurl_go_attestation_path,
        maximum=runtime.MAX_CONTROLLER_ATTESTATION_BYTES,
        name="qurl-go controller attestation",
    )
    producer_artifact, _ = _load(
        producer_artifact_path,
        maximum=MAX_BINDING_BYTES,
        name="producer artifact binding",
    )
    connector_artifact, _ = _load(
        connector_artifact_path,
        maximum=MAX_BINDING_BYTES,
        name="connector artifact binding",
    )
    qurl_go_artifact, _ = _load(
        qurl_go_artifact_path,
        maximum=MAX_BINDING_BYTES,
        name="qurl-go artifact binding",
    )
    now = (validation_time or datetime.now(timezone.utc)).astimezone(timezone.utc)
    runtime.validate_controller_attestation(
        connector_attestation,
        client="connector",
        proof_phase=proof_phase,
        producer_artifact=producer_artifact,
        client_artifact=connector_artifact,
        validation_time=now,
    )
    runtime.validate_controller_attestation(
        qurl_go_attestation,
        client="qurl_go",
        proof_phase=proof_phase,
        producer_artifact=producer_artifact,
        client_artifact=qurl_go_artifact,
        validation_time=now,
    )
    return runtime.validate_runtime_bytes(
        evidence_raw,
        proof_phase=proof_phase,
        producer_artifact=producer_artifact,
        connector_artifact=connector_artifact,
        qurl_go_artifact=qurl_go_artifact,
        connector_attestation_sha256=hashlib.sha256(
            connector_attestation_raw
        ).hexdigest(),
        qurl_go_attestation_sha256=hashlib.sha256(qurl_go_attestation_raw).hexdigest(),
        validation_time=now,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--connector-attestation", required=True, type=Path)
    parser.add_argument("--qurl-go-attestation", required=True, type=Path)
    parser.add_argument("--producer-artifact", required=True, type=Path)
    parser.add_argument("--connector-artifact", required=True, type=Path)
    parser.add_argument("--qurl-go-artifact", required=True, type=Path)
    parser.add_argument(
        "--proof-phase",
        choices=("pre_removal", "post_removal"),
        required=True,
    )
    args = parser.parse_args()
    try:
        validate(
            evidence_path=args.evidence,
            connector_attestation_path=args.connector_attestation,
            qurl_go_attestation_path=args.qurl_go_attestation,
            producer_artifact_path=args.producer_artifact,
            connector_artifact_path=args.connector_artifact,
            qurl_go_artifact_path=args.qurl_go_artifact,
            proof_phase=args.proof_phase,
        )
    except runtime.RuntimeEvidenceError as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
