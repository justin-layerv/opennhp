#!/usr/bin/env python3
"""Validate and publish the exact final UDP proof owner aggregate."""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
from typing import Any

import udp_proof_aggregate_contract as aggregate
import udp_proof_deployment_contract as deployment


MAX_INPUT_BYTES = 5 * 1024 * 1024


def _load(path: Path, name: str) -> tuple[Any, bytes]:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise aggregate.AggregateError(f"could not read {name}") from exc
    try:
        value = deployment.parse_canonical_bytes(
            raw,
            maximum=MAX_INPUT_BYTES,
            name=name,
        )
    except deployment.ContractError as exc:
        raise aggregate.AggregateError(str(exc)) from exc
    return value, raw


def _write_once(path: Path, raw: bytes) -> None:
    if not path.is_absolute() or path != path.resolve(strict=False):
        raise aggregate.AggregateError("output must be one canonical absolute path")
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
        raise aggregate.AggregateError(
            "could not publish immutable proof aggregate"
        ) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def build(
    *,
    proof_phase: str,
    qurl_go_inventory_path: Path,
    connector_inventory_path: Path,
    qurl_go_evidence_path: Path,
    connector_evidence_path: Path,
    static_nhp_evidence_path: Path,
    runtime_nhp_evidence_path: Path,
) -> bytes:
    qurl_go_inventory, qurl_go_inventory_raw = _load(
        qurl_go_inventory_path, "qurl-go inventory"
    )
    connector_inventory, connector_inventory_raw = _load(
        connector_inventory_path, "Connector inventory"
    )
    qurl_go_evidence, qurl_go_evidence_raw = _load(
        qurl_go_evidence_path, "qurl-go evidence"
    )
    connector_evidence, connector_evidence_raw = _load(
        connector_evidence_path, "Connector evidence"
    )
    static_nhp_evidence, static_nhp_evidence_raw = _load(
        static_nhp_evidence_path, "static NHP evidence"
    )
    runtime_nhp_evidence, runtime_nhp_evidence_raw = _load(
        runtime_nhp_evidence_path, "runtime NHP evidence"
    )
    document = aggregate.build_aggregate(
        proof_phase=proof_phase,
        qurl_go_inventory=qurl_go_inventory,
        connector_inventory=connector_inventory,
        qurl_go_evidence=qurl_go_evidence,
        connector_evidence=connector_evidence,
        static_nhp_evidence=static_nhp_evidence,
        runtime_nhp_evidence=runtime_nhp_evidence,
        input_sha256={
            "qurl_go_inventory_sha256": hashlib.sha256(
                qurl_go_inventory_raw
            ).hexdigest(),
            "connector_inventory_sha256": hashlib.sha256(
                connector_inventory_raw
            ).hexdigest(),
            "qurl_go_evidence_sha256": hashlib.sha256(qurl_go_evidence_raw).hexdigest(),
            "connector_evidence_sha256": hashlib.sha256(
                connector_evidence_raw
            ).hexdigest(),
            "static_nhp_evidence_sha256": hashlib.sha256(
                static_nhp_evidence_raw
            ).hexdigest(),
            "runtime_nhp_evidence_sha256": hashlib.sha256(
                runtime_nhp_evidence_raw
            ).hexdigest(),
        },
    )
    return aggregate.canonical_bytes(document)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--proof-phase",
        choices=("pre_removal", "post_removal"),
        required=True,
    )
    parser.add_argument("--qurl-go-inventory", required=True, type=Path)
    parser.add_argument("--connector-inventory", required=True, type=Path)
    parser.add_argument("--qurl-go-evidence", required=True, type=Path)
    parser.add_argument("--connector-evidence", required=True, type=Path)
    parser.add_argument("--static-nhp-evidence", required=True, type=Path)
    parser.add_argument("--runtime-nhp-evidence", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        raw = build(
            proof_phase=args.proof_phase,
            qurl_go_inventory_path=args.qurl_go_inventory,
            connector_inventory_path=args.connector_inventory,
            qurl_go_evidence_path=args.qurl_go_evidence,
            connector_evidence_path=args.connector_evidence,
            static_nhp_evidence_path=args.static_nhp_evidence,
            runtime_nhp_evidence_path=args.runtime_nhp_evidence,
        )
        _write_once(args.output, raw)
    except aggregate.AggregateError as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
