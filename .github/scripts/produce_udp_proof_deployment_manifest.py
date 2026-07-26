#!/usr/bin/env python3
"""Render the exact three-file UDP proof artifact from hydrated public evidence."""

from __future__ import annotations

import argparse
import json
import os
import stat
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import udp_proof_deployment_contract as contract


SNAPSHOT_MAX_BYTES = 256 * 1024
OUTPUT_FILES = set(contract.ARTIFACT_FILE_LIMITS)


def _load_snapshot(path: Path) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise contract.ContractError(
            "could not read hydrated evidence snapshot"
        ) from exc
    if not raw or len(raw) > SNAPSHOT_MAX_BYTES:
        raise contract.ContractError(
            f"hydrated evidence snapshot must contain 1..{SNAPSHOT_MAX_BYTES} bytes"
        )
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=contract._reject_duplicate_keys,
            parse_constant=contract._reject_nonfinite,
            parse_float=contract._parse_finite_float,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise contract.ContractError(
            "hydrated evidence snapshot must be valid UTF-8 JSON"
        ) from exc
    if not isinstance(value, dict) or set(value) != {
        "manifest",
        "runtime",
        "provenance",
    }:
        raise contract.ContractError(
            "hydrated evidence snapshot must contain exactly manifest, runtime, provenance"
        )
    return value


def _prepare_output_directory(path: Path) -> None:
    if path.exists():
        if path.is_symlink() or not path.is_dir():
            raise contract.ContractError(
                "artifact output path must be a real directory"
            )
        entries = list(path.iterdir())
        if entries:
            raise contract.ContractError("artifact output directory must be empty")
    else:
        path.mkdir(mode=0o700, parents=False)
    mode = path.lstat().st_mode
    if not stat.S_ISDIR(mode) or stat.S_IMODE(mode) & 0o022:
        raise contract.ContractError(
            "artifact output directory must not be group/world writable"
        )


def _atomic_write(path: Path, raw: bytes) -> None:
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def render(
    snapshot_path: Path,
    output_directory: Path,
    *,
    proof_phase: str,
    producer_run_id: int,
    producer_run_attempt: int,
    producer_head_sha: str,
    validation_time: datetime | None = None,
) -> None:
    snapshot = _load_snapshot(snapshot_path)
    manifest_raw, runtime_raw, provenance_raw = contract.validate_triplet(
        snapshot["manifest"],
        snapshot["runtime"],
        snapshot["provenance"],
        proof_phase=proof_phase,
        producer_run_id=producer_run_id,
        producer_run_attempt=producer_run_attempt,
        producer_head_sha=producer_head_sha,
        validation_time=validation_time or datetime.now(timezone.utc),
    )
    _prepare_output_directory(output_directory)
    for name, raw in (
        ("deployment-manifest.json", manifest_raw),
        ("deployment-runtime-inputs.json", runtime_raw),
        ("deployment-provenance.json", provenance_raw),
    ):
        _atomic_write(output_directory / name, raw)
    discovered = {path.name for path in output_directory.iterdir()}
    if discovered != OUTPUT_FILES:
        raise contract.ContractError("producer emitted an unexpected artifact file set")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--output-directory", type=Path, required=True)
    parser.add_argument(
        "--proof-phase", choices=("pre_removal", "post_removal"), required=True
    )
    parser.add_argument("--producer-run-id", type=int, required=True)
    parser.add_argument("--producer-run-attempt", type=int, required=True)
    parser.add_argument("--producer-head-sha", required=True)
    args = parser.parse_args()
    try:
        render(
            args.snapshot,
            args.output_directory,
            proof_phase=args.proof_phase,
            producer_run_id=args.producer_run_id,
            producer_run_attempt=args.producer_run_attempt,
            producer_head_sha=args.producer_head_sha,
        )
    except contract.ContractError as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
