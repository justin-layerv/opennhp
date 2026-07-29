#!/usr/bin/env python3
"""Authenticate one trusted-main controller run and its exact attestation bundle."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

import udp_proof_deployment_contract as deployment
import udp_proof_runtime_evidence_contract as runtime


def _load_json(path: Path, name: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise runtime.RuntimeEvidenceError(f"could not read {name}") from exc


def _write_outputs(path: Path, values: dict[str, str]) -> None:
    with path.open("a", encoding="utf-8") as stream:
        for key, value in values.items():
            if "\n" in value or "\r" in value:
                raise runtime.RuntimeEvidenceError(f"output {key} contains a newline")
            stream.write(f"{key}={value}\n")


def metadata(
    *,
    run_path: Path,
    artifacts_path: Path,
    client: str,
    proof_phase: str,
    run_id: str,
) -> dict[str, str]:
    if client not in runtime.CLIENT_REPOSITORIES:
        raise runtime.RuntimeEvidenceError("client must be connector or qurl_go")
    if proof_phase not in {"pre_removal", "post_removal"}:
        raise runtime.RuntimeEvidenceError("proof phase is invalid")
    expected_run_id = runtime._positive(int(run_id), "controller run ID")
    run = _load_json(run_path, "controller run")
    if (
        not isinstance(run, dict)
        or run.get("id") != expected_run_id
        or run.get("repository", {}).get("full_name") != "layervai/nhp"
        or run.get("path") != runtime.CONTROLLER_WORKFLOW
        or run.get("event") != "workflow_dispatch"
        or run.get("status") != "completed"
        or run.get("conclusion") != "success"
        or run.get("head_branch") != "main"
    ):
        raise runtime.RuntimeEvidenceError(
            "controller run is not a successful trusted-main workflow dispatch"
        )
    run_attempt = runtime._positive(run.get("run_attempt"), "controller run attempt")
    head_sha = runtime._sha(run.get("head_sha"), "controller head SHA")
    artifacts = _load_json(artifacts_path, "controller artifacts")
    if (
        not isinstance(artifacts, dict)
        or set(artifacts) != {"artifacts", "total_count"}
        or not isinstance(artifacts["artifacts"], list)
        or type(artifacts["total_count"]) is not int
        or artifacts["total_count"] != len(artifacts["artifacts"])
    ):
        raise runtime.RuntimeEvidenceError(
            "controller artifact inventory is incomplete or malformed"
        )
    expected_name = (
        f"udp-proof-controller-attestation-{client}-{proof_phase}-"
        f"{expected_run_id}-{run_attempt}"
    )
    candidates = [
        item
        for item in artifacts.get("artifacts", [])
        if isinstance(item, dict)
        and item.get("name") == expected_name
        and item.get("workflow_run", {}).get("id") == expected_run_id
        and item.get("expired") is False
    ]
    if len(candidates) != 1:
        raise runtime.RuntimeEvidenceError(
            "controller run does not expose one exact current-attempt bundle"
        )
    artifact = candidates[0]
    artifact_id = runtime._positive(artifact.get("id"), "controller artifact ID")
    digest = runtime._digest(
        artifact.get("digest"), "controller artifact digest"
    )
    return {
        "artifact_digest": digest,
        "artifact_id": str(artifact_id),
        "head_sha": head_sha,
        "run_attempt": str(run_attempt),
        "run_id": str(expected_run_id),
    }


def files(
    *,
    directory: Path,
    client: str,
    proof_phase: str,
    run_id: str,
    run_attempt: str,
    head_sha: str,
) -> dict[str, str]:
    if client not in runtime.CLIENT_REPOSITORIES:
        raise runtime.RuntimeEvidenceError("client must be connector or qurl_go")
    if proof_phase not in {"pre_removal", "post_removal"}:
        raise runtime.RuntimeEvidenceError("proof phase is invalid")
    expected_entries = {"client-artifact", "controller-attestation.json"}
    try:
        entries = {entry.name for entry in directory.iterdir()}
    except OSError as exc:
        raise runtime.RuntimeEvidenceError(
            "could not read controller bundle directory"
        ) from exc
    client_directory = directory / "client-artifact"
    if (
        entries != expected_entries
        or client_directory.is_symlink()
        or not client_directory.is_dir()
    ):
        raise runtime.RuntimeEvidenceError("controller bundle file set drift")
    attestation_path = directory / "controller-attestation.json"
    try:
        raw = attestation_path.read_bytes()
        attestation = deployment.parse_canonical_bytes(
            raw,
            maximum=runtime.MAX_CONTROLLER_ATTESTATION_BYTES,
            name=f"{client} controller attestation",
        )
    except (OSError, deployment.ContractError) as exc:
        raise runtime.RuntimeEvidenceError(str(exc)) from exc
    controller = attestation.get("controller") if isinstance(attestation, dict) else None
    if (
        not isinstance(controller, dict)
        or attestation.get("client") != client
        or attestation.get("phase") != proof_phase
        or controller.get("run_id") != int(run_id)
        or controller.get("run_attempt") != int(run_attempt)
        or controller.get("head_sha") != head_sha
    ):
        raise runtime.RuntimeEvidenceError("controller bundle attestation binding drift")
    artifact = attestation.get("client_artifact")
    if not isinstance(artifact, dict):
        raise runtime.RuntimeEvidenceError("controller bundle client binding is absent")
    evidence_name = (
        "strict-sandbox-proof.evidence.json"
        if client == "connector"
        else "native-udp-sandbox.evidence.json"
    )
    inventory_name = (
        "strict-proof-scenarios.json"
        if client == "connector"
        else "pre_retirement_scenarios.json"
    )
    try:
        evidence_raw = (directory / "client-artifact" / evidence_name).read_bytes()
        inventory_raw = (directory / "client-artifact" / inventory_name).read_bytes()
    except OSError as exc:
        raise runtime.RuntimeEvidenceError(
            "controller bundle client evidence is incomplete"
        ) from exc
    if hashlib.sha256(evidence_raw).hexdigest() != artifact.get("evidence_sha256"):
        raise runtime.RuntimeEvidenceError(
            "controller bundle client evidence digest drift"
        )
    return {
        "attestation_sha256": hashlib.sha256(raw).hexdigest(),
        "evidence_sha256": hashlib.sha256(evidence_raw).hexdigest(),
        "inventory_sha256": hashlib.sha256(inventory_raw).hexdigest(),
    }


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    commands = result.add_subparsers(dest="command", required=True)
    metadata_parser = commands.add_parser("metadata")
    metadata_parser.add_argument("--run-json", type=Path, required=True)
    metadata_parser.add_argument("--artifacts-json", type=Path, required=True)
    metadata_parser.add_argument("--client", required=True)
    metadata_parser.add_argument("--proof-phase", required=True)
    metadata_parser.add_argument("--run-id", required=True)
    metadata_parser.add_argument("--github-output", type=Path, required=True)
    files_parser = commands.add_parser("files")
    files_parser.add_argument("--directory", type=Path, required=True)
    files_parser.add_argument("--client", required=True)
    files_parser.add_argument("--proof-phase", required=True)
    files_parser.add_argument("--run-id", required=True)
    files_parser.add_argument("--run-attempt", required=True)
    files_parser.add_argument("--head-sha", required=True)
    files_parser.add_argument("--github-output", type=Path, required=True)
    return result


def main() -> int:
    args = parser().parse_args()
    try:
        if args.command == "metadata":
            outputs = metadata(
                run_path=args.run_json,
                artifacts_path=args.artifacts_json,
                client=args.client,
                proof_phase=args.proof_phase,
                run_id=args.run_id,
            )
        else:
            outputs = files(
                directory=args.directory,
                client=args.client,
                proof_phase=args.proof_phase,
                run_id=args.run_id,
                run_attempt=args.run_attempt,
                head_sha=args.head_sha,
            )
        _write_outputs(args.github_output, outputs)
    except (runtime.RuntimeEvidenceError, ValueError) as exc:
        parser().error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
