#!/usr/bin/env python3
"""Authenticate one governed UDP-proof producer artifact for the controller.

The wrapper normalizes GitHub API responses into the pure shared deployment
contract. Metadata mode binds one successful trusted-main producer run to its
current-attempt artifact. Files mode revalidates the complete three-file
contract before deriving any client dispatch input.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import udp_proof_deployment_contract as deployment
import udp_proof_orchestrator_contract as orchestrator
import udp_proof_retirement_targets_contract as retirement_targets
import validate_udp_proof_controller_inputs as controller


class ArtifactValidationError(controller.ValidationError):
    """Authenticated producer state violates the frozen proof contract."""


def _positive_int_string(value: str, name: str) -> int:
    if not isinstance(value, str) or not controller.RUN_ID_RE.fullmatch(value):
        raise ArtifactValidationError(f"{name} must be a positive integer")
    return int(value)


def _required_object(value: Any, required: set[str], name: str) -> dict[str, Any]:
    if not isinstance(value, dict) or not required.issubset(value):
        raise ArtifactValidationError(f"{name} is missing required fields")
    return value


def validate_metadata(
    run: Any,
    artifacts_response: Any,
    expected_run_id: str,
    *,
    current_time: datetime | None = None,
) -> dict[str, str]:
    """Bind one successful trusted-main run to one current-attempt artifact."""

    run_id = _positive_int_string(expected_run_id, "deployment producer run ID")
    run_object = _required_object(
        run,
        {
            "id",
            "path",
            "event",
            "status",
            "conclusion",
            "head_branch",
            "head_sha",
            "run_attempt",
            "repository",
            "head_repository",
        },
        "producer run",
    )
    repository = _required_object(
        run_object["repository"], {"id", "full_name"}, "producer repository"
    )
    repository_id = repository["id"]
    if type(repository_id) is not int or repository_id <= 0:
        raise ArtifactValidationError(
            "producer repository id must be a positive integer"
        )
    head_repository = _required_object(
        run_object["head_repository"],
        {"id", "full_name"},
        "producer head repository",
    )
    if (
        head_repository["id"] != repository_id
        or head_repository["full_name"] != repository["full_name"]
    ):
        raise ArtifactValidationError(
            "producer head repository differs from the authenticated repository"
        )

    normalized_run = {
        "repository": repository["full_name"],
        "workflow_path": run_object["path"],
        "event": run_object["event"],
        "status": run_object["status"],
        "conclusion": run_object["conclusion"],
        "run_id": run_object["id"],
        "run_attempt": run_object["run_attempt"],
        "head_branch": run_object["head_branch"],
        "head_sha": run_object["head_sha"],
    }
    try:
        deployment.validate_authenticated_producer_run(
            normalized_run,
            producer_run_id=run_id,
            producer_run_attempt=run_object["run_attempt"],
            producer_head_sha=run_object["head_sha"],
        )
    except deployment.ContractError as exc:
        raise ArtifactValidationError(str(exc)) from exc

    envelope = _required_object(
        artifacts_response, {"total_count", "artifacts"}, "producer artifacts response"
    )
    raw_artifacts = envelope["artifacts"]
    total_count = envelope["total_count"]
    if (
        type(total_count) is not int
        or not isinstance(raw_artifacts, list)
        or total_count != len(raw_artifacts)
        or not 1 <= total_count <= 100
    ):
        raise ArtifactValidationError(
            "producer artifact response must contain the complete bounded 1..100 list"
        )

    normalized_artifacts: list[dict[str, Any]] = []
    for index, raw in enumerate(raw_artifacts):
        artifact = _required_object(
            raw,
            {
                "id",
                "name",
                "digest",
                "size_in_bytes",
                "expired",
                "created_at",
                "workflow_run",
            },
            f"producer artifact {index}",
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
            f"producer artifact {index} workflow run",
        )
        if (
            artifact_run["id"] != run_id
            or artifact_run["repository_id"] != repository_id
            or artifact_run["head_repository_id"] != repository_id
            or artifact_run["head_branch"] != "main"
            or artifact_run["head_sha"] != run_object["head_sha"]
        ):
            raise ArtifactValidationError(
                f"producer artifact {index} does not belong to the authenticated run"
            )
        normalized_artifacts.append(
            {
                "artifact_id": artifact["id"],
                "name": artifact["name"],
                "digest": artifact["digest"],
                "size_in_bytes": artifact["size_in_bytes"],
                "expired": artifact["expired"],
                "workflow_run_id": artifact_run["id"],
                "created_at": artifact["created_at"],
            }
        )

    now = current_time or datetime.now(timezone.utc)
    try:
        selected = deployment.select_producer_artifact(
            normalized_artifacts,
            producer_run_id=run_id,
            producer_run_attempt=run_object["run_attempt"],
            current_time=now,
        )
    except deployment.ContractError as exc:
        raise ArtifactValidationError(str(exc)) from exc

    return {
        "producer_run_id": str(run_id),
        "producer_run_attempt": str(run_object["run_attempt"]),
        "producer_head_sha": run_object["head_sha"],
        "producer_artifact_id": str(selected["artifact_id"]),
        "producer_artifact_digest": selected["digest"],
    }


def _proof_recovery_alias_arn(provenance: dict[str, Any]) -> str:
    """Return the one deployment-attested selected recovery-control alias."""

    try:
        functions = provenance["evidence"]["workloads"]["qurl_service_authority"][
            "functions"
        ]
    except (KeyError, TypeError) as exc:
        raise ArtifactValidationError(
            "producer provenance omits the Authority function set"
        ) from exc
    if not isinstance(functions, list):
        raise ArtifactValidationError("producer Authority function set is invalid")
    prefix = "arn:aws:lambda:us-east-2:767397897469:function:layerv-nhp-sandbox-ca-pcr:"
    allowed = {prefix + "blue", prefix + "green"}
    matches = [
        item["alias_arn"]
        for item in functions
        if isinstance(item, dict) and item.get("alias_arn") in allowed
    ]
    if len(matches) != 1:
        raise ArtifactValidationError(
            "producer provenance must attest exactly one selected recovery-control alias"
        )
    return matches[0]


def validate_files(
    directory: Path,
    *,
    proof_phase: str,
    producer_run_id: str,
    producer_run_attempt: str,
    producer_head_sha: str,
    pre_removal_run_id: str,
    client: str,
    validation_time: datetime | None = None,
) -> dict[str, str]:
    """Revalidate the exact producer triplet and derive client dispatch inputs."""

    run_id = _positive_int_string(producer_run_id, "producer run ID")
    run_attempt = _positive_int_string(producer_run_attempt, "producer run attempt")
    now = validation_time or datetime.now(timezone.utc)
    try:
        manifest, runtime, provenance = deployment.load_triplet_directory(directory)
        manifest_raw, runtime_raw, provenance_raw = deployment.validate_triplet(
            manifest,
            runtime,
            provenance,
            proof_phase=proof_phase,
            producer_run_id=run_id,
            producer_run_attempt=run_attempt,
            producer_head_sha=producer_head_sha,
            validation_time=now,
        )
        # The orchestrator evidence rides in the same artifact, so validating it
        # here binds NHP's per-scenario rows to this exact deployment
        # observation before any client dispatch input is derived.
        orchestrator_raw = deployment.load_orchestrator_file(directory)
        orchestrator.validate_orchestrator_bytes(
            orchestrator_raw,
            manifest=manifest,
            runtime=runtime,
            provenance=provenance,
            manifest_bytes=manifest_raw,
            runtime_bytes=runtime_raw,
            provenance_bytes=provenance_raw,
            proof_phase=proof_phase,
            producer_run_id=run_id,
            producer_run_attempt=run_attempt,
            producer_head_sha=producer_head_sha,
            validation_time=now,
        )
        retirement_targets_value = deployment.load_canonical_file(
            directory / retirement_targets.ARTIFACT_FILE_NAME,
            maximum=retirement_targets.MAX_ARTIFACT_BYTES,
            name=retirement_targets.ARTIFACT_FILE_NAME,
        )
        retirement_targets.validate(
            retirement_targets_value,
            proof_phase=proof_phase,
            producer_run_id=run_id,
            producer_run_attempt=run_attempt,
            producer_head_sha=producer_head_sha,
            deployment_provenance_sha256=hashlib.sha256(
                provenance_raw
            ).hexdigest(),
            validation_time=now,
        )
        retirement_targets_raw = retirement_targets.canonical_bytes(
            retirement_targets_value
        )
    except deployment.ContractError as exc:
        raise ArtifactValidationError(str(exc)) from exc

    candidates = provenance["candidates"]
    manifest_b64 = base64.b64encode(manifest_raw).decode("ascii")
    try:
        outputs = controller.select_dispatch(
            client=client,
            proof_phase=proof_phase,
            manifest=manifest,
            candidates=candidates,
            pre_removal_run_id=pre_removal_run_id,
        )
    except controller.ValidationError as exc:
        raise ArtifactValidationError(str(exc)) from exc
    outputs.update(
        {
            "proof_recovery_alias_arn": _proof_recovery_alias_arn(provenance),
            "deployment_manifest_b64": manifest_b64,
            "deployment_runtime_inputs_b64": base64.b64encode(runtime_raw).decode(
                "ascii"
            ),
            "deployment_provenance_b64": base64.b64encode(provenance_raw).decode(
                "ascii"
            ),
            "retirement_probe_targets_b64": base64.b64encode(
                retirement_targets_raw
            ).decode("ascii"),
            "deployment_manifest_sha256": hashlib.sha256(manifest_raw).hexdigest(),
            "deployment_runtime_inputs_sha256": hashlib.sha256(runtime_raw).hexdigest(),
            "deployment_provenance_sha256": hashlib.sha256(
                provenance_raw
            ).hexdigest(),
            "retirement_probe_targets_sha256": hashlib.sha256(
                retirement_targets_raw
            ).hexdigest(),
            "orchestrator_evidence_sha256": hashlib.sha256(
                orchestrator_raw
            ).hexdigest(),
        }
    )
    return outputs


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
        raise ArtifactValidationError(f"could not read JSON input {path}") from exc


def _write_outputs(path: Path, outputs: dict[str, str]) -> None:
    with path.open("a", encoding="utf-8") as handle:
        for name, value in outputs.items():
            if "\n" in value or "\r" in value:
                raise ArtifactValidationError(f"output {name} contains a newline")
            handle.write(f"{name}={value}\n")


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    metadata = subparsers.add_parser("metadata")
    metadata.add_argument("--run-json", type=Path, required=True)
    metadata.add_argument("--artifacts-json", type=Path, required=True)
    metadata.add_argument("--producer-run-id", required=True)
    metadata.add_argument("--github-output", type=Path, required=True)

    files = subparsers.add_parser("files")
    files.add_argument("--directory", type=Path, required=True)
    files.add_argument("--client", required=True)
    files.add_argument("--proof-phase", required=True)
    files.add_argument("--producer-run-id", required=True)
    files.add_argument("--producer-run-attempt", required=True)
    files.add_argument("--producer-head-sha", required=True)
    files.add_argument("--pre-removal-run-id", default="")
    files.add_argument("--github-output", type=Path, required=True)
    args = parser.parse_args()

    try:
        if args.command == "metadata":
            outputs = validate_metadata(
                _load_json(args.run_json),
                _load_json(args.artifacts_json),
                args.producer_run_id,
            )
        else:
            outputs = validate_files(
                args.directory,
                proof_phase=args.proof_phase,
                producer_run_id=args.producer_run_id,
                producer_run_attempt=args.producer_run_attempt,
                producer_head_sha=args.producer_head_sha,
                pre_removal_run_id=args.pre_removal_run_id,
                client=args.client,
            )
        _write_outputs(args.github_output, outputs)
    except (ArtifactValidationError, OSError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
