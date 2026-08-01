#!/usr/bin/env python3
"""Observe the NHP-side per-scenario proof evidence for one producer run.

This runs inside the trusted-main deployment-manifest producer, immediately
after the deployment triplet is hydrated, and emits the fourth canonical
artifact file.  Every observation is read at the *deployed* source revision the
manifest pins -- never at the producer's own checkout -- so the evidence
describes what is actually running, and a producer commit cannot vouch for
source that was never deployed.

Reads are read-only GitHub contents API calls within the producer App token's
existing `contents: read` grant.  No AWS call and no new IAM permission is
required.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import re
import subprocess
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import udp_proof_deployment_contract as deployment
import udp_proof_orchestrator_contract as orchestrator


SNAPSHOT_MAX_BYTES = 256 * 1024
BLOB_MAX_BYTES = 1024 * 1024
API_RESPONSE_MAX_BYTES = 4 * 1024 * 1024
TERRAFORM_STATE_MAX_BYTES = 16 * 1024 * 1024
TERRAFORM_RECEIPT_ARCHIVE_MAX_BYTES = 1024 * 1024
COMMAND_TIMEOUT_SECONDS = 60
NHP_REPOSITORY = "layervai/nhp"
QURL_GO_REPOSITORY = "layervai/qurl-go"
TERRAFORM_STATE_BUCKET = "layerv-terraform-state-767397897469"
TERRAFORM_STATE_KEY = "nhp/sandbox/terraform.tfstate"

# Start of the single `iota` block in `nhp/core/packet.go` that declares every
# NHP wire message type.  Wire values are the declaration ordinals, so the
# producer re-derives them by position rather than trusting a comment.
MESSAGE_TYPE_BLOCK_START = "\tNHP_KPL = iota"
MESSAGE_TYPE_LINE_RE = re.compile(r"^\t(?P<symbol>(?:NHP|DHP)_[A-Z]{3})\b")

# Reviewed inventory of the exact NHP interfaces this row attests.
#
# `role`:
#   legacy_registrar -- the surface qurl-go's `retired_lifecycle_surface.json`
#                       retires: NHP's internal-HTTP registrar client and the
#                       HTTPS relay's native-lifecycle admission lists.
#   native_runtime   -- the direct-UDP lifecycle NHP keeps.  It is the control
#                       group: the row fails if these ever stop being present,
#                       so "everything disappeared" cannot pass the scenario.
#
# `anchor` is the exact declaration line that must exist in the deployed blob.
# `unused_guard` is the exact fail-closed fence that keeps a still-deployed
# legacy entry point from dispatching lifecycle work; its presence is what
# `dispatches_lifecycle_work: false` means, and it is read from the deployed
# blob rather than assumed.
REVIEWED_INTERFACES: tuple[dict[str, Any], ...] = (
    {
        "symbol": "(*registrar).requestOTP",
        "path": "endpoints/server/staticplugins/agent/registrar.go",
        "role": "legacy_registrar",
        "lifecycle_message_types": ["NHP_OTP"],
        "anchor": "func (r *registrar) requestOTP(",
        "unused_guard": {
            "path": "endpoints/server/staticplugins/agent/plugin.go",
            "anchor": "common.ErrRegistrationDisabled",
        },
    },
    {
        "symbol": "(*registrar).registerAgent",
        "path": "endpoints/server/staticplugins/agent/registrar.go",
        "role": "legacy_registrar",
        "lifecycle_message_types": ["NHP_RAK", "NHP_REG"],
        "anchor": "func (r *registrar) registerAgent(",
        "unused_guard": {
            "path": "endpoints/server/staticplugins/agent/plugin.go",
            "anchor": "common.ErrRegistrationDisabled",
        },
    },
    {
        "symbol": "httpsAgentTypeAllowed",
        "path": "endpoints/relay/relay.go",
        "role": "legacy_registrar",
        "lifecycle_message_types": ["NHP_LST", "NHP_OTP", "NHP_REG"],
        "anchor": (
            "case core.NHP_KNK, core.NHP_RKN, core.NHP_EXT, "
            "core.NHP_OTP, core.NHP_REG, core.NHP_LST:"
        ),
        "unused_guard": {
            "path": "endpoints/server/relay.go",
            "anchor": "rejectConnectorRegistrationOutsideDirectUDP",
        },
    },
    {
        "symbol": "relayReturnTypeAllowed",
        "path": "endpoints/relay/relay.go",
        "role": "legacy_registrar",
        "lifecycle_message_types": ["NHP_LRT", "NHP_RAK"],
        "anchor": "case core.NHP_ACK, core.NHP_COK, core.NHP_RAK, core.NHP_LRT:",
        "unused_guard": {
            "path": "endpoints/server/relay.go",
            "anchor": "rejectConnectorRegistrationOutsideDirectUDP",
        },
    },
    {
        "symbol": "(*UdpServer).HandleOTPRequest",
        "path": "endpoints/server/msghandler.go",
        "role": "native_runtime",
        "lifecycle_message_types": ["NHP_OTP"],
        "anchor": "func (s *UdpServer) HandleOTPRequest(",
        "unused_guard": None,
    },
    {
        "symbol": "(*UdpServer).HandleRegisterRequest",
        "path": "endpoints/server/msghandler.go",
        "role": "native_runtime",
        "lifecycle_message_types": ["NHP_RAK", "NHP_REG"],
        "anchor": "func (s *UdpServer) HandleRegisterRequest(",
        "unused_guard": None,
    },
    {
        "symbol": "(*UdpServer).HandleListRequest",
        "path": "endpoints/server/msghandler.go",
        "role": "native_runtime",
        "lifecycle_message_types": ["NHP_LRT", "NHP_LST"],
        "anchor": "func (s *UdpServer) HandleListRequest(",
        "unused_guard": None,
    },
    {
        "symbol": "(*UdpServer).dispatchReceivedMessage",
        "path": "endpoints/server/udpserver.go",
        "role": "native_runtime",
        "lifecycle_message_types": ["NHP_LST", "NHP_OTP", "NHP_REG"],
        "anchor": "func (s *UdpServer) dispatchReceivedMessage(",
        "unused_guard": None,
    },
)


class OrchestratorEvidenceError(orchestrator.OrchestratorContractError):
    """A live orchestrator observation is unavailable or not authoritative."""


class SourceBlobAbsent(OrchestratorEvidenceError):
    """The contents API authoritatively reported a reviewed blob absent."""


def _run_bounded(
    command: list[str],
    name: str,
    *,
    allow_not_found: bool = False,
) -> bytes | None:
    try:
        completed = subprocess.run(  # noqa: S603 - fixed argv, no shell
            command,
            capture_output=True,
            check=False,
            timeout=COMMAND_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise OrchestratorEvidenceError(f"could not run {name}") from exc
    if completed.returncode != 0:
        if allow_not_found:
            try:
                error = json.loads(completed.stdout.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                error = None
            if (
                isinstance(error, dict)
                and error.get("message") == "Not Found"
                and str(error.get("status")) == "404"
            ):
                return None
        raise OrchestratorEvidenceError(f"{name} failed")
    if not completed.stdout or len(completed.stdout) > API_RESPONSE_MAX_BYTES:
        raise OrchestratorEvidenceError(f"{name} returned an out-of-bounds response")
    return completed.stdout


def _gh_json(path: str, name: str, *, allow_not_found: bool = False) -> Any:
    raw = _run_bounded(
        ["gh", "api", "--method", "GET", path],
        name,
        allow_not_found=allow_not_found,
    )
    if raw is None:
        return None
    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=deployment._reject_duplicate_keys,
            parse_constant=deployment._reject_nonfinite,
            parse_float=deployment._parse_finite_float,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, deployment.ContractError) as exc:
        raise OrchestratorEvidenceError(f"{name} is not valid JSON") from exc


def read_terraform_state() -> dict[str, Any]:
    """Read the exact live sandbox cell0 state without retaining it as an artifact."""

    try:
        completed = subprocess.run(  # noqa: S603 - fixed argv, no shell
            [
                "aws",
                "s3",
                "cp",
                f"s3://{TERRAFORM_STATE_BUCKET}/{TERRAFORM_STATE_KEY}",
                "-",
                "--only-show-errors",
            ],
            capture_output=True,
            check=False,
            timeout=COMMAND_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise OrchestratorEvidenceError(
            "could not read the exact sandbox Terraform state"
        ) from exc
    raw = completed.stdout
    if completed.returncode != 0 or not raw or len(raw) > TERRAFORM_STATE_MAX_BYTES:
        raise OrchestratorEvidenceError(
            "sandbox Terraform state read failed or exceeded its byte bound"
        )
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=deployment._reject_duplicate_keys,
            parse_constant=deployment._reject_nonfinite,
            parse_float=deployment._parse_finite_float,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, deployment.ContractError) as exc:
        raise OrchestratorEvidenceError(
            "sandbox Terraform state is not valid JSON"
        ) from exc
    if not isinstance(value, dict):
        raise OrchestratorEvidenceError("sandbox Terraform state must be an object")
    return value


def read_authenticated_terraform_apply_receipt(
    run_id: int,
    *,
    expected_head_sha: str,
) -> dict[str, Any]:
    """Authenticate one successful trusted-main apply and its current receipt."""

    try:
        deployment._positive_int(run_id, "Terraform retirement apply run_id")
        deployment._sha(expected_head_sha, "Terraform retirement apply head_sha")
    except deployment.ContractError as exc:
        raise OrchestratorEvidenceError(str(exc)) from exc
    run = _gh_json(f"repos/{NHP_REPOSITORY}/actions/runs/{run_id}", "apply run")
    required = {
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
    }
    if not isinstance(run, dict) or not required.issubset(run):
        raise OrchestratorEvidenceError("Terraform apply run metadata is incomplete")
    repository = run["repository"]
    head_repository = run["head_repository"]
    if (
        not isinstance(repository, dict)
        or not isinstance(head_repository, dict)
        or repository.get("full_name") != NHP_REPOSITORY
        or head_repository.get("full_name") != NHP_REPOSITORY
        or repository.get("id") != head_repository.get("id")
        or run["id"] != run_id
        or run["path"] != orchestrator.TERRAFORM_APPLY_WORKFLOW_PATH
        or run["event"] not in {"push", "workflow_dispatch"}
        or run["status"] != "completed"
        or run["conclusion"] != "success"
        or run["head_branch"] != "main"
        or run["head_sha"] != expected_head_sha
        or type(run["run_attempt"]) is not int
        or run["run_attempt"] < 1
    ):
        raise OrchestratorEvidenceError(
            "Terraform apply run is not one successful trusted-main NHP apply"
        )

    artifact_name = (
        f"{orchestrator.TERRAFORM_APPLY_RECEIPT_ARTIFACT_PREFIX}-"
        f"{run_id}-{run['run_attempt']}"
    )
    response = _gh_json(
        f"repos/{NHP_REPOSITORY}/actions/runs/{run_id}/artifacts?per_page=100",
        "apply artifacts",
    )
    if not isinstance(response, dict) or not isinstance(
        response.get("artifacts"), list
    ):
        raise OrchestratorEvidenceError("Terraform apply artifacts are invalid")
    artifacts = [
        artifact
        for artifact in response["artifacts"]
        if isinstance(artifact, dict) and artifact.get("name") == artifact_name
    ]
    if len(artifacts) != 1:
        raise OrchestratorEvidenceError(
            "Terraform apply run must have exactly one current-attempt receipt"
        )
    artifact = artifacts[0]
    artifact_id = artifact.get("id")
    digest = artifact.get("digest")
    size = artifact.get("size_in_bytes")
    if (
        type(artifact_id) is not int
        or artifact_id < 1
        or artifact.get("expired") is not False
        or not isinstance(digest, str)
        or not deployment.DIGEST_RE.fullmatch(digest)
        or type(size) is not int
        or not 0 < size <= TERRAFORM_RECEIPT_ARCHIVE_MAX_BYTES
    ):
        raise OrchestratorEvidenceError(
            "Terraform apply receipt artifact metadata is invalid"
        )
    archive = _run_bounded(
        [
            "gh",
            "api",
            "--method",
            "GET",
            f"repos/{NHP_REPOSITORY}/actions/artifacts/{artifact_id}/zip",
        ],
        "apply receipt download",
    )
    if len(archive) > TERRAFORM_RECEIPT_ARCHIVE_MAX_BYTES:
        raise OrchestratorEvidenceError(
            "Terraform apply receipt archive exceeds its byte bound"
        )
    actual_digest = f"sha256:{hashlib.sha256(archive).hexdigest()}"
    if actual_digest != digest:
        raise OrchestratorEvidenceError(
            "Terraform apply receipt archive digest does not match GitHub metadata"
        )
    try:
        with zipfile.ZipFile(io.BytesIO(archive)) as zipped:
            if zipped.namelist() != [orchestrator.TERRAFORM_APPLY_RECEIPT_FILE]:
                raise OrchestratorEvidenceError(
                    "Terraform apply receipt archive must contain one exact file"
                )
            info = zipped.getinfo(orchestrator.TERRAFORM_APPLY_RECEIPT_FILE)
            if not 0 < info.file_size <= orchestrator.MAX_ORCHESTRATOR_EVIDENCE_BYTES:
                raise OrchestratorEvidenceError(
                    "Terraform apply receipt file size is out of bounds"
                )
            raw = zipped.read(info)
    except (OSError, zipfile.BadZipFile, KeyError) as exc:
        raise OrchestratorEvidenceError(
            "Terraform apply receipt archive is invalid"
        ) from exc
    try:
        value = deployment.parse_canonical_bytes(
            raw,
            maximum=orchestrator.MAX_ORCHESTRATOR_EVIDENCE_BYTES,
            name=orchestrator.TERRAFORM_APPLY_RECEIPT_FILE,
        )
    except deployment.ContractError as exc:
        raise OrchestratorEvidenceError(str(exc)) from exc
    return orchestrator.validate_terraform_apply_receipt(
        value,
        run_id=run_id,
        run_attempt=run["run_attempt"],
        head_sha=expected_head_sha,
    )


def observe_terraform_retirement(
    state: dict[str, Any],
    *,
    proof_phase: str,
    apply_receipt: dict[str, Any] | None,
) -> dict[str, Any]:
    """Project only reviewed lifecycle addresses from the secret-bearing state."""

    lineage = state.get("lineage")
    serial = state.get("serial")
    resources = state.get("resources")
    if (
        not isinstance(lineage, str)
        or not lineage
        or type(serial) is not int
        or serial < 1
        or not isinstance(resources, list)
    ):
        raise OrchestratorEvidenceError(
            "sandbox Terraform state is missing lineage, serial, or resources"
        )
    live_addresses: set[str] = set()
    for index, resource in enumerate(resources):
        if not isinstance(resource, dict):
            raise OrchestratorEvidenceError(
                f"sandbox Terraform resources[{index}] is not an object"
            )
        module = resource.get("module")
        resource_type = resource.get("type")
        name = resource.get("name")
        if (
            (module is not None and (not isinstance(module, str) or not module))
            or not isinstance(resource_type, str)
            or not isinstance(name, str)
        ):
            raise OrchestratorEvidenceError(
                f"sandbox Terraform resources[{index}] identity is invalid"
            )
        prefix = f"{module}." if module else ""
        live_addresses.add(f"{prefix}{resource_type}.{name}")

    observed_resources = []

    def is_present(address: str) -> bool:
        return address in live_addresses or any(
            candidate.startswith(f"{address}.") for candidate in live_addresses
        )

    for address in orchestrator.TERRAFORM_RETIREMENT_RESOURCES:
        present = is_present(address)
        expected_present = proof_phase == "pre_removal"
        if present != expected_present:
            expected = "present" if expected_present else "absent"
            raise OrchestratorEvidenceError(
                f"Terraform retirement surface {address} is not {expected}"
            )
        observed_resources.append(
            {
                "address": address,
                "state": "present" if present else "absent",
            }
        )

    state_projection = {
        "lineage": lineage,
        "serial": serial,
        "resources": observed_resources,
    }
    state_projection["observation_sha256"] = orchestrator._canonical_sha256(
        state_projection,
        "Terraform retirement state observation",
    )
    if proof_phase == "pre_removal":
        if apply_receipt is not None:
            raise OrchestratorEvidenceError(
                "pre-removal Terraform observation cannot claim an apply"
            )
        plan = {
            "saved_plan_sha256": None,
            "apply_run_id": None,
            "approved_deletions": [],
        }
    else:
        if apply_receipt is None:
            raise OrchestratorEvidenceError(
                "post-removal Terraform observation requires an authenticated "
                "successful apply receipt"
            )
        plan = {
            "saved_plan_sha256": apply_receipt["saved_plan_sha256"],
            "apply_run_id": apply_receipt["producer"]["run_id"],
            "approved_deletions": list(apply_receipt["approved_deletions"]),
        }
    row = {
        "kind": orchestrator.ORCHESTRATOR_SCENARIO_KINDS[
            "retirement.terraform_saved_plan_and_live_state"
        ],
        "surface": "terraform_retirement",
        "phase": proof_phase,
        "state": state_projection,
        "plan": plan,
    }
    row["row_sha256"] = orchestrator._canonical_sha256(
        row,
        "Terraform retirement row",
    )
    return row


def read_blob(repository: str, path: str, ref: str) -> bytes:
    """Return the exact file bytes at one immutable commit."""

    deployment._sha(ref, f"{repository} ref")
    name = f"{repository} contents {path}@{ref}"
    value = _gh_json(
        f"repos/{repository}/contents/{path}?ref={ref}",
        name,
        allow_not_found=True,
    )
    if value is None:
        raise SourceBlobAbsent(f"{name} is absent")
    if not isinstance(value, dict):
        raise OrchestratorEvidenceError(f"{name} is not a single file object")
    if value.get("type") != "file" or value.get("path") != path:
        raise OrchestratorEvidenceError(f"{name} is not the requested regular file")
    if value.get("encoding") != "base64":
        raise OrchestratorEvidenceError(f"{name} is not base64 content")
    size = value.get("size")
    if type(size) is not int or not 0 < size <= BLOB_MAX_BYTES:
        raise OrchestratorEvidenceError(f"{name} size is out of bounds")
    try:
        blob = base64.b64decode(value["content"], validate=False)
    except (TypeError, ValueError, KeyError) as exc:
        raise OrchestratorEvidenceError(f"{name} content is not base64") from exc
    if len(blob) != size:
        raise OrchestratorEvidenceError(f"{name} content size differs from metadata")
    return blob


def parse_message_type_wire_values(blob: bytes) -> dict[str, int]:
    """Derive every message-type wire value from the deployed `iota` block."""

    try:
        text = blob.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise OrchestratorEvidenceError("packet.go is not valid UTF-8") from exc
    lines = text.split("\n")
    start = None
    for index, line in enumerate(lines):
        if line.startswith(MESSAGE_TYPE_BLOCK_START):
            if start is not None:
                raise OrchestratorEvidenceError(
                    "packet.go declares more than one message-type iota block"
                )
            start = index
    if start is None:
        raise OrchestratorEvidenceError(
            "packet.go no longer declares the reviewed message-type iota block"
        )
    wire_values: dict[str, int] = {}
    ordinal = 0
    for line in lines[start:]:
        if line.startswith(")"):
            break
        match = MESSAGE_TYPE_LINE_RE.match(line)
        if match is None:
            continue
        symbol = match.group("symbol")
        if symbol in wire_values:
            raise OrchestratorEvidenceError(
                f"packet.go declares {symbol} more than once"
            )
        wire_values[symbol] = ordinal
        ordinal += 1
    missing = set(orchestrator.RETIRED_MESSAGE_TYPE_WIRE_VALUES) - set(wire_values)
    if missing:
        raise OrchestratorEvidenceError(
            f"packet.go no longer declares {sorted(missing)}"
        )
    return wire_values


def observe_interfaces(
    blobs: dict[str, bytes | None],
) -> list[dict[str, Any]]:
    """Turn the reviewed inventory into observed rows at the deployed revision."""

    observed: list[dict[str, Any]] = []
    for reviewed in REVIEWED_INTERFACES:
        path = reviewed["path"]
        blob = blobs[path]
        present = blob is not None and reviewed["anchor"].encode("utf-8") in blob
        guard = reviewed["unused_guard"]
        state = "present" if present else "absent"
        if reviewed["role"] == "native_runtime":
            # The retained runtime has no fence: it is supposed to dispatch.
            dispatches = present
        elif not present:
            dispatches = False
        else:
            # A still-deployed legacy entry point counts as unused only while
            # its reviewed fail-closed fence is also present at this revision.
            guard_blob = blobs[guard["path"]]
            if guard_blob is None:
                raise OrchestratorEvidenceError(
                    f"required legacy guard source {guard['path']} is absent"
                )
            dispatches = guard["anchor"].encode("utf-8") not in guard_blob
        observed.append(
            {
                "symbol": reviewed["symbol"],
                "path": path,
                "path_sha256": (
                    hashlib.sha256(blob).hexdigest() if blob is not None else None
                ),
                "role": reviewed["role"],
                "state": state,
                "lifecycle_message_types": list(reviewed["lifecycle_message_types"]),
                "dispatches_lifecycle_work": dispatches,
            }
        )
    return observed


def observe_generated_artifacts(
    *,
    manifest: dict[str, Any],
    proof_phase: str,
    read_blob_fn: Any,
) -> list[dict[str, Any]]:
    """Pin every reviewed generated/distribution surface to deployed source."""

    artifacts: list[dict[str, Any]] = []
    for surface, repository_key, path in orchestrator.GENERATED_ARTIFACT_SURFACES:
        repository = orchestrator.GENERATED_ARTIFACT_REPOSITORIES[repository_key]
        source_sha = manifest["repositories"][repository_key]
        blob = read_blob_fn(repository, path, source_sha)
        semantics = orchestrator.GENERATED_ARTIFACT_SEMANTICS[surface]
        required = [
            *semantics["required"],
            *(
                semantics["pre_removal_required"]
                if proof_phase == "pre_removal"
                else ()
            ),
        ]
        missing = [marker for marker in required if marker.encode("utf-8") not in blob]
        if missing:
            raise OrchestratorEvidenceError(
                f"{repository}/{path} is missing reviewed {proof_phase} semantic "
                f"markers {missing}"
            )
        if proof_phase == "post_removal":
            stale = [
                marker
                for marker in semantics["post_removal_forbidden"]
                if marker.encode("utf-8") in blob
            ]
            if stale:
                raise OrchestratorEvidenceError(
                    f"{repository}/{path} still exports retired lifecycle "
                    f"surface markers {stale}"
                )
        artifacts.append(
            {
                "surface": surface,
                "repository": repository,
                "source_sha": source_sha,
                "path": path,
                "path_sha256": hashlib.sha256(blob).hexdigest(),
                "contract_sha256": (orchestrator.RETIRED_SURFACE_CANONICAL_SHA256),
                "state": "matches_contract",
            }
        )
    return artifacts


def _load_snapshot(path: Path) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise OrchestratorEvidenceError(
            "could not read the hydrated evidence snapshot"
        ) from exc
    if not raw or len(raw) > SNAPSHOT_MAX_BYTES:
        raise OrchestratorEvidenceError(
            f"hydrated evidence snapshot must contain 1..{SNAPSHOT_MAX_BYTES} bytes"
        )
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=deployment._reject_duplicate_keys,
            parse_constant=deployment._reject_nonfinite,
            parse_float=deployment._parse_finite_float,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, deployment.ContractError) as exc:
        raise OrchestratorEvidenceError(
            "hydrated evidence snapshot must be valid UTF-8 JSON"
        ) from exc
    if not isinstance(value, dict) or set(value) != {
        "manifest",
        "runtime",
        "provenance",
    }:
        raise OrchestratorEvidenceError(
            "hydrated evidence snapshot must contain exactly manifest, runtime, "
            "provenance"
        )
    return value


def build(
    snapshot_path: Path,
    *,
    proof_phase: str,
    producer_run_id: int,
    producer_run_attempt: int,
    producer_head_sha: str,
    observed_at: datetime | None = None,
    read_blob_fn: Any = read_blob,
    read_terraform_state_fn: Any = read_terraform_state,
    read_terraform_apply_receipt_fn: Any = (read_authenticated_terraform_apply_receipt),
    terraform_apply_run_id: int | None = None,
) -> bytes:
    """Observe every produced row and return the canonical artifact bytes."""

    snapshot = _load_snapshot(snapshot_path)
    manifest_bytes, runtime_bytes, provenance_bytes = deployment.validate_triplet(
        snapshot["manifest"],
        snapshot["runtime"],
        snapshot["provenance"],
        proof_phase=proof_phase,
        producer_run_id=producer_run_id,
        producer_run_attempt=producer_run_attempt,
        producer_head_sha=producer_head_sha,
        validation_time=observed_at or datetime.now(timezone.utc),
    )
    manifest = snapshot["manifest"]
    runtime = snapshot["runtime"]
    provenance = snapshot["provenance"]
    nhp_sha = manifest["repositories"]["nhp"]
    qurl_go_sha = manifest["repositories"]["qurl_go"]

    paths = {reviewed["path"] for reviewed in REVIEWED_INTERFACES}
    paths.update(
        reviewed["unused_guard"]["path"]
        for reviewed in REVIEWED_INTERFACES
        if reviewed["unused_guard"] is not None
    )
    removable_legacy_paths = {
        path
        for path in paths
        if any(reviewed["path"] == path for reviewed in REVIEWED_INTERFACES)
        and all(
            reviewed["role"] == "legacy_registrar"
            for reviewed in REVIEWED_INTERFACES
            if reviewed["path"] == path
        )
    }
    blobs: dict[str, bytes | None] = {}
    for path in sorted(paths):
        try:
            blobs[path] = read_blob_fn(NHP_REPOSITORY, path, nhp_sha)
        except SourceBlobAbsent:
            if path not in removable_legacy_paths:
                raise
            blobs[path] = None
    packet_blob = read_blob_fn(
        NHP_REPOSITORY, orchestrator.MESSAGE_TYPE_SOURCE_PATH, nhp_sha
    )
    wire_values = parse_message_type_wire_values(packet_blob)

    surface_blob = read_blob_fn(
        QURL_GO_REPOSITORY, orchestrator.RETIRED_SURFACE_PATH, qurl_go_sha
    )
    surface_raw_sha256 = hashlib.sha256(surface_blob).hexdigest()
    try:
        surface_value = json.loads(
            surface_blob.decode("utf-8"),
            object_pairs_hook=deployment._reject_duplicate_keys,
            parse_constant=deployment._reject_nonfinite,
            parse_float=deployment._parse_finite_float,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, deployment.ContractError) as exc:
        raise OrchestratorEvidenceError(
            "retired lifecycle surface contract is not valid JSON"
        ) from exc
    surface_canonical_sha256 = hashlib.sha256(
        deployment.canonical_bytes(
            surface_value,
            maximum=orchestrator.MAX_ORCHESTRATOR_EVIDENCE_BYTES,
            name="retired lifecycle surface contract",
        )
    ).hexdigest()
    generated_artifacts = observe_generated_artifacts(
        manifest=manifest,
        proof_phase=proof_phase,
        read_blob_fn=read_blob_fn,
    )
    if proof_phase == "post_removal":
        if terraform_apply_run_id is None:
            raise OrchestratorEvidenceError(
                "post_removal requires terraform_apply_run_id"
            )
        terraform_apply_receipt = read_terraform_apply_receipt_fn(
            terraform_apply_run_id,
            expected_head_sha=nhp_sha,
        )
    else:
        if terraform_apply_run_id is not None:
            raise OrchestratorEvidenceError(
                "pre_removal cannot select a Terraform apply run"
            )
        terraform_apply_receipt = None
    terraform_retirement = observe_terraform_retirement(
        read_terraform_state_fn(),
        proof_phase=proof_phase,
        apply_receipt=terraform_apply_receipt,
    )

    interfaces = observe_interfaces(blobs)
    interfaces_sha256 = hashlib.sha256(
        deployment.canonical_bytes(
            interfaces,
            maximum=orchestrator.MAX_ORCHESTRATOR_EVIDENCE_BYTES,
            name="nhp registrar interfaces",
        )
    ).hexdigest()

    now = (observed_at or datetime.now(timezone.utc)).astimezone(timezone.utc)
    document = {
        "schema_version": orchestrator.SCHEMA_VERSION,
        "gate": orchestrator.GATE,
        "phase": proof_phase,
        "observed_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "producer": {
            "repository": NHP_REPOSITORY,
            "workflow_path": (".github/workflows/udp-proof-deployment-manifest.yml"),
            "run_id": producer_run_id,
            "run_attempt": producer_run_attempt,
            "head_sha": producer_head_sha,
        },
        "bindings": {
            "deployment_manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
            "deployment_runtime_inputs_sha256": hashlib.sha256(
                runtime_bytes
            ).hexdigest(),
            "deployment_provenance_sha256": hashlib.sha256(
                provenance_bytes
            ).hexdigest(),
            "nhp_source_sha": nhp_sha,
            "qurl_go_source_sha": qurl_go_sha,
            "retired_lifecycle_surface_path": orchestrator.RETIRED_SURFACE_PATH,
            "retired_lifecycle_surface_raw_sha256": surface_raw_sha256,
            "retired_lifecycle_surface_canonical_sha256": surface_canonical_sha256,
        },
        "produced_rows": sorted(orchestrator.PRODUCED_ROWS),
        "rows": {
            "orchestrator.real_hub_authority_and_two_cells": {
                "kind": orchestrator.ORCHESTRATOR_SCENARIO_KINDS[
                    "orchestrator.real_hub_authority_and_two_cells"
                ],
                "manifest_topology_sha256": orchestrator._canonical_sha256(
                    {"hub": manifest["hub"], "cells": manifest["cells"]},
                    "manifest topology",
                ),
                "runtime_topology_sha256": orchestrator._canonical_sha256(
                    {"hub": runtime["hub"], "cells": runtime["cells"]},
                    "runtime topology",
                ),
                "public_identities_sha256": orchestrator._canonical_sha256(
                    provenance["evidence"]["public_identities"],
                    "public identities",
                ),
                "workload_observations_sha256": orchestrator._canonical_sha256(
                    provenance["evidence"]["workloads"],
                    "workload observations",
                ),
                "hub": dict(manifest["hub"]),
                "cells": [dict(cell) for cell in manifest["cells"]],
                "authority": {
                    "source_sha": provenance["evidence"]["workloads"][
                        "qurl_service_authority"
                    ]["source_revision"],
                    "image_digest": provenance["evidence"]["workloads"][
                        "qurl_service_authority"
                    ]["image_digest"],
                    "proof_policy_consumers_active": provenance["evidence"][
                        "workloads"
                    ]["qurl_service_authority"]["proof_policy_consumers_active"],
                },
            },
            "retirement.generated_artifact_parity": {
                "kind": orchestrator.ORCHESTRATOR_SCENARIO_KINDS[
                    "retirement.generated_artifact_parity"
                ],
                "surface": "generated_artifact_parity",
                "phase": proof_phase,
                "canonical_contract": {
                    "repository": QURL_GO_REPOSITORY,
                    "path": orchestrator.RETIRED_SURFACE_PATH,
                    "source_sha": qurl_go_sha,
                    "raw_sha256": surface_raw_sha256,
                    "canonical_sha256": surface_canonical_sha256,
                },
                "artifacts": generated_artifacts,
                "artifacts_sha256": orchestrator._canonical_sha256(
                    generated_artifacts,
                    "generated artifact parity artifacts",
                ),
            },
            "retirement.nhp_registrar_surface_state": {
                "kind": orchestrator.ORCHESTRATOR_SCENARIO_KINDS[
                    "retirement.nhp_registrar_surface_state"
                ],
                "surface": "nhp_registrar",
                "phase": proof_phase,
                "source_repository": NHP_REPOSITORY,
                "source_sha": nhp_sha,
                "message_type_source_path": orchestrator.MESSAGE_TYPE_SOURCE_PATH,
                "message_type_source_sha256": hashlib.sha256(packet_blob).hexdigest(),
                "retired_message_type_wire_values": {
                    message_type: wire_values[message_type]
                    for message_type in orchestrator.RETIRED_MESSAGE_TYPE_WIRE_VALUES
                },
                "retired_internal_http_operations": [
                    dict(operation)
                    for operation in orchestrator.RETIRED_INTERNAL_HTTP_OPERATIONS
                ],
                "interfaces": interfaces,
                "interfaces_sha256": interfaces_sha256,
            },
            "retirement.terraform_saved_plan_and_live_state": (terraform_retirement),
        },
    }

    # Fail closed on our own output before it can reach the artifact.
    orchestrator.validate_orchestrator_evidence(
        document,
        manifest=manifest,
        runtime=runtime,
        provenance=provenance,
        manifest_bytes=manifest_bytes,
        runtime_bytes=runtime_bytes,
        provenance_bytes=provenance_bytes,
        proof_phase=proof_phase,
        producer_run_id=producer_run_id,
        producer_run_attempt=producer_run_attempt,
        producer_head_sha=producer_head_sha,
        validation_time=now,
    )
    return orchestrator.canonical_bytes(document)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--proof-phase", choices=("pre_removal", "post_removal"), required=True
    )
    parser.add_argument("--producer-run-id", type=int, required=True)
    parser.add_argument("--producer-run-attempt", type=int, required=True)
    parser.add_argument("--producer-head-sha", required=True)
    parser.add_argument("--terraform-apply-run-id", type=int)
    args = parser.parse_args()
    try:
        raw = build(
            args.snapshot,
            proof_phase=args.proof_phase,
            producer_run_id=args.producer_run_id,
            producer_run_attempt=args.producer_run_attempt,
            producer_head_sha=args.producer_head_sha,
            terraform_apply_run_id=args.terraform_apply_run_id,
        )
        args.output.write_bytes(raw)
    except deployment.ContractError as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
