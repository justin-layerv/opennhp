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
import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import udp_proof_deployment_contract as deployment
import udp_proof_orchestrator_contract as orchestrator


SNAPSHOT_MAX_BYTES = 256 * 1024
BLOB_MAX_BYTES = 1024 * 1024
API_RESPONSE_MAX_BYTES = 4 * 1024 * 1024
COMMAND_TIMEOUT_SECONDS = 60
NHP_REPOSITORY = "layervai/nhp"
QURL_GO_REPOSITORY = "layervai/qurl-go"

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
        "anchor": "func httpsAgentTypeAllowed(headerType int) bool {",
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
        "anchor": "func relayReturnTypeAllowed(headerType int) bool {",
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


def _run_bounded(command: list[str], name: str) -> bytes:
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
        raise OrchestratorEvidenceError(f"{name} failed")
    if not completed.stdout or len(completed.stdout) > API_RESPONSE_MAX_BYTES:
        raise OrchestratorEvidenceError(f"{name} returned an out-of-bounds response")
    return completed.stdout


def _gh_json(path: str, name: str) -> Any:
    raw = _run_bounded(["gh", "api", "--method", "GET", path], name)
    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=deployment._reject_duplicate_keys,
            parse_constant=deployment._reject_nonfinite,
            parse_float=deployment._parse_finite_float,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, deployment.ContractError) as exc:
        raise OrchestratorEvidenceError(f"{name} is not valid JSON") from exc


def read_blob(repository: str, path: str, ref: str) -> bytes:
    """Return the exact file bytes at one immutable commit."""

    deployment._sha(ref, f"{repository} ref")
    name = f"{repository} contents {path}@{ref}"
    value = _gh_json(f"repos/{repository}/contents/{path}?ref={ref}", name)
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
    blobs: dict[str, bytes],
) -> list[dict[str, Any]]:
    """Turn the reviewed inventory into observed rows at the deployed revision."""

    observed: list[dict[str, Any]] = []
    for reviewed in REVIEWED_INTERFACES:
        path = reviewed["path"]
        blob = blobs[path]
        present = reviewed["anchor"].encode("utf-8") in blob
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
            dispatches = guard["anchor"].encode("utf-8") not in guard_blob
        observed.append(
            {
                "symbol": reviewed["symbol"],
                "path": path,
                "path_sha256": hashlib.sha256(blob).hexdigest(),
                "role": reviewed["role"],
                "state": state,
                "lifecycle_message_types": list(reviewed["lifecycle_message_types"]),
                "dispatches_lifecycle_work": dispatches,
            }
        )
    return observed


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
) -> bytes:
    """Observe every produced row and return the canonical artifact bytes."""

    snapshot = _load_snapshot(snapshot_path)
    manifest_bytes, runtime_bytes, _ = deployment.validate_triplet(
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
    nhp_sha = manifest["repositories"]["nhp"]
    qurl_go_sha = manifest["repositories"]["qurl_go"]

    paths = {reviewed["path"] for reviewed in REVIEWED_INTERFACES}
    paths.update(
        reviewed["unused_guard"]["path"]
        for reviewed in REVIEWED_INTERFACES
        if reviewed["unused_guard"] is not None
    )
    blobs = {
        path: read_blob_fn(NHP_REPOSITORY, path, nhp_sha) for path in sorted(paths)
    }
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
            "workflow_path": (
                ".github/workflows/udp-proof-deployment-manifest.yml"
            ),
            "run_id": producer_run_id,
            "run_attempt": producer_run_attempt,
            "head_sha": producer_head_sha,
        },
        "bindings": {
            "deployment_manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
            "deployment_runtime_inputs_sha256": hashlib.sha256(
                runtime_bytes
            ).hexdigest(),
            "nhp_source_sha": nhp_sha,
            "qurl_go_source_sha": qurl_go_sha,
            "retired_lifecycle_surface_path": orchestrator.RETIRED_SURFACE_PATH,
            "retired_lifecycle_surface_raw_sha256": surface_raw_sha256,
            "retired_lifecycle_surface_canonical_sha256": surface_canonical_sha256,
        },
        "produced_rows": sorted(orchestrator.PRODUCED_ROWS),
        "rows": {
            "retirement.nhp_registrar_surface_state": {
                "kind": orchestrator.ORCHESTRATOR_SCENARIO_KINDS[
                    "retirement.nhp_registrar_surface_state"
                ],
                "surface": "nhp_registrar",
                "phase": proof_phase,
                "source_repository": NHP_REPOSITORY,
                "source_sha": nhp_sha,
                "message_type_source_path": orchestrator.MESSAGE_TYPE_SOURCE_PATH,
                "message_type_source_sha256": hashlib.sha256(
                    packet_blob
                ).hexdigest(),
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
            }
        },
    }

    # Fail closed on our own output before it can reach the artifact.
    orchestrator.validate_orchestrator_evidence(
        document,
        manifest=manifest,
        manifest_bytes=manifest_bytes,
        runtime_bytes=runtime_bytes,
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
    args = parser.parse_args()
    try:
        raw = build(
            args.snapshot,
            proof_phase=args.proof_phase,
            producer_run_id=args.producer_run_id,
            producer_run_attempt=args.producer_run_attempt,
            producer_head_sha=args.producer_head_sha,
        )
        args.output.write_bytes(raw)
    except deployment.ContractError as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
