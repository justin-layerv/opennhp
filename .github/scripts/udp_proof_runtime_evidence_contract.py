#!/usr/bin/env python3
"""Strict contract for attended, runtime-owned NHP proof rows.

The deployment producer proves four static NHP rows.  This contract covers the
remaining seven rows which can only be observed while the two attended client
controllers are running.  Controller attestations are normalized from the
already authenticated client artifacts, assignment receipt, transport receipt,
and runner metadata.  They must contain concrete counters, hashes, and protocol
sequences; a boolean ``verified`` placeholder is never accepted.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from datetime import datetime, timedelta
from typing import Any, Callable

import udp_proof_deployment_contract as deployment
import udp_proof_runtime_probe_contract as runtime_probe_contract
import udp_proof_server_receipt_contract as server_receipt_contract


SCHEMA_VERSION = 1
GATE = "udp_lifecycle_retirement"
ARTIFACT_FILE_NAME = "orchestrator-runtime-evidence.json"
MAX_RUNTIME_EVIDENCE_BYTES = 256 * 1024
MAX_CONTROLLER_ATTESTATION_BYTES = 128 * 1024

RUNTIME_SCENARIO_KINDS = {
    "negative.wrong_caller": "rejection_observation",
    "negative.wrong_source": "rejection_observation",
    "orchestrator.dedicated_linux_fault_runner": "runner_attestation",
    "retirement.http_lifecycle_surface_state": "surface_inventory",
    "retirement.relay_rejects_native_lifecycle_messages": "surface_inventory",
    "wire.registration_lst_lrt_reg_rak_completion": "wire_trace",
    "wire.session_knk_ack_ext_ack": "wire_trace",
}
PRODUCED_ROWS = tuple(sorted(RUNTIME_SCENARIO_KINDS))

CLIENT_REPOSITORIES = {
    "connector": "layervai/qurl-connector",
    "qurl_go": "layervai/qurl-go",
}
CLIENT_WORKFLOWS = {
    "connector": ".github/workflows/sandbox-smoke.yml",
    "qurl_go": ".github/workflows/native-udp-sandbox.yml",
}
CONTROLLER_WORKFLOW = ".github/workflows/udp-proof-controller.yml"

REGISTRATION_SEQUENCE = [
    "LST",
    "COK",
    "LST",
    "LRT",
    "REG",
    "RAK",
    "LST",
    "LRT",
]
SESSION_SEQUENCE = ["KNK", "COK", "RKN", "ACK", "EXT", "ACK"]
RELAY_NATIVE_LIFECYCLE_TYPES = ["LRT", "LST", "OTP", "REG"]
RUNNER_CAPABILITIES = [
    "docker",
    "narrow_kms_role",
    "net_admin",
    "packet_capture",
    "tc_netem",
    "udp_proxy",
]
RUN_ID_RE = re.compile(r"^[0-9a-f]{16}$")
INSTANCE_ID_RE = re.compile(r"^i-[0-9a-f]{8,17}$")
CIDR_RE = re.compile(r"^[0-9./:a-f]+$")
MAX_CONTROLLER_ATTESTATION_AGE = timedelta(hours=6)


class RuntimeEvidenceError(deployment.ContractError):
    """Runtime evidence is incomplete, unbound, stale, or semantically false."""


def _exact(value: Any, keys: set[str], name: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise RuntimeEvidenceError(f"{name} must contain exactly {sorted(keys)}")
    return value


def _string(value: Any, name: str, *, maximum: int = 512) -> str:
    try:
        return deployment._string(value, name, maximum=maximum)
    except deployment.ContractError as exc:
        raise RuntimeEvidenceError(str(exc)) from exc


def _sha(value: Any, name: str) -> str:
    if not isinstance(value, str) or deployment.SHA_RE.fullmatch(value) is None:
        raise RuntimeEvidenceError(f"{name} must be a lowercase commit SHA")
    return value


def _sha256(value: Any, name: str) -> str:
    if not isinstance(value, str) or deployment.SHA256_RE.fullmatch(value) is None:
        raise RuntimeEvidenceError(f"{name} must be a lowercase SHA-256")
    return value


def _digest(value: Any, name: str) -> str:
    if not isinstance(value, str) or deployment.DIGEST_RE.fullmatch(value) is None:
        raise RuntimeEvidenceError(f"{name} must be a lowercase sha256 digest")
    return value


def _positive(value: Any, name: str) -> int:
    if type(value) is not int or value <= 0 or value > 9_007_199_254_740_991:
        raise RuntimeEvidenceError(f"{name} must be a positive safe integer")
    return value


def _zero(value: Any, name: str) -> int:
    if type(value) is not int or value != 0:
        raise RuntimeEvidenceError(f"{name} must be zero")
    return value


def _bool(value: Any, expected: bool, name: str) -> bool:
    if type(value) is not bool or value is not expected:
        raise RuntimeEvidenceError(f"{name} must be {str(expected).lower()}")
    return value


def _timestamp(value: Any, name: str) -> datetime:
    try:
        return deployment._timestamp(value, name)
    except deployment.ContractError as exc:
        raise RuntimeEvidenceError(str(exc)) from exc


def _validate_fresh(
    value: Any,
    validation_time: datetime,
    name: str,
    *,
    maximum_age: timedelta = deployment.MAX_PROVENANCE_AGE,
) -> None:
    observed = _timestamp(value, name)
    try:
        validated = deployment._utc_time(validation_time, f"{name} validation time")
    except deployment.ContractError as exc:
        raise RuntimeEvidenceError(str(exc)) from exc
    if (
        observed > validated + deployment.MAX_CLOCK_SKEW
        or validated - observed > maximum_age
    ):
        raise RuntimeEvidenceError(
            f"{name} is outside its authenticated freshness window"
        )


def canonical_bytes(value: Any) -> bytes:
    return deployment.canonical_bytes(
        value,
        maximum=MAX_RUNTIME_EVIDENCE_BYTES,
        name=ARTIFACT_FILE_NAME,
    )


def canonical_attestation_bytes(value: Any, client: str) -> bytes:
    return deployment.canonical_bytes(
        value,
        maximum=MAX_CONTROLLER_ATTESTATION_BYTES,
        name=f"{client} controller attestation",
    )


def _validate_producer(value: Any, expected: dict[str, Any]) -> dict[str, Any]:
    producer = _exact(
        value,
        {
            "artifact_digest",
            "artifact_id",
            "head_sha",
            "manifest_sha256",
            "provenance_sha256",
            "run_attempt",
            "run_id",
            "runtime_inputs_sha256",
        },
        "producer artifact",
    )
    _positive(producer["artifact_id"], "producer artifact_id")
    _positive(producer["run_id"], "producer run_id")
    _positive(producer["run_attempt"], "producer run_attempt")
    _digest(producer["artifact_digest"], "producer artifact_digest")
    _sha(producer["head_sha"], "producer head_sha")
    for key in ("manifest_sha256", "provenance_sha256", "runtime_inputs_sha256"):
        _sha256(producer[key], f"producer {key}")
    if producer != expected:
        raise RuntimeEvidenceError("controller attestation producer binding drift")
    return producer


def _validate_client_artifact(
    value: Any, client: str, expected: dict[str, Any]
) -> dict[str, Any]:
    artifact = _exact(
        value,
        {
            "artifact_digest",
            "artifact_id",
            "evidence_sha256",
            "head_sha",
            "repository",
            "run_attempt",
            "run_id",
            "typed_evidence_sha256",
            "workflow_path",
        },
        f"{client} client artifact",
    )
    _positive(artifact["artifact_id"], f"{client} artifact_id")
    _positive(artifact["run_id"], f"{client} run_id")
    _positive(artifact["run_attempt"], f"{client} run_attempt")
    _digest(artifact["artifact_digest"], f"{client} artifact_digest")
    _sha(artifact["head_sha"], f"{client} head_sha")
    _sha256(artifact["evidence_sha256"], f"{client} evidence_sha256")
    _sha256(artifact["typed_evidence_sha256"], f"{client} typed_evidence_sha256")
    if (
        artifact["repository"] != CLIENT_REPOSITORIES[client]
        or artifact["workflow_path"] != CLIENT_WORKFLOWS[client]
        or artifact != expected
    ):
        raise RuntimeEvidenceError(f"{client} client artifact binding drift")
    return artifact


def _validate_runner(value: Any, client: str) -> dict[str, Any]:
    runner = _exact(
        value,
        {
            "capabilities",
            "egress_ip",
            "instance_id",
            "packet_capture_sha256",
            "reviewed_source_cidr",
            "runner_group",
            "runner_labels_sha256",
        },
        f"{client} runner",
    )
    if (
        runner["runner_group"] != "udp-proof-sandbox"
        or runner["capabilities"] != RUNNER_CAPABILITIES
        or not isinstance(runner["instance_id"], str)
        or INSTANCE_ID_RE.fullmatch(runner["instance_id"]) is None
    ):
        raise RuntimeEvidenceError(f"{client} runner identity/capabilities drift")
    _sha256(runner["runner_labels_sha256"], f"{client} runner_labels_sha256")
    _sha256(runner["packet_capture_sha256"], f"{client} packet_capture_sha256")
    cidr = _string(runner["reviewed_source_cidr"], f"{client} reviewed_source_cidr")
    ip = _string(runner["egress_ip"], f"{client} egress_ip")
    if CIDR_RE.fullmatch(cidr) is None:
        raise RuntimeEvidenceError(f"{client} reviewed_source_cidr is invalid")
    try:
        network = ipaddress.ip_network(cidr, strict=True)
        address = ipaddress.ip_address(ip)
    except ValueError as exc:
        raise RuntimeEvidenceError(
            f"{client} runner source address is invalid"
        ) from exc
    if address not in network:
        raise RuntimeEvidenceError(
            f"{client} runner egress IP is outside the reviewed source CIDR"
        )
    return runner


def _validate_assignment_receipt(
    value: Any, client_artifact: dict[str, Any]
) -> dict[str, Any]:
    receipt = _exact(
        value,
        {
            "agent_id_sha256",
            "assigned_cells",
            "checkpoint_sha256",
            "client_run_id",
            "client_sha",
            "correlation_id_sha256",
            "receipt_sha256",
        },
        "qurl-go assignment receipt",
    )
    for key in (
        "agent_id_sha256",
        "checkpoint_sha256",
        "correlation_id_sha256",
        "receipt_sha256",
    ):
        _sha256(receipt[key], f"qurl-go assignment {key}")
    if (
        receipt["client_run_id"] != client_artifact["run_id"]
        or receipt["client_sha"] != client_artifact["head_sha"]
        or receipt["assigned_cells"] != ["cell0", "cell1"]
    ):
        raise RuntimeEvidenceError("qurl-go assignment receipt binding drift")
    return receipt


def _validate_transport_receipt(
    value: Any, client_artifact: dict[str, Any]
) -> dict[str, Any]:
    receipt = _exact(
        value,
        {
            "capture_ended_at",
            "capture_sha256",
            "capture_started_at",
            "capture_targets_sha256",
            "client_run_id",
            "client_sha",
            "nhp_udp_lifecycle_success",
            "qurl_service_legacy_route_count",
            "receipt_sha256",
            "relay_route_count",
        },
        "qurl-go transport receipt",
    )
    for key in ("capture_sha256", "capture_targets_sha256", "receipt_sha256"):
        _sha256(receipt[key], f"qurl-go transport {key}")
    if (
        receipt["client_run_id"] != client_artifact["run_id"]
        or receipt["client_sha"] != client_artifact["head_sha"]
    ):
        raise RuntimeEvidenceError("qurl-go transport receipt binding drift")
    _bool(
        receipt["nhp_udp_lifecycle_success"],
        True,
        "qurl-go nhp_udp_lifecycle_success",
    )
    _zero(
        receipt["qurl_service_legacy_route_count"],
        "qurl-go qurl_service_legacy_route_count",
    )
    _zero(receipt["relay_route_count"], "qurl-go relay_route_count")
    started = _timestamp(receipt["capture_started_at"], "capture_started_at")
    ended = _timestamp(receipt["capture_ended_at"], "capture_ended_at")
    if ended < started or (ended - started).total_seconds() > 3600:
        raise RuntimeEvidenceError("qurl-go transport capture interval is invalid")
    return receipt


def _validate_wrong_caller(value: Any, phase: str) -> dict[str, Any]:
    row = _exact(
        value,
        {
            "accepted_operations",
            "attempted_operations",
            "audit_sha256",
            "capture_sha256",
            "cell_terminal_denials",
            "hub_terminal_denials",
            "kind",
            "phase",
        },
        "wrong caller row",
    )
    if row["kind"] != "rejection_observation" or row["phase"] != phase:
        raise RuntimeEvidenceError("wrong caller row identity drift")
    attempts = _positive(row["attempted_operations"], "wrong caller attempts")
    hub = _positive(row["hub_terminal_denials"], "wrong caller Hub denials")
    cell = _positive(row["cell_terminal_denials"], "wrong caller cell denials")
    if hub + cell != attempts:
        raise RuntimeEvidenceError("wrong caller attempts are not all terminal denials")
    _zero(row["accepted_operations"], "wrong caller accepted_operations")
    _sha256(row["capture_sha256"], "wrong caller capture_sha256")
    _sha256(row["audit_sha256"], "wrong caller audit_sha256")
    return row


def _validate_wrong_source(value: Any, phase: str) -> dict[str, Any]:
    row = _exact(
        value,
        {
            "accepted_packets",
            "audit_sha256",
            "capture_sha256",
            "injected_packets",
            "kind",
            "phase",
            "source_binding_failures",
        },
        "wrong source row",
    )
    if row["kind"] != "rejection_observation" or row["phase"] != phase:
        raise RuntimeEvidenceError("wrong source row identity drift")
    injected = _positive(row["injected_packets"], "wrong source injected_packets")
    if (
        _positive(
            row["source_binding_failures"], "wrong source source_binding_failures"
        )
        != injected
    ):
        raise RuntimeEvidenceError("wrong source packets were not all rejected")
    _zero(row["accepted_packets"], "wrong source accepted_packets")
    _sha256(row["capture_sha256"], "wrong source capture_sha256")
    _sha256(row["audit_sha256"], "wrong source audit_sha256")
    return row


def _validate_http_surface(value: Any, phase: str) -> dict[str, Any]:
    row = _exact(
        value,
        {
            "alias_reachable_count",
            "enumerated_surface_count",
            "kind",
            "legacy_route_observation_count",
            "openapi_entries_present",
            "phase",
            "probe_results_sha256",
            "surface_contract_sha256",
            "surface_state",
        },
        "HTTP lifecycle surface row",
    )
    if row["kind"] != "surface_inventory" or row["phase"] != phase:
        raise RuntimeEvidenceError("HTTP lifecycle surface row identity drift")
    _positive(row["enumerated_surface_count"], "HTTP enumerated_surface_count")
    _zero(
        row["legacy_route_observation_count"],
        "HTTP legacy_route_observation_count",
    )
    _zero(row["alias_reachable_count"], "HTTP alias_reachable_count")
    _sha256(row["surface_contract_sha256"], "HTTP surface_contract_sha256")
    _sha256(row["probe_results_sha256"], "HTTP probe_results_sha256")
    if phase == "pre_removal":
        if row["surface_state"] != "deployed_unused":
            raise RuntimeEvidenceError(
                "pre-removal HTTP surfaces are not deployed-unused"
            )
        _bool(
            row["openapi_entries_present"],
            True,
            "pre-removal HTTP openapi_entries_present",
        )
    else:
        if row["surface_state"] != "removed_404":
            raise RuntimeEvidenceError("post-removal HTTP surfaces are not removed")
        _bool(
            row["openapi_entries_present"],
            False,
            "post-removal HTTP openapi_entries_present",
        )
    return row


def _validate_relay(value: Any, phase: str) -> dict[str, Any]:
    row = _exact(
        value,
        {
            "accepted_messages",
            "attempted_message_types",
            "authority_invocations",
            "kind",
            "phase",
            "plugin_dispatches",
            "probe_results_sha256",
            "rejected_alias_type_pairs",
            "relay_route_count",
            "waiters_created",
        },
        "relay lifecycle row",
    )
    if row["kind"] != "surface_inventory" or row["phase"] != phase:
        raise RuntimeEvidenceError("relay lifecycle row identity drift")
    _zero(row["accepted_messages"], "relay accepted_messages")
    _zero(row["authority_invocations"], "relay authority_invocations")
    _zero(row["plugin_dispatches"], "relay plugin_dispatches")
    _zero(row["waiters_created"], "relay waiters_created")
    _zero(row["relay_route_count"], "relay relay_route_count")
    _sha256(row["probe_results_sha256"], "relay probe_results_sha256")
    if phase == "pre_removal":
        if row["attempted_message_types"] != []:
            raise RuntimeEvidenceError(
                "pre-removal relay row must be the zero-use observation"
            )
        _zero(
            row["rejected_alias_type_pairs"],
            "pre-removal relay rejected_alias_type_pairs",
        )
    else:
        if row["attempted_message_types"] != RELAY_NATIVE_LIFECYCLE_TYPES:
            raise RuntimeEvidenceError("post-removal relay probe type set drift")
        _positive(
            row["rejected_alias_type_pairs"],
            "post-removal relay rejected_alias_type_pairs",
        )
    return row


def _validate_registration_wire(value: Any, phase: str) -> dict[str, Any]:
    row = _exact(
        value,
        {
            "agent_id_sha256",
            "audit_sha256",
            "capture_sha256",
            "correlation_id_sha256",
            "kind",
            "message_sequence",
            "phase",
            "sequence_packet_count",
        },
        "registration wire row",
    )
    if (
        row["kind"] != "wire_trace"
        or row["phase"] != phase
        or row["message_sequence"] != REGISTRATION_SEQUENCE
        or row["sequence_packet_count"] != len(REGISTRATION_SEQUENCE)
    ):
        raise RuntimeEvidenceError("registration wire sequence drift")
    for key in (
        "agent_id_sha256",
        "audit_sha256",
        "capture_sha256",
        "correlation_id_sha256",
    ):
        _sha256(row[key], f"registration {key}")
    return row


def _validate_session_wire(value: Any, phase: str) -> dict[str, Any]:
    row = _exact(
        value,
        {
            "audit_sha256",
            "capture_sha256",
            "first_cycle_run_id",
            "kind",
            "message_sequence",
            "next_cycle_run_id",
            "phase",
            "same_run_id_message_types",
            "sequence_packet_count",
        },
        "session wire row",
    )
    first = row["first_cycle_run_id"]
    second = row["next_cycle_run_id"]
    if (
        row["kind"] != "wire_trace"
        or row["phase"] != phase
        or row["message_sequence"] != SESSION_SEQUENCE
        or row["sequence_packet_count"] != len(SESSION_SEQUENCE)
        or row["same_run_id_message_types"] != ["EXT", "KNK", "RKN"]
        or not isinstance(first, str)
        or RUN_ID_RE.fullmatch(first) is None
        or not isinstance(second, str)
        or RUN_ID_RE.fullmatch(second) is None
        or first == second
    ):
        raise RuntimeEvidenceError("session wire sequence/RunID binding drift")
    _sha256(row["capture_sha256"], "session capture_sha256")
    _sha256(row["audit_sha256"], "session audit_sha256")
    return row


def _observation_sha256(value: Any, name: str) -> str:
    return hashlib.sha256(
        deployment.canonical_bytes(value, maximum=128 * 1024, name=name)
    ).hexdigest()


def rows_from_runtime_observations(
    *,
    runtime_probe: dict[str, Any],
    server_receipt: dict[str, Any],
    transport_receipt: dict[str, Any],
    surface_contract_sha256: str,
    proof_phase: str,
) -> dict[str, Any]:
    """Normalize already-validated client/server facts into the six NHP rows."""

    observations = runtime_probe["observations"]
    wrong_caller = observations["wrong_caller"]
    caller_probes = wrong_caller["probes"]
    wrong_source = observations["wrong_source"]
    http = observations["http_lifecycle"]
    relay = observations["relay_lifecycle"]
    registration = observations["registration_wire"]
    session = observations["session_wire"]
    http_receipt = server_receipt["http"]
    relay_receipt = server_receipt["relay"]
    caller_digest = _observation_sha256(
        caller_probes, "wrong caller probe observations"
    )
    source_digest = _observation_sha256(
        wrong_source, "wrong source probe observations"
    )
    http_digest = _observation_sha256(
        {"client": http, "server": http_receipt},
        "HTTP lifecycle client/server observations",
    )
    relay_digest = _observation_sha256(
        {"client": relay, "server": relay_receipt},
        "relay lifecycle client/server observations",
    )
    registration_events = registration["events"]
    session_cycles = session["cycles"]
    message_types = sorted(
        {row["message_type"].removeprefix("NHP_") for row in relay["probes"]}
    )
    rows = {
        "negative.wrong_caller": {
            "accepted_operations": 0,
            "attempted_operations": len(caller_probes),
            "audit_sha256": caller_digest,
            "capture_sha256": caller_digest,
            "cell_terminal_denials": sum(
                row["target_role"] == "cell" for row in caller_probes
            ),
            "hub_terminal_denials": sum(
                row["target_role"] == "hub" for row in caller_probes
            ),
            "kind": "rejection_observation",
            "phase": proof_phase,
        },
        "negative.wrong_source": {
            "accepted_packets": wrong_source["accepted_packets"],
            "audit_sha256": source_digest,
            "capture_sha256": source_digest,
            "injected_packets": len(wrong_source["injections"]),
            "kind": "rejection_observation",
            "phase": proof_phase,
            "source_binding_failures": sum(
                row["outcome"] == "rejected" for row in wrong_source["injections"]
            ),
        },
        "retirement.http_lifecycle_surface_state": {
            "alias_reachable_count": 0,
            "enumerated_surface_count": len(runtime_probe_contract.HTTP_OPERATIONS),
            "kind": "surface_inventory",
            "legacy_route_observation_count": http_receipt[
                "legacy_handler_dispatch_count"
            ],
            "openapi_entries_present": proof_phase == "pre_removal",
            "phase": proof_phase,
            "probe_results_sha256": http_digest,
            "surface_contract_sha256": surface_contract_sha256,
            "surface_state": (
                "deployed_unused"
                if proof_phase == "pre_removal"
                else "removed_404"
            ),
        },
        "retirement.relay_rejects_native_lifecycle_messages": {
            "accepted_messages": 0,
            "attempted_message_types": message_types,
            "authority_invocations": 0,
            "kind": "surface_inventory",
            "phase": proof_phase,
            "plugin_dispatches": relay_receipt["server_dispatch_count"],
            "probe_results_sha256": relay_digest,
            "rejected_alias_type_pairs": len(relay["probes"]),
            "relay_route_count": relay["relay_route_count"],
            "waiters_created": relay_receipt["waiter_created_count"],
        },
        "wire.registration_lst_lrt_reg_rak_completion": {
            "agent_id_sha256": registration["agent_id_sha256"],
            "audit_sha256": registration["audit_sha256"],
            "capture_sha256": transport_receipt["capture_sha256"],
            "correlation_id_sha256": registration["correlation_id_sha256"],
            "kind": "wire_trace",
            "message_sequence": [row["message_type"] for row in registration_events],
            "phase": proof_phase,
            "sequence_packet_count": len(registration_events),
        },
        "wire.session_knk_ack_ext_ack": {
            "audit_sha256": session["audit_sha256"],
            "capture_sha256": transport_receipt["capture_sha256"],
            "first_cycle_run_id": session_cycles[0]["run_id"],
            "kind": "wire_trace",
            "message_sequence": [
                row["message_type"] for row in session_cycles[0]["events"]
            ],
            "next_cycle_run_id": session_cycles[1]["run_id"],
            "phase": proof_phase,
            "same_run_id_message_types": ["EXT", "KNK", "RKN"],
            "sequence_packet_count": len(session_cycles[0]["events"]),
        },
    }
    return rows


ROW_VALIDATORS: dict[str, Callable[[Any, str], dict[str, Any]]] = {
    "negative.wrong_caller": _validate_wrong_caller,
    "negative.wrong_source": _validate_wrong_source,
    "retirement.http_lifecycle_surface_state": _validate_http_surface,
    "retirement.relay_rejects_native_lifecycle_messages": _validate_relay,
    "wire.registration_lst_lrt_reg_rak_completion": _validate_registration_wire,
    "wire.session_knk_ack_ext_ack": _validate_session_wire,
}


def validate_controller_attestation(
    value: Any,
    *,
    client: str,
    proof_phase: str,
    producer_artifact: dict[str, Any],
    client_artifact: dict[str, Any],
    validation_time: datetime,
) -> dict[str, Any]:
    """Validate one controller's normalized, authenticated runtime inputs."""

    if client not in CLIENT_REPOSITORIES:
        raise RuntimeEvidenceError("client must be connector or qurl_go")
    if proof_phase not in {"pre_removal", "post_removal"}:
        raise RuntimeEvidenceError("proof phase is invalid")
    attestation = _exact(
        value,
        {
            "assignment_receipt",
            "client",
            "client_artifact",
            "controller",
            "gate",
            "observed_at",
            "phase",
            "producer_artifact",
            "rows",
            "runner",
            "runtime_probe",
            "schema_version",
            "server_authority",
            "server_receipt",
            "surface_contract_sha256",
            "transport_receipt",
        },
        f"{client} controller attestation",
    )
    if (
        attestation["schema_version"] != SCHEMA_VERSION
        or type(attestation["schema_version"]) is not int
        or attestation["gate"] != GATE
        or attestation["phase"] != proof_phase
        or attestation["client"] != client
    ):
        raise RuntimeEvidenceError(f"{client} controller attestation header drift")
    _validate_fresh(
        attestation["observed_at"],
        validation_time,
        f"{client} controller observed_at",
        maximum_age=MAX_CONTROLLER_ATTESTATION_AGE,
    )
    controller = _exact(
        attestation["controller"],
        {"head_sha", "repository", "run_attempt", "run_id", "workflow_path"},
        f"{client} controller",
    )
    if (
        controller["repository"] != "layervai/nhp"
        or controller["workflow_path"] != CONTROLLER_WORKFLOW
    ):
        raise RuntimeEvidenceError(f"{client} controller identity drift")
    _sha(controller["head_sha"], f"{client} controller head_sha")
    _positive(controller["run_id"], f"{client} controller run_id")
    _positive(controller["run_attempt"], f"{client} controller run_attempt")
    _validate_producer(attestation["producer_artifact"], producer_artifact)
    artifact = _validate_client_artifact(
        attestation["client_artifact"], client, client_artifact
    )
    _validate_runner(attestation["runner"], client)

    rows = attestation["rows"]
    if client == "connector":
        if (
            rows != {}
            or attestation["assignment_receipt"] is not None
            or attestation["runtime_probe"] is not None
            or attestation["server_authority"] is not None
            or attestation["server_receipt"] is not None
            or attestation["surface_contract_sha256"] is not None
        ):
            raise RuntimeEvidenceError(
                "Connector controller attestation must not claim NHP runtime rows"
            )
        if attestation["transport_receipt"] is not None:
            raise RuntimeEvidenceError(
                "Connector transport facts belong to its typed artifact, not NHP rows"
            )
        return attestation

    assignment = _validate_assignment_receipt(
        attestation["assignment_receipt"], artifact
    )
    transport = _validate_transport_receipt(attestation["transport_receipt"], artifact)
    server_authority = _exact(
        attestation["server_authority"],
        {"proof_source_ip", "qurl_service_log_groups", "relay_log_group"},
        "qurl-go server authority",
    )
    source_ip = _string(
        server_authority["proof_source_ip"], "qurl-go proof_source_ip"
    )
    try:
        ipaddress.ip_address(source_ip)
    except ValueError as exc:
        raise RuntimeEvidenceError("qurl-go proof_source_ip is invalid") from exc
    log_groups = server_authority["qurl_service_log_groups"]
    relay_log_group = server_authority["relay_log_group"]
    if (
        not isinstance(log_groups, list)
        or len(log_groups) != 2
        or len(set(log_groups)) != 2
        or any(not isinstance(value, str) or not value for value in log_groups)
        or not isinstance(relay_log_group, str)
        or not relay_log_group
    ):
        raise RuntimeEvidenceError("qurl-go server authority log groups are invalid")
    runtime_probe_value = attestation["runtime_probe"]
    if not isinstance(runtime_probe_value, dict):
        raise RuntimeEvidenceError("qurl-go runtime probe must be an object")
    probe_binding = runtime_probe_value.get("client_binding")
    if not isinstance(probe_binding, dict):
        raise RuntimeEvidenceError("qurl-go runtime probe binding is invalid")
    expected_binding = {
        "controller_run_attempt": str(controller["run_attempt"]),
        "controller_run_id": str(controller["run_id"]),
        "dispatch_correlation_id": probe_binding.get("dispatch_correlation_id"),
        "head_sha": artifact["head_sha"],
        "repository": artifact["repository"],
        "run_attempt": str(artifact["run_attempt"]),
        "run_id": str(artifact["run_id"]),
        "workflow_path": artifact["workflow_path"],
    }
    expected_capture = {
        "ended_at": transport["capture_ended_at"],
        "raw_sha256": transport["capture_sha256"],
        "started_at": transport["capture_started_at"],
        "targets_sha256": transport["capture_targets_sha256"],
    }
    try:
        runtime_probe = runtime_probe_contract.validate(
            runtime_probe_value,
            proof_phase=proof_phase,
            expected_binding=expected_binding,
            expected_capture=expected_capture,
            validation_time=validation_time,
        )
        server_receipt = server_receipt_contract.validate(
            attestation["server_receipt"],
            runtime_probe_document=runtime_probe,
            proof_source_ip=source_ip,
            qurl_service_log_groups=log_groups,
            relay_log_group=relay_log_group,
        )
    except (
        runtime_probe_contract.ProbeError,
        server_receipt_contract.ReceiptError,
    ) as exc:
        raise RuntimeEvidenceError(str(exc)) from exc
    surface_contract_sha256 = _sha256(
        attestation["surface_contract_sha256"],
        "qurl-go surface_contract_sha256",
    )
    expected_rows = rows_from_runtime_observations(
        runtime_probe=runtime_probe,
        server_receipt=server_receipt,
        transport_receipt=transport,
        surface_contract_sha256=surface_contract_sha256,
        proof_phase=proof_phase,
    )
    if rows != expected_rows:
        raise RuntimeEvidenceError(
            "qurl-go runtime rows differ from authoritative client/server observations"
        )
    for scenario_id, validator in ROW_VALIDATORS.items():
        rows[scenario_id] = validator(rows[scenario_id], proof_phase)

    registration = rows["wire.registration_lst_lrt_reg_rak_completion"]
    if (
        registration["capture_sha256"] != transport["capture_sha256"]
        or registration["agent_id_sha256"] != assignment["agent_id_sha256"]
        or registration["correlation_id_sha256"] != assignment["correlation_id_sha256"]
    ):
        raise RuntimeEvidenceError(
            "runtime rows are not bound to the authenticated assignment/transport receipts"
        )
    return attestation


def _runner_row(
    connector: dict[str, Any], qurl_go: dict[str, Any], proof_phase: str
) -> dict[str, Any]:
    runners = [connector["runner"], qurl_go["runner"]]
    instance_ids = sorted(runner["instance_id"] for runner in runners)
    if len(set(instance_ids)) != 2:
        raise RuntimeEvidenceError(
            "Connector and qurl-go proofs must use distinct one-use runner instances"
        )
    return {
        "kind": "runner_attestation",
        "phase": proof_phase,
        "runner_group": "udp-proof-sandbox",
        "capabilities": RUNNER_CAPABILITIES,
        "runner_count": 2,
        "instance_ids_sha256": hashlib.sha256(
            deployment.canonical_bytes(
                instance_ids,
                maximum=4096,
                name="runtime proof instance IDs",
            )
        ).hexdigest(),
        "runner_labels_set_sha256": hashlib.sha256(
            deployment.canonical_bytes(
                sorted(runner["runner_labels_sha256"] for runner in runners),
                maximum=4096,
                name="runtime proof runner labels",
            )
        ).hexdigest(),
        "packet_capture_set_sha256": hashlib.sha256(
            deployment.canonical_bytes(
                sorted(runner["packet_capture_sha256"] for runner in runners),
                maximum=4096,
                name="runtime proof packet captures",
            )
        ).hexdigest(),
    }


def _validate_runner_row(value: Any, proof_phase: str) -> dict[str, Any]:
    row = _exact(
        value,
        {
            "capabilities",
            "instance_ids_sha256",
            "kind",
            "packet_capture_set_sha256",
            "phase",
            "runner_count",
            "runner_group",
            "runner_labels_set_sha256",
        },
        "dedicated runner row",
    )
    if (
        row["kind"] != "runner_attestation"
        or row["phase"] != proof_phase
        or row["runner_group"] != "udp-proof-sandbox"
        or row["capabilities"] != RUNNER_CAPABILITIES
        or row["runner_count"] != 2
    ):
        raise RuntimeEvidenceError("dedicated runner row drift")
    for key in (
        "instance_ids_sha256",
        "packet_capture_set_sha256",
        "runner_labels_set_sha256",
    ):
        _sha256(row[key], f"dedicated runner {key}")
    return row


def build_runtime_evidence(
    connector_attestation: dict[str, Any],
    qurl_go_attestation: dict[str, Any],
    *,
    proof_phase: str,
    producer_artifact: dict[str, Any],
    connector_artifact: dict[str, Any],
    qurl_go_artifact: dict[str, Any],
    observed_at: datetime,
) -> dict[str, Any]:
    """Validate both controller attestations and assemble the exact seven rows."""

    connector = validate_controller_attestation(
        connector_attestation,
        client="connector",
        proof_phase=proof_phase,
        producer_artifact=producer_artifact,
        client_artifact=connector_artifact,
        validation_time=observed_at,
    )
    qurl_go = validate_controller_attestation(
        qurl_go_attestation,
        client="qurl_go",
        proof_phase=proof_phase,
        producer_artifact=producer_artifact,
        client_artifact=qurl_go_artifact,
        validation_time=observed_at,
    )
    if connector["controller"]["head_sha"] != qurl_go["controller"]["head_sha"]:
        raise RuntimeEvidenceError(
            "Connector and qurl-go attestations use different NHP controller revisions"
        )
    connector_raw = canonical_attestation_bytes(connector, "connector")
    qurl_go_raw = canonical_attestation_bytes(qurl_go, "qurl_go")
    connector_attestation_sha256 = hashlib.sha256(connector_raw).hexdigest()
    qurl_go_attestation_sha256 = hashlib.sha256(qurl_go_raw).hexdigest()
    rows = dict(qurl_go["rows"])
    rows["orchestrator.dedicated_linux_fault_runner"] = _runner_row(
        connector, qurl_go, proof_phase
    )
    document = {
        "schema_version": SCHEMA_VERSION,
        "gate": GATE,
        "phase": proof_phase,
        "observed_at": observed_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "producer_artifact": dict(producer_artifact),
        "controller_attestations": {
            "connector": {
                "run_id": connector["controller"]["run_id"],
                "run_attempt": connector["controller"]["run_attempt"],
                "head_sha": connector["controller"]["head_sha"],
                "sha256": connector_attestation_sha256,
            },
            "qurl_go": {
                "run_id": qurl_go["controller"]["run_id"],
                "run_attempt": qurl_go["controller"]["run_attempt"],
                "head_sha": qurl_go["controller"]["head_sha"],
                "sha256": qurl_go_attestation_sha256,
            },
        },
        "client_artifacts": {
            "connector": dict(connector_artifact),
            "qurl_go": dict(qurl_go_artifact),
        },
        "produced_rows": list(PRODUCED_ROWS),
        "rows": {key: rows[key] for key in PRODUCED_ROWS},
    }
    validate_runtime_evidence(
        document,
        proof_phase=proof_phase,
        producer_artifact=producer_artifact,
        connector_artifact=connector_artifact,
        qurl_go_artifact=qurl_go_artifact,
        connector_attestation_sha256=connector_attestation_sha256,
        qurl_go_attestation_sha256=qurl_go_attestation_sha256,
        validation_time=observed_at,
    )
    return document


def validate_runtime_evidence(
    value: Any,
    *,
    proof_phase: str,
    producer_artifact: dict[str, Any],
    connector_artifact: dict[str, Any],
    qurl_go_artifact: dict[str, Any],
    connector_attestation_sha256: str,
    qurl_go_attestation_sha256: str,
    validation_time: datetime,
) -> dict[str, Any]:
    document = _exact(
        value,
        {
            "client_artifacts",
            "controller_attestations",
            "gate",
            "observed_at",
            "phase",
            "produced_rows",
            "producer_artifact",
            "rows",
            "schema_version",
        },
        "runtime evidence",
    )
    if (
        document["schema_version"] != SCHEMA_VERSION
        or type(document["schema_version"]) is not int
        or document["gate"] != GATE
        or document["phase"] != proof_phase
    ):
        raise RuntimeEvidenceError("runtime evidence header drift")
    _validate_fresh(document["observed_at"], validation_time, "runtime observed_at")
    _validate_producer(document["producer_artifact"], producer_artifact)
    artifacts = _exact(
        document["client_artifacts"],
        {"connector", "qurl_go"},
        "runtime client_artifacts",
    )
    _validate_client_artifact(artifacts["connector"], "connector", connector_artifact)
    _validate_client_artifact(artifacts["qurl_go"], "qurl_go", qurl_go_artifact)
    controllers = _exact(
        document["controller_attestations"],
        {"connector", "qurl_go"},
        "runtime controller_attestations",
    )
    expected_attestation_digests = {
        "connector": _sha256(
            connector_attestation_sha256, "connector attestation SHA-256"
        ),
        "qurl_go": _sha256(qurl_go_attestation_sha256, "qurl-go attestation SHA-256"),
    }
    identities: set[tuple[int, int]] = set()
    controller_heads: set[str] = set()
    for client, controller in controllers.items():
        item = _exact(
            controller,
            {"head_sha", "run_attempt", "run_id", "sha256"},
            f"runtime {client} controller",
        )
        controller_heads.add(
            _sha(item["head_sha"], f"runtime {client} controller head_sha")
        )
        run_id = _positive(item["run_id"], f"runtime {client} controller run_id")
        attempt = _positive(
            item["run_attempt"], f"runtime {client} controller run_attempt"
        )
        if item["sha256"] != expected_attestation_digests[client]:
            raise RuntimeEvidenceError(
                f"runtime {client} controller attestation digest drift"
            )
        identities.add((run_id, attempt))
    if len(identities) != 2:
        raise RuntimeEvidenceError("runtime evidence reuses one controller run")
    if len(controller_heads) != 1:
        raise RuntimeEvidenceError("runtime evidence mixes NHP controller revisions")

    rows = document["rows"]
    if (
        not isinstance(rows, dict)
        or document["produced_rows"] != list(PRODUCED_ROWS)
        or set(rows) != set(PRODUCED_ROWS)
    ):
        raise RuntimeEvidenceError("runtime evidence row set is incomplete")
    for scenario_id, row in rows.items():
        if scenario_id == "orchestrator.dedicated_linux_fault_runner":
            _validate_runner_row(row, proof_phase)
        else:
            ROW_VALIDATORS[scenario_id](row, proof_phase)
    return document


def validate_runtime_bytes(raw: bytes, **kwargs: Any) -> dict[str, Any]:
    try:
        value = deployment.parse_canonical_bytes(
            raw,
            maximum=MAX_RUNTIME_EVIDENCE_BYTES,
            name=ARTIFACT_FILE_NAME,
        )
    except deployment.ContractError as exc:
        raise RuntimeEvidenceError(str(exc)) from exc
    return validate_runtime_evidence(value, **kwargs)
