#!/usr/bin/env python3
"""Strict client-produced facts for the attended NHP runtime proof.

The qurl-go proof runs on the one-use Linux fault runner, so it is the only
component that can truthfully report packet-level client observations.  This
module validates those observations before the NHP controller promotes them
into its seven runtime-owned rows.  It accepts no ``verified`` booleans or
caller-supplied aggregate counters in place of the underlying probe/event list.
"""

from __future__ import annotations

import ipaddress
import hashlib
import re
from datetime import datetime, timedelta, timezone
from typing import Any

import udp_proof_deployment_contract as deployment


SCHEMA_VERSION = 1
GATE = "udp_lifecycle_retirement"
ARTIFACT_FILE_NAME = "runtime-probe-observations.json"
MAX_ARTIFACT_BYTES = 256 * 1024
MAX_AGE = timedelta(hours=6)

CLIENT_REPOSITORY = "layervai/qurl-go"
CLIENT_WORKFLOW = ".github/workflows/native-udp-sandbox.yml"
RUN_ID_RE = re.compile(r"^[1-9][0-9]{0,19}$")
CYCLE_RUN_ID_RE = re.compile(r"^[0-9a-f]{16}$")
CELL_ID_RE = re.compile(r"^cell[0-9]+$")
PRECISE_UTC_RE = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,9})?Z$"
)
PROBE_UTC_RE = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"\.[0-9]{1,9}Z$"
)

REGISTRATION_SEQUENCE = ["LST", "COK", "LST", "LRT", "REG", "RAK", "LST", "LRT"]
SESSION_SEQUENCE = ["KNK", "COK", "RKN", "ACK", "EXT", "ACK"]
RELAY_TYPES = {"NHP_LRT": 6, "NHP_LST": 5, "NHP_OTP": 12, "NHP_REG": 13}

HTTP_OPERATIONS = (
    ("POST", "/v1/agent/bootstrap"),
    ("GET", "/v1/agent/registration-info"),
    ("POST", "/v1/agent/registration/complete"),
    ("POST", "/internal/v1/agent/otp"),
    ("POST", "/internal/v1/agent/register"),
)


class ProbeError(deployment.ContractError):
    """The client probe artifact is incomplete, stale, or semantically false."""


def _exact(value: Any, keys: set[str], name: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise ProbeError(f"{name} must contain exactly {sorted(keys)}")
    return value


def _string(value: Any, name: str, *, maximum: int = 512) -> str:
    try:
        return deployment._string(value, name, maximum=maximum)
    except deployment.ContractError as exc:
        raise ProbeError(str(exc)) from exc


def _sha(value: Any, name: str) -> str:
    if not isinstance(value, str) or deployment.SHA_RE.fullmatch(value) is None:
        raise ProbeError(f"{name} must be a lowercase commit SHA")
    return value


def _sha256(value: Any, name: str) -> str:
    if not isinstance(value, str) or deployment.SHA256_RE.fullmatch(value) is None:
        raise ProbeError(f"{name} must be a lowercase SHA-256")
    return value


def _positive(value: Any, name: str) -> int:
    if type(value) is not int or value <= 0 or value > 9_007_199_254_740_991:
        raise ProbeError(f"{name} must be a positive safe integer")
    return value


def _zero(value: Any, name: str) -> int:
    if type(value) is not int or value != 0:
        raise ProbeError(f"{name} must be zero")
    return value


def _timestamp(value: Any, name: str) -> datetime:
    if not isinstance(value, str) or PRECISE_UTC_RE.fullmatch(value) is None:
        raise ProbeError(f"{name} must be canonical UTC RFC3339Nano")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ProbeError(f"{name} is not a real UTC timestamp") from exc
    return parsed.astimezone(timezone.utc)


def _probe_timestamp(value: Any, name: str) -> datetime:
    if not isinstance(value, str) or PROBE_UTC_RE.fullmatch(value) is None:
        raise ProbeError(f"{name} must preserve fractional UTC precision")
    return _timestamp(value, name)


def _validate_binding(
    value: Any,
    *,
    phase: str,
    expected: dict[str, Any] | None,
) -> dict[str, Any]:
    binding = _exact(
        value,
        {
            "controller_run_attempt",
            "controller_run_id",
            "dispatch_correlation_id",
            "head_sha",
            "repository",
            "run_attempt",
            "run_id",
            "workflow_path",
        },
        "runtime probe client_binding",
    )
    _sha(binding["head_sha"], "runtime probe head_sha")
    for key in ("run_id", "run_attempt", "controller_run_id", "controller_run_attempt"):
        if not isinstance(binding[key], str) or RUN_ID_RE.fullmatch(binding[key]) is None:
            raise ProbeError(f"runtime probe {key} must be a positive integer string")
    correlation_prefix = (
        f"nhp-{binding['controller_run_id']}-{binding['controller_run_attempt']}-"
        f"qurl_go-{phase}-"
    )
    if (
        binding["repository"] != CLIENT_REPOSITORY
        or binding["workflow_path"] != CLIENT_WORKFLOW
        or not isinstance(binding["dispatch_correlation_id"], str)
        or re.fullmatch(
            re.escape(correlation_prefix) + r"[0-9a-f]{32}",
            binding["dispatch_correlation_id"],
        )
        is None
    ):
        raise ProbeError("runtime probe client binding is not controller-bound")
    if expected is not None and binding != expected:
        raise ProbeError("runtime probe client binding differs from the client run")
    return binding


def _validate_capture(
    value: Any,
    *,
    expected: dict[str, Any] | None,
) -> dict[str, Any]:
    capture = _exact(
        value,
        {"ended_at", "raw_sha256", "started_at", "targets_sha256"},
        "runtime probe capture",
    )
    _sha256(capture["raw_sha256"], "runtime probe capture raw_sha256")
    _sha256(capture["targets_sha256"], "runtime probe capture targets_sha256")
    started = _timestamp(capture["started_at"], "runtime probe capture started_at")
    ended = _timestamp(capture["ended_at"], "runtime probe capture ended_at")
    if ended < started or (ended - started).total_seconds() > 3600:
        raise ProbeError("runtime probe capture interval is invalid")
    if expected is not None and capture != expected:
        raise ProbeError("runtime probe capture differs from the transport receipt")
    return capture


def _validate_wrong_caller(
    value: Any, *, expected_cell_ids: set[str] | None
) -> dict[str, Any]:
    observation = _exact(
        value,
        {"probes"},
        "wrong caller observation",
    )
    probes = observation["probes"]
    if not isinstance(probes, list) or len(probes) != 2:
        raise ProbeError("wrong caller must contain exact Hub and cell probes")
    expected_roles = {
        ("hub", "registered_assignment_refresh", "LST", "LRT"),
        ("cell", "registration_completion", "LST", "LRT"),
    }
    observed_roles: set[tuple[str, str, str, str]] = set()
    peer_hashes: set[str] = set()
    for index, raw in enumerate(probes):
        probe = _exact(
            raw,
            {
                "cell_id",
                "error_code",
                "operation",
                "outcome",
                "peer_public_key_sha256",
                "request_packet_sha256",
                "request_type",
                "response_packet_sha256",
                "response_type",
                "target_role",
            },
            f"wrong caller probe {index}",
        )
        identity = (
            probe["target_role"],
            probe["operation"],
            probe["request_type"],
            probe["response_type"],
        )
        if identity in observed_roles or identity not in expected_roles:
            raise ProbeError(f"wrong caller probe {index} identity drift")
        observed_roles.add(identity)
        if (
            probe["outcome"] != "terminal_denial"
            or not isinstance(probe["error_code"], str)
            or re.fullmatch(r"^[1-9][0-9]{4}$", probe["error_code"]) is None
            or (probe["target_role"] == "hub" and probe["cell_id"] not in {"", None})
            or (
                probe["target_role"] == "cell"
                and (
                    not isinstance(probe["cell_id"], str)
                    or CELL_ID_RE.fullmatch(probe["cell_id"]) is None
                )
            )
        ):
            raise ProbeError(f"wrong caller probe {index} is not a terminal denial")
        for key in (
            "peer_public_key_sha256",
            "request_packet_sha256",
            "response_packet_sha256",
        ):
            _sha256(probe[key], f"wrong caller probe {index} {key}")
        peer_hashes.add(probe["peer_public_key_sha256"])
        if (
            probe["target_role"] == "cell"
            and expected_cell_ids is not None
            and probe["cell_id"] not in expected_cell_ids
        ):
            raise ProbeError("wrong caller cell is outside the deployment target set")
    if observed_roles != expected_roles:
        raise ProbeError("wrong caller Hub/cell probe set drift")
    if len(peer_hashes) != 1:
        raise ProbeError("wrong caller probes did not use one fresh caller identity")
    return observation


def _address(value: Any, name: str) -> str:
    raw = _string(value, name)
    host, separator, port = raw.rpartition(":")
    if not separator or not port.isdigit() or not 1 <= int(port) <= 65535:
        raise ProbeError(f"{name} must be one IP:port")
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError as exc:
        raise ProbeError(f"{name} must be one IP:port") from exc
    return raw


def _validate_wrong_source(
    value: Any, *, expected_cell_ids: set[str] | None
) -> dict[str, Any]:
    observation = _exact(
        value,
        {"accepted_packets", "injections"},
        "wrong source observation",
    )
    _zero(observation["accepted_packets"], "wrong source accepted_packets")
    injections = observation["injections"]
    if not isinstance(injections, list) or len(injections) != 2:
        raise ProbeError("wrong source must contain exact Hub and cell injections")
    roles: set[str] = set()
    injected_sources: set[str] = set()
    for index, raw in enumerate(injections):
        injection = _exact(
            raw,
            {
                "cell_id",
                "error_class",
                "expected_source",
                "injected_packet_sha256",
                "injected_source",
                "outcome",
                "request_packet_sha256",
                "request_type",
                "response_type",
                "target_role",
            },
            f"wrong source injection {index}",
        )
        role = injection["target_role"]
        if role not in {"hub", "cell"} or role in roles:
            raise ProbeError(f"wrong source injection {index} role drift")
        roles.add(role)
        expected = _address(
            injection["expected_source"], f"wrong source injection {index} expected"
        )
        injected = _address(
            injection["injected_source"], f"wrong source injection {index} injected"
        )
        if (
            expected == injected
            or injection["error_class"] != "nativeudp.ErrTransport"
            or injection["outcome"] != "rejected"
            or (role == "hub" and injection["request_type"] != "LST")
            or (role == "cell" and injection["request_type"] != "KNK")
            or injection["response_type"] != "COK"
            or (role == "hub" and injection["cell_id"] not in {"", None})
            or (
                role == "cell"
                and (
                    not isinstance(injection["cell_id"], str)
                    or CELL_ID_RE.fullmatch(injection["cell_id"]) is None
                )
            )
        ):
            raise ProbeError(f"wrong source injection {index} did not fail closed")
        if (
            role == "cell"
            and expected_cell_ids is not None
            and injection["cell_id"] not in expected_cell_ids
        ):
            raise ProbeError("wrong source cell is outside the deployment target set")
        _sha256(
            injection["injected_packet_sha256"],
            f"wrong source injection {index} packet SHA-256",
        )
        _sha256(
            injection["request_packet_sha256"],
            f"wrong source injection {index} request packet SHA-256",
        )
        injected_sources.add(injected)
    if roles != {"hub", "cell"} or len(injected_sources) != 2:
        raise ProbeError("wrong source probes did not use distinct injected sources")
    return observation


def _validate_http(
    value: Any,
    phase: str,
    *,
    expected_operations: list[dict[str, Any]] | None,
) -> dict[str, Any]:
    observation = _exact(
        value,
        {"legacy_route_observation_count", "probes"},
        "HTTP lifecycle observation",
    )
    _zero(
        observation["legacy_route_observation_count"],
        "HTTP legacy_route_observation_count",
    )
    probes = observation["probes"]
    if phase == "pre_removal":
        if probes != []:
            raise ProbeError(
                "pre-removal HTTP evidence must be a zero-use observation"
            )
        return observation
    if not isinstance(probes, list) or len(probes) != len(HTTP_OPERATIONS):
        raise ProbeError("post-removal HTTP evidence must probe all five operations")
    normalized: list[tuple[str, str]] = []
    for index, raw in enumerate(probes):
        probe = _exact(
            raw,
            {
                "correlation_id_sha256",
                "host",
                "method",
                "path",
                "response_sha256",
                "status",
            },
            f"HTTP lifecycle probe {index}",
        )
        _sha256(probe["response_sha256"], f"HTTP lifecycle probe {index} response")
        _sha256(
            probe["correlation_id_sha256"],
            f"HTTP lifecycle probe {index} correlation",
        )
        if probe["status"] != 404:
            raise ProbeError(f"HTTP lifecycle probe {index} did not return 404")
        _string(probe["host"], f"HTTP lifecycle probe {index} host")
        normalized.append((probe["method"], probe["path"]))
    if normalized != list(HTTP_OPERATIONS):
        raise ProbeError("post-removal HTTP probe inventory/order drift")
    if expected_operations is not None:
        expected = [
            {
                "host": row["host"],
                "method": row["method"],
                "path": row["path"],
            }
            for row in expected_operations
        ]
        observed = [
            {
                "host": row["host"],
                "method": row["method"],
                "path": row["path"],
            }
            for row in probes
        ]
        if observed != expected:
            raise ProbeError("HTTP probes differ from authenticated producer targets")
    return observation


def _validate_relay(
    value: Any,
    phase: str,
    *,
    expected_aliases: list[dict[str, Any]] | None,
) -> dict[str, Any]:
    observation = _exact(
        value,
        {"probes", "relay_route_count"},
        "relay lifecycle observation",
    )
    _zero(observation["relay_route_count"], "relay lifecycle relay_route_count")
    probes = observation["probes"]
    if phase == "pre_removal":
        if probes != []:
            raise ProbeError("pre-removal relay evidence must be zero-use")
        return observation
    if not isinstance(probes, list) or len(probes) != 2 * len(RELAY_TYPES):
        raise ProbeError("post-removal relay probe matrix is incomplete")
    observed: set[tuple[str, str, str]] = set()
    aliases: set[tuple[str, str]] = set()
    for index, raw in enumerate(probes):
        probe = _exact(
            raw,
            {
                "cell_id",
                "correlation_id_sha256",
                "http_status",
                "message_type",
                "outcome",
                "request_sha256",
                "response_sha256",
                "server_id",
                "wire_value",
            },
            f"relay lifecycle probe {index}",
        )
        cell_id = _string(probe["cell_id"], f"relay probe {index} cell_id")
        server_id = _string(probe["server_id"], f"relay probe {index} server_id")
        if CELL_ID_RE.fullmatch(cell_id) is None:
            raise ProbeError(f"relay probe {index} cell_id is invalid")
        pair = (cell_id, server_id)
        key = (cell_id, server_id, probe["message_type"])
        if (
            key in observed
            or probe["message_type"] not in RELAY_TYPES
            or probe["wire_value"] != RELAY_TYPES[probe["message_type"]]
            or probe["http_status"] != 400
            or probe["outcome"] != "terminal_rejection"
        ):
            raise ProbeError(f"relay lifecycle probe {index} did not fail closed")
        aliases.add(pair)
        observed.add(key)
        _sha256(probe["request_sha256"], f"relay probe {index} request")
        _sha256(probe["response_sha256"], f"relay probe {index} response")
        _sha256(
            probe["correlation_id_sha256"], f"relay probe {index} correlation"
        )
    if len(aliases) != 2 or len({cell_id for cell_id, _ in aliases}) != 2:
        raise ProbeError("post-removal relay probes do not bind two cell aliases")
    expected_pairs = {
        (cell_id, server_id, message_type)
        for cell_id, server_id in aliases
        for message_type in RELAY_TYPES
    }
    if observed != expected_pairs:
        raise ProbeError("post-removal relay alias/type matrix drift")
    if expected_aliases is not None and aliases != {
        (row["cell_id"], row["server_id"]) for row in expected_aliases
    }:
        raise ProbeError("relay aliases differ from authenticated producer targets")
    return observation


def _validate_wire_event(
    value: Any,
    *,
    name: str,
    ordinal: int,
    expected_type: str,
    run_id: str | None,
) -> dict[str, Any]:
    event = _exact(
        value,
        {
            "cell_id",
            "direction",
            "message_type",
            "ordinal",
            "packet_sha256",
            "run_id",
            "target_role",
        },
        name,
    )
    if event["ordinal"] != ordinal or event["message_type"] != expected_type:
        raise ProbeError(f"{name} ordering/type drift")
    expected_direction = "request" if ordinal % 2 == 1 else "response"
    if event["direction"] != expected_direction:
        raise ProbeError(f"{name} direction drift")
    _sha256(event["packet_sha256"], f"{name} packet_sha256")
    if run_id is None:
        if event["run_id"] is not None:
            raise ProbeError(f"{name} registration event must not claim a RunID")
    elif expected_type == "COK":
        if event["run_id"] is not None:
            raise ProbeError(f"{name} COK must not claim a RunID")
    elif event["run_id"] != run_id:
        raise ProbeError(f"{name} did not preserve the cycle RunID")
    return event


def _validate_registration_wire(
    value: Any, *, expected_cell_ids: set[str] | None
) -> dict[str, Any]:
    observation = _exact(
        value,
        {
            "agent_id_sha256",
            "audit_sha256",
            "correlation_id_sha256",
            "events",
        },
        "registration wire observation",
    )
    for key in (
        "agent_id_sha256",
        "audit_sha256",
        "correlation_id_sha256",
    ):
        _sha256(observation[key], f"registration wire {key}")
    events = observation["events"]
    if not isinstance(events, list) or len(events) != len(REGISTRATION_SEQUENCE):
        raise ProbeError("registration wire event count drift")
    registration_cells: set[str] = set()
    for index, message_type in enumerate(REGISTRATION_SEQUENCE, 1):
        event = _validate_wire_event(
            events[index - 1],
            name=f"registration wire event {index}",
            ordinal=index,
            expected_type=message_type,
            run_id=None,
        )
        expected_role = "hub" if index <= 4 else "cell"
        if event["target_role"] != expected_role:
            raise ProbeError(f"registration wire event {index} target role drift")
        if expected_role == "hub":
            if event["cell_id"] not in {"", None}:
                raise ProbeError(f"registration wire event {index} claims a cell")
        elif (
            not isinstance(event["cell_id"], str)
            or CELL_ID_RE.fullmatch(event["cell_id"]) is None
        ):
            raise ProbeError(f"registration wire event {index} cell_id is invalid")
        elif (
            expected_cell_ids is not None and event["cell_id"] not in expected_cell_ids
        ):
            raise ProbeError(
                f"registration wire event {index} cell is outside deployment targets"
            )
        if expected_role == "cell":
            registration_cells.add(event["cell_id"])
    if len(registration_cells) != 1:
        raise ProbeError("registration wire sequence crosses cells")
    if observation["audit_sha256"] != hashlib.sha256(
        deployment.canonical_bytes(
            events,
            maximum=128 * 1024,
            name="registration wire events",
        )
    ).hexdigest():
        raise ProbeError("registration wire audit SHA-256 is not event-derived")
    return observation


def _validate_session_wire(
    value: Any, *, expected_cell_ids: set[str] | None
) -> dict[str, Any]:
    observation = _exact(
        value,
        {"audit_sha256", "cycles"},
        "session wire observation",
    )
    _sha256(observation["audit_sha256"], "session wire audit_sha256")
    cycles = observation["cycles"]
    if not isinstance(cycles, list) or len(cycles) != 2:
        raise ProbeError("session wire must contain exactly two real cycles")
    run_ids: list[str] = []
    for cycle_index, raw in enumerate(cycles):
        cycle = _exact(raw, {"events", "run_id"}, f"session cycle {cycle_index}")
        run_id = cycle["run_id"]
        if not isinstance(run_id, str) or CYCLE_RUN_ID_RE.fullmatch(run_id) is None:
            raise ProbeError(f"session cycle {cycle_index} RunID is invalid")
        run_ids.append(run_id)
        events = cycle["events"]
        if not isinstance(events, list) or len(events) != len(SESSION_SEQUENCE):
            raise ProbeError(f"session cycle {cycle_index} event count drift")
        cell_ids: set[str] = set()
        for index, message_type in enumerate(SESSION_SEQUENCE, 1):
            event = _validate_wire_event(
                events[index - 1],
                name=f"session cycle {cycle_index} event {index}",
                ordinal=index,
                expected_type=message_type,
                run_id=run_id,
            )
            if event["target_role"] != "cell":
                raise ProbeError(
                    f"session cycle {cycle_index} event {index} target role drift"
                )
            if (
                not isinstance(event["cell_id"], str)
                or CELL_ID_RE.fullmatch(event["cell_id"]) is None
            ):
                raise ProbeError(
                    f"session cycle {cycle_index} event {index} cell_id is invalid"
                )
            cell_ids.add(event["cell_id"])
            if (
                expected_cell_ids is not None
                and event["cell_id"] not in expected_cell_ids
            ):
                raise ProbeError(
                    f"session cycle {cycle_index} cell is outside deployment targets"
                )
        if len(cell_ids) != 1:
            raise ProbeError(f"session cycle {cycle_index} crosses cells")
    if run_ids[0] == run_ids[1]:
        raise ProbeError("session cycle RunID did not rotate")
    if observation["audit_sha256"] != hashlib.sha256(
        deployment.canonical_bytes(
            cycles,
            maximum=128 * 1024,
            name="session wire cycles",
        )
    ).hexdigest():
        raise ProbeError("session wire audit SHA-256 is not cycle-derived")
    return observation


def validate(
    value: Any,
    *,
    proof_phase: str,
    expected_binding: dict[str, Any] | None = None,
    expected_capture: dict[str, Any] | None = None,
    expected_retirement_probe_targets_sha256: str | None = None,
    expected_http_operations: list[dict[str, Any]] | None = None,
    expected_relay_aliases: list[dict[str, Any]] | None = None,
    validation_time: datetime | None = None,
) -> dict[str, Any]:
    """Validate one canonical client runtime-facts document."""

    if proof_phase not in {"pre_removal", "post_removal"}:
        raise ProbeError("runtime probe phase is invalid")
    document = _exact(
        value,
        {
            "capture",
            "client_binding",
            "gate",
            "observations",
            "observed_at",
            "phase",
            "probe_ended_at",
            "probe_started_at",
            "retirement_probe_targets_sha256",
            "schema_version",
        },
        "runtime probe",
    )
    if (
        document["schema_version"] != SCHEMA_VERSION
        or type(document["schema_version"]) is not int
        or document["gate"] != GATE
        or document["phase"] != proof_phase
    ):
        raise ProbeError("runtime probe header drift")
    _sha256(
        document["retirement_probe_targets_sha256"],
        "runtime probe retirement_probe_targets_sha256",
    )
    if (
        expected_retirement_probe_targets_sha256 is not None
        and document["retirement_probe_targets_sha256"]
        != expected_retirement_probe_targets_sha256
    ):
        raise ProbeError(
            "runtime probe target descriptor differs from the producer artifact"
        )
    now = (validation_time or datetime.now(timezone.utc)).astimezone(timezone.utc)
    observed = _timestamp(document["observed_at"], "runtime probe observed_at")
    if (
        observed > now + deployment.MAX_CLOCK_SKEW
        or now - observed > MAX_AGE
    ):
        raise ProbeError("runtime probe is outside its freshness window")
    probe_started = _probe_timestamp(
        document["probe_started_at"], "runtime probe probe_started_at"
    )
    probe_ended = _probe_timestamp(
        document["probe_ended_at"], "runtime probe probe_ended_at"
    )
    if (
        probe_ended < probe_started
        or probe_ended - probe_started > timedelta(minutes=15)
        or observed < probe_ended
    ):
        raise ProbeError("runtime probe observation interval is invalid")
    _validate_binding(
        document["client_binding"],
        phase=proof_phase,
        expected=expected_binding,
    )
    dispatch_correlation_id = document["client_binding"][
        "dispatch_correlation_id"
    ]
    capture = _validate_capture(document["capture"], expected=expected_capture)
    if probe_started < _timestamp(
        capture["ended_at"], "runtime probe capture ended_at"
    ):
        raise ProbeError("runtime probes overlap the transport capture window")
    observations = _exact(
        document["observations"],
        {
            "http_lifecycle",
            "registration_wire",
            "relay_lifecycle",
            "session_wire",
            "wrong_caller",
            "wrong_source",
        },
        "runtime probe observations",
    )
    expected_cell_ids = (
        {row["cell_id"] for row in expected_relay_aliases}
        if expected_relay_aliases is not None
        else None
    )
    _validate_wrong_caller(
        observations["wrong_caller"], expected_cell_ids=expected_cell_ids
    )
    _validate_wrong_source(
        observations["wrong_source"], expected_cell_ids=expected_cell_ids
    )
    _validate_http(
        observations["http_lifecycle"],
        proof_phase,
        expected_operations=expected_http_operations,
    )
    _validate_relay(
        observations["relay_lifecycle"],
        proof_phase,
        expected_aliases=expected_relay_aliases,
    )
    for probe in observations["http_lifecycle"]["probes"]:
        expected = (
            f"{dispatch_correlation_id}:http:{probe['method']}:{probe['path']}"
        )
        if probe["correlation_id_sha256"] != hashlib.sha256(
            expected.encode("utf-8")
        ).hexdigest():
            raise ProbeError("HTTP probe correlation hash is not controller-derived")
    for probe in observations["relay_lifecycle"]["probes"]:
        expected = (
            f"{dispatch_correlation_id}:relay:{probe['cell_id']}:"
            f"{probe['message_type']}"
        )
        if probe["correlation_id_sha256"] != hashlib.sha256(
            expected.encode("utf-8")
        ).hexdigest():
            raise ProbeError("relay probe correlation hash is not controller-derived")
    _validate_registration_wire(
        observations["registration_wire"], expected_cell_ids=expected_cell_ids
    )
    _validate_session_wire(
        observations["session_wire"], expected_cell_ids=expected_cell_ids
    )
    return document


def validate_bytes(raw: bytes, **kwargs: Any) -> dict[str, Any]:
    try:
        value = deployment.parse_canonical_bytes(
            raw,
            maximum=MAX_ARTIFACT_BYTES,
            name=ARTIFACT_FILE_NAME,
        )
    except deployment.ContractError as exc:
        raise ProbeError(str(exc)) from exc
    return validate(value, **kwargs)
