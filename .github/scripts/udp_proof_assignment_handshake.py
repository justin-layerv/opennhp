#!/usr/bin/env python3
"""Coordinate one replay-bound qurl-go assignment mutation proof."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import secrets
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ACCOUNT_ID = "767397897469"
REGION = "us-east-2"
BUCKET = f"layerv-nhp-sandbox-udp-proof-handshake-{ACCOUNT_ID}"
KMS_ALIAS_ARN = (
    f"arn:aws:kms:{REGION}:{ACCOUNT_ID}:"
    "alias/layerv-nhp-sandbox-udp-proof-handshake"
)
KMS_KEY_ARN_RE = re.compile(
    rf"^arn:aws:kms:{REGION}:{ACCOUNT_ID}:key/"
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
ALIAS_RE = re.compile(
    rf"^arn:aws:lambda:{REGION}:{ACCOUNT_ID}:function:"
    r"layerv-nhp-sandbox-ca-pm:(blue|green)$"
)
HEX32_RE = re.compile(r"^[0-9a-f]{32}$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
RUN_RE = re.compile(r"^[1-9][0-9]{0,19}$")
TIMESTAMP_RE = re.compile(
    r"^[0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])"
    r"T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$"
)
PHASES = frozenset({"pre_removal", "post_removal"})
ARM_LEASE_SECONDS = 2100
EXPIRE_LEASE_SECONDS = 30
PROOF_SOURCE_IP = "3.141.109.76"
TRANSPORT_HTTP_HOSTS = [
    "api.layerv.xyz",
    "bootstrap.layerv.xyz",
    "relay.qurl.link.layerv.xyz",
]
QURL_SERVICE_LOG_GROUPS = [
    "/layerv/nhp/sandbox/cell0/qurl-api",
    "/layerv/nhp/sandbox/cell1/qurl-api",
]
RELAY_LOG_GROUP = "/layerv/nhp/sandbox/relay"
LEGACY_LIFECYCLE_HTTP_ROUTES = [
    {"method": "GET", "path": "/v1/agent/registration-info"},
    {"method": "POST", "path": "/v1/agent/bootstrap"},
    {"method": "POST", "path": "/v1/agent/registration/complete"},
]
COUNTER_INGESTION_WAIT_SECONDS = 120


class HandshakeError(RuntimeError):
    pass


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise HandshakeError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _loads(raw: bytes | str, name: str) -> Any:
    if isinstance(raw, bytes):
        try:
            raw = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise HandshakeError(f"{name} is not UTF-8") from exc
    try:
        return json.loads(
            raw,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda value: (_ for _ in ()).throw(
                HandshakeError(f"{name} contains non-finite {value}")
            ),
        )
    except json.JSONDecodeError as exc:
        raise HandshakeError(f"{name} is not strict JSON") from exc


def _canonical(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode()


def _exact(value: Any, keys: set[str], name: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        observed = sorted(value) if isinstance(value, dict) else type(value).__name__
        raise HandshakeError(f"{name} keys differ: {observed}")
    return value


def _decode_b64(raw: str, name: str, maximum: int = 4 * 1024 * 1024) -> bytes:
    if not isinstance(raw, str) or not raw or len(raw) > maximum * 2:
        raise HandshakeError(f"{name} length is invalid")
    try:
        decoded = base64.b64decode(raw, validate=True)
    except ValueError as exc:
        raise HandshakeError(f"{name} is not canonical base64") from exc
    if not decoded or len(decoded) > maximum:
        raise HandshakeError(f"{name} decoded length is invalid")
    return decoded


def _timestamp(value: Any, name: str) -> datetime:
    if not isinstance(value, str) or TIMESTAMP_RE.fullmatch(value) is None:
        raise HandshakeError(f"{name} must be canonical whole-second UTC")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as exc:
        raise HandshakeError(f"{name} is not a real UTC timestamp") from exc
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
        raise HandshakeError(f"{name} is not canonical whole-second UTC")
    return parsed


def select_ca_pm_alias(provenance: Any) -> str:
    root = _exact(
        provenance,
        {
            "candidates",
            "evidence",
            "files",
            "producer",
            "schema_version",
        },
        "deployment provenance",
    )
    evidence = root["evidence"]
    if not isinstance(evidence, dict):
        raise HandshakeError("deployment provenance evidence is invalid")
    workloads = evidence.get("workloads")
    if not isinstance(workloads, dict):
        raise HandshakeError("deployment provenance workloads are invalid")
    authority = workloads.get("qurl_service_authority")
    if not isinstance(authority, dict):
        raise HandshakeError("deployment manifest has no Authority workload")
    if authority.get("proof_policy_consumers_active") is not True:
        raise HandshakeError(
            "selected IA/RA/ICR proof-policy activation is not live; "
            "the governed zero-spill rollout is still required"
        )
    functions = authority.get("functions")
    if not isinstance(functions, list):
        raise HandshakeError("Authority function inventory is invalid")
    aliases = []
    for item in functions:
        if (
            isinstance(item, dict)
            and set(item) == {"alias_arn", "version_arn"}
            and isinstance(item.get("alias_arn"), str)
            and ALIAS_RE.fullmatch(item["alias_arn"])
        ):
            aliases.append(item["alias_arn"])
    if len(aliases) != 1:
        raise HandshakeError("manifest must bind exactly one selected ca-pm alias")
    return aliases[0]


def validate_descriptor(value: Any) -> dict[str, Any]:
    descriptor = _exact(
        value,
        {
            "agent_id",
            "arm_request_id",
            "bucket",
            "ca_pm_alias_arn",
            "channel_id",
            "checkpoint_key",
            "client",
            "controller_run_attempt",
            "controller_run_id",
            "correlation_id",
            "expire_request_id",
            "kms_key_arn",
            "arm_lease_seconds",
            "expire_lease_seconds",
            "move_request_id",
            "pinned_cell_id",
            "proof_phase",
            "receipt_key",
            "target_cell_id",
            "version",
        },
        "handshake descriptor",
    )
    run_id = descriptor["controller_run_id"]
    run_attempt = descriptor["controller_run_attempt"]
    phase = descriptor["proof_phase"]
    channel = descriptor["channel_id"]
    if (
        descriptor["version"] != 1
        or descriptor["client"] != "qurl_go"
        or not isinstance(run_id, str)
        or RUN_RE.fullmatch(run_id) is None
        or not isinstance(run_attempt, str)
        or RUN_RE.fullmatch(run_attempt) is None
        or phase not in PHASES
        or not isinstance(channel, str)
        or HEX32_RE.fullmatch(channel) is None
        or descriptor["bucket"] != BUCKET
        or not isinstance(descriptor["kms_key_arn"], str)
        or KMS_KEY_ARN_RE.fullmatch(descriptor["kms_key_arn"]) is None
        or descriptor["pinned_cell_id"] != "cell0"
        or descriptor["target_cell_id"] != "cell1"
        or descriptor["arm_lease_seconds"] != ARM_LEASE_SECONDS
        or descriptor["expire_lease_seconds"] != EXPIRE_LEASE_SECONDS
        or not isinstance(descriptor["ca_pm_alias_arn"], str)
        or ALIAS_RE.fullmatch(descriptor["ca_pm_alias_arn"]) is None
    ):
        raise HandshakeError("handshake descriptor scalar binding is invalid")
    prefix = f"handshake/v1/{run_id}/{run_attempt}/{channel}"
    expected = {
        "agent_id": f"qurl-go-sandbox-{run_id}-{run_attempt}",
        "correlation_id": f"nhp-{run_id}-{run_attempt}-qurl_go-{phase}-{channel}",
        "checkpoint_key": f"{prefix}/checkpoint.json",
        "receipt_key": f"{prefix}/receipt.json",
    }
    if any(descriptor[key] != item for key, item in expected.items()):
        raise HandshakeError("handshake descriptor run binding is invalid")
    for key in ("arm_request_id", "move_request_id", "expire_request_id"):
        if not isinstance(descriptor[key], str) or HEX64_RE.fullmatch(descriptor[key]) is None:
            raise HandshakeError(f"{key} is invalid")
    if len({descriptor[key] for key in ("arm_request_id", "move_request_id", "expire_request_id")}) != 3:
        raise HandshakeError("mutation request IDs must be distinct")
    return descriptor


def build_transport_descriptor(assignment: dict[str, Any]) -> dict[str, Any]:
    prefix = (
        f"handshake/v1/{assignment['controller_run_id']}/"
        f"{assignment['controller_run_attempt']}/{assignment['channel_id']}"
    )
    return {
        "version": 1,
        "controller_run_id": assignment["controller_run_id"],
        "controller_run_attempt": assignment["controller_run_attempt"],
        "client": assignment["client"],
        "proof_phase": assignment["proof_phase"],
        "channel_id": assignment["channel_id"],
        "correlation_id": assignment["correlation_id"],
        "agent_id": assignment["agent_id"],
        "bucket": assignment["bucket"],
        "kms_key_arn": assignment["kms_key_arn"],
        "checkpoint_key": f"{prefix}/transport-checkpoint.json",
        "receipt_key": f"{prefix}/transport-receipt.json",
        "proof_source_ip": PROOF_SOURCE_IP,
        "lifecycle_http_hosts": TRANSPORT_HTTP_HOSTS,
        "qurl_service_log_groups": QURL_SERVICE_LOG_GROUPS,
        "relay_log_group": RELAY_LOG_GROUP,
        "legacy_lifecycle_http_routes": LEGACY_LIFECYCLE_HTTP_ROUTES,
    }


def validate_transport_descriptor(
    value: Any, assignment: dict[str, Any]
) -> dict[str, Any]:
    expected = build_transport_descriptor(assignment)
    descriptor = _exact(value, set(expected), "transport descriptor")
    if descriptor != expected:
        raise HandshakeError("transport descriptor is not assignment-run-bound")
    return descriptor


def validate_mutation_response(
    value: Any,
    mutation: str,
    descriptor: dict[str, Any],
    checkpoint: dict[str, Any] | None = None,
    move: dict[str, Any] | None = None,
) -> dict[str, Any]:
    envelope = _exact(value, {"result", "version"}, f"{mutation} response")
    if envelope["version"] != 1 or not isinstance(envelope["result"], dict):
        raise HandshakeError(f"{mutation} response envelope is invalid")
    result = envelope["result"]
    common = {"agent_id", "mutated_at", "mutation"}
    if mutation == "arm":
        _exact(
            result,
            common
            | {
                "grant_correlation_id",
                "lease_seconds",
                "pinned_cell_id",
                "target_cell_id",
            },
            "arm result",
        )
        valid = (
            result["pinned_cell_id"] == descriptor["pinned_cell_id"]
            and result["target_cell_id"] == descriptor["target_cell_id"]
            and result["lease_seconds"] == descriptor["arm_lease_seconds"]
            and result["grant_correlation_id"] == descriptor["correlation_id"]
        )
    elif mutation == "move":
        _exact(
            result,
            common
            | {
                "lease_expires_at",
                "new_assignment_generation",
                "new_cell_id",
                "previous_assignment_generation",
                "previous_cell_id",
            },
            "move result",
        )
        if checkpoint is None:
            raise HandshakeError("move response requires checkpoint binding")
        valid = (
            result["previous_cell_id"] == descriptor["pinned_cell_id"]
            and result["new_cell_id"] == descriptor["target_cell_id"]
            and result["previous_assignment_generation"]
            == checkpoint["assignment_generation"]
            and result["new_assignment_generation"]
            == checkpoint["assignment_generation"] + 1
        )
    elif mutation == "expire_lease":
        _exact(result, common | {"lease_expires_at"}, "expire_lease result")
        valid = move is not None
    else:
        raise HandshakeError("unknown mutation response")
    if (
        result["mutation"] != mutation
        or result["agent_id"] != descriptor["agent_id"]
        or not isinstance(result["mutated_at"], str)
        or not valid
    ):
        raise HandshakeError(f"{mutation} response binding is invalid")
    mutated_at = _timestamp(result["mutated_at"], f"{mutation} mutated_at")
    if "lease_expires_at" in result:
        lease_expires_at = _timestamp(
            result["lease_expires_at"], f"{mutation} lease_expires_at"
        )
        expected_lifetime = (
            descriptor["arm_lease_seconds"]
            if mutation == "move"
            else descriptor["expire_lease_seconds"]
        )
        if lease_expires_at.timestamp() - mutated_at.timestamp() != expected_lifetime:
            raise HandshakeError(f"{mutation} lease transition is not exact")
        if mutation == "expire_lease":
            move_result = move["result"]
            move_mutated_at = _timestamp(
                move_result["mutated_at"], "move mutated_at"
            )
            move_expiry = _timestamp(
                move_result["lease_expires_at"], "move lease_expires_at"
            )
            if mutated_at < move_mutated_at or lease_expires_at >= move_expiry:
                raise HandshakeError(
                    "expire_lease does not shorten the exact moved assignment lease"
                )
    return envelope


def validate_checkpoint(
    value: Any,
    descriptor: dict[str, Any],
    *,
    client_run_id: str,
    client_sha: str,
) -> dict[str, Any]:
    checkpoint = _exact(
        value,
        {
            "agent_id",
            "assignment_generation",
            "channel_id",
            "client_run_id",
            "client_sha",
            "controller_run_attempt",
            "controller_run_id",
            "correlation_id",
            "lease_expires_at",
            "observed_cell_id",
            "version",
            "warm_open_confirmed",
        },
        "client checkpoint",
    )
    valid = (
        checkpoint["version"] == 1
        and checkpoint["client_run_id"] == client_run_id
        and checkpoint["client_sha"] == client_sha
        and RUN_RE.fullmatch(client_run_id) is not None
        and SHA_RE.fullmatch(client_sha) is not None
        and checkpoint["controller_run_id"] == descriptor["controller_run_id"]
        and checkpoint["controller_run_attempt"] == descriptor["controller_run_attempt"]
        and checkpoint["channel_id"] == descriptor["channel_id"]
        and checkpoint["correlation_id"] == descriptor["correlation_id"]
        and checkpoint["agent_id"] == descriptor["agent_id"]
        and checkpoint["observed_cell_id"] == descriptor["pinned_cell_id"]
        and type(checkpoint["assignment_generation"]) is int
        and checkpoint["assignment_generation"] >= 1
        and checkpoint["warm_open_confirmed"] is True
        and isinstance(checkpoint["lease_expires_at"], str)
    )
    if not valid:
        raise HandshakeError("client checkpoint does not bind this controller run")
    _timestamp(checkpoint["lease_expires_at"], "client checkpoint lease_expires_at")
    return checkpoint


def validate_transport_checkpoint(
    value: Any,
    descriptor: dict[str, Any],
    *,
    client_run_id: str,
    client_sha: str,
) -> dict[str, Any]:
    checkpoint = _exact(
        value,
        {
            "agent_id",
            "capture_ended_at",
            "capture_sha256",
            "capture_started_at",
            "capture_targets_sha256",
            "captured_packet_count",
            "channel_id",
            "client_run_id",
            "client_sha",
            "controller_run_attempt",
            "controller_run_id",
            "correlation_id",
            "http_trap_calls",
            "nhp_udp_lifecycle_success",
            "observed_cell_ids",
            "udp_62206_inbound",
            "udp_62206_outbound",
            "version",
        },
        "transport checkpoint",
    )
    valid = (
        checkpoint["version"] == 1
        and checkpoint["controller_run_id"] == descriptor["controller_run_id"]
        and checkpoint["controller_run_attempt"] == descriptor["controller_run_attempt"]
        and checkpoint["channel_id"] == descriptor["channel_id"]
        and checkpoint["client_run_id"] == client_run_id
        and checkpoint["client_sha"] == client_sha
        and checkpoint["correlation_id"] == descriptor["correlation_id"]
        and checkpoint["agent_id"] == descriptor["agent_id"]
        and isinstance(checkpoint["capture_sha256"], str)
        and HEX64_RE.fullmatch(checkpoint["capture_sha256"]) is not None
        and isinstance(checkpoint["capture_targets_sha256"], str)
        and HEX64_RE.fullmatch(checkpoint["capture_targets_sha256"]) is not None
        and type(checkpoint["captured_packet_count"]) is int
        and checkpoint["captured_packet_count"] >= 2
        and type(checkpoint["udp_62206_outbound"]) is int
        and checkpoint["udp_62206_outbound"] >= 1
        and type(checkpoint["udp_62206_inbound"]) is int
        and checkpoint["udp_62206_inbound"] >= 1
        and checkpoint["captured_packet_count"]
        == checkpoint["udp_62206_outbound"] + checkpoint["udp_62206_inbound"]
        and checkpoint["http_trap_calls"] == 0
        and checkpoint["observed_cell_ids"] == ["cell0", "cell1"]
        and checkpoint["nhp_udp_lifecycle_success"] is True
    )
    if not valid:
        raise HandshakeError("transport checkpoint does not prove the exact UDP run")
    started = _timestamp(checkpoint["capture_started_at"], "capture_started_at")
    ended = _timestamp(checkpoint["capture_ended_at"], "capture_ended_at")
    now = datetime.now(timezone.utc)
    if (
        ended < started
        or (ended - started).total_seconds() > 3600
        or (ended - now).total_seconds() > 30
        or (now - ended).total_seconds() > 300
    ):
        raise HandshakeError("transport capture interval is invalid")
    return checkpoint


def _run(command: list[str], name: str, *, timeout: int = 60) -> bytes:
    try:
        result = subprocess.run(
            command,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise HandshakeError(f"{name} failed to execute") from exc
    if result.returncode != 0:
        stderr = result.stderr.decode("utf-8", "replace")[:4096]
        raise HandshakeError(f"{name} failed: {stderr}")
    return result.stdout


def _invoke(alias: str, request: dict[str, Any]) -> dict[str, Any]:
    with tempfile.TemporaryDirectory() as directory:
        request_path = Path(directory, "request.json")
        response_path = Path(directory, "response.json")
        request_path.write_bytes(_canonical(request))
        metadata = _loads(
            _run(
                [
                    "aws",
                    "lambda",
                    "invoke",
                    "--region",
                    REGION,
                    "--function-name",
                    alias,
                    "--invocation-type",
                    "RequestResponse",
                    "--cli-binary-format",
                    "raw-in-base64-out",
                    "--payload",
                    f"fileb://{request_path}",
                    str(response_path),
                ],
                f"invoke {request['mutation']}",
            ),
            "Lambda invoke metadata",
        )
        if (
            not isinstance(metadata, dict)
            or metadata.get("StatusCode") != 200
            or "FunctionError" in metadata
        ):
            raise HandshakeError("Lambda invocation did not complete successfully")
        raw = response_path.read_bytes()
        if not raw or len(raw) > 64 * 1024:
            raise HandshakeError("Lambda response length is invalid")
        response = _loads(raw, "Lambda response")
        if isinstance(response, dict) and "error" in response:
            raise HandshakeError(f"mutation returned error: {response['error']}")
        return response


def _resolve_handshake_key_arn() -> str:
    response = _loads(
        _run(
            [
                "aws",
                "kms",
                "describe-key",
                "--region",
                REGION,
                "--key-id",
                KMS_ALIAS_ARN,
                "--output",
                "json",
            ],
            "resolve assignment proof KMS key",
        ),
        "KMS DescribeKey response",
    )
    if (
        not isinstance(response, dict)
        or set(response) != {"KeyMetadata"}
        or not isinstance(response["KeyMetadata"], dict)
        or not {"Arn", "Enabled", "KeyState"}.issubset(response["KeyMetadata"])
    ):
        raise HandshakeError("KMS DescribeKey response shape is invalid")
    metadata = response["KeyMetadata"]
    arn = metadata["Arn"]
    if (
        not isinstance(arn, str)
        or KMS_KEY_ARN_RE.fullmatch(arn) is None
        or metadata["Enabled"] is not True
        or metadata["KeyState"] != "Enabled"
    ):
        raise HandshakeError("assignment proof KMS key is not enabled or exact")
    return arn


def _put_object(descriptor: dict[str, Any], key: str, payload: bytes) -> None:
    with tempfile.NamedTemporaryFile() as stream:
        stream.write(payload)
        stream.flush()
        _run(
            [
                "aws",
                "s3api",
                "put-object",
                "--region",
                REGION,
                "--bucket",
                descriptor["bucket"],
                "--key",
                key,
                "--body",
                stream.name,
                "--content-type",
                "application/json",
                "--server-side-encryption",
                "aws:kms",
                "--ssekms-key-id",
                descriptor["kms_key_arn"],
                "--if-none-match",
                "*",
            ],
            "write assignment proof receipt",
        )


def _get_object(
    descriptor: dict[str, Any], key: str, *, timeout_seconds: int
) -> bytes:
    deadline = time.monotonic() + timeout_seconds
    with tempfile.TemporaryDirectory() as directory:
        destination = Path(directory, "checkpoint.json")
        while True:
            destination.unlink(missing_ok=True)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise HandshakeError("timed out waiting for client assignment checkpoint")
            try:
                result = subprocess.run(
                    [
                        "aws",
                        "s3api",
                        "get-object",
                        "--region",
                        REGION,
                        "--bucket",
                        descriptor["bucket"],
                        "--key",
                        key,
                        str(destination),
                    ],
                    check=False,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                    timeout=min(30, remaining),
                )
            except subprocess.TimeoutExpired:
                continue
            if result.returncode == 0:
                raw = destination.read_bytes()
                if not raw or len(raw) > 64 * 1024:
                    raise HandshakeError("assignment checkpoint length is invalid")
                return raw
            stderr = result.stderr.decode("utf-8", "replace")
            if "NoSuchKey" not in stderr and "404" not in stderr:
                raise HandshakeError(f"read assignment checkpoint failed: {stderr[:4096]}")
            if time.monotonic() >= deadline:
                raise HandshakeError("timed out waiting for client assignment checkpoint")
            time.sleep(5)


def _filter_log_events(
    log_group: str,
    *,
    start_millis: int,
    end_millis: int,
    filter_pattern: str,
) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    seen_event_ids: set[str] = set()
    token = ""
    seen_tokens: set[str] = set()
    for _ in range(100):
        command = [
            "aws",
            "logs",
            "filter-log-events",
            "--region",
            REGION,
            "--log-group-name",
            log_group,
            "--start-time",
            str(start_millis),
            "--end-time",
            str(end_millis),
            "--filter-pattern",
            filter_pattern,
            "--limit",
            "10000",
            "--no-paginate",
            "--output",
            "json",
        ]
        if token:
            command.extend(["--next-token", token])
        page = _loads(_run(command, f"read {log_group}", timeout=90), log_group)
        if not isinstance(page, dict) or not set(page).issubset(
            {"events", "nextToken", "searchedLogStreams"}
        ):
            raise HandshakeError(f"{log_group} returned malformed log results")
        page_events = page.get("events")
        if not isinstance(page_events, list):
            raise HandshakeError(f"{log_group} omitted log events")
        for event in page_events:
            event = _exact(
                event,
                {
                    "eventId",
                    "ingestionTime",
                    "logStreamName",
                    "message",
                    "timestamp",
                },
                f"{log_group} event",
            )
            event_id = event["eventId"]
            if (
                not isinstance(event_id, str)
                or not event_id
                or event_id in seen_event_ids
                or type(event["timestamp"]) is not int
                or not start_millis <= event["timestamp"] <= end_millis
                or type(event["ingestionTime"]) is not int
                or not isinstance(event["logStreamName"], str)
                or not event["logStreamName"]
                or not isinstance(event["message"], str)
            ):
                raise HandshakeError(f"{log_group} event is malformed or duplicated")
            seen_event_ids.add(event_id)
            events.append(event)
        next_token = page.get("nextToken", "")
        if next_token == token or next_token == "":
            return events
        if (
            not isinstance(next_token, str)
            or not next_token
            or next_token in seen_tokens
            or len(next_token) > 8192
        ):
            raise HandshakeError(f"{log_group} pagination token is invalid")
        seen_tokens.add(next_token)
        token = next_token
    raise HandshakeError(f"{log_group} pagination exceeded its bound")


def _count_qurl_service_legacy_routes(
    descriptor: dict[str, Any],
    *,
    start_millis: int,
    end_millis: int,
) -> int:
    routes = {
        (item["method"], item["path"])
        for item in descriptor["legacy_lifecycle_http_routes"]
    }
    count = 0
    filter_pattern = (
        '{ $.msg = "http request" && $.client_ip = "'
        + descriptor["proof_source_ip"]
        + '" }'
    )
    for log_group in descriptor["qurl_service_log_groups"]:
        for event in _filter_log_events(
            log_group,
            start_millis=start_millis,
            end_millis=end_millis,
            filter_pattern=filter_pattern,
        ):
            message = _loads(event["message"], f"{log_group} http request")
            if not isinstance(message, dict):
                raise HandshakeError("qurl-service HTTP request log is not an object")
            method = message.get("method")
            path = message.get("path")
            if (
                message.get("msg") != "http request"
                or message.get("client_ip") != descriptor["proof_source_ip"]
                or not isinstance(method, str)
                or not isinstance(path, str)
            ):
                raise HandshakeError("qurl-service HTTP request log binding is malformed")
            if (method, path.partition("?")[0]) in routes:
                count += 1
    return count


def _count_relay_routes(
    descriptor: dict[str, Any],
    *,
    start_millis: int,
    end_millis: int,
) -> int:
    events = _filter_log_events(
        descriptor["relay_log_group"],
        start_millis=start_millis,
        end_millis=end_millis,
        filter_pattern=(
            '"relay: proof request" "route=relay" "source_ip='
            + descriptor["proof_source_ip"]
            + '"'
        ),
    )
    pattern = re.compile(
        r"(?:^|\s)relay: proof request route=relay source_ip="
        + re.escape(descriptor["proof_source_ip"])
        + r"(?:\s|$)"
    )
    for event in events:
        if pattern.search(event["message"]) is None:
            raise HandshakeError("relay proof request log binding is malformed")
    return len(events)


def _observe_transport_counters(
    descriptor: dict[str, Any], checkpoint: dict[str, Any]
) -> tuple[int, int, str]:
    ended = _timestamp(checkpoint["capture_ended_at"], "capture_ended_at")
    deadline = ended.timestamp() + COUNTER_INGESTION_WAIT_SECONDS
    remaining = deadline - time.time()
    if remaining > 0:
        time.sleep(remaining)
    started = _timestamp(checkpoint["capture_started_at"], "capture_started_at")
    start_millis = int(started.timestamp() * 1000)
    end_millis = int(ended.timestamp() * 1000) + 999
    qurl_count = _count_qurl_service_legacy_routes(
        descriptor,
        start_millis=start_millis,
        end_millis=end_millis,
    )
    relay_count = _count_relay_routes(
        descriptor,
        start_millis=start_millis,
        end_millis=end_millis,
    )
    observed_at = datetime.now(timezone.utc).replace(microsecond=0).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    return qurl_count, relay_count, observed_at


def _write_output(path: Path, values: dict[str, str]) -> None:
    with path.open("a", encoding="utf-8") as stream:
        for key, value in values.items():
            if "\n" in value or "\r" in value:
                raise HandshakeError(f"output {key} contains a newline")
            stream.write(f"{key}={value}\n")


def _write_once(path: Path, raw: bytes) -> None:
    if not path.is_absolute() or path != path.resolve(strict=False):
        raise HandshakeError("receipt output must be one canonical absolute path")
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
        raise HandshakeError("could not publish immutable proof receipt") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def prepare(args: argparse.Namespace) -> None:
    if RUN_RE.fullmatch(args.controller_run_id) is None or RUN_RE.fullmatch(
        args.controller_run_attempt
    ) is None:
        raise HandshakeError("controller run binding is invalid")
    if args.proof_phase not in PHASES:
        raise HandshakeError("proof phase is invalid")
    provenance = _loads(
        _decode_b64(args.deployment_provenance_b64, "provenance"), "provenance"
    )
    channel = secrets.token_hex(16)
    prefix = (
        f"handshake/v1/{args.controller_run_id}/"
        f"{args.controller_run_attempt}/{channel}"
    )
    descriptor = validate_descriptor(
        {
            "version": 1,
            "controller_run_id": args.controller_run_id,
            "controller_run_attempt": args.controller_run_attempt,
            "client": "qurl_go",
            "proof_phase": args.proof_phase,
            "channel_id": channel,
            "correlation_id": (
                f"nhp-{args.controller_run_id}-{args.controller_run_attempt}-"
                f"qurl_go-{args.proof_phase}-{channel}"
            ),
            "agent_id": (
                f"qurl-go-sandbox-{args.controller_run_id}-"
                f"{args.controller_run_attempt}"
            ),
            "bucket": BUCKET,
            "kms_key_arn": _resolve_handshake_key_arn(),
            "checkpoint_key": f"{prefix}/checkpoint.json",
            "receipt_key": f"{prefix}/receipt.json",
            "ca_pm_alias_arn": select_ca_pm_alias(provenance),
            "pinned_cell_id": "cell0",
            "target_cell_id": "cell1",
            "arm_lease_seconds": ARM_LEASE_SECONDS,
            "expire_lease_seconds": EXPIRE_LEASE_SECONDS,
            "arm_request_id": secrets.token_hex(32),
            "move_request_id": secrets.token_hex(32),
            "expire_request_id": secrets.token_hex(32),
        }
    )
    arm = validate_mutation_response(
        _invoke(
            descriptor["ca_pm_alias_arn"],
            {
                "version": 1,
                "hub_request_id": descriptor["arm_request_id"],
                "mutation": "arm",
                "agent_id": descriptor["agent_id"],
                "grant_correlation_id": descriptor["correlation_id"],
                "pinned_cell_id": descriptor["pinned_cell_id"],
                "target_cell_id": descriptor["target_cell_id"],
                "lease_seconds": descriptor["arm_lease_seconds"],
            },
        ),
        "arm",
        descriptor,
    )
    transport = validate_transport_descriptor(
        build_transport_descriptor(descriptor), descriptor
    )
    payload = {"descriptor": descriptor, "arm": arm, "transport": transport}
    encoded = base64.b64encode(_canonical(payload)).decode()
    _write_output(
        args.github_output,
        {
            "agent_id": descriptor["agent_id"],
            "correlation_id": descriptor["correlation_id"],
            "handshake_b64": encoded,
        },
    )


def complete(args: argparse.Namespace) -> None:
    payload = _exact(
        _loads(_decode_b64(args.handshake_b64, "handshake"), "handshake"),
        {"arm", "descriptor", "transport"},
        "handshake",
    )
    descriptor = validate_descriptor(payload["descriptor"])
    transport = validate_transport_descriptor(payload["transport"], descriptor)
    validate_mutation_response(payload["arm"], "arm", descriptor)
    if (
        RUN_RE.fullmatch(args.client_run_id) is None
        or SHA_RE.fullmatch(args.client_sha) is None
    ):
        raise HandshakeError("resolved client workflow run/SHA binding is invalid")
    assignment_output = getattr(args, "assignment_receipt_output", None)
    transport_output = getattr(args, "transport_receipt_output", None)
    if (assignment_output is None) != (transport_output is None):
        raise HandshakeError("both normalized receipt outputs must be supplied together")
    checkpoint_raw = _get_object(
        descriptor, descriptor["checkpoint_key"], timeout_seconds=args.timeout_seconds
    )
    checkpoint = validate_checkpoint(
        _loads(checkpoint_raw, "client checkpoint"),
        descriptor,
        client_run_id=args.client_run_id,
        client_sha=args.client_sha,
    )
    move = validate_mutation_response(
        _invoke(
            descriptor["ca_pm_alias_arn"],
            {
                "version": 1,
                "hub_request_id": descriptor["move_request_id"],
                "mutation": "move",
                "agent_id": descriptor["agent_id"],
                "grant_correlation_id": descriptor["correlation_id"],
                "target_cell_id": descriptor["target_cell_id"],
            },
        ),
        "move",
        descriptor,
        checkpoint,
    )
    expire = validate_mutation_response(
        _invoke(
            descriptor["ca_pm_alias_arn"],
            {
                "version": 1,
                "hub_request_id": descriptor["expire_request_id"],
                "mutation": "expire_lease",
                "agent_id": descriptor["agent_id"],
                "grant_correlation_id": descriptor["correlation_id"],
                "lease_seconds": descriptor["expire_lease_seconds"],
            },
        ),
        "expire_lease",
        descriptor,
        move=move,
    )
    receipt = {
        "version": 1,
        "descriptor": descriptor,
        "arm": payload["arm"],
        "client_run_id": args.client_run_id,
        "client_sha": args.client_sha,
        "checkpoint_sha256": hashlib.sha256(checkpoint_raw).hexdigest(),
        "move": move,
        "expire_lease": expire,
    }
    receipt_raw = _canonical(receipt)
    _put_object(descriptor, descriptor["receipt_key"], receipt_raw)
    transport_checkpoint_raw = _get_object(
        transport,
        transport["checkpoint_key"],
        timeout_seconds=args.timeout_seconds,
    )
    transport_checkpoint = validate_transport_checkpoint(
        _loads(transport_checkpoint_raw, "transport checkpoint"),
        transport,
        client_run_id=args.client_run_id,
        client_sha=args.client_sha,
    )
    qurl_count, relay_count, observed_at = _observe_transport_counters(
        transport, transport_checkpoint
    )
    if qurl_count != 0 or relay_count != 0:
        raise HandshakeError(
            "exact qurl-go lifecycle touched a legacy HTTP or relay route"
        )
    transport_receipt = {
        "version": 1,
        "descriptor": transport,
        "client_run_id": args.client_run_id,
        "client_sha": args.client_sha,
        "checkpoint_sha256": hashlib.sha256(
            transport_checkpoint_raw
        ).hexdigest(),
        "capture_sha256": transport_checkpoint["capture_sha256"],
        "capture_targets_sha256": transport_checkpoint[
            "capture_targets_sha256"
        ],
        "capture_started_at": transport_checkpoint["capture_started_at"],
        "capture_ended_at": transport_checkpoint["capture_ended_at"],
        "nhp_udp_lifecycle_success": True,
        "qurl_service_legacy_route_count": qurl_count,
        "relay_route_count": relay_count,
        "counters_observed_at": observed_at,
    }
    transport_receipt_raw = _canonical(transport_receipt)
    _put_object(
        transport,
        transport["receipt_key"],
        transport_receipt_raw,
    )
    if assignment_output is not None:
        normalized_assignment = {
            "agent_id_sha256": hashlib.sha256(
                descriptor["agent_id"].encode("utf-8")
            ).hexdigest(),
            "assigned_cells": [
                descriptor["pinned_cell_id"],
                descriptor["target_cell_id"],
            ],
            "checkpoint_sha256": hashlib.sha256(checkpoint_raw).hexdigest(),
            "client_run_id": int(args.client_run_id),
            "client_sha": args.client_sha,
            "correlation_id_sha256": hashlib.sha256(
                descriptor["correlation_id"].encode("utf-8")
            ).hexdigest(),
            "receipt_sha256": hashlib.sha256(receipt_raw).hexdigest(),
        }
        normalized_transport = {
            "capture_ended_at": transport_checkpoint["capture_ended_at"],
            "capture_sha256": transport_checkpoint["capture_sha256"],
            "capture_started_at": transport_checkpoint["capture_started_at"],
            "capture_targets_sha256": transport_checkpoint[
                "capture_targets_sha256"
            ],
            "client_run_id": int(args.client_run_id),
            "client_sha": args.client_sha,
            "nhp_udp_lifecycle_success": True,
            "qurl_service_legacy_route_count": qurl_count,
            "receipt_sha256": hashlib.sha256(transport_receipt_raw).hexdigest(),
            "relay_route_count": relay_count,
        }
        _write_once(assignment_output, _canonical(normalized_assignment))
        _write_once(transport_output, _canonical(normalized_transport))


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser()
    subparsers = root.add_subparsers(dest="command", required=True)
    start = subparsers.add_parser("prepare")
    start.add_argument("--controller-run-id", required=True)
    start.add_argument("--controller-run-attempt", required=True)
    start.add_argument("--proof-phase", required=True)
    start.add_argument("--deployment-provenance-b64", required=True)
    start.add_argument("--github-output", required=True, type=Path)
    start.set_defaults(func=prepare)
    finish = subparsers.add_parser("complete")
    finish.add_argument("--handshake-b64", required=True)
    finish.add_argument("--client-run-id", required=True)
    finish.add_argument("--client-sha", required=True)
    finish.add_argument("--assignment-receipt-output", type=Path)
    finish.add_argument("--transport-receipt-output", type=Path)
    finish.add_argument("--timeout-seconds", type=int, default=3600, choices=range(30, 5401))
    finish.set_defaults(func=complete)
    return root


def main(argv: list[str] | None = None) -> int:
    try:
        args = parser().parse_args(argv)
        args.func(args)
        return 0
    except (HandshakeError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
