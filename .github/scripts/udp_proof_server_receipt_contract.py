#!/usr/bin/env python3
"""Strict controller receipt for post-probe HTTP and relay server observations."""

from __future__ import annotations

import ipaddress
from typing import Any

import udp_proof_deployment_contract as deployment
import udp_proof_runtime_probe_contract as runtime_probe


SCHEMA_VERSION = 1
GATE = "udp_lifecycle_retirement"
ARTIFACT_FILE_NAME = "post-probe-server-receipt.json"
MAX_ARTIFACT_BYTES = 128 * 1024


class ReceiptError(deployment.ContractError):
    """The server-side receipt is incomplete or is not bound to the client probe."""


def _exact(value: Any, keys: set[str], name: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise ReceiptError(f"{name} must contain exactly {sorted(keys)}")
    return value


def _sha256(value: Any, name: str) -> str:
    if not isinstance(value, str) or deployment.SHA256_RE.fullmatch(value) is None:
        raise ReceiptError(f"{name} must be a lowercase SHA-256")
    return value


def _event(
    value: Any,
    *,
    name: str,
    start_millis: int,
    end_millis: int,
) -> dict[str, Any]:
    event = _exact(
        value,
        {
            "event_id_sha256",
            "event_timestamp_millis",
            "ingestion_timestamp_millis",
            "log_group",
            "log_stream_sha256",
        },
        name,
    )
    _sha256(event["event_id_sha256"], f"{name} event_id_sha256")
    _sha256(event["log_stream_sha256"], f"{name} log_stream_sha256")
    for key in ("event_timestamp_millis", "ingestion_timestamp_millis"):
        if type(event[key]) is not int or event[key] < 0:
            raise ReceiptError(f"{name} {key} must be a non-negative integer")
    if not start_millis <= event["event_timestamp_millis"] <= end_millis:
        raise ReceiptError(f"{name} is outside the precise client probe window")
    if event["ingestion_timestamp_millis"] < event["event_timestamp_millis"]:
        raise ReceiptError(f"{name} ingestion predates the server event")
    if not isinstance(event["log_group"], str) or not event["log_group"]:
        raise ReceiptError(f"{name} log_group is invalid")
    return event


def _window_millis(probe: dict[str, Any]) -> tuple[int, int]:
    started = runtime_probe._probe_timestamp(
        probe["probe_started_at"], "server receipt probe_started_at"
    )
    ended = runtime_probe._probe_timestamp(
        probe["probe_ended_at"], "server receipt probe_ended_at"
    )
    return int(started.timestamp() * 1000), int(ended.timestamp() * 1000)


def canonical_bytes(value: Any) -> bytes:
    return deployment.canonical_bytes(
        value,
        maximum=MAX_ARTIFACT_BYTES,
        name=ARTIFACT_FILE_NAME,
    )


def validate(
    value: Any,
    *,
    runtime_probe_document: dict[str, Any],
    proof_source_ip: str,
    qurl_service_log_groups: list[str],
    relay_log_group: str,
) -> dict[str, Any]:
    """Validate exact log observations against an already-authenticated probe."""

    try:
        ipaddress.ip_address(proof_source_ip)
    except ValueError as exc:
        raise ReceiptError("proof source IP is invalid") from exc
    if (
        not isinstance(qurl_service_log_groups, list)
        or len(qurl_service_log_groups) != 2
        or len(set(qurl_service_log_groups)) != 2
        or any(not isinstance(item, str) or not item for item in qurl_service_log_groups)
        or not isinstance(relay_log_group, str)
        or not relay_log_group
    ):
        raise ReceiptError("server receipt log-group binding is invalid")

    receipt = _exact(
        value,
        {
            "client_binding",
            "gate",
            "http",
            "observed_at",
            "phase",
            "probe_window",
            "proof_source_ip",
            "relay",
            "retirement_probe_targets_sha256",
            "schema_version",
        },
        "post-probe server receipt",
    )
    if (
        receipt["schema_version"] != SCHEMA_VERSION
        or type(receipt["schema_version"]) is not int
        or receipt["gate"] != GATE
        or receipt["phase"] != runtime_probe_document["phase"]
        or receipt["client_binding"] != runtime_probe_document["client_binding"]
        or receipt["proof_source_ip"] != proof_source_ip
        or receipt["retirement_probe_targets_sha256"]
        != runtime_probe_document["retirement_probe_targets_sha256"]
    ):
        raise ReceiptError("post-probe server receipt binding drift")
    try:
        observed_at = deployment._timestamp(
            receipt["observed_at"], "server receipt observed_at"
        )
        ended = runtime_probe._probe_timestamp(
            runtime_probe_document["probe_ended_at"],
            "server receipt probe_ended_at",
        )
    except deployment.ContractError as exc:
        raise ReceiptError(str(exc)) from exc
    if observed_at < ended:
        raise ReceiptError("server receipt predates the client probe")
    probe_window = _exact(
        receipt["probe_window"],
        {"ended_at", "started_at"},
        "server receipt probe_window",
    )
    if probe_window != {
        "started_at": runtime_probe_document["probe_started_at"],
        "ended_at": runtime_probe_document["probe_ended_at"],
    }:
        raise ReceiptError("server receipt probe window differs from client evidence")
    start_millis, end_millis = _window_millis(runtime_probe_document)

    http = _exact(
        receipt["http"],
        {
            "legacy_handler_dispatch_count",
            "log_groups",
            "observations",
        },
        "server receipt HTTP",
    )
    if (
        http["legacy_handler_dispatch_count"] != 0
        or type(http["legacy_handler_dispatch_count"]) is not int
        or http["log_groups"] != qurl_service_log_groups
    ):
        raise ReceiptError("server receipt HTTP authority binding drift")
    expected_http = {
        (
            item["correlation_id_sha256"],
            item["method"],
            item["path"],
            item["status"],
        )
        for item in runtime_probe_document["observations"]["http_lifecycle"]["probes"]
    }
    http_rows = http["observations"]
    if not isinstance(http_rows, list) or len(http_rows) != len(expected_http):
        raise ReceiptError("server receipt HTTP observation count drift")
    observed_http: set[tuple[str, str, str, int]] = set()
    event_ids: set[str] = set()
    observed_handler_dispatch_count = 0
    for index, raw in enumerate(http_rows):
        row = _exact(
            raw,
            {
                "correlation_id_sha256",
                "event",
                "handler_dispatched",
                "method",
                "path",
                "source_ip",
                "status",
            },
            f"server receipt HTTP observation {index}",
        )
        _sha256(
            row["correlation_id_sha256"],
            f"server receipt HTTP observation {index} correlation",
        )
        identity = (
            row["correlation_id_sha256"],
            row["method"],
            row["path"],
            row["status"],
        )
        event = _event(
            row["event"],
            name=f"server receipt HTTP observation {index} event",
            start_millis=start_millis,
            end_millis=end_millis,
        )
        if (
            identity not in expected_http
            or identity in observed_http
            or row["handler_dispatched"] is not False
            or row["source_ip"] != proof_source_ip
            or event["log_group"] not in qurl_service_log_groups
            or event["event_id_sha256"] in event_ids
        ):
            raise ReceiptError(f"server receipt HTTP observation {index} drift")
        observed_handler_dispatch_count += int(row["handler_dispatched"])
        observed_http.add(identity)
        event_ids.add(event["event_id_sha256"])
    if (
        observed_http != expected_http
        or http["legacy_handler_dispatch_count"]
        != observed_handler_dispatch_count
    ):
        raise ReceiptError("server receipt HTTP observation set is incomplete")

    relay = _exact(
        receipt["relay"],
        {
            "forward_count",
            "log_group",
            "observations",
            "server_dispatch_count",
            "waiter_created_count",
        },
        "server receipt relay",
    )
    if (
        relay["log_group"] != relay_log_group
        or relay["waiter_created_count"] != 0
        or relay["forward_count"] != 0
        or relay["server_dispatch_count"] != 0
        or any(
            type(relay[key]) is not int
            for key in (
                "waiter_created_count",
                "forward_count",
                "server_dispatch_count",
            )
        )
    ):
        raise ReceiptError("server receipt relay dispatch binding drift")
    expected_relay = {
        (
            item["cell_id"],
            item["server_id"],
            item["message_type"],
            item["correlation_id_sha256"],
        )
        for item in runtime_probe_document["observations"]["relay_lifecycle"]["probes"]
    }
    relay_rows = relay["observations"]
    if not isinstance(relay_rows, list) or len(relay_rows) != len(expected_relay):
        raise ReceiptError("server receipt relay observation count drift")
    observed_relay: set[tuple[str, str, str, str]] = set()
    observed_forward_count = 0
    observed_server_dispatch_count = 0
    observed_waiter_count = 0
    for index, raw in enumerate(relay_rows):
        row = _exact(
            raw,
            {
                "before_forward",
                "before_server_dispatch",
                "before_waiter",
                "cell_id",
                "correlation_id_sha256",
                "event",
                "message_type",
                "outcome",
                "server_id",
                "source_ip",
            },
            f"server receipt relay observation {index}",
        )
        _sha256(
            row["correlation_id_sha256"],
            f"server receipt relay observation {index} correlation",
        )
        identity = (
            row["cell_id"],
            row["server_id"],
            row["message_type"],
            row["correlation_id_sha256"],
        )
        event = _event(
            row["event"],
            name=f"server receipt relay observation {index} event",
            start_millis=start_millis,
            end_millis=end_millis,
        )
        if (
            identity not in expected_relay
            or identity in observed_relay
            or row["before_waiter"] is not True
            or row["before_forward"] is not True
            or row["before_server_dispatch"] is not True
            or row["source_ip"] != proof_source_ip
            or row["outcome"] != "unsupported_type_rejected"
            or event["log_group"] != relay_log_group
            or event["event_id_sha256"] in event_ids
        ):
            raise ReceiptError(f"server receipt relay observation {index} drift")
        observed_forward_count += int(not row["before_forward"])
        observed_server_dispatch_count += int(not row["before_server_dispatch"])
        observed_waiter_count += int(not row["before_waiter"])
        observed_relay.add(identity)
        event_ids.add(event["event_id_sha256"])
    if (
        observed_relay != expected_relay
        or relay["forward_count"] != observed_forward_count
        or relay["server_dispatch_count"] != observed_server_dispatch_count
        or relay["waiter_created_count"] != observed_waiter_count
    ):
        raise ReceiptError("server receipt relay observation set is incomplete")
    return receipt


def validate_bytes(raw: bytes, **kwargs: Any) -> dict[str, Any]:
    try:
        value = deployment.parse_canonical_bytes(
            raw,
            maximum=MAX_ARTIFACT_BYTES,
            name=ARTIFACT_FILE_NAME,
        )
    except deployment.ContractError as exc:
        raise ReceiptError(str(exc)) from exc
    return validate(value, **kwargs)
