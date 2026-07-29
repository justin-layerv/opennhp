#!/usr/bin/env python3
"""Collect correlation-bound server observations after the qurl-go runtime probes."""

from __future__ import annotations

import argparse
import base64
import hashlib
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import udp_proof_assignment_handshake as handshake
import udp_proof_deployment_contract as deployment
import udp_proof_retirement_targets_contract as retirement_targets
import udp_proof_runtime_probe_contract as runtime_probe
import udp_proof_server_receipt_contract as receipt_contract


INGESTION_WAIT_SECONDS = 120
HTTP_LOG_MESSAGE = "udp retirement proof HTTP observation"
RELAY_LOG_RE = re.compile(
    r"^relay: proof rejection route=relay "
    r"source_ip=(?P<source_ip>[0-9a-fA-F:.]+) "
    r"cell_id=(?P<cell_id>cell[0-9]+) "
    r"server_id=(?P<server_id>[A-Za-z0-9_-]{11}) "
    r"message_type=(?P<message_type>NHP_LRT|NHP_LST|NHP_OTP|NHP_REG) "
    r"correlation_id_sha256=(?P<correlation_id_sha256>[0-9a-f]{64}) "
    r"outcome=unsupported_type_rejected "
    r"before_waiter=(?P<before_waiter>true|false) "
    r"before_forward=(?P<before_forward>true|false) "
    r"before_server_dispatch=(?P<before_server_dispatch>true|false)$"
)


class CollectionError(RuntimeError):
    """The live server logs do not prove the exact client probes."""


def _canonical_event(event: dict[str, Any], log_group: str) -> dict[str, Any]:
    return {
        "event_id_sha256": hashlib.sha256(event["eventId"].encode()).hexdigest(),
        "event_timestamp_millis": event["timestamp"],
        "ingestion_timestamp_millis": event["ingestionTime"],
        "log_group": log_group,
        "log_stream_sha256": hashlib.sha256(
            event["logStreamName"].encode()
        ).hexdigest(),
    }


def _http_observations(
    descriptor: dict[str, Any],
    *,
    start_millis: int,
    end_millis: int,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    filter_pattern = (
        '{ $.msg = "'
        + HTTP_LOG_MESSAGE
        + '" && $.source_ip = "'
        + descriptor["proof_source_ip"]
        + '" }'
    )
    for log_group in descriptor["qurl_service_log_groups"]:
        events = handshake._filter_log_events(
            log_group,
            start_millis=start_millis,
            end_millis=end_millis,
            filter_pattern=filter_pattern,
        )
        for event in events:
            message = handshake._loads(
                event["message"], f"{log_group} HTTP proof observation"
            )
            if not isinstance(message, dict):
                raise CollectionError("qurl-service proof observation is not JSON")
            required = {
                "correlation_id_sha256",
                "handler_dispatched",
                "method",
                "path",
                "source_ip",
                "status",
            }
            if (
                message.get("msg") != HTTP_LOG_MESSAGE
                or any(key not in message for key in required)
                or not isinstance(message["correlation_id_sha256"], str)
                or deployment.SHA256_RE.fullmatch(
                    message["correlation_id_sha256"]
                )
                is None
                or type(message["handler_dispatched"]) is not bool
                or not isinstance(message["method"], str)
                or not isinstance(message["path"], str)
                or message["source_ip"] != descriptor["proof_source_ip"]
                or type(message["status"]) is not int
            ):
                raise CollectionError("qurl-service proof observation is malformed")
            rows.append(
                {
                    "correlation_id_sha256": message["correlation_id_sha256"],
                    "event": _canonical_event(event, log_group),
                    "handler_dispatched": message["handler_dispatched"],
                    "method": message["method"],
                    "path": message["path"],
                    "source_ip": message["source_ip"],
                    "status": message["status"],
                }
            )
    return sorted(
        rows,
        key=lambda row: (
            row["method"],
            row["path"],
            row["correlation_id_sha256"],
        ),
    )


def _relay_observations(
    descriptor: dict[str, Any],
    *,
    start_millis: int,
    end_millis: int,
) -> list[dict[str, Any]]:
    log_group = descriptor["relay_log_group"]
    events = handshake._filter_log_events(
        log_group,
        start_millis=start_millis,
        end_millis=end_millis,
        filter_pattern=(
            '"relay: proof rejection" "route=relay" "source_ip='
            + descriptor["proof_source_ip"]
            + '"'
        ),
    )
    rows: list[dict[str, Any]] = []
    for event in events:
        message = event["message"]
        if message.endswith("\n"):
            message = message[:-1]
        matched = RELAY_LOG_RE.fullmatch(message)
        if matched is None or matched.group("source_ip") != descriptor["proof_source_ip"]:
            raise CollectionError("relay proof rejection observation is malformed")
        values = matched.groupdict()
        rows.append(
            {
                "before_forward": values["before_forward"] == "true",
                "before_server_dispatch": (
                    values["before_server_dispatch"] == "true"
                ),
                "before_waiter": values["before_waiter"] == "true",
                "cell_id": values["cell_id"],
                "correlation_id_sha256": values["correlation_id_sha256"],
                "event": _canonical_event(event, log_group),
                "message_type": values["message_type"],
                "outcome": "unsupported_type_rejected",
                "server_id": values["server_id"],
                "source_ip": values["source_ip"],
            }
        )
    return sorted(
        rows,
        key=lambda row: (
            row["cell_id"],
            row["server_id"],
            row["message_type"],
            row["correlation_id_sha256"],
        ),
    )


def collect(args: argparse.Namespace) -> dict[str, Any]:
    try:
        payload = handshake._exact(
            handshake._loads(
                handshake._decode_b64(args.handshake_b64, "handshake"),
                "handshake",
            ),
            {"arm", "descriptor", "transport"},
            "handshake",
        )
        assignment = handshake.validate_descriptor(payload["descriptor"])
        descriptor = handshake.validate_transport_descriptor(
            payload["transport"], assignment
        )
        targets_raw = base64.b64decode(
            args.retirement_probe_targets_b64, validate=True
        )
        if hashlib.sha256(targets_raw).hexdigest() != args.targets_sha256:
            raise CollectionError("retirement probe target digest drift")
        targets = deployment.parse_canonical_bytes(
            targets_raw,
            maximum=retirement_targets.MAX_ARTIFACT_BYTES,
            name=retirement_targets.ARTIFACT_FILE_NAME,
        )
        probe_raw = args.runtime_probe.read_bytes()
        probe_value = deployment.parse_canonical_bytes(
            probe_raw,
            maximum=runtime_probe.MAX_ARTIFACT_BYTES,
            name=runtime_probe.ARTIFACT_FILE_NAME,
        )
        client_binding = probe_value.get("client_binding", {})
        if not isinstance(client_binding, dict):
            raise CollectionError("runtime probe client binding is invalid")
        expected_binding = {
            "controller_run_attempt": assignment["controller_run_attempt"],
            "controller_run_id": assignment["controller_run_id"],
            "dispatch_correlation_id": assignment["correlation_id"],
            "head_sha": args.client_sha,
            "repository": runtime_probe.CLIENT_REPOSITORY,
            "run_attempt": args.client_run_attempt,
            "run_id": args.client_run_id,
            "workflow_path": runtime_probe.CLIENT_WORKFLOW,
        }
        probe = runtime_probe.validate(
            probe_value,
            proof_phase=assignment["proof_phase"],
            expected_binding=expected_binding,
            expected_retirement_probe_targets_sha256=args.targets_sha256,
            expected_http_operations=targets["http_operations"],
            expected_relay_aliases=targets["relay"]["aliases"],
        )
    except (
        ValueError,
        OSError,
        deployment.ContractError,
        handshake.HandshakeError,
    ) as exc:
        raise CollectionError(str(exc)) from exc

    probe_started = runtime_probe._probe_timestamp(
        probe["probe_started_at"], "server receipt probe_started_at"
    )
    probe_ended = runtime_probe._probe_timestamp(
        probe["probe_ended_at"], "server receipt probe_ended_at"
    )
    remaining = probe_ended.timestamp() + INGESTION_WAIT_SECONDS - time.time()
    if remaining > 0:
        time.sleep(remaining)
    start_millis = int(probe_started.timestamp() * 1000)
    # CloudWatch log events are millisecond-resolution. Include the entire
    # ending millisecond, then let the receipt validator reject out-of-window
    # event timestamps.
    end_millis = int(probe_ended.timestamp() * 1000)
    http = _http_observations(
        descriptor,
        start_millis=start_millis,
        end_millis=end_millis,
    )
    relay = _relay_observations(
        descriptor,
        start_millis=start_millis,
        end_millis=end_millis,
    )
    document = {
        "client_binding": probe["client_binding"],
        "gate": receipt_contract.GATE,
        "http": {
            "legacy_handler_dispatch_count": sum(
                1 for row in http if row["handler_dispatched"]
            ),
            "log_groups": descriptor["qurl_service_log_groups"],
            "observations": http,
        },
        "observed_at": datetime.now(timezone.utc)
        .replace(microsecond=0)
        .strftime("%Y-%m-%dT%H:%M:%SZ"),
        "phase": probe["phase"],
        "probe_window": {
            "ended_at": probe["probe_ended_at"],
            "started_at": probe["probe_started_at"],
        },
        "proof_source_ip": descriptor["proof_source_ip"],
        "relay": {
            "forward_count": sum(1 for row in relay if not row["before_forward"]),
            "log_group": descriptor["relay_log_group"],
            "observations": relay,
            "server_dispatch_count": sum(
                1 for row in relay if not row["before_server_dispatch"]
            ),
            "waiter_created_count": sum(
                1 for row in relay if not row["before_waiter"]
            ),
        },
        "retirement_probe_targets_sha256": args.targets_sha256,
        "schema_version": receipt_contract.SCHEMA_VERSION,
    }
    receipt_contract.validate(
        document,
        runtime_probe_document=probe,
        proof_source_ip=descriptor["proof_source_ip"],
        qurl_service_log_groups=descriptor["qurl_service_log_groups"],
        relay_log_group=descriptor["relay_log_group"],
    )
    return document


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    result.add_argument("--handshake-b64", required=True)
    result.add_argument("--retirement-probe-targets-b64", required=True)
    result.add_argument("--targets-sha256", required=True)
    result.add_argument("--runtime-probe", type=Path, required=True)
    result.add_argument("--client-run-id", required=True)
    result.add_argument("--client-run-attempt", required=True)
    result.add_argument("--client-sha", required=True)
    result.add_argument("--output", type=Path, required=True)
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        document = collect(args)
        raw = receipt_contract.canonical_bytes(document)
        args.output.write_bytes(raw)
        return 0
    except (CollectionError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
