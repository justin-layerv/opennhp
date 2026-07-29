from __future__ import annotations

import copy
import hashlib
import json
import sys
import unittest
from pathlib import Path
from unittest import mock


SCRIPTS = Path(__file__).resolve().parents[2] / ".github" / "scripts"
sys.path.insert(0, str(SCRIPTS))

import collect_udp_proof_server_receipt as collector  # noqa: E402
import udp_proof_server_receipt_contract as contract  # noqa: E402


SOURCE = "3.141.109.76"
QURL_GROUPS = [
    "/layerv/nhp/sandbox/cell0/qurl-api",
    "/layerv/nhp/sandbox/cell1/qurl-api",
]
RELAY_GROUP = "/layerv/nhp/sandbox/relay"


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def probe() -> dict[str, object]:
    dispatch = "nhp-123-1-qurl_go-post_removal-" + "a" * 32
    http = [
        ("POST", "/v1/agent/bootstrap"),
        ("GET", "/v1/agent/registration-info"),
        ("POST", "/v1/agent/registration/complete"),
        ("POST", "/internal/v1/agent/otp"),
        ("POST", "/internal/v1/agent/register"),
    ]
    relay = [
        (cell, server, message_type)
        for cell, server in (
            ("cell0", "AAAAAAAAAAA"),
            ("cell1", "BBBBBBBBBBB"),
        )
        for message_type in ("NHP_LRT", "NHP_LST", "NHP_OTP", "NHP_REG")
    ]
    return {
        "client_binding": {
            "controller_run_attempt": "1",
            "controller_run_id": "123",
            "dispatch_correlation_id": dispatch,
            "head_sha": "b" * 40,
            "repository": "layervai/qurl-go",
            "run_attempt": "1",
            "run_id": "456",
            "workflow_path": ".github/workflows/native-udp-sandbox.yml",
        },
        "observations": {
            "http_lifecycle": {
                "probes": [
                    {
                        "correlation_id_sha256": digest(
                            f"{dispatch}:http:{method}:{path}"
                        ),
                        "method": method,
                        "path": path,
                        "status": 404,
                    }
                    for method, path in http
                ]
            },
            "relay_lifecycle": {
                "probes": [
                    {
                        "cell_id": cell,
                        "correlation_id_sha256": digest(
                            f"{dispatch}:relay:{cell}:{message_type}"
                        ),
                        "message_type": message_type,
                        "server_id": server,
                    }
                    for cell, server, message_type in relay
                ]
            },
        },
        "phase": "post_removal",
        "probe_ended_at": "2026-07-28T12:00:01.900000000Z",
        "probe_started_at": "2026-07-28T12:00:00.100000000Z",
        "retirement_probe_targets_sha256": "c" * 64,
    }


def event(index: int, log_group: str) -> dict[str, object]:
    return {
        "event_id_sha256": digest(f"event-{index}"),
        "event_timestamp_millis": 1_785_240_000_500 + index,
        "ingestion_timestamp_millis": 1_785_240_001_500 + index,
        "log_group": log_group,
        "log_stream_sha256": digest(f"stream-{index}"),
    }


def receipt(runtime: dict[str, object]) -> dict[str, object]:
    http_probes = runtime["observations"]["http_lifecycle"]["probes"]
    relay_probes = runtime["observations"]["relay_lifecycle"]["probes"]
    return {
        "client_binding": runtime["client_binding"],
        "gate": "udp_lifecycle_retirement",
        "http": {
            "legacy_handler_dispatch_count": 0,
            "log_groups": QURL_GROUPS,
            "observations": [
                {
                    **item,
                    "event": event(index, QURL_GROUPS[index % 2]),
                    "handler_dispatched": False,
                    "source_ip": SOURCE,
                }
                for index, item in enumerate(http_probes)
            ],
        },
        "observed_at": "2026-07-28T12:02:02Z",
        "phase": "post_removal",
        "probe_window": {
            "ended_at": runtime["probe_ended_at"],
            "started_at": runtime["probe_started_at"],
        },
        "proof_source_ip": SOURCE,
        "relay": {
            "forward_count": 0,
            "log_group": RELAY_GROUP,
            "observations": [
                {
                    **item,
                    "before_forward": True,
                    "before_server_dispatch": True,
                    "before_waiter": True,
                    "event": event(index + len(http_probes), RELAY_GROUP),
                    "outcome": "unsupported_type_rejected",
                    "source_ip": SOURCE,
                }
                for index, item in enumerate(relay_probes)
            ],
            "server_dispatch_count": 0,
            "waiter_created_count": 0,
        },
        "retirement_probe_targets_sha256": runtime[
            "retirement_probe_targets_sha256"
        ],
        "schema_version": 1,
    }


class ReceiptContractTest(unittest.TestCase):
    def test_accepts_exact_server_observations(self) -> None:
        runtime = probe()
        value = receipt(runtime)
        self.assertIs(
            contract.validate(
                value,
                runtime_probe_document=runtime,
                proof_source_ip=SOURCE,
                qurl_service_log_groups=QURL_GROUPS,
                relay_log_group=RELAY_GROUP,
            ),
            value,
        )

    def test_rejects_duplicate_or_unbound_observations(self) -> None:
        runtime = probe()
        for mutate in (
            lambda value: value["http"]["observations"].append(
                copy.deepcopy(value["http"]["observations"][0])
            ),
            lambda value: value["relay"]["observations"][0].update(
                {"source_ip": "203.0.113.1"}
            ),
            lambda value: value["relay"].update({"forward_count": 1}),
            lambda value: value["http"]["observations"][0].update(
                {"handler_dispatched": True}
            ),
            lambda value: value["relay"]["observations"][0].update(
                {"before_forward": False}
            ),
            lambda value: value["http"]["observations"][0]["event"].update(
                {"event_timestamp_millis": 1}
            ),
        ):
            with self.subTest(mutate=mutate):
                value = receipt(runtime)
                mutate(value)
                with self.assertRaises(contract.ReceiptError):
                    contract.validate(
                        value,
                        runtime_probe_document=runtime,
                        proof_source_ip=SOURCE,
                        qurl_service_log_groups=QURL_GROUPS,
                        relay_log_group=RELAY_GROUP,
                    )


class CollectorParserTest(unittest.TestCase):
    def test_parses_exact_http_and_relay_server_logs(self) -> None:
        correlation = "d" * 64
        http_event = {
            "eventId": "http-event",
            "ingestionTime": 1_785_240_001_000,
            "logStreamName": "http-stream",
            "message": json.dumps(
                {
                    "msg": collector.HTTP_LOG_MESSAGE,
                    "correlation_id_sha256": correlation,
                    "handler_dispatched": False,
                    "method": "POST",
                    "path": "/v1/agent/bootstrap",
                    "source_ip": SOURCE,
                    "status": 404,
                }
            ),
            "timestamp": 1_785_240_000_500,
        }
        relay_event = {
            "eventId": "relay-event",
            "ingestionTime": 1_785_240_001_000,
            "logStreamName": "relay-stream",
            "message": (
                "relay: proof rejection route=relay source_ip=3.141.109.76 "
                "cell_id=cell0 server_id=AAAAAAAAAAA message_type=NHP_LRT "
                f"correlation_id_sha256={correlation} "
                "outcome=unsupported_type_rejected before_waiter=true "
                "before_forward=true before_server_dispatch=true"
            ),
            "timestamp": 1_785_240_000_500,
        }
        descriptor = {
            "proof_source_ip": SOURCE,
            "qurl_service_log_groups": QURL_GROUPS,
            "relay_log_group": RELAY_GROUP,
        }
        with mock.patch.object(
            collector.handshake,
            "_filter_log_events",
            side_effect=[[http_event], [], [relay_event]],
        ):
            http = collector._http_observations(
                descriptor, start_millis=1, end_millis=2_000_000_000_000
            )
            relay = collector._relay_observations(
                descriptor, start_millis=1, end_millis=2_000_000_000_000
            )
        self.assertEqual(http[0]["correlation_id_sha256"], correlation)
        self.assertFalse(http[0]["handler_dispatched"])
        self.assertTrue(relay[0]["before_waiter"])
        self.assertEqual(relay[0]["message_type"], "NHP_LRT")
        self.assertEqual(relay[0]["outcome"], "unsupported_type_rejected")


if __name__ == "__main__":
    unittest.main()
