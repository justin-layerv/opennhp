#!/usr/bin/env python3

from __future__ import annotations

import copy
import hashlib
import json
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / ".github" / "scripts"
sys.path.insert(0, str(SCRIPTS))

import collect_udp_proof_runtime_evidence as collector  # noqa: E402
import udp_proof_aggregate_contract as aggregate  # noqa: E402
import udp_proof_deployment_contract as deployment  # noqa: E402
import udp_proof_runtime_evidence_contract as runtime  # noqa: E402
import validate_udp_proof_aggregate as aggregate_cli  # noqa: E402
import validate_udp_proof_runtime_evidence as runtime_validator  # noqa: E402


NOW = datetime(2026, 7, 29, 3, 0, tzinfo=timezone.utc)
SHA = "a" * 40


def producer() -> dict[str, object]:
    return {
        "artifact_digest": "sha256:" + "1" * 64,
        "artifact_id": 1001,
        "head_sha": "b" * 40,
        "manifest_sha256": "2" * 64,
        "provenance_sha256": "3" * 64,
        "run_attempt": 1,
        "run_id": 9001,
        "runtime_inputs_sha256": "4" * 64,
    }


def client_artifact(client: str) -> dict[str, object]:
    run_id = 2001 if client == "connector" else 2002
    return {
        "artifact_digest": "sha256:" + ("5" if client == "connector" else "6") * 64,
        "artifact_id": 3001 if client == "connector" else 3002,
        "evidence_sha256": ("7" if client == "connector" else "8") * 64,
        "head_sha": ("c" if client == "connector" else "d") * 40,
        "repository": runtime.CLIENT_REPOSITORIES[client],
        "run_attempt": 1,
        "run_id": run_id,
        "typed_evidence_sha256": ("9" if client == "connector" else "0") * 64,
        "workflow_path": runtime.CLIENT_WORKFLOWS[client],
    }


def client_deployment_producer() -> dict[str, object]:
    binding = producer()
    return {
        "artifact_digest": binding["artifact_digest"],
        "artifact_id": str(binding["artifact_id"]),
        "head_sha": binding["head_sha"],
        "repository": "layervai/nhp",
        "run_attempt": str(binding["run_attempt"]),
        "run_id": str(binding["run_id"]),
        "workflow_path": ".github/workflows/udp-proof-deployment-manifest.yml",
    }


def runner(client: str) -> dict[str, object]:
    connector = client == "connector"
    return {
        "capabilities": list(runtime.RUNNER_CAPABILITIES),
        "egress_ip": "3.141.109.76",
        "instance_id": "i-0123456789abcdef0" if connector else "i-0fedcba9876543210",
        "packet_capture_sha256": ("a" if connector else "b") * 64,
        "reviewed_source_cidr": "3.141.109.76/32",
        "runner_group": "udp-proof-sandbox",
        "runner_labels_sha256": ("c" if connector else "d") * 64,
    }


def digest(value: object, name: str) -> str:
    return hashlib.sha256(
        deployment.canonical_bytes(value, maximum=128 * 1024, name=name)
    ).hexdigest()


def runtime_inputs(
    phase: str,
    artifact: dict[str, object],
    controller_run_id: int,
) -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
    capture_started = (NOW - timedelta(minutes=6)).strftime("%Y-%m-%dT%H:%M:%SZ")
    capture_ended = (NOW - timedelta(minutes=4)).strftime("%Y-%m-%dT%H:%M:%SZ")
    probe_started = (NOW - timedelta(minutes=3)).strftime(
        "%Y-%m-%dT%H:%M:%S.100000000Z"
    )
    probe_ended = (NOW - timedelta(minutes=2)).strftime(
        "%Y-%m-%dT%H:%M:%S.900000000Z"
    )
    dispatch = (
        f"nhp-{controller_run_id}-1-qurl_go-{phase}-" + "f" * 32
    )
    registration_events = [
        {
            "cell_id": "" if index <= 4 else "cell0",
            "direction": "request" if index % 2 else "response",
            "message_type": message_type,
            "ordinal": index,
            "packet_sha256": f"{index:064x}",
            "run_id": None,
            "target_role": "hub" if index <= 4 else "cell",
        }
        for index, message_type in enumerate(runtime.REGISTRATION_SEQUENCE, 1)
    ]
    cycles = []
    for cycle_index, run_id in enumerate(
        ("0123456789abcdef", "fedcba9876543210")
    ):
        cycles.append(
            {
                "run_id": run_id,
                "events": [
                    {
                        "cell_id": f"cell{cycle_index}",
                        "direction": "request" if index % 2 else "response",
                        "message_type": message_type,
                        "ordinal": index,
                        "packet_sha256": f"{32 + cycle_index * 8 + index:064x}",
                        "run_id": None if message_type == "COK" else run_id,
                        "target_role": "cell",
                    }
                    for index, message_type in enumerate(
                        runtime.SESSION_SEQUENCE, 1
                    )
                ],
            }
        )
    http_operations = [
        ("POST", "/v1/agent/bootstrap"),
        ("GET", "/v1/agent/registration-info"),
        ("POST", "/v1/agent/registration/complete"),
        ("POST", "/internal/v1/agent/otp"),
        ("POST", "/internal/v1/agent/register"),
    ]
    http_probes = (
        []
        if phase == "pre_removal"
        else [
            {
                "correlation_id_sha256": hashlib.sha256(
                    f"{dispatch}:http:{method}:{path}".encode()
                ).hexdigest(),
                "host": "api.layerv.xyz",
                "method": method,
                "path": path,
                "response_sha256": f"{64 + index:064x}",
                "status": 404,
            }
            for index, (method, path) in enumerate(http_operations)
        ]
    )
    relay_probes = (
        []
        if phase == "pre_removal"
        else [
            {
                "cell_id": cell_id,
                "correlation_id_sha256": hashlib.sha256(
                    f"{dispatch}:relay:{cell_id}:{message_type}".encode()
                ).hexdigest(),
                "http_status": 400,
                "message_type": message_type,
                "outcome": "terminal_rejection",
                "request_sha256": f"{96 + index:064x}",
                "response_sha256": f"{112 + index:064x}",
                "server_id": server_id,
                "wire_value": {
                    "NHP_LRT": 6,
                    "NHP_LST": 5,
                    "NHP_OTP": 12,
                    "NHP_REG": 13,
                }[message_type],
            }
            for index, (cell_id, server_id, message_type) in enumerate(
                (
                    (cell, server, message_type)
                    for cell, server in (
                        ("cell0", "AAAAAAAAAAA"),
                        ("cell1", "BBBBBBBBBBB"),
                    )
                    for message_type in ("NHP_LRT", "NHP_LST", "NHP_OTP", "NHP_REG")
                )
            )
        ]
    )
    wrong_caller = {
        "probes": [
            {
                "cell_id": "",
                "error_code": "10001",
                "operation": "registered_assignment_refresh",
                "outcome": "terminal_denial",
                "peer_public_key_sha256": "1" * 64,
                "request_packet_sha256": "2" * 64,
                "request_type": "LST",
                "response_packet_sha256": "3" * 64,
                "response_type": "LRT",
                "target_role": "hub",
            },
            {
                "cell_id": "cell0",
                "error_code": "10002",
                "operation": "registration_completion",
                "outcome": "terminal_denial",
                "peer_public_key_sha256": "1" * 64,
                "request_packet_sha256": "4" * 64,
                "request_type": "LST",
                "response_packet_sha256": "5" * 64,
                "response_type": "LRT",
                "target_role": "cell",
            },
        ]
    }
    wrong_source = {
        "accepted_packets": 0,
        "injections": [
            {
                "cell_id": "",
                "error_class": "nativeudp.ErrTransport",
                "expected_source": "127.0.0.1:30001",
                "injected_packet_sha256": "6" * 64,
                "injected_source": "127.0.0.1:30002",
                "outcome": "rejected",
                "request_packet_sha256": "7" * 64,
                "request_type": "LST",
                "response_type": "COK",
                "target_role": "hub",
            },
            {
                "cell_id": "cell0",
                "error_class": "nativeudp.ErrTransport",
                "expected_source": "127.0.0.1:30003",
                "injected_packet_sha256": "8" * 64,
                "injected_source": "127.0.0.1:30004",
                "outcome": "rejected",
                "request_packet_sha256": "9" * 64,
                "request_type": "KNK",
                "response_type": "COK",
                "target_role": "cell",
            },
        ],
    }
    probe = {
        "capture": {
            "ended_at": capture_ended,
            "raw_sha256": "e" * 64,
            "started_at": capture_started,
            "targets_sha256": "f" * 64,
        },
        "client_binding": {
            "controller_run_attempt": "1",
            "controller_run_id": str(controller_run_id),
            "dispatch_correlation_id": dispatch,
            "head_sha": artifact["head_sha"],
            "repository": "layervai/qurl-go",
            "run_attempt": str(artifact["run_attempt"]),
            "run_id": str(artifact["run_id"]),
            "workflow_path": runtime.CLIENT_WORKFLOWS["qurl_go"],
        },
        "gate": runtime.GATE,
        "observations": {
            "http_lifecycle": {
                "legacy_route_observation_count": 0,
                "probes": http_probes,
            },
            "registration_wire": {
                "agent_id_sha256": "8" * 64,
                "audit_sha256": digest(
                    registration_events, "registration wire events"
                ),
                "correlation_id_sha256": "0" * 64,
                "events": registration_events,
            },
            "relay_lifecycle": {
                "probes": relay_probes,
                "relay_route_count": 0,
            },
            "session_wire": {
                "audit_sha256": digest(cycles, "session wire cycles"),
                "cycles": cycles,
            },
            "wrong_caller": wrong_caller,
            "wrong_source": wrong_source,
        },
        "observed_at": (NOW - timedelta(minutes=1)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        ),
        "phase": phase,
        "probe_ended_at": probe_ended,
        "probe_started_at": probe_started,
        "retirement_probe_targets_sha256": "c" * 64,
        "schema_version": 1,
    }
    start_millis = int(
        datetime.fromisoformat(probe_started.replace("Z", "+00:00")).timestamp()
        * 1000
    )

    def event(index: int, log_group: str) -> dict[str, object]:
        timestamp = start_millis + index + 1
        return {
            "event_id_sha256": hashlib.sha256(f"event-{index}".encode()).hexdigest(),
            "event_timestamp_millis": timestamp,
            "ingestion_timestamp_millis": timestamp + 1000,
            "log_group": log_group,
            "log_stream_sha256": hashlib.sha256(
                f"stream-{index}".encode()
            ).hexdigest(),
        }

    groups = [
        "/layerv/nhp/sandbox/cell0/qurl-api",
        "/layerv/nhp/sandbox/cell1/qurl-api",
    ]
    server_receipt = {
        "client_binding": probe["client_binding"],
        "gate": runtime.GATE,
        "http": {
            "legacy_handler_dispatch_count": 0,
            "log_groups": groups,
            "observations": [
                {
                    "correlation_id_sha256": row["correlation_id_sha256"],
                    "event": event(index, groups[index % 2]),
                    "handler_dispatched": False,
                    "method": row["method"],
                    "path": row["path"],
                    "source_ip": "3.141.109.76",
                    "status": row["status"],
                }
                for index, row in enumerate(http_probes)
            ],
        },
        "observed_at": NOW.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "phase": phase,
        "probe_window": {
            "ended_at": probe_ended,
            "started_at": probe_started,
        },
        "proof_source_ip": "3.141.109.76",
        "relay": {
            "forward_count": 0,
            "log_group": "/layerv/nhp/sandbox/relay",
            "observations": [
                {
                    "before_forward": True,
                    "before_server_dispatch": True,
                    "before_waiter": True,
                    "cell_id": row["cell_id"],
                    "correlation_id_sha256": row["correlation_id_sha256"],
                    "event": event(index + len(http_probes), "/layerv/nhp/sandbox/relay"),
                    "message_type": row["message_type"],
                    "outcome": "unsupported_type_rejected",
                    "server_id": row["server_id"],
                    "source_ip": "3.141.109.76",
                }
                for index, row in enumerate(relay_probes)
            ],
            "server_dispatch_count": 0,
            "waiter_created_count": 0,
        },
        "retirement_probe_targets_sha256": "c" * 64,
        "schema_version": 1,
    }
    transport = {
        "capture_ended_at": capture_ended,
        "capture_sha256": "e" * 64,
        "capture_started_at": capture_started,
        "capture_targets_sha256": "f" * 64,
        "client_run_id": artifact["run_id"],
        "client_sha": artifact["head_sha"],
        "nhp_udp_lifecycle_success": True,
        "qurl_service_legacy_route_count": 0,
        "receipt_sha256": "1" * 64,
        "relay_route_count": 0,
    }
    return probe, server_receipt, transport


def attestation(client: str, phase: str = "pre_removal") -> dict[str, object]:
    artifact = client_artifact(client)
    root: dict[str, object] = {
        "assignment_receipt": None,
        "client": client,
        "client_artifact": artifact,
        "controller": {
            "head_sha": SHA,
            "repository": "layervai/nhp",
            "run_attempt": 1,
            "run_id": 7001 if client == "connector" else 7002,
            "workflow_path": runtime.CONTROLLER_WORKFLOW,
        },
        "gate": runtime.GATE,
        "observed_at": NOW.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "phase": phase,
        "producer_artifact": producer(),
        "rows": {},
        "runner": runner(client),
        "runtime_probe": None,
        "schema_version": 1,
        "server_authority": None,
        "server_receipt": None,
        "surface_contract_sha256": None,
        "transport_receipt": None,
    }
    if client == "qurl_go":
        probe, server_receipt, transport = runtime_inputs(
            phase, artifact, root["controller"]["run_id"]
        )
        root["runtime_probe"] = probe
        root["server_receipt"] = server_receipt
        root["server_authority"] = {
            "proof_source_ip": "3.141.109.76",
            "qurl_service_log_groups": [
                "/layerv/nhp/sandbox/cell0/qurl-api",
                "/layerv/nhp/sandbox/cell1/qurl-api",
            ],
            "relay_log_group": "/layerv/nhp/sandbox/relay",
        }
        root["surface_contract_sha256"] = "6" * 64
        root["rows"] = runtime.rows_from_runtime_observations(
            runtime_probe=probe,
            server_receipt=server_receipt,
            transport_receipt=transport,
            surface_contract_sha256=root["surface_contract_sha256"],
            proof_phase=phase,
        )
        root["assignment_receipt"] = {
            "agent_id_sha256": "8" * 64,
            "assigned_cells": ["cell0", "cell1"],
            "checkpoint_sha256": "c" * 64,
            "client_run_id": artifact["run_id"],
            "client_sha": artifact["head_sha"],
            "correlation_id_sha256": "0" * 64,
            "receipt_sha256": "d" * 64,
        }
        root["transport_receipt"] = transport
    return root


def build_runtime(phase: str = "pre_removal") -> dict[str, object]:
    return runtime.build_runtime_evidence(
        attestation("connector", phase),
        attestation("qurl_go", phase),
        proof_phase=phase,
        producer_artifact=producer(),
        connector_artifact=client_artifact("connector"),
        qurl_go_artifact=client_artifact("qurl_go"),
        observed_at=NOW,
    )


class RuntimeEvidenceTest(unittest.TestCase):
    def test_registration_sequence_matches_native_qurl_go_profile(self) -> None:
        self.assertEqual(
            runtime.REGISTRATION_SEQUENCE,
            ["LST", "COK", "LST", "LRT", "REG", "RAK", "LST", "LRT"],
        )

    def test_builds_exact_seven_real_rows_and_round_trips(self) -> None:
        document = build_runtime()
        self.assertEqual(document["produced_rows"], list(runtime.PRODUCED_ROWS))
        self.assertEqual(len(document["rows"]), 7)
        self.assertNotIn({"verified": True}, document["rows"].values())
        connector_sha = document["controller_attestations"]["connector"]["sha256"]
        qurl_go_sha = document["controller_attestations"]["qurl_go"]["sha256"]
        raw = runtime.canonical_bytes(document)
        runtime.validate_runtime_bytes(
            raw,
            proof_phase="pre_removal",
            producer_artifact=producer(),
            connector_artifact=client_artifact("connector"),
            qurl_go_artifact=client_artifact("qurl_go"),
            connector_attestation_sha256=connector_sha,
            qurl_go_attestation_sha256=qurl_go_sha,
            validation_time=NOW,
        )

    def test_post_removal_requires_active_relay_rejection_and_removed_http(
        self,
    ) -> None:
        document = build_runtime("post_removal")
        self.assertEqual(
            document["rows"]["retirement.http_lifecycle_surface_state"][
                "surface_state"
            ],
            "removed_404",
        )
        self.assertEqual(
            document["rows"]["retirement.relay_rejects_native_lifecycle_messages"][
                "attempted_message_types"
            ],
            runtime.RELAY_NATIVE_LIFECYCLE_TYPES,
        )
        self.assertEqual(
            document["rows"]["retirement.relay_rejects_native_lifecycle_messages"][
                "rejected_alias_type_pairs"
            ],
            8,
        )

    def test_rejects_false_runtime_outcomes(self) -> None:
        mutations = {
            "accepted wrong caller": lambda value: value["rows"][
                "negative.wrong_caller"
            ].__setitem__("accepted_operations", 1),
            "accepted wrong source": lambda value: value["rows"][
                "negative.wrong_source"
            ].__setitem__("accepted_packets", 1),
            "legacy HTTP route": lambda value: value["rows"][
                "retirement.http_lifecycle_surface_state"
            ].__setitem__("legacy_route_observation_count", 1),
            "relay dispatch": lambda value: value["rows"][
                "retirement.relay_rejects_native_lifecycle_messages"
            ].__setitem__("plugin_dispatches", 1),
            "wire reorder": lambda value: value["rows"][
                "wire.registration_lst_lrt_reg_rak_completion"
            ]["message_sequence"].reverse(),
            "RunID reuse": lambda value: value["rows"][
                "wire.session_knk_ack_ext_ack"
            ].__setitem__("next_cycle_run_id", "0123456789abcdef"),
        }
        for name, mutation in mutations.items():
            with self.subTest(name=name):
                value = attestation("qurl_go")
                mutation(value)
                with self.assertRaises(deployment.ContractError):
                    runtime.validate_controller_attestation(
                        value,
                        client="qurl_go",
                        proof_phase="pre_removal",
                        producer_artifact=producer(),
                        client_artifact=client_artifact("qurl_go"),
                        validation_time=NOW,
                    )

    def test_rejects_stale_binding_and_runner_reuse(self) -> None:
        stale = attestation("qurl_go")
        stale["observed_at"] = (NOW - timedelta(hours=6, seconds=1)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        with self.assertRaises(deployment.ContractError):
            runtime.validate_controller_attestation(
                stale,
                client="qurl_go",
                proof_phase="pre_removal",
                producer_artifact=producer(),
                client_artifact=client_artifact("qurl_go"),
                validation_time=NOW,
            )
        reused = attestation("qurl_go")
        reused["runner"] = runner("connector")
        with self.assertRaises(deployment.ContractError):
            runtime.build_runtime_evidence(
                attestation("connector"),
                reused,
                proof_phase="pre_removal",
                producer_artifact=producer(),
                connector_artifact=client_artifact("connector"),
                qurl_go_artifact=client_artifact("qurl_go"),
                observed_at=NOW,
            )
        mixed_revision = attestation("qurl_go")
        mixed_revision["controller"]["head_sha"] = "f" * 40
        with self.assertRaises(deployment.ContractError):
            runtime.build_runtime_evidence(
                attestation("connector"),
                mixed_revision,
                proof_phase="pre_removal",
                producer_artifact=producer(),
                connector_artifact=client_artifact("connector"),
                qurl_go_artifact=client_artifact("qurl_go"),
                observed_at=NOW,
            )

    def test_collector_requires_canonical_inputs_and_publishes_once(self) -> None:
        documents = {
            "connector.json": attestation("connector"),
            "qurl-go.json": attestation("qurl_go"),
            "producer.json": producer(),
            "connector-artifact.json": client_artifact("connector"),
            "qurl-go-artifact.json": client_artifact("qurl_go"),
        }
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            for name, value in documents.items():
                (directory / name).write_bytes(
                    deployment.canonical_bytes(value, maximum=128 * 1024, name=name)
                )
            raw = collector.collect(
                connector_attestation_path=directory / "connector.json",
                qurl_go_attestation_path=directory / "qurl-go.json",
                producer_artifact_path=directory / "producer.json",
                connector_artifact_path=directory / "connector-artifact.json",
                qurl_go_artifact_path=directory / "qurl-go-artifact.json",
                proof_phase="pre_removal",
                observed_at=NOW,
            )
            self.assertEqual(
                json.loads(raw)["produced_rows"], list(runtime.PRODUCED_ROWS)
            )
            with self.assertRaisesRegex(
                deployment.ContractError,
                "outside its authenticated freshness window",
            ):
                collector.collect(
                    connector_attestation_path=directory / "connector.json",
                    qurl_go_attestation_path=directory / "qurl-go.json",
                    producer_artifact_path=directory / "producer.json",
                    connector_artifact_path=directory / "connector-artifact.json",
                    qurl_go_artifact_path=directory / "qurl-go-artifact.json",
                    proof_phase="pre_removal",
                )
            output = (directory / "output.json").resolve()
            collector._write_once(output, raw)
            validated = runtime_validator.validate(
                evidence_path=output,
                connector_attestation_path=directory / "connector.json",
                qurl_go_attestation_path=directory / "qurl-go.json",
                producer_artifact_path=directory / "producer.json",
                connector_artifact_path=directory / "connector-artifact.json",
                qurl_go_artifact_path=directory / "qurl-go-artifact.json",
                proof_phase="pre_removal",
                validation_time=NOW,
            )
            self.assertEqual(validated["produced_rows"], list(runtime.PRODUCED_ROWS))
            with self.assertRaises(deployment.ContractError):
                collector._write_once(output, raw)


def qurl_inventory() -> dict[str, object]:
    owners = (
        [(scenario, "qurl-go") for scenario in aggregate.QURL_GO_ROWS]
        + [(scenario, "qurl-connector") for scenario in aggregate.CONNECTOR_ROWS]
        + [(scenario, "nhp-orchestrator") for scenario in aggregate.NHP_ROWS]
    )
    return {
        "schema_version": 1,
        "gate": aggregate.GATE,
        "proof_phases": ["pre_removal", "post_removal"],
        "all_scenarios_required": True,
        "scenarios": [
            {
                "id": scenario,
                "owner": owner,
                "status": "implemented"
                if owner == "qurl-go"
                else "external_dependency",
                "test_name": f"TestProof/row_{index}",
                "requirement": f"Prove {scenario}.",
            }
            for index, (scenario, owner) in enumerate(owners)
        ],
    }


def connector_inventory() -> dict[str, object]:
    return {
        "schema": 1,
        "gate": aggregate.GATE,
        "proof_phases": ["pre_removal", "post_removal"],
        "all_scenarios_required": True,
        "scenarios": [
            {
                "name": scenario,
                "status": "implemented",
                "test": f"TestSandboxConnectorUDP/row_{index}",
                "requires_env": [],
                "reason": f"Prove {scenario}.",
            }
            for index, scenario in enumerate(aggregate.CONNECTOR_ROWS)
        ],
    }


def typed_item(kind: str, observation: dict[str, object]) -> dict[str, object]:
    return {
        "kind": kind,
        "observation": observation,
        "observation_sha256": hashlib.sha256(
            deployment.canonical_bytes(
                observation, maximum=64 * 1024, name="observation"
            )
        ).hexdigest(),
    }


def static_document() -> dict[str, object]:
    binding = producer()
    return {
        "schema_version": 1,
        "gate": aggregate.GATE,
        "phase": "pre_removal",
        "producer": {
            "head_sha": binding["head_sha"],
            "repository": "layervai/nhp",
            "run_attempt": binding["run_attempt"],
            "run_id": binding["run_id"],
            "workflow_path": ".github/workflows/udp-proof-deployment-manifest.yml",
        },
        "bindings": {
            "deployment_manifest_sha256": binding["manifest_sha256"],
            "deployment_provenance_sha256": binding["provenance_sha256"],
            "deployment_runtime_inputs_sha256": binding["runtime_inputs_sha256"],
        },
        "produced_rows": list(aggregate.STATIC_NHP_ROWS),
        "rows": {
            scenario: {"kind": "static", "scenario": scenario, "fact": index + 1}
            for index, scenario in enumerate(aggregate.STATIC_NHP_ROWS)
        },
    }


def client_evidence(client: str, static: dict[str, object]) -> dict[str, object]:
    if client == "connector":
        keys = aggregate.CONNECTOR_ROWS
        typed = [
            {
                "scenario_key": scenario,
                "evidence": [
                    typed_item(
                        "connector_observation",
                        {
                            "producer": "layervai/qurl-connector",
                            "scenario_key": scenario,
                            "facts_sha256": f"{index:064x}",
                        },
                    )
                ],
            }
            for index, scenario in enumerate(keys, 1)
        ]
    else:
        typed = []
        static_rows = static["rows"]
        for index, scenario in enumerate(aggregate.ALL_ROWS, 1):
            evidence: list[dict[str, object]] = []
            if scenario in aggregate.QURL_GO_ROWS:
                evidence = [
                    typed_item(
                        "wire_trace",
                        {
                            "producer": "layervai/qurl-go",
                            "scenario_key": scenario,
                            "test_name": f"TestProof/{index}",
                            "outcome": "pass",
                        },
                    )
                ]
            elif scenario in aggregate.STATIC_NHP_ROWS:
                row = static_rows[scenario]
                row_sha = hashlib.sha256(
                    deployment.canonical_bytes(
                        row, maximum=128 * 1024, name="static row"
                    )
                ).hexdigest()
                evidence = [
                    typed_item(
                        "surface_inventory",
                        {
                            "evidence_kind": "surface_inventory",
                            "producer": "layervai/nhp",
                            "producer_run_id": 9001,
                            "row_sha256": row_sha,
                            "scenario_key": scenario,
                            "source_sha": SHA,
                            "verified": True,
                        },
                    )
                ]
            typed.append({"scenario_key": scenario, "evidence": evidence})
    return {
        "phase": "pre_removal",
        "deployment_manifest_sha256": producer()["manifest_sha256"],
        "deployment_producer": client_deployment_producer(),
        "deployment_runtime_inputs_sha256": producer()["runtime_inputs_sha256"],
        "inventory_sha256": "2" * 64 if client == "connector" else "4" * 64,
        "typed_evidence": typed,
    }


class AggregateTest(unittest.TestCase):
    def inputs(self) -> dict[str, object]:
        static = static_document()
        return {
            "proof_phase": "pre_removal",
            "qurl_go_inventory": qurl_inventory(),
            "connector_inventory": connector_inventory(),
            "qurl_go_evidence": client_evidence("qurl_go", static),
            "connector_evidence": client_evidence("connector", static),
            "static_nhp_evidence": static,
            "runtime_nhp_evidence": build_runtime(),
            "input_sha256": {
                "connector_evidence_sha256": "7" * 64,
                "connector_inventory_sha256": "2" * 64,
                "qurl_go_evidence_sha256": "8" * 64,
                "qurl_go_inventory_sha256": "4" * 64,
                "runtime_nhp_evidence_sha256": "5" * 64,
                "static_nhp_evidence_sha256": "6" * 64,
            },
        }

    def test_exact_46_11_11_aggregate(self) -> None:
        document = aggregate.build_aggregate(**self.inputs())
        self.assertEqual(
            document["counts"],
            {
                "connector": 11,
                "nhp_orchestrator": 11,
                "qurl_go": 46,
                "total": 68,
            },
        )
        aggregate.validate_aggregate(json.loads(aggregate.canonical_bytes(document)))

    def test_rejects_missing_placeholder_and_static_mismatch(self) -> None:
        mutations = {
            "missing qurl row": lambda values: values["qurl_go_evidence"][
                "typed_evidence"
            ].pop(),
            "placeholder Connector row": lambda values: values["connector_evidence"][
                "typed_evidence"
            ][0].__setitem__(
                "evidence", [typed_item("wire_trace", {"verified": True})]
            ),
            "static row mismatch": lambda values: values["static_nhp_evidence"]["rows"][
                aggregate.STATIC_NHP_ROWS[0]
            ].__setitem__("fact", 99),
            "runtime row missing": lambda values: values["runtime_nhp_evidence"][
                "rows"
            ].pop(aggregate.RUNTIME_NHP_ROWS[0]),
            "runtime false acceptance": lambda values: values["runtime_nhp_evidence"][
                "rows"
            ]["negative.wrong_source"].__setitem__("accepted_packets", 1),
            "runtime client evidence mismatch": lambda values: values[
                "runtime_nhp_evidence"
            ]["client_artifacts"]["connector"].__setitem__("evidence_sha256", "f" * 64),
            "client inventory mismatch": lambda values: values[
                "qurl_go_evidence"
            ].__setitem__("inventory_sha256", "f" * 64),
            "client producer mismatch": lambda values: values["connector_evidence"][
                "deployment_producer"
            ].__setitem__("run_id", "9999"),
            "static producer mismatch": lambda values: values["static_nhp_evidence"][
                "producer"
            ].__setitem__("head_sha", "f" * 40),
            "static provenance mismatch": lambda values: values["static_nhp_evidence"][
                "bindings"
            ].__setitem__("deployment_provenance_sha256", "f" * 64),
        }
        for name, mutation in mutations.items():
            with self.subTest(name=name):
                values = copy.deepcopy(self.inputs())
                mutation(values)
                with self.assertRaises(deployment.ContractError):
                    aggregate.build_aggregate(**values)

    def test_cli_build_binds_exact_input_bytes(self) -> None:
        values = self.inputs()
        file_values = {
            "qurl-go-inventory.json": values["qurl_go_inventory"],
            "connector-inventory.json": values["connector_inventory"],
            "qurl-go-evidence.json": values["qurl_go_evidence"],
            "connector-evidence.json": values["connector_evidence"],
            "static.json": values["static_nhp_evidence"],
            "runtime.json": values["runtime_nhp_evidence"],
        }
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            for name in ("qurl-go-inventory.json", "connector-inventory.json"):
                (directory / name).write_bytes(
                    deployment.canonical_bytes(
                        file_values[name], maximum=5 * 1024 * 1024, name=name
                    )
                )
            values["qurl_go_evidence"]["inventory_sha256"] = hashlib.sha256(
                (directory / "qurl-go-inventory.json").read_bytes()
            ).hexdigest()
            values["connector_evidence"]["inventory_sha256"] = hashlib.sha256(
                (directory / "connector-inventory.json").read_bytes()
            ).hexdigest()
            for name in ("qurl-go-evidence.json", "connector-evidence.json"):
                (directory / name).write_bytes(
                    deployment.canonical_bytes(
                        file_values[name], maximum=5 * 1024 * 1024, name=name
                    )
                )
            values["runtime_nhp_evidence"]["client_artifacts"]["qurl_go"][
                "evidence_sha256"
            ] = hashlib.sha256(
                (directory / "qurl-go-evidence.json").read_bytes()
            ).hexdigest()
            values["runtime_nhp_evidence"]["client_artifacts"]["connector"][
                "evidence_sha256"
            ] = hashlib.sha256(
                (directory / "connector-evidence.json").read_bytes()
            ).hexdigest()
            for name in ("static.json", "runtime.json"):
                (directory / name).write_bytes(
                    deployment.canonical_bytes(
                        file_values[name], maximum=5 * 1024 * 1024, name=name
                    )
                )
            raw = aggregate_cli.build(
                proof_phase="pre_removal",
                qurl_go_inventory_path=directory / "qurl-go-inventory.json",
                connector_inventory_path=directory / "connector-inventory.json",
                qurl_go_evidence_path=directory / "qurl-go-evidence.json",
                connector_evidence_path=directory / "connector-evidence.json",
                static_nhp_evidence_path=directory / "static.json",
                runtime_nhp_evidence_path=directory / "runtime.json",
            )
            document = json.loads(raw)
            self.assertEqual(document["counts"]["total"], 68)
            self.assertEqual(
                document["bindings"]["runtime_nhp_evidence_sha256"],
                hashlib.sha256((directory / "runtime.json").read_bytes()).hexdigest(),
            )


if __name__ == "__main__":
    unittest.main()
