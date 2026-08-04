#!/usr/bin/env python3

from __future__ import annotations

import copy
import base64
import hashlib
import importlib.util
import io
import json
import stat
import sys
import tempfile
import unittest
import warnings
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / ".github" / "scripts"
TESTS = ROOT / "tests" / "scripts"
sys.path.insert(0, str(SCRIPTS))
sys.path.insert(0, str(TESTS))

import test_udp_proof_deployment_contract as producer_fixture  # noqa: E402
import udp_proof_deployment_contract as contract  # noqa: E402
import udp_proof_retirement_targets_contract as retirement_targets  # noqa: E402


VALIDATOR_PATH = SCRIPTS / "validate_udp_proof_client_artifact.py"
SPEC = importlib.util.spec_from_file_location(
    "client_artifact_validator", VALIDATOR_PATH
)
assert SPEC is not None and SPEC.loader is not None
validator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(validator)

CLIENT_RUN_ID = 12345
CLIENT_RUN_ATTEMPT = 1
CONTROLLER_RUN_ID = 54321
CONTROLLER_RUN_ATTEMPT = 2
PRODUCER_RUN_ID = 999
PRODUCER_RUN_ATTEMPT = 1
PRODUCER_ARTIFACT_ID = 24680
PRODUCER_ARTIFACT_DIGEST = "sha256:" + "d" * 64
PRODUCER_HEAD_SHA = producer_fixture.PRODUCER_SHA
REPOSITORY_ID = 67890
CLIENT_ARTIFACT_ID = 13579


def target(client: str) -> dict[str, str]:
    snapshot = producer_fixture.valid_snapshot()
    if client == "connector":
        return {
            "repository": "layervai/qurl-connector",
            "ref": snapshot["provenance"]["candidates"]["qurl_connector"]["head_ref"],
            "sha": snapshot["manifest"]["repositories"]["qurl_connector"],
            "workflow": ".github/workflows/sandbox-smoke.yml",
            "prefix": "strict-sandbox-proof",
        }
    return {
        "repository": "layervai/qurl-go",
        "ref": snapshot["provenance"]["candidates"]["qurl_go"]["head_ref"],
        "sha": snapshot["manifest"]["repositories"]["qurl_go"],
        "workflow": ".github/workflows/native-udp-sandbox.yml",
        "prefix": "native-udp-sandbox",
    }


def correlation(client: str, phase: str) -> str:
    return (
        f"nhp-{CONTROLLER_RUN_ID}-{CONTROLLER_RUN_ATTEMPT}-{client}-{phase}-" + "a" * 32
    )


def valid_run(client: str, phase: str = "pre_removal") -> dict[str, object]:
    selected = target(client)
    return {
        "conclusion": "success",
        "display_title": f"UDP proof [corr:{correlation(client, phase)}]",
        "event": "workflow_dispatch",
        "head_branch": selected["ref"],
        "head_repository": {
            "full_name": selected["repository"],
            "id": REPOSITORY_ID,
        },
        "head_sha": selected["sha"],
        "id": CLIENT_RUN_ID,
        "path": selected["workflow"],
        "repository": {
            "full_name": selected["repository"],
            "id": REPOSITORY_ID,
        },
        "run_attempt": CLIENT_RUN_ATTEMPT,
        "status": "completed",
    }


def artifact(client: str, phase: str = "pre_removal") -> dict[str, object]:
    selected = target(client)
    return {
        "digest": "sha256:" + "e" * 64,
        "expired": False,
        "id": CLIENT_ARTIFACT_ID,
        "name": (
            f"{selected['prefix']}-{phase}-{selected['sha']}-{CLIENT_RUN_ATTEMPT}"
        ),
        "size_in_bytes": 4096,
        "workflow_run": {
            "head_branch": selected["ref"],
            "head_repository_id": REPOSITORY_ID,
            "head_sha": selected["sha"],
            "id": CLIENT_RUN_ID,
            "repository_id": REPOSITORY_ID,
        },
    }


def artifacts_response(client: str, phase: str = "pre_removal") -> dict[str, object]:
    artifacts = [artifact(client, phase)]
    return {"artifacts": artifacts, "total_count": len(artifacts)}


def producer_object() -> dict[str, str]:
    return {
        "artifact_digest": PRODUCER_ARTIFACT_DIGEST,
        "artifact_id": str(PRODUCER_ARTIFACT_ID),
        "head_sha": PRODUCER_HEAD_SHA,
        "repository": "layervai/nhp",
        "run_attempt": str(PRODUCER_RUN_ATTEMPT),
        "run_id": str(PRODUCER_RUN_ID),
        "workflow_path": ".github/workflows/udp-proof-deployment-manifest.yml",
    }


def inventory(client: str) -> dict[str, object]:
    if client == "connector":
        return {
            "schema": 1,
            "gate": "udp_lifecycle_retirement",
            "proof_phases": ["pre_removal", "post_removal"],
            "all_scenarios_required": True,
            "scenarios": [
                {
                    "name": name,
                    "status": "implemented",
                    "test": test_name,
                    "requires_env": [],
                    "reason": "Prove the exact Connector scenario.",
                }
                for name, test_name in sorted(
                    validator.CONNECTOR_CANONICAL_SCENARIOS.items()
                )
            ],
        }
    return {
        "schema_version": 1,
        "gate": "udp_lifecycle_retirement",
        "proof_phases": ["pre_removal", "post_removal"],
        "all_scenarios_required": True,
        "scenarios": [
            {
                "id": "proof.client",
                "owner": "qurl-go",
                "status": "implemented",
                "test_name": "TestProof/client",
                "requirement": "Prove the producer-owned qurl-go scenario.",
            },
            {
                "id": "proof.external",
                "owner": "qurl-connector",
                "status": "external_dependency",
                "test_name": "TestProof/external",
                "requirement": "Keep the external owner explicit.",
            },
        ],
    }


def typed_contract(
    client: str, inventory_document: dict[str, object]
) -> dict[str, object]:
    scenarios = inventory_document["scenarios"]
    assert isinstance(scenarios, list)
    if client == "connector":
        return {
            "schema_version": 2,
            "gate": "udp_lifecycle_retirement",
            "observation_schema": {
                "schema_version": 1,
                "producer_repository": "layervai/qurl-connector",
                "producer_commit_sha_pattern": "^[0-9a-f]{40}$",
                "scenario_id_field": "scenario_id",
                "proof_phases": ["pre_removal", "post_removal"],
            },
            "scenario_key_field": "name",
            "scenarios": {
                scenario["name"]: {
                    "kind": "wire_trace",
                    "facts": connector_fixture_fact_schema(scenario["name"]),
                }
                for scenario in scenarios
            },
        }
    return {
        "schema_version": 1,
        "gate": "udp_lifecycle_retirement",
        "evidence_kinds": {
            "surface_inventory": {"observation_schema": "owner_bound_v1"},
            "wire_trace": {"observation_schema": "owner_bound_v1"},
        },
        "scenario_key_field": "id",
        "scenarios": {
            scenario["id"]: [
                "wire_trace" if scenario["owner"] == "qurl-go" else "surface_inventory"
            ]
            for scenario in scenarios
        },
    }


def connector_fixture_fact_schema(scenario_key: str) -> dict[str, str]:
    values = connector_fixture_facts(scenario_key)
    types = {
        bool: "boolean",
        int: "nonnegative_integer",
        str: "nonempty_string",
    }
    return {name: types[type(value)] for name, value in values.items()}


def connector_fixture_facts(scenario_key: str) -> dict[str, object]:
    required = validator.CONNECTOR_REQUIRED_FACT_VALUES.get(scenario_key)
    facts = dict(required) if required is not None else {"passed": True}
    if scenario_key == "connector.zero_http_network_capture":
        facts["packet_capture_sha256"] = "f" * 64
    return facts


def evidence(
    client: str,
    manifest_raw: bytes,
    runtime_raw: bytes,
    inventory_raw: bytes,
    *,
    phase: str = "pre_removal",
    pre_removal_run_id: str = "",
) -> dict[str, object]:
    selected = target(client)
    inventory_document = json.loads(inventory_raw)
    scenarios = inventory_document["scenarios"]
    scenario_keys = [
        scenario["name" if client == "connector" else "id"] for scenario in scenarios
    ]
    owned_scenarios = (
        scenarios
        if client == "connector"
        else [scenario for scenario in scenarios if scenario["owner"] == "qurl-go"]
    )
    owned_keys = {
        scenario["name" if client == "connector" else "id"]
        for scenario in owned_scenarios
    }
    inventory_by_key = {
        scenario["name" if client == "connector" else "id"]: scenario
        for scenario in scenarios
    }

    def typed_item(scenario_key: str) -> dict[str, object]:
        scenario = inventory_by_key[scenario_key]
        if client == "connector":
            kind = "wire_trace"
            observation = {
                "schema_version": 1,
                "producer_repository": "layervai/qurl-connector",
                "producer_commit_sha": selected["sha"],
                "proof_phase": phase,
                "scenario_id": scenario_key,
                "facts": connector_fixture_facts(scenario_key),
            }
        else:
            kind = "wire_trace"
            observation = {
                "evidence_kind": kind,
                "outcome": "pass",
                "producer": "layervai/qurl-go",
                "scenario_key": scenario_key,
                "test_name": scenario["test_name"],
                "verified": True,
            }
        return {
            "kind": kind,
            "observation": observation,
            "observation_sha256": hashlib.sha256(
                canonical(observation, 4096, f"{scenario_key} observation")
            ).hexdigest(),
        }

    value: dict[str, object] = {
        "commit_sha": selected["sha"],
        "deployment_manifest_sha256": hashlib.sha256(manifest_raw).hexdigest(),
        "deployment_producer": producer_object(),
        "deployment_runtime_inputs_sha256": hashlib.sha256(runtime_raw).hexdigest(),
        "dispatch_correlation_id": correlation(client, phase),
        "enforcement_outcome": "success",
        "gate_passed": True,
        "inputs_unchanged": True,
        "inventory_sha256": hashlib.sha256(inventory_raw).hexdigest(),
        "nhp_controller_run_attempt": str(CONTROLLER_RUN_ATTEMPT),
        "nhp_controller_run_id": str(CONTROLLER_RUN_ID),
        "phase": phase,
        "pre_removal_deployment_sha256": None,
        "pre_removal_evidence_sha256": None,
        "pre_removal_run_id": None,
        "proof_harness_sha256": "2" * 64,
        "provenance": {},
        "provenance_valid": True,
        "repository": selected["repository"],
        "run_attempt": str(CLIENT_RUN_ATTEMPT),
        "run_id": str(CLIENT_RUN_ID),
        "scenario_contract_sha256": "3" * 64,
        "scenario_results": [
            {
                "action": "pass",
                "elapsed_seconds": 1,
                "test_name": scenario["test" if client == "connector" else "test_name"],
            }
            for scenario in owned_scenarios
        ],
        "schema_version": 1,
        "two_cell_provenance": True,
        "typed_evidence": [
            {
                "evidence": (
                    [typed_item(scenario_key)] if scenario_key in owned_keys else []
                ),
                "scenario_key": scenario_key,
            }
            for scenario_key in scenario_keys
        ],
        "typed_evidence_complete": True,
        "typed_evidence_contract_sha256": "5" * 64,
    }
    if phase == "post_removal":
        value["pre_removal_run_id"] = pre_removal_run_id
        value["pre_removal_evidence_sha256"] = "6" * 64
        value["pre_removal_deployment_sha256"] = "7" * 64
    if client == "connector":
        total = len(scenarios)
        value.update(
            {
                "counts": {
                    "blocking": 0,
                    "exact_passes": total,
                    "failures": 0,
                    "implemented": total,
                    "skips": 0,
                },
                "input_outcome": "success",
                "scenario_attestation": {
                    "schema_version": 1,
                    "gate": "udp_lifecycle_retirement",
                    "scenario_contract_sha256": "3" * 64,
                    "scenario_key_field": "name",
                    "typed_evidence_contract_sha256": "5" * 64,
                    "counts": {"proven": total, "total": total, "unproven": 0},
                    "scenarios": [
                        {
                            "name": scenario["name"],
                            "observed_evidence_kinds": ["wire_trace"],
                            "outcome": "pass",
                            "required_evidence_kinds": ["wire_trace"],
                            "status": "implemented",
                            "test": scenario["test"],
                        }
                        for scenario in scenarios
                    ],
                },
            }
        )
    else:
        value.update(
            {
                "counts": {
                    "producer_owned": 1,
                    "external_dependency": 1,
                    "failures": 0,
                    "skips": 0,
                    "exact_passes": 1,
                },
                "inventory_mapping_sha256": "9" * 64,
                "retired_lifecycle_surface_sha256": "a" * 64,
                "strict_outcome": "success",
            }
        )
    return value


def canonical(value: object, maximum: int, name: str) -> bytes:
    return contract.canonical_bytes(value, maximum=maximum, name=name)


def runtime_probe(phase: str) -> dict[str, object]:
    now = datetime.now(timezone.utc).replace(microsecond=0)

    def event(
        ordinal: int,
        message_type: str,
        role: str,
        *,
        run_id: str | None = None,
    ) -> dict[str, object]:
        return {
            "cell_id": "" if role == "hub" else "cell0",
            "direction": "request" if ordinal % 2 else "response",
            "message_type": message_type,
            "ordinal": ordinal,
            "packet_sha256": f"{ordinal:x}" * 64,
            "run_id": run_id,
            "target_role": role,
        }

    registration_types = ["LST", "COK", "LST", "LRT", "REG", "RAK", "LST", "LRT"]
    registration = [
        event(index, message_type, "hub" if index <= 4 else "cell")
        for index, message_type in enumerate(registration_types, 1)
    ]
    registration_audit = hashlib.sha256(
        canonical(registration, 128 * 1024, "registration events")
    ).hexdigest()
    session_types = ["KNK", "COK", "RKN", "ACK", "EXT", "ACK"]
    cycles = []
    for run_id in ("0123456789abcdef", "fedcba9876543210"):
        cycles.append(
            {
                "run_id": run_id,
                "events": [
                    event(
                        index,
                        message_type,
                        "cell",
                        run_id=None if message_type == "COK" else run_id,
                    )
                    for index, message_type in enumerate(session_types, 1)
                ],
            }
        )
    session_audit = hashlib.sha256(
        canonical(cycles, 128 * 1024, "session cycles")
    ).hexdigest()
    http_probes = []
    relay_probes = []
    if phase == "post_removal":
        hosts = (
            "bootstrap.layerv.xyz",
            "api.layerv.xyz",
            "api.layerv.xyz",
            "internal-api.qurl.layerv.xyz",
            "internal-api.qurl.layerv.xyz",
        )
        operations = (
            ("POST", "/v1/agent/bootstrap"),
            ("GET", "/v1/agent/registration-info"),
            ("POST", "/v1/agent/registration/complete"),
            ("POST", "/internal/v1/agent/otp"),
            ("POST", "/internal/v1/agent/register"),
        )
        http_probes = [
            {
                "correlation_id_sha256": hashlib.sha256(
                    (
                        f"{correlation('qurl_go', phase)}:http:"
                        f"{operation[0]}:{operation[1]}"
                    ).encode()
                ).hexdigest(),
                "host": host,
                "method": operation[0],
                "path": operation[1],
                "response_sha256": f"{index:x}" * 64,
                "status": 404,
            }
            for index, (host, operation) in enumerate(
                zip(hosts, operations, strict=True), 1
            )
        ]
        wire_values = {
            "NHP_LRT": 6,
            "NHP_LST": 5,
            "NHP_OTP": 12,
            "NHP_REG": 13,
        }
        for cell_id, server_id in (
            ("cell0", "AAAAAAAAAAA"),
            ("cell1", "BBBBBBBBBBB"),
        ):
            for message_type, wire_value in wire_values.items():
                relay_probes.append(
                    {
                        "cell_id": cell_id,
                        "correlation_id_sha256": hashlib.sha256(
                            (
                                f"{correlation('qurl_go', phase)}:relay:"
                                f"{cell_id}:{message_type}"
                            ).encode()
                        ).hexdigest(),
                        "http_status": 400,
                        "message_type": message_type,
                        "outcome": "terminal_rejection",
                        "request_sha256": "c" * 64,
                        "response_sha256": "d" * 64,
                        "server_id": server_id,
                        "wire_value": wire_value,
                    }
                )
    return {
        "capture": {
            "ended_at": (now - timedelta(minutes=2)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "raw_sha256": "1" * 64,
            "started_at": (now - timedelta(minutes=3)).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
            "targets_sha256": "2" * 64,
        },
        "client_binding": {
            "controller_run_attempt": str(CONTROLLER_RUN_ATTEMPT),
            "controller_run_id": str(CONTROLLER_RUN_ID),
            "dispatch_correlation_id": correlation("qurl_go", phase),
            "head_sha": target("qurl_go")["sha"],
            "repository": "layervai/qurl-go",
            "run_attempt": str(CLIENT_RUN_ATTEMPT),
            "run_id": str(CLIENT_RUN_ID),
            "workflow_path": ".github/workflows/native-udp-sandbox.yml",
        },
        "gate": "udp_lifecycle_retirement",
        "observations": {
            "http_lifecycle": {
                "legacy_route_observation_count": 0,
                "probes": http_probes,
            },
            "registration_wire": {
                "agent_id_sha256": "3" * 64,
                "audit_sha256": registration_audit,
                "correlation_id_sha256": "5" * 64,
                "events": registration,
            },
            "relay_lifecycle": {"probes": relay_probes, "relay_route_count": 0},
            "session_wire": {"audit_sha256": session_audit, "cycles": cycles},
            "wrong_caller": {
                "probes": [
                    {
                        "cell_id": "",
                        "error_code": "10001",
                        "operation": "registered_assignment_refresh",
                        "outcome": "terminal_denial",
                        "peer_public_key_sha256": "7" * 64,
                        "request_packet_sha256": "8" * 64,
                        "request_type": "LST",
                        "response_packet_sha256": "9" * 64,
                        "response_type": "LRT",
                        "target_role": "hub",
                    },
                    {
                        "cell_id": "cell0",
                        "error_code": "10002",
                        "operation": "registration_completion",
                        "outcome": "terminal_denial",
                        "peer_public_key_sha256": "7" * 64,
                        "request_packet_sha256": "a" * 64,
                        "request_type": "LST",
                        "response_packet_sha256": "b" * 64,
                        "response_type": "LRT",
                        "target_role": "cell",
                    },
                ]
            },
            "wrong_source": {
                "accepted_packets": 0,
                "injections": [
                    {
                        "cell_id": "",
                        "error_class": "nativeudp.ErrTransport",
                        "expected_source": "127.0.0.1:30001",
                        "injected_packet_sha256": "c" * 64,
                        "injected_source": "127.0.0.1:30002",
                        "outcome": "rejected",
                        "request_packet_sha256": "d" * 64,
                        "request_type": "LST",
                        "response_type": "COK",
                        "target_role": "hub",
                    },
                    {
                        "cell_id": "cell0",
                        "error_class": "nativeudp.ErrTransport",
                        "expected_source": "127.0.0.1:30003",
                        "injected_packet_sha256": "e" * 64,
                        "injected_source": "127.0.0.1:30004",
                        "outcome": "rejected",
                        "request_packet_sha256": "f" * 64,
                        "request_type": "KNK",
                        "response_type": "COK",
                        "target_role": "cell",
                    },
                ],
            },
        },
        "observed_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "phase": phase,
        "probe_ended_at": (now - timedelta(seconds=10)).strftime(
            "%Y-%m-%dT%H:%M:%S.000000000Z"
        ),
        "probe_started_at": (now - timedelta(seconds=30)).strftime(
            "%Y-%m-%dT%H:%M:%S.000000000Z"
        ),
        "retirement_probe_targets_sha256": hashlib.sha256(
            retirement_targets_raw(phase)
        ).hexdigest(),
        "schema_version": 1,
    }


def retirement_targets_raw(phase: str) -> bytes:
    # The retired hosts only have an alias before the retirement applies; after
    # it, post_removal asserts absence.
    # The retired HTTP hosts only have an alias before the retirement applies;
    # after it, post_removal asserts absence. The relay is NOT retired, so it
    # keeps its alias in both phases.
    def route53(host, zone, *, retired=True):
        # Only a host whose RECORD the retirement removed goes absent. The other
        # operation hosts keep serving their remaining routes, so they resolve
        # in both phases -- see RETIRED_DNS_HOSTS.
        present = (
            phase == "pre_removal"
            or not retired
            or host not in retirement_targets.RETIRED_DNS_HOSTS
        )
        return {
            "alias_dns_name": f"dualstack.{host}" if present else None,
            "record_name": host,
            "zone_id": zone,
        }
    document = {
        "gate": "udp_lifecycle_retirement",
        "http_operations": [
            {
                "host": host,
                "method": method,
                "path": path,
                "route53": route53(host, zone),
            }
            for host, method, path, zone in (
                (
                    "bootstrap.layerv.xyz",
                    "POST",
                    "/v1/agent/bootstrap",
                    "Z10394893FM38A1RXLL32",
                ),
                (
                    "api.layerv.xyz",
                    "GET",
                    "/v1/agent/registration-info",
                    "Z10394893FM38A1RXLL32",
                ),
                (
                    "api.layerv.xyz",
                    "POST",
                    "/v1/agent/registration/complete",
                    "Z10394893FM38A1RXLL32",
                ),
                (
                    "internal-api.qurl.layerv.xyz",
                    "POST",
                    "/internal/v1/agent/otp",
                    "Z0583929NF6JQSC2XALS",
                ),
                (
                    "internal-api.qurl.layerv.xyz",
                    "POST",
                    "/internal/v1/agent/register",
                    "Z0583929NF6JQSC2XALS",
                ),
            )
        ],
        "observed_at": "2026-07-28T12:00:00Z",
        "phase": phase,
        "producer": {
            "deployment_provenance_sha256": "a" * 64,
            "head_sha": PRODUCER_HEAD_SHA,
            "run_attempt": PRODUCER_RUN_ATTEMPT,
            "run_id": PRODUCER_RUN_ID,
            "surface_contract_sha256": hashlib.sha256(b"{}").hexdigest(),
        },
        "relay": {
            "aliases": [
                {"cell_id": "cell0", "server_id": "AAAAAAAAAAA"},
                {"cell_id": "cell1", "server_id": "BBBBBBBBBBB"},
            ],
            "base_url": "https://relay.qurl.link.layerv.xyz",
            "route53": route53(
                "relay.qurl.link.layerv.xyz",
                "Z10394893FM38A1RXLL32",
                retired=False,
            ),
            "ssm": {
                "name": "/sandbox/nhp/qurl/relay-url",
                "value_sha256": hashlib.sha256(
                    b"https://relay.qurl.link.layerv.xyz"
                ).hexdigest(),
                "version": 2,
            },
        },
        "schema_version": 1,
    }
    return canonical(document, 32 * 1024, "retirement-probe-targets.json")


def raw_typed_contract(client: str, value: object) -> bytes:
    if client == "connector":
        return (
            json.dumps(value, separators=(",", ":"), sort_keys=True) + "\n"
        ).encode("utf-8")
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def write_client_files(
    directory: Path,
    client: str,
    *,
    phase: str = "pre_removal",
    pre_removal_run_id: str = "",
) -> tuple[bytes, bytes]:
    snapshot = producer_fixture.valid_snapshot()
    snapshot["manifest"]["phase"] = phase
    snapshot["manifest"]["retirement_state"] = (
        "http_lifecycle_present" if phase == "pre_removal" else "http_lifecycle_removed"
    )
    manifest_raw = canonical(
        snapshot["manifest"],
        contract.MAX_MANIFEST_BYTES,
        "sandbox-deployment-manifest.json",
    )
    runtime_raw = canonical(
        snapshot["runtime"],
        contract.MAX_RUNTIME_BYTES,
        "deployment-runtime-inputs.json",
    )
    documents: dict[str, bytes] = {
        "deployment-runtime-inputs.json": runtime_raw,
        "sandbox-deployment-manifest.json": manifest_raw,
    }
    inventory_document = inventory(client)
    inventory_raw = canonical(
        inventory_document,
        validator.MAX_INVENTORY_BYTES,
        (
            "strict-proof-scenarios.json"
            if client == "connector"
            else "pre_retirement_scenarios.json"
        ),
    )
    if client == "connector":
        typed_contract_raw = raw_typed_contract(
            client,
            typed_contract(client, inventory_document),
        )
        documents["strict-proof-scenarios.json"] = inventory_raw
        documents["typed-evidence-contract.json"] = typed_contract_raw
        connector_evidence = evidence(
            client,
            manifest_raw,
            runtime_raw,
            inventory_raw,
            phase=phase,
            pre_removal_run_id=pre_removal_run_id,
        )
        connector_evidence["typed_evidence_contract_sha256"] = hashlib.sha256(
            typed_contract_raw
        ).hexdigest()
        connector_evidence["scenario_attestation"]["typed_evidence_contract_sha256"] = (
            connector_evidence["typed_evidence_contract_sha256"]
        )
        documents["strict-typed-evidence.json"] = canonical(
            {
                "complete": True,
                "scenarios": connector_evidence["typed_evidence"],
            },
            validator.MAX_EVIDENCE_BYTES,
            "strict-typed-evidence.json",
        )
        documents["strict-sandbox-proof.evidence.json"] = canonical(
            connector_evidence,
            validator.MAX_EVIDENCE_BYTES,
            "strict-sandbox-proof.evidence.json",
        )
    else:
        retired_surface_raw = b"{}"
        typed_contract_raw = raw_typed_contract(
            client,
            typed_contract(client, inventory_document),
        )
        documents["pre_retirement_scenarios.json"] = inventory_raw
        documents["retired_lifecycle_surface.json"] = retired_surface_raw
        documents["typed_evidence_contract.json"] = typed_contract_raw
        documents["runtime-probe-observations.json"] = canonical(
            runtime_probe(phase),
            validator.runtime_probe.MAX_ARTIFACT_BYTES,
            "runtime-probe-observations.json",
        )
        qurl_go_evidence = evidence(
            client,
            manifest_raw,
            runtime_raw,
            inventory_raw,
            phase=phase,
            pre_removal_run_id=pre_removal_run_id,
        )
        qurl_go_evidence["retired_lifecycle_surface_sha256"] = hashlib.sha256(
            retired_surface_raw
        ).hexdigest()
        qurl_go_evidence["typed_evidence_contract_sha256"] = hashlib.sha256(
            typed_contract_raw
        ).hexdigest()
        documents["native-udp-sandbox.evidence.json"] = canonical(
            qurl_go_evidence,
            validator.MAX_EVIDENCE_BYTES,
            "native-udp-sandbox.evidence.json",
        )
    for name, raw in documents.items():
        (directory / name).write_bytes(raw)
    return manifest_raw, runtime_raw


def validate_files(
    directory: Path,
    client: str,
    manifest_raw: bytes,
    runtime_raw: bytes,
    *,
    phase: str = "pre_removal",
    pre_removal_run_id: str = "",
) -> dict[str, str]:
    selected = target(client)
    expected_inventory_sha = validator.QURL_GO_CANONICAL_INVENTORY_SHA256
    expected_typed_contract_sha = validator.QURL_GO_TYPED_EVIDENCE_CONTRACT_SHA256
    expected_connector_contract_sha = (
        validator.CONNECTOR_TYPED_EVIDENCE_CONTRACT_SHA256
    )
    if client == "qurl_go":
        expected_inventory_sha = hashlib.sha256(
            (directory / "pre_retirement_scenarios.json").read_bytes()
        ).hexdigest()
        expected_typed_contract_sha = hashlib.sha256(
            (directory / "typed_evidence_contract.json").read_bytes()
        ).hexdigest()
    else:
        expected_connector_contract_sha = hashlib.sha256(
            (directory / "typed-evidence-contract.json").read_bytes()
        ).hexdigest()
    with (
        mock.patch.object(
            validator,
            "QURL_GO_CANONICAL_INVENTORY_SHA256",
            expected_inventory_sha,
        ),
        mock.patch.object(
            validator,
            "QURL_GO_TYPED_EVIDENCE_CONTRACT_SHA256",
            expected_typed_contract_sha,
        ),
        mock.patch.object(
            validator,
            "CONNECTOR_TYPED_EVIDENCE_CONTRACT_SHA256",
            expected_connector_contract_sha,
        ),
    ):
        return validator.validate_files(
            directory,
            client=client,
            proof_phase=phase,
            client_repository=selected["repository"],
            client_sha=selected["sha"],
            client_run_id=str(CLIENT_RUN_ID),
            client_run_attempt=str(CLIENT_RUN_ATTEMPT),
            dispatch_correlation_id=correlation(client, phase),
            controller_run_id=str(CONTROLLER_RUN_ID),
            controller_run_attempt=str(CONTROLLER_RUN_ATTEMPT),
            deployment_manifest_sha256=hashlib.sha256(manifest_raw).hexdigest(),
            deployment_runtime_inputs_sha256=hashlib.sha256(runtime_raw).hexdigest(),
            deployment_provenance_sha256="a" * 64,
            retirement_probe_targets_sha256=hashlib.sha256(
                retirement_targets_raw(phase)
            ).hexdigest(),
            retirement_probe_targets_b64=base64.b64encode(
                retirement_targets_raw(phase)
            ).decode("ascii"),
            producer_run_id=str(PRODUCER_RUN_ID),
            producer_run_attempt=str(PRODUCER_RUN_ATTEMPT),
            producer_head_sha=PRODUCER_HEAD_SHA,
            producer_artifact_id=str(PRODUCER_ARTIFACT_ID),
            producer_artifact_digest=PRODUCER_ARTIFACT_DIGEST,
            pre_removal_run_id=pre_removal_run_id,
        )


class MetadataTest(unittest.TestCase):
    def validate(
        self,
        client: str,
        *,
        phase: str = "pre_removal",
        run: dict[str, object] | None = None,
        artifacts: dict[str, object] | None = None,
    ) -> dict[str, str]:
        selected = target(client)
        return validator.validate_metadata(
            run or valid_run(client, phase),
            artifacts or artifacts_response(client, phase),
            client=client,
            proof_phase=phase,
            client_run_id=str(CLIENT_RUN_ID),
            client_repository=selected["repository"],
            client_ref=selected["ref"],
            client_sha=selected["sha"],
            client_run_title=f"UDP proof [corr:{correlation(client, phase)}]",
        )

    def test_selects_exact_artifact_for_each_client(self) -> None:
        for client in ("connector", "qurl_go"):
            with self.subTest(client=client):
                outputs = self.validate(client)
                self.assertEqual(outputs["client_artifact_id"], str(CLIENT_ARTIFACT_ID))
                self.assertEqual(outputs["client_run_attempt"], "1")

    def test_rejects_run_candidate_or_correlation_drift(self) -> None:
        for field, value in (
            ("run_attempt", True),
            ("head_branch", "other"),
            ("head_sha", "f" * 40),
            ("display_title", "UDP proof [corr:wrong]"),
            ("path", ".github/workflows/other.yml"),
            ("conclusion", "failure"),
        ):
            with self.subTest(field=field):
                run = valid_run("connector")
                run[field] = value
                with self.assertRaises(validator.ClientArtifactError):
                    self.validate("connector", run=run)

    def test_rejects_missing_duplicate_or_cross_run_artifact(self) -> None:
        missing = {"artifacts": [], "total_count": 0}
        duplicate = artifacts_response("connector")
        duplicate["artifacts"].append(copy.deepcopy(duplicate["artifacts"][0]))  # type: ignore[union-attr]
        duplicate["total_count"] = 2
        wrong_run = artifacts_response("connector")
        wrong_run["artifacts"][0]["workflow_run"]["id"] = CLIENT_RUN_ID + 1  # type: ignore[index]
        for artifacts in (missing, duplicate, wrong_run):
            with self.subTest(artifacts=artifacts):
                with self.assertRaises(validator.ClientArtifactError):
                    self.validate("connector", artifacts=artifacts)


class ArchiveTest(unittest.TestCase):
    def archive(
        self,
        client: str,
        *,
        duplicate: bool = False,
        symlink: bool = False,
        extra: bool = False,
    ) -> bytes:
        expected = validator.CLIENTS[client]["files"]
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as bundle:
            for name in expected:
                if symlink and name == next(iter(expected)):
                    info = zipfile.ZipInfo(name)
                    info.create_system = 3
                    info.external_attr = (stat.S_IFLNK | 0o777) << 16
                    bundle.writestr(info, b"target")
                else:
                    bundle.writestr(name, b"{}")
            if duplicate:
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", UserWarning)
                    bundle.writestr(next(iter(expected)), b"{}")
            if extra:
                bundle.writestr("extra.json", b"{}")
        return output.getvalue()

    def extract(self, client: str, archive_raw: bytes, *, digest: str | None = None):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        archive = root / "artifact.zip"
        destination = root / "artifact"
        archive.write_bytes(archive_raw)
        validator.extract_archive(
            archive,
            destination,
            client=client,
            expected_digest=(
                digest or "sha256:" + hashlib.sha256(archive_raw).hexdigest()
            ),
        )
        return destination

    def test_extracts_exact_regular_files(self) -> None:
        for client in ("connector", "qurl_go"):
            with self.subTest(client=client):
                destination = self.extract(client, self.archive(client))
                self.assertEqual(
                    {path.name for path in destination.iterdir()},
                    set(validator.CLIENTS[client]["files"]),
                )

    def test_rejects_digest_extra_duplicate_and_symlink(self) -> None:
        cases = (
            (self.archive("connector"), "sha256:" + "0" * 64),
            (self.archive("connector", extra=True), None),
            (self.archive("connector", duplicate=True), None),
            (self.archive("connector", symlink=True), None),
        )
        for archive_raw, digest in cases:
            with self.subTest(digest=digest, size=len(archive_raw)):
                with self.assertRaises(validator.ClientArtifactError):
                    self.extract("connector", archive_raw, digest=digest)


class FilesTest(unittest.TestCase):
    def test_accepts_exact_connector_and_qurl_go_results(self) -> None:
        cases = (
            ("connector", "pre_removal", ""),
            ("connector", "post_removal", "111"),
            ("qurl_go", "pre_removal", ""),
            ("qurl_go", "post_removal", "222"),
        )
        for client, phase, pre_run in cases:
            with (
                self.subTest(client=client, phase=phase),
                tempfile.TemporaryDirectory() as tmp,
            ):
                directory = Path(tmp)
                manifest_raw, runtime_raw = write_client_files(
                    directory,
                    client,
                    phase=phase,
                    pre_removal_run_id=pre_run,
                )
                outputs = validate_files(
                    directory,
                    client,
                    manifest_raw,
                    runtime_raw,
                    phase=phase,
                    pre_removal_run_id=pre_run,
                )
                self.assertEqual(
                    outputs["client_manifest_sha256"],
                    hashlib.sha256(manifest_raw).hexdigest(),
                )

    def test_rejects_runtime_probe_protocol_or_target_drift(self) -> None:
        mutations = {
            "wrong source did not receive COK": lambda document: document[
                "observations"
            ]["wrong_source"]["injections"][0].update({"response_type": "LRT"}),
            "COK claims a RunID": lambda document: document["observations"][
                "session_wire"
            ]["cycles"][0]["events"][1].update({"run_id": "0123456789abcdef"}),
            "HTTP target differs from producer": lambda document: document[
                "observations"
            ]["http_lifecycle"]["probes"][0].update({"host": "attacker.example"}),
            "relay alias differs from producer": lambda document: document[
                "observations"
            ]["relay_lifecycle"]["probes"][0].update({"server_id": "CCCCCCCCCCC"}),
            "session RunID reused": lambda document: document["observations"][
                "session_wire"
            ]["cycles"][1].update({"run_id": "0123456789abcdef"}),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                directory = Path(tmp)
                manifest_raw, runtime_raw = write_client_files(
                    directory,
                    "qurl_go",
                    phase="post_removal",
                    pre_removal_run_id="222",
                )
                probe_path = directory / "runtime-probe-observations.json"
                document = json.loads(probe_path.read_text(encoding="utf-8"))
                mutate(document)
                probe_path.write_bytes(
                    canonical(
                        document,
                        validator.runtime_probe.MAX_ARTIFACT_BYTES,
                        probe_path.name,
                    )
                )
                with self.assertRaises(validator.ClientArtifactError):
                    validate_files(
                        directory,
                        "qurl_go",
                        manifest_raw,
                        runtime_raw,
                        phase="post_removal",
                        pre_removal_run_id="222",
                    )

    def test_qurl_go_counts_are_owner_specific_and_inventory_derived(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            manifest_raw, runtime_raw = write_client_files(directory, "qurl_go")
            evidence_path = directory / "native-udp-sandbox.evidence.json"
            document = json.loads(evidence_path.read_text(encoding="utf-8"))
            document["counts"] = {
                "implemented": 1,
                "blocking": 1,
                "failures": 0,
                "skips": 0,
                "exact_passes": 1,
            }
            evidence_path.write_bytes(
                canonical(document, validator.MAX_EVIDENCE_BYTES, evidence_path.name)
            )
            with self.assertRaisesRegex(
                validator.ClientArtifactError,
                "client evidence counts",
            ):
                validate_files(
                    directory,
                    "qurl_go",
                    manifest_raw,
                    runtime_raw,
                )

    def test_qurl_go_rejects_external_row_relabeling(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            manifest_raw, runtime_raw = write_client_files(directory, "qurl_go")
            inventory_path = directory / "pre_retirement_scenarios.json"
            inventory_document = json.loads(inventory_path.read_text(encoding="utf-8"))
            inventory_document["scenarios"][1]["status"] = "implemented"
            inventory_raw = canonical(
                inventory_document,
                validator.MAX_INVENTORY_BYTES,
                inventory_path.name,
            )
            inventory_path.write_bytes(inventory_raw)
            evidence_path = directory / "native-udp-sandbox.evidence.json"
            document = json.loads(evidence_path.read_text(encoding="utf-8"))
            document["inventory_sha256"] = hashlib.sha256(inventory_raw).hexdigest()
            document["counts"] = {
                "producer_owned": 1,
                "external_dependency": 0,
                "failures": 0,
                "skips": 0,
                "exact_passes": 1,
            }
            evidence_path.write_bytes(
                canonical(document, validator.MAX_EVIDENCE_BYTES, evidence_path.name)
            )
            with self.assertRaisesRegex(
                validator.ClientArtifactError,
                "external qurl-go inventory row",
            ):
                validate_files(
                    directory,
                    "qurl_go",
                    manifest_raw,
                    runtime_raw,
                )

    def test_connector_requires_complete_scenario_attestation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            manifest_raw, runtime_raw = write_client_files(directory, "connector")
            evidence_path = directory / "strict-sandbox-proof.evidence.json"
            document = json.loads(evidence_path.read_text(encoding="utf-8"))
            document["scenario_attestation"]["counts"] = {
                "proven": 0,
                "total": 1,
                "unproven": 1,
            }
            document["scenario_attestation"]["scenarios"][0]["outcome"] = "not_proven"
            evidence_path.write_bytes(
                canonical(document, validator.MAX_EVIDENCE_BYTES, evidence_path.name)
            )
            with self.assertRaisesRegex(
                validator.ClientArtifactError,
                "Connector scenario attestation",
            ):
                validate_files(
                    directory,
                    "connector",
                    manifest_raw,
                    runtime_raw,
                )

    def test_rejects_placeholder_only_typed_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            manifest_raw, runtime_raw = write_client_files(directory, "qurl_go")
            evidence_path = directory / "native-udp-sandbox.evidence.json"
            document = json.loads(evidence_path.read_text(encoding="utf-8"))
            item = document["typed_evidence"][0]["evidence"][0]
            item["observation"] = {"verified": True}
            item["observation_sha256"] = hashlib.sha256(
                canonical(item["observation"], 4096, "placeholder observation")
            ).hexdigest()
            evidence_path.write_bytes(
                canonical(document, validator.MAX_EVIDENCE_BYTES, evidence_path.name)
            )
            with self.assertRaisesRegex(
                validator.ClientArtifactError,
                "qurl-go observation",
            ):
                validate_files(directory, "qurl_go", manifest_raw, runtime_raw)

    def test_connector_outcome_facts_are_fail_closed(self) -> None:
        schemas = {
            "connector.dns_key_destination_source_observations": {
                "authenticated_outcome": "boolean"
            },
            "connector.frp_authenticated_login_before_proxy": {
                "order": "nonempty_string"
            },
            "connector.hardened_linux_container": {
                "hardened_runtime": "boolean"
            },
            "connector.resource_id_distinct_from_knock_resource_id": {
                "distinct": "boolean"
            },
            "connector.sealed_restart_without_setup_mount": {
                "plaintext_state_absent": "boolean",
                "provider": "nonempty_string",
                "setup_mount_absent": "boolean",
            },
            "connector.zero_http_network_capture": {
                "forbidden_lifecycle_route_count": "nonnegative_integer"
            },
        }
        invalid_values = {
            "authenticated_outcome": False,
            "order": "proxy_allow<knock_success",
            "hardened_runtime": False,
            "distinct": False,
            "plaintext_state_absent": False,
            "provider": "file",
            "setup_mount_absent": False,
            "forbidden_lifecycle_route_count": 1,
        }
        required = validator.CONNECTOR_REQUIRED_FACT_VALUES
        for scenario_key, schema in schemas.items():
            facts = dict(required[scenario_key])
            for fact_name in schema:
                if fact_name not in facts:
                    facts[fact_name] = required[scenario_key][fact_name]
            for fact_name in schema:
                with self.subTest(scenario=scenario_key, fact=fact_name):
                    mutated = dict(facts)
                    mutated[fact_name] = invalid_values[fact_name]
                    with self.assertRaisesRegex(
                        validator.ClientArtifactError,
                        "does not prove the required outcome",
                    ):
                        validator._validate_connector_observation(
                            {
                                "schema_version": 1,
                                "producer_repository": "layervai/qurl-connector",
                                "producer_commit_sha": target("connector")["sha"],
                                "proof_phase": "pre_removal",
                                "scenario_id": scenario_key,
                                "facts": mutated,
                            },
                            scenario_key=scenario_key,
                            kind="test",
                            client_sha=target("connector")["sha"],
                            proof_phase="pre_removal",
                            fact_schema=schema,
                        )

    def test_rejects_every_result_lineage_drift(self) -> None:
        mutations = {
            "correlation": ("dispatch_correlation_id", "wrong"),
            "phase": ("phase", "post_removal"),
            "candidate": ("commit_sha", "f" * 40),
            "producer artifact": (
                "deployment_producer",
                {**producer_object(), "artifact_id": "1"},
            ),
            "runtime digest": ("deployment_runtime_inputs_sha256", "f" * 64),
            "extra evidence": ("unexpected", True),
        }
        for name, (field, value) in mutations.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                directory = Path(tmp)
                manifest_raw, runtime_raw = write_client_files(directory, "connector")
                path = directory / "strict-sandbox-proof.evidence.json"
                document = json.loads(path.read_text(encoding="utf-8"))
                document[field] = value
                path.write_bytes(
                    canonical(
                        document,
                        validator.MAX_EVIDENCE_BYTES,
                        path.name,
                    )
                )
                with self.assertRaises(validator.ClientArtifactError):
                    validate_files(
                        directory,
                        "connector",
                        manifest_raw,
                        runtime_raw,
                    )

    def test_post_removal_rejects_a_surviving_retirement_alias(self) -> None:
        """A retired host that still resolves must fail post_removal.

        post_removal no longer requires a paired pre_removal run, so the
        absence assertion is the only thing left proving the HTTP surface is
        actually gone. If a surviving alias were merely recorded rather than
        refused, the phase would certify nothing about the removal.
        """
        document = json.loads(
            retirement_targets_raw("post_removal").decode("utf-8")
        )
        # Sanity: the honest post-removal shape validates.
        retirement_targets.validate(
            document,
            proof_phase="post_removal",
            producer_run_id=PRODUCER_RUN_ID,
            producer_run_attempt=PRODUCER_RUN_ATTEMPT,
            producer_head_sha=PRODUCER_HEAD_SHA,
            deployment_provenance_sha256="a" * 64,
        )
        document["http_operations"][0]["route53"]["alias_dns_name"] = (
            "dualstack.bootstrap.layerv.xyz"
        )
        with self.assertRaisesRegex(
            retirement_targets.TargetsError, "must be absent"
        ):
            retirement_targets.validate(
                document,
                proof_phase="post_removal",
                producer_run_id=PRODUCER_RUN_ID,
                producer_run_attempt=PRODUCER_RUN_ATTEMPT,
                producer_head_sha=PRODUCER_HEAD_SHA,
                deployment_provenance_sha256="a" * 64,
            )

    def test_post_removal_rejects_partial_pre_removal_lineage(self) -> None:
        """Half a lineage is drift, not an unpaired run.

        The sandbox HTTP retirement applied before the proof ever gated it, so
        post_removal is admitted with NO pre-removal lineage at all. That path
        must not become a hole: a document carrying one pre-removal field while
        pre_removal_run_id is null is a truncated or mismatched pairing and
        fails closed rather than being read as unpaired.
        """
        for field in (
            "pre_removal_evidence_sha256",
            "pre_removal_deployment_sha256",
        ):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as tmp:
                directory = Path(tmp)
                manifest_raw, runtime_raw = write_client_files(
                    directory, "connector", phase="post_removal"
                )
                path = directory / "strict-sandbox-proof.evidence.json"
                document = json.loads(path.read_text(encoding="utf-8"))
                # Genuinely unpaired: no run id, but one lineage digest left over.
                document["pre_removal_run_id"] = None
                document["pre_removal_evidence_sha256"] = None
                document["pre_removal_deployment_sha256"] = None
                document[field] = "a" * 64
                path.write_bytes(
                    canonical(
                        document,
                        validator.MAX_EVIDENCE_BYTES,
                        path.name,
                    )
                )
                with self.assertRaisesRegex(
                    validator.ClientArtifactError,
                    "partial pre-removal lineage",
                ):
                    validate_files(
                        directory,
                        "connector",
                        manifest_raw,
                        runtime_raw,
                        phase="post_removal",
                    )

    def test_rejects_manifest_bytes_drift(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            manifest_raw, runtime_raw = write_client_files(directory, "connector")
            with self.assertRaises(validator.ClientArtifactError):
                validate_files(
                    directory,
                    "connector",
                    b"{}",
                    runtime_raw,
                )

    def test_rejects_missing_extra_and_noncanonical_files(self) -> None:
        for mutation in ("missing", "extra", "noncanonical"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as tmp:
                directory = Path(tmp)
                manifest_raw, runtime_raw = write_client_files(directory, "connector")
                if mutation == "missing":
                    (directory / "strict-proof-scenarios.json").unlink()
                elif mutation == "extra":
                    (directory / "extra.json").write_text("{}", encoding="utf-8")
                else:
                    (directory / "strict-proof-scenarios.json").write_text(
                        "{}\n", encoding="utf-8"
                    )
                with self.assertRaises(validator.ClientArtifactError):
                    validate_files(
                        directory,
                        "connector",
                        manifest_raw,
                        runtime_raw,
                    )


if __name__ == "__main__":
    unittest.main()
