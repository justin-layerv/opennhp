#!/usr/bin/env python3
"""Exact 46 qurl-go + 11 Connector + 11 NHP retirement-gate aggregate."""

from __future__ import annotations

import hashlib
from typing import Any

import udp_proof_deployment_contract as deployment
import udp_proof_runtime_evidence_contract as runtime


SCHEMA_VERSION = 1
GATE = "udp_lifecycle_retirement"
ARTIFACT_FILE_NAME = "udp-proof-aggregate.json"
MAX_AGGREGATE_BYTES = 256 * 1024

QURL_GO_ROWS = (
    "assignment.authenticated_invalid_response_matrix",
    "assignment.authenticated_refresh",
    "assignment.hub_cookie_proof_lst_return_routability",
    "assignment.lease_expiry_refresh",
    "dns.cell_authoritative_address_refresh",
    "dns.hub_authoritative_address_refresh",
    "dns.multi_address_ipv4_ipv6_bounds",
    "identity.public_resource_id_distinct_from_knock_resource_id",
    "negative.cell_dns_failure",
    "negative.hub_dns_failure",
    "negative.wrong_cell_key",
    "negative.wrong_hub_key",
    "otp.dedupe",
    "otp.error",
    "otp.rate_limit",
    "otp.send",
    "packet.cancellation",
    "packet.delay",
    "packet.duplicate",
    "packet.hub_first_lst_timeout",
    "packet.loss",
    "packet.malformed",
    "packet.oversize",
    "packet.remaining_phase_timeouts",
    "packet.reorder",
    "packet.replay",
    "packet.unknown_message",
    "provenance.exact_build_and_hub_trust",
    "provenance.exact_qurl_go_93_candidate",
    "reassignment.cell0_to_cell1",
    "reassignment.stale_assignment_rejection",
    "recovery.ambiguous_completion_lrt",
    "recovery.ambiguous_rak",
    "recovery.device_credential",
    "recovery.final_state_save_ambiguity",
    "recovery.registration_restart",
    "recovery.two_cell_completion_refresh",
    "registration.public_api_lifecycle_success",
    "session.cell_cookie_reknock_return_routability",
    "session.public_api_exit_success",
    "session.public_api_knock_success",
    "state.persisted_runtime_warm_open",
    "state.sealed_cold_start",
    "state.sealed_warm_restart_without_setup_credential",
    "transport.zero_http_injected_trap",
    "transport.zero_http_packet_capture_and_route_counters",
)
CONNECTOR_ROWS = (
    "connector.complete_strict_evidence_attestation",
    "connector.dns_key_destination_source_observations",
    "connector.exact_artifact_manifest",
    "connector.frp_authenticated_login_before_proxy",
    "connector.hardened_linux_container",
    "connector.provision_journal_crash_consistency",
    "connector.real_backend_traffic",
    "connector.remove_journal_crash_consistency",
    "connector.resource_id_distinct_from_knock_resource_id",
    "connector.sealed_restart_without_setup_mount",
    "connector.zero_http_network_capture",
)
STATIC_NHP_ROWS = (
    "orchestrator.real_hub_authority_and_two_cells",
    "retirement.generated_artifact_parity",
    "retirement.nhp_registrar_surface_state",
    "retirement.terraform_saved_plan_and_live_state",
)
RUNTIME_NHP_ROWS = runtime.PRODUCED_ROWS
NHP_ROWS = tuple(sorted(set(STATIC_NHP_ROWS) | set(RUNTIME_NHP_ROWS)))
ALL_ROWS = tuple(sorted(set(QURL_GO_ROWS) | set(CONNECTOR_ROWS) | set(NHP_ROWS)))


class AggregateError(deployment.ContractError):
    """One final proof partition is incomplete, overlapping, or unbound."""


def _exact(value: Any, keys: set[str], name: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise AggregateError(f"{name} must contain exactly {sorted(keys)}")
    return value


def _sha256(value: Any, name: str) -> str:
    if not isinstance(value, str) or deployment.SHA256_RE.fullmatch(value) is None:
        raise AggregateError(f"{name} must be a lowercase SHA-256")
    return value


def _positive_int(value: Any, name: str) -> int:
    if type(value) is int:
        parsed = value
    elif (
        isinstance(value, str)
        and value.isascii()
        and value.isdigit()
        and not value.startswith("0")
    ):
        parsed = int(value)
    else:
        raise AggregateError(f"{name} must be a positive integer")
    if parsed <= 0 or parsed > 9_007_199_254_740_991:
        raise AggregateError(f"{name} must be a positive safe integer")
    return parsed


def _bind_producer_identity(
    value: Any,
    *,
    expected: dict[str, Any],
    name: str,
    include_artifact: bool,
) -> None:
    if not isinstance(value, dict):
        raise AggregateError(f"{name} producer must be an object")
    required = {"head_sha", "run_attempt", "run_id"}
    if include_artifact:
        required |= {"artifact_digest", "artifact_id"}
    if not required.issubset(value):
        raise AggregateError(f"{name} producer identity is incomplete")
    if (
        value["head_sha"] != expected["head_sha"]
        or _positive_int(value["run_id"], f"{name} producer run_id")
        != expected["run_id"]
        or _positive_int(value["run_attempt"], f"{name} producer run_attempt")
        != expected["run_attempt"]
    ):
        raise AggregateError(f"{name} producer run identity drift")
    if include_artifact and (
        _positive_int(value["artifact_id"], f"{name} producer artifact_id")
        != expected["artifact_id"]
        or value["artifact_digest"] != expected["artifact_digest"]
    ):
        raise AggregateError(f"{name} producer artifact identity drift")


def _bind_aggregate_inputs(
    *,
    qurl_go_inventory: Any,
    connector_inventory: Any,
    qurl_go_evidence: dict[str, Any],
    connector_evidence: dict[str, Any],
    static_nhp_evidence: dict[str, Any],
    runtime_nhp_evidence: dict[str, Any],
    input_sha256: dict[str, str],
) -> None:
    """Prove every hashed input belongs to the same authenticated run family."""

    producer = runtime_nhp_evidence.get("producer_artifact")
    if not isinstance(producer, dict):
        raise AggregateError("runtime NHP evidence has no producer artifact binding")
    try:
        runtime._validate_producer(producer, producer)
    except runtime.RuntimeEvidenceError as exc:
        raise AggregateError(str(exc)) from exc
    runtime_clients = runtime_nhp_evidence.get("client_artifacts")
    if not isinstance(runtime_clients, dict) or set(runtime_clients) != {
        "connector",
        "qurl_go",
    }:
        raise AggregateError("runtime NHP client artifact bindings are incomplete")
    for client, evidence_key in (
        ("connector", "connector_evidence_sha256"),
        ("qurl_go", "qurl_go_evidence_sha256"),
    ):
        artifact = runtime_clients[client]
        try:
            runtime._validate_client_artifact(artifact, client, artifact)
        except runtime.RuntimeEvidenceError as exc:
            raise AggregateError(str(exc)) from exc
        if (
            not isinstance(artifact, dict)
            or artifact.get("evidence_sha256") != input_sha256[evidence_key]
        ):
            raise AggregateError(
                f"runtime NHP {client} artifact is not the aggregated evidence file"
            )

    if (
        qurl_go_evidence.get("inventory_sha256")
        != input_sha256["qurl_go_inventory_sha256"]
        or connector_evidence.get("inventory_sha256")
        != input_sha256["connector_inventory_sha256"]
    ):
        raise AggregateError("client evidence is not bound to its inventory bytes")
    # The objects were structurally validated above; keep the arguments explicit
    # here so a future caller cannot omit either inventory from this binding lane.
    if not isinstance(qurl_go_inventory, dict) or not isinstance(
        connector_inventory, dict
    ):
        raise AggregateError("client inventories are invalid")

    for name, evidence in (
        ("qurl-go", qurl_go_evidence),
        ("Connector", connector_evidence),
    ):
        _bind_producer_identity(
            evidence.get("deployment_producer"),
            expected=producer,
            name=name,
            include_artifact=True,
        )
        if evidence.get("deployment_manifest_sha256") != producer.get(
            "manifest_sha256"
        ) or evidence.get("deployment_runtime_inputs_sha256") != producer.get(
            "runtime_inputs_sha256"
        ):
            raise AggregateError(
                f"{name} evidence is not bound to the runtime producer files"
            )

    _bind_producer_identity(
        static_nhp_evidence.get("producer"),
        expected=producer,
        name="static NHP",
        include_artifact=False,
    )
    static_bindings = static_nhp_evidence.get("bindings")
    if not isinstance(static_bindings, dict):
        raise AggregateError("static NHP evidence has no deployment bindings")
    expected_static = {
        "deployment_manifest_sha256": producer.get("manifest_sha256"),
        "deployment_provenance_sha256": producer.get("provenance_sha256"),
        "deployment_runtime_inputs_sha256": producer.get("runtime_inputs_sha256"),
    }
    if any(static_bindings.get(key) != value for key, value in expected_static.items()):
        raise AggregateError(
            "static NHP evidence is not bound to the runtime producer files"
        )


def canonical_bytes(value: Any) -> bytes:
    return deployment.canonical_bytes(
        value,
        maximum=MAX_AGGREGATE_BYTES,
        name=ARTIFACT_FILE_NAME,
    )


def _inventory_partitions(qurl_go_inventory: Any) -> dict[str, set[str]]:
    inventory = _exact(
        qurl_go_inventory,
        {
            "all_scenarios_required",
            "gate",
            "proof_phases",
            "scenarios",
            "schema_version",
        },
        "qurl-go inventory",
    )
    if (
        inventory["schema_version"] != 1
        or type(inventory["schema_version"]) is not int
        or inventory["gate"] != GATE
        or inventory["proof_phases"] != ["pre_removal", "post_removal"]
        or inventory["all_scenarios_required"] is not True
        or not isinstance(inventory["scenarios"], list)
        or len(inventory["scenarios"]) != 68
    ):
        raise AggregateError("qurl-go inventory header/count drift")
    partitions = {
        "qurl_go": set(),
        "connector": set(),
        "nhp_orchestrator": set(),
    }
    test_names: set[str] = set()
    for index, raw in enumerate(inventory["scenarios"]):
        row = _exact(
            raw,
            {"id", "owner", "requirement", "status", "test_name"},
            f"qurl-go inventory row {index}",
        )
        owner = {
            "qurl-go": "qurl_go",
            "qurl-connector": "connector",
            "nhp-orchestrator": "nhp_orchestrator",
        }.get(row["owner"])
        if owner not in partitions:
            raise AggregateError(f"qurl-go inventory row {index} has unknown owner")
        scenario_id = row["id"]
        test_name = row["test_name"]
        if (
            not isinstance(scenario_id, str)
            or not scenario_id
            or scenario_id in partitions[owner]
            or not isinstance(test_name, str)
            or not test_name
            or test_name in test_names
        ):
            raise AggregateError(f"qurl-go inventory row {index} is duplicated/invalid")
        partitions[owner].add(scenario_id)
        test_names.add(test_name)
    expected = {
        "qurl_go": set(QURL_GO_ROWS),
        "connector": set(CONNECTOR_ROWS),
        "nhp_orchestrator": set(NHP_ROWS),
    }
    if partitions != expected:
        raise AggregateError("qurl-go inventory does not equal the frozen 46/11/11 set")
    return partitions


def _validate_connector_inventory(value: Any) -> None:
    inventory = _exact(
        value,
        {"all_scenarios_required", "gate", "proof_phases", "scenarios", "schema"},
        "Connector inventory",
    )
    scenarios = inventory["scenarios"]
    if (
        inventory["schema"] != 1
        or type(inventory["schema"]) is not int
        or inventory["gate"] != GATE
        or inventory["proof_phases"] != ["pre_removal", "post_removal"]
        or inventory["all_scenarios_required"] is not True
        or not isinstance(scenarios, list)
        or len(scenarios) != 11
    ):
        raise AggregateError("Connector inventory header/count drift")
    names = {
        row.get("name")
        for row in scenarios
        if isinstance(row, dict) and row.get("status") == "implemented"
    }
    if names != set(CONNECTOR_ROWS):
        raise AggregateError("Connector inventory does not equal its frozen 11 rows")


def _typed_rows(value: Any, name: str) -> dict[str, list[dict[str, Any]]]:
    if not isinstance(value, list):
        raise AggregateError(f"{name} typed evidence must be an array")
    rows: dict[str, list[dict[str, Any]]] = {}
    for index, raw in enumerate(value):
        row = _exact(
            raw,
            {"evidence", "scenario_key"},
            f"{name} typed evidence row {index}",
        )
        key = row["scenario_key"]
        evidence = row["evidence"]
        if (
            not isinstance(key, str)
            or not key
            or key in rows
            or not isinstance(evidence, list)
        ):
            raise AggregateError(f"{name} typed evidence row {index} is invalid")
        kinds: set[str] = set()
        for item_index, raw_item in enumerate(evidence):
            item = _exact(
                raw_item,
                {"kind", "observation", "observation_sha256"},
                f"{name} typed evidence row {index} item {item_index}",
            )
            if (
                not isinstance(item["kind"], str)
                or not item["kind"]
                or item["kind"] in kinds
                or item["observation"] == {"verified": True}
            ):
                raise AggregateError(
                    f"{name} typed evidence row {index} has placeholder/duplicate evidence"
                )
            digest = hashlib.sha256(
                deployment.canonical_bytes(
                    item["observation"],
                    maximum=64 * 1024,
                    name=f"{name} {key} observation",
                )
            ).hexdigest()
            if item["observation_sha256"] != digest:
                raise AggregateError(
                    f"{name} typed evidence row {index} digest is invalid"
                )
            kinds.add(item["kind"])
        rows[key] = evidence
    return rows


def _static_rows(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AggregateError("static NHP evidence must be an object")
    if value.get("gate") != GATE:
        raise AggregateError("static NHP evidence gate drift")
    produced = value.get("produced_rows")
    rows = value.get("rows")
    if (
        produced != list(STATIC_NHP_ROWS)
        or not isinstance(rows, dict)
        or set(rows) != set(STATIC_NHP_ROWS)
    ):
        raise AggregateError("static NHP evidence row set is incomplete")
    return rows


def _runtime_rows(value: Any, proof_phase: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AggregateError("runtime NHP evidence must be an object")
    if value.get("gate") != GATE:
        raise AggregateError("runtime NHP evidence gate drift")
    produced = value.get("produced_rows")
    rows = value.get("rows")
    if (
        produced != list(RUNTIME_NHP_ROWS)
        or not isinstance(rows, dict)
        or set(rows) != set(RUNTIME_NHP_ROWS)
    ):
        raise AggregateError("runtime NHP evidence row set is incomplete")
    for scenario_id, row in rows.items():
        try:
            if scenario_id == "orchestrator.dedicated_linux_fault_runner":
                runtime._validate_runner_row(row, proof_phase)
            else:
                runtime.ROW_VALIDATORS[scenario_id](row, proof_phase)
        except runtime.RuntimeEvidenceError as exc:
            raise AggregateError(str(exc)) from exc
    return rows


def build_aggregate(
    *,
    proof_phase: str,
    qurl_go_inventory: Any,
    connector_inventory: Any,
    qurl_go_evidence: Any,
    connector_evidence: Any,
    static_nhp_evidence: Any,
    runtime_nhp_evidence: Any,
    input_sha256: dict[str, str],
) -> dict[str, Any]:
    """Validate every owner partition and return a compact bound summary."""

    if proof_phase not in {"pre_removal", "post_removal"}:
        raise AggregateError("proof phase is invalid")
    _inventory_partitions(qurl_go_inventory)
    _validate_connector_inventory(connector_inventory)
    qurl_document = qurl_go_evidence
    connector_document = connector_evidence
    if (
        not isinstance(qurl_document, dict)
        or qurl_document.get("phase") != proof_phase
        or not isinstance(connector_document, dict)
        or connector_document.get("phase") != proof_phase
    ):
        raise AggregateError("client evidence phase drift")
    qurl_rows = _typed_rows(qurl_document.get("typed_evidence"), "qurl-go")
    connector_rows = _typed_rows(connector_document.get("typed_evidence"), "Connector")
    expected_qurl_nonempty = set(QURL_GO_ROWS) | set(STATIC_NHP_ROWS)
    if set(qurl_rows) != set(ALL_ROWS):
        raise AggregateError("qurl-go typed evidence does not cover all 68 identities")
    if {
        key for key, evidence in qurl_rows.items() if evidence
    } != expected_qurl_nonempty:
        raise AggregateError(
            "qurl-go artifact must contain exactly 46 owned + 4 static NHP rows"
        )
    if set(connector_rows) != set(CONNECTOR_ROWS) or any(
        not evidence for evidence in connector_rows.values()
    ):
        raise AggregateError("Connector artifact does not prove its exact 11 rows")

    static_rows = _static_rows(static_nhp_evidence)
    _runtime_rows(runtime_nhp_evidence, proof_phase)
    if (
        static_nhp_evidence.get("phase") != proof_phase
        or runtime_nhp_evidence.get("phase") != proof_phase
    ):
        raise AggregateError("NHP evidence phase drift")
    for scenario_id, row in static_rows.items():
        evidence = qurl_rows[scenario_id]
        if len(evidence) != 1:
            raise AggregateError(f"static NHP row {scenario_id} is not singular")
        observation = evidence[0]["observation"]
        row_digest = hashlib.sha256(
            deployment.canonical_bytes(
                row,
                maximum=128 * 1024,
                name=f"static NHP row {scenario_id}",
            )
        ).hexdigest()
        if (
            not isinstance(observation, dict)
            or observation.get("scenario_key") != scenario_id
            or observation.get("producer") != "layervai/nhp"
            or observation.get("row_sha256") != row_digest
        ):
            raise AggregateError(
                f"qurl-go static observation {scenario_id} is not row-bound"
            )

    expected_inputs = {
        "connector_evidence_sha256",
        "connector_inventory_sha256",
        "qurl_go_evidence_sha256",
        "qurl_go_inventory_sha256",
        "runtime_nhp_evidence_sha256",
        "static_nhp_evidence_sha256",
    }
    if set(input_sha256) != expected_inputs:
        raise AggregateError("aggregate input digest set drift")
    for key, value in input_sha256.items():
        _sha256(value, f"aggregate {key}")
    _bind_aggregate_inputs(
        qurl_go_inventory=qurl_go_inventory,
        connector_inventory=connector_inventory,
        qurl_go_evidence=qurl_document,
        connector_evidence=connector_document,
        static_nhp_evidence=static_nhp_evidence,
        runtime_nhp_evidence=runtime_nhp_evidence,
        input_sha256=input_sha256,
    )

    row_sets = {
        "connector": list(CONNECTOR_ROWS),
        "nhp_orchestrator": list(NHP_ROWS),
        "qurl_go": list(QURL_GO_ROWS),
    }
    all_rows_digest = hashlib.sha256(
        deployment.canonical_bytes(
            row_sets,
            maximum=128 * 1024,
            name="aggregate row sets",
        )
    ).hexdigest()
    document = {
        "schema_version": SCHEMA_VERSION,
        "gate": GATE,
        "phase": proof_phase,
        "counts": {
            "connector": len(CONNECTOR_ROWS),
            "nhp_orchestrator": len(NHP_ROWS),
            "qurl_go": len(QURL_GO_ROWS),
            "total": len(ALL_ROWS),
        },
        "bindings": dict(sorted(input_sha256.items())),
        "row_sets": row_sets,
        "all_rows_sha256": all_rows_digest,
    }
    validate_aggregate(document)
    return document


def validate_aggregate(value: Any) -> dict[str, Any]:
    document = _exact(
        value,
        {
            "all_rows_sha256",
            "bindings",
            "counts",
            "gate",
            "phase",
            "row_sets",
            "schema_version",
        },
        "proof aggregate",
    )
    if (
        document["schema_version"] != SCHEMA_VERSION
        or type(document["schema_version"]) is not int
        or document["gate"] != GATE
        or document["phase"] not in {"pre_removal", "post_removal"}
        or document["counts"]
        != {
            "connector": 11,
            "nhp_orchestrator": 11,
            "qurl_go": 46,
            "total": 68,
        }
        or document["row_sets"]
        != {
            "connector": list(CONNECTOR_ROWS),
            "nhp_orchestrator": list(NHP_ROWS),
            "qurl_go": list(QURL_GO_ROWS),
        }
    ):
        raise AggregateError("proof aggregate partition drift")
    expected_digest = hashlib.sha256(
        deployment.canonical_bytes(
            document["row_sets"],
            maximum=128 * 1024,
            name="aggregate row sets",
        )
    ).hexdigest()
    if document["all_rows_sha256"] != expected_digest:
        raise AggregateError("proof aggregate row-set digest drift")
    if not isinstance(document["bindings"], dict) or len(document["bindings"]) != 6:
        raise AggregateError("proof aggregate bindings are incomplete")
    for key, value in document["bindings"].items():
        if not isinstance(key, str) or not key.endswith("_sha256"):
            raise AggregateError("proof aggregate binding identity drift")
        _sha256(value, f"proof aggregate {key}")
    return document
