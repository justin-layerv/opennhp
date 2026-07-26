#!/usr/bin/env python3
"""Pure schema contract for the NHP-side per-scenario proof evidence document.

`deployment-manifest.json` proves *what is deployed*.  This fourth artifact file
proves the orchestrator-owned scenario rows of qurl-go's pre-retirement
inventory -- the rows whose evidence is structurally impossible to produce from
the client, because it lives in NHP's own source, substrate, or authority plane.

Like `udp_proof_deployment_contract`, this module performs no GitHub or AWS I/O.
The trusted-main producer hydrates observations, builds the document below, and
uses this module to fail closed before publishing.  The proof controller imports
the same contract when it revalidates the downloaded producer artifact.

Fail-closed properties enforced here:

* `produced_rows` must equal both the sorted row keys and the frozen
  `PRODUCED_ROWS` tuple, so a producer that cannot observe one row fails the
  whole artifact instead of silently shipping a partial document.
* A row key must be an orchestrator-owned scenario id, and its `kind` must be
  the typed-evidence kind qurl-go's `typed_evidence_contract.json` requires for
  that id.
* The document is bound to one proof run: the producer run identity, the exact
  canonical digests of the sibling artifact files, the deployed source
  revisions those files pin, and a bounded `observed_at`.
"""

from __future__ import annotations

import hashlib
from datetime import datetime
from typing import Any

import udp_proof_deployment_contract as deployment


SCHEMA_VERSION = 1
GATE = "udp_lifecycle_retirement"
ARTIFACT_FILE_NAME = "orchestrator-evidence.json"
MAX_ORCHESTRATOR_EVIDENCE_BYTES = 64 * 1024

# Closed map of every orchestrator-owned scenario in qurl-go's
# `pre_retirement_scenarios.json` to the single typed-evidence kind that
# `typed_evidence_contract.json` requires for it.  A row may only be emitted
# for a key in this map, and only under the kind recorded here.
ORCHESTRATOR_SCENARIO_KINDS = {
    "negative.wrong_caller": "rejection_observation",
    "negative.wrong_source": "rejection_observation",
    "orchestrator.dedicated_linux_fault_runner": "runner_attestation",
    "orchestrator.real_hub_authority_and_two_cells": "topology_observation",
    "retirement.generated_artifact_parity": "surface_inventory",
    "retirement.http_lifecycle_surface_state": "surface_inventory",
    "retirement.nhp_registrar_surface_state": "surface_inventory",
    "retirement.relay_rejects_native_lifecycle_messages": "surface_inventory",
    "retirement.terraform_saved_plan_and_live_state": "surface_inventory",
    "wire.registration_lst_lrt_reg_rak_completion": "wire_trace",
    "wire.session_knk_ack_ext_ack": "wire_trace",
}

# Exactly the rows this producer proves today.  Extending the producer means
# adding a key here *and* a validator in ROW_VALIDATORS; nothing else in the
# pipeline changes.
PRODUCED_ROWS = ("retirement.nhp_registrar_surface_state",)

# `retired_lifecycle_surface.json` in layervai/qurl-go is the human-reviewed,
# digest-pinned contract both sides quote.  These are the two digests the
# reviewed Go literal and the qurl-go proof workflow independently pin: the
# canonical-JSON digest asserted by `reviewedRetiredLifecycleSurfaceSHA256` in
# `retired_lifecycle_surface_test.go`, and the raw-bytes digest the proof
# workflow computes with `sha256sum`.  Binding both means the producer and the
# client cannot be quoting different revisions of the surface contract.
RETIRED_SURFACE_PATH = "tests/e2e/nativeudp/retired_lifecycle_surface.json"
RETIRED_SURFACE_CANONICAL_SHA256 = (
    "3fe8872c3da9913c28d763f5561d82b67805aae5a6962c6dc403c7d6305da00c"
)
RETIRED_SURFACE_RAW_SHA256 = (
    "39fe3deb3c92c5506e8b101b843529099d67ab462d350168122d3732a8adf3eb"
)

# The NHP wire message types `retired_lifecycle_surface.json` retires, with the
# wire values it pins.  The producer re-derives these from the `iota` block of
# the deployed NHP source; this table is what it must match.
RETIRED_MESSAGE_TYPE_WIRE_VALUES = {
    "NHP_LST": 5,
    "NHP_LRT": 6,
    "NHP_OTP": 12,
    "NHP_REG": 13,
    "NHP_RAK": 14,
}
MESSAGE_TYPE_SOURCE_PATH = "nhp/core/packet.go"

# The internal HTTP operations qurl-go's surface contract retires.  NHP's legacy
# registrar (`endpoints/server/staticplugins/agent/registrar.go`) is the *client*
# of exactly these two operations, which is why NHP can attest their retirement
# and the client cannot.
RETIRED_INTERNAL_HTTP_OPERATIONS = (
    {"method": "POST", "path": "/internal/v1/agent/otp"},
    {"method": "POST", "path": "/internal/v1/agent/register"},
)

MAX_SURFACE_ENTRIES = 64
# `state` describes only whether the reviewed declaration exists in the deployed
# blob. Whether a still-deployed entry point can actually do lifecycle work is a
# separate axis (`dispatches_lifecycle_work`), decided by its fail-closed fence.
# There is deliberately no "compatibility_stub" state: no such stub exists yet,
# and admitting a state the observer cannot derive would let a row pass on a
# value nothing produces.
SURFACE_STATES = frozenset({"present", "absent"})
SURFACE_ROLES = frozenset({"legacy_registrar", "native_runtime"})


class OrchestratorContractError(deployment.ContractError):
    """One orchestrator evidence value violates the frozen contract."""


def _exact(value: Any, keys: set[str], name: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise OrchestratorContractError(f"{name} must contain exactly {sorted(keys)}")
    return value


def _sha256(value: Any, name: str) -> str:
    if not isinstance(value, str) or not deployment.SHA256_RE.fullmatch(value):
        raise OrchestratorContractError(f"{name} must be a lowercase SHA-256")
    return value


def _sha(value: Any, name: str) -> str:
    if not isinstance(value, str) or not deployment.SHA_RE.fullmatch(value):
        raise OrchestratorContractError(f"{name} must be a lowercase commit SHA")
    return value


def _string(
    value: Any, name: str, *, maximum: int = deployment.MAX_LABEL_LENGTH
) -> str:
    try:
        return deployment._string(value, name, maximum=maximum)
    except deployment.ContractError as exc:
        raise OrchestratorContractError(str(exc)) from exc


def _repository_path(value: Any, name: str) -> str:
    path = _string(value, name, maximum=512)
    if (
        path != path.strip()
        or path.startswith("/")
        or path.endswith("/")
        or ".." in path.split("/")
        or "//" in path
        or "\\" in path
    ):
        raise OrchestratorContractError(f"{name} must be a clean relative repo path")
    return path


def _bool(value: Any, name: str) -> bool:
    if type(value) is not bool:
        raise OrchestratorContractError(f"{name} must be a JSON boolean")
    return value


def canonical_bytes(value: Any) -> bytes:
    return deployment.canonical_bytes(
        value,
        maximum=MAX_ORCHESTRATOR_EVIDENCE_BYTES,
        name=ARTIFACT_FILE_NAME,
    )


def _validate_interface(
    entry: Any,
    name: str,
    *,
    proof_phase: str,
) -> dict[str, Any]:
    item = _exact(
        entry,
        {
            "symbol",
            "path",
            "path_sha256",
            "role",
            "state",
            "lifecycle_message_types",
            "dispatches_lifecycle_work",
        },
        name,
    )
    _string(item["symbol"], f"{name}.symbol")
    _repository_path(item["path"], f"{name}.path")
    _sha256(item["path_sha256"], f"{name}.path_sha256")
    role = item["role"]
    if role not in SURFACE_ROLES:
        raise OrchestratorContractError(f"{name}.role is not an allowed role")
    state = item["state"]
    if state not in SURFACE_STATES:
        raise OrchestratorContractError(f"{name}.state is not an allowed state")
    types = item["lifecycle_message_types"]
    if (
        not isinstance(types, list)
        or not types
        or types != sorted(types)
        or len(types) != len(set(types))
        or any(entry_type not in RETIRED_MESSAGE_TYPE_WIRE_VALUES for entry_type in types)
    ):
        raise OrchestratorContractError(
            f"{name}.lifecycle_message_types must be a sorted unique non-empty "
            "subset of the retired lifecycle message types"
        )
    dispatches = _bool(
        item["dispatches_lifecycle_work"], f"{name}.dispatches_lifecycle_work"
    )

    # Phase semantics, straight from the scenario requirement.
    #
    #   pre_removal  -- "the exact legacy NHP registrar/runtime interfaces
    #                    remain deployed but unused"
    #   post_removal -- "their implementation is absent and every required
    #                    compatibility stub fails closed without dispatching
    #                    lifecycle work"
    #
    # `native_runtime` entries are the direct-UDP lifecycle NHP keeps. They are
    # the control group: the row fails if they ever stop being present and
    # dispatching, so "the observer saw nothing" cannot pass the scenario.
    if role == "native_runtime":
        if state != "present" or not dispatches:
            raise OrchestratorContractError(
                f"{name} is the retained native runtime and must stay present "
                "and dispatching in both phases"
            )
        return item
    # A legacy entry point must never dispatch lifecycle work in either phase.
    # Before removal that is what "deployed but unused" means; after removal it
    # is what "every required compatibility stub fails closed" means.
    if dispatches:
        raise OrchestratorContractError(
            f"{name} legacy registrar still dispatches lifecycle work"
        )
    if proof_phase == "pre_removal":
        if state != "present":
            raise OrchestratorContractError(
                f"{name} legacy registrar must still be deployed in pre_removal"
            )
        return item
    if state != "absent":
        raise OrchestratorContractError(
            f"{name} legacy registrar implementation is still present in "
            "post_removal"
        )
    return item


def _validate_nhp_registrar_surface(
    value: Any,
    *,
    proof_phase: str,
    nhp_source_sha: str,
) -> dict[str, Any]:
    """Validate the deployed-NHP legacy registrar/runtime surface row.

    The row is derived from the exact NHP source revision the deployment
    manifest pins, which the deployment collector already cross-checked against
    the OCI revision labels of the running Hub and cell containers.  "Deployed"
    is therefore established by the manifest, not asserted here.
    """

    row = _exact(
        value,
        {
            "kind",
            "surface",
            "phase",
            "source_repository",
            "source_sha",
            "message_type_source_path",
            "message_type_source_sha256",
            "retired_message_type_wire_values",
            "retired_internal_http_operations",
            "interfaces",
            "interfaces_sha256",
        },
        "nhp registrar surface row",
    )
    expected_kind = ORCHESTRATOR_SCENARIO_KINDS["retirement.nhp_registrar_surface_state"]
    if row["kind"] != expected_kind:
        raise OrchestratorContractError("nhp registrar surface row kind drift")
    if row["surface"] != "nhp_registrar":
        raise OrchestratorContractError("nhp registrar surface row identity drift")
    if row["phase"] != proof_phase:
        raise OrchestratorContractError("nhp registrar surface row phase drift")
    if row["source_repository"] != "layervai/nhp":
        raise OrchestratorContractError("nhp registrar surface row repository drift")
    if _sha(row["source_sha"], "nhp registrar source_sha") != nhp_source_sha:
        raise OrchestratorContractError(
            "nhp registrar surface row is not the deployed NHP revision"
        )
    if row["message_type_source_path"] != MESSAGE_TYPE_SOURCE_PATH:
        raise OrchestratorContractError("nhp registrar message-type source drift")
    _sha256(
        row["message_type_source_sha256"],
        "nhp registrar message_type_source_sha256",
    )

    wire_values = _exact(
        row["retired_message_type_wire_values"],
        set(RETIRED_MESSAGE_TYPE_WIRE_VALUES),
        "nhp registrar retired_message_type_wire_values",
    )
    for message_type, expected in RETIRED_MESSAGE_TYPE_WIRE_VALUES.items():
        observed = wire_values[message_type]
        if type(observed) is not int or observed != expected:
            raise OrchestratorContractError(
                f"deployed NHP wire value for {message_type} differs from the "
                "reviewed retired lifecycle surface contract"
            )

    operations = row["retired_internal_http_operations"]
    if not isinstance(operations, list) or len(operations) != len(
        RETIRED_INTERNAL_HTTP_OPERATIONS
    ):
        raise OrchestratorContractError(
            "nhp registrar retired_internal_http_operations must list exactly "
            "the retired internal operations"
        )
    for index, operation in enumerate(operations):
        _exact(
            operation,
            {"method", "path"},
            f"nhp registrar retired_internal_http_operations[{index}]",
        )
        if operation != RETIRED_INTERNAL_HTTP_OPERATIONS[index]:
            raise OrchestratorContractError(
                "nhp registrar retired internal HTTP operation drift at index "
                f"{index}"
            )

    interfaces = row["interfaces"]
    if (
        not isinstance(interfaces, list)
        or not interfaces
        or len(interfaces) > MAX_SURFACE_ENTRIES
    ):
        raise OrchestratorContractError(
            f"nhp registrar interfaces must be a 1..{MAX_SURFACE_ENTRIES} list"
        )
    seen: set[tuple[str, str]] = set()
    normalized: list[dict[str, Any]] = []
    for index, entry in enumerate(interfaces):
        item = _validate_interface(
            entry,
            f"nhp registrar interfaces[{index}]",
            proof_phase=proof_phase,
        )
        identity = (item["path"], item["symbol"])
        if identity in seen:
            raise OrchestratorContractError(
                f"nhp registrar interfaces[{index}] duplicates an earlier entry"
            )
        seen.add(identity)
        normalized.append(item)

    roles = {item["role"] for item in normalized}
    if roles != SURFACE_ROLES:
        raise OrchestratorContractError(
            "nhp registrar interfaces must cover both the legacy registrar and "
            "the retained native runtime"
        )
    for role in sorted(SURFACE_ROLES):
        covered = {
            message_type
            for item in normalized
            if item["role"] == role
            for message_type in item["lifecycle_message_types"]
        }
        if covered != set(RETIRED_MESSAGE_TYPE_WIRE_VALUES):
            raise OrchestratorContractError(
                f"nhp registrar {role} interfaces must cover every retired "
                "lifecycle message type"
            )

    expected_digest = hashlib.sha256(
        deployment.canonical_bytes(
            normalized,
            maximum=MAX_ORCHESTRATOR_EVIDENCE_BYTES,
            name="nhp registrar interfaces",
        )
    ).hexdigest()
    observed_digest = _sha256(
        row["interfaces_sha256"], "nhp registrar interfaces_sha256"
    )
    if observed_digest != expected_digest:
        raise OrchestratorContractError("nhp registrar interfaces_sha256 is wrong")
    return row


ROW_VALIDATORS = {
    "retirement.nhp_registrar_surface_state": _validate_nhp_registrar_surface,
}


def validate_orchestrator_evidence(
    value: Any,
    *,
    manifest: dict[str, Any],
    manifest_bytes: bytes,
    runtime_bytes: bytes,
    proof_phase: str,
    producer_run_id: int,
    producer_run_attempt: int,
    producer_head_sha: str,
    validation_time: datetime,
) -> dict[str, Any]:
    """Validate the orchestrator evidence document against one proof run."""

    if proof_phase not in {"pre_removal", "post_removal"}:
        raise OrchestratorContractError(
            "proof_phase must be pre_removal or post_removal"
        )

    document = _exact(
        value,
        {
            "schema_version",
            "gate",
            "phase",
            "observed_at",
            "producer",
            "bindings",
            "produced_rows",
            "rows",
        },
        "orchestrator evidence",
    )
    version = document["schema_version"]
    if version != SCHEMA_VERSION or type(version) is not int:
        raise OrchestratorContractError(
            "orchestrator evidence schema_version must be 1"
        )
    if document["gate"] != GATE:
        raise OrchestratorContractError("orchestrator evidence gate drift")
    if document["phase"] != proof_phase:
        raise OrchestratorContractError(
            "orchestrator evidence phase differs from the proof phase"
        )

    try:
        observed_at = deployment._timestamp(
            document["observed_at"], "orchestrator evidence observed_at"
        )
        validated_at = deployment._utc_time(
            validation_time, "orchestrator evidence validation_time"
        )
    except deployment.ContractError as exc:
        raise OrchestratorContractError(str(exc)) from exc
    if (
        observed_at > validated_at + deployment.MAX_CLOCK_SKEW
        or validated_at - observed_at > deployment.MAX_PROVENANCE_AGE
    ):
        raise OrchestratorContractError(
            "orchestrator evidence must be no more than 10 minutes old"
        )

    producer = _exact(
        document["producer"],
        {"repository", "workflow_path", "run_id", "run_attempt", "head_sha"},
        "orchestrator evidence producer",
    )
    if producer != {
        "repository": "layervai/nhp",
        "workflow_path": ".github/workflows/udp-proof-deployment-manifest.yml",
        "run_id": producer_run_id,
        "run_attempt": producer_run_attempt,
        "head_sha": producer_head_sha,
    }:
        raise OrchestratorContractError(
            "orchestrator evidence producer identity drift"
        )
    try:
        deployment._positive_int(producer_run_id, "producer run_id")
        deployment._positive_int(producer_run_attempt, "producer run_attempt")
        deployment._sha(producer_head_sha, "producer head_sha")
    except deployment.ContractError as exc:
        raise OrchestratorContractError(str(exc)) from exc

    bindings = _exact(
        document["bindings"],
        {
            "deployment_manifest_sha256",
            "deployment_runtime_inputs_sha256",
            "nhp_source_sha",
            "qurl_go_source_sha",
            "retired_lifecycle_surface_path",
            "retired_lifecycle_surface_raw_sha256",
            "retired_lifecycle_surface_canonical_sha256",
        },
        "orchestrator evidence bindings",
    )
    if (
        _sha256(
            bindings["deployment_manifest_sha256"],
            "bindings.deployment_manifest_sha256",
        )
        != hashlib.sha256(manifest_bytes).hexdigest()
        or _sha256(
            bindings["deployment_runtime_inputs_sha256"],
            "bindings.deployment_runtime_inputs_sha256",
        )
        != hashlib.sha256(runtime_bytes).hexdigest()
    ):
        raise OrchestratorContractError(
            "orchestrator evidence is not bound to this artifact's manifest files"
        )
    repositories = manifest.get("repositories")
    if not isinstance(repositories, dict):
        raise OrchestratorContractError("deployment manifest has no repository pins")
    nhp_source_sha = _sha(bindings["nhp_source_sha"], "bindings.nhp_source_sha")
    if nhp_source_sha != repositories.get("nhp"):
        raise OrchestratorContractError(
            "orchestrator evidence NHP revision differs from the deployment manifest"
        )
    if _sha(
        bindings["qurl_go_source_sha"], "bindings.qurl_go_source_sha"
    ) != repositories.get("qurl_go"):
        raise OrchestratorContractError(
            "orchestrator evidence qurl-go revision differs from the deployment "
            "manifest"
        )
    if (
        bindings["retired_lifecycle_surface_path"] != RETIRED_SURFACE_PATH
        or _sha256(
            bindings["retired_lifecycle_surface_raw_sha256"],
            "bindings.retired_lifecycle_surface_raw_sha256",
        )
        != RETIRED_SURFACE_RAW_SHA256
        or _sha256(
            bindings["retired_lifecycle_surface_canonical_sha256"],
            "bindings.retired_lifecycle_surface_canonical_sha256",
        )
        != RETIRED_SURFACE_CANONICAL_SHA256
    ):
        raise OrchestratorContractError(
            "orchestrator evidence is not bound to the reviewed retired "
            "lifecycle surface contract"
        )

    rows = document["rows"]
    if not isinstance(rows, dict) or not rows:
        raise OrchestratorContractError(
            "orchestrator evidence rows must be a non-empty object"
        )
    produced = document["produced_rows"]
    if (
        not isinstance(produced, list)
        or produced != sorted(rows)
        or tuple(produced) != tuple(sorted(PRODUCED_ROWS))
    ):
        raise OrchestratorContractError(
            "orchestrator evidence must produce exactly the frozen row set "
            f"{sorted(PRODUCED_ROWS)}"
        )
    for scenario_id in produced:
        if scenario_id not in ORCHESTRATOR_SCENARIO_KINDS:
            raise OrchestratorContractError(
                f"{scenario_id} is not an orchestrator-owned scenario"
            )
        validator = ROW_VALIDATORS.get(scenario_id)
        if validator is None:
            raise OrchestratorContractError(f"{scenario_id} has no row validator")
        rows[scenario_id] = validator(
            rows[scenario_id],
            proof_phase=proof_phase,
            nhp_source_sha=nhp_source_sha,
        )
    return document


def validate_orchestrator_bytes(
    raw: bytes,
    *,
    manifest: dict[str, Any],
    manifest_bytes: bytes,
    runtime_bytes: bytes,
    proof_phase: str,
    producer_run_id: int,
    producer_run_attempt: int,
    producer_head_sha: str,
    validation_time: datetime,
) -> dict[str, Any]:
    """Parse canonical bytes then validate them, for the controller side."""

    try:
        value = deployment.parse_canonical_bytes(
            raw,
            maximum=MAX_ORCHESTRATOR_EVIDENCE_BYTES,
            name=ARTIFACT_FILE_NAME,
        )
    except deployment.ContractError as exc:
        raise OrchestratorContractError(str(exc)) from exc
    return validate_orchestrator_evidence(
        value,
        manifest=manifest,
        manifest_bytes=manifest_bytes,
        runtime_bytes=runtime_bytes,
        proof_phase=proof_phase,
        producer_run_id=producer_run_id,
        producer_run_attempt=producer_run_attempt,
        producer_head_sha=producer_head_sha,
        validation_time=validation_time,
    )
