#!/usr/bin/env python3
"""Authenticate and validate one attended UDP client proof artifact.

The controller uses metadata mode to bind the completed workflow run to one
immutable artifact, archive mode to reject unsafe or ambiguous ZIP contents,
and files mode to reconcile the client's canonical evidence with the exact
producer snapshot and controller dispatch.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import re
import stat
import zipfile
from pathlib import Path
from typing import Any

import udp_proof_deployment_contract as deployment
import udp_proof_runtime_probe_contract as runtime_probe
import udp_proof_retirement_targets_contract as retirement_targets


MAX_CLIENT_ARTIFACT_BYTES = 5 * 1024 * 1024
MAX_EVIDENCE_BYTES = 4 * 1024 * 1024
MAX_INVENTORY_BYTES = 256 * 1024
MAX_RETIRED_SURFACE_BYTES = 64 * 1024
MAX_TYPED_EVIDENCE_CONTRACT_BYTES = 256 * 1024
RAW_PINNED_JSON_FILES = {
    "typed-evidence-contract.json",
    "typed_evidence_contract.json",
}
RUN_ID_RE = re.compile(r"^[1-9][0-9]{0,19}$")
QURL_GO_CANONICAL_INVENTORY_SHA256 = (
    "0bbe6cbddaea32f9b3079798235161547ce7c9dccd4d6b793c5f9d3e235958c3"
)
QURL_GO_TYPED_EVIDENCE_CONTRACT_SHA256 = (
    "f4b37aceb2dd55f2c1cf6d7ec4e955cfeb69297ff6151b565935d03d01f65d08"
)
CONNECTOR_TYPED_EVIDENCE_CONTRACT_SHA256 = (
    "c5274f926584451201a992ef551549ecffbaf89e58ba0a5fb206732f1fa55d74"
)
CONNECTOR_CANONICAL_SCENARIOS = {
    "connector.complete_strict_evidence_attestation": (
        "TestSandboxConnectorUDP/complete_strict_evidence_attestation"
    ),
    "connector.dns_key_destination_source_observations": (
        "TestSandboxConnectorUDP/network_observations"
    ),
    "connector.exact_artifact_manifest": (
        "TestSandboxConnectorUDP/exact_artifact_manifest"
    ),
    "connector.frp_authenticated_login_before_proxy": (
        "TestSandboxConnectorUDP/frp_authenticated_login_before_proxy"
    ),
    "connector.hardened_linux_container": (
        "TestSandboxConnectorUDP/hardened_linux_container"
    ),
    "connector.provision_journal_crash_consistency": (
        "TestSandboxConnectorUDP/provision_journal_crash_consistency"
    ),
    "connector.real_backend_traffic": ("TestSandboxConnectorUDP/real_backend_traffic"),
    "connector.remove_journal_crash_consistency": (
        "TestSandboxConnectorUDP/remove_journal_crash_consistency"
    ),
    "connector.resource_id_distinct_from_knock_resource_id": (
        "TestSandboxConnectorUDP/resource_and_knock_identity_distinct"
    ),
    "connector.sealed_restart_without_setup_mount": (
        "TestSandboxConnectorUDP/sealed_restart_without_setup_mount"
    ),
    "connector.zero_http_network_capture": (
        "TestSandboxConnectorUDP/zero_lifecycle_http_packet_capture"
    ),
}
STATIC_NHP_SCENARIOS = {
    "orchestrator.real_hub_authority_and_two_cells",
    "retirement.generated_artifact_parity",
    "retirement.nhp_registrar_surface_state",
    "retirement.terraform_saved_plan_and_live_state",
}

CLIENTS = {
    "connector": {
        "repository": "layervai/qurl-connector",
        "workflow_path": ".github/workflows/sandbox-smoke.yml",
        "artifact_prefix": "strict-sandbox-proof",
        "files": {
            "deployment-runtime-inputs.json": deployment.MAX_RUNTIME_BYTES,
            "sandbox-deployment-manifest.json": deployment.MAX_MANIFEST_BYTES,
            "strict-typed-evidence.json": MAX_EVIDENCE_BYTES,
            "strict-proof-scenarios.json": MAX_INVENTORY_BYTES,
            "strict-sandbox-proof.evidence.json": MAX_EVIDENCE_BYTES,
            "typed-evidence-contract.json": MAX_TYPED_EVIDENCE_CONTRACT_BYTES,
        },
        "evidence_file": "strict-sandbox-proof.evidence.json",
    },
    "qurl_go": {
        "repository": "layervai/qurl-go",
        "workflow_path": ".github/workflows/native-udp-sandbox.yml",
        "artifact_prefix": "native-udp-sandbox",
        "files": {
            "deployment-runtime-inputs.json": deployment.MAX_RUNTIME_BYTES,
            "native-udp-sandbox.evidence.json": MAX_EVIDENCE_BYTES,
            "pre_retirement_scenarios.json": MAX_INVENTORY_BYTES,
            "retired_lifecycle_surface.json": MAX_RETIRED_SURFACE_BYTES,
            runtime_probe.ARTIFACT_FILE_NAME: runtime_probe.MAX_ARTIFACT_BYTES,
            "sandbox-deployment-manifest.json": deployment.MAX_MANIFEST_BYTES,
            "typed_evidence_contract.json": MAX_TYPED_EVIDENCE_CONTRACT_BYTES,
        },
        "evidence_file": "native-udp-sandbox.evidence.json",
    },
}

COMMON_EVIDENCE_KEYS = {
    "commit_sha",
    "counts",
    "deployment_manifest_sha256",
    "deployment_producer",
    "deployment_runtime_inputs_sha256",
    "dispatch_correlation_id",
    "enforcement_outcome",
    "gate_passed",
    "inputs_unchanged",
    "inventory_sha256",
    "nhp_controller_run_attempt",
    "nhp_controller_run_id",
    "phase",
    "pre_removal_deployment_sha256",
    "pre_removal_evidence_sha256",
    "pre_removal_run_id",
    "proof_harness_sha256",
    "provenance",
    "provenance_valid",
    "repository",
    "run_attempt",
    "run_id",
    "scenario_contract_sha256",
    "scenario_results",
    "schema_version",
    "two_cell_provenance",
    "typed_evidence",
    "typed_evidence_complete",
    "typed_evidence_contract_sha256",
}
CONNECTOR_EVIDENCE_KEYS = COMMON_EVIDENCE_KEYS | {
    "input_outcome",
    "scenario_attestation",
}
QURL_GO_EVIDENCE_KEYS = COMMON_EVIDENCE_KEYS | {
    "inventory_mapping_sha256",
    "retired_lifecycle_surface_sha256",
    "strict_outcome",
}


class ClientArtifactError(ValueError):
    """A completed client result is not the exact dispatched proof."""


def _client(client: str) -> dict[str, Any]:
    if client not in CLIENTS:
        raise ClientArtifactError("client must be connector or qurl_go")
    return CLIENTS[client]


def _positive_int_string(value: str, name: str) -> int:
    if not isinstance(value, str) or not RUN_ID_RE.fullmatch(value):
        raise ClientArtifactError(f"{name} must be a positive integer")
    return int(value)


def _required_object(value: Any, required: set[str], name: str) -> dict[str, Any]:
    if not isinstance(value, dict) or not required.issubset(value):
        raise ClientArtifactError(f"{name} is missing required fields")
    return value


def _exact_object(value: Any, keys: set[str], name: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise ClientArtifactError(f"{name} must contain exactly {sorted(keys)}")
    return value


def _sha(value: Any, name: str) -> str:
    if not isinstance(value, str) or not deployment.SHA_RE.fullmatch(value):
        raise ClientArtifactError(f"{name} must be a lowercase Git SHA")
    return value


def _sha256(value: Any, name: str) -> str:
    if not isinstance(value, str) or not deployment.SHA256_RE.fullmatch(value):
        raise ClientArtifactError(f"{name} must be a lowercase SHA-256")
    return value


def _digest(value: Any, name: str) -> str:
    if not isinstance(value, str) or not deployment.DIGEST_RE.fullmatch(value):
        raise ClientArtifactError(f"{name} must be a lowercase sha256 digest")
    return value


def _load_json(path: Path) -> Any:
    try:
        return json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=deployment._reject_duplicate_keys,
            parse_constant=deployment._reject_nonfinite,
            parse_float=deployment._parse_finite_float,
        )
    except (
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        deployment.ContractError,
    ) as exc:
        raise ClientArtifactError(f"could not read JSON input {path}") from exc


def validate_metadata(
    run: Any,
    artifacts_response: Any,
    *,
    client: str,
    proof_phase: str,
    client_run_id: str,
    client_repository: str,
    client_ref: str,
    client_sha: str,
    client_run_title: str,
) -> dict[str, str]:
    """Bind the exact completed candidate run to one current-attempt artifact."""

    target = _client(client)
    run_id = _positive_int_string(client_run_id, "client run ID")
    if proof_phase not in {"pre_removal", "post_removal"}:
        raise ClientArtifactError("proof phase must be pre_removal or post_removal")
    _sha(client_sha, "client SHA")
    if client_repository != target["repository"]:
        raise ClientArtifactError("client repository does not match client")

    run_object = _required_object(
        run,
        {
            "id",
            "run_attempt",
            "repository",
            "head_repository",
            "path",
            "event",
            "status",
            "conclusion",
            "head_branch",
            "head_sha",
            "display_title",
        },
        "client run",
    )
    repository = _required_object(
        run_object["repository"], {"id", "full_name"}, "client repository"
    )
    head_repository = _required_object(
        run_object["head_repository"],
        {"id", "full_name"},
        "client head repository",
    )
    repository_id = repository["id"]
    if (
        type(repository_id) is not int
        or repository_id <= 0
        or type(head_repository["id"]) is not int
        or type(run_object["id"]) is not int
        or type(run_object["run_attempt"]) is not int
    ):
        raise ClientArtifactError("client repository id must be a positive integer")
    if (
        head_repository["id"] != repository_id
        or head_repository["full_name"] != client_repository
    ):
        raise ClientArtifactError(
            "client head repository differs from the authenticated repository"
        )
    expected_run = {
        "id": run_id,
        "run_attempt": 1,
        "repository": client_repository,
        "workflow_path": target["workflow_path"],
        "event": "workflow_dispatch",
        "status": "completed",
        "conclusion": "success",
        "head_branch": client_ref,
        "head_sha": client_sha,
        "display_title": client_run_title,
    }
    normalized_run = {
        "id": run_object["id"],
        "run_attempt": run_object["run_attempt"],
        "repository": repository["full_name"],
        "workflow_path": run_object["path"],
        "event": run_object["event"],
        "status": run_object["status"],
        "conclusion": run_object["conclusion"],
        "head_branch": run_object["head_branch"],
        "head_sha": run_object["head_sha"],
        "display_title": run_object["display_title"],
    }
    if normalized_run != expected_run:
        raise ClientArtifactError("client workflow run identity drift")

    envelope = _required_object(
        artifacts_response, {"total_count", "artifacts"}, "client artifacts response"
    )
    artifacts = envelope["artifacts"]
    if (
        type(envelope["total_count"]) is not int
        or not isinstance(artifacts, list)
        or envelope["total_count"] != len(artifacts)
        or not 1 <= len(artifacts) <= 100
    ):
        raise ClientArtifactError(
            "client artifact response must contain the complete bounded 1..100 list"
        )
    expected_name = (
        f"{target['artifact_prefix']}-{proof_phase}-{client_sha}-"
        f"{run_object['run_attempt']}"
    )
    matches: list[dict[str, Any]] = []
    for index, raw in enumerate(artifacts):
        artifact = _required_object(
            raw,
            {
                "id",
                "name",
                "digest",
                "size_in_bytes",
                "expired",
                "workflow_run",
            },
            f"client artifact {index}",
        )
        artifact_run = _required_object(
            artifact["workflow_run"],
            {
                "id",
                "repository_id",
                "head_repository_id",
                "head_branch",
                "head_sha",
            },
            f"client artifact {index} workflow run",
        )
        if (
            type(artifact_run["id"]) is not int
            or type(artifact_run["repository_id"]) is not int
            or type(artifact_run["head_repository_id"]) is not int
            or artifact_run["id"] != run_id
            or artifact_run["repository_id"] != repository_id
            or artifact_run["head_repository_id"] != repository_id
            or artifact_run["head_branch"] != client_ref
            or artifact_run["head_sha"] != client_sha
        ):
            raise ClientArtifactError(
                f"client artifact {index} does not belong to the exact candidate run"
            )
        if (
            type(artifact["id"]) is not int
            or artifact["id"] <= 0
            or not isinstance(artifact["name"], str)
            or not artifact["name"]
            or type(artifact["size_in_bytes"]) is not int
            or not 1 <= artifact["size_in_bytes"] <= MAX_CLIENT_ARTIFACT_BYTES
            or not isinstance(artifact["expired"], bool)
        ):
            raise ClientArtifactError(
                f"client artifact {index} has invalid bounded metadata"
            )
        _digest(artifact["digest"], f"client artifact {index} digest")
        if artifact["name"] == expected_name:
            matches.append(artifact)
    if len(matches) != 1 or matches[0]["expired"]:
        raise ClientArtifactError(
            "expected exactly one unexpired exact client proof artifact"
        )
    selected = matches[0]
    return {
        "client_artifact_id": str(selected["id"]),
        "client_artifact_name": selected["name"],
        "client_artifact_digest": selected["digest"],
        "client_run_attempt": str(run_object["run_attempt"]),
    }


def extract_archive(
    archive: Path,
    directory: Path,
    *,
    client: str,
    expected_digest: str,
) -> None:
    """Verify and safely extract exactly the client's allowlisted root files."""

    target = _client(client)
    _digest(expected_digest, "client artifact digest")
    try:
        metadata = archive.lstat()
        raw_size = metadata.st_size
    except OSError as exc:
        raise ClientArtifactError("cannot read client artifact archive") from exc
    if (
        archive.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or not 1 <= raw_size <= MAX_CLIENT_ARTIFACT_BYTES
    ):
        raise ClientArtifactError("client artifact archive is not a bounded file")
    actual_digest = "sha256:" + hashlib.sha256(archive.read_bytes()).hexdigest()
    if actual_digest != expected_digest:
        raise ClientArtifactError("client artifact archive digest mismatch")
    if directory.exists() or directory.is_symlink():
        raise ClientArtifactError("client artifact destination already exists")

    expected_files: dict[str, int] = target["files"]
    try:
        with zipfile.ZipFile(archive) as bundle:
            entries = bundle.infolist()
            names = [entry.filename for entry in entries]
            if (
                len(entries) != len(expected_files)
                or len(names) != len(set(names))
                or set(names) != set(expected_files)
            ):
                raise ClientArtifactError(
                    "client artifact must contain exactly the allowlisted files once"
                )
            total_expanded = 0
            for entry in entries:
                mode = entry.external_attr >> 16
                limit = expected_files[entry.filename]
                if (
                    entry.is_dir()
                    or "/" in entry.filename
                    or "\\" in entry.filename
                    or stat.S_ISLNK(mode)
                    or (stat.S_IFMT(mode) not in {0, stat.S_IFREG})
                    or entry.flag_bits & 0x1
                    or not 1 <= entry.file_size <= limit
                    or entry.compress_size > MAX_CLIENT_ARTIFACT_BYTES
                ):
                    raise ClientArtifactError(
                        f"unsafe or oversized client artifact entry: {entry.filename}"
                    )
                total_expanded += entry.file_size
            if total_expanded > MAX_CLIENT_ARTIFACT_BYTES:
                raise ClientArtifactError(
                    "client artifact expanded size exceeds the bound"
                )

            directory.mkdir(mode=0o700)
            for entry in entries:
                body = bundle.read(entry)
                if len(body) != entry.file_size:
                    raise ClientArtifactError(
                        f"client artifact entry size drift: {entry.filename}"
                    )
                descriptor = os.open(
                    directory / entry.filename,
                    os.O_CREAT | os.O_EXCL | os.O_WRONLY,
                    0o600,
                )
                with os.fdopen(descriptor, "wb") as handle:
                    handle.write(body)
    except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
        raise ClientArtifactError("could not safely extract client artifact") from exc


def _nonempty_string(value: Any, name: str, *, maximum: int = 4096) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > maximum
    ):
        raise ClientArtifactError(f"{name} must be a bounded non-empty string")
    return value


def _validate_counts(
    value: Any,
    *,
    expected_keys: set[str],
    expected: dict[str, int],
) -> None:
    counts = _exact_object(value, expected_keys, "client evidence counts")
    for name, count in counts.items():
        if type(count) is not int or count < 0:
            raise ClientArtifactError(f"client evidence counts.{name} is invalid")
    if counts != expected:
        raise ClientArtifactError(
            "client evidence counts do not match the canonical inventory"
        )


def _validate_connector_inventory(value: Any) -> dict[str, Any]:
    inventory = _exact_object(
        value,
        {"schema", "gate", "proof_phases", "all_scenarios_required", "scenarios"},
        "Connector scenario inventory",
    )
    if (
        inventory["schema"] != 1
        or inventory["gate"] != "udp_lifecycle_retirement"
        or inventory["proof_phases"] != ["pre_removal", "post_removal"]
        or inventory["all_scenarios_required"] is not True
        or not isinstance(inventory["scenarios"], list)
        or not inventory["scenarios"]
    ):
        raise ClientArtifactError("Connector scenario inventory header is invalid")
    scenarios: list[dict[str, Any]] = []
    names: set[str] = set()
    tests: set[str] = set()
    for index, raw in enumerate(inventory["scenarios"]):
        scenario = _exact_object(
            raw,
            {"name", "status", "test", "requires_env", "reason"},
            f"Connector scenario {index}",
        )
        name = scenario["name"]
        test_name = scenario["test"]
        required_env = scenario["requires_env"]
        if (
            not isinstance(name, str)
            or re.fullmatch(r"[a-z0-9]+(?:[._-][a-z0-9]+)*", name) is None
            or name in names
            or scenario["status"] != "implemented"
            or not isinstance(test_name, str)
            or re.fullmatch(r"Test[A-Za-z0-9_]+(?:/[a-z0-9_]+)*", test_name) is None
            or test_name in tests
            or not isinstance(required_env, list)
            or any(
                not isinstance(item, str)
                or re.fullmatch(r"[A-Z][A-Z0-9_]{0,127}", item) is None
                for item in required_env
            )
            or len(required_env) != len(set(required_env))
        ):
            raise ClientArtifactError(
                f"Connector scenario {index} is not one unique implemented row"
            )
        _nonempty_string(scenario["reason"], f"Connector scenario {index}.reason")
        names.add(name)
        tests.add(test_name)
        scenarios.append(scenario)
    observed = {scenario["name"]: scenario["test"] for scenario in scenarios}
    if observed != CONNECTOR_CANONICAL_SCENARIOS:
        raise ClientArtifactError(
            "Connector inventory does not match the frozen canonical scenario set"
        )
    return {
        "implemented": len(scenarios),
        "blocking": 0,
        "scenario_keys": names,
        "test_names": tests,
        "scenarios": scenarios,
    }


def _validate_qurl_go_inventory(value: Any) -> dict[str, Any]:
    inventory = _exact_object(
        value,
        {
            "schema_version",
            "gate",
            "proof_phases",
            "all_scenarios_required",
            "scenarios",
        },
        "qurl-go scenario inventory",
    )
    if (
        inventory["schema_version"] != 1
        or inventory["gate"] != "udp_lifecycle_retirement"
        or inventory["proof_phases"] != ["pre_removal", "post_removal"]
        or inventory["all_scenarios_required"] is not True
        or not isinstance(inventory["scenarios"], list)
        or not inventory["scenarios"]
    ):
        raise ClientArtifactError("qurl-go scenario inventory header is invalid")
    scenarios: list[dict[str, Any]] = []
    scenario_ids: set[str] = set()
    test_names: set[str] = set()
    producer_tests: set[str] = set()
    producer_owned = 0
    external_dependency = 0
    for index, raw in enumerate(inventory["scenarios"]):
        scenario = _exact_object(
            raw,
            {"id", "owner", "status", "test_name", "requirement"},
            f"qurl-go scenario {index}",
        )
        scenario_id = scenario["id"]
        owner = scenario["owner"]
        status = scenario["status"]
        test_name = scenario["test_name"]
        if (
            not isinstance(scenario_id, str)
            or re.fullmatch(r"[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+", scenario_id)
            is None
            or scenario_id in scenario_ids
            or owner not in {"qurl-go", "nhp-orchestrator", "qurl-connector"}
            or not isinstance(test_name, str)
            or re.fullmatch(r"Test[A-Za-z0-9_]+(?:/[a-z][a-z0-9_]*)?", test_name)
            is None
            or test_name in test_names
        ):
            raise ClientArtifactError(f"qurl-go scenario {index} is invalid")
        _nonempty_string(
            scenario["requirement"], f"qurl-go scenario {index}.requirement"
        )
        if owner == "qurl-go":
            if status != "implemented":
                raise ClientArtifactError("qurl-go-owned scenario is not implemented")
            producer_owned += 1
            producer_tests.add(test_name)
        else:
            if status != "external_dependency":
                raise ClientArtifactError(
                    "external qurl-go inventory row is not an external dependency"
                )
            external_dependency += 1
        scenario_ids.add(scenario_id)
        test_names.add(test_name)
        scenarios.append(scenario)
    if producer_owned <= 0 or external_dependency <= 0:
        raise ClientArtifactError(
            "qurl-go inventory does not separate producer and external ownership"
        )
    return {
        "producer_owned": producer_owned,
        "external_dependency": external_dependency,
        "scenario_keys": scenario_ids,
        "test_names": producer_tests,
        "allowed_test_names": test_names,
        "scenarios": scenarios,
    }


def _validate_scenario_results(
    value: Any,
    *,
    required_tests: set[str],
    allowed_tests: set[str],
) -> None:
    if not isinstance(value, list) or len(value) < len(required_tests):
        raise ClientArtifactError("client scenario results are incomplete")
    observed: set[str] = set()
    for index, raw in enumerate(value):
        result = _exact_object(
            raw,
            {"test_name", "action", "elapsed_seconds"},
            f"client scenario result {index}",
        )
        test_name = result["test_name"]
        elapsed = result["elapsed_seconds"]
        if (
            test_name not in allowed_tests
            or test_name in observed
            or result["action"] not in {"pass", "skip"}
            or (test_name in required_tests and result["action"] != "pass")
            or (
                elapsed is not None
                and (type(elapsed) not in {int, float} or elapsed < 0)
            )
        ):
            raise ClientArtifactError(f"client scenario result {index} is invalid")
        observed.add(test_name)
    if not required_tests.issubset(observed):
        raise ClientArtifactError("client scenario result identities are incomplete")


def _validate_qurl_go_typed_contract(
    value: Any,
    *,
    inventory: dict[str, Any],
) -> dict[str, set[str]]:
    contract = _exact_object(
        value,
        {
            "schema_version",
            "gate",
            "evidence_kinds",
            "scenario_key_field",
            "scenarios",
        },
        "qurl-go typed evidence contract",
    )
    if (
        contract["schema_version"] != 1
        or contract["gate"] != "udp_lifecycle_retirement"
        or contract["scenario_key_field"] != "id"
        or not isinstance(contract["evidence_kinds"], dict)
        or not contract["evidence_kinds"]
        or not isinstance(contract["scenarios"], dict)
        or set(contract["scenarios"]) != inventory["scenario_keys"]
    ):
        raise ClientArtifactError("qurl-go typed evidence contract header is invalid")
    allowed_kinds: set[str] = set()
    for kind, raw in contract["evidence_kinds"].items():
        if (
            not isinstance(kind, str)
            or re.fullmatch(r"[a-z][a-z0-9_]{0,63}", kind) is None
            or _exact_object(
                raw,
                {"observation_schema"},
                f"qurl-go typed evidence kind {kind}",
            )["observation_schema"]
            != "owner_bound_v1"
        ):
            raise ClientArtifactError(
                f"qurl-go typed evidence kind {kind!r} is invalid"
            )
        allowed_kinds.add(kind)
    required: dict[str, set[str]] = {}
    for scenario_key, kinds in contract["scenarios"].items():
        if (
            not isinstance(kinds, list)
            or not kinds
            or kinds != sorted(kinds)
            or len(kinds) != len(set(kinds))
            or any(kind not in allowed_kinds for kind in kinds)
        ):
            raise ClientArtifactError(
                f"qurl-go typed evidence scenario {scenario_key} is invalid"
            )
        required[scenario_key] = set(kinds)
    if {kind for kinds in required.values() for kind in kinds} != allowed_kinds:
        raise ClientArtifactError(
            "qurl-go typed evidence kinds do not exactly cover the scenario contract"
        )
    return required


CONNECTOR_FACT_TYPES = {
    "boolean",
    "git_sha",
    "image_digest",
    "nonempty_string",
    "nonnegative_integer",
    "positive_decimal_string",
    "positive_integer",
    "relative_path",
    "sha256",
}


def _validate_connector_typed_contract(
    value: Any,
    *,
    inventory: dict[str, Any],
) -> tuple[dict[str, str], dict[str, dict[str, str]]]:
    contract = _exact_object(
        value,
        {
            "schema_version",
            "gate",
            "observation_schema",
            "scenario_key_field",
            "scenarios",
        },
        "Connector typed evidence contract",
    )
    observation_schema = _exact_object(
        contract["observation_schema"],
        {
            "schema_version",
            "producer_repository",
            "producer_commit_sha_pattern",
            "scenario_id_field",
            "proof_phases",
        },
        "Connector observation schema",
    )
    if (
        contract["schema_version"] != 2
        or contract["gate"] != "udp_lifecycle_retirement"
        or contract["scenario_key_field"] != "name"
        or observation_schema
        != {
            "schema_version": 1,
            "producer_repository": "layervai/qurl-connector",
            "producer_commit_sha_pattern": "^[0-9a-f]{40}$",
            "scenario_id_field": "scenario_id",
            "proof_phases": ["pre_removal", "post_removal"],
        }
        or not isinstance(contract["scenarios"], dict)
        or set(contract["scenarios"]) != inventory["scenario_keys"]
    ):
        raise ClientArtifactError("Connector typed evidence contract header is invalid")
    required_kinds: dict[str, str] = {}
    fact_schemas: dict[str, dict[str, str]] = {}
    for scenario_key, raw in contract["scenarios"].items():
        scenario = _exact_object(
            raw,
            {"kind", "facts"},
            f"Connector typed evidence scenario {scenario_key}",
        )
        kind = scenario["kind"]
        facts = scenario["facts"]
        if (
            not isinstance(kind, str)
            or re.fullmatch(r"[a-z][a-z0-9_]{0,63}", kind) is None
            or not isinstance(facts, dict)
            or not facts
            or any(
                not isinstance(name, str)
                or re.fullmatch(r"[a-z][a-z0-9_]{0,63}", name) is None
                or fact_type not in CONNECTOR_FACT_TYPES
                for name, fact_type in facts.items()
            )
        ):
            raise ClientArtifactError(
                f"Connector typed evidence scenario {scenario_key} is invalid"
            )
        required_kinds[scenario_key] = kind
        fact_schemas[scenario_key] = facts
    return required_kinds, fact_schemas


def _validate_typed_evidence(
    value: Any,
    *,
    client: str,
    client_sha: str,
    proof_phase: str,
    inventory: dict[str, Any],
    scenario_results: Any,
    expected_keys: set[str],
    required_keys: set[str],
    required_kinds: dict[str, set[str]],
    connector_fact_schemas: dict[str, dict[str, str]] | None = None,
    nhp_source_sha: str | None = None,
    producer_run_id: int | None = None,
) -> dict[str, set[str]]:
    if not isinstance(value, list) or len(value) != len(expected_keys):
        raise ClientArtifactError("client typed evidence row set is incomplete")
    observed: dict[str, set[str]] = {}
    for index, raw in enumerate(value):
        row = _exact_object(
            raw,
            {"scenario_key", "evidence"},
            f"client typed evidence row {index}",
        )
        key = row["scenario_key"]
        items = row["evidence"]
        if (
            key not in expected_keys
            or key in observed
            or not isinstance(items, list)
            or (key in required_keys and not items)
        ):
            raise ClientArtifactError(f"client typed evidence row {index} is invalid")
        kinds: set[str] = set()
        for item_index, raw_item in enumerate(items):
            item = _exact_object(
                raw_item,
                {"kind", "observation", "observation_sha256"},
                f"client typed evidence row {index} item {item_index}",
            )
            kind = item["kind"]
            observation = item["observation"]
            if (
                not isinstance(kind, str)
                or re.fullmatch(r"[a-z][a-z0-9_]{0,63}", kind) is None
                or kind in kinds
                or kind not in required_kinds.get(key, set())
            ):
                raise ClientArtifactError(
                    f"client typed evidence row {index} item {item_index} is invalid"
                )
            if client == "connector":
                _validate_connector_observation(
                    observation,
                    scenario_key=key,
                    kind=kind,
                    client_sha=client_sha,
                    proof_phase=proof_phase,
                    fact_schema=(connector_fact_schemas or {}).get(key),
                )
            else:
                _validate_qurl_go_observation(
                    observation,
                    scenario_key=key,
                    kind=kind,
                    inventory=inventory,
                    scenario_results=scenario_results,
                    nhp_source_sha=nhp_source_sha,
                    producer_run_id=producer_run_id,
                )
            observation_bytes = deployment.canonical_bytes(
                observation,
                maximum=4096,
                name=f"typed observation {key}/{kind}",
            )
            if (
                item["observation_sha256"]
                != hashlib.sha256(observation_bytes).hexdigest()
            ):
                raise ClientArtifactError(
                    f"client typed evidence row {index} item {item_index} digest is invalid"
                )
            kinds.add(kind)
        if items and kinds != required_kinds.get(key, set()):
            raise ClientArtifactError(
                f"client typed evidence row {index} does not contain its exact kinds"
            )
        observed[key] = kinds
    if set(observed) != expected_keys:
        raise ClientArtifactError("client typed evidence identities are incomplete")
    return observed


def _validate_connector_fact(value: Any, fact_type: str, name: str) -> None:
    if fact_type == "boolean":
        valid = type(value) is bool
    elif fact_type == "nonnegative_integer":
        valid = type(value) is int and value >= 0
    elif fact_type == "positive_integer":
        valid = type(value) is int and value > 0
    elif fact_type == "sha256":
        valid = isinstance(value, str) and deployment.SHA256_RE.fullmatch(value)
    elif fact_type == "git_sha":
        valid = isinstance(value, str) and deployment.SHA_RE.fullmatch(value)
    elif fact_type == "image_digest":
        valid = isinstance(value, str) and deployment.DIGEST_RE.fullmatch(value)
    elif fact_type == "positive_decimal_string":
        valid = isinstance(value, str) and re.fullmatch(
            r"[1-9][0-9]*(?:\.[0-9]*[1-9])?", value
        )
    elif fact_type == "relative_path":
        valid = (
            isinstance(value, str)
            and 0 < len(value) <= 512
            and value == value.strip()
            and not value.startswith("/")
            and not value.endswith("/")
            and "\\" not in value
            and "//" not in value
            and ".." not in value.split("/")
        )
    else:
        valid = (
            fact_type == "nonempty_string"
            and isinstance(value, str)
            and 0 < len(value) <= 4096
            and value == value.strip()
        )
    if not valid:
        raise ClientArtifactError(f"{name} is not a valid {fact_type}")


CONNECTOR_REQUIRED_FACT_VALUES: dict[str, dict[str, Any]] = {
    "connector.dns_key_destination_source_observations": {
        "authenticated_outcome": True,
    },
    "connector.frp_authenticated_login_before_proxy": {
        "order": "knock_success<authenticated_login_success<proxy_allow",
    },
    "connector.hardened_linux_container": {
        "hardened_runtime": True,
    },
    "connector.resource_id_distinct_from_knock_resource_id": {
        "distinct": True,
    },
    "connector.sealed_restart_without_setup_mount": {
        "plaintext_state_absent": True,
        "provider": "aws-kms",
        "setup_mount_absent": True,
    },
    "connector.zero_http_network_capture": {
        "forbidden_lifecycle_route_count": 0,
    },
}


def _validate_connector_observation(
    value: Any,
    *,
    scenario_key: str,
    kind: str,
    client_sha: str,
    proof_phase: str,
    fact_schema: dict[str, str] | None,
) -> None:
    observation = _exact_object(
        value,
        {
            "schema_version",
            "producer_repository",
            "producer_commit_sha",
            "proof_phase",
            "scenario_id",
            "facts",
        },
        f"Connector observation {scenario_key}",
    )
    facts = observation["facts"]
    if (
        observation["schema_version"] != 1
        or observation["producer_repository"] != "layervai/qurl-connector"
        or observation["producer_commit_sha"] != client_sha
        or observation["proof_phase"] != proof_phase
        or observation["scenario_id"] != scenario_key
        or fact_schema is None
        or not isinstance(facts, dict)
        or set(facts) != set(fact_schema)
    ):
        raise ClientArtifactError(
            f"Connector observation {scenario_key} is not owner-bound"
        )
    for fact_name, fact_type in fact_schema.items():
        _validate_connector_fact(
            facts[fact_name],
            fact_type,
            f"Connector observation {scenario_key}.facts.{fact_name}",
        )
    required_values = CONNECTOR_REQUIRED_FACT_VALUES.get(scenario_key, {})
    for fact_name, expected in required_values.items():
        if fact_name not in facts or facts[fact_name] != expected:
            raise ClientArtifactError(
                f"Connector observation {scenario_key}.facts.{fact_name} "
                "does not prove the required outcome"
            )


def _validate_qurl_go_observation(
    value: Any,
    *,
    scenario_key: str,
    kind: str,
    inventory: dict[str, Any],
    scenario_results: Any,
    nhp_source_sha: str | None,
    producer_run_id: int | None,
) -> None:
    rows = {row["id"]: row for row in inventory["scenarios"]}
    row = rows[scenario_key]
    if row["owner"] == "qurl-go":
        expected = {
            "evidence_kind": kind,
            "outcome": "pass",
            "producer": "layervai/qurl-go",
            "scenario_key": scenario_key,
            "test_name": row["test_name"],
            "verified": True,
        }
        if value != expected or not any(
            result.get("test_name") == row["test_name"]
            and result.get("action") == "pass"
            for result in scenario_results
            if isinstance(result, dict)
        ):
            raise ClientArtifactError(
                f"qurl-go observation {scenario_key} is not owner-bound"
            )
        return
    observation = _exact_object(
        value,
        {
            "evidence_kind",
            "producer",
            "producer_run_id",
            "row_sha256",
            "scenario_key",
            "source_sha",
            "verified",
        },
        f"NHP observation {scenario_key}",
    )
    if (
        row["owner"] != "nhp-orchestrator"
        or scenario_key not in STATIC_NHP_SCENARIOS
        or observation["evidence_kind"] != kind
        or observation["producer"] != "layervai/nhp"
        or observation["producer_run_id"] != producer_run_id
        or observation["scenario_key"] != scenario_key
        or observation["source_sha"] != nhp_source_sha
        or observation["verified"] is not True
    ):
        raise ClientArtifactError(
            f"NHP observation {scenario_key} is not producer-bound"
        )
    _sha256(observation["row_sha256"], f"NHP observation {scenario_key}.row_sha256")


def _validate_connector_attestation(
    value: Any,
    *,
    inventory: dict[str, Any],
    evidence: dict[str, Any],
    typed_kinds: dict[str, set[str]],
) -> None:
    attestation = _exact_object(
        value,
        {
            "schema_version",
            "gate",
            "scenario_contract_sha256",
            "scenario_key_field",
            "scenarios",
            "counts",
            "typed_evidence_contract_sha256",
        },
        "Connector scenario attestation",
    )
    total = inventory["implemented"]
    counts = _exact_object(
        attestation["counts"],
        {"proven", "total", "unproven"},
        "Connector scenario attestation counts",
    )
    if (
        attestation["schema_version"] != 1
        or attestation["gate"] != "udp_lifecycle_retirement"
        or attestation["scenario_key_field"] != "name"
        or attestation["scenario_contract_sha256"]
        != evidence["scenario_contract_sha256"]
        or attestation["typed_evidence_contract_sha256"]
        != evidence["typed_evidence_contract_sha256"]
        or counts != {"proven": total, "total": total, "unproven": 0}
        or not isinstance(attestation["scenarios"], list)
        or len(attestation["scenarios"]) != total
    ):
        raise ClientArtifactError("Connector scenario attestation is incomplete")
    inventory_by_name = {
        scenario["name"]: scenario for scenario in inventory["scenarios"]
    }
    observed: set[str] = set()
    for index, raw in enumerate(attestation["scenarios"]):
        row = _exact_object(
            raw,
            {
                "name",
                "observed_evidence_kinds",
                "outcome",
                "required_evidence_kinds",
                "status",
                "test",
            },
            f"Connector scenario attestation row {index}",
        )
        name = row["name"]
        required = row["required_evidence_kinds"]
        if (
            name not in inventory_by_name
            or name in observed
            or row["status"] != "implemented"
            or row["outcome"] != "pass"
            or row["test"] != inventory_by_name[name]["test"]
            or not isinstance(required, list)
            or not required
            or required != sorted(required)
            or len(required) != len(set(required))
            or any(
                not isinstance(kind, str)
                or re.fullmatch(r"[a-z][a-z0-9_]{0,63}", kind) is None
                for kind in required
            )
            or row["observed_evidence_kinds"] != required
            or typed_kinds.get(name) != set(required)
        ):
            raise ClientArtifactError(
                f"Connector scenario attestation row {index} is invalid"
            )
        observed.add(name)
    if observed != set(inventory_by_name):
        raise ClientArtifactError(
            "Connector scenario attestation identities are incomplete"
        )


def validate_files(
    directory: Path,
    *,
    client: str,
    proof_phase: str,
    client_repository: str,
    client_sha: str,
    client_run_id: str,
    client_run_attempt: str,
    dispatch_correlation_id: str,
    controller_run_id: str,
    controller_run_attempt: str,
    deployment_manifest_sha256: str,
    deployment_runtime_inputs_sha256: str,
    deployment_provenance_sha256: str,
    retirement_probe_targets_sha256: str,
    retirement_probe_targets_b64: str,
    producer_run_id: str,
    producer_run_attempt: str,
    producer_head_sha: str,
    producer_artifact_id: str,
    producer_artifact_digest: str,
    pre_removal_run_id: str,
) -> dict[str, str]:
    """Reconcile canonical client evidence with the exact controller dispatch."""

    target = _client(client)
    expected_files: dict[str, int] = target["files"]
    try:
        metadata = directory.lstat()
        entries = {entry.name for entry in directory.iterdir()}
    except OSError as exc:
        raise ClientArtifactError("cannot read client artifact directory") from exc
    if (
        directory.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or entries != set(expected_files)
    ):
        raise ClientArtifactError(
            "client artifact directory does not contain the exact file set"
        )

    parsed: dict[str, dict[str, Any]] = {}
    raw: dict[str, bytes] = {}
    for name, maximum in expected_files.items():
        path = directory / name
        try:
            file_metadata = path.lstat()
            body = path.read_bytes()
        except OSError as exc:
            raise ClientArtifactError(
                f"cannot read client artifact file {name}"
            ) from exc
        if path.is_symlink() or not stat.S_ISREG(file_metadata.st_mode):
            raise ClientArtifactError(f"client artifact file {name} is not regular")
        if name in RAW_PINNED_JSON_FILES:
            parsed[name] = _load_json(path)
        else:
            try:
                parsed[name] = deployment.parse_canonical_bytes(
                    body, maximum=maximum, name=name
                )
            except deployment.ContractError as exc:
                raise ClientArtifactError(str(exc)) from exc
        raw[name] = body

    manifest = parsed["sandbox-deployment-manifest.json"]
    runtime = parsed["deployment-runtime-inputs.json"]
    try:
        deployment.validate_manifest(manifest, proof_phase)
        deployment.validate_runtime_inputs(runtime, manifest)
    except deployment.ContractError as exc:
        raise ClientArtifactError(str(exc)) from exc

    expected_manifest_sha = _sha256(
        deployment_manifest_sha256, "deployment manifest SHA-256"
    )
    expected_runtime_sha = _sha256(
        deployment_runtime_inputs_sha256, "deployment runtime SHA-256"
    )
    actual_manifest_sha = hashlib.sha256(
        raw["sandbox-deployment-manifest.json"]
    ).hexdigest()
    actual_runtime_sha = hashlib.sha256(
        raw["deployment-runtime-inputs.json"]
    ).hexdigest()
    if (
        actual_manifest_sha != expected_manifest_sha
        or actual_runtime_sha != expected_runtime_sha
    ):
        raise ClientArtifactError(
            "client artifact deployment bytes differ from the producer snapshot"
        )

    evidence = parsed[target["evidence_file"]]
    expected_evidence_keys = (
        CONNECTOR_EVIDENCE_KEYS if client == "connector" else QURL_GO_EVIDENCE_KEYS
    )
    _exact_object(evidence, expected_evidence_keys, "client evidence")
    run_id = _positive_int_string(client_run_id, "client run ID")
    run_attempt = _positive_int_string(client_run_attempt, "client run attempt")
    controller_id = _positive_int_string(controller_run_id, "controller run ID")
    controller_attempt = _positive_int_string(
        controller_run_attempt, "controller run attempt"
    )
    producer_id = _positive_int_string(producer_run_id, "producer run ID")
    producer_attempt = _positive_int_string(
        producer_run_attempt, "producer run attempt"
    )
    producer_artifact = _positive_int_string(
        producer_artifact_id, "producer artifact ID"
    )
    _sha(client_sha, "client SHA")
    _sha(producer_head_sha, "producer head SHA")
    _digest(producer_artifact_digest, "producer artifact digest")
    expected_producer = {
        "repository": "layervai/nhp",
        "workflow_path": ".github/workflows/udp-proof-deployment-manifest.yml",
        "run_id": str(producer_id),
        "run_attempt": str(producer_attempt),
        "head_sha": producer_head_sha,
        "artifact_id": str(producer_artifact),
        "artifact_digest": producer_artifact_digest,
    }
    expected_common = {
        "schema_version": 1,
        "phase": proof_phase,
        "repository": client_repository,
        "commit_sha": client_sha,
        "run_id": str(run_id),
        "run_attempt": str(run_attempt),
        "dispatch_correlation_id": dispatch_correlation_id,
        "nhp_controller_run_id": str(controller_id),
        "nhp_controller_run_attempt": str(controller_attempt),
        "deployment_producer": expected_producer,
        "deployment_manifest_sha256": actual_manifest_sha,
        "deployment_runtime_inputs_sha256": actual_runtime_sha,
        "enforcement_outcome": "success",
        "inputs_unchanged": True,
        "gate_passed": True,
        "provenance_valid": True,
        "two_cell_provenance": True,
        "typed_evidence_complete": True,
    }
    for key, expected in expected_common.items():
        if evidence[key] != expected:
            raise ClientArtifactError(f"client evidence {key} does not match dispatch")
    if type(evidence["schema_version"]) is not int or any(
        type(evidence[key]) is not bool
        for key in (
            "gate_passed",
            "inputs_unchanged",
            "provenance_valid",
            "two_cell_provenance",
            "typed_evidence_complete",
        )
    ):
        raise ClientArtifactError("client evidence scalar types are not exact")
    if client_repository != target["repository"]:
        raise ClientArtifactError("client evidence repository does not match client")
    if proof_phase not in {"pre_removal", "post_removal"}:
        raise ClientArtifactError("proof phase must be pre_removal or post_removal")
    correlation = f"nhp-{controller_id}-{controller_attempt}-{client}-{proof_phase}-"
    if not isinstance(dispatch_correlation_id, str) or not re.fullmatch(
        re.escape(correlation) + r"[0-9a-f]{32}", dispatch_correlation_id
    ):
        raise ClientArtifactError("dispatch correlation ID is not canonical")

    inventory_file = (
        "strict-proof-scenarios.json"
        if client == "connector"
        else "pre_retirement_scenarios.json"
    )
    actual_inventory_sha = hashlib.sha256(raw[inventory_file]).hexdigest()
    if evidence["inventory_sha256"] != actual_inventory_sha:
        raise ClientArtifactError(
            "client evidence inventory SHA-256 differs from the artifact"
        )
    if client == "connector":
        inventory = _validate_connector_inventory(parsed[inventory_file])
        implemented = inventory["implemented"]
        _validate_counts(
            evidence["counts"],
            expected_keys={
                "implemented",
                "blocking",
                "failures",
                "skips",
                "exact_passes",
            },
            expected={
                "implemented": implemented,
                "blocking": inventory["blocking"],
                "failures": 0,
                "skips": 0,
                "exact_passes": implemented,
            },
        )
    else:
        if actual_inventory_sha != QURL_GO_CANONICAL_INVENTORY_SHA256:
            raise ClientArtifactError(
                "qurl-go inventory does not match the frozen canonical artifact"
            )
        inventory = _validate_qurl_go_inventory(parsed[inventory_file])
        implemented = inventory["producer_owned"]
        _validate_counts(
            evidence["counts"],
            expected_keys={
                "producer_owned",
                "external_dependency",
                "failures",
                "skips",
                "exact_passes",
            },
            expected={
                "producer_owned": implemented,
                "external_dependency": inventory["external_dependency"],
                "failures": 0,
                "skips": 0,
                "exact_passes": implemented,
            },
        )
    digest_fields = [
        "scenario_contract_sha256",
        "proof_harness_sha256",
        "typed_evidence_contract_sha256",
    ]
    if client == "qurl_go":
        digest_fields.extend(
            ["inventory_mapping_sha256", "retired_lifecycle_surface_sha256"]
        )
    for name in digest_fields:
        _sha256(evidence[name], f"client evidence {name}")
    typed_contract_file = (
        "typed-evidence-contract.json"
        if client == "connector"
        else "typed_evidence_contract.json"
    )
    typed_contract_sha = hashlib.sha256(raw[typed_contract_file]).hexdigest()
    if evidence["typed_evidence_contract_sha256"] != typed_contract_sha:
        raise ClientArtifactError(
            "client typed evidence contract differs from its evidence digest"
        )
    connector_fact_schemas: dict[str, dict[str, str]] | None = None
    if client == "connector":
        if typed_contract_sha != CONNECTOR_TYPED_EVIDENCE_CONTRACT_SHA256:
            raise ClientArtifactError(
                "Connector typed evidence contract is not the frozen canonical artifact"
            )
        connector_kinds, connector_fact_schemas = _validate_connector_typed_contract(
            parsed[typed_contract_file],
            inventory=inventory,
        )
        required_kinds = {
            scenario_key: {kind} for scenario_key, kind in connector_kinds.items()
        }
    else:
        if typed_contract_sha != QURL_GO_TYPED_EVIDENCE_CONTRACT_SHA256:
            raise ClientArtifactError(
                "qurl-go typed evidence contract is not the frozen canonical artifact"
            )
        required_kinds = _validate_qurl_go_typed_contract(
            parsed[typed_contract_file],
            inventory=inventory,
        )
    if client == "qurl_go":
        retired_surface_sha = hashlib.sha256(
            raw["retired_lifecycle_surface.json"]
        ).hexdigest()
        if evidence["retired_lifecycle_surface_sha256"] != retired_surface_sha:
            raise ClientArtifactError(
                "qurl-go retired lifecycle surface differs from its evidence digest"
            )
    _validate_scenario_results(
        evidence["scenario_results"],
        required_tests=inventory["test_names"],
        allowed_tests=inventory.get("allowed_test_names", inventory["test_names"]),
    )
    typed_kinds = _validate_typed_evidence(
        evidence["typed_evidence"],
        client=client,
        client_sha=client_sha,
        proof_phase=proof_phase,
        inventory=inventory,
        scenario_results=evidence["scenario_results"],
        expected_keys=inventory["scenario_keys"],
        required_keys=(
            inventory["scenario_keys"]
            if client == "connector"
            else (
                {
                    scenario["id"]
                    for scenario in inventory["scenarios"]
                    if scenario["owner"] == "qurl-go"
                }
                | STATIC_NHP_SCENARIOS
            )
        ),
        required_kinds=required_kinds,
        connector_fact_schemas=connector_fact_schemas,
        nhp_source_sha=manifest["repositories"]["nhp"],
        producer_run_id=producer_id,
    )
    if client == "connector":
        typed_summary = _exact_object(
            parsed["strict-typed-evidence.json"],
            {"complete", "scenarios"},
            "Connector typed evidence summary",
        )
        if (
            typed_summary["complete"] is not True
            or typed_summary["scenarios"] != evidence["typed_evidence"]
        ):
            raise ClientArtifactError(
                "Connector typed evidence summary differs from client evidence"
            )
    if not isinstance(evidence["provenance"], dict):
        raise ClientArtifactError("client evidence provenance is incomplete")

    if proof_phase == "pre_removal":
        if (
            pre_removal_run_id
            or evidence["pre_removal_run_id"] is not None
            or evidence["pre_removal_evidence_sha256"] is not None
            or evidence["pre_removal_deployment_sha256"] is not None
        ):
            raise ClientArtifactError("pre-removal client evidence has prior lineage")
    else:
        _positive_int_string(pre_removal_run_id, "pre-removal run ID")
        if evidence["pre_removal_run_id"] != pre_removal_run_id:
            raise ClientArtifactError("post-removal client evidence run lineage drift")
        _sha256(
            evidence["pre_removal_evidence_sha256"],
            "pre-removal evidence SHA-256",
        )
        _sha256(
            evidence["pre_removal_deployment_sha256"],
            "pre-removal deployment SHA-256",
        )

    if client == "connector":
        if evidence["input_outcome"] != "success" or not isinstance(
            evidence["typed_evidence_contract_sha256"], str
        ):
            raise ClientArtifactError("Connector evidence outcome is incomplete")
        _validate_connector_attestation(
            evidence["scenario_attestation"],
            inventory=inventory,
            evidence=evidence,
            typed_kinds=typed_kinds,
        )
    else:
        if evidence["strict_outcome"] != "success":
            raise ClientArtifactError("qurl-go evidence outcome is incomplete")

    outputs = {
        "client_evidence_sha256": hashlib.sha256(
            raw[target["evidence_file"]]
        ).hexdigest(),
        "client_manifest_sha256": actual_manifest_sha,
        "client_runtime_inputs_sha256": actual_runtime_sha,
        "client_typed_evidence_sha256": hashlib.sha256(
            deployment.canonical_bytes(
                evidence["typed_evidence"],
                maximum=MAX_EVIDENCE_BYTES,
                name=f"{client} typed evidence",
            )
        ).hexdigest(),
    }
    if client == "connector":
        transport_rows = [
            row
            for row in evidence["typed_evidence"]
            if row.get("scenario_key") == "connector.zero_http_network_capture"
        ]
        try:
            transport_item = transport_rows[0]["evidence"][0]
            outputs["client_packet_capture_sha256"] = transport_item["observation"][
                "facts"
            ]["packet_capture_sha256"]
        except (IndexError, KeyError, TypeError) as exc:
            raise ClientArtifactError(
                "Connector packet-capture evidence is missing"
            ) from exc
        _sha256(
            outputs["client_packet_capture_sha256"],
            "Connector packet capture SHA-256",
        )
    else:
        try:
            targets_raw = base64.b64decode(
                retirement_probe_targets_b64, validate=True
            )
            targets_document = deployment.parse_canonical_bytes(
                targets_raw,
                maximum=retirement_targets.MAX_ARTIFACT_BYTES,
                name=retirement_targets.ARTIFACT_FILE_NAME,
            )
        except (binascii.Error, ValueError, deployment.ContractError) as exc:
            raise ClientArtifactError(
                "retirement probe targets are not canonical base64 JSON"
            ) from exc
        expected_binding = {
            "controller_run_attempt": str(controller_attempt),
            "controller_run_id": str(controller_id),
            "dispatch_correlation_id": dispatch_correlation_id,
            "head_sha": client_sha,
            "repository": client_repository,
            "run_attempt": str(run_attempt),
            "run_id": str(run_id),
            "workflow_path": target["workflow_path"],
        }
        try:
            expected_targets_sha256 = _sha256(
                retirement_probe_targets_sha256,
                "retirement probe targets SHA-256",
            )
            if hashlib.sha256(targets_raw).hexdigest() != expected_targets_sha256:
                raise ClientArtifactError(
                    "retirement probe target bytes differ from producer digest"
                )
            retirement_targets.validate(
                targets_document,
                proof_phase=proof_phase,
                producer_run_id=producer_id,
                producer_run_attempt=producer_attempt,
                producer_head_sha=producer_head_sha,
                deployment_provenance_sha256=deployment_provenance_sha256,
                surface_contract_sha256=evidence[
                    "retired_lifecycle_surface_sha256"
                ],
                validation_time=deployment._timestamp(
                    targets_document["observed_at"],
                    "retirement target observed_at",
                ),
            )
            probe = runtime_probe.validate(
                parsed[runtime_probe.ARTIFACT_FILE_NAME],
                proof_phase=proof_phase,
                expected_binding=expected_binding,
                expected_retirement_probe_targets_sha256=(
                    expected_targets_sha256
                ),
                expected_http_operations=targets_document["http_operations"],
                expected_relay_aliases=targets_document["relay"]["aliases"],
            )
        except (retirement_targets.TargetsError, runtime_probe.ProbeError) as exc:
            raise ClientArtifactError(str(exc)) from exc
        outputs["client_runtime_probe_sha256"] = hashlib.sha256(
            raw[runtime_probe.ARTIFACT_FILE_NAME]
        ).hexdigest()
        outputs["client_packet_capture_sha256"] = probe["capture"]["raw_sha256"]
        outputs["retirement_probe_targets_sha256"] = probe[
            "retirement_probe_targets_sha256"
        ]
    return outputs


def _write_outputs(path: Path, outputs: dict[str, str]) -> None:
    with path.open("a", encoding="utf-8") as handle:
        for name, value in outputs.items():
            if "\n" in value or "\r" in value:
                raise ClientArtifactError(f"output {name} contains a newline")
            handle.write(f"{name}={value}\n")


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    metadata = subparsers.add_parser("metadata")
    metadata.add_argument("--run-json", type=Path, required=True)
    metadata.add_argument("--artifacts-json", type=Path, required=True)
    metadata.add_argument("--client", required=True)
    metadata.add_argument("--proof-phase", required=True)
    metadata.add_argument("--client-run-id", required=True)
    metadata.add_argument("--client-repository", required=True)
    metadata.add_argument("--client-ref", required=True)
    metadata.add_argument("--client-sha", required=True)
    metadata.add_argument("--client-run-title", required=True)
    metadata.add_argument("--github-output", type=Path, required=True)

    archive = subparsers.add_parser("archive")
    archive.add_argument("--archive", type=Path, required=True)
    archive.add_argument("--directory", type=Path, required=True)
    archive.add_argument("--client", required=True)
    archive.add_argument("--expected-digest", required=True)

    files = subparsers.add_parser("files")
    files.add_argument("--directory", type=Path, required=True)
    files.add_argument("--client", required=True)
    files.add_argument("--proof-phase", required=True)
    files.add_argument("--client-repository", required=True)
    files.add_argument("--client-sha", required=True)
    files.add_argument("--client-run-id", required=True)
    files.add_argument("--client-run-attempt", required=True)
    files.add_argument("--dispatch-correlation-id", required=True)
    files.add_argument("--controller-run-id", required=True)
    files.add_argument("--controller-run-attempt", required=True)
    files.add_argument("--deployment-manifest-sha256", required=True)
    files.add_argument("--deployment-runtime-inputs-sha256", required=True)
    files.add_argument("--deployment-provenance-sha256", required=True)
    files.add_argument("--retirement-probe-targets-sha256", required=True)
    files.add_argument("--retirement-probe-targets-b64", required=True)
    files.add_argument("--producer-run-id", required=True)
    files.add_argument("--producer-run-attempt", required=True)
    files.add_argument("--producer-head-sha", required=True)
    files.add_argument("--producer-artifact-id", required=True)
    files.add_argument("--producer-artifact-digest", required=True)
    files.add_argument("--pre-removal-run-id", default="")
    files.add_argument("--github-output", type=Path, required=True)
    args = parser.parse_args()

    try:
        if args.command == "metadata":
            outputs = validate_metadata(
                _load_json(args.run_json),
                _load_json(args.artifacts_json),
                client=args.client,
                proof_phase=args.proof_phase,
                client_run_id=args.client_run_id,
                client_repository=args.client_repository,
                client_ref=args.client_ref,
                client_sha=args.client_sha,
                client_run_title=args.client_run_title,
            )
            _write_outputs(args.github_output, outputs)
        elif args.command == "archive":
            extract_archive(
                args.archive,
                args.directory,
                client=args.client,
                expected_digest=args.expected_digest,
            )
        else:
            outputs = validate_files(
                args.directory,
                client=args.client,
                proof_phase=args.proof_phase,
                client_repository=args.client_repository,
                client_sha=args.client_sha,
                client_run_id=args.client_run_id,
                client_run_attempt=args.client_run_attempt,
                dispatch_correlation_id=args.dispatch_correlation_id,
                controller_run_id=args.controller_run_id,
                controller_run_attempt=args.controller_run_attempt,
                deployment_manifest_sha256=args.deployment_manifest_sha256,
                deployment_runtime_inputs_sha256=(
                    args.deployment_runtime_inputs_sha256
                ),
                deployment_provenance_sha256=args.deployment_provenance_sha256,
                retirement_probe_targets_sha256=(
                    args.retirement_probe_targets_sha256
                ),
                retirement_probe_targets_b64=args.retirement_probe_targets_b64,
                producer_run_id=args.producer_run_id,
                producer_run_attempt=args.producer_run_attempt,
                producer_head_sha=args.producer_head_sha,
                producer_artifact_id=args.producer_artifact_id,
                producer_artifact_digest=args.producer_artifact_digest,
                pre_removal_run_id=args.pre_removal_run_id,
            )
            _write_outputs(args.github_output, outputs)
    except (ClientArtifactError, OSError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
