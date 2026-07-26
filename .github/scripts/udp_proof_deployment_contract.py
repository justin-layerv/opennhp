#!/usr/bin/env python3
"""Pure schema and canonicalization contract for attended UDP proof artifacts.

This module deliberately performs no GitHub or AWS I/O.  The trusted-main
producer hydrates public evidence, constructs the three objects below, and then
uses this module to fail closed before publishing them.  The proof controller
imports the same contract after the producer lands.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import ipaddress
import json
import math
import re
import stat
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path
from typing import Any


SCHEMA_VERSION = 1
UDP_PORT = 62206
MAX_MANIFEST_BYTES = 32 * 1024
MAX_RUNTIME_BYTES = 8 * 1024
MAX_PROVENANCE_BYTES = 64 * 1024
MAX_RUNTIME_ATTESTATION_BYTES = 32 * 1024
MAX_PRODUCER_ARTIFACT_BYTES = 256 * 1024
MAX_TASKS = 32
MAX_INSTANCES = 32
MAX_LAMBDA_FUNCTIONS = 32
MAX_LABEL_LENGTH = 256
MAX_ARN_LENGTH = 2048
MAX_S3_KEY_LENGTH = 1024
MAX_CLOCK_SKEW = timedelta(seconds=30)
MAX_PROVENANCE_AGE = timedelta(minutes=10)
MAX_ATTESTATION_AGE = timedelta(minutes=10)
MAX_REPAIR_AGE = timedelta(minutes=40)
ARTIFACT_FILE_LIMITS = {
    "deployment-manifest.json": MAX_MANIFEST_BYTES,
    "deployment-runtime-inputs.json": MAX_RUNTIME_BYTES,
    "deployment-provenance.json": MAX_PROVENANCE_BYTES,
}

SHA_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
UTC_SECONDS_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
CELL_ID_RE = re.compile(r"^[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$")
HOST_RE = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*"
    r"\.nhp\.layerv\.(?:ai|xyz)$"
)
PUBLIC_KEY_RE = re.compile(r"^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$")
BRANCH_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$")
DECIMAL_WEIGHT_RE = re.compile(r"^(?:0|[1-9][0-9]*)(?:\.[0-9]*[1-9])?$")
ECR_REPOSITORY_RE = re.compile(
    r"^[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*$"
)
S3_KEY_RE = re.compile(r"^[\x21-\x7e]+$")
PROOF_SOURCE_CIDR = "3.141.109.76/32"
PROTECTED_EDGE_IDENTITIES = {
    "hub.nhp.layerv.xyz": {
        "load_balancer_name": "layerv-nhp-sandbox-hub-edge",
        "load_balancer_security_group_name": (
            "layerv-nhp-sandbox-control-hub-nlb"
        ),
        "backend_security_group_name": "layerv-nhp-sandbox-control-hub",
        "backend_udp_cidrs": (),
        "backend_health_cidrs": (),
    },
    "cell0.nhp.layerv.xyz": {
        "load_balancer_name": "layerv-nhp-sandbox-edge",
        "load_balancer_security_group_name": "layerv-nhp-sandbox-sg-nlb",
        "backend_security_group_name": "layerv-nhp-sandbox-sg-server",
        "backend_udp_cidrs": (
            "10.101.10.0/24",
            "10.101.11.0/24",
            "10.101.12.0/24",
        ),
        "backend_health_cidrs": ("10.100.0.0/16",),
    },
    "cell1.nhp.layerv.xyz": {
        "load_balancer_name": "layerv-nhp-sandbox-cell1-edge",
        "load_balancer_security_group_name": (
            "layerv-nhp-sandbox-cell1-sg-nlb"
        ),
        "backend_security_group_name": "layerv-nhp-sandbox-cell1-sg-server",
        "backend_udp_cidrs": (),
        "backend_health_cidrs": ("10.104.0.0/16",),
    },
}

REPOSITORIES = {
    "frp": "layervai/frp",
    "nhp": "layervai/nhp",
    "qurl_connector": "layervai/qurl-connector",
    "qurl_go": "layervai/qurl-go",
    "qurl_integrations": "layervai/qurl-integrations",
    "qurl_mcp": "layervai/qurl-mcp",
    "qurl_python": "layervai/qurl-python",
    "qurl_reverse_tunnel_server": "layervai/qurl-reverse-tunnel-server",
    "qurl_service": "layervai/qurl-service",
    "qurl_typescript": "layervai/qurl-typescript",
    "website": "layervai/website",
}
DEFAULT_BRANCH_REPOSITORIES = {
    "qurl_integrations",
    "qurl_mcp",
    "qurl_python",
    "qurl_typescript",
    "website",
}
IMAGE_KEYS = {
    "nhp_cell0",
    "nhp_cell1",
    "nhp_hub",
    "qurl_connector",
    "qurl_reverse_tunnel_server",
    "qurl_service_authority",
    "qurl_service_cell0",
    "qurl_service_cell1",
}
WORKLOAD_REPOSITORY_KEYS = {
    "nhp_cell0": "nhp",
    "nhp_cell1": "nhp",
    "nhp_hub": "nhp",
    "qurl_connector": "qurl_connector",
    "qurl_reverse_tunnel_server": "qurl_reverse_tunnel_server",
    "qurl_service_authority": "qurl_service",
    "qurl_service_cell0": "qurl_service",
    "qurl_service_cell1": "qurl_service",
}
WORKLOAD_KINDS = {
    "nhp_cell0": "ec2_attestation_set",
    "nhp_cell1": "ec2_attestation_set",
    "nhp_hub": "ecs",
    "qurl_connector": "connector_canary",
    "qurl_reverse_tunnel_server": "ec2_attestation_set",
    "qurl_service_authority": "lambda_image_set",
    "qurl_service_cell0": "ecs",
    "qurl_service_cell1": "ecs",
}
WORKLOAD_IMAGE_REPOSITORIES = {
    "nhp_cell0": "layerv/nhp-server",
    "nhp_cell1": "layerv/nhp-server",
    "nhp_hub": "layerv/nhp-hub",
    "qurl_reverse_tunnel_server": "layerv/qurl-reverse-tunnel-server",
    "qurl_service_authority": "layerv/qurl-connector-authority",
    "qurl_service_cell0": "layerv/nhp-qurl",
    "qurl_service_cell1": "layerv/nhp-qurl",
}


class ContractError(ValueError):
    """One influence-bearing artifact value violates the frozen contract."""


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ContractError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_nonfinite(value: str) -> None:
    raise ContractError(f"non-finite JSON number: {value}")


def _parse_finite_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        _reject_nonfinite(value)
    return parsed


def canonical_bytes(value: Any, *, maximum: int, name: str) -> bytes:
    """Return the one accepted ASCII JSON encoding and enforce its size bound."""

    try:
        raw = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (TypeError, ValueError) as exc:
        raise ContractError(f"{name} is not finite JSON") from exc
    if not raw or len(raw) > maximum:
        raise ContractError(f"{name} must contain 1..{maximum} canonical JSON bytes")
    return raw


def parse_canonical_bytes(raw: bytes, *, maximum: int, name: str) -> dict[str, Any]:
    if not raw or len(raw) > maximum:
        raise ContractError(f"{name} must contain 1..{maximum} canonical JSON bytes")
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite,
            parse_float=_parse_finite_float,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ContractError(f"{name} must be valid UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise ContractError(f"{name} must be a JSON object")
    if raw != canonical_bytes(value, maximum=maximum, name=name):
        raise ContractError(f"{name} must use canonical JSON encoding")
    return value


def load_canonical_file(path: Path, *, maximum: int, name: str) -> dict[str, Any]:
    try:
        metadata = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
            raise ContractError(f"{name} must be a regular file")
        raw = path.read_bytes()
    except OSError as exc:
        raise ContractError(f"cannot read {name}") from exc
    return parse_canonical_bytes(raw, maximum=maximum, name=name)


def load_triplet_directory(path: Path) -> tuple[dict[str, Any], ...]:
    """Load only the exact three regular canonical files from an artifact."""

    try:
        metadata = path.lstat()
        entries = {entry.name for entry in path.iterdir()}
    except OSError as exc:
        raise ContractError("cannot read deployment artifact directory") from exc
    if (
        path.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or entries != set(ARTIFACT_FILE_LIMITS)
    ):
        raise ContractError(
            "deployment artifact must contain exactly the three canonical files"
        )
    return tuple(
        load_canonical_file(path / name, maximum=maximum, name=name)
        for name, maximum in ARTIFACT_FILE_LIMITS.items()
    )


def _exact(value: Any, keys: set[str], name: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise ContractError(f"{name} must contain exactly {sorted(keys)}")
    return value


def _schema_version(value: dict[str, Any], name: str) -> None:
    version = value["schema_version"]
    if version != SCHEMA_VERSION or type(version) is not int:
        raise ContractError(f"{name} schema_version must be 1")


def _string(value: Any, name: str, *, maximum: int = MAX_LABEL_LENGTH) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise ContractError(f"{name} must be a non-empty string up to {maximum} bytes")
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in value):
        raise ContractError(f"{name} contains a control character")
    return value


def _positive_int(value: Any, name: str) -> int:
    if type(value) is not int or value <= 0:
        raise ContractError(f"{name} must be a positive integer")
    return value


def _sha(value: Any, name: str) -> str:
    if not isinstance(value, str) or not SHA_RE.fullmatch(value):
        raise ContractError(f"{name} must be a lowercase 40-character commit SHA")
    return value


def _sha256(value: Any, name: str) -> str:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise ContractError(f"{name} must be a lowercase SHA-256")
    return value


def _digest(value: Any, name: str) -> str:
    if not isinstance(value, str) or not DIGEST_RE.fullmatch(value):
        raise ContractError(f"{name} must be a lowercase sha256 digest")
    return value


def _arn(value: Any, name: str) -> str:
    result = _string(value, name, maximum=MAX_ARN_LENGTH)
    if not result.startswith("arn:aws:"):
        raise ContractError(f"{name} must be an AWS ARN")
    return result


def _timestamp(value: Any, name: str) -> datetime:
    if not isinstance(value, str) or not UTC_SECONDS_RE.fullmatch(value):
        raise ContractError(f"{name} must be UTC seconds (YYYY-MM-DDTHH:MM:SSZ)")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as exc:
        raise ContractError(f"{name} is not a real UTC timestamp") from exc


def _utc_time(value: datetime, name: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ContractError(f"{name} must be a timezone-aware datetime")
    return value.astimezone(timezone.utc)


def producer_artifact_name(run_id: int, run_attempt: int) -> str:
    """Return the only artifact name accepted for one producer run attempt."""

    _positive_int(run_id, "producer run_id")
    _positive_int(run_attempt, "producer run_attempt")
    return f"udp-proof-deployment-manifest-{run_id}-{run_attempt}"


def validate_authenticated_producer_run(
    value: Any,
    *,
    producer_run_id: int,
    producer_run_attempt: int,
    producer_head_sha: str,
) -> dict[str, Any]:
    """Validate the controller's normalized, API-authenticated workflow run."""

    run = _exact(
        value,
        {
            "repository",
            "workflow_path",
            "event",
            "status",
            "conclusion",
            "run_id",
            "run_attempt",
            "head_branch",
            "head_sha",
        },
        "authenticated producer run",
    )
    expected = {
        "repository": "layervai/nhp",
        "workflow_path": ".github/workflows/udp-proof-deployment-manifest.yml",
        "event": "workflow_dispatch",
        "status": "completed",
        "conclusion": "success",
        "run_id": producer_run_id,
        "run_attempt": producer_run_attempt,
        "head_branch": "main",
        "head_sha": producer_head_sha,
    }
    if run != expected:
        raise ContractError("authenticated producer workflow run identity drift")
    # Validate the caller-supplied expected identity independently: Python dict
    # equality treats booleans as integers, so equality alone is not a type gate.
    _positive_int(producer_run_id, "producer run_id")
    _positive_int(producer_run_attempt, "producer run_attempt")
    _sha(producer_head_sha, "producer head_sha")
    return run


def select_producer_artifact(
    value: Any,
    *,
    producer_run_id: int,
    producer_run_attempt: int,
    current_time: datetime,
) -> dict[str, Any]:
    """Select exactly one current-attempt artifact while tolerating older reruns."""

    now = _utc_time(current_time, "artifact selection current_time")
    if not isinstance(value, list) or not 1 <= len(value) <= 100:
        raise ContractError("producer artifact list must contain 1..100 entries")
    expected_name = producer_artifact_name(
        producer_run_id,
        producer_run_attempt,
    )
    matches: list[dict[str, Any]] = []
    for index, raw in enumerate(value):
        artifact = _exact(
            raw,
            {
                "artifact_id",
                "name",
                "digest",
                "size_in_bytes",
                "expired",
                "workflow_run_id",
                "created_at",
            },
            f"producer artifacts[{index}]",
        )
        _positive_int(
            artifact["artifact_id"], f"producer artifacts[{index}].artifact_id"
        )
        size = _positive_int(
            artifact["size_in_bytes"],
            f"producer artifacts[{index}].size_in_bytes",
        )
        if size > MAX_PRODUCER_ARTIFACT_BYTES:
            raise ContractError(
                f"producer artifacts[{index}] exceeds the bounded artifact size"
            )
        _string(artifact["name"], f"producer artifacts[{index}].name")
        if not isinstance(artifact["expired"], bool):
            raise ContractError(f"producer artifacts[{index}].expired must be boolean")
        _positive_int(
            artifact["workflow_run_id"],
            f"producer artifacts[{index}].workflow_run_id",
        )
        if not isinstance(artifact["digest"], str) or not DIGEST_RE.fullmatch(
            artifact["digest"]
        ):
            raise ContractError(
                f"producer artifacts[{index}].digest must be a lowercase sha256 digest"
            )
        created_at = _timestamp(
            artifact["created_at"],
            f"producer artifacts[{index}].created_at",
        )
        if created_at > now + MAX_CLOCK_SKEW:
            raise ContractError("producer artifact creation time is in the future")
        if (
            artifact["name"] == expected_name
            and artifact["workflow_run_id"] == producer_run_id
        ):
            matches.append(artifact)
    if len(matches) != 1 or matches[0]["expired"]:
        raise ContractError(
            "expected exactly one unexpired artifact for the current producer attempt"
        )
    return matches[0]


def _sorted_unique_strings(
    value: Any,
    name: str,
    *,
    minimum: int,
    maximum: int,
) -> list[str]:
    if not isinstance(value, list) or not minimum <= len(value) <= maximum:
        raise ContractError(f"{name} must contain {minimum}..{maximum} values")
    result = [
        _string(item, f"{name}[{index}]", maximum=MAX_ARN_LENGTH)
        for index, item in enumerate(value)
    ]
    if result != sorted(set(result)):
        raise ContractError(f"{name} must be sorted and unique")
    return result


def validate_branch(value: Any, name: str) -> str:
    branch = _string(value, name, maximum=200)
    if (
        SHA_RE.fullmatch(branch)
        or not BRANCH_RE.fullmatch(branch)
        or branch.startswith(("/", "."))
        or branch.endswith(("/", "."))
        or "//" in branch
        or ".." in branch
        or "@{" in branch
        or any(char in branch for char in "\\ ~^:?*[")
        or any(
            part.startswith(".") or part.endswith(".lock") for part in branch.split("/")
        )
    ):
        raise ContractError(f"{name} is not a safe Git branch name")
    return branch


def decode_public_key(value: Any, name: str) -> bytes:
    if not isinstance(value, str) or not PUBLIC_KEY_RE.fullmatch(value):
        raise ContractError(f"{name} must be canonical padded base64 for 32 bytes")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ContractError(f"{name} must be strict standard base64") from exc
    if (
        len(decoded) != 32
        or base64.b64encode(decoded).decode("ascii") != value
        or decoded == b"\x00" * 32
    ):
        raise ContractError(f"{name} must be a canonical nonzero 32-byte key")
    return decoded


def _endpoint(
    value: Any,
    name: str,
    *,
    include_cell_id: bool,
    include_public_key: bool,
) -> dict[str, Any]:
    keys = {"host", "port"}
    keys.add(
        "server_public_key_b64" if include_public_key else "server_public_key_sha256"
    )
    if include_cell_id:
        keys.add("cell_id")
    endpoint = _exact(value, keys, name)
    if include_cell_id:
        cell_id = endpoint["cell_id"]
        if not isinstance(cell_id, str) or not CELL_ID_RE.fullmatch(cell_id):
            raise ContractError(f"{name}.cell_id is invalid")
    host = endpoint["host"]
    if not isinstance(host, str) or len(host) > 253 or not HOST_RE.fullmatch(host):
        raise ContractError(f"{name}.host must be a LayerV-owned NHP DNS name")
    if type(endpoint["port"]) is not int or endpoint["port"] != UDP_PORT:
        raise ContractError(f"{name}.port must be UDP {UDP_PORT}")
    if include_public_key:
        decode_public_key(
            endpoint["server_public_key_b64"], f"{name}.server_public_key_b64"
        )
    else:
        _sha256(
            endpoint["server_public_key_sha256"],
            f"{name}.server_public_key_sha256",
        )
    return endpoint


def validate_manifest(value: Any, proof_phase: str) -> dict[str, Any]:
    manifest = _exact(
        value,
        {
            "cells",
            "connector_modules",
            "hub",
            "images",
            "phase",
            "repositories",
            "retirement_state",
            "schema_version",
        },
        "deployment manifest",
    )
    _schema_version(manifest, "deployment manifest")
    if proof_phase not in {"pre_removal", "post_removal"}:
        raise ContractError("proof_phase must be pre_removal or post_removal")
    if manifest["phase"] != proof_phase:
        raise ContractError("deployment manifest phase differs from proof phase")
    expected_retirement = (
        "http_lifecycle_present"
        if proof_phase == "pre_removal"
        else "http_lifecycle_removed"
    )
    if manifest["retirement_state"] != expected_retirement:
        raise ContractError("deployment manifest retirement state is wrong")

    repositories = _exact(
        manifest["repositories"], set(REPOSITORIES), "manifest repositories"
    )
    for key, sha in repositories.items():
        _sha(sha, f"manifest repositories.{key}")
    modules = _exact(
        manifest["connector_modules"], {"frp", "qurl_go"}, "connector modules"
    )
    if modules != {
        "frp": repositories["frp"],
        "qurl_go": repositories["qurl_go"],
    }:
        raise ContractError("connector module SHAs must match repository SHAs")
    images = _exact(manifest["images"], IMAGE_KEYS, "manifest images")
    for key, digest in images.items():
        _digest(digest, f"manifest images.{key}")

    hub = _endpoint(
        manifest["hub"],
        "manifest hub",
        include_cell_id=False,
        include_public_key=False,
    )
    cells = manifest["cells"]
    if not isinstance(cells, list) or len(cells) != 2:
        raise ContractError("manifest cells must contain exactly two cells")
    checked_cells = [
        _endpoint(
            cell,
            f"manifest cells[{index}]",
            include_cell_id=True,
            include_public_key=False,
        )
        for index, cell in enumerate(cells)
    ]
    if [cell["cell_id"] for cell in checked_cells] != ["cell0", "cell1"]:
        raise ContractError("manifest cells must be ordered cell0 then cell1")
    for field in ("host", "server_public_key_sha256"):
        values = [cell[field] for cell in checked_cells]
        if len(set(values)) != 2:
            raise ContractError(f"manifest cells must have unique {field}")
    if hub["host"] in {cell["host"] for cell in checked_cells}:
        raise ContractError("Hub and cell hosts must be distinct")
    if hub["server_public_key_sha256"] in {
        cell["server_public_key_sha256"] for cell in checked_cells
    }:
        raise ContractError("Hub and cell keys must be distinct")
    return manifest


def validate_runtime_inputs(value: Any, manifest: dict[str, Any]) -> dict[str, Any]:
    runtime = _exact(
        value, {"schema_version", "hub", "cells"}, "deployment runtime inputs"
    )
    _schema_version(runtime, "runtime inputs")
    hub = _endpoint(
        runtime["hub"], "runtime hub", include_cell_id=False, include_public_key=True
    )
    manifest_hub = manifest["hub"]
    if (
        hub["host"] != manifest_hub["host"]
        or hub["port"] != manifest_hub["port"]
        or hashlib.sha256(
            decode_public_key(hub["server_public_key_b64"], "runtime hub key")
        ).hexdigest()
        != manifest_hub["server_public_key_sha256"]
    ):
        raise ContractError("runtime Hub does not match the manifest")

    cells = runtime["cells"]
    if not isinstance(cells, list) or len(cells) != 2:
        raise ContractError("runtime inputs must contain exactly two cells")
    manifest_cells = {cell["cell_id"]: cell for cell in manifest["cells"]}
    checked_cells = [
        _endpoint(
            cell,
            f"runtime cells[{index}]",
            include_cell_id=True,
            include_public_key=True,
        )
        for index, cell in enumerate(cells)
    ]
    if [cell["cell_id"] for cell in checked_cells] != ["cell0", "cell1"]:
        raise ContractError("runtime cells must be ordered cell0 then cell1")
    for cell in checked_cells:
        expected = manifest_cells[cell["cell_id"]]
        if (
            cell["host"] != expected["host"]
            or cell["port"] != expected["port"]
            or hashlib.sha256(
                decode_public_key(
                    cell["server_public_key_b64"],
                    f"runtime {cell['cell_id']} key",
                )
            ).hexdigest()
            != expected["server_public_key_sha256"]
        ):
            raise ContractError(f"runtime {cell['cell_id']} does not match manifest")
    return runtime


def _validate_repository_evidence(
    value: Any,
    manifest_repositories: dict[str, str],
    candidates: dict[str, Any],
) -> dict[str, Any]:
    repositories = _exact(value, set(REPOSITORIES), "evidence repositories")
    for key, expected_repository in REPOSITORIES.items():
        item = _exact(
            repositories[key],
            {"repository", "source", "ref", "sha"},
            f"evidence repositories.{key}",
        )
        if item["repository"] != expected_repository:
            raise ContractError(f"repository identity drift for {key}")
        sha = _sha(item["sha"], f"evidence repositories.{key}.sha")
        if sha != manifest_repositories[key]:
            raise ContractError(f"repository SHA drift for {key}")
        source = item["source"]
        ref = _string(item["ref"], f"evidence repositories.{key}.ref")
        if key in DEFAULT_BRANCH_REPOSITORIES:
            if source != "default_branch" or not ref.startswith("refs/heads/"):
                raise ContractError(f"{key} must come from an exact default branch")
        elif key in {"qurl_connector", "qurl_go"}:
            candidate_key = "qurl_connector" if key == "qurl_connector" else "qurl_go"
            candidate = candidates[candidate_key]
            if (
                source != "candidate"
                or ref != f"refs/heads/{candidate['head_ref']}"
                or sha != candidate["head_sha"]
            ):
                raise ContractError(f"{key} must come from its current candidate")
        elif key == "frp":
            if source != "canary_module" or not ref.startswith("refs/tags/"):
                raise ContractError("frp must come from the verified canary module")
        else:
            if source != "deployed_runtime" or ref != "deployed-runtime":
                raise ContractError(f"{key} must come from deployed runtime evidence")
    return repositories


def _validate_public_identities(
    value: Any,
    manifest: dict[str, Any],
) -> dict[str, Any]:
    def validate_edge(edge: dict[str, Any], host: str, name: str) -> None:
        load_balancer_name = _string(
            edge["load_balancer_name"], f"{name}.load_balancer_name"
        )
        expected_edge = PROTECTED_EDGE_IDENTITIES.get(host)
        if (
            expected_edge is None
            or load_balancer_name != expected_edge["load_balancer_name"]
        ):
            raise ContractError(f"{name} does not use the protected sandbox edge")
        if (
            edge["load_balancer_security_group_name"]
            != expected_edge["load_balancer_security_group_name"]
            or edge["backend_security_group_name"]
            != expected_edge["backend_security_group_name"]
            or edge["backend_udp_cidrs"]
            != list(expected_edge["backend_udp_cidrs"])
            or edge["backend_health_cidrs"]
            != list(expected_edge["backend_health_cidrs"])
            or edge["proof_source_cidr"] != PROOF_SOURCE_CIDR
        ):
            raise ContractError(f"{name} protected-edge security identity drift")
        for field in (
            "load_balancer_security_group_id",
            "backend_security_group_id",
        ):
            if not re.fullmatch(r"sg-[0-9a-f]{17}", _string(edge[field], f"{name}.{field}")):
                raise ContractError(f"{name}.{field} is not an exact security group")
        if (
            edge["load_balancer_security_group_id"]
            == edge["backend_security_group_id"]
        ):
            raise ContractError(f"{name} edge and backend security groups must differ")
        nlb_arn = _arn(edge["load_balancer_arn"], f"{name}.load_balancer_arn")
        nlb_identity = (
            rf"arn:aws:elasticloadbalancing:us-east-2:767397897469:"
            rf"loadbalancer/net/{re.escape(load_balancer_name)}/[0-9a-f]{{16}}"
        )
        if not re.fullmatch(nlb_identity, nlb_arn):
            raise ContractError(f"{name}.load_balancer_arn is not the exact NLB")
        nlb_dns = _string(
            edge["load_balancer_dns_name"],
            f"{name}.load_balancer_dns_name",
        )
        if not re.fullmatch(
            rf"{re.escape(load_balancer_name)}-[0-9a-f]{{16}}"
            r"\.elb\.us-east-2\.amazonaws\.com",
            nlb_dns,
        ):
            raise ContractError(f"{name}.load_balancer_dns_name is invalid")
        listener_arn = _arn(edge["listener_arn"], f"{name}.listener_arn")
        if not re.fullmatch(
            rf"arn:aws:elasticloadbalancing:us-east-2:767397897469:"
            rf"listener/net/{re.escape(load_balancer_name)}/[0-9a-f]{{16}}/"
            r"[0-9a-f]{16}",
            listener_arn,
        ):
            raise ContractError(f"{name}.listener_arn is not bound to the NLB")
        target_group_arn = _arn(edge["target_group_arn"], f"{name}.target_group_arn")
        if not re.fullmatch(
            r"arn:aws:elasticloadbalancing:us-east-2:767397897469:"
            r"targetgroup/[a-zA-Z0-9-]{1,32}/[0-9a-f]{16}",
            target_group_arn,
        ):
            raise ContractError(f"{name}.target_group_arn is invalid")
        if edge["route53_zone_id"] != "Z10394893FM38A1RXLL32":
            raise ContractError(
                f"{name}.route53_zone_id is not the public sandbox zone"
            )
        target_ids = _sorted_unique_strings(
            edge["healthy_target_ids"],
            f"{name}.healthy_target_ids",
            minimum=1,
            maximum=MAX_TASKS,
        )
        for target_id in target_ids:
            if re.fullmatch(r"i-[0-9a-f]{17}", target_id):
                continue
            try:
                ipaddress.ip_address(target_id)
            except ValueError as exc:
                raise ContractError(
                    f"{name}.healthy_target_ids contains an invalid target"
                ) from exc

    identities = _exact(value, {"hub", "cells"}, "public identities")
    hub = _exact(
        identities["hub"],
        {
            "host",
            "port",
            "public_key_parameter_name",
            "public_key_parameter_version",
            "server_public_key_sha256",
            "load_balancer_name",
            "load_balancer_arn",
            "load_balancer_dns_name",
            "load_balancer_security_group_id",
            "load_balancer_security_group_name",
            "backend_security_group_id",
            "backend_security_group_name",
            "backend_udp_cidrs",
            "backend_health_cidrs",
            "proof_source_cidr",
            "listener_arn",
            "target_group_arn",
            "healthy_target_ids",
            "route53_zone_id",
        },
        "public identities hub",
    )
    _positive_int(
        hub["public_key_parameter_version"], "Hub public-key parameter version"
    )
    if (
        hub["host"] != manifest["hub"]["host"]
        or hub["port"] != UDP_PORT
        or hub["public_key_parameter_name"]
        != "/sandbox/nhp/control/hub/identity/public-key"
        or hub["server_public_key_sha256"]
        != manifest["hub"]["server_public_key_sha256"]
    ):
        raise ContractError("Hub public identity evidence differs from the manifest")
    validate_edge(hub, hub["host"], "public identities hub")

    cells = identities["cells"]
    if not isinstance(cells, list) or len(cells) != 2:
        raise ContractError("public identities cells must contain exactly two rows")
    manifest_cells = {cell["cell_id"]: cell for cell in manifest["cells"]}
    for index, value_cell in enumerate(cells):
        cell = _exact(
            value_cell,
            {
                "cell_id",
                "catalog_table",
                "pk",
                "sk",
                "status",
                "endpoint_revision",
                "selection_weight",
                "updated_at",
                "host",
                "port",
                "server_public_key_sha256",
                "load_balancer_name",
                "load_balancer_arn",
                "load_balancer_dns_name",
                "load_balancer_security_group_id",
                "load_balancer_security_group_name",
                "backend_security_group_id",
                "backend_security_group_name",
                "backend_udp_cidrs",
                "backend_health_cidrs",
                "proof_source_cidr",
                "listener_arn",
                "target_group_arn",
                "healthy_target_ids",
                "route53_zone_id",
            },
            f"public identities cells[{index}]",
        )
        cell_id = f"cell{index}"
        expected = manifest_cells[cell_id]
        _positive_int(cell["endpoint_revision"], f"{cell_id} endpoint revision")
        weight = cell["selection_weight"]
        if (
            not isinstance(weight, str)
            or len(weight) > 64
            or not DECIMAL_WEIGHT_RE.fullmatch(weight)
            or Decimal(weight) <= 0
        ):
            raise ContractError(f"{cell_id} selection_weight must be positive")
        _timestamp(cell["updated_at"], f"{cell_id} updated_at")
        if (
            cell["cell_id"] != cell_id
            or cell["catalog_table"] != "layerv-nhp-sandbox-control-connector-authority"
            or cell["pk"] != "REGISTRY"
            or cell["sk"] != f"CELL#{cell_id}"
            or cell["status"] != "active"
            or cell["host"] != expected["host"]
            or cell["port"] != UDP_PORT
            or cell["server_public_key_sha256"] != expected["server_public_key_sha256"]
        ):
            raise ContractError(f"{cell_id} catalog evidence differs from manifest")
        validate_edge(cell, cell["host"], f"public identities {cell_id}")
    return identities


def _validate_collector_contract(value: Any, name: str) -> dict[str, Any]:
    collector = _exact(
        value,
        {
            "schema_version",
            "parameter_name",
            "parameter_version",
            "contract_sha256",
            "collector_sha256",
            "service_unit_sha256",
            "timer_unit_sha256",
            "repair_document_name",
            "repair_document_version",
            "repair_document_sha256",
            "bucket_policy_sha256",
        },
        name,
    )
    if (
        collector["schema_version"] != SCHEMA_VERSION
        or type(collector["schema_version"]) is not int
        or collector["parameter_name"]
        != "/sandbox/nhp/udp-proof/runtime-attestation-collector-contract"
        or collector["repair_document_name"]
        != "layerv-nhp-sandbox-runtime-attestation-repair"
    ):
        raise ContractError(f"{name} identity drift")
    _positive_int(collector["parameter_version"], f"{name}.parameter_version")
    repair_document_version = _string(
        collector["repair_document_version"],
        f"{name}.repair_document_version",
    )
    if not re.fullmatch(r"[1-9][0-9]{0,9}", repair_document_version):
        raise ContractError(f"{name}.repair_document_version is invalid")
    for field in (
        "contract_sha256",
        "collector_sha256",
        "service_unit_sha256",
        "timer_unit_sha256",
        "repair_document_sha256",
        "bucket_policy_sha256",
    ):
        _sha256(collector[field], f"{name}.{field}")
    return collector


def normalize_runtime_attestation(
    raw: bytes,
    *,
    workload_key: str,
    autoscaling_group: str,
    bucket_arn: str,
    key: str,
    version_id: str,
    expected_instance_id: str,
    expected_role_arn: str,
    expected_collector_contract: dict[str, Any],
) -> dict[str, Any]:
    """Validate one canonical node object and add its immutable S3 reference."""

    value = parse_canonical_bytes(
        raw,
        maximum=MAX_RUNTIME_ATTESTATION_BYTES,
        name="runtime attestation object",
    )
    root = _exact(
        value,
        {"schema_version", "observed_at", "identity", "collector", "repair", "runtime"},
        "runtime attestation object",
    )
    _schema_version(root, "runtime attestation")
    _timestamp(root["observed_at"], "runtime attestation observed_at")
    identity = _exact(
        root["identity"],
        {
            "account_id",
            "region",
            "instance_id",
            "role_arn",
            "aws_userid",
            "autoscaling_group",
            "launch_template_id",
            "launch_template_version",
            "boot_id",
        },
        "runtime attestation identity",
    )
    if (
        identity["account_id"] != "767397897469"
        or identity["region"] != "us-east-2"
        or identity["instance_id"] != expected_instance_id
        or identity["role_arn"] != expected_role_arn
        or identity["autoscaling_group"] != autoscaling_group
    ):
        raise ContractError("runtime attestation AWS identity differs from live state")
    _arn(identity["role_arn"], "runtime attestation role_arn")
    aws_userid = _string(identity["aws_userid"], "runtime attestation aws_userid")
    if not aws_userid.endswith(f":{expected_instance_id}"):
        raise ContractError("runtime attestation aws_userid is not instance-bound")
    _string(identity["launch_template_id"], "runtime attestation launch_template_id")
    _positive_int(
        identity["launch_template_version"],
        "runtime attestation launch_template_version",
    )
    _string(identity["boot_id"], "runtime attestation boot_id")

    expected_collector = _validate_collector_contract(
        expected_collector_contract,
        "expected runtime-attestation collector contract",
    )
    collector = _exact(
        root["collector"],
        {"sha256", "service_unit_sha256", "timer_unit_sha256"},
        "runtime attestation collector",
    )
    for field in ("sha256", "service_unit_sha256", "timer_unit_sha256"):
        _sha256(collector[field], f"runtime attestation collector.{field}")
    repair = _exact(
        root["repair"],
        {"document_name", "association_id", "last_success_at", "status"},
        "runtime attestation repair",
    )
    _string(repair["document_name"], "runtime attestation repair.document_name")
    _string(repair["association_id"], "runtime attestation repair.association_id")
    _timestamp(repair["last_success_at"], "runtime attestation repair.last_success_at")
    if repair["status"] != "Success":
        raise ContractError("runtime attestation repair status must be Success")
    if (
        collector["sha256"] != expected_collector["collector_sha256"]
        or collector["service_unit_sha256"] != expected_collector["service_unit_sha256"]
        or collector["timer_unit_sha256"] != expected_collector["timer_unit_sha256"]
        or repair["document_name"] != expected_collector["repair_document_name"]
    ):
        raise ContractError(
            "runtime attestation collector or repair identity differs from "
            "the authoritative collector contract"
        )

    # The provenance-level validator owns the same exact runtime discriminators
    # and cross-checks them against the manifest.  Reuse it by constructing the
    # external-reference shape and validating with the object's own identities.
    normalized = {
        "bucket_arn": bucket_arn,
        "key": key,
        "version_id": version_id,
        "object_sha256": hashlib.sha256(raw).hexdigest(),
        "observed_at": root["observed_at"],
        "instance_id": identity["instance_id"],
        "role_arn": identity["role_arn"],
        "aws_userid": identity["aws_userid"],
        "launch_template_id": identity["launch_template_id"],
        "launch_template_version": identity["launch_template_version"],
        "boot_id": identity["boot_id"],
        "collector_sha256": collector["sha256"],
        "service_unit_sha256": collector["service_unit_sha256"],
        "timer_unit_sha256": collector["timer_unit_sha256"],
        "repair_document_name": repair["document_name"],
        "repair_association_id": repair["association_id"],
        "repair_last_success_at": repair["last_success_at"],
        "runtime": root["runtime"],
    }
    # Structural validation here catches an unsupported runtime kind before
    # collection continues.  Freshness and manifest binding are checked once the
    # whole deployment observation has one common observed_at.
    if workload_key == "qurl_reverse_tunnel_server":
        expected_runtime_keys = {
            "kind",
            "image_repository",
            "image_digest",
            "source_revision",
            "installed_binary_sha256",
            "build_receipt_sha256",
            "source_kind",
        }
        if (
            not isinstance(root["runtime"], dict)
            or set(root["runtime"]) != expected_runtime_keys
            or root["runtime"].get("kind") != "installed_binary"
            or root["runtime"].get("source_kind") != "ecr_build_receipt"
        ):
            raise ContractError("qRTS attestation must bind an ECR build receipt")
    else:
        expected_runtime_keys = {
            "kind",
            "container_name",
            "container_id",
            "image_repository",
            "image_digest",
            "source_revision",
        }
        if (
            not isinstance(root["runtime"], dict)
            or set(root["runtime"]) != expected_runtime_keys
            or root["runtime"].get("kind") != "docker_container"
        ):
            raise ContractError("NHP attestation must bind a running Docker container")
    return normalized


def _validate_source_evidence(
    value: Any,
    name: str,
    *,
    image_digest: str,
    source_revision: str,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ContractError(f"{name} must be an object")
    kind = value.get("kind")
    if kind == "oci_revision_label":
        evidence = _exact(
            value,
            {"kind", "manifest_digest", "config_digest", "revision_label"},
            name,
        )
        if (
            _digest(evidence["manifest_digest"], f"{name}.manifest_digest")
            != image_digest
            or _sha(evidence["revision_label"], f"{name}.revision_label")
            != source_revision
        ):
            raise ContractError(f"{name} does not bind image and source")
        _digest(evidence["config_digest"], f"{name}.config_digest")
    elif kind == "ssm_runtime_contract":
        evidence = _exact(
            value,
            {
                "kind",
                "parameter_name",
                "parameter_version",
                "contract_sha256",
                "image_uri",
                "source_revision",
            },
            name,
        )
        parameter_name = _string(evidence["parameter_name"], f"{name}.parameter_name")
        if parameter_name not in {
            "/sandbox/nhp/qurl-service/runtime-contract",
            "/sandbox-cell1/nhp/qurl-service/runtime-contract",
        }:
            raise ContractError(f"{name} uses an unknown runtime-contract parameter")
        image_uri = _string(evidence["image_uri"], f"{name}.image_uri")
        _positive_int(evidence["parameter_version"], f"{name}.parameter_version")
        _sha256(evidence["contract_sha256"], f"{name}.contract_sha256")
        if (
            not re.fullmatch(
                r"767397897469\.dkr\.ecr\.us-east-2\.amazonaws\.com/"
                rf"layerv/nhp-qurl@{re.escape(image_digest)}",
                image_uri,
            )
            or _sha(evidence["source_revision"], f"{name}.source_revision")
            != source_revision
        ):
            raise ContractError(f"{name} does not bind image and source")
    elif kind == "ecr_build_receipt":
        evidence = _exact(
            value,
            {
                "kind",
                "manifest_digest",
                "config_digest",
                "revision_label",
                "installed_binary_sha256",
                "build_receipt_sha256",
            },
            name,
        )
        if (
            _digest(evidence["manifest_digest"], f"{name}.manifest_digest")
            != image_digest
            or _sha(evidence["revision_label"], f"{name}.revision_label")
            != source_revision
        ):
            raise ContractError(f"{name} does not bind image and source")
        _digest(evidence["config_digest"], f"{name}.config_digest")
        _sha256(
            evidence["installed_binary_sha256"],
            f"{name}.installed_binary_sha256",
        )
        _sha256(
            evidence["build_receipt_sha256"],
            f"{name}.build_receipt_sha256",
        )
    else:
        raise ContractError(f"{name}.kind is unsupported")
    return value


def _validate_ecs_workload(
    value: Any,
    name: str,
    *,
    image_digest: str,
    source_revision: str,
) -> dict[str, Any]:
    workload = _exact(
        value,
        {
            "kind",
            "cluster_arn",
            "service_arn",
            "task_definition_arn",
            "tasks",
            "image_repository",
            "image_digest",
            "source_revision",
            "source_evidence",
        },
        name,
    )
    if workload["kind"] != "ecs":
        raise ContractError(f"{name}.kind must be ecs")
    _arn(workload["cluster_arn"], f"{name}.cluster_arn")
    _arn(workload["service_arn"], f"{name}.service_arn")
    _arn(workload["task_definition_arn"], f"{name}.task_definition_arn")
    repository = _string(workload["image_repository"], f"{name}.image_repository")
    if not ECR_REPOSITORY_RE.fullmatch(repository):
        raise ContractError(f"{name}.image_repository is invalid")
    if (
        workload["image_digest"] != image_digest
        or workload["source_revision"] != source_revision
    ):
        raise ContractError(f"{name} differs from manifest repository/image identity")
    tasks = workload["tasks"]
    if not isinstance(tasks, list) or not 1 <= len(tasks) <= MAX_TASKS:
        raise ContractError(f"{name}.tasks must contain 1..{MAX_TASKS} tasks")
    task_ids: list[str] = []
    for index, task_value in enumerate(tasks):
        task = _exact(
            task_value,
            {
                "task_arn",
                "container_name",
                "image_digest",
                "private_ipv4_addresses",
            },
            f"{name}.tasks[{index}]",
        )
        task_ids.append(_arn(task["task_arn"], f"{name}.tasks[{index}].task_arn"))
        _string(task["container_name"], f"{name}.tasks[{index}].container_name")
        if task["image_digest"] != image_digest:
            raise ContractError(f"{name} task image digest drift")
        addresses = _sorted_unique_strings(
            task["private_ipv4_addresses"],
            f"{name}.tasks[{index}].private_ipv4_addresses",
            minimum=1,
            maximum=8,
        )
        for raw_address in addresses:
            try:
                address = ipaddress.ip_address(raw_address)
            except ValueError as exc:
                raise ContractError(
                    f"{name}.tasks[{index}] contains an invalid private address"
                ) from exc
            if address.version != 4 or not address.is_private:
                raise ContractError(
                    f"{name}.tasks[{index}] must contain only private IPv4 addresses"
                )
    if task_ids != sorted(set(task_ids)):
        raise ContractError(f"{name}.tasks must be sorted and unique")
    _validate_source_evidence(
        workload["source_evidence"],
        f"{name}.source_evidence",
        image_digest=image_digest,
        source_revision=source_revision,
    )
    return workload


def _validate_lambda_workload(
    value: Any,
    name: str,
    *,
    image_digest: str,
    source_revision: str,
) -> dict[str, Any]:
    workload = _exact(
        value,
        {
            "kind",
            "functions",
            "image_repository",
            "image_digest",
            "source_revision",
            "source_evidence",
        },
        name,
    )
    if workload["kind"] != "lambda_image_set":
        raise ContractError(f"{name}.kind must be lambda_image_set")
    functions = workload["functions"]
    if (
        not isinstance(functions, list)
        or not 1 <= len(functions) <= MAX_LAMBDA_FUNCTIONS
    ):
        raise ContractError(
            f"{name}.functions must contain 1..{MAX_LAMBDA_FUNCTIONS} pairs"
        )
    pairs: list[tuple[str, str]] = []
    for index, function_value in enumerate(functions):
        function = _exact(
            function_value,
            {"alias_arn", "version_arn"},
            f"{name}.functions[{index}]",
        )
        pairs.append(
            (
                _arn(function["alias_arn"], f"{name}.functions[{index}].alias_arn"),
                _arn(
                    function["version_arn"],
                    f"{name}.functions[{index}].version_arn",
                ),
            )
        )
    if pairs != sorted(set(pairs)):
        raise ContractError(f"{name}.functions must be sorted unique pairs")
    repository = _string(workload["image_repository"], f"{name}.image_repository")
    if not ECR_REPOSITORY_RE.fullmatch(repository):
        raise ContractError(f"{name}.image_repository is invalid")
    if (
        workload["image_digest"] != image_digest
        or workload["source_revision"] != source_revision
    ):
        raise ContractError(f"{name} differs from manifest repository/image identity")
    _validate_source_evidence(
        workload["source_evidence"],
        f"{name}.source_evidence",
        image_digest=image_digest,
        source_revision=source_revision,
    )
    return workload


def _validate_attestation(
    value: Any,
    name: str,
    *,
    expected_component: str,
    observed_at: datetime,
    image_digest: str,
    source_revision: str,
    bucket_arn: str,
    collector_contract: dict[str, Any],
) -> dict[str, Any]:
    common_keys = {
        "bucket_arn",
        "key",
        "version_id",
        "object_sha256",
        "observed_at",
        "instance_id",
        "role_arn",
        "aws_userid",
        "launch_template_id",
        "launch_template_version",
        "boot_id",
        "collector_sha256",
        "service_unit_sha256",
        "timer_unit_sha256",
        "repair_document_name",
        "repair_association_id",
        "repair_last_success_at",
        "runtime",
    }
    attestation = _exact(value, common_keys, name)
    attestation_bucket_arn = _arn(attestation["bucket_arn"], f"{name}.bucket_arn")
    if ":s3:::" not in attestation_bucket_arn:
        raise ContractError(f"{name}.bucket_arn must be an S3 bucket ARN")
    if attestation_bucket_arn != bucket_arn:
        raise ContractError(f"{name}.bucket_arn differs from authoritative storage")
    timestamp = _timestamp(attestation["observed_at"], f"{name}.observed_at")
    repair_time = _timestamp(
        attestation["repair_last_success_at"], f"{name}.repair_last_success_at"
    )
    if (
        timestamp > observed_at + MAX_CLOCK_SKEW
        or observed_at - timestamp > MAX_ATTESTATION_AGE
    ):
        raise ContractError(f"{name} is missing the <=10 minute freshness proof")
    if (
        repair_time > observed_at + MAX_CLOCK_SKEW
        or observed_at - repair_time > MAX_REPAIR_AGE
    ):
        raise ContractError(f"{name} is missing the <=40 minute repair proof")
    instance_id = _string(attestation["instance_id"], f"{name}.instance_id")
    if not re.fullmatch(r"i-[0-9a-f]{17}", instance_id):
        raise ContractError(f"{name}.instance_id is invalid")
    _arn(attestation["role_arn"], f"{name}.role_arn")
    aws_userid = _string(attestation["aws_userid"], f"{name}.aws_userid")
    if not aws_userid.endswith(f":{instance_id}"):
        raise ContractError(f"{name}.aws_userid is not bound to instance_id")
    key = _string(attestation["key"], f"{name}.key", maximum=MAX_S3_KEY_LENGTH)
    if not S3_KEY_RE.fullmatch(key) or key != f"runtime/{aws_userid}/latest.json":
        raise ContractError(f"{name}.key is not self-bound to aws_userid")
    _string(attestation["version_id"], f"{name}.version_id")
    _sha256(attestation["object_sha256"], f"{name}.object_sha256")
    _string(attestation["launch_template_id"], f"{name}.launch_template_id")
    _positive_int(
        attestation["launch_template_version"], f"{name}.launch_template_version"
    )
    _string(attestation["boot_id"], f"{name}.boot_id")
    for field in ("collector_sha256", "service_unit_sha256", "timer_unit_sha256"):
        _sha256(attestation[field], f"{name}.{field}")
    _string(attestation["repair_document_name"], f"{name}.repair_document_name")
    _string(attestation["repair_association_id"], f"{name}.repair_association_id")
    if (
        attestation["collector_sha256"] != collector_contract["collector_sha256"]
        or attestation["service_unit_sha256"]
        != collector_contract["service_unit_sha256"]
        or attestation["timer_unit_sha256"] != collector_contract["timer_unit_sha256"]
        or attestation["repair_document_name"]
        != collector_contract["repair_document_name"]
    ):
        raise ContractError(f"{name} differs from authoritative collector contract")

    runtime = attestation["runtime"]
    if expected_component == "qurl_reverse_tunnel_server":
        runtime_value = _exact(
            runtime,
            {
                "kind",
                "image_repository",
                "image_digest",
                "source_revision",
                "installed_binary_sha256",
                "build_receipt_sha256",
                "source_kind",
            },
            f"{name}.runtime",
        )
        if runtime_value["kind"] != "installed_binary":
            raise ContractError(f"{name}.runtime kind must be installed_binary")
        _sha256(
            runtime_value["installed_binary_sha256"],
            f"{name}.runtime.installed_binary_sha256",
        )
        _sha256(
            runtime_value["build_receipt_sha256"],
            f"{name}.runtime.build_receipt_sha256",
        )
        if runtime_value["source_kind"] != "ecr_build_receipt":
            raise ContractError(f"{name} cannot use the qRTS S3 binary fallback")
    else:
        runtime_value = _exact(
            runtime,
            {
                "kind",
                "container_name",
                "container_id",
                "image_repository",
                "image_digest",
                "source_revision",
            },
            f"{name}.runtime",
        )
        if runtime_value["kind"] != "docker_container":
            raise ContractError(f"{name}.runtime kind must be docker_container")
        _string(runtime_value["container_name"], f"{name}.runtime.container_name")
        _string(runtime_value["container_id"], f"{name}.runtime.container_id")
    repository = _string(
        runtime_value["image_repository"], f"{name}.runtime.image_repository"
    )
    if (
        not ECR_REPOSITORY_RE.fullmatch(repository)
        or runtime_value["image_digest"] != image_digest
        or runtime_value["source_revision"] != source_revision
    ):
        raise ContractError(f"{name}.runtime differs from manifest identity")
    return attestation


def _validate_ec2_workload(
    value: Any,
    name: str,
    *,
    workload_key: str,
    observed_at: datetime,
    image_digest: str,
    source_revision: str,
    bucket_arn: str,
    collector_contract: dict[str, Any],
) -> dict[str, Any]:
    workload = _exact(
        value,
        {
            "kind",
            "autoscaling_group",
            "in_service_instance_ids",
            "attestations",
            "image_repository",
            "image_digest",
            "source_revision",
            "source_evidence",
        },
        name,
    )
    if workload["kind"] != "ec2_attestation_set":
        raise ContractError(f"{name}.kind must be ec2_attestation_set")
    _string(workload["autoscaling_group"], f"{name}.autoscaling_group")
    instances = _sorted_unique_strings(
        workload["in_service_instance_ids"],
        f"{name}.in_service_instance_ids",
        minimum=1,
        maximum=MAX_INSTANCES,
    )
    attestations = workload["attestations"]
    if not isinstance(attestations, list) or len(attestations) != len(instances):
        raise ContractError(f"{name}.attestations must cover every in-service instance")
    attested_ids: list[str] = []
    object_refs: list[tuple[str, str, str]] = []
    for index, attestation_value in enumerate(attestations):
        attestation = _validate_attestation(
            attestation_value,
            f"{name}.attestations[{index}]",
            expected_component=workload_key,
            observed_at=observed_at,
            image_digest=image_digest,
            source_revision=source_revision,
            bucket_arn=bucket_arn,
            collector_contract=collector_contract,
        )
        attested_ids.append(attestation["instance_id"])
        object_refs.append(
            (
                attestation["bucket_arn"],
                attestation["key"],
                attestation["version_id"],
            )
        )
    if attested_ids != instances:
        raise ContractError(f"{name}.attestations must be ordered by instance_id")
    if object_refs != sorted(set(object_refs)):
        raise ContractError(f"{name}.attestation object references must be unique")
    repository = _string(workload["image_repository"], f"{name}.image_repository")
    if (
        not ECR_REPOSITORY_RE.fullmatch(repository)
        or workload["image_digest"] != image_digest
        or workload["source_revision"] != source_revision
    ):
        raise ContractError(f"{name} differs from manifest repository/image identity")
    source_evidence = _validate_source_evidence(
        workload["source_evidence"],
        f"{name}.source_evidence",
        image_digest=image_digest,
        source_revision=source_revision,
    )
    if workload_key == "qurl_reverse_tunnel_server":
        if source_evidence["kind"] != "ecr_build_receipt":
            raise ContractError(f"{name} must use an ECR build receipt")
        for index, attestation in enumerate(attestations):
            runtime = attestation["runtime"]
            if (
                runtime["installed_binary_sha256"]
                != source_evidence["installed_binary_sha256"]
                or runtime["build_receipt_sha256"]
                != source_evidence["build_receipt_sha256"]
            ):
                raise ContractError(
                    f"{name}.attestations[{index}] differs from the ECR build receipt"
                )
    elif source_evidence["kind"] != "oci_revision_label":
        raise ContractError(f"{name} must use OCI revision evidence")
    return workload


def _validate_connector_workload(
    value: Any,
    name: str,
    *,
    image_digest: str,
    source_revision: str,
    canary: dict[str, Any],
) -> dict[str, Any]:
    workload = _exact(
        value,
        {
            "kind",
            "image_digest",
            "source_revision",
            "canary_artifact_digest",
        },
        name,
    )
    if (
        workload["kind"] != "connector_canary"
        or workload["image_digest"] != image_digest
        or workload["source_revision"] != source_revision
        or workload["canary_artifact_digest"] != canary["artifact_digest"]
    ):
        raise ContractError("Connector workload is not bound to the canary")
    return workload


def _validate_canary(
    value: Any,
    manifest: dict[str, Any],
    candidates: dict[str, Any],
) -> dict[str, Any]:
    canary = _exact(
        value,
        {
            "repository",
            "workflow_path",
            "run_id",
            "run_attempt",
            "head_sha",
            "artifact_id",
            "artifact_name",
            "artifact_digest",
            "image_ref",
            "image_digest",
            "provenance_sha256",
            "frp_sha",
            "qurl_go_sha",
        },
        "connector canary evidence",
    )
    _positive_int(canary["run_id"], "canary run_id")
    _positive_int(canary["run_attempt"], "canary run_attempt")
    if (
        canary["repository"] != "layervai/qurl-connector"
        or canary["workflow_path"] != ".github/workflows/connector-canary-publish.yml"
        or not SHA_RE.fullmatch(str(canary["head_sha"]))
        or canary["artifact_name"]
        != (
            "connector-canary-pr-"
            f"{candidates['qurl_connector']['pull_request_number']}-"
            f"{candidates['qurl_connector']['head_sha']}"
        )
        or not isinstance(canary["artifact_digest"], str)
        or not DIGEST_RE.fullmatch(canary["artifact_digest"])
        or canary["image_ref"]
        != (
            "ghcr.io/layervai/qurl-connector-canary@"
            f"{manifest['images']['qurl_connector']}"
        )
        or canary["image_digest"] != manifest["images"]["qurl_connector"]
        or canary["frp_sha"] != manifest["repositories"]["frp"]
        or canary["qurl_go_sha"] != manifest["repositories"]["qurl_go"]
    ):
        raise ContractError("Connector canary evidence differs from the manifest")
    _sha(canary["head_sha"], "canary head_sha")
    _positive_int(canary["artifact_id"], "canary artifact_id")
    _sha256(canary["provenance_sha256"], "canary provenance_sha256")
    return canary


def validate_provenance(
    value: Any,
    *,
    manifest: dict[str, Any],
    runtime_bytes: bytes,
    manifest_bytes: bytes,
    producer_run_id: int,
    producer_run_attempt: int,
    producer_head_sha: str,
    validation_time: datetime,
) -> dict[str, Any]:
    provenance = _exact(
        value,
        {"schema_version", "producer", "candidates", "files", "evidence"},
        "deployment provenance",
    )
    _schema_version(provenance, "deployment provenance")
    producer = _exact(
        provenance["producer"],
        {"repository", "workflow_path", "run_id", "run_attempt", "head_sha"},
        "deployment provenance producer",
    )
    if producer != {
        "repository": "layervai/nhp",
        "workflow_path": ".github/workflows/udp-proof-deployment-manifest.yml",
        "run_id": producer_run_id,
        "run_attempt": producer_run_attempt,
        "head_sha": producer_head_sha,
    }:
        raise ContractError("deployment provenance producer identity drift")
    _positive_int(producer_run_id, "producer run_id")
    _positive_int(producer_run_attempt, "producer run_attempt")
    _sha(producer_head_sha, "producer head_sha")

    candidates = _exact(
        provenance["candidates"],
        {"qurl_connector", "qurl_go"},
        "deployment provenance candidates",
    )
    for key, repository in (
        ("qurl_connector", "layervai/qurl-connector"),
        ("qurl_go", "layervai/qurl-go"),
    ):
        candidate = _exact(
            candidates[key],
            {"repository", "pull_request_number", "head_ref", "head_sha"},
            f"deployment provenance candidates.{key}",
        )
        if candidate["repository"] != repository:
            raise ContractError(f"candidate repository drift for {key}")
        _positive_int(candidate["pull_request_number"], f"{key} PR number")
        validate_branch(candidate["head_ref"], f"{key} head_ref")
        if candidate["head_sha"] != manifest["repositories"][key]:
            raise ContractError(f"candidate head SHA drift for {key}")

    files = _exact(
        provenance["files"],
        {"deployment-manifest.json", "deployment-runtime-inputs.json"},
        "deployment provenance files",
    )
    expected_files = {
        "deployment-manifest.json": f"sha256:{hashlib.sha256(manifest_bytes).hexdigest()}",
        "deployment-runtime-inputs.json": f"sha256:{hashlib.sha256(runtime_bytes).hexdigest()}",
    }
    if files != expected_files:
        raise ContractError("deployment provenance file digests are wrong")

    evidence = _exact(
        provenance["evidence"],
        {
            "observed_at",
            "aws",
            "repositories",
            "public_identities",
            "connector_canary",
            "workloads",
        },
        "deployment provenance evidence",
    )
    observed_at = _timestamp(evidence["observed_at"], "evidence observed_at")
    validated_at = _utc_time(validation_time, "provenance validation_time")
    if (
        observed_at > validated_at + MAX_CLOCK_SKEW
        or validated_at - observed_at > MAX_PROVENANCE_AGE
    ):
        raise ContractError("deployment evidence must be no more than 10 minutes old")
    aws = _exact(
        evidence["aws"],
        {"account_id", "region", "proof_source", "runtime_attestation"},
        "evidence aws",
    )
    if aws["account_id"] != "767397897469" or aws["region"] != "us-east-2":
        raise ContractError("producer AWS identity must remain sandbox us-east-2")
    proof_source = _exact(
        aws["proof_source"],
        {"name", "allocation_id", "public_ip", "cidr"},
        "evidence aws.proof_source",
    )
    if (
        proof_source["name"] != "layerv-nhp-sandbox-udp-proof-source"
        or not re.fullmatch(
            r"eipalloc-[0-9a-f]{17}",
            _string(
                proof_source["allocation_id"],
                "evidence aws.proof_source.allocation_id",
            ),
        )
        or proof_source["public_ip"] != PROOF_SOURCE_CIDR.removesuffix("/32")
        or proof_source["cidr"] != PROOF_SOURCE_CIDR
    ):
        raise ContractError("deployment evidence proof source EIP identity drift")
    storage = _exact(
        aws["runtime_attestation"],
        {
            "bucket_parameter_name",
            "bucket_parameter_version",
            "bucket_arn",
            "kms_key_arn",
            "bucket_policy_sha256",
            "collector_contract",
        },
        "evidence aws.runtime_attestation",
    )
    if (
        storage["bucket_parameter_name"]
        != "/sandbox/nhp/udp-proof/runtime-attestation-bucket-arn"
    ):
        raise ContractError("runtime-attestation bucket parameter identity drift")
    _positive_int(
        storage["bucket_parameter_version"],
        "evidence aws.runtime_attestation.bucket_parameter_version",
    )
    bucket_arn = _arn(
        storage["bucket_arn"],
        "evidence aws.runtime_attestation.bucket_arn",
    )
    if not re.fullmatch(
        r"arn:aws:s3:::layerv-nhp-sandbox-[a-z0-9][a-z0-9.-]{1,61}",
        bucket_arn,
    ):
        raise ContractError("runtime-attestation bucket ARN is not sandbox-owned")
    kms_key_arn = _arn(
        storage["kms_key_arn"],
        "evidence aws.runtime_attestation.kms_key_arn",
    )
    if not re.fullmatch(
        r"arn:aws:kms:us-east-2:767397897469:key/"
        r"(?:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
        r"|mrk-[0-9a-f]{32})",
        kms_key_arn,
    ):
        raise ContractError("runtime-attestation KMS key is outside sandbox")
    _sha256(
        storage["bucket_policy_sha256"],
        "evidence aws.runtime_attestation.bucket_policy_sha256",
    )
    collector_contract = _validate_collector_contract(
        storage["collector_contract"],
        "evidence aws.runtime_attestation.collector_contract",
    )
    if collector_contract["bucket_policy_sha256"] != storage["bucket_policy_sha256"]:
        raise ContractError(
            "runtime-attestation bucket policy differs from collector contract"
        )
    repositories = _validate_repository_evidence(
        evidence["repositories"], manifest["repositories"], candidates
    )
    public_identities = _validate_public_identities(
        evidence["public_identities"], manifest
    )
    canary = _validate_canary(evidence["connector_canary"], manifest, candidates)

    workloads = _exact(evidence["workloads"], IMAGE_KEYS, "evidence workloads")
    for workload_key in sorted(IMAGE_KEYS):
        image_digest = manifest["images"][workload_key]
        source_revision = manifest["repositories"][
            WORKLOAD_REPOSITORY_KEYS[workload_key]
        ]
        workload = workloads[workload_key]
        expected_kind = WORKLOAD_KINDS[workload_key]
        if not isinstance(workload, dict) or workload.get("kind") != expected_kind:
            raise ContractError(
                f"workload {workload_key} must use kind {expected_kind}"
            )
        expected_repository = WORKLOAD_IMAGE_REPOSITORIES.get(workload_key)
        if (
            expected_repository is not None
            and workload.get("image_repository") != expected_repository
        ):
            raise ContractError(
                f"workload {workload_key} uses an unexpected image repository"
            )
        if expected_kind == "ecs":
            _validate_ecs_workload(
                workload,
                f"workloads.{workload_key}",
                image_digest=image_digest,
                source_revision=source_revision,
            )
        elif expected_kind == "lambda_image_set":
            _validate_lambda_workload(
                workload,
                f"workloads.{workload_key}",
                image_digest=image_digest,
                source_revision=source_revision,
            )
        elif expected_kind == "ec2_attestation_set":
            _validate_ec2_workload(
                workload,
                f"workloads.{workload_key}",
                workload_key=workload_key,
                observed_at=observed_at,
                image_digest=image_digest,
                source_revision=source_revision,
                bucket_arn=bucket_arn,
                collector_contract=collector_contract,
            )
        else:
            _validate_connector_workload(
                workload,
                f"workloads.{workload_key}",
                image_digest=image_digest,
                source_revision=source_revision,
                canary=canary,
            )
    if repositories["frp"]["sha"] != canary["frp_sha"]:
        raise ContractError("FRP repository evidence differs from canary")
    cell_evidence = {cell["cell_id"]: cell for cell in public_identities["cells"]}
    for cell_id in ("cell0", "cell1"):
        if (
            cell_evidence[cell_id]["healthy_target_ids"]
            != workloads[f"nhp_{cell_id}"]["in_service_instance_ids"]
        ):
            raise ContractError(
                f"{cell_id} public NLB targets differ from its attested ASG"
            )
    hub_task_addresses = sorted(
        address
        for task in workloads["nhp_hub"]["tasks"]
        for address in task["private_ipv4_addresses"]
    )
    if public_identities["hub"]["healthy_target_ids"] != hub_task_addresses:
        raise ContractError("Hub public NLB targets differ from healthy ECS tasks")
    return provenance


def validate_triplet(
    manifest: dict[str, Any],
    runtime: dict[str, Any],
    provenance: dict[str, Any],
    *,
    proof_phase: str,
    producer_run_id: int,
    producer_run_attempt: int,
    producer_head_sha: str,
    validation_time: datetime,
) -> tuple[bytes, bytes, bytes]:
    checked_manifest = validate_manifest(manifest, proof_phase)
    checked_runtime = validate_runtime_inputs(runtime, checked_manifest)
    manifest_bytes = canonical_bytes(
        checked_manifest,
        maximum=MAX_MANIFEST_BYTES,
        name="deployment-manifest.json",
    )
    runtime_bytes = canonical_bytes(
        checked_runtime,
        maximum=MAX_RUNTIME_BYTES,
        name="deployment-runtime-inputs.json",
    )
    checked_provenance = validate_provenance(
        provenance,
        manifest=checked_manifest,
        runtime_bytes=runtime_bytes,
        manifest_bytes=manifest_bytes,
        producer_run_id=producer_run_id,
        producer_run_attempt=producer_run_attempt,
        producer_head_sha=producer_head_sha,
        validation_time=validation_time,
    )
    provenance_bytes = canonical_bytes(
        checked_provenance,
        maximum=MAX_PROVENANCE_BYTES,
        name="deployment-provenance.json",
    )
    return manifest_bytes, runtime_bytes, provenance_bytes
