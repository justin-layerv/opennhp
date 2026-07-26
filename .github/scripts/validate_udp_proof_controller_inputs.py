#!/usr/bin/env python3
"""Validate attended UDP-proof controller inputs without inventing topology.

The deployment manifest is produced outside this workflow from reviewed, live
deployment evidence.  This validator deliberately accepts that manifest only as
an opaque operator input, then fails closed on canonical encoding, the complete
public schema, candidate commit bindings, and phase/run linkage.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import os
import re
from pathlib import Path
from typing import Any


# workflow_dispatch caps the complete inputs payload at 65,535 characters.  A
# 32-KiB manifest expands to at most 43,692 base64 characters, leaving ample
# room for the other controller inputs and the forwarded client dispatch.
MAX_MANIFEST_BYTES = 32 * 1024
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
BRANCH_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
KEY_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
RUN_ID_RE = re.compile(r"^[1-9][0-9]{0,19}$")
CELL_ID_RE = re.compile(r"^[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$")
HOST_RE = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*"
    r"\.nhp\.layerv\.(?:ai|xyz)$"
)

TOP_LEVEL_KEYS = {
    "cells",
    "connector_modules",
    "hub",
    "images",
    "phase",
    "repositories",
    "retirement_state",
    "schema_version",
}
REPOSITORY_KEYS = {
    "frp",
    "nhp",
    "qurl_connector",
    "qurl_go",
    "qurl_integrations",
    "qurl_mcp",
    "qurl_python",
    "qurl_reverse_tunnel_server",
    "qurl_service",
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
CLIENT_TARGETS = {
    "connector": {
        "repository": "layervai/qurl-connector",
        "workflow": "sandbox-smoke.yml",
        "repository_key": "qurl_connector",
    },
    "qurl_go": {
        "repository": "layervai/qurl-go",
        "workflow": "native-udp-sandbox.yml",
        "repository_key": "qurl_go",
    },
}


class ValidationError(ValueError):
    """A caller-supplied controller input violates the proof contract."""


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValidationError(f"deployment manifest contains duplicate key: {key}")
        value[key] = item
    return value


def _reject_nonfinite(value: str) -> None:
    raise ValidationError(f"deployment manifest contains non-finite number: {value}")


def _require_exact_keys(value: Any, expected: set[str], name: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise ValidationError(f"{name} must contain exactly {sorted(expected)}")
    return value


def _require_sha_map(value: Any, expected: set[str], name: str) -> dict[str, str]:
    mapping = _require_exact_keys(value, expected, name)
    if not all(
        isinstance(item, str) and SHA_RE.fullmatch(item) for item in mapping.values()
    ):
        raise ValidationError(
            f"{name} values must all be exact lowercase 40-character commit SHAs"
        )
    return mapping


def _validate_endpoint(
    value: Any, name: str, expected_keys: set[str]
) -> dict[str, Any]:
    endpoint = _require_exact_keys(value, expected_keys, name)
    host = endpoint.get("host")
    if not isinstance(host, str) or len(host) > 253 or not HOST_RE.fullmatch(host):
        raise ValidationError(f"{name}.host is not a LayerV-owned NHP DNS name")
    if type(endpoint.get("port")) is not int or endpoint["port"] != 62206:
        raise ValidationError(f"{name}.port must be UDP 62206")
    key_digest = endpoint.get("server_public_key_sha256")
    if not isinstance(key_digest, str) or not KEY_DIGEST_RE.fullmatch(key_digest):
        raise ValidationError(
            f"{name}.server_public_key_sha256 must be a lowercase SHA-256"
        )
    return endpoint


def _validate_candidate_ref(value: str, name: str) -> None:
    if not isinstance(value, str) or not value or len(value) > 200:
        raise ValidationError(f"{name} must be a non-empty candidate branch name")
    if SHA_RE.fullmatch(value):
        raise ValidationError(
            f"{name} must be a branch name; the exact SHA comes from the manifest"
        )
    if (
        not BRANCH_RE.fullmatch(value)
        or value.startswith(("/", "."))
        or value.endswith(("/", "."))
        or "//" in value
        or ".." in value
        or "@{" in value
        or any(char in value for char in "\\ ~^:?*[")
        or any(
            part.startswith(".") or part.endswith(".lock") for part in value.split("/")
        )
    ):
        raise ValidationError(f"{name} is not a safe Git branch name")


def decode_and_validate_manifest(encoded: str, proof_phase: str) -> dict[str, Any]:
    if not encoded:
        raise ValidationError("deployment_manifest_b64 is required")
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValidationError(
            "deployment_manifest_b64 must be strict standard base64"
        ) from exc
    if not raw or len(raw) > MAX_MANIFEST_BYTES:
        raise ValidationError(
            f"decoded deployment manifest must contain 1..{MAX_MANIFEST_BYTES} bytes"
        )
    try:
        manifest = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValidationError("deployment manifest must be valid UTF-8 JSON") from exc

    try:
        canonical = json.dumps(
            manifest,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except ValueError as exc:
        raise ValidationError(
            "deployment manifest JSON numbers must be finite"
        ) from exc
    if raw != canonical:
        raise ValidationError(
            "deployment manifest must use the canonical JSON encoding"
        )

    root = _require_exact_keys(manifest, TOP_LEVEL_KEYS, "deployment manifest")
    if type(root["schema_version"]) is not int or root["schema_version"] != 1:
        raise ValidationError("deployment manifest schema_version must be 1")
    if root["phase"] != proof_phase:
        raise ValidationError("deployment manifest phase does not match proof_phase")
    expected_retirement_state = (
        "http_lifecycle_present"
        if proof_phase == "pre_removal"
        else "http_lifecycle_removed"
    )
    if root["retirement_state"] != expected_retirement_state:
        raise ValidationError(
            "deployment manifest retirement_state does not match the selected proof phase"
        )

    repositories = _require_sha_map(
        root["repositories"], REPOSITORY_KEYS, "repositories"
    )
    modules = _require_sha_map(
        root["connector_modules"], {"frp", "qurl_go"}, "connector_modules"
    )
    if (
        modules["frp"] != repositories["frp"]
        or modules["qurl_go"] != repositories["qurl_go"]
    ):
        raise ValidationError("connector module SHAs must match their repository SHAs")

    images = _require_exact_keys(root["images"], IMAGE_KEYS, "images")
    if not all(
        isinstance(item, str) and DIGEST_RE.fullmatch(item) for item in images.values()
    ):
        raise ValidationError("images values must all be immutable sha256 digests")

    hub = _validate_endpoint(
        root["hub"],
        "hub",
        {"host", "port", "server_public_key_sha256"},
    )
    cells = root["cells"]
    if not isinstance(cells, list) or len(cells) != 2:
        raise ValidationError("cells must contain exactly the two sandbox proof cells")
    validated_cells: list[dict[str, Any]] = []
    for index, value in enumerate(cells):
        cell = _validate_endpoint(
            value,
            f"cells[{index}]",
            {"cell_id", "host", "port", "server_public_key_sha256"},
        )
        cell_id = cell.get("cell_id")
        if not isinstance(cell_id, str) or not CELL_ID_RE.fullmatch(cell_id):
            raise ValidationError(f"cells[{index}].cell_id is invalid")
        validated_cells.append(cell)

    for field in ("cell_id", "host", "server_public_key_sha256"):
        values = [cell[field] for cell in validated_cells]
        if len(values) != len(set(values)):
            raise ValidationError(f"cells must have unique {field} values")
    if {cell["cell_id"] for cell in validated_cells} != {"cell0", "cell1"}:
        raise ValidationError("cells must contain exactly cell0 and cell1")
    if hub["host"] in {cell["host"] for cell in validated_cells}:
        raise ValidationError("Hub and cell hosts must be distinct")
    if hub["server_public_key_sha256"] in {
        cell["server_public_key_sha256"] for cell in validated_cells
    }:
        raise ValidationError("Hub and cell server identities must be distinct")

    return manifest


def _workflow_identity(target: dict[str, str], repositories: dict[str, str]) -> str:
    return (
        f"{target['repository']}/.github/workflows/"
        f"{target['workflow']}@{repositories[target['repository_key']]}"
    )


def validate_inputs(
    *,
    client: str,
    proof_phase: str,
    deployment_manifest_b64: str,
    connector_ref: str,
    qurl_go_ref: str,
    connector_proof_run_id: str,
    pre_removal_run_id: str,
) -> dict[str, str]:
    if client not in CLIENT_TARGETS:
        raise ValidationError("client must be connector or qurl_go")
    if proof_phase not in {"pre_removal", "post_removal"}:
        raise ValidationError("proof_phase must be pre_removal or post_removal")
    _validate_candidate_ref(connector_ref, "connector_ref")
    _validate_candidate_ref(qurl_go_ref, "qurl_go_ref")

    if client == "qurl_go":
        if not RUN_ID_RE.fullmatch(connector_proof_run_id):
            raise ValidationError(
                "qurl_go requires an exact successful Connector proof run ID"
            )
    elif connector_proof_run_id:
        raise ValidationError(
            "connector_proof_run_id must be empty for a Connector proof"
        )

    if proof_phase == "post_removal":
        if not RUN_ID_RE.fullmatch(pre_removal_run_id):
            raise ValidationError(
                "post_removal requires the selected client's pre-removal run ID"
            )
    elif pre_removal_run_id:
        raise ValidationError("pre_removal_run_id must be empty during pre_removal")

    manifest = decode_and_validate_manifest(deployment_manifest_b64, proof_phase)
    repositories = manifest["repositories"]
    target = CLIENT_TARGETS[client]
    connector_target = CLIENT_TARGETS["connector"]
    qurl_go_target = CLIENT_TARGETS["qurl_go"]
    client_ref = connector_ref if client == "connector" else qurl_go_ref
    return {
        "connector_workflow_identity": _workflow_identity(
            connector_target, repositories
        ),
        "qurl_go_workflow_identity": _workflow_identity(qurl_go_target, repositories),
        "client_repository": target["repository"],
        "client_workflow": target["workflow"],
        "client_ref": client_ref,
        "client_sha": repositories[target["repository_key"]],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--client", required=True)
    parser.add_argument("--proof-phase", required=True)
    parser.add_argument("--connector-ref", required=True)
    parser.add_argument("--qurl-go-ref", required=True)
    parser.add_argument("--connector-proof-run-id", default="")
    parser.add_argument("--pre-removal-run-id", default="")
    parser.add_argument("--github-output", type=Path, required=True)
    args = parser.parse_args()

    try:
        outputs = validate_inputs(
            client=args.client,
            proof_phase=args.proof_phase,
            deployment_manifest_b64=os.environ.get("DEPLOYMENT_MANIFEST_B64", ""),
            connector_ref=args.connector_ref,
            qurl_go_ref=args.qurl_go_ref,
            connector_proof_run_id=args.connector_proof_run_id,
            pre_removal_run_id=args.pre_removal_run_id,
        )
    except ValidationError as exc:
        parser.error(str(exc))

    with args.github_output.open("a", encoding="utf-8") as handle:
        for name, value in outputs.items():
            handle.write(f"{name}={value}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
