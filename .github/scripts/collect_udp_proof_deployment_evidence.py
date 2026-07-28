#!/usr/bin/env python3
"""Hydrate and authenticate public GitHub/AWS evidence for the UDP proof.

All network reads stay here; udp_proof_deployment_contract.py remains a pure,
stdlib-only schema module shared with the proof controller.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import ipaddress
import json
import os
import re
import selectors
import stat
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, TypedDict

import udp_proof_deployment_contract as contract


GITHUB_METADATA_MAX_BYTES = 64 * 1024
CANARY_ARTIFACT_MAX_BYTES = 2 * 1024 * 1024
MAX_CANARY_ARTIFACTS = 1000
CANARY_FILES = {
    "buildkit-metadata.json": 64 * 1024,
    "go-version-m.txt": 64 * 1024,
    "provenance.json": 64 * 1024,
    "published-canary.json": 16 * 1024,
    "version-output.txt": 4 * 1024,
}
CANARY_WORKFLOW_PATH = ".github/workflows/connector-canary-publish.yml"
CANARY_ATTESTATION_TYPE = "https://layerv.ai/attestations/qurl-connector-canary/v1"
PRODUCER_WORKFLOW_PATH = ".github/workflows/udp-proof-deployment-manifest.yml"
AWS_ACCOUNT_ID = "767397897469"
AWS_REGION = "us-east-2"
ROUTE53_ZONE_ID = "Z10394893FM38A1RXLL32"
CATALOG_TABLE = "layerv-nhp-sandbox-control-connector-authority"
ATTESTATION_BUCKET_PARAMETER = "/sandbox/nhp/udp-proof/runtime-attestation-bucket-arn"
ATTESTATION_COLLECTOR_PARAMETER = (
    "/sandbox/nhp/udp-proof/runtime-attestation-collector-contract"
)
PRODUCER_ROLE_NAME = "layerv-nhp-sandbox-udp-proof-manifest-producer"
MAX_COLLECTION_DURATION = timedelta(minutes=5)
# Closed allow-list of AWS instance-refresh statuses that mean the refresh has
# stopped mutating the fleet. Every other status, including an unrecognised or
# future one, is treated as an active refresh and fails collection closed.
TERMINAL_INSTANCE_REFRESH_STATUSES = frozenset(
    {
        "Successful",
        "Failed",
        "Cancelled",
        "RollbackSuccessful",
        "RollbackFailed",
    }
)
AUTHORITY_FUNCTIONS = [
    "layerv-nhp-sandbox-ca-ar-cell0",
    "layerv-nhp-sandbox-ca-ar-cell1",
    "layerv-nhp-sandbox-ca-ccr-cell0",
    "layerv-nhp-sandbox-ca-ccr-cell1",
    "layerv-nhp-sandbox-ca-cr-cell0",
    "layerv-nhp-sandbox-ca-cr-cell1",
    "layerv-nhp-sandbox-ca-ia",
    "layerv-nhp-sandbox-ca-icr",
    "layerv-nhp-sandbox-ca-iro-cell0",
    "layerv-nhp-sandbox-ca-iro-cell1",
    "layerv-nhp-sandbox-ca-ra",
]


class ECSWorkloadSpec(TypedDict):
    cluster: str
    service: str
    container: str
    repository: str
    source_parameter: str | None


ECS_WORKLOADS: dict[str, ECSWorkloadSpec] = {
    "nhp_hub": {
        "cluster": "layerv-nhp-sandbox-control-hub",
        "service": "layerv-nhp-sandbox-control-hub",
        "container": "hub",
        "repository": "layerv/nhp-hub",
        "source_parameter": None,
    },
    "qurl_service_cell0": {
        "cluster": "layerv-nhp-sandbox-cell0-qurl-api",
        "service": "layerv-nhp-sandbox-cell0-qurl-api",
        "container": "qurl-api",
        "repository": "layerv/nhp-qurl",
        "source_parameter": "/sandbox/nhp/qurl-service/runtime-contract",
    },
    "qurl_service_cell1": {
        "cluster": "layerv-nhp-sandbox-cell1-qurl-api",
        "service": "layerv-nhp-sandbox-cell1-qurl-api",
        "container": "qurl-api",
        "repository": "layerv/nhp-qurl",
        "source_parameter": "/sandbox-cell1/nhp/qurl-service/runtime-contract",
    },
}
EC2_WORKLOADS = {
    "nhp_cell0": {
        "asg_parameter": "/sandbox/nhp/server/asg-name",
        "repository": "layerv/nhp-server",
    },
    "nhp_cell1": {
        "asg_parameter": "/sandbox-cell1/nhp/server/asg-name",
        "repository": "layerv/nhp-server",
    },
    "qurl_reverse_tunnel_server": {
        "asg_parameter": "/sandbox/nhp/reverse-tunnel-server/asg-name",
        "repository": "layerv/qurl-reverse-tunnel-server",
    },
}
REPOSITORY_ID_RE = re.compile(r"^[1-9][0-9]{0,19}$")
IMAGE_REF_RE = re.compile(
    r"^ghcr\.io/layervai/qurl-connector-canary@sha256:[0-9a-f]{64}$"
)
GO_SUM_RE = re.compile(r"^h1:[A-Za-z0-9+/]{43}=$")
MODULE_VERSION_RE = re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$")
QURL_RUNTIME_SIGNER = "layervai/qurl-service/.github/workflows/publish-cell-runtime.yml"
QRTS_COSIGN_IDENTITY = (
    "https://github.com/layervai/qurl-reverse-tunnel-server/"
    ".github/workflows/docker-publish.yml@refs/heads/main"
)
QRTS_COSIGN_REPOSITORY = "layervai/qurl-reverse-tunnel-server"
QRTS_ECR_REPOSITORY = "layerv/qurl-reverse-tunnel-server"
QRTS_BUILD_RECEIPT_ATTESTATION_TYPE = (
    "https://layerv.ai/attestations/qurl-reverse-tunnel-server-build-receipt/v1"
)
QRTS_BUILD_RECEIPT_BINARY_PATH = "/usr/local/bin/qurl-reverse-tunnel-server"
QRTS_BUILD_RECEIPT_MAX_BYTES = 1024
QRTS_VERIFIED_ATTESTATIONS_MAX_BYTES = 4 * 1024 * 1024
QRTS_VERIFIED_ATTESTATIONS_MAX_COUNT = 32
COMMAND_STDERR_MAX_BYTES = 64 * 1024
JSON_RESPONSE_MAX_BYTES = 4 * 1024 * 1024
PROOF_SOURCE_CIDR = contract.PROOF_SOURCE_CIDR
KMS_KEY_ARN_RE = re.compile(
    rf"^arn:aws:kms:{AWS_REGION}:{AWS_ACCOUNT_ID}:key/"
    r"(?:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
    r"|mrk-[0-9a-f]{32})$"
)
PUBLIC_EDGE_CONTRACTS = {
    "hub.nhp.layerv.xyz": {
        **contract.PROTECTED_EDGE_IDENTITIES["hub.nhp.layerv.xyz"],
        "target_type": "ip",
        "health_protocol": "TCP",
        "health_port": 62207,
        "health_path": None,
        "health_matcher": None,
        "healthy_threshold": 3,
        "unhealthy_threshold": 3,
        "health_interval": 10,
    },
    "cell0.nhp.layerv.xyz": {
        **contract.PROTECTED_EDGE_IDENTITIES["cell0.nhp.layerv.xyz"],
        "target_type": "instance",
        "health_protocol": "HTTP",
        "health_port": 8888,
        "health_path": "/health/live",
        "health_matcher": {"HttpCode": "200"},
        "healthy_threshold": 2,
        "unhealthy_threshold": 2,
        "health_interval": 30,
    },
    "cell1.nhp.layerv.xyz": {
        **contract.PROTECTED_EDGE_IDENTITIES["cell1.nhp.layerv.xyz"],
        "target_type": "instance",
        "health_protocol": "HTTP",
        "health_port": 8888,
        "health_path": "/health/live",
        "health_matcher": {"HttpCode": "200"},
        "healthy_threshold": 2,
        "unhealthy_threshold": 2,
        "health_interval": 30,
    },
}
_VERIFIED_QURL_RUNTIME_ATTESTATIONS: set[tuple[str, str]] = set()
_VERIFIED_QRTS_RUNTIME_SIGNATURES: set[tuple[str, str]] = set()


class EvidenceError(contract.ContractError):
    """A live producer input is unavailable, malformed, or not authoritative."""


def _loads(raw: str | bytes, name: str) -> Any:
    if isinstance(raw, str):
        raw = raw.encode("utf-8")
    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=contract._reject_duplicate_keys,
            parse_constant=contract._reject_nonfinite,
            parse_float=contract._parse_finite_float,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EvidenceError(f"{name} is not valid UTF-8 JSON") from exc


def _run_bounded(
    command: list[str],
    name: str,
    *,
    maximum: int,
    timeout: int = 60,
) -> subprocess.CompletedProcess[bytes]:
    if maximum <= 0:
        raise ValueError("maximum must be positive")
    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except OSError as exc:
        raise EvidenceError(f"{name} could not be read") from exc
    if process.stdout is None or process.stderr is None:
        process.kill()
        process.wait()
        raise EvidenceError(f"{name} could not be read")

    stdout = bytearray()
    stderr = bytearray()
    selector = selectors.DefaultSelector()
    deadline = time.monotonic() + timeout
    try:
        selector.register(process.stdout, selectors.EVENT_READ, (stdout, maximum))
        selector.register(
            process.stderr,
            selectors.EVENT_READ,
            (stderr, COMMAND_STDERR_MAX_BYTES),
        )
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(command, timeout)
            events = selector.select(remaining)
            if not events:
                raise subprocess.TimeoutExpired(command, timeout)
            for key, _ in events:
                chunk = os.read(key.fileobj.fileno(), 64 * 1024)
                if not chunk:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                buffer, limit = key.data
                if len(buffer) + len(chunk) > limit:
                    stream = "response" if buffer is stdout else "stderr"
                    raise EvidenceError(
                        f"{name} {stream} exceeds {limit} bytes"
                    )
                buffer.extend(chunk)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise subprocess.TimeoutExpired(command, timeout)
        returncode = process.wait(timeout=remaining)
    except (EvidenceError, OSError, subprocess.TimeoutExpired) as exc:
        process.kill()
        process.wait()
        if isinstance(exc, (OSError, subprocess.TimeoutExpired)):
            raise EvidenceError(f"{name} could not be read") from exc
        raise
    finally:
        selector.close()
        for stream in (process.stdout, process.stderr):
            if not stream.closed:
                stream.close()
    return subprocess.CompletedProcess(
        args=command,
        returncode=returncode,
        stdout=bytes(stdout),
        stderr=bytes(stderr),
    )


def _run_json(command: list[str], name: str) -> Any:
    result = _run_bounded(
        command,
        name,
        maximum=JSON_RESPONSE_MAX_BYTES,
    )
    if result.returncode != 0:
        stderr = result.stderr.decode("utf-8", errors="replace")[:1000]
        raise EvidenceError(f"{name} read failed: {stderr}") from None
    return _loads(result.stdout, name)


def _gh(path: str, name: str) -> Any:
    return _run_json(["gh", "api", path], name)


def _github_run_artifacts(run_id: int) -> list[dict[str, Any]]:
    artifacts: list[dict[str, Any]] = []
    total_count: int | None = None
    for page in range(1, (MAX_CANARY_ARTIFACTS // 100) + 1):
        response = _gh(
            (
                "repos/layervai/qurl-connector/actions/runs/"
                f"{run_id}/artifacts?per_page=100&page={page}"
            ),
            f"Connector canary artifacts page {page}",
        )
        page_artifacts = (
            response.get("artifacts") if isinstance(response, dict) else None
        )
        page_total = response.get("total_count") if isinstance(response, dict) else None
        if (
            type(page_total) is not int
            or not 0 <= page_total <= MAX_CANARY_ARTIFACTS
            or not isinstance(page_artifacts, list)
            or len(page_artifacts) > 100
            or (total_count is not None and page_total != total_count)
        ):
            raise EvidenceError("Connector canary artifact response is malformed")
        total_count = page_total
        artifacts.extend(page_artifacts)
        if len(artifacts) >= total_count:
            break
    if total_count is None or len(artifacts) != total_count:
        raise EvidenceError("Connector canary artifact pagination is incomplete")
    return artifacts


def _aws(service: str, arguments: list[str], name: str) -> Any:
    return _run_json(
        [
            "aws",
            service,
            *arguments,
            "--no-paginate",
            "--region",
            AWS_REGION,
            "--output",
            "json",
        ],
        name,
    )


def _exact(value: Any, keys: set[str], name: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise EvidenceError(f"{name} must contain exactly {sorted(keys)}")
    return value


def _write_canonical(path: Path, value: Any, *, maximum: int, name: str) -> None:
    raw = contract.canonical_bytes(value, maximum=maximum, name=name)
    path.write_bytes(raw)
    os.chmod(path, 0o600)


def _append_outputs(path: Path, outputs: dict[str, str]) -> None:
    with path.open("a", encoding="utf-8") as handle:
        for key, value in outputs.items():
            if "\n" in value or "\r" in value:
                raise EvidenceError(f"GitHub output {key} contains a newline")
            handle.write(f"{key}={value}\n")


def _positive_input(value: str, name: str) -> int:
    if not REPOSITORY_ID_RE.fullmatch(value):
        raise EvidenceError(f"{name} must be a positive integer")
    return int(value)


def _verify_commit(repository: str, sha: str, name: str) -> None:
    commit = _gh(f"repos/{repository}/commits/{sha}", f"{name} commit")
    if not isinstance(commit, dict):
        raise EvidenceError(f"{name} commit response must be an object")
    verification = (commit.get("commit") or {}).get("verification")
    if (
        commit.get("sha") != sha
        or not isinstance(verification, dict)
        or verification.get("verified") is not True
        or verification.get("reason") != "valid"
    ):
        raise EvidenceError(f"{name} exact head is not GitHub signature-verified")


def _resolve_candidate(repository: str, number: int, name: str) -> dict[str, Any]:
    pull = _gh(f"repos/{repository}/pulls/{number}", f"{name} pull request")
    if not isinstance(pull, dict):
        raise EvidenceError(f"{name} pull request response must be an object")
    head = pull.get("head")
    base = pull.get("base")
    if not isinstance(head, dict) or not isinstance(base, dict):
        raise EvidenceError(f"{name} pull request head/base are missing")
    head_repo = head.get("repo")
    base_repo = base.get("repo")
    sha = head.get("sha")
    head_ref = head.get("ref")
    if (
        pull.get("number") != number
        or pull.get("state") != "open"
        or not isinstance(head_repo, dict)
        or head_repo.get("full_name") != repository
        or not isinstance(base_repo, dict)
        or base_repo.get("full_name") != repository
        or base.get("ref") != "main"
        or not isinstance(sha, str)
        or not contract.SHA_RE.fullmatch(sha)
    ):
        raise EvidenceError(f"{name} must be an open same-repository PR onto main")
    head_ref = contract.validate_branch(head_ref, f"{name} head ref")
    _verify_commit(repository, sha, name)
    return {
        "repository": repository,
        "pull_request_number": number,
        "head_ref": head_ref,
        "head_sha": sha,
    }


def _resolve_default_branch(repository_key: str) -> dict[str, Any]:
    repository = contract.REPOSITORIES[repository_key]
    repo = _gh(f"repos/{repository}", f"{repository} repository")
    if not isinstance(repo, dict) or repo.get("full_name") != repository:
        raise EvidenceError(f"{repository} repository identity drift")
    branch = contract.validate_branch(
        repo.get("default_branch"), f"{repository} default branch"
    )
    ref = _gh(
        f"repos/{repository}/git/ref/heads/{branch}",
        f"{repository} default ref",
    )
    sha = (
        ((ref or {}).get("object") or {}).get("sha") if isinstance(ref, dict) else None
    )
    if not isinstance(sha, str) or not contract.SHA_RE.fullmatch(sha):
        raise EvidenceError(f"{repository} default ref has no exact commit")
    _verify_commit(repository, sha, repository)
    return {
        "repository": repository,
        "source": "default_branch",
        "ref": f"refs/heads/{branch}",
        "sha": sha,
    }


def collect_github_metadata(
    *,
    connector_pr_number: int,
    qurl_go_pr_number: int,
    canary_run_id: int,
) -> tuple[dict[str, Any], dict[str, str]]:
    expected_context = {
        "GITHUB_REPOSITORY": "layervai/nhp",
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_WORKFLOW_REF": (
            f"layervai/nhp/{PRODUCER_WORKFLOW_PATH}@refs/heads/main"
        ),
    }
    for name, expected in expected_context.items():
        if os.environ.get(name) != expected:
            raise EvidenceError(f"{name} must be exactly {expected}")
    producer_sha = os.environ.get("GITHUB_SHA", "")
    if not contract.SHA_RE.fullmatch(producer_sha):
        raise EvidenceError("GITHUB_SHA must be an exact lowercase commit SHA")
    producer_run_id = _positive_input(os.environ.get("GITHUB_RUN_ID", ""), "run id")
    producer_run_attempt = _positive_input(
        os.environ.get("GITHUB_RUN_ATTEMPT", ""), "run attempt"
    )
    main_ref = _gh("repos/layervai/nhp/git/ref/heads/main", "producer main ref")
    current_main_sha = (
        ((main_ref or {}).get("object") or {}).get("sha")
        if isinstance(main_ref, dict)
        else None
    )
    if current_main_sha != producer_sha:
        raise EvidenceError("producer workflow is not the current NHP main commit")
    _verify_commit("layervai/nhp", producer_sha, "producer workflow")

    candidates = {
        "qurl_connector": _resolve_candidate(
            "layervai/qurl-connector",
            connector_pr_number,
            "qurl-connector candidate",
        ),
        "qurl_go": _resolve_candidate(
            "layervai/qurl-go",
            qurl_go_pr_number,
            "qurl-go candidate",
        ),
    }
    default_branches = {
        key: _resolve_default_branch(key)
        for key in sorted(contract.DEFAULT_BRANCH_REPOSITORIES)
    }

    run = _gh(
        f"repos/layervai/qurl-connector/actions/runs/{canary_run_id}",
        "Connector canary run",
    )
    if not isinstance(run, dict):
        raise EvidenceError("Connector canary run response must be an object")
    head_repository = run.get("head_repository")
    if (
        run.get("id") != canary_run_id
        or run.get("path") != CANARY_WORKFLOW_PATH
        or run.get("event") != "workflow_dispatch"
        or run.get("status") != "completed"
        or run.get("conclusion") != "success"
        or run.get("head_branch") != "main"
        or not isinstance(head_repository, dict)
        or head_repository.get("full_name") != "layervai/qurl-connector"
    ):
        raise EvidenceError(
            "Connector canary must be one successful trusted-main workflow dispatch"
        )
    canary_head_sha = run.get("head_sha")
    if not isinstance(canary_head_sha, str) or not contract.SHA_RE.fullmatch(
        canary_head_sha
    ):
        raise EvidenceError("Connector canary run has no exact head SHA")
    _verify_commit(
        "layervai/qurl-connector", canary_head_sha, "Connector canary workflow"
    )
    run_attempt = run.get("run_attempt")
    if type(run_attempt) is not int or run_attempt <= 0:
        raise EvidenceError("Connector canary run attempt is invalid")
    attempt_run = _gh(
        (
            "repos/layervai/qurl-connector/actions/runs/"
            f"{canary_run_id}/attempts/{run_attempt}"
        ),
        "Connector canary run attempt",
    )
    if (
        not isinstance(attempt_run, dict)
        or attempt_run.get("id") != canary_run_id
        or attempt_run.get("run_attempt") != run_attempt
        or attempt_run.get("head_sha") != canary_head_sha
        or attempt_run.get("status") != "completed"
        or attempt_run.get("conclusion") != "success"
    ):
        raise EvidenceError("Connector canary current run attempt identity drift")
    attempt_started_at = contract._timestamp(
        attempt_run.get("run_started_at"),
        "Connector canary attempt start",
    )
    attempt_finished_at = contract._timestamp(
        attempt_run.get("updated_at"),
        "Connector canary attempt finish",
    )
    if attempt_finished_at < attempt_started_at:
        raise EvidenceError("Connector canary attempt timestamps are invalid")

    artifacts = _github_run_artifacts(canary_run_id)
    expected_name = (
        "connector-canary-pr-"
        f"{connector_pr_number}-{candidates['qurl_connector']['head_sha']}"
    )
    matches = [
        artifact
        for artifact in artifacts
        if isinstance(artifact, dict)
        and artifact.get("name") == expected_name
        and isinstance(artifact.get("created_at"), str)
        and (
            attempt_started_at - contract.MAX_CLOCK_SKEW
            <= contract._timestamp(
                artifact["created_at"],
                "Connector canary artifact creation",
            )
            <= attempt_finished_at + contract.MAX_CLOCK_SKEW
        )
    ]
    if len(matches) != 1:
        raise EvidenceError("Connector canary must expose one exact evidence artifact")
    artifact = matches[0]
    workflow_run = artifact.get("workflow_run")
    artifact_id = artifact.get("id")
    artifact_size = artifact.get("size_in_bytes")
    artifact_digest = artifact.get("digest")
    if (
        type(artifact_id) is not int
        or artifact_id <= 0
        or type(artifact_size) is not int
        or not 0 < artifact_size <= CANARY_ARTIFACT_MAX_BYTES
        or artifact.get("expired") is not False
        or not isinstance(artifact_digest, str)
        or not contract.DIGEST_RE.fullmatch(artifact_digest)
        or not isinstance(workflow_run, dict)
        or workflow_run.get("id") != canary_run_id
        or workflow_run.get("head_branch") != "main"
        or workflow_run.get("head_sha") != canary_head_sha
    ):
        raise EvidenceError("Connector canary artifact metadata is not run-bound")

    metadata = {
        "schema_version": 1,
        "producer": {
            "repository": "layervai/nhp",
            "workflow_path": PRODUCER_WORKFLOW_PATH,
            "run_id": producer_run_id,
            "run_attempt": producer_run_attempt,
            "head_sha": producer_sha,
        },
        "candidates": candidates,
        "default_branches": default_branches,
        "canary": {
            "repository": "layervai/qurl-connector",
            "workflow_path": CANARY_WORKFLOW_PATH,
            "run_id": canary_run_id,
            "run_attempt": run_attempt,
            "head_sha": canary_head_sha,
            "artifact_id": artifact_id,
            "artifact_name": expected_name,
            "artifact_digest": artifact_digest,
            "artifact_size": artifact_size,
        },
    }
    outputs = {
        "canary_artifact_id": str(artifact_id),
        "canary_artifact_digest": artifact_digest,
        "canary_run_attempt": str(run_attempt),
        "canary_head_sha": canary_head_sha,
    }
    return metadata, outputs


def _read_bounded(path: Path, maximum: int, name: str) -> bytes:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise EvidenceError(f"{name} is missing") from exc
    if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
        raise EvidenceError(f"{name} must be a regular file")
    raw = path.read_bytes()
    if not raw or len(raw) > maximum:
        raise EvidenceError(f"{name} must contain 1..{maximum} bytes")
    return raw


def _read_json(path: Path, maximum: int, name: str) -> dict[str, Any]:
    value = _loads(_read_bounded(path, maximum, name), name)
    if not isinstance(value, dict):
        raise EvidenceError(f"{name} must be a JSON object")
    return value


def _validate_canary_provenance(
    provenance: dict[str, Any],
    *,
    metadata: dict[str, Any],
) -> tuple[str, str, str, str]:
    root = _exact(
        provenance,
        {
            "schema",
            "repository",
            "pr_number",
            "head_sha",
            "signed_head_verified",
            "trusted_workflow",
            "workflow_run",
            "build",
            "connector_modules",
            "image",
        },
        "canary provenance",
    )
    candidate = metadata["candidates"]["qurl_connector"]
    canary = metadata["canary"]
    if (
        root["schema"] != "layerv.qurl-connector.canary-provenance.v1"
        or root["repository"] != "layervai/qurl-connector"
        or root["pr_number"] != candidate["pull_request_number"]
        or root["head_sha"] != candidate["head_sha"]
        or root["signed_head_verified"] is not True
    ):
        raise EvidenceError("canary provenance candidate identity drift")
    trusted = _exact(
        root["trusted_workflow"], {"sha", "ref"}, "canary trusted_workflow"
    )
    expected_workflow_ref = (
        f"layervai/qurl-connector/{CANARY_WORKFLOW_PATH}@refs/heads/main"
    )
    if trusted["sha"] != canary["head_sha"] or trusted["ref"] != expected_workflow_ref:
        raise EvidenceError("canary trusted workflow identity drift")
    workflow_run = _exact(
        root["workflow_run"], {"id", "attempt"}, "canary workflow_run"
    )
    if str(workflow_run["id"]) != str(canary["run_id"]) or str(
        workflow_run["attempt"]
    ) != str(canary["run_attempt"]):
        raise EvidenceError("canary provenance run identity drift")
    build = _exact(
        root["build"],
        {
            "platform",
            "date",
            "source_sha256",
            "source_artifact_digest",
            "definition_sha256",
        },
        "canary build",
    )
    if build["platform"] != "linux/amd64":
        raise EvidenceError("Connector canary must be linux/amd64")
    contract._timestamp(build["date"], "canary build date")
    contract._sha256(build["source_sha256"], "canary source sha256")
    # Bare lowercase SHA-256, not an OCI "sha256:"-prefixed descriptor. This is
    # the content hash of the canary's source artifact archive, exactly like its
    # sibling source_sha256 and definition_sha256 in the same build block; the
    # OCI form belongs to image and layer descriptors. The canary has always
    # emitted the bare form -- verified against the published provenance of runs
    # 29994779471 (2026-07-23) and 30216718538 (2026-07-26) -- so _digest here
    # could never have matched a real canary, and this step had simply never
    # been reached before.
    contract._sha256(
        build["source_artifact_digest"], "canary source artifact digest"
    )
    contract._sha256(build["definition_sha256"], "canary definition sha256")

    modules = _exact(
        root["connector_modules"],
        {"module_path", "frp", "qurl_go", "yamux"},
        "canary connector_modules",
    )
    if modules["module_path"] != "github.com/layervai/qurl-reverse-tunnel-client":
        raise EvidenceError("canary module path is unexpected")
    frp = _exact(
        modules["frp"],
        {
            "required_version",
            "version",
            "sha",
            "archive_sha256",
            "artifact_digest",
            "replacement",
        },
        "canary FRP module",
    )
    if (
        frp["required_version"] != "v0.70.0"
        or not isinstance(frp["version"], str)
        or not MODULE_VERSION_RE.fullmatch(frp["version"])
        or frp["replacement"] != "./frp"
    ):
        raise EvidenceError("canary FRP module contract drift")
    frp_sha = contract._sha(frp["sha"], "canary FRP SHA")
    contract._sha256(frp["archive_sha256"], "canary FRP archive sha256")
    # Bare lowercase SHA-256, matching build.source_artifact_digest. Across the
    # canary's whole evidence document exactly one value is an OCI descriptor --
    # image.digest, validated with _digest below. Every other hash, including
    # both *_artifact_digest fields, is a plain content hash of an archive.
    contract._sha256(frp["artifact_digest"], "canary FRP artifact digest")
    qurl_go = _exact(
        modules["qurl_go"],
        {"version", "sha", "sum", "go_mod_sum", "replaced"},
        "canary qurl-go module",
    )
    if (
        not isinstance(qurl_go["version"], str)
        or not MODULE_VERSION_RE.fullmatch(qurl_go["version"])
        or qurl_go["replaced"] is not False
        or not isinstance(qurl_go["sum"], str)
        or not GO_SUM_RE.fullmatch(qurl_go["sum"])
        or not isinstance(qurl_go["go_mod_sum"], str)
        or not GO_SUM_RE.fullmatch(qurl_go["go_mod_sum"])
    ):
        raise EvidenceError("canary qurl-go module contract drift")
    qurl_go_sha = contract._sha(qurl_go["sha"], "canary qurl-go SHA")
    if qurl_go_sha != metadata["candidates"]["qurl_go"]["head_sha"]:
        raise EvidenceError("canary qurl-go module is not the current candidate")
    yamux = _exact(
        modules["yamux"],
        {"required_version", "replacement", "version", "sum"},
        "canary yamux module",
    )
    for value in yamux.values():
        contract._string(value, "canary yamux value")

    image = _exact(
        root["image"],
        {
            "local_tag",
            "digest",
            "archive_sha256",
            "buildkit_metadata_sha256",
            "go_version_m_sha256",
            "version_output_sha256",
        },
        "canary image",
    )
    image_digest = contract._digest(image["digest"], "canary image digest")
    for key in (
        "archive_sha256",
        "buildkit_metadata_sha256",
        "go_version_m_sha256",
        "version_output_sha256",
    ):
        contract._sha256(image[key], f"canary image {key}")
    contract._string(image["local_tag"], "canary local tag")
    return frp["version"], frp_sha, qurl_go_sha, image_digest


def validate_canary_files(
    *,
    metadata: dict[str, Any],
    directory: Path,
) -> tuple[dict[str, Any], dict[str, str]]:
    if not directory.is_dir() or directory.is_symlink():
        raise EvidenceError("canary artifact path must be a real directory")
    discovered = {path.name for path in directory.iterdir()}
    if discovered != set(CANARY_FILES):
        raise EvidenceError(
            f"canary artifact files must be exactly {sorted(CANARY_FILES)}"
        )
    provenance_raw = _read_bounded(
        directory / "provenance.json",
        CANARY_FILES["provenance.json"],
        "canary provenance.json",
    )
    provenance = _loads(provenance_raw, "canary provenance.json")
    if not isinstance(provenance, dict):
        raise EvidenceError("canary provenance must be an object")
    frp_version, frp_sha, qurl_go_sha, image_digest = _validate_canary_provenance(
        provenance, metadata=metadata
    )
    provenance_sha256 = hashlib.sha256(provenance_raw).hexdigest()

    published = _read_json(
        directory / "published-canary.json",
        CANARY_FILES["published-canary.json"],
        "published-canary.json",
    )
    published = _exact(
        published,
        {
            "schema",
            "repository",
            "pr_number",
            "head_ref",
            "head_sha",
            "image_ref",
            "image_digest",
            "provenance_sha256",
            "workflow_run",
        },
        "published canary",
    )
    workflow_run = _exact(
        published["workflow_run"], {"id", "attempt"}, "published canary workflow_run"
    )
    candidate = metadata["candidates"]["qurl_connector"]
    canary = metadata["canary"]
    image_ref = published["image_ref"]
    if (
        published["schema"] != "layerv.qurl-connector.published-canary.v1"
        or published["repository"] != "layervai/qurl-connector"
        or published["pr_number"] != candidate["pull_request_number"]
        or published["head_ref"] != candidate["head_ref"]
        or published["head_sha"] != candidate["head_sha"]
        or not isinstance(image_ref, str)
        or not IMAGE_REF_RE.fullmatch(image_ref)
        or published["image_digest"] != image_digest
        or image_ref != f"ghcr.io/layervai/qurl-connector-canary@{image_digest}"
        or published["provenance_sha256"] != provenance_sha256
        or str(workflow_run["id"]) != str(canary["run_id"])
        or str(workflow_run["attempt"]) != str(canary["run_attempt"])
    ):
        raise EvidenceError("published canary handoff differs from authenticated run")

    buildkit_raw = _read_bounded(
        directory / "buildkit-metadata.json",
        CANARY_FILES["buildkit-metadata.json"],
        "canary buildkit metadata",
    )
    if (
        hashlib.sha256(buildkit_raw).hexdigest()
        != provenance["image"]["buildkit_metadata_sha256"]
    ):
        raise EvidenceError("canary buildkit metadata digest drift")
    buildkit = _loads(buildkit_raw, "canary buildkit metadata")
    if (
        not isinstance(buildkit, dict)
        or buildkit.get("containerimage.digest") != image_digest
        or (
            (buildkit.get("containerimage.descriptor") or {}).get("platform") or {}
        ).get("os")
        != "linux"
        or (
            (buildkit.get("containerimage.descriptor") or {}).get("platform") or {}
        ).get("architecture")
        != "amd64"
    ):
        raise EvidenceError("canary BuildKit platform or digest drift")
    for filename, provenance_key in (
        ("go-version-m.txt", "go_version_m_sha256"),
        ("version-output.txt", "version_output_sha256"),
    ):
        raw = _read_bounded(
            directory / filename, CANARY_FILES[filename], f"canary {filename}"
        )
        if hashlib.sha256(raw).hexdigest() != provenance["image"][provenance_key]:
            raise EvidenceError(f"canary {filename} digest drift")

    result = {
        "schema_version": 1,
        "producer": metadata["producer"],
        "candidates": metadata["candidates"],
        "default_branches": metadata["default_branches"],
        "canary": {
            **metadata["canary"],
            "image_ref": image_ref,
            "image_digest": image_digest,
            "provenance_sha256": provenance_sha256,
            "frp_version": frp_version,
            "frp_sha": frp_sha,
            "qurl_go_sha": qurl_go_sha,
        },
    }
    return result, {
        "canary_image_ref": image_ref,
        "canary_image_digest": image_digest,
    }


def _read_metadata(path: Path) -> dict[str, Any]:
    return contract.load_canonical_file(
        path,
        maximum=GITHUB_METADATA_MAX_BYTES,
        name="GitHub evidence metadata",
    )


def _ssm_parameter(name: str) -> dict[str, Any]:
    response = _aws(
        "ssm",
        ["get-parameter", "--name", name],
        f"SSM parameter {name}",
    )
    parameter = response.get("Parameter") if isinstance(response, dict) else None
    if (
        not isinstance(parameter, dict)
        or parameter.get("Name") != name
        or parameter.get("Type") != "String"
        or type(parameter.get("Version")) is not int
        or parameter["Version"] <= 0
        or not isinstance(parameter.get("Value"), str)
    ):
        raise EvidenceError(f"SSM parameter {name} is not one exact public String")
    return parameter


def _parse_image_uri(value: str, name: str) -> tuple[str, str]:
    match = re.fullmatch(
        rf"{AWS_ACCOUNT_ID}\.dkr\.ecr\.{AWS_REGION}\.amazonaws\.com/"
        r"(?P<repository>[a-z0-9][a-z0-9./_-]*)@"
        r"(?P<digest>sha256:[0-9a-f]{64})",
        value,
    )
    if not match:
        raise EvidenceError(f"{name} must be one exact sandbox ECR digest URI")
    repository = match.group("repository")
    if not contract.ECR_REPOSITORY_RE.fullmatch(repository):
        raise EvidenceError(f"{name} has an invalid ECR repository")
    return repository, match.group("digest")


def _verify_ecr_runtime_image(
    value: Any,
    *,
    expected_repository: str,
    name: str,
) -> None:
    if not isinstance(value, str):
        raise EvidenceError(f"{name} must be an ECR image reference")
    match = re.fullmatch(
        rf"{AWS_ACCOUNT_ID}\.dkr\.ecr\.{AWS_REGION}\.amazonaws\.com/"
        rf"(?P<repository>{re.escape(expected_repository)})"
        r"(?::[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}|@sha256:[0-9a-f]{64})",
        value,
    )
    if not match or match.group("repository") != expected_repository:
        raise EvidenceError(
            f"{name} repository differs from the expected ECR repository"
        )


def _ecr_manifest(
    repository: str, digest: str, name: str
) -> tuple[dict[str, Any], str]:
    response = _aws(
        "ecr",
        [
            "batch-get-image",
            "--repository-name",
            repository,
            "--image-ids",
            f"imageDigest={digest}",
            "--accepted-media-types",
            "application/vnd.oci.image.index.v1+json",
            "application/vnd.docker.distribution.manifest.list.v2+json",
            "application/vnd.oci.image.manifest.v1+json",
            "application/vnd.docker.distribution.manifest.v2+json",
        ],
        f"{name} ECR manifest",
    )
    if (
        not isinstance(response, dict)
        or response.get("failures") != []
        or not isinstance(response.get("images"), list)
        or len(response["images"]) != 1
    ):
        raise EvidenceError(f"{name} ECR digest does not resolve exactly once")
    image = response["images"][0]
    if (
        not isinstance(image, dict)
        or image.get("imageId", {}).get("imageDigest") != digest
    ):
        raise EvidenceError(f"{name} ECR response digest drift")
    manifest_raw = image.get("imageManifest")
    if not isinstance(manifest_raw, str) or len(manifest_raw) > 256 * 1024:
        raise EvidenceError(f"{name} ECR manifest is missing or oversized")
    if hashlib.sha256(manifest_raw.encode("utf-8")).hexdigest() != digest.removeprefix(
        "sha256:"
    ):
        raise EvidenceError(f"{name} ECR manifest content digest drift")
    manifest = _loads(manifest_raw, f"{name} ECR manifest")
    if not isinstance(manifest, dict):
        raise EvidenceError(f"{name} ECR manifest must be an object")
    return manifest, str(image.get("imageManifestMediaType", ""))


def _ecr_config(repository: str, digest: str, name: str) -> tuple[dict[str, Any], str]:
    manifest, media_type = _ecr_manifest(repository, digest, name)
    if media_type in {
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
    }:
        descriptors = manifest.get("manifests")
        if not isinstance(descriptors, list):
            raise EvidenceError(f"{name} image index has no descriptors")
        platform_descriptors = [
            descriptor
            for descriptor in descriptors
            if isinstance(descriptor, dict)
            and isinstance(descriptor.get("platform"), dict)
            and descriptor["platform"].get("os") == "linux"
            and descriptor["platform"].get("architecture") == "amd64"
        ]
        known_platforms = [
            descriptor
            for descriptor in descriptors
            if isinstance(descriptor, dict)
            and isinstance(descriptor.get("platform"), dict)
            and descriptor["platform"].get("os") != "unknown"
        ]
        if len(platform_descriptors) != 1 or len(known_platforms) != 1:
            raise EvidenceError(f"{name} must expose exactly linux/amd64")
        child_digest = contract._digest(
            platform_descriptors[0].get("digest"),
            f"{name} linux/amd64 child digest",
        )
        child_manifest, child_type = _ecr_manifest(
            repository, child_digest, f"{name} linux/amd64 child"
        )
        if child_type not in {
            "application/vnd.oci.image.manifest.v1+json",
            "application/vnd.docker.distribution.manifest.v2+json",
        }:
            raise EvidenceError(f"{name} linux/amd64 child is not an image manifest")
        manifest = child_manifest
    elif media_type not in {
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json",
    }:
        raise EvidenceError(f"{name} has an unsupported image media type")
    config = manifest.get("config")
    config_digest = config.get("digest") if isinstance(config, dict) else None
    if not isinstance(config_digest, str) or not contract.DIGEST_RE.fullmatch(
        config_digest
    ):
        raise EvidenceError(f"{name} image config digest is invalid")
    download = _aws(
        "ecr",
        [
            "get-download-url-for-layer",
            "--repository-name",
            repository,
            "--layer-digest",
            config_digest,
        ],
        f"{name} ECR config URL",
    )
    url = download.get("downloadUrl") if isinstance(download, dict) else None
    if not isinstance(url, str) or not url.startswith("https://"):
        raise EvidenceError(f"{name} ECR config URL is missing")
    try:
        with urllib.request.urlopen(url, timeout=30) as response:
            raw = response.read(256 * 1024 + 1)
    except (OSError, urllib.error.URLError) as exc:
        raise EvidenceError(f"{name} ECR config could not be downloaded") from exc
    if not raw or len(raw) > 256 * 1024:
        raise EvidenceError(f"{name} ECR config is missing or oversized")
    if hashlib.sha256(raw).hexdigest() != config_digest.removeprefix("sha256:"):
        raise EvidenceError(f"{name} ECR config content digest drift")
    value = _loads(raw, f"{name} ECR config")
    if not isinstance(value, dict):
        raise EvidenceError(f"{name} ECR config must be an object")
    return value, config_digest


def _oci_revision(
    repository: str, digest: str, name: str
) -> tuple[str, dict[str, Any]]:
    config, config_digest = _ecr_config(repository, digest, name)
    labels = (config.get("config") or {}).get("Labels")
    revision = (
        labels.get("org.opencontainers.image.revision")
        if isinstance(labels, dict)
        else None
    )
    if not isinstance(revision, str) or not contract.SHA_RE.fullmatch(revision):
        raise EvidenceError(f"{name} has no full OCI source revision label")
    return revision, {
        "kind": "oci_revision_label",
        "manifest_digest": digest,
        "config_digest": config_digest,
        "revision_label": revision,
    }


def _qrts_build_receipt(
    repository: str,
    digest: str,
    name: str,
    expected_source_revision: str,
) -> tuple[str, dict[str, Any]]:
    if repository != QRTS_ECR_REPOSITORY:
        raise EvidenceError(f"{name} uses an unexpected ECR repository")
    config, config_digest = _ecr_config(repository, digest, name)
    labels = (config.get("config") or {}).get("Labels")
    if not isinstance(labels, dict):
        raise EvidenceError(f"{name} has no OCI labels")
    revision = labels.get("org.opencontainers.image.revision")
    if not isinstance(revision, str) or not contract.SHA_RE.fullmatch(revision):
        raise EvidenceError(f"{name} has no full OCI source revision label")
    expected_source_revision = contract._sha(
        expected_source_revision,
        f"{name} expected main source revision",
    )
    if revision != expected_source_revision:
        raise EvidenceError(f"{name} OCI revision is not the expected main commit")

    _verify_qrts_runtime_signature(repository, digest, expected_source_revision)
    receipt = _verify_qrts_build_receipt_attestation(
        repository,
        digest,
        expected_source_revision,
    )
    receipt_raw = _qrts_canonical_receipt_bytes(receipt)
    return revision, {
        "kind": "ecr_build_receipt",
        "manifest_digest": digest,
        "config_digest": config_digest,
        "revision_label": revision,
        "installed_binary_sha256": receipt["binary_sha256"],
        "build_receipt_sha256": hashlib.sha256(receipt_raw).hexdigest(),
    }


def _verify_qrts_runtime_signature(
    repository: str,
    digest: str,
    expected_source_revision: str,
) -> None:
    image_uri = (
        f"{AWS_ACCOUNT_ID}.dkr.ecr.{AWS_REGION}.amazonaws.com/{repository}@{digest}"
    )
    cache_key = (image_uri, expected_source_revision)
    if cache_key in _VERIFIED_QRTS_RUNTIME_SIGNATURES:
        return
    result = _run_bounded(
        [
            "cosign",
            "verify",
            image_uri,
            "--certificate-identity",
            QRTS_COSIGN_IDENTITY,
            "--certificate-oidc-issuer",
            "https://token.actions.githubusercontent.com",
            "--certificate-github-workflow-name",
            "Docker Publish",
            "--certificate-github-workflow-ref",
            "refs/heads/main",
            "--certificate-github-workflow-repository",
            QRTS_COSIGN_REPOSITORY,
            "--certificate-github-workflow-sha",
            expected_source_revision,
        ],
        "qRTS runtime signature",
        maximum=1024 * 1024,
    )
    if result.returncode != 0:
        stderr = result.stderr.decode("utf-8", errors="replace")[:1000]
        raise EvidenceError(
            f"qRTS runtime signature verification failed: {stderr}"
        ) from None
    _VERIFIED_QRTS_RUNTIME_SIGNATURES.add(cache_key)


def _json_stream(raw: bytes, name: str, *, maximum_count: int) -> list[Any]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise EvidenceError(f"{name} is not valid UTF-8 JSON") from exc
    decoder = json.JSONDecoder(
        object_pairs_hook=contract._reject_duplicate_keys,
        parse_constant=contract._reject_nonfinite,
        parse_float=contract._parse_finite_float,
    )
    values: list[Any] = []
    offset = 0
    while offset < len(text):
        while offset < len(text) and text[offset].isspace():
            offset += 1
        if offset == len(text):
            break
        try:
            value, offset = decoder.raw_decode(text, offset)
        except json.JSONDecodeError as exc:
            raise EvidenceError(f"{name} is not a valid JSON stream") from exc
        if isinstance(value, list):
            values.extend(value)
        else:
            values.append(value)
        if len(values) > maximum_count:
            raise EvidenceError(f"{name} has too many records")
    return values


def _qrts_canonical_receipt_bytes(receipt: dict[str, Any]) -> bytes:
    raw = (
        '{"schema_version":1,"source_revision":"%s","binary_path":"%s",'
        '"binary_sha256":"%s"}\n'
        % (
            receipt["source_revision"],
            QRTS_BUILD_RECEIPT_BINARY_PATH,
            receipt["binary_sha256"],
        )
    ).encode("ascii")
    if len(raw) > QRTS_BUILD_RECEIPT_MAX_BYTES:
        raise EvidenceError("qRTS canonical build receipt is oversized")
    return raw


def _qrts_receipt_from_verified_attestations(
    raw: bytes,
    *,
    image_repository: str,
    digest: str,
    expected_source_revision: str,
) -> dict[str, Any]:
    if not raw or len(raw) > QRTS_VERIFIED_ATTESTATIONS_MAX_BYTES:
        raise EvidenceError(
            "qRTS verified build-receipt attestations are missing or oversized"
        )
    records = _json_stream(
        raw,
        "qRTS verified build-receipt attestations",
        maximum_count=QRTS_VERIFIED_ATTESTATIONS_MAX_COUNT,
    )
    if not records:
        raise EvidenceError("qRTS has no verified build-receipt attestation")

    expected_subject = (
        f"{AWS_ACCOUNT_ID}.dkr.ecr.{AWS_REGION}.amazonaws.com/{image_repository}"
    )
    expected_digest = contract._digest(digest, "qRTS attestation subject digest")
    expected_source_revision = contract._sha(
        expected_source_revision,
        "qRTS attestation expected source revision",
    )
    receipts: list[dict[str, Any]] = []
    canonical_receipts: set[bytes] = set()
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            raise EvidenceError(
                f"qRTS verified attestation record {index} must be an object"
            )
        payload = record.get("payload")
        if not isinstance(payload, str) or len(payload) > 256 * 1024:
            raise EvidenceError(
                f"qRTS verified attestation record {index} has no bounded payload"
            )
        try:
            statement_raw = base64.b64decode(payload, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise EvidenceError(
                f"qRTS verified attestation record {index} payload is not base64"
            ) from exc
        if not statement_raw or len(statement_raw) > 64 * 1024:
            raise EvidenceError(
                f"qRTS verified attestation statement {index} is missing or oversized"
            )
        statement = _exact(
            _loads(statement_raw, f"qRTS verified attestation statement {index}"),
            {"_type", "predicateType", "subject", "predicate"},
            f"qRTS verified attestation statement {index}",
        )
        if (
            statement["_type"] != "https://in-toto.io/Statement/v0.1"
            or statement["predicateType"] != QRTS_BUILD_RECEIPT_ATTESTATION_TYPE
        ):
            raise EvidenceError(
                f"qRTS verified attestation statement {index} type drift"
            )
        subjects = statement["subject"]
        if not isinstance(subjects, list) or len(subjects) != 1:
            raise EvidenceError(
                f"qRTS verified attestation statement {index} must have one subject"
            )
        subject = _exact(
            subjects[0],
            {"name", "digest"},
            f"qRTS verified attestation statement {index} subject",
        )
        subject_digest = _exact(
            subject["digest"],
            {"sha256"},
            f"qRTS verified attestation statement {index} subject digest",
        )
        if subject["name"] != expected_subject or subject_digest[
            "sha256"
        ] != expected_digest.removeprefix("sha256:"):
            raise EvidenceError(
                f"qRTS verified attestation statement {index} subject drift"
            )
        receipt = _exact(
            statement["predicate"],
            {"schema_version", "source_revision", "binary_path", "binary_sha256"},
            f"qRTS verified attestation statement {index} receipt",
        )
        if (
            type(receipt["schema_version"]) is not int
            or receipt["schema_version"] != 1
            or receipt["source_revision"] != expected_source_revision
            or receipt["binary_path"] != QRTS_BUILD_RECEIPT_BINARY_PATH
            or not isinstance(receipt["binary_sha256"], str)
            or not contract.SHA256_RE.fullmatch(receipt["binary_sha256"])
        ):
            raise EvidenceError(
                f"qRTS verified attestation statement {index} receipt drift"
            )
        canonical_receipts.add(_qrts_canonical_receipt_bytes(receipt))
        receipts.append(receipt)

    if len(canonical_receipts) != 1:
        raise EvidenceError("qRTS verified build-receipt attestations diverge")
    return receipts[0]


def _verify_qrts_build_receipt_attestation(
    repository: str,
    digest: str,
    expected_source_revision: str,
) -> dict[str, Any]:
    image_uri = (
        f"{AWS_ACCOUNT_ID}.dkr.ecr.{AWS_REGION}.amazonaws.com/{repository}@{digest}"
    )
    result = _run_bounded(
        [
            "cosign",
            "verify-attestation",
            image_uri,
            "--type",
            QRTS_BUILD_RECEIPT_ATTESTATION_TYPE,
            "--certificate-identity",
            QRTS_COSIGN_IDENTITY,
            "--certificate-oidc-issuer",
            "https://token.actions.githubusercontent.com",
            "--certificate-github-workflow-name",
            "Docker Publish",
            "--certificate-github-workflow-ref",
            "refs/heads/main",
            "--certificate-github-workflow-repository",
            QRTS_COSIGN_REPOSITORY,
            "--certificate-github-workflow-sha",
            expected_source_revision,
        ],
        "qRTS build-receipt attestation",
        maximum=QRTS_VERIFIED_ATTESTATIONS_MAX_BYTES,
    )
    if result.returncode != 0:
        stderr = result.stderr.decode("utf-8", errors="replace")[:1000]
        raise EvidenceError(
            f"qRTS build-receipt attestation verification failed: {stderr}"
        ) from None
    return _qrts_receipt_from_verified_attestations(
        result.stdout,
        image_repository=repository,
        digest=digest,
        expected_source_revision=expected_source_revision,
    )


def _runtime_contract(
    parameter_name: str,
    *,
    expected_repository: str,
    expected_digest: str,
) -> tuple[str, dict[str, Any]]:
    parameter = _ssm_parameter(parameter_name)
    raw = parameter["Value"].encode("utf-8")
    value = contract.parse_canonical_bytes(
        raw, maximum=4096, name=f"{parameter_name} value"
    )
    value = _exact(
        value,
        {"image_uri", "schema_version", "source_revision"},
        f"{parameter_name} value",
    )
    repository, digest = _parse_image_uri(
        value["image_uri"], f"{parameter_name}.image_uri"
    )
    if (
        value["schema_version"] != 1
        or type(value["schema_version"]) is not int
        or repository != expected_repository
        or digest != expected_digest
    ):
        raise EvidenceError(f"{parameter_name} does not match the live image")
    revision = contract._sha(
        value["source_revision"], f"{parameter_name}.source_revision"
    )
    _verify_qurl_runtime_attestation(value["image_uri"], revision)
    return revision, {
        "kind": "ssm_runtime_contract",
        "parameter_name": parameter_name,
        "parameter_version": parameter["Version"],
        "contract_sha256": hashlib.sha256(raw).hexdigest(),
        "image_uri": value["image_uri"],
        "source_revision": revision,
    }


def _verify_qurl_runtime_attestation(image_uri: str, source_revision: str) -> None:
    identity = (image_uri, source_revision)
    if identity in _VERIFIED_QURL_RUNTIME_ATTESTATIONS:
        return
    result = _run_bounded(
        [
            "gh",
            "attestation",
            "verify",
            f"oci://{image_uri}",
            "--repo",
            "layervai/qurl-service",
            "--signer-workflow",
            QURL_RUNTIME_SIGNER,
            "--source-digest",
            source_revision,
            "--source-ref",
            "refs/heads/main",
            "--deny-self-hosted-runners",
        ],
        "qurl-service runtime attestation",
        maximum=1024 * 1024,
    )
    if result.returncode != 0:
        stderr = result.stderr.decode("utf-8", errors="replace")[:1000]
        raise EvidenceError(
            f"qurl-service runtime attestation verification failed: {stderr}"
        ) from None
    _VERIFIED_QURL_RUNTIME_ATTESTATIONS.add(identity)


def _runtime_attestation_collector_contract() -> dict[str, Any]:
    parameter = _ssm_parameter(ATTESTATION_COLLECTOR_PARAMETER)
    raw = parameter["Value"].encode("utf-8")
    value = contract.parse_canonical_bytes(
        raw,
        maximum=4096,
        name=f"{ATTESTATION_COLLECTOR_PARAMETER} value",
    )
    value = _exact(
        value,
        {
            "schema_version",
            "collector_sha256",
            "service_unit_sha256",
            "timer_unit_sha256",
            "repair_document_name",
            "repair_document_version",
            "repair_document_sha256",
            "bucket_policy_sha256",
        },
        f"{ATTESTATION_COLLECTOR_PARAMETER} value",
    )
    if value["schema_version"] != 1 or type(value["schema_version"]) is not int:
        raise EvidenceError("runtime-attestation collector schema_version must be 1")
    for field in (
        "collector_sha256",
        "service_unit_sha256",
        "timer_unit_sha256",
        "repair_document_sha256",
        "bucket_policy_sha256",
    ):
        contract._sha256(value[field], f"runtime-attestation collector {field}")
    document_name = contract._string(
        value["repair_document_name"],
        "runtime-attestation collector repair_document_name",
    )
    if document_name != "layerv-nhp-sandbox-runtime-attestation-repair":
        raise EvidenceError("runtime-attestation repair document identity drift")
    document_version = contract._string(
        value["repair_document_version"],
        "runtime-attestation collector repair_document_version",
    )
    if not re.fullmatch(r"[1-9][0-9]{0,9}", document_version):
        raise EvidenceError("runtime-attestation repair document version is invalid")
    return {
        **value,
        "parameter_name": ATTESTATION_COLLECTOR_PARAMETER,
        "parameter_version": parameter["Version"],
        "contract_sha256": hashlib.sha256(raw).hexdigest(),
    }


def _terraform_jsonencode_digest(value: Any, *, maximum: int, name: str) -> str:
    """Digest a document the way Terraform's jsonencode would have.

    Every digest in the collector contract is published by Terraform as
    `sha256(jsonencode(<value>))`, so re-deriving it here means reproducing
    Terraform's encoder, not merely "some canonical JSON".

    The two agree on the easy parts -- both sort object keys and emit compact
    separators -- which is why the bucket policy happened to match under plain
    canonical_bytes. They diverge on escaping: Terraform's jsonencode is Go's
    encoding/json, which HTML-escapes `<`, `>` and `&` into \\u003c, \\u003e and
    \\u0026. Python writes those characters literally.

    That difference is invisible until a document actually contains them -- and
    the repair document is a shell script full of `>` redirects and `&&`, so it
    diverged on every single run while the policy did not. Reproducing the
    escaping yields the published digest exactly.

    U+2028/U+2029 are escaped for the same reason: Go escapes them too, and a
    document is free to contain them.
    """
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    for character, escape in (
        ("<", "\\u003c"),
        (">", "\\u003e"),
        ("&", "\\u0026"),
        ("\u2028", "\\u2028"),
        ("\u2029", "\\u2029"),
    ):
        encoded = encoded.replace(character, escape)
    raw = encoded.encode("utf-8")
    if len(raw) > maximum:
        raise EvidenceError(f"{name} is oversized")
    return hashlib.sha256(raw).hexdigest()


def _validate_repair_document(collector_contract: dict[str, Any]) -> None:
    response = _aws(
        "ssm",
        [
            "get-document",
            "--name",
            collector_contract["repair_document_name"],
            "--document-version",
            collector_contract["repair_document_version"],
            "--document-format",
            "JSON",
        ],
        "runtime-attestation repair document",
    )
    content = response.get("Content") if isinstance(response, dict) else None
    if (
        not isinstance(content, str)
        or response.get("Name") != collector_contract["repair_document_name"]
        or response.get("DocumentVersion")
        != collector_contract["repair_document_version"]
        or response.get("DocumentType") != "Command"
    ):
        raise EvidenceError("runtime-attestation repair document identity drift")
    document = _loads(content, "runtime-attestation repair document content")
    if not isinstance(document, dict):
        raise EvidenceError("runtime-attestation repair document must be JSON")
    digest = _terraform_jsonencode_digest(
        document,
        maximum=64 * 1024,
        name="runtime-attestation repair document",
    )
    if digest != collector_contract["repair_document_sha256"]:
        raise EvidenceError("runtime-attestation repair document content drift")


def _collect_ecs_workload(workload_key: str) -> dict[str, Any]:
    spec = ECS_WORKLOADS[workload_key]
    cluster = spec["cluster"]
    service_name = spec["service"]
    response = _aws(
        "ecs",
        [
            "describe-services",
            "--cluster",
            cluster,
            "--services",
            service_name,
        ],
        f"{workload_key} ECS service",
    )
    services = response.get("services") if isinstance(response, dict) else None
    failures = response.get("failures") if isinstance(response, dict) else None
    if (
        not isinstance(services, list)
        or len(services) != 1
        or failures not in ([], None)
    ):
        raise EvidenceError(f"{workload_key} ECS service is missing")
    service = services[0]
    deployments = service.get("deployments")
    if (
        service.get("status") != "ACTIVE"
        or type(service.get("desiredCount")) is not int
        or service["desiredCount"] <= 0
        or service.get("runningCount") != service["desiredCount"]
        or service.get("pendingCount") != 0
        or not isinstance(deployments, list)
        or len(deployments) != 1
    ):
        raise EvidenceError(f"{workload_key} ECS service is not stably converged")
    deployment = deployments[0]
    if (
        deployment.get("status") != "PRIMARY"
        or deployment.get("rolloutState") != "COMPLETED"
        or deployment.get("taskDefinition") != service.get("taskDefinition")
        or deployment.get("desiredCount") != service["desiredCount"]
        or deployment.get("runningCount") != service["desiredCount"]
        or deployment.get("pendingCount") != 0
    ):
        raise EvidenceError(f"{workload_key} ECS primary deployment is not stable")
    cluster_arn = service.get("clusterArn")
    service_arn = service.get("serviceArn")
    task_definition = service.get("taskDefinition")
    for value, label in (
        (cluster_arn, "cluster ARN"),
        (service_arn, "service ARN"),
        (task_definition, "task definition ARN"),
    ):
        contract._arn(value, f"{workload_key} {label}")

    listed = _aws(
        "ecs",
        [
            "list-tasks",
            "--cluster",
            cluster,
            "--service-name",
            service_name,
            "--desired-status",
            "RUNNING",
        ],
        f"{workload_key} ECS task list",
    )
    task_arns = listed.get("taskArns") if isinstance(listed, dict) else None
    if (
        not isinstance(listed, dict)
        or listed.get("nextToken") not in (None, "")
        or not isinstance(task_arns, list)
        or len(task_arns) != service["desiredCount"]
        or not 1 <= len(task_arns) <= contract.MAX_TASKS
        or len(set(task_arns)) != len(task_arns)
    ):
        raise EvidenceError(f"{workload_key} ECS task set differs from desired count")
    task_arns = sorted(task_arns)
    described = _aws(
        "ecs",
        ["describe-tasks", "--cluster", cluster, "--tasks", *task_arns],
        f"{workload_key} ECS tasks",
    )
    tasks = described.get("tasks") if isinstance(described, dict) else None
    if (
        not isinstance(tasks, list)
        or len(tasks) != len(task_arns)
        or any(not isinstance(task, dict) for task in tasks)
    ):
        raise EvidenceError(f"{workload_key} ECS tasks are incomplete")
    normalized_tasks = []
    image_digest = None
    for task in sorted(tasks, key=lambda item: item.get("taskArn", "")):
        containers = task.get("containers")
        matches = [
            container
            for container in containers or []
            if isinstance(container, dict)
            and container.get("name") == spec["container"]
        ]
        if (
            task.get("lastStatus") != "RUNNING"
            or task.get("healthStatus") != "HEALTHY"
            or task.get("taskDefinitionArn") != task_definition
            or len(matches) != 1
            or matches[0].get("lastStatus") != "RUNNING"
            or matches[0].get("healthStatus") != "HEALTHY"
        ):
            raise EvidenceError(f"{workload_key} ECS task is not healthy and exact")
        container_digest = matches[0].get("imageDigest")
        if not isinstance(container_digest, str) or not contract.DIGEST_RE.fullmatch(
            container_digest
        ):
            raise EvidenceError(f"{workload_key} ECS task has no image digest")
        if image_digest is None:
            image_digest = container_digest
        elif image_digest != container_digest:
            raise EvidenceError(f"{workload_key} ECS tasks run mixed image digests")
        _verify_ecr_runtime_image(
            matches[0].get("image"),
            expected_repository=spec["repository"],
            name=f"{workload_key} running container image",
        )
        private_addresses = sorted(
            detail["value"]
            for attachment in task.get("attachments") or []
            if isinstance(attachment, dict)
            and attachment.get("type") == "ElasticNetworkInterface"
            and attachment.get("status") == "ATTACHED"
            for detail in attachment.get("details") or []
            if isinstance(detail, dict)
            and detail.get("name") == "privateIPv4Address"
            and isinstance(detail.get("value"), str)
        )
        if not 1 <= len(private_addresses) <= 8 or len(set(private_addresses)) != len(
            private_addresses
        ):
            raise EvidenceError(f"{workload_key} ECS task ENI identity is ambiguous")
        for raw_address in private_addresses:
            try:
                address = ipaddress.ip_address(raw_address)
            except ValueError as exc:
                raise EvidenceError(
                    f"{workload_key} ECS task has an invalid private address"
                ) from exc
            if address.version != 4 or not address.is_private:
                raise EvidenceError(
                    f"{workload_key} ECS task has a non-private IPv4 address"
                )
        normalized_tasks.append(
            {
                "task_arn": task["taskArn"],
                "container_name": spec["container"],
                "image_digest": container_digest,
                "private_ipv4_addresses": private_addresses,
            }
        )
    if image_digest is None:
        raise EvidenceError(f"{workload_key} ECS task set has no image identity")
    if spec["source_parameter"] is None:
        source_revision, source_evidence = _oci_revision(
            spec["repository"], image_digest, workload_key
        )
    else:
        _ecr_manifest(spec["repository"], image_digest, workload_key)
        source_revision, source_evidence = _runtime_contract(
            spec["source_parameter"],
            expected_repository=spec["repository"],
            expected_digest=image_digest,
        )
    return {
        "kind": "ecs",
        "cluster_arn": cluster_arn,
        "service_arn": service_arn,
        "task_definition_arn": task_definition,
        "tasks": normalized_tasks,
        "image_repository": spec["repository"],
        "image_digest": image_digest,
        "source_revision": source_revision,
        "source_evidence": source_evidence,
    }


def _collect_authority_workload() -> dict[str, Any]:
    function_pairs = []
    digest = None
    repository = "layerv/qurl-connector-authority"
    for function_name in AUTHORITY_FUNCTIONS:
        configs = _aws(
            "lambda",
            [
                "list-provisioned-concurrency-configs",
                "--function-name",
                function_name,
            ],
            f"{function_name} provisioned concurrency",
        )
        values = (
            configs.get("ProvisionedConcurrencyConfigs")
            if isinstance(configs, dict)
            else None
        )
        if not isinstance(configs, dict) or configs.get("NextToken") is not None:
            raise EvidenceError(
                f"{function_name} provisioned concurrency response is incomplete"
            )
        ready = [
            value
            for value in values or []
            if isinstance(value, dict)
            and value.get("Status") == "READY"
            and type(value.get("RequestedProvisionedConcurrentExecutions")) is int
            and value["RequestedProvisionedConcurrentExecutions"] > 0
            and value.get("AvailableProvisionedConcurrentExecutions")
            == value["RequestedProvisionedConcurrentExecutions"]
            and value.get("AllocatedProvisionedConcurrentExecutions")
            == value["RequestedProvisionedConcurrentExecutions"]
        ]
        if len(ready) != 1:
            raise EvidenceError(
                f"{function_name} must expose one ready active deployment alias"
            )
        alias_arn = ready[0].get("FunctionArn")
        qualifier = alias_arn.rsplit(":", 1)[-1] if isinstance(alias_arn, str) else ""
        if qualifier not in {"blue", "green"}:
            raise EvidenceError(f"{function_name} active qualifier is not closed")
        alias = _aws(
            "lambda",
            ["get-alias", "--function-name", function_name, "--name", qualifier],
            f"{function_name} active alias",
        )
        version = alias.get("FunctionVersion") if isinstance(alias, dict) else None
        routing = alias.get("RoutingConfig") if isinstance(alias, dict) else None
        if (
            alias.get("AliasArn") != alias_arn
            or not isinstance(version, str)
            or not version.isdecimal()
            or int(version) <= 0
            or (
                isinstance(routing, dict)
                and routing.get("AdditionalVersionWeights") not in (None, {})
            )
        ):
            raise EvidenceError(f"{function_name} active alias is invalid")
        function = _aws(
            "lambda",
            [
                "get-function",
                "--function-name",
                function_name,
                "--qualifier",
                version,
            ],
            f"{function_name} active version",
        )
        configuration = (
            function.get("Configuration") if isinstance(function, dict) else None
        )
        code = function.get("Code") if isinstance(function, dict) else None
        expected_version_arn = (
            f"arn:aws:lambda:{AWS_REGION}:{AWS_ACCOUNT_ID}:"
            f"function:{function_name}:{version}"
        )
        if (
            not isinstance(configuration, dict)
            or not isinstance(code, dict)
            or configuration.get("FunctionArn") != expected_version_arn
            or configuration.get("PackageType") != "Image"
            or configuration.get("State") != "Active"
            or configuration.get("LastUpdateStatus") != "Successful"
        ):
            raise EvidenceError(f"{function_name} active version is not an image")
        image_uri = contract._string(
            code.get("ResolvedImageUri"),
            f"{function_name} active image URI",
        )
        resolved_repository, resolved_digest = _parse_image_uri(
            image_uri, f"{function_name} active image"
        )
        if resolved_repository != repository:
            raise EvidenceError(f"{function_name} active repository drift")
        if digest is None:
            digest = resolved_digest
        elif digest != resolved_digest:
            raise EvidenceError("Authority functions run mixed image digests")
        function_pairs.append(
            {"alias_arn": alias_arn, "version_arn": expected_version_arn}
        )
    if function_pairs != sorted(
        function_pairs, key=lambda item: (item["alias_arn"], item["version_arn"])
    ):
        raise EvidenceError("Authority function identities are not stable-sorted")
    if digest is None:
        raise EvidenceError("Authority functions have no image identity")
    source_revision, source_evidence = _oci_revision(
        repository, digest, "Connector Authority"
    )
    return {
        "kind": "lambda_image_set",
        "functions": function_pairs,
        "image_repository": repository,
        "image_digest": digest,
        "source_revision": source_revision,
        "source_evidence": source_evidence,
    }


def _public_key_parameter() -> tuple[str, int, str]:
    parameter = _ssm_parameter("/sandbox/nhp/control/hub/identity/public-key")
    public_key = parameter["Value"]
    decoded = contract.decode_public_key(public_key, "Hub public key parameter")
    return public_key, parameter["Version"], hashlib.sha256(decoded).hexdigest()


def _catalog_cells() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    runtime_cells = []
    evidence_cells = []
    for cell_id in ("cell0", "cell1"):
        response = _aws(
            "dynamodb",
            [
                "get-item",
                "--table-name",
                CATALOG_TABLE,
                "--consistent-read",
                "--key",
                json.dumps(
                    {"pk": {"S": "REGISTRY"}, "sk": {"S": f"CELL#{cell_id}"}},
                    separators=(",", ":"),
                    sort_keys=True,
                ),
            ],
            f"{cell_id} catalog row",
        )
        item = response.get("Item") if isinstance(response, dict) else None
        expected_keys = {
            "pk",
            "sk",
            "cell_id",
            "status",
            "endpoint_revision",
            "nhp_host",
            "nhp_port",
            "server_public_key_b64",
            "selection_weight",
            "updated_at",
        }
        if not isinstance(item, dict) or set(item) != expected_keys:
            raise EvidenceError(f"{cell_id} catalog row shape drift")

        def string_field(name: str) -> str:
            value = item.get(name)
            if not isinstance(value, dict) or set(value) != {"S"}:
                raise EvidenceError(f"{cell_id} catalog {name} must be String")
            return value["S"]

        def number_field(name: str) -> str:
            value = item.get(name)
            if not isinstance(value, dict) or set(value) != {"N"}:
                raise EvidenceError(f"{cell_id} catalog {name} must be Number")
            return value["N"]

        if (
            string_field("pk") != "REGISTRY"
            or string_field("sk") != f"CELL#{cell_id}"
            or string_field("cell_id") != cell_id
            or string_field("status") != "active"
            or number_field("nhp_port") != str(contract.UDP_PORT)
        ):
            raise EvidenceError(f"{cell_id} catalog row is not active and exact")
        endpoint_revision_raw = number_field("endpoint_revision")
        if not endpoint_revision_raw.isdecimal() or int(endpoint_revision_raw) <= 0:
            raise EvidenceError(f"{cell_id} endpoint revision is invalid")
        host = string_field("nhp_host")
        public_key = string_field("server_public_key_b64")
        decoded = contract.decode_public_key(public_key, f"{cell_id} public key")
        key_digest = hashlib.sha256(decoded).hexdigest()
        weight = number_field("selection_weight")
        updated_at = string_field("updated_at")
        runtime_cells.append(
            {
                "cell_id": cell_id,
                "host": host,
                "port": contract.UDP_PORT,
                "server_public_key_b64": public_key,
            }
        )
        evidence_cells.append(
            {
                "cell_id": cell_id,
                "catalog_table": CATALOG_TABLE,
                "pk": "REGISTRY",
                "sk": f"CELL#{cell_id}",
                "status": "active",
                "endpoint_revision": int(endpoint_revision_raw),
                "selection_weight": weight,
                "updated_at": updated_at,
                "host": host,
                "port": contract.UDP_PORT,
                "server_public_key_sha256": key_digest,
            }
        )
    return runtime_cells, evidence_cells


def _proof_source_eip() -> dict[str, str]:
    name = "layerv-nhp-sandbox-udp-proof-source"
    response = _aws(
        "ec2",
        [
            "describe-addresses",
            "--filters",
            f"Name=tag:Name,Values={name}",
        ],
        "UDP proof source EIP",
    )
    addresses = response.get("Addresses") if isinstance(response, dict) else None
    if not isinstance(addresses, list) or len(addresses) != 1:
        raise EvidenceError("UDP proof source EIP is missing or ambiguous")
    address = addresses[0]
    tags = address.get("Tags") if isinstance(address, dict) else None
    names = [
        tag.get("Value")
        for tag in tags or []
        if isinstance(tag, dict) and tag.get("Key") == "Name"
    ]
    if (
        not isinstance(address, dict)
        or not isinstance(tags, list)
        or names != [name]
        or address.get("PublicIp") != PROOF_SOURCE_CIDR.removesuffix("/32")
        or address.get("Domain") != "vpc"
        or address.get("NetworkBorderGroup") != AWS_REGION
        or not re.fullmatch(
            r"eipalloc-[0-9a-f]{17}",
            str(address.get("AllocationId", "")),
        )
    ):
        raise EvidenceError("UDP proof source EIP identity drift")
    return {
        "name": name,
        "allocation_id": address["AllocationId"],
        "public_ip": address["PublicIp"],
        "cidr": PROOF_SOURCE_CIDR,
    }


def _permission_covers(
    permission: dict[str, Any],
    protocol: str,
    port: int,
) -> bool:
    ip_protocol = permission.get("IpProtocol")
    if ip_protocol == "-1":
        return True
    return (
        ip_protocol == protocol
        and type(permission.get("FromPort")) is int
        and type(permission.get("ToPort")) is int
        and permission["FromPort"] <= port <= permission["ToPort"]
    )


def _permission_sources(
    permissions: Any,
    *,
    protocol: str,
    port: int,
    name: str,
) -> list[tuple[str, str]]:
    if not isinstance(permissions, list) or any(
        not isinstance(permission, dict) for permission in permissions
    ):
        raise EvidenceError(f"{name} security-group permissions are malformed")
    sources: list[tuple[str, str]] = []
    for permission in permissions:
        if not _permission_covers(permission, protocol, port):
            continue
        if (
            permission.get("IpProtocol") != protocol
            or permission.get("FromPort") != port
            or permission.get("ToPort") != port
        ):
            raise EvidenceError(
                f"{name} security-group permission widens {protocol}/{port}"
            )
        fields = (
            ("UserIdGroupPairs", "GroupId", "sg"),
            ("IpRanges", "CidrIp", "ipv4"),
            ("Ipv6Ranges", "CidrIpv6", "ipv6"),
            ("PrefixListIds", "PrefixListId", "prefix"),
        )
        for field, identity_field, kind in fields:
            values = permission.get(field, [])
            if not isinstance(values, list) or any(
                not isinstance(value, dict)
                or not isinstance(value.get(identity_field), str)
                for value in values
            ):
                raise EvidenceError(f"{name} security-group sources are malformed")
            sources.extend((kind, value[identity_field]) for value in values)
    return sorted(sources)


def _security_groups_for_edge(
    host: str,
    *,
    vpc_id: str,
    attached_group_id: str,
    edge_contract: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    expected_names = {
        edge_contract["load_balancer_security_group_name"],
        edge_contract["backend_security_group_name"],
    }
    response = _aws(
        "ec2",
        [
            "describe-security-groups",
            "--filters",
            f"Name=vpc-id,Values={vpc_id}",
            "Name=tag:Name,Values=" + ",".join(sorted(expected_names)),
        ],
        f"{host} protected-edge security groups",
    )
    groups = response.get("SecurityGroups") if isinstance(response, dict) else None
    if (
        not isinstance(response, dict)
        or response.get("NextToken") not in (None, "")
        or not isinstance(groups, list)
        or len(groups) != 2
        or any(not isinstance(group, dict) for group in groups)
    ):
        raise EvidenceError(f"{host} protected-edge security groups are incomplete")
    by_name: dict[str, dict[str, Any]] = {}
    for group in groups:
        tags = group.get("Tags")
        names = [
            tag.get("Value")
            for tag in tags or []
            if isinstance(tag, dict) and tag.get("Key") == "Name"
        ]
        if (
            not isinstance(tags, list)
            or len(names) != 1
            or names[0] not in expected_names
            or group.get("VpcId") != vpc_id
            or not re.fullmatch(r"sg-[0-9a-f]{17}", str(group.get("GroupId", "")))
            or names[0] in by_name
        ):
            raise EvidenceError(f"{host} protected-edge security-group identity drift")
        by_name[names[0]] = group
    if set(by_name) != expected_names:
        raise EvidenceError(f"{host} protected-edge security-group identity drift")
    nlb_group = by_name[edge_contract["load_balancer_security_group_name"]]
    target_group = by_name[edge_contract["backend_security_group_name"]]
    if nlb_group["GroupId"] != attached_group_id:
        raise EvidenceError(f"{host} NLB does not attach the protected-edge group")
    return nlb_group, target_group


def _verify_edge_security_groups(
    host: str,
    *,
    nlb_group: dict[str, Any],
    target_group: dict[str, Any],
    edge_contract: dict[str, Any],
) -> None:
    nlb_group_id = nlb_group["GroupId"]
    target_group_id = target_group["GroupId"]
    nlb_ingress = nlb_group.get("IpPermissions")
    nlb_egress = nlb_group.get("IpPermissionsEgress")
    if not isinstance(nlb_ingress, list) or len(nlb_ingress) != 1:
        raise EvidenceError(f"{host} NLB ingress is not the exact one-rule contract")
    if not isinstance(nlb_egress, list) or len(nlb_egress) != 2:
        raise EvidenceError(f"{host} NLB egress is not the exact two-rule contract")
    expected_ingress = [("ipv4", PROOF_SOURCE_CIDR)]
    if (
        _permission_sources(
            nlb_ingress,
            protocol="udp",
            port=contract.UDP_PORT,
            name=f"{host} NLB ingress",
        )
        != expected_ingress
    ):
        raise EvidenceError(
            f"{host} NLB UDP ingress is not the stable proof-runner /32"
        )
    if (
        _permission_sources(
            nlb_egress,
            protocol="udp",
            port=contract.UDP_PORT,
            name=f"{host} NLB egress",
        )
        != [("sg", target_group_id)]
    ):
        raise EvidenceError(f"{host} NLB UDP egress does not trust the exact backend")

    target_sources = _permission_sources(
        target_group.get("IpPermissions"),
        protocol="udp",
        port=contract.UDP_PORT,
        name=f"{host} backend ingress",
    )
    expected_target_sources = sorted(
        [("sg", nlb_group_id)]
        + [("ipv4", cidr) for cidr in edge_contract["backend_udp_cidrs"]]
    )
    if target_sources != expected_target_sources:
        raise EvidenceError(f"{host} backend UDP ingress uses a wrong source path")

    health_protocol = (
        "tcp"
        if edge_contract["health_protocol"] in {"HTTP", "HTTPS", "TCP", "TLS"}
        else edge_contract["health_protocol"].lower()
    )
    health_port = edge_contract["health_port"]
    if (
        _permission_sources(
            nlb_egress,
            protocol=health_protocol,
            port=health_port,
            name=f"{host} NLB health egress",
        )
        != [("sg", target_group_id)]
    ):
        raise EvidenceError(f"{host} NLB health egress does not trust the backend")
    health_sources = _permission_sources(
        target_group.get("IpPermissions"),
        protocol=health_protocol,
        port=health_port,
        name=f"{host} backend health ingress",
    )
    expected_health_sources = sorted(
        [("sg", nlb_group_id)]
        + [
            ("ipv4", cidr)
            for cidr in edge_contract["backend_health_cidrs"]
        ]
    )
    if health_sources != expected_health_sources:
        raise EvidenceError(f"{host} backend health ingress uses a wrong source path")


def _group_ids(groups: Any, name: str) -> list[str]:
    if not isinstance(groups, list) or any(
        not isinstance(group, dict)
        or not re.fullmatch(r"sg-[0-9a-f]{17}", str(group.get("GroupId", "")))
        for group in groups
    ):
        raise EvidenceError(f"{name} security-group attachments are malformed")
    return sorted(str(group["GroupId"]) for group in groups)


def _verify_target_security_group_attachments(
    host: str,
    *,
    target_type: str,
    target_ids: list[str],
    vpc_id: str,
    backend_group_id: str,
) -> None:
    if target_type == "instance":
        if any(
            not re.fullmatch(r"i-[0-9a-f]{17}", target_id)
            for target_id in target_ids
        ):
            raise EvidenceError(f"{host} target instance identity is malformed")
        response = _aws(
            "ec2",
            ["describe-instances", "--instance-ids", *target_ids],
            f"{host} target instances",
        )
        reservations = (
            response.get("Reservations") if isinstance(response, dict) else None
        )
        if (
            not isinstance(response, dict)
            or response.get("NextToken") not in (None, "")
            or not isinstance(reservations, list)
            or any(
                not isinstance(reservation, dict)
                or not isinstance(reservation.get("Instances"), list)
                or any(
                    not isinstance(instance, dict)
                    for instance in reservation["Instances"]
                )
                for reservation in reservations
            )
        ):
            raise EvidenceError(f"{host} target instances are incomplete")
        instances = [
            instance
            for reservation in reservations
            for instance in reservation["Instances"]
        ]
        by_id = {instance.get("InstanceId"): instance for instance in instances}
        if set(by_id) != set(target_ids) or len(by_id) != len(instances):
            raise EvidenceError(f"{host} target instance identities are ambiguous")
        for target_id in target_ids:
            instance = by_id[target_id]
            state = instance.get("State")
            if (
                instance.get("VpcId") != vpc_id
                or not isinstance(state, dict)
                or state.get("Name") != "running"
                or _group_ids(
                    instance.get("SecurityGroups"),
                    f"{host} target {target_id}",
                )
                != [backend_group_id]
            ):
                raise EvidenceError(
                    f"{host} target {target_id} does not attach only the backend group"
                )
        return

    if target_type != "ip":
        raise EvidenceError(f"{host} uses an unsupported target type")
    try:
        target_addresses = [ipaddress.ip_address(target_id) for target_id in target_ids]
    except ValueError as exc:
        raise EvidenceError(f"{host} target IP identity is malformed") from exc
    if any(address.version != 4 for address in target_addresses):
        raise EvidenceError(f"{host} target IP identity is not IPv4")
    response = _aws(
        "ec2",
        [
            "describe-network-interfaces",
            "--filters",
            f"Name=vpc-id,Values={vpc_id}",
            "Name=addresses.private-ip-address,Values=" + ",".join(target_ids),
        ],
        f"{host} target network interfaces",
    )
    interfaces = (
        response.get("NetworkInterfaces") if isinstance(response, dict) else None
    )
    if (
        not isinstance(response, dict)
        or response.get("NextToken") not in (None, "")
        or not isinstance(interfaces, list)
        or not interfaces
        or any(not isinstance(interface, dict) for interface in interfaces)
    ):
        raise EvidenceError(f"{host} target network interfaces are incomplete")
    target_set = set(target_ids)
    coverage = {target_id: [] for target_id in target_ids}
    for interface in interfaces:
        interface_id = interface.get("NetworkInterfaceId")
        raw_addresses = interface.get("PrivateIpAddresses")
        attachment = interface.get("Attachment")
        if not isinstance(raw_addresses, list) or any(
            not isinstance(address, dict) for address in raw_addresses
        ):
            raise EvidenceError(f"{host} target interface addresses are malformed")
        addresses = {
            address.get("PrivateIpAddress")
            for address in raw_addresses
            if isinstance(address.get("PrivateIpAddress"), str)
        }
        if isinstance(interface.get("PrivateIpAddress"), str):
            addresses.add(interface["PrivateIpAddress"])
        matched = target_set & addresses
        if (
            not re.fullmatch(r"eni-[0-9a-f]{17}", str(interface_id))
            or not matched
            or interface.get("VpcId") != vpc_id
            or interface.get("Status") != "in-use"
            or not isinstance(attachment, dict)
            or attachment.get("Status") != "attached"
            or _group_ids(
                interface.get("Groups"),
                f"{host} target interface {interface_id}",
            )
            != [backend_group_id]
        ):
            raise EvidenceError(
                f"{host} target interface does not attach only the backend group"
            )
        for target_id in matched:
            coverage[target_id].append(str(interface_id))
    if any(len(interface_ids) != 1 for interface_ids in coverage.values()):
        raise EvidenceError(f"{host} target IP-to-interface binding is ambiguous")


def _verify_route53_alias_record(
    record: Any,
    *,
    host: str,
    nlb_dns_name: str,
    canonical_hosted_zone_id: str,
) -> None:
    if not isinstance(record, dict) or set(record) != {
        "Name",
        "Type",
        "AliasTarget",
    }:
        raise EvidenceError(
            f"{host} Route53 alias must not use a routing policy or health check"
        )
    alias = record["AliasTarget"]
    if (
        record["Name"] != f"{host}."
        or record["Type"] != "A"
        or not isinstance(alias, dict)
        or set(alias) != {
            "DNSName",
            "HostedZoneId",
            "EvaluateTargetHealth",
        }
        or alias["DNSName"] != f"{nlb_dns_name}."
        or alias["HostedZoneId"] != canonical_hosted_zone_id
        or alias["EvaluateTargetHealth"] is not True
    ):
        raise EvidenceError(f"{host} Route53 alias does not target the exact NLB")


def _verify_dns_alias(host: str) -> dict[str, Any]:
    edge_contract = PUBLIC_EDGE_CONTRACTS.get(host)
    if edge_contract is None:
        raise EvidenceError(f"{host} has no protected-edge contract")
    nlb_name = edge_contract["load_balancer_name"]
    load_balancers = _aws(
        "elbv2",
        ["describe-load-balancers", "--names", nlb_name],
        f"{host} NLB",
    )
    values = (
        load_balancers.get("LoadBalancers")
        if isinstance(load_balancers, dict)
        else None
    )
    if not isinstance(values, list) or len(values) != 1:
        raise EvidenceError(f"{host} NLB is missing")
    nlb = values[0]
    if (
        nlb.get("LoadBalancerName") != nlb_name
        or nlb.get("Type") != "network"
        or nlb.get("Scheme") != "internet-facing"
        or nlb.get("IpAddressType") != "ipv4"
        or (nlb.get("State") or {}).get("Code") != "active"
        or nlb.get("EnforceSecurityGroupInboundRulesOnPrivateLinkTraffic") != "on"
        or not re.fullmatch(r"vpc-[0-9a-f]{17}", str(nlb.get("VpcId", "")))
        or not isinstance(nlb.get("SecurityGroups"), list)
        or len(nlb["SecurityGroups"]) != 1
        or not re.fullmatch(r"sg-[0-9a-f]{17}", str(nlb["SecurityGroups"][0]))
    ):
        raise EvidenceError(f"{host} NLB is not the protected public network edge")
    nlb_arn = contract._arn(nlb.get("LoadBalancerArn"), f"{host} NLB ARN")
    nlb_dns_name = contract._string(nlb.get("DNSName"), f"{host} NLB DNS name")
    nlb_group, backend_group = _security_groups_for_edge(
        host,
        vpc_id=nlb["VpcId"],
        attached_group_id=nlb["SecurityGroups"][0],
        edge_contract=edge_contract,
    )
    _verify_edge_security_groups(
        host,
        nlb_group=nlb_group,
        target_group=backend_group,
        edge_contract=edge_contract,
    )
    listeners_response = _aws(
        "elbv2",
        ["describe-listeners", "--load-balancer-arn", nlb_arn],
        f"{host} listeners",
    )
    listeners = (
        listeners_response.get("Listeners")
        if isinstance(listeners_response, dict)
        else None
    )
    if not isinstance(listeners, list) or len(listeners) != 1:
        raise EvidenceError(f"{host} must expose exactly one public listener")
    listener = listeners[0]
    actions = listener.get("DefaultActions") if isinstance(listener, dict) else None
    if (
        listener.get("Protocol") != "UDP"
        or listener.get("Port") != contract.UDP_PORT
        or not isinstance(actions, list)
        or len(actions) != 1
        or actions[0].get("Type") != "forward"
        or not isinstance(actions[0].get("TargetGroupArn"), str)
    ):
        raise EvidenceError(f"{host} listener is not exact UDP 62206 forwarding")
    listener_arn = contract._arn(listener.get("ListenerArn"), f"{host} listener ARN")
    target_group_arn = actions[0]["TargetGroupArn"]
    forward_config = actions[0].get("ForwardConfig")
    if forward_config not in (None, {}):
        forward_targets = (
            forward_config.get("TargetGroups")
            if isinstance(forward_config, dict)
            else None
        )
        stickiness = (
            forward_config.get("TargetGroupStickinessConfig")
            if isinstance(forward_config, dict)
            else None
        )
        if (
            not isinstance(forward_config, dict)
            or not set(forward_config).issubset(
                {"TargetGroups", "TargetGroupStickinessConfig"}
            )
            or not isinstance(forward_targets, list)
            or len(forward_targets) != 1
            or not isinstance(forward_targets[0], dict)
            or forward_targets[0].get("TargetGroupArn") != target_group_arn
            or forward_targets[0].get("Weight") not in (None, 1)
            or stickiness not in (None, {}, {"Enabled": False})
        ):
            raise EvidenceError(f"{host} listener uses weighted or sticky forwarding")
    target_groups_response = _aws(
        "elbv2",
        ["describe-target-groups", "--target-group-arns", target_group_arn],
        f"{host} target group",
    )
    target_groups = (
        target_groups_response.get("TargetGroups")
        if isinstance(target_groups_response, dict)
        else None
    )
    if not isinstance(target_groups, list) or len(target_groups) != 1:
        raise EvidenceError(f"{host} target group is missing")
    target_group = target_groups[0]
    if (
        target_group.get("TargetGroupArn") != target_group_arn
        or target_group.get("Protocol") != "UDP"
        or target_group.get("Port") != contract.UDP_PORT
        or target_group.get("TargetType") != edge_contract["target_type"]
        or target_group.get("VpcId") != nlb["VpcId"]
        or target_group.get("HealthCheckEnabled") is not True
        or target_group.get("HealthCheckProtocol")
        != edge_contract["health_protocol"]
        or str(target_group.get("HealthCheckPort")) != str(edge_contract["health_port"])
        or target_group.get("HealthyThresholdCount")
        != edge_contract["healthy_threshold"]
        or target_group.get("UnhealthyThresholdCount")
        != edge_contract["unhealthy_threshold"]
        or target_group.get("HealthCheckIntervalSeconds")
        != edge_contract["health_interval"]
        or target_group.get("Matcher") != edge_contract["health_matcher"]
        or (
            edge_contract["health_path"] is not None
            and target_group.get("HealthCheckPath") != edge_contract["health_path"]
        )
        or target_group.get("LoadBalancerArns") != [nlb_arn]
    ):
        raise EvidenceError(f"{host} target group is not exact and health-checked")
    health_response = _aws(
        "elbv2",
        ["describe-target-health", "--target-group-arn", target_group_arn],
        f"{host} target health",
    )
    health = (
        health_response.get("TargetHealthDescriptions")
        if isinstance(health_response, dict)
        else None
    )
    if not isinstance(health, list) or not 1 <= len(health) <= contract.MAX_TASKS:
        raise EvidenceError(f"{host} target group has no bounded healthy target set")
    target_ids = []
    for target in health:
        target_identity = target.get("Target") if isinstance(target, dict) else None
        target_health = target.get("TargetHealth") if isinstance(target, dict) else None
        target_id = (
            target_identity.get("Id") if isinstance(target_identity, dict) else None
        )
        target_port = (
            target_identity.get("Port") if isinstance(target_identity, dict) else None
        )
        if (
            not isinstance(target_id, str)
            or not target_id
            or target_port != contract.UDP_PORT
            or not isinstance(target_health, dict)
            or target_health.get("State") != "healthy"
        ):
            raise EvidenceError(f"{host} target group is not fully healthy")
        target_ids.append(target_id)
    if len(target_ids) != len(set(target_ids)):
        raise EvidenceError(f"{host} healthy target identities are not unique")
    target_ids = sorted(target_ids)
    _verify_target_security_group_attachments(
        host,
        target_type=edge_contract["target_type"],
        target_ids=target_ids,
        vpc_id=nlb["VpcId"],
        backend_group_id=backend_group["GroupId"],
    )
    records = _aws(
        "route53",
        [
            "list-resource-record-sets",
            "--hosted-zone-id",
            ROUTE53_ZONE_ID,
            "--start-record-name",
            host,
            "--start-record-type",
            "A",
            "--max-items",
            "100",
        ],
        f"{host} Route53 record",
    )
    values = records.get("ResourceRecordSets") if isinstance(records, dict) else None
    route_page_truncated = records.get("IsTruncated") if isinstance(records, dict) else None
    exact_records = [
        value
        for value in values or []
        if isinstance(value, dict) and value.get("Name") == f"{host}."
    ]
    if (
        not isinstance(records, dict)
        or records.get("NextToken") not in (None, "")
        or not isinstance(values, list)
        or len(values) > 100
        or type(route_page_truncated) is not bool
        or (
            route_page_truncated
            and (
                not isinstance(records.get("NextRecordName"), str)
                or not isinstance(records.get("NextRecordType"), str)
            )
        )
        or (
            not route_page_truncated
            and (
                records.get("NextRecordName") not in (None, "")
                or records.get("NextRecordType") not in (None, "")
                or records.get("NextRecordIdentifier") not in (None, "")
            )
        )
        or len(exact_records) != 1
    ):
        raise EvidenceError(f"{host} must have one unambiguous Route53 record")
    record = exact_records[0]
    _verify_route53_alias_record(
        record,
        host=host,
        nlb_dns_name=nlb_dns_name,
        canonical_hosted_zone_id=contract._string(
            nlb.get("CanonicalHostedZoneId"),
            f"{host} NLB canonical hosted-zone ID",
        ),
    )
    return {
        "load_balancer_name": nlb_name,
        "load_balancer_arn": nlb_arn,
        "load_balancer_dns_name": nlb_dns_name,
        "load_balancer_security_group_id": nlb_group["GroupId"],
        "load_balancer_security_group_name": (
            edge_contract["load_balancer_security_group_name"]
        ),
        "backend_security_group_id": backend_group["GroupId"],
        "backend_security_group_name": edge_contract["backend_security_group_name"],
        "backend_udp_cidrs": list(edge_contract["backend_udp_cidrs"]),
        "backend_health_cidrs": list(edge_contract["backend_health_cidrs"]),
        "proof_source_cidr": PROOF_SOURCE_CIDR,
        "listener_arn": listener_arn,
        "target_group_arn": contract._arn(target_group_arn, f"{host} target group ARN"),
        "healthy_target_ids": target_ids,
        "route53_zone_id": ROUTE53_ZONE_ID,
    }


def _bucket_name(bucket_arn: str) -> str:
    prefix = "arn:aws:s3:::"
    if not bucket_arn.startswith(prefix):
        raise EvidenceError("runtime-attestation bucket parameter is not a bucket ARN")
    name = bucket_arn.removeprefix(prefix)
    if not re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", name):
        raise EvidenceError("runtime-attestation bucket name is invalid")
    return name


def _sorted_policy_scalar_lists(value: Any) -> Any:
    """Order-normalise an IAM policy document before digesting it.

    The published contract digest is `sha256(jsonencode(<authored policy>))`
    from Terraform, and Terraform's jsonencode is byte-identical to
    `contract.canonical_bytes` for this document -- both sort object keys and
    emit compact separators. The two sides therefore already agree on
    canonicalisation, and the digest is a genuine binding of the whole policy.

    What they do NOT agree on is list order. S3 stores the document and
    GetBucketPolicy returns `Principal.AWS` arrays in an order that differs from
    the authored one (here: `layerv-nhp-sandbox-server` comes back first rather
    than in the authored sort order). The principal SETS are identical -- this
    is a re-ordering by AWS, not a policy change, and `terraform plan` is
    correctly a no-op because aws_s3_bucket_policy diffs by policy equivalence,
    not by bytes.

    So digesting the returned document verbatim compares an AWS-ordered
    document against a Terraform-ordered one and can never match except by
    luck. Sorting scalar lists first is exactly the missing normalisation:
    Action, Resource, Principal and Condition values are SETS in IAM semantics,
    where order carries no meaning, so this discards nothing the digest is
    supposed to protect. Every element is still bound -- an added, removed or
    altered principal changes the digest.

    Lists holding non-scalars (statement lists) keep their order untouched.
    """
    if isinstance(value, dict):
        return {key: _sorted_policy_scalar_lists(item) for key, item in value.items()}
    if isinstance(value, list):
        items = [_sorted_policy_scalar_lists(item) for item in value]
        if all(isinstance(item, str) for item in items):
            return sorted(items)
        return items
    return value


def _validate_attestation_bucket(bucket: str) -> tuple[str, str]:
    versioning = _aws(
        "s3api", ["get-bucket-versioning", "--bucket", bucket], "attestation versioning"
    )
    public = _aws(
        "s3api",
        ["get-public-access-block", "--bucket", bucket],
        "attestation public access block",
    )
    ownership = _aws(
        "s3api",
        ["get-bucket-ownership-controls", "--bucket", bucket],
        "attestation ownership controls",
    )
    encryption = _aws(
        "s3api",
        ["get-bucket-encryption", "--bucket", bucket],
        "attestation encryption",
    )
    policy_response = _aws(
        "s3api",
        ["get-bucket-policy", "--bucket", bucket],
        "attestation bucket policy",
    )
    policy_status = _aws(
        "s3api",
        ["get-bucket-policy-status", "--bucket", bucket],
        "attestation bucket policy status",
    )
    public_config = (
        public.get("PublicAccessBlockConfiguration")
        if isinstance(public, dict)
        else None
    )
    ownership_rules = (
        (ownership.get("OwnershipControls") or {}).get("Rules")
        if isinstance(ownership, dict)
        else None
    )
    encryption_rules = (
        (encryption.get("ServerSideEncryptionConfiguration") or {}).get("Rules")
        if isinstance(encryption, dict)
        else None
    )
    encryption_default = (
        encryption_rules[0].get("ApplyServerSideEncryptionByDefault")
        if isinstance(encryption_rules, list) and len(encryption_rules) == 1
        else None
    )
    kms_key_arn = (
        encryption_default.get("KMSMasterKeyID")
        if isinstance(encryption_default, dict)
        else None
    )
    policy_raw = (
        policy_response.get("Policy") if isinstance(policy_response, dict) else None
    )
    if not isinstance(policy_raw, str) or len(policy_raw) > 64 * 1024:
        raise EvidenceError("runtime-attestation bucket policy is missing or oversized")
    policy = _loads(policy_raw, "runtime-attestation bucket policy")
    if not isinstance(policy, dict):
        raise EvidenceError("runtime-attestation bucket policy must be an object")
    policy_sha256 = _terraform_jsonencode_digest(
        _sorted_policy_scalar_lists(policy),
        maximum=64 * 1024,
        name="runtime-attestation bucket policy",
    )
    if (
        versioning.get("Status") != "Enabled"
        or public_config
        != {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        }
        or ownership_rules != [{"ObjectOwnership": "BucketOwnerEnforced"}]
        or not isinstance(encryption_rules, list)
        or len(encryption_rules) != 1
        or not isinstance(encryption_default, dict)
        or encryption_default.get("SSEAlgorithm") != "aws:kms"
        or not isinstance(kms_key_arn, str)
        or not KMS_KEY_ARN_RE.fullmatch(kms_key_arn)
        or encryption_rules[0].get("BucketKeyEnabled") is not True
        or policy_status != {"PolicyStatus": {"IsPublic": False}}
    ):
        raise EvidenceError(
            "runtime-attestation bucket lacks versioning/BOE/KMS/public-block controls"
        )
    return kms_key_arn, policy_sha256


def _iso_utc_seconds(value: Any, name: str) -> str:
    if not isinstance(value, str):
        raise EvidenceError(f"{name} timestamp is missing")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise EvidenceError(f"{name} timestamp is invalid") from exc
    if parsed.tzinfo is None:
        raise EvidenceError(f"{name} timestamp lacks a timezone")
    return parsed.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _verify_repair(
    attestation: dict[str, Any],
    instance_id: str,
    *,
    autoscaling_group: str,
    collector_contract: dict[str, Any],
) -> str:
    association_id = attestation["repair_association_id"]
    description = _aws(
        "ssm",
        ["describe-association", "--association-id", association_id],
        f"{instance_id} repair association",
    )
    association = (
        description.get("AssociationDescription")
        if isinstance(description, dict)
        else None
    )
    if (
        not isinstance(association, dict)
        or association.get("AssociationId") != association_id
        or association.get("Name") != collector_contract["repair_document_name"]
        or association.get("DocumentVersion")
        != collector_contract["repair_document_version"]
        or association.get("Targets")
        != [
            {
                "Key": "tag:aws:autoscaling:groupName",
                "Values": [autoscaling_group],
            }
        ]
        or (association.get("Status") or {}).get("Name") != "Success"
    ):
        raise EvidenceError(f"{instance_id} repair association identity drift")
    executions_response = _aws(
        "ssm",
        [
            "describe-association-executions",
            "--association-id",
            association_id,
            "--filters",
            "Key=CreatedTime,"
            f"Value={attestation['repair_last_success_at']},Type=EQUAL",
            "--max-results",
            "10",
        ],
        f"{instance_id} repair executions",
    )
    executions = (
        executions_response.get("AssociationExecutions")
        if isinstance(executions_response, dict)
        else None
    )
    if (
        not isinstance(executions_response, dict)
        or executions_response.get("NextToken") not in (None, "")
        or not isinstance(executions, list)
        or len(executions) > 10
    ):
        raise EvidenceError(f"{instance_id} repair executions are incomplete")
    successful = [
        execution
        for execution in executions or []
        if isinstance(execution, dict) and execution.get("Status") == "Success"
    ]
    if len(successful) != 1:
        raise EvidenceError(
            f"{instance_id} has no unique successful repair execution"
        )
    execution = successful[0]
    execution_id = contract._string(
        execution.get("ExecutionId"), f"{instance_id} repair execution ID"
    )
    targets_response = _aws(
        "ssm",
        [
            "describe-association-execution-targets",
            "--association-id",
            association_id,
            "--execution-id",
            execution_id,
            "--max-results",
            "50",
        ],
        f"{instance_id} repair execution targets",
    )
    targets = (
        targets_response.get("AssociationExecutionTargets")
        if isinstance(targets_response, dict)
        else None
    )
    if (
        not isinstance(targets_response, dict)
        or targets_response.get("NextToken") not in (None, "")
        or not isinstance(targets, list)
        or len(targets) > 50
    ):
        raise EvidenceError(f"{instance_id} repair execution targets are incomplete")
    matches = [
        target
        for target in targets or []
        if isinstance(target, dict)
        and target.get("ResourceId") == instance_id
        and target.get("Status") == "Success"
    ]
    if len(matches) != 1:
        raise EvidenceError(f"{instance_id} repair execution was not successful")
    return _iso_utc_seconds(execution.get("CreatedTime"), "repair execution")


def _current_object_version(
    response: Any,
    *,
    key: str,
    instance_id: str,
) -> str:
    if not isinstance(response, dict):
        raise EvidenceError(f"{instance_id} attestation versions are malformed")
    version_rows = response.get("Versions", [])
    delete_rows = response.get("DeleteMarkers", [])
    truncated = response.get("IsTruncated")
    if (
        not isinstance(version_rows, list)
        or not isinstance(delete_rows, list)
        or len(version_rows) + len(delete_rows) > 20
        or type(truncated) is not bool
        or (
            truncated
            and (
                not isinstance(response.get("NextKeyMarker"), str)
                or not isinstance(response.get("NextVersionIdMarker"), str)
            )
        )
        or (
            not truncated
            and (
                response.get("NextKeyMarker") not in (None, "")
                or response.get("NextVersionIdMarker") not in (None, "")
            )
        )
    ):
        raise EvidenceError(f"{instance_id} attestation version page is malformed")
    versions = [
        version
        for version in version_rows
        if isinstance(version, dict)
        and version.get("Key") == key
        and version.get("IsLatest") is True
    ]
    latest_deletes = [
        marker
        for marker in delete_rows
        if isinstance(marker, dict)
        and marker.get("Key") == key
        and marker.get("IsLatest") is True
    ]
    if len(versions) != 1 or latest_deletes:
        raise EvidenceError(f"{instance_id} has no unique current attestation")
    return contract._string(
        versions[0].get("VersionId"), f"{instance_id} attestation version"
    )


def _require_no_active_instance_refresh(workload_key: str, asg_name: str) -> None:
    """Reject a fleet whose most recent instance refresh has not terminated.

    A converged instance count is not by itself proof of a stable fleet: an
    active refresh keeps replacing members for as long as it runs, so evidence
    collected mid-refresh binds a fleet identity that AWS is still mutating.
    The status allow-list is closed, so an unrecognised or absent status fails
    rather than being treated as terminal.
    """
    response = _aws(
        "autoscaling",
        [
            "describe-instance-refreshes",
            "--auto-scaling-group-name",
            asg_name,
            "--max-records",
            "1",
        ],
        f"{workload_key} ASG instance refreshes",
    )
    refreshes = (
        response.get("InstanceRefreshes") if isinstance(response, dict) else None
    )
    if (
        not isinstance(response, dict)
        or response.get("NextToken") not in (None, "")
        or not isinstance(refreshes, list)
        or len(refreshes) > 1
        or any(not isinstance(refresh, dict) for refresh in refreshes)
    ):
        raise EvidenceError(f"{workload_key} ASG refresh readback is incomplete")
    if not refreshes:
        return
    status = refreshes[0].get("Status")
    if (
        refreshes[0].get("AutoScalingGroupName") != asg_name
        or not isinstance(status, str)
        or status not in TERMINAL_INSTANCE_REFRESH_STATUSES
    ):
        raise EvidenceError(f"{workload_key} ASG instance refresh is still active")


LAUNCH_TEMPLATE_ID_TAG = "aws:ec2launchtemplate:id"
LAUNCH_TEMPLATE_VERSION_TAG = "aws:ec2launchtemplate:version"
LAUNCH_TEMPLATE_ID_RE = re.compile(r"lt-[0-9a-f]{8,17}")
LAUNCH_TEMPLATE_VERSION_RE = re.compile(r"[1-9][0-9]{0,9}")


def _launch_template_pair(source: Any, name: str) -> tuple[str, str]:
    """Normalize one control-plane launch-template record, failing closed."""

    if not isinstance(source, dict):
        raise EvidenceError(f"{name} has no launch-template identity")
    template_id = source.get("LaunchTemplateId")
    version = source.get("Version")
    if (
        not isinstance(template_id, str)
        or LAUNCH_TEMPLATE_ID_RE.fullmatch(template_id) is None
        or not isinstance(version, str)
        or LAUNCH_TEMPLATE_VERSION_RE.fullmatch(version) is None
    ):
        raise EvidenceError(f"{name} launch-template identity is malformed")
    return template_id, version


def _reserved_launch_template_tags(instance: dict[str, Any]) -> dict[str, Any]:
    """Read the reserved launch-template tags EC2 stamps on the instance.

    `ec2:DescribeInstances` returns no top-level `LaunchTemplate` for an
    ASG-launched instance, so this record and the Auto Scaling membership row
    are the two independent control-plane statements of what launched it.  The
    `aws:` tag namespace is reserved — no principal, including the node's own
    instance role, may write a key in it — so neither is node-authored.
    """

    tags = instance.get("Tags")
    if not isinstance(tags, list):
        raise EvidenceError("instance description carries no tags")
    reserved: dict[str, Any] = {}
    for tag in tags:
        if not isinstance(tag, dict):
            raise EvidenceError("instance tag set is malformed")
        key = tag.get("Key")
        if key in (LAUNCH_TEMPLATE_ID_TAG, LAUNCH_TEMPLATE_VERSION_TAG):
            if key in reserved:
                raise EvidenceError("instance has duplicate launch-template tags")
            reserved[key] = tag.get("Value")
    return {
        "LaunchTemplateId": reserved.get(LAUNCH_TEMPLATE_ID_TAG),
        "Version": reserved.get(LAUNCH_TEMPLATE_VERSION_TAG),
    }


def _collect_ec2_workload(
    workload_key: str,
    *,
    bucket_arn: str,
    bucket: str,
    bucket_kms_key_arn: str,
    collector_contract: dict[str, Any],
    expected_source_revision: str | None = None,
) -> dict[str, Any]:
    spec = EC2_WORKLOADS[workload_key]
    asg_parameter = _ssm_parameter(spec["asg_parameter"])
    asg_name = asg_parameter["Value"]
    contract._string(asg_name, f"{workload_key} ASG name")
    response = _aws(
        "autoscaling",
        ["describe-auto-scaling-groups", "--auto-scaling-group-names", asg_name],
        f"{workload_key} ASG",
    )
    groups = response.get("AutoScalingGroups") if isinstance(response, dict) else None
    if (
        not isinstance(response, dict)
        or response.get("NextToken") not in (None, "")
        or not isinstance(groups, list)
        or len(groups) != 1
    ):
        raise EvidenceError(f"{workload_key} ASG is missing")
    group = groups[0]
    instances = group.get("Instances")
    if not isinstance(instances, list) or any(
        not isinstance(instance, dict) for instance in instances
    ):
        raise EvidenceError(f"{workload_key} ASG instance list is malformed")
    in_service_unsorted = [
        instance.get("InstanceId")
        for instance in instances
        if instance.get("LifecycleState") == "InService"
        and instance.get("HealthStatus") == "Healthy"
    ]
    if (
        group.get("AutoScalingGroupName") != asg_name
        or type(group.get("DesiredCapacity")) is not int
        or group["DesiredCapacity"] <= 0
        or len(in_service_unsorted) != group["DesiredCapacity"]
        or not 1 <= len(in_service_unsorted) <= contract.MAX_INSTANCES
        or any(not isinstance(instance_id, str) for instance_id in in_service_unsorted)
        or len(set(in_service_unsorted)) != len(in_service_unsorted)
        # Every group member must be exactly one of the converged in-service
        # instances. Counting only InService/Healthy members and comparing that
        # count to DesiredCapacity is fail-open during a rolling replacement:
        # once the replacement instance reaches InService the count matches
        # DesiredCapacity while a Terminating or Pending:Wait member is still
        # attached, still serving UDP, and still an NLB target, yet absent from
        # the evidence bound into the immutable manifest.
        or len(instances) != len(in_service_unsorted)
    ):
        raise EvidenceError(f"{workload_key} ASG is not healthily converged")
    _require_no_active_instance_refresh(workload_key, asg_name)
    in_service = sorted(in_service_unsorted)
    # The membership row records the template each member was *launched with*,
    # so it does not drift to the group's newer desired version mid-replacement.
    asg_launch_templates = {
        instance.get("InstanceId"): instance.get("LaunchTemplate")
        for instance in instances
    }
    described = _aws(
        "ec2",
        ["describe-instances", "--instance-ids", *in_service],
        f"{workload_key} instances",
    )
    reservations = (
        described.get("Reservations") if isinstance(described, dict) else None
    )
    if (
        not isinstance(described, dict)
        or described.get("NextToken") not in (None, "")
        or not isinstance(reservations, list)
        or any(
            not isinstance(reservation, dict)
            or not isinstance(reservation.get("Instances"), list)
            or any(
                not isinstance(instance, dict)
                for instance in reservation["Instances"]
            )
            for reservation in reservations
        )
    ):
        raise EvidenceError(f"{workload_key} EC2 instance readback is incomplete")
    live_instances = [
        instance
        for reservation in reservations
        for instance in reservation["Instances"]
    ]
    by_id = {instance.get("InstanceId"): instance for instance in live_instances}
    if set(by_id) != set(in_service) or len(by_id) != len(live_instances):
        raise EvidenceError(f"{workload_key} EC2 instance readback is incomplete")

    normalized = []
    shared_digest = None
    shared_revision = None
    for instance_id in in_service:
        instance = by_id[instance_id]
        profile_arn = (instance.get("IamInstanceProfile") or {}).get("Arn")
        if (
            (instance.get("State") or {}).get("Name") != "running"
            or not isinstance(profile_arn, str)
            or ":instance-profile/" not in profile_arn
        ):
            raise EvidenceError(f"{instance_id} has no running instance profile")
        profile_name = profile_arn.rsplit("/", 1)[-1]
        profile_response = _aws(
            "iam",
            ["get-instance-profile", "--instance-profile-name", profile_name],
            f"{instance_id} instance profile",
        )
        profile = (
            profile_response.get("InstanceProfile")
            if isinstance(profile_response, dict)
            else None
        )
        roles = profile.get("Roles") if isinstance(profile, dict) else None
        if (
            not isinstance(profile, dict)
            or profile.get("Arn") != profile_arn
            or profile.get("InstanceProfileName") != profile_name
            or not isinstance(roles, list)
            or len(roles) != 1
            or not isinstance(roles[0], dict)
            or roles[0].get("Arn") is None
            or roles[0].get("RoleId") is None
        ):
            raise EvidenceError(f"{instance_id} instance role is ambiguous")
        role_arn = roles[0]["Arn"]
        aws_userid = f"{roles[0]['RoleId']}:{instance_id}"
        key = f"runtime/{aws_userid}/latest.json"
        versions_response = _aws(
            "s3api",
            [
                "list-object-versions",
                "--bucket",
                bucket,
                "--prefix",
                key,
                "--max-keys",
                "20",
            ],
            f"{instance_id} attestation versions",
        )
        version_id = _current_object_version(
            versions_response,
            key=key,
            instance_id=instance_id,
        )
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "attestation.json"
            response = _run_json(
                [
                    "aws",
                    "s3api",
                    "get-object",
                    "--bucket",
                    bucket,
                    "--key",
                    key,
                    "--version-id",
                    version_id,
                    "--range",
                    f"bytes=0-{contract.MAX_RUNTIME_ATTESTATION_BYTES}",
                    "--region",
                    AWS_REGION,
                    "--output",
                    "json",
                    str(output),
                ],
                f"{instance_id} runtime attestation",
            )
            content_length = (
                response.get("ContentLength") if isinstance(response, dict) else None
            )
            content_range = (
                response.get("ContentRange") if isinstance(response, dict) else None
            )
            range_match = (
                re.fullmatch(r"bytes 0-([0-9]+)/([0-9]+)", content_range)
                if isinstance(content_range, str)
                else None
            )
            if (
                not isinstance(response, dict)
                or response.get("VersionId") != version_id
                or response.get("ServerSideEncryption") != "aws:kms"
                or response.get("SSEKMSKeyId") != bucket_kms_key_arn
                or type(content_length) is not int
                or not 0 < content_length <= contract.MAX_RUNTIME_ATTESTATION_BYTES
                or range_match is None
                or int(range_match.group(1)) + 1 != content_length
                or int(range_match.group(2)) != content_length
            ):
                raise EvidenceError(f"{instance_id} attestation version readback drift")
            raw = output.read_bytes()
            if len(raw) != content_length:
                raise EvidenceError(
                    f"{instance_id} attestation body length differs from metadata"
                )
        attestation = contract.normalize_runtime_attestation(
            raw,
            workload_key=workload_key,
            autoscaling_group=asg_name,
            bucket_arn=bucket_arn,
            key=key,
            version_id=version_id,
            expected_instance_id=instance_id,
            expected_role_arn=role_arn,
            expected_collector_contract=collector_contract,
        )
        live_launch_template = _launch_template_pair(
            asg_launch_templates.get(instance_id), f"{instance_id} ASG membership"
        )
        tagged_launch_template = _launch_template_pair(
            _reserved_launch_template_tags(instance),
            f"{instance_id} reserved instance tag",
        )
        attested_launch_template = (
            attestation["launch_template_id"],
            str(attestation["launch_template_version"]),
        )
        if (
            live_launch_template != tagged_launch_template
            or attested_launch_template != live_launch_template
        ):
            raise EvidenceError(f"{instance_id} launch-template attestation drift")
        live_repair = _verify_repair(
            attestation,
            instance_id,
            autoscaling_group=asg_name,
            collector_contract=collector_contract,
        )
        if attestation["repair_last_success_at"] != live_repair:
            raise EvidenceError(f"{instance_id} repair execution attestation drift")
        runtime = attestation["runtime"]
        if runtime["image_repository"] != spec["repository"]:
            raise EvidenceError(f"{instance_id} runtime repository drift")
        digest = contract._digest(
            runtime["image_digest"], f"{instance_id} runtime image digest"
        )
        revision = contract._sha(
            runtime["source_revision"], f"{instance_id} runtime source revision"
        )
        if shared_digest is None:
            shared_digest, shared_revision = digest, revision
        elif shared_digest != digest or shared_revision != revision:
            raise EvidenceError(f"{workload_key} fleet has mixed runtime identity")
        normalized.append(attestation)
    if shared_digest is None or shared_revision is None:
        raise EvidenceError(f"{workload_key} has no attested runtime identity")
    if workload_key == "qurl_reverse_tunnel_server":
        if expected_source_revision is None:
            raise EvidenceError("qRTS expected main source revision is missing")
        verified_revision, source_evidence = _qrts_build_receipt(
            spec["repository"],
            shared_digest,
            workload_key,
            expected_source_revision,
        )
        for attestation in normalized:
            runtime = attestation["runtime"]
            if (
                runtime["installed_binary_sha256"]
                != source_evidence["installed_binary_sha256"]
                or runtime["build_receipt_sha256"]
                != source_evidence["build_receipt_sha256"]
            ):
                raise EvidenceError("qRTS runtime differs from its ECR build receipt")
    else:
        if expected_source_revision is not None:
            raise EvidenceError(f"{workload_key} has an unexpected source pin")
        verified_revision, source_evidence = _oci_revision(
            spec["repository"], shared_digest, workload_key
        )
    if verified_revision != shared_revision:
        raise EvidenceError(f"{workload_key} runtime source revision is not ECR-bound")
    return {
        "kind": "ec2_attestation_set",
        "autoscaling_group": asg_name,
        "in_service_instance_ids": in_service,
        "attestations": normalized,
        "image_repository": spec["repository"],
        "image_digest": shared_digest,
        "source_revision": shared_revision,
        "source_evidence": source_evidence,
    }


def _verify_frp_tag(version: str, sha: str) -> None:
    ref = _gh(f"repos/layervai/frp/git/ref/tags/{version}", "FRP release ref")
    target = (ref.get("object") or {}) if isinstance(ref, dict) else {}
    if target.get("type") != "tag":
        raise EvidenceError("FRP canary module must use a signed annotated tag")
    tag = _gh(
        f"repos/layervai/frp/git/tags/{target.get('sha')}",
        "FRP annotated tag",
    )
    verification = tag.get("verification") if isinstance(tag, dict) else None
    tagged = tag.get("object") if isinstance(tag, dict) else None
    if (
        not isinstance(verification, dict)
        or verification.get("verified") is not True
        or verification.get("reason") != "valid"
        or not isinstance(tagged, dict)
        or tagged.get("type") != "commit"
        or tagged.get("sha") != sha
    ):
        raise EvidenceError("FRP release tag is not signed and commit-bound")
    _verify_commit("layervai/frp", sha, "FRP module")


def _validate_github_evidence(value: Any) -> dict[str, Any]:
    evidence = _exact(
        value,
        {"schema_version", "producer", "candidates", "default_branches", "canary"},
        "GitHub evidence",
    )
    if evidence["schema_version"] != 1 or type(evidence["schema_version"]) is not int:
        raise EvidenceError("GitHub evidence schema_version must be 1")
    producer = _exact(
        evidence["producer"],
        {"repository", "workflow_path", "run_id", "run_attempt", "head_sha"},
        "GitHub evidence producer",
    )
    if (
        producer["repository"] != "layervai/nhp"
        or producer["workflow_path"] != PRODUCER_WORKFLOW_PATH
    ):
        raise EvidenceError("GitHub evidence producer identity drift")
    contract._positive_int(producer["run_id"], "GitHub evidence producer run_id")
    contract._positive_int(
        producer["run_attempt"], "GitHub evidence producer run_attempt"
    )
    contract._sha(producer["head_sha"], "GitHub evidence producer head_sha")

    candidates = _exact(
        evidence["candidates"],
        {"qurl_connector", "qurl_go"},
        "GitHub evidence candidates",
    )
    for key in ("qurl_connector", "qurl_go"):
        candidate = _exact(
            candidates[key],
            {"repository", "pull_request_number", "head_ref", "head_sha"},
            f"GitHub evidence candidates.{key}",
        )
        if candidate["repository"] != contract.REPOSITORIES[key]:
            raise EvidenceError(f"GitHub evidence candidate repository drift for {key}")
        contract._positive_int(
            candidate["pull_request_number"],
            f"GitHub evidence candidates.{key}.pull_request_number",
        )
        contract.validate_branch(
            candidate["head_ref"], f"GitHub evidence candidates.{key}.head_ref"
        )
        contract._sha(
            candidate["head_sha"], f"GitHub evidence candidates.{key}.head_sha"
        )

    defaults = _exact(
        evidence["default_branches"],
        contract.DEFAULT_BRANCH_REPOSITORIES,
        "GitHub evidence default branches",
    )
    for key in sorted(contract.DEFAULT_BRANCH_REPOSITORIES):
        item = _exact(
            defaults[key],
            {"repository", "source", "ref", "sha"},
            f"GitHub evidence default branches.{key}",
        )
        if (
            item["repository"] != contract.REPOSITORIES[key]
            or item["source"] != "default_branch"
            or not str(item["ref"]).startswith("refs/heads/")
        ):
            raise EvidenceError(f"GitHub default-branch identity drift for {key}")
        contract._sha(item["sha"], f"GitHub evidence default branches.{key}.sha")

    canary = _exact(
        evidence["canary"],
        {
            "repository",
            "workflow_path",
            "run_id",
            "run_attempt",
            "head_sha",
            "artifact_id",
            "artifact_name",
            "artifact_digest",
            "artifact_size",
            "image_ref",
            "image_digest",
            "provenance_sha256",
            "frp_version",
            "frp_sha",
            "qurl_go_sha",
        },
        "GitHub evidence canary",
    )
    if (
        canary["repository"] != "layervai/qurl-connector"
        or canary["workflow_path"] != CANARY_WORKFLOW_PATH
        or canary["artifact_name"]
        != (
            "connector-canary-pr-"
            f"{candidates['qurl_connector']['pull_request_number']}-"
            f"{candidates['qurl_connector']['head_sha']}"
        )
        or canary["image_ref"]
        != f"ghcr.io/layervai/qurl-connector-canary@{canary['image_digest']}"
        or canary["qurl_go_sha"] != candidates["qurl_go"]["head_sha"]
    ):
        raise EvidenceError("GitHub evidence canary identity drift")
    for field in ("run_id", "run_attempt", "artifact_id", "artifact_size"):
        contract._positive_int(canary[field], f"GitHub evidence canary.{field}")
    if canary["artifact_size"] > CANARY_ARTIFACT_MAX_BYTES:
        raise EvidenceError("GitHub evidence canary artifact is oversized")
    contract._sha(canary["head_sha"], "GitHub evidence canary.head_sha")
    contract._digest(
        canary["artifact_digest"], "GitHub evidence canary.artifact_digest"
    )
    contract._digest(canary["image_digest"], "GitHub evidence canary.image_digest")
    contract._sha256(
        canary["provenance_sha256"], "GitHub evidence canary.provenance_sha256"
    )
    contract.validate_branch(
        canary["frp_version"], "GitHub evidence canary.frp_version"
    )
    contract._sha(canary["frp_sha"], "GitHub evidence canary.frp_sha")
    contract._sha(canary["qurl_go_sha"], "GitHub evidence canary.qurl_go_sha")
    return evidence


def collect_aws_and_build_snapshot(
    *,
    github_evidence: dict[str, Any],
    proof_phase: str,
) -> dict[str, Any]:
    github_evidence = _validate_github_evidence(github_evidence)
    collection_started_at = datetime.now(timezone.utc)
    identity = _aws("sts", ["get-caller-identity"], "AWS caller identity")
    assumed_role_pattern = re.compile(
        rf"^arn:aws:sts::{AWS_ACCOUNT_ID}:assumed-role/"
        rf"{re.escape(PRODUCER_ROLE_NAME)}/[A-Za-z0-9+=,.@_-]{{2,64}}$"
    )
    if identity.get("Account") != AWS_ACCOUNT_ID or not assumed_role_pattern.fullmatch(
        str(identity.get("Arn", ""))
    ):
        raise EvidenceError("producer did not assume the dedicated sandbox read role")
    proof_source = _proof_source_eip()
    hub_key, hub_key_version, hub_key_digest = _public_key_parameter()
    runtime_cells, catalog_evidence = _catalog_cells()
    hub_edge = _verify_dns_alias("hub.nhp.layerv.xyz")
    cell_edges = {
        "cell0": _verify_dns_alias("cell0.nhp.layerv.xyz"),
        "cell1": _verify_dns_alias("cell1.nhp.layerv.xyz"),
    }

    bucket_parameter = _ssm_parameter(ATTESTATION_BUCKET_PARAMETER)
    bucket_arn = bucket_parameter["Value"]
    bucket = _bucket_name(bucket_arn)
    bucket_kms_key_arn, bucket_policy_sha256 = _validate_attestation_bucket(bucket)
    collector_contract = _runtime_attestation_collector_contract()
    if collector_contract["bucket_policy_sha256"] != bucket_policy_sha256:
        raise EvidenceError(
            "runtime-attestation bucket policy differs from collector contract"
        )
    _validate_repair_document(collector_contract)
    qrts_main = _resolve_default_branch("qurl_reverse_tunnel_server")

    workloads = {key: _collect_ecs_workload(key) for key in sorted(ECS_WORKLOADS)}
    workloads["qurl_service_authority"] = _collect_authority_workload()
    for key in sorted(EC2_WORKLOADS):
        workloads[key] = _collect_ec2_workload(
            key,
            bucket_arn=bucket_arn,
            bucket=bucket,
            bucket_kms_key_arn=bucket_kms_key_arn,
            collector_contract=collector_contract,
            expected_source_revision=(
                qrts_main["sha"] if key == "qurl_reverse_tunnel_server" else None
            ),
        )
    for cell_id in ("cell0", "cell1"):
        workload = workloads[f"nhp_{cell_id}"]
        if (
            cell_edges[cell_id]["healthy_target_ids"]
            != workload["in_service_instance_ids"]
        ):
            raise EvidenceError(
                f"{cell_id} public NLB targets differ from its healthy ASG"
            )
    hub_task_addresses = sorted(
        address
        for task in workloads["nhp_hub"]["tasks"]
        for address in task["private_ipv4_addresses"]
    )
    if hub_edge["healthy_target_ids"] != hub_task_addresses:
        raise EvidenceError("Hub public NLB targets differ from healthy ECS tasks")
    canary = github_evidence["canary"]
    workloads["qurl_connector"] = {
        "kind": "connector_canary",
        "image_digest": canary["image_digest"],
        "source_revision": github_evidence["candidates"]["qurl_connector"]["head_sha"],
        "canary_artifact_digest": canary["artifact_digest"],
    }

    nhp_revisions = {
        workloads[key]["source_revision"]
        for key in ("nhp_cell0", "nhp_cell1", "nhp_hub")
    }
    qurl_service_revisions = {
        workloads[key]["source_revision"]
        for key in (
            "qurl_service_authority",
            "qurl_service_cell0",
            "qurl_service_cell1",
        )
    }
    if len(nhp_revisions) != 1 or len(qurl_service_revisions) != 1:
        raise EvidenceError("deployed NHP or qurl-service source revisions are mixed")
    repository_shas = {
        "frp": canary["frp_sha"],
        "nhp": next(iter(nhp_revisions)),
        "qurl_connector": github_evidence["candidates"]["qurl_connector"]["head_sha"],
        "qurl_go": github_evidence["candidates"]["qurl_go"]["head_sha"],
        "qurl_reverse_tunnel_server": workloads["qurl_reverse_tunnel_server"][
            "source_revision"
        ],
        "qurl_service": next(iter(qurl_service_revisions)),
        **{
            key: github_evidence["default_branches"][key]["sha"]
            for key in contract.DEFAULT_BRANCH_REPOSITORIES
        },
    }
    for key in ("nhp", "qurl_reverse_tunnel_server", "qurl_service"):
        _verify_commit(
            contract.REPOSITORIES[key], repository_shas[key], f"deployed {key}"
        )
    _verify_frp_tag(canary["frp_version"], canary["frp_sha"])
    for key in ("qurl_connector", "qurl_go"):
        candidate = github_evidence["candidates"][key]
        refreshed = _resolve_candidate(
            candidate["repository"],
            candidate["pull_request_number"],
            f"refreshed {key} candidate",
        )
        if refreshed != candidate:
            raise EvidenceError(f"{key} candidate moved during evidence collection")
    for key in sorted(contract.DEFAULT_BRANCH_REPOSITORIES):
        if _resolve_default_branch(key) != github_evidence["default_branches"][key]:
            raise EvidenceError(
                f"{key} default branch moved during evidence collection"
            )
    if _resolve_default_branch("qurl_reverse_tunnel_server") != qrts_main:
        raise EvidenceError(
            "qurl_reverse_tunnel_server default branch moved during evidence collection"
        )
    collection_finished_at = datetime.now(timezone.utc)
    if collection_finished_at - collection_started_at > MAX_COLLECTION_DURATION:
        raise EvidenceError("live evidence collection exceeded its five-minute window")
    observed_at = collection_finished_at.strftime("%Y-%m-%dT%H:%M:%SZ")

    repository_evidence = {
        key: github_evidence["default_branches"][key]
        for key in contract.DEFAULT_BRANCH_REPOSITORIES
    }
    for key in ("qurl_connector", "qurl_go"):
        candidate = github_evidence["candidates"][key]
        repository_evidence[key] = {
            "repository": candidate["repository"],
            "source": "candidate",
            "ref": f"refs/heads/{candidate['head_ref']}",
            "sha": candidate["head_sha"],
        }
    repository_evidence["frp"] = {
        "repository": "layervai/frp",
        "source": "canary_module",
        "ref": f"refs/tags/{canary['frp_version']}",
        "sha": canary["frp_sha"],
    }
    for key in ("nhp", "qurl_reverse_tunnel_server", "qurl_service"):
        repository_evidence[key] = {
            "repository": contract.REPOSITORIES[key],
            "source": "deployed_runtime",
            "ref": "deployed-runtime",
            "sha": repository_shas[key],
        }

    manifest_cells = [
        {
            "cell_id": cell["cell_id"],
            "host": cell["host"],
            "port": cell["port"],
            "server_public_key_sha256": evidence["server_public_key_sha256"],
        }
        for cell, evidence in zip(runtime_cells, catalog_evidence, strict=True)
    ]
    images = {key: workloads[key]["image_digest"] for key in contract.IMAGE_KEYS}
    manifest = {
        "schema_version": 1,
        "phase": proof_phase,
        "retirement_state": (
            "http_lifecycle_present"
            if proof_phase == "pre_removal"
            else "http_lifecycle_removed"
        ),
        "repositories": repository_shas,
        "connector_modules": {
            "frp": repository_shas["frp"],
            "qurl_go": repository_shas["qurl_go"],
        },
        "images": images,
        "hub": {
            "host": "hub.nhp.layerv.xyz",
            "port": contract.UDP_PORT,
            "server_public_key_sha256": hub_key_digest,
        },
        "cells": manifest_cells,
    }
    runtime = {
        "schema_version": 1,
        "hub": {
            "host": "hub.nhp.layerv.xyz",
            "port": contract.UDP_PORT,
            "server_public_key_b64": hub_key,
        },
        "cells": runtime_cells,
    }
    manifest_raw = contract.canonical_bytes(
        manifest,
        maximum=contract.MAX_MANIFEST_BYTES,
        name="deployment-manifest.json",
    )
    runtime_raw = contract.canonical_bytes(
        runtime,
        maximum=contract.MAX_RUNTIME_BYTES,
        name="deployment-runtime-inputs.json",
    )
    producer = github_evidence["producer"]
    provenance = {
        "schema_version": 1,
        "producer": producer,
        "candidates": github_evidence["candidates"],
        "files": {
            "deployment-manifest.json": (
                f"sha256:{hashlib.sha256(manifest_raw).hexdigest()}"
            ),
            "deployment-runtime-inputs.json": (
                f"sha256:{hashlib.sha256(runtime_raw).hexdigest()}"
            ),
        },
        "evidence": {
            "observed_at": observed_at,
            "aws": {
                "account_id": AWS_ACCOUNT_ID,
                "region": AWS_REGION,
                "proof_source": proof_source,
                "runtime_attestation": {
                    "bucket_parameter_name": ATTESTATION_BUCKET_PARAMETER,
                    "bucket_parameter_version": bucket_parameter["Version"],
                    "bucket_arn": bucket_arn,
                    "kms_key_arn": bucket_kms_key_arn,
                    "bucket_policy_sha256": bucket_policy_sha256,
                    "collector_contract": collector_contract,
                },
            },
            "repositories": repository_evidence,
            "public_identities": {
                "hub": {
                    "host": "hub.nhp.layerv.xyz",
                    "port": contract.UDP_PORT,
                    "public_key_parameter_name": (
                        "/sandbox/nhp/control/hub/identity/public-key"
                    ),
                    "public_key_parameter_version": hub_key_version,
                    "server_public_key_sha256": hub_key_digest,
                    **hub_edge,
                },
                "cells": [
                    {**cell, **cell_edges[cell["cell_id"]]} for cell in catalog_evidence
                ],
            },
            "connector_canary": {
                "repository": canary["repository"],
                "workflow_path": canary["workflow_path"],
                "run_id": canary["run_id"],
                "run_attempt": canary["run_attempt"],
                "head_sha": canary["head_sha"],
                "artifact_id": canary["artifact_id"],
                "artifact_name": canary["artifact_name"],
                "artifact_digest": canary["artifact_digest"],
                "image_ref": canary["image_ref"],
                "image_digest": canary["image_digest"],
                "provenance_sha256": canary["provenance_sha256"],
                "frp_sha": canary["frp_sha"],
                "qurl_go_sha": canary["qurl_go_sha"],
            },
            "workloads": workloads,
        },
    }
    snapshot = {"manifest": manifest, "runtime": runtime, "provenance": provenance}
    contract.validate_triplet(
        manifest,
        runtime,
        provenance,
        proof_phase=proof_phase,
        producer_run_id=producer["run_id"],
        producer_run_attempt=producer["run_attempt"],
        producer_head_sha=producer["head_sha"],
        validation_time=datetime.strptime(observed_at, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        ),
    )
    return snapshot


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    metadata = subparsers.add_parser("github-metadata")
    metadata.add_argument("--connector-pr-number", required=True)
    metadata.add_argument("--qurl-go-pr-number", required=True)
    metadata.add_argument("--canary-run-id", required=True)
    metadata.add_argument("--output", type=Path, required=True)
    metadata.add_argument("--github-output", type=Path, required=True)

    files = subparsers.add_parser("github-files")
    files.add_argument("--metadata", type=Path, required=True)
    files.add_argument("--directory", type=Path, required=True)
    files.add_argument("--output", type=Path, required=True)
    files.add_argument("--github-output", type=Path, required=True)

    aws_build = subparsers.add_parser("aws-build")
    aws_build.add_argument("--github-evidence", type=Path, required=True)
    aws_build.add_argument(
        "--proof-phase",
        choices=("pre_removal", "post_removal"),
        required=True,
    )
    aws_build.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    try:
        if args.command == "github-metadata":
            value, outputs = collect_github_metadata(
                connector_pr_number=_positive_input(
                    args.connector_pr_number, "qurl-connector PR number"
                ),
                qurl_go_pr_number=_positive_input(
                    args.qurl_go_pr_number, "qurl-go PR number"
                ),
                canary_run_id=_positive_input(
                    args.canary_run_id, "Connector canary run id"
                ),
            )
        elif args.command == "github-files":
            value, outputs = validate_canary_files(
                metadata=_read_metadata(args.metadata),
                directory=args.directory,
            )
        else:
            value = collect_aws_and_build_snapshot(
                github_evidence=_read_metadata(args.github_evidence),
                proof_phase=args.proof_phase,
            )
            outputs = {}
        _write_canonical(
            args.output,
            value,
            maximum=(
                GITHUB_METADATA_MAX_BYTES if args.command != "aws-build" else 256 * 1024
            ),
            name=(
                "GitHub evidence"
                if args.command != "aws-build"
                else "hydrated evidence snapshot"
            ),
        )
        if args.command != "aws-build":
            _append_outputs(args.github_output, outputs)
    except contract.ContractError as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
