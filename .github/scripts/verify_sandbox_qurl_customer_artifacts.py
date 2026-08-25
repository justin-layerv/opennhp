#!/usr/bin/env python3
"""Verify and materialize one qURL sandbox customer-journey artifact set.

The GitHub workflow projects the caller run and artifact API responses into
closed canonical JSON before this command runs.  This command then binds those
responses to the dispatch request, verifies both downloaded ZIP digests and
their exact members, verifies Go build metadata, and installs the three reviewed
binaries into one fresh owner-only directory.  It has no AWS or GitHub client.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any, Callable

SCHEMA = 1
CALLER_REPOSITORY = "layervai/qurl-integrations"
CALLER_WORKFLOW = ".github/workflows/cli.yml"
SOURCE_RECEIPT_MEMBER = "sandbox-matched-cohort-source-receipt.json"
BINARY_MEMBERS = (
    "bin/sandbox-matched-cohort-authority",
    "bin/sandbox-matched-cohort-lifecycle",
    "bin/qurl",
)
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
API_DIGEST = re.compile(r"sha256:([0-9a-f]{64})\Z")
ARTIFACT_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
CORRELATION = re.compile(r"qurl-([1-9][0-9]*)-([1-9][0-9]*)-([0-9a-f]{12})\Z")
MAX_ZIP_BYTES = 300 << 20
MAX_BINARY_BYTES = 256 << 20
MAX_RECEIPT_BYTES = 64 << 10


class VerificationError(RuntimeError):
    """The artifact set is not one exact reviewed source authority."""


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise VerificationError("JSON contains a duplicate field")
        result[key] = value
    return result


def canonical(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode()


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _load_canonical(path: Path, label: str, *, limit: int = MAX_RECEIPT_BYTES) -> tuple[dict[str, Any], bytes]:
    raw = path.read_bytes()
    if not raw or len(raw) > limit or not raw.endswith(b"\n") or b"\r" in raw or b"\n" in raw[:-1]:
        raise VerificationError(f"{label} framing is invalid")
    try:
        value = json.loads(raw[:-1], object_pairs_hook=_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise VerificationError(f"{label} JSON is invalid") from error
    if not isinstance(value, dict) or canonical(value) != raw:
        raise VerificationError(f"{label} is not canonical")
    return value, raw


def _exact(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise VerificationError(f"{label} schema is not exact")
    return value


def validate_request(value: Any) -> dict[str, Any]:
    request = _exact(
        value,
        {
            "schema",
            "operation",
            "expected_nhp_source_sha",
            "caller_repository",
            "caller_mode",
            "caller_head_sha",
            "caller_run_id",
            "caller_run_attempt",
            "qurl_go_source_sha",
            "qurl_infra_source_sha",
            "qurl_infra_helper_sha256",
            "binary_artifact_name",
            "binary_artifact_digest",
            "source_receipt_artifact_name",
            "source_receipt_artifact_digest",
            "correlation_id",
        },
        "journey request",
    )
    run_id, run_attempt = request["caller_run_id"], request["caller_run_attempt"]
    if (
        request["schema"] != SCHEMA
        or request["operation"] != "qurl-customer-journey"
        or HEX40.fullmatch(str(request["expected_nhp_source_sha"])) is None
        or request["caller_repository"] != CALLER_REPOSITORY
        or request["caller_mode"] not in {"active", "postdeploy"}
        or HEX40.fullmatch(str(request["caller_head_sha"])) is None
        or type(run_id) is not int
        or run_id <= 0
        or type(run_attempt) is not int
        or run_attempt <= 0
        or HEX40.fullmatch(str(request["qurl_go_source_sha"])) is None
        or HEX40.fullmatch(str(request["qurl_infra_source_sha"])) is None
        or HEX64.fullmatch(str(request["qurl_infra_helper_sha256"])) is None
        or ARTIFACT_NAME.fullmatch(str(request["binary_artifact_name"])) is None
        or API_DIGEST.fullmatch(str(request["binary_artifact_digest"])) is None
        or ARTIFACT_NAME.fullmatch(str(request["source_receipt_artifact_name"])) is None
        or API_DIGEST.fullmatch(str(request["source_receipt_artifact_digest"])) is None
    ):
        raise VerificationError("journey request identity is invalid")
    expected_correlation = f"qurl-{run_id}-{run_attempt}-{request['caller_head_sha'][:12]}"
    if CORRELATION.fullmatch(str(request["correlation_id"])) is None or request["correlation_id"] != expected_correlation:
        raise VerificationError("journey correlation is not exact")
    return request


def validate_caller_run(value: Any, request: dict[str, Any]) -> None:
    run = _exact(
        value,
        {"schema", "repository", "workflow", "head_sha", "run_id", "run_attempt", "event", "status", "conclusion"},
        "caller run",
    )
    expected_event = "pull_request" if request["caller_mode"] == "active" else "push"
    status, conclusion = ("in_progress", None) if request["caller_mode"] == "active" else ("completed", "success")
    expected = {
        "schema": SCHEMA,
        "repository": CALLER_REPOSITORY,
        "workflow": CALLER_WORKFLOW,
        "head_sha": request["caller_head_sha"],
        "run_id": request["caller_run_id"],
        "run_attempt": request["caller_run_attempt"],
        "event": expected_event,
        "status": status,
        "conclusion": conclusion,
    }
    if run != expected:
        raise VerificationError("caller run does not match its exact lifecycle authority")


def validate_artifact(value: Any, request: dict[str, Any], kind: str) -> None:
    artifact = _exact(value, {"schema", "name", "digest", "size_in_bytes", "run_id", "expired"}, f"{kind} artifact")
    name_key = "binary_artifact_name" if kind == "binary" else "source_receipt_artifact_name"
    digest_key = "binary_artifact_digest" if kind == "binary" else "source_receipt_artifact_digest"
    if (
        artifact["schema"] != SCHEMA
        or artifact["name"] != request[name_key]
        or artifact["digest"] != request[digest_key]
        or type(artifact["size_in_bytes"]) is not int
        or not 1 <= artifact["size_in_bytes"] <= MAX_ZIP_BYTES
        or artifact["run_id"] != request["caller_run_id"]
        or artifact["expired"] is not False
    ):
        raise VerificationError(f"{kind} artifact metadata is not exact")


def _read_zip(path: Path, api_digest: str, expected: set[str], limits: dict[str, int]) -> dict[str, bytes]:
    raw_digest = digest(path.read_bytes())
    match = API_DIGEST.fullmatch(api_digest)
    if match is None or match.group(1) != raw_digest:
        raise VerificationError("downloaded artifact digest differs from GitHub authority")
    values: dict[str, bytes] = {}
    try:
        with zipfile.ZipFile(path) as archive:
            infos = archive.infolist()
            if len(infos) != len(expected) or {item.filename for item in infos} != expected:
                raise VerificationError("artifact member inventory is not exact")
            for item in infos:
                member = PurePosixPath(item.filename)
                mode = item.external_attr >> 16
                if (
                    member.is_absolute()
                    or ".." in member.parts
                    or item.is_dir()
                    or stat.S_ISLNK(mode)
                    or (mode and not stat.S_ISREG(mode))
                    or item.flag_bits & 0x1
                    or item.file_size <= 0
                    or item.file_size > limits[item.filename]
                ):
                    raise VerificationError("artifact contains an unsafe member")
                values[item.filename] = archive.read(item)
    except (OSError, zipfile.BadZipFile, RuntimeError) as error:
        if isinstance(error, VerificationError):
            raise
        raise VerificationError("artifact ZIP is invalid") from error
    return values


def _parse_build_info(raw: str, binary: str, revision_expected: str, qurl_go_source_expected: str) -> dict[str, Any]:
    revision = modified = main_module = main_version = ""
    dependencies: dict[str, str] = {}
    for line in raw.splitlines():
        fields = line.lstrip().split("\t")
        if len(fields) >= 3 and fields[0] == "mod":
            main_module, main_version = fields[1], fields[2]
        elif len(fields) >= 3 and fields[0] == "dep":
            dependencies[fields[1]] = fields[2]
        elif len(fields) == 2 and fields[0] == "build" and "=" in fields[1]:
            key, value = fields[1].split("=", 1)
            if key == "vcs.revision":
                revision = value
            elif key == "vcs.modified":
                modified = value
    if (
        main_module != "github.com/layervai/qurl-integrations"
        or revision != revision_expected
        or modified != "false"
        or dependencies.get("github.com/layervai/qurl-go") != binary
        or not binary.endswith("-" + qurl_go_source_expected[:12])
        or not main_version
    ):
        raise VerificationError("qURL binary Go build authority is not exact")
    return {"main_module": main_module, "main_version": main_version, "qurl_go_module_version": binary}


def _go_build_info(path: Path) -> str:
    completed = subprocess.run(
        ["go", "version", "-m", str(path)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=10,
        check=False,
    )
    if completed.returncode != 0 or completed.stderr:
        raise VerificationError("qURL binary build metadata is unavailable")
    return completed.stdout


def verify(
    request_path: Path,
    run_path: Path,
    binary_metadata_path: Path,
    receipt_metadata_path: Path,
    binary_zip: Path,
    receipt_zip: Path,
    output_directory: Path,
    authority_path: Path,
    *,
    build_info: Callable[[Path], str] = _go_build_info,
) -> dict[str, Any]:
    request, request_raw = _load_canonical(request_path, "journey request")
    request = validate_request(request)
    run, _ = _load_canonical(run_path, "caller run")
    validate_caller_run(run, request)
    binary_metadata, _ = _load_canonical(binary_metadata_path, "binary artifact metadata")
    receipt_metadata, _ = _load_canonical(receipt_metadata_path, "source receipt artifact metadata")
    validate_artifact(binary_metadata, request, "binary")
    validate_artifact(receipt_metadata, request, "source_receipt")
    binaries = _read_zip(binary_zip, request["binary_artifact_digest"], set(BINARY_MEMBERS), {name: MAX_BINARY_BYTES for name in BINARY_MEMBERS})
    receipt_members = _read_zip(receipt_zip, request["source_receipt_artifact_digest"], {SOURCE_RECEIPT_MEMBER}, {SOURCE_RECEIPT_MEMBER: MAX_RECEIPT_BYTES})
    receipt_raw = receipt_members[SOURCE_RECEIPT_MEMBER]
    try:
        receipt = json.loads(receipt_raw, object_pairs_hook=_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise VerificationError("source receipt JSON is invalid") from error
    if not isinstance(receipt, dict) or canonical(receipt) != receipt_raw:
        raise VerificationError("source receipt is not canonical")
    receipt = _exact(
        receipt,
        {"schema_version", "repository", "head_sha", "run_id", "run_attempt", "qurl_go_source_sha", "qurl_go_module_version", "binaries"},
        "source receipt",
    )
    expected_identity = {
        "schema_version": 1,
        "repository": CALLER_REPOSITORY,
        "head_sha": request["caller_head_sha"],
        "run_id": request["caller_run_id"],
        "run_attempt": request["caller_run_attempt"],
        "qurl_go_source_sha": request["qurl_go_source_sha"],
    }
    if any(receipt.get(key) != value for key, value in expected_identity.items()):
        raise VerificationError("source receipt identity does not match the caller")
    binary_receipts = _exact(receipt["binaries"], {"lifecycle", "authority", "qurl"}, "source receipt binaries")
    named = {
        "authority": BINARY_MEMBERS[0],
        "lifecycle": BINARY_MEMBERS[1],
        "qurl": BINARY_MEMBERS[2],
    }
    installed: dict[str, dict[str, str]] = {}
    if output_directory.exists() or authority_path.exists() or authority_path.is_symlink():
        raise VerificationError("artifact output paths are not fresh")
    output_directory.mkdir(mode=0o700)
    for label, member in named.items():
        expected = _exact(binary_receipts[label], {"path", "sha256"}, f"{label} binary receipt")
        if expected["path"] != member or HEX64.fullmatch(str(expected["sha256"])) is None or digest(binaries[member]) != expected["sha256"]:
            raise VerificationError(f"{label} binary digest is not exact")
        destination = output_directory / Path(member).name
        descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o500)
        try:
            os.write(descriptor, binaries[member])
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        module_version = str(receipt["qurl_go_module_version"])
        info = _parse_build_info(
            build_info(destination),
            module_version,
            request["caller_head_sha"],
            request["qurl_go_source_sha"],
        )
        installed[label] = {"path": str(destination), "sha256": expected["sha256"], **info}
    authority = {
        "schema": SCHEMA,
        "environment": "sandbox",
        "operation": "qurl-customer-journey",
        "correlation_id": request["correlation_id"],
        "request_sha256": digest(request_raw),
        "caller": {key: run[key] for key in ("repository", "workflow", "head_sha", "run_id", "run_attempt")},
        "sources": {
            "nhp": request["expected_nhp_source_sha"],
            "qurl_integrations_head": request["caller_head_sha"],
            "qurl_go": request["qurl_go_source_sha"],
            "qurl_infra": request["qurl_infra_source_sha"],
            "qurl_infra_helper_sha256": request["qurl_infra_helper_sha256"],
        },
        "artifacts": {
            "binary": {"name": binary_metadata["name"], "digest": binary_metadata["digest"]},
            "source_receipt": {"name": receipt_metadata["name"], "digest": receipt_metadata["digest"], "sha256": digest(receipt_raw)},
        },
        "binaries": installed,
    }
    raw = canonical(authority)
    descriptor = os.open(authority_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        os.write(descriptor, raw)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return authority


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--request-file", type=Path, required=True)
    parser.add_argument("--caller-run-file", type=Path, required=True)
    parser.add_argument("--binary-artifact-metadata-file", type=Path, required=True)
    parser.add_argument("--source-receipt-artifact-metadata-file", type=Path, required=True)
    parser.add_argument("--binary-artifact-zip", type=Path, required=True)
    parser.add_argument("--source-receipt-artifact-zip", type=Path, required=True)
    parser.add_argument("--output-directory", type=Path, required=True)
    parser.add_argument("--authority-file", type=Path, required=True)
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    verify(
        args.request_file,
        args.caller_run_file,
        args.binary_artifact_metadata_file,
        args.source_receipt_artifact_metadata_file,
        args.binary_artifact_zip,
        args.source_receipt_artifact_zip,
        args.output_directory,
        args.authority_file,
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except (OSError, VerificationError, subprocess.SubprocessError, zipfile.BadZipFile):
        print("sandbox qURL customer artifact verification failed", file=sys.stderr)
        raise SystemExit(1) from None
