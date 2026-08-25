#!/usr/bin/env python3
"""Launch and validate one protected sandbox fixed-canary customer phase.

The runner owns no AWS client and never reads the ordinary API key. The
workflow starts the owner-only custody server first, then passes only its Unix
socket and private file paths here. A current, verified source authority binds
the qurl-go and qurl-integrations artifacts before this script starts a child.
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
import tempfile
from pathlib import Path
from typing import Any

HEX40 = re.compile(r"[0-9a-f]{40}")
HEX64 = re.compile(r"[0-9a-f]{64}")
SANDBOX_API_ENDPOINT = "https://api.layerv.xyz"
MAX_PRIVATE_JSON = 2 << 20
MAX_DIAGNOSTIC = 64 << 10
MAX_COMMAND_SIZE = 256 << 20
RECOVERY_OPERATION = "recover-prepared"
LIFECYCLE_INPUT_KEYS = {
    "schema", "environment", "operation", "release_id", "phase", "attempt", "transport", "authority",
    "admission_hub", "admission_cell_endpoint", "recovery_endpoint", "run_ids", "prepared_at_ms", "expires_at_ms",
    "api_endpoint", "api_key_file", "deployment_file", "deployment_sha256", "relay_hostname",
    "lifecycle_command_sha256", "qurl_binary", "qurl_binary_sha256", "qurl_source_sha", "qurl_go_source_sha", "client_version",
}


class RunnerError(RuntimeError):
    """A generic fail-closed runner error."""


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise RunnerError("duplicate JSON key")
        value[key] = item
    return value


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _load_private(path: str, *, must_exist: bool = True) -> tuple[dict[str, Any], bytes]:
    file_path = Path(path)
    if not file_path.is_absolute() or str(file_path) != path:
        raise RunnerError("private path is not exact")
    try:
        before = file_path.lstat()
    except FileNotFoundError:
        if must_exist:
            raise RunnerError("private file is absent") from None
        return {}, b""
    if not stat.S_ISREG(before.st_mode) or stat.S_IMODE(before.st_mode) not in {0o400, 0o600} or before.st_nlink != 1:
        raise RunnerError("private file metadata is invalid")
    if before.st_uid not in {0, os.geteuid()} or before.st_size < 2 or before.st_size > MAX_PRIVATE_JSON:
        raise RunnerError("private file ownership or size is invalid")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise RunnerError("private file open failed") from error
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise RunnerError("private file changed while opening")
        raw = b""
        while len(raw) <= MAX_PRIVATE_JSON:
            chunk = os.read(descriptor, min(65536, MAX_PRIVATE_JSON + 1 - len(raw)))
            if not chunk:
                break
            raw += chunk
    finally:
        os.close(descriptor)
    after = file_path.lstat()
    if (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_mode) != (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_mode,
    ) or len(raw) != before.st_size:
        raise RunnerError("private file changed while reading")
    if not raw.endswith(b"\n") or b"\n" in raw[:-1] or b"\r" in raw:
        raise RunnerError("private file framing is invalid")
    try:
        value = json.loads(raw[:-1], object_pairs_hook=_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RunnerError("private JSON is invalid") from error
    if not isinstance(value, dict):
        raise RunnerError("private JSON is not an object")
    return value, raw


def _open_stable_executable(path: str) -> tuple[int, str, os.stat_result]:
    file_path = Path(path)
    if not file_path.is_absolute() or str(file_path) != path:
        raise RunnerError("lifecycle command path is not exact")
    try:
        before = file_path.lstat()
    except OSError as error:
        raise RunnerError("lifecycle command is unavailable") from error
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_uid not in {0, os.geteuid()}
        or stat.S_IMODE(before.st_mode) & 0o222
        or stat.S_IMODE(before.st_mode) & 0o111 == 0
        or before.st_size <= 0
        or before.st_size > MAX_COMMAND_SIZE
    ):
        raise RunnerError("lifecycle command metadata is invalid")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise RunnerError("lifecycle command open failed") from error
    digest = hashlib.sha256()
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino, opened.st_mode, opened.st_nlink, opened.st_uid, opened.st_gid, opened.st_size) != (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_nlink,
            before.st_uid,
            before.st_gid,
            before.st_size,
        ):
            raise RunnerError("lifecycle command changed while opening")
        remaining = opened.st_size
        while remaining:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                raise RunnerError("lifecycle command read was short")
            digest.update(chunk)
            remaining -= len(chunk)
        after = file_path.lstat()
        if (after.st_dev, after.st_ino, after.st_mode, after.st_nlink, after.st_uid, after.st_gid, after.st_size, after.st_mtime_ns) != (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_nlink,
            before.st_uid,
            before.st_gid,
            before.st_size,
            before.st_mtime_ns,
        ):
            raise RunnerError("lifecycle command changed while reading")
        os.lseek(descriptor, 0, os.SEEK_SET)
        return descriptor, digest.hexdigest(), before
    except BaseException:
        os.close(descriptor)
        raise


def _stable_executable_sha256(path: str) -> str:
    descriptor, digest, _ = _open_stable_executable(path)
    os.close(descriptor)
    return digest


def _require_same_executable_path(path: str, expected: os.stat_result) -> None:
    try:
        current = Path(path).lstat()
    except OSError as error:
        raise RunnerError("lifecycle command path changed during execution") from error
    if (current.st_dev, current.st_ino, current.st_mode, current.st_nlink, current.st_uid, current.st_gid, current.st_size, current.st_mtime_ns) != (
        expected.st_dev,
        expected.st_ino,
        expected.st_mode,
        expected.st_nlink,
        expected.st_uid,
        expected.st_gid,
        expected.st_size,
        expected.st_mtime_ns,
    ):
        raise RunnerError("lifecycle command path changed during execution")


def _exact_keys(value: Any, expected: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise RunnerError(f"{label} schema is not exact")
    return value


def _state_reference(value: Any, label: str) -> dict[str, Any]:
    reference = _exact_keys(value, {"key", "version_id", "sha256"}, label)
    if (
        not isinstance(reference["key"], str)
        or not reference["key"]
        or reference["key"] != reference["key"].strip()
        or not isinstance(reference["version_id"], str)
        or HEX64.fullmatch(reference["version_id"]) is None
        or not isinstance(reference["sha256"], str)
        or HEX64.fullmatch(reference["sha256"]) is None
    ):
        raise RunnerError(f"{label} is invalid")
    return reference


def _validate_state_updates(report: dict[str, Any], input_value: dict[str, Any]) -> None:
    operation = input_value["operation"]
    if operation == "lifecycle":
        labels = ["direct-a", "direct-b"] if input_value["transport"] == "direct" else ["relay-c", "relay-d"]
    else:
        labels = []
    updates = report["state_updates"]
    if not isinstance(updates, list) or len(updates) != len(labels):
        raise RunnerError("state update count is not exact")
    for index, label in enumerate(labels):
        update = _exact_keys(updates[index], {"label", "before", "after"}, "state update")
        before = _state_reference(update["before"], "state update before reference")
        after = _state_reference(update["after"], "state update after reference")
        if (
            update["label"] != label
            or before["key"] != after["key"]
            or before["version_id"] == after["version_id"]
            or before["sha256"] == after["sha256"]
        ):
            raise RunnerError("state update does not bind an exact durable refresh")


def validate_report(report: Any, input_value: dict[str, Any], input_raw: bytes) -> None:
    value = _exact_keys(
        report,
        {
            "schema",
            "environment",
            "operation",
            "release_id",
            "phase",
            "attempt",
            "transport",
            "input_sha256",
            "authority",
            "state_updates",
            "lifecycle_command_sha256",
            "qurl_binary_sha256",
            "qurl_source_sha",
            "qurl_go_source_sha",
            "lifecycle",
        }
        if input_value["operation"] == "lifecycle"
        else {
            "schema",
            "environment",
            "operation",
            "release_id",
            "phase",
            "attempt",
            "transport",
            "input_sha256",
            "authority",
            "state_updates",
            "lifecycle_command_sha256",
            "qurl_binary_sha256",
            "qurl_source_sha",
            "qurl_go_source_sha",
            "recovery",
        },
        "lifecycle report",
    )
    for key in (
        "schema",
        "environment",
        "operation",
        "release_id",
        "phase",
        "attempt",
        "transport",
        "authority",
        "lifecycle_command_sha256",
        "qurl_binary_sha256",
        "qurl_source_sha",
        "qurl_go_source_sha",
    ):
        if value[key] != input_value[key]:
            raise RunnerError("lifecycle report does not match its input")
    if value["input_sha256"] != hashlib.sha256(input_raw).hexdigest():
        raise RunnerError("lifecycle report input digest is not exact")
    _validate_state_updates(value, input_value)
    if input_value["operation"] == "lifecycle":
        lifecycle_value = value["lifecycle"]
        if not isinstance(lifecycle_value, dict) or lifecycle_value.get("status") not in {"completed", "settled-retry-required"}:
            raise RunnerError("lifecycle status is not exact")
        payload_key = "outcome" if lifecycle_value["status"] == "completed" else "settlement"
        lifecycle = _exact_keys(lifecycle_value, {"status", "intent", "primary_first_key", "sibling_key", "replacement_key", payload_key}, "lifecycle outcome")
        if lifecycle["status"] == "settled-retry-required":
            settlement = _exact_keys(lifecycle["settlement"], {"attempt", "operation_keys", "terminal_states", "retry_required"}, "lifecycle settlement")
            keys = [lifecycle["primary_first_key"], lifecycle["sibling_key"], lifecycle["replacement_key"]]
            if settlement["attempt"] != input_value["attempt"] or settlement["operation_keys"] != keys or settlement["retry_required"] is not True or not isinstance(settlement["terminal_states"], list) or len(settlement["terminal_states"]) != 3 or any(state not in {"CANCELED", "CLOSED"} for state in settlement["terminal_states"]):
                raise RunnerError("lifecycle settlement is not terminal")
            return
        outcome = _exact_keys(lifecycle["outcome"], {
            "transport", "primary_first_run_id", "sibling_run_id", "primary_replacement_run_id",
            "primary_exact_retirement", "get_both_before_retire", "sibling_continued", "replacement_ready",
            "get_both_after_replacement", "replacement_exact_retirement", "sibling_exact_retirement",
        }, "customer outcome")
        if outcome["transport"] != input_value["transport"] or any(
            outcome[key] is not True
            for key in (
                "primary_exact_retirement", "get_both_before_retire", "sibling_continued", "replacement_ready",
                "get_both_after_replacement", "replacement_exact_retirement", "sibling_exact_retirement",
            )
        ):
            raise RunnerError("customer lifecycle outcome is incomplete")
        if [outcome["primary_first_run_id"], outcome["sibling_run_id"], outcome["primary_replacement_run_id"]] != input_value["run_ids"]:
            raise RunnerError("customer lifecycle RunIDs changed")
    elif input_value["operation"] == RECOVERY_OPERATION:
        recovery = _exact_keys(value["recovery"], {"status", "label", "receipt"}, "recovery-first outcome")
        receipt = _exact_keys(
            recovery["receipt"],
            {"operation_key", "record", "operation_id", "binding_sha256", "terminal"},
            "recovery-first receipt",
        )
        record = _state_reference(receipt["record"], "recovery-first durable record")
        terminal = _exact_keys(receipt["terminal"], {"state", "was_admitted"}, "recovery-first terminal")
        if (
            recovery["status"] != "completed"
            or recovery["label"] != "direct-a"
            or not isinstance(receipt["operation_key"], str)
            or not receipt["operation_key"]
            or record["key"] != receipt["operation_key"]
            or HEX64.fullmatch(str(receipt["operation_id"])) is None
            or HEX64.fullmatch(str(receipt["binding_sha256"])) is None
            or terminal != {"state": "CANCELED", "was_admitted": False}
        ):
            raise RunnerError("recovery-first receipt is not exact CANCELED authority")


def _validate_source_authority(value: Any, input_value: dict[str, Any], command: str, command_digest: str) -> None:
    authority = _exact_keys(
        value,
        {
            "schema",
            "environment",
            "operation",
            "correlation_id",
            "request_sha256",
            "caller",
            "sources",
            "artifacts",
            "binaries",
        },
        "source authority",
    )
    caller = _exact_keys(authority["caller"], {"repository", "workflow", "head_sha", "run_id", "run_attempt"}, "source caller")
    sources = _exact_keys(
        authority["sources"],
        {"nhp", "qurl_integrations_head", "qurl_go", "qurl_infra", "qurl_infra_helper_sha256"},
        "source commits",
    )
    binaries = _exact_keys(authority["binaries"], {"authority", "lifecycle", "qurl"}, "source binaries")
    if (
        authority["schema"] != 1
        or authority["environment"] != "sandbox"
        or authority["operation"] != "qurl-customer-journey"
        or caller["repository"] != "layervai/qurl-integrations"
        or caller["workflow"] != ".github/workflows/cli.yml"
        or HEX40.fullmatch(str(caller["head_sha"])) is None
        or HEX40.fullmatch(str(sources["nhp"])) is None
        or sources["qurl_integrations_head"] != caller["head_sha"]
        or sources["qurl_integrations_head"] != input_value.get("qurl_source_sha")
        or HEX40.fullmatch(str(sources["qurl_go"])) is None
        or HEX40.fullmatch(str(sources["qurl_infra"])) is None
        or HEX64.fullmatch(str(sources["qurl_infra_helper_sha256"])) is None
        or input_value.get("qurl_go_source_sha") != sources["qurl_go"]
    ):
        raise RunnerError("source authority does not match the reviewed customer input")
    for label, expected_path, expected_digest in (
        ("lifecycle", command, command_digest),
        ("qurl", input_value.get("qurl_binary"), input_value.get("qurl_binary_sha256")),
    ):
        binary = _exact_keys(
            binaries[label],
            {"path", "sha256", "main_module", "main_version", "qurl_go_module_version"},
            f"{label} source binary",
        )
        if binary["path"] != expected_path or binary["sha256"] != expected_digest:
            raise RunnerError(f"{label} source binary does not match the opened customer input")


def run(command: str, socket_path: str, input_path: str, source_authority_path: str, report_path: str) -> None:
    input_value, input_raw = _load_private(input_path)
    _exact_keys(input_value, LIFECYCLE_INPUT_KEYS, "lifecycle input")
    if (
        input_value.get("environment") != "sandbox"
        or input_value.get("api_endpoint") != SANDBOX_API_ENDPOINT
        or HEX40.fullmatch(str(input_value.get("qurl_go_source_sha"))) is None
        or HEX40.fullmatch(str(input_value.get("qurl_source_sha"))) is None
        or input_value.get("operation") not in {"lifecycle", RECOVERY_OPERATION}
    ):
        raise RunnerError("lifecycle input environment or reviewed source is not exact")
    if input_value.get("operation") == RECOVERY_OPERATION and (
        input_value.get("transport") != "direct"
        or input_value.get("phase") != "fixed_shared_recovery_first"
        or input_value.get("attempt") != 1
        or not isinstance(input_value.get("run_ids"), list)
        or len(input_value["run_ids"]) != 1
    ):
        raise RunnerError("recovery-first input is not exact")
    if input_value.get("operation") == "lifecycle" and (
        input_value.get("transport") not in {"direct", "relay"}
        or input_value.get("phase") != f"fixed_shared_{input_value.get('transport')}"
        or not isinstance(input_value.get("run_ids"), list)
        or len(input_value["run_ids"]) != 3
    ):
        raise RunnerError("shared lifecycle input is not exact")
    report = Path(report_path)
    if report.exists() or report.is_symlink() or not report.parent.is_dir() or stat.S_IMODE(report.parent.stat().st_mode) != 0o700:
        raise RunnerError("report output path is not fresh and private")
    if not sys.platform.startswith("linux"):
        raise RunnerError("exact lifecycle executable launch requires Linux")
    expected_command_digest = input_value.get("lifecycle_command_sha256")
    descriptor, command_digest, command_stat = _open_stable_executable(command)
    try:
        if not isinstance(expected_command_digest, str) or HEX64.fullmatch(expected_command_digest) is None or command_digest != expected_command_digest:
            raise RunnerError("lifecycle command digest does not match the release input")
        source_authority, _ = _load_private(source_authority_path)
        _validate_source_authority(source_authority, input_value, command, command_digest)
        descriptor_path = f"/proc/self/fd/{descriptor}"
        with tempfile.TemporaryFile() as output:
            completed = subprocess.run(
                [descriptor_path, "--authority-socket", socket_path, "--input-file", input_path, "--report-file", report_path],
                executable=descriptor_path,
                pass_fds=(descriptor,),
                stdin=subprocess.DEVNULL,
                stdout=output,
                stderr=output,
                env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
                timeout=180,
                check=False,
            )
            size = output.seek(0, os.SEEK_END)
            if completed.returncode != 0 or size != 0 or size > MAX_DIAGNOSTIC:
                raise RunnerError("protected lifecycle command failed")
        _require_same_executable_path(command, command_stat)
    finally:
        os.close(descriptor)
    report_value, _ = _load_private(report_path)
    validate_report(report_value, input_value, input_raw)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--command", required=True)
    parser.add_argument("--authority-socket", required=True)
    parser.add_argument("--input-file", required=True)
    parser.add_argument("--source-authority-file", required=True)
    parser.add_argument("--report-file", required=True)
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    run(args.command, args.authority_socket, args.input_file, args.source_authority_file, args.report_file)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except (RunnerError, OSError, subprocess.SubprocessError):
        print("sandbox matched-cohort lifecycle runner failed", file=sys.stderr)
        raise SystemExit(1) from None
