#!/usr/bin/env python3
"""Coordinate one replay-bound qurl-go assignment mutation proof."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import secrets
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ACCOUNT_ID = "767397897469"
REGION = "us-east-2"
BUCKET = f"layerv-nhp-sandbox-udp-proof-handshake-{ACCOUNT_ID}"
KMS_ALIAS_ARN = (
    f"arn:aws:kms:{REGION}:{ACCOUNT_ID}:"
    "alias/layerv-nhp-sandbox-udp-proof-handshake"
)
KMS_KEY_ARN_RE = re.compile(
    rf"^arn:aws:kms:{REGION}:{ACCOUNT_ID}:key/"
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
ALIAS_RE = re.compile(
    rf"^arn:aws:lambda:{REGION}:{ACCOUNT_ID}:function:"
    r"layerv-nhp-sandbox-ca-pm:(blue|green)$"
)
HEX32_RE = re.compile(r"^[0-9a-f]{32}$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
RUN_RE = re.compile(r"^[1-9][0-9]{0,19}$")
TIMESTAMP_RE = re.compile(
    r"^[0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])"
    r"T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$"
)
PHASES = frozenset({"pre_removal", "post_removal"})
ARM_LEASE_SECONDS = 2100
EXPIRE_LEASE_SECONDS = 30


class HandshakeError(RuntimeError):
    pass


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise HandshakeError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _loads(raw: bytes | str, name: str) -> Any:
    if isinstance(raw, bytes):
        try:
            raw = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise HandshakeError(f"{name} is not UTF-8") from exc
    try:
        return json.loads(
            raw,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda value: (_ for _ in ()).throw(
                HandshakeError(f"{name} contains non-finite {value}")
            ),
        )
    except json.JSONDecodeError as exc:
        raise HandshakeError(f"{name} is not strict JSON") from exc


def _canonical(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode()


def _exact(value: Any, keys: set[str], name: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        observed = sorted(value) if isinstance(value, dict) else type(value).__name__
        raise HandshakeError(f"{name} keys differ: {observed}")
    return value


def _decode_b64(raw: str, name: str, maximum: int = 4 * 1024 * 1024) -> bytes:
    if not isinstance(raw, str) or not raw or len(raw) > maximum * 2:
        raise HandshakeError(f"{name} length is invalid")
    try:
        decoded = base64.b64decode(raw, validate=True)
    except ValueError as exc:
        raise HandshakeError(f"{name} is not canonical base64") from exc
    if not decoded or len(decoded) > maximum:
        raise HandshakeError(f"{name} decoded length is invalid")
    return decoded


def _timestamp(value: Any, name: str) -> datetime:
    if not isinstance(value, str) or TIMESTAMP_RE.fullmatch(value) is None:
        raise HandshakeError(f"{name} must be canonical whole-second UTC")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as exc:
        raise HandshakeError(f"{name} is not a real UTC timestamp") from exc
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
        raise HandshakeError(f"{name} is not canonical whole-second UTC")
    return parsed


def select_ca_pm_alias(provenance: Any) -> str:
    root = _exact(
        provenance,
        {
            "candidates",
            "evidence",
            "files",
            "producer",
            "schema_version",
        },
        "deployment provenance",
    )
    evidence = root["evidence"]
    if not isinstance(evidence, dict):
        raise HandshakeError("deployment provenance evidence is invalid")
    workloads = evidence.get("workloads")
    if not isinstance(workloads, dict):
        raise HandshakeError("deployment provenance workloads are invalid")
    authority = workloads.get("qurl_service_authority")
    if not isinstance(authority, dict):
        raise HandshakeError("deployment manifest has no Authority workload")
    if authority.get("proof_policy_consumers_active") is not True:
        raise HandshakeError(
            "selected IA/RA/ICR proof-policy activation is not live; "
            "the governed zero-spill rollout is still required"
        )
    functions = authority.get("functions")
    if not isinstance(functions, list):
        raise HandshakeError("Authority function inventory is invalid")
    aliases = []
    for item in functions:
        if (
            isinstance(item, dict)
            and set(item) == {"alias_arn", "version_arn"}
            and isinstance(item.get("alias_arn"), str)
            and ALIAS_RE.fullmatch(item["alias_arn"])
        ):
            aliases.append(item["alias_arn"])
    if len(aliases) != 1:
        raise HandshakeError("manifest must bind exactly one selected ca-pm alias")
    return aliases[0]


def validate_descriptor(value: Any) -> dict[str, Any]:
    descriptor = _exact(
        value,
        {
            "agent_id",
            "arm_request_id",
            "bucket",
            "ca_pm_alias_arn",
            "channel_id",
            "checkpoint_key",
            "client",
            "controller_run_attempt",
            "controller_run_id",
            "correlation_id",
            "expire_request_id",
            "kms_key_arn",
            "arm_lease_seconds",
            "expire_lease_seconds",
            "move_request_id",
            "pinned_cell_id",
            "proof_phase",
            "receipt_key",
            "target_cell_id",
            "version",
        },
        "handshake descriptor",
    )
    run_id = descriptor["controller_run_id"]
    run_attempt = descriptor["controller_run_attempt"]
    phase = descriptor["proof_phase"]
    channel = descriptor["channel_id"]
    if (
        descriptor["version"] != 1
        or descriptor["client"] != "qurl_go"
        or not isinstance(run_id, str)
        or RUN_RE.fullmatch(run_id) is None
        or not isinstance(run_attempt, str)
        or RUN_RE.fullmatch(run_attempt) is None
        or phase not in PHASES
        or not isinstance(channel, str)
        or HEX32_RE.fullmatch(channel) is None
        or descriptor["bucket"] != BUCKET
        or not isinstance(descriptor["kms_key_arn"], str)
        or KMS_KEY_ARN_RE.fullmatch(descriptor["kms_key_arn"]) is None
        or descriptor["pinned_cell_id"] != "cell0"
        or descriptor["target_cell_id"] != "cell1"
        or descriptor["arm_lease_seconds"] != ARM_LEASE_SECONDS
        or descriptor["expire_lease_seconds"] != EXPIRE_LEASE_SECONDS
        or not isinstance(descriptor["ca_pm_alias_arn"], str)
        or ALIAS_RE.fullmatch(descriptor["ca_pm_alias_arn"]) is None
    ):
        raise HandshakeError("handshake descriptor scalar binding is invalid")
    prefix = f"handshake/v1/{run_id}/{run_attempt}/{channel}"
    expected = {
        "agent_id": f"qurl-go-sandbox-{run_id}-{run_attempt}",
        "correlation_id": f"nhp-{run_id}-{run_attempt}-qurl_go-{phase}-{channel}",
        "checkpoint_key": f"{prefix}/checkpoint.json",
        "receipt_key": f"{prefix}/receipt.json",
    }
    if any(descriptor[key] != item for key, item in expected.items()):
        raise HandshakeError("handshake descriptor run binding is invalid")
    for key in ("arm_request_id", "move_request_id", "expire_request_id"):
        if not isinstance(descriptor[key], str) or HEX64_RE.fullmatch(descriptor[key]) is None:
            raise HandshakeError(f"{key} is invalid")
    if len({descriptor[key] for key in ("arm_request_id", "move_request_id", "expire_request_id")}) != 3:
        raise HandshakeError("mutation request IDs must be distinct")
    return descriptor


def validate_mutation_response(
    value: Any,
    mutation: str,
    descriptor: dict[str, Any],
    checkpoint: dict[str, Any] | None = None,
    move: dict[str, Any] | None = None,
) -> dict[str, Any]:
    envelope = _exact(value, {"result", "version"}, f"{mutation} response")
    if envelope["version"] != 1 or not isinstance(envelope["result"], dict):
        raise HandshakeError(f"{mutation} response envelope is invalid")
    result = envelope["result"]
    common = {"agent_id", "mutated_at", "mutation"}
    if mutation == "arm":
        _exact(
            result,
            common
            | {
                "grant_correlation_id",
                "lease_seconds",
                "pinned_cell_id",
                "target_cell_id",
            },
            "arm result",
        )
        valid = (
            result["pinned_cell_id"] == descriptor["pinned_cell_id"]
            and result["target_cell_id"] == descriptor["target_cell_id"]
            and result["lease_seconds"] == descriptor["arm_lease_seconds"]
            and result["grant_correlation_id"] == descriptor["correlation_id"]
        )
    elif mutation == "move":
        _exact(
            result,
            common
            | {
                "lease_expires_at",
                "new_assignment_generation",
                "new_cell_id",
                "previous_assignment_generation",
                "previous_cell_id",
            },
            "move result",
        )
        if checkpoint is None:
            raise HandshakeError("move response requires checkpoint binding")
        valid = (
            result["previous_cell_id"] == descriptor["pinned_cell_id"]
            and result["new_cell_id"] == descriptor["target_cell_id"]
            and result["previous_assignment_generation"]
            == checkpoint["assignment_generation"]
            and result["new_assignment_generation"]
            == checkpoint["assignment_generation"] + 1
        )
    elif mutation == "expire_lease":
        _exact(result, common | {"lease_expires_at"}, "expire_lease result")
        valid = move is not None
    else:
        raise HandshakeError("unknown mutation response")
    if (
        result["mutation"] != mutation
        or result["agent_id"] != descriptor["agent_id"]
        or not isinstance(result["mutated_at"], str)
        or not valid
    ):
        raise HandshakeError(f"{mutation} response binding is invalid")
    mutated_at = _timestamp(result["mutated_at"], f"{mutation} mutated_at")
    if "lease_expires_at" in result:
        lease_expires_at = _timestamp(
            result["lease_expires_at"], f"{mutation} lease_expires_at"
        )
        expected_lifetime = (
            descriptor["arm_lease_seconds"]
            if mutation == "move"
            else descriptor["expire_lease_seconds"]
        )
        if lease_expires_at.timestamp() - mutated_at.timestamp() != expected_lifetime:
            raise HandshakeError(f"{mutation} lease transition is not exact")
        if mutation == "expire_lease":
            move_result = move["result"]
            move_mutated_at = _timestamp(
                move_result["mutated_at"], "move mutated_at"
            )
            move_expiry = _timestamp(
                move_result["lease_expires_at"], "move lease_expires_at"
            )
            if mutated_at < move_mutated_at or lease_expires_at >= move_expiry:
                raise HandshakeError(
                    "expire_lease does not shorten the exact moved assignment lease"
                )
    return envelope


def validate_checkpoint(
    value: Any,
    descriptor: dict[str, Any],
    *,
    client_run_id: str,
    client_sha: str,
) -> dict[str, Any]:
    checkpoint = _exact(
        value,
        {
            "agent_id",
            "assignment_generation",
            "channel_id",
            "client_run_id",
            "client_sha",
            "controller_run_attempt",
            "controller_run_id",
            "correlation_id",
            "lease_expires_at",
            "observed_cell_id",
            "version",
            "warm_open_confirmed",
        },
        "client checkpoint",
    )
    valid = (
        checkpoint["version"] == 1
        and checkpoint["client_run_id"] == client_run_id
        and checkpoint["client_sha"] == client_sha
        and RUN_RE.fullmatch(client_run_id) is not None
        and SHA_RE.fullmatch(client_sha) is not None
        and checkpoint["controller_run_id"] == descriptor["controller_run_id"]
        and checkpoint["controller_run_attempt"] == descriptor["controller_run_attempt"]
        and checkpoint["channel_id"] == descriptor["channel_id"]
        and checkpoint["correlation_id"] == descriptor["correlation_id"]
        and checkpoint["agent_id"] == descriptor["agent_id"]
        and checkpoint["observed_cell_id"] == descriptor["pinned_cell_id"]
        and type(checkpoint["assignment_generation"]) is int
        and checkpoint["assignment_generation"] >= 1
        and checkpoint["warm_open_confirmed"] is True
        and isinstance(checkpoint["lease_expires_at"], str)
    )
    if not valid:
        raise HandshakeError("client checkpoint does not bind this controller run")
    _timestamp(checkpoint["lease_expires_at"], "client checkpoint lease_expires_at")
    return checkpoint


def _run(command: list[str], name: str, *, timeout: int = 60) -> bytes:
    try:
        result = subprocess.run(
            command,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise HandshakeError(f"{name} failed to execute") from exc
    if result.returncode != 0:
        stderr = result.stderr.decode("utf-8", "replace")[:4096]
        raise HandshakeError(f"{name} failed: {stderr}")
    return result.stdout


def _invoke(alias: str, request: dict[str, Any]) -> dict[str, Any]:
    with tempfile.TemporaryDirectory() as directory:
        request_path = Path(directory, "request.json")
        response_path = Path(directory, "response.json")
        request_path.write_bytes(_canonical(request))
        metadata = _loads(
            _run(
                [
                    "aws",
                    "lambda",
                    "invoke",
                    "--region",
                    REGION,
                    "--function-name",
                    alias,
                    "--invocation-type",
                    "RequestResponse",
                    "--cli-binary-format",
                    "raw-in-base64-out",
                    "--payload",
                    f"fileb://{request_path}",
                    str(response_path),
                ],
                f"invoke {request['mutation']}",
            ),
            "Lambda invoke metadata",
        )
        if (
            not isinstance(metadata, dict)
            or metadata.get("StatusCode") != 200
            or "FunctionError" in metadata
        ):
            raise HandshakeError("Lambda invocation did not complete successfully")
        raw = response_path.read_bytes()
        if not raw or len(raw) > 64 * 1024:
            raise HandshakeError("Lambda response length is invalid")
        response = _loads(raw, "Lambda response")
        if isinstance(response, dict) and "error" in response:
            raise HandshakeError(f"mutation returned error: {response['error']}")
        return response


def _resolve_handshake_key_arn() -> str:
    response = _loads(
        _run(
            [
                "aws",
                "kms",
                "describe-key",
                "--region",
                REGION,
                "--key-id",
                KMS_ALIAS_ARN,
                "--output",
                "json",
            ],
            "resolve assignment proof KMS key",
        ),
        "KMS DescribeKey response",
    )
    if (
        not isinstance(response, dict)
        or set(response) != {"KeyMetadata"}
        or not isinstance(response["KeyMetadata"], dict)
        or not {"Arn", "Enabled", "KeyState"}.issubset(response["KeyMetadata"])
    ):
        raise HandshakeError("KMS DescribeKey response shape is invalid")
    metadata = response["KeyMetadata"]
    arn = metadata["Arn"]
    if (
        not isinstance(arn, str)
        or KMS_KEY_ARN_RE.fullmatch(arn) is None
        or metadata["Enabled"] is not True
        or metadata["KeyState"] != "Enabled"
    ):
        raise HandshakeError("assignment proof KMS key is not enabled or exact")
    return arn


def _put_object(descriptor: dict[str, Any], key: str, payload: bytes) -> None:
    with tempfile.NamedTemporaryFile() as stream:
        stream.write(payload)
        stream.flush()
        _run(
            [
                "aws",
                "s3api",
                "put-object",
                "--region",
                REGION,
                "--bucket",
                descriptor["bucket"],
                "--key",
                key,
                "--body",
                stream.name,
                "--content-type",
                "application/json",
                "--server-side-encryption",
                "aws:kms",
                "--ssekms-key-id",
                descriptor["kms_key_arn"],
                "--if-none-match",
                "*",
            ],
            "write assignment proof receipt",
        )


def _get_object(
    descriptor: dict[str, Any], key: str, *, timeout_seconds: int
) -> bytes:
    deadline = time.monotonic() + timeout_seconds
    with tempfile.TemporaryDirectory() as directory:
        destination = Path(directory, "checkpoint.json")
        while True:
            destination.unlink(missing_ok=True)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise HandshakeError("timed out waiting for client assignment checkpoint")
            try:
                result = subprocess.run(
                    [
                        "aws",
                        "s3api",
                        "get-object",
                        "--region",
                        REGION,
                        "--bucket",
                        descriptor["bucket"],
                        "--key",
                        key,
                        str(destination),
                    ],
                    check=False,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                    timeout=min(30, remaining),
                )
            except subprocess.TimeoutExpired:
                continue
            if result.returncode == 0:
                raw = destination.read_bytes()
                if not raw or len(raw) > 64 * 1024:
                    raise HandshakeError("assignment checkpoint length is invalid")
                return raw
            stderr = result.stderr.decode("utf-8", "replace")
            if "NoSuchKey" not in stderr and "404" not in stderr:
                raise HandshakeError(f"read assignment checkpoint failed: {stderr[:4096]}")
            if time.monotonic() >= deadline:
                raise HandshakeError("timed out waiting for client assignment checkpoint")
            time.sleep(5)


def _write_output(path: Path, values: dict[str, str]) -> None:
    with path.open("a", encoding="utf-8") as stream:
        for key, value in values.items():
            if "\n" in value or "\r" in value:
                raise HandshakeError(f"output {key} contains a newline")
            stream.write(f"{key}={value}\n")


def prepare(args: argparse.Namespace) -> None:
    if RUN_RE.fullmatch(args.controller_run_id) is None or RUN_RE.fullmatch(
        args.controller_run_attempt
    ) is None:
        raise HandshakeError("controller run binding is invalid")
    if args.proof_phase not in PHASES:
        raise HandshakeError("proof phase is invalid")
    provenance = _loads(
        _decode_b64(args.deployment_provenance_b64, "provenance"), "provenance"
    )
    channel = secrets.token_hex(16)
    prefix = (
        f"handshake/v1/{args.controller_run_id}/"
        f"{args.controller_run_attempt}/{channel}"
    )
    descriptor = validate_descriptor(
        {
            "version": 1,
            "controller_run_id": args.controller_run_id,
            "controller_run_attempt": args.controller_run_attempt,
            "client": "qurl_go",
            "proof_phase": args.proof_phase,
            "channel_id": channel,
            "correlation_id": (
                f"nhp-{args.controller_run_id}-{args.controller_run_attempt}-"
                f"qurl_go-{args.proof_phase}-{channel}"
            ),
            "agent_id": (
                f"qurl-go-sandbox-{args.controller_run_id}-"
                f"{args.controller_run_attempt}"
            ),
            "bucket": BUCKET,
            "kms_key_arn": _resolve_handshake_key_arn(),
            "checkpoint_key": f"{prefix}/checkpoint.json",
            "receipt_key": f"{prefix}/receipt.json",
            "ca_pm_alias_arn": select_ca_pm_alias(provenance),
            "pinned_cell_id": "cell0",
            "target_cell_id": "cell1",
            "arm_lease_seconds": ARM_LEASE_SECONDS,
            "expire_lease_seconds": EXPIRE_LEASE_SECONDS,
            "arm_request_id": secrets.token_hex(32),
            "move_request_id": secrets.token_hex(32),
            "expire_request_id": secrets.token_hex(32),
        }
    )
    arm = validate_mutation_response(
        _invoke(
            descriptor["ca_pm_alias_arn"],
            {
                "version": 1,
                "hub_request_id": descriptor["arm_request_id"],
                "mutation": "arm",
                "agent_id": descriptor["agent_id"],
                "grant_correlation_id": descriptor["correlation_id"],
                "pinned_cell_id": descriptor["pinned_cell_id"],
                "target_cell_id": descriptor["target_cell_id"],
                "lease_seconds": descriptor["arm_lease_seconds"],
            },
        ),
        "arm",
        descriptor,
    )
    payload = {"descriptor": descriptor, "arm": arm}
    encoded = base64.b64encode(_canonical(payload)).decode()
    _write_output(
        args.github_output,
        {
            "agent_id": descriptor["agent_id"],
            "correlation_id": descriptor["correlation_id"],
            "handshake_b64": encoded,
        },
    )


def complete(args: argparse.Namespace) -> None:
    payload = _exact(
        _loads(_decode_b64(args.handshake_b64, "handshake"), "handshake"),
        {"arm", "descriptor"},
        "handshake",
    )
    descriptor = validate_descriptor(payload["descriptor"])
    validate_mutation_response(payload["arm"], "arm", descriptor)
    if (
        RUN_RE.fullmatch(args.client_run_id) is None
        or SHA_RE.fullmatch(args.client_sha) is None
    ):
        raise HandshakeError("resolved client workflow run/SHA binding is invalid")
    checkpoint_raw = _get_object(
        descriptor, descriptor["checkpoint_key"], timeout_seconds=args.timeout_seconds
    )
    checkpoint = validate_checkpoint(
        _loads(checkpoint_raw, "client checkpoint"),
        descriptor,
        client_run_id=args.client_run_id,
        client_sha=args.client_sha,
    )
    move = validate_mutation_response(
        _invoke(
            descriptor["ca_pm_alias_arn"],
            {
                "version": 1,
                "hub_request_id": descriptor["move_request_id"],
                "mutation": "move",
                "agent_id": descriptor["agent_id"],
                "grant_correlation_id": descriptor["correlation_id"],
                "target_cell_id": descriptor["target_cell_id"],
            },
        ),
        "move",
        descriptor,
        checkpoint,
    )
    expire = validate_mutation_response(
        _invoke(
            descriptor["ca_pm_alias_arn"],
            {
                "version": 1,
                "hub_request_id": descriptor["expire_request_id"],
                "mutation": "expire_lease",
                "agent_id": descriptor["agent_id"],
                "grant_correlation_id": descriptor["correlation_id"],
                "lease_seconds": descriptor["expire_lease_seconds"],
            },
        ),
        "expire_lease",
        descriptor,
        move=move,
    )
    receipt = {
        "version": 1,
        "descriptor": descriptor,
        "arm": payload["arm"],
        "client_run_id": args.client_run_id,
        "client_sha": args.client_sha,
        "checkpoint_sha256": hashlib.sha256(checkpoint_raw).hexdigest(),
        "move": move,
        "expire_lease": expire,
    }
    _put_object(descriptor, descriptor["receipt_key"], _canonical(receipt))


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser()
    subparsers = root.add_subparsers(dest="command", required=True)
    start = subparsers.add_parser("prepare")
    start.add_argument("--controller-run-id", required=True)
    start.add_argument("--controller-run-attempt", required=True)
    start.add_argument("--proof-phase", required=True)
    start.add_argument("--deployment-provenance-b64", required=True)
    start.add_argument("--github-output", required=True, type=Path)
    start.set_defaults(func=prepare)
    finish = subparsers.add_parser("complete")
    finish.add_argument("--handshake-b64", required=True)
    finish.add_argument("--client-run-id", required=True)
    finish.add_argument("--client-sha", required=True)
    finish.add_argument("--timeout-seconds", type=int, default=3600, choices=range(30, 5401))
    finish.set_defaults(func=complete)
    return root


def main(argv: list[str] | None = None) -> int:
    try:
        args = parser().parse_args(argv)
        args.func(args)
        return 0
    except (HandshakeError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
