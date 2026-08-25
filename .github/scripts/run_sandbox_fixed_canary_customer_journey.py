#!/usr/bin/env python3
"""Run the non-fleet-mutating fixed-canary sandbox customer journey."""

from __future__ import annotations

import argparse
import base64
import errno
import hashlib
import importlib.util
import json
import os
import re
import socket
import stat
import subprocess
import sys
import time
import urllib.request
from pathlib import Path
from collections.abc import Callable
from typing import Any

ACCOUNT = "767397897469"
REGION = "us-east-2"
API_ENDPOINT = "https://api.layerv.xyz"
AUTH0_TOKEN_ENDPOINT = "https://auth.layerv.xyz/oauth/token"
AUTH0_ISSUER = "https://auth.layerv.xyz/"
CONTRACT_PARAMETER = "/sandbox/nhp/customer-journey/fixed-canary-v1"
SESSION_TABLE = "layerv-nhp-sandbox-cell0-nhp-session-control"
PHASE_ATTEMPT_TIMEOUT_SECONDS = 180
PHASE_BUNDLE_VALIDITY_MS = 30 * 60 * 1000
MAX_PHASE_BUNDLE_GENERATIONS = 3
MAX_DURABLE_PHASE_LEDGER_BYTES = 300 << 10
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
OWNER = re.compile(r"[A-Za-z0-9_-]{20,128}@clients\Z")

ROOT = Path(__file__).resolve().parents[2]


class JourneyError(RuntimeError):
    """One protected journey boundary failed closed."""


def _module(name: str, relative: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    if spec is None or spec.loader is None:
        raise JourneyError("customer journey source module is absent")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


PLAN = _module("build_sandbox_fixed_canary_plan", ".github/scripts/build_sandbox_fixed_canary_plan.py")
RUNNER = _module("sandbox_fixed_canary_lifecycle_runner", ".github/scripts/sandbox_fixed_canary_lifecycle_runner.py")


def canonical(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def ordered(value: Any) -> bytes:
    """Encode a Go-struct-shaped input without reordering its closed fields."""
    return (json.dumps(value, separators=(",", ":"), ensure_ascii=True) + "\n").encode()


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def phase_run_id(release_id: str, generation: int, phase: str, attempt: int, index: int) -> str:
    return digest(
        b"layerv/sandbox-fixed-canary-run-id/v1\x00"
        + release_id.encode()
        + b"\x00"
        + generation.to_bytes(1, "big")
        + phase.encode()
        + b"\x00"
        + attempt.to_bytes(1, "big")
        + index.to_bytes(1, "big")
    )[:16]


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise JourneyError("private customer JSON has duplicate fields")
        value[key] = item
    return value


def read_json(path: Path, *, canonical_required: bool = True) -> dict[str, Any]:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) not in {0o400, 0o600} or info.st_nlink != 1 or info.st_uid != os.geteuid():
        raise JourneyError("private customer file metadata is invalid")
    raw = path.read_bytes()
    if not raw.endswith(b"\n") or b"\r" in raw or b"\n" in raw[:-1]:
        raise JourneyError("private customer file framing is invalid")
    try:
        value = json.loads(raw[:-1], object_pairs_hook=_pairs)
    except json.JSONDecodeError as error:
        raise JourneyError("private customer JSON is invalid") from error
    if not isinstance(value, dict) or (canonical_required and raw != canonical(value)):
        raise JourneyError("private customer JSON is not canonical")
    return value


def decode_canonical(raw: bytes, label: str) -> dict[str, Any]:
    if not raw.endswith(b"\n") or b"\r" in raw or b"\n" in raw[:-1]:
        raise JourneyError(f"{label} framing is invalid")
    try:
        value = json.loads(raw[:-1], object_pairs_hook=_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise JourneyError(f"{label} JSON is invalid") from error
    if not isinstance(value, dict) or canonical(value) != raw:
        raise JourneyError(f"{label} is not canonical")
    return value


def decode_ordered(raw: bytes, label: str) -> dict[str, Any]:
    if not raw.endswith(b"\n") or b"\r" in raw or b"\n" in raw[:-1]:
        raise JourneyError(f"{label} framing is invalid")
    try:
        value = json.loads(raw[:-1], object_pairs_hook=_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise JourneyError(f"{label} JSON is invalid") from error
    if not isinstance(value, dict) or ordered(value) != raw:
        raise JourneyError(f"{label} field order is not exact")
    return value


def write_private(path: Path, raw: bytes, mode: int = 0o600) -> None:
    if path.exists() or path.is_symlink() or not path.parent.is_dir() or stat.S_IMODE(path.parent.stat().st_mode) != 0o700:
        raise JourneyError("private customer output path is unsafe")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), mode)
    try:
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise JourneyError("private customer output write was short")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def materialize_private(path: Path, raw: bytes, mode: int = 0o600) -> None:
    """Create exact private bytes, or accept only the byte-identical prior file."""
    if path.exists() and not path.is_symlink():
        info = path.lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or stat.S_IMODE(info.st_mode) != mode
            or info.st_nlink != 1
            or info.st_uid != os.geteuid()
            or path.read_bytes() != raw
        ):
            raise JourneyError("private customer replay bytes drifted")
        return
    write_private(path, raw, mode)


def read_private_line(path: Path) -> str:
    info = path.lstat()
    raw = path.read_bytes()
    if (
        not stat.S_ISREG(info.st_mode)
        or stat.S_IMODE(info.st_mode) not in {0o400, 0o600}
        or info.st_nlink != 1
        or info.st_uid != os.geteuid()
        or not raw.endswith(b"\n")
        or b"\n" in raw[:-1]
        or b"\r" in raw
    ):
        raise JourneyError("private customer text authority is invalid")
    try:
        value = raw[:-1].decode("ascii")
    except UnicodeDecodeError as error:
        raise JourneyError("private customer text authority is invalid") from error
    if not value:
        raise JourneyError("private customer text authority is empty")
    return value


def run_exact(argv: list[str], *, timeout: int, env: dict[str, str] | None = None) -> None:
    completed = subprocess.run(
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env or {"PATH": "/usr/local/bin:/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
        timeout=timeout,
        check=False,
    )
    if completed.returncode != 0 or completed.stdout or completed.stderr:
        raise JourneyError("protected customer child failed")


def _jwt_payload(token: str) -> dict[str, Any]:
    parts = token.split(".")
    if len(parts) != 3:
        raise JourneyError("Auth0 token shape is invalid")
    try:
        raw = base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4))
        payload = json.loads(raw)
    except (ValueError, json.JSONDecodeError) as error:
        raise JourneyError("Auth0 token payload is invalid") from error
    audience = payload.get("aud")
    if isinstance(audience, str):
        audience = [audience]
    now = int(time.time())
    if (
        not isinstance(payload, dict)
        or payload.get("iss") != AUTH0_ISSUER
        or not isinstance(audience, list)
        or API_ENDPOINT not in audience
        or OWNER.fullmatch(str(payload.get("sub"))) is None
        or type(payload.get("exp")) is not int
        or not now < payload["exp"] <= now + 86400
    ):
        raise JourneyError("Auth0 token authority is invalid")
    return payload


def mint_jwt(secrets_client: Any, secret_name: str) -> tuple[str, str]:
    response = secrets_client.get_secret_value(SecretId=secret_name)
    raw = response.get("SecretString")
    if not isinstance(raw, str):
        raise JourneyError("Auth0 smoke credential is absent")
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as error:
        raise JourneyError("Auth0 smoke credential is invalid") from error
    if not isinstance(value, dict) or not {"client_id", "client_secret"}.issubset(value) or set(value) - {"client_id", "client_secret", "audience", "domain", "AUTH0_CLIENT_ID", "AUTH0_CLIENT_SECRET"}:
        raise JourneyError("Auth0 smoke credential schema is not exact")
    client_id, client_secret = value.get("client_id"), value.get("client_secret")
    if not isinstance(client_id, str) or not client_id or not isinstance(client_secret, str) or not client_secret:
        raise JourneyError("Auth0 smoke credential is incomplete")
    body = json.dumps({"client_id": client_id, "client_secret": client_secret, "audience": API_ENDPOINT, "grant_type": "client_credentials"}, separators=(",", ":")).encode()
    request = urllib.request.Request(AUTH0_TOKEN_ENDPOINT, data=body, method="POST", headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=20) as response_body:  # noqa: S310 - exact reviewed Auth0 origin.
            result = json.loads(response_body.read(1 << 20))
    except Exception as error:  # noqa: BLE001 - external boundary is normalized.
        raise JourneyError("Auth0 smoke token request failed") from error
    token = result.get("access_token") if isinstance(result, dict) else None
    if not isinstance(token, str) or not token:
        raise JourneyError("Auth0 smoke token response is invalid")
    owner = _jwt_payload(token)["sub"]
    return token, owner


def load_contract(ssm: Any) -> dict[str, Any]:
    raw = ssm.get_parameter(Name=CONTRACT_PARAMETER, WithDecryption=False).get("Parameter", {}).get("Value")
    try:
        value = json.loads(raw)
    except (TypeError, json.JSONDecodeError) as error:
        raise JourneyError("fixed-canary custody contract is invalid") from error
    if not isinstance(value, dict) or set(value) != {"schema", "environment", "assignment_generation", "authority_role_arn", "state_table", "auth0_secret_name", "secret_map", "otp_mailbox"}:
        raise JourneyError("fixed-canary custody contract schema is not exact")
    expected_role = f"arn:aws:iam::{ACCOUNT}:role/layerv-nhp-sandbox-fixed-canary"
    if value["schema"] != 1 or value["environment"] != "sandbox" or value["authority_role_arn"] != expected_role:
        raise JourneyError("fixed-canary custody identity is invalid")
    if type(value["assignment_generation"]) is not int or value["assignment_generation"] <= 0:
        raise JourneyError("fixed-canary assignment generation is invalid")
    if not isinstance(value["secret_map"], dict) or set(value["secret_map"]) != {f"shared/{label}" for label in PLAN.LABELS}:
        raise JourneyError("fixed-canary secret map is not exact")
    mailbox = value["otp_mailbox"]
    if not isinstance(mailbox, dict) or set(mailbox) != {"queue_url", "bucket", "recipient"}:
        raise JourneyError("fixed-canary OTP mailbox is invalid")
    return value


def active_nhp_operation_source(runtime: dict[str, Any]) -> str:
    try:
        server = runtime["cohorts"][runtime["active_colors"]["server"]]["server"]["source_sha"]
        ac = runtime["cohorts"][runtime["active_colors"]["ac"]]["ac"]["source_sha"]
        relay = runtime["relay"]["source_sha"]
    except (KeyError, TypeError) as error:
        raise JourneyError("active NHP runtime source projection is incomplete") from error
    if (
        re.fullmatch(r"[0-9a-f]{40}", str(server)) is None
        or server != ac
        or server != relay
    ):
        raise JourneyError("active NHP server, AC, and relay sources differ")
    return server


class WriterConnection:
    def __init__(self, socket_path: Path) -> None:
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.socket.settimeout(5)
        self.socket.connect(str(socket_path))
        self.file = self.socket.makefile("rwb", buffering=0)
        self.token = ""

    def request(self, value: dict[str, Any]) -> dict[str, Any]:
        self.file.write(canonical(value))
        raw = self.file.readline(1 << 20)
        try:
            response = json.loads(raw)
        except json.JSONDecodeError as error:
            raise JourneyError("custody writer response is invalid") from error
        if not isinstance(response, dict) or response.get("schema") != 1 or response.get("status") not in {"ok", "not_found"}:
            raise JourneyError("custody writer request was rejected")
        return response

    def acquire(self, writer: dict[str, Any]) -> None:
        response = self.request({"schema": 1, "operation": "writer_acquire", "writer": writer})
        token = response.get("writer_token")
        if not isinstance(token, str) or HEX64.fullmatch(token) is None:
            raise JourneyError("custody writer token is invalid")
        self.token = token

    def load_blob_record(self, key: str) -> dict[str, Any] | None:
        response = self.request({"schema": 1, "operation": "blob_load", "key": key})
        if response.get("status") == "not_found":
            return None
        blob = response.get("blob")
        if not isinstance(blob, dict) or blob.get("key") != key:
            raise JourneyError("custody blob load is invalid")
        try:
            raw = base64.b64decode(blob["body_b64"], validate=True)
        except (KeyError, TypeError, ValueError) as error:
            raise JourneyError("custody blob body is invalid") from error
        if blob.get("sha256") != digest(raw):
            raise JourneyError("custody blob digest is invalid")
        if HEX64.fullmatch(str(blob.get("version_id"))) is None:
            raise JourneyError("custody blob version is invalid")
        return {**blob, "body": raw}

    def load_blob(self, key: str) -> bytes | None:
        record = self.load_blob_record(key)
        return None if record is None else record["body"]

    def commit_blob(self, key: str, expected_version: str, raw: bytes) -> dict[str, Any]:
        if key.endswith("/phase-inputs") and len(raw) > MAX_DURABLE_PHASE_LEDGER_BYTES:
            raise JourneyError("durable phase ledger exceeds its DynamoDB size budget")
        operation_id = digest(
            b"layerv/sandbox-fixed-canary-blob/v1\x00"
            + key.encode()
            + b"\x00"
            + expected_version.encode()
            + b"\x00"
            + raw
        )
        response = self.request(
            {
                "schema": 1,
                "operation": "blob_commit",
                "candidate": {
                    "key": key,
                    "expected_version": expected_version,
                    "operation_id": operation_id,
                    "sha256": digest(raw),
                    "body_b64": base64.b64encode(raw).decode(),
                },
            }
        )
        blob = response.get("blob")
        if (
            not isinstance(blob, dict)
            or blob.get("key") != key
            or blob.get("version_id") != operation_id
            or blob.get("previous_version") != expected_version
            or blob.get("sha256") != digest(raw)
        ):
            raise JourneyError("custody blob commit is invalid")
        return blob

    def commit_initial_blob(self, key: str, raw: bytes) -> None:
        self.commit_blob(key, "", raw)

    def release(self) -> None:
        if self.token:
            self.request({"schema": 1, "operation": "writer_release", "writer_token": self.token})
            self.token = ""

    def close(self) -> None:
        self.file.close()
        self.socket.close()


def wait_socket(path: Path, process: subprocess.Popen[bytes]) -> None:
    for _ in range(100):
        if process.poll() is not None:
            raise JourneyError("custody server stopped before readiness")
        if path.exists() and stat.S_IMODE(path.stat().st_mode) == 0o600:
            return
        time.sleep(0.05)
    raise JourneyError("custody server readiness timed out")


def existing_authority_socket_is_live(path: Path) -> bool:
    """Accept one exact listener or unlink one unchanged stale private socket."""
    try:
        before = path.lstat()
    except FileNotFoundError:
        return False
    if (
        not stat.S_ISSOCK(before.st_mode)
        or stat.S_IMODE(before.st_mode) != 0o600
        or before.st_uid != os.geteuid()
        or before.st_nlink != 1
    ):
        raise JourneyError("prior custody server socket is not exact")
    probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    probe.settimeout(1)
    try:
        probe.connect(str(path))
    except OSError as error:
        if error.errno not in {errno.ECONNREFUSED, errno.ENOENT}:
            raise JourneyError("prior custody server socket cannot be classified") from error
    else:
        return True
    finally:
        probe.close()
    try:
        after = path.lstat()
    except FileNotFoundError:
        return False
    if (
        (after.st_dev, after.st_ino, after.st_mode, after.st_uid, after.st_nlink)
        != (before.st_dev, before.st_ino, before.st_mode, before.st_uid, before.st_nlink)
    ):
        raise JourneyError("prior custody server socket changed during classification")
    path.unlink()
    return False


def stop_authority_process(process: subprocess.Popen[bytes], socket_path: Path) -> None:
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)
    if socket_path.exists() and existing_authority_socket_is_live(socket_path):
        raise JourneyError("owned custody server remained live after termination")


def deployment(runtime: dict[str, Any], *, transport: str) -> dict[str, Any]:
    issuers = [{"kid": runtime["issuer"]["kid"], "spki_der_b64": runtime["issuer"]["spki_der_b64"]}]
    hub = runtime["hub_endpoint"]
    if transport == "direct":
        cell = {"cell_id": runtime["cell_id"], **runtime["cell_endpoint"]}
        return {"issuers": issuers, "cells": [cell], "relay_allowlist": [], "hub": hub}
    return {"issuers": issuers, "cells": [], "relay_allowlist": [runtime["relay"]["hostname"]], "hub": hub}


def operation_receipt(ddb: Any, report: dict[str, Any]) -> dict[str, Any]:
    receipt = report["recovery"]["receipt"]
    operation_id, binding = receipt["operation_id"], receipt["binding_sha256"]
    result = ddb.get_item(TableName=SESSION_TABLE, Key={"pk": {"S": "OP#" + operation_id}, "sk": {"S": "AUTHORITY"}}, ConsistentRead=True)
    item = result.get("Item")
    if not isinstance(item, dict):
        raise JourneyError("recovery-first terminal OP is absent")
    exact = {
        "pk", "sk", "kind", "schema_version", "operation_id", "binding_sha256", "state",
        "owner_id", "agent_id", "agent_public_key", "resource_id", "auth_service_id",
        "run_id", "run_attempt", "prepared_at_ms", "expires_at_ms", "aws_account_id",
        "aws_region", "cell_id", "session_control_table", "agent_keys_table",
        "agent_key_schema_version", "enrollment_credential_kind", "connector_id_claim",
        "terminal_at_ms", "ttl",
    }
    if set(item) != exact:
        raise JourneyError("recovery-first terminal OP shape is invalid")
    try:
        ttl = int(item["ttl"]["N"])
        prepared_at_ms = int(item["prepared_at_ms"]["N"])
        expires_at_ms = int(item["expires_at_ms"]["N"])
        terminal_at_ms = int(item["terminal_at_ms"]["N"])
    except (KeyError, TypeError, ValueError) as error:
        raise JourneyError("recovery-first terminal TTL is invalid") from error
    retained_until_ms = max(
        prepared_at_ms + 24 * 60 * 60 * 1000,
        expires_at_ms + 125 * 1000,
        terminal_at_ms + 125 * 1000,
    )
    expected_ttl = (retained_until_ms + 999) // 1000
    if (
        item["pk"] != {"S": "OP#" + operation_id}
        or item["sk"] != {"S": "AUTHORITY"}
        or item["operation_id"] != {"S": operation_id}
        or item["binding_sha256"] != {"S": binding}
        or item["state"] != {"S": "CANCELED"}
        or item["kind"] != {"S": "native_session_operation"}
        or item["schema_version"] != {"N": "1"}
        or item["aws_account_id"] != {"S": ACCOUNT}
        or item["aws_region"] != {"S": REGION}
        or item["cell_id"] != {"S": "cell0"}
        or item["session_control_table"] != {"S": SESSION_TABLE}
        or item["agent_keys_table"] != {"S": PLAN.AGENT_KEYS_TABLE}
        or item["agent_key_schema_version"] != {"N": "2"}
        or item["enrollment_credential_kind"] != {"S": "account"}
        or item["connector_id_claim"] != {"S": ""}
        or ttl != expected_ttl
        or ttl <= int(time.time())
    ):
        raise JourneyError("recovery-first terminal OP authority drifted")
    # The absent-recovery transaction can write only identity ConditionChecks
    # and this CANCELED OP. Strongly query the exact recovery agent partition
    # before any positive lifecycle can create a membership for this identity.
    agent_key = item["agent_public_key"].get("S")
    if not isinstance(agent_key, str) or not agent_key:
        raise JourneyError("recovery-first agent authority is invalid")
    agent_partition = "AGENT#" + hashlib.sha256(agent_key.encode()).hexdigest()
    observed: list[dict[str, Any]] = []
    query: dict[str, Any] = {
        "TableName": SESSION_TABLE,
        "ConsistentRead": True,
        "KeyConditionExpression": "pk = :pk",
        "ExpressionAttributeValues": {":pk": {"S": agent_partition}},
    }
    while True:
        page = ddb.query(**query)
        observed.extend(page.get("Items", []))
        last = page.get("LastEvaluatedKey")
        if not last:
            break
        query["ExclusiveStartKey"] = last
    after = ddb.get_item(
        TableName=SESSION_TABLE,
        Key={"pk": {"S": "OP#" + operation_id}, "sk": {"S": "AUTHORITY"}},
        ConsistentRead=True,
    ).get("Item")
    if observed or after != item:
        raise JourneyError("recovery-first session or membership authority is present")
    return {"operation_id": operation_id, "binding_sha256": binding, "state": "CANCELED", "terminal_ttl": ttl, "terminal_op_retained": True, "session_absent": True, "membership_absent": True}


def report_entry(path: Path) -> dict[str, Any]:
    value = read_json(path, canonical_required=False)
    return {"sha256": digest(canonical(value)), "report": value}


def phase_bundle(
    *,
    generation: int,
    prepared_at_ms: int,
    release_id: str,
    runtime: dict[str, Any],
    plan: dict[str, Any],
    authority: dict[str, Any],
    deployment_paths: dict[str, Path],
    lifecycle_binary: dict[str, Any],
    qurl_binary: dict[str, Any],
    qurl_source: str,
    api_key_file: Path,
) -> dict[str, Any]:
    if type(generation) is not int or not 1 <= generation <= MAX_PHASE_BUNDLE_GENERATIONS:
        raise JourneyError("durable phase generation is invalid")
    phase_inputs: dict[str, Any] = {}
    for phase in ("recovery", "direct", "relay"):
        transport = "direct" if phase == "recovery" else phase
        attempts: list[dict[str, str]] = []
        if phase == "recovery":
            operation_attempts = (generation,)
        else:
            first_attempt = (generation - 1) * 3 + 1
            operation_attempts = range(first_attempt, first_attempt + 3)
        for attempt in operation_attempts:
            run_count = 1 if phase == "recovery" else 3
            value = PLAN.build_lifecycle_input(
                runtime,
                plan,
                operation="recover-prepared" if phase == "recovery" else "lifecycle",
                transport=transport,
                authority=authority,
                attempt=attempt,
                run_ids=[phase_run_id(release_id, generation, phase, attempt, index) for index in range(run_count)],
                prepared_at_ms=prepared_at_ms,
                expires_at_ms=prepared_at_ms + PHASE_BUNDLE_VALIDITY_MS,
                api_key_file=str(api_key_file),
                deployment_file=str(deployment_paths[transport]),
                deployment_sha256=digest(deployment_paths[transport].read_bytes()),
                lifecycle_command_sha256=lifecycle_binary["sha256"],
                qurl_binary=qurl_binary["path"],
                qurl_binary_sha256=qurl_binary["sha256"],
                qurl_source_sha=qurl_source,
                release_id=release_id,
            )
            input_raw = ordered(value)
            attempts.append({"body_b64": base64.b64encode(input_raw).decode(), "sha256": digest(input_raw)})
        phase_inputs[phase] = {"attempts": attempts}
    return {
        "schema": 1,
        "environment": "sandbox",
        "release_id": release_id,
        "generation": generation,
        "generation_id": plan["generation_id"],
        "authority": authority,
        "prepared_at_ms": prepared_at_ms,
        "expires_at_ms": prepared_at_ms + PHASE_BUNDLE_VALIDITY_MS,
        "phases": phase_inputs,
    }


def validate_phase_bundle(value: Any, *, release_id: str, plan: dict[str, Any], authority: dict[str, Any]) -> int:
    if (
        not isinstance(value, dict)
        or set(value) != {
            "schema", "environment", "release_id", "generation", "generation_id", "authority",
            "prepared_at_ms", "expires_at_ms", "phases",
        }
        or value["schema"] != 1
        or value["environment"] != "sandbox"
        or value["release_id"] != release_id
        or type(value["generation"]) is not int
        or not 1 <= value["generation"] <= MAX_PHASE_BUNDLE_GENERATIONS
        or value["generation_id"] != plan["generation_id"]
        or value["authority"] != authority
        or type(value["prepared_at_ms"]) is not int
        or type(value["expires_at_ms"]) is not int
        or value["expires_at_ms"] - value["prepared_at_ms"] != PHASE_BUNDLE_VALIDITY_MS
        or not isinstance(value["phases"], dict)
        or set(value["phases"]) != {"recovery", "direct", "relay"}
    ):
        raise JourneyError("durable phase input authority drifted")
    generation = value["generation"]
    for phase in ("recovery", "direct", "relay"):
        journal = value["phases"][phase]
        if not isinstance(journal, dict) or set(journal) != {"attempts"} or not isinstance(journal["attempts"], list):
            raise JourneyError("durable phase attempt journal is invalid")
        expected_attempts = [generation] if phase == "recovery" else list(range((generation - 1) * 3 + 1, generation * 3 + 1))
        if len(journal["attempts"]) != len(expected_attempts):
            raise JourneyError("durable phase attempt journal is incomplete")
        for record, attempt in zip(journal["attempts"], expected_attempts, strict=True):
            if not isinstance(record, dict) or set(record) != {"body_b64", "sha256"} or HEX64.fullmatch(str(record["sha256"])) is None:
                raise JourneyError("durable phase input record is invalid")
            try:
                raw = base64.b64decode(record["body_b64"], validate=True)
            except (TypeError, ValueError) as error:
                raise JourneyError("durable phase input body is invalid") from error
            if digest(raw) != record["sha256"]:
                raise JourneyError("durable phase input digest drifted")
            body = decode_ordered(raw, f"{phase} lifecycle input")
            expected_operation = "recover-prepared" if phase == "recovery" else "lifecycle"
            expected_transport = "direct" if phase == "recovery" else phase
            expected_phase = "fixed_shared_recovery_first" if phase == "recovery" else f"fixed_shared_{phase}"
            if (
                set(body) != RUNNER.LIFECYCLE_INPUT_KEYS
                or body.get("operation") != expected_operation
                or body.get("transport") != expected_transport
                or body.get("phase") != expected_phase
                or body.get("release_id") != release_id
                or body.get("attempt") != attempt
                or body.get("authority") != authority
                or body.get("prepared_at_ms") != value["prepared_at_ms"]
                or body.get("expires_at_ms") != value["expires_at_ms"]
                or not isinstance(body.get("run_ids"), list)
                or len(body["run_ids"]) != (1 if phase == "recovery" else 3)
                or len(set(body["run_ids"])) != len(body["run_ids"])
            ):
                raise JourneyError("durable phase input does not match its ledger")
    return generation


def phase_ledger(bundle: dict[str, Any]) -> dict[str, Any]:
    """Retain every immutable generation so a new runner can replay exact inputs."""
    return {
        "schema": 1,
        "environment": "sandbox",
        "release_id": bundle["release_id"],
        "generation_id": bundle["generation_id"],
        "authority": bundle["authority"],
        "generations": [bundle],
    }


def validate_phase_ledger(
    value: Any,
    *,
    release_id: str,
    plan: dict[str, Any],
    authority: dict[str, Any],
) -> list[dict[str, Any]]:
    if (
        not isinstance(value, dict)
        or set(value) != {"schema", "environment", "release_id", "generation_id", "authority", "generations"}
        or value["schema"] != 1
        or value["environment"] != "sandbox"
        or value["release_id"] != release_id
        or value["generation_id"] != plan["generation_id"]
        or value["authority"] != authority
        or not isinstance(value["generations"], list)
        or not 1 <= len(value["generations"]) <= MAX_PHASE_BUNDLE_GENERATIONS
    ):
        raise JourneyError("durable phase ledger authority drifted")
    generations: list[dict[str, Any]] = []
    for expected, bundle in enumerate(value["generations"], start=1):
        if validate_phase_bundle(bundle, release_id=release_id, plan=plan, authority=authority) != expected:
            raise JourneyError("durable phase ledger generation sequence drifted")
        generations.append(bundle)
    return generations


def run_phase_attempt_chain(
    phase: str,
    phase_journal: Any,
    private_root: Path,
    lifecycle_binary: dict[str, Any],
    socket_path: Path,
    source_authority_file: Path,
    generation: int = 1,
) -> Path | None:
    if (
        phase not in {"recovery", "direct", "relay"}
        or not isinstance(phase_journal, dict)
        or set(phase_journal) != {"attempts"}
        or not isinstance(phase_journal["attempts"], list)
    ):
        raise JourneyError("durable phase attempt journal is invalid")
    expected_attempts = 1 if phase == "recovery" else 3
    if len(phase_journal["attempts"]) != expected_attempts:
        raise JourneyError("customer lifecycle bounded attempt chain is incomplete")
    first_attempt = generation if phase == "recovery" else (generation - 1) * 3 + 1
    for offset, phase_record in enumerate(phase_journal["attempts"]):
        attempt = first_attempt + offset
        if not isinstance(phase_record, dict) or set(phase_record) != {"body_b64", "sha256"} or HEX64.fullmatch(str(phase_record["sha256"])) is None:
            raise JourneyError("durable phase input is invalid")
        try:
            input_raw = base64.b64decode(phase_record["body_b64"], validate=True)
        except (TypeError, ValueError) as error:
            raise JourneyError("durable phase input body is invalid") from error
        if digest(input_raw) != phase_record["sha256"]:
            raise JourneyError("durable phase input digest drifted")
        value = decode_ordered(input_raw, f"{phase} lifecycle input")
        if value.get("attempt") != attempt:
            raise JourneyError("durable phase attempt number drifted")
        input_path = private_root / f"{phase}-generation-{generation}-attempt-{attempt}-input.json"
        materialize_private(input_path, input_raw)
        report_path = private_root / f"{phase}-generation-{generation}-attempt-{attempt}-report.json"
        if report_path.exists():
            report_value = read_json(report_path, canonical_required=False)
            RUNNER.validate_report(report_value, value, input_raw)
        else:
            RUNNER.run(lifecycle_binary["path"], str(socket_path), str(input_path), str(source_authority_file), str(report_path))
            report_value = read_json(report_path, canonical_required=False)
        if phase == "recovery" or report_value["lifecycle"]["status"] == "completed":
            return report_path
        if report_value["lifecycle"]["status"] != "settled-retry-required":
            raise JourneyError("customer lifecycle exhausted its bounded attempts")
        if offset == expected_attempts - 1:
            return None
    raise JourneyError("customer lifecycle attempt chain is incomplete")


def run_phase_ledger(
    generations: list[dict[str, Any]],
    private_root: Path,
    lifecycle_binary: dict[str, Any],
    socket_path: Path,
    source_authority_file: Path,
    append_generation: Callable[[int], list[dict[str, Any]]],
) -> dict[str, Path]:
    """Run each phase from its oldest exact authority without repeating success."""
    reports: dict[str, Path] = {}
    for phase in ("recovery", "direct", "relay"):
        generation_index = 0
        while True:
            if generation_index == len(generations):
                if generation_index >= MAX_PHASE_BUNDLE_GENERATIONS:
                    raise JourneyError("customer lifecycle exhausted its durable phase generations")
                generations = append_generation(generation_index + 1)
            bundle = generations[generation_index]
            generation = bundle["generation"]
            report = run_phase_attempt_chain(
                phase,
                bundle["phases"][phase],
                private_root,
                lifecycle_binary,
                socket_path,
                source_authority_file,
                generation,
            )
            if report is not None:
                reports[phase] = report
                break
            generation_index += 1
    return reports


def settle_ordinary_key(
    *,
    helper: Path,
    helper_common: list[str],
    key_dir: Path,
    candidate: Path,
    revoke: Path,
    verification: Path,
    writer: WriterConnection,
) -> None:
    if not revoke.exists():
        run_exact(
            [
                str(helper), "--profile", "sandbox", "revoke", *helper_common,
                "--api-key-id-file", str(key_dir / "api-key-id"),
                "--api-key-prefix-file", str(key_dir / "api-key-prefix"),
                "--receipt-file", str(revoke),
            ],
            timeout=60,
        )
    if not verification.exists():
        run_exact(
            [
                str(helper), "--profile", "sandbox", "verify-revoked",
                "--qurl-endpoint", API_ENDPOINT,
                "--candidate-file", str(candidate),
                "--candidate-sha256", digest(candidate.read_bytes()),
                "--api-key-id-file", str(key_dir / "api-key-id"),
                "--api-key-prefix-file", str(key_dir / "api-key-prefix"),
                "--api-key-file", str(key_dir / "api-key"),
                "--revoke-receipt-file", str(revoke),
                "--verification-file", str(verification),
            ],
            timeout=90,
        )
    writer.release()


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--operation", choices=("run", "reconcile"), default="run")
    parser.add_argument("--runtime-file", type=Path)
    parser.add_argument("--source-authority-file", type=Path)
    parser.add_argument("--key-helper-file", type=Path)
    parser.add_argument("--qurl-service-provenance-file", type=Path)
    parser.add_argument("--private-root", type=Path, required=True)
    parser.add_argument("--terminal-receipt", type=Path)
    parser.add_argument("--caller-event", choices=("pull_request", "push"))
    return parser.parse_args(argv)


def journey(args: argparse.Namespace, session: Any) -> None:  # noqa: PLR0915 - exact external sequence is intentionally linear.
    private_root = args.private_root.resolve()
    if private_root != args.private_root or stat.S_IMODE(private_root.stat().st_mode) != 0o700:
        raise JourneyError("customer journey root is not exact private storage")
    runtime, _ = PLAN.load_runtime(args.runtime_file)
    source = read_json(args.source_authority_file)
    if args.caller_event not in {"pull_request", "push"}:
        raise JourneyError("customer caller event is not exact")
    helper = args.key_helper_file
    if (
        not helper.is_file()
        or digest(helper.read_bytes()) != source.get("sources", {}).get("qurl_infra_helper_sha256")
        or stat.S_IMODE(helper.stat().st_mode) != 0o500
    ):
        raise JourneyError("sandbox key helper is not the reviewed executable")
    provenance = read_json(args.qurl_service_provenance_file)
    if (
        set(provenance) != {
            "schema", "environment", "repository", "source_sha", "source_tag", "source_ref", "image_index_digest",
            "platform_image_digest", "attestation_manifest_digest", "statement_digest", "builder_id",
            "build_run_id", "build_run_attempt", "build_started_on", "build_finished_on",
        }
        or provenance["schema"] != 1
        or provenance["environment"] != "sandbox"
        or provenance["repository"] != "layervai/qurl-service"
        or provenance["source_tag"] != runtime["qurl_service"]["source_tag"]
        or re.fullmatch(r"[0-9a-f]{40}", str(provenance["source_sha"])) is None
        or not str(provenance["source_sha"]).startswith(provenance["source_tag"])
        or provenance["source_ref"] != "refs/heads/main"
        or provenance["image_index_digest"] != runtime["qurl_service"]["image_digest"]
        or provenance["platform_image_digest"] != runtime["qurl_service"]["platform_image_digest"]
        or type(provenance["build_run_id"]) is not int
        or type(provenance["build_run_attempt"]) is not int
        or provenance["build_run_id"] <= 0
        or provenance["build_run_attempt"] <= 0
        or any(HEX64.fullmatch(str(provenance[key]).removeprefix("sha256:")) is None for key in ("attestation_manifest_digest", "statement_digest"))
    ):
        raise JourneyError("qurl-service provenance receipt does not match deployed runtime")
    sts = session.client("sts").get_caller_identity()
    if sts.get("Account") != ACCOUNT or session.region_name != REGION or not re.fullmatch(rf"arn:aws:sts::{ACCOUNT}:assumed-role/layerv-nhp-sandbox-fixed-canary/.+", str(sts.get("Arn"))):
        raise JourneyError("customer journey AWS principal is not the fixed-canary role")
    contract = load_contract(session.client("ssm"))
    if runtime.get("assignment_generation") != contract["assignment_generation"]:
        raise JourneyError("runtime and custody assignment generation differ")
    operation_source = active_nhp_operation_source(runtime)
    jwt_path = private_root / "auth0.jwt"
    if jwt_path.exists():
        token = read_private_line(jwt_path)
        owner = _jwt_payload(token)["sub"]
    else:
        token, owner = mint_jwt(session.client("secretsmanager"), contract["auth0_secret_name"])
        write_private(jwt_path, (token + "\n").encode(), 0o600)
    plan = PLAN.build_plan(runtime, owner, operation_source, source["sources"]["qurl_go"])
    plan_path = private_root / "plan.json"
    materialize_private(plan_path, ordered(plan))
    plan_raw = plan_path.read_bytes()[:-1]
    plan_sha = digest(plan_raw)
    correlation = source["correlation_id"]
    release_id = digest(
        b"layerv/sandbox-qurl-customer-journey/v1\x00"
        + str(source["caller"]["run_id"]).encode()
        + b"\x00"
        + source["caller"]["head_sha"].encode()
    )
    invocation = digest(b"layerv/sandbox-fixed-canary-writer/v1\x00" + release_id.encode())
    token = ""
    secret_map_path = private_root / "secret-map.json"
    materialize_private(secret_map_path, canonical(contract["secret_map"]))
    socket_path = private_root / "authority.sock"
    server_log = private_root / f"authority-{os.getpid()}.log"
    log_handle = None
    authority_env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}
    for name in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_REGION", "AWS_DEFAULT_REGION"):
        if name in os.environ:
            authority_env[name] = os.environ[name]
    server: subprocess.Popen[bytes] | None = None
    if not existing_authority_socket_is_live(socket_path):
        log_handle = open(server_log, "xb", buffering=0)  # noqa: SIM115 - must remain open with child.
        os.chmod(server_log, 0o600)
        server = subprocess.Popen(
            [sys.executable, str(ROOT / ".github/scripts/sandbox_fixed_canary_authority.py"), "--socket-path", str(socket_path), "--table", contract["state_table"], "--secret-map-file", str(secret_map_path), "--owner-subject", owner, "--resume-writer-invocation-token", invocation, "--region", REGION, "--otp-mailbox-queue-url", contract["otp_mailbox"]["queue_url"], "--otp-mailbox-bucket", contract["otp_mailbox"]["bucket"], "--otp-mailbox-recipient", contract["otp_mailbox"]["recipient"]],
            stdin=subprocess.DEVNULL,
            stdout=log_handle,
            stderr=log_handle,
            env=authority_env,
        )
    writer: WriterConnection | None = None
    key_may_exist = False
    helper_common: list[str] = []
    key_dir = private_root / "ordinary-key"
    revoke = private_root / "key-revoke.json"
    verification = private_root / "key-post-cache.json"
    try:
        if server is not None:
            wait_socket(socket_path, server)
        writer = WriterConnection(socket_path)
        writer.acquire({"schema": 1, "owner_subject": owner, "operation": "provision", "generation_id": plan["generation_id"], "plan_sha256": plan_sha, "invocation_token": invocation})
        candidate = private_root / "key-candidate.json"
        candidate_key = f"runs/{release_id}/ordinary-key-candidate"
        candidate_raw = writer.load_blob(candidate_key)
        if candidate_raw is None:
            run_exact([str(helper), "--profile", "sandbox", "candidate", "--release-id", release_id, "--attempt", "1", "--owner-subject", owner, "--requested-at", str(int(time.time())), "--output-file", str(candidate)], timeout=10)
            candidate_raw = candidate.read_bytes()
            writer.commit_initial_blob(candidate_key, candidate_raw)
        else:
            materialize_private(candidate, candidate_raw)
        candidate_sha = digest(candidate_raw)
        if key_dir.exists():
            if not key_dir.is_dir() or stat.S_IMODE(key_dir.stat().st_mode) != 0o700:
                raise JourneyError("ordinary key directory is not exact")
        else:
            key_dir.mkdir(mode=0o700)
        compensation = private_root / "key-compensation.json"
        helper_common = ["--qurl-endpoint", API_ENDPOINT, "--candidate-file", str(candidate), "--candidate-sha256", candidate_sha, "--jwt-file", str(jwt_path)]
        key_may_exist = True
        key_outputs = (key_dir / "api-key", key_dir / "api-key-id", key_dir / "api-key-prefix")
        if not all(path.exists() for path in key_outputs):
            run_exact([str(helper), "--profile", "sandbox", "create", *helper_common, "--output-dir", str(key_dir), "--compensation-receipt-file", str(compensation)], timeout=30)
        for path in key_outputs:
            read_private_line(path)
        provision = private_root / "provision-report.json"
        if not provision.exists():
            run_exact([source["binaries"]["authority"]["path"], "provision", "--authority-socket", str(socket_path), "--invocation-token", invocation, "--input-file", str(plan_path), "--api-key-file", str(key_dir / "api-key"), "--report-file", str(provision)], timeout=600)
        provision_value = read_json(provision, canonical_required=False)
        authority_ref = provision_value["authority"]
        qurl_source = source["sources"]["qurl_integrations_head"]
        qurl_binary = source["binaries"]["qurl"]
        lifecycle_binary = source["binaries"]["lifecycle"]
        deployment_paths: dict[str, Path] = {}
        for transport in ("direct", "relay"):
            deployment_path = private_root / f"{transport}-deployment.json"
            materialize_private(deployment_path, ordered(deployment(runtime, transport=transport)))
            deployment_paths[transport] = deployment_path

        phase_key = f"runs/{release_id}/phase-inputs"
        phase_blob = writer.load_blob_record(phase_key)
        if phase_blob is None:
            phase_raw = canonical(
                phase_ledger(
                    phase_bundle(
                        generation=1,
                        prepared_at_ms=int(time.time() * 1000),
                        release_id=release_id,
                        runtime=runtime,
                        plan=plan,
                        authority=authority_ref,
                        deployment_paths=deployment_paths,
                        lifecycle_binary=lifecycle_binary,
                        qurl_binary=qurl_binary,
                        qurl_source=qurl_source,
                        api_key_file=key_dir / "api-key",
                    )
                )
            )
            phase_blob = writer.commit_blob(phase_key, "", phase_raw)
            phase_blob = {**phase_blob, "body": phase_raw}
        else:
            phase_raw = phase_blob["body"]
        if len(phase_raw) > MAX_DURABLE_PHASE_LEDGER_BYTES:
            raise JourneyError("durable phase ledger exceeds its DynamoDB size budget")
        ledger_value = decode_canonical(phase_raw, "durable phase input ledger")
        generations = validate_phase_ledger(
            ledger_value,
            release_id=release_id,
            plan=plan,
            authority=authority_ref,
        )

        def append_generation(generation: int) -> list[dict[str, Any]]:
            nonlocal phase_blob, phase_raw, ledger_value
            if generation != len(ledger_value["generations"]) + 1:
                raise JourneyError("durable phase successor generation is not contiguous")
            successor = phase_bundle(
                generation=generation,
                prepared_at_ms=int(time.time() * 1000),
                release_id=release_id,
                runtime=runtime,
                plan=plan,
                authority=authority_ref,
                deployment_paths=deployment_paths,
                lifecycle_binary=lifecycle_binary,
                qurl_binary=qurl_binary,
                qurl_source=qurl_source,
                api_key_file=key_dir / "api-key",
            )
            ledger_value = {**ledger_value, "generations": [*ledger_value["generations"], successor]}
            successor_raw = canonical(ledger_value)
            committed = writer.commit_blob(phase_key, phase_blob["version_id"], successor_raw)
            phase_blob = {**committed, "body": successor_raw}
            phase_raw = successor_raw
            return validate_phase_ledger(
                ledger_value,
                release_id=release_id,
                plan=plan,
                authority=authority_ref,
            )

        reports = run_phase_ledger(
            generations,
            private_root,
            lifecycle_binary,
            socket_path,
            args.source_authority_file,
            append_generation,
        )
        recovery_report = read_json(reports["recovery"], canonical_required=False)
        for phase in ("direct", "relay"):
            if read_json(reports[phase], canonical_required=False).get("lifecycle", {}).get("status") != "completed":
                raise JourneyError("customer lifecycle did not reach a completed outcome")
        recovery_authority = operation_receipt(session.client("dynamodb"), recovery_report)
        settle_ordinary_key(
            helper=helper,
            helper_common=helper_common,
            key_dir=key_dir,
            candidate=candidate,
            revoke=revoke,
            verification=verification,
            writer=writer,
        )
        key_may_exist = False
        rotation = private_root / "rotation-report.json"
        if not rotation.exists():
            run_exact([source["binaries"]["authority"]["path"], "rotate", "--authority-socket", str(socket_path), "--invocation-token", digest(b"layerv/sandbox-fixed-canary-rotate/v1\x00" + release_id.encode()), "--input-file", str(provision), "--report-file", str(rotation)], timeout=60)
        rotation_value = read_json(rotation, canonical_required=False)
        if rotation_value.get("generation_id") != plan["generation_id"]:
            raise JourneyError("fixed identity rotation changed the generation")
        terminal = {
            "schema": 1,
            "environment": "sandbox",
            "operation": "qurl-customer-journey",
            "correlation_id": correlation,
            "nhp_run": {"source_sha": source["sources"]["nhp"], "run_id": int(os.environ["GITHUB_RUN_ID"]), "run_attempt": int(os.environ["GITHUB_RUN_ATTEMPT"])},
            "caller": {**source["caller"], "event": args.caller_event, "binary_artifact": source["artifacts"]["binary"], "source_receipt_artifact": source["artifacts"]["source_receipt"]},
            "runtime": {"observation_sha256": runtime["runtime_sha256"], "deployed_nhp_source_sha": operation_source, "server_image_digest": runtime["cohorts"][runtime["active_colors"]["server"]]["server"]["image_digest"], "ac_image_digest": runtime["cohorts"][runtime["active_colors"]["ac"]]["ac"]["image_digest"], "relay_image_digest": runtime["relay"]["image_digest"], "qurl_service_source_sha": provenance["source_sha"], "qurl_service_image_digest": runtime["qurl_service"]["image_digest"]},
            "reports": {"direct": report_entry(reports["direct"]), "relay": report_entry(reports["relay"])},
            "recovery": {**report_entry(reports["recovery"]), "operation_authority": recovery_authority},
            "cleanup": {"generation_id": plan["generation_id"], "authority_version_id": authority_ref["version_id"], "authority_sha256": authority_ref["sha256"], "ordinary_key_revoke_receipt_sha256": digest(revoke.read_bytes()), "ordinary_key_post_cache_receipt_sha256": digest(verification.read_bytes()), "fixed_identity_generation_unchanged": True, "writer_lock_released": True},
            "status": "succeeded",
        }
        materialize_private(args.terminal_receipt, canonical(terminal))
    finally:
        if key_may_exist:
            try:
                if writer is None:
                    raise JourneyError("ordinary key cleanup has no writer authority")
                settle_ordinary_key(
                    helper=helper,
                    helper_common=helper_common,
                    key_dir=key_dir,
                    candidate=private_root / "key-candidate.json",
                    revoke=revoke,
                    verification=verification,
                    writer=writer,
                )
                key_may_exist = False
            except Exception:  # noqa: BLE001 - preserve durable lock for successor resume.
                pass
        elif writer is not None and writer.token:
            writer.release()
        if writer is not None:
            writer.close()
        if server is not None:
            stop_authority_process(server, socket_path)
        if log_handle is not None:
            log_handle.close()


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    if args.runtime_file is None or args.source_authority_file is None or args.key_helper_file is None or args.qurl_service_provenance_file is None or args.terminal_receipt is None or args.caller_event is None:
        raise JourneyError("customer journey inputs are incomplete")
    if args.operation == "reconcile" and args.terminal_receipt.exists():
        terminal = read_json(args.terminal_receipt)
        if terminal.get("status") != "succeeded":
            raise JourneyError("customer terminal receipt is not successful")
        return 0
    import boto3

    journey(args, boto3.session.Session(region_name=REGION))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except (OSError, JourneyError, PLAN.PlanError, RUNNER.RunnerError):
        print("sandbox fixed-canary customer journey failed", file=sys.stderr)
        raise SystemExit(1) from None
