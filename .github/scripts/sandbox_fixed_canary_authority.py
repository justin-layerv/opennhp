#!/usr/bin/env python3
"""Owner-only fixed-canary custody server for sandbox customer journeys.

The qurl worker has no AWS credentials.  This process is the only component
that can read or mutate the fixed DynamoDB journal and the four KMS-encrypted
Secrets Manager state containers.  It exposes a closed canonical-JSON protocol
over one mode-0600 Unix socket.

Agent-state bodies are stored only in the fixed secret selected by identity
label. Non-secret plans, resource receipts, operation rows,
and authority envelopes stay in DynamoDB.  Every write is an exact CAS and
every ambiguous AWS response is classified by a fresh strong pointer read plus
an exact secret VersionId/value digest readback.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import datetime as dt
import email
import email.policy
import email.utils
import hashlib
import json
import os
import re
import signal
import socketserver
import stat
import sys
import threading
import time
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

SCHEMA = 1
MAX_MESSAGE_BYTES = 16 << 20
HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEX40 = re.compile(r"^[0-9a-f]{40}$")
AWS_ACCOUNT = re.compile(r"^[0-9]{12}$")
AWS_REGION = re.compile(r"^[a-z]{2}-[a-z]+-[1-9][0-9]*$")
IDENTITY_NAME = re.compile(r"^[a-z][a-z0-9-]{2,63}$")
GENERATION = r"[0-9a-f]{64}"
LABEL = r"(?:direct-a|direct-b|relay-c|relay-d)"
SECRET_BLOB_KEY = re.compile(
    rf"^generations/(?P<generation>{GENERATION})/shared/"
    rf"(?P<label>{LABEL})/(?P<kind>agent-state|enrollment-otp)$"
)
PRIVATE_SOCKET_MODE = 0o600
PRIVATE_DIRECTORY_MODE = 0o700
OTP_SUBJECT = "qURL Connector verification code"
OTP_CODE = re.compile(r"Your qURL Connector verification code is:\s*([0-9]{8})\b")
MAX_MAIL_BYTES = 256 << 10
MAX_ASSIGNMENT_TICKET_LIFETIME = dt.timedelta(seconds=900)
LABELS = ("direct-a", "direct-b", "relay-c", "relay-d")


class AuthorityError(RuntimeError):
    """Closed protocol or durable-authority failure."""


class Conflict(AuthorityError):
    """Exact compare-and-swap conflict."""


class Ambiguous(AuthorityError):
    """Mutation could not be classified by exact readback."""


class NotFound(AuthorityError):
    """Exact strongly-read pointer is absent."""


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise AuthorityError(f"duplicate JSON key {key!r}")
        value[key] = item
    return value


def decode_canonical(raw: bytes) -> dict[str, Any]:
    if not raw or len(raw) > MAX_MESSAGE_BYTES or raw.endswith(b"\n"):
        raise AuthorityError("request byte envelope is invalid")
    try:
        text = raw.decode("utf-8", "strict")
        value = json.loads(text, object_pairs_hook=_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError, AuthorityError) as error:
        raise AuthorityError("request JSON is invalid") from error
    if not isinstance(value, dict) or encode_canonical(value) != raw:
        raise AuthorityError("request JSON is not canonical")
    return value


def encode_canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _text(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip() or any(ord(c) < 0x20 for c in value):
        raise AuthorityError(f"{name} is not exact text")
    return value


def _hex64(value: Any, name: str) -> str:
    value = _text(value, name)
    if HEX64.fullmatch(value) is None:
        raise AuthorityError(f"{name} is not lowercase 64-hex")
    return value


def _exact_keys(value: Any, expected: set[str], name: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise AuthorityError(f"{name} field set is not exact")
    return value


def _integer(value: Any, name: str, minimum: int, maximum: int | None = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum or (maximum is not None and value > maximum):
        raise AuthorityError(f"{name} is not an exact integer")
    return value


def _base64_raw32(value: Any, name: str) -> str:
    value = _text(value, name)
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as error:
        raise AuthorityError(f"{name} is not canonical base64") from error
    if len(raw) != 32 or base64.b64encode(raw).decode() != value:
        raise AuthorityError(f"{name} is not canonical base64 raw32")
    return value


def _dns(value: Any, name: str) -> str:
    value = _text(value, name)
    if "." not in value or any(character in value for character in "/:@"):
        raise AuthorityError(f"{name} is not canonical DNS")
    return value


def _endpoint(value: Any, name: str) -> dict[str, Any]:
    value = _exact_keys(value, {"host", "port", "server_public_key_b64"}, name)
    _dns(value["host"], f"{name} host")
    if _integer(value["port"], f"{name} port", 1, 65535) != 443:
        raise AuthorityError(f"{name} port is not 443")
    _base64_raw32(value["server_public_key_b64"], f"{name} key")
    return value


def _validate_plan(plan: Any) -> dict[str, Any]:
    plan = _exact_keys(
        plan,
        {
            "schema",
            "environment",
            "generation_id",
            "owner_subject",
            "aws_account_id",
            "aws_region",
            "nhp_source_sha",
            "qurl_go_source_sha",
            "cohorts",
            "identities",
        },
        "plan",
    )
    if plan["schema"] != 1 or plan["environment"] != "sandbox":
        raise AuthorityError("plan is not sandbox schema 1")
    _hex64(plan["generation_id"], "plan generation")
    _text(plan["owner_subject"], "plan owner")
    if not isinstance(plan["aws_account_id"], str) or AWS_ACCOUNT.fullmatch(plan["aws_account_id"]) is None:
        raise AuthorityError("plan AWS account is invalid")
    if not isinstance(plan["aws_region"], str) or AWS_REGION.fullmatch(plan["aws_region"]) is None:
        raise AuthorityError("plan AWS region is invalid")
    if not isinstance(plan["nhp_source_sha"], str) or HEX40.fullmatch(plan["nhp_source_sha"]) is None:
        raise AuthorityError("plan NHP source authority is invalid")
    if not isinstance(plan["qurl_go_source_sha"], str) or HEX40.fullmatch(plan["qurl_go_source_sha"]) is None:
        raise AuthorityError("plan qurl-go source authority is invalid")
    if not isinstance(plan["cohorts"], list) or len(plan["cohorts"]) != 1:
        raise AuthorityError("plan does not contain the exact shared cohort")
    if not isinstance(plan["identities"], list) or len(plan["identities"]) != 4:
        raise AuthorityError("plan does not contain the exact four identities")
    agents: set[str] = set()
    connectors: set[str] = set()
    cohort = _exact_keys(
            plan["cohorts"][0],
            {
                "server_asg",
                "ac_asg",
                "relay_asg",
                "session_control_table",
                "qurl_agent_keys_table",
                "cell_id",
                "assignment_generation",
                "hub_host",
                "hub_port",
                "hub_server_public_key_b64",
                "cell_endpoint",
            },
            "shared cohort",
        )
    for field in ("server_asg", "ac_asg", "relay_asg", "session_control_table", "qurl_agent_keys_table", "cell_id"):
        _text(cohort[field], f"shared cohort {field}")
    _integer(cohort["assignment_generation"], "shared assignment generation", 1)
    _dns(cohort["hub_host"], "shared hub host")
    if _integer(cohort["hub_port"], "shared hub port", 1, 65535) != 443:
        raise AuthorityError("cohort hub port is not 443")
    _base64_raw32(cohort["hub_server_public_key_b64"], "shared hub key")
    _endpoint(cohort["cell_endpoint"], "shared cell endpoint")
    selectors: dict[str, tuple[str, int]] = {}
    for label_index, label in enumerate(LABELS):
        identity = _exact_keys(
            plan["identities"][label_index],
            {"label", "owner_id", "agent_id", "connector_id", "frps_selector"},
            f"shared {label} identity",
        )
        if identity["label"] != label:
            raise AuthorityError("plan identity order or label is invalid")
        if _text(identity["owner_id"], f"shared {label} owner") != plan["owner_subject"]:
            raise AuthorityError("plan identity owner does not match the authenticated owner subject")
        for field, seen in (("agent_id", agents), ("connector_id", connectors)):
            value = identity[field]
            if not isinstance(value, str) or IDENTITY_NAME.fullmatch(value) is None or value in seen:
                raise AuthorityError(f"plan {field} is invalid or duplicated")
            seen.add(value)
        selector = _exact_keys(identity["frps_selector"], {"resource_id", "host", "port"}, f"shared {label} selector")
        expected_resource = {
            "direct-a": "qurl-tunnel-server-a",
            "direct-b": "qurl-tunnel-server-b",
            "relay-c": "qurl-tunnel-server-c",
            "relay-d": "qurl-tunnel-server-a",
        }[label]
        if _text(selector["resource_id"], "selector resource") != expected_resource:
            raise AuthorityError("selector resource does not match fixed identity")
        projection = (_dns(selector["host"], "selector host"), _integer(selector["port"], "selector port", 1, 65535))
        if expected_resource in selectors and selectors[expected_resource] != projection:
            raise AuthorityError("duplicate selector projection is inconsistent")
        selectors[expected_resource] = projection
    if set(selectors) != {"qurl-tunnel-server-a", "qurl-tunnel-server-b", "qurl-tunnel-server-c"}:
        raise AuthorityError("selector set is incomplete")
    hosts = {projection[0] for projection in selectors.values()}
    ports = {projection[1] for projection in selectors.values()}
    if len(hosts) != 1 or len(ports) != 3:
        raise AuthorityError("selector host and port set is not exact")
    return plan


def _ddb_s(value: str) -> dict[str, str]:
    return {"S": value}


def _ddb_n(value: int) -> dict[str, str]:
    return {"N": str(value)}


def _ddb_b(value: bytes) -> dict[str, bytes]:
    return {"B": value}


@dataclass(frozen=True)
class BlobCandidate:
    key: str
    expected_version: str
    operation_id: str
    sha256: str
    body: bytes


@dataclass(frozen=True)
class Blob:
    key: str
    version_id: str
    previous_version: str
    operation_id: str
    sha256: str
    body: bytes


class AWSDurableAuthority:
    """Exact DDB pointer and Secrets Manager body adapter."""

    def __init__(self, ddb: Any, secrets: Any, table: str, secret_map: dict[str, str]):
        self.ddb = ddb
        self.secrets = secrets
        self.table = _text(table, "table")
        required = {f"shared/{label}" for label in LABELS}
        if set(secret_map) != required or any(not isinstance(value, str) or not value for value in secret_map.values()):
            raise AuthorityError("secret map is not the exact four-identity union")
        if len(set(secret_map.values())) != 4:
            raise AuthorityError("secret containers are not distinct")
        self.secret_map = dict(secret_map)

    @staticmethod
    def row_key(key: str) -> str:
        _text(key, "blob key")
        return "BLOB#" + key

    def _secret_id(self, key: str) -> str | None:
        match = SECRET_BLOB_KEY.fullmatch(key)
        if match is None:
            if key.endswith("/agent-state") or key.endswith("/enrollment-otp"):
                raise AuthorityError("secret blob key escaped fixed shared identity")
            return None
        return self.secret_map[f"shared/{match.group('label')}"]

    def _read_item(self, key: str) -> dict[str, Any] | None:
        result = self.ddb.get_item(
            TableName=self.table,
            Key={"lock_id": _ddb_s(self.row_key(key))},
            ConsistentRead=True,
        )
        item = result.get("Item")
        if item is not None and not isinstance(item, dict):
            raise AuthorityError("DynamoDB pointer response is malformed")
        return item

    def load(self, key: str) -> Blob:
        item = self._read_item(key)
        if item is None:
            raise NotFound(key)
        required = {"lock_id", "schema", "kind", "blob_key", "version_id", "previous_version", "operation_id", "sha256", "storage"}
        storage = item.get("storage", {}).get("S")
        required |= {"body"} if storage == "dynamodb" else {"secret_id"}
        if set(item) != required or item.get("schema") != _ddb_n(SCHEMA) or item.get("kind") != _ddb_s("blob") or item.get("blob_key") != _ddb_s(key):
            raise AuthorityError("DynamoDB blob pointer is not exact")
        version_id = _hex64(item["version_id"].get("S"), "blob version")
        previous = item["previous_version"].get("S")
        if not isinstance(previous, str) or (previous and HEX64.fullmatch(previous) is None):
            raise AuthorityError("previous blob version is invalid")
        operation_id = _hex64(item["operation_id"].get("S"), "blob operation")
        sha256 = _hex64(item["sha256"].get("S"), "blob digest")
        if version_id != operation_id:
            raise AuthorityError("blob version is not its idempotent operation")
        secret_id = self._secret_id(key)
        if storage == "secretsmanager":
            if secret_id is None or item["secret_id"] != _ddb_s(secret_id):
                raise AuthorityError("secret pointer escaped its fixed container")
            result = self.secrets.get_secret_value(SecretId=secret_id, VersionId=version_id)
            if result.get("VersionId") != version_id or set(result) - {"ARN", "Name", "VersionId", "SecretBinary", "SecretString", "VersionStages", "CreatedDate", "ResponseMetadata"}:
                raise AuthorityError("secret version response is not exact")
            if "SecretString" not in result or "SecretBinary" in result:
                raise AuthorityError("secret version body encoding is invalid")
            body = result["SecretString"].encode()
        elif storage == "dynamodb":
            if secret_id is not None or not isinstance(item["body"].get("B"), (bytes, bytearray)):
                raise AuthorityError("DynamoDB blob body escaped storage policy")
            body = bytes(item["body"]["B"])
        else:
            raise AuthorityError("blob storage kind is invalid")
        if digest(body) != sha256:
            raise AuthorityError("blob body digest does not match pointer")
        return Blob(key, version_id, previous, operation_id, sha256, body)

    def commit(self, candidate: BlobCandidate) -> Blob:
        if not HEX64.fullmatch(candidate.operation_id) or not HEX64.fullmatch(candidate.sha256) or digest(candidate.body) != candidate.sha256:
            raise AuthorityError("blob candidate is invalid")
        if candidate.expected_version and HEX64.fullmatch(candidate.expected_version) is None:
            raise AuthorityError("blob expected version is invalid")
        secret_id = self._secret_id(candidate.key)
        if secret_id is not None:
            try:
                result = self.secrets.put_secret_value(
                    SecretId=secret_id,
                    ClientRequestToken=candidate.operation_id,
                    SecretString=candidate.body.decode("utf-8", "strict"),
                )
            except (UnicodeDecodeError, Exception) as error:  # noqa: BLE001 - exact readback below classifies AWS ambiguity
                try:
                    observed = self.secrets.get_secret_value(SecretId=secret_id, VersionId=candidate.operation_id)
                    if observed.get("VersionId") != candidate.operation_id or observed.get("SecretString", "").encode() != candidate.body:
                        raise Ambiguous("secret write could not be classified") from error
                except Ambiguous:
                    raise
                except Exception as read_error:  # noqa: BLE001
                    raise Ambiguous("secret write could not be classified") from read_error
            else:
                if result.get("VersionId") != candidate.operation_id:
                    raise Ambiguous("secret write returned the wrong VersionId")
        item = {
            "lock_id": _ddb_s(self.row_key(candidate.key)),
            "schema": _ddb_n(SCHEMA),
            "kind": _ddb_s("blob"),
            "blob_key": _ddb_s(candidate.key),
            "version_id": _ddb_s(candidate.operation_id),
            "previous_version": _ddb_s(candidate.expected_version),
            "operation_id": _ddb_s(candidate.operation_id),
            "sha256": _ddb_s(candidate.sha256),
            "storage": _ddb_s("secretsmanager" if secret_id is not None else "dynamodb"),
        }
        if secret_id is not None:
            item["secret_id"] = _ddb_s(secret_id)
        else:
            item["body"] = _ddb_b(candidate.body)
        names = {"#key": "lock_id"}
        values: dict[str, Any] = {}
        condition = "attribute_not_exists(#key)"
        if candidate.expected_version:
            names = {"#version": "version_id"}
            values = {":expected": _ddb_s(candidate.expected_version)}
            condition = "#version = :expected"
        try:
            request: dict[str, Any] = {
                "TableName": self.table,
                "Item": item,
                "ConditionExpression": condition,
                "ExpressionAttributeNames": names,
            }
            if values:
                request["ExpressionAttributeValues"] = values
            self.ddb.put_item(**request)
        except Exception as error:  # noqa: BLE001 - condition/lost response are classified by exact readback
            try:
                observed = self.load(candidate.key)
            except NotFound as read_error:
                raise Ambiguous("blob commit is absent after an uncertain write") from read_error
            except Exception as read_error:  # noqa: BLE001
                raise Ambiguous("blob commit could not be classified") from read_error
            if observed.version_id == candidate.operation_id and observed.previous_version == candidate.expected_version and observed.sha256 == candidate.sha256 and observed.body == candidate.body:
                return observed
            raise Conflict("blob commit lost the compare-and-swap") from error
        return self.load(candidate.key)


class CredentialWriter:
    """Fixed no-TTL writer mutex with explicit successor adoption authority."""

    def __init__(self, ddb: Any, table: str, owner_subject: str, resume_from: str = ""):
        self.ddb = ddb
        self.table = _text(table, "writer table")
        self.owner_subject = _text(owner_subject, "writer owner")
        self.resume_from = resume_from
        if resume_from and HEX64.fullmatch(resume_from) is None:
            raise AuthorityError("resume invocation is not lowercase 64-hex")
        self.row_key = "CREDENTIAL_WRITER#" + digest(owner_subject.encode())
        self._used_resume = False
        self._guard = threading.Lock()
        self._held_connection: int | None = None
        self._held_token = ""
        self._held_binding: dict[str, str] | None = None
        self._delegate_connection: int | None = None
        self._delegate_token = ""

    def _read(self) -> dict[str, Any] | None:
        result = self.ddb.get_item(TableName=self.table, Key={"lock_id": _ddb_s(self.row_key)}, ConsistentRead=True)
        return result.get("Item")

    @staticmethod
    def _binding(operation: dict[str, Any]) -> dict[str, Any]:
        _exact_keys(operation, {"schema", "owner_subject", "operation", "generation_id", "plan_sha256", "invocation_token"}, "writer")
        if operation["schema"] != 1 or operation["operation"] not in {"provision", "rotate", "normal-release"}:
            raise AuthorityError("writer operation is invalid")
        return {
            "owner_subject": _text(operation["owner_subject"], "writer owner"),
            "operation": operation["operation"],
            "generation_id": _hex64(operation["generation_id"], "writer generation"),
            "plan_sha256": _hex64(operation["plan_sha256"], "writer plan"),
            "invocation_token": _hex64(operation["invocation_token"], "writer invocation"),
        }

    def acquire(self, connection_id: int, operation: dict[str, Any]) -> str:
        binding = self._binding(operation)
        if binding["owner_subject"] != self.owner_subject:
            raise Conflict("writer owner drift")
        writer_token = digest(os.urandom(32))
        desired = {
            "lock_id": _ddb_s(self.row_key), "schema": _ddb_n(SCHEMA), "kind": _ddb_s("credential_writer"),
            **{name: _ddb_s(value) for name, value in binding.items()}, "writer_token": _ddb_s(writer_token),
        }
        with self._guard:
            if self._held_connection is not None or self._delegate_connection is not None:
                # Provisioning is one composite operation: the AWS-owning
                # orchestrator acquires the durable row before it creates the
                # ordinary key, then the credential-free qurl child enters the
                # exact same operation while the outer connection stays live.
                # Only one delegate can exist. Its token is process-local and
                # cannot delete or replace the durable outer row.
                if (
                    self._held_connection is None
                    or self._delegate_connection is not None
                    or self._held_binding != binding
                    or binding["operation"] != "provision"
                ):
                    raise Conflict("credential writer is already held by a live connection")
                current = self._read()
                if (
                    current is None
                    or current.get("writer_token") != _ddb_s(self._held_token)
                    or any(current.get(name) != _ddb_s(value) for name, value in binding.items())
                ):
                    raise Conflict("credential writer delegate lost outer authority")
                self._delegate_connection = connection_id
                self._delegate_token = writer_token
                return writer_token
            current = self._read()
            if current is None:
                condition = "attribute_not_exists(#key)"
                names = {"#key": "lock_id"}
                values: dict[str, Any] = {}
            else:
                current_binding = {name: current.get(name, {}).get("S") for name in binding}
                prior = current_binding.get("invocation_token")
                same_authority = all(current_binding[name] == binding[name] for name in binding if name != "invocation_token")
                if not same_authority or prior != self.resume_from or self._used_resume:
                    raise Conflict("credential writer is owned by another invocation")
                condition = "writer_token = :token AND invocation_token = :prior"
                names = {}
                values = {":token": current["writer_token"], ":prior": _ddb_s(prior)}
            try:
                request: dict[str, Any] = {
                    "TableName": self.table,
                    "Item": desired,
                    "ConditionExpression": condition,
                }
                if names:
                    request["ExpressionAttributeNames"] = names
                if values:
                    request["ExpressionAttributeValues"] = values
                self.ddb.put_item(**request)
            except Exception as error:  # noqa: BLE001
                observed = self._read()
                if observed != desired:
                    raise Conflict("credential writer acquire did not establish exact ownership") from error
            self._held_connection = connection_id
            self._held_token = writer_token
            self._held_binding = binding
            self._used_resume = current is not None
            return writer_token

    def release(self, connection_id: int, writer_token: str) -> None:
        writer_token = _hex64(writer_token, "writer token")
        with self._guard:
            if self._delegate_connection == connection_id:
                if writer_token != self._delegate_token:
                    raise Conflict("credential writer delegate token drift")
                current = self._read()
                if (
                    current is None
                    or self._held_binding is None
                    or current.get("writer_token") != _ddb_s(self._held_token)
                    or any(current.get(name) != _ddb_s(value) for name, value in self._held_binding.items())
                ):
                    raise Ambiguous("credential writer delegate release lost outer authority")
                self._delegate_connection = None
                self._delegate_token = ""
                return
            if self._held_connection != connection_id:
                raise Conflict("connection does not own credential writer")
            if writer_token != self._held_token:
                raise Conflict("credential writer token drift")
            if self._delegate_connection is not None:
                raise Conflict("credential writer delegate is still active")
            try:
                self.ddb.delete_item(
                    TableName=self.table,
                    Key={"lock_id": _ddb_s(self.row_key)},
                    ConditionExpression="writer_token = :token",
                    ExpressionAttributeValues={":token": _ddb_s(writer_token)},
                )
            except Exception as error:  # noqa: BLE001
                if self._read() is not None:
                    raise Ambiguous("credential writer release did not establish absence") from error
            self._held_connection = None
            self._held_token = ""
            self._held_binding = None

    def connection_lost(self, connection_id: int) -> None:
        with self._guard:
            if self._delegate_connection == connection_id:
                self._delegate_connection = None
                self._delegate_token = ""
                return
            if self._held_connection == connection_id:
                # The durable row intentionally remains. A successor requires
                # explicit resume_from authority; transport loss never unlocks.
                self._held_connection = None

    def current_binding(self, connection_id: int) -> dict[str, str]:
        with self._guard:
            if connection_id not in {self._held_connection, self._delegate_connection}:
                raise Conflict("connection does not own credential writer")
            item = self._read()
            if item is None:
                raise Conflict("credential writer row is absent")
            result = {
                name: item.get(name, {}).get("S")
                for name in ("owner_subject", "operation", "generation_id", "plan_sha256", "invocation_token")
            }
            if any(not isinstance(value, str) or not value for value in result.values()):
                raise AuthorityError("credential writer row is malformed")
            return result  # type: ignore[return-value]


class MailboxOTP:
    """Durable-before-return reader for the sandbox SES/S3/SQS mailbox."""

    def __init__(self, blobs: AWSDurableAuthority, writer: CredentialWriter, connection_id: int,
                 sqs: Any, s3: Any, queue_url: str, bucket: str, recipient: str,
                 wait_seconds: int = 240, now: Callable[[], dt.datetime] | None = None):
        self.blobs, self.writer, self.connection_id = blobs, writer, connection_id
        self.sqs, self.s3 = sqs, s3
        self.queue_url, self.bucket, self.recipient = (_text(queue_url, "OTP queue"), _text(bucket, "OTP bucket"), _text(recipient, "OTP recipient"))
        if wait_seconds <= 0 or wait_seconds > 300:
            raise AuthorityError("OTP mailbox wait is out of bounds")
        self.wait_seconds = wait_seconds
        self.now = now or (lambda: dt.datetime.now(dt.timezone.utc))

    def _plan_identity(self, identity: dict[str, Any], challenge: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any], str]:
        binding = self.writer.current_binding(self.connection_id)
        plan_blob = self.blobs.load(f"generations/{binding['generation_id']}/plan")
        if plan_blob.sha256 != binding["plan_sha256"]:
            raise Conflict("writer plan pointer does not match durable plan")
        plan = _validate_plan(decode_canonical(plan_blob.body))
        if plan["generation_id"] != binding["generation_id"] or plan["owner_subject"] != binding["owner_subject"]:
            raise Conflict("writer does not match sandbox plan")
        _exact_keys(identity, {"label", "owner_id", "agent_id", "connector_id", "frps_selector"}, "OTP identity")
        matches = [item for item in plan["identities"] if item == identity]
        if len(matches) != 1:
            raise Conflict("OTP identity is not an exact plan member")
        cohorts = plan["cohorts"]
        _exact_keys(challenge, {"agent_id", "credential_key_id", "cell_id", "assignment_ticket_expires_at", "pending_activation_recovery"}, "OTP challenge")
        if challenge["agent_id"] != identity["agent_id"] or challenge["cell_id"] != cohorts[0].get("cell_id") or not isinstance(challenge["pending_activation_recovery"], bool):
            raise Conflict("OTP challenge does not match identity and cohort")
        credential_key = _text(challenge["credential_key_id"], "OTP credential key")
        expires = _text(challenge["assignment_ticket_expires_at"], "OTP expiry")
        try:
            parsed = dt.datetime.fromisoformat(expires.replace("Z", "+00:00"))
        except ValueError as error:
            raise AuthorityError("OTP expiry is invalid") from error
        if parsed.tzinfo is None:
            raise AuthorityError("OTP expiry has no timezone")
        now = self.now()
        if now.tzinfo is None or not parsed > now or parsed - now > MAX_ASSIGNMENT_TICKET_LIFETIME:
            raise Conflict("OTP assignment ticket is expired or exceeds its lifetime")
        return plan, cohorts[0], credential_key

    @staticmethod
    def _extract(raw: bytes, recipient: str, agent_id: str) -> str | None:
        if len(raw) > MAX_MAIL_BYTES:
            raise AuthorityError("OTP message exceeds size bound")
        try:
            message = email.message_from_bytes(raw, policy=email.policy.default)
        except Exception as error:  # noqa: BLE001
            raise AuthorityError("OTP message is malformed") from error
        if str(message.get("Subject", "")) != OTP_SUBJECT:
            return None
        recipients = [address.casefold() for _, address in email.utils.getaddresses(message.get_all("To", []))]
        if recipients != [recipient.casefold()]:
            return None
        parts: list[str] = []
        for part in message.walk() if message.is_multipart() else [message]:
            if part.is_multipart():
                continue
            try:
                value = part.get_content()
            except Exception as error:  # noqa: BLE001
                raise AuthorityError("OTP MIME body is malformed") from error
            if isinstance(value, str):
                parts.append(value)
        body = "\n".join(parts)
        if len(body.encode()) > MAX_MAIL_BYTES:
            raise AuthorityError("decoded OTP body exceeds size bound")
        if f'Connector ID:  "{agent_id}"' not in body:
            return None
        matches = set(OTP_CODE.findall(body))
        if len(matches) != 1:
            raise AuthorityError("OTP message does not contain one distinct code")
        return next(iter(matches))

    def _delete(self, receipt: str) -> None:
        self.sqs.delete_message(QueueUrl=self.queue_url, ReceiptHandle=receipt)

    def _receive(self, agent_id: str) -> tuple[str, str]:
        started = self.now()
        deadline = time.monotonic() + self.wait_seconds
        while time.monotonic() < deadline:
            remaining = max(1, int(deadline - time.monotonic()))
            result = self.sqs.receive_message(QueueUrl=self.queue_url, MaxNumberOfMessages=1,
                                              WaitTimeSeconds=min(10, remaining), VisibilityTimeout=60)
            messages = result.get("Messages", [])
            if not messages:
                continue
            allowed_message_keys = {"MessageId", "ReceiptHandle", "MD5OfBody", "Body"}
            if len(messages) != 1 or not {"ReceiptHandle", "Body"}.issubset(messages[0]) or not set(messages[0]).issubset(allowed_message_keys):
                raise AuthorityError("OTP queue response is not exact")
            receipt = _text(messages[0]["ReceiptHandle"], "OTP receipt")
            try:
                notice = json.loads(messages[0]["Body"], object_pairs_hook=_pairs)
            except (json.JSONDecodeError, AuthorityError) as error:
                raise AuthorityError("OTP S3 notification is malformed") from error
            if notice.get("Event") == "s3:TestEvent":
                self._delete(receipt)
                continue
            records = notice.get("Records")
            if not isinstance(records, list) or len(records) != 1:
                raise AuthorityError("OTP notification record union is not exact")
            record = records[0]
            try:
                delivered = dt.datetime.fromisoformat(record["eventTime"].replace("Z", "+00:00"))
                bucket = record["s3"]["bucket"]["name"]
                key = urllib.parse.unquote_plus(record["s3"]["object"]["key"])
            except (KeyError, TypeError, ValueError) as error:
                raise AuthorityError("OTP notification fields are invalid") from error
            if delivered < started:
                self._delete(receipt)
                continue
            if bucket != self.bucket or not key.startswith("otp/"):
                raise AuthorityError("OTP object escaped mailbox authority")
            response = self.s3.get_object(Bucket=self.bucket, Key=key)
            stream = response.get("Body")
            raw = stream.read(MAX_MAIL_BYTES + 1) if stream is not None else b""
            if stream is not None and hasattr(stream, "close"):
                stream.close()
            if not isinstance(raw, bytes) or len(raw) > MAX_MAIL_BYTES:
                raise AuthorityError("OTP object body is invalid")
            code = self._extract(raw, self.recipient, agent_id)
            if code is not None:
                return code, receipt
            self.sqs.change_message_visibility(QueueUrl=self.queue_url, ReceiptHandle=receipt, VisibilityTimeout=10)
        raise AuthorityError("OTP mailbox wait expired")

    def __call__(self, identity: dict[str, Any], challenge: dict[str, Any]) -> str:
        plan, _cohort, credential_key = self._plan_identity(identity, challenge)
        key = f"generations/{plan['generation_id']}/shared/{identity['label']}/enrollment-otp"
        try:
            current = self.blobs.load(key)
        except NotFound:
            current = None
        if current is not None:
            record = decode_canonical(current.body)
            _exact_keys(record, {"schema", "generation_id", "label", "agent_id", "credential_key_id", "code"}, "OTP record")
            if record != {"schema": 1, "generation_id": plan["generation_id"], "label": identity["label"],
                          "agent_id": identity["agent_id"], "credential_key_id": credential_key, "code": record.get("code")} or re.fullmatch(r"[0-9]{8}", str(record.get("code"))) is None:
                raise Conflict("persisted OTP does not match challenge")
            return record["code"]
        if challenge["pending_activation_recovery"]:
            raise Conflict("activation recovery has no durable OTP")
        code, receipt = self._receive(identity["agent_id"])
        record = {"schema": 1, "generation_id": plan["generation_id"], "label": identity["label"],
                  "agent_id": identity["agent_id"], "credential_key_id": credential_key, "code": code}
        raw = encode_canonical(record)
        operation_id = digest(b"layerv/matched-cohort-enrollment-otp/v1\x00" + key.encode() + b"\x00" + credential_key.encode() + b"\x00" + code.encode())
        self.blobs.commit(BlobCandidate(key, "", operation_id, digest(raw), raw))
        self._delete(receipt)
        return code


def _blob_wire(blob: Blob) -> dict[str, Any]:
    return {
        "key": blob.key,
        "version_id": blob.version_id,
        "previous_version": blob.previous_version,
        "operation_id": blob.operation_id,
        "sha256": blob.sha256,
        "body_b64": base64.b64encode(blob.body).decode(),
    }


class Protocol:
    """Closed request dispatcher; each instance serves one socket connection."""

    def __init__(self, blobs: AWSDurableAuthority, writer: CredentialWriter, otp: Callable[[dict[str, Any], dict[str, Any]], str], connection_id: int):
        self.blobs = blobs
        self.writer = writer
        self.otp = otp
        self.connection_id = connection_id
        self.writer_token = ""

    @staticmethod
    def response(status: str, **values: Any) -> dict[str, Any]:
        response = {"schema": SCHEMA, "status": status}
        for name in ("error", "blob", "credential", "otp", "writer_token"):
            if name in values and values[name] not in (None, ""):
                response[name] = values[name]
        return response

    def dispatch(self, request: dict[str, Any]) -> dict[str, Any]:
        operation = request.get("operation")
        if request.get("schema") != SCHEMA or not isinstance(operation, str):
            raise AuthorityError("request schema or operation is invalid")
        if operation == "blob_load":
            _exact_keys(request, {"schema", "operation", "key"}, "blob_load")
            try:
                return self.response("ok", blob=_blob_wire(self.blobs.load(_text(request["key"], "blob key"))))
            except NotFound:
                return self.response("not_found")
        if operation == "blob_commit":
            _exact_keys(request, {"schema", "operation", "candidate"}, "blob_commit")
            candidate = _exact_keys(request["candidate"], {"key", "expected_version", "operation_id", "sha256", "body_b64"}, "candidate")
            try:
                body = base64.b64decode(candidate["body_b64"], validate=True)
            except (binascii.Error, TypeError) as error:
                raise AuthorityError("candidate body is not canonical base64") from error
            value = BlobCandidate(_text(candidate["key"], "candidate key"), candidate["expected_version"],
                                  _hex64(candidate["operation_id"], "candidate operation"),
                                  _hex64(candidate["sha256"], "candidate digest"), body)
            try:
                return self.response("ok", blob=_blob_wire(self.blobs.commit(value)))
            except Conflict:
                return self.response("conflict")
            except Ambiguous:
                return self.response("ambiguous")
        if operation == "writer_acquire":
            _exact_keys(request, {"schema", "operation", "writer"}, "writer_acquire")
            if self.writer_token:
                raise Conflict("connection already holds credential writer")
            self.writer_token = self.writer.acquire(self.connection_id, request["writer"])
            return self.response("ok", writer_token=self.writer_token)
        if operation == "writer_release":
            _exact_keys(request, {"schema", "operation", "writer_token"}, "writer_release")
            if not self.writer_token or request["writer_token"] != self.writer_token:
                raise Conflict("writer token does not match connection")
            self.writer.release(self.connection_id, self.writer_token)
            self.writer_token = ""
            return self.response("ok")
        if operation == "enrollment_otp":
            _exact_keys(request, {"schema", "operation", "identity", "challenge"}, "enrollment_otp")
            if not self.writer_token:
                raise Conflict("OTP requested outside credential writer")
            code = self.otp(request["identity"], request["challenge"])
            if not isinstance(code, str) or re.fullmatch(r"[0-9]{8}", code) is None:
                raise AuthorityError("OTP provider returned an invalid code")
            return self.response("ok", otp=code)
        raise AuthorityError("operation is not allowed")

    def close(self) -> None:
        self.writer.connection_lost(self.connection_id)


class _Handler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        connection_id = id(self.request)
        protocol = Protocol(self.server.blobs, self.server.writer, self.server.otp_factory(connection_id), connection_id)  # type: ignore[attr-defined]
        try:
            while True:
                raw = self.rfile.readline(MAX_MESSAGE_BYTES + 2)
                if not raw:
                    return
                if len(raw) > MAX_MESSAGE_BYTES + 1 or not raw.endswith(b"\n"):
                    return
                try:
                    response = protocol.dispatch(decode_canonical(raw[:-1]))
                except (AuthorityError, ValueError):
                    response = Protocol.response("rejected", error="authority request rejected")
                self.wfile.write(encode_canonical(response) + b"\n")
                self.wfile.flush()
        finally:
            protocol.close()


class UnixAuthorityServer(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True

    def __init__(self, path: str, blobs: AWSDurableAuthority, writer: CredentialWriter,
                 otp_factory: Callable[[int], Callable[[dict[str, Any], dict[str, Any]], str]]):
        parent = Path(path).parent
        if not Path(path).is_absolute() or str(Path(path)) != path or len(path) > 100:
            raise AuthorityError("socket path is not absolute and clean")
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != PRIVATE_DIRECTORY_MODE or info.st_uid != os.geteuid():
            raise AuthorityError("socket directory is not owner-only")
        if Path(path).exists() or Path(path).is_symlink():
            raise AuthorityError("socket leaf already exists")
        self.blobs, self.writer, self.otp_factory = blobs, writer, otp_factory
        super().__init__(path, _Handler)
        os.chmod(path, PRIVATE_SOCKET_MODE)


def _load_secret_map(path: str) -> dict[str, str]:
    raw = Path(path).read_bytes()
    if not raw.endswith(b"\n") or b"\n" in raw[:-1] or b"\r" in raw:
        raise AuthorityError("secret map must have one terminal LF")
    value = decode_canonical(raw[:-1])
    return {str(key): str(item) for key, item in value.items()}


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--socket-path", required=True)
    parser.add_argument("--table", required=True)
    parser.add_argument("--secret-map-file", required=True)
    parser.add_argument("--owner-subject", required=True)
    parser.add_argument("--resume-writer-invocation-token", default="")
    parser.add_argument("--region", required=True)
    parser.add_argument("--otp-mailbox-queue-url", required=True)
    parser.add_argument("--otp-mailbox-bucket", required=True)
    parser.add_argument("--otp-mailbox-recipient", required=True)
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    import boto3  # Imported only by the AWS-owning orchestration process.

    session = boto3.session.Session(region_name=args.region)
    blobs = AWSDurableAuthority(session.client("dynamodb"), session.client("secretsmanager"), args.table, _load_secret_map(args.secret_map_file))
    writer = CredentialWriter(blobs.ddb, args.table, args.owner_subject, args.resume_writer_invocation_token)
    sqs, s3 = session.client("sqs"), session.client("s3")

    def otp_factory(connection_id: int) -> MailboxOTP:
        return MailboxOTP(blobs, writer, connection_id, sqs, s3, args.otp_mailbox_queue_url,
                          args.otp_mailbox_bucket, args.otp_mailbox_recipient)

    server = UnixAuthorityServer(args.socket_path, blobs, writer, otp_factory)
    def terminate(_signum: int, _frame: object) -> None:
        raise SystemExit(0)

    prior_term = signal.signal(signal.SIGTERM, terminate)
    try:
        server.serve_forever()
    finally:
        signal.signal(signal.SIGTERM, prior_term)
        server.server_close()
        try:
            Path(args.socket_path).unlink()
        except FileNotFoundError:
            pass
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except AuthorityError as error:
        print(f"matched-cohort authority server failed: {error}", file=sys.stderr)
        raise SystemExit(1) from None
