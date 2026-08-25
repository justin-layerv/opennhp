from __future__ import annotations

import base64
import copy
import importlib.util
import io
import json
import os
import pathlib
import sys
import tempfile
import datetime as dt
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
SOURCE = ROOT / ".github/scripts/sandbox_fixed_canary_authority.py"
SPEC = importlib.util.spec_from_file_location("sandbox_fixed_canary_authority", SOURCE)
assert SPEC and SPEC.loader
server = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = server
SPEC.loader.exec_module(server)


class FakeDDB:
    def __init__(self) -> None:
        self.items: dict[str, dict] = {}
        self.fail_put_after = False
        self.fail_delete_after = False

    def get_item(self, *, TableName: str, Key: dict, ConsistentRead: bool) -> dict:
        assert TableName == "sandbox-authority" and ConsistentRead is True
        value = self.items.get(Key["lock_id"]["S"])
        return {} if value is None else {"Item": copy.deepcopy(value)}

    def put_item(self, *, TableName: str, Item: dict, ConditionExpression: str,
                 ExpressionAttributeNames: dict | None = None, ExpressionAttributeValues: dict | None = None) -> dict:
        assert TableName == "sandbox-authority"
        ExpressionAttributeNames = ExpressionAttributeNames or {}
        ExpressionAttributeValues = ExpressionAttributeValues or {}
        key = Item["lock_id"]["S"]
        current = self.items.get(key)
        accepted = False
        if ConditionExpression == "attribute_not_exists(#key)":
            accepted = current is None
        elif ConditionExpression == "#version = :expected":
            accepted = current is not None and current.get("version_id") == ExpressionAttributeValues[":expected"]
        elif ConditionExpression == "writer_token = :token AND invocation_token = :prior":
            accepted = current is not None and current.get("writer_token") == ExpressionAttributeValues[":token"] and current.get("invocation_token") == ExpressionAttributeValues[":prior"]
        if not accepted:
            raise RuntimeError("ConditionalCheckFailedException")
        self.items[key] = copy.deepcopy(Item)
        if self.fail_put_after:
            self.fail_put_after = False
            raise RuntimeError("committed response lost")
        return {}

    def delete_item(self, *, TableName: str, Key: dict, ConditionExpression: str,
                    ExpressionAttributeValues: dict) -> dict:
        assert TableName == "sandbox-authority" and ConditionExpression == "writer_token = :token"
        key = Key["lock_id"]["S"]
        current = self.items.get(key)
        if current is None or current.get("writer_token") != ExpressionAttributeValues[":token"]:
            raise RuntimeError("ConditionalCheckFailedException")
        del self.items[key]
        if self.fail_delete_after:
            self.fail_delete_after = False
            raise RuntimeError("committed response lost")
        return {}


class FakeSecrets:
    def __init__(self) -> None:
        self.values: dict[tuple[str, str], str] = {}
        self.fail_put_after = False

    def put_secret_value(self, *, SecretId: str, ClientRequestToken: str, SecretString: str) -> dict:
        key = (SecretId, ClientRequestToken)
        current = self.values.get(key)
        if current is not None and current != SecretString:
            raise RuntimeError("idempotency token body drift")
        self.values[key] = SecretString
        if self.fail_put_after:
            self.fail_put_after = False
            raise RuntimeError("committed response lost")
        return {"VersionId": ClientRequestToken}

    def get_secret_value(self, *, SecretId: str, VersionId: str) -> dict:
        key = (SecretId, VersionId)
        if key not in self.values:
            raise RuntimeError("ResourceNotFoundException")
        return {"ARN": SecretId, "Name": SecretId, "VersionId": VersionId, "SecretString": self.values[key]}


class FakeSQS:
    def __init__(self, messages: list[dict]) -> None:
        self.messages = list(messages)
        self.deleted: list[str] = []
        self.released: list[str] = []

    def receive_message(self, **_kwargs: object) -> dict:
        return {"Messages": [self.messages.pop(0)]} if self.messages else {"Messages": []}

    def delete_message(self, *, QueueUrl: str, ReceiptHandle: str) -> None:
        assert QueueUrl == "https://sqs.example/otp"
        self.deleted.append(ReceiptHandle)

    def change_message_visibility(self, *, QueueUrl: str, ReceiptHandle: str, VisibilityTimeout: int) -> None:
        assert QueueUrl == "https://sqs.example/otp" and VisibilityTimeout == 10
        self.released.append(ReceiptHandle)


class FakeS3:
    def __init__(self, body: bytes) -> None:
        self.body = body
        self.calls = 0

    def get_object(self, *, Bucket: str, Key: str) -> dict:
        assert Bucket == "sandbox-otp" and Key.startswith("otp/")
        self.calls += 1
        return {"Body": io.BytesIO(self.body)}


def secret_map() -> dict[str, str]:
    return {
        f"shared/{label}": f"arn:aws:secretsmanager:us-east-2:111122223333:secret:sandbox-shared-{label}"
        for label in ("direct-a", "direct-b", "relay-c", "relay-d")
    }


def candidate(key: str, body: bytes, previous: str = "", char: str = "a") -> server.BlobCandidate:
    return server.BlobCandidate(key, previous, char * 64, server.digest(body), body)


def writer_operation(invocation: str = "1" * 64) -> dict:
    return {
        "schema": 1,
        "owner_subject": "sandbox-fixed-canary-owner",
        "operation": "provision",
        "generation_id": "2" * 64,
        "plan_sha256": "3" * 64,
        "invocation_token": invocation,
    }


def fixed_plan() -> dict:
    public_key = base64.b64encode(bytes(range(32))).decode()
    cohorts = [{
        "server_asg": "sandbox-server-active",
        "ac_asg": "sandbox-ac-active",
        "relay_asg": "sandbox-relay",
        "session_control_table": "sandbox-session-control",
        "qurl_agent_keys_table": "sandbox-qurl-agent-keys",
        "cell_id": "sandbox-cell-01",
        "assignment_generation": 1,
        "hub_host": "hub.sandbox.example",
        "hub_port": 443,
        "hub_server_public_key_b64": public_key,
        "cell_endpoint": {
            "host": "cell.sandbox.example",
            "port": 443,
            "server_public_key_b64": public_key,
        },
    }]
    identities = []
    for label_index, label in enumerate(("direct-a", "direct-b", "relay-c", "relay-d")):
        identities.append({
            "label": label,
            "owner_id": "sandbox-fixed-canary-owner",
            "agent_id": f"sandbox-shared-{label}-agent",
            "connector_id": f"sandbox-shared-{label}-connector",
            "frps_selector": {
                "resource_id": f"qurl-tunnel-server-{chr(ord('a') + label_index % 3)}",
                "host": "connect.sandbox.example",
                "port": 6001 + label_index % 3,
            },
        })
    return {
        "schema": 1,
        "environment": "sandbox",
        "generation_id": "2" * 64,
        "owner_subject": "sandbox-fixed-canary-owner",
        "aws_account_id": "111122223333",
        "aws_region": "us-east-2",
        "nhp_source_sha": "a" * 40,
        "qurl_go_source_sha": "b" * 40,
        "cohorts": cohorts,
        "identities": identities,
    }


class AuthorityStorageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.ddb = FakeDDB()
        self.secrets = FakeSecrets()
        self.authority = server.AWSDurableAuthority(self.ddb, self.secrets, "sandbox-authority", secret_map())

    def test_nonsecret_blob_cas_and_lost_response(self) -> None:
        first = candidate("generations/" + "4" * 64 + "/plan", b'{"schema":1}', char="5")
        self.ddb.fail_put_after = True
        committed = self.authority.commit(first)
        self.assertEqual(committed.body, first.body)
        self.assertEqual(committed.version_id, first.operation_id)
        second = candidate(first.key, b'{"schema":2}', previous=committed.version_id, char="6")
        committed = self.authority.commit(second)
        self.assertEqual(self.authority.load(first.key), committed)
        with self.assertRaises(server.Conflict):
            self.authority.commit(candidate(first.key, b'{"schema":3}', previous=first.operation_id, char="7"))

    def test_agent_state_uses_only_fixed_secret_and_classifies_lost_write(self) -> None:
        key = "generations/" + "8" * 64 + "/shared/relay-c/agent-state"
        value = candidate(key, b'{"agent_id":"fixed-shared-relay-c"}', char="9")
        self.secrets.fail_put_after = True
        self.ddb.fail_put_after = True
        committed = self.authority.commit(value)
        self.assertEqual(committed.body, value.body)
        self.assertEqual(len(self.secrets.values), 1)
        secret_id, version = next(iter(self.secrets.values))
        self.assertEqual(secret_id, secret_map()["shared/relay-c"])
        self.assertEqual(version, value.operation_id)
        with self.assertRaises(server.AuthorityError):
            self.authority.commit(candidate("wrong/relay-c/agent-state", b"{}", char="a"))

    def test_secret_pointer_mutations_fail_closed(self) -> None:
        key = "generations/" + "b" * 64 + "/shared/direct-a/agent-state"
        value = candidate(key, b'{"schema":7}', char="c")
        self.authority.commit(value)
        row = self.ddb.items[self.authority.row_key(key)]
        for name, mutate in {
            "wrong secret": lambda item: item.__setitem__("secret_id", {"S": "wrong"}),
            "wrong digest": lambda item: item.__setitem__("sha256", {"S": "d" * 64}),
            "extra": lambda item: item.__setitem__("extra", {"S": "x"}),
            "storage": lambda item: item.__setitem__("storage", {"S": "dynamodb"}),
        }.items():
            with self.subTest(name=name):
                saved = copy.deepcopy(row)
                mutate(row)
                with self.assertRaises(server.AuthorityError):
                    self.authority.load(key)
                row.clear()
                row.update(saved)


class WriterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.ddb = FakeDDB()

    def test_exact_provision_delegate_is_single_and_cannot_release_outer_row(self) -> None:
        lock = server.CredentialWriter(self.ddb, "sandbox-authority", "sandbox-fixed-canary-owner")
        outer = lock.acquire(10, writer_operation())
        delegated = lock.acquire(11, writer_operation())
        self.assertNotEqual(delegated, outer)
        with self.assertRaises(server.Conflict):
            lock.acquire(12, writer_operation())
        with self.assertRaises(server.Conflict):
            lock.release(10, outer)
        lock.release(11, delegated)
        self.assertEqual(self.ddb.items[lock.row_key]["writer_token"]["S"], outer)
        lock.release(10, outer)
        self.assertNotIn(lock.row_key, self.ddb.items)

    def test_delegate_rejects_operation_binding_and_token_drift(self) -> None:
        lock = server.CredentialWriter(self.ddb, "sandbox-authority", "sandbox-fixed-canary-owner")
        outer = lock.acquire(10, writer_operation())
        for field, value in (
            ("operation", "normal-release"),
            ("generation_id", "8" * 64),
            ("plan_sha256", "9" * 64),
            ("invocation_token", "a" * 64),
        ):
            with self.subTest(field=field):
                changed = writer_operation()
                changed[field] = value
                with self.assertRaises(server.Conflict):
                    lock.acquire(11, changed)
        delegated = lock.acquire(11, writer_operation())
        with self.assertRaises(server.Conflict):
            lock.release(11, "f" * 64)
        lock.release(11, delegated)
        lock.release(10, outer)

    def test_outer_transport_loss_retains_row_while_delegate_finishes(self) -> None:
        lock = server.CredentialWriter(self.ddb, "sandbox-authority", "sandbox-fixed-canary-owner")
        outer = lock.acquire(10, writer_operation())
        delegated = lock.acquire(11, writer_operation())
        lock.connection_lost(10)
        self.assertEqual(lock.current_binding(11)["invocation_token"], writer_operation()["invocation_token"])
        lock.release(11, delegated)
        self.assertEqual(self.ddb.items[lock.row_key]["writer_token"]["S"], outer)
        with self.assertRaises(server.Conflict):
            lock.acquire(12, writer_operation())

    def test_explicit_successor_adopts_exact_binding_once(self) -> None:
        prior = "1" * 64
        first = server.CredentialWriter(self.ddb, "sandbox-authority", "sandbox-fixed-canary-owner")
        first.acquire(10, writer_operation(prior))
        first.connection_lost(10)
        successor = server.CredentialWriter(self.ddb, "sandbox-authority", "sandbox-fixed-canary-owner", prior)
        token = successor.acquire(20, writer_operation("4" * 64))
        with self.assertRaises(server.Conflict):
            successor.acquire(21, writer_operation("5" * 64))
        self.ddb.fail_delete_after = True
        successor.release(20, token)
        self.assertNotIn(successor.row_key, self.ddb.items)

    def test_successor_rejects_binding_drift_and_wrong_prior(self) -> None:
        first = server.CredentialWriter(self.ddb, "sandbox-authority", "sandbox-fixed-canary-owner")
        first.acquire(10, writer_operation())
        first.connection_lost(10)
        wrong = server.CredentialWriter(self.ddb, "sandbox-authority", "sandbox-fixed-canary-owner", "9" * 64)
        with self.assertRaises(server.Conflict):
            wrong.acquire(20, writer_operation("4" * 64))
        exact = server.CredentialWriter(self.ddb, "sandbox-authority", "sandbox-fixed-canary-owner", "1" * 64)
        drift = writer_operation("4" * 64)
        drift["plan_sha256"] = "5" * 64
        with self.assertRaises(server.Conflict):
            exact.acquire(20, drift)


class MailboxOTPTests(unittest.TestCase):
    def test_code_is_secret_committed_before_return_and_replays_without_mailbox(self) -> None:
        ddb, secrets = FakeDDB(), FakeSecrets()
        blobs = server.AWSDurableAuthority(ddb, secrets, "sandbox-authority", secret_map())
        plan = fixed_plan()
        identity = plan["identities"][0]
        plan_raw = server.encode_canonical(plan)
        blobs.commit(candidate("generations/" + plan["generation_id"] + "/plan", plan_raw, char="5"))
        writer = server.CredentialWriter(ddb, "sandbox-authority", plan["owner_subject"])
        operation = writer_operation()
        operation["plan_sha256"] = server.digest(plan_raw)
        writer.acquire(100, operation)
        now = dt.datetime(2026, 8, 24, 18, 0, tzinfo=dt.timezone.utc)
        delivered = (now + dt.timedelta(seconds=1)).isoformat().replace("+00:00", "Z")
        notice = json.dumps({"Records": [{"eventTime": delivered, "s3": {"bucket": {"name": "sandbox-otp"}, "object": {"key": "otp/message"}}}]})
        sqs = FakeSQS([{"MessageId": "message", "ReceiptHandle": "receipt", "MD5OfBody": "digest", "Body": notice}])
        mail = ("To: otp@example.test\r\nSubject: qURL Connector verification code\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n"
                f'Connector ID:  "{identity["agent_id"]}"\nYour qURL Connector verification code is: 12345678\n').encode()
        mailbox = server.MailboxOTP(blobs, writer, 100, sqs, FakeS3(mail), "https://sqs.example/otp", "sandbox-otp", "otp@example.test", 1, lambda: now)
        challenge = {"agent_id": identity["agent_id"], "credential_key_id": "credential-key", "cell_id": plan["cohorts"][0]["cell_id"],
                     "assignment_ticket_expires_at": "2026-08-24T18:10:00Z", "pending_activation_recovery": False}
        self.assertEqual(mailbox(identity, challenge), "12345678")
        self.assertEqual(sqs.deleted, ["receipt"])
        otp_key = "generations/" + plan["generation_id"] + "/shared/direct-a/enrollment-otp"
        persisted = blobs.load(otp_key)
        self.assertIn(b'"code":"12345678"', persisted.body)
        challenge["pending_activation_recovery"] = True
        empty = FakeSQS([])
        replay = server.MailboxOTP(blobs, writer, 100, empty, FakeS3(b""), "https://sqs.example/otp", "sandbox-otp", "otp@example.test", 1, lambda: now)
        self.assertEqual(replay(identity, challenge), "12345678")
        self.assertEqual(empty.deleted, [])

    def test_plan_and_ticket_mutations_fail_before_mailbox_read(self) -> None:
        for name, mutate in {
            "missing cohort": lambda plan: plan["cohorts"].pop(),
            "three identities": lambda plan: plan["identities"].pop(),
            "wrong NHP source": lambda plan: plan.__setitem__("nhp_source_sha", "A" * 40),
            "reordered identities": lambda plan: plan["identities"].__setitem__(slice(0, 2), reversed(plan["identities"][:2])),
            "duplicate agent": lambda plan: plan["identities"][1].__setitem__("agent_id", plan["identities"][0]["agent_id"]),
            "wrong identity owner": lambda plan: plan["identities"][0].__setitem__("owner_id", "other-owner"),
            "boolean generation": lambda plan: plan["cohorts"][0].__setitem__("assignment_generation", True),
            "wrong selector resource": lambda plan: plan["identities"][0]["frps_selector"].__setitem__("resource_id", "qurl-tunnel-server-c"),
            "duplicate selector drift": lambda plan: plan["identities"][3]["frps_selector"].__setitem__("port", 7000),
            "selector host split": lambda plan: plan["identities"][1]["frps_selector"].__setitem__("host", "other.sandbox.example"),
            "selector port collision": lambda plan: plan["identities"][2]["frps_selector"].__setitem__("port", plan["identities"][1]["frps_selector"]["port"]),
        }.items():
            with self.subTest(name=name):
                ddb, secrets = FakeDDB(), FakeSecrets()
                blobs = server.AWSDurableAuthority(ddb, secrets, "sandbox-authority", secret_map())
                plan = fixed_plan()
                identity = copy.deepcopy(plan["identities"][0])
                mutate(plan)
                raw = server.encode_canonical(plan)
                blobs.commit(candidate("generations/" + plan["generation_id"] + "/plan", raw, char="5"))
                writer = server.CredentialWriter(ddb, "sandbox-authority", plan["owner_subject"])
                operation = writer_operation()
                operation["plan_sha256"] = server.digest(raw)
                writer.acquire(100, operation)
                mailbox = server.MailboxOTP(blobs, writer, 100, FakeSQS([]), FakeS3(b""), "https://sqs.example/otp", "sandbox-otp", "otp@example.test", 1,
                                            lambda: dt.datetime(2026, 8, 24, 18, 0, tzinfo=dt.timezone.utc))
                challenge = {"agent_id": identity["agent_id"], "credential_key_id": "credential-key", "cell_id": "sandbox-cell-01",
                             "assignment_ticket_expires_at": "2026-08-24T18:10:00Z", "pending_activation_recovery": False}
                with self.assertRaises(server.AuthorityError):
                    mailbox(identity, challenge)

        plan = fixed_plan()
        identity = plan["identities"][0]
        for expiry in ("2026-08-24T18:00:00Z", "2026-08-24T18:15:01Z"):
            with self.subTest(expiry=expiry):
                ddb, secrets = FakeDDB(), FakeSecrets()
                blobs = server.AWSDurableAuthority(ddb, secrets, "sandbox-authority", secret_map())
                raw = server.encode_canonical(plan)
                blobs.commit(candidate("generations/" + plan["generation_id"] + "/plan", raw, char="5"))
                writer = server.CredentialWriter(ddb, "sandbox-authority", plan["owner_subject"])
                operation = writer_operation()
                operation["plan_sha256"] = server.digest(raw)
                writer.acquire(100, operation)
                mailbox = server.MailboxOTP(blobs, writer, 100, FakeSQS([]), FakeS3(b""), "https://sqs.example/otp", "sandbox-otp", "otp@example.test", 1,
                                            lambda: dt.datetime(2026, 8, 24, 18, 0, tzinfo=dt.timezone.utc))
                challenge = {"agent_id": identity["agent_id"], "credential_key_id": "credential-key", "cell_id": "sandbox-cell-01",
                             "assignment_ticket_expires_at": expiry, "pending_activation_recovery": False}
                with self.assertRaises(server.Conflict):
                    mailbox(identity, challenge)


class ProtocolTests(unittest.TestCase):
    def setUp(self) -> None:
        self.ddb = FakeDDB()
        self.blobs = server.AWSDurableAuthority(self.ddb, FakeSecrets(), "sandbox-authority", secret_map())
        self.writer = server.CredentialWriter(self.ddb, "sandbox-authority", "sandbox-fixed-canary-owner")
        self.protocol = server.Protocol(self.blobs, self.writer, lambda _identity, _challenge: "12345678", 100)

    def test_canonical_request_and_blob_round_trip(self) -> None:
        body = b'{"schema":1}'
        request = {
            "schema": 1,
            "operation": "blob_commit",
            "candidate": {
                "key": "fixed/blob",
                "expected_version": "",
                "operation_id": "a" * 64,
                "sha256": server.digest(body),
                "body_b64": base64.b64encode(body).decode(),
            },
        }
        raw = server.encode_canonical(request)
        self.assertEqual(server.decode_canonical(raw), request)
        response = self.protocol.dispatch(request)
        self.assertEqual(response["status"], "ok")
        loaded = self.protocol.dispatch({"schema": 1, "operation": "blob_load", "key": "fixed/blob"})
        self.assertEqual(loaded["blob"]["body_b64"], base64.b64encode(body).decode())
        self.assertEqual(self.protocol.dispatch({"schema": 1, "operation": "blob_load", "key": "missing"}), {"schema": 1, "status": "not_found"})

    def test_protocol_forbids_plaintext_credential_and_otp_outside_lock(self) -> None:
        with self.assertRaises(server.AuthorityError):
            self.protocol.dispatch({"schema": 1, "operation": "enrollment_credential", "identity": {}})
        identity = {"label": "direct-a", "owner_id": "owner", "agent_id": "agent", "connector_id": "connector", "frps_selector": {"resource_id": "a", "host": "a.example", "port": 1}}
        challenge = {"agent_id": "agent", "credential_key_id": "key", "cell_id": "cell", "assignment_ticket_expires_at": "2026-08-24T00:00:00Z", "pending_activation_recovery": False}
        with self.assertRaises(server.Conflict):
            self.protocol.dispatch({"schema": 1, "operation": "enrollment_otp", "identity": identity, "challenge": challenge})
        acquired = self.protocol.dispatch({"schema": 1, "operation": "writer_acquire", "writer": writer_operation()})
        self.assertRegex(acquired["writer_token"], r"^[0-9a-f]{64}$")
        response = self.protocol.dispatch({"schema": 1, "operation": "enrollment_otp", "identity": identity, "challenge": challenge})
        self.assertEqual(response, {"schema": 1, "status": "ok", "otp": "12345678"})
        self.assertEqual(self.protocol.dispatch({"schema": 1, "operation": "writer_release", "writer_token": acquired["writer_token"]}), {"schema": 1, "status": "ok"})

    def test_duplicate_noncanonical_and_unknown_unions_reject(self) -> None:
        for raw in (
            b'{"schema":1,"schema":1,"operation":"blob_load","key":"x"}',
            b'{ "schema":1,"operation":"blob_load","key":"x"}',
        ):
            with self.subTest(raw=raw):
                with self.assertRaises(server.AuthorityError):
                    server.decode_canonical(raw)
        with self.assertRaises(server.AuthorityError):
            self.protocol.dispatch({"schema": 1, "operation": "blob_load", "key": "x", "extra": True})


class FilesystemTests(unittest.TestCase):
    def test_server_socket_is_owner_only_and_existing_leaf_rejects(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            os.chmod(directory, 0o700)
            path = os.path.join(directory, "authority.sock")
            ddb = FakeDDB()
            blobs = server.AWSDurableAuthority(ddb, FakeSecrets(), "sandbox-authority", secret_map())
            writer = server.CredentialWriter(ddb, "sandbox-authority", "sandbox-fixed-canary-owner")
            instance = server.UnixAuthorityServer(path, blobs, writer, lambda _connection: (lambda _i, _c: "12345678"))
            try:
                self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
            finally:
                instance.server_close()
                os.unlink(path)
            pathlib.Path(path).write_text("occupied")
            with self.assertRaises(server.AuthorityError):
                server.UnixAuthorityServer(path, blobs, writer, lambda _connection: (lambda _i, _c: "12345678"))


if __name__ == "__main__":
    unittest.main()
