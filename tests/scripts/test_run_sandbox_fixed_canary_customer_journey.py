from __future__ import annotations

import base64
import copy
import importlib.util
import inspect
import json
import os
import socket
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "run_sandbox_fixed_canary_customer_journey",
    ROOT / ".github/scripts/run_sandbox_fixed_canary_customer_journey.py",
)
assert SPEC and SPEC.loader
JOURNEY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(JOURNEY)


def s(value: str) -> dict[str, str]:
    return {"S": value}


def n(value: int) -> dict[str, str]:
    return {"N": str(value)}


def operation_item(operation_id: str, binding: str) -> dict[str, dict[str, str]]:
    return {
        "pk": s("OP#" + operation_id),
        "sk": s("AUTHORITY"),
        "kind": s("native_session_operation"),
        "schema_version": n(1),
        "operation_id": s(operation_id),
        "binding_sha256": s(binding),
        "state": s("CANCELED"),
        "owner_id": s("abcdefghijklmnopqrstuv@clients"),
        "agent_id": s("fixed-shared-direct-a-agent"),
        "agent_public_key": s(base64.b64encode(b"a" * 32).decode()),
        "resource_id": s("qurl-tunnel-server-a"),
        "auth_service_id": s("registered-agent"),
        "run_id": s("1" * 16),
        "run_attempt": n(1),
        "prepared_at_ms": n(1_800_000_000_000),
        "expires_at_ms": n(1_800_001_200_000),
        "aws_account_id": s(JOURNEY.ACCOUNT),
        "aws_region": s(JOURNEY.REGION),
        "cell_id": s("cell0"),
        "session_control_table": s(JOURNEY.SESSION_TABLE),
        "agent_keys_table": s(JOURNEY.PLAN.AGENT_KEYS_TABLE),
        "agent_key_schema_version": n(2),
        "enrollment_credential_kind": s("account"),
        "connector_id_claim": s(""),
        "terminal_at_ms": n(1_800_000_000_100),
        "ttl": n(1_800_086_400),
    }


class DDB:
    def __init__(self, item: dict, memberships: list[dict] | None = None) -> None:
        self.item = item
        self.memberships = memberships or []
        self.queries: list[dict] = []

    def get_item(self, **request):
        self.last_get = request
        return {"Item": self.item}

    def query(self, **request):
        self.queries.append(request)
        return {"Items": self.memberships}


class SandboxFixedCanaryCustomerJourneyTest(unittest.TestCase):
    @staticmethod
    def phase_journal(phase: str, attempts: int) -> dict:
        records = []
        for attempt in range(1, attempts + 1):
            raw = JOURNEY.ordered({"attempt": attempt, "phase": phase})
            records.append({"body_b64": base64.b64encode(raw).decode(), "sha256": JOURNEY.digest(raw)})
        return {"attempts": records}

    def test_oversized_phase_ledger_is_rejected_before_writer_rpc(self) -> None:
        writer = object.__new__(JOURNEY.WriterConnection)
        writer.request = mock.Mock()
        with self.assertRaisesRegex(JOURNEY.JourneyError, "DynamoDB size budget"):
            writer.commit_blob(
                "runs/" + "a" * 64 + "/phase-inputs",
                "0" * 64,
                b"x" * (JOURNEY.MAX_DURABLE_PHASE_LEDGER_BYTES + 1),
            )
        writer.request.assert_not_called()

    def test_direct_and_relay_deployments_are_distinct_closed_projections(self) -> None:
        runtime = {
            "issuer": {"kid": "kid", "spki_der_b64": "spki"},
            "hub_endpoint": {"host": "hub.nhp.layerv.xyz", "port": 443, "server_public_key_b64": "hub-key"},
            "cell_id": "cell0",
            "cell_endpoint": {"host": "cell0.nhp.layerv.xyz", "port": 443, "server_public_key_b64": "cell-key"},
            "relay": {"hostname": "relay.qurl.link.layerv.xyz"},
        }
        direct = JOURNEY.deployment(runtime, transport="direct")
        relay = JOURNEY.deployment(runtime, transport="relay")
        self.assertEqual(direct["cells"], [{"cell_id": "cell0", **runtime["cell_endpoint"]}])
        self.assertEqual(direct["relay_allowlist"], [])
        self.assertEqual(relay["cells"], [])
        self.assertEqual(relay["relay_allowlist"], [runtime["relay"]["hostname"]])
        self.assertEqual(direct["hub"], relay["hub"])

    def test_stale_private_authority_socket_is_removed_before_reconcile_restart(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as raw_directory:
            directory = Path(raw_directory)
            directory.chmod(0o700)
            path = directory / "authority.sock"
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(str(path))
            os.chmod(path, 0o600)
            listener.close()
            self.assertFalse(JOURNEY.existing_authority_socket_is_live(path))
            self.assertFalse(path.exists())

            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(str(path))
            os.chmod(path, 0o600)
            listener.listen(1)
            try:
                self.assertTrue(JOURNEY.existing_authority_socket_is_live(path))
            finally:
                listener.close()
                path.unlink()

    def test_owned_process_teardown_removes_stale_socket_for_same_root_reconcile(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as raw_directory:
            directory = Path(raw_directory)
            directory.chmod(0o700)
            path = directory / "authority.sock"
            child = subprocess.Popen(
                [
                    sys.executable,
                    "-c",
                    (
                        "import os,socket,sys,time;"
                        "s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);"
                        "s.bind(sys.argv[1]);os.chmod(sys.argv[1],0o600);s.listen(1);"
                        "time.sleep(60)"
                    ),
                    str(path),
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            for _ in range(100):
                if path.exists():
                    break
                if child.poll() is not None:
                    self.fail("socket fixture exited before readiness")
                JOURNEY.time.sleep(0.01)
            JOURNEY.stop_authority_process(child, path)
            self.assertFalse(path.exists())
            self.assertFalse(JOURNEY.existing_authority_socket_is_live(path))

            key_dir = directory / "ordinary-key"
            key_dir.mkdir(mode=0o700)
            candidate = directory / "key-candidate.json"
            JOURNEY.write_private(candidate, JOURNEY.canonical({"schema": 1}))
            for name in ("api-key", "api-key-id", "api-key-prefix"):
                JOURNEY.write_private(key_dir / name, b"value\n")
            revoke = directory / "key-revoke.json"
            verification = directory / "key-post-cache.json"
            calls: list[str] = []

            def helper(command, *, timeout):
                calls.append(command[3])
                target_flag = "--receipt-file" if command[3] == "revoke" else "--verification-file"
                JOURNEY.write_private(Path(command[command.index(target_flag) + 1]), JOURNEY.canonical({"status": "completed"}))

            class Writer:
                released = False

                def release(self):
                    self.released = True

            writer = Writer()
            with mock.patch.object(JOURNEY, "run_exact", side_effect=helper):
                JOURNEY.settle_ordinary_key(
                    helper=directory / "helper",
                    helper_common=["--candidate-file", str(candidate)],
                    key_dir=key_dir,
                    candidate=candidate,
                    revoke=revoke,
                    verification=verification,
                    writer=writer,
                )
            self.assertEqual(calls, ["revoke", "verify-revoked"])
            self.assertTrue(revoke.exists() and verification.exists())
            self.assertTrue(writer.released)

    def test_active_operation_source_is_dynamic_and_requires_component_equality(self) -> None:
        source = "a" * 40
        runtime = {
            "active_colors": {"server": "blue", "ac": "green"},
            "cohorts": {
                "blue": {"server": {"source_sha": source}, "ac": {"source_sha": "b" * 40}},
                "green": {"server": {"source_sha": "c" * 40}, "ac": {"source_sha": source}},
            },
            "relay": {"source_sha": source},
        }
        self.assertEqual(JOURNEY.active_nhp_operation_source(runtime), source)
        for path, replacement in (
            (("cohorts", "blue", "server", "source_sha"), "d" * 40),
            (("cohorts", "green", "ac", "source_sha"), "d" * 40),
            (("relay", "source_sha"), "d" * 40),
        ):
            changed = json.loads(json.dumps(runtime))
            cursor = changed
            for key in path[:-1]:
                cursor = cursor[key]
            cursor[path[-1]] = replacement
            with self.assertRaises(JOURNEY.JourneyError):
                JOURNEY.active_nhp_operation_source(changed)
        journey_source = inspect.getsource(JOURNEY.journey)
        self.assertLess(
            journey_source.index("operation_source = active_nhp_operation_source(runtime)"),
            journey_source.index("mint_jwt("),
        )

    def test_recovery_receipt_strongly_requires_canceled_op_and_zero_membership(self) -> None:
        operation_id, binding = "a" * 64, "b" * 64
        item = operation_item(operation_id, binding)
        ddb = DDB(item)
        report = {"recovery": {"receipt": {"operation_id": operation_id, "binding_sha256": binding}}}
        with mock.patch.object(JOURNEY.time, "time", return_value=1_800_000_100):
            receipt = JOURNEY.operation_receipt(ddb, report)
        self.assertTrue(receipt["terminal_op_retained"])
        self.assertTrue(receipt["session_absent"])
        self.assertTrue(receipt["membership_absent"])
        self.assertEqual(len(ddb.queries), 1)
        self.assertTrue(ddb.queries[0]["ConsistentRead"])
        self.assertRegex(ddb.queries[0]["ExpressionAttributeValues"][":pk"]["S"], r"^AGENT#[0-9a-f]{64}$")
        self.assertNotIn("FilterExpression", ddb.queries[0])
        self.assertNotIn("ExpressionAttributeNames", ddb.queries[0])

        for label, mutate in (
            ("mapped", lambda value: value.__setitem__("mapped_session_id", n(1))),
            ("wrong-state", lambda value: value.__setitem__("state", s("CLOSED"))),
            ("wrong-agent-table", lambda value: value.__setitem__("agent_keys_table", s("retired-cell-table"))),
            ("short-retention", lambda value: value.__setitem__("ttl", n(1_800_086_399))),
        ):
            changed = dict(item)
            mutate(changed)
            with self.subTest(label=label), self.assertRaises(JOURNEY.JourneyError), mock.patch.object(JOURNEY.time, "time", return_value=1_800_000_100):
                JOURNEY.operation_receipt(DDB(changed), report)
        with self.assertRaises(JOURNEY.JourneyError), mock.patch.object(JOURNEY.time, "time", return_value=1_800_000_100):
            JOURNEY.operation_receipt(DDB(item, [{"operation_id": s(operation_id)}]), report)
        with self.assertRaises(JOURNEY.JourneyError), mock.patch.object(JOURNEY.time, "time", return_value=1_800_000_100):
            JOURNEY.operation_receipt(DDB(item, [{"operation_id": s("c" * 64)}]), report)

    def test_jwt_and_private_json_contracts_fail_closed(self) -> None:
        payload = {
            "iss": JOURNEY.AUTH0_ISSUER,
            "aud": JOURNEY.API_ENDPOINT,
            "sub": "abcdefghijklmnopqrstuv@clients",
            "exp": 1_900_000_100,
        }
        encoded = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
        token = "header." + encoded + ".signature"
        with mock.patch.object(JOURNEY.time, "time", return_value=1_900_000_000):
            self.assertEqual(JOURNEY._jwt_payload(token), payload)
            for mutation in (
                {**payload, "iss": "https://auth.example/"},
                {**payload, "aud": "https://api.layerv.ai"},
                {**payload, "sub": "wrong"},
            ):
                body = base64.urlsafe_b64encode(json.dumps(mutation).encode()).decode().rstrip("=")
                with self.assertRaises(JOURNEY.JourneyError):
                    JOURNEY._jwt_payload("header." + body + ".signature")

        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            directory.chmod(0o700)
            path = directory / "input.json"
            value = {"schema": 1, "z": 2, "a": 3}
            JOURNEY.write_private(path, JOURNEY.ordered(value))
            self.assertEqual(JOURNEY.read_json(path, canonical_required=False), value)
            with self.assertRaises(JOURNEY.JourneyError):
                JOURNEY.read_json(path)

    def test_three_attempt_chain_resumes_after_settlement_report_crash(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            directory.chmod(0o700)
            calls: list[int] = []

            def run(_command, _socket, input_path, _source, report_path):
                attempt = JOURNEY.read_json(Path(input_path), canonical_required=False)["attempt"]
                calls.append(attempt)
                status = "settled-retry-required" if attempt == 1 else "completed"
                JOURNEY.write_private(Path(report_path), JOURNEY.ordered({"lifecycle": {"status": status}}))
                if attempt == 1:
                    raise RuntimeError("runner lost after durable settlement report")

            common = (
                "direct",
                self.phase_journal("direct", 3),
                directory,
                {"path": "/private/lifecycle"},
                directory / "authority.sock",
                directory / "source.json",
            )
            with mock.patch.object(JOURNEY.RUNNER, "run", side_effect=run), mock.patch.object(JOURNEY.RUNNER, "validate_report"):
                with self.assertRaises(RuntimeError):
                    JOURNEY.run_phase_attempt_chain(*common)
                report = JOURNEY.run_phase_attempt_chain(*common)
            self.assertEqual(calls, [1, 2])
            self.assertEqual(JOURNEY.read_json(report, canonical_required=False)["lifecycle"]["status"], "completed")

    def test_attempt_chain_never_skips_an_unsettled_predecessor(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            directory.chmod(0o700)
            calls: list[int] = []

            def run(_command, _socket, input_path, _source, report_path):
                attempt = JOURNEY.read_json(Path(input_path), canonical_required=False)["attempt"]
                calls.append(attempt)
                status = "settled-retry-required" if attempt < 3 else "completed"
                JOURNEY.write_private(Path(report_path), JOURNEY.ordered({"lifecycle": {"status": status}}))

            # A later report without its predecessor is not authority to skip.
            JOURNEY.write_private(
                directory / "direct-generation-1-attempt-2-report.json",
                JOURNEY.ordered({"lifecycle": {"status": "completed"}}),
            )
            common = (
                "direct",
                self.phase_journal("direct", 3),
                directory,
                {"path": "/private/lifecycle"},
                directory / "authority.sock",
                directory / "source.json",
            )
            with mock.patch.object(JOURNEY.RUNNER, "run", side_effect=run), mock.patch.object(JOURNEY.RUNNER, "validate_report"):
                result = JOURNEY.run_phase_attempt_chain(*common)
            self.assertEqual(calls, [1])
            self.assertEqual(result, directory / "direct-generation-1-attempt-2-report.json")

    def test_attempt_three_resume_reuses_all_exact_prior_reports(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            directory.chmod(0o700)
            for attempt in (1, 2):
                JOURNEY.write_private(
                    directory / f"relay-generation-1-attempt-{attempt}-report.json",
                    JOURNEY.ordered({"lifecycle": {"status": "settled-retry-required"}}),
                )
            JOURNEY.write_private(
                directory / "relay-generation-1-attempt-3-report.json",
                JOURNEY.ordered({"lifecycle": {"status": "completed"}}),
            )
            with mock.patch.object(JOURNEY.RUNNER, "run") as run, mock.patch.object(JOURNEY.RUNNER, "validate_report") as validate:
                result = JOURNEY.run_phase_attempt_chain(
                    "relay",
                    self.phase_journal("relay", 3),
                    directory,
                    {"path": "/private/lifecycle"},
                    directory / "authority.sock",
                    directory / "source.json",
                )
            run.assert_not_called()
            self.assertEqual(validate.call_count, 3)
            self.assertEqual(result, directory / "relay-generation-1-attempt-3-report.json")

    def test_exhausted_attempt_chain_requires_a_fresh_durable_generation(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            directory.chmod(0o700)

            def run(_command, _socket, _input, _source, report_path):
                JOURNEY.write_private(Path(report_path), JOURNEY.ordered({"lifecycle": {"status": "settled-retry-required"}}))

            with mock.patch.object(JOURNEY.RUNNER, "run", side_effect=run), mock.patch.object(JOURNEY.RUNNER, "validate_report"):
                self.assertIsNone(
                    JOURNEY.run_phase_attempt_chain(
                        "direct",
                        self.phase_journal("direct", 3),
                        directory,
                        {"path": "/private/lifecycle"},
                        directory / "authority.sock",
                        directory / "source.json",
                        1,
                    )
                )
            self.assertTrue((directory / "direct-generation-1-attempt-3-report.json").exists())
            self.assertFalse((directory / "direct-generation-2-attempt-1-input.json").exists())

    def test_phase_generation_window_has_job_margin_and_boundary_is_exact(self) -> None:
        self.assertEqual(JOURNEY.PHASE_BUNDLE_VALIDITY_MS, 30 * 60 * 1000)
        worst_case = 7 * JOURNEY.PHASE_ATTEMPT_TIMEOUT_SECONDS * 1000
        self.assertLess(worst_case, JOURNEY.PHASE_BUNDLE_VALIDITY_MS)
        prepared = 1_800_000_000_000
        expires = prepared + JOURNEY.PHASE_BUNDLE_VALIDITY_MS
        self.assertLess(prepared + 29 * 60 * 1000 + 59_000, expires)
        self.assertEqual(prepared + 30 * 60 * 1000, expires)
        self.assertGreater(prepared + 30 * 60 * 1000 + 1_000, expires)

    def test_successor_generation_keeps_release_and_uses_fresh_global_attempt_keys(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            directory.chmod(0o700)
            deployments = {}
            for transport in ("direct", "relay"):
                path = directory / f"{transport}.json"
                JOURNEY.write_private(path, JOURNEY.ordered({"transport": transport}))
                deployments[transport] = path

            def build(_runtime, _plan, **kwargs):
                return {
                    "operation": kwargs["operation"],
                    "transport": kwargs["transport"],
                    "phase": "fixed_shared_recovery_first" if kwargs["operation"] == "recover-prepared" else f"fixed_shared_{kwargs['transport']}",
                    "attempt": kwargs["attempt"],
                    "release_id": kwargs["release_id"],
                    "authority": kwargs["authority"],
                    "prepared_at_ms": kwargs["prepared_at_ms"],
                    "expires_at_ms": kwargs["expires_at_ms"],
                    "run_ids": kwargs["run_ids"],
                }

            common = {
                "prepared_at_ms": 1_800_000_000_000,
                "release_id": "a" * 64,
                "runtime": {},
                "plan": {"generation_id": "b" * 64},
                "authority": {"key": "authority"},
                "deployment_paths": deployments,
                "lifecycle_binary": {"path": "/private/lifecycle", "sha256": "c" * 64},
                "qurl_binary": {"path": "/private/qurl", "sha256": "d" * 64},
                "qurl_source": "e" * 40,
                "api_key_file": directory / "api-key",
            }
            with mock.patch.object(JOURNEY.PLAN, "build_lifecycle_input", side_effect=build):
                first = JOURNEY.phase_bundle(generation=1, **common)
                second = JOURNEY.phase_bundle(generation=2, **common)
            first_direct = [JOURNEY.decode_ordered(base64.b64decode(row["body_b64"]), "input") for row in first["phases"]["direct"]["attempts"]]
            second_direct = [JOURNEY.decode_ordered(base64.b64decode(row["body_b64"]), "input") for row in second["phases"]["direct"]["attempts"]]
            self.assertEqual([row["attempt"] for row in first_direct], [1, 2, 3])
            self.assertEqual([row["attempt"] for row in second_direct], [4, 5, 6])
            self.assertEqual({row["release_id"] for row in first_direct + second_direct}, {"a" * 64})
            self.assertNotEqual(first_direct[0]["run_ids"], second_direct[0]["run_ids"])
            ledger = JOURNEY.phase_ledger(first)
            ledger["generations"].append(second)
            input_keys = set(first_direct[0])
            with mock.patch.object(JOURNEY.RUNNER, "LIFECYCLE_INPUT_KEYS", input_keys):
                restored = JOURNEY.validate_phase_ledger(
                    ledger,
                    release_id="a" * 64,
                    plan=common["plan"],
                    authority=common["authority"],
                )
            self.assertEqual([value["generation"] for value in restored], [1, 2])
            for mutation in (
                {**ledger, "generations": [second]},
                {**ledger, "generations": [first, first]},
                {**ledger, "generations": [first, second, second, second]},
            ):
                with mock.patch.object(JOURNEY.RUNNER, "LIFECYCLE_INPUT_KEYS", input_keys), self.assertRaises(JOURNEY.JourneyError):
                    JOURNEY.validate_phase_ledger(
                        mutation,
                        release_id="a" * 64,
                        plan=common["plan"],
                        authority=common["authority"],
                    )
            drifted = copy.deepcopy(ledger)
            record = drifted["generations"][1]["phases"]["direct"]["attempts"][0]
            body = JOURNEY.decode_ordered(base64.b64decode(record["body_b64"]), "input")
            body["phase"] = "fixed_shared_relay"
            raw = JOURNEY.ordered(body)
            record.update(body_b64=base64.b64encode(raw).decode(), sha256=JOURNEY.digest(raw))
            with mock.patch.object(JOURNEY.RUNNER, "LIFECYCLE_INPUT_KEYS", input_keys), self.assertRaises(JOURNEY.JourneyError):
                JOURNEY.validate_phase_ledger(
                    drifted,
                    release_id="a" * 64,
                    plan=common["plan"],
                    authority=common["authority"],
                )

    def test_phase_success_is_not_repeated_when_a_later_phase_needs_a_successor(self) -> None:
        generations = [
            {
                "generation": 1,
                "phases": {phase: self.phase_journal(phase, 1 if phase == "recovery" else 3) for phase in ("recovery", "direct", "relay")},
            }
        ]
        calls: list[tuple[str, int]] = []

        def run(phase, _journal, directory, _binary, _socket, _source, generation):
            calls.append((phase, generation))
            if phase == "relay" and generation == 1:
                return None
            return directory / f"{phase}-generation-{generation}-report.json"

        def append(generation):
            self.assertEqual(generation, 2)
            generations.append(
                {
                    "generation": 2,
                    "phases": {phase: self.phase_journal(phase, 1 if phase == "recovery" else 3) for phase in ("recovery", "direct", "relay")},
                }
            )
            return generations

        with mock.patch.object(JOURNEY, "run_phase_attempt_chain", side_effect=run):
            reports = JOURNEY.run_phase_ledger(
                generations,
                Path("/private"),
                {"path": "/private/lifecycle"},
                Path("/private/authority.sock"),
                Path("/private/source.json"),
                append,
            )
        self.assertEqual(calls, [("recovery", 1), ("direct", 1), ("relay", 1), ("relay", 2)])
        self.assertEqual(reports["recovery"], Path("/private/recovery-generation-1-report.json"))
        self.assertEqual(reports["direct"], Path("/private/direct-generation-1-report.json"))
        self.assertEqual(reports["relay"], Path("/private/relay-generation-2-report.json"))

    def test_phase_run_ids_are_deterministic_distinct_and_attempt_bound(self) -> None:
        release = "a" * 64
        values = set()
        for generation in range(1, 4):
            values.add(JOURNEY.phase_run_id(release, generation, "recovery", generation, 0))
            for phase in ("direct", "relay"):
                for attempt in range((generation - 1) * 3 + 1, generation * 3 + 1):
                    for index in range(3):
                        values.add(JOURNEY.phase_run_id(release, generation, phase, attempt, index))
        self.assertEqual(len(values), 57)
        self.assertTrue(all(len(value) == 16 for value in values))
        self.assertEqual(
            JOURNEY.phase_run_id(release, 2, "direct", 4, 1),
            JOURNEY.phase_run_id(release, 2, "direct", 4, 1),
        )


if __name__ == "__main__":
    unittest.main()
