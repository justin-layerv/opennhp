from __future__ import annotations

import copy
import importlib.util
import json
import os
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
PATH = ROOT / "terraform/modules/compute/lambda/server_candidate_termination_cleanup.py"


class ClientError(Exception):
    def __init__(self, response: dict, operation_name: str) -> None:
        super().__init__(response.get("Error", {}).get("Message", operation_name))
        self.response = response
        self.operation_name = operation_name


class BotoCoreError(Exception):
    pass


class BootstrapDDB:
    def resource(self, name: str):
        if name != "dynamodb":
            raise AssertionError(name)
        return self

    def client(self, name: str):
        if name not in {"autoscaling", "ec2", "servicediscovery"}:
            raise AssertionError(name)
        return self


bootstrap = BootstrapDDB()
fake_boto3 = types.ModuleType("boto3")
fake_boto3.resource = bootstrap.resource
fake_boto3.client = bootstrap.client
previous_boto3 = sys.modules.get("boto3")
previous_botocore = sys.modules.get("botocore")
previous_botocore_exceptions = sys.modules.get("botocore.exceptions")
sys.modules["boto3"] = fake_boto3
fake_botocore = types.ModuleType("botocore")
fake_botocore_exceptions = types.ModuleType("botocore.exceptions")
fake_botocore_exceptions.BotoCoreError = BotoCoreError
fake_botocore_exceptions.ClientError = ClientError
fake_botocore.exceptions = fake_botocore_exceptions
sys.modules["botocore"] = fake_botocore
sys.modules["botocore.exceptions"] = fake_botocore_exceptions
os.environ["AC_ASSIGNMENTS_TABLE"] = "candidate-assignments"
os.environ["CLOUDMAP_SERVICE_ID"] = "srv-candidate"
try:
    spec = importlib.util.spec_from_file_location("candidate_cleanup", PATH)
    assert spec and spec.loader
    CLEANUP = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(CLEANUP)
finally:
    if previous_boto3 is None:
        del sys.modules["boto3"]
    else:
        sys.modules["boto3"] = previous_boto3
    if previous_botocore is None:
        del sys.modules["botocore"]
    else:
        sys.modules["botocore"] = previous_botocore
    if previous_botocore_exceptions is None:
        del sys.modules["botocore.exceptions"]
    else:
        sys.modules["botocore.exceptions"] = previous_botocore_exceptions


def row(ac_id: str = "ac-1", version: int = 3) -> dict:
    return {
        "ac_id": ac_id,
        "version": version,
        "assigned_servers": [
            {
                "id": "green-old",
                "internal_ip": "10.0.1.2",
                "port": 62206,
                "http_port": 8888,
                "pub_key": "server-key",
            },
            {"id": "green-live", "internal_ip": "10.0.1.3", "port": 62206},
        ],
    }


def conflict() -> ClientError:
    return ClientError(
        {"Error": {"Code": "ConditionalCheckFailedException", "Message": "raced"}},
        "UpdateItem",
    )


class FakeTable:
    def __init__(self, rows: list[dict], operations: list[str]) -> None:
        self.rows = {item["ac_id"]: copy.deepcopy(item) for item in rows}
        self.operations = operations
        self.conflicts = 0
        self.scan_error: Exception | None = None
        self.update_calls = 0
        self.delete_calls = 0
        self.put_calls = 0
        self.scan_calls = 0
        self.strong_reads = 0
        self.remove_on_last_conflict = False
        self.scan_hooks: dict[int, object] = {}
        self.page_size: int | None = None
        self.late_write_attempts = 0

    def put_item(self, **request):
        self.put_calls += 1
        self.operations.append("fence")
        item = copy.deepcopy(request["Item"])
        key = item["ac_id"]
        if key in self.rows:
            raise conflict()
        if request.get("ConditionExpression") != "attribute_not_exists(ac_id)":
            raise AssertionError("termination fence must use create-only authority")
        self.rows[key] = item

    def scan(self, **request):
        self.scan_calls += 1
        self.operations.append(f"scan-{self.scan_calls}")
        if self.scan_error:
            raise self.scan_error
        if request.get("ConsistentRead") is not True:
            raise AssertionError("candidate cleanup scan must be strong")
        hook = self.scan_hooks.get(self.scan_calls)
        if hook is not None:
            hook()
        keys = sorted(self.rows)
        start = request.get("ExclusiveStartKey")
        start_index = 0 if start is None else keys.index(start["ac_id"]) + 1
        page_keys = keys[start_index:]
        if self.page_size is not None:
            page_keys = page_keys[: self.page_size]
        response = {"Items": [copy.deepcopy(self.rows[key]) for key in page_keys]}
        if page_keys and start_index + len(page_keys) < len(keys):
            response["LastEvaluatedKey"] = {"ac_id": page_keys[-1]}
        return response

    def attempt_late_route_write(self, ac_id: str, server_id: str) -> None:
        self.late_write_attempts += 1
        if CLEANUP.FENCE_PREFIX + server_id in self.rows:
            return
        assignment = self.rows.setdefault(ac_id, row(ac_id, 1))
        assignment["assigned_servers"].append({"id": server_id, "internal_ip": "10.0.9.9", "port": 62206})
        raise AssertionError("late candidate route crossed the termination fence")

    def get_item(self, **request):
        if request.get("ConsistentRead") is not True:
            raise AssertionError("conflict reconciliation must be strong")
        self.strong_reads += 1
        item = self.rows.get(request["Key"]["ac_id"])
        return {} if item is None else {"Item": copy.deepcopy(item)}

    def update_item(self, **request):
        self.update_calls += 1
        ac_id = request["Key"]["ac_id"]
        if self.conflicts:
            self.conflicts -= 1
            # Model a concurrent sibling update that preserves the terminating
            # server but advances the exact row version.
            if self.remove_on_last_conflict and self.conflicts == 0:
                self.rows[ac_id]["assigned_servers"] = [
                    server
                    for server in self.rows[ac_id]["assigned_servers"]
                    if server["id"] != "green-old"
                ]
            else:
                self.rows[ac_id]["version"] += 1
            raise conflict()
        values = request["ExpressionAttributeValues"]
        current = self.rows[ac_id]
        if current["version"] != values[":version"] or current["assigned_servers"] != values[":assigned"]:
            raise conflict()
        current["assigned_servers"] = copy.deepcopy(values[":remaining"])
        current["version"] = values[":next"]
        current["reassigned_at"] = values[":now"]

    def delete_item(self, **request):
        self.delete_calls += 1
        ac_id = request["Key"]["ac_id"]
        values = request["ExpressionAttributeValues"]
        current = self.rows[ac_id]
        if current["version"] != values[":version"] or current["assigned_servers"] != values[":assigned"]:
            raise conflict()
        del self.rows[ac_id]


class FakeDDB:
    def __init__(self, table: FakeTable) -> None:
        self.table = table
        self.requested: list[str] = []

    def Table(self, name: str):
        self.requested.append(name)
        if name != "candidate-assignments":
            raise AssertionError(f"cleanup opened unexpected table {name}")
        return self.table


class FakeASG:
    def __init__(self, operations: list[str]) -> None:
        self.operations = operations
        self.completions: list[dict] = []
        self.before_complete = None
        self.commit_then_fail = False
        self.no_active_lifecycle = False

    def complete_lifecycle_action(self, **request):
        if self.before_complete is not None:
            self.before_complete()
        self.operations.append("complete")
        self.completions.append(request)
        if self.no_active_lifecycle:
            raise ClientError(
                {"Error": {"Code": "ValidationError", "Message": "No active Lifecycle Action found"}},
                "CompleteLifecycleAction",
            )
        if self.commit_then_fail:
            raise BotoCoreError("completion response lost")


class FakeEC2:
    def __init__(self, operations: list[str]) -> None:
        self.operations = operations
        self.results: list[object] = [("green-old", "terminated")]
        self.describe_calls = 0

    def describe_instances(self, **request):
        self.operations.append("describe")
        self.describe_calls += 1
        if request != {"InstanceIds": ["green-old"]}:
            raise AssertionError(request)
        result = self.results.pop(0) if len(self.results) > 1 else self.results[0]
        if isinstance(result, BaseException):
            raise result
        if result is None:
            return {"Reservations": []}
        instance_id, state = result
        return {
            "Reservations": [{"Instances": [{"InstanceId": instance_id, "State": {"Name": state}}]}]
        }


class FakeCloudMap:
    def __init__(self, operations: list[str]) -> None:
        self.operations = operations
        self.instances = {"green-old"}
        self.deregister_calls: list[dict] = []
        self.get_instance_calls = 0
        self.operation_statuses = ["SUCCESS"]
        self.commit_then_fail = False

    def deregister_instance(self, **request):
        self.operations.append("deregister")
        self.deregister_calls.append(request)
        self.instances.discard(request["InstanceId"])
        if self.commit_then_fail:
            raise ClientError({"Error": {"Code": "RequestTimeout"}}, "DeregisterInstance")
        return {"OperationId": "op-1"}

    def get_operation(self, **request):
        self.operations.append("deregister-read")
        if request != {"OperationId": "op-1"}:
            raise AssertionError(request)
        status = self.operation_statuses.pop(0) if len(self.operation_statuses) > 1 else self.operation_statuses[0]
        return {"Operation": {"Status": status}}

    def get_instance(self, **request):
        self.get_instance_calls += 1
        if request != {"ServiceId": "srv-candidate", "InstanceId": "green-old"}:
            raise AssertionError(request)
        if request["InstanceId"] not in self.instances:
            raise ClientError({"Error": {"Code": "InstanceNotFound"}}, "GetInstance")
        return {"Instance": {"Id": request["InstanceId"]}}


def event() -> dict:
    return {
        "detail": {
            "LifecycleHookName": "candidate-termination",
            "AutoScalingGroupName": "candidate-asg",
            "LifecycleActionToken": "token",
            "EC2InstanceId": "green-old",
        }
    }


class CandidateTerminationCleanupTest(unittest.TestCase):
    def setUp(self) -> None:
        self.operations: list[str] = []
        self.table = FakeTable([row(), row("ac-only", 8)], self.operations)
        self.table.rows["ac-only"]["assigned_servers"] = [
            {"id": "green-old", "internal_ip": "10.0.1.2", "port": 62206}
        ]
        self.ddb = FakeDDB(self.table)
        self.asg = FakeASG(self.operations)
        self.ec2 = FakeEC2(self.operations)
        self.cloudmap = FakeCloudMap(self.operations)
        CLEANUP.DDB = self.ddb
        CLEANUP.ASG = self.asg
        CLEANUP.EC2 = self.ec2
        CLEANUP.CLOUDMAP = self.cloudmap

    def test_removes_candidate_routes_then_completes_lifecycle(self) -> None:
        active = {
            "ac-1": {
                "revoked_pubkeys": {"key-a"},
                "assigned_servers": [{"id": "blue-live"}],
            }
        }
        before = copy.deepcopy(active)
        result = CLEANUP.handler(event(), None)
        self.assertEqual(result, {"updated": 1, "deleted": 1, "unchanged": 0})
        self.assertEqual([server["id"] for server in self.table.rows["ac-1"]["assigned_servers"]], ["green-live"])
        self.assertNotIn("ac-only", self.table.rows)
        self.assertEqual(active, before, "candidate cleanup altered active revocation authority")
        self.assertEqual(self.ddb.requested, ["candidate-assignments"])
        self.assertEqual(len(self.asg.completions), 1)
        self.assertEqual(
            self.operations,
            [
                "fence",
                "deregister",
                "deregister-read",
                "scan-1",
                "scan-2",
                "complete",
                "describe",
                "deregister",
                "deregister-read",
            ],
        )
        self.assertNotIn("green-old", self.cloudmap.instances)

    def test_conditional_race_strongly_rereads_and_converges(self) -> None:
        self.table.conflicts = 2
        result = CLEANUP.handler(event(), None)
        self.assertEqual(result["updated"], 1)
        self.assertEqual(self.table.strong_reads, 2)
        self.assertEqual([server["id"] for server in self.table.rows["ac-1"]["assigned_servers"]], ["green-live"])
        self.assertEqual(len(self.asg.completions), 1)

    def test_scan_failure_does_not_release_termination(self) -> None:
        self.table.scan_error = RuntimeError("injected scan failure")
        with self.assertRaisesRegex(RuntimeError, "injected scan failure"):
            CLEANUP.handler(event(), None)
        self.assertEqual(self.asg.completions, [])

    def test_nonconvergent_race_does_not_release_termination(self) -> None:
        self.table.conflicts = CLEANUP.MAX_CONFLICT_ATTEMPTS
        with self.assertRaisesRegex(RuntimeError, "did not converge"):
            CLEANUP.handler(event(), None)
        self.assertEqual(self.asg.completions, [])

    def test_final_conflict_strong_reread_accepts_sibling_cleanup(self) -> None:
        self.table.rows = {"ac-1": row()}
        self.table.conflicts = CLEANUP.MAX_CONFLICT_ATTEMPTS
        self.table.remove_on_last_conflict = True
        result = CLEANUP.handler(event(), None)
        self.assertEqual(result, {"updated": 0, "deleted": 0, "unchanged": 1})
        self.assertEqual(self.table.strong_reads, CLEANUP.MAX_CONFLICT_ATTEMPTS)
        self.assertEqual(
            [server["id"] for server in self.table.rows["ac-1"]["assigned_servers"]],
            ["green-live"],
        )
        self.assertEqual(len(self.asg.completions), 1)

    def test_malformed_candidate_row_fails_closed_without_touching_active(self) -> None:
        self.table.rows["ac-1"]["assigned_servers"][0]["unexpected"] = "route"
        with self.assertRaisesRegex(RuntimeError, "malformed server"):
            CLEANUP.handler(event(), None)
        self.assertEqual(self.table.update_calls, 0)
        self.assertEqual(self.table.delete_calls, 0)
        self.assertEqual(self.asg.completions, [])

    def test_exact_fence_replay_is_idempotent(self) -> None:
        expected = CLEANUP._fence_item(event()["detail"])
        self.table.rows[expected["ac_id"]] = expected
        result = CLEANUP.handler(event(), None)
        self.assertEqual(result, {"updated": 1, "deleted": 1, "unchanged": 0})
        self.assertEqual(self.table.strong_reads, 1)
        self.assertEqual(len(self.cloudmap.deregister_calls), 2)
        self.assertEqual(len(self.asg.completions), 1)

    def test_conflicting_fence_fails_before_deregistration_or_scan(self) -> None:
        malformed = CLEANUP._fence_item(event()["detail"])
        malformed["hook_name"] = "other-hook"
        self.table.rows[malformed["ac_id"]] = malformed
        with self.assertRaisesRegex(RuntimeError, "fence is malformed or conflicts"):
            CLEANUP.handler(event(), None)
        self.assertEqual(self.cloudmap.deregister_calls, [])
        self.assertEqual(self.table.scan_calls, 0)
        self.assertEqual(self.asg.completions, [])

    def test_cloudmap_deregistration_failure_holds_lifecycle(self) -> None:
        self.cloudmap.operation_statuses = ["FAIL"]
        with self.assertRaisesRegex(RuntimeError, "deregistration failed"):
            CLEANUP.handler(event(), None)
        self.assertIn(CLEANUP.FENCE_PREFIX + "green-old", self.table.rows)
        self.assertEqual(self.table.scan_calls, 0)
        self.assertEqual(self.asg.completions, [])

    def test_cloudmap_lost_response_is_classified_by_exact_absence(self) -> None:
        self.cloudmap.commit_then_fail = True
        result = CLEANUP.handler(event(), None)
        self.assertEqual(result, {"updated": 1, "deleted": 1, "unchanged": 0})
        self.assertGreaterEqual(self.cloudmap.get_instance_calls, 2)
        self.assertEqual(len(self.asg.completions), 1)

    def test_reregistration_before_completion_and_during_cleanup_is_removed_only_after_terminal(self) -> None:
        for boundary in ("cleanup", "completion"):
            with self.subTest(boundary=boundary):
                self.setUp()
                if boundary == "cleanup":
                    self.table.scan_hooks[1] = lambda: self.cloudmap.instances.add("green-old")
                else:
                    self.asg.before_complete = lambda: self.cloudmap.instances.add("green-old")
                result = CLEANUP.handler(event(), None)
                self.assertEqual(result, {"updated": 1, "deleted": 1, "unchanged": 0})
                self.assertEqual(len(self.cloudmap.deregister_calls), 2)
                self.assertNotIn("green-old", self.cloudmap.instances)
                self.assertLess(self.operations.index("describe"), len(self.operations) - 2)
                self.assertEqual(self.operations[-2:], ["deregister", "deregister-read"])

    def test_lost_completion_response_retries_to_terminal_then_final_absence(self) -> None:
        self.asg.commit_then_fail = True
        self.asg.before_complete = lambda: self.cloudmap.instances.add("green-old")
        self.ec2.results = [("green-old", "shutting-down")]
        with (
            patch.object(CLEANUP, "MAX_TERMINATION_READS", 2),
            patch.object(CLEANUP.time, "sleep"),
            self.assertRaisesRegex(RuntimeError, "completion could not be classified"),
        ):
            CLEANUP.handler(event(), None)
        self.assertIn("green-old", self.cloudmap.instances)
        self.assertEqual(len(self.cloudmap.deregister_calls), 1)

        self.asg.commit_then_fail = False
        self.asg.no_active_lifecycle = True
        self.asg.before_complete = None
        self.ec2.results = [("green-old", "terminated")]
        result = CLEANUP.handler(event(), None)
        self.assertEqual(result, {"updated": 0, "deleted": 0, "unchanged": 1})
        self.assertNotIn("green-old", self.cloudmap.instances)
        self.assertEqual(len(self.cloudmap.deregister_calls), 3)

    def test_terminal_read_retries_transport_wrong_instance_and_nonterminal_state(self) -> None:
        self.ec2.results = [
            BotoCoreError("EC2 transport failed"),
            ("wrong-instance", "terminated"),
            ("green-old", "running"),
            ("green-old", "terminated"),
        ]
        with patch.object(CLEANUP.time, "sleep") as sleep:
            result = CLEANUP.handler(event(), None)
        self.assertEqual(result, {"updated": 1, "deleted": 1, "unchanged": 0})
        self.assertEqual(self.ec2.describe_calls, 4)
        self.assertEqual(sleep.call_count, 3)
        self.assertNotIn("green-old", self.cloudmap.instances)

    def test_malformed_unrelated_fence_row_fails_final_scan_closed(self) -> None:
        self.table.rows[CLEANUP.FENCE_PREFIX + "other"] = {
            "ac_id": CLEANUP.FENCE_PREFIX + "other",
            "kind": CLEANUP.FENCE_KIND,
            "schema": 1,
            "server_id": "other",
            "asg_name": "candidate-asg",
            "hook_name": "candidate-termination",
            "token_sha256": "not-a-digest",
        }
        with self.assertRaisesRegex(RuntimeError, "fence row is malformed"):
            CLEANUP.handler(event(), None)
        self.assertEqual(self.asg.completions, [])

    def test_late_writes_at_scan_page_verification_and_completion_are_fenced(self) -> None:
        self.table.page_size = 1
        for call in (1, 2, 4):
            self.table.scan_hooks[call] = lambda: self.table.attempt_late_route_write("late-ac", "green-old")
        self.asg.before_complete = lambda: self.table.attempt_late_route_write("late-complete", "green-old")
        result = CLEANUP.handler(event(), None)
        self.assertEqual(result, {"updated": 1, "deleted": 1, "unchanged": 0})
        self.assertEqual(self.table.late_write_attempts, 4)
        self.assertNotIn("late-ac", self.table.rows)
        self.assertNotIn("late-complete", self.table.rows)
        self.assertGreaterEqual(self.table.scan_calls, 4)
        self.assertEqual(len(self.asg.completions), 1)

    def test_queue_and_lambda_destination_events_replay_exact_cleanup(self) -> None:
        for wrapped in (
            {"Records": [{"eventSource": "aws:sqs", "body": json.dumps(event())}]},
            {"requestPayload": event()},
        ):
            with self.subTest(wrapped=next(iter(wrapped))):
                self.setUp()
                result = CLEANUP.handler(wrapped, None)
                self.assertEqual(result, {"updated": 1, "deleted": 1, "unchanged": 0})
                self.assertEqual(len(self.asg.completions), 1)


if __name__ == "__main__":
    unittest.main()
