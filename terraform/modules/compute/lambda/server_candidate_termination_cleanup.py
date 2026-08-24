"""Fence and remove a terminating candidate server from candidate authority."""

import hashlib
import json
import logging
import os
import time

import boto3
from botocore.exceptions import BotoCoreError, ClientError


LOGGER = logging.getLogger()
LOGGER.setLevel(logging.INFO)
TABLE_NAME = os.environ["AC_ASSIGNMENTS_TABLE"]
DDB = boto3.resource("dynamodb")
ASG = boto3.client("autoscaling")
CLOUDMAP = boto3.client("servicediscovery")
EC2 = boto3.client("ec2")
MAX_CONFLICT_ATTEMPTS = 5
MAX_DEREGISTER_READS = 20
MAX_TERMINATION_READS = 100
TERMINATION_READ_INTERVAL_SECONDS = 0.5
FENCE_PREFIX = "__server_termination__#"
FENCE_KIND = "SERVER_TERMINATION_FENCE"
FENCE_KEYS = {
    "ac_id",
    "kind",
    "schema",
    "server_id",
    "asg_name",
    "hook_name",
    "token_sha256",
}
CLOUDMAP_SERVICE_ID = os.environ["CLOUDMAP_SERVICE_ID"]


def _assigned_server_id(server):
    if not isinstance(server, dict) or set(server) - {
        "id",
        "ip",
        "internal_ip",
        "az",
        "port",
        "http_port",
        "pub_key",
        "asg_name",
    }:
        raise RuntimeError("candidate assignment contains a malformed server")
    server_id = server.get("id")
    if not isinstance(server_id, str) or not server_id:
        raise RuntimeError("candidate assignment contains a malformed server id")
    return server_id


def _validate_item(item, expected_ac_id=None):
    if not isinstance(item, dict):
        raise RuntimeError("candidate assignment is not an object")
    ac_id = item.get("ac_id")
    if not isinstance(ac_id, str) or not ac_id or (expected_ac_id is not None and ac_id != expected_ac_id):
        raise RuntimeError("candidate assignment has an invalid ac_id")
    version = item.get("version")
    if isinstance(version, bool) or not isinstance(version, int) or version < 1:
        raise RuntimeError(f"assignment {ac_id} has invalid version")
    assigned = item.get("assigned_servers")
    if not isinstance(assigned, list) or not assigned:
        raise RuntimeError(f"assignment {ac_id} has invalid assigned_servers")
    server_ids = [_assigned_server_id(server) for server in assigned]
    if len(server_ids) != len(set(server_ids)):
        raise RuntimeError(f"assignment {ac_id} contains duplicate servers")
    return ac_id, version, assigned


def _strong_assignment(table, ac_id):
    response = table.get_item(
        Key={"ac_id": ac_id},
        ConsistentRead=True,
        ProjectionExpression="ac_id, assigned_servers, #version",
        ExpressionAttributeNames={"#version": "version"},
    )
    item = response.get("Item")
    if item is None:
        return None
    _validate_item(item, ac_id)
    return item


def _fence_item(detail):
    instance_id = detail["EC2InstanceId"]
    return {
        "ac_id": FENCE_PREFIX + instance_id,
        "kind": FENCE_KIND,
        "schema": 1,
        "server_id": instance_id,
        "asg_name": detail["AutoScalingGroupName"],
        "hook_name": detail["LifecycleHookName"],
        "token_sha256": hashlib.sha256(detail["LifecycleActionToken"].encode()).hexdigest(),
    }


def _validate_fence(item, expected):
    if not isinstance(item, dict) or set(item) != set(expected) or item != expected:
        raise RuntimeError("candidate termination fence is malformed or conflicts with this lifecycle action")
    return item


def _install_fence(table, detail):
    expected = _fence_item(detail)
    try:
        table.put_item(
            Item=expected,
            ConditionExpression="attribute_not_exists(ac_id)",
        )
    except ClientError as error:
        if error.response.get("Error", {}).get("Code") != "ConditionalCheckFailedException":
            raise
        response = table.get_item(Key={"ac_id": expected["ac_id"]}, ConsistentRead=True)
        _validate_fence(response.get("Item"), expected)
    return expected


def _is_fence(item):
    if not isinstance(item, dict):
        return False
    ac_id = item.get("ac_id")
    if not isinstance(ac_id, str) or not ac_id.startswith(FENCE_PREFIX):
        return False
    if set(item) != FENCE_KEYS or item.get("kind") != FENCE_KIND or item.get("schema") != 1:
        raise RuntimeError("candidate termination fence row is malformed")
    server_id = item.get("server_id")
    if (
        not isinstance(server_id, str)
        or not server_id
        or ac_id != FENCE_PREFIX + server_id
        or any(not isinstance(item.get(key), str) or not item[key] for key in ("asg_name", "hook_name"))
        or not isinstance(item.get("token_sha256"), str)
        or len(item["token_sha256"]) != 64
        or any(character not in "0123456789abcdef" for character in item["token_sha256"])
    ):
        raise RuntimeError("candidate termination fence row is malformed")
    return True


def _remove_server(table, item, instance_id):
    ac_id, version, assigned = _validate_item(item)
    for attempt in range(MAX_CONFLICT_ATTEMPTS):
        remaining = [server for server in assigned if _assigned_server_id(server) != instance_id]
        if len(remaining) == len(assigned):
            return "unchanged"
        condition = "#version = :version AND assigned_servers = :assigned"
        names = {"#version": "version"}
        values = {":version": version, ":assigned": assigned}
        try:
            if not remaining:
                table.delete_item(
                    Key={"ac_id": ac_id},
                    ConditionExpression=condition,
                    ExpressionAttributeNames=names,
                    ExpressionAttributeValues=values,
                )
                return "deleted"
            values.update({":remaining": remaining, ":next": version + 1, ":now": int(time.time())})
            table.update_item(
                Key={"ac_id": ac_id},
                ConditionExpression=condition,
                UpdateExpression="SET assigned_servers = :remaining, #version = :next, reassigned_at = :now",
                ExpressionAttributeNames=names,
                ExpressionAttributeValues=values,
            )
            return "updated"
        except ClientError as error:
            if error.response.get("Error", {}).get("Code") != "ConditionalCheckFailedException":
                raise
            current = _strong_assignment(table, ac_id)
            if current is None:
                return "deleted"
            ac_id, version, assigned = _validate_item(current, ac_id)
            if all(_assigned_server_id(server) != instance_id for server in assigned):
                return "unchanged"
            if attempt + 1 == MAX_CONFLICT_ATTEMPTS:
                raise RuntimeError(f"assignment {ac_id} did not converge after conditional races") from error
    raise AssertionError("unreachable conflict loop")


def _scan(table, instance_id, remove):
    start = None
    totals = {"updated": 0, "deleted": 0, "unchanged": 0}
    while True:
        request = {
            "ProjectionExpression": (
                "ac_id, assigned_servers, #version, #kind, #schema, "
                "server_id, asg_name, hook_name, token_sha256"
            ),
            "ExpressionAttributeNames": {
                "#kind": "kind",
                "#schema": "schema",
                "#version": "version",
            },
            "ConsistentRead": True,
        }
        if start is not None:
            request["ExclusiveStartKey"] = start
        response = table.scan(**request)
        for item in response.get("Items", []):
            if _is_fence(item):
                continue
            if remove:
                outcome = _remove_server(table, item, instance_id)
                if outcome in totals:
                    totals[outcome] += 1
            else:
                _, _, assigned = _validate_item(item)
                if any(_assigned_server_id(server) == instance_id for server in assigned):
                    raise RuntimeError("candidate assignment still references the fenced server")
        start = response.get("LastEvaluatedKey")
        if not start:
            return totals


def _cleanup(table, instance_id):
    totals = _scan(table, instance_id, True)
    # The fence is already committed, so every runtime Put that contains this
    # server fails its same-transaction ConditionCheck. This second full strong
    # scan is verification, not a timing heuristic: no late writer can cross
    # the fence between either scan or lifecycle completion.
    _scan(table, instance_id, False)
    return totals


def _instance_absent(instance_id):
    try:
        CLOUDMAP.get_instance(ServiceId=CLOUDMAP_SERVICE_ID, InstanceId=instance_id)
    except ClientError as error:
        if error.response.get("Error", {}).get("Code") == "InstanceNotFound":
            return True
        raise
    return False


def _deregister(instance_id):
    try:
        response = CLOUDMAP.deregister_instance(ServiceId=CLOUDMAP_SERVICE_ID, InstanceId=instance_id)
    except (BotoCoreError, ClientError):
        if _instance_absent(instance_id):
            return
        raise
    operation_id = response.get("OperationId")
    if not isinstance(operation_id, str) or not operation_id:
        if _instance_absent(instance_id):
            return
        raise RuntimeError("Cloud Map deregistration returned no operation identity")
    for attempt in range(MAX_DEREGISTER_READS):
        operation = CLOUDMAP.get_operation(OperationId=operation_id).get("Operation")
        if not isinstance(operation, dict):
            raise RuntimeError("Cloud Map deregistration operation is malformed")
        status = operation.get("Status")
        if status == "SUCCESS":
            if _instance_absent(instance_id):
                return
            raise RuntimeError("Cloud Map deregistration succeeded but the server is still selectable")
        if status == "FAIL":
            raise RuntimeError("Cloud Map deregistration failed")
        if status not in ("SUBMITTED", "PENDING"):
            raise RuntimeError("Cloud Map deregistration returned an unknown status")
        if attempt + 1 < MAX_DEREGISTER_READS:
            time.sleep(0.25)
    raise RuntimeError("Cloud Map deregistration did not converge")


def _instance_state(instance_id):
    response = EC2.describe_instances(InstanceIds=[instance_id])
    reservations = response.get("Reservations") if isinstance(response, dict) else None
    if not isinstance(reservations, list):
        raise RuntimeError("EC2 termination read is malformed")
    instances = []
    for reservation in reservations:
        if not isinstance(reservation, dict) or not isinstance(reservation.get("Instances"), list):
            raise RuntimeError("EC2 termination read is malformed")
        instances.extend(reservation["Instances"])
    if len(instances) != 1 or not isinstance(instances[0], dict) or instances[0].get("InstanceId") != instance_id:
        raise RuntimeError("EC2 termination read did not return the exact candidate server")
    state = instances[0].get("State")
    name = state.get("Name") if isinstance(state, dict) else None
    if name not in {"pending", "running", "shutting-down", "terminated", "stopping", "stopped"}:
        raise RuntimeError("EC2 termination read returned an unknown state")
    return name


def _wait_instance_terminal(instance_id):
    last_error = None
    for attempt in range(MAX_TERMINATION_READS):
        try:
            if _instance_state(instance_id) == "terminated":
                return
            last_error = RuntimeError("candidate server is not terminal")
        except ClientError as error:
            if error.response.get("Error", {}).get("Code") == "InvalidInstanceID.NotFound":
                return
            last_error = error
        except BotoCoreError as error:
            last_error = error
        except RuntimeError as error:
            last_error = error
        if attempt + 1 < MAX_TERMINATION_READS:
            time.sleep(TERMINATION_READ_INTERVAL_SECONDS)
    raise RuntimeError(f"candidate server termination did not converge: {last_error}") from last_error


def _complete_and_wait(detail):
    completion_error = None
    try:
        ASG.complete_lifecycle_action(
            LifecycleHookName=detail["LifecycleHookName"],
            AutoScalingGroupName=detail["AutoScalingGroupName"],
            LifecycleActionToken=detail["LifecycleActionToken"],
            LifecycleActionResult="CONTINUE",
            InstanceId=detail["EC2InstanceId"],
        )
    except (BotoCoreError, ClientError) as error:
        if isinstance(error, ClientError):
            code = error.response.get("Error", {}).get("Code")
            message = error.response.get("Error", {}).get("Message", "")
            if code == "ValidationError" and "No active Lifecycle Action" in message:
                error = None
        completion_error = error
    try:
        _wait_instance_terminal(detail["EC2InstanceId"])
    except BaseException as error:  # noqa: BLE001 - retain the ambiguous completion cause for retry diagnosis
        if completion_error is not None:
            raise RuntimeError(
                f"candidate lifecycle completion could not be classified before terminal state: {error}"
            ) from completion_error
        raise


def _unwrap_event(event):
    if not isinstance(event, dict):
        raise ValueError("candidate termination event is not an object")
    if "Records" in event:
        records = event.get("Records")
        if not isinstance(records, list) or len(records) != 1:
            raise ValueError("candidate termination SQS batch must contain exactly one record")
        record = records[0]
        if not isinstance(record, dict) or record.get("eventSource") != "aws:sqs" or not isinstance(record.get("body"), str):
            raise ValueError("candidate termination SQS record is malformed")
        try:
            event = json.loads(record["body"])
        except json.JSONDecodeError as error:
            raise ValueError("candidate termination SQS body is malformed") from error
        if not isinstance(event, dict):
            raise ValueError("candidate termination SQS body is not an object")
    if "requestPayload" in event:
        event = event["requestPayload"]
        if not isinstance(event, dict):
            raise ValueError("candidate termination destination payload is malformed")
    detail = event.get("detail") if "detail" in event else event
    return detail


def handler(event, _context):
    detail = _unwrap_event(event)
    required = {
        "LifecycleHookName",
        "AutoScalingGroupName",
        "LifecycleActionToken",
        "EC2InstanceId",
    }
    if not isinstance(detail, dict) or not required.issubset(detail):
        raise ValueError("candidate termination event is incomplete")
    if any(not isinstance(detail[key], str) or not detail[key] for key in required):
        raise ValueError("candidate termination event fields must be non-empty strings")
    table = DDB.Table(TABLE_NAME)
    _install_fence(table, detail)
    _deregister(detail["EC2InstanceId"])
    totals = _cleanup(table, detail["EC2InstanceId"])
    LOGGER.info("candidate assignment cleanup: %s", json.dumps(totals, sort_keys=True))
    # Do not release the termination hook on a scan, shape, or convergence
    # failure. The direct lifecycle queue and EventBridge/Lambda retry paths own
    # recovery; acknowledging a failed cleanup would strand a dead candidate
    # server in an addressable route.
    _complete_and_wait(detail)
    # A server can re-register itself while Terminating:Wait. Only the exact
    # terminal EC2 read above proves that another registration is impossible;
    # this final deregistration and absence read close that last-writer seam.
    _deregister(detail["EC2InstanceId"])
    return totals
