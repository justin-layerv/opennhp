from __future__ import annotations

import hashlib
import json
import queue
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from typing import Callable
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
SCRIPT_DIR = ROOT / ".github/scripts"
sys.path.insert(0, str(SCRIPT_DIR))
import prod_matched_cohort_control as CONTROL  # noqa: E402


def ingress(group: str, identity: str, protocol: str, port: int, description: str) -> dict:
    return {
        "security_group_id": group,
        "security_group_rule_id": identity,
        "description": description,
        "ip_protocol": protocol,
        "from_port": port,
        "to_port": port,
        "open_cidr_ipv4": "0.0.0.0/0",
    }


def target_group(name: str) -> str:
    return f"arn:aws:elasticloadbalancing:us-east-2:111122223333:targetgroup/{name}/0123456789abcdef"


def fleet(name: str, image_parameter: str, target_groups: list[str], *, desired: int = 2) -> dict:
    return {
        "asg_name": f"{name}-asg",
        "min_size": desired,
        "max_size": 10,
        "desired_capacity": desired,
        "launch_template_id": f"lt-{hashlib.sha256(name.encode()).hexdigest()[:8]}",
        "launch_template_version": "7",
        "image_parameter": image_parameter,
        "image_tag": f"{name}-image-sha",
        "target_group_arns": sorted(target_groups),
    }


def contract() -> dict:
    server_blue = target_group("server-blue")
    server_candidate = target_group("server-candidate")
    server_smoke = target_group("server-candidate-smoke")
    ac_blue = target_group("ac-blue")
    ac_candidate = target_group("ac-candidate")
    ac_smoke = target_group("ac-candidate-smoke")
    ac_primary_blue = target_group("ac-frps-primary-blue")
    ac_primary_candidate = target_group("ac-frps-primary-candidate")
    ac_b_blue = target_group("ac-frps-b-blue")
    ac_b_candidate = target_group("ac-frps-b-candidate")
    relay_blue = target_group("relay-blue")
    relay_candidate = target_group("relay-candidate")
    return {
        "schema": 2,
        "environment": "prod",
        "server": {
            "canonical_endpoint": "server-public.example",
            "canonical_listener_arn": "arn:server-listener",
            "blue_target_group_arn": server_blue,
            "candidate_target_group_arn": server_candidate,
            "candidate_endpoint": "server-candidate.example",
            "candidate_listener_arn": "arn:server-candidate-listener",
            "candidate_smoke_target_group_arn": server_smoke,
            "blue_rollback": fleet(
                "server-blue",
                "/prod/nhp/server/image-tag",
                [server_blue, target_group("server-blue-registration"), target_group("server-blue-relay")],
            ),
            "candidate_authority": fleet(
                "server-candidate",
                "/prod/nhp/server/green-image-tag",
                [
                    server_candidate,
                    server_smoke,
                    target_group("server-candidate-registration"),
                    target_group("server-candidate-relay"),
                ],
            ),
            "active_assignment_table": "nhp-prod-ac-assignments",
            "candidate_assignment_table": "nhp-prod-ac-assignments-candidate",
            "candidate_cloudmap_service_arn": "arn:cloudmap:server-candidate",
            "blue_registration_endpoint": "server-blue.internal",
            "green_registration_endpoint": "server-green.internal",
        },
        "ac": {
            "canonical_endpoint": "ac-public.example",
            "canonical_listener_arn": "arn:ac-listener",
            "blue_target_group_arn": ac_blue,
            "candidate_target_group_arn": ac_candidate,
            "candidate_endpoint": "ac-candidate.example",
            "candidate_listener_arn": "arn:ac-candidate-listener",
            "candidate_smoke_target_group_arn": ac_smoke,
            "active_asg": "ac-active-asg",
            "blue_rollback": fleet(
                "ac-blue", "/prod/nhp/ac/image-tag", [ac_blue, ac_primary_blue, ac_b_blue]
            ),
            "candidate_authority": fleet(
                "ac-candidate",
                "/prod/nhp/ac/green-image-tag",
                [ac_candidate, ac_smoke, ac_primary_candidate, ac_b_candidate],
            ),
            "frps_selectors": {
                "primary": {
                    "canonical_listener_arn": "arn:ac-frps-primary-listener",
                    "blue_target_group_arn": ac_primary_blue,
                    "candidate_target_group_arn": ac_primary_candidate,
                    "candidate_listener_arn": "arn:ac-frps-primary-smoke-listener",
                    "listen_port": 7000,
                },
                "b": {
                    "canonical_listener_arn": "arn:ac-frps-b-listener",
                    "blue_target_group_arn": ac_b_blue,
                    "candidate_target_group_arn": ac_b_candidate,
                    "candidate_listener_arn": "arn:ac-frps-b-smoke-listener",
                    "listen_port": 7001,
                },
            },
        },
        "relay": {
            "canonical_rule_arn": "arn:relay-rule",
            "blue_target_group_arn": relay_blue,
            "candidate_target_group_arn": relay_candidate,
            "candidate_listener_arn": "arn:relay-candidate-listener",
            "candidate_rule_arn": "arn:relay-candidate-rule",
            "candidate_endpoint": "relay-candidate.example",
            "public_hostname": "relay.qurl.link.layerv.ai",
            "blue_rollback": fleet("relay-blue", "/prod/nhp/relay/image-tag", [relay_blue], desired=3),
            "candidate_authority": fleet(
                "relay-candidate", "/prod/nhp/relay/green-image-tag", [relay_candidate], desired=3
            ),
            "blue_server_endpoint": "server-blue-relay.internal",
            "green_server_endpoint": "server-green-relay.internal",
        },
        "maintenance": {
            "closed_cidr_ipv4": "192.0.2.255/32",
            "operator_lock_table": "nhp-prod-matched-cohort-operator-lock",
            "server_ingress_rules": {
                "nhp": ingress("sg-a1", "sgr-a1", "udp", 62206, "server public"),
            },
            "ac_ingress_rules": {
                "https": ingress("sg-b2", "sgr-b1", "tcp", 443, "ac https"),
                "frps_primary": ingress("sg-b2", "sgr-b2", "tcp", 7000, "ac frps primary"),
                "frps_b": ingress("sg-b2", "sgr-b3", "tcp", 7001, "ac frps b"),
                "http": ingress("sg-b2", "sgr-b4", "tcp", 80, "ac http"),
                "portal": ingress("sg-b2", "sgr-b5", "tcp", 8888, "ac portal"),
                "nhp_connector": ingress("sg-b2", "sgr-b6", "tcp", 4732, "ac connector"),
                "nhp_knock": ingress("sg-b2", "sgr-b7", "udp", 62206, "ac knock"),
            },
            "relay_rule": {
                "rule_arn": "arn:relay-maintenance",
                "open_path": "/__layerv_matched_cohort_maintenance_disabled__",
                "closed_path": "/relay/*",
                "methods": ["POST", "OPTIONS"],
                "status_code": "503",
                "content_type": "application/json",
                "message_body": '{"error":"maintenance"}',
            },
        },
    }


class FakeAws:
    def __init__(self, selector_state: str = "blue", gate_state: str = "open") -> None:
        self.contract = contract()
        self.selectors = {label: selector_state for label, _, _ in CONTROL.selector_units(self.contract)}
        self.gates = {
            **{f"server.{name}": gate_state for name in self.contract["maintenance"]["server_ingress_rules"]},
            **{f"ac.{name}": gate_state for name in self.contract["maintenance"]["ac_ingress_rules"]},
            "relay": gate_state,
        }
        self.calls: list[tuple[str, str, str]] = []
        self.fail_once: tuple[str, str, str] | None = None
        self.interrupt_once: tuple[str, str, str] | None = None
        self.commit_then_fail_once: tuple[str, str, str] | None = None
        self.started: queue.Queue[tuple[str, str, str]] | None = None
        self.release: threading.Event | None = None
        self.after_selector_mutation: Callable[[], None] | None = None
        self.after_gate_open: Callable[[], None] | None = None
        self.gate_read_failures_remaining = 0
        self._hook_lock = threading.Lock()
        self._selector_hook_ran = False
        self._gate_hook_ran = False
        self.operator_lock_item: dict | None = None
        self.lock_api_calls: list[str] = []
        self.lock_delete_commit_then_fail = False
        self.lock_delete_recreate_item: dict | None = None
        self.lock_idle_recreate_item: dict | None = None
        self.active_asg = {
            "AutoScalingGroupName": "ac-active-asg",
            "MinSize": 0,
            "MaxSize": 0,
            "DesiredCapacity": 0,
            "Instances": [],
            "SuspendedProcesses": [],
        }
        self.asgs: dict[str, dict] = {}
        self.target_health: dict[str, list[dict]] = {}
        self.image_tags: dict[str, str] = {}
        for label, authority in CONTROL.fleet_units(self.contract):
            launch_template = {
                "LaunchTemplateId": authority["launch_template_id"],
                "Version": authority["launch_template_version"],
            }
            instances = [
                {
                    "InstanceId": f"i-{label.replace('.', '-')}-{index}",
                    "LifecycleState": "InService",
                    "HealthStatus": "Healthy",
                    "LaunchTemplate": dict(launch_template),
                }
                for index in range(authority["desired_capacity"])
            ]
            self.asgs[authority["asg_name"]] = {
                "AutoScalingGroupName": authority["asg_name"],
                "MinSize": authority["min_size"],
                "MaxSize": authority["max_size"],
                "DesiredCapacity": authority["desired_capacity"],
                "SuspendedProcesses": [],
                "TargetGroupARNs": list(authority["target_group_arns"]),
                "LaunchTemplate": dict(launch_template),
                "Instances": instances,
            }
            self.image_tags[authority["image_parameter"]] = authority["image_tag"]
            for target_group_arn in authority["target_group_arns"]:
                self.target_health[target_group_arn] = [
                    {
                        "Target": {"Id": instance["InstanceId"]},
                        "TargetHealth": {"State": "healthy"},
                    }
                    for instance in instances
                ]
        self.blue_rollback_asg = self.asgs[self.contract["ac"]["blue_rollback"]["asg_name"]]
        self.blue_target_health = {
            target: self.target_health[target]
            for target in self.contract["ac"]["blue_rollback"]["target_group_arns"]
        }

    def _selector_for_arn(self, arn: str) -> tuple[str, dict]:
        for label, kind, part in CONTROL.selector_units(self.contract):
            key = "canonical_listener_arn" if kind == "listener" else "canonical_rule_arn"
            if part[key] == arn:
                return label, part
        raise AssertionError(arn)

    def _candidate_target(self, arn: str) -> str | None:
        for _, kind, part in CONTROL.selector_units(self.contract):
            key = "candidate_listener_arn" if kind == "listener" else "candidate_rule_arn"
            if part[key] == arn:
                return part.get("candidate_smoke_target_group_arn", part["candidate_target_group_arn"])
        return None

    def _maybe_fail(self, unit: tuple[str, str, str], commit: callable) -> None:
        self.calls.append(unit)
        if self.started is not None and self.release is not None:
            self.started.put(unit)
            if not self.release.wait(timeout=2):
                raise AssertionError("parallel mutation was not released")
        if self.fail_once == unit:
            self.fail_once = None
            raise CONTROL.ControlError("injected definite failure")
        if self.interrupt_once == unit:
            self.interrupt_once = None
            raise KeyboardInterrupt("injected cancellation")
        commit()
        if self.commit_then_fail_once == unit:
            self.commit_then_fail_once = None
            raise CONTROL.ControlError("injected lost response")

    def _maybe_fail_gate_read(self) -> None:
        with self._hook_lock:
            if self.gate_read_failures_remaining > 0:
                self.gate_read_failures_remaining -= 1
                raise CONTROL.ControlError("injected gate read failure")

    def _run_selector_hook(self) -> None:
        with self._hook_lock:
            if self._selector_hook_ran or self.after_selector_mutation is None:
                return
            self._selector_hook_ran = True
            hook = self.after_selector_mutation
        hook()

    def _run_gate_open_hook(self) -> None:
        with self._hook_lock:
            if self._gate_hook_ran or self.after_gate_open is None:
                return
            self._gate_hook_ran = True
            hook = self.after_gate_open
        hook()

    def __call__(self, command: list[str]) -> dict:
        action = command[2]
        if command[1] == "dynamodb":
            with self._hook_lock:
                self.lock_api_calls.append(action)
                if action == "get-item":
                    return {} if self.operator_lock_item is None else {
                        "Item": json.loads(json.dumps(self.operator_lock_item))
                    }
                if action == "put-item":
                    desired = json.loads(command[command.index("--item") + 1])
                    condition = command[command.index("--condition-expression") + 1]
                    if condition == "attribute_not_exists(lock_id)":
                        if self.operator_lock_item is not None:
                            raise CONTROL.ControlError("ConditionalCheckFailedException")
                    else:
                        values = json.loads(command[command.index("--expression-attribute-values") + 1])
                        expected = {key.removeprefix(":"): value for key, value in values.items()}
                        if self.operator_lock_item != expected:
                            raise CONTROL.ControlError("ConditionalCheckFailedException")
                    self.operator_lock_item = desired
                    if (
                        desired.get("state") == {"S": "idle"}
                        and self.lock_idle_recreate_item is not None
                    ):
                        self.operator_lock_item = json.loads(
                            json.dumps(self.lock_idle_recreate_item)
                        )
                    return {}
                if action == "delete-item":
                    values = json.loads(command[command.index("--expression-attribute-values") + 1])
                    current = self.operator_lock_item
                    if current is None or any(
                        current[key][kind] != values[value_key][kind]
                        for key, kind, value_key in (
                            ("release_id", "S", ":release"),
                            ("contract_sha256", "S", ":digest"),
                            ("schema", "N", ":schema"),
                            ("state", "S", ":state"),
                            ("operation", "S", ":operation"),
                            ("invocation_token", "S", ":token"),
                        )
                    ):
                        raise CONTROL.ControlError("ConditionalCheckFailedException")
                    self.operator_lock_item = None
                    if self.lock_delete_recreate_item is not None:
                        self.operator_lock_item = json.loads(json.dumps(self.lock_delete_recreate_item))
                    if self.lock_delete_commit_then_fail:
                        raise CONTROL.ControlError("injected lost delete response")
                    return {}
                raise AssertionError(command)
        if action == "describe-security-group-rules":
            self._maybe_fail_gate_read()
            ids = command[command.index("--security-group-rule-ids") + 1:command.index("--region")]
            rules = []
            for group_name in ("server_ingress_rules", "ac_ingress_rules"):
                prefix = "server" if group_name.startswith("server") else "ac"
                for name, rule in self.contract["maintenance"][group_name].items():
                    if rule["security_group_rule_id"] not in ids:
                        continue
                    state = self.gates[f"{prefix}.{name}"]
                    rules.append({
                        "SecurityGroupRuleId": rule["security_group_rule_id"],
                        "GroupId": rule["security_group_id"],
                        "IsEgress": False,
                        "IpProtocol": rule["ip_protocol"],
                        "FromPort": rule["from_port"],
                        "ToPort": rule["to_port"],
                        "Description": rule["description"],
                        "CidrIpv4": rule["open_cidr_ipv4"] if state == "open" else "192.0.2.255/32",
                    })
            return {"SecurityGroupRules": rules}
        if action == "modify-security-group-rules":
            payload = json.loads(command[command.index("--cli-input-json") + 1])
            item = payload["SecurityGroupRules"][0]
            identity = item["SecurityGroupRuleId"]
            desired = "open" if item["SecurityGroupRule"]["CidrIpv4"] == "0.0.0.0/0" else "closed"
            label = next(
                f"{prefix}.{name}"
                for group_name, prefix in (("server_ingress_rules", "server"), ("ac_ingress_rules", "ac"))
                for name, rule in self.contract["maintenance"][group_name].items()
                if rule["security_group_rule_id"] == identity
            )
            self._maybe_fail(("gate", label, desired), lambda: self.gates.__setitem__(label, desired))
            if desired == "open":
                self._run_gate_open_hook()
            return {}
        if action == "describe-listeners":
            arn = command[command.index("--listener-arns") + 1]
            candidate = self._candidate_target(arn)
            if candidate is not None:
                target = candidate
            else:
                label, part = self._selector_for_arn(arn)
                target = part[f"{self.selectors[label]}_target_group_arn"]
            return {"Listeners": [{"DefaultActions": [{"Type": "forward", "TargetGroupArn": target}]}]}
        if action == "describe-rules":
            arn = command[command.index("--rule-arns") + 1]
            if arn == "arn:relay-maintenance":
                self._maybe_fail_gate_read()
                gate = self.contract["maintenance"]["relay_rule"]
                return {"Rules": [{
                    "RuleArn": arn,
                    "Priority": "1",
                    "Actions": [{
                        "Type": "fixed-response",
                        "FixedResponseConfig": {
                            "MessageBody": gate["message_body"],
                            "StatusCode": gate["status_code"],
                            "ContentType": gate["content_type"],
                        },
                    }],
                    "Conditions": [
                        {
                            "Field": "path-pattern",
                            "Values": [gate[f"{self.gates['relay']}_path"]],
                            "PathPatternConfig": {"Values": [gate[f"{self.gates['relay']}_path"]]},
                        },
                        {
                            "Field": "http-request-method",
                            "Values": gate["methods"],
                            "HttpRequestMethodConfig": {"Values": gate["methods"]},
                        },
                    ],
                }]}
            candidate = self._candidate_target(arn)
            if candidate is not None:
                target = candidate
            else:
                label, part = self._selector_for_arn(arn)
                target = part[f"{self.selectors[label]}_target_group_arn"]
            return {"Rules": [{"Actions": [{"Type": "forward", "TargetGroupArn": target}]}]}
        if action == "modify-rule" and command[command.index("--rule-arn") + 1] == "arn:relay-maintenance":
            conditions = json.loads(command[command.index("--conditions") + 1])
            path = conditions[0]["PathPatternConfig"]["Values"][0]
            desired = "closed" if path == "/relay/*" else "open"
            self._maybe_fail(("gate", "relay", desired), lambda: self.gates.__setitem__("relay", desired))
            if desired == "open":
                self._run_gate_open_hook()
            return {}
        if action in ("modify-listener", "modify-rule"):
            arn_key = "--listener-arn" if action == "modify-listener" else "--rule-arn"
            payload_key = "--default-actions" if action == "modify-listener" else "--actions"
            label, part = self._selector_for_arn(command[command.index(arn_key) + 1])
            target = json.loads(command[command.index(payload_key) + 1])[0]["TargetGroupArn"]
            desired = next(state for state in ("blue", "candidate") if part[f"{state}_target_group_arn"] == target)
            self._maybe_fail(("selector", label, desired), lambda: self.selectors.__setitem__(label, desired))
            self._run_selector_hook()
            return {}
        if action == "describe-auto-scaling-groups":
            name = command[command.index("--auto-scaling-group-names") + 1]
            if name == self.active_asg["AutoScalingGroupName"]:
                return {"AutoScalingGroups": [dict(self.active_asg)]}
            if name in self.asgs:
                return {"AutoScalingGroups": [dict(self.asgs[name])]}
            return {"AutoScalingGroups": []}
        if action == "describe-target-health":
            target_group = command[command.index("--target-group-arn") + 1]
            if target_group not in self.target_health:
                raise AssertionError(target_group)
            return {"TargetHealthDescriptions": self.target_health[target_group]}
        if action == "get-parameter" and command[1] == "ssm":
            name = command[command.index("--name") + 1]
            if name not in self.image_tags:
                raise AssertionError(name)
            return {"Parameter": {
                "Name": name,
                "Type": "String",
                "Value": self.image_tags[name],
                "Version": 19,
                "DataType": "text",
            }}
        raise AssertionError(command)


LOCK_DIGEST = "a" * 64
RELEASE_ID = "b" * 64
OTHER_RELEASE_ID = "c" * 64


def operator_lock(
    fake: FakeAws,
    release_id: str = RELEASE_ID,
    invocation_token: str = "",
) -> CONTROL.OperatorLock:
    return CONTROL.OperatorLock(
        fake.contract["maintenance"]["operator_lock_table"],
        release_id,
        LOCK_DIGEST,
        "us-east-2",
        fake,
        invocation_token,
    )


def selector_controller(
    fake: FakeAws,
    release_id: str = RELEASE_ID,
    *,
    resume: bool = False,
) -> CONTROL.SelectorController:
    lock = operator_lock(fake, release_id)
    if fake.operator_lock_item is None:
        fake.operator_lock_item = lock.idle_item()
    return CONTROL.SelectorController(
        fake.contract,
        "us-east-2",
        fake,
        lock,
        resume,
    )


def maintenance_controller(
    fake: FakeAws,
    release_id: str = RELEASE_ID,
    *,
    resume: bool = False,
) -> CONTROL.MaintenanceController:
    lock = operator_lock(fake, release_id)
    if fake.operator_lock_item is None:
        fake.operator_lock_item = lock.idle_item()
    return CONTROL.MaintenanceController(
        fake.contract,
        "us-east-2",
        fake,
        lock,
        resume,
    )


class ContractTest(unittest.TestCase):
    def test_contract_is_exact_and_duplicate_json_fails_closed(self) -> None:
        CONTROL.validate_contract(contract())
        mutations = []
        for path in (("maintenance", "closed_cidr_ipv4"), ("server", "candidate_endpoint")):
            value = contract()
            del value[path[0]][path[1]]
            mutations.append(value)
        value = contract()
        value["maintenance"]["relay_rule"]["open_path"] = "/relay/*"
        mutations.append(value)
        value = contract()
        value["maintenance"]["ac_ingress_rules"]["https"]["open_cidr_ipv4"] = "10.0.0.0/8"
        mutations.append(value)
        value = contract()
        value["maintenance"]["ac_ingress_rules"]["https"]["security_group_rule_id"] = "sgr-b2"
        mutations.append(value)
        value = contract()
        del value["server"]["blue_rollback"]["image_tag"]
        mutations.append(value)
        value = contract()
        value["ac"]["candidate_authority"]["desired_capacity"] = 0
        mutations.append(value)
        value = contract()
        value["relay"]["blue_rollback"]["launch_template_version"] = "$Latest"
        mutations.append(value)
        value = contract()
        value["relay"]["candidate_authority"]["target_group_arns"].append(
            value["relay"]["candidate_authority"]["target_group_arns"][0]
        )
        mutations.append(value)
        value = contract()
        value["server"]["blue_rollback"]["target_group_arns"].remove(
            value["server"]["blue_target_group_arn"]
        )
        mutations.append(value)
        value = contract()
        value["ac"]["candidate_authority"]["target_group_arns"].remove(
            value["ac"]["frps_selectors"]["primary"]["candidate_target_group_arn"]
        )
        mutations.append(value)
        for value in mutations:
            with self.assertRaises(CONTROL.ControlError):
                CONTROL.validate_contract(value)
        with self.assertRaisesRegex(CONTROL.ControlError, "duplicate"):
            CONTROL.strict_json('{"schema":2,"schema":2}')


class MaintenanceTest(unittest.TestCase):
    def test_only_close_can_create_journal_switch_and_open_require_prior_release(self) -> None:
        fake = FakeAws()
        lock = operator_lock(fake)
        close = CONTROL.MaintenanceController(fake.contract, "us-east-2", fake, lock)
        self.assertEqual(close.transition("open", "closed"), "closed")
        self.assertEqual(fake.operator_lock_item, lock.idle_item())

        missing = FakeAws(gate_state="closed")
        missing_lock = operator_lock(missing)
        selector = CONTROL.SelectorController(missing.contract, "us-east-2", missing, missing_lock)
        with self.assertRaisesRegex(CONTROL.ControlError, "journal is absent"):
            selector.switch("blue", "candidate", lambda: None)
        with self.assertRaisesRegex(CONTROL.ControlError, "journal is absent"):
            CONTROL.MaintenanceController(
                missing.contract, "us-east-2", missing, missing_lock
            ).transition("closed", "open", required_selector="blue")
        self.assertFalse(missing.calls)

    def test_shared_lock_serializes_close_switch_and_open_across_crash_resume(self) -> None:
        fake = FakeAws()
        self.assertEqual(maintenance_controller(fake).transition("open", "closed"), "closed")
        self.assertEqual(fake.operator_lock_item, operator_lock(fake).idle_item())

        calls_before = list(fake.calls)
        with self.assertRaisesRegex(CONTROL.ControlError, "another release"):
            selector_controller(fake, OTHER_RELEASE_ID).switch("blue", "candidate", lambda: None)
        self.assertEqual(fake.calls, calls_before, "contending release mutated selectors or gates")

        self.assertEqual(
            selector_controller(fake).switch("blue", "candidate", lambda: None),
            {"server": "candidate", "ac": "candidate", "relay": "candidate"},
        )
        self.assertEqual(fake.operator_lock_item, operator_lock(fake).idle_item())
        self.assertEqual(
            maintenance_controller(fake).transition(
                "closed", "open", required_selector="candidate"
            ),
            "open",
        )
        self.assertIsNone(fake.operator_lock_item)

    def test_journal_release_accepts_only_exact_absence_after_delete(self) -> None:
        with self.subTest("lost-response"):
            fake = FakeAws(gate_state="closed")
            lock = operator_lock(fake, invocation_token="1" * 64)
            fake.operator_lock_item = lock.active_item("open")
            fake.lock_delete_commit_then_fail = True
            lock.complete("open", release=True)
            self.assertIsNone(fake.operator_lock_item)

        for recreated, error in (
            (operator_lock(FakeAws(), OTHER_RELEASE_ID).idle_item(), "release is not exact"),
            ({"lock_id": {"S": CONTROL.OPERATOR_LOCK_ID}}, "unexpected key set"),
        ):
            with self.subTest(recreated=recreated):
                fake = FakeAws(gate_state="closed")
                lock = operator_lock(fake, invocation_token="1" * 64)
                fake.operator_lock_item = lock.active_item("open")
                fake.lock_delete_recreate_item = recreated
                with self.assertRaisesRegex(CONTROL.ControlError, error):
                    lock.complete("open", release=True)
                self.assertEqual(fake.operator_lock_item, recreated)

    def test_two_concurrent_invocations_have_one_exact_journal_winner(self) -> None:
        fake = FakeAws()
        start = threading.Barrier(3)
        results: queue.Queue[tuple[str, object]] = queue.Queue()

        def acquire(token: str) -> None:
            start.wait(timeout=1)
            try:
                operator_lock(fake, invocation_token=token).begin("close")
                results.put((token, "acquired"))
            except BaseException as error:  # noqa: BLE001 - fixture records the losing authority
                results.put((token, error))

        tokens = ("1" * 64, "2" * 64)
        workers = [threading.Thread(target=acquire, args=(token,)) for token in tokens]
        for worker in workers:
            worker.start()
        start.wait(timeout=1)
        for worker in workers:
            worker.join(timeout=2)
        observed = [results.get_nowait(), results.get_nowait()]
        winners = [token for token, result in observed if result == "acquired"]
        losers = [result for _, result in observed if isinstance(result, CONTROL.ControlError)]
        self.assertEqual(len(winners), 1)
        self.assertEqual(len(losers), 1)
        self.assertEqual(
            fake.operator_lock_item,
            operator_lock(fake, invocation_token=winners[0]).active_item("close"),
        )

    def test_stale_close_never_rolls_back_after_successor_resumes_its_token(self) -> None:
        fake = FakeAws(gate_state="open")
        old = operator_lock(fake, invocation_token="1" * 64)
        successor = operator_lock(fake, invocation_token="2" * 64)
        controller = CONTROL.MaintenanceController(
            fake.contract,
            "us-east-2",
            fake,
            old,
        )
        fake.fail_once = ("gate", "server.nhp", "closed")
        original_flat_state = controller.flat_state
        reads = 0
        calls_at_handoff = -1

        def resume_after_failed_close_readback() -> dict[str, str]:
            nonlocal reads, calls_at_handoff
            observed = original_flat_state()
            reads += 1
            if reads == 2:
                successor.begin("close", resume=True)
                calls_at_handoff = len(fake.calls)
            return observed

        with (
            patch.object(controller, "flat_state", side_effect=resume_after_failed_close_readback),
            self.assertRaisesRegex(CONTROL.ControlError, "ownership changed"),
        ):
            controller.transition("open", "closed")
        self.assertGreaterEqual(calls_at_handoff, 0)
        self.assertEqual(
            len(fake.calls),
            calls_at_handoff,
            "the stale close mutated gates after the successor acquired the journal",
        )
        self.assertEqual(fake.operator_lock_item, successor.active_item("close"))

    def test_stale_open_never_recloses_after_successor_resumes_its_token(self) -> None:
        fake = FakeAws(selector_state="candidate", gate_state="closed")
        old = operator_lock(fake, invocation_token="1" * 64)
        successor = operator_lock(fake, invocation_token="2" * 64)
        fake.operator_lock_item = old.idle_item()
        controller = CONTROL.MaintenanceController(
            fake.contract,
            "us-east-2",
            fake,
            old,
        )
        original_preflight = controller._open_preflight
        reads = 0
        calls_at_handoff = -1

        def resume_during_final_open_bracket(required_selector: str) -> dict[str, str]:
            nonlocal reads, calls_at_handoff
            observed = original_preflight(required_selector)
            reads += 1
            if reads == 3:
                successor.begin("open", resume=True)
                calls_at_handoff = len(fake.calls)
            return observed

        with (
            patch.object(controller, "_open_preflight", side_effect=resume_during_final_open_bracket),
            self.assertRaisesRegex(CONTROL.ControlError, "ownership changed"),
        ):
            controller.transition("closed", "open", required_selector="candidate")
        self.assertGreaterEqual(calls_at_handoff, 0)
        self.assertEqual(
            len(fake.calls),
            calls_at_handoff,
            "the stale open re-closed gates after the successor acquired the journal",
        )
        self.assertEqual(set(fake.gates.values()), {"open"})
        self.assertEqual(fake.operator_lock_item, successor.active_item("open"))

    def test_successor_resumes_each_abandoned_normal_operation_with_new_token(self) -> None:
        old_token = "1" * 64
        for operation in ("close", "switch", "open"):
            with self.subTest(operation=operation):
                selector_state = "candidate" if operation == "open" else "blue"
                gate_state = "open" if operation == "close" else "closed"
                fake = FakeAws(selector_state=selector_state, gate_state=gate_state)
                fake.operator_lock_item = operator_lock(
                    fake, invocation_token=old_token
                ).active_item(operation)
                calls_before = list(fake.calls)
                if operation == "switch":
                    fake.selectors["server"] = "candidate"
                    without_resume = selector_controller(fake)
                elif operation == "close":
                    fake.gates["server.nhp"] = "closed"
                    without_resume = maintenance_controller(fake)
                else:
                    fake.gates["server.nhp"] = "open"
                    without_resume = maintenance_controller(fake)

                def action() -> None:
                    if operation == "switch":
                        without_resume.switch("blue", "candidate", lambda: None)
                    elif operation == "close":
                        without_resume.transition("open", "closed")
                    else:
                        without_resume.transition(
                            "closed", "open", required_selector="candidate"
                        )
                with self.assertRaisesRegex(CONTROL.ControlError, "active invocation"):
                    action()
                self.assertEqual(fake.calls, calls_before)

                if operation == "switch":
                    result = selector_controller(fake, resume=True).switch(
                        "blue", "candidate", lambda: None
                    )
                    self.assertEqual(set(result.values()), {"candidate"})
                    self.assertEqual(fake.operator_lock_item, operator_lock(fake).idle_item())
                elif operation == "close":
                    self.assertEqual(
                        maintenance_controller(fake, resume=True).transition("open", "closed"),
                        "closed",
                    )
                    self.assertEqual(fake.operator_lock_item, operator_lock(fake).idle_item())
                else:
                    self.assertEqual(
                        maintenance_controller(fake, resume=True).transition(
                            "closed", "open", required_selector="candidate"
                        ),
                        "open",
                    )
                    self.assertIsNone(fake.operator_lock_item)

    def test_healthy_close_and_open_use_exact_parallel_control_plane_budgets(self) -> None:
        original_parallel = CONTROL.parallel
        for expected, desired, selector in (
            ("open", "closed", None),
            ("closed", "open", "blue"),
        ):
            with self.subTest(desired=desired):
                fake = FakeAws(gate_state=expected)
                waves: list[set[str]] = []

                def tracked(tasks):
                    tasks = list(tasks)
                    waves.append({label for label, _ in tasks})
                    return original_parallel(tasks)

                with patch.object(CONTROL, "parallel", side_effect=tracked):
                    result = maintenance_controller(fake).transition(
                        expected,
                        desired,
                        required_selector=selector,
                    )
                self.assertEqual(result, desired)
                expected_waves = (
                    CONTROL.HEALTHY_MAINTENANCE_OPEN_PARALLEL_WAVES
                    if desired == "open"
                    else CONTROL.HEALTHY_MAINTENANCE_CLOSE_PARALLEL_WAVES
                )
                self.assertEqual(len(waves), expected_waves)
                self.assertIn("security-groups", waves[0])
                self.assertIn("relay", waves[0])
                if desired == "open":
                    self.assertIn("selector.server", waves[0])

    def test_close_and_open_mutate_independent_gates_in_parallel_and_read_back(self) -> None:
        fake = FakeAws()
        started: queue.Queue[tuple[str, str, str]] = queue.Queue()
        release = threading.Event()
        fake.started = started
        fake.release = release
        outcome: queue.Queue[object] = queue.Queue()

        def run() -> None:
            try:
                outcome.put(maintenance_controller(fake).transition("open", "closed"))
            except BaseException as error:  # noqa: BLE001
                outcome.put(error)

        worker = threading.Thread(target=run)
        worker.start()
        observed = [started.get(timeout=1) for _ in range(len(fake.gates))]
        release.set()
        worker.join(timeout=2)
        self.assertEqual(outcome.get_nowait(), "closed")
        self.assertEqual({item[1] for item in observed}, set(fake.gates))
        fake.started = None
        fake.release = None
        self.assertEqual(
            maintenance_controller(fake).transition(
                "closed", "open", required_selector="blue"
            ),
            "open",
        )

    def test_every_gate_lost_response_is_classified_by_exact_readback(self) -> None:
        for label in FakeAws().gates:
            with self.subTest(label=label):
                fake = FakeAws()
                fake.commit_then_fail_once = ("gate", label, "closed")
                self.assertEqual(
                    maintenance_controller(fake).transition("open", "closed"),
                    "closed",
                )

    def test_partial_close_rolls_every_gate_open_and_partial_open_rolls_closed(self) -> None:
        fake = FakeAws()
        fake.fail_once = ("gate", "ac.https", "closed")
        fake.commit_then_fail_once = ("gate", "server.nhp", "open")
        with self.assertRaisesRegex(CONTROL.ControlError, "rollback: complete"):
            maintenance_controller(fake).transition("open", "closed")
        self.assertEqual(set(fake.gates.values()), {"open"})

        fake = FakeAws(selector_state="candidate", gate_state="closed")
        fake.fail_once = ("gate", "relay", "open")
        with self.assertRaisesRegex(CONTROL.ControlError, "rollback: complete"):
            maintenance_controller(fake).transition(
                "closed", "open", required_selector="candidate"
            )
        self.assertEqual(set(fake.gates.values()), {"closed"})

        fake = FakeAws(selector_state="candidate", gate_state="closed")
        fake.interrupt_once = ("gate", "ac.nhp_knock", "open")
        with self.assertRaisesRegex(CONTROL.ControlError, "rollback: complete"):
            maintenance_controller(fake).transition(
                "closed", "open", required_selector="candidate"
            )
        self.assertEqual(set(fake.gates.values()), {"closed"})

    def test_open_requires_exact_coherent_selector_readback_before_any_gate_write(self) -> None:
        fake = FakeAws(gate_state="closed")
        fake.selectors["relay"] = "candidate"
        with self.assertRaisesRegex(CONTROL.ControlError, "selectors are not exact blue"):
            maintenance_controller(fake).transition(
                "closed", "open", required_selector="blue"
            )
        self.assertFalse(fake.calls)

    def test_open_rechecks_selector_after_writes_and_recloses_on_drift_or_lost_response(self) -> None:
        fake = FakeAws(gate_state="closed")
        fake.after_gate_open = lambda: fake.selectors.__setitem__("relay", "candidate")
        fake.commit_then_fail_once = ("gate", "server.nhp", "open")
        with self.assertRaisesRegex(CONTROL.ControlError, "selector recheck failed.*re-close: complete"):
            maintenance_controller(fake).transition(
                "closed", "open", required_selector="blue"
            )
        self.assertEqual(set(fake.gates.values()), {"closed"})

        exact = FakeAws(gate_state="closed")
        exact.commit_then_fail_once = ("gate", "server.nhp", "open")
        self.assertEqual(
            maintenance_controller(exact).transition(
                "closed", "open", required_selector="blue"
            ),
            "open",
        )

    def test_idempotent_open_rechecks_selector_and_gates_then_recloses_on_drift(self) -> None:
        fake = FakeAws(gate_state="open")
        original_parallel = CONTROL.parallel
        preflights = 0

        def drift_after_first_preflight(tasks):
            nonlocal preflights
            tasks = list(tasks)
            result = original_parallel(tasks)
            if {label for label, _ in tasks} >= {"selector.server", "security-groups", "relay"}:
                preflights += 1
                if preflights == 1:
                    fake.selectors["relay"] = "candidate"
            return result

        with (
            patch.object(CONTROL, "parallel", side_effect=drift_after_first_preflight),
            self.assertRaisesRegex(CONTROL.ControlError, "selector recheck failed.*re-close: complete"),
        ):
            maintenance_controller(fake).transition(
                "closed", "open", required_selector="blue"
            )
        self.assertEqual(set(fake.gates.values()), {"closed"})
        self.assertEqual(fake.selectors["relay"], "candidate")


class SelectorTest(unittest.TestCase):
    def test_selector_drift_during_every_health_bracket_fails_closed(self) -> None:
        original_parallel = CONTROL.parallel
        for boundary in (1, 2, 3):
            with self.subTest(boundary=boundary):
                fake = FakeAws(gate_state="closed")
                health_waves = 0

                def drift_after_health(tasks):
                    nonlocal health_waves
                    tasks = list(tasks)
                    result = original_parallel(tasks)
                    if tasks and all("|" in label for label, _ in tasks):
                        health_waves += 1
                        if health_waves == boundary:
                            fake.selectors["relay"] = "blue" if boundary == 3 else "candidate"
                    return result

                error = "rollback: complete" if boundary == 3 else "selector vector changed"
                with (
                    patch.object(CONTROL, "parallel", side_effect=drift_after_health),
                    self.assertRaisesRegex(CONTROL.ControlError, error),
                ):
                    selector_controller(fake).switch("blue", "candidate", lambda: None)
                self.assertEqual(set(fake.gates.values()), {"closed"})
                if boundary == 3:
                    self.assertEqual(set(fake.selectors.values()), {"blue"})
                else:
                    self.assertFalse(any(call[0] == "selector" for call in fake.calls))

    def test_healthy_switch_uses_only_ten_parallel_control_plane_waves(self) -> None:
        fake = FakeAws(gate_state="closed")
        original_parallel = CONTROL.parallel
        waves: list[set[str]] = []

        def tracked(tasks):
            tasks = list(tasks)
            waves.append({label for label, _ in tasks})
            return original_parallel(tasks)

        with patch.object(CONTROL, "parallel", side_effect=tracked):
            result = selector_controller(fake).switch(
                "blue", "candidate", lambda: None
            )

        self.assertEqual(result, {"server": "candidate", "ac": "candidate", "relay": "candidate"})
        self.assertEqual(len(waves), CONTROL.HEALTHY_SWITCH_PARALLEL_WAVES)
        self.assertIn("active-ac", waves[0])
        self.assertIn("candidate.server", waves[0])
        self.assertIn("gate.security-groups", waves[0])
        self.assertIn("gate.relay", waves[0])
        expected_health = {
            f"{label}|{target}"
            for label, authority in CONTROL.fleet_units(fake.contract)
            for target in authority["target_group_arns"]
        }
        self.assertEqual(waves[1], expected_health)
        self.assertIn("fleet.server.blue", waves[2])
        self.assertIn("gate.security-groups", waves[2])
        self.assertIn("active-ac", waves[3])
        self.assertEqual(waves[4], expected_health)
        self.assertIn("fleet.server.blue", waves[5])
        self.assertEqual(waves[6], set(fake.selectors))
        self.assertIn("gate.security-groups", waves[7])
        self.assertEqual(waves[8], expected_health)
        self.assertIn("fleet.server.blue", waves[9])
        self.assertIn("gate.security-groups", waves[9])

    def test_idempotent_desired_selector_recloses_gate_opened_after_second_health_wave(self) -> None:
        fake = FakeAws(selector_state="candidate", gate_state="closed")
        original_parallel = CONTROL.parallel
        health_waves = 0

        def open_after_second_health(tasks):
            nonlocal health_waves
            tasks = list(tasks)
            result = original_parallel(tasks)
            if tasks and all("|" in label for label, _ in tasks):
                health_waves += 1
                if health_waves == 2:
                    fake.gates["relay"] = "open"
            return result

        with (
            patch.object(CONTROL, "parallel", side_effect=open_after_second_health),
            self.assertRaisesRegex(CONTROL.ControlError, "post-probe selector readiness failed.*re-close: complete"),
        ):
            selector_controller(fake).switch(
                "blue", "candidate", lambda: None
            )
        self.assertEqual(set(fake.selectors.values()), {"candidate"})
        self.assertEqual(set(fake.gates.values()), {"closed"})
        self.assertFalse(any(call[0] == "selector" for call in fake.calls))
        self.assertEqual(
            {call[1] for call in fake.calls if call[0] == "gate" and call[2] == "closed"},
            set(fake.gates),
        )

    def test_gate_vector_transition_during_every_health_wave_fails_closed(self) -> None:
        original_parallel = CONTROL.parallel
        for boundary in (1, 2, 3):
            for before, after in (("open", "closed"), ("closed", "open")):
                with self.subTest(boundary=boundary, transition=f"{before}-to-{after}"):
                    selector_state = "candidate" if boundary < 3 else "blue"
                    initial_gate = before if boundary == 1 else "closed"
                    fake = FakeAws(selector_state=selector_state, gate_state=initial_gate)
                    health_waves = 0

                    def set_gates(state: str) -> None:
                        for label in fake.gates:
                            fake.gates[label] = state

                    def transition_after_health(tasks):
                        nonlocal health_waves
                        tasks = list(tasks)
                        result = original_parallel(tasks)
                        if tasks and all("|" in label for label, _ in tasks):
                            health_waves += 1
                            if health_waves == boundary:
                                set_gates(after)
                        return result

                    def closure_probe() -> None:
                        if boundary == 2:
                            set_gates(before)

                    if boundary == 3:
                        fake.after_selector_mutation = lambda: set_gates(before)

                    expected_error = {
                        1: "initial selector readiness failed.*re-close: complete",
                        2: "post-probe selector readiness failed.*re-close: complete",
                        3: "rollback: complete",
                    }[boundary]
                    with (
                        patch.object(CONTROL, "parallel", side_effect=transition_after_health),
                        self.assertRaisesRegex(CONTROL.ControlError, expected_error),
                    ):
                        selector_controller(fake).switch(
                            "blue", "candidate", closure_probe
                        )
                    self.assertEqual(set(fake.gates.values()), {"closed"})
                    self.assertEqual(
                        set(fake.selectors.values()),
                        {"candidate" if boundary < 3 else "blue"},
                    )
                    if boundary < 3:
                        self.assertFalse(any(call[0] == "selector" for call in fake.calls))

    def test_snapshot_brackets_full_fleet_and_image_authority_around_target_health(self) -> None:
        original_parallel = CONTROL.parallel
        for mutation in ("membership", "image"):
            with self.subTest(mutation=mutation):
                fake = FakeAws(gate_state="closed")
                authority = fake.contract["server"]["candidate_authority"]
                health_waves = 0

                def drift_after_health(tasks):
                    nonlocal health_waves
                    tasks = list(tasks)
                    result = original_parallel(tasks)
                    if tasks and all("|" in label for label, _ in tasks):
                        health_waves += 1
                        if health_waves == 1:
                            if mutation == "membership":
                                group = fake.asgs[authority["asg_name"]]
                                old_id = group["Instances"][0]["InstanceId"]
                                group["Instances"][0]["InstanceId"] = "i-replacement"
                                for rows in fake.target_health.values():
                                    for row in rows:
                                        if row["Target"]["Id"] == old_id:
                                            row["Target"]["Id"] = "i-replacement"
                            else:
                                fake.image_tags[authority["image_parameter"]] = "drift-after-health"
                    return result

                error = "membership changed" if mutation == "membership" else "image authority drifted"
                with (
                    patch.object(CONTROL, "parallel", side_effect=drift_after_health),
                    self.assertRaisesRegex(CONTROL.ControlError, error),
                ):
                    selector_controller(fake).switch(
                        "blue", "candidate", lambda: None
                    )
                self.assertEqual(set(fake.gates.values()), {"closed"})
                self.assertFalse(fake.calls)

    def test_membership_torn_read_fails_at_initial_post_probe_and_post_write_boundaries(self) -> None:
        original_parallel = CONTROL.parallel
        for boundary in (1, 2, 3):
            with self.subTest(boundary=boundary):
                fake = FakeAws(gate_state="closed")
                authority = fake.contract["relay"]["candidate_authority"]
                health_waves = 0

                def replace_after_health(tasks):
                    nonlocal health_waves
                    tasks = list(tasks)
                    result = original_parallel(tasks)
                    if tasks and all("|" in label for label, _ in tasks):
                        health_waves += 1
                        if health_waves == boundary:
                            group = fake.asgs[authority["asg_name"]]
                            old_id = group["Instances"][0]["InstanceId"]
                            group["Instances"][0]["InstanceId"] = f"i-replacement-{boundary}"
                            for target_group in authority["target_group_arns"]:
                                for row in fake.target_health[target_group]:
                                    if row["Target"]["Id"] == old_id:
                                        row["Target"]["Id"] = f"i-replacement-{boundary}"
                    return result

                error = "rollback: complete" if boundary == 3 else "membership changed"
                with (
                    patch.object(CONTROL, "parallel", side_effect=replace_after_health),
                    self.assertRaisesRegex(CONTROL.ControlError, error),
                ):
                    selector_controller(fake).switch(
                        "blue", "candidate", lambda: None
                    )
                self.assertEqual(set(fake.gates.values()), {"closed"})
                self.assertEqual(set(fake.selectors.values()), {"blue"})
                if boundary < 3:
                    self.assertFalse(any(call[0] == "selector" for call in fake.calls))

    def test_switch_runs_real_probe_while_gates_closed_then_mutates_all_selectors_in_parallel(self) -> None:
        fake = FakeAws(gate_state="closed")
        started: queue.Queue[tuple[str, str, str]] = queue.Queue()
        release = threading.Event()
        fake.started = started
        fake.release = release
        probe_seen = []
        outcome: queue.Queue[object] = queue.Queue()

        def probe() -> None:
            self.assertEqual(set(fake.gates.values()), {"closed"})
            self.assertEqual(set(fake.selectors.values()), {"blue"})
            probe_seen.append(True)

        def run() -> None:
            try:
                outcome.put(selector_controller(fake).switch("blue", "candidate", probe))
            except BaseException as error:  # noqa: BLE001
                outcome.put(error)

        worker = threading.Thread(target=run)
        worker.start()
        observed = [started.get(timeout=1) for _ in range(5)]
        release.set()
        worker.join(timeout=2)
        self.assertEqual(outcome.get_nowait(), {"server": "candidate", "ac": "candidate", "relay": "candidate"})
        self.assertEqual(probe_seen, [True])
        self.assertEqual({item[1] for item in observed}, set(fake.selectors))
        self.assertEqual(set(fake.gates.values()), {"closed"})

    def test_open_gate_or_failed_probe_prevents_every_selector_write(self) -> None:
        fake = FakeAws(gate_state="open")
        with self.assertRaisesRegex(CONTROL.ControlError, "maintenance gates"):
            selector_controller(fake).switch("blue", "candidate", lambda: None)
        self.assertFalse(fake.calls)

        fake = FakeAws(gate_state="closed")
        with self.assertRaisesRegex(CONTROL.ControlError, "probe failed"):
            selector_controller(fake).switch(
                "blue", "candidate", lambda: (_ for _ in ()).throw(CONTROL.ControlError("probe failed"))
            )
        self.assertFalse(fake.calls)

    def test_every_selector_lost_response_is_exact_success_and_gate_stays_closed(self) -> None:
        for label in FakeAws().selectors:
            with self.subTest(label=label):
                fake = FakeAws(gate_state="closed")
                fake.commit_then_fail_once = ("selector", label, "candidate")
                result = selector_controller(fake).switch(
                    "blue", "candidate", lambda: None
                )
                self.assertEqual(set(result.values()), {"candidate"})
                self.assertEqual(set(fake.gates.values()), {"closed"})

    def test_selector_failure_rolls_every_member_back_while_gates_stay_closed(self) -> None:
        fake = FakeAws(gate_state="closed")
        fake.fail_once = ("selector", "ac.frps.b", "candidate")
        fake.commit_then_fail_once = ("selector", "server", "blue")
        with self.assertRaisesRegex(CONTROL.ControlError, "rollback: complete"):
            selector_controller(fake).switch("blue", "candidate", lambda: None)
        self.assertEqual(set(fake.selectors.values()), {"blue"})
        self.assertEqual(set(fake.gates.values()), {"closed"})

    def test_selector_completion_handoff_never_rolls_back_under_successor_lock(self) -> None:
        fake = FakeAws(gate_state="closed")
        successor = operator_lock(fake, invocation_token="9" * 64).active_item("open")
        fake.lock_idle_recreate_item = successor
        with self.assertRaisesRegex(CONTROL.ControlError, "rollback"):
            selector_controller(fake).switch("blue", "candidate", lambda: None)
        self.assertEqual(set(fake.selectors.values()), {"candidate"})
        self.assertEqual(set(fake.gates.values()), {"closed"})
        self.assertEqual(fake.operator_lock_item, successor)
        self.assertFalse(
            any(call[0] == "selector" and call[2] == "blue" for call in fake.calls),
            "the predecessor mutated selectors after the successor acquired the journal",
        )

        fake = FakeAws(gate_state="closed")
        fake.interrupt_once = ("selector", "relay", "candidate")
        with self.assertRaisesRegex(CONTROL.ControlError, "rollback: complete"):
            selector_controller(fake).switch(
                "blue", "candidate", lambda: None
            )
        self.assertEqual(set(fake.selectors.values()), {"blue"})
        self.assertEqual(set(fake.gates.values()), {"closed"})

    def test_crash_torn_selector_vector_resumes_but_unreviewed_state_fails(self) -> None:
        fake = FakeAws(gate_state="closed")
        fake.selectors["server"] = "candidate"
        fake.selectors["ac.https"] = "candidate"
        result = selector_controller(fake).switch("blue", "candidate", lambda: None)
        self.assertEqual(set(result.values()), {"candidate"})

        fake = FakeAws(gate_state="closed")
        fake.selectors["relay"] = "drift"
        with self.assertRaises(CONTROL.ControlError):
            selector_controller(fake).switch("blue", "candidate", lambda: None)
        self.assertFalse(fake.calls)

    def test_switch_requires_stopped_canonical_endpoint_ac_and_candidate_routes(self) -> None:
        fake = FakeAws(gate_state="closed")
        fake.active_asg["DesiredCapacity"] = 1
        with self.assertRaisesRegex(CONTROL.ControlError, "0/0/0"):
            selector_controller(fake).switch("blue", "candidate", lambda: None)
        self.assertFalse(fake.calls)

    def test_switch_requires_full_healthy_exact_blue_rollback_before_any_mutation(self) -> None:
        mutations = []

        partial = FakeAws(gate_state="closed")
        partial.blue_rollback_asg["Instances"].pop()
        mutations.append(partial)

        unhealthy = FakeAws(gate_state="closed")
        unhealthy.blue_rollback_asg["Instances"][0]["HealthStatus"] = "Unhealthy"
        mutations.append(unhealthy)

        wrong_capacity = FakeAws(gate_state="closed")
        wrong_capacity.blue_rollback_asg["MinSize"] = 1
        mutations.append(wrong_capacity)

        wrong_template = FakeAws(gate_state="closed")
        wrong_template.blue_rollback_asg["LaunchTemplate"]["Version"] = "8"
        mutations.append(wrong_template)

        wrong_instance_template = FakeAws(gate_state="closed")
        wrong_instance_template.blue_rollback_asg["Instances"][0]["LaunchTemplate"]["Version"] = "8"
        mutations.append(wrong_instance_template)

        wrong_image = FakeAws(gate_state="closed")
        wrong_image.image_tags[wrong_image.contract["ac"]["blue_rollback"]["image_parameter"]] = (
            "different-old-image"
        )
        mutations.append(wrong_image)

        for index, fake in enumerate(mutations):
            with self.subTest(index=index), self.assertRaises(CONTROL.ControlError):
                selector_controller(fake).switch(
                    "blue", "candidate", lambda: None
                )
            self.assertFalse(fake.calls)

    def test_every_blue_selector_target_must_be_attached_to_rollback_asg(self) -> None:
        base = FakeAws(gate_state="closed")
        targets = list(base.blue_rollback_asg["TargetGroupARNs"])
        for missing in targets:
            with self.subTest(missing=missing):
                fake = FakeAws(gate_state="closed")
                fake.blue_rollback_asg["TargetGroupARNs"].remove(missing)
                with self.assertRaisesRegex(CONTROL.ControlError, "target-group authority drifted"):
                    selector_controller(fake).switch(
                        "blue", "candidate", lambda: None
                    )
                self.assertFalse(fake.calls)

    def test_every_blue_selector_target_must_have_exact_healthy_rollback_membership(self) -> None:
        targets = list(FakeAws(gate_state="closed").blue_target_health)
        for target in targets:
            with self.subTest(target=target, mutation="missing"):
                fake = FakeAws(gate_state="closed")
                fake.blue_target_health[target].pop()
                with self.assertRaisesRegex(CONTROL.ControlError, "target health is incomplete"):
                    selector_controller(fake).switch(
                        "blue", "candidate", lambda: None
                    )
                self.assertFalse(fake.calls)

            with self.subTest(target=target, mutation="unhealthy"):
                fake = FakeAws(gate_state="closed")
                fake.blue_target_health[target][0]["TargetHealth"]["State"] = "unhealthy"
                with self.assertRaisesRegex(CONTROL.ControlError, "target is not healthy"):
                    selector_controller(fake).switch(
                        "blue", "candidate", lambda: None
                    )
                self.assertFalse(fake.calls)

            with self.subTest(target=target, mutation="wrong-member"):
                fake = FakeAws(gate_state="closed")
                fake.blue_target_health[target][0]["Target"]["Id"] = "i-wrong"
                with self.assertRaisesRegex(CONTROL.ControlError, "target membership drifted"):
                    selector_controller(fake).switch(
                        "blue", "candidate", lambda: None
                    )
                self.assertFalse(fake.calls)

    def test_every_server_ac_relay_candidate_and_blue_fleet_is_exact_before_mutation(self) -> None:
        for label, authority in CONTROL.fleet_units(contract()):
            with self.subTest(label=label, mutation="identity"):
                fake = FakeAws(gate_state="closed")
                fake.asgs[authority["asg_name"]]["AutoScalingGroupName"] += "-drift"
                with self.assertRaisesRegex(CONTROL.ControlError, "capacity or identity drifted"):
                    selector_controller(fake).switch(
                        "blue", "candidate", lambda: None
                    )
                self.assertFalse(fake.calls)

            with self.subTest(label=label, mutation="capacity"):
                fake = FakeAws(gate_state="closed")
                fake.asgs[authority["asg_name"]]["DesiredCapacity"] += 1
                with self.assertRaisesRegex(CONTROL.ControlError, "capacity or identity drifted"):
                    selector_controller(fake).switch(
                        "blue", "candidate", lambda: None
                    )
                self.assertFalse(fake.calls)

            with self.subTest(label=label, mutation="image"):
                fake = FakeAws(gate_state="closed")
                fake.image_tags[authority["image_parameter"]] = "wrong-image"
                with self.assertRaisesRegex(CONTROL.ControlError, "image authority drifted"):
                    selector_controller(fake).switch(
                        "blue", "candidate", lambda: None
                    )
                self.assertFalse(fake.calls)

            with self.subTest(label=label, mutation="launch-template"):
                fake = FakeAws(gate_state="closed")
                fake.asgs[authority["asg_name"]]["LaunchTemplate"]["Version"] = "999"
                with self.assertRaisesRegex(CONTROL.ControlError, "ASG launch template drifted"):
                    selector_controller(fake).switch(
                        "blue", "candidate", lambda: None
                    )
                self.assertFalse(fake.calls)

            with self.subTest(label=label, mutation="instance-launch-template"):
                fake = FakeAws(gate_state="closed")
                fake.asgs[authority["asg_name"]]["Instances"][0]["LaunchTemplate"]["Version"] = "999"
                with self.assertRaisesRegex(CONTROL.ControlError, "instance launch template drifted"):
                    selector_controller(fake).switch(
                        "blue", "candidate", lambda: None
                    )
                self.assertFalse(fake.calls)

            with self.subTest(label=label, mutation="membership"):
                fake = FakeAws(gate_state="closed")
                fake.asgs[authority["asg_name"]]["Instances"].pop()
                with self.assertRaisesRegex(CONTROL.ControlError, "full desired membership"):
                    selector_controller(fake).switch(
                        "blue", "candidate", lambda: None
                    )
                self.assertFalse(fake.calls)

            with self.subTest(label=label, mutation="suspended"):
                fake = FakeAws(gate_state="closed")
                fake.asgs[authority["asg_name"]]["SuspendedProcesses"] = [{"ProcessName": "Launch"}]
                with self.assertRaisesRegex(CONTROL.ControlError, "suspended processes"):
                    selector_controller(fake).switch(
                        "blue", "candidate", lambda: None
                    )
                self.assertFalse(fake.calls)

            with self.subTest(label=label, mutation="target-attachment"):
                fake = FakeAws(gate_state="closed")
                fake.asgs[authority["asg_name"]]["TargetGroupARNs"].pop()
                with self.assertRaisesRegex(CONTROL.ControlError, "target-group authority drifted"):
                    selector_controller(fake).switch(
                        "blue", "candidate", lambda: None
                    )
                self.assertFalse(fake.calls)

            for target_group in authority["target_group_arns"]:
                with self.subTest(label=label, mutation="target-health", target_group=target_group):
                    fake = FakeAws(gate_state="closed")
                    fake.target_health[target_group][0]["TargetHealth"]["State"] = "unhealthy"
                    with self.assertRaisesRegex(CONTROL.ControlError, "target is not healthy"):
                        selector_controller(fake).switch(
                            "blue", "candidate", lambda: None
                        )
                    self.assertFalse(fake.calls)

                with self.subTest(label=label, mutation="target-member", target_group=target_group):
                    fake = FakeAws(gate_state="closed")
                    fake.target_health[target_group][0]["Target"]["Id"] = "i-wrong"
                    with self.assertRaisesRegex(CONTROL.ControlError, "target membership drifted"):
                        selector_controller(fake).switch(
                            "blue", "candidate", lambda: None
                        )
                    self.assertFalse(fake.calls)

    def test_full_readiness_is_reproved_after_probe_and_after_selector_write(self) -> None:
        after_probe = FakeAws(gate_state="closed")
        blue = after_probe.contract["relay"]["blue_rollback"]

        def mutate_after_probe() -> None:
            after_probe.image_tags[blue["image_parameter"]] = "drift-after-probe"

        with self.assertRaisesRegex(CONTROL.ControlError, "image authority drifted"):
            selector_controller(after_probe).switch(
                "blue", "candidate", mutate_after_probe
            )
        self.assertEqual(set(after_probe.gates.values()), {"closed"})
        self.assertFalse(any(call[0] == "selector" for call in after_probe.calls))

        after_write = FakeAws(gate_state="closed")
        candidate = after_write.contract["server"]["candidate_authority"]

        def mutate_after_write() -> None:
            after_write.target_health[candidate["target_group_arns"][0]][0]["TargetHealth"]["State"] = (
                "unhealthy"
            )

        after_write.after_selector_mutation = mutate_after_write
        with self.assertRaisesRegex(CONTROL.ControlError, "rollback: complete"):
            selector_controller(after_write).switch(
                "blue", "candidate", lambda: None
            )
        self.assertEqual(set(after_write.selectors.values()), {"blue"})
        self.assertEqual(set(after_write.gates.values()), {"closed"})

    def test_final_gate_open_or_read_failure_recloses_before_selector_rollback(self) -> None:
        opened = FakeAws(gate_state="closed")
        opened.commit_then_fail_once = ("selector", "server", "candidate")
        original_parallel = CONTROL.parallel
        health_waves = 0

        def open_after_final_health(tasks):
            nonlocal health_waves
            tasks = list(tasks)
            result = original_parallel(tasks)
            if tasks and all("|" in label for label, _ in tasks):
                health_waves += 1
                if health_waves == 3:
                    opened.gates["relay"] = "open"
            return result

        with (
            patch.object(CONTROL, "parallel", side_effect=open_after_final_health),
            self.assertRaisesRegex(CONTROL.ControlError, "rollback: complete"),
        ):
            selector_controller(opened).switch("blue", "candidate", lambda: None)
        self.assertEqual(set(opened.gates.values()), {"closed"})
        self.assertEqual(set(opened.selectors.values()), {"blue"})
        first_rollback = next(
            index
            for index, call in enumerate(opened.calls)
            if call[0] == "selector" and call[2] == "blue"
        )
        closure_calls = {
            call[1]
            for call in opened.calls[:first_rollback]
            if call[0] == "gate" and call[2] == "closed"
        }
        self.assertEqual(closure_calls, set(opened.gates))

        unreadable = FakeAws(gate_state="closed")
        health_waves = 0

        def fail_read_after_final_health(tasks):
            nonlocal health_waves
            tasks = list(tasks)
            result = original_parallel(tasks)
            if tasks and all("|" in label for label, _ in tasks):
                health_waves += 1
                if health_waves == 3:
                    unreadable.gate_read_failures_remaining = 1
            return result

        with (
            patch.object(CONTROL, "parallel", side_effect=fail_read_after_final_health),
            self.assertRaisesRegex(CONTROL.ControlError, "rollback: complete"),
        ):
            selector_controller(unreadable).switch(
                "blue", "candidate", lambda: None
            )
        self.assertEqual(set(unreadable.gates.values()), {"closed"})
        self.assertEqual(set(unreadable.selectors.values()), {"blue"})
        first_rollback = next(
            index
            for index, call in enumerate(unreadable.calls)
            if call[0] == "selector" and call[2] == "blue"
        )
        closure_calls = {
            call[1]
            for call in unreadable.calls[:first_rollback]
            if call[0] == "gate" and call[2] == "closed"
        }
        self.assertEqual(closure_calls, set(unreadable.gates))


class BlackBoxProbeTest(unittest.TestCase):
    def test_probe_requires_exact_digest_mode_latency_and_no_success_shape(self) -> None:
        report = {
            "schema": 1,
            "public_admission_closed": True,
            "server_success": False,
            "ac_https_success": False,
            "ac_frps_success": False,
            "relay_success": False,
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "probe"
            path.write_text("#!/bin/sh\nprintf '%s\\n' '" + json.dumps(report, separators=(",", ":")) + "'\n")
            path.chmod(0o700)
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            CONTROL.run_black_box_probe(str(path), digest, 1, contract())
            with self.assertRaisesRegex(CONTROL.ControlError, "digest"):
                CONTROL.run_black_box_probe(str(path), "0" * 64, 1, contract())
            path.chmod(0o720)
            with self.assertRaisesRegex(CONTROL.ControlError, "mode"):
                CONTROL.run_black_box_probe(str(path), digest, 1, contract())


class WrapperContractTest(unittest.TestCase):
    def test_cli_contract_has_independent_gate_and_selector_operations(self) -> None:
        selector = (SCRIPT_DIR / "prod-matched-cohort-selector.py").read_text()
        maintenance = (SCRIPT_DIR / "prod-matched-cohort-maintenance.py").read_text()
        self.assertIn('choices=("status", "switch")', selector)
        self.assertNotIn('"close"', selector)
        self.assertIn('choices=("status", "close", "open")', maintenance)
        self.assertNotIn('"switch"', maintenance)
        self.assertIn("black_box_probe", selector)
        self.assertIn('"--release-id"', selector)
        self.assertIn("switch requires --release-id", selector)
        self.assertIn('"--release-id"', maintenance)
        self.assertIn("requires --release-id", maintenance)
        self.assertIn('parser.add_argument("--resume", action="store_true")', selector)
        self.assertIn('parser.add_argument("--resume", action="store_true")', maintenance)
        self.assertIn("OperatorLock", selector)
        self.assertIn("OperatorLock", maintenance)
        self.assertIn("signal.SIGTERM", selector)
        self.assertIn("signal.SIGTERM", maintenance)
        self.assertEqual(CONTROL.BLACK_BOX_DEFAULT_TIMEOUT_SECONDS, 2.0)
        self.assertEqual(CONTROL.BLACK_BOX_MAX_TIMEOUT_SECONDS, 5.0)
        self.assertEqual(CONTROL.AWS_CLI_CONNECT_TIMEOUT_SECONDS, 2)
        self.assertEqual(CONTROL.AWS_CLI_READ_TIMEOUT_SECONDS, 3)


if __name__ == "__main__":
    unittest.main()
