#!/usr/bin/env python3
"""Exact maintenance-gate and selector primitives for the prod matched cohort."""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import stat
import subprocess
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Sequence


class ControlError(RuntimeError):
    pass


class GateVectorChanged(ControlError):
    pass


AWS_CLI_CONNECT_TIMEOUT_SECONDS = 2
AWS_CLI_READ_TIMEOUT_SECONDS = 3
BLACK_BOX_DEFAULT_TIMEOUT_SECONDS = 2.0
BLACK_BOX_MAX_TIMEOUT_SECONDS = 5.0
# A healthy selector switch exact-reads every cohort and then its complete
# target-health vector at each of three boundaries: before the closure probe,
# after the probe, and after the parallel selector writes. Each vector is
# bracketed by a second fleet/image/maintenance read that requires unchanged
# physical membership. The selector write is the seventh wave and the final
# bracket is the tenth. This is an integration-test budget, not a retry
# schedule: there is no healthy-path sleep or poll.
HEALTHY_SWITCH_PARALLEL_WAVES = 10
HEALTHY_MAINTENANCE_CLOSE_PARALLEL_WAVES = 3
HEALTHY_MAINTENANCE_OPEN_PARALLEL_WAVES = 5
OPERATOR_LOCK_ID = "prod-matched-cohort"
OPERATOR_LOCK_KEYS = {
    "lock_id",
    "schema",
    "release_id",
    "contract_sha256",
    "state",
    "operation",
    "invocation_token",
}
OPERATOR_OPERATIONS = {"close", "switch", "open"}
CONTRACT_KEYS = {"schema", "environment", "server", "ac", "relay", "maintenance"}
SERVER_KEYS = {
    "canonical_endpoint",
    "canonical_listener_arn",
    "blue_target_group_arn",
    "candidate_target_group_arn",
    "candidate_endpoint",
    "candidate_listener_arn",
    "candidate_smoke_target_group_arn",
    "blue_rollback",
    "candidate_authority",
    "active_assignment_table",
    "candidate_assignment_table",
    "candidate_cloudmap_service_arn",
    "blue_registration_endpoint",
    "green_registration_endpoint",
}
AC_KEYS = {
    "canonical_endpoint",
    "canonical_listener_arn",
    "blue_target_group_arn",
    "candidate_target_group_arn",
    "candidate_endpoint",
    "candidate_listener_arn",
    "candidate_smoke_target_group_arn",
    "active_asg",
    "blue_rollback",
    "candidate_authority",
    "frps_selectors",
}
FLEET_AUTHORITY_KEYS = {
    "asg_name",
    "min_size",
    "max_size",
    "desired_capacity",
    "launch_template_id",
    "launch_template_version",
    "image_parameter",
    "image_tag",
    "target_group_arns",
}
FRPS_SELECTOR_KEYS = {
    "canonical_listener_arn",
    "blue_target_group_arn",
    "candidate_target_group_arn",
    "candidate_listener_arn",
    "listen_port",
}
RELAY_KEYS = {
    "canonical_rule_arn",
    "blue_target_group_arn",
    "candidate_target_group_arn",
    "candidate_listener_arn",
    "candidate_rule_arn",
    "candidate_endpoint",
    "public_hostname",
    "blue_rollback",
    "candidate_authority",
    "blue_server_endpoint",
    "green_server_endpoint",
}
MAINTENANCE_KEYS = {
    "closed_cidr_ipv4",
    "operator_lock_table",
    "server_ingress_rules",
    "ac_ingress_rules",
    "relay_rule",
}
INGRESS_RULE_KEYS = {
    "security_group_id",
    "security_group_rule_id",
    "description",
    "ip_protocol",
    "from_port",
    "to_port",
    "open_cidr_ipv4",
}
RELAY_MAINTENANCE_RULE_KEYS = {
    "rule_arn",
    "open_path",
    "closed_path",
    "methods",
    "status_code",
    "content_type",
    "message_body",
}
BLACK_BOX_KEYS = {
    "schema",
    "public_admission_closed",
    "server_success",
    "ac_https_success",
    "ac_frps_success",
    "relay_success",
}


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def strict_json(raw: str) -> Any:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ControlError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    try:
        return json.loads(raw, object_pairs_hook=reject_duplicates)
    except json.JSONDecodeError as error:
        raise ControlError("JSON is malformed") from error


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ControlError(f"{label} must be an object")
    return value


def _nonempty_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ControlError(f"{label} must be a non-empty string")
    return value


def _validate_ingress_rules(value: Any, label: str, required_names: set[str] | None = None) -> dict[str, Any]:
    rules = _object(value, label)
    if not rules or (required_names is not None and set(rules) != required_names):
        raise ControlError(f"{label} has an unexpected rule set")
    identities: set[str] = set()
    for name, raw in rules.items():
        if not isinstance(name, str) or re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", name) is None:
            raise ControlError(f"{label} contains a malformed name")
        rule = _object(raw, f"{label}.{name}")
        if set(rule) != INGRESS_RULE_KEYS:
            raise ControlError(f"{label}.{name} has an unexpected key set")
        for key in ("security_group_id", "security_group_rule_id", "description", "ip_protocol", "open_cidr_ipv4"):
            _nonempty_string(rule.get(key), f"{label}.{name}.{key}")
        if re.fullmatch(r"sg-[0-9a-f]+", rule["security_group_id"]) is None:
            raise ControlError(f"{label}.{name}.security_group_id is malformed")
        if re.fullmatch(r"sgr-[0-9a-f]+", rule["security_group_rule_id"]) is None:
            raise ControlError(f"{label}.{name}.security_group_rule_id is malformed")
        if rule["security_group_rule_id"] in identities:
            raise ControlError("maintenance ingress rule identities must be unique")
        identities.add(rule["security_group_rule_id"])
        if rule["ip_protocol"] not in ("tcp", "udp"):
            raise ControlError(f"{label}.{name}.ip_protocol is not tcp or udp")
        for key in ("from_port", "to_port"):
            if not isinstance(rule.get(key), int) or isinstance(rule[key], bool) or not 1 <= rule[key] <= 65535:
                raise ControlError(f"{label}.{name}.{key} is not an exact port")
        if rule["from_port"] != rule["to_port"] or rule["open_cidr_ipv4"] != "0.0.0.0/0":
            raise ControlError(f"{label}.{name} is not an exact public single-port rule")
    return rules


def validate_contract(value: Any) -> dict[str, Any]:
    contract = _object(value, "contract")
    if set(contract) != CONTRACT_KEYS or contract.get("schema") != 2 or contract.get("environment") != "prod":
        raise ControlError("contract top-level schema is not exact prod v2")
    for label, keys in (("server", SERVER_KEYS), ("ac", AC_KEYS), ("relay", RELAY_KEYS)):
        part = _object(contract.get(label), f"contract.{label}")
        if set(part) != keys:
            raise ControlError(f"contract.{label} has an unexpected key set")
        for key, item in part.items():
            if key in ("blue_rollback", "candidate_authority") or (label == "ac" and key == "frps_selectors"):
                continue
            _nonempty_string(item, f"contract.{label}.{key}")
    for label in ("server", "ac", "relay"):
        part = contract[label]
        if part["blue_target_group_arn"] == part["candidate_target_group_arn"]:
            raise ControlError(f"contract.{label} target groups must be distinct")
    for label in ("server", "ac"):
        if contract[label]["canonical_listener_arn"] == contract[label]["candidate_listener_arn"]:
            raise ControlError(f"contract.{label} canonical and candidate listeners must be distinct")
        if contract[label]["canonical_endpoint"] == contract[label]["candidate_endpoint"]:
            raise ControlError(f"contract.{label} canonical and candidate endpoints must be distinct")
    if contract["relay"]["public_hostname"] == contract["relay"]["candidate_endpoint"]:
        raise ControlError("contract.relay public and candidate endpoints must be distinct")
    if contract["server"]["blue_registration_endpoint"] == contract["server"]["green_registration_endpoint"]:
        raise ControlError("server registration endpoints must be color-isolated")
    if contract["relay"]["blue_server_endpoint"] == contract["relay"]["green_server_endpoint"]:
        raise ControlError("relay server endpoints must be color-isolated")
    if contract["server"]["active_assignment_table"] == contract["server"]["candidate_assignment_table"]:
        raise ControlError("candidate assignment table must be distinct from active assignment authority")
    for component in ("server", "ac", "relay"):
        for cohort in ("blue_rollback", "candidate_authority"):
            label = f"contract.{component}.{cohort}"
            authority = _object(contract[component][cohort], label)
            if set(authority) != FLEET_AUTHORITY_KEYS:
                raise ControlError(f"{label} has an unexpected key set")
            for key in ("asg_name", "launch_template_id", "launch_template_version", "image_parameter", "image_tag"):
                _nonempty_string(authority.get(key), f"{label}.{key}")
            if re.fullmatch(r"lt-[0-9a-f]+", authority["launch_template_id"]) is None:
                raise ControlError(f"{label}.launch_template_id is malformed")
            if not authority["launch_template_version"].isdigit():
                raise ControlError(f"{label}.launch_template_version is malformed")
            if not authority["image_parameter"].startswith("/prod/nhp/"):
                raise ControlError(f"{label}.image_parameter is outside prod NHP authority")
            if re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}", authority["image_tag"]) is None:
                raise ControlError(f"{label}.image_tag is malformed")
            sizes = [authority.get(key) for key in ("min_size", "desired_capacity", "max_size")]
            if (
                any(isinstance(size, bool) or not isinstance(size, int) for size in sizes)
                or not 1 <= authority["min_size"] <= authority["desired_capacity"] <= authority["max_size"] <= 100
            ):
                raise ControlError(f"{label} capacity is malformed")
            target_groups = authority.get("target_group_arns")
            if (
                not isinstance(target_groups, list)
                or not target_groups
                or target_groups != sorted(target_groups)
                or len(target_groups) != len(set(target_groups))
                or any(
                    not isinstance(target, str)
                    or not target.startswith("arn:aws:elasticloadbalancing:")
                    for target in target_groups
                )
            ):
                raise ControlError(f"{label}.target_group_arns is malformed")

    frps = _object(contract["ac"]["frps_selectors"], "contract.ac.frps_selectors")
    if not frps:
        raise ControlError("contract.ac.frps_selectors must contain the production listener vector")
    ports: set[int] = set()
    listeners = {contract["ac"]["canonical_listener_arn"]}
    for name, raw in frps.items():
        if not isinstance(name, str) or re.fullmatch(r"(?:primary|[a-z][a-z0-9_-]{0,31})", name) is None:
            raise ControlError("contract.ac.frps_selectors contains a malformed name")
        selector = _object(raw, f"contract.ac.frps_selectors.{name}")
        if set(selector) != FRPS_SELECTOR_KEYS:
            raise ControlError(f"contract.ac.frps_selectors.{name} has an unexpected key set")
        for key in FRPS_SELECTOR_KEYS - {"listen_port"}:
            _nonempty_string(selector.get(key), f"contract.ac.frps_selectors.{name}.{key}")
        port = selector.get("listen_port")
        if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535 or port in ports:
            raise ControlError("contract.ac.frps_selectors ports must be unique integers")
        if selector["canonical_listener_arn"] in listeners:
            raise ControlError("contract.ac.frps_selectors canonical listeners must be unique")
        if selector["blue_target_group_arn"] == selector["candidate_target_group_arn"]:
            raise ControlError("contract.ac.frps_selectors target groups must be distinct")
        ports.add(port)
        listeners.add(selector["canonical_listener_arn"])

    required_targets = {
        "server.blue_rollback": {contract["server"]["blue_target_group_arn"]},
        "server.candidate_authority": {
            contract["server"]["candidate_target_group_arn"],
            contract["server"]["candidate_smoke_target_group_arn"],
        },
        "ac.blue_rollback": {
            contract["ac"]["blue_target_group_arn"],
            *[selector["blue_target_group_arn"] for selector in frps.values()],
        },
        "ac.candidate_authority": {
            contract["ac"]["candidate_target_group_arn"],
            contract["ac"]["candidate_smoke_target_group_arn"],
            *[selector["candidate_target_group_arn"] for selector in frps.values()],
        },
        "relay.blue_rollback": {contract["relay"]["blue_target_group_arn"]},
        "relay.candidate_authority": {contract["relay"]["candidate_target_group_arn"]},
    }
    for label, required in required_targets.items():
        component, cohort = label.split(".")
        if not required.issubset(set(contract[component][cohort]["target_group_arns"])):
            raise ControlError(f"contract.{label} omits a selector or smoke target")

    maintenance = _object(contract["maintenance"], "contract.maintenance")
    if set(maintenance) != MAINTENANCE_KEYS or maintenance.get("closed_cidr_ipv4") != "192.0.2.255/32":
        raise ControlError("contract.maintenance is not the exact v2 gate envelope")
    lock_table = _nonempty_string(
        maintenance.get("operator_lock_table"), "contract.maintenance.operator_lock_table"
    )
    if re.fullmatch(r"[A-Za-z0-9_.-]{3,255}", lock_table) is None:
        raise ControlError("contract.maintenance.operator_lock_table is malformed")
    server_rules = _validate_ingress_rules(
        maintenance.get("server_ingress_rules"), "contract.maintenance.server_ingress_rules", {"nhp"}
    )
    ac_rules = _validate_ingress_rules(maintenance.get("ac_ingress_rules"), "contract.maintenance.ac_ingress_rules")
    expected_ac_rules = {"https", "http", "portal", "nhp_connector", "nhp_knock"} | {
        f"frps_{name}" for name in frps
    }
    if set(ac_rules) != expected_ac_rules:
        raise ControlError("AC maintenance rules are not the exact public target-rule vector")
    all_rule_ids = [rule["security_group_rule_id"] for rule in [*server_rules.values(), *ac_rules.values()]]
    if len(all_rule_ids) != len(set(all_rule_ids)):
        raise ControlError("maintenance rule identities overlap")
    relay_gate = _object(maintenance.get("relay_rule"), "contract.maintenance.relay_rule")
    if set(relay_gate) != RELAY_MAINTENANCE_RULE_KEYS:
        raise ControlError("contract.maintenance.relay_rule has an unexpected key set")
    if (
        not isinstance(relay_gate.get("rule_arn"), str)
        or not relay_gate["rule_arn"]
        or relay_gate.get("open_path") != "/__layerv_matched_cohort_maintenance_disabled__"
        or relay_gate.get("closed_path") != "/relay/*"
        or relay_gate.get("methods") != ["POST", "OPTIONS"]
        or relay_gate.get("status_code") != "503"
        or relay_gate.get("content_type") != "application/json"
        or relay_gate.get("message_body") != '{"error":"maintenance"}'
    ):
        raise ControlError("contract.maintenance.relay_rule is not the exact fixed-response gate")
    return contract


def _run(command: Sequence[str]) -> dict[str, Any]:
    result = subprocess.run(command, text=True, capture_output=True, check=False)
    if result.returncode != 0:
        raise ControlError(f"AWS command failed ({command[1]}): {result.stderr.strip()}")
    try:
        return _object(strict_json(result.stdout), f"{command[1]} response")
    except ControlError as error:
        raise ControlError(f"AWS command returned malformed JSON ({command[1]})") from error


def aws_call(invoke: Callable[[Sequence[str]], dict[str, Any]], region: str, *args: str) -> dict[str, Any]:
    return invoke([
        "aws",
        *args,
        "--region",
        region,
        "--output",
        "json",
        "--cli-connect-timeout",
        str(AWS_CLI_CONNECT_TIMEOUT_SECONDS),
        "--cli-read-timeout",
        str(AWS_CLI_READ_TIMEOUT_SECONDS),
    ])


def parallel(tasks: list[tuple[str, Callable[[], Any]]]) -> dict[str, Any]:
    if not tasks:
        return {}
    results: dict[str, Any] = {}
    errors: list[str] = []
    with ThreadPoolExecutor(max_workers=len(tasks), thread_name_prefix="matched-cohort") as executor:
        pending = [(label, executor.submit(operation)) for label, operation in tasks]
        for label, future in pending:
            try:
                results[label] = future.result()
            except BaseException as error:  # noqa: BLE001 - aggregate every independent operation
                errors.append(f"{label}: {error}")
    if errors:
        raise ControlError("; ".join(errors))
    return results


def load_contract(parameter: str, region: str, expected_sha: str) -> dict[str, Any]:
    response = _run([
        "aws",
        "ssm",
        "get-parameter",
        "--name",
        parameter,
        "--region",
        region,
        "--output",
        "json",
        "--cli-connect-timeout",
        str(AWS_CLI_CONNECT_TIMEOUT_SECONDS),
        "--cli-read-timeout",
        str(AWS_CLI_READ_TIMEOUT_SECONDS),
    ])
    raw = _object(response.get("Parameter"), "SSM Parameter").get("Value")
    if not isinstance(raw, str):
        raise ControlError("SSM contract value is missing")
    contract = validate_contract(strict_json(raw))
    digest = hashlib.sha256(canonical_json(contract).encode()).hexdigest()
    if digest != expected_sha:
        raise ControlError(f"SSM contract digest mismatch: expected {expected_sha}, got {digest}")
    return contract


@dataclass
class OperatorLock:
    """Durable release journal plus one exact per-command invocation mutex."""

    table: str
    release_id: str
    contract_sha256: str
    region: str
    invoke: Callable[[Sequence[str]], dict[str, Any]] = _run
    invocation_token: str = ""

    def __post_init__(self) -> None:
        if re.fullmatch(r"[A-Za-z0-9_.-]{3,255}", self.table) is None:
            raise ControlError("operator lock table is malformed")
        if re.fullmatch(r"[0-9a-f]{64}", self.release_id) is None:
            raise ControlError("operator release identity must be 64 lowercase hex")
        if re.fullmatch(r"[0-9a-f]{64}", self.contract_sha256) is None:
            raise ControlError("operator lock contract digest is malformed")
        if not self.invocation_token:
            self.invocation_token = secrets.token_hex(32)
        if re.fullmatch(r"[0-9a-f]{64}", self.invocation_token) is None:
            raise ControlError("operator invocation token must be 64 lowercase hex")

    def _aws(self, *args: str) -> dict[str, Any]:
        return aws_call(self.invoke, self.region, *args)

    def _item(self, state: str, operation: str, invocation_token: str) -> dict[str, dict[str, str]]:
        return {
            "lock_id": {"S": OPERATOR_LOCK_ID},
            "schema": {"N": "1"},
            "release_id": {"S": self.release_id},
            "contract_sha256": {"S": self.contract_sha256},
            "state": {"S": state},
            "operation": {"S": operation},
            "invocation_token": {"S": invocation_token},
        }

    def idle_item(self) -> dict[str, dict[str, str]]:
        return self._item("idle", "none", "none")

    def active_item(self, operation: str) -> dict[str, dict[str, str]]:
        if operation not in OPERATOR_OPERATIONS:
            raise ControlError("operator lock operation is not closed")
        return self._item("active", operation, self.invocation_token)

    def _read(self) -> dict[str, dict[str, str]] | None:
        response = self._aws(
            "dynamodb",
            "get-item",
            "--table-name",
            self.table,
            "--key",
            canonical_json({"lock_id": {"S": OPERATOR_LOCK_ID}}),
            "--consistent-read",
        )
        raw = response.get("Item")
        if raw is None:
            return None
        item = _object(raw, "operator lock item")
        if set(item) != OPERATOR_LOCK_KEYS:
            raise ControlError("operator lock item has an unexpected key set")
        expected_types = {
            "lock_id": "S",
            "schema": "N",
            "release_id": "S",
            "contract_sha256": "S",
            "state": "S",
            "operation": "S",
            "invocation_token": "S",
        }
        for key, value_type in expected_types.items():
            value = _object(item.get(key), f"operator lock item.{key}")
            if set(value) != {value_type} or not isinstance(value[value_type], str):
                raise ControlError(f"operator lock item.{key} is malformed")
        return item

    @staticmethod
    def _value(item: dict[str, dict[str, str]], key: str) -> str:
        kind = "N" if key == "schema" else "S"
        return item[key][kind]

    def _replace(
        self,
        current: dict[str, dict[str, str]] | None,
        desired: dict[str, dict[str, str]],
    ) -> None:
        mutation_error: BaseException | None = None
        try:
            args = [
                "dynamodb", "put-item", "--table-name", self.table,
                "--item", canonical_json(desired),
            ]
            if current is None:
                args.extend(["--condition-expression", "attribute_not_exists(lock_id)"])
            else:
                names = {f"#{key}": key for key in OPERATOR_LOCK_KEYS}
                values = {
                    f":{key}": current[key]
                    for key in OPERATOR_LOCK_KEYS
                }
                condition = " AND ".join(f"#{key} = :{key}" for key in sorted(OPERATOR_LOCK_KEYS))
                args.extend([
                    "--condition-expression", condition,
                    "--expression-attribute-names", canonical_json(names),
                    "--expression-attribute-values", canonical_json(values),
                ])
            self._aws(*args)
        except BaseException as error:  # noqa: BLE001 - exact strong read classifies lost response/contention
            mutation_error = error
        observed = self._read()
        if observed != desired:
            raise ControlError(
                "operator journal CAS did not establish this invocation: "
                f"current={canonical_json(observed)} mutation={mutation_error}"
            )

    def begin(self, operation: str, *, resume: bool = False) -> None:
        desired = self.active_item(operation)
        current = self._read()
        if current is None:
            if operation != "close":
                raise ControlError("operator journal is absent; maintenance close must run first")
            self._replace(None, desired)
            return
        if (
            self._value(current, "release_id") != self.release_id
            or self._value(current, "contract_sha256") != self.contract_sha256
            or self._value(current, "lock_id") != OPERATOR_LOCK_ID
            or self._value(current, "schema") != "1"
        ):
            raise ControlError(f"operator journal belongs to another release: {canonical_json(current)}")
        state = self._value(current, "state")
        current_operation = self._value(current, "operation")
        current_token = self._value(current, "invocation_token")
        if state == "idle" and current_operation == "none" and current_token == "none":
            self._replace(current, desired)
            return
        if state != "active" or current_operation not in OPERATOR_OPERATIONS or re.fullmatch(
            r"[0-9a-f]{64}", current_token
        ) is None:
            raise ControlError("operator journal state is malformed")
        if current_operation != operation:
            raise ControlError(
                f"operator journal has active {current_operation}; cannot begin {operation}"
            )
        if not resume:
            raise ControlError(f"operator {operation} already has an active invocation")
        # PR2's normal workflow concurrency must first cancel and await the
        # predecessor. Resume then uses this exact CAS to adopt an abandoned
        # same-operation token; two successor attempts still have one winner.
        self._replace(current, desired)

    def assert_owned(self, operation: str) -> None:
        current = self._read()
        if current != self.active_item(operation):
            raise ControlError(f"operator invocation ownership changed: {canonical_json(current)}")

    def complete(self, operation: str, *, release: bool = False) -> None:
        expected = self.active_item(operation)
        self.assert_owned(operation)
        if not release:
            self._replace(expected, self.idle_item())
            return
        mutation_error: BaseException | None = None
        try:
            self._aws(
                "dynamodb",
                "delete-item",
                "--table-name",
                self.table,
                "--key",
                canonical_json({"lock_id": {"S": OPERATOR_LOCK_ID}}),
                "--condition-expression",
                "#release = :release AND contract_sha256 = :digest AND #schema = :schema AND #state = :state AND operation = :operation AND invocation_token = :token",
                "--expression-attribute-names", canonical_json({
                    "#release": "release_id", "#schema": "schema", "#state": "state",
                }),
                "--expression-attribute-values",
                canonical_json({
                    ":release": {"S": self.release_id},
                    ":digest": {"S": self.contract_sha256},
                    ":schema": {"N": "1"},
                    ":state": {"S": "active"},
                    ":operation": {"S": operation},
                    ":token": {"S": self.invocation_token},
                }),
            )
        except BaseException as error:  # noqa: BLE001 - post-read classifies a committed lost response
            mutation_error = error
        current = self._read()
        if current is not None:
            raise ControlError(
                "operator journal release is not exact: "
                f"current={canonical_json(current)} mutation={mutation_error}"
            )


def _validate_forward(action: Any, label: str) -> str:
    value = _object(action, label)
    if set(value) - {"Type", "TargetGroupArn", "Order", "ForwardConfig"} or value.get("Type") != "forward":
        raise ControlError(f"{label} is not an exact forward")
    target = value.get("TargetGroupArn")
    if not isinstance(target, str) or not target:
        raise ControlError(f"{label} target is missing")
    if "ForwardConfig" in value:
        config = _object(value["ForwardConfig"], f"{label}.ForwardConfig")
        if set(config) - {"TargetGroups", "TargetGroupStickinessConfig"}:
            raise ControlError(f"{label}.ForwardConfig has unexpected fields")
        groups = config.get("TargetGroups")
        if not isinstance(groups, list) or len(groups) != 1:
            raise ControlError(f"{label}.ForwardConfig is not single-target")
        group = _object(groups[0], f"{label}.ForwardConfig target")
        if set(group) - {"TargetGroupArn", "Weight"} or group.get("TargetGroupArn") != target:
            raise ControlError(f"{label}.ForwardConfig target disagrees")
        if group.get("Weight", 1) != 1:
            raise ControlError(f"{label}.ForwardConfig weight is not one")
        if config.get("TargetGroupStickinessConfig") not in (None, {"Enabled": False}):
            raise ControlError(f"{label}.ForwardConfig stickiness is enabled")
    return target


def selector_units(contract: dict[str, Any]) -> list[tuple[str, str, dict[str, Any]]]:
    units = [
        ("server", "listener", contract["server"]),
        ("ac.https", "listener", contract["ac"]),
    ]
    units.extend(
        (f"ac.frps.{name}", "listener", selector)
        for name, selector in sorted(contract["ac"]["frps_selectors"].items())
    )
    units.append(("relay", "rule", contract["relay"]))
    return units


def fleet_units(contract: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    return [
        (f"{component}.{cohort}", contract[component][authority])
        for component in ("server", "ac", "relay")
        for cohort, authority in (("blue", "blue_rollback"), ("candidate", "candidate_authority"))
    ]


@dataclass
class SelectorController:
    contract: dict[str, Any]
    region: str
    invoke: Callable[[Sequence[str]], dict[str, Any]] = _run
    operator_lock: OperatorLock | None = None
    resume_active: bool = False

    def _aws(self, *args: str) -> dict[str, Any]:
        return aws_call(self.invoke, self.region, *args)

    def _read_unit(self, label: str, kind: str, part: dict[str, Any]) -> str:
        if kind == "listener":
            response = self._aws("elbv2", "describe-listeners", "--listener-arns", part["canonical_listener_arn"])
            rows = response.get("Listeners")
            actions = _object(rows[0], label).get("DefaultActions") if isinstance(rows, list) and len(rows) == 1 else None
        else:
            response = self._aws("elbv2", "describe-rules", "--rule-arns", part["canonical_rule_arn"])
            rows = response.get("Rules")
            actions = _object(rows[0], label).get("Actions") if isinstance(rows, list) and len(rows) == 1 else None
        if not isinstance(actions, list) or len(actions) != 1:
            raise ControlError(f"{label} selector action is not singular")
        target = _validate_forward(actions[0], f"{label} selector")
        mapping = {
            part["blue_target_group_arn"]: "blue",
            part["candidate_target_group_arn"]: "candidate",
        }
        if target not in mapping:
            raise ControlError(f"{label} selector points outside the reviewed contract")
        return mapping[target]

    def flat_state(self) -> dict[str, str]:
        return parallel([
            (label, lambda label=label, kind=kind, part=part: self._read_unit(label, kind, part))
            for label, kind, part in selector_units(self.contract)
        ])

    def state(self) -> dict[str, str]:
        flat = self.flat_state()
        return self._state_from_flat(flat)

    def _state_from_flat(self, flat: dict[str, str]) -> dict[str, str]:
        expected = {label for label, _, _ in selector_units(self.contract)}
        if set(flat) != expected:
            raise ControlError("selector read does not have exact physical parity")
        ac = {state for label, state in flat.items() if label.startswith("ac.")}
        if len(ac) != 1:
            raise ControlError(f"AC selector vector is torn: {canonical_json(flat)}")
        return {"server": flat["server"], "ac": next(iter(ac)), "relay": flat["relay"]}

    def _read_candidate_unit(self, label: str, kind: str, part: dict[str, Any]) -> None:
        if kind == "listener":
            response = self._aws("elbv2", "describe-listeners", "--listener-arns", part["candidate_listener_arn"])
            rows = response.get("Listeners")
            actions = _object(rows[0], label).get("DefaultActions") if isinstance(rows, list) and len(rows) == 1 else None
            expected = part.get("candidate_smoke_target_group_arn", part["candidate_target_group_arn"])
        else:
            response = self._aws("elbv2", "describe-rules", "--rule-arns", part["candidate_rule_arn"])
            rows = response.get("Rules")
            actions = _object(rows[0], label).get("Actions") if isinstance(rows, list) and len(rows) == 1 else None
            expected = part["candidate_target_group_arn"]
        if not isinstance(actions, list) or len(actions) != 1:
            raise ControlError(f"{label} candidate action is not singular")
        if _validate_forward(actions[0], f"{label} candidate") != expected:
            raise ControlError(f"{label} candidate route points outside its reviewed target")

    def _assert_active_ac_stopped(self) -> None:
        name = self.contract["ac"]["active_asg"]
        response = self._aws("autoscaling", "describe-auto-scaling-groups", "--auto-scaling-group-names", name)
        groups = response.get("AutoScalingGroups")
        if not isinstance(groups, list) or len(groups) != 1:
            raise ControlError("active AC ASG read is not singular")
        group = _object(groups[0], "active AC ASG")
        if group.get("AutoScalingGroupName") != name:
            raise ControlError("active AC ASG identity changed")
        if any(group.get(field) != 0 for field in ("MinSize", "MaxSize", "DesiredCapacity")):
            raise ControlError("active canonical-endpoint AC ASG is not fenced at 0/0/0")
        if group.get("Instances") != [] or group.get("SuspendedProcesses") != []:
            raise ControlError("active canonical-endpoint AC ASG retains instances or process drift")

    def _read_fleet(self, label: str, authority: dict[str, Any]) -> set[str]:
        name = authority["asg_name"]
        response = self._aws("autoscaling", "describe-auto-scaling-groups", "--auto-scaling-group-names", name)
        groups = response.get("AutoScalingGroups")
        if not isinstance(groups, list) or len(groups) != 1:
            raise ControlError(f"{label} ASG read is not singular")
        group = _object(groups[0], f"{label} ASG")
        expected_scalars = {
            "AutoScalingGroupName": name,
            "MinSize": authority["min_size"],
            "MaxSize": authority["max_size"],
            "DesiredCapacity": authority["desired_capacity"],
        }
        if any(group.get(key) != value for key, value in expected_scalars.items()):
            raise ControlError(f"{label} ASG capacity or identity drifted")
        if group.get("SuspendedProcesses") != [] or group.get("MixedInstancesPolicy") not in (None, {}):
            raise ControlError(f"{label} ASG has suspended processes or mixed launch authority")
        target_groups = group.get("TargetGroupARNs")
        if (
            not isinstance(target_groups, list)
            or len(target_groups) != len(set(target_groups))
            or sorted(target_groups) != authority["target_group_arns"]
        ):
            raise ControlError(f"{label} ASG target-group authority drifted")
        expected_template = {
            "LaunchTemplateId": authority["launch_template_id"],
            "Version": authority["launch_template_version"],
        }
        launch_template = _object(group.get("LaunchTemplate"), f"{label} launch template")
        if launch_template != expected_template:
            raise ControlError(f"{label} ASG launch template drifted")
        instances = group.get("Instances")
        if not isinstance(instances, list) or len(instances) != authority["desired_capacity"]:
            raise ControlError(f"{label} ASG does not have full desired membership")
        instance_ids: set[str] = set()
        for raw in instances:
            instance = _object(raw, f"{label} instance")
            instance_id = instance.get("InstanceId")
            if not isinstance(instance_id, str) or not instance_id or instance_id in instance_ids:
                raise ControlError(f"{label} instance identity is malformed or duplicated")
            instance_ids.add(instance_id)
            if instance.get("LifecycleState") != "InService" or instance.get("HealthStatus") != "Healthy":
                raise ControlError(f"{label} ASG contains a non-ready instance")
            if _object(instance.get("LaunchTemplate"), f"{label} instance launch template") != expected_template:
                raise ControlError(f"{label} instance launch template drifted")
        return instance_ids

    def _assert_target_health(self, label: str, target_group: str, instance_ids: set[str]) -> None:
        response = self._aws("elbv2", "describe-target-health", "--target-group-arn", target_group)
        descriptions = response.get("TargetHealthDescriptions")
        if not isinstance(descriptions, list) or len(descriptions) != len(instance_ids):
            raise ControlError(f"{label} target health is incomplete for {target_group}")
        observed_ids: set[str] = set()
        for raw in descriptions:
            description = _object(raw, f"{label} target health description")
            target = _object(description.get("Target"), f"{label} target")
            instance_id = target.get("Id")
            if not isinstance(instance_id, str) or instance_id in observed_ids:
                raise ControlError(f"{label} target identity is malformed for {target_group}")
            observed_ids.add(instance_id)
            health = _object(description.get("TargetHealth"), f"{label} target health")
            if health.get("State") != "healthy":
                raise ControlError(f"{label} target is not healthy for {target_group}")
        if observed_ids != instance_ids:
            raise ControlError(f"{label} target membership drifted for {target_group}")

    def _assert_fleet_image(self, label: str, authority: dict[str, Any]) -> None:
        response = self._aws("ssm", "get-parameter", "--name", authority["image_parameter"])
        parameter = _object(response.get("Parameter"), f"{label} image parameter")
        if (
            parameter.get("Name") != authority["image_parameter"]
            or parameter.get("Type") != "String"
            or parameter.get("DataType", "text") != "text"
            or parameter.get("Value") != authority["image_tag"]
            or isinstance(parameter.get("Version"), bool)
            or not isinstance(parameter.get("Version"), int)
            or parameter["Version"] < 1
        ):
            raise ControlError(f"{label} image authority drifted")

    def _snapshot(
        self,
        gates: MaintenanceController,
    ) -> tuple[dict[str, str], dict[str, str]]:
        candidate_tasks = [
            (f"candidate.{label}", lambda label=label, kind=kind, part=part: self._read_candidate_unit(label, kind, part))
            for label, kind, part in selector_units(self.contract)
        ]
        fleets = fleet_units(self.contract)
        results = parallel([
            (f"selector.{label}", lambda label=label, kind=kind, part=part: self._read_unit(label, kind, part))
            for label, kind, part in selector_units(self.contract)
        ] + candidate_tasks + [
            ("active-ac", self._assert_active_ac_stopped),
            *[
                (f"fleet.{label}", lambda label=label, authority=authority: self._read_fleet(label, authority))
                for label, authority in fleets
            ],
            *[
                (f"image.{label}", lambda label=label, authority=authority: self._assert_fleet_image(label, authority))
                for label, authority in fleets
            ],
            ("gate.security-groups", gates._read_sg_rules),
            ("gate.relay", gates._read_relay_gate),
        ])
        parallel([
            (
                f"{label}|{target_group}",
                lambda label=label, target_group=target_group, instance_ids=results[f"fleet.{label}"]: self._assert_target_health(
                    label, target_group, instance_ids
                ),
            )
            for label, authority in fleets
            for target_group in authority["target_group_arns"]
        ])
        bracket = parallel([
            *[
                (f"selector.{label}", lambda label=label, kind=kind, part=part: self._read_unit(label, kind, part))
                for label, kind, part in selector_units(self.contract)
            ],
            *candidate_tasks,
            ("active-ac", self._assert_active_ac_stopped),
            *[
                (f"fleet.{label}", lambda label=label, authority=authority: self._read_fleet(label, authority))
                for label, authority in fleets
            ],
            *[
                (f"image.{label}", lambda label=label, authority=authority: self._assert_fleet_image(label, authority))
                for label, authority in fleets
            ],
            ("gate.security-groups", gates._read_sg_rules),
            ("gate.relay", gates._read_relay_gate),
        ])
        for label, _ in fleets:
            if bracket[f"fleet.{label}"] != results[f"fleet.{label}"]:
                raise ControlError(f"{label} ASG membership changed during target-health verification")
        selectors = {
            key.removeprefix("selector."): value
            for key, value in results.items()
            if key.startswith("selector.")
        }
        selectors_after = {
            key.removeprefix("selector."): value
            for key, value in bracket.items()
            if key.startswith("selector.")
        }
        if selectors_after != selectors:
            raise ControlError(
                "selector vector changed during target-health verification: "
                f"before={canonical_json(selectors)} after={canonical_json(selectors_after)}"
            )
        gate_before = dict(results["gate.security-groups"])
        gate_before["relay"] = results["gate.relay"]
        gate_after = dict(bracket["gate.security-groups"])
        gate_after["relay"] = bracket["gate.relay"]
        if gate_before != gate_after:
            raise GateVectorChanged(
                "maintenance gate vector changed during target-health verification: "
                f"before={canonical_json(gate_before)} after={canonical_json(gate_after)}"
            )
        return selectors, gate_after

    @staticmethod
    def _require_closed(gate_state: dict[str, str]) -> None:
        if not gate_state or not all(value == "closed" for value in gate_state.values()):
            raise ControlError(f"maintenance gates are not exact closed: {canonical_json(gate_state)}")

    def _set_unit(self, label: str, kind: str, part: dict[str, Any], state: str) -> None:
        action = canonical_json([{"Type": "forward", "TargetGroupArn": part[f"{state}_target_group_arn"]}])
        if kind == "listener":
            self._aws("elbv2", "modify-listener", "--listener-arn", part["canonical_listener_arn"], "--default-actions", action)
        else:
            self._aws("elbv2", "modify-rule", "--rule-arn", part["canonical_rule_arn"], "--actions", action)

    def _set_all(self, state: str) -> None:
        parallel([
            (label, lambda label=label, kind=kind, part=part: self._set_unit(label, kind, part, state))
            for label, kind, part in selector_units(self.contract)
        ])

    def switch(self, expected: str, desired: str, closure_probe: Callable[[], None]) -> dict[str, str]:
        if {expected, desired} != {"blue", "candidate"}:
            raise ControlError("selector switch must be blue to candidate or candidate to blue")
        if self.operator_lock is None:
            raise ControlError("selector switch requires the shared operator lock")
        self.operator_lock.begin("switch", resume=self.resume_active)
        gates = MaintenanceController(self.contract, self.region, self.invoke)
        try:
            initial, gate_state = self._snapshot(gates)
        except GateVectorChanged as error:
            close_error: BaseException | None = None
            try:
                gates.reestablish_closed()
            except BaseException as close_failure:  # noqa: BLE001
                close_error = close_failure
            raise ControlError(
                f"initial selector readiness failed: {error}; re-close: {close_error or 'complete'}"
            ) from error
        self._require_closed(gate_state)
        if any(state not in (expected, desired) for state in initial.values()):
            raise ControlError(f"selector state is outside the requested transition: {canonical_json(initial)}")
        closure_probe()
        try:
            current, gate_state = self._snapshot(gates)
            self._require_closed(gate_state)
        except BaseException as error:  # noqa: BLE001 - no success may escape an uncertain closure bracket
            close_error: BaseException | None = None
            try:
                gates.reestablish_closed()
            except BaseException as close_failure:  # noqa: BLE001
                close_error = close_failure
            raise ControlError(
                f"post-probe selector readiness failed: {error}; re-close: {close_error or 'complete'}"
            ) from error
        if any(state not in (expected, desired) for state in current.values()):
            raise ControlError(f"selector changed during closure probe: {canonical_json(current)}")
        if all(state == desired for state in current.values()):
            self.operator_lock.assert_owned("switch")
            self.operator_lock.complete("switch")
            return self._state_from_flat(current)
        mutation_error: BaseException | None = None
        try:
            self._set_all(desired)
        except BaseException as error:  # noqa: BLE001 - classify every ambiguous member by exact readback
            mutation_error = error
        try:
            observed, gate_state = self._snapshot(gates)
            self._require_closed(gate_state)
            if all(state == desired for state in observed.values()):
                self.operator_lock.assert_owned("switch")
                self.operator_lock.complete("switch")
                return self._state_from_flat(observed)
        except BaseException as error:  # noqa: BLE001
            mutation_error = ControlError(f"selector readback failed: {error}; mutation: {mutation_error}")
            observed = {}
            gate_state = {}
        rollback_error: BaseException | None = None
        try:
            # Completion may have established idle before its response/readback
            # raced a successor acquisition. Never mutate selectors or gates
            # after this invocation has lost the journal mutex.
            self.operator_lock.assert_owned("switch")
            gates.reestablish_closed()
            rollback_mutation_error: BaseException | None = None
            try:
                self._set_all(expected)
            except BaseException as error:  # noqa: BLE001 - exact readback classifies lost responses
                rollback_mutation_error = error
            restored = self.flat_state()
            if not all(state == expected for state in restored.values()):
                raise ControlError(
                    f"selector rollback is torn: {canonical_json(restored)}; mutation: {rollback_mutation_error}"
                )
            gates.require_state("closed")
            self.operator_lock.complete("switch")
        except BaseException as error:  # noqa: BLE001
            rollback_error = error
        raise ControlError(
            f"selector switch failed: {mutation_error or canonical_json(observed)}; rollback: {rollback_error or 'complete'}"
        )


@dataclass
class MaintenanceController:
    contract: dict[str, Any]
    region: str
    invoke: Callable[[Sequence[str]], dict[str, Any]] = _run
    operator_lock: OperatorLock | None = None
    resume_active: bool = False

    def _aws(self, *args: str) -> dict[str, Any]:
        return aws_call(self.invoke, self.region, *args)

    def _rules(self) -> list[tuple[str, dict[str, Any]]]:
        maintenance = self.contract["maintenance"]
        return [
            *[(f"server.{name}", rule) for name, rule in sorted(maintenance["server_ingress_rules"].items())],
            *[(f"ac.{name}", rule) for name, rule in sorted(maintenance["ac_ingress_rules"].items())],
        ]

    def _read_sg_rules(self) -> dict[str, str]:
        rules = self._rules()
        response = self._aws(
            "ec2", "describe-security-group-rules", "--security-group-rule-ids",
            *[rule["security_group_rule_id"] for _, rule in rules],
        )
        rows = response.get("SecurityGroupRules")
        if not isinstance(rows, list) or len(rows) != len(rules):
            raise ControlError("maintenance ingress-rule read does not have exact physical parity")
        by_id = {}
        for raw in rows:
            row = _object(raw, "maintenance ingress rule")
            identity = row.get("SecurityGroupRuleId")
            if not isinstance(identity, str) or identity in by_id:
                raise ControlError("maintenance ingress-rule read has duplicate or missing identity")
            by_id[identity] = row
        state: dict[str, str] = {}
        closed = self.contract["maintenance"]["closed_cidr_ipv4"]
        for label, rule in rules:
            row = by_id.get(rule["security_group_rule_id"])
            if row is None:
                raise ControlError(f"{label} maintenance rule is missing")
            exact = {
                "GroupId": rule["security_group_id"],
                "IsEgress": False,
                "IpProtocol": rule["ip_protocol"],
                "FromPort": rule["from_port"],
                "ToPort": rule["to_port"],
                "Description": rule["description"],
            }
            if any(row.get(key) != value for key, value in exact.items()):
                raise ControlError(f"{label} maintenance rule authority drifted")
            if any(key in row for key in ("CidrIpv6", "PrefixListId", "ReferencedGroupInfo")):
                raise ControlError(f"{label} maintenance rule gained a second source authority")
            cidr = row.get("CidrIpv4")
            if cidr == rule["open_cidr_ipv4"]:
                state[label] = "open"
            elif cidr == closed:
                state[label] = "closed"
            else:
                raise ControlError(f"{label} maintenance rule CIDR is outside the reviewed gate")
        return state

    def _read_relay_gate(self) -> str:
        gate = self.contract["maintenance"]["relay_rule"]
        response = self._aws("elbv2", "describe-rules", "--rule-arns", gate["rule_arn"])
        rows = response.get("Rules")
        if not isinstance(rows, list) or len(rows) != 1:
            raise ControlError("relay maintenance rule read is not singular")
        row = _object(rows[0], "relay maintenance rule")
        if set(row) - {"RuleArn", "Priority", "Conditions", "Actions", "IsDefault", "Transforms"}:
            raise ControlError("relay maintenance rule has unexpected fields")
        if row.get("RuleArn") != gate["rule_arn"] or row.get("Priority") != "1":
            raise ControlError("relay maintenance rule identity or priority drifted")
        if row.get("IsDefault") not in (None, False) or row.get("Transforms") not in (None, []):
            raise ControlError("relay maintenance rule gained default or transform authority")
        actions = row.get("Actions")
        if not isinstance(actions, list) or len(actions) != 1:
            raise ControlError("relay maintenance action is not singular")
        action = _object(actions[0], "relay maintenance action")
        if set(action) - {"Type", "Order", "FixedResponseConfig"} or action.get("Type") != "fixed-response":
            raise ControlError("relay maintenance action is not an exact fixed response")
        if action.get("FixedResponseConfig") != {
            "MessageBody": gate["message_body"],
            "StatusCode": gate["status_code"],
            "ContentType": gate["content_type"],
        }:
            raise ControlError("relay maintenance fixed response drifted")
        conditions = row.get("Conditions")
        if not isinstance(conditions, list) or len(conditions) != 2:
            raise ControlError("relay maintenance conditions are not exact")
        path: str | None = None
        methods: list[str] | None = None
        for raw in conditions:
            condition = _object(raw, "relay maintenance condition")
            field = condition.get("Field")
            if field == "path-pattern":
                if set(condition) not in (
                    {"Field", "Values", "PathPatternConfig"},
                    {"Field", "PathPatternConfig"},
                ):
                    raise ControlError("relay maintenance path condition has unexpected fields")
                config = _object(condition.get("PathPatternConfig"), "relay maintenance path")
                values = config.get("Values")
                if set(config) != {"Values"} or condition.get("Values") not in (None, values):
                    raise ControlError("relay maintenance path condition drifted")
                if not isinstance(values, list) or len(values) != 1:
                    raise ControlError("relay maintenance path is not singular")
                path = values[0]
            elif field == "http-request-method":
                if set(condition) not in (
                    {"Field", "Values", "HttpRequestMethodConfig"},
                    {"Field", "HttpRequestMethodConfig"},
                ):
                    raise ControlError("relay maintenance method condition has unexpected fields")
                config = _object(condition.get("HttpRequestMethodConfig"), "relay maintenance methods")
                values = config.get("Values")
                if set(config) != {"Values"} or condition.get("Values") not in (None, values):
                    raise ControlError("relay maintenance method condition drifted")
                if values != gate["methods"]:
                    raise ControlError("relay maintenance methods drifted")
                methods = values
            else:
                raise ControlError("relay maintenance gained an unreviewed condition")
        if methods is None:
            raise ControlError("relay maintenance method condition is missing")
        if path == gate["open_path"]:
            return "open"
        if path == gate["closed_path"]:
            return "closed"
        raise ControlError("relay maintenance path is outside the reviewed gate")

    def flat_state(self) -> dict[str, str]:
        results = parallel([
            ("security-groups", self._read_sg_rules),
            ("relay", self._read_relay_gate),
        ])
        return self._gate_state_from_results(results)

    @staticmethod
    def _gate_state_from_results(results: dict[str, Any]) -> dict[str, str]:
        state = dict(results["security-groups"])
        state["relay"] = results["relay"]
        return state

    def _open_preflight(self, required_selector: str) -> dict[str, str]:
        selector = SelectorController(self.contract, self.region, self.invoke)
        results = parallel([
            *[
                (
                    f"selector.{label}",
                    lambda label=label, kind=kind, part=part: selector._read_unit(label, kind, part),
                )
                for label, kind, part in selector_units(self.contract)
            ],
            ("security-groups", self._read_sg_rules),
            ("relay", self._read_relay_gate),
        ])
        selector_state = selector._state_from_flat({
            key.removeprefix("selector."): value
            for key, value in results.items()
            if key.startswith("selector.")
        })
        if not all(value == required_selector for value in selector_state.values()):
            raise ControlError(f"selectors are not exact {required_selector}: {canonical_json(selector_state)}")
        return self._gate_state_from_results(results)

    def _postcheck_open_or_reclose(self, required_selector: str) -> None:
        try:
            if self.operator_lock is None:
                raise ControlError("maintenance open requires the shared operator lock")
            self.operator_lock.assert_owned("open")
            before = self._open_preflight(required_selector)
            after = self._open_preflight(required_selector)
            if before != after:
                raise ControlError(
                    "selector or maintenance gate vector changed during final open bracket: "
                    f"before={canonical_json(before)} after={canonical_json(after)}"
                )
            if not all(state == "open" for state in after.values()):
                raise ControlError(f"maintenance gates are not exact open: {canonical_json(after)}")
            self.operator_lock.assert_owned("open")
        except BaseException as error:  # noqa: BLE001 - re-close after any post-open uncertainty
            close_error: BaseException | None = None
            try:
                # A successor can resume the abandoned open token while the
                # final bracket is in flight. Only the current journal owner
                # may re-close public admission.
                self.operator_lock.assert_owned("open")
                self.reestablish_closed()
            except BaseException as close_failure:  # noqa: BLE001
                close_error = close_failure
            raise ControlError(
                f"maintenance open selector recheck failed: {error}; re-close: {close_error or 'complete'}"
            ) from error

    def state(self) -> str:
        values = set(self.flat_state().values())
        if len(values) != 1:
            raise ControlError("maintenance gates are torn")
        return next(iter(values))

    def require_state(self, expected: str) -> None:
        state = self.flat_state()
        if not all(value == expected for value in state.values()):
            raise ControlError(f"maintenance gates are not exact {expected}: {canonical_json(state)}")

    def reestablish_closed(self) -> None:
        mutation_error: BaseException | None = None
        try:
            self._set_all("closed")
        except BaseException as error:  # noqa: BLE001 - exact readback classifies lost responses
            mutation_error = error
        try:
            observed = self.flat_state()
        except BaseException as error:  # noqa: BLE001
            raise ControlError(
                f"maintenance closure readback failed: {error}; mutation: {mutation_error}"
            ) from error
        if not all(state == "closed" for state in observed.values()):
            raise ControlError(
                f"maintenance could not be re-established closed: {canonical_json(observed)}; mutation: {mutation_error}"
            )

    def _set_sg(self, rule: dict[str, Any], state: str) -> None:
        cidr = rule["open_cidr_ipv4"] if state == "open" else self.contract["maintenance"]["closed_cidr_ipv4"]
        payload = {
            "GroupId": rule["security_group_id"],
            "SecurityGroupRules": [{
                "SecurityGroupRuleId": rule["security_group_rule_id"],
                "SecurityGroupRule": {
                    "Description": rule["description"],
                    "IpProtocol": rule["ip_protocol"],
                    "FromPort": rule["from_port"],
                    "ToPort": rule["to_port"],
                    "CidrIpv4": cidr,
                },
            }],
        }
        self._aws("ec2", "modify-security-group-rules", "--cli-input-json", canonical_json(payload))

    def _set_relay_gate(self, state: str) -> None:
        gate = self.contract["maintenance"]["relay_rule"]
        conditions = [
            {"Field": "path-pattern", "PathPatternConfig": {"Values": [gate[f"{state}_path"]]}},
            {"Field": "http-request-method", "HttpRequestMethodConfig": {"Values": gate["methods"]}},
        ]
        self._aws(
            "elbv2", "modify-rule", "--rule-arn", gate["rule_arn"],
            "--conditions", canonical_json(conditions),
        )

    def _set_all(self, state: str) -> None:
        parallel([
            *[(label, lambda rule=rule: self._set_sg(rule, state)) for label, rule in self._rules()],
            ("relay", lambda: self._set_relay_gate(state)),
        ])

    def transition(self, expected: str, desired: str, *, required_selector: str | None = None) -> str:
        if {expected, desired} != {"open", "closed"}:
            raise ControlError("maintenance transition must be open to closed or closed to open")
        if self.operator_lock is None:
            raise ControlError("maintenance transition requires the shared operator lock")
        operation = "close" if desired == "closed" else "open"
        self.operator_lock.begin(operation, resume=self.resume_active)
        if desired == "open":
            if required_selector not in ("blue", "candidate"):
                raise ControlError("opening maintenance requires an exact selector target")
            initial = self._open_preflight(required_selector)
        else:
            initial = self.flat_state()
        if any(state not in (expected, desired) for state in initial.values()):
            raise ControlError(f"maintenance state is outside the requested transition: {canonical_json(initial)}")
        if all(state == desired for state in initial.values()):
            if desired == "open":
                self._postcheck_open_or_reclose(required_selector)
                self.operator_lock.complete("open", release=True)
            else:
                self.operator_lock.complete("close")
            return desired
        mutation_error: BaseException | None = None
        try:
            self._set_all(desired)
        except BaseException as error:  # noqa: BLE001 - classify ambiguous writes by exact readback
            mutation_error = error
        try:
            observed = self.flat_state()
        except BaseException as error:  # noqa: BLE001
            mutation_error = ControlError(f"maintenance readback failed: {error}; mutation: {mutation_error}")
            observed = {}
        if observed and all(state == desired for state in observed.values()):
            if desired == "open":
                self._postcheck_open_or_reclose(required_selector)
                self.operator_lock.complete("open", release=True)
            else:
                self.operator_lock.complete("close")
            return desired
        rollback_error: BaseException | None = None
        try:
            # A normal successor may have exact-resumed an abandoned close or
            # open token after the last read. The stale invocation must not
            # mutate any gate once it no longer owns the journal mutex.
            self.operator_lock.assert_owned(operation)
            rollback_mutation_error: BaseException | None = None
            try:
                self._set_all(expected)
            except BaseException as error:  # noqa: BLE001 - exact readback classifies lost responses
                rollback_mutation_error = error
            restored = self.flat_state()
            if not all(state == expected for state in restored.values()):
                raise ControlError(
                    f"maintenance rollback is torn: {canonical_json(restored)}; mutation: {rollback_mutation_error}"
                )
            self.operator_lock.complete(operation)
        except BaseException as error:  # noqa: BLE001
            rollback_error = error
        raise ControlError(
            f"maintenance transition failed: {mutation_error or canonical_json(observed)}; rollback: {rollback_error or 'complete'}"
        )


def run_black_box_probe(
    path: str,
    expected_sha: str,
    timeout_seconds: float,
    contract: dict[str, Any],
) -> None:
    if re.fullmatch(r"[0-9a-f]{64}", expected_sha) is None:
        raise ControlError("black-box probe digest must be 64 lowercase hex")
    probe = Path(path)
    try:
        info = probe.lstat()
    except OSError as error:
        raise ControlError("black-box probe is unavailable") from error
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise ControlError("black-box probe must be a regular non-symlink file")
    if info.st_uid not in (0, os.getuid()) or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise ControlError("black-box probe ownership or mode is unsafe")
    if hashlib.sha256(probe.read_bytes()).hexdigest() != expected_sha:
        raise ControlError("black-box probe digest mismatch")
    try:
        result = subprocess.run(
            [
                str(probe),
                "--server-endpoint",
                contract["server"]["canonical_endpoint"],
                "--ac-endpoint",
                contract["ac"]["canonical_endpoint"],
                "--ac-frps-ports-json",
                canonical_json(sorted(
                    selector["listen_port"]
                    for selector in contract["ac"]["frps_selectors"].values()
                )),
                "--relay-hostname",
                contract["relay"]["public_hostname"],
            ],
            stdin=subprocess.DEVNULL,
            text=True,
            capture_output=True,
            check=False,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as error:
        raise ControlError("black-box closure probe exceeded its latency budget") from error
    if result.returncode != 0:
        raise ControlError("black-box closure probe rejected public-gate state")
    report = _object(strict_json(result.stdout), "black-box closure report")
    if set(report) != BLACK_BOX_KEYS or report != {
        "schema": 1,
        "public_admission_closed": True,
        "server_success": False,
        "ac_https_success": False,
        "ac_frps_success": False,
        "relay_success": False,
    }:
        raise ControlError("black-box closure report is not the exact no-success result")
