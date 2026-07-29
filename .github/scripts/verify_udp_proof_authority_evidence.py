#!/usr/bin/env python3
"""Fail closed on Authority blue/green readiness and zero-spill proof evidence."""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import subprocess
import sys
import time
from datetime import datetime, timezone
from typing import Any


ACCOUNT = "767397897469"
REGION = "us-east-2"
FUNCTIONS = (
    "layerv-nhp-sandbox-ca-ia",
    "layerv-nhp-sandbox-ca-ra",
    "layerv-nhp-sandbox-ca-icr",
    "layerv-nhp-sandbox-ca-pm",
)


class EvidenceError(RuntimeError):
    pass


def _aws(service: str, arguments: list[str], label: str) -> dict[str, Any]:
    process = subprocess.run(
        ["aws", service, *arguments, "--region", REGION, "--output", "json"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=30,
    )
    if process.returncode != 0:
        raise EvidenceError(f"{label} AWS read failed")
    try:
        value = json.loads(process.stdout)
    except json.JSONDecodeError as exc:
        raise EvidenceError(f"{label} AWS response is not JSON") from exc
    if not isinstance(value, dict):
        raise EvidenceError(f"{label} AWS response is not an object")
    return value


def _decode_provenance(encoded: str) -> dict[str, Any]:
    try:
        raw = base64.b64decode(encoded, validate=True)
        value = json.loads(raw)
    except (binascii.Error, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EvidenceError("deployment provenance is not strict base64 JSON") from exc
    if not isinstance(value, dict):
        raise EvidenceError("deployment provenance is not an object")
    return value


def _selected_versions(provenance: dict[str, Any]) -> dict[str, tuple[str, str]]:
    try:
        pairs = provenance["evidence"]["workloads"]["qurl_service_authority"][
            "functions"
        ]
    except (KeyError, TypeError) as exc:
        raise EvidenceError("deployment provenance has no Authority functions") from exc
    if not isinstance(pairs, list):
        raise EvidenceError("deployment provenance Authority functions are invalid")
    selected: dict[str, tuple[str, str]] = {}
    prefix = f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:"
    for pair in pairs:
        if not isinstance(pair, dict) or set(pair) != {"alias_arn", "version_arn"}:
            raise EvidenceError("deployment provenance Authority pair is invalid")
        alias_arn = pair["alias_arn"]
        version_arn = pair["version_arn"]
        if not isinstance(alias_arn, str) or not isinstance(version_arn, str):
            raise EvidenceError("deployment provenance Authority ARN is invalid")
        for function_name in FUNCTIONS:
            function_prefix = f"{prefix}{function_name}:"
            if alias_arn.startswith(function_prefix):
                color = alias_arn.removeprefix(function_prefix)
                version = version_arn.removeprefix(function_prefix)
                if (
                    color not in {"blue", "green"}
                    or not version.isdecimal()
                    or int(version) <= 0
                    or function_name in selected
                ):
                    raise EvidenceError(
                        f"deployment provenance {function_name} identity is invalid"
                    )
                selected[function_name] = (color, version)
    if set(selected) != set(FUNCTIONS):
        raise EvidenceError(
            "deployment provenance lacks the exact IA/RA/ICR/ca-pm identities"
        )
    if len({color for color, _ in selected.values()}) != 1:
        raise EvidenceError("deployment provenance Authority proof colors differ")
    return selected


def _ready_capacity(
    function_name: str,
    selected_color: str | None = None,
    selected_version: str | None = None,
) -> None:
    concurrency = _aws(
        "lambda",
        ["get-function-concurrency", "--function-name", function_name],
        f"{function_name} reserved concurrency",
    )
    reserved = concurrency.get("ReservedConcurrentExecutions")
    configs = _aws(
        "lambda",
        ["list-provisioned-concurrency-configs", "--function-name", function_name],
        f"{function_name} provisioned concurrency",
    )
    values = configs.get("ProvisionedConcurrencyConfigs")
    if (
        type(reserved) is not int
        or not isinstance(values, list)
        or configs.get("NextToken") is not None
        or len(values) != 2
    ):
        raise EvidenceError(f"{function_name} concurrency inventory is incomplete")
    requested: list[int] = []
    qualifiers: set[str] = set()
    for value in values:
        if not isinstance(value, dict):
            raise EvidenceError(f"{function_name} concurrency entry is invalid")
        arn = value.get("FunctionArn")
        qualifier = arn.rsplit(":", 1)[-1] if isinstance(arn, str) else ""
        allocation = value.get("RequestedProvisionedConcurrentExecutions")
        if (
            qualifier not in {"blue", "green"}
            or type(allocation) is not int
            or allocation <= 0
            or value.get("Status") != "READY"
            or value.get("AllocatedProvisionedConcurrentExecutions") != allocation
            or value.get("AvailableProvisionedConcurrentExecutions") != allocation
        ):
            raise EvidenceError(f"{function_name} concurrency is not exactly READY")
        qualifiers.add(qualifier)
        requested.append(allocation)
    if qualifiers != {"blue", "green"} or len(set(requested)) != 1:
        raise EvidenceError(f"{function_name} warm pools are not equal blue/green")
    if reserved != sum(requested):
        raise EvidenceError(f"{function_name} reserved concurrency differs from pools")
    if selected_color is None:
        return
    alias = _aws(
        "lambda",
        [
            "get-alias",
            "--function-name",
            function_name,
            "--name",
            selected_color,
        ],
        f"{function_name} selected alias",
    )
    routing = alias.get("RoutingConfig")
    actual_version = alias.get("FunctionVersion")
    if selected_version is not None:
        version_ok = actual_version == selected_version
    else:
        version_ok = (
            isinstance(actual_version, str)
            and actual_version.isdecimal()
            and int(actual_version) > 0
        )
    routing_dirty = (
        isinstance(routing, dict)
        and routing.get("AdditionalVersionWeights") not in (None, {})
    )
    if not version_ok or routing_dirty:
        raise EvidenceError(
            f"{function_name} selected alias differs from authenticated provenance"
        )


def _metric(
    function_name: str,
    color: str,
    metric_name: str,
    start: datetime,
    end: datetime,
    *,
    version: str | None = None,
) -> float:
    dimensions = [
        f"Name=FunctionName,Value={function_name}",
        f"Name=Resource,Value={function_name}:{color}",
    ]
    if version is not None:
        dimensions.append(f"Name=ExecutedVersion,Value={version}")
    response = _aws(
        "cloudwatch",
        [
            "get-metric-statistics",
            "--namespace",
            "AWS/Lambda",
            "--metric-name",
            metric_name,
            "--dimensions",
            *dimensions,
            "--start-time",
            start.isoformat(),
            "--end-time",
            end.isoformat(),
            "--period",
            "60",
            "--statistics",
            "Sum",
        ],
        f"{function_name} {metric_name}",
    )
    datapoints = response.get("Datapoints")
    if not isinstance(datapoints, list):
        raise EvidenceError(f"{function_name} {metric_name} datapoints are invalid")
    total = 0.0
    for datapoint in datapoints:
        value = datapoint.get("Sum") if isinstance(datapoint, dict) else None
        if type(value) not in (int, float) or value < 0:
            raise EvidenceError(f"{function_name} {metric_name} sum is invalid")
        total += float(value)
    return total


def _closed_minute(value: datetime) -> datetime:
    return value.astimezone(timezone.utc).replace(second=0, microsecond=0)


def _verify_metrics(
    selected: dict[str, tuple[str, str]], start: datetime
) -> dict[str, dict[str, float]]:
    start = _closed_minute(start)
    last_error = "metrics have not converged"
    for attempt in range(1, 9):
        end = _closed_minute(datetime.now(timezone.utc))
        if end <= start:
            last_error = "proof has no closed CloudWatch minute"
        else:
            results: dict[str, dict[str, float]] = {}
            try:
                for function_name, (color, version) in selected.items():
                    invocations = _metric(
                        function_name, color, "Invocations", start, end
                    )
                    executed = _metric(
                        function_name,
                        color,
                        "Invocations",
                        start,
                        end,
                        version=version,
                    )
                    provisioned = _metric(
                        function_name,
                        color,
                        "ProvisionedConcurrencyInvocations",
                        start,
                        end,
                    )
                    spillover = _metric(
                        function_name,
                        color,
                        "ProvisionedConcurrencySpilloverInvocations",
                        start,
                        end,
                    )
                    errors = _metric(function_name, color, "Errors", start, end)
                    throttles = _metric(function_name, color, "Throttles", start, end)
                    if (
                        invocations <= 0
                        or executed != invocations
                        or provisioned + spillover != invocations
                        or spillover != 0
                        or errors != 0
                        or throttles != 0
                    ):
                        raise EvidenceError(
                            f"{function_name} zero-spill evidence is not exact"
                        )
                    results[function_name] = {
                        "invocations": invocations,
                        "executed_version_invocations": executed,
                        "provisioned_concurrency_invocations": provisioned,
                        "spillover_invocations": spillover,
                        "errors": errors,
                        "throttles": throttles,
                    }
                return results
            except EvidenceError as exc:
                last_error = str(exc)
        if attempt < 8:
            time.sleep(15)
    raise EvidenceError(last_error)


def main() -> int:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    readiness = commands.add_parser("readiness")
    readiness.add_argument(
        "--selected-color", required=True, choices=("blue", "green")
    )
    evidence = commands.add_parser("evidence")
    evidence.add_argument("--deployment-provenance-b64", required=True)
    evidence.add_argument("--proof-start-time", required=True)
    args = parser.parse_args()
    try:
        if args.command == "readiness":
            for function_name in FUNCTIONS:
                _ready_capacity(function_name, args.selected_color)
            return 0
        selected = _selected_versions(_decode_provenance(args.deployment_provenance_b64))
        try:
            start = datetime.fromisoformat(args.proof_start_time.replace("Z", "+00:00"))
        except ValueError as exc:
            raise EvidenceError("proof start time is invalid") from exc
        if start.tzinfo is None:
            raise EvidenceError("proof start time must include a timezone")
        for function_name, (color, version) in selected.items():
            _ready_capacity(function_name, color, version)
        evidence = _verify_metrics(selected, start)
        print(json.dumps(evidence, sort_keys=True, separators=(",", ":")))
        return 0
    except (EvidenceError, subprocess.TimeoutExpired) as exc:
        print(f"authority evidence failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
