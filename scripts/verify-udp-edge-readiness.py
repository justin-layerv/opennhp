#!/usr/bin/env python3
"""Fail-closed CloudWatch evidence check for the assigned-cell UDP flood test."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import subprocess
import sys
import time


FIXED_CAPACITY_LIMITS = {
    "HandlerInFlight": 4096,
    "HandlerProtectedInFlight": 1024,
    "PacketDecryptQueueDepth": 10240,
    "DecryptedMessageQueueDepth": 10240,
}

ZERO_TOLERANCE_METRICS = (
    "UDPReceiveBufferDrop",
    "UDPEdgeCollectorError",
    "PacketDecryptQueueDrop",
    "DecryptedMessageQueueDrop",
    "HandlerProtectedReserveExhausted",
)

# Host EMF values are emitted every collector interval, including zero. The Go
# drop counters below are event-only Publisher counters: no bad event means no
# CloudWatch series/datapoint, which is the healthy state rather than a wiring
# failure. Always-emitted server gauges provide the application publisher fence.
REQUIRED_SUM_METRICS = (
    "UDPIngressDatagram",
    "UDPEdgeCollectorHeartbeat",
    "UDPReceiveBufferDrop",
    "UDPEdgeCollectorError",
)

SUM_METRICS = (
    "UDPIngressDatagram",
    "UDPGlobalRateLimitDrop",
    "UDPPerSourceRateLimitDrop",
    "UDPKernelReceiveError",
    "UDPReceiveBufferDrop",
    "UDPEdgeCollectorError",
    "UDPEdgeCollectorHeartbeat",
    "UDPRateLimitDrop",
    "PacketDecryptQueueDrop",
    "DecryptedMessageQueueDrop",
    "HandlerBudgetExhausted",
    "HandlerProtectedReserveExhausted",
    "GlobalCapRejections",
)

MAXIMUM_METRICS = (
    "HandlerInFlight",
    "HandlerProtectedInFlight",
    "PacketDecryptQueueDepth",
    "DecryptedMessageQueueDepth",
    "RuntimeGoroutine",
    "RuntimeHeapAllocBytes",
)

AWS_JSON_MAX_ATTEMPTS = 3


def reached_capacity(maximum: float, capacity: int) -> bool:
    return maximum >= capacity


def missing_datapoint_failures(report: dict[str, dict[str, float | int]], required: tuple[str, ...]) -> list[str]:
    return [f"{name} had no datapoints" for name in required if report[name]["datapoints"] == 0]


def aws_json(args: list[str]) -> dict:
    command = ["aws", *args, "--output", "json"]
    for attempt in range(1, AWS_JSON_MAX_ATTEMPTS + 1):
        try:
            completed = subprocess.run(command, check=True, capture_output=True, text=True, timeout=30)
            return json.loads(completed.stdout)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            if attempt == AWS_JSON_MAX_ATTEMPTS:
                raise
            print(
                f"aws {args[0]} {args[1]} attempt {attempt} failed; retrying bounded evidence read",
                file=sys.stderr,
            )
            time.sleep(attempt)
    raise AssertionError("unreachable")


def metric(namespace: str, name: str, dimensions: dict[str, str], statistic: str, start: int, end: int) -> tuple[float, int]:
    dim_args = [{"Name": key, "Value": value} for key, value in dimensions.items()]
    data = aws_json(
        [
            "cloudwatch",
            "get-metric-statistics",
            "--namespace",
            namespace,
            "--metric-name",
            name,
            "--dimensions",
            json.dumps(dim_args),
            "--start-time",
            datetime.fromtimestamp(start, timezone.utc).isoformat(),
            "--end-time",
            datetime.fromtimestamp(end, timezone.utc).isoformat(),
            "--period",
            "60",
            "--statistics",
            statistic,
        ]
    )
    values = [float(point[statistic]) for point in data.get("Datapoints", []) if statistic in point]
    if not values:
        return 0.0, 0
    return (sum(values) if statistic == "Sum" else max(values)), len(values)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--environment", required=True)
    parser.add_argument("--cell", required=True)
    parser.add_argument("--asg-name", required=True)
    parser.add_argument("--start-epoch", required=True, type=int)
    parser.add_argument("--end-epoch", required=True, type=int)
    parser.add_argument("--max-cpu-percent", type=float, default=95)
    parser.add_argument("--max-heap-bytes", type=int, default=1 << 30)
    parser.add_argument("--max-goroutines", type=int, default=10000)
    return parser.parse_args()


def readiness_failures(
    report: dict[str, dict[str, float | int]],
    *,
    max_cpu_percent: float,
    max_heap_bytes: int,
    max_goroutines: int,
) -> list[str]:
    required_metrics = (*REQUIRED_SUM_METRICS, *MAXIMUM_METRICS, "ASGCPUUtilization")
    failures = missing_datapoint_failures(report, required_metrics)
    if report["UDPPerSourceRateLimitDrop"]["sum"] <= 0:
        failures.append("per-source host hashlimit did not engage; the offered load was not a valid edge-admission test")
    # UDPKernelReceiveError is host-wide and can include unrelated UDP;
    # UDPGlobalRateLimitDrop and GlobalCapRejections are permitted fail-safe
    # sheds when the exact per-source/SLO gates still pass. Keep all three in
    # the evidence report as diagnostics, but do not assign a zero threshold.
    for zero_metric in ZERO_TOLERANCE_METRICS:
        if report[zero_metric]["sum"] != 0:
            failures.append(f"{zero_metric} was non-zero ({report[zero_metric]['sum']})")
    # Keep these exact hard bounds in lockstep with
    # endpoints/server/constants.go (MaxConcurrentHandlers and
    # HandlerProtectedReserve) and nhp/core/constants.go (RecvQueueSize).
    # tests/scripts/test_udp_edge_metrics.py parses those declarations and
    # fails if this verifier drifts.
    # Reaching a physical channel capacity is itself a failure: the next item
    # could shed even when this sample happened just before a drop counter
    # increment. Runtime/resource limits remain inclusive ceilings below.
    for name, capacity in FIXED_CAPACITY_LIMITS.items():
        if reached_capacity(float(report[name]["maximum"]), capacity):
            failures.append(f"{name} maximum {report[name]['maximum']} reached capacity {capacity}")
    limits = {
        "RuntimeGoroutine": max_goroutines,
        "RuntimeHeapAllocBytes": max_heap_bytes,
        "ASGCPUUtilization": max_cpu_percent,
    }
    for name, limit in limits.items():
        if report[name]["maximum"] > limit:
            failures.append(f"{name} maximum {report[name]['maximum']} exceeded {limit}")
    return failures


def main() -> None:
    args = parse_args()
    dims = {"Environment": args.environment, "Cell": args.cell}
    report: dict[str, dict[str, float | int]] = {}
    for name in SUM_METRICS:
        value, points = metric("LayerV/NHP", name, dims, "Sum", args.start_epoch, args.end_epoch)
        report[name] = {"sum": value, "datapoints": points}
    for name in MAXIMUM_METRICS:
        value, points = metric("LayerV/NHP", name, dims, "Maximum", args.start_epoch, args.end_epoch)
        report[name] = {"maximum": value, "datapoints": points}
    cpu, cpu_points = metric(
        "AWS/EC2",
        "CPUUtilization",
        {"AutoScalingGroupName": args.asg_name},
        "Maximum",
        args.start_epoch,
        args.end_epoch,
    )
    report["ASGCPUUtilization"] = {"maximum": cpu, "datapoints": cpu_points}

    failures = readiness_failures(
        report,
        max_cpu_percent=args.max_cpu_percent,
        max_heap_bytes=args.max_heap_bytes,
        max_goroutines=args.max_goroutines,
    )

    print(json.dumps({"metrics": report, "failures": failures}, indent=2, sort_keys=True))
    if failures:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
