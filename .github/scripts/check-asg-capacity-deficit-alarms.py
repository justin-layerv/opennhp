#!/usr/bin/env python3
"""Assert #2041's ASG alarms stay on real Auto Scaling metrics.

AWS does not publish an Auto Scaling group metric named
`GroupUnHealthyInstanceCount`. The four alarms below must therefore stay
implemented as metric math over `GroupDesiredCapacity` and
`GroupInServiceInstances`; otherwise the alarm quietly watches a
non-existent metric stream and never trips.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any, NamedTuple

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _tf_lint_lib import error, iter_resources, parse_tf_files, unquote  # noqa: E402


class AlarmSpec(NamedTuple):
    name: str
    stats: dict[str, str]
    period: int
    evaluation_periods: Any
    require_datapoints_to_alarm: bool = False


CANARY_STATS = {
    "desired": "Average",
    "in_service": "Average",
}
STANDBY_STATS = {
    "desired": "Minimum",
    "in_service": "Maximum",
}
# Deliberate regression fence, not a discovery scan: these are the four
# historical #2041 alarms that previously used the non-published flat metric.
# If a new ASG capacity-deficit alarm is added, extend this allowlist in the
# same PR so the checker validates its exact shape too.
EXPECTED_ALARMS = {
    Path("modules/ac/blue_green.tf"): AlarmSpec(
        "ac_green_asg_unhealthy",
        STANDBY_STATS,
        period=300,
        evaluation_periods=2,
    ),
    Path("modules/canary-deployment/alarms.tf"): AlarmSpec(
        "canary_asg_unhealthy",
        CANARY_STATS,
        period=60,
        evaluation_periods="${local.canary_asg_capacity_deficit_evaluation_periods}",
        require_datapoints_to_alarm=True,
    ),
    Path("modules/compute/blue_green.tf"): AlarmSpec(
        "green_asg_unhealthy",
        STANDBY_STATS,
        period=300,
        evaluation_periods=2,
    ),
    Path("modules/qurl-reverse-tunnel-server/blue_green.tf"): AlarmSpec(
        "frps_green_asg_unhealthy",
        STANDBY_STATS,
        period=300,
        evaluation_periods=2,
    ),
}

CAPACITY_DEFICIT_EXPRESSION = "FILL(desired, 0) - FILL(in_service, 0)"
EXPECTED_QUERY_METRICS = {
    "desired": "GroupDesiredCapacity",
    "in_service": "GroupInServiceInstances",
}


def normalize(value: Any) -> Any:
    return unquote(value)


def query_by_id(metric_queries: Any) -> tuple[dict[str, dict[str, Any]], list[str]]:
    if not isinstance(metric_queries, list):
        return {}, []

    queries: dict[str, dict[str, Any]] = {}
    duplicate_ids: list[str] = []
    for query in metric_queries:
        if not isinstance(query, dict):
            continue
        query_id = normalize(query.get("id"))
        if isinstance(query_id, str):
            if query_id in queries:
                duplicate_ids.append(query_id)
            queries[query_id] = query
    return queries, sorted(set(duplicate_ids))


def validate_alarm(
    spec: AlarmSpec,
    body: dict[str, Any],
) -> list[str]:
    violations: list[str] = []
    name = spec.name

    if "metric_name" in body:
        violations.append(
            f"{name} must not use top-level metric_name; use metric_query math"
        )
    if normalize(body.get("comparison_operator")) != "GreaterThanThreshold":
        violations.append(f"{name} comparison_operator must be 'GreaterThanThreshold'")
    if body.get("threshold") != 0:
        violations.append(f"{name} threshold must be 0")
    if normalize(body.get("treat_missing_data")) != "notBreaching":
        violations.append(f"{name} treat_missing_data must be 'notBreaching'")
    if body.get("evaluation_periods") != spec.evaluation_periods:
        violations.append(f"{name} evaluation_periods must be {spec.evaluation_periods!r}")
    if spec.require_datapoints_to_alarm:
        if "datapoints_to_alarm" not in body:
            violations.append(f"{name} must set datapoints_to_alarm")
        # python-hcl2 leaves Terraform locals unresolved; this is an
        # identity fence that requires both fields to reference the same
        # expression, not an arithmetic proof of the resolved values.
        elif body.get("datapoints_to_alarm") != body.get("evaluation_periods"):
            violations.append(f"{name} datapoints_to_alarm must equal evaluation_periods")

    queries, duplicate_ids = query_by_id(body.get("metric_query"))
    for duplicate_id in duplicate_ids:
        violations.append(f"{name} duplicate metric_query id: {duplicate_id}")

    missing = sorted({"capacity_deficit", *EXPECTED_QUERY_METRICS} - set(queries))
    if missing:
        violations.append(f"{name} missing metric_query id(s): {', '.join(missing)}")
        return violations

    capacity = queries["capacity_deficit"]
    if normalize(capacity.get("expression")) != CAPACITY_DEFICIT_EXPRESSION:
        violations.append(
            f"{name}.capacity_deficit expression must be {CAPACITY_DEFICIT_EXPRESSION!r}"
        )
    if capacity.get("return_data") is not True:
        violations.append(f"{name}.capacity_deficit must set return_data = true")

    metric_periods: dict[str, int] = {}
    for query_id, expected_metric_name in EXPECTED_QUERY_METRICS.items():
        query = queries[query_id]
        if query.get("return_data") is True:
            violations.append(f"{name}.{query_id} must not set return_data = true")

        metrics = query.get("metric")
        if (
            not isinstance(metrics, list)
            or len(metrics) != 1
            or not isinstance(metrics[0], dict)
        ):
            violations.append(f"{name}.{query_id} must contain exactly one metric block")
            continue

        metric = metrics[0]
        if normalize(metric.get("metric_name")) != expected_metric_name:
            violations.append(
                f"{name}.{query_id} metric_name must be {expected_metric_name!r}"
            )
        if normalize(metric.get("namespace")) != "AWS/AutoScaling":
            violations.append(f"{name}.{query_id} namespace must be 'AWS/AutoScaling'")
        expected_stat = spec.stats[query_id]
        if normalize(metric.get("stat")) != expected_stat:
            violations.append(f"{name}.{query_id} stat must be {expected_stat!r}")

        period = metric.get("period")
        if not isinstance(period, int) or period <= 0:
            violations.append(f"{name}.{query_id} period must be a positive integer")
        else:
            metric_periods[query_id] = period
            if period != spec.period:
                violations.append(f"{name}.{query_id} period must be {spec.period}")

        dimensions = metric.get("dimensions")
        if not isinstance(dimensions, dict) or "AutoScalingGroupName" not in dimensions:
            violations.append(
                f"{name}.{query_id} must dimension on AutoScalingGroupName"
            )

    desired_period = metric_periods.get("desired")
    in_service_period = metric_periods.get("in_service")
    if (
        desired_period is not None
        and in_service_period is not None
        and desired_period != in_service_period
    ):
        violations.append(
            f"{name}.desired and {name}.in_service periods must match"
        )

    return violations


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--terraform-root",
        default="terraform",
        type=Path,
        help="Terraform root to scan; defaults to ./terraform",
    )
    args = parser.parse_args()

    root = args.terraform_root
    if not root.is_dir():
        error(f"terraform root not found: {root}")
        return 2

    found: dict[tuple[Path, str], tuple[Path, dict[str, Any]]] = {}
    for file, rtype, name, body in iter_resources(parse_tf_files(root)):
        if rtype != "aws_cloudwatch_metric_alarm":
            continue
        try:
            rel = file.relative_to(root)
        except ValueError:
            rel = file
        found[(rel, name)] = (file, body)

    failures = 0
    for rel, spec in EXPECTED_ALARMS.items():
        match = found.get((rel, spec.name))
        if match is None:
            error(f"expected aws_cloudwatch_metric_alarm.{spec.name} in {root / rel}")
            failures += 1
            continue
        file, body = match
        for violation in validate_alarm(spec, body):
            error(violation, file=file)
            failures += 1

    if failures:
        return 1

    print("ASG capacity-deficit alarm shape check: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
