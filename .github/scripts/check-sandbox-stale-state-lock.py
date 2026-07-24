#!/usr/bin/env python3
"""Fail-closed evidence gate for the one-shot sandbox state-lock recovery."""

from __future__ import annotations

import argparse
import datetime as dt
import json
from pathlib import Path
from typing import Any


EXPECTED_LOCK = {
    "ID": "cf94626e-a9b3-f45f-08cc-c6c68c2f1ed0",
    "Operation": "OperationTypePlan",
    "Info": "",
    "Who": "runner@runnervm3jd5f",
    "Version": "1.14.3",
    "Created": "2026-07-23T23:10:49.864170142Z",
    "Path": "layerv-terraform-state-767397897469/nhp/sandbox/terraform.tfstate",
}
EXPECTED_LOCK_KEYS = frozenset(EXPECTED_LOCK)
EXPECTED_RUN_ID = 30051956048
EXPECTED_JOB_ID = 89356869295
EXPECTED_HEAD_SHA = "b95327e3045093f358f84dc4e1662becb5b88100"
EXPECTED_JOB_COMPLETED_AT = "2026-07-23T23:56:08Z"
EXPECTED_STEP_NAME = "Handle ASG Attachment Migrations and Taint Recovery"
EXPECTED_STEP_STARTED_AT = "2026-07-23T23:10:48Z"
MINIMUM_STALE_AGE = dt.timedelta(hours=1)
MINIMUM_DEAD_JOB_AGE = dt.timedelta(minutes=30)


class ContractError(ValueError):
    """The live evidence does not identify the one reviewed stale lock."""


def _read_object(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ContractError(f"{label} is not readable JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise ContractError(f"{label} must be a JSON object")
    return value


def _parse_timestamp(value: str, label: str) -> dt.datetime:
    # datetime.fromisoformat accepts at most microsecond precision portably.
    # The Terraform lock contains nanoseconds, so truncate only for age math;
    # its full Created value is compared byte-for-byte before this helper runs.
    if not value.endswith("Z") or "T" not in value:
        raise ContractError(f"{label} is not an RFC3339 UTC timestamp")
    timestamp = value[:-1]
    if "." in timestamp:
        date, fractional = timestamp.split(".", 1)
        timestamp = f"{date}.{fractional[:6].ljust(6, '0')}"
    normalized = f"{timestamp}+00:00"
    try:
        return dt.datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ContractError(f"{label} is not an RFC3339 UTC timestamp") from exc


def _require_fields(
    actual: dict[str, Any], expected: dict[str, Any], prefix: str, subject: str
) -> None:
    for key, value in expected.items():
        if actual.get(key) != value:
            raise ContractError(
                f"{prefix} {key} does not match the reviewed {subject}"
            )


def _unique_step(steps: list[Any], predicate, label: str) -> dict[str, Any]:
    matches = [
        step for step in steps if isinstance(step, dict) and predicate(step)
    ]
    if len(matches) != 1:
        raise ContractError(f"source workflow job has no unique {label}")
    return matches[0]


def check_contract(
    lock: dict[str, Any],
    run: dict[str, Any],
    job: dict[str, Any],
    *,
    now: dt.datetime,
) -> None:
    if frozenset(lock) != EXPECTED_LOCK_KEYS:
        raise ContractError(
            "lock metadata keys changed; refusing to unlock an unreviewed object"
        )
    _require_fields(lock, EXPECTED_LOCK, "lock metadata", "stale lock")

    lock_created = _parse_timestamp(EXPECTED_LOCK["Created"], "lock Created")
    if now.tzinfo is None or now.utcoffset() is None:
        raise ContractError("current time must be timezone-aware")
    now_utc = now.astimezone(dt.timezone.utc)
    if now_utc - lock_created < MINIMUM_STALE_AGE:
        raise ContractError("reviewed lock is not yet at least one hour old")

    expected_run = {
        "id": EXPECTED_RUN_ID,
        "status": "completed",
        "conclusion": "failure",
        "event": "push",
        "head_branch": "main",
        "head_sha": EXPECTED_HEAD_SHA,
    }
    _require_fields(run, expected_run, "source workflow run", "failed run")

    expected_job = {
        "id": EXPECTED_JOB_ID,
        "run_id": EXPECTED_RUN_ID,
        "name": "Deploy Sandbox - Infrastructure",
        "status": "completed",
        "conclusion": "failure",
        "runner_group_name": "GitHub Actions",
        "runner_name": "GitHub Actions 1000643066",
        "completed_at": EXPECTED_JOB_COMPLETED_AT,
    }
    _require_fields(job, expected_job, "source workflow job", "failed job")
    job_completed = _parse_timestamp(
        EXPECTED_JOB_COMPLETED_AT, "source workflow job completed_at"
    )
    if now_utc - job_completed < MINIMUM_DEAD_JOB_AGE:
        raise ContractError("source workflow job has not been dead for 30 minutes")

    steps = job.get("steps")
    if not isinstance(steps, list):
        raise ContractError("source workflow job has no inspectable steps")
    owner_step = _unique_step(
        steps, lambda step: step.get("number") == 10, "lock-owner step"
    )
    if owner_step.get("name") != EXPECTED_STEP_NAME:
        raise ContractError("source workflow lock-owner step name changed")
    if owner_step.get("started_at") != EXPECTED_STEP_STARTED_AT:
        raise ContractError("source workflow lock-owner step start changed")
    if owner_step.get("status") != "in_progress" or owner_step.get(
        "conclusion"
    ) is not None:
        raise ContractError(
            "source workflow lock-owner step no longer has the lost-runner shape"
        )

    apply_step = _unique_step(
        steps,
        lambda step: step.get("name") == "Terraform Apply",
        "Terraform Apply step",
    )
    if (
        apply_step.get("status") != "pending"
        or apply_step.get("conclusion") is not None
        or apply_step.get("started_at") is not None
    ):
        raise ContractError(
            "source workflow unexpectedly reached Terraform Apply; refusing unlock"
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("lock_json", type=Path)
    parser.add_argument("run_json", type=Path)
    parser.add_argument("job_json", type=Path)
    parser.add_argument(
        "--now",
        help="RFC3339 UTC time for deterministic tests; defaults to current UTC",
    )
    args = parser.parse_args()

    try:
        now = (
            _parse_timestamp(args.now, "--now")
            if args.now
            else dt.datetime.now(dt.timezone.utc)
        )
        check_contract(
            _read_object(args.lock_json, "lock metadata"),
            _read_object(args.run_json, "source workflow run"),
            _read_object(args.job_json, "source workflow job"),
            now=now,
        )
    except ContractError as exc:
        print(f"::error::{exc}")
        return 1
    print(
        json.dumps(
            {
                "lock_id": EXPECTED_LOCK["ID"],
                "operation": EXPECTED_LOCK["Operation"],
                "source_run_id": EXPECTED_RUN_ID,
                "source_job_id": EXPECTED_JOB_ID,
                "source_apply_started": False,
                "safe_to_force_unlock": True,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
