#!/usr/bin/env python3
"""Tests for the one-shot sandbox stale-state-lock evidence gate."""

from __future__ import annotations

import copy
import datetime as dt
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPT = REPO_ROOT / ".github" / "scripts" / "check-sandbox-stale-state-lock.py"
SPEC = importlib.util.spec_from_file_location("stale_lock", SCRIPT)
assert SPEC and SPEC.loader
STALE_LOCK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(STALE_LOCK)


def _run() -> dict:
    return {
        "id": STALE_LOCK.EXPECTED_RUN_ID,
        "status": "completed",
        "conclusion": "failure",
        "event": "push",
        "head_branch": "main",
        "head_sha": STALE_LOCK.EXPECTED_HEAD_SHA,
    }


def _job() -> dict:
    return {
        "id": STALE_LOCK.EXPECTED_JOB_ID,
        "run_id": STALE_LOCK.EXPECTED_RUN_ID,
        "name": "Deploy Sandbox - Infrastructure",
        "status": "completed",
        "conclusion": "failure",
        "runner_group_name": "GitHub Actions",
        "runner_name": "GitHub Actions 1000643066",
        "completed_at": STALE_LOCK.EXPECTED_JOB_COMPLETED_AT,
        "steps": [
            {
                "number": 10,
                "name": STALE_LOCK.EXPECTED_STEP_NAME,
                "status": "in_progress",
                "conclusion": None,
                "started_at": STALE_LOCK.EXPECTED_STEP_STARTED_AT,
            },
            {
                "number": 12,
                "name": "Terraform Apply",
                "status": "pending",
                "conclusion": None,
                "started_at": None,
            },
        ],
    }


class StaleLockContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = dt.datetime(2026, 7, 24, 1, 30, tzinfo=dt.timezone.utc)

    def check(self, lock=None, run=None, job=None, now=None):
        STALE_LOCK.check_contract(
            copy.deepcopy(
                STALE_LOCK.EXPECTED_LOCK if lock is None else lock
            ),
            copy.deepcopy(_run() if run is None else run),
            copy.deepcopy(_job() if job is None else job),
            now=self.now if now is None else now,
        )

    def test_accepts_only_reviewed_dead_plan_lock(self):
        self.check()

    def test_rejects_every_lock_field_change(self):
        for field in STALE_LOCK.EXPECTED_LOCK:
            with self.subTest(field=field):
                lock = copy.deepcopy(STALE_LOCK.EXPECTED_LOCK)
                lock[field] = f"changed-{lock[field]}"
                with self.assertRaises(STALE_LOCK.ContractError):
                    self.check(lock=lock)

    def test_rejects_extra_lock_metadata(self):
        lock = copy.deepcopy(STALE_LOCK.EXPECTED_LOCK)
        lock["unexpected"] = True
        with self.assertRaises(STALE_LOCK.ContractError):
            self.check(lock=lock)

    def test_rejects_live_or_changed_source_run(self):
        for field, value in (
            ("status", "in_progress"),
            ("conclusion", "cancelled"),
            ("head_sha", "0" * 40),
            ("event", "workflow_dispatch"),
        ):
            with self.subTest(field=field):
                run = _run()
                run[field] = value
                with self.assertRaises(STALE_LOCK.ContractError):
                    self.check(run=run)

    def test_rejects_every_source_job_field_change(self):
        changed_values = {
            "id": 1,
            "run_id": 1,
            "name": "Different job",
            "status": "in_progress",
            "conclusion": "cancelled",
            "runner_group_name": "different group",
            "runner_name": "different runner",
            "completed_at": "2026-07-23T23:56:09Z",
        }
        for field, value in changed_values.items():
            with self.subTest(field=field):
                job = _job()
                job[field] = value
                with self.assertRaises(STALE_LOCK.ContractError):
                    self.check(job=job)

    def test_rejects_missing_or_duplicate_lock_owner_step(self):
        for steps in (
            _job()["steps"][1:],
            [_job()["steps"][0], *_job()["steps"]],
        ):
            with self.subTest(
                owner_count=sum(step["number"] == 10 for step in steps)
            ):
                job = _job()
                job["steps"] = steps
                with self.assertRaisesRegex(
                    STALE_LOCK.ContractError, "unique lock-owner step"
                ):
                    self.check(job=job)

    def test_rejects_changed_lock_owner_step(self):
        changed_values = {
            "name": "Different step",
            "started_at": "2026-07-23T23:10:49Z",
            "status": "completed",
            "conclusion": "failure",
        }
        for field, value in changed_values.items():
            with self.subTest(field=field):
                job = _job()
                job["steps"][0][field] = value
                with self.assertRaises(STALE_LOCK.ContractError):
                    self.check(job=job)

    def test_rejects_missing_or_duplicate_apply_step(self):
        for steps in (
            _job()["steps"][:1],
            [*_job()["steps"], _job()["steps"][1]],
        ):
            with self.subTest(
                apply_count=sum(step["name"] == "Terraform Apply" for step in steps)
            ):
                job = _job()
                job["steps"] = steps
                with self.assertRaisesRegex(
                    STALE_LOCK.ContractError, "unique Terraform Apply step"
                ):
                    self.check(job=job)

    def test_rejects_source_job_that_reached_apply(self):
        job = _job()
        job["steps"][1].update(
            status="completed",
            conclusion="success",
            started_at="2026-07-23T23:12:00Z",
        )
        with self.assertRaisesRegex(STALE_LOCK.ContractError, "reached Terraform Apply"):
            self.check(job=job)

    def test_rejects_recent_lock(self):
        now = dt.datetime(2026, 7, 23, 23, 30, tzinfo=dt.timezone.utc)
        with self.assertRaisesRegex(STALE_LOCK.ContractError, "one hour old"):
            self.check(now=now)

    def test_rejects_recently_completed_source_job(self):
        now = dt.datetime(2026, 7, 24, 0, 20, tzinfo=dt.timezone.utc)
        with self.assertRaisesRegex(STALE_LOCK.ContractError, "dead for 30 minutes"):
            self.check(now=now)

    def test_parses_nanosecond_timestamp_for_age_math(self):
        parsed = STALE_LOCK._parse_timestamp(
            STALE_LOCK.EXPECTED_LOCK["Created"], "lock Created"
        )
        self.assertEqual(
            parsed,
            dt.datetime(
                2026, 7, 23, 23, 10, 49, 864170, tzinfo=dt.timezone.utc
            ),
        )

    def test_rejects_non_utc_or_non_rfc3339_timestamp(self):
        for value in ("2026-07-23T23:10:49+00:00", "2026-07-23 23:10:49Z"):
            with self.subTest(value=value):
                with self.assertRaisesRegex(
                    STALE_LOCK.ContractError, "RFC3339 UTC timestamp"
                ):
                    STALE_LOCK._parse_timestamp(value, "test timestamp")

    def test_rejects_naive_current_time(self):
        with self.assertRaisesRegex(STALE_LOCK.ContractError, "timezone-aware"):
            self.check(now=dt.datetime(2026, 7, 24, 1, 30))

    def test_cli_emits_summary_and_annotated_contract_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = [
                Path(tmp) / name
                for name in ("lock.json", "run.json", "job.json")
            ]
            for path, value in zip(
                paths,
                (STALE_LOCK.EXPECTED_LOCK, _run(), _job()),
                strict=True,
            ):
                path.write_text(json.dumps(value), encoding="utf-8")

            command = [
                sys.executable,
                str(SCRIPT),
                *(str(path) for path in paths),
                "--now",
                "2026-07-24T01:30:00Z",
            ]
            success = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(success.returncode, 0, success.stderr)
            self.assertEqual(
                json.loads(success.stdout),
                {
                    "lock_id": STALE_LOCK.EXPECTED_LOCK["ID"],
                    "operation": STALE_LOCK.EXPECTED_LOCK["Operation"],
                    "safe_to_force_unlock": True,
                    "source_apply_started": False,
                    "source_job_id": STALE_LOCK.EXPECTED_JOB_ID,
                    "source_run_id": STALE_LOCK.EXPECTED_RUN_ID,
                },
            )

            paths[0].write_text(json.dumps({"ID": "wrong"}), encoding="utf-8")
            failure = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(failure.returncode, 1)
            self.assertIn("::error::lock metadata keys changed", failure.stdout)
            self.assertNotIn("Traceback", failure.stderr)

            invalid_now = subprocess.run(
                [*command[:-1], "not-a-timestamp"],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(invalid_now.returncode, 1)
            self.assertIn("::error::--now is not an RFC3339", invalid_now.stdout)
            self.assertNotIn("Traceback", invalid_now.stderr)


if __name__ == "__main__":
    unittest.main()
