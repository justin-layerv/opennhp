"""Release contract for the blue/green sandbox qURL live-environment lock.

Regression fence for the four-hour lock hold observed on 2026-07-28. Run
30337884706 acquired /layerv-nhp-sandbox/qurl-live-env-lock at 09:14:03Z, failed
in `Deploy to Standby` at `[Server] Verify Knock Readiness (AC Peers Connected)`
at 09:28:32Z, and retained the lock until its 13:14:03Z TTL. Run 30354530304
then took the lock the moment that TTL lapsed, failed the same way, and held it
another four hours - a compounding livelock that stalled `Build and Deploy NHP`
on main.

The two invariants under test:

  1. A run that never reached switch-traffic never moved the live boundary and
     MUST release, whether it failed, was cancelled, or selected no component.
  2. A run that did reach switch-traffic and did not cleanly converge MUST
     retain, and no run may ever delete a lock recorded to a different owner.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[2]
CLASSIFIER = ROOT / ".github/scripts/classify-blue-green-lock-release.sh"
LOCK_SCRIPT = ROOT / ".github/scripts/ssm-live-env-lock.sh"
WORKFLOW = ROOT / ".github/workflows/blue-green-deploy.yml"

# Exact shape read from the live sandbox parameter on 2026-07-28, not an assumed
# schema: aws ssm get-parameter --name /layerv-nhp-sandbox/qurl-live-env-lock
LIVE_LOCK_VALUE = (
    '{"owner":"nhp:30337884706:1:blue-green",'
    '"created_at":1785230043,"expires_at":1785244443}'
)

# The owner token blue-green-deploy.yml builds for both acquire and release.
OWNER_TEMPLATE = "nhp:{run_id}:{run_attempt}:blue-green"

STATEFUL_AWS = r"""#!/usr/bin/env bash
set -euo pipefail

case "${1:-} ${2:-}" in
  "ssm get-parameter")
    [[ -f "$FAKE_AWS_STATE" ]] && cat "$FAKE_AWS_STATE"
    exit 0
    ;;
  "ssm delete-parameter")
    echo "delete $*" >> "$FAKE_AWS_LOG"
    : > "$FAKE_AWS_STATE"
    exit 0
    ;;
  "cloudwatch put-metric-data")
    echo "metric $*" >> "$FAKE_AWS_LOG"
    exit 0
    ;;
esac

echo "unexpected aws args: $*" >&2
exit 99
"""


def classify(
    *,
    action: str = "deploy",
    dry_run: str = "false",
    prepare: str = "success",
    deploy: str = "success",
    switch: str = "success",
    validate: str = "success",
    scale_down: str = "success",
    deploy_server: str = "true",
    deploy_ac: str = "true",
) -> str:
    """Run the real classifier with the workflow's positional argument order."""

    result = subprocess.run(
        [
            "bash",
            str(CLASSIFIER),
            action,
            dry_run,
            prepare,
            deploy,
            switch,
            validate,
            scale_down,
            deploy_server,
            deploy_ac,
        ],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        raise AssertionError(
            f"classifier exited {result.returncode}: {result.stderr}"
        )
    return result.stdout.strip()


def load_jobs() -> dict:
    """Parse blue-green-deploy.yml's job graph."""

    return yaml.safe_load(WORKFLOW.read_text())["jobs"]


def write_executable(path: Path, content: str) -> None:
    path.write_text(content)
    path.chmod(0o755)


def run_release(
    tmp_path: Path, owner: str, *, state: str
) -> tuple[subprocess.CompletedProcess[str], Path, Path]:
    """Drive the vendored helper's release path against a seeded lock value."""

    state_path = tmp_path / "state"
    log_path = tmp_path / "aws.log"
    state_path.write_text(state)

    write_executable(tmp_path / "aws", STATEFUL_AWS)
    env = os.environ.copy()
    env.update(
        {
            "AWS_REGION": "us-east-2",
            "FAKE_AWS_STATE": str(state_path),
            "FAKE_AWS_LOG": str(log_path),
            "PATH": f"{tmp_path}{os.pathsep}{env['PATH']}",
        }
    )

    result = subprocess.run(
        [
            "bash",
            str(LOCK_SCRIPT),
            "release",
            "/layerv-nhp-sandbox/qurl-live-env-lock",
            owner,
        ],
        cwd=ROOT,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    return result, state_path, log_path


class ReleaseWhenBoundaryNeverMovedTests(unittest.TestCase):
    """switch-traffic never ran => the customer path is untouched => release."""

    def test_releases_on_deploy_to_standby_failure(self) -> None:
        """The exact shape of run 30337884706, which held the lock four hours."""

        self.assertEqual(
            classify(
                prepare="success",
                deploy="failure",
                switch="skipped",
                validate="skipped",
                scale_down="skipped",
            ),
            "true",
        )

    def test_releases_on_cancellation_before_the_switch(self) -> None:
        """A cancelled roll is skipped past switch-traffic by its own guard."""

        self.assertEqual(
            classify(
                prepare="success",
                deploy="cancelled",
                switch="skipped",
                validate="skipped",
                scale_down="skipped",
            ),
            "true",
        )

    def test_releases_when_a_cancelled_run_skips_every_later_job(self) -> None:
        for action in ("deploy", "rollback", "switch-only"):
            with self.subTest(action=action):
                self.assertEqual(
                    classify(
                        action=action,
                        deploy="cancelled",
                        switch="skipped",
                        validate="skipped",
                        scale_down="skipped",
                    ),
                    "true",
                )

    def test_releases_on_prepare_failure_and_dry_runs(self) -> None:
        self.assertEqual(classify(prepare="failure"), "true")
        self.assertEqual(classify(prepare="cancelled"), "true")
        self.assertEqual(classify(dry_run="true", deploy="failure"), "true")

    def test_releases_a_read_only_no_component_run(self) -> None:
        self.assertEqual(
            classify(deploy_server="false", deploy_ac="false", deploy="failure"),
            "true",
        )


class RetainWhenBoundaryMayHaveMovedTests(unittest.TestCase):
    """Fail closed for anything that could leave a half-switched boundary."""

    def test_retains_when_the_switch_itself_failed(self) -> None:
        self.assertEqual(
            classify(switch="failure", validate="skipped", scale_down="skipped"),
            "false",
        )

    def test_retains_when_the_switch_was_cancelled_mid_flight(self) -> None:
        """Cancelled != skipped: listeners may have moved partway."""

        self.assertEqual(
            classify(switch="cancelled", validate="skipped", scale_down="skipped"),
            "false",
        )

    def test_retains_when_post_switch_validation_failed(self) -> None:
        self.assertEqual(classify(switch="success", validate="failure"), "false")

    def test_retains_when_scale_down_did_not_converge(self) -> None:
        self.assertEqual(classify(action="deploy", scale_down="failure"), "false")

    def test_retains_when_the_deploy_failed_but_the_switch_still_ran(self) -> None:
        self.assertEqual(classify(action="deploy", deploy="failure"), "false")

    def test_fully_converged_deploy_releases(self) -> None:
        self.assertEqual(classify(action="deploy"), "true")
        self.assertEqual(classify(action="rollback", deploy="skipped"), "true")
        self.assertEqual(classify(action="switch-only", deploy="skipped"), "true")


class ExactOwnerReleaseTests(unittest.TestCase):
    """A release must never delete a lock some other run legitimately holds."""

    def test_refuses_to_release_a_lock_owned_by_a_different_run(self) -> None:
        """Live shape, foreign run_id: no delete, no failure, lock preserved."""

        ours = OWNER_TEMPLATE.format(run_id="30354530304", run_attempt="1")
        with tempfile.TemporaryDirectory() as tmp:
            result, state_path, log_path = run_release(
                Path(tmp), ours, state=LIVE_LOCK_VALUE
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("Not releasing live-environment lock", result.stdout)
            self.assertIn("nhp:30337884706:1:blue-green", result.stdout)
            self.assertNotIn("Released live-environment lock", result.stdout)
            # Nothing was deleted, and the foreign lock survives byte-for-byte.
            self.assertFalse(log_path.exists())
            self.assertEqual(
                json.loads(state_path.read_text()), json.loads(LIVE_LOCK_VALUE)
            )

    def test_refuses_when_only_the_run_attempt_differs(self) -> None:
        """Re-running a failed job changes run_attempt, so it owns nothing."""

        retry = OWNER_TEMPLATE.format(run_id="30337884706", run_attempt="2")
        with tempfile.TemporaryDirectory() as tmp:
            result, state_path, log_path = run_release(
                Path(tmp), retry, state=LIVE_LOCK_VALUE
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("Not releasing live-environment lock", result.stdout)
            self.assertFalse(log_path.exists())
            self.assertEqual(
                json.loads(state_path.read_text()), json.loads(LIVE_LOCK_VALUE)
            )

    def test_releases_its_own_lock_in_the_live_shape(self) -> None:
        ours = OWNER_TEMPLATE.format(run_id="30337884706", run_attempt="1")
        with tempfile.TemporaryDirectory() as tmp:
            result, _, log_path = run_release(Path(tmp), ours, state=LIVE_LOCK_VALUE)

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("Released live-environment lock", result.stdout)
            self.assertIn("delete", log_path.read_text())

    def test_live_lock_value_carries_the_fields_the_helper_reads(self) -> None:
        """Guard the fixture itself against drifting from the real parameter."""

        lock = json.loads(LIVE_LOCK_VALUE)
        self.assertEqual(set(lock), {"owner", "created_at", "expires_at"})
        self.assertRegex(lock["owner"], r"^nhp:\d+:\d+:blue-green$")
        self.assertIsInstance(lock["expires_at"], int)
        # 14400s ttl-seconds, the documented backstop that must stay in place.
        self.assertEqual(lock["expires_at"] - lock["created_at"], 14400)


class SwitchTrafficGuardTests(unittest.TestCase):
    """The premise the `switch == skipped` release branch is built on.

    Releasing on a skipped switch is safe only when standby deployment did not
    succeed, or when the explicit prepare-only action intentionally stops
    before listeners. Pin that closed union here.
    """

    def setUp(self) -> None:
        self.job = load_jobs()["switch-traffic"]

    def test_switch_traffic_depends_only_on_prepare_and_deploy_to_standby(self) -> None:
        needs = self.job["needs"]
        needs = [needs] if isinstance(needs, str) else list(needs)
        self.assertEqual(sorted(needs), ["deploy-to-standby", "prepare"])

    def test_switch_traffic_skips_only_for_pre_switch_outcomes(
        self,
    ) -> None:
        condition = " ".join(self.job["if"].split())
        self.assertEqual(
            condition,
            "always() && inputs.action != 'prepare-only' && "
            "needs.prepare.result == 'success' && "
            "(needs.deploy-to-standby.result == 'success' || "
            "needs.deploy-to-standby.result == 'skipped')",
        )

    def test_switch_traffic_owns_the_only_live_boundary_mutation(self) -> None:
        """No other job may call the switch helper that moves the listeners."""

        callers = {
            name
            for name, job in load_jobs().items()
            if "blue-green-switch.sh" in yaml.safe_dump(job)
        }
        self.assertEqual(callers, {"switch-traffic"})


class FinalizeJobWiringTests(unittest.TestCase):
    """The classifier only helps if finalization actually reaches it."""

    def setUp(self) -> None:
        self.workflow = WORKFLOW.read_text()
        match = re.search(
            r"\n  finalize-qurl-live-env-lock:\n(.*?)(?=\n  [a-z][a-z0-9-]*:\n)",
            self.workflow,
            re.DOTALL,
        )
        self.assertIsNotNone(match, "finalize-qurl-live-env-lock job not found")
        self.block = match.group(1)
        self.steps = {
            step["name"]: step
            for step in load_jobs()["finalize-qurl-live-env-lock"]["steps"]
            if "name" in step
        }

    def test_classifier_is_called_with_its_documented_argument_order(self) -> None:
        """Cross-check the call site against the classifier's own usage line.

        Both sides are load-bearing and neither is self-describing at runtime: a
        reordered positional would keep every standalone classifier test green
        while inverting the real release decision.
        """

        usage = re.search(r"usage: \$0 (.+?)\" >&2", CLASSIFIER.read_text())
        self.assertIsNotNone(usage, "classifier usage line not found")
        expected = [
            token.strip("<>").replace("-", "_").upper()
            for token in usage.group(1).split()
            if token.startswith("<")
        ]
        self.assertEqual(len(expected), 9, expected)

        step = self.steps["Classify blue/green terminal state"]
        invocation = re.search(
            r"classify-blue-green-lock-release\.sh(.*?)\)", step["run"], re.DOTALL
        )
        self.assertIsNotNone(invocation, "classifier invocation not found")
        actual = re.findall(r'"\$([A-Z_]+)"', invocation.group(1))
        self.assertEqual(actual, expected)

    def test_classifier_reads_each_result_from_the_matching_job(self) -> None:
        env = self.steps["Classify blue/green terminal state"]["env"]
        self.assertEqual(env["PREPARE_RESULT"], "${{ needs.prepare.result }}")
        self.assertEqual(env["DEPLOY_RESULT"], "${{ needs.deploy-to-standby.result }}")
        self.assertEqual(env["SWITCH_RESULT"], "${{ needs.switch-traffic.result }}")
        self.assertEqual(env["VALIDATE_RESULT"], "${{ needs.validate.result }}")
        self.assertEqual(
            env["SCALE_DOWN_RESULT"], "${{ needs.scale-down-previous.result }}"
        )

    def test_release_is_gated_on_the_classifier_verdict(self) -> None:
        release = self.steps["Release sandbox live-environment lock"]
        self.assertEqual(
            " ".join(release["if"].split()),
            "steps.terminal-state.outputs.safe_to_release == 'true'",
        )
        retain = self.steps[
            "Retain sandbox live-environment lock after blue/green failure"
        ]
        self.assertIn("safe_to_release != 'true'", " ".join(retain["if"].split()))

    def test_finalization_is_not_gated_on_the_acquire_job_result(self) -> None:
        """The acquire job can be cancelled after it has written the lock."""

        self.assertRegex(self.block, r"\n    if: always\(\)\n")
        self.assertNotIn(
            "needs.acquire-qurl-live-env-lock.result == 'success'", self.block
        )

    def test_finalization_waits_for_every_job_the_classifier_reads(self) -> None:
        for dependency in (
            "acquire-qurl-live-env-lock",
            "prepare",
            "deploy-to-standby",
            "switch-traffic",
            "validate",
            "scale-down-previous",
        ):
            with self.subTest(dependency=dependency):
                self.assertRegex(self.block, rf"\n      - {dependency}\n")

    def test_release_uses_this_runs_exact_owner_token(self) -> None:
        self.assertIn(
            "owner: nhp:${{ github.run_id }}:${{ github.run_attempt }}:blue-green",
            self.block,
        )

    def test_ttl_backstop_is_retained(self) -> None:
        self.assertIn("ttl-seconds: '14400'", self.block)



class WarmStandbyConvergenceTest(unittest.TestCase):
    """The scale-down wait must test SERVING capacity, not the ASG's raw
    instance list.

    Run 31425138552 failed for its full 300 s deadline on
    `desired=1 total=2 healthy-in-service=1`: warm standby had been reached
    immediately, and the gate was blocked by a second instance already out of
    service, held in Terminating:Wait by layerv-nhp-sandbox-termination-hook —
    whose 300 s heartbeat timeout equals the deadline, so the wait could never
    reliably outlast the hook it was waiting on. The red run retained the
    sandbox live-env lock for four hours.

    A revert to length(Instances) reintroduces exactly that, so it is fenced
    rather than only commented.
    """

    def setUp(self):
        self.body = WORKFLOW.read_text()

    def test_convergence_counts_inservice_not_every_instance(self):
        self.assertIn(
            "length(Instances[?LifecycleState==`InService`])",
            self.body,
            "the warm-standby query must count InService instances",
        )
        self.assertNotIn(
            "[DesiredCapacity,length(Instances),",
            self.body,
            "counting every instance re-couples this wait to the termination "
            "lifecycle hook, which can hold a draining instance for the whole "
            "deadline (run 31425138552)",
        )

    def test_convergence_condition_uses_inservice(self):
        self.assertIn(
            '"$desired" == "1" && "$in_service" == "1" && "$healthy_in_service" == "1"',
            self.body,
            "warm standby is desired=1 with exactly one healthy InService "
            "instance; draining instances do not serve",
        )

if __name__ == "__main__":
    unittest.main(verbosity=2)
