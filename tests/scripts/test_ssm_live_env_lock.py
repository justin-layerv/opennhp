"""Behavioral and provenance tests for the vendored SSM sandbox lock."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
ACTION = ROOT / ".github/actions/sandbox-live-env-lock/action.yml"
LOCK_SCRIPT = ROOT / ".github/scripts/ssm-live-env-lock.sh"
METRIC_SCRIPT = ROOT / ".github/scripts/emit-sandbox-lock-failure-metric.sh"
SSM_READER = ROOT / "scripts/ssm-read-optional.sh"
PROVENANCE = ROOT / ".github/actions/sandbox-live-env-lock/provenance.json"
RUNBOOK = ROOT / "docs/runbooks/sandbox-live-env-lock.md"


STATEFUL_AWS = r"""#!/usr/bin/env bash
set -euo pipefail

case "${1:-} ${2:-}" in
  "ssm put-parameter")
    if [[ -s "$FAKE_AWS_STATE" ]]; then
      echo "An error occurred (ParameterAlreadyExists) when calling the PutParameter operation: The parameter already exists." >&2
      exit 254
    fi
    while [[ $# -gt 0 ]]; do
      if [[ "$1" == "--value" ]]; then
        shift
        printf '%s' "$1" > "$FAKE_AWS_STATE"
        exit 0
      fi
      shift
    done
    echo "missing --value" >&2
    exit 99
    ;;
  "ssm get-parameter")
    [[ -f "$FAKE_AWS_STATE" ]] && cat "$FAKE_AWS_STATE"
    exit 0
    ;;
  "ssm delete-parameter")
    echo "delete" >> "$FAKE_AWS_LOG"
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


READ_FAIL_AWS = r"""#!/usr/bin/env bash
set -euo pipefail

case "${1:-} ${2:-}" in
  "ssm put-parameter")
    echo "An error occurred (ParameterAlreadyExists) when calling the PutParameter operation: The parameter already exists." >&2
    exit 254
    ;;
  "ssm get-parameter")
    echo "An error occurred (ThrottlingException) when calling the GetParameter operation: Rate exceeded" >&2
    exit 254
    ;;
  "ssm delete-parameter")
    echo "delete" >> "$FAKE_AWS_LOG"
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


READ_FAIL_ON_STALE_DELETE_AWS = r"""#!/usr/bin/env bash
set -euo pipefail

get_count_file="${FAKE_AWS_STATE}.get-count"

case "${1:-} ${2:-}" in
  "ssm put-parameter")
    echo "An error occurred (ParameterAlreadyExists) when calling the PutParameter operation: The parameter already exists." >&2
    exit 254
    ;;
  "ssm get-parameter")
    count=0
    if [[ -f "$get_count_file" ]]; then
      count="$(cat "$get_count_file")"
    fi
    count=$((count + 1))
    printf '%s' "$count" > "$get_count_file"
    if [[ "$count" -eq 1 ]]; then
      cat "$FAKE_AWS_STATE"
      exit 0
    fi
    echo "An error occurred (ThrottlingException) when calling the GetParameter operation: Rate exceeded" >&2
    exit 254
    ;;
  "ssm delete-parameter")
    echo "delete" >> "$FAKE_AWS_LOG"
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


DELETE_FAIL_AWS = r"""#!/usr/bin/env bash
set -euo pipefail

case "${1:-} ${2:-}" in
  "ssm get-parameter")
    [[ -f "$FAKE_AWS_STATE" ]] && cat "$FAKE_AWS_STATE"
    exit 0
    ;;
  "ssm delete-parameter")
    echo "An error occurred (ThrottlingException) when calling the DeleteParameter operation: Rate exceeded" >&2
    exit 254
    ;;
  "cloudwatch put-metric-data")
    echo "metric $*" >> "$FAKE_AWS_LOG"
    exit 0
    ;;
esac

echo "unexpected aws args: $*" >&2
exit 99
"""


PARAMETER_NOT_FOUND_AWS = r"""#!/usr/bin/env bash
echo "An error occurred (ParameterNotFound) when calling the GetParameter operation: Parameter not found" >&2
exit 254
"""


ACCESS_DENIED_AWS = r"""#!/usr/bin/env bash
echo "An error occurred (AccessDeniedException) when calling the GetParameter operation: denied" >&2
exit 254
"""


PUT_FAIL_AWS = r"""#!/usr/bin/env bash
set -euo pipefail

case "${1:-} ${2:-}" in
  "ssm put-parameter")
    echo "An error occurred (AccessDeniedException) when calling the PutParameter operation: denied" >&2
    exit 254
    ;;
  "cloudwatch put-metric-data")
    echo "metric $*" >> "$FAKE_AWS_LOG"
    exit 0
    ;;
esac

echo "unexpected aws args: $*" >&2
exit 99
"""


METRIC_AWS = r"""#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$FAKE_AWS_LOG"
is_diagnostic=false
if [[ " $* " == *" --dimensions "* ]]; then
  is_diagnostic=true
fi
case "${FAKE_AWS_FAIL:-}" in
  alarm) [[ "$is_diagnostic" == "false" ]] && exit 254 ;;
  diagnostic) [[ "$is_diagnostic" == "true" ]] && exit 254 ;;
  all) exit 254 ;;
esac
"""


def write_executable(path: Path, content: str) -> None:
    path.write_text(content)
    path.chmod(0o755)


def run_lock(
    tmp_path: Path,
    args: list[str],
    *,
    aws_script: str,
    state: str | None = None,
) -> tuple[subprocess.CompletedProcess[str], Path, Path]:
    state_path = tmp_path / "state"
    log_path = tmp_path / "aws.log"
    if state is not None:
        state_path.write_text(state)

    write_executable(tmp_path / "aws", aws_script)
    write_executable(tmp_path / "sleep", "#!/usr/bin/env bash\nexit 0\n")
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
        ["bash", str(LOCK_SCRIPT), *args],
        cwd=ROOT,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    return result, state_path, log_path


def read_action_inputs() -> dict[str, dict[str, str]]:
    """Parse the deliberately simple top-level action input mapping."""

    inputs: dict[str, dict[str, str]] = {}
    current: str | None = None
    in_inputs = False
    for line in ACTION.read_text().splitlines():
        if line == "inputs:":
            in_inputs = True
            continue
        if in_inputs and line == "runs:":
            break
        if not in_inputs:
            continue
        input_match = re.fullmatch(r"  ([a-z0-9-]+):", line)
        if input_match:
            current = input_match.group(1)
            inputs[current] = {}
            continue
        property_match = re.fullmatch(r"    ([a-z-]+):\s*(.*)", line)
        if current and property_match:
            value = property_match.group(2).strip("'\"")
            inputs[current][property_match.group(1)] = value
    return inputs


def assert_lock_metric(
    test: unittest.TestCase, log_path: Path, *, reason: str, action: str
) -> None:
    metric_lines = [
        line for line in log_path.read_text().splitlines() if line.startswith("metric ")
    ]
    test.assertEqual(
        metric_lines,
        [
            "metric cloudwatch put-metric-data --region us-east-2 "
            "--namespace LayerV/QURLServiceCI "
            "--metric-name SandboxLiveEnvLockFailure --value 1 --unit Count",
            "metric cloudwatch put-metric-data --region us-east-2 "
            "--namespace LayerV/QURLServiceCI "
            "--metric-name SandboxLiveEnvLockFailure "
            f"--dimensions Reason={reason},Action={action} --value 1 --unit Count",
        ],
    )


class ProvenanceAndSchemaTests(unittest.TestCase):
    def test_manifest_pins_every_vendored_file_and_hash(self) -> None:
        manifest = json.loads(PROVENANCE.read_text())
        self.assertEqual(
            set(manifest),
            {"schema_version", "source_repository", "source_commit", "files"},
        )
        self.assertEqual(manifest["schema_version"], 1)
        self.assertEqual(manifest["source_repository"], "layervai/qurl-service")
        self.assertRegex(manifest["source_commit"], r"^[0-9a-f]{40}$")

        expected_sources = {
            ".github/actions/sandbox-live-env-lock/action.yml",
            ".github/scripts/ssm-live-env-lock.sh",
            ".github/scripts/emit-sandbox-lock-failure-metric.sh",
            "scripts/ssm-read-optional.sh",
        }
        records = manifest["files"]
        self.assertEqual({record["source"] for record in records}, expected_sources)
        self.assertEqual(
            {record["destination"] for record in records}, expected_sources
        )
        self.assertEqual(len(records), len(expected_sources))

        for record in records:
            self.assertEqual(set(record), {"source", "destination", "sha256"})
            destination = ROOT / record["destination"]
            self.assertTrue(destination.is_file(), destination)
            self.assertRegex(record["sha256"], r"^[0-9a-f]{64}$")
            self.assertEqual(
                hashlib.sha256(destination.read_bytes()).hexdigest(),
                record["sha256"],
                destination,
            )

        runbook_text = RUNBOOK.read_text()
        self.assertIn(manifest["source_commit"], runbook_text)
        self.assertIn("provenance.json", runbook_text)

    def test_action_schema_and_budget_are_locked(self) -> None:
        inputs = read_action_inputs()
        self.assertEqual(
            set(inputs),
            {
                "action",
                "owner",
                "ssm-parameter-name",
                "aws-region",
                "ttl-seconds",
                "wait-seconds",
            },
        )
        for name in ("action", "owner", "ssm-parameter-name", "aws-region"):
            self.assertEqual(inputs[name].get("required"), "true")
        self.assertEqual(inputs["ttl-seconds"].get("required"), "false")
        self.assertEqual(inputs["ttl-seconds"].get("default"), "14400")
        self.assertEqual(inputs["wait-seconds"].get("required"), "false")
        self.assertEqual(inputs["wait-seconds"].get("default"), "7200")

        ttl_seconds = int(inputs["ttl-seconds"]["default"])
        wait_seconds = int(inputs["wait-seconds"]["default"])
        self.assertLess(wait_seconds, ttl_seconds)
        self.assertGreaterEqual(ttl_seconds, 180 * 60 + 900)

        action_text = ACTION.read_text()
        self.assertIn("using: composite", action_text)
        self.assertIn("shell: bash", action_text)
        for name in inputs:
            self.assertEqual(action_text.count(f"${{{{ inputs.{name} }}}}"), 1)

    def test_vendored_annotations_reference_the_local_runbook(self) -> None:
        self.assertTrue(RUNBOOK.is_file())
        references = re.findall(
            r"docs/runbooks/sandbox-live-env-lock\.md", LOCK_SCRIPT.read_text()
        )
        self.assertGreaterEqual(len(references), 1)


class LockBehaviorTests(unittest.TestCase):
    def test_lock_requires_region_before_aws_call(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            aws_path = tmp_path / "aws"
            write_executable(
                aws_path,
                "#!/usr/bin/env bash\necho aws-called > \"$FAKE_AWS_LOG\"\nexit 99\n",
            )
            log_path = tmp_path / "aws.log"
            env = os.environ.copy()
            env.update(
                {
                    "FAKE_AWS_LOG": str(log_path),
                    "PATH": f"{tmp_path}{os.pathsep}{env['PATH']}",
                }
            )
            env.pop("AWS_REGION", None)
            env.pop("AWS_DEFAULT_REGION", None)
            result = subprocess.run(
                [
                    "bash",
                    str(LOCK_SCRIPT),
                    "acquire",
                    "/test/qurl-live-env-lock",
                    "owner-a",
                ],
                cwd=ROOT,
                env=env,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("AWS_REGION must be set", result.stderr)
            self.assertFalse(log_path.exists())

    def test_acquire_creates_well_formed_owned_lock(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result, state_path, log_path = run_lock(
                Path(tmp),
                ["acquire", "/test/qurl-live-env-lock", "owner-a", "60", "1"],
                aws_script=STATEFUL_AWS,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            lock = json.loads(state_path.read_text())
            self.assertEqual(lock["owner"], "owner-a")
            self.assertEqual(lock["expires_at"] - lock["created_at"], 60)
            self.assertFalse(log_path.exists())

    def test_acquire_fails_closed_on_malformed_existing_lock(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result, _, log_path = run_lock(
                Path(tmp),
                ["acquire", "/test/qurl-live-env-lock", "owner-a", "60", "1"],
                aws_script=STATEFUL_AWS,
                state="not-json",
            )
            self.assertEqual(result.returncode, 1)
            self.assertIn("Malformed sandbox live-environment lock", result.stderr)
            self.assertIn(
                "not valid lock JSON with owner and numeric expires_at", result.stderr
            )
            assert_lock_metric(self, log_path, reason="Malformed", action="acquire")

    def test_acquire_fails_closed_with_annotated_read_error(self) -> None:
        state = json.dumps(
            {"owner": "owner-b", "created_at": 1, "expires_at": 9999999999}
        )
        with tempfile.TemporaryDirectory() as tmp:
            result, _, log_path = run_lock(
                Path(tmp),
                ["acquire", "/test/qurl-live-env-lock", "owner-a", "60", "1"],
                aws_script=READ_FAIL_AWS,
                state=state,
            )
            self.assertEqual(result.returncode, 3)
            self.assertIn("Sandbox live-environment lock read failed", result.stderr)
            self.assertIn("failing closed without retry", result.stderr)
            self.assertIn("not a qv2 admission result", result.stderr)
            assert_lock_metric(self, log_path, reason="ReadFailed", action="acquire")

    def test_acquire_breaks_stale_lock_then_acquires(self) -> None:
        stale = json.dumps({"owner": "owner-old", "created_at": 1, "expires_at": 1})
        with tempfile.TemporaryDirectory() as tmp:
            result, state_path, log_path = run_lock(
                Path(tmp),
                ["acquire", "/test/qurl-live-env-lock", "owner-new", "60", "1"],
                aws_script=STATEFUL_AWS,
                state=stale,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("Deleting stale live-environment lock", result.stdout)
            self.assertIn("Acquired live-environment lock", result.stdout)
            self.assertEqual(log_path.read_text(), "delete\n")
            self.assertEqual(json.loads(state_path.read_text())["owner"], "owner-new")

    def test_acquire_stale_break_fails_closed_on_second_read_error(self) -> None:
        stale = json.dumps({"owner": "owner-old", "created_at": 1, "expires_at": 1})
        with tempfile.TemporaryDirectory() as tmp:
            result, state_path, log_path = run_lock(
                Path(tmp),
                ["acquire", "/test/qurl-live-env-lock", "owner-new", "60", "1"],
                aws_script=READ_FAIL_ON_STALE_DELETE_AWS,
                state=stale,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Deleting stale live-environment lock", result.stdout)
            self.assertIn("Sandbox live-environment lock read failed", result.stderr)
            self.assertEqual(json.loads(state_path.read_text())["owner"], "owner-old")
            self.assertNotIn("delete", log_path.read_text())
            assert_lock_metric(self, log_path, reason="ReadFailed", action="acquire")

    def test_acquire_contention_emits_metric_before_failing(self) -> None:
        live = json.dumps(
            {"owner": "owner-b", "created_at": 1, "expires_at": 9999999999}
        )
        with tempfile.TemporaryDirectory() as tmp:
            result, _, log_path = run_lock(
                Path(tmp),
                ["acquire", "/test/qurl-live-env-lock", "owner-a", "60", "0"],
                aws_script=STATEFUL_AWS,
                state=live,
            )
            self.assertEqual(result.returncode, 1)
            self.assertIn("Sandbox live-environment lock contention", result.stderr)
            assert_lock_metric(self, log_path, reason="Contention", action="acquire")

    def test_acquire_unexpected_put_failure_emits_metric_and_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result, _, log_path = run_lock(
                Path(tmp),
                ["acquire", "/test/qurl-live-env-lock", "owner-a", "60", "1"],
                aws_script=PUT_FAIL_AWS,
            )
            self.assertEqual(result.returncode, 1)
            self.assertIn("failed to acquire live-environment lock", result.stderr)
            assert_lock_metric(self, log_path, reason="PutFailed", action="acquire")

    def test_release_deletes_only_the_callers_lock(self) -> None:
        owned = json.dumps(
            {"owner": "owner-a", "created_at": 1, "expires_at": 9999999999}
        )
        with tempfile.TemporaryDirectory() as tmp:
            result, state_path, log_path = run_lock(
                Path(tmp),
                ["release", "/test/qurl-live-env-lock", "owner-a"],
                aws_script=STATEFUL_AWS,
                state=owned,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("Released live-environment lock", result.stdout)
            self.assertEqual(log_path.read_text(), "delete\n")
            self.assertEqual(state_path.read_text(), "")

    def test_release_is_idempotent_when_lock_is_absent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result, _, log_path = run_lock(
                Path(tmp),
                ["release", "/test/qurl-live-env-lock", "owner-a"],
                aws_script=STATEFUL_AWS,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("Live-environment lock already absent", result.stdout)
            self.assertFalse(log_path.exists())


    def test_release_fails_closed_on_read_error(self) -> None:
        owned = json.dumps(
            {"owner": "owner-a", "created_at": 1, "expires_at": 9999999999}
        )
        with tempfile.TemporaryDirectory() as tmp:
            result, state_path, log_path = run_lock(
                Path(tmp),
                ["release", "/test/qurl-live-env-lock", "owner-a"],
                aws_script=READ_FAIL_AWS,
                state=owned,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Sandbox live-environment lock read failed", result.stderr)
            self.assertEqual(json.loads(state_path.read_text())["owner"], "owner-a")
            self.assertNotIn("delete", log_path.read_text())
            assert_lock_metric(self, log_path, reason="ReadFailed", action="release")

    def test_release_fails_closed_on_malformed_existing_lock(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result, state_path, log_path = run_lock(
                Path(tmp),
                ["release", "/test/qurl-live-env-lock", "owner-a"],
                aws_script=STATEFUL_AWS,
                state="not-json",
            )
            self.assertEqual(result.returncode, 1)
            self.assertIn("Malformed sandbox live-environment lock", result.stderr)
            self.assertEqual(state_path.read_text(), "not-json")
            self.assertNotIn("delete", log_path.read_text())
            assert_lock_metric(self, log_path, reason="Malformed", action="release")

    def test_release_fails_loudly_when_delete_fails(self) -> None:
        owned = json.dumps(
            {"owner": "owner-a", "created_at": 1, "expires_at": 9999999999}
        )
        with tempfile.TemporaryDirectory() as tmp:
            result, state_path, log_path = run_lock(
                Path(tmp),
                ["release", "/test/qurl-live-env-lock", "owner-a"],
                aws_script=DELETE_FAIL_AWS,
                state=owned,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Sandbox live-environment lock delete failed", result.stderr)
            self.assertNotIn("Released live-environment lock", result.stdout)
            self.assertEqual(json.loads(state_path.read_text())["owner"], "owner-a")
            assert_lock_metric(self, log_path, reason="DeleteFailed", action="release")

    def test_release_preserves_another_owners_lock(self) -> None:
        foreign = json.dumps(
            {"owner": "owner-b", "created_at": 1, "expires_at": 9999999999}
        )
        with tempfile.TemporaryDirectory() as tmp:
            result, state_path, log_path = run_lock(
                Path(tmp),
                ["release", "/test/qurl-live-env-lock", "owner-a"],
                aws_script=STATEFUL_AWS,
                state=foreign,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("owner is owner-b, not owner-a", result.stdout)
            self.assertFalse(log_path.exists())
            self.assertEqual(json.loads(state_path.read_text())["owner"], "owner-b")

    def test_unknown_action_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result, _, _ = run_lock(
                Path(tmp),
                ["renew", "/test/qurl-live-env-lock", "owner-a"],
                aws_script=STATEFUL_AWS,
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("usage:", result.stderr)


class OptionalSSMReaderTests(unittest.TestCase):
    def run_reader(
        self, aws_script: str, *, region: str | None = "us-east-2"
    ) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            write_executable(tmp_path / "aws", aws_script)
            env = os.environ.copy()
            env["PATH"] = f"{tmp_path}{os.pathsep}{env['PATH']}"
            env.pop("AWS_DEFAULT_REGION", None)
            if region is None:
                env.pop("AWS_REGION", None)
            else:
                env["AWS_REGION"] = region
            return subprocess.run(
                ["bash", str(SSM_READER), "/test/optional"],
                cwd=ROOT,
                env=env,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

    def test_parameter_not_found_is_the_only_soft_failure(self) -> None:
        result = self.run_reader(PARAMETER_NOT_FOUND_AWS)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "")

    def test_other_aws_errors_fail_loudly(self) -> None:
        result = self.run_reader(ACCESS_DENIED_AWS)
        self.assertEqual(result.returncode, 1)
        self.assertIn("reason other than ParameterNotFound", result.stderr)
        self.assertIn("AccessDeniedException", result.stderr)

    def test_missing_region_fails_before_aws_call(self) -> None:
        result = self.run_reader(PARAMETER_NOT_FOUND_AWS, region=None)
        self.assertEqual(result.returncode, 2)
        self.assertIn("AWS_REGION must be set", result.stderr)


class MetricBehaviorTests(unittest.TestCase):
    def run_metric(
        self,
        reason: str,
        action: str,
        *,
        fail: str = "",
        region: str | None = "us-east-2",
    ) -> tuple[subprocess.CompletedProcess[str], Path, tempfile.TemporaryDirectory[str]]:
        tmp = tempfile.TemporaryDirectory()
        tmp_path = Path(tmp.name)
        log_path = tmp_path / "aws.log"
        write_executable(tmp_path / "aws", METRIC_AWS)
        env = os.environ.copy()
        env.update(
            {
                "FAKE_AWS_LOG": str(log_path),
                "FAKE_AWS_FAIL": fail,
                "PATH": f"{tmp_path}{os.pathsep}{env['PATH']}",
            }
        )
        env.pop("AWS_DEFAULT_REGION", None)
        if region is None:
            env.pop("AWS_REGION", None)
        else:
            env["AWS_REGION"] = region
        result = subprocess.run(
            ["bash", str(METRIC_SCRIPT), reason, action],
            cwd=ROOT,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        return result, log_path, tmp

    def test_exact_alarm_then_diagnostic_samples(self) -> None:
        result, log_path, tmp = self.run_metric("RollFailedRetained", "release")
        self.addCleanup(tmp.cleanup)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            log_path.read_text().splitlines(),
            [
                "cloudwatch put-metric-data --region us-east-2 --namespace LayerV/QURLServiceCI --metric-name SandboxLiveEnvLockFailure --value 1 --unit Count",
                "cloudwatch put-metric-data --region us-east-2 --namespace LayerV/QURLServiceCI --metric-name SandboxLiveEnvLockFailure --dimensions Reason=RollFailedRetained,Action=release --value 1 --unit Count",
            ],
        )

    def test_each_stream_is_attempted_when_the_other_fails(self) -> None:
        for failed_stream in ("alarm", "diagnostic"):
            with self.subTest(failed_stream=failed_stream):
                result, log_path, tmp = self.run_metric(
                    "Contention", "acquire", fail=failed_stream
                )
                self.addCleanup(tmp.cleanup)
                self.assertEqual(result.returncode, 0)
                self.assertEqual(len(log_path.read_text().splitlines()), 2)
                self.assertIn(f"stream={failed_stream}", result.stderr)

    def test_invalid_diagnostic_values_fail_after_alarm_attempt(self) -> None:
        result, log_path, tmp = self.run_metric("bad,reason", "retain")
        self.addCleanup(tmp.cleanup)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(len(log_path.read_text().splitlines()), 1)
        self.assertNotIn("--dimensions", log_path.read_text())

    def test_missing_region_fails_before_aws_call(self) -> None:
        result, log_path, tmp = self.run_metric(
            "Contention", "acquire", region=None
        )
        self.addCleanup(tmp.cleanup)
        self.assertEqual(result.returncode, 2)
        self.assertIn("AWS_REGION must be set", result.stderr)
        self.assertFalse(log_path.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
