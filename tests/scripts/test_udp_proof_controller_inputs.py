#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import json
import os
import re
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
VALIDATOR_PATH = (
    REPO_ROOT / ".github" / "scripts" / "validate_udp_proof_controller_inputs.py"
)
BROKER_SCRIPT = REPO_ROOT / ".github" / "scripts" / "invoke_udp_proof_broker.sh"
WAIT_SCRIPT = REPO_ROOT / ".github" / "scripts" / "wait_for_action_run.sh"
SPEC = importlib.util.spec_from_file_location(
    "udp_proof_controller_inputs", VALIDATOR_PATH
)
assert SPEC is not None and SPEC.loader is not None
validator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(validator)

SHA = {
    "frp": "1" * 40,
    "nhp": "2" * 40,
    "qurl_connector": "3" * 40,
    "qurl_go": "4" * 40,
    "qurl_integrations": "5" * 40,
    "qurl_mcp": "6" * 40,
    "qurl_python": "7" * 40,
    "qurl_reverse_tunnel_server": "8" * 40,
    "qurl_service": "9" * 40,
    "qurl_typescript": "a" * 40,
    "website": "b" * 40,
}


def valid_manifest(phase: str = "pre_removal") -> dict[str, object]:
    return {
        "phase": phase,
        "repositories": dict(SHA),
    }


def valid_candidates() -> dict[str, object]:
    return {
        "qurl_connector": {
            "head_ref": "justin/fix/connector-routing-identity",
        },
        "qurl_go": {
            "head_ref": "justin/feat/udp-credential-recovery",
        },
    }


class ValidatorTest(unittest.TestCase):
    def select_dispatch(self, **overrides: object) -> dict[str, str]:
        values: dict[str, object] = {
            "client": "connector",
            "proof_phase": "pre_removal",
            "manifest": valid_manifest(),
            "candidates": valid_candidates(),
            "connector_proof_run_id": "",
            "pre_removal_run_id": "",
        }
        values.update(overrides)
        return validator.select_dispatch(**values)

    def test_selects_connector_from_authenticated_provenance(self) -> None:
        outputs = self.select_dispatch()
        self.assertEqual(outputs["client_repository"], "layervai/qurl-connector")
        self.assertEqual(outputs["client_workflow"], "sandbox-smoke.yml")
        self.assertEqual(outputs["client_ref"], "justin/fix/connector-routing-identity")
        self.assertEqual(outputs["client_sha"], SHA["qurl_connector"])
        self.assertEqual(
            outputs["connector_workflow_identity"],
            (
                "layervai/qurl-connector/.github/workflows/"
                f"sandbox-smoke.yml@{SHA['qurl_connector']}"
            ),
        )

    def test_selects_qurl_go_from_authenticated_provenance(self) -> None:
        outputs = self.select_dispatch(
            client="qurl_go",
            proof_phase="post_removal",
            manifest=valid_manifest("post_removal"),
            connector_proof_run_id="12345",
            pre_removal_run_id="67890",
        )
        self.assertEqual(outputs["client_repository"], "layervai/qurl-go")
        self.assertEqual(outputs["client_workflow"], "native-udp-sandbox.yml")
        self.assertEqual(outputs["client_ref"], "justin/feat/udp-credential-recovery")
        self.assertEqual(outputs["client_sha"], SHA["qurl_go"])
        self.assertEqual(
            outputs["qurl_go_workflow_identity"],
            (
                "layervai/qurl-go/.github/workflows/"
                f"native-udp-sandbox.yml@{SHA['qurl_go']}"
            ),
        )

    def test_rejects_missing_or_cross_client_linkage(self) -> None:
        with self.assertRaisesRegex(
            validator.ValidationError, "Connector proof run ID"
        ):
            self.select_dispatch(client="qurl_go")
        with self.assertRaisesRegex(validator.ValidationError, "must be empty"):
            self.select_dispatch(connector_proof_run_id="123")
        with self.assertRaisesRegex(validator.ValidationError, "pre-removal run ID"):
            self.select_dispatch(
                proof_phase="post_removal",
                manifest=valid_manifest("post_removal"),
            )
        with self.assertRaisesRegex(validator.ValidationError, "must be empty"):
            self.select_dispatch(pre_removal_run_id="123")

    def test_rejects_invalid_client_or_phase_before_selection(self) -> None:
        with self.assertRaisesRegex(validator.ValidationError, "client"):
            self.select_dispatch(client="other")
        with self.assertRaisesRegex(validator.ValidationError, "proof_phase"):
            self.select_dispatch(proof_phase="other")


class WorkflowContractTest(unittest.TestCase):
    def test_controller_dispatch_is_exact_and_single_client_per_run(self) -> None:
        workflow = (
            REPO_ROOT / ".github" / "workflows" / "udp-proof-controller.yml"
        ).read_text()
        gate = workflow.split("jobs:\n  gate:\n", 1)[1].split("\n  proof:\n", 1)[0]
        proof = workflow.split("\n  proof:\n", 1)[1]
        self.assertIn("\npermissions: {}\n", workflow.split("\njobs:\n", 1)[0])
        self.assertIn("      actions: read\n", gate)
        self.assertIn("      contents: read\n", gate)
        self.assertIn("    timeout-minutes: 10\n", gate)
        self.assertIn('if timeout 30s gh api "$@" >"${destination}.tmp"; then', gate)
        self.assertNotIn("id-token: write", gate)
        self.assertIn("      contents: read\n", proof)
        self.assertIn("      id-token: write\n", proof)
        self.assertEqual(workflow.count("id-token: write"), 1)
        for required in (
            "client:",
            "proof_phase:",
            "deployment_producer_run_id:",
            "connector_proof_run_id:",
            "pre_removal_run_id:",
            "validate_udp_proof_producer_artifact.py metadata",
            "validate_udp_proof_producer_artifact.py files",
            "validate_udp_proof_client_artifact.py metadata",
            "validate_udp_proof_client_artifact.py archive",
            "validate_udp_proof_client_artifact.py files",
            "actions: read",
            "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c",
            "artifact-ids: ${{ steps.metadata.outputs.producer_artifact_id }}",
            "digest-mismatch: error",
            "actions/runs/${PRODUCER_RUN_ID}",
            "actions/runs/${PRODUCER_RUN_ID}/artifacts?per_page=100",
            "could not authenticate the producer run after bounded retries",
            "could not authenticate the producer artifact after bounded retries",
            "PINNED_CONNECTOR_SHA: 16cdff6260c20b671cdee735333a9096007b5f6e",
            "PINNED_QURL_GO_SHA: aaf682e3cd8836cf874627e95a5d2d4b9e8b12ab",
            "producer artifact does not bind the frozen Connector head",
            "producer artifact does not bind the frozen qurl-go head",
            "invoke_udp_proof_broker.sh",
            "wait_for_action_run.sh",
            "permission-actions: write",
            "permission-organization-self-hosted-runners: write",
            "retry_gh_api()",
            "could not read runner-group controls after bounded retries",
            "could not read runner-group repositories after bounded retries",
            '-f "proof_phase=$PROOF_PHASE"',
            '-f "deployment_manifest_b64=$DEPLOYMENT_MANIFEST_B64"',
            '-f "deployment_runtime_inputs_b64=$DEPLOYMENT_RUNTIME_INPUTS_B64"',
            '-f "deployment_producer_run_id=$DEPLOYMENT_PRODUCER_RUN_ID"',
            '-f "deployment_producer_run_attempt=$DEPLOYMENT_PRODUCER_RUN_ATTEMPT"',
            '-f "deployment_producer_head_sha=$DEPLOYMENT_PRODUCER_HEAD_SHA"',
            '-f "deployment_artifact_id=$DEPLOYMENT_ARTIFACT_ID"',
            '-f "deployment_artifact_digest=$DEPLOYMENT_ARTIFACT_DIGEST"',
            '-f "pre_removal_run_id=$PRE_REMOVAL_RUN_ID"',
            '-f "connector_proof_run_id=$CONNECTOR_PROOF_RUN_ID"',
            '-f "dispatch_correlation_id=$correlation_id"',
            '--branch "$CLIENT_REF"',
            "--limit 100",
            "client_run_title=$expected_title",
            "dispatch_correlation_id=$correlation_id",
            "deployment_manifest_sha256:",
            "deployment_runtime_inputs_sha256:",
            ".head_sha == $sha",
            ".display_title == $title",
            "index($runner_label)",
            "gh api --paginate --slurp",
            '"$CLIENT_REPOSITORY" "$CLIENT_RUN_ID" 155 allow',
            '"$CLIENT_REPOSITORY" "$CLIENT_RUN_ID" 155 fail',
            "timeout-minutes: 165",
            "id: app_wait2",
            "id: app_final",
            "id: app_cancel",
            "id: result",
            "steps.result.outcome != 'success'",
            "steps.app_cancel.outputs.token",
            "steps.dispatch.outputs.client_run_title != ''",
            'if [[ -z "$CLIENT_RUN_ID" ]]; then',
            'if ! runs="$(',
            "last_lookup_succeeded=false",
            'if status="$(gh api',
            'if gh run cancel "$CLIENT_RUN_ID"',
            '[[ "$status" == "completed" ]]; then',
            'if ! status="$(gh api',
            "Refresh AWS credentials for broker cleanup",
            "for attempt in $(seq 1 24)",
            "for attempt in $(seq 1 60)",
            "resolved_client_sha",
            "actions/runs/${CLIENT_RUN_ID}/artifacts?per_page=100",
            "actions/artifacts/${CLIENT_ARTIFACT_ID}/zip",
            "could not authenticate the client artifact after bounded retries",
            "could not download the exact client artifact after bounded retries",
            "--expected-digest \"$CLIENT_ARTIFACT_DIGEST\"",
            "--dispatch-correlation-id \"$DISPATCH_CORRELATION_ID\"",
            "--producer-artifact-digest \"$PRODUCER_ARTIFACT_DIGEST\"",
            "Client artifact: \\`${CLIENT_ARTIFACT_ID}\\` / \\`${CLIENT_ARTIFACT_DIGEST}\\`",
        ):
            self.assertIn(required, workflow)
        dispatch_inputs = workflow.split("    inputs:\n", 1)[1].split(
            "\nconcurrency:", 1
        )[0]
        self.assertNotIn("deployment_manifest_b64:", dispatch_inputs)
        self.assertNotIn("connector_ref:", dispatch_inputs)
        self.assertNotIn("qurl_go_ref:", dispatch_inputs)
        self.assertNotIn("--ref main", workflow)
        self.assertNotIn("--created", workflow)
        self.assertNotIn("needs: connector", workflow)
        self.assertNotIn("mapfile -t repositories < <(\n            gh api", workflow)
        self.assertEqual(workflow.count("secretsmanager create-secret"), 1)
        self.assertEqual(workflow.count("generate-jitconfig"), 1)
        self.assertEqual(
            workflow.count("aws-actions/configure-aws-credentials@"),
            2,
        )
        self.assertEqual(
            workflow.count('"$CLIENT_REPOSITORY" "$CLIENT_RUN_ID" 155 allow'),
            2,
        )
        self.assertEqual(
            workflow.count("--json databaseId,displayTitle,headBranch,headSha"),
            2,
        )
        self.assertEqual(
            len(
                re.findall(
                    r"\.displayTitle == \$title and\s+"
                    r"\.headBranch == \$ref and\s+"
                    r"\.headSha == \$sha",
                    workflow,
                )
            ),
            1,
        )
        self.assertEqual(workflow.count("permission-actions: write"), 3)
        self.assertEqual(workflow.count("permission-actions: read"), 1)
        self.assertEqual(
            workflow.count(
                "repositories: ${{ inputs.client == 'connector' && "
                "'qurl-connector' || 'qurl-go' }}"
            ),
            4,
        )
        self.assertEqual(
            workflow.count("permission-organization-self-hosted-runners: write"),
            1,
        )
        cancellation_token = next(
            line
            for line in workflow.splitlines()
            if "GH_TOKEN:" in line and "steps.app_cancel.outputs.token" in line
        )
        self.assertIn("steps.app_final.outputs.token", cancellation_token)
        self.assertNotIn("steps.app_wait2.outputs.token", cancellation_token)
        self.assertNotIn("steps.app.outputs.token", cancellation_token)
        self.assertNotIn('case "$CLIENT" in', workflow)
        self.assertNotIn("aws lambda invoke", workflow)


class ShellHelperTest(unittest.TestCase):
    def write_command(self, directory: Path, name: str, body: str) -> None:
        command = directory / name
        command.write_text(
            "#!/usr/bin/env bash\nset -euo pipefail\n" + textwrap.dedent(body)
        )
        command.chmod(0o755)

    def run_broker_with_response(
        self,
        response: str,
        *,
        action: str,
    ) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as directory:
            bin_dir = Path(directory)
            self.write_command(
                bin_dir,
                "aws",
                """
                response_file="${@: -1}"
                printf '%s\\n' "$BROKER_TEST_RESPONSE" >"$response_file"
                printf '{"StatusCode":200}\\n'
                """,
            )
            self.write_command(bin_dir, "sleep", "exit 0")
            env = os.environ.copy()
            env.update(
                {
                    "AWS_REGION": "us-east-2",
                    "BROKER_FUNCTION": "test-broker",
                    "BROKER_TEST_RESPONSE": response,
                    "PATH": f"{bin_dir}:{env['PATH']}",
                }
            )
            return subprocess.run(
                ["bash", str(BROKER_SCRIPT), action, "12345", "1"],
                check=False,
                capture_output=True,
                text=True,
                cwd=REPO_ROOT,
                env=env,
            )

    def test_broker_helper_accepts_only_exact_start_and_stop_responses(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bin_dir = Path(directory)
            self.write_command(
                bin_dir,
                "aws",
                r"""
                response_file="${@: -1}"
                payload=""
                while (( $# > 0 )); do
                  if [[ "$1" == "--payload" ]]; then
                    payload="$2"
                    break
                  fi
                  shift
                done
                if jq -e '.action == "start"' <<<"$payload" >/dev/null; then
                  printf '{"action":"start","status":"launched","instance_id":"i-123abc"}\n' >"$response_file"
                else
                  printf '{"action":"stop","status":"terminated","instances":["i-123abc"],"secret_deleted":true}\n' >"$response_file"
                fi
                printf '{"StatusCode":200}\n'
                """,
            )
            env = os.environ.copy()
            env.update(
                {
                    "AWS_REGION": "us-east-2",
                    "BROKER_FUNCTION": "test-broker",
                    "PATH": f"{bin_dir}:{env['PATH']}",
                }
            )
            for action in ("start", "stop"):
                subprocess.run(
                    ["bash", str(BROKER_SCRIPT), action, "12345", "1"],
                    check=True,
                    cwd=REPO_ROOT,
                    env=env,
                )

    def test_broker_helper_rejects_an_unrecognized_action_before_aws(self) -> None:
        result = subprocess.run(
            ["bash", str(BROKER_SCRIPT), "sweep", "12345", "1"],
            check=False,
            capture_output=True,
            text=True,
            cwd=REPO_ROOT,
            env={
                **os.environ,
                "AWS_REGION": "us-east-2",
                "BROKER_FUNCTION": "test-broker",
            },
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("must be start or stop", result.stdout)

    def test_broker_helper_rejects_response_protocol_extensions(self) -> None:
        result = self.run_broker_with_response(
            '{"action":"start","status":"launched","instance_id":"i-123abc","unexpected":true}',
            action="start",
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("did not confirm an exact ready runner", result.stdout)

    def test_broker_helper_accepts_exact_absent_stop_response(self) -> None:
        result = self.run_broker_with_response(
            '{"action":"stop","status":"absent","instances":[],"secret_deleted":false}',
            action="stop",
        )
        self.assertEqual(result.returncode, 0)

    def test_broker_helper_rejects_ambiguous_stop_instance_sets(self) -> None:
        responses = (
            '{"action":"stop","status":"terminated","instances":["i-123abc","i-123abc"],"secret_deleted":true}',
            '{"action":"stop","status":"terminated","instances":["not-an-instance"],"secret_deleted":true}',
        )
        for response in responses:
            with self.subTest(response=response):
                result = self.run_broker_with_response(response, action="stop")
                self.assertEqual(result.returncode, 1)
                self.assertIn(
                    "did not confirm exact runner/JIT cleanup",
                    result.stdout,
                )

    def test_wait_helper_captures_completed_run_body(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bin_dir = root / "bin"
            bin_dir.mkdir()
            self.write_command(
                bin_dir,
                "gh",
                """
                printf '{"status":"completed","conclusion":"success"}\n'
                """,
            )
            output = root / "run.json"
            env = os.environ.copy()
            env.update({"GH_TOKEN": "test", "PATH": f"{bin_dir}:{env['PATH']}"})
            subprocess.run(
                [
                    "bash",
                    str(WAIT_SCRIPT),
                    "layervai/qurl-go",
                    "12345",
                    "1",
                    "fail",
                    str(output),
                ],
                check=True,
                cwd=REPO_ROOT,
                env=env,
            )
            self.assertEqual(json.loads(output.read_text())["conclusion"], "success")

    def test_wait_helper_rejects_repository_outside_allowlist(self) -> None:
        result = subprocess.run(
            [
                "bash",
                str(WAIT_SCRIPT),
                "attacker/repository",
                "12345",
                "1",
                "fail",
                "/tmp/unused.json",
            ],
            check=False,
            capture_output=True,
            text=True,
            cwd=REPO_ROOT,
            env={**os.environ, "GH_TOKEN": "test"},
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("outside the UDP proof allowlist", result.stdout)

    def test_wait_helper_fail_mode_rejects_bounded_timeout(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bin_dir = root / "bin"
            bin_dir.mkdir()
            self.write_command(
                bin_dir,
                "gh",
                """
                printf '{"status":"in_progress"}\n'
                """,
            )
            self.write_command(bin_dir, "sleep", "exit 0")
            output = root / "run.json"
            env = os.environ.copy()
            env.update({"GH_TOKEN": "test", "PATH": f"{bin_dir}:{env['PATH']}"})
            result = subprocess.run(
                [
                    "bash",
                    str(WAIT_SCRIPT),
                    "layervai/qurl-go",
                    "12345",
                    "2",
                    "fail",
                    str(output),
                ],
                check=False,
                capture_output=True,
                text=True,
                cwd=REPO_ROOT,
                env=env,
            )
            self.assertEqual(result.returncode, 1)
            self.assertIn(
                "client proof exceeded the bounded verification windows",
                result.stdout,
            )
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
