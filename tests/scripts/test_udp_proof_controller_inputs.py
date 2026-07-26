#!/usr/bin/env python3

from __future__ import annotations

import base64
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
        "cells": [
            {
                "cell_id": "cell0",
                "host": "cell0.sandbox.nhp.layerv.xyz",
                "port": 62206,
                "server_public_key_sha256": "1" * 64,
            },
            {
                "cell_id": "cell1",
                "host": "cell1.sandbox.nhp.layerv.xyz",
                "port": 62206,
                "server_public_key_sha256": "2" * 64,
            },
        ],
        "connector_modules": {"frp": SHA["frp"], "qurl_go": SHA["qurl_go"]},
        "hub": {
            "host": "hub.sandbox.nhp.layerv.xyz",
            "port": 62206,
            "server_public_key_sha256": "3" * 64,
        },
        "images": {
            "nhp_cell0": "sha256:" + "1" * 64,
            "nhp_cell1": "sha256:" + "2" * 64,
            "nhp_hub": "sha256:" + "3" * 64,
            "qurl_connector": "sha256:" + "4" * 64,
            "qurl_reverse_tunnel_server": "sha256:" + "5" * 64,
            "qurl_service_authority": "sha256:" + "6" * 64,
            "qurl_service_cell0": "sha256:" + "7" * 64,
            "qurl_service_cell1": "sha256:" + "8" * 64,
        },
        "phase": phase,
        "repositories": dict(SHA),
        "retirement_state": (
            "http_lifecycle_present"
            if phase == "pre_removal"
            else "http_lifecycle_removed"
        ),
        "schema_version": 1,
    }


def encode_manifest(manifest: dict[str, object]) -> str:
    canonical = json.dumps(
        manifest,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return base64.b64encode(canonical).decode("ascii")


class ValidatorTest(unittest.TestCase):
    def call_validator(self, **overrides: str) -> dict[str, str]:
        values = {
            "client": "connector",
            "proof_phase": "pre_removal",
            "deployment_manifest_b64": encode_manifest(valid_manifest()),
            "connector_ref": "justin/fix/connector-routing-identity",
            "qurl_go_ref": "justin/feat/udp-credential-recovery",
            "connector_proof_run_id": "",
            "pre_removal_run_id": "",
        }
        values.update(overrides)
        return validator.validate_inputs(**values)

    def test_accepts_canonical_pre_removal_connector_manifest(self) -> None:
        outputs = self.call_validator()
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

    def test_accepts_post_removal_qurl_go_linkage(self) -> None:
        outputs = self.call_validator(
            client="qurl_go",
            proof_phase="post_removal",
            deployment_manifest_b64=encode_manifest(valid_manifest("post_removal")),
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
            self.call_validator(client="qurl_go")
        with self.assertRaisesRegex(validator.ValidationError, "must be empty"):
            self.call_validator(connector_proof_run_id="123")
        with self.assertRaisesRegex(validator.ValidationError, "pre-removal run ID"):
            self.call_validator(
                proof_phase="post_removal",
                deployment_manifest_b64=encode_manifest(valid_manifest("post_removal")),
            )
        with self.assertRaisesRegex(validator.ValidationError, "must be empty"):
            self.call_validator(pre_removal_run_id="123")

    def test_rejects_noncanonical_and_duplicate_json(self) -> None:
        noncanonical = base64.b64encode(json.dumps(valid_manifest()).encode()).decode()
        with self.assertRaisesRegex(validator.ValidationError, "canonical JSON"):
            self.call_validator(deployment_manifest_b64=noncanonical)

        canonical = base64.b64decode(encode_manifest(valid_manifest())).decode()
        duplicate = canonical[:-1] + ',"schema_version":1}'
        with self.assertRaisesRegex(validator.ValidationError, "duplicate key"):
            self.call_validator(
                deployment_manifest_b64=base64.b64encode(duplicate.encode()).decode()
            )

    def test_rejects_manifest_larger_than_dispatch_transport_budget(self) -> None:
        oversized = base64.b64encode(
            b"x" * (validator.MAX_MANIFEST_BYTES + 1)
        ).decode()
        with self.assertRaisesRegex(validator.ValidationError, "1..32768 bytes"):
            self.call_validator(deployment_manifest_b64=oversized)

    def test_rejects_numeric_overflow_without_a_traceback(self) -> None:
        canonical = base64.b64decode(encode_manifest(valid_manifest())).decode()
        overflow = canonical.replace('"schema_version":1', '"schema_version":1e400')
        with self.assertRaisesRegex(
            validator.ValidationError, "numbers must be finite"
        ):
            self.call_validator(
                deployment_manifest_b64=base64.b64encode(overflow.encode()).decode()
            )

    def test_rejects_manifest_phase_sha_and_topology_drift(self) -> None:
        with self.assertRaisesRegex(validator.ValidationError, "phase"):
            self.call_validator(
                proof_phase="post_removal",
                deployment_manifest_b64=encode_manifest(valid_manifest()),
                pre_removal_run_id="123",
            )

        bad_sha = valid_manifest()
        bad_sha["repositories"]["qurl_go"] = "not-a-sha"  # type: ignore[index]
        with self.assertRaisesRegex(validator.ValidationError, "commit SHAs"):
            self.call_validator(deployment_manifest_b64=encode_manifest(bad_sha))

        duplicate_cell = valid_manifest()
        duplicate_cell["cells"][1]["host"] = duplicate_cell["cells"][0]["host"]  # type: ignore[index]
        with self.assertRaisesRegex(validator.ValidationError, "unique host"):
            self.call_validator(deployment_manifest_b64=encode_manifest(duplicate_cell))

        boolean_schema = valid_manifest()
        boolean_schema["schema_version"] = True
        with self.assertRaisesRegex(validator.ValidationError, "schema_version"):
            self.call_validator(deployment_manifest_b64=encode_manifest(boolean_schema))

        boolean_port = valid_manifest()
        boolean_port["hub"]["port"] = True  # type: ignore[index]
        with self.assertRaisesRegex(validator.ValidationError, "UDP 62206"):
            self.call_validator(deployment_manifest_b64=encode_manifest(boolean_port))

    def test_rejects_missing_extra_or_misnamed_sandbox_cells(self) -> None:
        missing = valid_manifest()
        missing["cells"] = missing["cells"][:1]  # type: ignore[index]
        with self.assertRaisesRegex(validator.ValidationError, "exactly the two"):
            self.call_validator(deployment_manifest_b64=encode_manifest(missing))

        extra = valid_manifest()
        extra["cells"].append(  # type: ignore[union-attr]
            {
                "cell_id": "cell2",
                "host": "cell2.sandbox.nhp.layerv.xyz",
                "port": 62206,
                "server_public_key_sha256": "4" * 64,
            }
        )
        with self.assertRaisesRegex(validator.ValidationError, "exactly the two"):
            self.call_validator(deployment_manifest_b64=encode_manifest(extra))

        misnamed = valid_manifest()
        misnamed["cells"][1]["cell_id"] = "cell2"  # type: ignore[index]
        with self.assertRaisesRegex(
            validator.ValidationError, "exactly cell0 and cell1"
        ):
            self.call_validator(deployment_manifest_b64=encode_manifest(misnamed))

    def test_rejects_sha_or_shell_syntax_as_dispatch_ref(self) -> None:
        with self.assertRaisesRegex(validator.ValidationError, "branch name"):
            self.call_validator(connector_ref=SHA["qurl_connector"])
        with self.assertRaisesRegex(validator.ValidationError, "safe Git branch"):
            self.call_validator(qurl_go_ref="candidate;echo-owned")

    def test_cli_writes_only_validated_dispatch_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "github-output"
            env = os.environ.copy()
            env["DEPLOYMENT_MANIFEST_B64"] = encode_manifest(valid_manifest())
            subprocess.run(
                [
                    "python3",
                    str(VALIDATOR_PATH),
                    "--client",
                    "connector",
                    "--proof-phase",
                    "pre_removal",
                    "--connector-ref",
                    "justin/fix/connector-routing-identity",
                    "--qurl-go-ref",
                    "justin/feat/udp-credential-recovery",
                    "--github-output",
                    str(output),
                ],
                check=True,
                cwd=REPO_ROOT,
                env=env,
            )
            self.assertEqual(
                dict(line.split("=", 1) for line in output.read_text().splitlines()),
                {
                    "connector_workflow_identity": (
                        "layervai/qurl-connector/.github/workflows/"
                        f"sandbox-smoke.yml@{SHA['qurl_connector']}"
                    ),
                    "qurl_go_workflow_identity": (
                        "layervai/qurl-go/.github/workflows/"
                        f"native-udp-sandbox.yml@{SHA['qurl_go']}"
                    ),
                    "client_repository": "layervai/qurl-connector",
                    "client_workflow": "sandbox-smoke.yml",
                    "client_ref": "justin/fix/connector-routing-identity",
                    "client_sha": SHA["qurl_connector"],
                },
            )


class WorkflowContractTest(unittest.TestCase):
    def test_controller_dispatch_is_exact_and_single_client_per_run(self) -> None:
        workflow = (
            REPO_ROOT / ".github" / "workflows" / "udp-proof-controller.yml"
        ).read_text()
        for required in (
            "client:",
            "proof_phase:",
            "deployment_manifest_b64:",
            "connector_ref:",
            "qurl_go_ref:",
            "connector_proof_run_id:",
            "pre_removal_run_id:",
            "validate_udp_proof_controller_inputs.py",
            "invoke_udp_proof_broker.sh",
            "wait_for_action_run.sh",
            "permission-actions: write",
            "permission-organization-self-hosted-runners: write",
            "retry_gh_api()",
            "could not read runner-group controls after bounded retries",
            "could not read runner-group repositories after bounded retries",
            '-f "proof_phase=$PROOF_PHASE"',
            '-f "deployment_manifest_b64=$DEPLOYMENT_MANIFEST_B64"',
            '-f "pre_removal_run_id=$PRE_REMOVAL_RUN_ID"',
            '-f "connector_proof_run_id=$CONNECTOR_PROOF_RUN_ID"',
            '-f "dispatch_correlation_id=$correlation_id"',
            '--branch "$CLIENT_REF"',
            "--limit 100",
            "client_run_title=$expected_title",
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
        ):
            self.assertIn(required, workflow)
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
