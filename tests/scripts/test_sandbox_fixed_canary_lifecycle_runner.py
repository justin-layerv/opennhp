from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / ".github/scripts"
sys.path.insert(0, str(SCRIPTS))
SPEC = importlib.util.spec_from_file_location(
    "sandbox_fixed_canary_lifecycle_runner",
    SCRIPTS / "sandbox_fixed_canary_lifecycle_runner.py",
)
assert SPEC and SPEC.loader
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)


def build_lifecycle_fixture(directory: Path, payload_path: Path, marker: Path | None = None) -> Path:
    if shutil.which("go") is None:
        raise unittest.SkipTest("Go is required to build the exact ELF lifecycle fixture")
    source = directory / "lifecycle-fixture.go"
    marker_statement = ""
    if marker is not None:
        marker_statement = f"if err := os.WriteFile({json.dumps(str(marker))}, []byte(\"reviewed\"), 0o600); err != nil {{ panic(err) }}"
    source.write_text(
        "package main\nimport \"os\"\nfunc main() {\n"
        f"{marker_statement}\n"
        "for index := 1; index+1 < len(os.Args); index++ {\n"
        "if os.Args[index] != \"--report-file\" { continue }\n"
        f"raw, err := os.ReadFile({json.dumps(str(payload_path))}); if err != nil {{ panic(err) }}\n"
        "if err := os.WriteFile(os.Args[index+1], raw, 0o600); err != nil { panic(err) }; return\n"
        "}\nos.Exit(2)\n}\n"
    )
    command = directory / "lifecycle"
    subprocess.run(["go", "build", "-o", str(command), str(source)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    command.chmod(0o500)
    return command


def input_value(operation: str = "lifecycle") -> dict:
    value = {
        "schema": 1,
        "environment": "sandbox",
        "operation": operation,
        "release_id": "a" * 64,
        "phase": "fixed_shared_direct",
        "attempt": 1,
        "transport": "direct",
        "authority": {"key": "authority", "version_id": "b" * 64, "sha256": "c" * 64},
        "admission_hub": {"host": "green-candidate.example", "port": 443, "server_public_key_b64": "A" * 44},
        "admission_cell_endpoint": {"host": "green-ac-candidate.example", "port": 443, "server_public_key_b64": "A" * 44},
        "recovery_endpoint": {"host": "green-recovery.example", "port": 443, "server_public_key_b64": "A" * 44},
        "run_ids": ["0123456789abcdef", "1123456789abcdef", "2123456789abcdef"],
        "prepared_at_ms": 1_800_000_000_000,
        "expires_at_ms": 1_800_001_200_000,
        "api_endpoint": "https://api.layerv.xyz",
        "api_key_file": "/private/api-key",
        "deployment_file": "/private/deployment.json",
        "deployment_sha256": "e" * 64,
        "relay_hostname": "relay.qurl.link.layerv.xyz",
        "lifecycle_command_sha256": "f" * 64,
        "qurl_binary": "/private/qurl",
        "qurl_binary_sha256": "d" * 64,
        "qurl_source_sha": "1" * 40,
        "qurl_go_source_sha": "2" * 40,
        "client_version": "sandbox-test",
    }
    if operation == RUNNER.RECOVERY_OPERATION:
        value["phase"] = "fixed_shared_recovery_first"
        value["run_ids"] = ["0123456789abcdef"]
    return value


def report(value: dict) -> tuple[dict, bytes]:
    raw = json.dumps(value, separators=(",", ":")).encode() + b"\n"
    common = {
        "schema": 1,
        "environment": value["environment"],
        "operation": value["operation"],
        "release_id": value["release_id"],
        "phase": value["phase"],
        "attempt": value["attempt"],
        "transport": value["transport"],
        "input_sha256": hashlib.sha256(raw).hexdigest(),
        "authority": value["authority"],
        "state_updates": [
            {
                "label": label,
                "before": {"key": f"state-{label}", "version_id": str(index + 1) * 64, "sha256": str(index + 2) * 64},
                "after": {"key": f"state-{label}", "version_id": str(index + 3) * 64, "sha256": str(index + 4) * 64},
            }
            for index, label in enumerate(["direct-a", "direct-b"] if value["operation"] == "lifecycle" else [])
        ],
        "lifecycle_command_sha256": value["lifecycle_command_sha256"],
        "qurl_binary_sha256": value["qurl_binary_sha256"],
        "qurl_source_sha": value["qurl_source_sha"],
        "qurl_go_source_sha": value["qurl_go_source_sha"],
    }
    if value["operation"] == "lifecycle":
        common["lifecycle"] = {
            "status": "completed",
            "intent": {"key": "intent", "version_id": "e" * 64, "sha256": "f" * 64},
            "primary_first_key": "first",
            "sibling_key": "sibling",
            "replacement_key": "replacement",
            "outcome": {
                "transport": value["transport"],
                "primary_first_run_id": value["run_ids"][0],
                "sibling_run_id": value["run_ids"][1],
                "primary_replacement_run_id": value["run_ids"][2],
                "primary_exact_retirement": True,
                "get_both_before_retire": True,
                "sibling_continued": True,
                "replacement_ready": True,
                "get_both_after_replacement": True,
                "replacement_exact_retirement": True,
                "sibling_exact_retirement": True,
            },
        }
    elif value["operation"] == RUNNER.RECOVERY_OPERATION:
        common["recovery"] = {
            "status": "completed",
            "label": "direct-a",
            "receipt": {
                "operation_key": "operation/one",
                "record": {"key": "operation/one", "version_id": "e" * 64, "sha256": "f" * 64},
                "operation_id": "1" * 64,
                "binding_sha256": "2" * 64,
                "terminal": {"state": "CANCELED", "was_admitted": False},
            },
        }
    return common, raw


def source_authority(value: dict, command: Path) -> dict:
    module = "v0.8.1-0.20260824120000-c92478b3f70f"
    binary = lambda path, sha: {  # noqa: E731 - Compact exact fixture projection.
        "path": path,
        "sha256": sha,
        "main_module": "github.com/layervai/qurl-integrations",
        "main_version": "(devel)",
        "qurl_go_module_version": module,
    }
    return {
        "schema": 1,
        "environment": "sandbox",
        "operation": "qurl-customer-journey",
        "correlation_id": "qurl-1-1-aaaaaaaaaaaa",
        "request_sha256": "a" * 64,
        "caller": {
            "repository": "layervai/qurl-integrations",
            "workflow": ".github/workflows/cli.yml",
            "head_sha": value["qurl_source_sha"],
            "run_id": 1,
            "run_attempt": 1,
        },
        "sources": {
            "nhp": "e" * 40,
            "qurl_integrations_head": value["qurl_source_sha"],
            "qurl_go": value["qurl_go_source_sha"],
            "qurl_infra": "3" * 40,
            "qurl_infra_helper_sha256": "4" * 64,
        },
        "artifacts": {
            "binary": {"name": "binary", "digest": "sha256:" + "b" * 64},
            "source_receipt": {"name": "source", "digest": "sha256:" + "c" * 64, "sha256": "d" * 64},
        },
        "binaries": {
            "authority": binary("/private/authority", "a" * 64),
            "lifecycle": binary(str(command), value["lifecycle_command_sha256"]),
            "qurl": binary(value["qurl_binary"], value["qurl_binary_sha256"]),
        },
    }


def write_source_authority(path: Path, value: dict, command: Path) -> None:
    path.write_bytes(json.dumps(source_authority(value, command), sort_keys=True, separators=(",", ":")).encode() + b"\n")
    path.chmod(0o600)


class SandboxMatchedCohortLifecycleRunnerTest(unittest.TestCase):
    def test_lifecycle_command_digest_rejects_mutable_and_linked_executables(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            command = directory / "lifecycle"
            body = b"#!/bin/sh\nexit 0\n"
            command.write_bytes(body)
            command.chmod(0o500)
            self.assertEqual(RUNNER._stable_executable_sha256(str(command)), hashlib.sha256(body).hexdigest())

            command.chmod(0o700)
            with self.assertRaises(RUNNER.RunnerError):
                RUNNER._stable_executable_sha256(str(command))
            command.chmod(0o500)

            hard_link = directory / "hard-link"
            os.link(command, hard_link)
            with self.assertRaises(RUNNER.RunnerError):
                RUNNER._stable_executable_sha256(str(command))
            hard_link.unlink()

            symbolic_link = directory / "symbolic-link"
            symbolic_link.symlink_to(command)
            with self.assertRaises(RUNNER.RunnerError):
                RUNNER._stable_executable_sha256(str(symbolic_link))

    @unittest.skipUnless(sys.platform.startswith("linux"), "exact descriptor execution requires Linux")
    def test_launches_only_digest_bound_command_and_validates_report(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            directory.chmod(0o700)
            payload_path = directory / "child-report-payload"
            command = build_lifecycle_fixture(directory, payload_path)
            value = input_value()
            value["lifecycle_command_sha256"] = RUNNER._stable_executable_sha256(str(command))
            receipt, raw = report(value)
            payload_path.write_bytes(json.dumps(receipt, separators=(",", ":")).encode() + b"\n")
            payload_path.chmod(0o400)
            input_path = directory / "input.json"
            input_path.write_bytes(raw)
            input_path.chmod(0o600)
            report_path = directory / "report.json"
            source_path = directory / "source-authority.json"
            write_source_authority(source_path, value, command)
            RUNNER.run(str(command), str(directory / "authority.sock"), str(input_path), str(source_path), str(report_path))
            wrong = copy.deepcopy(value)
            wrong["api_endpoint"] = "https://api.layerv.ai"
            wrong_path = directory / "wrong-input.json"
            wrong_path.write_bytes(json.dumps(wrong, separators=(",", ":")).encode() + b"\n")
            wrong_path.chmod(0o600)
            with self.assertRaises(RUNNER.RunnerError):
                RUNNER.run(str(command), str(directory / "authority.sock"), str(wrong_path), str(source_path), str(directory / "wrong-report.json"))

    @unittest.skipUnless(sys.platform.startswith("linux"), "exact descriptor execution requires Linux")
    def test_path_swap_after_hash_executes_only_opened_inode_and_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            directory.chmod(0o700)
            reviewed_path = directory / "reviewed-lifecycle"
            payload_path = directory / "child-report-payload"
            marker = directory / "executed"
            command = build_lifecycle_fixture(directory, payload_path, marker)
            value = input_value()
            value["lifecycle_command_sha256"] = RUNNER._stable_executable_sha256(str(command))
            receipt, raw = report(value)
            payload_path.write_bytes(json.dumps(receipt, separators=(",", ":")).encode() + b"\n")
            payload_path.chmod(0o400)
            input_path = directory / "input.json"
            input_path.write_bytes(raw)
            input_path.chmod(0o600)
            source_path = directory / "source-authority.json"
            write_source_authority(source_path, value, command)
            real_run = subprocess.run
            swapped = False

            def swap_then_run(*args: object, **kwargs: object) -> subprocess.CompletedProcess:
                nonlocal swapped
                if not swapped:
                    swapped = True
                    command.rename(reviewed_path)
                    shutil.copyfile("/bin/false", command)
                    command.chmod(0o500)
                return real_run(*args, **kwargs)  # type: ignore[arg-type]

            with (
                mock.patch.object(RUNNER.subprocess, "run", side_effect=swap_then_run),
                self.assertRaisesRegex(RUNNER.RunnerError, "path changed during execution"),
            ):
                RUNNER.run(
                    str(command),
                    str(directory / "authority.sock"),
                    str(input_path),
                    str(source_path),
                    str(directory / "report.json"),
                )
            self.assertEqual(marker.read_text(), "reviewed")

    def test_launch_binds_exact_reviewed_cross_repo_sources(self) -> None:
        value = input_value()
        command = Path("/private/lifecycle")
        authority = source_authority(value, command)
        RUNNER._validate_source_authority(authority, value, str(command), value["lifecycle_command_sha256"])
        for key, replacement in (
            ("qurl_go_source_sha", "3" * 40),
            ("qurl_source_sha", "4" * 40),
        ):
            changed = copy.deepcopy(value)
            changed[key] = replacement
            with self.assertRaisesRegex(RUNNER.RunnerError, "source authority"):
                RUNNER._validate_source_authority(
                    authority,
                    changed,
                    str(command),
                    value["lifecycle_command_sha256"],
                )

    def test_lifecycle_report_requires_every_customer_outcome_and_run_id(self) -> None:
        value = input_value()
        receipt, raw = report(value)
        RUNNER.validate_report(receipt, value, raw)
        mutations = []
        changed = copy.deepcopy(receipt)
        changed["lifecycle"]["outcome"]["sibling_continued"] = False
        mutations.append(changed)
        changed = copy.deepcopy(receipt)
        changed["lifecycle"]["outcome"]["primary_first_run_id"] = "f" * 16
        mutations.append(changed)
        changed = copy.deepcopy(receipt)
        changed["lifecycle"]["outcome"]["extra"] = True
        mutations.append(changed)
        changed = copy.deepcopy(receipt)
        changed["input_sha256"] = "0" * 64
        mutations.append(changed)
        changed = copy.deepcopy(receipt)
        changed["lifecycle_command_sha256"] = "0" * 64
        mutations.append(changed)
        changed = copy.deepcopy(receipt)
        changed["state_updates"][0]["after"]["version_id"] = changed["state_updates"][0]["before"]["version_id"]
        mutations.append(changed)
        changed = copy.deepcopy(receipt)
        changed["state_updates"].reverse()
        mutations.append(changed)
        for index, changed in enumerate(mutations):
            with self.subTest(index=index), self.assertRaises(RUNNER.RunnerError):
                RUNNER.validate_report(changed, value, raw)

    def test_recovery_first_report_requires_retained_canceled_receipt(self) -> None:
        value = input_value(RUNNER.RECOVERY_OPERATION)
        receipt, raw = report(value)
        RUNNER.validate_report(receipt, value, raw)
        mutations = []
        changed = copy.deepcopy(receipt)
        changed["recovery"]["receipt"]["terminal"]["state"] = "CLOSED"
        mutations.append(changed)
        changed = copy.deepcopy(receipt)
        changed["recovery"]["receipt"]["terminal"]["was_admitted"] = True
        mutations.append(changed)
        changed = copy.deepcopy(receipt)
        changed["recovery"]["receipt"]["record"]["key"] = "other"
        mutations.append(changed)
        changed = copy.deepcopy(receipt)
        changed["recovery"]["receipt"]["binding_sha256"] = "bad"
        mutations.append(changed)
        changed = copy.deepcopy(receipt)
        changed["state_updates"] = [{"extra": True}]
        mutations.append(changed)
        for index, changed in enumerate(mutations):
            with self.subTest(index=index), self.assertRaises(RUNNER.RunnerError):
                RUNNER.validate_report(changed, value, raw)

    def test_recovery_first_input_phase_transport_and_run_set_are_exact(self) -> None:
        value = input_value(RUNNER.RECOVERY_OPERATION)
        for field, replacement in (
            ("phase", "candidate_green_direct"),
            ("transport", "relay"),
            ("run_ids", ["0123456789abcdef", "1123456789abcdef"]),
            ("color", "green"),
        ):
            changed = copy.deepcopy(value)
            changed[field] = replacement
            with self.subTest(field=field), self.assertRaisesRegex(RUNNER.RunnerError, "(?:recovery-first|lifecycle input)"):
                with mock.patch.object(RUNNER, "_load_private", return_value=(changed, b"{}\n")):
                    RUNNER.run("/missing", "/private/socket", "/private/input", "/private/source", "/private/report")

    def test_interrupted_lifecycle_requires_terminal_settlement_before_retry(self) -> None:
        value = input_value()
        receipt, raw = report(value)
        lifecycle = receipt["lifecycle"]
        keys = [lifecycle["primary_first_key"], lifecycle["sibling_key"], lifecycle["replacement_key"]]
        receipt["lifecycle"] = {
            "status": "settled-retry-required",
            "intent": lifecycle["intent"],
            "primary_first_key": keys[0],
            "sibling_key": keys[1],
            "replacement_key": keys[2],
            "settlement": {
                "attempt": 1,
                "operation_keys": keys,
                "terminal_states": ["CLOSED", "CANCELED", "CANCELED"],
                "retry_required": True,
            },
        }
        RUNNER.validate_report(receipt, value, raw)
        for mutation in (
            lambda item: item["lifecycle"]["settlement"].update(attempt=2),
            lambda item: item["lifecycle"]["settlement"]["terminal_states"].__setitem__(0, "CLOSING"),
            lambda item: item["lifecycle"]["settlement"].update(retry_required=False),
            lambda item: item["lifecycle"]["settlement"]["operation_keys"].pop(),
        ):
            changed = copy.deepcopy(receipt)
            mutation(changed)
            with self.assertRaises(RUNNER.RunnerError):
                RUNNER.validate_report(changed, value, raw)


if __name__ == "__main__":
    unittest.main()
