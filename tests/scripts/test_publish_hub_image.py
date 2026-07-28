#!/usr/bin/env python3
"""Contract tests for the dark Connector Hub image publication carrier."""

from __future__ import annotations

import argparse
import datetime as dt
import importlib.util
import json
import stat
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / ".github/scripts/publish-hub-image.py"
WORKFLOW = ROOT / ".github/workflows/publish-hub-image.yml"
PUBLISHER_TF = ROOT / "terraform/modules/connector-authority-foundation/publisher.tf"
OUTPUTS_TF = ROOT / "terraform/modules/connector-authority-foundation/outputs.tf"
BUILD_WORKFLOW = ROOT / ".github/workflows/build-and-push.yml"

SPEC = importlib.util.spec_from_file_location("hub_publisher", SCRIPT)
assert SPEC and SPEC.loader
PUBLISHER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = PUBLISHER
SPEC.loader.exec_module(PUBLISHER)

SHA = "a" * 40
CONFIG_DIGEST = "sha256:" + "b" * 64


def invocation(**overrides: object) -> argparse.Namespace:
    values: dict[str, object] = {
        "repository": PUBLISHER.REPOSITORY,
        "target_environment": "sandbox",
        "publication_environment": "hub-publish-sandbox",
        "source_ref": "refs/heads/main",
        "source_sha": SHA,
        "source_commit_time": "2026-07-23 12:34:56",
        "workflow_ref": PUBLISHER.WORKFLOW_REF,
        "run_id": "123",
        "run_attempt": "2",
        "local_image": f"local/{PUBLISHER.ECR_REPOSITORY}:{SHA}",
        "provenance_file": Path("/tmp/provenance.json"),
    }
    values.update(overrides)
    return argparse.Namespace(**values)


def manifest_fixture() -> tuple[str, str]:
    manifest = json.dumps(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": CONFIG_DIGEST,
                "size": 123,
            },
            "layers": [],
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    digest = "sha256:" + __import__("hashlib").sha256(manifest.encode()).hexdigest()
    return manifest, digest


def inspect_fixture(repo_digests: list[str] | None = None, **overrides: object) -> str:
    image: dict[str, object] = {
        "Id": CONFIG_DIGEST,
        "Architecture": "amd64",
        "Os": "linux",
        "Config": {
            "Labels": {
                "org.opencontainers.image.revision": SHA,
                "org.opencontainers.image.source": PUBLISHER.SOURCE_URL,
            }
        },
        "RepoDigests": repo_digests
        if repo_digests is not None
        else [
            "767397897469.dkr.ecr.us-east-2.amazonaws.com/"
            + PUBLISHER.ECR_REPOSITORY
            + "@sha256:"
            + "c" * 64
        ],
    }
    image.update(overrides)
    return json.dumps([image])


class StubRunner:
    def __init__(
        self,
        *,
        aws_outputs: list[str] | None = None,
        run_outputs: list[str] | None = None,
    ):
        self.aws_outputs = list(aws_outputs or [])
        self.run_outputs = list(run_outputs or [])
        self.aws_calls: list[tuple[str, ...]] = []
        self.run_calls: list[tuple[str, ...]] = []

    def aws(self, *arguments: str) -> str:
        self.aws_calls.append(arguments)
        if not self.aws_outputs:
            raise AssertionError(f"unexpected aws call: {arguments}")
        return self.aws_outputs.pop(0)

    def run(self, command: tuple[str, ...], *, input_text: str | None = None) -> str:
        del input_text
        self.run_calls.append(tuple(command))
        if not self.run_outputs:
            raise AssertionError(f"unexpected command: {command}")
        return self.run_outputs.pop(0)


class InvocationContractTests(unittest.TestCase):
    def test_exact_environment_contracts(self) -> None:
        sandbox = PUBLISHER.validate_invocation(invocation())
        production = PUBLISHER.validate_invocation(
            invocation(
                target_environment="production",
                publication_environment="hub-publish-production",
            )
        )
        self.assertEqual(sandbox.account_id, "767397897469")
        self.assertEqual(
            sandbox.role_arn,
            "arn:aws:iam::767397897469:role/layerv-nhp-sandbox-control-hub-publisher",
        )
        self.assertEqual(
            sandbox.parameter_name, "/sandbox/nhp/control/hub/image-digest"
        )
        self.assertEqual(production.account_id, "235500187906")
        self.assertEqual(
            production.role_arn,
            "arn:aws:iam::235500187906:role/layerv-nhp-prod-control-hub-publisher",
        )
        self.assertEqual(
            production.parameter_name, "/prod/nhp/control/hub/image-digest"
        )

    def test_repository_ref_workflow_sha_image_and_environment_fail_closed(
        self,
    ) -> None:
        cases = {
            "repository": {"repository": "fork/nhp"},
            "ref": {"source_ref": "refs/heads/feature"},
            "workflow": {
                "workflow_ref": PUBLISHER.WORKFLOW_REF.replace("main", "feature")
            },
            "uppercase-sha": {"source_sha": "A" * 40},
            "short-sha": {"source_sha": "a" * 39},
            "image": {"local_image": f"local/{PUBLISHER.ECR_REPOSITORY}:latest"},
            "shared-environment": {"publication_environment": "sandbox"},
            "cross-environment": {"publication_environment": "hub-publish-production"},
            "commit-time": {"source_commit_time": "2026-07-23T12:34:56Z"},
            "run-id": {"run_id": "0"},
        }
        for label, overrides in cases.items():
            with self.subTest(label=label), self.assertRaises(PUBLISHER.ContractError):
                PUBLISHER.validate_invocation(invocation(**overrides))


class ImageContractTests(unittest.TestCase):
    def test_exact_local_and_remote_image_contracts_pass(self) -> None:
        runner = StubRunner(run_outputs=[inspect_fixture()])
        result = PUBLISHER.inspect_image(runner, "local/image", SHA)
        self.assertEqual(result["config_digest"], CONFIG_DIGEST)
        digest_ref = json.loads(inspect_fixture())[0]["RepoDigests"][0]
        runner = StubRunner(run_outputs=[inspect_fixture()])
        PUBLISHER.inspect_image(
            runner,
            digest_ref,
            SHA,
            expected_repo_digest=digest_ref,
        )

    def test_containerd_store_descriptor_selects_config_digest(self) -> None:
        manifest_digest = "sha256:" + "e" * 64
        raw = inspect_fixture(
            Id=manifest_digest,
            Descriptor={
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": manifest_digest,
                "annotations": {"config.digest": CONFIG_DIGEST},
            },
        )
        result = PUBLISHER.inspect_image(StubRunner(run_outputs=[raw]), "image", SHA)
        self.assertEqual(result["config_digest"], CONFIG_DIGEST)

    def test_architecture_labels_and_repo_digest_fail_closed(self) -> None:
        cases = (
            inspect_fixture(Architecture="arm64"),
            inspect_fixture(Os="windows"),
            inspect_fixture(
                Config={
                    "Labels": {
                        "org.opencontainers.image.revision": "d" * 40,
                        "org.opencontainers.image.source": PUBLISHER.SOURCE_URL,
                    }
                }
            ),
            inspect_fixture(RepoDigests=[]),
            inspect_fixture(
                Id="sha256:" + "e" * 64,
                Descriptor={
                    "mediaType": "application/vnd.oci.image.index.v1+json",
                    "digest": "sha256:" + "e" * 64,
                    "annotations": {"config.digest": CONFIG_DIGEST},
                },
            ),
        )
        for raw in cases:
            with self.subTest(raw=raw), self.assertRaises(PUBLISHER.ContractError):
                PUBLISHER.inspect_image(
                    StubRunner(run_outputs=[raw]),
                    "image",
                    SHA,
                    expected_repo_digest="repo@sha256:" + "c" * 64,
                )

    def test_ecr_manifest_bytes_bind_digest_and_config(self) -> None:
        manifest, digest = manifest_fixture()
        response = json.dumps(
            {
                "images": [
                    {
                        "imageId": {"imageTag": SHA, "imageDigest": digest},
                        "imageManifest": manifest,
                    }
                ],
                "failures": [],
            }
        )
        parsed, actual = PUBLISHER.batch_get_image(
            StubRunner(aws_outputs=[response]), SHA
        )
        self.assertEqual(actual, digest)
        self.assertEqual(parsed["config"]["digest"], CONFIG_DIGEST)

        tampered = json.loads(response)
        tampered["images"][0]["imageId"]["imageDigest"] = "sha256:" + "d" * 64
        with self.assertRaises(PUBLISHER.ContractError):
            PUBLISHER.batch_get_image(
                StubRunner(aws_outputs=[json.dumps(tampered)]), SHA
            )

    def test_missing_image_requires_exact_image_not_found(self) -> None:
        missing = {
            "images": [],
            "failures": [
                {
                    "imageId": {"imageTag": SHA},
                    "failureCode": "ImageNotFound",
                }
            ],
        }
        self.assertEqual(
            PUBLISHER.batch_get_image(
                StubRunner(aws_outputs=[json.dumps(missing)]), SHA
            ),
            (None, None),
        )
        missing["failures"][0]["failureCode"] = "MissingDigestAndTag"
        with self.assertRaises(PUBLISHER.ContractError):
            PUBLISHER.batch_get_image(
                StubRunner(aws_outputs=[json.dumps(missing)]), SHA
            )

    def test_existing_matching_image_is_reused_without_push(self) -> None:
        manifest, digest = manifest_fixture()
        found = json.dumps(
            {
                "images": [
                    {
                        "imageId": {"imageTag": SHA, "imageDigest": digest},
                        "imageManifest": manifest,
                    }
                ],
                "failures": [],
            }
        )
        described = json.dumps(
            {
                "imageDetails": [
                    {"imageDigest": digest, "imageTags": [SHA]},
                ]
            }
        )
        runner = StubRunner(aws_outputs=[found, found, described])

        actual, pushed = PUBLISHER.publish_or_reuse(
            runner,
            PUBLISHER.TARGETS["sandbox"],
            SHA,
            f"local/{PUBLISHER.ECR_REPOSITORY}:{SHA}",
            CONFIG_DIGEST,
        )

        self.assertEqual(actual, digest)
        self.assertFalse(pushed)
        self.assertEqual(runner.run_calls, [])

    def test_existing_source_sha_with_different_config_fails_before_push(self) -> None:
        manifest, digest = manifest_fixture()
        parsed = json.loads(manifest)
        parsed["config"]["digest"] = "sha256:" + "d" * 64
        manifest = json.dumps(parsed, sort_keys=True, separators=(",", ":"))
        digest = "sha256:" + __import__("hashlib").sha256(manifest.encode()).hexdigest()
        found = json.dumps(
            {
                "images": [
                    {
                        "imageId": {"imageTag": SHA, "imageDigest": digest},
                        "imageManifest": manifest,
                    }
                ],
                "failures": [],
            }
        )
        runner = StubRunner(aws_outputs=[found])

        with self.assertRaises(PUBLISHER.ContractError):
            PUBLISHER.publish_or_reuse(
                runner,
                PUBLISHER.TARGETS["sandbox"],
                SHA,
                f"local/{PUBLISHER.ECR_REPOSITORY}:{SHA}",
                CONFIG_DIGEST,
            )
        self.assertEqual(runner.run_calls, [])


class ScanAndPinContractTests(unittest.TestCase):
    def scan(
        self,
        status: str,
        counts: object,
        *,
        completed: bool = True,
        account_id: str = "767397897469",
        repository: str = PUBLISHER.ECR_REPOSITORY,
        digest: str = "sha256:" + "c" * 64,
    ) -> str:
        findings: dict[str, object] = {"findingSeverityCounts": counts}
        if completed:
            findings.update(
                {
                    "imageScanCompletedAt": "2026-07-23T12:34:56+00:00",
                    "vulnerabilitySourceUpdatedAt": "2026-07-23T12:00:00Z",
                }
            )
        return json.dumps(
            {
                "registryId": account_id,
                "repositoryName": repository,
                "imageId": {"imageDigest": digest},
                "imageScanStatus": {"status": status},
                "imageScanFindings": findings,
            }
        )

    def test_scan_waits_and_requires_zero_high_and_critical(self) -> None:
        runner = StubRunner(
            aws_outputs=[
                self.scan("IN_PROGRESS", {}),
                self.scan("COMPLETE", {"LOW": 3, "HIGH": 0}),
            ]
        )
        evidence = PUBLISHER.wait_for_scan(
            runner,
            PUBLISHER.TARGETS["sandbox"],
            "sha256:" + "c" * 64,
            attempts=2,
            poll_seconds=0,
        )
        self.assertEqual(evidence.status, "COMPLETE")
        self.assertEqual(evidence.finding_severity_counts, {"HIGH": 0, "LOW": 3})
        self.assertEqual(evidence.completed_at, "2026-07-23T12:34:56Z")
        active = PUBLISHER.wait_for_scan(
            StubRunner(aws_outputs=[self.scan("ACTIVE", {"CRITICAL": 0})]),
            PUBLISHER.TARGETS["sandbox"],
            "sha256:" + "c" * 64,
            attempts=1,
            poll_seconds=0,
        )
        self.assertEqual(active.status, "ACTIVE")
        self.assertEqual(active.finding_severity_counts, {"CRITICAL": 0})

        for counts in ({"HIGH": 1}, {"CRITICAL": 1}, {"HIGH": -1}, []):
            with (
                self.subTest(counts=counts),
                self.assertRaises(PUBLISHER.ContractError),
            ):
                PUBLISHER.wait_for_scan(
                    StubRunner(aws_outputs=[self.scan("COMPLETE", counts)]),
                    PUBLISHER.TARGETS["sandbox"],
                    "sha256:" + "c" * 64,
                    attempts=1,
                    poll_seconds=0,
                )

    def test_noncomplete_and_timeout_scan_statuses_fail(self) -> None:
        with self.assertRaises(PUBLISHER.ContractError):
            PUBLISHER.wait_for_scan(
                StubRunner(aws_outputs=[self.scan("FAILED", {})]),
                PUBLISHER.TARGETS["sandbox"],
                "sha256:" + "c" * 64,
                attempts=1,
                poll_seconds=0,
            )
        incomplete = json.loads(self.scan("COMPLETE", {}))
        del incomplete["imageScanFindings"]["imageScanCompletedAt"]
        with self.assertRaises(PUBLISHER.ContractError):
            PUBLISHER.wait_for_scan(
                StubRunner(aws_outputs=[json.dumps(incomplete)]),
                PUBLISHER.TARGETS["sandbox"],
                "sha256:" + "c" * 64,
                attempts=1,
                poll_seconds=0,
            )
        for status, completed in (
            ("PENDING", True),
            ("IN_PROGRESS", True),
            ("ACTIVE", False),
        ):
            with (
                self.subTest(status=status),
                self.assertRaises(PUBLISHER.ContractError),
            ):
                PUBLISHER.wait_for_scan(
                    StubRunner(
                        aws_outputs=[
                            self.scan(status, {}, completed=completed),
                        ]
                    ),
                    PUBLISHER.TARGETS["sandbox"],
                    "sha256:" + "c" * 64,
                    attempts=1,
                    poll_seconds=0,
                )

    def test_pending_and_active_without_evidence_wait_for_completion(self) -> None:
        digest = "sha256:" + "c" * 64
        for first_status, first_completed, final_status in (
            ("PENDING", True, "COMPLETE"),
            ("ACTIVE", False, "ACTIVE"),
        ):
            with self.subTest(first_status=first_status):
                evidence = PUBLISHER.wait_for_scan(
                    StubRunner(
                        aws_outputs=[
                            self.scan(
                                first_status,
                                {},
                                completed=first_completed,
                            ),
                            self.scan(final_status, {"HIGH": 0, "CRITICAL": 0}),
                        ]
                    ),
                    PUBLISHER.TARGETS["sandbox"],
                    digest,
                    attempts=2,
                    poll_seconds=0,
                )
                self.assertEqual(evidence.status, final_status)

    def test_scan_identity_mismatch_fails_closed(self) -> None:
        cases = (
            self.scan("COMPLETE", {}, account_id="000000000000"),
            self.scan("COMPLETE", {}, repository="other/repository"),
            self.scan("COMPLETE", {}, digest="sha256:" + "d" * 64),
        )
        for response in cases:
            with (
                self.subTest(response=response),
                self.assertRaises(PUBLISHER.ContractError),
            ):
                PUBLISHER.wait_for_scan(
                    StubRunner(aws_outputs=[response]),
                    PUBLISHER.TARGETS["sandbox"],
                    "sha256:" + "c" * 64,
                    attempts=1,
                    poll_seconds=0,
                )

    def test_scan_timestamps_preserve_fractional_precision_and_normalize_utc(
        self,
    ) -> None:
        response = json.loads(self.scan("COMPLETE", {"HIGH": 0}))
        response["imageScanFindings"]["imageScanCompletedAt"] = (
            "2026-07-23T12:34:56.144000-06:00"
        )
        response["imageScanFindings"]["vulnerabilitySourceUpdatedAt"] = (
            "2026-07-23T12:00:00.500000+02:00"
        )

        evidence = PUBLISHER.wait_for_scan(
            StubRunner(aws_outputs=[json.dumps(response)]),
            PUBLISHER.TARGETS["sandbox"],
            "sha256:" + "c" * 64,
            attempts=1,
            poll_seconds=0,
        )

        self.assertEqual(evidence.completed_at, "2026-07-23T18:34:56.144000Z")
        self.assertEqual(
            evidence.vulnerability_source_updated_at,
            "2026-07-23T10:00:00.500000Z",
        )

    def test_scan_not_found_retries_but_other_command_errors_fail(self) -> None:
        complete = self.scan("COMPLETE", {"HIGH": 0, "CRITICAL": 0})

        class RetryRunner:
            def __init__(self, retryable: bool):
                self.retryable = retryable
                self.calls = 0

            def aws(self, *arguments: str) -> str:
                self.calls += 1
                if self.calls == 1:
                    stderr = (
                        "ScanNotFoundException"
                        if self.retryable
                        else "AccessDeniedException"
                    )
                    raise PUBLISHER.CommandError(arguments, 254, stderr)
                return complete

        retryable = RetryRunner(True)
        evidence = PUBLISHER.wait_for_scan(
            retryable,
            PUBLISHER.TARGETS["sandbox"],
            "sha256:" + "c" * 64,
            attempts=2,
            poll_seconds=0,
        )
        self.assertEqual(evidence.status, "COMPLETE")
        self.assertEqual(retryable.calls, 2)

        denied = RetryRunner(False)
        with self.assertRaises(PUBLISHER.CommandError):
            PUBLISHER.wait_for_scan(
                denied,
                PUBLISHER.TARGETS["sandbox"],
                "sha256:" + "c" * 64,
                attempts=2,
                poll_seconds=0,
            )
        self.assertEqual(denied.calls, 1)

    def test_scan_not_found_at_bound_reports_bounded_timeout(self) -> None:
        class MissingScanRunner:
            def __init__(self) -> None:
                self.calls = 0

            def aws(self, *arguments: str) -> str:
                self.calls += 1
                raise PUBLISHER.CommandError(
                    arguments,
                    254,
                    "ScanNotFoundException",
                )

        runner = MissingScanRunner()
        with self.assertRaisesRegex(
            PUBLISHER.ContractError,
            "did not complete within the bounded wait",
        ):
            PUBLISHER.wait_for_scan(
                runner,
                PUBLISHER.TARGETS["sandbox"],
                "sha256:" + "c" * 64,
                attempts=2,
                poll_seconds=0,
            )
        self.assertEqual(runner.calls, 2)

    def parameter(self, value: str, version: int) -> str:
        return json.dumps(
            {
                "Parameter": {
                    "Name": "/sandbox/nhp/control/hub/image-digest",
                    "Type": "String",
                    "Value": value,
                    "Version": version,
                }
            }
        )

    def test_digest_pin_updates_once_and_reads_back_exactly(self) -> None:
        digest = "sha256:" + "c" * 64
        runner = StubRunner(
            aws_outputs=[
                self.parameter("UNPUBLISHED", 1),
                json.dumps({"Version": 2}),
                self.parameter(digest, 2),
            ]
        )
        version = PUBLISHER.pin_digest(runner, PUBLISHER.TARGETS["sandbox"], digest)
        self.assertEqual(version, 2)
        self.assertEqual(sum("put-parameter" in call for call in runner.aws_calls), 1)

        runner = StubRunner(
            aws_outputs=[self.parameter(digest, 2), self.parameter(digest, 2)]
        )
        self.assertEqual(
            PUBLISHER.pin_digest(runner, PUBLISHER.TARGETS["sandbox"], digest), 2
        )
        self.assertFalse(any("put-parameter" in call for call in runner.aws_calls))

    def test_pin_readback_mismatch_fails(self) -> None:
        digest = "sha256:" + "c" * 64
        runner = StubRunner(
            aws_outputs=[
                self.parameter("UNPUBLISHED", 1),
                json.dumps({"Version": 2}),
                self.parameter("sha256:" + "d" * 64, 2),
            ]
        )
        with self.assertRaises(PUBLISHER.ContractError):
            PUBLISHER.pin_digest(runner, PUBLISHER.TARGETS["sandbox"], digest)

    def test_digest_pin_requires_parameter_version_to_advance(self) -> None:
        digest = "sha256:" + "c" * 64
        runner = StubRunner(
            aws_outputs=[
                self.parameter("UNPUBLISHED", 2),
                json.dumps({"Version": 2}),
            ]
        )
        with self.assertRaises(PUBLISHER.ContractError):
            PUBLISHER.pin_digest(runner, PUBLISHER.TARGETS["sandbox"], digest)

    def test_digest_pin_rejects_regressed_update_readback_version(self) -> None:
        digest = "sha256:" + "c" * 64
        runner = StubRunner(
            aws_outputs=[
                self.parameter("UNPUBLISHED", 1),
                json.dumps({"Version": 2}),
                self.parameter(digest, 1),
            ]
        )
        with self.assertRaises(PUBLISHER.ContractError):
            PUBLISHER.pin_digest(runner, PUBLISHER.TARGETS["sandbox"], digest)

    def test_digest_pin_rejects_regressed_idempotent_readback_version(self) -> None:
        digest = "sha256:" + "c" * 64
        runner = StubRunner(
            aws_outputs=[
                self.parameter(digest, 2),
                self.parameter(digest, 1),
            ]
        )
        with self.assertRaises(PUBLISHER.ContractError):
            PUBLISHER.pin_digest(runner, PUBLISHER.TARGETS["sandbox"], digest)

    def test_corrupt_current_pin_fails_before_overwrite(self) -> None:
        digest = "sha256:" + "c" * 64
        runner = StubRunner(aws_outputs=[self.parameter("corrupt", 1)])
        with self.assertRaises(PUBLISHER.ContractError):
            PUBLISHER.pin_digest(runner, PUBLISHER.TARGETS["sandbox"], digest)
        self.assertFalse(any("put-parameter" in call for call in runner.aws_calls))


class PublicationSagaTests(unittest.TestCase):
    def test_new_image_runs_full_fail_closed_saga_and_writes_provenance(self) -> None:
        target = PUBLISHER.TARGETS["sandbox"]
        manifest, digest = manifest_fixture()
        digest_ref = f"{target.repository_url}@{digest}"
        missing = json.dumps(
            {
                "images": [],
                "failures": [
                    {
                        "imageId": {"imageTag": SHA},
                        "failureCode": "ImageNotFound",
                    }
                ],
            }
        )
        found = json.dumps(
            {
                "images": [
                    {
                        "imageId": {"imageTag": SHA, "imageDigest": digest},
                        "imageManifest": manifest,
                    }
                ],
                "failures": [],
            }
        )
        described = json.dumps(
            {
                "imageDetails": [
                    {
                        "imageDigest": digest,
                        "imageTags": [SHA],
                    }
                ]
            }
        )
        scan = json.dumps(
            {
                "registryId": target.account_id,
                "repositoryName": PUBLISHER.ECR_REPOSITORY,
                "imageId": {"imageDigest": digest},
                "imageScanStatus": {"status": "COMPLETE"},
                "imageScanFindings": {
                    "imageScanCompletedAt": "2026-07-23T12:34:56+00:00",
                    "vulnerabilitySourceUpdatedAt": "2026-07-23T12:00:00Z",
                    "findingSeverityCounts": {"CRITICAL": 0, "HIGH": 0, "LOW": 2},
                },
            }
        )

        def parameter(value: str, version: int) -> str:
            return json.dumps(
                {
                    "Parameter": {
                        "Name": target.parameter_name,
                        "Type": "String",
                        "Value": value,
                        "Version": version,
                    }
                }
            )

        runner = StubRunner(
            aws_outputs=[
                json.dumps(
                    {
                        "Account": target.account_id,
                        "Arn": (
                            f"arn:aws:sts::{target.account_id}:assumed-role/"
                            f"{target.role_name}/hub-123-2"
                        ),
                        "UserId": "role-id:hub-123-2",
                    }
                ),
                "temporary-password\n",
                missing,
                found,
                described,
                scan,
                parameter("UNPUBLISHED", 1),
                json.dumps({"Version": 2}),
                parameter(digest, 2),
            ],
            run_outputs=[
                inspect_fixture(),
                "Login Succeeded\n",
                "",
                "",
                "",
                inspect_fixture([digest_ref]),
            ],
        )
        with tempfile.TemporaryDirectory() as directory:
            args = invocation(provenance_file=Path(directory) / "provenance.json")
            summary = PUBLISHER.publish(
                args,
                runner,
                generated_at=dt.datetime(2026, 7, 23, 20, 0, 0, tzinfo=dt.timezone.utc),
            )
            provenance = json.loads(args.provenance_file.read_text())

        self.assertEqual(summary["digest"], digest)
        self.assertEqual(provenance["image"]["reference"], digest_ref)
        self.assertTrue(provenance["image"]["pushed_by_this_attempt"])
        self.assertEqual(provenance["scan"]["finding_severity_counts"]["LOW"], 2)
        self.assertEqual(provenance["scan"]["completed_at"], "2026-07-23T12:34:56Z")
        self.assertEqual(
            provenance["scan"]["vulnerability_source_updated_at"],
            "2026-07-23T12:00:00Z",
        )
        self.assertEqual(provenance["digest_pin"]["parameter_version"], 2)
        self.assertEqual(provenance["generated_at"], "2026-07-23T20:00:00Z")
        self.assertIn(
            ("docker", "push", f"{target.repository_url}:{SHA}"), runner.run_calls
        )
        self.assertFalse(
            any(
                reference.endswith(":latest")
                or reference.endswith(":sandbox")
                or reference.endswith(":production")
                for call in runner.run_calls
                for reference in call
            )
        )


class ProvenanceAndWorkflowContractTests(unittest.TestCase):
    def test_provenance_writer_is_atomic_and_private(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "provenance.json"
            value = {"schema_version": 1, "secret_free": True}
            PUBLISHER.write_json_atomic(output, value)
            self.assertEqual(json.loads(output.read_text()), value)
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
            self.assertEqual(
                [path.name for path in output.parent.iterdir()], [output.name]
            )

    def test_workflow_stays_manual_dark_exact_sha_and_preflight_before_oidc(
        self,
    ) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("workflow_dispatch:", workflow)
        self.assertNotIn("\n  push:", workflow)
        self.assertNotIn("\n  pull_request:", workflow)
        self.assertIn(
            "environment:\n      name: hub-publish-${{ inputs.target_environment }}",
            workflow,
        )
        self.assertIn("persist-credentials: false", workflow)
        self.assertIn("push: false", workflow)
        self.assertNotIn("push: true", workflow)
        self.assertIn("provenance: false", workflow)
        self.assertIn("sbom: false", workflow)
        self.assertIn("local/layerv/nhp-hub:${GITHUB_SHA}", workflow)
        self.assertNotIn("layerv/nhp-hub:latest", workflow)
        self.assertNotIn("layerv/nhp-hub:sandbox", workflow)
        self.assertNotIn("layerv/nhp-hub:production", workflow)
        self.assertIn("permissions:\n  actions: read", workflow)
        preflight = workflow.index(
            "- name: Verify protected publication Environment before AWS access"
        )
        local_scan = workflow.index("- name: Scan exact local Hub image")
        live_main = workflow.index("- name: Re-read live main before AWS access")
        oidc = workflow.index("- name: Configure dedicated Hub publisher session")
        publish = workflow.index(
            "- name: Publish, scan, and pin exact source-SHA image"
        )
        self.assertLess(local_scan, live_main)
        self.assertLess(live_main, preflight)
        self.assertLess(preflight, oidc)
        self.assertLess(oidc, publish)
        self.assertIn(
            'run: scripts/check-live-main-ref.sh "$GITHUB_SHA"',
            workflow,
        )
        self.assertIn("output-env-credentials: false", workflow)
        self.assertIn("output-credentials: true", workflow)
        self.assertIn(
            "AWS_ACCESS_KEY_ID: ${{ steps.aws.outputs.aws-access-key-id }}",
            workflow,
        )
        self.assertIn("- name: Remove publisher registry credentials", workflow)
        self.assertIn("severity: CRITICAL,HIGH", workflow)
        self.assertIn("runtime deployment: **none**", workflow)

    def test_workflow_role_and_environment_contract_match_terraform(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        publisher = PUBLISHER_TF.read_text(encoding="utf-8")
        outputs = OUTPUTS_TF.read_text(encoding="utf-8")
        build_workflow = BUILD_WORKFLOW.read_text(encoding="utf-8")
        for value in (
            "hub-publish-${{ inputs.target_environment }}",
            "layerv-nhp-${terraform_environment}-control-hub-publisher",
            "767397897469",
            "235500187906",
            "us-east-2",
        ):
            self.assertIn(value, workflow)
        self.assertIn(
            'hub_publisher_github_environment = local.is_prod ? "hub-publish-production" : "hub-publish-sandbox"',
            publisher,
        )
        self.assertIn('output "hub_publisher_github_environment"', outputs)
        hub_row = build_workflow.split("- image: hub", 1)[1].split("steps:", 1)[0]
        self.assertIn("publish: false", hub_row)


if __name__ == "__main__":
    unittest.main()


class ScanWaiverTest(unittest.TestCase):
    """Time-boxed waivers for glibc CVEs with no upstream fix.

    The waiver must never be able to hide something it does not name, and must
    stop working on its own once it expires.
    """

    TODAY = "2026-07-28"
    EXPIRED = "2026-08-28"

    def finding(self, name, package, severity="CRITICAL"):
        return {
            "name": name,
            "severity": severity,
            "attributes": [{"key": "package_name", "value": package}],
        }

    def glibc_findings(self):
        out = []
        for cve, severity in (
            ("CVE-2026-5450", "CRITICAL"),
            ("CVE-2026-5435", "HIGH"),
            ("CVE-2026-5928", "HIGH"),
            ("CVE-2026-4046", "HIGH"),
        ):
            for package in ("libc6", "glibc", "libc-bin"):
                out.append(self.finding(cve, package, severity))
        return out

    def counts(self, findings):
        out = {}
        for f in findings:
            out[f["severity"]] = out.get(f["severity"], 0) + 1
        return out

    def test_the_live_glibc_set_is_fully_waived(self) -> None:
        findings = self.glibc_findings()
        waived, blocking = PUBLISHER.partition_scan_findings(
            findings, self.counts(findings), self.TODAY
        )
        self.assertEqual(len(waived), 12)
        self.assertEqual(blocking, [])

    def test_waiver_is_inert_after_expiry(self) -> None:
        findings = self.glibc_findings()
        with self.assertRaisesRegex(PUBLISHER.ContractError, "expired"):
            PUBLISHER.partition_scan_findings(
                findings, self.counts(findings), self.EXPIRED
            )

    def test_an_unlisted_cve_still_blocks(self) -> None:
        findings = self.glibc_findings() + [self.finding("CVE-9999-1", "openssl")]
        _, blocking = PUBLISHER.partition_scan_findings(
            findings, self.counts(findings), self.TODAY
        )
        self.assertEqual([f["name"] for f in blocking], ["CVE-9999-1"])

    def test_a_waived_cve_on_another_package_still_blocks(self) -> None:
        """The waiver is (CVE, package), never a CVE wildcard."""
        findings = self.glibc_findings() + [self.finding("CVE-2026-5450", "openssl")]
        _, blocking = PUBLISHER.partition_scan_findings(
            findings, self.counts(findings), self.TODAY
        )
        self.assertEqual(len(blocking), 1)

    def test_another_glibc_cve_still_blocks(self) -> None:
        """The waiver is not a package wildcard either."""
        findings = self.glibc_findings() + [self.finding("CVE-2027-0001", "libc6")]
        _, blocking = PUBLISHER.partition_scan_findings(
            findings, self.counts(findings), self.TODAY
        )
        self.assertEqual(len(blocking), 1)

    def test_a_short_findings_list_fails_closed(self) -> None:
        """Counts are reported independently, so they must reconcile."""
        findings = self.glibc_findings()
        with self.assertRaisesRegex(PUBLISHER.ContractError, "incomplete list"):
            PUBLISHER.partition_scan_findings(
                findings[:3], self.counts(findings), self.TODAY
            )

    def test_a_finding_without_a_package_fails_closed(self) -> None:
        findings = [{"name": "CVE-2026-5450", "severity": "CRITICAL"}]
        with self.assertRaisesRegex(PUBLISHER.ContractError, "name or package"):
            PUBLISHER.partition_scan_findings(
                findings, {"CRITICAL": 1}, self.TODAY
            )

    def test_medium_findings_are_ignored_entirely(self) -> None:
        findings = self.glibc_findings() + [
            self.finding("CVE-2026-1111", "curl", severity="MEDIUM")
        ]
        counts = self.counts(findings)
        waived, blocking = PUBLISHER.partition_scan_findings(
            findings, counts, self.TODAY
        )
        self.assertEqual(len(waived), 12)
        self.assertEqual(blocking, [])
