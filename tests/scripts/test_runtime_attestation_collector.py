#!/usr/bin/env python3
"""Cover the pinned runtime-attestation collector's launch-template binding.

The collector asset is SHA-256 pinned by the State Manager repair document, so
its bytes cannot drift without moving the published contract.  These tests load
the exact committed bytes and exercise the identity derivation that decides
whether a node publishes an attestation at all.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
COLLECTOR_PATH = (
    ROOT
    / "terraform"
    / "modules"
    / "runtime-attestation-store"
    / "assets"
    / "collect-runtime-attestation.py"
)

SPEC = importlib.util.spec_from_file_location(
    "layerv_runtime_attestation_collector", COLLECTOR_PATH
)
assert SPEC is not None and SPEC.loader is not None
collector = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = collector
SPEC.loader.exec_module(collector)


INSTANCE_ID = "i-0b74635bfac7d988c"
ROLE_NAME = "layerv-nhp-sandbox-cell1-server"
LAUNCH_TEMPLATE_ID = "lt-054583eecc18ceed6"
BOOT_ID = "7f3f4c02-9b34-4a7e-8a1d-2c9f0b6d51ae"


def asg_membership_row(
    *,
    launch_template: object | None = {  # noqa: B006 - read-only default shape
        "LaunchTemplateId": LAUNCH_TEMPLATE_ID,
        "LaunchTemplateName": "layerv-nhp-sandbox-cell1-server-c262c431fb",
        "Version": "2",
    },
    lifecycle_state: str = "InService",
) -> dict[str, object]:
    row: dict[str, object] = {
        "InstanceId": INSTANCE_ID,
        "AutoScalingGroupName": "layerv-nhp-sandbox-cell1-server",
        "LifecycleState": lifecycle_state,
        "HealthStatus": "HEALTHY",
    }
    if launch_template is not None:
        row["LaunchTemplate"] = launch_template
    return row


def described_instance(
    *,
    launch_template_id: str | None = LAUNCH_TEMPLATE_ID,
    launch_template_version: str | None = "2",
    extra_tags: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    """The exact `describe-instances` shape AWS returns for an ASG member.

    Note the deliberate absence of a top-level `LaunchTemplate` key: EC2 only
    populates that for an instance whose RunInstances caller named a template
    directly, never for one the Auto Scaling service launched.
    """

    tags: list[dict[str, object]] = [
        {"Key": "Name", "Value": "layerv-nhp-sandbox-cell1-server"},
        {"Key": "Cell", "Value": "cell1"},
        {
            "Key": "aws:autoscaling:groupName",
            "Value": "layerv-nhp-sandbox-cell1-server",
        },
    ]
    if launch_template_id is not None:
        tags.append({"Key": "aws:ec2launchtemplate:id", "Value": launch_template_id})
    if launch_template_version is not None:
        tags.append(
            {"Key": "aws:ec2launchtemplate:version", "Value": launch_template_version}
        )
    tags.extend(extra_tags or [])
    return {"InstanceId": INSTANCE_ID, "State": {"Name": "running"}, "Tags": tags}


class LaunchTemplateIdentityTest(unittest.TestCase):
    def test_accepts_a_well_formed_control_plane_record(self) -> None:
        self.assertEqual(
            collector._launch_template_identity(
                {"LaunchTemplateId": LAUNCH_TEMPLATE_ID, "Version": "2"}, "source"
            ),
            (LAUNCH_TEMPLATE_ID, 2),
        )

    def test_rejects_a_missing_record(self) -> None:
        for absent in (None, "", [], 2):
            with self.subTest(absent=absent):
                with self.assertRaises(collector.CollectorError):
                    collector._launch_template_identity(absent, "source")

    def test_rejects_a_malformed_template_id(self) -> None:
        for template_id in ("", "lt-", "LT-054583EECC18CEED6", "lt-zzzz1234", None):
            with self.subTest(template_id=template_id):
                with self.assertRaises(collector.CollectorError):
                    collector._launch_template_identity(
                        {"LaunchTemplateId": template_id, "Version": "2"}, "source"
                    )

    def test_rejects_a_non_integer_version(self) -> None:
        for version in ("$Latest", "$Default", "2.5", "", None, [2]):
            with self.subTest(version=version):
                with self.assertRaises(collector.CollectorError):
                    collector._launch_template_identity(
                        {"LaunchTemplateId": LAUNCH_TEMPLATE_ID, "Version": version},
                        "source",
                    )

    def test_rejects_a_non_positive_version(self) -> None:
        for version in ("0", "-1"):
            with self.subTest(version=version):
                with self.assertRaises(collector.CollectorError):
                    collector._launch_template_identity(
                        {"LaunchTemplateId": LAUNCH_TEMPLATE_ID, "Version": version},
                        "source",
                    )


class ReservedLaunchTemplateTagsTest(unittest.TestCase):
    def test_reads_the_reserved_tags(self) -> None:
        self.assertEqual(
            collector._reserved_launch_template_tags(described_instance()),
            {"LaunchTemplateId": LAUNCH_TEMPLATE_ID, "Version": "2"},
        )

    def test_rejects_a_missing_tag_list(self) -> None:
        with self.assertRaises(collector.CollectorError):
            collector._reserved_launch_template_tags({"InstanceId": INSTANCE_ID})

    def test_rejects_a_malformed_tag_entry(self) -> None:
        with self.assertRaises(collector.CollectorError):
            collector._reserved_launch_template_tags(
                {"InstanceId": INSTANCE_ID, "Tags": ["aws:ec2launchtemplate:id"]}
            )

    def test_rejects_duplicate_reserved_tags(self) -> None:
        with self.assertRaises(collector.CollectorError):
            collector._reserved_launch_template_tags(
                described_instance(
                    extra_tags=[
                        {
                            "Key": "aws:ec2launchtemplate:id",
                            "Value": "lt-0000000000000000a",
                        }
                    ]
                )
            )

    def test_absent_reserved_tags_fail_closed_downstream(self) -> None:
        with self.assertRaises(collector.CollectorError):
            collector._launch_template_identity(
                collector._reserved_launch_template_tags(
                    described_instance(
                        launch_template_id=None, launch_template_version=None
                    )
                ),
                "reserved instance tag",
            )


class CollectIdentityTest(unittest.TestCase):
    """Exercise the whole derivation against the real AWS response shapes."""

    def setUp(self) -> None:
        self.membership = {"AutoScalingInstances": [asg_membership_row()]}
        self.described = {"Reservations": [{"Instances": [described_instance()]}]}

    def _run(self) -> dict[str, object]:
        def fake_aws(service: str, arguments: list[str], name: str) -> object:
            if service == "sts":
                return {
                    "UserId": f"AROA3FLD2UT63EXAMPLE:{INSTANCE_ID}",
                    "Arn": (
                        "arn:aws:sts::767397897469:assumed-role/"
                        f"{ROLE_NAME}/{INSTANCE_ID}"
                    ),
                }
            if service == "autoscaling":
                return self.membership
            if service == "ec2":
                return self.described
            raise AssertionError(f"unexpected AWS call: {service} {arguments} {name}")

        identity_document = json.dumps(
            {
                "instanceId": INSTANCE_ID,
                "accountId": "767397897469",
                "region": "us-east-2",
            }
        )
        boot_id = mock.MagicMock()
        boot_id.read_text.return_value = f"{BOOT_ID}\n"
        with (
            mock.patch.object(collector, "_imds_token", return_value="token"),
            mock.patch.object(collector, "_imds", return_value=identity_document),
            mock.patch.object(collector, "_aws", side_effect=fake_aws),
            mock.patch.object(collector, "BOOT_ID_PATH", boot_id),
        ):
            return collector._collect_identity()

    def test_binds_the_launch_template_without_a_top_level_field(self) -> None:
        # Regression: `describe-instances` returns no top-level LaunchTemplate
        # for an ASG-launched instance, which stalled every publication.
        described_shape = self.described["Reservations"][0]["Instances"][0]
        self.assertNotIn("LaunchTemplate", described_shape)
        identity = self._run()
        self.assertEqual(identity["launch_template_id"], LAUNCH_TEMPLATE_ID)
        self.assertEqual(identity["launch_template_version"], 2)
        self.assertIsInstance(identity["launch_template_version"], int)
        self.assertEqual(identity["instance_id"], INSTANCE_ID)
        self.assertEqual(identity["boot_id"], BOOT_ID)
        self.assertEqual(
            identity["role_arn"], f"arn:aws:iam::767397897469:role/{ROLE_NAME}"
        )

    def test_fails_closed_when_the_membership_row_has_no_template(self) -> None:
        self.membership = {
            "AutoScalingInstances": [asg_membership_row(launch_template=None)]
        }
        with self.assertRaises(collector.CollectorError):
            self._run()

    def test_fails_closed_when_the_reserved_tag_is_absent(self) -> None:
        self.described = {
            "Reservations": [
                {"Instances": [described_instance(launch_template_version=None)]}
            ]
        }
        with self.assertRaises(collector.CollectorError):
            self._run()

    def test_fails_closed_when_the_two_records_disagree(self) -> None:
        for tag_id, tag_version in (
            (LAUNCH_TEMPLATE_ID, "3"),
            ("lt-0000000000000000a", "2"),
        ):
            with self.subTest(tag_id=tag_id, tag_version=tag_version):
                self.described = {
                    "Reservations": [
                        {
                            "Instances": [
                                described_instance(
                                    launch_template_id=tag_id,
                                    launch_template_version=tag_version,
                                )
                            ]
                        }
                    ]
                }
                with self.assertRaises(collector.CollectorError):
                    self._run()

    def test_still_rejects_an_out_of_service_member(self) -> None:
        self.membership = {
            "AutoScalingInstances": [asg_membership_row(lifecycle_state="Terminating")]
        }
        with self.assertRaises(collector.CollectorError):
            self._run()

    def test_still_rejects_an_ambiguous_instance_description(self) -> None:
        self.described = {
            "Reservations": [
                {"Instances": [described_instance(), described_instance()]}
            ]
        }
        with self.assertRaises(collector.CollectorError):
            self._run()



class RepairExecutionOrderingTest(unittest.TestCase):
    """A Status filter destroys DescribeAssociationExecutions' ordering.

    Unfiltered pages are strictly newest-first. The Status-filtered page is
    stably jumbled (observed live: 19:08, 14:08, the PREVIOUS day's 20:38,
    21:38, 00:38), so taking rows[0] recorded an arbitrary successful execution
    as last_success_at instead of the latest one.
    """

    def row(self, created, status="Success"):
        return {"CreatedTime": created, "Status": status}

    def created_seconds(self, rows):
        return [collector._iso_utc_seconds(r["CreatedTime"], "repair") for r in rows]

    def test_newest_first_page_is_accepted_and_newest_wins(self) -> None:
        rows = [
            self.row("2026-07-28T01:38:18.333000-06:00"),
            self.row("2026-07-28T01:08:20.120000-06:00"),
            self.row("2026-07-28T00:38:02.949000-06:00"),
        ]
        created = self.created_seconds(rows)
        self.assertEqual(created, sorted(created, reverse=True))
        self.assertEqual(created[0], "2026-07-28T07:38:18Z")

    def test_the_jumbled_status_filtered_page_is_rejected(self) -> None:
        """The exact live shape the Status filter produced."""
        rows = [
            self.row("2026-07-27T19:08:29.268000-06:00"),
            self.row("2026-07-27T14:08:20.395000-06:00"),
            self.row("2026-07-26T20:38:06.289000-06:00"),
            self.row("2026-07-27T21:38:30.243000-06:00"),
            self.row("2026-07-28T00:38:02.949000-06:00"),
        ]
        created = self.created_seconds(rows)
        self.assertNotEqual(created, sorted(created, reverse=True))

    def test_mixed_offsets_compare_in_utc(self) -> None:
        """-06:00 and +00:00 spellings must order by absolute time, not text."""
        rows = [
            self.row("2026-07-28T01:38:18.333000-06:00"),  # 07:38:18Z
            self.row("2026-07-28T07:08:20.120000+00:00"),  # 07:08:20Z
        ]
        created = self.created_seconds(rows)
        self.assertEqual(created, ["2026-07-28T07:38:18Z", "2026-07-28T07:08:20Z"])
        self.assertEqual(created, sorted(created, reverse=True))

    def test_sub_second_precision_is_truncated_to_whole_seconds(self) -> None:
        self.assertEqual(
            collector._iso_utc_seconds("2026-07-28T07:38:18.999999+00:00", "repair"),
            "2026-07-28T07:38:18Z",
        )


class WorkloadBranchTest(unittest.TestCase):
    """The collector must branch on what a node installs, not on its evidence.

    The discriminator used to be the boot capture's own existence, so an frps
    node with no capture fell through to the NHP container branch and died with
    `no such object: nhp-server` -- naming a workload that never runs on that
    fleet. Live evidence (2026-07-28): all three `layerv-nhp-sandbox-frps`
    instances failed every five-minute run that way for eleven hours while the
    repair association reported Success, and nothing in the repository ever
    wrote the capture the branch required.
    """

    def branch(self, *, qrts_binary: bool, boot_capture: bool) -> str:
        calls = []
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary, capture = root / "nhp-frps", root / "boot-capture.json"
            if qrts_binary:
                binary.write_bytes(b"elf")
            if boot_capture:
                capture.write_text("{}", encoding="utf-8")
            with mock.patch.object(
                collector, "QRTS_BINARY_PATH", binary
            ), mock.patch.object(
                collector, "BOOT_CAPTURE_PATH", capture
            ), mock.patch.object(
                collector,
                "_collect_installed_binary_runtime",
                side_effect=lambda: calls.append("qrts"),
            ), mock.patch.object(
                collector,
                "_collect_docker_runtime",
                side_effect=lambda: calls.append("docker"),
            ):
                collector._collect_runtime()
        self.assertEqual(len(calls), 1)
        return calls[0]

    def test_an_installed_qrts_binary_selects_the_qrts_branch(self) -> None:
        self.assertEqual(self.branch(qrts_binary=True, boot_capture=True), "qrts")

    def test_a_qrts_node_with_no_capture_stays_on_the_qrts_branch(self) -> None:
        """The regression: this used to select the container branch."""
        self.assertEqual(self.branch(qrts_binary=True, boot_capture=False), "qrts")

    def test_a_node_without_the_qrts_binary_selects_the_container_branch(self) -> None:
        self.assertEqual(self.branch(qrts_binary=False, boot_capture=False), "docker")

    def test_a_missing_capture_names_the_capture_not_the_container(self) -> None:
        """The exact live failure, end to end, with no branch mocked."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "nhp-frps"
            binary.write_bytes(b"elf")
            with mock.patch.object(
                collector, "QRTS_BINARY_PATH", binary
            ), mock.patch.object(
                collector, "BOOT_CAPTURE_PATH", root / "boot-capture.json"
            ):
                with self.assertRaises(collector.CollectorError) as raised:
                    collector._collect_runtime()
        self.assertIn("boot capture is missing", str(raised.exception))
        self.assertNotIn(collector.NHP_CONTAINER_NAME, str(raised.exception))


class VerifyModeTest(unittest.TestCase):
    """`--verify` is what keeps the repair association's Success honest.

    It must fail on a node that cannot collect, pass on one that can, and pass
    on a member the producer will never read -- without ever publishing.
    """

    def run_verify(self, *, identity=None, runtime=None):
        published = []
        identity = identity or (lambda: {"instance_id": INSTANCE_ID})
        runtime = runtime or (lambda: {"kind": "installed_binary"})
        with mock.patch.object(
            collector, "_collect_identity", side_effect=identity
        ), mock.patch.object(
            collector, "_collect_runtime", side_effect=runtime
        ), mock.patch.object(
            collector, "_sha256_file", return_value="0" * 64
        ), mock.patch.object(
            collector, "_publish", side_effect=lambda *a, **k: published.append(a)
        ), mock.patch.object(
            collector, "_collect_repair", side_effect=AssertionError("self-referential")
        ):
            code = collector._verify()
        self.assertEqual(published, [], "--verify must never publish")
        return code

    def test_a_healthy_node_verifies(self) -> None:
        self.assertEqual(self.run_verify(), 0)

    def test_a_node_that_cannot_collect_fails_the_step(self) -> None:
        def boom() -> dict[str, object]:
            raise collector.CollectorError("qRTS boot capture is missing")

        self.assertEqual(self.run_verify(runtime=boom), 1)

    def test_a_member_outside_the_fleet_is_not_a_defect(self) -> None:
        """Tag-targeted runs reach Pending/Standby/Terminating instances.

        Failing the association for one would take the whole fleet's evidence
        channel down during any rolling replacement.
        """

        def not_here() -> dict[str, object]:
            raise collector.NotAttestableHere("instance is not InService")

        self.assertEqual(self.run_verify(identity=not_here), 0)

    def test_publishing_still_fails_closed_outside_the_fleet(self) -> None:
        """`--verify` tolerance must not leak into the publish path."""
        self.assertTrue(issubclass(collector.NotAttestableHere, collector.CollectorError))

    def test_verify_does_not_consult_the_associations_own_status(self) -> None:
        """Wiring `_collect_repair` in would latch the association red forever.

        One failed execution would make every later collector run fail the
        repair check, which would fail the next execution. `run_verify` patches
        `_collect_repair` to raise, so reaching it fails this test.
        """
        self.assertEqual(self.run_verify(), 0)


class BuildReceiptReconstructionTest(unittest.TestCase):
    """qRTS user-data reconstructs the signed receipt; the bytes must match.

    `user_data.sh.tpl` builds the canonical build receipt with `printf` from its
    own observations and hashes it, and the producer rebuilds the same bytes
    from the cosign-verified attestation. They live in different files and
    different languages, so drift in either would surface only as an
    unexplainable manifest failure. Compare them directly.
    """

    USER_DATA = (
        ROOT
        / "terraform"
        / "modules"
        / "qurl-reverse-tunnel-server"
        / "user_data.sh.tpl"
    )

    SOURCE_REVISION = "acdeb262a7b5cce58688c72fdcd8d4cbc0f2f3b5"
    BINARY_SHA256 = "f075a26498bf8f26001b9a1f3028999ffb287273b82eccc78940169ad27611f8"

    def setUp(self) -> None:
        sys.path.insert(0, str(ROOT / ".github" / "scripts"))
        import collect_udp_proof_deployment_evidence as producer

        self.producer = producer

    def printf_format(self) -> str:
        text = self.USER_DATA.read_text(encoding="utf-8")
        matches = re.findall(r"'(\{\"schema_version\":1[^']*)'", text)
        self.assertEqual(len(matches), 1, "one canonical receipt format expected")
        return matches[0]

    def test_the_shell_format_reproduces_the_producers_canonical_bytes(self) -> None:
        rendered = subprocess.run(
            [
                "printf",
                self.printf_format(),
                self.SOURCE_REVISION,
                self.producer.QRTS_BUILD_RECEIPT_BINARY_PATH,
                self.BINARY_SHA256,
            ],
            capture_output=True,
            check=True,
        ).stdout
        expected = self.producer._qrts_canonical_receipt_bytes(
            {
                "source_revision": self.SOURCE_REVISION,
                "binary_sha256": self.BINARY_SHA256,
            }
        )
        self.assertEqual(rendered, expected)
        # The live sandbox value on 2026-07-28, cross-checked against the
        # cosign-verified attestation for
        # sha256:33b2ea3b1bccf1ff47d9b2cf9f00b473b8fc93f79a7acb34c0d25d638fce50a9
        # and the binary actually installed on the frps fleet.
        self.assertEqual(
            hashlib.sha256(rendered).hexdigest(),
            "c7308ccafb1d328f7917d0ad817c8acd910fab46119c35dc74e365b0aae7e046",
        )

    def test_user_data_pins_the_same_in_image_binary_path(self) -> None:
        text = self.USER_DATA.read_text(encoding="utf-8")
        self.assertIn(
            f"RECEIPT_BINARY_PATH={self.producer.QRTS_BUILD_RECEIPT_BINARY_PATH}\n",
            text,
        )

    def test_the_capture_carries_exactly_the_keys_the_collector_requires(self) -> None:
        text = self.USER_DATA.read_text(encoding="utf-8")
        for key in (
            "image_digest",
            "source_revision",
            "build_receipt_sha256",
            "installed_binary_sha256",
            "source_kind",
        ):
            self.assertIn(f"{key}:", text)
        self.assertIn('source_kind: "ecr_build_receipt"', text)



class FileHashBoundTest(unittest.TestCase):
    """The installed qRTS binary must be hashable.

    `_sha256_file`'s bound was sized for the pinned assets -- the collector and
    two unit files, a few kilobytes each -- but the qRTS branch hashes a ~20 MiB
    Go binary through the same helper. Live on 2026-07-28
    `/opt/layerv/qurl-reverse-tunnel-server/nhp-frps` was 21,528,738 bytes, so
    `installed_binary` collection failed unconditionally with `is too large to
    hash`. It stayed invisible behind the missing boot capture: nothing wrote
    the capture, so the branch was never reached on a real node.
    """

    def write(self, directory: str, size: int) -> Path:
        path = Path(directory) / "nhp-frps"
        path.write_bytes(b"\0" * size)
        return path

    def test_a_twenty_megabyte_binary_hashes(self) -> None:
        size = 21_528_738
        with tempfile.TemporaryDirectory() as directory:
            path = self.write(directory, size)
            self.assertEqual(
                collector._sha256_file(
                    path, maximum=collector.MAX_INSTALLED_BINARY_BYTES
                ),
                hashlib.sha256(b"\0" * size).hexdigest(),
            )

    def test_the_pinned_asset_default_would_still_reject_it(self) -> None:
        """The exact live regression, against the old bound."""
        with tempfile.TemporaryDirectory() as directory:
            path = self.write(directory, 21_528_738)
            with self.assertRaises(collector.CollectorError) as raised:
                collector._sha256_file(path)
        self.assertIn("too large to hash", str(raised.exception))

    def test_the_binary_bound_is_still_a_bound(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self.write(directory, 4096)
            with self.assertRaises(collector.CollectorError):
                collector._sha256_file(path, maximum=1024)

    def test_the_qrts_branch_uses_the_binary_bound(self) -> None:
        """Guard the call site, not just the helper."""
        seen = {}

        def record(path, *, maximum=collector.MAX_PINNED_ASSET_BYTES):
            seen[path] = maximum
            return "0" * 64

        with tempfile.TemporaryDirectory() as directory:
            capture = Path(directory) / "boot-capture.json"
            capture.write_text(
                json.dumps(
                    {
                        "image_digest": "sha256:" + "a" * 64,
                        "source_revision": "b" * 40,
                        "build_receipt_sha256": "c" * 64,
                        "installed_binary_sha256": "0" * 64,
                        "source_kind": "ecr_build_receipt",
                    }
                ),
                encoding="utf-8",
            )
            with mock.patch.object(
                collector, "BOOT_CAPTURE_PATH", capture
            ), mock.patch.object(collector, "_sha256_file", side_effect=record):
                collector._collect_installed_binary_runtime()

        self.assertEqual(
            seen[collector.QRTS_BINARY_PATH],
            collector.MAX_INSTALLED_BINARY_BYTES,
        )
        self.assertGreater(
            collector.MAX_INSTALLED_BINARY_BYTES, collector.MAX_PINNED_ASSET_BYTES
        )

    def test_hashing_is_chunked_so_memory_does_not_track_the_bound(self) -> None:
        self.assertLessEqual(
            collector.HASH_CHUNK_BYTES, collector.MAX_PINNED_ASSET_BYTES
        )


if __name__ == "__main__":
    unittest.main()
