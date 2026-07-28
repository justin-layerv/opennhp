#!/usr/bin/env python3
"""Cover the pinned runtime-attestation collector's launch-template binding.

The collector asset is SHA-256 pinned by the State Manager repair document, so
its bytes cannot drift without moving the published contract.  These tests load
the exact committed bytes and exercise the identity derivation that decides
whether a node publishes an attestation at all.
"""

from __future__ import annotations

import importlib.util
import json
import sys
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


if __name__ == "__main__":
    unittest.main()


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
