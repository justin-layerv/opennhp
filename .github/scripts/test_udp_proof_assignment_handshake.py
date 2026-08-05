import argparse
import base64
import hashlib
import importlib.util
import json
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock


MODULE_PATH = Path(__file__).with_name("udp_proof_assignment_handshake.py")
SPEC = importlib.util.spec_from_file_location("assignment_handshake", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
handshake = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = handshake
SPEC.loader.exec_module(handshake)


def descriptor():
    channel = "0123456789abcdef0123456789abcdef"
    prefix = f"handshake/v1/123/1/{channel}"
    return {
        "version": 1,
        "controller_run_id": "123",
        "controller_run_attempt": "1",
        "client": "qurl_go",
        "proof_phase": "pre_removal",
        "channel_id": channel,
        "correlation_id": f"nhp-123-1-qurl_go-pre_removal-{channel}",
        "agent_id": "qurl-go-sandbox-123-1",
        "bucket": handshake.BUCKET,
        "kms_key_arn": (
            "arn:aws:kms:us-east-2:767397897469:key/"
            "01234567-89ab-cdef-0123-456789abcdef"
        ),
        "checkpoint_key": f"{prefix}/checkpoint.json",
        "receipt_key": f"{prefix}/receipt.json",
        "ca_pm_alias_arn": (
            "arn:aws:lambda:us-east-2:767397897469:function:"
            "layerv-nhp-sandbox-ca-pm:blue"
        ),
        "pinned_cell_id": "cell0",
        "target_cell_id": "cell1",
        # Derived, not literal: validate_descriptor requires these to equal the
        # module constants, so a hardcoded copy silently pins the very value a
        # lease-ceiling fix has to change.
        "arm_lease_seconds": handshake.ARM_LEASE_SECONDS,
        "expire_lease_seconds": handshake.EXPIRE_LEASE_SECONDS,
        "arm_request_id": "a" * 64,
        "move_request_id": "b" * 64,
        "expire_request_id": "c" * 64,
    }


def transport_descriptor():
    assignment = descriptor()
    prefix = (
        f"handshake/v1/{assignment['controller_run_id']}/"
        f"{assignment['controller_run_attempt']}/{assignment['channel_id']}"
    )
    return {
        "version": 1,
        "controller_run_id": assignment["controller_run_id"],
        "controller_run_attempt": assignment["controller_run_attempt"],
        "client": assignment["client"],
        "proof_phase": assignment["proof_phase"],
        "channel_id": assignment["channel_id"],
        "correlation_id": assignment["correlation_id"],
        "agent_id": assignment["agent_id"],
        "bucket": assignment["bucket"],
        "kms_key_arn": assignment["kms_key_arn"],
        "checkpoint_key": f"{prefix}/transport-checkpoint.json",
        "receipt_key": f"{prefix}/transport-receipt.json",
        "proof_source_ip": handshake.PROOF_SOURCE_IP,
        "lifecycle_http_hosts": handshake.TRANSPORT_HTTP_HOSTS,
        "qurl_service_log_groups": handshake.QURL_SERVICE_LOG_GROUPS,
        "relay_log_group": handshake.RELAY_LOG_GROUP,
        "legacy_lifecycle_http_routes": handshake.LEGACY_LIFECYCLE_HTTP_ROUTES,
    }


class AssignmentHandshakeTest(unittest.TestCase):
    def test_resolves_exact_enabled_kms_key_arn(self):
        expected = descriptor()["kms_key_arn"]
        payload = json.dumps(
            {
                "KeyMetadata": {
                    "Arn": expected,
                    "Enabled": True,
                    "KeyState": "Enabled",
                    "KeyId": expected.rsplit("/", 1)[1],
                }
            }
        ).encode()
        with mock.patch.object(handshake, "_run", return_value=payload) as run:
            self.assertEqual(handshake._resolve_handshake_key_arn(), expected)
        self.assertIn(handshake.KMS_ALIAS_ARN, run.call_args.args[0])

        for changed in (
            payload.replace(b'"Enabled": true', b'"Enabled": false'),
            payload.replace(b'"KeyState": "Enabled"', b'"KeyState": "PendingDeletion"'),
            payload.replace(b":key/", b":alias/"),
        ):
            with mock.patch.object(handshake, "_run", return_value=changed):
                with self.assertRaises(handshake.HandshakeError):
                    handshake._resolve_handshake_key_arn()

    def test_selects_only_exact_ca_pm_alias(self):
        alias = descriptor()["ca_pm_alias_arn"]
        provenance = {
            "schema_version": 1,
            "producer": {},
            "candidates": {},
            "files": {},
            "evidence": {
                "workloads": {
                    "qurl_service_authority": {
                        "proof_policy_consumers_active": True,
                        "functions": [
                            {
                                "alias_arn": alias,
                                "version_arn": (
                                    "arn:aws:lambda:us-east-2:767397897469:"
                                    "function:layerv-nhp-sandbox-ca-pm:7"
                                ),
                            }
                        ]
                    }
                }
            },
        }
        self.assertEqual(handshake.select_ca_pm_alias(provenance), alias)
        provenance["evidence"]["workloads"]["qurl_service_authority"]["functions"].append(
            {
                "alias_arn": alias.replace(":blue", ":green"),
                "version_arn": alias.replace(":blue", ":8"),
            }
        )
        with self.assertRaises(handshake.HandshakeError):
            handshake.select_ca_pm_alias(provenance)

    def test_rejects_unactivated_proof_policy_consumers(self):
        alias = descriptor()["ca_pm_alias_arn"]
        provenance = {
            "schema_version": 1,
            "producer": {},
            "candidates": {},
            "files": {},
            "evidence": {
                "workloads": {
                    "qurl_service_authority": {
                        "proof_policy_consumers_active": False,
                        "functions": [
                            {
                                "alias_arn": alias,
                                "version_arn": alias.replace(":blue", ":7"),
                            }
                        ],
                    }
                }
            },
        }
        with self.assertRaisesRegex(
            handshake.HandshakeError, "governed zero-spill rollout"
        ):
            handshake.select_ca_pm_alias(provenance)

    def test_descriptor_rejects_cross_run_replay(self):
        value = descriptor()
        self.assertEqual(handshake.validate_descriptor(value), value)
        value["controller_run_id"] = "124"
        with self.assertRaises(handshake.HandshakeError):
            handshake.validate_descriptor(value)

    def test_transport_descriptor_binds_exact_counter_sources(self):
        value = transport_descriptor()
        self.assertEqual(
            handshake.validate_transport_descriptor(value, descriptor()), value
        )
        value["qurl_service_log_groups"] = ["/foreign"]
        with self.assertRaises(handshake.HandshakeError):
            handshake.validate_transport_descriptor(value, descriptor())

    def test_checkpoint_binds_run_agent_cell_and_generation(self):
        value = descriptor()
        checkpoint = {
            "version": 1,
            "controller_run_id": "123",
            "controller_run_attempt": "1",
            "channel_id": value["channel_id"],
            "client_run_id": "456",
            "client_sha": "d" * 40,
            "correlation_id": value["correlation_id"],
            "agent_id": value["agent_id"],
            "observed_cell_id": "cell0",
            "assignment_generation": 1,
            "lease_expires_at": "2026-07-28T20:30:00Z",
            "warm_open_confirmed": True,
        }
        self.assertEqual(
            handshake.validate_checkpoint(
                checkpoint,
                value,
                client_run_id="456",
                client_sha="d" * 40,
            ),
            checkpoint,
        )
        checkpoint["correlation_id"] = checkpoint["correlation_id"].replace(
            "pre_removal", "post_removal"
        )
        with self.assertRaises(handshake.HandshakeError):
            handshake.validate_checkpoint(
                checkpoint,
                value,
                client_run_id="456",
                client_sha="d" * 40,
            )

    def test_move_must_advance_exact_observed_generation(self):
        value = descriptor()
        checkpoint = {"assignment_generation": 7}
        response = {
            "version": 1,
            "result": {
                "mutation": "move",
                "agent_id": value["agent_id"],
                "previous_cell_id": "cell0",
                "previous_assignment_generation": 7,
                "new_cell_id": "cell1",
                "new_assignment_generation": 8,
                "lease_expires_at": (
                    datetime(2026, 7, 28, 20, 0, tzinfo=timezone.utc)
                    + timedelta(seconds=handshake.ARM_LEASE_SECONDS)
                ).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "mutated_at": "2026-07-28T20:00:00Z",
            },
        }
        self.assertEqual(
            handshake.validate_mutation_response(
                response, "move", value, checkpoint
            ),
            response,
        )
        response["result"]["new_assignment_generation"] = 9
        with self.assertRaises(handshake.HandshakeError):
            handshake.validate_mutation_response(
                response, "move", value, checkpoint
            )

    def test_mutations_require_whole_second_exact_lease_transitions(self):
        value = descriptor()
        move = {
            "version": 1,
            "result": {
                "mutation": "move",
                "agent_id": value["agent_id"],
                "previous_cell_id": "cell0",
                "previous_assignment_generation": 7,
                "new_cell_id": "cell1",
                "new_assignment_generation": 8,
                "lease_expires_at": (
                    datetime(2026, 7, 28, 20, 0, tzinfo=timezone.utc)
                    + timedelta(seconds=handshake.ARM_LEASE_SECONDS)
                ).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "mutated_at": "2026-07-28T20:00:00Z",
            },
        }
        expire = {
            "version": 1,
            "result": {
                "mutation": "expire_lease",
                "agent_id": value["agent_id"],
                "lease_expires_at": "2026-07-28T20:01:30Z",
                "mutated_at": "2026-07-28T20:01:00Z",
            },
        }
        self.assertEqual(
            handshake.validate_mutation_response(
                expire, "expire_lease", value, move=move
            ),
            expire,
        )
        expire["result"]["mutated_at"] = "2026-07-28T20:01:00.000Z"
        with self.assertRaises(handshake.HandshakeError):
            handshake.validate_mutation_response(
                expire, "expire_lease", value, move=move
            )

    def test_transport_checkpoint_requires_bidirectional_udp_and_zero_http(self):
        value = transport_descriptor()
        now = datetime.now(timezone.utc).replace(microsecond=0)
        checkpoint = {
            "version": 1,
            "controller_run_id": "123",
            "controller_run_attempt": "1",
            "channel_id": value["channel_id"],
            "client_run_id": "456",
            "client_sha": "d" * 40,
            "correlation_id": value["correlation_id"],
            "agent_id": value["agent_id"],
            "capture_started_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "capture_ended_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "capture_sha256": "a" * 64,
            "capture_targets_sha256": "b" * 64,
            "captured_packet_count": 2,
            "udp_443_outbound": 1,
            "udp_443_inbound": 1,
            "http_trap_calls": 0,
            "observed_cell_ids": ["cell0", "cell1"],
            "nhp_udp_lifecycle_success": True,
        }
        self.assertEqual(
            handshake.validate_transport_checkpoint(
                checkpoint,
                value,
                client_run_id="456",
                client_sha="d" * 40,
            ),
            checkpoint,
        )
        checkpoint["http_trap_calls"] = 1
        with self.assertRaises(handshake.HandshakeError):
            handshake.validate_transport_checkpoint(
                checkpoint,
                value,
                client_run_id="456",
                client_sha="d" * 40,
            )

    def test_counter_parsers_count_only_exact_bound_routes(self):
        value = transport_descriptor()
        qurl_event = {
            "eventId": "q1",
            "ingestionTime": 2,
            "logStreamName": "qurl",
            "message": (
                '{"client_ip":"3.141.109.76","method":"POST",'
                '"msg":"http request","path":"/v1/agent/bootstrap","status":200}'
            ),
            "timestamp": 1,
        }
        relay_event = {
            "eventId": "r1",
            "ingestionTime": 2,
            "logStreamName": "relay",
            "message": (
                "INFO relay: proof request route=relay "
                "source_ip=3.141.109.76"
            ),
            "timestamp": 1,
        }
        original = handshake._filter_log_events
        try:
            handshake._filter_log_events = lambda group, **_: (
                [relay_event] if group == handshake.RELAY_LOG_GROUP else [qurl_event]
            )
            self.assertEqual(
                handshake._count_qurl_service_legacy_routes(
                    value, start_millis=0, end_millis=10
                ),
                2,
            )
            self.assertEqual(
                handshake._count_relay_routes(
                    value, start_millis=0, end_millis=10
                ),
                1,
            )
        finally:
            handshake._filter_log_events = original

    def test_complete_publishes_immutable_normalized_receipts(self):
        assignment = descriptor()
        transport = transport_descriptor()
        now = datetime.now(timezone.utc).replace(microsecond=0)
        arm = {
            "version": 1,
            "result": {
                "agent_id": assignment["agent_id"],
                "grant_correlation_id": assignment["correlation_id"],
                "lease_seconds": assignment["arm_lease_seconds"],
                "mutated_at": (now - timedelta(minutes=2)).strftime(
                    "%Y-%m-%dT%H:%M:%SZ"
                ),
                "mutation": "arm",
                "pinned_cell_id": assignment["pinned_cell_id"],
                "target_cell_id": assignment["target_cell_id"],
            },
        }
        checkpoint = {
            "agent_id": assignment["agent_id"],
            "assignment_generation": 7,
            "channel_id": assignment["channel_id"],
            "client_run_id": "456",
            "client_sha": "d" * 40,
            "controller_run_attempt": assignment["controller_run_attempt"],
            "controller_run_id": assignment["controller_run_id"],
            "correlation_id": assignment["correlation_id"],
            "lease_expires_at": (now + timedelta(minutes=20)).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
            "observed_cell_id": assignment["pinned_cell_id"],
            "version": 1,
            "warm_open_confirmed": True,
        }
        move_time = now - timedelta(minutes=1)
        move = {
            "version": 1,
            "result": {
                "agent_id": assignment["agent_id"],
                "lease_expires_at": (
                    move_time + timedelta(seconds=assignment["arm_lease_seconds"])
                ).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "mutated_at": move_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "mutation": "move",
                "new_assignment_generation": 8,
                "new_cell_id": assignment["target_cell_id"],
                "previous_assignment_generation": 7,
                "previous_cell_id": assignment["pinned_cell_id"],
            },
        }
        expire = {
            "version": 1,
            "result": {
                "agent_id": assignment["agent_id"],
                "lease_expires_at": (
                    now + timedelta(seconds=assignment["expire_lease_seconds"])
                ).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "mutated_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "mutation": "expire_lease",
            },
        }
        transport_checkpoint = {
            "agent_id": assignment["agent_id"],
            "capture_ended_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "capture_sha256": "a" * 64,
            "capture_started_at": (now - timedelta(seconds=10)).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
            "capture_targets_sha256": "b" * 64,
            "captured_packet_count": 2,
            "channel_id": assignment["channel_id"],
            "client_run_id": "456",
            "client_sha": "d" * 40,
            "controller_run_attempt": assignment["controller_run_attempt"],
            "controller_run_id": assignment["controller_run_id"],
            "correlation_id": assignment["correlation_id"],
            "http_trap_calls": 0,
            "nhp_udp_lifecycle_success": True,
            "observed_cell_ids": ["cell0", "cell1"],
            "udp_443_inbound": 1,
            "udp_443_outbound": 1,
            "version": 1,
        }
        checkpoint_raw = handshake._canonical(checkpoint)
        transport_checkpoint_raw = handshake._canonical(transport_checkpoint)
        encoded = base64.b64encode(
            handshake._canonical(
                {"arm": arm, "descriptor": assignment, "transport": transport}
            )
        ).decode()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            assignment_path = (root / "assignment.json").resolve()
            transport_path = (root / "transport.json").resolve()
            args = argparse.Namespace(
                assignment_receipt_output=assignment_path,
                client_run_id="456",
                client_sha="d" * 40,
                handshake_b64=encoded,
                timeout_seconds=30,
                transport_receipt_output=transport_path,
            )
            with (
                mock.patch.object(
                    handshake,
                    "_get_object",
                    side_effect=[checkpoint_raw, transport_checkpoint_raw],
                ),
                mock.patch.object(
                    handshake, "_invoke", side_effect=[move, expire]
                ),
                mock.patch.object(handshake, "_put_object"),
                mock.patch.object(
                    handshake,
                    "_observe_transport_counters",
                    return_value=(0, 0, now.strftime("%Y-%m-%dT%H:%M:%SZ")),
                ),
            ):
                handshake.complete(args)

            normalized_assignment = json.loads(assignment_path.read_bytes())
            normalized_transport = json.loads(transport_path.read_bytes())
            self.assertEqual(
                normalized_assignment["assigned_cells"], ["cell0", "cell1"]
            )
            self.assertEqual(normalized_assignment["client_run_id"], 456)
            self.assertEqual(
                normalized_assignment["checkpoint_sha256"],
                hashlib.sha256(checkpoint_raw).hexdigest(),
            )
            self.assertEqual(
                normalized_transport["capture_sha256"],
                transport_checkpoint["capture_sha256"],
            )
            self.assertTrue(normalized_transport["nhp_udp_lifecycle_success"])
            with self.assertRaises(handshake.HandshakeError):
                handshake._write_once(
                    assignment_path, handshake._canonical(normalized_assignment)
                )


class ArmLeaseStaysWithinTheAuthorityCeiling(unittest.TestCase):
    """The Authority REFUSES an over-long lease; it does not clamp it.

    ProofMutationService.validLeaseSeconds in layervai/qurl-service rejects any
    lease above repository.AgentAssignmentLeaseLifetime (30 minutes), returning
    ErrProofMutationInvalid -- which reaches this side only as an opaque
    {'code': 'invalid_request'}. ARM_LEASE_SECONDS was 2100, so every arm
    failed. The step had never executed before, so nothing caught it.
    """

    # Mirrors repository.AgentAssignmentLeaseLifetime (30 * time.Minute) in
    # layervai/qurl-service internal/repository/agent_placement.go.
    AUTHORITY_LEASE_CEILING_SECONDS = 1800

    def test_arm_lease_is_grantable(self) -> None:
        self.assertGreater(handshake.ARM_LEASE_SECONDS, 0)
        self.assertLessEqual(
            handshake.ARM_LEASE_SECONDS,
            self.AUTHORITY_LEASE_CEILING_SECONDS,
            "the Authority refuses this arm outright; raise "
            "AgentAssignmentLeaseLifetime in qurl-service first",
        )

    def test_expire_lease_is_grantable(self) -> None:
        self.assertGreater(handshake.EXPIRE_LEASE_SECONDS, 0)
        self.assertLessEqual(
            handshake.EXPIRE_LEASE_SECONDS,
            self.AUTHORITY_LEASE_CEILING_SECONDS,
        )

    def test_expire_shortens_the_arm_lease(self) -> None:
        """expire_lease exists to cut the arm lease short, so it must be less."""
        self.assertLess(
            handshake.EXPIRE_LEASE_SECONDS,
            handshake.ARM_LEASE_SECONDS,
        )


if __name__ == "__main__":
    unittest.main()
