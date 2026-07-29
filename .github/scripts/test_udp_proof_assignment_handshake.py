import importlib.util
import json
import sys
import unittest
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
        "arm_lease_seconds": 2100,
        "expire_lease_seconds": 30,
        "arm_request_id": "a" * 64,
        "move_request_id": "b" * 64,
        "expire_request_id": "c" * 64,
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
                "lease_expires_at": "2026-07-28T20:35:00Z",
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
                "lease_expires_at": "2026-07-28T20:35:00Z",
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


if __name__ == "__main__":
    unittest.main()
