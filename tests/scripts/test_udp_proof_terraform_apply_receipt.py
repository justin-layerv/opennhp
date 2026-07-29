#!/usr/bin/env python3

from __future__ import annotations

import copy
import hashlib
import io
import sys
import unittest
import zipfile
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / ".github" / "scripts"
sys.path.insert(0, str(SCRIPTS))

import collect_udp_proof_orchestrator_evidence as collector  # noqa: E402
import produce_udp_proof_terraform_apply_receipt as producer  # noqa: E402
import udp_proof_orchestrator_contract as orchestrator  # noqa: E402


RUN_ID = 12345
RUN_ATTEMPT = 2
HEAD_SHA = "a" * 40
PLAN_SHA256 = "b" * 64


def change(address: str, actions: list[str]) -> dict[str, object]:
    return {"address": address, "change": {"actions": actions}}


def exact_retirement_changes() -> list[dict[str, object]]:
    result = []
    for address in orchestrator.TERRAFORM_RETIREMENT_RESOURCES:
        if address == "module.nhp.module.bootstrap_alb[0]":
            address = f"{address}.aws_lb.this[0]"
        result.append(change(address, ["delete"]))
    return result


def exact_receipt() -> dict[str, object]:
    receipt = producer.build_receipt(
        {"resource_changes": exact_retirement_changes()},
        saved_plan_sha256=PLAN_SHA256,
        run_id=RUN_ID,
        run_attempt=RUN_ATTEMPT,
        head_sha=HEAD_SHA,
    )
    if receipt is None:
        raise AssertionError("exact retirement plan did not emit a receipt")
    return receipt


def receipt_archive(receipt: dict[str, object]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(
            orchestrator.TERRAFORM_APPLY_RECEIPT_FILE,
            orchestrator.canonical_bytes(receipt),
        )
    return buffer.getvalue()


class SavedPlanReceiptTest(unittest.TestCase):
    def test_exact_retirement_plan_emits_exact_receipt(self) -> None:
        receipt = exact_receipt()
        self.assertEqual(
            receipt["approved_deletions"],
            list(orchestrator.TERRAFORM_RETIREMENT_RESOURCES),
        )
        self.assertEqual(receipt["saved_plan_sha256"], PLAN_SHA256)

    def test_normal_non_destructive_plan_emits_nothing(self) -> None:
        self.assertIsNone(
            producer.build_receipt(
                {
                    "resource_changes": [
                        change("module.nhp.aws_ecs_service.server", ["update"])
                    ]
                },
                saved_plan_sha256=PLAN_SHA256,
                run_id=RUN_ID,
                run_attempt=RUN_ATTEMPT,
                head_sha=HEAD_SHA,
            )
        )

    def test_partial_retirement_deletion_fails_closed(self) -> None:
        with self.assertRaisesRegex(
            producer.TerraformApplyReceiptError, "deletion set drift"
        ):
            producer.build_receipt(
                {"resource_changes": exact_retirement_changes()[:-1]},
                saved_plan_sha256=PLAN_SHA256,
                run_id=RUN_ID,
                run_attempt=RUN_ATTEMPT,
                head_sha=HEAD_SHA,
            )

    def test_every_unapproved_delete_action_fails_closed(self) -> None:
        for actions in (["delete"], ["delete", "create"], ["create", "delete"]):
            with self.subTest(actions=actions):
                with self.assertRaisesRegex(
                    producer.TerraformApplyReceiptError,
                    "unapproved deletion actions",
                ):
                    producer.build_receipt(
                        {
                            "resource_changes": [
                                change("module.nhp.aws_s3_bucket.unrelated", actions)
                            ]
                        },
                        saved_plan_sha256=PLAN_SHA256,
                        run_id=RUN_ID,
                        run_attempt=RUN_ATTEMPT,
                        head_sha=HEAD_SHA,
                    )

    def test_approved_target_replacement_fails_closed(self) -> None:
        changes = exact_retirement_changes()
        changes[0]["change"] = {"actions": ["delete", "create"]}
        with self.assertRaisesRegex(
            producer.TerraformApplyReceiptError, "must be a pure deletion"
        ):
            producer.build_receipt(
                {"resource_changes": changes},
                saved_plan_sha256=PLAN_SHA256,
                run_id=RUN_ID,
                run_attempt=RUN_ATTEMPT,
                head_sha=HEAD_SHA,
            )

    def test_shared_native_otp_and_status_resources_are_not_approved(self) -> None:
        excluded = {
            "module.nhp.aws_cloudwatch_metric_alarm.agent_otp_bounce",
            "module.nhp.aws_cloudwatch_metric_alarm.agent_relay_otp_reject_rate_limited",
            "module.nhp.aws_sesv2_configuration_set.agent_otp",
            "module.nhp.module.compute.aws_vpc_security_group_ingress_rule.server_http_plugins",
            "module.nhp.module.compute.aws_vpc_security_group_ingress_rule.server_http_traefik",
            "module.nhp.time_sleep.bootstrap_alb_iam_propagation",
        }
        self.assertTrue(
            excluded.isdisjoint(orchestrator.TERRAFORM_RETIREMENT_RESOURCES)
        )

    def test_receipt_validator_rejects_influence_bearing_drift(self) -> None:
        receipt = exact_receipt()
        mutations = (
            lambda value: value.update(saved_plan_sha256="not-a-digest"),
            lambda value: value["producer"].update(head_sha="c" * 40),
            lambda value: value["approved_deletions"].pop(),
        )
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                candidate = copy.deepcopy(receipt)
                mutate(candidate)
                with self.assertRaises(orchestrator.OrchestratorContractError):
                    orchestrator.validate_terraform_apply_receipt(
                        candidate,
                        run_id=RUN_ID,
                        run_attempt=RUN_ATTEMPT,
                        head_sha=HEAD_SHA,
                    )


class AuthenticatedReceiptReadTest(unittest.TestCase):
    def metadata(self, digest: str) -> tuple[dict[str, object], dict[str, object]]:
        run = {
            "id": RUN_ID,
            "path": orchestrator.TERRAFORM_APPLY_WORKFLOW_PATH,
            "event": "push",
            "status": "completed",
            "conclusion": "success",
            "head_branch": "main",
            "head_sha": HEAD_SHA,
            "run_attempt": RUN_ATTEMPT,
            "repository": {"id": 777, "full_name": collector.NHP_REPOSITORY},
            "head_repository": {"id": 777, "full_name": collector.NHP_REPOSITORY},
        }
        artifacts = {
            "artifacts": [
                {
                    "id": 888,
                    "name": (
                        f"{orchestrator.TERRAFORM_APPLY_RECEIPT_ARTIFACT_PREFIX}-"
                        f"{RUN_ID}-{RUN_ATTEMPT}"
                    ),
                    "expired": False,
                    "digest": digest,
                    "size_in_bytes": 512,
                }
            ]
        }
        return run, artifacts

    def test_accepts_exact_authenticated_archive(self) -> None:
        archive = receipt_archive(exact_receipt())
        run, artifacts = self.metadata(f"sha256:{hashlib.sha256(archive).hexdigest()}")
        with (
            mock.patch.object(collector, "_gh_json", side_effect=[run, artifacts]),
            mock.patch.object(collector, "_run_bounded", return_value=archive),
        ):
            observed = collector.read_authenticated_terraform_apply_receipt(
                RUN_ID, expected_head_sha=HEAD_SHA
            )
        self.assertEqual(observed, exact_receipt())

    def test_rejects_archive_bytes_that_do_not_match_github_digest(self) -> None:
        archive = receipt_archive(exact_receipt())
        run, artifacts = self.metadata(f"sha256:{'0' * 64}")
        with (
            mock.patch.object(collector, "_gh_json", side_effect=[run, artifacts]),
            mock.patch.object(collector, "_run_bounded", return_value=archive),
            self.assertRaisesRegex(
                collector.OrchestratorEvidenceError,
                "digest does not match",
            ),
        ):
            collector.read_authenticated_terraform_apply_receipt(
                RUN_ID, expected_head_sha=HEAD_SHA
            )


class ApplyWorkflowWiringTest(unittest.TestCase):
    def test_receipt_is_prepared_from_saved_plan_and_uploaded_only_after_apply(
        self,
    ) -> None:
        workflow = (ROOT / ".github" / "workflows" / "build-and-push.yml").read_text(
            encoding="utf-8"
        )
        prepare = workflow.index("- name: Prepare UDP retirement apply receipt")
        apply = workflow.index("- name: Terraform Apply", prepare)
        upload = workflow.index(
            "- name: Upload authenticated UDP retirement apply receipt", apply
        )
        self.assertLess(prepare, apply)
        self.assertLess(apply, upload)
        prepared = workflow[prepare:apply]
        uploaded = workflow[upload : workflow.index("\n      - name:", upload + 1)]
        self.assertIn("--plan-json plan-show.json", prepared)
        self.assertIn("--saved-plan tfplan", prepared)
        self.assertIn(
            "if: steps.udp-retirement-receipt.outputs.produced == 'true'",
            uploaded,
        )
        self.assertIn(
            "udp-proof-terraform-apply-${{ github.run_id }}-${{ github.run_attempt }}",
            uploaded,
        )


if __name__ == "__main__":
    unittest.main()
