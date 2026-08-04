#!/usr/bin/env python3

from __future__ import annotations

import copy
import re
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
        """A dropped resource that still EXISTS is drift, not a resumption.

        prior_state lists every governed address, so the one missing from the
        plan is provably still alive — the case the drift check is for. The
        resumption path (missing because already destroyed) is covered by
        test_resumed_retirement_accepts_the_remainder.
        """
        prior = {
            "values": {
                "root_module": {
                    "resources": [
                        {"address": address}
                        for address in orchestrator.TERRAFORM_RETIREMENT_RESOURCES
                    ]
                }
            }
        }
        with self.assertRaisesRegex(
            producer.TerraformApplyReceiptError, "deletion set drift"
        ):
            producer.build_receipt(
                {
                    "resource_changes": exact_retirement_changes()[:-1],
                    "prior_state": prior,
                },
                saved_plan_sha256=PLAN_SHA256,
                run_id=RUN_ID,
                run_attempt=RUN_ATTEMPT,
                head_sha=HEAD_SHA,
            )

    def test_the_complete_retirement_still_emits_its_receipt(self) -> None:
        """The whole set in one plan is still the ordinary retirement apply.

        Kept from #3659 after its scope narrowing was reverted: the narrowing was
        wrong, but a direct assertion that a complete plan still emits a receipt
        naming the full canonical set is worth having on its own.
        """
        receipt = exact_receipt()
        self.assertIn(producer.BOOTSTRAP_ALB, receipt["approved_deletions"])
        self.assertEqual(
            sorted(receipt["approved_deletions"]),
            sorted(orchestrator.TERRAFORM_RETIREMENT_RESOURCES),
        )

    def test_normal_non_retirement_deletes_emit_nothing(self) -> None:
        for actions in (["delete"], ["delete", "create"], ["create", "delete"]):
            with self.subTest(actions=actions):
                self.assertIsNone(
                    producer.build_receipt(
                        {
                            "resource_changes": [
                                change(
                                    "module.nhp.module.qurl_service[0]."
                                    "aws_ecs_task_definition.qurl",
                                    actions,
                                )
                            ]
                        },
                        saved_plan_sha256=PLAN_SHA256,
                        run_id=RUN_ID,
                        run_attempt=RUN_ATTEMPT,
                        head_sha=HEAD_SHA,
                    )
                )

    def test_retirement_with_unapproved_pure_delete_fails_closed(self) -> None:
        """An unexplained DESTROY riding along with the retirement is refused."""
        with self.assertRaisesRegex(
            producer.TerraformApplyReceiptError,
            "unapproved deletion actions",
        ):
            producer.build_receipt(
                {
                    "resource_changes": exact_retirement_changes()
                    + [change("module.nhp.aws_s3_bucket.unrelated", ["delete"])]
                },
                saved_plan_sha256=PLAN_SHA256,
                run_id=RUN_ID,
                run_attempt=RUN_ATTEMPT,
                head_sha=HEAD_SHA,
            )

    def test_retirement_tolerates_ordinary_replacements(self) -> None:
        """A replacement is not a retirement, even during the retirement apply.

        This is not hypothetical. The real retirement apply carried
        `aws_ecs_task_definition.qurl must be replaced` — task definitions are
        immutable and replace on every image change — and the receipt rejected
        the whole apply for it. The producer's scope note always said ordinary
        replacements were out of scope; the early return implementing that only
        fired when NO retirement resource was present, i.e. everywhere except
        the one apply this receipt governs.
        """
        for actions in (["delete", "create"], ["create", "delete"]):
            with self.subTest(actions=actions):
                receipt = producer.build_receipt(
                    {
                        "resource_changes": exact_retirement_changes()
                        + [
                            change(
                                "module.nhp.module.qurl_service[0]."
                                "aws_ecs_task_definition.qurl",
                                actions,
                            )
                        ]
                    },
                    saved_plan_sha256=PLAN_SHA256,
                    run_id=RUN_ID,
                    run_attempt=RUN_ATTEMPT,
                    head_sha=HEAD_SHA,
                )
                self.assertIsNotNone(receipt)
                # The replacement is tolerated, never recorded as approved.
                self.assertNotIn(
                    "module.nhp.module.qurl_service[0]."
                    "aws_ecs_task_definition.qurl",
                    receipt["approved_deletions"],
                )

    def _prior_state(self, addresses):
        return {
            "values": {
                "root_module": {
                    "resources": [{"address": a} for a in addresses]
                }
            }
        }

    def test_resumed_retirement_accepts_the_remainder(self) -> None:
        """A retirement may span applies; the remainder plan is still valid.

        The real sandbox apply destroyed 41 of 43 resources and then failed
        emptying the versioned access-log bucket on a missing IAM verb. The
        remainder plan legitimately contained only what was left, and requiring
        the whole set every time made the retirement unfinishable.
        """
        bootstrap = "module.nhp.module.bootstrap_alb[0]"
        remainder = [
            change(f"{bootstrap}.aws_s3_bucket.alb_access_logs", ["delete"])
        ]
        receipt = producer.build_receipt(
            {
                "resource_changes": remainder,
                # Only the bootstrap module survives; everything else already went.
                "prior_state": self._prior_state(
                    [f"{bootstrap}.aws_s3_bucket.alb_access_logs"]
                ),
            },
            saved_plan_sha256=PLAN_SHA256,
            run_id=RUN_ID,
            run_attempt=RUN_ATTEMPT,
            head_sha=HEAD_SHA,
        )
        self.assertIsNotNone(receipt)
        # The receipt still attests the canonical retirement set.
        self.assertEqual(
            receipt["approved_deletions"],
            list(orchestrator.TERRAFORM_RETIREMENT_RESOURCES),
        )

    def test_completed_retirement_still_emits_a_receipt(self) -> None:
        """Once the retirement is done, no plan deletes anything governed again.

        The producer used to return None for that shape, which meant the receipt
        could only be produced while the retirement was UNFINISHED -- so finishing
        it left post_removal with no obtainable input, forever. Prior state with
        every governed address absent is the proof that it is complete.
        """
        receipt = producer.build_receipt(
            {
                "resource_changes": [
                    change("module.nhp.aws_ecs_service.server", ["update"])
                ],
                "prior_state": self._prior_state(
                    ["module.nhp.aws_ecs_service.server"]
                ),
            },
            saved_plan_sha256=PLAN_SHA256,
            run_id=RUN_ID,
            run_attempt=RUN_ATTEMPT,
            head_sha=HEAD_SHA,
        )
        self.assertIsNotNone(receipt)
        self.assertEqual(receipt["phase"], "post_removal")
        self.assertEqual(
            receipt["approved_deletions"],
            list(orchestrator.TERRAFORM_RETIREMENT_RESOURCES),
        )

    def test_completion_requires_prior_state(self) -> None:
        """No prior state cannot prove absence, so it is not completion."""
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

    def test_any_surviving_governed_address_is_not_completion(self) -> None:
        """One governed resource still alive means an ordinary, pre-retirement deploy.

        Covered per address so a future addition to the governed set cannot be
        silently certified as retired while it is still standing.
        """
        for address in orchestrator.TERRAFORM_RETIREMENT_RESOURCES:
            with self.subTest(address=address):
                self.assertIsNone(
                    producer.build_receipt(
                        {
                            "resource_changes": [
                                change(
                                    "module.nhp.aws_ecs_service.server",
                                    ["update"],
                                )
                            ],
                            "prior_state": self._prior_state([address]),
                        },
                        saved_plan_sha256=PLAN_SHA256,
                        run_id=RUN_ID,
                        run_attempt=RUN_ATTEMPT,
                        head_sha=HEAD_SHA,
                    )
                )

    def test_a_surviving_bootstrap_alb_child_is_not_completion(self) -> None:
        """The ALB is a module: a live child keeps the retirement unfinished."""
        self.assertIsNone(
            producer.build_receipt(
                {
                    "resource_changes": [
                        change("module.nhp.aws_ecs_service.server", ["update"])
                    ],
                    "prior_state": self._prior_state(
                        [f"{producer.BOOTSTRAP_ALB}.aws_s3_bucket.alb_access_logs"]
                    ),
                },
                saved_plan_sha256=PLAN_SHA256,
                run_id=RUN_ID,
                run_attempt=RUN_ATTEMPT,
                head_sha=HEAD_SHA,
            )
        )

    def test_missing_deletion_still_present_in_state_fails_closed(self) -> None:
        """Absent from the plan but alive in state is drift, not resumption."""
        bootstrap = "module.nhp.module.bootstrap_alb[0]"
        survivor = "module.nhp.aws_secretsmanager_secret.agent_otp_pepper"
        with self.assertRaisesRegex(
            producer.TerraformApplyReceiptError, re.escape(survivor)
        ):
            producer.build_receipt(
                {
                    "resource_changes": [
                        change(f"{bootstrap}.aws_s3_bucket.alb_access_logs", ["delete"])
                    ],
                    "prior_state": self._prior_state(
                        [f"{bootstrap}.aws_s3_bucket.alb_access_logs", survivor]
                    ),
                },
                saved_plan_sha256=PLAN_SHA256,
                run_id=RUN_ID,
                run_attempt=RUN_ATTEMPT,
                head_sha=HEAD_SHA,
            )

    def test_partial_deletion_without_prior_state_fails_closed(self) -> None:
        """No prior state cannot prove already-applied, so it must not pass."""
        bootstrap = "module.nhp.module.bootstrap_alb[0]"
        with self.assertRaisesRegex(
            producer.TerraformApplyReceiptError, "omits prior state"
        ):
            producer.build_receipt(
                {
                    "resource_changes": [
                        change(f"{bootstrap}.aws_s3_bucket.alb_access_logs", ["delete"])
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
            mock.patch.object(
                collector,
                "_gh_json",
                side_effect=[run, {"status": "behind"}, artifacts],
            ),
            mock.patch.object(collector, "_run_bounded", return_value=archive),
        ):
            observed = collector.read_authenticated_terraform_apply_receipt(
                RUN_ID, expected_head_sha=HEAD_SHA
            )
        self.assertEqual(observed, exact_receipt())

    def test_accepts_an_apply_main_has_moved_past(self) -> None:
        """The whole point: sandbox runs a commit that is BEHIND main.

        The previous fixtures held run/receipt head_sha equal to
        expected_head_sha, which is not what "behind" means -- an ancestor
        differs from the tip. That internal inconsistency hid a transitive
        equality: the receipt was validated against expected_head_sha, and since
        the apply stamps the receipt with its OWN github.sha, that re-imposed
        run["head_sha"] == main tip and nullified the reachability check.

        Here they genuinely differ, so this fails on any build that re-couples
        the receipt's identity to main's tip.
        """
        archive = receipt_archive(exact_receipt())
        run, artifacts = self.metadata(f"sha256:{hashlib.sha256(archive).hexdigest()}")
        main_tip = "c" * 40
        self.assertNotEqual(run["head_sha"], main_tip)
        with (
            mock.patch.object(
                collector,
                "_gh_json",
                side_effect=[run, {"status": "behind"}, artifacts],
            ),
            mock.patch.object(collector, "_run_bounded", return_value=archive),
        ):
            observed = collector.read_authenticated_terraform_apply_receipt(
                RUN_ID, expected_head_sha=main_tip
            )
        self.assertEqual(observed, exact_receipt())

    def test_rejects_an_apply_carrying_code_main_never_took(self) -> None:
        """"ahead"/"diverged" is still refused -- reachability is the judge."""
        for status in ("ahead", "diverged"):
            with self.subTest(status=status):
                archive = receipt_archive(exact_receipt())
                run, artifacts = self.metadata(
                    f"sha256:{hashlib.sha256(archive).hexdigest()}"
                )
                with (
                    mock.patch.object(
                        collector,
                        "_gh_json",
                        side_effect=[run, {"status": status}, artifacts],
                    ),
                    mock.patch.object(
                        collector, "_run_bounded", return_value=archive
                    ),
                ):
                    with self.assertRaises(collector.OrchestratorEvidenceError):
                        collector.read_authenticated_terraform_apply_receipt(
                            RUN_ID, expected_head_sha="c" * 40
                        )

    def test_rejects_archive_bytes_that_do_not_match_github_digest(self) -> None:
        archive = receipt_archive(exact_receipt())
        run, artifacts = self.metadata(f"sha256:{'0' * 64}")
        with (
            mock.patch.object(
                collector,
                "_gh_json",
                side_effect=[run, {"status": "behind"}, artifacts],
            ),
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
