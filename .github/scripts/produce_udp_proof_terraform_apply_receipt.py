#!/usr/bin/env python3
"""Emit a non-secret receipt for one exact saved retirement plan.

The build-and-push workflow creates this before apply and uploads it only after
that exact `tfplan` applies successfully. Normal sandbox deploys emit nothing.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any

import udp_proof_deployment_contract as deployment
import udp_proof_orchestrator_contract as orchestrator


MAX_PLAN_BYTES = 128 * 1024 * 1024


class TerraformApplyReceiptError(orchestrator.OrchestratorContractError):
    """The saved plan is not the exact reviewed retirement deletion set."""


def _read_bounded(path: Path, name: str) -> bytes:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise TerraformApplyReceiptError(f"could not read {name}") from exc
    if not raw or len(raw) > MAX_PLAN_BYTES:
        raise TerraformApplyReceiptError(
            f"{name} must contain 1..{MAX_PLAN_BYTES} bytes"
        )
    return raw


# The HTTP bootstrap ALB is a whole MODULE, not a single retirement artifact.
# Ordinary work legitimately deletes resources inside it, so on its own it does
# not identify the retirement apply -- see the scope note in build_receipt.
BOOTSTRAP_ALB = "module.nhp.module.bootstrap_alb[0]"


def _logical_retirement_address(address: str) -> str | None:
    bootstrap = BOOTSTRAP_ALB
    if address.startswith(f"{bootstrap}."):
        return bootstrap
    for expected in orchestrator.TERRAFORM_RETIREMENT_RESOURCES:
        if address == expected or re.fullmatch(
            rf"{re.escape(expected)}\[[^\]\r\n]+\]", address
        ):
            return expected
    return None


def _prior_state_addresses(plan_value: dict[str, Any]) -> "set[str] | None":
    """Every resource address Terraform recorded as existing before this plan.

    Returns None when the plan carries no prior state, so callers can fail
    closed rather than read "no state" as "everything is already destroyed".
    """
    prior = plan_value.get("prior_state")
    if not isinstance(prior, dict):
        return None
    values = prior.get("values")
    if not isinstance(values, dict):
        return None
    root = values.get("root_module")
    if not isinstance(root, dict):
        return None

    addresses: set[str] = set()

    def walk(module: dict[str, Any]) -> None:
        for resource in module.get("resources") or ():
            if isinstance(resource, dict) and isinstance(
                resource.get("address"), str
            ):
                addresses.add(resource["address"])
        for child in module.get("child_modules") or ():
            if isinstance(child, dict):
                walk(child)

    walk(root)
    return addresses


def _retirement_address_present(expected: str, prior: "set[str]") -> bool:
    """True when a governed retirement address still exists in prior state."""
    prefix = f"{expected}."
    for address in prior:
        if address == expected or address.startswith(prefix):
            return True
        if re.fullmatch(rf"{re.escape(expected)}\[[^\]\r\n]+\]", address):
            return True
    return False


def build_receipt(
    plan_value: Any,
    *,
    saved_plan_sha256: str,
    run_id: int,
    run_attempt: int,
    head_sha: str,
) -> dict[str, Any] | None:
    if not isinstance(plan_value, dict):
        raise TerraformApplyReceiptError("Terraform plan JSON must be an object")
    changes = plan_value.get("resource_changes")
    if not isinstance(changes, list):
        raise TerraformApplyReceiptError(
            "Terraform plan JSON must contain resource_changes"
        )

    deletions: list[tuple[str, list[str], str | None]] = []
    for index, raw_change in enumerate(changes):
        if not isinstance(raw_change, dict):
            raise TerraformApplyReceiptError(
                f"Terraform resource_changes[{index}] must be an object"
            )
        address = raw_change.get("address")
        change = raw_change.get("change")
        if not isinstance(address, str) or not isinstance(change, dict):
            raise TerraformApplyReceiptError(
                f"Terraform resource_changes[{index}] identity is invalid"
            )
        actions = change.get("actions")
        if not isinstance(actions, list) or not all(
            isinstance(action, str) for action in actions
        ):
            raise TerraformApplyReceiptError(
                f"Terraform resource_changes[{index}] actions are invalid"
            )
        if "delete" not in actions:
            continue
        logical = _logical_retirement_address(address)
        # Ordinary Terraform replacements carry a delete action paired with a
        # create, and are not retirements. Skip them here rather than relying
        # on the early return below, which only excludes them while NO
        # retirement resource is in the plan — that is, everywhere except the
        # one apply this receipt exists to govern. An ECS task definition is
        # immutable and replaces on every image change, so the retirement apply
        # was guaranteed to carry one and be rejected for it.
        #
        # Replacement of a GOVERNED retirement address is a different thing and
        # stays in scope: the loop below still rejects it as not-a-pure-deletion.
        if logical is None and "create" in actions:
            continue
        deletions.append((address, actions, logical))

    # This producer runs on every sandbox apply, but only governs the exact
    # one-time UDP retirement. A plan with no retirement resource in it is out
    # of scope entirely.
    #
    # bootstrap_alb is deliberately NOT excluded here. #3659 excluded it, on the
    # theory that a lone deletion inside that module is ordinary work rather than
    # the retirement. That is wrong: the retirement's FINAL apply is exactly a
    # bootstrap_alb-only plan -- the real one destroyed 41 of 43 resources and
    # left the versioned access-log bucket -- so excluding it means the last
    # apply of the retirement emits no governed receipt at all.
    #
    # The #3657 red that motivated #3659 is already fixed correctly below, by
    # prior state: an address may be missing from the plan only when it is also
    # gone from state. That answers "is this the retirement resuming, or an
    # unrelated change?" with evidence instead of a heuristic.
    if not any(logical is not None for _, _, logical in deletions):
        # This is also the shape of every plan AFTER the retirement finishes:
        # nothing governed left to delete. Returning None unconditionally made
        # the receipt producible only while the retirement was still UNFINISHED,
        # so the moment it completed, post_removal -- the phase whose entire
        # premise is that the HTTP surface is gone -- lost its only input and
        # became permanently unreachable. The receipt exists to certify that the
        # retirement happened under governance; "it is provably complete" says
        # that at least as strongly as "some of it is in this plan".
        #
        # Out of scope everywhere else, exactly as before: a plan with no prior
        # state cannot prove absence, and any governed address still alive means
        # this is an ordinary deploy with the retirement not yet done.
        if not _retirement_is_complete(plan_value):
            return None
        return _receipt(
            saved_plan_sha256=saved_plan_sha256,
            run_id=run_id,
            run_attempt=run_attempt,
            head_sha=head_sha,
        )

    approved: set[str] = set()
    unapproved_deletions: list[str] = []
    for address, actions, logical in deletions:
        if logical is None:
            unapproved_deletions.append(address)
        elif actions == ["delete"]:
            approved.add(logical)
        else:
            raise TerraformApplyReceiptError(
                f"retirement resource {address} must be a pure deletion, got {actions}"
            )

    if unapproved_deletions:
        raise TerraformApplyReceiptError(
            "Terraform plan includes unapproved deletion actions "
            f"{sorted(unapproved_deletions)}"
        )
    expected = set(orchestrator.TERRAFORM_RETIREMENT_RESOURCES)
    extra = sorted(approved - expected)
    missing = sorted(expected - approved)
    if extra:
        raise TerraformApplyReceiptError(
            f"retirement plan deletion set drift; missing={missing}, extra={extra}"
        )
    if missing:
        # The retirement can span more than one apply. The first sandbox apply
        # destroyed 41 of 43 resources and then failed emptying the versioned
        # access-log bucket on a missing IAM verb; the remainder plan legitimately
        # contains only what is left. Requiring the WHOLE set in every plan made
        # that remainder unappliable and the retirement unfinishable.
        #
        # A governed address may be absent from this plan only when it is also
        # absent from prior state — already destroyed. Absent from the plan while
        # still present in state is real drift and still fails closed. A plan with
        # no prior state at all cannot prove either way, so it fails closed too.
        prior = _prior_state_addresses(plan_value)
        if prior is None:
            raise TerraformApplyReceiptError(
                "retirement plan omits prior state, so a partial deletion set "
                f"cannot be proved already-applied; missing={missing}"
            )
        unfinished = sorted(
            address
            for address in missing
            if _retirement_address_present(address, prior)
        )
        if unfinished:
            raise TerraformApplyReceiptError(
                "retirement plan deletion set drift; "
                f"missing={unfinished}, extra=[]"
            )

    return _receipt(
        saved_plan_sha256=saved_plan_sha256,
        run_id=run_id,
        run_attempt=run_attempt,
        head_sha=head_sha,
    )


def _retirement_is_complete(plan_value: dict[str, Any]) -> bool:
    """True when prior state proves every governed address is already gone.

    Same evidence the resumption path above already trusts, read for the
    opposite conclusion. No prior state cannot prove absence, so it is not
    completion.
    """
    prior = _prior_state_addresses(plan_value)
    if prior is None:
        return False
    return not any(
        _retirement_address_present(address, prior)
        for address in orchestrator.TERRAFORM_RETIREMENT_RESOURCES
    )


def _receipt(
    *,
    saved_plan_sha256: str,
    run_id: int,
    run_attempt: int,
    head_sha: str,
) -> dict[str, Any]:
    receipt = {
        "schema_version": orchestrator.TERRAFORM_APPLY_RECEIPT_SCHEMA_VERSION,
        "gate": orchestrator.GATE,
        "phase": "post_removal",
        "producer": {
            "repository": "layervai/nhp",
            "workflow_path": orchestrator.TERRAFORM_APPLY_WORKFLOW_PATH,
            "run_id": run_id,
            "run_attempt": run_attempt,
            "head_sha": head_sha,
        },
        "saved_plan_sha256": saved_plan_sha256,
        "approved_deletions": list(orchestrator.TERRAFORM_RETIREMENT_RESOURCES),
    }
    return orchestrator.validate_terraform_apply_receipt(
        receipt,
        run_id=run_id,
        run_attempt=run_attempt,
        head_sha=head_sha,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--plan-json", type=Path, required=True)
    parser.add_argument("--saved-plan", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--github-output", type=Path, required=True)
    parser.add_argument("--run-id", type=int, required=True)
    parser.add_argument("--run-attempt", type=int, required=True)
    parser.add_argument("--head-sha", required=True)
    args = parser.parse_args()
    try:
        raw_plan_json = _read_bounded(args.plan_json, "Terraform plan JSON")
        saved_plan = _read_bounded(args.saved_plan, "Terraform saved plan")
        try:
            plan_value = json.loads(
                raw_plan_json.decode("utf-8"),
                object_pairs_hook=deployment._reject_duplicate_keys,
                parse_constant=deployment._reject_nonfinite,
                parse_float=deployment._parse_finite_float,
            )
        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
            deployment.ContractError,
        ) as exc:
            raise TerraformApplyReceiptError("Terraform plan JSON is invalid") from exc
        receipt = build_receipt(
            plan_value,
            saved_plan_sha256=hashlib.sha256(saved_plan).hexdigest(),
            run_id=args.run_id,
            run_attempt=args.run_attempt,
            head_sha=args.head_sha,
        )
        with args.github_output.open("a", encoding="utf-8") as output:
            if receipt is None:
                output.write("produced=false\n")
                return 0
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_bytes(orchestrator.canonical_bytes(receipt))
            output.write("produced=true\n")
    except deployment.ContractError as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
