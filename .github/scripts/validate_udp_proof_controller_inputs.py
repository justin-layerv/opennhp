#!/usr/bin/env python3
"""Select one attended UDP-proof dispatch from authenticated producer objects.

The trusted-main deployment producer's shared contract owns every topology,
runtime, candidate, and canonical-encoding check.  This module deliberately
adds only the controller's client-lineage rules and dispatch selection.
"""

from __future__ import annotations

import re
from typing import Any

RUN_ID_RE = re.compile(r"^[1-9][0-9]{0,19}$")
CLIENT_TARGETS = {
    "connector": {
        "repository": "layervai/qurl-connector",
        "workflow": "sandbox-smoke.yml",
        "repository_key": "qurl_connector",
    },
    "qurl_go": {
        "repository": "layervai/qurl-go",
        "workflow": "native-udp-sandbox.yml",
        "repository_key": "qurl_go",
    },
}


class ValidationError(ValueError):
    """Authenticated deployment objects select an invalid proof dispatch."""


def _workflow_identity(target: dict[str, str], repositories: dict[str, str]) -> str:
    return (
        f"{target['repository']}/.github/workflows/"
        f"{target['workflow']}@{repositories[target['repository_key']]}"
    )


def _workflow_group_identity(
    target: dict[str, str], candidates: dict[str, dict[str, str]]
) -> str:
    """The identity GitHub actually matches a runner group against.

    A client proof run is dispatched by BRANCH (`client_ref` below is the
    candidate's head_ref, and the dispatch sets head_branch from it), so the
    workflow ref GitHub records for that run is `refs/heads/<branch>` -- never
    the commit SHA. A runner group whose selected_workflows pin the SHA
    therefore matches nothing, and the job stays queued forever with an idle,
    correctly-labelled runner sitting next to it.

    The frozen-head guarantee does NOT live here. It is enforced separately
    against the producer artifact by the "Require the frozen client candidate
    heads" step, which compares _workflow_identity (SHA-form) to the pinned
    SHAs. This identity only scopes WHICH workflow may claim the runners.
    """
    return (
        f"{target['repository']}/.github/workflows/"
        f"{target['workflow']}@refs/heads/"
        f"{candidates[target['repository_key']]['head_ref']}"
    )


def select_dispatch(
    *,
    client: str,
    proof_phase: str,
    manifest: dict[str, Any],
    candidates: dict[str, Any],
    pre_removal_run_id: str,
) -> dict[str, str]:
    if client not in CLIENT_TARGETS:
        raise ValidationError("client must be connector or qurl_go")
    if proof_phase not in {"pre_removal", "post_removal"}:
        raise ValidationError("proof_phase must be pre_removal or post_removal")

    if proof_phase == "post_removal":
        if not RUN_ID_RE.fullmatch(pre_removal_run_id):
            raise ValidationError(
                "post_removal requires the selected client's pre-removal run ID"
            )
    elif pre_removal_run_id:
        raise ValidationError("pre_removal_run_id must be empty during pre_removal")

    repositories = manifest["repositories"]
    target = CLIENT_TARGETS[client]
    connector_target = CLIENT_TARGETS["connector"]
    qurl_go_target = CLIENT_TARGETS["qurl_go"]
    candidate_key = target["repository_key"]
    client_ref = candidates[candidate_key]["head_ref"]
    return {
        "connector_workflow_identity": _workflow_identity(
            connector_target, repositories
        ),
        "qurl_go_workflow_identity": _workflow_identity(qurl_go_target, repositories),
        "connector_workflow_group_identity": _workflow_group_identity(
            connector_target, candidates
        ),
        "qurl_go_workflow_group_identity": _workflow_group_identity(
            qurl_go_target, candidates
        ),
        "client_repository": target["repository"],
        "client_workflow": target["workflow"],
        "client_ref": client_ref,
        "client_sha": repositories[target["repository_key"]],
    }
