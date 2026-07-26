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


def select_dispatch(
    *,
    client: str,
    proof_phase: str,
    manifest: dict[str, Any],
    candidates: dict[str, Any],
    connector_proof_run_id: str,
    pre_removal_run_id: str,
) -> dict[str, str]:
    if client not in CLIENT_TARGETS:
        raise ValidationError("client must be connector or qurl_go")
    if proof_phase not in {"pre_removal", "post_removal"}:
        raise ValidationError("proof_phase must be pre_removal or post_removal")

    if client == "qurl_go":
        if not RUN_ID_RE.fullmatch(connector_proof_run_id):
            raise ValidationError(
                "qurl_go requires an exact successful Connector proof run ID"
            )
    elif connector_proof_run_id:
        raise ValidationError(
            "connector_proof_run_id must be empty for a Connector proof"
        )

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
        "client_repository": target["repository"],
        "client_workflow": target["workflow"],
        "client_ref": client_ref,
        "client_sha": repositories[target["repository_key"]],
    }
