#!/usr/bin/env python3
"""Verify the immutable sandbox Authority basis and emit ephemeral tfvars.

The manifest deliberately omits evidence references.  Their source commit and
digest are properties of the committed blob itself, so embedding them in that
blob would create a circular self-reference.  This checker requires a complete
Git history, derives the last commit that changed the path, verifies that
commit's regular-file bytes against the checkout, and only then injects the
reference into a generated Terraform variable file.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any, NoReturn


SCHEMA_VERSION = 1
REPOSITORY = "layervai/nhp"
MODE = "sandbox-exact-main"
MANIFEST_PREFIX = PurePosixPath("docs/evidence/connector-authority/v1")
EXPECTED_ENVIRONMENT = "sandbox"
EXPECTED_ACCOUNT_ID = "767397897469"
EXPECTED_REGION = "us-east-2"
EXPECTED_PARTITION = "aws"
EXPECTED_REPOSITORY_URL = (
    "767397897469.dkr.ecr.us-east-2.amazonaws.com/"
    "layerv/qurl-connector-authority"
)
EXPECTED_DIGEST_PARAMETER = (
    "/sandbox/nhp/control/connector-authority/image-digest"
)
EXPECTED_QAT1_ALIAS = (
    "arn:aws:kms:us-east-2:767397897469:"
    "alias/layerv-nhp-sandbox-control-qat1"
)
EXPECTED_QAT1_RAW_KEY = (
    "arn:aws:kms:us-east-2:767397897469:"
    "key/90bcbd44-48aa-4489-aee9-8ce86027024a"
)
EXPECTED_REDIS_NAME = "layerv-nhp-sandbox-control-otp"
EXPECTED_REDIS_ENDPOINT = (
    "layerv-nhp-sandbox-control-otp-9bd8jz."
    "serverless.use2.cache.amazonaws.com:6379"
)
EXPECTED_HUB_OPERATIONS = {
    "issue_assignment": "ia",
    "refresh_assignment": "ra",
    "issue_credential_recovery": "icr",
}
EXPECTED_CELL_OPERATIONS = {
    "issue_registration_otp",
    "activate_registration",
    "complete_registration",
    "complete_credential_recovery",
}
TOP_KEYS = {"schema_version", "contract"}
CONTRACT_KEYS = {
    "schema_version",
    "phase",
    "selected_authority_color",
    "provisioned_cells",
    "qat1_kid",
    "global",
    "functions",
}
GLOBAL_KEYS = {
    "environment",
    "aws_partition",
    "aws_account_id",
    "aws_region",
    "authority_repository_url",
    "authority_digest_parameter_name",
    "authority_image_digest",
    "qat1_raw_key_arn",
    "qat1_alias_arn",
    "otp_redis_cache_name",
    "otp_redis_endpoint",
    "regional_lambda_concurrency_quota",
    "non_authority_reserved_concurrency",
    "retained_unreserved_concurrency",
    "dependency_headroom",
    "caller_capacity",
}
DEPENDENCY_KEYS = {
    "dynamodb_max_in_flight",
    "kms_max_in_flight",
    "redis_max_connections",
    "ses_max_in_flight",
}
CALLER_CAPACITY_KEYS = {"hub_workers", "cell_workers"}
WORKER_KEYS = {"max_replicas", "preinvoke_limits", "preinvoke_rate_limits"}
RATE_KEYS = {"burst", "refill_per_second"}
FUNCTION_KEYS = {
    "steady_provisioned_concurrency",
    "steady_reserved_concurrency",
    "rollout_active_provisioned_concurrency",
    "rollout_standby_provisioned_concurrency",
    "rollout_reserved_concurrency",
    "max_caller_in_flight",
    "max_caller_requests_per_second",
    "rollback_retention_seconds",
}
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
IMAGE_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
KEY_ARN = re.compile(
    r"^arn:aws:kms:us-east-2:767397897469:"
    r"key/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
KID = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
CELL_ID = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
REDIS_ENDPOINT = re.compile(
    r"^layerv-nhp-sandbox-control-otp-[a-z0-9]+"
    r"\.serverless\.use2\.cache\.amazonaws\.com:6379$"
)


class ContractError(ValueError):
    """A fail-closed manifest, Git, or schema violation."""


def fail(message: str) -> NoReturn:
    raise ContractError(message)


def exact_keys(value: Any, expected: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        actual = sorted(value) if isinstance(value, dict) else type(value).__name__
        fail(f"{label} keys differ: got {actual}, want {sorted(expected)}")
    return value


def exact_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        fail(f"{label} must be a nonempty trimmed string")
    return value


def exact_integer(
    value: Any, label: str, *, minimum: int = 0, maximum: int | None = None
) -> int:
    if type(value) is not int or value < minimum:
        fail(f"{label} must be an integer >= {minimum}")
    if maximum is not None and value > maximum:
        fail(f"{label} must be an integer <= {maximum}")
    return value


def run_git(root: Path, *args: str, binary: bool = False) -> bytes | str:
    result = subprocess.run(
        ["git", "-C", str(root), *args],
        check=False,
        capture_output=True,
    )
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", "replace").strip()
        fail(f"git {' '.join(args)} failed: {detail}")
    return result.stdout if binary else result.stdout.decode("utf-8").strip()


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            fail(f"manifest contains duplicate key {key!r}")
        result[key] = value
    return result


def canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + "\n"
    ).encode("utf-8")


def validate_path(root: Path, raw_path: str) -> tuple[str, Path]:
    exact_string(raw_path, "manifest path")
    if "\\" in raw_path:
        fail("manifest path must use repository-relative POSIX separators")
    pure = PurePosixPath(raw_path)
    if (
        pure.is_absolute()
        or any(part in ("", ".", "..") for part in pure.parts)
        or pure.parent != MANIFEST_PREFIX
        or not pure.name.endswith(".json")
    ):
        fail(
            "manifest path must be one JSON file directly beneath "
            f"{MANIFEST_PREFIX}"
        )
    candidate = root.joinpath(*pure.parts)
    try:
        mode = candidate.lstat().st_mode
    except OSError as exc:
        fail(f"cannot stat manifest: {exc}")
    if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
        fail("manifest checkout path must be a regular non-symlink file")
    if stat.S_IMODE(mode) != 0o644:
        fail("manifest checkout mode must be exactly 100644")
    return pure.as_posix(), candidate


def verified_blob(
    root: Path, path: str, checkout_path: Path, expected_checkout: str
) -> tuple[str, bytes, str]:
    if not HEX40.fullmatch(expected_checkout):
        fail("expected checkout commit must be lowercase 40-hex")
    head = run_git(root, "rev-parse", "HEAD")
    if head != expected_checkout:
        fail("checkout HEAD does not match the exact expected main commit")
    if run_git(root, "rev-parse", "--is-shallow-repository") != "false":
        fail("full Git history is required to derive the stable blob-owning commit")

    source_commit = run_git(root, "log", "-1", "--format=%H", "--", path)
    if not isinstance(source_commit, str) or not HEX40.fullmatch(source_commit):
        fail("manifest has no stable blob-owning commit")
    ancestor = subprocess.run(
        ["git", "-C", str(root), "merge-base", "--is-ancestor", source_commit, head],
        check=False,
        capture_output=True,
    )
    if ancestor.returncode != 0:
        fail("manifest blob-owning commit is not an ancestor of the checkout")

    tree_entry = run_git(root, "ls-tree", source_commit, "--", path)
    if not isinstance(tree_entry, str):
        fail("manifest tree entry is malformed")
    match = re.fullmatch(r"100644 blob ([0-9a-f]{40})\t(.+)", tree_entry)
    if match is None or match.group(2) != path:
        fail("manifest source entry must be the exact 100644 blob path")

    committed = run_git(root, "show", f"{source_commit}:{path}", binary=True)
    if not isinstance(committed, bytes):
        fail("manifest blob read returned text unexpectedly")
    try:
        checkout = checkout_path.read_bytes()
    except OSError as exc:
        fail(f"cannot read manifest checkout bytes: {exc}")
    if committed != checkout:
        fail("manifest checkout bytes differ from the stable source blob")
    digest = hashlib.sha256(committed).hexdigest()
    if not HEX64.fullmatch(digest):
        fail("manifest SHA-256 is malformed")
    return source_commit, committed, digest


def validate_worker(
    worker: Any, operations: set[str], label: str
) -> dict[str, Any]:
    worker = exact_keys(worker, WORKER_KEYS, label)
    replicas = exact_integer(worker["max_replicas"], f"{label}.max_replicas", minimum=1)
    limits = exact_keys(worker["preinvoke_limits"], operations, f"{label}.preinvoke_limits")
    rates = exact_keys(
        worker["preinvoke_rate_limits"], operations, f"{label}.preinvoke_rate_limits"
    )
    for operation in sorted(operations):
        exact_integer(limits[operation], f"{label}.preinvoke_limits.{operation}", minimum=1)
        rate = exact_keys(
            rates[operation], RATE_KEYS, f"{label}.preinvoke_rate_limits.{operation}"
        )
        exact_integer(rate["burst"], f"{label}.{operation}.burst", minimum=1)
        exact_integer(
            rate["refill_per_second"],
            f"{label}.{operation}.refill_per_second",
            minimum=1,
        )
    if replicas > 100:
        fail(f"{label}.max_replicas exceeds the reviewed measurement ceiling")
    return worker


def validate_manifest(value: Any) -> dict[str, Any]:
    root = exact_keys(value, TOP_KEYS, "manifest")
    if root["schema_version"] != SCHEMA_VERSION or type(root["schema_version"]) is not int:
        fail("manifest schema_version is unsupported")
    contract = exact_keys(root["contract"], CONTRACT_KEYS, "contract")
    if contract["schema_version"] != SCHEMA_VERSION or type(contract["schema_version"]) is not int:
        fail("contract schema_version is unsupported")
    if contract["phase"] != "measurement":
        fail("basis manifest must remain in measurement phase")
    if contract["selected_authority_color"] not in ("blue", "green"):
        fail("selected Authority color must be exactly blue or green")
    kid = exact_string(contract["qat1_kid"], "qat1_kid")
    if KID.fullmatch(kid) is None:
        fail("qat1_kid is malformed")

    cells = contract["provisioned_cells"]
    if not isinstance(cells, dict) or set(cells) != {"cell0"}:
        fail("initial sandbox basis must contain exactly canonical cell0")
    for cell_id, cell in cells.items():
        if CELL_ID.fullmatch(cell_id) is None or len(cell_id) > 32:
            fail(f"invalid provisioned cell ID {cell_id!r}")
        cell = exact_keys(cell, {"caller_role_arn"}, f"provisioned_cells.{cell_id}")
        expected_role = (
            "arn:aws:iam::767397897469:"
            "role/layerv-nhp-sandbox-server"
        )
        if cell["caller_role_arn"] != expected_role:
            fail("cell0 caller role is not the canonical legacy role ARN")

    global_value = exact_keys(contract["global"], GLOBAL_KEYS, "global")
    expected_identity = {
        "environment": EXPECTED_ENVIRONMENT,
        "aws_partition": EXPECTED_PARTITION,
        "aws_account_id": EXPECTED_ACCOUNT_ID,
        "aws_region": EXPECTED_REGION,
        "authority_repository_url": EXPECTED_REPOSITORY_URL,
        "authority_digest_parameter_name": EXPECTED_DIGEST_PARAMETER,
        "qat1_raw_key_arn": EXPECTED_QAT1_RAW_KEY,
        "qat1_alias_arn": EXPECTED_QAT1_ALIAS,
        "otp_redis_cache_name": EXPECTED_REDIS_NAME,
        "otp_redis_endpoint": EXPECTED_REDIS_ENDPOINT,
    }
    mismatches = sorted(
        key for key, expected in expected_identity.items()
        if global_value.get(key) != expected
    )
    if mismatches:
        fail(f"global environment/AWS identity differs: {mismatches}")
    if IMAGE_DIGEST.fullmatch(
        exact_string(global_value["authority_image_digest"], "authority_image_digest")
    ) is None:
        fail("authority image digest must be canonical lowercase sha256")
    if KEY_ARN.fullmatch(
        exact_string(global_value["qat1_raw_key_arn"], "qat1_raw_key_arn")
    ) is None:
        fail("QAT1 raw key ARN is not the exact sandbox key shape")
    if REDIS_ENDPOINT.fullmatch(
        exact_string(global_value["otp_redis_endpoint"], "otp_redis_endpoint")
    ) is None:
        fail("OTP Redis endpoint is not the exact sandbox TLS endpoint shape")

    quota = exact_integer(
        global_value["regional_lambda_concurrency_quota"],
        "regional_lambda_concurrency_quota",
        minimum=1,
    )
    non_authority = exact_integer(
        global_value["non_authority_reserved_concurrency"],
        "non_authority_reserved_concurrency",
    )
    retained = exact_integer(
        global_value["retained_unreserved_concurrency"],
        "retained_unreserved_concurrency",
        minimum=100,
    )
    available = quota - non_authority - retained
    if available < 1:
        fail("regional Lambda concurrency has no retained Authority capacity")
    dependencies = exact_keys(
        global_value["dependency_headroom"], DEPENDENCY_KEYS, "dependency_headroom"
    )
    for name, amount in dependencies.items():
        exact_integer(amount, f"dependency_headroom.{name}", minimum=1)

    callers = exact_keys(
        global_value["caller_capacity"], CALLER_CAPACITY_KEYS, "caller_capacity"
    )
    hub = validate_worker(
        callers["hub_workers"], set(EXPECTED_HUB_OPERATIONS), "caller_capacity.hub_workers"
    )
    cell_workers = callers["cell_workers"]
    if not isinstance(cell_workers, dict) or set(cell_workers) != set(cells):
        fail("cell worker capacity keys must equal provisioned_cells")
    for cell_id, worker in cell_workers.items():
        validate_worker(
            worker, EXPECTED_CELL_OPERATIONS, f"caller_capacity.cell_workers.{cell_id}"
        )

    expected_functions = {
        f"layerv-nhp-sandbox-ca-{suffix}": operation
        for operation, suffix in EXPECTED_HUB_OPERATIONS.items()
    }
    functions = contract["functions"]
    if not isinstance(functions, dict) or set(functions) != set(expected_functions):
        fail("measurement basis must contain the exact complete three-function Hub graph")
    for function_name, operation in expected_functions.items():
        function = exact_keys(
            functions[function_name], FUNCTION_KEYS, f"functions.{function_name}"
        )
        values = {
            key: exact_integer(
                function[key],
                f"functions.{function_name}.{key}",
                minimum=1,
                maximum=86400 if key == "rollback_retention_seconds" else None,
            )
            for key in FUNCTION_KEYS
        }
        expected_in_flight = hub["max_replicas"] * hub["preinvoke_limits"][operation]
        rate = hub["preinvoke_rate_limits"][operation]
        expected_rps = hub["max_replicas"] * (
            rate["burst"] + rate["refill_per_second"]
        )
        if values["steady_reserved_concurrency"] != values["steady_provisioned_concurrency"]:
            fail(f"{function_name} steady concurrency algebra differs")
        if values["rollout_reserved_concurrency"] != (
            values["rollout_active_provisioned_concurrency"]
            + values["rollout_standby_provisioned_concurrency"]
        ):
            fail(f"{function_name} rollout concurrency algebra differs")
        if values["max_caller_in_flight"] != expected_in_flight:
            fail(f"{function_name} caller in-flight capacity differs")
        if values["max_caller_requests_per_second"] != expected_rps:
            fail(f"{function_name} caller request-rate capacity differs")
        for allocation in (
            values["steady_provisioned_concurrency"],
            values["rollout_active_provisioned_concurrency"],
            values["rollout_standby_provisioned_concurrency"],
        ):
            if expected_in_flight > allocation or expected_rps > 10 * allocation:
                fail(f"{function_name} provisioned allocation is below caller demand")
        if max(
            values["steady_reserved_concurrency"],
            values["rollout_reserved_concurrency"],
        ) > available:
            fail(f"{function_name} exceeds available Regional concurrency")
    if sum(
        function["steady_reserved_concurrency"] for function in functions.values()
    ) > available:
        fail("aggregate retained steady concurrency exceeds Regional capacity")
    if sum(
        function["rollout_reserved_concurrency"] for function in functions.values()
    ) > available:
        fail("aggregate retained rollout concurrency exceeds Regional capacity")
    return contract


def load_verified_manifest(
    repo_root: Path, raw_path: str, expected_checkout: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    path, checkout_path = validate_path(repo_root, raw_path)
    source_commit, raw, digest = verified_blob(
        repo_root, path, checkout_path, expected_checkout
    )
    try:
        text = raw.decode("utf-8")
        parsed = json.loads(text, object_pairs_hook=reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        fail(f"manifest is not strict UTF-8 JSON: {exc}")
    if canonical_json(parsed) != raw:
        fail("manifest bytes must be canonical sorted two-space JSON with one newline")
    contract = validate_manifest(parsed)
    evidence = {
        "repository": REPOSITORY,
        "source_commit": source_commit,
        "path": path,
        "sha256": digest,
        "schema_version": SCHEMA_VERSION,
    }
    return contract, evidence


def generated_input(
    contract: dict[str, Any],
    evidence: dict[str, Any],
    *,
    runtime_functions_enabled: bool = False,
    hub_edge_enabled: bool = False,
    hub_worker_enabled: bool = False,
) -> dict[str, Any]:
    generated = json.loads(json.dumps(contract))
    generated["provisioned_cells_evidence"] = evidence
    generated["global"]["basis_evidence"] = evidence
    generated["global"]["result_evidence"] = None
    for function in generated["functions"].values():
        function["basis_evidence"] = evidence
        function["result_evidence"] = None
    payload: dict[str, Any] = {
        "authority_runtime_contract": generated,
        "authority_runtime_contract_evidence_verified": True,
    }
    # Second, independent runtime-slice gate (the Step-4 enablement). Emit the
    # key ONLY when the caller explicitly opts in; when omitted the key is absent
    # entirely so the committed Terraform default (false) governs and the
    # foundation stays dark. The key name matches the Terraform variable
    # authority_runtime_functions_enabled exactly.
    if runtime_functions_enabled:
        payload["authority_runtime_functions_enabled"] = True
    # Third, independent Step-5 Hub public edge gate. Emit the key ONLY when the
    # caller explicitly opts in; when omitted the key is absent entirely so the
    # committed Terraform default (false) governs and the edge stays dark. The
    # key name matches the Terraform variable hub_edge_enabled exactly.
    if hub_edge_enabled:
        payload["hub_edge_enabled"] = True
    # Fourth, independent Step-5 Hub Fargate worker gate (slice 5b). Emit the key
    # ONLY when the caller explicitly opts in; when omitted the key is absent
    # entirely so the committed Terraform default (false) governs and the worker
    # stays dark. The key name matches the Terraform variable hub_worker_enabled
    # exactly. The module fails closed if it is set without hub_edge_enabled and a
    # live authority runtime.
    if hub_worker_enabled:
        payload["hub_worker_enabled"] = True
    return payload


def atomic_write(path: Path, payload: bytes) -> None:
    if path.exists() and path.is_symlink():
        fail("output path must not be a symlink")
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", required=True)
    parser.add_argument("--repository-root", type=Path, required=True)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--expected-checkout-commit", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--runtime-functions-enabled",
        action="store_true",
        default=False,
        help=(
            "Also emit authority_runtime_functions_enabled=true into the "
            "generated tfvars (the Step-4 runtime-slice opt-in). Omit to leave "
            "the key absent so the committed default (false) keeps the "
            "foundation dark."
        ),
    )
    parser.add_argument(
        "--hub-edge-enabled",
        action="store_true",
        default=False,
        help=(
            "Also emit hub_edge_enabled=true into the generated tfvars (the "
            "Step-5 Hub public edge opt-in). Omit to leave the key absent so "
            "the committed default (false) keeps the edge dark."
        ),
    )
    parser.add_argument(
        "--hub-worker-enabled",
        action="store_true",
        default=False,
        help=(
            "Also emit hub_worker_enabled=true into the generated tfvars (the "
            "Step-5 Hub Fargate worker opt-in, slice 5b). Omit to leave the key "
            "absent so the committed default (false) keeps the worker dark. "
            "Requires hub_edge_enabled and a live authority runtime."
        ),
    )
    args = parser.parse_args(argv)
    try:
        if args.mode != MODE:
            fail(f"mode must be exactly {MODE}")
        root = args.repository_root.resolve(strict=True)
        if run_git(root, "rev-parse", "--show-toplevel") != str(root):
            fail("repository root must be the exact Git top level")
        contract, evidence = load_verified_manifest(
            root, args.manifest, args.expected_checkout_commit
        )
        payload = canonical_json(
            generated_input(
                contract,
                evidence,
                runtime_functions_enabled=args.runtime_functions_enabled,
                hub_edge_enabled=args.hub_edge_enabled,
                hub_worker_enabled=args.hub_worker_enabled,
            )
        )
        atomic_write(args.output, payload)
        print(
            json.dumps(
                {
                    "environment": EXPECTED_ENVIRONMENT,
                    "function_count": len(contract["functions"]),
                    "manifest_path": evidence["path"],
                    "manifest_sha256": evidence["sha256"],
                    "source_commit": evidence["source_commit"],
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 0
    except (ContractError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
