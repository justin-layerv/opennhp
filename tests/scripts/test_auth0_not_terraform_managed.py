#!/usr/bin/env python3
"""Fence: Terraform must not manage the Auth0 tenant (#3284).

The Auth0 provider was retired for a security reason, not a stylistic one.
`terraform-plan-pr.yml` executes PR-head HCL, and the credential it used to be
handed belonged to an M2M client with 37 Management API scopes — including
`create:connections`, `update:connections`, client CRUD, and `read:client_keys`,
which reads every client secret in the shared tenant, prod included. Adding an
`auth0_*` resource back re-creates the need for that credential, and the
re-introduction would look like ordinary IaC hygiene rather than the trust-
boundary change it actually is.

Two further reasons it must not come back are recorded in terraform/CLAUDE.md:
Terraform cannot write connection `options` with the available grant (the #2305
drift broke *every* unrelated apply until it was un-managed), and it cannot read
client secrets back, which is why the credential secrets are operator-written.

This fence also guards the transitional pieces: the `provider "auth0"` stub must
stay credential-free, and it must stay present until both states are clean.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / ".github" / "scripts"))

from _tf_lint_lib import iter_data_sources, iter_resources, parse_tf_files  # noqa: E402

TERRAFORM_ROOT = REPO_ROOT / "terraform"
AUTH0_MODULE = TERRAFORM_ROOT / "modules" / "auth0"
WORKFLOWS = REPO_ROOT / ".github" / "workflows"
ENVIRONMENTS = ("prod", "sandbox")

# Retired 2026-07-26. Kept as data so the failure message can name what was
# forgotten rather than just asserting a count.
RETIRED_TYPES = {
    "auth0_action",
    "auth0_attack_protection",
    "auth0_branding",
    "auth0_branding_theme",
    "auth0_client",
    "auth0_client_credentials",
    "auth0_client_grant",
    "auth0_connection",
    "auth0_connection_clients",
    "auth0_email_provider",
    "auth0_email_template",
    "auth0_resource_server",
    "auth0_resource_server_scopes",
    "auth0_role",
    "auth0_role_permissions",
    "auth0_trigger_actions",
}


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_no_auth0_resources_are_declared() -> None:
    parsed = parse_tf_files(TERRAFORM_ROOT)
    declared = sorted(
        f"{rtype}.{name}"
        for _f, rtype, name, _b in iter_resources(parsed)
        if rtype.startswith("auth0_")
    )
    assert not declared, (
        "Terraform must not manage Auth0 resources — found "
        f"{declared}. Auth0 tenant configuration is owned in the Auth0 "
        "dashboard; see terraform/CLAUDE.md 'Auth0 Is Not Terraform-Managed'. "
        "Re-adding one requires restoring a tenant-write credential to PR-time "
        "plan execution, which is a trust-boundary change, not a refactor."
    )


def test_no_auth0_data_sources_are_declared() -> None:
    """Data sources need the same credential a resource does."""
    parsed = parse_tf_files(TERRAFORM_ROOT)
    declared = sorted(
        f"data.{dtype}.{name}"
        for _f, dtype, name, _b in iter_data_sources(parsed)
        if dtype.startswith("auth0_")
    )
    assert not declared, (
        f"Terraform must not read Auth0 via data sources either — found {declared}. "
        "A data source authenticates against the Management API exactly like a "
        "resource does."
    )


def test_retirement_is_declared_as_forget_not_destroy() -> None:
    """`removed` must carry destroy = false, or an apply deletes the tenant."""
    removed_tf = AUTH0_MODULE / "removed.tf"
    assert removed_tf.is_file(), f"{removed_tf} must exist while state still holds auth0_* entries"
    text = read(removed_tf)

    blocks = re.findall(r"removed\s*\{(.*?)\n\}", text, re.S)
    assert blocks, "removed.tf must declare removed blocks"

    for block in blocks:
        target = re.search(r"from\s*=\s*(\S+)", block)
        assert target, f"removed block missing `from`: {block[:80]}"
        assert re.search(r"destroy\s*=\s*false", block), (
            f"removed block for {target.group(1)} must set `destroy = false`. "
            "Without it Terraform DESTROYS the live Auth0 object — deleting "
            "clients, the API, or user-bearing connections in a shared tenant."
        )

    covered = {re.search(r"from\s*=\s*(\S+)", b).group(1).split("[")[0] for b in blocks}
    missing = {t for t in RETIRED_TYPES if not any(c.startswith(t + ".") for c in covered)}
    assert not missing, (
        f"removed.tf does not cover retired resource types {sorted(missing)}; "
        "their state entries would be stranded."
    )


def test_provider_stub_carries_no_real_credential() -> None:
    """The stub exists to decode state, not to authenticate."""
    for env in ENVIRONMENTS:
        text = read(TERRAFORM_ROOT / "environments" / env / "backend.tf")
        block = re.search(r'provider\s+"auth0"\s*\{(.*?)\n\}', text, re.S)
        assert block, (
            f"{env}/backend.tf must keep the auth0 provider stub until state is "
            "clean; without it a forget-only plan fails with 'Invalid provider "
            "configuration'."
        )
        body = block.group(1)
        for forbidden in ("client_secret", "var.auth0_tf_client_id", "var.auth0_api_token"):
            assert forbidden not in body, (
                f"{env} auth0 provider stub references {forbidden!r}. The stub makes "
                "no API calls and must stay credential-free."
            )


def test_no_auth0_credentials_reach_terraform_in_ci() -> None:
    for workflow in sorted(WORKFLOWS.glob("*.yml")):
        text = read(workflow)
        assert "TF_VAR_auth0_tf_client" not in text and "TF_VAR_auth0_api_token" not in text, (
            f"{workflow.name} passes an Auth0 credential to Terraform. The provider "
            "is retired; PR-head plan execution must not receive a tenant-write token."
        )
        assert "fetch-auth0-token.sh" not in text, (
            f"{workflow.name} references the deleted Auth0 token fetch helper."
        )


def test_auth0_token_fetch_helper_is_deleted() -> None:
    helper = REPO_ROOT / ".github" / "scripts" / "fetch-auth0-token.sh"
    assert not helper.exists(), (
        f"{helper} must stay deleted — it minted the Management API token that "
        "PR-head plan code could exfiltrate."
    )


def test_client_ids_are_inputs_not_secrets() -> None:
    """Client IDs are public; secrets must never become Terraform inputs."""
    text = read(AUTH0_MODULE / "variables.tf")
    for var in (
        "backend_service_client_id",
        "smoke_test_client_id",
        "spa_dashboard_client_id",
        "slack_oauth_client_id",
    ):
        assert f'variable "{var}"' in text, f"modules/auth0 must declare {var}"

    bad = re.findall(r'variable\s+"([a-z0-9_]*client_secret[a-z0-9_]*)"', text)
    assert not bad, (
        f"modules/auth0 must not take Auth0 client secrets as variables: {bad}. "
        "They are written directly into Secrets Manager by an operator so they "
        "never enter Terraform state or a plan log."
    )
