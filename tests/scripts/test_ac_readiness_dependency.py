#!/usr/bin/env python3
"""Structural fence for the targeted AC internal-ALB readiness edge (#3232)."""

import re
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]


def require(condition: object, message: str) -> None:
    """Raise even under python -O; structural gates must not use assert."""
    if not condition:
        raise AssertionError(message)


def hcl_block(text: str, header: str) -> str:
    """Extract one balanced HCL block by its exact header.

    This deliberately small source fence does not parse HCL strings: a lone
    brace added inside a quoted value in a fenced block requires this helper
    and its expectations to be updated in the same change. The token regex is
    intentionally formatting-sensitive for the same lockstep reason.
    """
    start = text.find(header)
    if start < 0:
        raise AssertionError(f"missing HCL block: {header}")
    opening = text.find("{", start + len(header))
    if opening < 0:
        raise AssertionError(f"missing opening brace: {header}")
    depth = 0
    for index in range(opening, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return text[start : index + 1]
    raise AssertionError(f"unterminated HCL block: {header}")


def check() -> None:
    root = (REPO_ROOT / "terraform/main.tf").read_text()
    ac = (REPO_ROOT / "terraform/modules/ac/main.tf").read_text()
    variables = (REPO_ROOT / "terraform/modules/ac/variables.tf").read_text()
    qrts = "\n".join(
        path.read_text()
        for path in sorted(
            (REPO_ROOT / "terraform/modules/qurl-reverse-tunnel-server").rglob("*.tf")
        )
    )
    prod_tfvars = (REPO_ROOT / "terraform/environments/prod/terraform.tfvars").read_text()
    prod_variables = (REPO_ROOT / "terraform/environments/prod/variables.tf").read_text()

    require(
        root.count('module "ac"') == 1,
        'terraform/main.tf must contain exactly one module "ac" header; an '
        "earlier comment match would make the source extractor ambiguous",
    )
    root_module = hcl_block(root, 'module "ac"')
    token_assignment = re.search(
        r"qurl_internal_alb_readiness_token\s*=\s*"
        r"local\.qurl_internal_alb_enabled\s*\?\s*sha256\(join\("
        r'[\s\S]*?aws_acm_certificate_validation\.qurl_internal\[0\]\.id'
        r'[\s\S]*?aws_route53_record\.qurl_internal_alias\[0\]\.fqdn'
        r'[\s\S]*?\)\)\s*:\s*""',
        root_module,
    )
    require(
        token_assignment,
        "module.ac must pass a disabled-safe token derived from both internal "
        "ALB certificate validation and DNS alias readiness",
    )
    require(
        not re.search(r"(?m)^\s*depends_on\s*=", root_module),
        "module.ac must not regain a module-wide depends_on; it defers the "
        "Route53 zone lookup and forces public DNS replacement",
    )

    # qURL reverse-tunnel-server deliberately retains the same root readiness
    # resources as a module-wide edge. That is safe only while the module has
    # no Route53 zone lookup or record that Terraform could defer into an
    # unknown identity; fail before a future addition recreates the AC hazard.
    require(
        root.count('module "qurl_reverse_tunnel_server"') == 1,
        'terraform/main.tf must contain exactly one module "qurl_reverse_tunnel_server" header',
    )
    qrts_root_module = hcl_block(root, 'module "qurl_reverse_tunnel_server"')
    require(
        re.search(r"(?m)^\s*depends_on\s*=", qrts_root_module),
        "qURL reverse-tunnel-server must retain its explicit readiness edge",
    )
    for dependency in (
        "aws_acm_certificate_validation.qurl_internal",
        "aws_route53_record.qurl_internal_alias",
    ):
        require(
            dependency in qrts_root_module,
            f"qURL reverse-tunnel-server readiness edge must retain {dependency}",
        )
    require(
        'data "aws_route53_zone"' not in qrts,
        "narrow qURL reverse-tunnel-server readiness to its launch template "
        "before adding a Route53 zone data source",
    )
    require(
        'resource "aws_route53_record"' not in qrts,
        "narrow qURL reverse-tunnel-server readiness to its launch template "
        "before adding a Route53 record",
    )

    variable = hcl_block(variables, 'variable "qurl_internal_alb_readiness_token"')
    require(
        re.search(r'(?m)^\s*type\s*=\s*string\s*$', variable),
        "readiness token must remain a string",
    )
    require(
        re.search(r'(?m)^\s*default\s*=\s*""\s*$', variable),
        "readiness token must default to the inert empty value",
    )

    readiness = hcl_block(ac, 'resource "terraform_data" "qurl_internal_alb_readiness"')
    require(
        re.search(
            r"(?m)^\s*input\s*=\s*var\.qurl_internal_alb_readiness_token\s*$",
            readiness,
        ),
        "module readiness resource must consume the root-produced token",
    )
    require(
        not re.search(r"(?m)^\s*count\s*=", readiness),
        "the readiness resource must stay plan-safe: its enabled token is "
        "unknown on first apply, so token-derived count would fail planning",
    )

    launch_template = hcl_block(ac, 'resource "aws_launch_template" "ac"')
    require(
        "terraform_data.qurl_internal_alb_readiness" in launch_template,
        "AC launch template must depend on the narrow readiness resource",
    )
    require(
        "aws_s3_object.init_script" in launch_template,
        "AC launch template must retain its init-script dependency",
    )

    # Narrowing the module dependency makes both AC archives plan-time strict.
    # The promote workflow is prod-only and gates the reconciliation artifact
    # on deploy_ac, so pin the underlying prod toggle to prevent a future
    # deploy_ac=true / reconciliation=false mismatch from failing opaquely in
    # the upload step after a successful Terraform plan. Keep this assertion
    # aligned with docs/runbooks/promote-to-prod-lambda-artifacts.md.
    require(
        re.search(
            r"(?m)^enable_secret_reconciliation\s*=\s*true\s*$", prod_tfvars
        ),
        "prod must keep enable_secret_reconciliation=true for the strict AC artifact gate",
    )
    prod_reconciliation = hcl_block(
        prod_variables, 'variable "enable_secret_reconciliation"'
    )
    require(
        re.search(r"(?m)^\s*default\s*=\s*true\s*$", prod_reconciliation),
        "prod enable_secret_reconciliation default must remain true for the "
        "strict AC artifact gate",
    )


if __name__ == "__main__":
    try:
        check()
    except (AssertionError, OSError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        raise SystemExit(1)
    print("AC internal-ALB readiness dependency: targeted graph OK")
