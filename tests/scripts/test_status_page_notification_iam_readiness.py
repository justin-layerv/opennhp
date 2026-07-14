#!/usr/bin/env python3
"""Fence the status-bucket notification IAM edge from run 29308758963."""

import re
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]


def require(condition: object, message: str) -> None:
    """Raise even under python -O; structural gates must not use assert."""
    if not condition:
        raise AssertionError(message)


def hcl_block(text: str, header: str) -> str:
    """Extract one balanced, heredoc-free HCL block by exact header."""
    require(text.count(header) == 1, f"expected exactly one HCL block: {header}")
    start = text.find(header)
    opening = text.find("{", start + len(header))
    require(opening >= 0, f"missing opening brace: {header}")
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
    status_main = (REPO_ROOT / "terraform/modules/status-page/main.tf").read_text()
    status_variables = (
        REPO_ROOT / "terraform/modules/status-page/variables.tf"
    ).read_text()
    ecr = (REPO_ROOT / "terraform/modules/ecr/main.tf").read_text()

    wait = hcl_block(root, 'resource "time_sleep" "bootstrap_alb_iam_propagation"')
    require(
        re.search(
            r"count\s*=\s*var\.deploy_bootstrap_alb\s*\|\|\s*"
            r"var\.deploy_status_page\s*\?\s*1\s*:\s*0",
            wait,
        ),
        "terraform-apply-services wait must be enabled for both bootstrap-alb "
        "and status-page consumers",
    )
    for trigger in (
        "module.ecr.terraform_apply_services_policy_doc_hash",
        "module.ecr.terraform_apply_services_policy_arn",
        "module.ecr.terraform_apply_services_attachment_id",
    ):
        require(trigger in wait, f"IAM propagation wait must retain {trigger}")
    require(
        "local.iam_conservative_propagation_duration" in wait,
        "status notification must retain the conservative IAM propagation window",
    )

    status_call = hcl_block(root, 'module "status_page"')
    require(
        re.search(
            r"terraform_apply_services_ready\s*=\s*"
            r"var\.deploy_status_page\s*\?\s*one\("
            r"time_sleep\.bootstrap_alb_iam_propagation\[\*\]\.id\)\s*:\s*\"\"",
            status_call,
        ),
        "root status module must receive the terraform-apply-services wait token",
    )
    require(
        not re.search(r"(?m)^\s*depends_on\s*=", status_call),
        "status_page must not use module-wide depends_on; keep the IAM edge on "
        "the bucket notification so provider data remains plan-known",
    )

    variable = hcl_block(status_variables, 'variable "terraform_apply_services_ready"')
    require(
        re.search(r"(?m)^\s*type\s*=\s*string\s*$", variable),
        "status notification readiness token must remain a string",
    )
    require(
        re.search(r'(?m)^\s*default\s*=\s*""\s*$', variable),
        "standalone status-page module use must retain an inert empty default",
    )

    readiness = hcl_block(
        status_main,
        'resource "terraform_data" "terraform_apply_services_ready"',
    )
    require(
        re.search(
            r"(?m)^\s*input\s*=\s*var\.terraform_apply_services_ready\s*$",
            readiness,
        ),
        "child readiness resource must consume the root wait token",
    )
    require(
        not re.search(r"(?m)^\s*count\s*=", readiness),
        "readiness resource must not gate on its apply-time-unknown token",
    )

    notification = hcl_block(
        status_main, 'resource "aws_s3_bucket_notification" "status"'
    )
    require(
        "terraform_data.terraform_apply_services_ready" in notification,
        "status bucket notification must wait for apply-role IAM propagation",
    )

    services_policy = hcl_block(
        ecr, 'resource "aws_iam_policy" "terraform_apply_services"'
    )
    require(
        '"s3:PutBucketNotification"' in services_policy,
        "terraform-apply-services must retain s3:PutBucketNotification",
    )
    require(
        '"arn:aws:s3:::layerv-nhp-*"' in services_policy,
        "notification grant must retain status-bucket ARN coverage",
    )


if __name__ == "__main__":
    try:
        check()
    except (AssertionError, OSError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        raise SystemExit(1)
    print("Status-page bucket-notification IAM readiness: targeted graph OK")
