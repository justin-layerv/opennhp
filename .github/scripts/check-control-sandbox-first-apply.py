#!/usr/bin/env python3
"""Fail-closed contracts for the sandbox Connector Control foundation."""

from __future__ import annotations

import argparse
import base64
import binascii
import copy
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any, Iterable


ACCOUNT_ID = "767397897469"
AWS_REGION = "us-east-2"
CONTROL_VPC_CIDR = "10.102.0.0/16"
STATE_KMS_KEY_ARN = (
    "arn:aws:kms:us-east-2:767397897469:key/289dbe35-ab5a-4752-8564-4c96c607c9f4"
)
# Locked by the active no-op plan contract and permanent live-state verifier.
TF_VERSION = "1.14.3"
CONTROL_PREFIX = "layerv-nhp-sandbox-control"
# The CIDR the sandbox Control Hub NLB security group admits, and therefore the
# for_each key of its ingress rule. Sandbox is open to developers inside and
# outside the company (qurl-go ADR 0001), which replaced the proof runner /32
# this pin previously carried. It must move in lockstep with the Control root's
# hub_public_udp_ingress_cidrs input.
HUB_PUBLIC_UDP_INGRESS_CIDR = "0.0.0.0/0"
AUTHORITY_PROOF_OWNER_ID = "layerv-nhp-sandbox-udp-proof"
AUTHORITY_PROOF_CONTROLLER_ROLE_ARN = (
    f"arn:aws:iam::{ACCOUNT_ID}:role/layerv-nhp-sandbox-udp-proof-controller"
)
AUTHORITY_PROOF_FUNCTION_NAME = "layerv-nhp-sandbox-ca-pm"
AUTHORITY_PROOF_EXEC_POLICY_ADDRESS = (
    'module.control.aws_iam_role_policy.authority_exec["'
    f'{AUTHORITY_PROOF_FUNCTION_NAME}"]'
)
AUTHORITY_PROOF_OPERATION = "mutate_proof_agent"
AUTHORITY_PROOF_ALIAS_OUTPUT = "authority_proof_mutation_alias_arn"
AUTHORITY_PROOF_RECOVERY_FUNCTION_NAME = "layerv-nhp-sandbox-ca-pcr"
AUTHORITY_PROOF_RECOVERY_OPERATION = "prepare_proof_credential_recovery"
AUTHORITY_PROOF_RECOVERY_ALIAS_OUTPUT = (
    "authority_proof_credential_recovery_alias_arn"
)
AUTHORITY_PROOF_ALIAS_OUTPUTS = {
    AUTHORITY_PROOF_FUNCTION_NAME: AUTHORITY_PROOF_ALIAS_OUTPUT,
    AUTHORITY_PROOF_RECOVERY_FUNCTION_NAME: AUTHORITY_PROOF_RECOVERY_ALIAS_OUTPUT,
}
AUTHORITY_PROOF_CONTROLLER_POLICY_ADDRESS = (
    "module.control.aws_iam_role_policy.authority_proof_controller_invoke[0]"
)
AUTHORITY_PROOF_CONTROLLER_POLICY_NAME = "connector-authority-proof-invoke"
AUTHORITY_PROOF_CONTROLLER_ROLE_NAME = "layerv-nhp-sandbox-udp-proof-controller"
# The single reviewed deposed object left by the Authority function-SG
# generation change: its create-before-destroy replacement applied, but the
# generation-1 delete could not complete while published function versions still
# pinned that group to live Lambda ENIs. Pinned exactly so no other deposed
# object is admitted; see _is_exact_legacy_authority_sg_deposed_delete. Remove
# all three once the object is reaped.
AUTHORITY_FUNCTION_SG_ADDRESS = "module.control.aws_security_group.authority_lambda[0]"
AUTHORITY_FUNCTION_SG_DEPOSED_KEY = "4a2844f4"
AUTHORITY_FUNCTION_SG_DEPOSED_ID = "sg-0584cd75da80a2c7d"
AUTHORITY_PUBLISHER_ROLE_NAME = (
    "layerv-nhp-sandbox-control-connector-authority-publisher"
)
AUTHORITY_PUBLISHER_ECR_ARN = (
    f"arn:aws:ecr:{AWS_REGION}:{ACCOUNT_ID}:repository/"
    "layerv/qurl-connector-authority"
)
AUTHORITY_PUBLISHER_DIGEST_PARAMETER_NAME = (
    "/sandbox/nhp/control/connector-authority/image-digest"
)
AUTHORITY_PUBLISHER_DIGEST_PARAMETER_ARN = (
    f"arn:aws:ssm:{AWS_REGION}:{ACCOUNT_ID}:parameter"
    f"{AUTHORITY_PUBLISHER_DIGEST_PARAMETER_NAME}"
)
AUTHORITY_PUBLISHER_TRUST_POLICY = {
    "Statement": [
        {
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {
                "StringEquals": {
                    "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
                    "token.actions.githubusercontent.com:sub": (
                        "repo:layervai/qurl-service:environment:sandbox"
                    ),
                }
            },
            "Effect": "Allow",
            "Principal": {
                "Federated": (
                    f"arn:aws:iam::{ACCOUNT_ID}:oidc-provider/"
                    "token.actions.githubusercontent.com"
                )
            },
            "Sid": "GitHubEnvironmentPublisher",
        }
    ],
    "Version": "2012-10-17",
}
AUTHORITY_PUBLISHER_POLICY = {
    "Statement": [
        {
            "Action": "ecr:GetAuthorizationToken",
            "Effect": "Allow",
            "Resource": "*",
            "Sid": "ECRAuthorization",
        },
        {
            "Action": [
                "ecr:BatchCheckLayerAvailability",
                "ecr:BatchGetImage",
                "ecr:CompleteLayerUpload",
                "ecr:DescribeImages",
                "ecr:GetDownloadUrlForLayer",
                "ecr:InitiateLayerUpload",
                "ecr:PutImage",
                "ecr:UploadLayerPart",
            ],
            "Effect": "Allow",
            "Resource": AUTHORITY_PUBLISHER_ECR_ARN,
            "Sid": "AuthorityRepository",
        },
        {
            "Action": ["ssm:GetParameter", "ssm:PutParameter"],
            "Effect": "Allow",
            "Resource": AUTHORITY_PUBLISHER_DIGEST_PARAMETER_ARN,
            "Sid": "AuthorityDigestPin",
        },
    ],
    "Version": "2012-10-17",
}
HUB_PUBLISHER_ROLE_NAME = f"{CONTROL_PREFIX}-hub-publisher"
HUB_PUBLISHER_GITHUB_ENVIRONMENT = "hub-publish-sandbox"
HUB_PUBLISHER_GITHUB_SUBJECT = (
    f"repo:layervai/nhp:environment:{HUB_PUBLISHER_GITHUB_ENVIRONMENT}"
)
HUB_ECR_REPOSITORY_NAME = "layerv/nhp-hub"
HUB_ECR_REPOSITORY_ARN = (
    f"arn:aws:ecr:{AWS_REGION}:{ACCOUNT_ID}:repository/{HUB_ECR_REPOSITORY_NAME}"
)
HUB_IMAGE_DIGEST_PARAMETER_NAME = "/sandbox/nhp/control/hub/image-digest"
HUB_IMAGE_DIGEST_PARAMETER_ARN = (
    f"arn:aws:ssm:{AWS_REGION}:{ACCOUNT_ID}:parameter"
    f"{HUB_IMAGE_DIGEST_PARAMETER_NAME}"
)
HUB_PUBLISHER_TRUST_POLICY = {
    "Statement": [
        {
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {
                "StringEquals": {
                    "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
                    "token.actions.githubusercontent.com:sub": HUB_PUBLISHER_GITHUB_SUBJECT,
                }
            },
            "Effect": "Allow",
            "Principal": {
                "Federated": (
                    f"arn:aws:iam::{ACCOUNT_ID}:oidc-provider/"
                    "token.actions.githubusercontent.com"
                )
            },
            "Sid": "GitHubEnvironmentPublisher",
        }
    ],
    "Version": "2012-10-17",
}
HUB_PUBLISHER_POLICY = {
    "Statement": [
        {
            "Action": "ecr:GetAuthorizationToken",
            "Effect": "Allow",
            "Resource": "*",
            "Sid": "ECRAuthorization",
        },
        {
            "Action": [
                "ecr:BatchCheckLayerAvailability",
                "ecr:BatchGetImage",
                "ecr:CompleteLayerUpload",
                "ecr:DescribeImages",
                "ecr:DescribeImageScanFindings",
                "ecr:GetDownloadUrlForLayer",
                "ecr:InitiateLayerUpload",
                "ecr:PutImage",
                "ecr:UploadLayerPart",
            ],
            "Effect": "Allow",
            "Resource": HUB_ECR_REPOSITORY_ARN,
            "Sid": "HubRepository",
        },
        {
            "Action": ["ssm:GetParameter", "ssm:PutParameter"],
            "Effect": "Allow",
            "Resource": HUB_IMAGE_DIGEST_PARAMETER_ARN,
            "Sid": "HubDigestPin",
        },
    ],
    "Version": "2012-10-17",
}
HUB_ECR_LIFECYCLE_POLICY = {
    "rules": [
        {
            "action": {"type": "expire"},
            "description": "Expire untagged Hub images after 7 days",
            "rulePriority": 1,
            "selection": {
                "countNumber": 7,
                "countType": "sinceImagePushed",
                "countUnit": "days",
                "tagStatus": "untagged",
            },
        }
    ]
}
OTP_REDIS_LEGACY_ACCESS = (
    "on ~connector:* -@all +@connection +@read +@write +@scripting"
)
OTP_REDIS_ISSUER_ACCESS = (
    "on %W~connector:registration-otp:v2:{*}:challenge "
    "%W~connector:registration-otp:v2:{*}:state "
    "~connector:ratelimit:registration-otp:credential:* "
    "~connector:ratelimit:registration-otp:owner:* "
    "~connector:ratelimit:registration-otp:peer:* "
    "~connector:ratelimit:registration-otp:source:* "
    "resetchannels -@all +hello +auth +ping +command +cluster|slots "
    "+multi +exec +discard +del +hset +expire "
    "+eval +evalsha +zremrangebyscore +zcard +zrange +zadd"
)
OTP_REDIS_ACTIVATOR_ACCESS = (
    "on %R~connector:registration-otp:v2:{*}:challenge "
    "~connector:registration-otp:v2:{*}:state "
    "resetchannels -@all +hello +auth +ping +command +cluster|slots "
    "+watch +unwatch +multi +exec +discard "
    "+hmget +hlen +pttl +hset +pexpire"
)
_DYNAMODB_TABLES = (
    "agent_keys",
    "api_key_idempotency",
    "api_keys",
    "connector_authority",
    "customers",
)
# Keep this reviewed inventory synchronized with sandbox/outputs.tf. The
# refresh-only output-contract test parses that file and fails on either drift.
EXPECTED_CONTROL_OUTPUTS = frozenset(
    {
        "authority_cell_alias_targets",
        "authority_image_uri",
        "authority_data_kms_key_arn",
        "authority_ecr_repository_url",
        "authority_image_digest_parameter_name",
        "authority_proof_credential_recovery_alias_arn",
        "authority_proof_mutation_alias_arn",
        "authority_publisher_github_environment",
        "authority_publisher_role_arn",
        "authority_publisher_role_name",
        "control_table_names",
        "control_table_prefix",
        "hub_ecr_repository_arn",
        "hub_ecr_repository_url",
        "hub_image_digest_parameter_name",
        "hub_publisher_github_environment",
        "hub_publisher_github_subject",
        "hub_publisher_role_arn",
        "hub_publisher_role_name",
        "hub_nlb_dns_name",
        "hub_nlb_zone_id",
        "hub_public_key_parameter_name",
        "hub_udp_listener_arn",
        "interface_endpoint_ids",
        "isolated_subnet_ids",
        "otp_pepper_secret_arn",
        "otp_redis_activator_user_arn",
        "otp_redis_activator_user_id",
        "otp_redis_endpoint",
        "otp_redis_issuer_user_arn",
        "otp_redis_issuer_user_id",
        "otp_redis_user_group_id",
        "provisioned_cells",
        "qat1_signing_kms_key_arn",
        "ses_identity_arn",
        "vpc_id",
    }
)
_OUTPUT_ENTRY_KEYS = frozenset({"sensitive", "type", "value"})
# Exact key set of a Terraform change envelope (shared by resource-drift and
# output changes in the plan JSON).
_CHANGE_KEYS = frozenset(
    {
        "actions",
        "after",
        "after_sensitive",
        "after_unknown",
        "before",
        "before_sensitive",
    }
)
# Value-free masks emitted by Terraform 1.14.3 with AWS provider 6.55.0 for
# this exact role normalization. Re-review both masks when either pinned version
# changes; the test lockfile assertion and literal golden move with them.
_PUBLISHER_REFRESH_BEFORE_SENSITIVE = {
    "inline_policy": [],
    "managed_policy_arns": [],
    "tags": {},
    "tags_all": {},
}
_PUBLISHER_REFRESH_AFTER_SENSITIVE = {
    "inline_policy": [{}],
    "managed_policy_arns": [],
    "tags": {},
    "tags_all": {},
}
_DIGEST_REFRESH_SENSITIVE = {
    "tags": {},
    "tags_all": {},
    "value": True,
    "value_wo": True,
}
_AUTHORITY_DIGEST_ADDRESS = (
    "module.control.aws_ssm_parameter.authority_image_digest"
)
_HUB_DIGEST_ADDRESS = "module.control.aws_ssm_parameter.hub_image_digest"
_DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
# An immutable digest reference into the canonical Authority repository. This
# is the invariant that survives BOTH image sources: a pinned contract names
# one digest, a publish-tracking contract lets it advance, but neither may ever
# deploy a mutable tag.
_AUTHORITY_IMAGE_URI_PATTERN = re.compile(
    r"[0-9]{12}\.dkr\.ecr\.[a-z0-9-]+\.amazonaws\.com/layerv/"
    r"qurl-connector-authority@sha256:[0-9a-f]{64}"
)


def _authority_image_tracks_publish(contract: Any) -> bool:
    if not isinstance(contract, dict):
        return False
    global_contract = contract.get("global")
    if not isinstance(global_contract, dict):
        return False
    return global_contract.get("authority_image_source") == "publish_parameter"
_AUTHORITY_DIGEST_SPEC = {
    "address": _AUTHORITY_DIGEST_ADDRESS,
    "description": (
        "Immutable sha256 digest for the separately published Connector "
        "Authority Lambda image"
    ),
    "kind": "authority-digest",
    "label": "authority",
    "name": "authority_image_digest",
    "parameter_arn": AUTHORITY_PUBLISHER_DIGEST_PARAMETER_ARN,
    "parameter_name": AUTHORITY_PUBLISHER_DIGEST_PARAMETER_NAME,
}
_HUB_DIGEST_SPEC = {
    "address": _HUB_DIGEST_ADDRESS,
    "description": (
        "Immutable sha256 digest for the separately published Connector Hub image"
    ),
    "kind": "hub-digest",
    "label": "Hub",
    "name": "hub_image_digest",
    "parameter_arn": HUB_IMAGE_DIGEST_PARAMETER_ARN,
    "parameter_name": HUB_IMAGE_DIGEST_PARAMETER_NAME,
}
_DRIFT_IDENTITY_LIMIT = 8
_DRIFT_IDENTITY_FIELD_MAX_CHARS = 256
# A separate rendered-JSON ceiling covers escape expansion: 256 source
# characters can occupy far more than 256 bytes when ensure_ascii escapes them.
_DRIFT_IDENTITY_FIELD_MAX_JSON_CHARS = 2_048
_DRIFT_DIAGNOSTIC_MAX_CHARS = 7_500
_DRIFT_IDENTITY_FIELDS = ("address", "mode", "type")

# The public identities below were read back from each live cell producer:
# cell1's Terraform 1.14.3 output and a readback emitting only the server
# secret's publicKey field agree on the exact key and FQDN; cell0's equivalent
# public-key readback agrees with its
# previously recorded fleet invariant. cell1 is deliberately non-assignable.
#
# updated_at is a deterministic mutation revision included in qurl-service's
# optimistic cell fence. Change it with every reviewed row mutation; never
# derive it from wall-clock plan/apply time.
# selection_weight mirrors Terraform's tostring(tonumber(...)) stored spelling,
# not a noncanonical form accepted only at the module input.
PROVISIONED_CELL_CATALOG = {
    "cell0": {
        "cell_id": "cell0",
        "status": "active",
        "endpoint_revision": 2,
        "nhp_host": "cell0.nhp.layerv.xyz",
        "nhp_port": 443,
        "server_public_key_b64": "9dVku2oF589tWz9/Hn01STtstgkum4MM4kgKEp7lCw8=",
        "selection_weight": "1",
        "updated_at": "2026-08-01T18:00:00Z",
    },
    "cell1": {
        "cell_id": "cell1",
        "status": "active",
        "endpoint_revision": 2,
        "nhp_host": "cell1.nhp.layerv.xyz",
        "nhp_port": 443,
        "server_public_key_b64": "Sb4lH7rfkKTagGvpKeBx/ArYual9fM4EQCQkiqxGNBs=",
        "selection_weight": "1",
        "updated_at": "2026-08-01T18:00:00Z",
    },
}
PROVISIONED_CELL_DYNAMODB_ITEMS = {
    cell_id: {
        "pk": {"S": "REGISTRY"},
        "sk": {"S": f"CELL#{cell_id}"},
        "cell_id": {"S": cell["cell_id"]},
        "status": {"S": cell["status"]},
        "endpoint_revision": {"N": str(cell["endpoint_revision"])},
        "nhp_host": {"S": cell["nhp_host"]},
        "nhp_port": {"N": str(cell["nhp_port"])},
        "server_public_key_b64": {"S": cell["server_public_key_b64"]},
        "selection_weight": {"N": cell["selection_weight"]},
        "updated_at": {"S": cell["updated_at"]},
    }
    for cell_id, cell in PROVISIONED_CELL_CATALOG.items()
}
PROVISIONED_CELL_ADDRESSES = {
    cell_id: f'module.control.aws_dynamodb_table_item.provisioned_cell["{cell_id}"]'
    for cell_id in PROVISIONED_CELL_CATALOG
}
PROVISIONED_CELL_RESOURCES = {
    address: "aws_dynamodb_table_item"
    for address in PROVISIONED_CELL_ADDRESSES.values()
}
PROVISIONED_CELL_ID_BY_ADDRESS = {
    address: cell_id for cell_id, address in PROVISIONED_CELL_ADDRESSES.items()
}
# The configuration's `jsonencode` spelling of each row, fixed per cell and
# serialized once at import. This is the exact create-plan rendering; a
# refreshed read re-renders the same object differently (see
# `_require_provisioned_cell_item`), so the checker compares the DECODED item
# and this literal only documents the canonical create-time text.
PROVISIONED_CELL_EXPECTED_ITEM_JSON = {
    cell_id: json.dumps(item, separators=(",", ":"), sort_keys=True)
    for cell_id, item in PROVISIONED_CELL_DYNAMODB_ITEMS.items()
}
PROVISIONED_CELL_TABLE_NAME = f"{CONTROL_PREFIX}-connector-authority"
# Separator the locked hashicorp/aws 6.55.0 provider uses to compose the
# aws_dynamodb_table_item resource id. Observed on the applied sandbox rows,
# not assumed; a provider that changed it must fail closed and be re-proven
# from a real refreshed state.
PROVISIONED_CELL_ID_SEPARATOR = ","

EXPECTED_RESOURCES = {
    "module.control.aws_cloudwatch_log_group.flow_logs": "aws_cloudwatch_log_group",
    "module.control.aws_default_security_group.control": "aws_default_security_group",
    "module.control.aws_dynamodb_table.agent_keys": "aws_dynamodb_table",
    "module.control.aws_dynamodb_table.api_key_idempotency": "aws_dynamodb_table",
    "module.control.aws_dynamodb_table.api_keys": "aws_dynamodb_table",
    "module.control.aws_dynamodb_table.connector_authority": "aws_dynamodb_table",
    "module.control.aws_dynamodb_table.customers": "aws_dynamodb_table",
    **PROVISIONED_CELL_RESOURCES,
    "module.control.aws_ecr_lifecycle_policy.hub": "aws_ecr_lifecycle_policy",
    "module.control.aws_ecr_repository.authority": "aws_ecr_repository",
    "module.control.aws_ecr_repository.hub": "aws_ecr_repository",
    "module.control.aws_elasticache_serverless_cache.otp": "aws_elasticache_serverless_cache",
    "module.control.aws_elasticache_user.otp_activator": "aws_elasticache_user",
    "module.control.aws_elasticache_user.otp_disabled_default": "aws_elasticache_user",
    "module.control.aws_elasticache_user.otp_issuer": "aws_elasticache_user",
    "module.control.aws_elasticache_user_group.otp": "aws_elasticache_user_group",
    "module.control.aws_flow_log.control": "aws_flow_log",
    "module.control.aws_iam_role.flow_logs": "aws_iam_role",
    "module.control.aws_iam_role.authority_publisher": "aws_iam_role",
    "module.control.aws_iam_role.hub_publisher": "aws_iam_role",
    "module.control.aws_iam_role_policy.authority_publisher": "aws_iam_role_policy",
    "module.control.aws_iam_role_policy.flow_logs": "aws_iam_role_policy",
    "module.control.aws_iam_role_policy.hub_publisher": "aws_iam_role_policy",
    "module.control.aws_kms_alias.authority_data": "aws_kms_alias",
    "module.control.aws_kms_alias.qat1_signing": "aws_kms_alias",
    "module.control.aws_kms_key.authority_data": "aws_kms_key",
    "module.control.aws_kms_key.qat1_signing": "aws_kms_key",
    "module.control.aws_route_table.isolated[0]": "aws_route_table",
    "module.control.aws_route_table.isolated[1]": "aws_route_table",
    "module.control.aws_route_table.isolated[2]": "aws_route_table",
    "module.control.aws_route_table_association.isolated[0]": "aws_route_table_association",
    "module.control.aws_route_table_association.isolated[1]": "aws_route_table_association",
    "module.control.aws_route_table_association.isolated[2]": "aws_route_table_association",
    "module.control.aws_secretsmanager_secret.otp_pepper": "aws_secretsmanager_secret",
    "module.control.aws_security_group.interface_endpoints": "aws_security_group",
    "module.control.aws_security_group.otp_redis": "aws_security_group",
    "module.control.aws_ssm_parameter.authority_image_digest": "aws_ssm_parameter",
    "module.control.aws_ssm_parameter.hub_image_digest": "aws_ssm_parameter",
    "module.control.aws_subnet.isolated[0]": "aws_subnet",
    "module.control.aws_subnet.isolated[1]": "aws_subnet",
    "module.control.aws_subnet.isolated[2]": "aws_subnet",
    "module.control.aws_vpc.control": "aws_vpc",
    "module.control.aws_vpc_endpoint.dynamodb": "aws_vpc_endpoint",
    'module.control.aws_vpc_endpoint.interface["email"]': "aws_vpc_endpoint",
    'module.control.aws_vpc_endpoint.interface["kms"]': "aws_vpc_endpoint",
    'module.control.aws_vpc_endpoint.interface["lambda"]': "aws_vpc_endpoint",
    'module.control.aws_vpc_endpoint.interface["logs"]': "aws_vpc_endpoint",
    'module.control.aws_vpc_endpoint.interface["monitoring"]': "aws_vpc_endpoint",
    'module.control.aws_vpc_endpoint.interface["secretsmanager"]': "aws_vpc_endpoint",
    "module.control.terraform_data.foundation_contract": "terraform_data",
}

PUBLISHER_BOOTSTRAP_RESOURCES = frozenset(
    {
        "module.control.aws_iam_role.authority_publisher",
        "module.control.aws_iam_role_policy.authority_publisher",
    }
)
HUB_ARTIFACT_BOOTSTRAP_RESOURCES = frozenset(
    {
        "module.control.aws_ecr_lifecycle_policy.hub",
        "module.control.aws_ecr_repository.hub",
        "module.control.aws_iam_role.hub_publisher",
        "module.control.aws_iam_role_policy.hub_publisher",
        "module.control.aws_ssm_parameter.hub_image_digest",
    }
)
REDIS_SPLIT_USER_RESOURCES = frozenset(
    {
        "module.control.aws_elasticache_user.otp_activator",
        "module.control.aws_elasticache_user.otp_issuer",
    }
)
# The single reviewed removal of the broad `~connector:*` legacy Connector OTP
# Redis user (NHP #3362). The split rollout detached it from the user group but
# deliberately kept the resource so that destructive cleanup never rode along
# with the reviewed user-split migration. Source no longer declares it, so the
# one admitted plan that still mentions this address is its exact delete, which
# _is_exact_legacy_otp_user_delete pins field-for-field and check_plan refuses
# to combine with any other Control change. It is absent from EXPECTED_RESOURCES
# because the state and state-list lanes run only AFTER that apply. Remove all
# three names once the delete is applied and its no-op proof is recorded.
# The Hub source-fence ingress rule the open-sandbox transition removes
# (qurl-go ADR 0001, ledger 2026-08-03-open-sandbox-udp-edges). Source no longer
# declares it, so a plan against the fenced state names it exactly once, as its
# delete. Its replacement, hub_nlb_udp["0.0.0.0/0"], is an ordinary member of
# HUB_EDGE_RESOURCES and needs no special handling.
LEGACY_HUB_SOURCE_FENCE_ADDRESS = (
    "module.control.aws_vpc_security_group_ingress_rule."
    'hub_nlb_udp["3.141.109.76/32"]'
)
LEGACY_HUB_SOURCE_FENCE_CIDR = "3.141.109.76/32"
LEGACY_HUB_SOURCE_FENCE_TYPE = "aws_vpc_security_group_ingress_rule"

LEGACY_OTP_REDIS_USER_ADDRESS = "module.control.aws_elasticache_user.otp_authority"
LEGACY_OTP_REDIS_USER_ID = f"{CONTROL_PREFIX}-otp-auth"
LEGACY_OTP_REDIS_USER_TYPE = "aws_elasticache_user"

# ---------------------------------------------------------------------------
# Connector Authority runtime slice (Step 4).
#
# The runtime deploys the complete frozen two-cell graph: 3 Hub functions plus
# 4 functions for each of cell0/cell1, both closed blue/green aliases, per-operation
# execution roles, steady provisioned/reserved concurrency, spillover alarms,
# a dedicated function SG, and the lockstep opening of only the dependency
# endpoints those functions reach. It is an
# all-or-nothing transition on top of the already-bound contract: the plan's
# managed inventory is either the base foundation OR the base + this exact
# runtime set, and nothing else may become non-no-op.
#
# CALIBRATION BOUNDARY (POST-STEP-3): the exhaustive value-free create-envelope
# for every runtime resource (provider default nulls/unknowns, exactly as the
# base resources are pinned in _check_planned_security) can only be captured
# from a real Terraform 1.14.3 / AWS provider 6.55.0 Step-4 plan, which requires
# the Step-3 contract bind to be applied first. This checker therefore enforces
# the fail-closed STRUCTURE now — exact inventory, exact all-or-nothing
# transition membership, pure-create vs the exact dependency endpoint/SG opens, the
# security content of those opens (principals/actions/resources, no wildcard),
# the reserved/provisioned concurrency tie-back to the frozen contract, and the
# dark endpoints staying deny — and the first real plan JSON must extend the
# per-field envelope before the summary is frozen into the apply gate.
# ---------------------------------------------------------------------------
AUTHORITY_RUNTIME_HUB_FUNCTIONS = {
    f"{CONTROL_PREFIX.removesuffix('-control')}-ca-ia": "issue_assignment",
    f"{CONTROL_PREFIX.removesuffix('-control')}-ca-ra": "refresh_assignment",
    f"{CONTROL_PREFIX.removesuffix('-control')}-ca-icr": "issue_credential_recovery",
}
# The provisioned cells and the per-cell operation suffix -> operation map are
# the two independent axes of the cell function inventory; keep each stated once
# so adding a cell or an operation is a single-line edit.
AUTHORITY_CELLS = ("cell0", "cell1")
AUTHORITY_CELL_OPERATION_SUFFIXES = {
    "iro": "issue_registration_otp",
    "ar": "activate_registration",
    "cr": "complete_registration",
    "ccr": "complete_credential_recovery",
}
AUTHORITY_RUNTIME_CELL_FUNCTIONS = {
    f"{CONTROL_PREFIX.removesuffix('-control')}-ca-{suffix}-{cell_id}": operation
    for cell_id in AUTHORITY_CELLS
    for suffix, operation in AUTHORITY_CELL_OPERATION_SUFFIXES.items()
}
AUTHORITY_RUNTIME_FUNCTIONS = {
    **AUTHORITY_RUNTIME_HUB_FUNCTIONS,
    **AUTHORITY_RUNTIME_CELL_FUNCTIONS,
}
AUTHORITY_PROOF_FUNCTIONS = {
    AUTHORITY_PROOF_FUNCTION_NAME: AUTHORITY_PROOF_OPERATION,
    AUTHORITY_PROOF_RECOVERY_FUNCTION_NAME: AUTHORITY_PROOF_RECOVERY_OPERATION,
}
AUTHORITY_RUNTIME_FUNCTIONS_WITH_PROOF = {
    **AUTHORITY_RUNTIME_FUNCTIONS,
    **AUTHORITY_PROOF_FUNCTIONS,
}
AUTHORITY_RUNTIME_LEGACY_HUB_EVIDENCE = {
    "path": "docs/evidence/connector-authority/v1/sandbox-measurement-basis.json",
    "repository": "layervai/nhp",
    "schema_version": 1,
    "sha256": "d535970977ba3b31da2b224c01897c535786ff802a91edbe8319884c23924eff",
    "source_commit": "388a22f7a5333a246e623a19dd5ca3793bd89f60",
}
AUTHORITY_RUNTIME_LAMBDA_SG_ADDRESS = (
    "module.control.aws_security_group.authority_lambda[0]"
)
AUTHORITY_RUNTIME_RESOURCES: dict[str, str] = {}
for _fn in AUTHORITY_RUNTIME_FUNCTIONS:
    AUTHORITY_RUNTIME_RESOURCES[
        f'module.control.aws_lambda_function.authority["{_fn}"]'
    ] = "aws_lambda_function"
    AUTHORITY_RUNTIME_RESOURCES[
        f'module.control.aws_lambda_alias.authority["{_fn}:blue"]'
    ] = "aws_lambda_alias"
    AUTHORITY_RUNTIME_RESOURCES[
        f'module.control.aws_lambda_alias.authority["{_fn}:green"]'
    ] = "aws_lambda_alias"
    AUTHORITY_RUNTIME_RESOURCES[
        f'module.control.aws_lambda_provisioned_concurrency_config.authority["{_fn}"]'
    ] = "aws_lambda_provisioned_concurrency_config"
    AUTHORITY_RUNTIME_RESOURCES[
        f'module.control.aws_iam_role.authority_exec["{_fn}"]'
    ] = "aws_iam_role"
    AUTHORITY_RUNTIME_RESOURCES[
        f'module.control.aws_iam_role_policy.authority_exec["{_fn}"]'
    ] = "aws_iam_role_policy"
    AUTHORITY_RUNTIME_RESOURCES[
        f'module.control.aws_cloudwatch_log_group.authority["{_fn}"]'
    ] = "aws_cloudwatch_log_group"
    AUTHORITY_RUNTIME_RESOURCES[
        f'module.control.aws_cloudwatch_metric_alarm.authority_spillover["{_fn}"]'
    ] = "aws_cloudwatch_metric_alarm"
AUTHORITY_RUNTIME_RESOURCES[AUTHORITY_RUNTIME_LAMBDA_SG_ADDRESS] = "aws_security_group"
AUTHORITY_RUNTIME_RESOURCES[
    "module.control.aws_vpc_security_group_egress_rule.authority_interface_endpoints[0]"
] = "aws_vpc_security_group_egress_rule"
AUTHORITY_RUNTIME_RESOURCES[
    "module.control.aws_vpc_security_group_egress_rule.authority_dynamodb[0]"
] = "aws_vpc_security_group_egress_rule"
AUTHORITY_RUNTIME_RESOURCES[
    "module.control.aws_vpc_security_group_egress_rule.authority_otp_redis[0]"
] = "aws_vpc_security_group_egress_rule"
AUTHORITY_RUNTIME_RESOURCES[
    "module.control.aws_vpc_security_group_ingress_rule.otp_redis_authority[0]"
] = "aws_vpc_security_group_ingress_rule"

# ---------------------------------------------------------------------------
# Operator alert routing and the full runtime alarm set (NHP #3455).
#
# The spillover alarm above is the one member that already exists live; every
# address below is new. They are folded into AUTHORITY_RUNTIME_RESOURCES so the
# exact-inventory equality admits them, and deliberately EXCLUDED from the
# legacy-expansion create set (that transition is historical and provably did
# not contain them).
#
# AUTHORITY_ALARM_DIMENSIONS is the authoritative expected dim set per address.
# It is written out longhand rather than derived from the Terraform, so a
# Terraform-side dimension change has to be restated here to pass — that is the
# whole point of the check. The prefix mirrors the qurl-service EMF publisher
# (internal/connectorauthorityruntime/telemetry.go::emitPoint): EnvironmentID
# and AuthorityOperation always, CellID only for cell operations, then the
# metric's own dynamic dimensions.
# ---------------------------------------------------------------------------
AUTHORITY_ALARM_NAMESPACE_LAMBDA = "AWS/Lambda"
AUTHORITY_ALARM_NAMESPACE_CUSTOM = "LayerV/ConnectorAuthority"
AUTHORITY_OPERATION_CONFORMANCE_NAME = {
    "issue_assignment": "IssueAssignment",
    "refresh_assignment": "RefreshAssignment",
    "issue_credential_recovery": "IssueCredentialRecovery",
    "issue_registration_otp": "IssueRegistrationOTP",
    "activate_registration": "ActivateRegistration",
    "complete_registration": "CompleteRegistration",
    "complete_credential_recovery": "CompleteCredentialRecovery",
    "mutate_proof_agent": "MutateProofAgent",
    "prepare_proof_credential_recovery": "PrepareProofCredentialRecovery",
}
# The reviewed Lambda timeout is 10s; the duration alarm pages at 80% of it.
AUTHORITY_ALARM_LAMBDA_TIMEOUT_SECONDS = 10
AUTHORITY_ALARM_DURATION_THRESHOLD_MS = AUTHORITY_ALARM_LAMBDA_TIMEOUT_SECONDS * 800
# Registration-adapter metrics are emitted only by the admission-gated cell
# operations; completion identity rejection only by CompleteRegistration.
AUTHORITY_ADMISSION_OPERATIONS = frozenset(
    {"activate_registration", "complete_registration"}
)
AUTHORITY_ALARM_ADMISSION_OUTCOMES = ("limited", "unavailable")
AUTHORITY_ALARM_TERMINAL_OUTCOMES = ("internal", "unavailable")
AUTHORITY_ALARM_COMPLETION_CAUSE = "authority_fence"
# (resource name, metric name, statistic, extended statistic, comparison,
#  threshold; None threshold == resolved from the bound contract).
# A None statistic/extended_statistic means the alarm leaves that field unset --
# the two are mutually exclusive. It matches both the creation plan's `null` and
# the applied state's `""`; see _authority_alarm_statistic.
AUTHORITY_ALARM_LAMBDA_FAMILIES = {
    "errors": ("Errors", "Sum", None, "GreaterThanThreshold", 0),
    "throttles": ("Throttles", "Sum", None, "GreaterThanThreshold", 0),
    "duration": (
        "Duration",
        None,
        "p99",
        "GreaterThanThreshold",
        AUTHORITY_ALARM_DURATION_THRESHOLD_MS,
    ),
    "concurrency_exhaustion": (
        "ConcurrentExecutions",
        "Maximum",
        None,
        "GreaterThanOrEqualToThreshold",
        None,
    ),
    "async_invocation": (
        "AsyncEventsReceived",
        "Sum",
        None,
        "GreaterThanThreshold",
        0,
    ),
}
AUTHORITY_ALARM_RESOURCES: dict[str, str] = {}
AUTHORITY_ALARM_DIMENSIONS: dict[str, dict[str, str]] = {}


def _authority_alarm_identity_dimensions(function_name: str) -> dict[str, str]:
    """The EMF publisher's identity dimension prefix for one function."""
    operation = AUTHORITY_RUNTIME_FUNCTIONS_WITH_PROOF[function_name]
    dimensions = {
        "EnvironmentID": CONTROL_PREFIX.removeprefix("layerv-nhp-").removesuffix(
            "-control"
        ),
        "AuthorityOperation": AUTHORITY_OPERATION_CONFORMANCE_NAME[operation],
    }
    if function_name in AUTHORITY_RUNTIME_CELL_FUNCTIONS:
        dimensions["CellID"] = function_name.rsplit("-", 1)[1]
    return dimensions


AUTHORITY_ALARM_ADDRESSES_BY_FUNCTION: dict[str, set[str]] = {}
for _fn, _operation in AUTHORITY_RUNTIME_FUNCTIONS_WITH_PROOF.items():
    _function_alarm_addresses: set[str] = set()
    # AWS/Lambda platform alarms key on the published function-wide dim set.
    _spillover_address = (
        f'module.control.aws_cloudwatch_metric_alarm.authority_spillover["{_fn}"]'
    )
    AUTHORITY_ALARM_DIMENSIONS[_spillover_address] = {"FunctionName": _fn}
    _function_alarm_addresses.add(_spillover_address)
    for _family in AUTHORITY_ALARM_LAMBDA_FAMILIES:
        _address = (
            "module.control.aws_cloudwatch_metric_alarm."
            f'authority_runtime["{_fn}:{_family}"]'
        )
        AUTHORITY_ALARM_RESOURCES[_address] = "aws_cloudwatch_metric_alarm"
        AUTHORITY_ALARM_DIMENSIONS[_address] = {"FunctionName": _fn}
        _function_alarm_addresses.add(_address)
    _composite_address = (
        "module.control.aws_cloudwatch_composite_alarm."
        f'authority_non_provisioned_initialization["{_fn}"]'
    )
    AUTHORITY_ALARM_RESOURCES[_composite_address] = "aws_cloudwatch_composite_alarm"
    _function_alarm_addresses.add(_composite_address)
    for _outcome in AUTHORITY_ALARM_TERMINAL_OUTCOMES:
        _address = (
            "module.control.aws_cloudwatch_metric_alarm."
            f'authority_terminal_outcome["{_fn}:{_outcome}"]'
        )
        AUTHORITY_ALARM_RESOURCES[_address] = "aws_cloudwatch_metric_alarm"
        AUTHORITY_ALARM_DIMENSIONS[_address] = {
            **_authority_alarm_identity_dimensions(_fn),
            "Outcome": _outcome,
        }
        _function_alarm_addresses.add(_address)
    if _operation in AUTHORITY_ADMISSION_OPERATIONS:
        for _outcome in AUTHORITY_ALARM_ADMISSION_OUTCOMES:
            _address = (
                "module.control.aws_cloudwatch_metric_alarm."
                f'authority_admission_rejected["{_fn}:{_outcome}"]'
            )
            AUTHORITY_ALARM_RESOURCES[_address] = "aws_cloudwatch_metric_alarm"
            AUTHORITY_ALARM_DIMENSIONS[_address] = {
                **_authority_alarm_identity_dimensions(_fn),
                "Outcome": _outcome,
            }
            _function_alarm_addresses.add(_address)
        for _resource in (
            "authority_adapter_contract_violation",
            "authority_adapter_late_result",
        ):
            _address = (
                f'module.control.aws_cloudwatch_metric_alarm.{_resource}["{_fn}"]'
            )
            AUTHORITY_ALARM_RESOURCES[_address] = "aws_cloudwatch_metric_alarm"
            # These two counters carry NO dynamic dimension.
            AUTHORITY_ALARM_DIMENSIONS[_address] = (
                _authority_alarm_identity_dimensions(_fn)
            )
            _function_alarm_addresses.add(_address)
    if _operation == "complete_registration":
        _address = (
            "module.control.aws_cloudwatch_metric_alarm."
            f'authority_completion_identity_rejected["{_fn}"]'
        )
        AUTHORITY_ALARM_RESOURCES[_address] = "aws_cloudwatch_metric_alarm"
        AUTHORITY_ALARM_DIMENSIONS[_address] = {
            **_authority_alarm_identity_dimensions(_fn),
            "Cause": AUTHORITY_ALARM_COMPLETION_CAUSE,
        }
        _function_alarm_addresses.add(_address)
    AUTHORITY_ALARM_ADDRESSES_BY_FUNCTION[_fn] = _function_alarm_addresses

AUTHORITY_PROOF_ALARM_RESOURCES = {
    address: AUTHORITY_ALARM_RESOURCES[address]
    for function_name in AUTHORITY_PROOF_FUNCTIONS
    for address in AUTHORITY_ALARM_ADDRESSES_BY_FUNCTION[function_name]
    if address in AUTHORITY_ALARM_RESOURCES
}
AUTHORITY_ALARM_RESOURCES = {
    address: resource_type
    for address, resource_type in AUTHORITY_ALARM_RESOURCES.items()
    if address not in AUTHORITY_PROOF_ALARM_RESOURCES
}
AUTHORITY_RUNTIME_RESOURCES.update(AUTHORITY_ALARM_RESOURCES)
AUTHORITY_PROOF_RESOURCES: dict[str, str] = {
    **AUTHORITY_PROOF_ALARM_RESOURCES,
}
for _fn in AUTHORITY_PROOF_FUNCTIONS:
    AUTHORITY_PROOF_RESOURCES.update(
        {
            f'module.control.aws_lambda_function.authority["{_fn}"]': (
                "aws_lambda_function"
            ),
            f'module.control.aws_lambda_alias.authority["{_fn}:blue"]': (
                "aws_lambda_alias"
            ),
            f'module.control.aws_lambda_alias.authority["{_fn}:green"]': (
                "aws_lambda_alias"
            ),
            (
                "module.control.aws_lambda_provisioned_concurrency_config."
                f'authority["{_fn}"]'
            ): "aws_lambda_provisioned_concurrency_config",
            f'module.control.aws_iam_role.authority_exec["{_fn}"]': "aws_iam_role",
            f'module.control.aws_iam_role_policy.authority_exec["{_fn}"]': (
                "aws_iam_role_policy"
            ),
            f'module.control.aws_cloudwatch_log_group.authority["{_fn}"]': (
                "aws_cloudwatch_log_group"
            ),
            (
                "module.control.aws_cloudwatch_metric_alarm."
                f'authority_spillover["{_fn}"]'
            ): "aws_cloudwatch_metric_alarm",
        }
    )
AUTHORITY_PROOF_ENABLE_UPDATE_ADDRESSES = frozenset(
    {
        "module.control.terraform_data.foundation_contract",
        "module.control.aws_vpc_endpoint.dynamodb",
    }
)
AUTHORITY_PROOF_ENABLE_ALL_CHANGES = frozenset(
    set(AUTHORITY_PROOF_RESOURCES) | set(AUTHORITY_PROOF_ENABLE_UPDATE_ADDRESSES)
)
AUTHORITY_PROOF_CONSUMER_FUNCTIONS = frozenset(
    {
        "layerv-nhp-sandbox-ca-ia",
        "layerv-nhp-sandbox-ca-ra",
        "layerv-nhp-sandbox-ca-icr",
    }
)
AUTHORITY_PROOF_CONSUMER_LIVE_ALIAS_DATA_RESOURCES = frozenset(
    f'module.control.data.aws_lambda_alias.authority_proof_policy_live["{function_name}:{color}"]'
    for function_name in AUTHORITY_PROOF_CONSUMER_FUNCTIONS
    for color in ("blue", "green")
)
AUTHORITY_PROOF_ROLLOUT_LIVE_ALIAS_DATA_RESOURCES = frozenset(
    f'module.control.data.aws_lambda_alias.authority_proof_policy_live["{AUTHORITY_PROOF_FUNCTION_NAME}:{color}"]'
    for color in ("blue", "green")
)
AUTHORITY_PROOF_CONSUMER_BASE_UPDATE_ADDRESSES = frozenset(
    {
        "module.control.terraform_data.foundation_contract",
        *(
            address
            for function_name in AUTHORITY_PROOF_CONSUMER_FUNCTIONS
            for address in (
                f'module.control.aws_lambda_function.authority["{function_name}"]',
                f'module.control.aws_iam_role_policy.authority_exec["{function_name}"]',
            )
        ),
    }
)
AUTHORITY_PROOF_ROLLOUT_FUNCTIONS = frozenset(
    {*AUTHORITY_PROOF_CONSUMER_FUNCTIONS, AUTHORITY_PROOF_FUNCTION_NAME}
)
AUTHORITY_PROOF_ROLLOUT_RESOURCES = {
    (
        "module.control.aws_lambda_provisioned_concurrency_config."
        f'authority_proof_standby["{function_name}"]'
    ): "aws_lambda_provisioned_concurrency_config"
    for function_name in AUTHORITY_PROOF_ROLLOUT_FUNCTIONS
}
AUTHORITY_PROOF_ROLLOUT_SELECTOR_CHANGES = frozenset(
    {
        "module.control.terraform_data.foundation_contract",
        "module.control.aws_ecs_task_definition.hub[0]",
        "module.control.aws_ecs_service.hub[0]",
    }
)
# The 11 already-live spillover alarms gain alarm_actions in place; every other
# alarm address is a pure create.
AUTHORITY_ALARM_UPDATE_ADDRESSES = frozenset(
    f'module.control.aws_cloudwatch_metric_alarm.authority_spillover["{_fn}"]'
    for _fn in AUTHORITY_RUNTIME_FUNCTIONS
)

# Exec-policy addresses for EVERY authority function the contract knows about,
# hub and per-cell and proof alike.
#
# The legacy set below is built from the hub functions only, which was the whole
# runtime when it was written. The runtime has since grown per-cell and proof
# functions, so a plan that touches all of their exec policies presents
# addresses the legacy set cannot name -- the shape is identical, the membership
# test is simply out of date. Deriving from the function map keeps the claim
# bounded (an address for an unknown function is still never claimable) while
# tracking the runtime instead of a moment in its history.
AUTHORITY_EXEC_POLICY_ADDRESSES = frozenset(
    f'module.control.aws_iam_role_policy.authority_exec["{_fn}"]'
    for _fn in AUTHORITY_RUNTIME_FUNCTIONS_WITH_PROOF
)

AUTHORITY_RUNTIME_LEGACY_HUB_RESOURCE_ADDRESSES = {
    AUTHORITY_RUNTIME_LAMBDA_SG_ADDRESS
}
for _fn in AUTHORITY_RUNTIME_HUB_FUNCTIONS:
    AUTHORITY_RUNTIME_LEGACY_HUB_RESOURCE_ADDRESSES.update(
        {
            f'module.control.aws_lambda_function.authority["{_fn}"]',
            f'module.control.aws_lambda_alias.authority["{_fn}:blue"]',
            f'module.control.aws_lambda_alias.authority["{_fn}:green"]',
            (
                "module.control.aws_lambda_provisioned_concurrency_config."
                f'authority["{_fn}"]'
            ),
            f'module.control.aws_iam_role.authority_exec["{_fn}"]',
            f'module.control.aws_iam_role_policy.authority_exec["{_fn}"]',
            f'module.control.aws_cloudwatch_log_group.authority["{_fn}"]',
            (
                "module.control.aws_cloudwatch_metric_alarm."
                f'authority_spillover["{_fn}"]'
            ),
        }
    )
AUTHORITY_RUNTIME_LEGACY_EXPANSION_CREATE_ADDRESSES = frozenset(
    set(AUTHORITY_RUNTIME_RESOURCES)
    - AUTHORITY_RUNTIME_LEGACY_HUB_RESOURCE_ADDRESSES
    # The alarm-routing addresses post-date the legacy expansion; that reviewed
    # transition provably did not contain them, so admitting them here would
    # widen a historical shape.
    - set(AUTHORITY_ALARM_RESOURCES)
)
AUTHORITY_RUNTIME_LEGACY_EXPANSION_REPLACE_ADDRESSES = frozenset(
    {AUTHORITY_RUNTIME_LAMBDA_SG_ADDRESS}
)
# The reviewed image migration retags every Authority function that exists in
# the complete sandbox graph. The target image is the first published artifact
# containing the attended-proof PM/PCR operations, so the two proof functions
# participate alongside the eleven steady runtime functions. Keep the admitted
# set to immutable-image function and alias updates only.
AUTHORITY_IMAGE_UPDATE_RESOURCES = {
    address: resource_type
    for address, resource_type in {
        **AUTHORITY_RUNTIME_RESOURCES,
        **AUTHORITY_PROOF_RESOURCES,
    }.items()
    if resource_type in {"aws_lambda_alias", "aws_lambda_function"}
}
AUTHORITY_IMAGE_UPDATE_FROM_URI = (
    f"{ACCOUNT_ID}.dkr.ecr.{AWS_REGION}.amazonaws.com/"
    "layerv/qurl-connector-authority@"
    "sha256:7d15a8ce1a9b34586c79d1ce3310b66041f8b55de2fda01b330f54ec94feaa9a"
)
AUTHORITY_IMAGE_UPDATE_TO_URI = (
    f"{ACCOUNT_ID}.dkr.ecr.{AWS_REGION}.amazonaws.com/"
    "layerv/qurl-connector-authority@"
    "sha256:264d9a20b55c9b122213c9426bf3cdc39933b3200567bb617c70e68a28aa6f0c"
)
AUTHORITY_IMAGE_UPDATE_FOUNDATION_ADDRESS = (
    "module.control.terraform_data.foundation_contract"
)
AUTHORITY_IMAGE_UPDATE_FROM_EVIDENCE_SHA256 = (
    "d84cb3e223f0af1d3c4542d007f0a611ca272f21598907a01f19516e0d4e1308"
)
AUTHORITY_IMAGE_UPDATE_FROM_EVIDENCE_SOURCE = (
    "666eaf6fdb63650ad77238c1e817d7e36e24bc5d"
)
AUTHORITY_IMAGE_UPDATE_TO_EVIDENCE_SHA256 = (
    "6d5f5a2e1e7bb38234ff5edb568fa3a163ca6a3ff3093c07ca8d4f38819e3dd0"
)
AUTHORITY_IMAGE_UPDATE_TO_EVIDENCE_SOURCE = (
    "a59795ae56859e37cfbe6f2c00df0a8c14c8d47a"
)
AUTHORITY_IMAGE_UPDATE_RECOVERY_REPLACES = frozenset(
    address
    for address, resource_type in AUTHORITY_PROOF_RESOURCES.items()
    if resource_type == "aws_lambda_provisioned_concurrency_config"
)
AUTHORITY_PROOF_CONCURRENCY_RECOVERY_NORMALIZATION_KIND = (
    "authority-proof-concurrency-recovery"
)
AUTHORITY_PROOF_PREPARE_RECOVERY_CONCURRENCY_ADDRESSES = frozenset(
    "module.control.aws_lambda_provisioned_concurrency_config."
    f'authority_proof_standby["{function_name}"]'
    for function_name in AUTHORITY_PROOF_CONSUMER_FUNCTIONS
)
AUTHORITY_PROOF_PREPARE_RECOVERY_HUB_ROLE_ADDRESS = (
    "module.control.aws_iam_role.hub_task[0]"
)
AUTHORITY_PROOF_PREPARE_RECOVERY_DRIFT_ADDRESSES = frozenset(
    {
        AUTHORITY_PROOF_PREPARE_RECOVERY_HUB_ROLE_ADDRESS,
        *AUTHORITY_PROOF_PREPARE_RECOVERY_CONCURRENCY_ADDRESSES,
    }
)
AUTHORITY_PROOF_PREPARE_RECOVERY_NORMALIZATION_KIND = (
    "authority-proof-rollout-prepare-recovery"
)
# The historical live Hub predecessor sat at ONE of the two reviewed endpoints
# of its original Authority image transition, and at no other basis:
#   * FROM (d535970977.../388a22f7a) -- the expansion plans before the reviewed
#     image update applies. This IS AUTHORITY_RUNTIME_LEGACY_HUB_EVIDENCE.
#   * TO   (b44ee0ca10.../38c11ec13) -- the reviewed image update ALREADY applied
#     its foundation contract, so the live predecessor advanced to the exact
#     basis _check_authority_image_update itself pins as that transition's
#     after-state. This is the observed sandbox state: the image apply converged
#     the contract and every function's $LATEST, then failed on
#     lambda:PublishVersion, leaving the alias rebind pending.
# These historical endpoints deliberately remain independent of the current
# full-graph image migration pins above. Enumerating exactly these two keeps the
# admitted predecessor set closed: a basis that is neither -- including any
# mixture across the evidence slots -- still fails.
AUTHORITY_RUNTIME_LEGACY_HUB_EVIDENCE_CANDIDATES = tuple(
    {
        **AUTHORITY_RUNTIME_LEGACY_HUB_EVIDENCE,
        "sha256": sha256,
        "source_commit": source_commit,
    }
    for sha256, source_commit in (
        (
            "d535970977ba3b31da2b224c01897c535786ff802a91edbe8319884c23924eff",
            "388a22f7a5333a246e623a19dd5ca3793bd89f60",
        ),
        (
            "b44ee0ca10d555db931713f2809b1e45c149c0382d5aaee2a5bf1cf252b55056",
            "38c11ec130f7443339581eb42692f3577812f904",
        ),
    )
)
_AUTHORITY_FUNCTION_UPDATE_COMPUTED_FIELDS = frozenset(
    {"last_modified", "qualified_arn", "qualified_invoke_arn", "version"}
)

# Connector Hub public UDP edge slice (Step 5 slice 5a): the authority's only
# caller-facing public edge. These types are moved out of the lexical forbidden
# set (check-connector-authority-foundation.sh) and gated instead by this exact
# set -- admitted only all-at-once, compositionally alongside the runtime slice.
# check_live additionally proves the 0.0.0.0/0 route lives ONLY on the public
# edge route table and that exactly this one internet gateway exists.
HUB_EDGE_RESOURCES: dict[str, str] = {
    "module.control.aws_subnet.hub_public[0]": "aws_subnet",
    "module.control.aws_subnet.hub_public[1]": "aws_subnet",
    "module.control.aws_subnet.hub_public[2]": "aws_subnet",
    "module.control.aws_internet_gateway.hub_edge[0]": "aws_internet_gateway",
    "module.control.aws_route_table.hub_public[0]": "aws_route_table",
    "module.control.aws_route.hub_public_default[0]": "aws_route",
    "module.control.aws_route_table_association.hub_public[0]": "aws_route_table_association",
    "module.control.aws_route_table_association.hub_public[1]": "aws_route_table_association",
    "module.control.aws_route_table_association.hub_public[2]": "aws_route_table_association",
    "module.control.aws_security_group.hub_nlb[0]": "aws_security_group",
    'module.control.aws_vpc_security_group_ingress_rule.hub_nlb_udp["0.0.0.0/0"]': "aws_vpc_security_group_ingress_rule",
    "module.control.aws_lb.hub[0]": "aws_lb",
    "module.control.aws_lb_target_group.hub[0]": "aws_lb_target_group",
    "module.control.aws_lb_listener.hub[0]": "aws_lb_listener",
    "module.control.aws_ssm_parameter.hub_udp_listener_arn[0]": "aws_ssm_parameter",
}

# The Hub public UDP edge's replacement network load balancer name. The
# distinct `-hub-edge` suffix is correctness-relevant because AWS cannot attach
# a security group to the already-created NLB. check_live admits exactly this
# one internet-facing NLB, and only once the tagged public-edge route table
# proves the edge is live.
HUB_EDGE_LOAD_BALANCER_NAME = "layerv-nhp-sandbox-hub-edge"
# The generation-1 name, still live until the source-fence replacement applies.
# Attaching a security group to an NLB forces replacement (AWS only accepts
# `security_groups` at creation), and the replacement also renames. The
# PRE-apply boundary check therefore observes this name, while the post-apply
# state carries HUB_EDGE_LOAD_BALANCER_NAME. Admitting only the post name made
# the check reject the exact state it exists to gate.
HUB_EDGE_LEGACY_LOAD_BALANCER_NAME = f"{CONTROL_PREFIX}-hub"
HUB_EDGE_REVIEWED_LOAD_BALANCER_NAMES = frozenset(
    {HUB_EDGE_LOAD_BALANCER_NAME, HUB_EDGE_LEGACY_LOAD_BALANCER_NAME}
)
HUB_EDGE_TARGET_GROUP_NAME = f"{CONTROL_PREFIX}-hub"
HUB_SOURCE_FENCE_PROVIDER_FIXTURE_PATH = (
    Path(__file__).resolve().parents[2]
    / "tests/fixtures/control-hub-source-fence/"
    "hub-replacement-terraform-1.14.3-aws-6.55.0.json"
)
HUB_SOURCE_FENCE_PROVIDER_FIXTURE_SHA256 = (
    "914cb030cf7563ad0302431d77065d939056c82ad501fa75a56cc257e19898e1"
)
HUB_SOURCE_FENCE_SOURCE_PLAN_SHA256 = (
    "53646f92eb2dc734f57a4a0500782411118ac985091d5dc9c1c5c10a7ab1265b"
)
HUB_SOURCE_FENCE_SOURCE_PLAN_JSON_SHA256 = (
    "9aba1730bfe9f15e419626fa3e44ddf40e7faf6705c69e72250bda876a48e4ec"
)
HUB_SOURCE_FENCE_SOURCE_ENVELOPE_SHA256 = (
    "2820788513e5272b7bf2707e7c6828769221cdea3f249b2c90777477409bc04c"
)
HUB_SOURCE_FENCE_PROVIDER_ADDRESSES = (
    "module.control.aws_lb.hub[0]",
    "module.control.aws_lb_listener.hub[0]",
    "module.control.aws_lb_target_group.hub[0]",
    "module.control.aws_security_group.hub_worker[0]",
    "module.control.aws_ssm_parameter.hub_udp_listener_arn[0]",
)

# Exact non-no-op graph for the one-time replacement of the already-live Hub
# NLB. The target group remains a validated no-op and is intentionally absent.
HUB_SOURCE_FENCE_ACTIONS: dict[str, list[str]] = {
    "module.control.aws_security_group.hub_nlb[0]": ["create"],
    'module.control.aws_vpc_security_group_ingress_rule.hub_nlb_udp["0.0.0.0/0"]': [
        "create"
    ],
    "module.control.aws_vpc_security_group_egress_rule.hub_nlb_udp[0]": ["create"],
    "module.control.aws_vpc_security_group_egress_rule.hub_nlb_health[0]": ["create"],
    "module.control.aws_lb.hub[0]": ["create", "delete"],
    "module.control.aws_lb_listener.hub[0]": ["delete", "create"],
    "module.control.aws_security_group.hub_worker[0]": ["update"],
    "module.control.aws_ssm_parameter.hub_udp_listener_arn[0]": ["update"],
}

# Configuration-block view of the Hub edge (un-indexed resource addresses). The
# blocks are declared unconditionally, so -- exactly like the runtime blocks --
# they always appear in the plan configuration even while count=0 (dark). Added
# to EXPECTED_CONFIGURATION_RESOURCES unconditionally below.
HUB_EDGE_CONFIGURATION_RESOURCES: dict[str, tuple[str, str, str]] = {
    "module.control.aws_subnet.hub_public": ("managed", "aws_subnet", "aws"),
    "module.control.aws_internet_gateway.hub_edge": (
        "managed",
        "aws_internet_gateway",
        "aws",
    ),
    "module.control.aws_route_table.hub_public": (
        "managed",
        "aws_route_table",
        "aws",
    ),
    "module.control.aws_route.hub_public_default": ("managed", "aws_route", "aws"),
    "module.control.aws_route_table_association.hub_public": (
        "managed",
        "aws_route_table_association",
        "aws",
    ),
    "module.control.aws_security_group.hub_nlb": (
        "managed",
        "aws_security_group",
        "aws",
    ),
    "module.control.aws_vpc_security_group_ingress_rule.hub_nlb_udp": (
        "managed",
        "aws_vpc_security_group_ingress_rule",
        "aws",
    ),
    "module.control.aws_lb.hub": ("managed", "aws_lb", "aws"),
    "module.control.aws_lb_target_group.hub": (
        "managed",
        "aws_lb_target_group",
        "aws",
    ),
    "module.control.aws_lb_listener.hub": ("managed", "aws_lb_listener", "aws"),
    "module.control.aws_ssm_parameter.hub_udp_listener_arn": (
        "managed",
        "aws_ssm_parameter",
        "aws",
    ),
}

# Connector Hub Fargate worker slice (Step 5 slice 5b): the ECS cluster/service/
# task-definition fronting the 5a NLB target group, the Hub key-material secret
# and its keygen Lambda (which seeds the value in-account so no key ever enters
# tfstate), the worker security group, the Hub log group, and the ECR/S3 image-
# pull endpoints. This slice both CREATES the above AND OPENS two pre-existing
# base resources: the `lambda` interface endpoint policy (deny -> scoped to the
# worker task role) and the interface-endpoints SG (a second 443 ingress from the
# worker SG). Admitted only all-at-once, compositionally, and only alongside BOTH
# the authority runtime slice (the aliases it invokes) and the Hub edge slice
# (the target group it registers into).
HUB_WORKER_RESOURCES: dict[str, str] = {
    "module.control.aws_secretsmanager_secret.hub_key_material[0]": "aws_secretsmanager_secret",
    "module.control.aws_ssm_parameter.hub_public_key[0]": "aws_ssm_parameter",
    "module.control.aws_iam_role.hub_keygen[0]": "aws_iam_role",
    "module.control.aws_iam_role_policy.hub_keygen[0]": "aws_iam_role_policy",
    "module.control.aws_cloudwatch_log_group.hub_keygen[0]": "aws_cloudwatch_log_group",
    "module.control.aws_lambda_function.hub_keygen[0]": "aws_lambda_function",
    "module.control.aws_lambda_invocation.hub_keygen[0]": "aws_lambda_invocation",
    "module.control.aws_lambda_invocation.hub_identity_publication[0]": "aws_lambda_invocation",
    "module.control.aws_iam_role.hub_execution[0]": "aws_iam_role",
    "module.control.aws_iam_role_policy_attachment.hub_execution[0]": "aws_iam_role_policy_attachment",
    "module.control.aws_iam_role_policy.hub_execution[0]": "aws_iam_role_policy",
    "module.control.aws_iam_role.hub_task[0]": "aws_iam_role",
    "module.control.aws_iam_role_policy.hub_task[0]": "aws_iam_role_policy",
    "module.control.aws_security_group.hub_worker[0]": "aws_security_group",
    "module.control.aws_cloudwatch_log_group.hub[0]": "aws_cloudwatch_log_group",
    "module.control.aws_ecs_cluster.hub[0]": "aws_ecs_cluster",
    "module.control.aws_ecs_task_definition.hub[0]": "aws_ecs_task_definition",
    "module.control.aws_ecs_service.hub[0]": "aws_ecs_service",
    "module.control.aws_vpc_endpoint.hub_ecr_api[0]": "aws_vpc_endpoint",
    "module.control.aws_vpc_endpoint.hub_ecr_dkr[0]": "aws_vpc_endpoint",
    "module.control.aws_vpc_endpoint.hub_s3[0]": "aws_vpc_endpoint",
    "module.control.aws_vpc_security_group_egress_rule.hub_nlb_udp[0]": "aws_vpc_security_group_egress_rule",
    "module.control.aws_vpc_security_group_egress_rule.hub_nlb_health[0]": "aws_vpc_security_group_egress_rule",
}

# Count-gated data sources the worker slice adds (the published image digest and
# the keygen zip). Present in state only when the slice is live -- compositional,
# exactly like the managed set above.
HUB_WORKER_DATA_RESOURCES: dict[str, str] = {
    "module.control.data.aws_ssm_parameter.hub_image_digest[0]": "aws_ssm_parameter",
    "module.control.data.archive_file.hub_keygen[0]": "archive_file",
}

# Configuration-block view (un-indexed). Declared unconditionally in the module,
# so -- exactly like the runtime/edge blocks -- they always appear in the plan
# configuration even while count=0 (dark). The archive_file data source is the
# only non-aws provider block the Control root declares.
HUB_WORKER_CONFIGURATION_RESOURCES: dict[str, tuple[str, str, str]] = {
    "module.control.aws_secretsmanager_secret.hub_key_material": (
        "managed",
        "aws_secretsmanager_secret",
        "aws",
    ),
    "module.control.aws_ssm_parameter.hub_public_key": (
        "managed",
        "aws_ssm_parameter",
        "aws",
    ),
    "module.control.aws_iam_role.hub_keygen": ("managed", "aws_iam_role", "aws"),
    "module.control.aws_iam_role_policy.hub_keygen": (
        "managed",
        "aws_iam_role_policy",
        "aws",
    ),
    "module.control.aws_cloudwatch_log_group.hub_keygen": (
        "managed",
        "aws_cloudwatch_log_group",
        "aws",
    ),
    "module.control.aws_lambda_function.hub_keygen": (
        "managed",
        "aws_lambda_function",
        "aws",
    ),
    "module.control.aws_lambda_invocation.hub_keygen": (
        "managed",
        "aws_lambda_invocation",
        "aws",
    ),
    "module.control.aws_lambda_invocation.hub_identity_publication": (
        "managed",
        "aws_lambda_invocation",
        "aws",
    ),
    "module.control.aws_iam_role.hub_execution": ("managed", "aws_iam_role", "aws"),
    "module.control.aws_iam_role_policy_attachment.hub_execution": (
        "managed",
        "aws_iam_role_policy_attachment",
        "aws",
    ),
    "module.control.aws_iam_role_policy.hub_execution": (
        "managed",
        "aws_iam_role_policy",
        "aws",
    ),
    "module.control.aws_iam_role.hub_task": ("managed", "aws_iam_role", "aws"),
    "module.control.aws_iam_role_policy.hub_task": (
        "managed",
        "aws_iam_role_policy",
        "aws",
    ),
    "module.control.aws_security_group.hub_worker": (
        "managed",
        "aws_security_group",
        "aws",
    ),
    "module.control.aws_cloudwatch_log_group.hub": (
        "managed",
        "aws_cloudwatch_log_group",
        "aws",
    ),
    "module.control.aws_ecs_cluster.hub": ("managed", "aws_ecs_cluster", "aws"),
    "module.control.aws_ecs_task_definition.hub": (
        "managed",
        "aws_ecs_task_definition",
        "aws",
    ),
    "module.control.aws_ecs_service.hub": ("managed", "aws_ecs_service", "aws"),
    "module.control.aws_vpc_endpoint.hub_ecr_api": (
        "managed",
        "aws_vpc_endpoint",
        "aws",
    ),
    "module.control.aws_vpc_endpoint.hub_ecr_dkr": (
        "managed",
        "aws_vpc_endpoint",
        "aws",
    ),
    "module.control.aws_vpc_endpoint.hub_s3": ("managed", "aws_vpc_endpoint", "aws"),
    "module.control.aws_vpc_security_group_egress_rule.hub_nlb_udp": (
        "managed",
        "aws_vpc_security_group_egress_rule",
        "aws",
    ),
    "module.control.aws_vpc_security_group_egress_rule.hub_nlb_health": (
        "managed",
        "aws_vpc_security_group_egress_rule",
        "aws",
    ),
    "module.control.data.aws_ssm_parameter.hub_image_digest": (
        "data",
        "aws_ssm_parameter",
        "aws",
    ),
    "module.control.data.archive_file.hub_keygen": (
        "data",
        "archive_file",
        # Module-local provider (declared in the module's required_providers, not
        # configured at the root), so its provider_config_key is namespaced like
        # terraform_data's "module.control:terraform".
        "module.control:archive",
    ),
}

# The two pre-existing base resources the worker slice OPENS (their addresses do
# not change; their policy/ingress does). Used by the plan_mode transition and
# the partial-retry normalization lane.
HUB_WORKER_LAMBDA_ENDPOINT_ADDRESS = 'module.control.aws_vpc_endpoint.interface["lambda"]'
HUB_WORKER_SECRETSMANAGER_ENDPOINT_ADDRESS = (
    'module.control.aws_vpc_endpoint.interface["secretsmanager"]'
)
HUB_WORKER_LOGS_ENDPOINT_ADDRESS = 'module.control.aws_vpc_endpoint.interface["logs"]'
HUB_WORKER_MONITORING_ENDPOINT_ADDRESS = (
    'module.control.aws_vpc_endpoint.interface["monitoring"]'
)
HUB_WORKER_OPENED_ADDRESSES = frozenset(
    {
        HUB_WORKER_LAMBDA_ENDPOINT_ADDRESS,
        HUB_WORKER_SECRETSMANAGER_ENDPOINT_ADDRESS,
        HUB_WORKER_LOGS_ENDPOINT_ADDRESS,
        HUB_WORKER_MONITORING_ENDPOINT_ADDRESS,
        "module.control.aws_security_group.interface_endpoints",
    }
)
# The Hub S3 gateway endpoint. Unlike the interface endpoints above (pre-existing,
# opened deny->scoped by the slice), hub_s3 is CREATED by the worker slice with
# its policy inline, so a later policy correction presents as a standalone in-place
# ["update"] on a HUB_WORKER_RESOURCES member -- admitted by the bounded
# hub-s3-endpoint-policy-correction lane, not the opened-address tolerance.
HUB_WORKER_S3_ENDPOINT_ADDRESS = "module.control.aws_vpc_endpoint.hub_s3[0]"
# The Hub public edge NLB. Also the sole participant of the bounded
# hub-privatelink-enforcement lane below.
HUB_EDGE_LOAD_BALANCER_ADDRESS = "module.control.aws_lb.hub[0]"
PRIVATELINK_ENFORCEMENT_ATTRIBUTE = (
    "enforce_security_group_inbound_rules_on_private_link_traffic"
)
# ELBv2 leaves the attribute empty until it is set explicitly; "off" is the
# documented disabled value. Both mean the Hub source fence is NOT enforced for
# PrivateLink traffic, so both are legal predecessors of the corrective flip.
PRIVATELINK_ENFORCEMENT_BEFORE_VALUES = frozenset({"", "off"})
# The Hub worker container log group ARN (awslogs driver target), matched exactly
# in the opened logs endpoint policy. Slash-namespaced, distinct from the dash
# CONTROL_PREFIX.
HUB_LOG_GROUP_ARN = (
    f"arn:aws:logs:{AWS_REGION}:{ACCOUNT_ID}:log-group:/layerv/nhp/sandbox/control/hub:*"
)
HUB_WORKER_IMAGE_RE = re.compile(
    rf"^{ACCOUNT_ID}\.dkr\.ecr\.{re.escape(AWS_REGION)}\.amazonaws\.com/"
    rf"{re.escape(HUB_ECR_REPOSITORY_NAME)}@sha256:[0-9a-f]{{64}}$"
)
# The Hub key-material secret ARN carries a random 6-char Secrets Manager suffix,
# so the opened secretsmanager endpoint policy Resource is matched by shape, not a
# constructed literal.
HUB_KEY_MATERIAL_SECRET_ARN_RE = re.compile(
    rf"^arn:aws:secretsmanager:{AWS_REGION}:{ACCOUNT_ID}:secret:"
    rf"{CONTROL_PREFIX}-hub-key-material-[A-Za-z0-9]{{6}}$"
)
HUB_KEY_MATERIAL_SECRET_NAME = f"{CONTROL_PREFIX}-hub-key-material"
HUB_PUBLIC_KEY_PARAMETER_NAME = (
    "/sandbox/nhp/control/hub/identity/public-key"
)
HUB_PUBLIC_KEY_PARAMETER_ARN = (
    f"arn:aws:ssm:{AWS_REGION}:{ACCOUNT_ID}:parameter"
    f"{HUB_PUBLIC_KEY_PARAMETER_NAME}"
)
HUB_KEYGEN_ROLE_ARN = (
    f"arn:aws:iam::{ACCOUNT_ID}:role/{CONTROL_PREFIX}-hub-keygen"
)
HUB_KEYGEN_LOG_GROUP_ARN = (
    f"arn:aws:logs:{AWS_REGION}:{ACCOUNT_ID}:"
    f"log-group:/aws/lambda/{CONTROL_PREFIX}-hub-keygen:*"
)
HUB_SECRETSMANAGER_KMS_VIA_SERVICE = (
    f"secretsmanager.{AWS_REGION}.amazonaws.com"
)
HUB_IDENTITY_CREATE_ADDRESSES = frozenset(
    {
        "module.control.aws_ssm_parameter.hub_public_key[0]",
        "module.control.aws_lambda_invocation.hub_identity_publication[0]",
    }
)
HUB_IDENTITY_UPDATE_ADDRESSES = frozenset(
    {
        "module.control.aws_iam_role_policy.hub_keygen[0]",
        "module.control.aws_lambda_function.hub_keygen[0]",
        "module.control.aws_iam_role_policy.hub_execution[0]",
    }
)
HUB_IDENTITY_MIGRATION_ADDRESSES = (
    HUB_IDENTITY_CREATE_ADDRESSES | HUB_IDENTITY_UPDATE_ADDRESSES
)

# Constructed, plan-known worker principal ARNs (same technique as
# AUTHORITY_RUNTIME_EXEC_ROLE_ARNS): the module names the roles deterministically
# so the opened lambda-endpoint policy and the task policy are fully known at
# plan time and independently checkable, with no function<->role<->policy cycle.
HUB_TASK_ROLE_ARN = f"arn:aws:iam::{ACCOUNT_ID}:role/{CONTROL_PREFIX}-hub-task"
HUB_EXECUTION_ROLE_ARN = f"arn:aws:iam::{ACCOUNT_ID}:role/{CONTROL_PREFIX}-hub-exec"
# The Hub keygen Lambda persists in the Control prefix once the worker slice is
# live (it seeds the key-material secret once, then stays). check_live admits it
# ONLY alongside the 3 authority functions -- the worker requires the runtime.
HUB_KEYGEN_FUNCTION_NAME = f"{CONTROL_PREFIX}-hub-keygen"

# The Hub invokes the SELECTED authority color's alias for each of the 3 Hub
# operations. The merged measurement basis freezes selected_authority_color=blue
# (docs/evidence/connector-authority/v1/sandbox-measurement-basis.json), which is
# the live sandbox deployment; a future green switch revises this in lockstep
# with the runtime slice.
HUB_AUTHORITY_ALIAS_ARNS = frozenset(
    f"arn:aws:lambda:{AWS_REGION}:{ACCOUNT_ID}:function:{_fn}:blue"
    for _fn in AUTHORITY_RUNTIME_HUB_FUNCTIONS
)

# ECR/S3 image-pull endpoint policy expectations (scoped to the execution role).
HUB_ECR_REPOSITORY_ARN = (
    f"arn:aws:ecr:{AWS_REGION}:{ACCOUNT_ID}:repository/layerv/nhp-hub"
)
HUB_ECR_PULL_ACTIONS = frozenset(
    {
        "ecr:GetDownloadUrlForLayer",
        "ecr:BatchGetImage",
        "ecr:BatchCheckLayerAvailability",
    }
)
HUB_S3_LAYER_BUCKET_ARN = f"arn:aws:s3:::prod-{AWS_REGION}-starport-layer-bucket/*"

AUTHORITY_RUNTIME_CONFIGURATION_RESOURCES: dict[str, tuple[str, str, str]] = {
    "module.control.data.aws_lambda_alias.authority_proof_policy_live": (
        "data",
        "aws_lambda_alias",
        "aws",
    ),
    # Live alias versions for the blue/green hold. Declared unconditionally in
    # the module, so it is in the configuration map even while the gate is dark
    # and its for_each resolves empty.
    "module.control.data.aws_lambda_alias.authority_live": (
        "data",
        "aws_lambda_alias",
        "aws",
    ),
    "module.control.aws_lambda_function.authority": (
        "managed",
        "aws_lambda_function",
        "aws",
    ),
    "module.control.aws_lambda_alias.authority": (
        "managed",
        "aws_lambda_alias",
        "aws",
    ),
    "module.control.aws_lambda_provisioned_concurrency_config.authority": (
        "managed",
        "aws_lambda_provisioned_concurrency_config",
        "aws",
    ),
    "module.control.aws_lambda_provisioned_concurrency_config.authority_proof_standby": (
        "managed",
        "aws_lambda_provisioned_concurrency_config",
        "aws",
    ),
    "module.control.aws_iam_role.authority_exec": ("managed", "aws_iam_role", "aws"),
    "module.control.aws_iam_role_policy.authority_exec": (
        "managed",
        "aws_iam_role_policy",
        "aws",
    ),
    "module.control.aws_cloudwatch_log_group.authority": (
        "managed",
        "aws_cloudwatch_log_group",
        "aws",
    ),
    "module.control.aws_cloudwatch_metric_alarm.authority_spillover": (
        "managed",
        "aws_cloudwatch_metric_alarm",
        "aws",
    ),
    "module.control.aws_cloudwatch_metric_alarm.authority_runtime": (
        "managed",
        "aws_cloudwatch_metric_alarm",
        "aws",
    ),
    "module.control.aws_cloudwatch_composite_alarm.authority_non_provisioned_initialization": (
        "managed",
        "aws_cloudwatch_composite_alarm",
        "aws",
    ),
    "module.control.aws_cloudwatch_metric_alarm.authority_terminal_outcome": (
        "managed",
        "aws_cloudwatch_metric_alarm",
        "aws",
    ),
    "module.control.aws_cloudwatch_metric_alarm.authority_admission_rejected": (
        "managed",
        "aws_cloudwatch_metric_alarm",
        "aws",
    ),
    "module.control.aws_cloudwatch_metric_alarm.authority_adapter_contract_violation": (
        "managed",
        "aws_cloudwatch_metric_alarm",
        "aws",
    ),
    "module.control.aws_cloudwatch_metric_alarm.authority_adapter_late_result": (
        "managed",
        "aws_cloudwatch_metric_alarm",
        "aws",
    ),
    "module.control.aws_cloudwatch_metric_alarm.authority_completion_identity_rejected": (
        "managed",
        "aws_cloudwatch_metric_alarm",
        "aws",
    ),
    "module.control.aws_security_group.authority_lambda": (
        "managed",
        "aws_security_group",
        "aws",
    ),
    "module.control.aws_vpc_security_group_egress_rule.authority_interface_endpoints": (
        "managed",
        "aws_vpc_security_group_egress_rule",
        "aws",
    ),
    "module.control.aws_vpc_security_group_egress_rule.authority_dynamodb": (
        "managed",
        "aws_vpc_security_group_egress_rule",
        "aws",
    ),
    "module.control.aws_vpc_security_group_egress_rule.authority_otp_redis": (
        "managed",
        "aws_vpc_security_group_egress_rule",
        "aws",
    ),
    "module.control.aws_vpc_security_group_ingress_rule.otp_redis_authority": (
        "managed",
        "aws_vpc_security_group_ingress_rule",
        "aws",
    ),
}

# Constructed identities (known at plan time, so the opened endpoint policies
# are fully checkable). The qat1 KMS key ARN carries a live UUID, matched by
# pattern rather than a fixed literal.
AUTHORITY_RUNTIME_EXEC_ROLE_ARNS = frozenset(
    f"arn:aws:iam::{ACCOUNT_ID}:role/{name}-exec"
    for name in AUTHORITY_RUNTIME_FUNCTIONS
)
AUTHORITY_PROOF_EXEC_ROLE_ARNS = frozenset(
    f"arn:aws:iam::{ACCOUNT_ID}:role/{name}-exec"
    for name in AUTHORITY_PROOF_FUNCTIONS
)
AUTHORITY_RUNTIME_TABLE_ARNS = {
    "api_keys": (
        f"arn:aws:dynamodb:{AWS_REGION}:{ACCOUNT_ID}:table/"
        f"{CONTROL_PREFIX}-qurl-api-keys"
    ),
    "agent_keys": (
        f"arn:aws:dynamodb:{AWS_REGION}:{ACCOUNT_ID}:table/"
        f"{CONTROL_PREFIX}-qurl-agent-keys"
    ),
    "customers": (
        f"arn:aws:dynamodb:{AWS_REGION}:{ACCOUNT_ID}:table/"
        f"{CONTROL_PREFIX}-qurl-customers"
    ),
    "api_key_idempotency": (
        f"arn:aws:dynamodb:{AWS_REGION}:{ACCOUNT_ID}:table/"
        f"{CONTROL_PREFIX}-qurl-apikey-idempotency"
    ),
    "connector_authority": (
        f"arn:aws:dynamodb:{AWS_REGION}:{ACCOUNT_ID}:table/"
        f"{CONTROL_PREFIX}-connector-authority"
    ),
}
# Per-table resources. Only agent_keys is read through a GSI (the pubkey index
# used by refresh/recovery identity resolution, agent_keys_repo.go GetByPublicKey);
# api_keys and connector_authority are reached only by primary key, so they carry
# no /index/* grant.
AUTHORITY_RUNTIME_TABLE_RESOURCES = {
    "api_keys": frozenset({AUTHORITY_RUNTIME_TABLE_ARNS["api_keys"]}),
    "agent_keys": frozenset(
        {
            AUTHORITY_RUNTIME_TABLE_ARNS["agent_keys"],
            f"{AUTHORITY_RUNTIME_TABLE_ARNS['agent_keys']}/index/*",
        }
    ),
    "customers": frozenset({AUTHORITY_RUNTIME_TABLE_ARNS["customers"]}),
    "api_key_idempotency": frozenset(
        {AUTHORITY_RUNTIME_TABLE_ARNS["api_key_idempotency"]}
    ),
    "connector_authority": frozenset(
        {AUTHORITY_RUNTIME_TABLE_ARNS["connector_authority"]}
    ),
}
# The DynamoDB gateway-endpoint resource union (coarse, TABLE-GRANULAR gate for
# all runtime roles). Gateway VPC-endpoint policies reject a /index/* sub-resource
# with InvalidPolicyDocument, so the endpoint lists only the five BASE-table
# ARNs; a GSI Query is authorized at this network gate by its base table, and the
# finer /index/* grant lives in the per-op identity policies
# (AUTHORITY_RUNTIME_TABLE_RESOURCES, checked separately on the exec-role policies).
AUTHORITY_RUNTIME_DYNAMODB_RESOURCES = frozenset(AUTHORITY_RUNTIME_TABLE_ARNS.values())
AUTHORITY_RUNTIME_DYNAMODB_LEGACY_RESOURCES = (
    AUTHORITY_RUNTIME_DYNAMODB_RESOURCES
    - AUTHORITY_RUNTIME_TABLE_RESOURCES["api_key_idempotency"]
)
# Shared read set. DescribeTable is REQUIRED: every op verifies its Control
# tables' SSE-KMS key at cold start (dynamodb_sse.go). BatchGetItem/
# TransactGetItems are intentionally absent (a read inside a transaction is
# authorized by GetItem, not a Transact* action).
AUTHORITY_RUNTIME_DYNAMODB_READ_ACTIONS = frozenset(
    {
        "dynamodb:ConditionCheckItem",
        "dynamodb:DescribeTable",
        "dynamodb:GetItem",
        "dynamodb:Query",
    }
)
# IssueAssignment + RefreshAssignment write only the single-item replay Put.
AUTHORITY_RUNTIME_DYNAMODB_REPLAY_WRITE_ACTIONS = frozenset({"dynamodb:PutItem"})
# IssueCredentialRecovery additionally UPDATEs the head anchor on the first grant.
# DeleteItem and TransactWriteItems are intentionally absent.
AUTHORITY_RUNTIME_DYNAMODB_RECOVERY_WRITE_ACTIONS = frozenset(
    {"dynamodb:PutItem", "dynamodb:UpdateItem"}
)
# The DynamoDB gateway-endpoint action union (reads + the widest write set).
AUTHORITY_RUNTIME_DYNAMODB_ACTIONS = (
    AUTHORITY_RUNTIME_DYNAMODB_READ_ACTIONS
    | AUTHORITY_RUNTIME_DYNAMODB_RECOVERY_WRITE_ACTIONS
)
# Only IssueAssignment reaches KMS: GetPublicKey to load the qat1 key, Sign to
# mint the ticket. No op uses kms:Verify (verification is local p256).
AUTHORITY_RUNTIME_KMS_ACTIONS = frozenset({"kms:GetPublicKey", "kms:Sign"})
# The Lambda-VPC ENI statement keeps the AWS-required Resource="*" (the ONLY
# sanctioned wildcard in any authority execution policy).
AUTHORITY_RUNTIME_ENI_ACTIONS = frozenset(
    {
        "ec2:AssignPrivateIpAddresses",
        "ec2:CreateNetworkInterface",
        "ec2:DeleteNetworkInterface",
        "ec2:DescribeNetworkInterfaces",
        "ec2:UnassignPrivateIpAddresses",
    }
)
AUTHORITY_RUNTIME_LOG_ACTIONS = frozenset(
    {"logs:CreateLogStream", "logs:PutLogEvents"}
)
# The qat1 endpoint principal and the identity-layer Sign statement open to the
# IssueAssignment execution role alone.
_AUTHORITY_SIGN_FUNCTION = next(
    fn
    for fn, operation in AUTHORITY_RUNTIME_HUB_FUNCTIONS.items()
    if operation == "issue_assignment"
)
AUTHORITY_RUNTIME_SIGN_ROLE_ARNS = frozenset(
    {f"arn:aws:iam::{ACCOUNT_ID}:role/{_AUTHORITY_SIGN_FUNCTION}-exec"}
)
def _authority_exec_role_arns(operations: set[str]) -> frozenset[str]:
    """Exec-role ARNs of the functions whose operation is in ``operations``."""
    return frozenset(
        f"arn:aws:iam::{ACCOUNT_ID}:role/{fn}-exec"
        for fn, operation in AUTHORITY_RUNTIME_FUNCTIONS.items()
        if operation in operations
    )


AUTHORITY_RUNTIME_PUBLIC_KEY_ROLE_ARNS = _authority_exec_role_arns(
    {"issue_assignment", "issue_registration_otp", "activate_registration"}
)
AUTHORITY_RUNTIME_OTP_ROLE_ARNS = _authority_exec_role_arns(
    {"issue_registration_otp", "activate_registration"}
)
AUTHORITY_RUNTIME_SES_ROLE_ARNS = _authority_exec_role_arns(
    {"issue_registration_otp"}
)
# Per-operation identity-policy scope, reconciled against the live handler
# (layervai/qurl-service origin/main).
AUTHORITY_RUNTIME_OPERATION_IAM = {
    "issue_assignment": {
        "read_tables": ("api_keys", "connector_authority"),
        "write_sid": "AuthorityReplayWrite",
        "write_actions": AUTHORITY_RUNTIME_DYNAMODB_REPLAY_WRITE_ACTIONS,
        "signs": True,
        # The signed assignment ticket is stored under a handle instead of
        # being sent, so this operation alone creates ASSIGNMENT_TICKET# rows.
        # A separate Sid, not a wider AuthorityReplayWrite: the replay grant
        # must keep meaning exactly "its own replay tombstone".
        "ticket_handle_write": True,
        "ticket_handle_write_actions": ("dynamodb:PutItem",),
    },
    "refresh_assignment": {
        "read_tables": ("agent_keys", "connector_authority"),
        "write_sid": "AuthorityReplayWrite",
        "write_actions": AUTHORITY_RUNTIME_DYNAMODB_REPLAY_WRITE_ACTIONS,
        "signs": False,
    },
    "issue_credential_recovery": {
        "read_tables": ("api_keys", "agent_keys", "connector_authority"),
        "write_sid": "AuthorityRecoveryWrite",
        "write_actions": AUTHORITY_RUNTIME_DYNAMODB_RECOVERY_WRITE_ACTIONS,
        "signs": False,
    },
}
AUTHORITY_RUNTIME_CELL_OPERATION_IAM = {
    "issue_registration_otp": {
        "read_tables": ("api_keys", "customers"),
        "writes": {},
        "public_key": True,
        "otp_user": "issuer",
        "sends_email": True,
        # Resolves the handle a client presents back to the signed ticket. It
        # has no other business on connector_authority, so this is GetItem on
        # the ASSIGNMENT_TICKET# prefix rather than a read-table entry.
        "ticket_handle_read": True,
    },
    "activate_registration": {
        "read_tables": ("api_keys", "agent_keys", "connector_authority"),
        "writes": {
            "RegistrationCredentialWrite": (
                frozenset({"dynamodb:UpdateItem"}),
                AUTHORITY_RUNTIME_TABLE_RESOURCES["api_keys"],
            ),
            "RegistrationIdentityWrite": (
                frozenset({"dynamodb:PutItem", "dynamodb:UpdateItem"}),
                frozenset({AUTHORITY_RUNTIME_TABLE_ARNS["agent_keys"]}),
            ),
            "RegistrationAuthorityWrite": (
                frozenset({"dynamodb:PutItem", "dynamodb:UpdateItem"}),
                AUTHORITY_RUNTIME_TABLE_RESOURCES["connector_authority"],
            ),
        },
        "public_key": True,
        "otp_user": "activator",
        "sends_email": False,
    },
    "complete_registration": {
        "read_tables": ("api_keys", "agent_keys", "connector_authority"),
        "writes": {
            "RegistrationCredentialWrite": (
                frozenset({"dynamodb:PutItem", "dynamodb:UpdateItem"}),
                AUTHORITY_RUNTIME_TABLE_RESOURCES["api_keys"],
            ),
            "RegistrationAuthorityWrite": (
                frozenset({"dynamodb:PutItem"}),
                AUTHORITY_RUNTIME_TABLE_RESOURCES["connector_authority"],
            ),
        },
        "public_key": False,
        "otp_user": None,
        "sends_email": False,
    },
    "complete_credential_recovery": {
        "read_tables": ("api_keys", "agent_keys", "connector_authority"),
        "writes": {
            "RecoveryCredentialWrite": (
                frozenset({"dynamodb:PutItem", "dynamodb:UpdateItem"}),
                AUTHORITY_RUNTIME_TABLE_RESOURCES["api_keys"],
            ),
            "RecoveryAuthorityWrite": (
                frozenset({"dynamodb:PutItem"}),
                AUTHORITY_RUNTIME_TABLE_RESOURCES["connector_authority"],
            ),
        },
        "public_key": False,
        "otp_user": None,
        "sends_email": False,
    },
}
_QAT1_KEY_ARN_RE = re.compile(
    rf"^arn:aws:kms:{AWS_REGION}:{ACCOUNT_ID}:key/"
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
_AUTHORITY_OTP_SECRET_ARN_RE = re.compile(
    rf"^arn:aws:secretsmanager:{AWS_REGION}:{ACCOUNT_ID}:secret:"
    rf"{CONTROL_PREFIX}-otp-pepper-[A-Za-z0-9]{{6}}$"
)
_AUTHORITY_DATA_KEY_ARN_RE = _QAT1_KEY_ARN_RE
AUTHORITY_RUNTIME_REDIS_CACHE_ARN = (
    f"arn:aws:elasticache:{AWS_REGION}:{ACCOUNT_ID}:serverlesscache:"
    f"{CONTROL_PREFIX}-otp"
)
AUTHORITY_RUNTIME_REDIS_USER_ARNS = {
    "issuer": (
        f"arn:aws:elasticache:{AWS_REGION}:{ACCOUNT_ID}:user:"
        f"{CONTROL_PREFIX}-otp-issuer"
    ),
    "activator": (
        f"arn:aws:elasticache:{AWS_REGION}:{ACCOUNT_ID}:user:"
        f"{CONTROL_PREFIX}-otp-activator"
    ),
}
AUTHORITY_RUNTIME_SES_RESOURCES = frozenset(
    {
        f"arn:aws:ses:{AWS_REGION}:{ACCOUNT_ID}:identity/notify.layerv.xyz",
        f"arn:aws:ses:{AWS_REGION}:{ACCOUNT_ID}:configuration-set/layerv-nhp-sandbox-agent-otp",
    }
)
AUTHORITY_RUNTIME_DYNAMODB_ADDRESS = "module.control.aws_vpc_endpoint.dynamodb"
AUTHORITY_RUNTIME_KMS_ENDPOINT_ADDRESS = (
    'module.control.aws_vpc_endpoint.interface["kms"]'
)
AUTHORITY_RUNTIME_SECRETS_ENDPOINT_ADDRESS = (
    'module.control.aws_vpc_endpoint.interface["secretsmanager"]'
)
AUTHORITY_RUNTIME_EMAIL_ENDPOINT_ADDRESS = (
    'module.control.aws_vpc_endpoint.interface["email"]'
)
AUTHORITY_RUNTIME_INTERFACE_SG_ADDRESS = (
    "module.control.aws_security_group.interface_endpoints"
)
# The exact five base resources whose policy/ingress the runtime opens.
AUTHORITY_RUNTIME_OPENED_ADDRESSES = frozenset(
    {
        AUTHORITY_RUNTIME_DYNAMODB_ADDRESS,
        AUTHORITY_RUNTIME_KMS_ENDPOINT_ADDRESS,
        AUTHORITY_RUNTIME_SECRETS_ENDPOINT_ADDRESS,
        AUTHORITY_RUNTIME_EMAIL_ENDPOINT_ADDRESS,
        AUTHORITY_RUNTIME_INTERFACE_SG_ADDRESS,
    }
)
AUTHORITY_RUNTIME_LEGACY_EXPANSION_UPDATE_ADDRESSES = frozenset(
    AUTHORITY_RUNTIME_OPENED_ADDRESSES
    | {
        "module.control.terraform_data.foundation_contract",
        *(
            (f'module.control.aws_lambda_function.authority["{function_name}"]')
            for function_name in AUTHORITY_RUNTIME_HUB_FUNCTIONS
        ),
        *(
            (f'module.control.aws_lambda_alias.authority["{function_name}:{color}"]')
            for function_name in AUTHORITY_RUNTIME_HUB_FUNCTIONS
            for color in ("blue", "green")
        ),
    }
)

# Exact value-free Terraform 1.14.3 / AWS provider 6.55.0 create envelope for
# an IAM-authenticated ElastiCache user. The provider computes password_count
# only after create; the configured absence of passwords remains a sensitive
# null. Reproduce and re-review this shape when either pinned version changes.
_REDIS_IAM_CREATE_AUTHENTICATION_MODE = [{"passwords": None, "type": "iam"}]
_REDIS_IAM_CREATE_AUTHENTICATION_MODE_UNKNOWN = [{"password_count": True}]
_REDIS_IAM_CREATE_AUTHENTICATION_MODE_SENSITIVE = [{"passwords": True}]
_REDIS_PASSWORD_NORMALIZATION_ADDRESSES = (
    "module.control.aws_elasticache_user.otp_activator",
    "module.control.aws_elasticache_user.otp_issuer",
)
_REDIS_PASSWORD_NORMALIZATION_SENSITIVE = {
    "authentication_mode": [{"passwords": True}],
    "passwords": True,
    "passwords_wo": True,
    "tags": {},
    "tags_all": {},
}

# The Step-3 Connector Authority enablement plan (plan_mode
# ``authority-contract-binding``) always refreshes two independent, externally
# driven state normalizations in the SAME plan, so its ``resource_drift`` carries
# exactly this benign pair rather than a single entry:
#   * ``module.control.aws_iam_role.hub_publisher`` -- the provider reflecting the
#     Hub publisher's separately managed inline policy into role state (validated
#     by ``_check_publisher_role_normalization`` + ``_require_hub_publisher_identity``;
#     accepted singly as ``hub-publisher-role``).
#   * ``_AUTHORITY_DIGEST_ADDRESS`` -- the Authority image-digest SSM value, which
#     ``layervai/qurl-service`` republishes/ROLLS on every main push and whose value
#     Terraform intentionally ignores (``ignore_changes=[value]``); validated by
#     ``_check_digest_normalization`` + ``_AUTHORITY_DIGEST_SPEC`` (accepted singly
#     as ``authority-digest``).
# Both drifts are refresh-phase observations that stand independently of the
# foundation-contract config change, so they co-occur on every enablement plan.
# Each is still validated against its own exact reviewed shape; only this precise
# 2-address set (in either serialization order) is admitted, and only for the
# enablement transition. Any other address, count, or shape still fails closed.
_AUTHORITY_ENABLEMENT_NORMALIZATION_ADDRESSES = frozenset(
    {
        "module.control.aws_iam_role.hub_publisher",
        _AUTHORITY_DIGEST_ADDRESS,
    }
)
_AUTHORITY_ENABLEMENT_NORMALIZATION_KIND = "authority-enablement-normalization"
# The runtime-slice re-projection composed with the Authority image digest.
# Both halves keep their own validator; only their co-occurrence is new.
_SLICE_AND_AUTHORITY_DIGEST_NORMALIZATION_KIND = (
    "authority-runtime-slice-with-authority-digest"
)

_AUTHORITY_RUNTIME_NORMALIZATION_PLAN_MODES = frozenset(
    {
        "no-op",
        "authority-runtime-slice",
        "authority-runtime-slice-retry",
        "authority-runtime-legacy-expansion",
        "authority-runtime-legacy-expansion-hub-identity",
        "authority-runtime-legacy-expansion-provisioned-cell-catalog",
        (
            "authority-runtime-legacy-expansion-hub-identity-"
            "provisioned-cell-catalog"
        ),
        # Proof rollout plans update and validate resources in the same runtime
        # slice. Provider refresh re-projections confined to that slice are no
        # less exact merely because prepare or selector owns the config change.
        "authority-proof-rollout-prepare",
        "authority-proof-rollout-selector",
        # Closing the rollout window touches the same runtime slice the rollout
        # itself did, so the same provider re-projection rides along. The drift
        # half stays fully validated by the exec-identity subset test and
        # _check_planned_security, which run outside this dispatch.
        "authority-proof-rollout-retirement",
    }
)


def _is_exact_passwordless_authentication_mode(
    auth: Any,
    auth_type: str,
) -> bool:
    """Accept only the provider's three proven passwordless state projections.

    A refresh-enabled plan materializes the optional sensitive ``passwords``
    set as an empty list. A refresh-disabled plan can read an older state
    projection that omits the empty field or a newly applied projection that
    represents the same known absence as null. All three retain the
    provider-computed ``password_count = 0`` proof and an exact auth type;
    after_unknown is rejected separately by the caller. Non-empty,
    wrong-typed, unknown, or extra fields remain rejected.
    """
    if (
        not isinstance(auth, list)
        or len(auth) != 1
        or not isinstance(auth[0], dict)
    ):
        return False
    mode = auth[0]
    if set(mode) not in (
        {"password_count", "type"},
        {"password_count", "passwords", "type"},
    ):
        return False
    password_count = mode.get("password_count")
    if type(password_count) is not int or password_count != 0:
        return False
    if mode.get("type") != auth_type:
        return False
    # An absent key reads back as None; of all JSON projections, accept only
    # that omitted/null form and the provider's explicit empty-list form.
    return mode.get("passwords") in (None, [])


INTERFACE_ENDPOINT_SERVICES = (
    "email",
    "kms",
    "lambda",
    "logs",
    "monitoring",
    "secretsmanager",
)
EXPECTED_DATA_RESOURCES = {
    "module.control.data.aws_ecr_image.authority_runtime[0]": "aws_ecr_image",
    "module.control.data.aws_ssm_parameter.authority_image_publish[0]": "aws_ssm_parameter",
    "module.control.data.aws_availability_zones.available": "aws_availability_zones",
    "module.control.data.aws_caller_identity.current": "aws_caller_identity",
    "module.control.data.aws_partition.current": "aws_partition",
    "module.control.data.aws_region.current": "aws_region",
}
DENY_ENDPOINT_POLICY = {
    "Statement": [
        {
            "Action": "*",
            "Effect": "Deny",
            "Principal": "*",
            "Resource": "*",
            "Sid": "DenyUntilAuthorityRuntimeExists",
        }
    ],
    "Version": "2012-10-17",
}
ACCOUNT_KMS_STATEMENT = {
    "Action": "kms:*",
    "Effect": "Allow",
    "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT_ID}:root"},
    "Resource": "*",
    "Sid": "EnableAccountIAM",
}
AUTHORITY_DATA_KMS_POLICY = {
    "Statement": [
        ACCOUNT_KMS_STATEMENT,
        {
            "Action": [
                "kms:Decrypt",
                "kms:DescribeKey",
                "kms:Encrypt",
                "kms:GenerateDataKey*",
                "kms:ReEncrypt*",
            ],
            "Condition": {
                "ArnEquals": {
                    "kms:EncryptionContext:aws:logs:arn": (
                        f"arn:aws:logs:{AWS_REGION}:{ACCOUNT_ID}:"
                        "log-group:/layerv/nhp/sandbox/control/vpc-flow-logs"
                    )
                }
            },
            "Effect": "Allow",
            "Principal": {"Service": f"logs.{AWS_REGION}.amazonaws.com"},
            "Resource": "*",
            "Sid": "AllowControlFlowLogs",
        },
    ],
    "Version": "2012-10-17",
}
QAT1_SIGNING_KMS_POLICY = {
    "Statement": [ACCOUNT_KMS_STATEMENT],
    "Version": "2012-10-17",
}

EXPECTED_CONFIGURATION_RESOURCES: dict[str, tuple[str, str, str]] = {}
for _address, _resource_type in EXPECTED_RESOURCES.items():
    _configuration_address = re.sub(r"\[[^]]+\]", "", _address)
    _provider_config_key = (
        "module.control:terraform" if _resource_type == "terraform_data" else "aws"
    )
    _existing = EXPECTED_CONFIGURATION_RESOURCES.setdefault(
        _configuration_address,
        ("managed", _resource_type, _provider_config_key),
    )
    if _existing != ("managed", _resource_type, _provider_config_key):
        raise RuntimeError(
            f"inconsistent configuration resource type for {_configuration_address}"
        )
EXPECTED_CONFIGURATION_RESOURCES.update(
    {
        "module.control.data.aws_availability_zones.available": (
            "data",
            "aws_availability_zones",
            "aws",
        ),
        "module.control.data.aws_caller_identity.current": (
            "data",
            "aws_caller_identity",
            "aws",
        ),
        "module.control.data.aws_partition.current": (
            "data",
            "aws_partition",
            "aws",
        ),
        "module.control.data.aws_region.current": ("data", "aws_region", "aws"),
        "module.control.data.aws_ecr_image.authority_runtime": (
            "data",
            "aws_ecr_image",
            "aws",
        ),
        "module.control.data.aws_ssm_parameter.authority_image_publish": (
            "data",
            "aws_ssm_parameter",
            "aws",
        ),
    }
)
# The runtime-slice resources are declared unconditionally in the module (their
# instances are for_each/count gated), so the CONFIGURATION always lists them,
# in the dark plan as well as the runtime plan. The managed inventory checked
# against resource_changes stays gated separately (AUTHORITY_RUNTIME_RESOURCES).
EXPECTED_CONFIGURATION_RESOURCES.update(AUTHORITY_RUNTIME_CONFIGURATION_RESOURCES)
EXPECTED_CONFIGURATION_RESOURCES.update(HUB_EDGE_CONFIGURATION_RESOURCES)
# The Hub worker slice's blocks (including its two count-gated data sources) are
# likewise declared unconditionally, so the configuration always lists them.
EXPECTED_CONFIGURATION_RESOURCES.update(HUB_WORKER_CONFIGURATION_RESOURCES)

ExpressionPath = tuple[str | int, ...]
STANDALONE_RULE_SECURITY_GROUPS = frozenset(
    {
        "module.control.aws_security_group.authority_lambda",
        "module.control.aws_security_group.otp_redis",
    }
)
STANDALONE_RULE_EMPTY_PATHS: tuple[ExpressionPath, ...] = (
    ("egress",),
    ("ingress",),
)
CONFIG_REFERENCE_CONTRACT: dict[str, dict[ExpressionPath, list[str]]] = {
    "module.control.aws_dynamodb_table_item.provisioned_cell": {
        ("for_each",): ["local.provisioned_cell_dynamodb_items"],
        ("table_name",): [
            "aws_dynamodb_table.connector_authority.name",
            "aws_dynamodb_table.connector_authority",
        ],
        ("hash_key",): [
            "aws_dynamodb_table.connector_authority.hash_key",
            "aws_dynamodb_table.connector_authority",
        ],
        ("range_key",): [
            "aws_dynamodb_table.connector_authority.range_key",
            "aws_dynamodb_table.connector_authority",
        ],
        ("item",): ["each.value"],
    },
    "module.control.data.aws_ssm_parameter.authority_image_publish": {
        ("count",): [
            "local.authority_runtime_contract_enabled",
            "local.authority_image_tracks_publish",
        ],
        # The known local, not the managed parameter's attribute. Referencing the
        # resource would defer this read to apply, and an unknown digest cannot
        # be checked by authority_contract_identity_valid at plan time.
        ("name",): ["local.authority_image_digest_parameter_name"],
    },
    "module.control.data.aws_ecr_image.authority_runtime": {
        ("count",): ["local.authority_runtime_contract_enabled"],
        ("image_digest",): ["local.authority_runtime_image_digest"],
        ("repository_name",): [
            "aws_ecr_repository.authority.name",
            "aws_ecr_repository.authority",
        ],
    },
    "module.control.aws_vpc.control": {
        ("cidr_block",): ["var.vpc_cidr"],
    },
    "module.control.aws_default_security_group.control": {
        ("vpc_id",): ["aws_vpc.control.id", "aws_vpc.control"],
    },
    "module.control.aws_security_group.interface_endpoints": {
        ("vpc_id",): ["aws_vpc.control.id", "aws_vpc.control"],
        # Ingress is the reviewed single local (empty while dark; exactly TLS/443
        # from the function SG in the runtime slice). Pinning the expression here
        # binds the opening to that reviewed local in every plan, dark included.
        ("ingress",): ["local.interface_endpoint_ingress"],
    },
    "module.control.aws_security_group.otp_redis": {
        ("vpc_id",): ["aws_vpc.control.id", "aws_vpc.control"],
    },
    "module.control.aws_security_group.authority_lambda": {
        ("vpc_id",): ["aws_vpc.control.id", "aws_vpc.control"],
    },
    "module.control.aws_vpc_security_group_egress_rule.authority_interface_endpoints": {
        ("security_group_id",): [
            "aws_security_group.authority_lambda[0].id",
            "aws_security_group.authority_lambda[0]",
            "aws_security_group.authority_lambda",
        ],
        ("referenced_security_group_id",): [
            "aws_security_group.interface_endpoints.id",
            "aws_security_group.interface_endpoints",
        ],
    },
    "module.control.aws_vpc_security_group_egress_rule.authority_dynamodb": {
        ("security_group_id",): [
            "aws_security_group.authority_lambda[0].id",
            "aws_security_group.authority_lambda[0]",
            "aws_security_group.authority_lambda",
        ],
        ("prefix_list_id",): [
            "aws_vpc_endpoint.dynamodb.prefix_list_id",
            "aws_vpc_endpoint.dynamodb",
        ],
    },
    "module.control.aws_vpc_security_group_egress_rule.authority_otp_redis": {
        ("security_group_id",): [
            "aws_security_group.authority_lambda[0].id",
            "aws_security_group.authority_lambda[0]",
            "aws_security_group.authority_lambda",
        ],
        ("referenced_security_group_id",): [
            "aws_security_group.otp_redis.id",
            "aws_security_group.otp_redis",
        ],
    },
    "module.control.aws_vpc_security_group_ingress_rule.otp_redis_authority": {
        ("security_group_id",): [
            "aws_security_group.otp_redis.id",
            "aws_security_group.otp_redis",
        ],
        ("referenced_security_group_id",): [
            "aws_security_group.authority_lambda[0].id",
            "aws_security_group.authority_lambda[0]",
            "aws_security_group.authority_lambda",
        ],
    },
    "module.control.aws_subnet.isolated": {
        ("availability_zone",): ["local.availability_zones", "count.index"],
        ("cidr_block",): ["var.vpc_cidr", "count.index"],
        ("vpc_id",): ["aws_vpc.control.id", "aws_vpc.control"],
    },
    "module.control.aws_route_table.isolated": {
        ("vpc_id",): ["aws_vpc.control.id", "aws_vpc.control"],
    },
    "module.control.aws_route_table_association.isolated": {
        ("route_table_id",): ["aws_route_table.isolated", "count.index"],
        ("subnet_id",): ["aws_subnet.isolated", "count.index"],
    },
    "module.control.aws_security_group.hub_nlb": {
        ("vpc_id",): ["aws_vpc.control.id", "aws_vpc.control"],
    },
    "module.control.aws_vpc_security_group_ingress_rule.hub_nlb_udp": {
        ("security_group_id",): [
            "aws_security_group.hub_nlb[0].id",
            "aws_security_group.hub_nlb[0]",
            "aws_security_group.hub_nlb",
        ],
    },
    "module.control.aws_lb.hub": {
        ("security_groups",): [
            "aws_security_group.hub_nlb[0].id",
            "aws_security_group.hub_nlb[0]",
            "aws_security_group.hub_nlb",
        ],
        ("subnets",): ["aws_subnet.hub_public"],
    },
    "module.control.aws_vpc_security_group_egress_rule.hub_nlb_udp": {
        ("security_group_id",): [
            "aws_security_group.hub_nlb[0].id",
            "aws_security_group.hub_nlb[0]",
            "aws_security_group.hub_nlb",
        ],
        ("referenced_security_group_id",): [
            "aws_security_group.hub_worker[0].id",
            "aws_security_group.hub_worker[0]",
            "aws_security_group.hub_worker",
        ],
    },
    "module.control.aws_vpc_security_group_egress_rule.hub_nlb_health": {
        ("security_group_id",): [
            "aws_security_group.hub_nlb[0].id",
            "aws_security_group.hub_nlb[0]",
            "aws_security_group.hub_nlb",
        ],
        ("referenced_security_group_id",): [
            "aws_security_group.hub_worker[0].id",
            "aws_security_group.hub_worker[0]",
            "aws_security_group.hub_worker",
        ],
    },
    "module.control.aws_security_group.hub_worker": {
        # Both reviewed inline ingress rules use the same edge gate and Hub NLB
        # SG. Keep the duplicate traversal sequence because Terraform 1.14 emits
        # one copy per rule; this source-locks create-time-unknown SG IDs.
        ("ingress",): [
            "local.hub_edge_enabled",
            "aws_security_group.hub_nlb[0].id",
            "aws_security_group.hub_nlb[0]",
            "aws_security_group.hub_nlb",
            "local.hub_edge_enabled",
            "aws_security_group.hub_nlb[0].id",
            "aws_security_group.hub_nlb[0]",
            "aws_security_group.hub_nlb",
        ],
    },
    "module.control.aws_vpc_endpoint.dynamodb": {
        ("route_table_ids",): ["aws_route_table.isolated"],
        ("vpc_id",): ["aws_vpc.control.id", "aws_vpc.control"],
    },
    "module.control.aws_vpc_endpoint.interface": {
        ("security_group_ids",): [
            "aws_security_group.interface_endpoints.id",
            "aws_security_group.interface_endpoints",
        ],
        ("subnet_ids",): ["aws_subnet.isolated"],
        ("vpc_id",): ["aws_vpc.control.id", "aws_vpc.control"],
    },
    "module.control.aws_elasticache_serverless_cache.otp": {
        ("kms_key_id",): [
            "aws_kms_key.authority_data.arn",
            "aws_kms_key.authority_data",
        ],
        ("security_group_ids",): [
            "aws_security_group.otp_redis.id",
            "aws_security_group.otp_redis",
        ],
        ("subnet_ids",): ["aws_subnet.isolated"],
        ("user_group_id",): [
            "aws_elasticache_user_group.otp.user_group_id",
            "aws_elasticache_user_group.otp",
        ],
    },
    "module.control.aws_elasticache_user_group.otp": {
        ("user_ids",): [
            "aws_elasticache_user.otp_disabled_default.user_id",
            "aws_elasticache_user.otp_disabled_default",
            "aws_elasticache_user.otp_issuer.user_id",
            "aws_elasticache_user.otp_issuer",
            "aws_elasticache_user.otp_activator.user_id",
            "aws_elasticache_user.otp_activator",
        ],
    },
    "module.control.aws_flow_log.control": {
        ("iam_role_arn",): ["aws_iam_role.flow_logs.arn", "aws_iam_role.flow_logs"],
        ("log_destination",): [
            "aws_cloudwatch_log_group.flow_logs.arn",
            "aws_cloudwatch_log_group.flow_logs",
        ],
        ("vpc_id",): ["aws_vpc.control.id", "aws_vpc.control"],
    },
    "module.control.aws_iam_role_policy.flow_logs": {
        ("policy",): ["local.flow_log_group_arn", "local.flow_log_group_arn"],
        ("role",): ["aws_iam_role.flow_logs.id", "aws_iam_role.flow_logs"],
    },
    "module.control.aws_iam_role_policy.authority_publisher": {
        ("role",): [
            "aws_iam_role.authority_publisher.id",
            "aws_iam_role.authority_publisher",
        ],
    },
    "module.control.aws_iam_role_policy.hub_publisher": {
        ("role",): [
            "aws_iam_role.hub_publisher.id",
            "aws_iam_role.hub_publisher",
        ],
    },
    "module.control.aws_cloudwatch_log_group.flow_logs": {
        ("kms_key_id",): [
            "aws_kms_key.authority_data.arn",
            "aws_kms_key.authority_data",
        ],
    },
    "module.control.aws_secretsmanager_secret.otp_pepper": {
        ("kms_key_id",): [
            "aws_kms_key.authority_data.arn",
            "aws_kms_key.authority_data",
        ],
    },
    "module.control.aws_secretsmanager_secret.hub_key_material": {
        ("count",): ["local.hub_worker_count"],
        ("kms_key_id",): [
            "aws_kms_key.authority_data.arn",
            "aws_kms_key.authority_data",
        ],
    },
    "module.control.aws_ssm_parameter.hub_public_key": {
        ("count",): ["local.hub_worker_count"],
        ("name",): ["local.hub_public_key_parameter_name"],
    },
    "module.control.aws_iam_role.hub_keygen": {
        ("count",): ["local.hub_worker_count"],
        ("assume_role_policy",): [
            "data.aws_partition.current.dns_suffix",
            "data.aws_partition.current",
        ],
        ("name",): ["local.name_prefix"],
    },
    "module.control.aws_iam_role_policy.hub_keygen": {
        ("count",): ["local.hub_worker_count"],
        ("policy",): [
            "aws_secretsmanager_secret.hub_key_material[0].arn",
            "aws_secretsmanager_secret.hub_key_material[0]",
            "aws_secretsmanager_secret.hub_key_material",
            "local.hub_public_key_parameter_arn",
            "aws_kms_key.authority_data.arn",
            "aws_kms_key.authority_data",
            "data.aws_region.current.region",
            "data.aws_region.current",
            "data.aws_partition.current.dns_suffix",
            "data.aws_partition.current",
            "aws_secretsmanager_secret.hub_key_material[0].arn",
            "aws_secretsmanager_secret.hub_key_material[0]",
            "aws_secretsmanager_secret.hub_key_material",
            "local.hub_keygen_log_group_arn",
        ],
        ("role",): [
            "aws_iam_role.hub_keygen[0].id",
            "aws_iam_role.hub_keygen[0]",
            "aws_iam_role.hub_keygen",
        ],
    },
    "module.control.aws_lambda_function.hub_keygen": {
        ("count",): ["local.hub_worker_count"],
        ("description",): ["var.environment"],
        ("environment", 0, "variables"): [
            "var.environment",
            "aws_ssm_parameter.hub_public_key[0].name",
            "aws_ssm_parameter.hub_public_key[0]",
            "aws_ssm_parameter.hub_public_key",
            "aws_secretsmanager_secret.hub_key_material[0].arn",
            "aws_secretsmanager_secret.hub_key_material[0]",
            "aws_secretsmanager_secret.hub_key_material",
        ],
        ("filename",): [
            "data.archive_file.hub_keygen[0].output_path",
            "data.archive_file.hub_keygen[0]",
            "data.archive_file.hub_keygen",
        ],
        ("function_name",): ["local.hub_keygen_function_name"],
        ("role",): [
            "aws_iam_role.hub_keygen[0].arn",
            "aws_iam_role.hub_keygen[0]",
            "aws_iam_role.hub_keygen",
        ],
        ("source_code_hash",): [
            "data.archive_file.hub_keygen[0].output_base64sha256",
            "data.archive_file.hub_keygen[0]",
            "data.archive_file.hub_keygen",
        ],
    },
    "module.control.aws_cloudwatch_log_group.hub_keygen": {
        ("count",): ["local.hub_worker_count"],
        ("name",): ["local.hub_keygen_log_group_name"],
        ("retention_in_days",): ["local.hub_log_retention_days"],
    },
    "module.control.data.archive_file.hub_keygen": {
        ("count",): ["local.hub_worker_count"],
        ("output_path",): ["path.module"],
        ("source_file",): ["path.module"],
    },
    "module.control.aws_lambda_invocation.hub_keygen": {
        ("count",): ["local.hub_worker_count"],
        ("function_name",): [
            "aws_lambda_function.hub_keygen[0].function_name",
            "aws_lambda_function.hub_keygen[0]",
            "aws_lambda_function.hub_keygen",
        ],
    },
    "module.control.aws_lambda_invocation.hub_identity_publication": {
        ("count",): ["local.hub_worker_count"],
        ("function_name",): [
            "aws_lambda_function.hub_keygen[0].function_name",
            "aws_lambda_function.hub_keygen[0]",
            "aws_lambda_function.hub_keygen",
        ],
    },
    "module.control.aws_iam_role_policy.hub_execution": {
        ("count",): ["local.hub_worker_count"],
        ("policy",): [
            "aws_secretsmanager_secret.hub_key_material[0].arn",
            "aws_secretsmanager_secret.hub_key_material[0]",
            "aws_secretsmanager_secret.hub_key_material",
            "aws_kms_key.authority_data.arn",
            "aws_kms_key.authority_data",
            "data.aws_region.current.region",
            "data.aws_region.current",
            "data.aws_partition.current.dns_suffix",
            "data.aws_partition.current",
            "aws_secretsmanager_secret.hub_key_material[0].arn",
            "aws_secretsmanager_secret.hub_key_material[0]",
            "aws_secretsmanager_secret.hub_key_material",
        ],
        ("role",): [
            "aws_iam_role.hub_execution[0].id",
            "aws_iam_role.hub_execution[0]",
            "aws_iam_role.hub_execution",
        ],
    },
    "module.control.aws_ecr_repository.authority": {
        ("encryption_configuration", 0, "kms_key"): [
            "aws_kms_key.authority_data.arn",
            "aws_kms_key.authority_data",
        ],
    },
    "module.control.aws_ecr_repository.hub": {
        ("encryption_configuration", 0, "kms_key"): [
            "aws_kms_key.authority_data.arn",
            "aws_kms_key.authority_data",
        ],
    },
    "module.control.aws_ecr_lifecycle_policy.hub": {
        ("repository",): [
            "aws_ecr_repository.hub.name",
            "aws_ecr_repository.hub",
        ],
    },
    "module.control.aws_kms_alias.authority_data": {
        ("target_key_id",): [
            "aws_kms_key.authority_data.key_id",
            "aws_kms_key.authority_data",
        ],
    },
    "module.control.aws_kms_alias.qat1_signing": {
        ("target_key_id",): [
            "aws_kms_key.qat1_signing.key_id",
            "aws_kms_key.qat1_signing",
        ],
    },
}
for _table in _DYNAMODB_TABLES:
    CONFIG_REFERENCE_CONTRACT[f"module.control.aws_dynamodb_table.{_table}"] = {
        ("server_side_encryption", 0, "kms_key_arn"): [
            "aws_kms_key.authority_data.arn",
            "aws_kms_key.authority_data",
        ]
    }

CONFIG_CONSTANT_CONTRACT: dict[str, dict[ExpressionPath, Any]] = {
    "module.control.aws_iam_role.authority_publisher": {
        ("max_session_duration",): 3600,
    },
    "module.control.aws_iam_role.hub_publisher": {
        ("max_session_duration",): 3600,
    },
    "module.control.aws_secretsmanager_secret.hub_key_material": {
        ("description",): (
            "Connector Hub private key and cookie keys; seeded once by the "
            "keygen Lambda, never via Terraform state"
        ),
    },
    "module.control.aws_ssm_parameter.hub_public_key": {
        ("description",): (
            "Connector Hub X25519 public identity; private key remains in "
            "Secrets Manager"
        ),
        ("type",): "String",
        ("value",): "pending-keygen",
    },
    "module.control.aws_iam_role.hub_keygen": {
        ("max_session_duration",): 3600,
    },
    "module.control.aws_lambda_function.hub_keygen": {
        ("handler",): "keygen.handler",
        ("reserved_concurrent_executions",): 1,
        ("runtime",): "nodejs22.x",
        ("timeout",): 30,
    },
    "module.control.aws_lambda_invocation.hub_keygen": {
        ("lifecycle_scope",): "CREATE_ONLY",
    },
    "module.control.aws_lambda_invocation.hub_identity_publication": {
        ("lifecycle_scope",): "CREATE_ONLY",
    },
    "module.control.data.archive_file.hub_keygen": {
        ("type",): "zip",
    },
    "module.control.aws_vpc.control": {
        ("enable_dns_hostnames",): True,
        ("enable_dns_support",): True,
    },
    "module.control.aws_default_security_group.control": {
        ("egress",): [],
        ("ingress",): [],
    },
    "module.control.aws_security_group.interface_endpoints": {
        ("egress",): [],
        # ingress moved to CONFIG_REFERENCE_CONTRACT: it is now the reviewed
        # local.interface_endpoint_ingress (empty while dark), not a literal [].
    },
    "module.control.aws_security_group.otp_redis": {
        ("egress",): [],
        ("ingress",): [],
    },
    "module.control.aws_security_group.authority_lambda": {
        ("description",): (
            "Connector Authority function ENIs; egress to Control dependency "
            "endpoints only"
        ),
        ("egress",): [],
        ("ingress",): [],
    },
    "module.control.aws_vpc_security_group_egress_rule.authority_interface_endpoints": {
        ("description",): "HTTPS to Control interface endpoints",
        ("from_port",): 443,
        ("ip_protocol",): "tcp",
        ("to_port",): 443,
    },
    "module.control.aws_vpc_security_group_egress_rule.authority_dynamodb": {
        ("description",): "HTTPS to the DynamoDB gateway endpoint",
        ("from_port",): 443,
        ("ip_protocol",): "tcp",
        ("to_port",): 443,
    },
    "module.control.aws_vpc_security_group_egress_rule.authority_otp_redis": {
        ("description",): "TLS to Connector OTP Redis",
        ("from_port",): 6379,
        ("ip_protocol",): "tcp",
        ("to_port",): 6379,
    },
    "module.control.aws_vpc_security_group_ingress_rule.otp_redis_authority": {
        ("description",): "TLS from Connector Authority OTP functions",
        ("from_port",): 6379,
        ("ip_protocol",): "tcp",
        ("to_port",): 6379,
    },
    "module.control.aws_subnet.isolated": {
        ("map_public_ip_on_launch",): False,
    },
    "module.control.aws_vpc_endpoint.dynamodb": {
        ("vpc_endpoint_type",): "Gateway",
    },
    "module.control.aws_vpc_endpoint.interface": {
        ("private_dns_enabled",): True,
        ("vpc_endpoint_type",): "Interface",
    },
    "module.control.aws_ecr_repository.authority": {
        ("encryption_configuration", 0, "encryption_type"): "KMS",
        ("image_scanning_configuration", 0, "scan_on_push"): True,
        ("image_tag_mutability",): "IMMUTABLE",
    },
    "module.control.aws_ecr_repository.hub": {
        ("encryption_configuration", 0, "encryption_type"): "KMS",
        ("image_scanning_configuration", 0, "scan_on_push"): True,
        ("image_tag_mutability",): "IMMUTABLE",
    },
    "module.control.aws_elasticache_user.otp_activator": {
        ("authentication_mode", 0, "type"): "iam",
    },
    "module.control.aws_elasticache_user.otp_disabled_default": {
        ("authentication_mode", 0, "type"): "no-password-required",
    },
    "module.control.aws_elasticache_user.otp_issuer": {
        ("authentication_mode", 0, "type"): "iam",
    },
}
for _table in _DYNAMODB_TABLES:
    CONFIG_CONSTANT_CONTRACT[f"module.control.aws_dynamodb_table.{_table}"] = {
        ("server_side_encryption", 0, "enabled"): True
    }

CONFIG_ABSENT_PATHS: dict[str, tuple[ExpressionPath, ...]] = {
    "module.control.aws_vpc.control": tuple(
        (field,)
        for field in (
            "assign_generated_ipv6_cidr_block",
            "ipv4_ipam_pool_id",
            "ipv4_netmask_length",
            "ipv6_cidr_block",
            "ipv6_ipam_pool_id",
            "ipv6_netmask_length",
        )
    ),
    "module.control.aws_subnet.isolated": tuple(
        (field,)
        for field in (
            "assign_ipv6_address_on_creation",
            "customer_owned_ipv4_pool",
            "enable_dns64",
            "ipv6_cidr_block",
            "ipv6_ipam_pool_id",
            "ipv6_native",
            "ipv6_netmask_length",
            "map_customer_owned_ip_on_launch",
        )
    ),
    "module.control.aws_route_table.isolated": (("route",),),
    "module.control.aws_vpc_endpoint.dynamodb": (
        ("security_group_ids",),
        ("subnet_ids",),
    ),
    "module.control.aws_vpc_endpoint.interface": (("route_table_ids",),),
    "module.control.aws_elasticache_serverless_cache.otp": (
        ("daily_snapshot_time",),
        ("snapshot_arns_to_restore",),
    ),
    "module.control.aws_ssm_parameter.hub_image_digest": (
        ("allowed_pattern",),
        ("data_type",),
        ("has_value_wo",),
        ("insecure_value",),
        ("key_id",),
        ("overwrite",),
        ("tier",),
        ("value_wo",),
        ("value_wo_version",),
    ),
    "module.control.aws_ssm_parameter.hub_public_key": (
        ("allowed_pattern",),
        ("data_type",),
        ("has_value_wo",),
        ("insecure_value",),
        ("key_id",),
        ("overwrite",),
        ("tier",),
        ("value_wo",),
        ("value_wo_version",),
    ),
    "module.control.aws_lambda_function.hub_keygen": (
        ("dead_letter_config",),
        ("file_system_config",),
        ("image_config",),
        ("vpc_config",),
    ),
    "module.control.aws_elasticache_user.otp_activator": (
        ("authentication_mode", 0, "passwords"),
        ("no_password_required",),
        ("passwords",),
        ("passwords_wo",),
        ("passwords_wo_version",),
    ),
    "module.control.aws_elasticache_user.otp_disabled_default": (
        ("authentication_mode", 0, "passwords"),
        ("no_password_required",),
        ("passwords",),
        ("passwords_wo",),
        ("passwords_wo_version",),
    ),
    "module.control.aws_iam_role.authority_publisher": (
        ("inline_policy",),
        ("managed_policy_arns",),
        ("permissions_boundary",),
    ),
    "module.control.aws_iam_role.hub_publisher": (
        ("inline_policy",),
        ("managed_policy_arns",),
        ("permissions_boundary",),
    ),
    "module.control.aws_elasticache_user.otp_issuer": (
        ("authentication_mode", 0, "passwords"),
        ("no_password_required",),
        ("passwords",),
        ("passwords_wo",),
        ("passwords_wo_version",),
    ),
}


class ContractError(ValueError):
    """Raised when plan or live evidence violates the reviewed contract."""


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ContractError(f"cannot read JSON {path}: {exc}") from exc


def _canonical_json(value: Any) -> bytes:
    # Keep default ensure_ascii=True aligned with the per-field json.dumps
    # budget in _bounded_drift_identity_field; changing either requires
    # re-validating the 7,500-character diagnostic ceiling.
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _json_sha256(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _json_equal(left: Any, right: Any) -> bool:
    """Compare JSON values without Python's ``False == 0`` coercion."""
    return _canonical_json(left) == _canonical_json(right)


def _normalization_drift_sha256(drift: list[dict[str, Any]]) -> str:
    """Hash the admitted drift independent of Terraform's serialization order.

    The review-time plan and the immediate pre-apply live-refresh plan observe
    the same admitted drift, but Terraform does not guarantee the ``resource_drift``
    array is serialized in an identical order across the two separate plans. The
    order carries no security weight -- every entry is validated independently
    against its exact reviewed shape -- so canonicalize by sorting on ``address``
    before hashing. This is a no-op for the single-drift kinds and for the
    already-address-sorted Redis pair, and it makes the enablement pair's
    plan-vs-live ``normalization_drift_sha256`` comparison deterministic.
    """
    ordered = sorted(drift, key=lambda item: item.get("address") or "")
    return _json_sha256(ordered)


def _drift_before_is_unrecorded(before: dict[str, Any], key: str) -> bool:
    """Return True when state held NO prior value for ``key``.

    "Unrecorded" is deliberately narrow: the key is absent, explicitly null, or
    an EMPTY collection. A populated value of any kind is a recorded value, and
    so is ``""``/``0``/``False`` -- those are real settings a provider can
    return, not placeholders, and admitting them would let a scalar flip
    (``false`` -> ``true`` on a public-access toggle) pass as a projection.
    Emptiness is tested only on list/dict so Python's ``0 == False`` and
    ``[] == ()`` coercions cannot widen it.
    """
    if key not in before:
        return True
    value = before[key]
    if value is None:
        return True
    return isinstance(value, (list, dict)) and not value


def _drift_is_first_projection_only(item: Any) -> bool:
    """Return True when a drift entry carries no out-of-band-change signal.

    Terraform's ``resource_drift`` mixes two very different things. When state
    held a PRIOR VALUE and the refresh read a DIFFERENT one, something changed
    outside Terraform -- an edited policy, a widened security-group rule, a
    revoked KMS grant. That is the signal this checker exists to catch. When
    state held NOTHING for an attribute and the refresh recorded one, state is
    merely catching up to a reality it never described: Optional+Computed
    collections the provider now returns (``ok_actions``,
    ``insufficient_data_actions``, ``tags``), or a deprecated read-back such as
    ``inline_policy``. Nothing changed; there was no prior value to change FROM.

    The discriminator is NOT the attribute name -- signal and noise arrive in
    the SAME attributes (``ingress``, ``inline_policy``) -- so it is the
    before-value that decides.

    Admitting these does not blind the checker to a live/config divergence. The
    projected after-state is what Terraform computes the PLANNED changes
    against, and those are validated separately and in full (inventory
    equality, per-address action shape, ``_check_planned_security``, the
    endpoint-policy and runtime-resource field contracts). If live differed
    from config, the owning resource would carry a non-no-op planned change and
    fail there. This is the same reasoning ``_require_inline_policy_projection``
    already relies on for policy content.

    Fails closed on anything it cannot positively prove benign.
    """
    change = item.get("change") if isinstance(item, dict) else None
    before = change.get("before") if isinstance(change, dict) else None
    after = change.get("after") if isinstance(change, dict) else None
    if not isinstance(before, dict) or not isinstance(after, dict):
        return False
    if not before:
        # An empty before object is a CREATE (or a malformed entry), not a
        # re-projection onto an object state already tracked.
        return False
    differing = [
        key
        for key in (set(before) | set(after))
        if not _json_equal(before.get(key), after.get(key))
    ]
    if not differing:
        # Nothing differs. Returning True here would be vacuous and would admit
        # malformed entries whose before/after are identical, so fail closed and
        # let the strict path reject them with the bounded identity diagnostic.
        return False
    return all(_drift_before_is_unrecorded(before, key) for key in differing)


# Addresses whose drift ALWAYS takes the strict reviewed-kind path, even when it
# is a pure first projection. These are not exceptions to the discriminator --
# they are the two roles whose reviewed normalization
# (``_check_publisher_role_normalization``) is BY DEFINITION a first projection:
# it requires ``before["inline_policy"]`` to be null or ``[]``. Filtering them
# would make that checker unreachable and silently drop what it proves beyond
# noise-classification: that the drifted role is the reviewed publisher identity
# and that its projected inline policy matches the separately managed
# ``aws_iam_role_policy`` in the same plan. The caller additionally binds this
# kind to a pure no-op plan. Both properties are real invariants, so the two
# addresses stay strict. This set is fixed and does NOT grow as new slices apply
# -- neither role appears in the sandbox drift this change was measured against
# -- so it cannot reintroduce the widening treadmill.
_STRICT_DRIFT_ADDRESSES = frozenset(
    {
        "module.control.aws_iam_role.authority_publisher",
        "module.control.aws_iam_role.hub_publisher",
    }
)


def _partition_first_projection_drift(
    drift: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Split drift into (benign first projections, everything else)."""
    benign: list[dict[str, Any]] = []
    substantive: list[dict[str, Any]] = []
    for item in drift:
        address = item.get("address") if isinstance(item, dict) else None
        # Guard the isinstance BEFORE the set membership: a malformed address can
        # be an unhashable value (a dict), which would raise TypeError here
        # instead of reaching the bounded, value-free rejection diagnostic. A
        # non-str or strict address always routes to ``substantive``.
        if (
            isinstance(address, str)
            and address not in _STRICT_DRIFT_ADDRESSES
            and _drift_is_first_projection_only(item)
        ):
            benign.append(item)
        else:
            substantive.append(item)
    return benign, substantive


# Distinct un-indexed resources named in the histogram before the tail folds.
_DRIFT_RESOURCE_HISTOGRAM_LIMIT = 12


def _bounded_drift_identity_field(field: str, value: Any) -> tuple[str, bool]:
    """Render one public Terraform identity field without arbitrary values."""
    if not isinstance(value, str):
        return "<malformed>", True
    if field == "address" and ("[" in value or "]" in value):
        # Terraform addresses embed for_each instance keys in brackets. Even
        # though the current Control root has only static addresses, never let
        # a future key cross this value-free diagnostic boundary.
        return "<indexed-address>", True

    source = value[:_DRIFT_IDENTITY_FIELD_MAX_CHARS]
    truncated = len(source) != len(value)
    marker = "<truncated>"

    candidate = source + (marker if truncated else "")
    if len(json.dumps(candidate)) <= _DRIFT_IDENTITY_FIELD_MAX_JSON_CHARS:
        return candidate, truncated

    low, high = 0, len(source)
    while low < high:
        midpoint = (low + high + 1) // 2
        if len(json.dumps(source[:midpoint] + marker)) <= (
            _DRIFT_IDENTITY_FIELD_MAX_JSON_CHARS
        ):
            low = midpoint
        else:
            high = midpoint - 1
    return source[:low] + marker, True


def _drift_resource_histogram(drift: list[dict[str, Any]]) -> dict[str, int]:
    """Count drift per UN-INDEXED address, which is code rather than data.

    The per-identity rows below redact any address carrying a for_each key, so a
    rejection over N instances of one resource renders as N identical
    ``<indexed-address>`` rows and says nothing about WHAT drifted. A real
    rejection of 27 entries showed eight of those and no way to tell which
    resources were involved; diagnosing it took a state download and a
    resource-by-resource diff against live AWS.

    Stripping the bracketed key leaves ``module.control.aws_iam_role.authority_exec``
    -- a static identifier that already appears verbatim in this file's own
    constants. It carries no instance key, no attribute, and no value, so it
    crosses the value-free boundary the per-row redaction protects while
    restoring the one fact an operator needs first: which resources, and how
    many of each.
    """
    counts: dict[str, int] = {}
    for item in drift:
        address = item.get("address") if isinstance(item, dict) else None
        if not isinstance(address, str):
            base = "<malformed>"
        else:
            # Cap length with the SAME renderer the per-identity rows use. The
            # bracket strip happens first, so the indexed-address redaction can
            # never fire here -- what remains is the length bound, which is the
            # part that matters: an unbounded key would blow the diagnostic
            # ceiling and push every identity row out of the message.
            base, _ = _bounded_drift_identity_field(
                "address", address.split("[", 1)[0]
            )
        counts[base] = counts.get(base, 0) + 1
    if len(counts) <= _DRIFT_RESOURCE_HISTOGRAM_LIMIT:
        return counts
    # Bounded by construction: keep the largest groups, which are the ones that
    # explain a bulk rejection, and fold the tail into one counted bucket.
    ranked = sorted(counts.items(), key=lambda entry: (-entry[1], entry[0]))
    kept = dict(ranked[:_DRIFT_RESOURCE_HISTOGRAM_LIMIT])
    kept["<other-resources>"] = sum(
        count for _, count in ranked[_DRIFT_RESOURCE_HISTOGRAM_LIMIT:]
    )
    return kept


def _drift_identity_diagnostic(drift: list[dict[str, Any]]) -> str:
    """Return bounded, value-free identities for rejected resource drift."""
    identities = []
    fields_truncated = False
    for item in drift[:_DRIFT_IDENTITY_LIMIT]:
        item = item if isinstance(item, dict) else {}
        identity = {}
        for field in _DRIFT_IDENTITY_FIELDS:
            rendered, truncated = _bounded_drift_identity_field(
                field, item.get(field)
            )
            identity[field] = rendered
            fields_truncated = fields_truncated or truncated
        identities.append(identity)
    resources: dict[str, int] | None = _drift_resource_histogram(drift)
    while True:
        identities_omitted = len(drift) > len(identities)
        rendered = _canonical_json(
            {
                "count": len(drift),
                **({} if resources is None else {"resources": resources}),
                "identities": identities,
                # True means some identity information was omitted, redacted,
                # or shortened; consumers must not interpret it as row-only.
                "truncated": identities_omitted or fields_truncated,
            }
        ).decode("utf-8")
        if len(rendered) <= _DRIFT_DIAGNOSTIC_MAX_CHARS:
            return rendered
        # One identity always fits: each of its three fields is capped at 2,048
        # rendered JSON characters, leaving ample room under the 7,500 ceiling
        # for keys and envelope metadata. Therefore pop() cannot empty the list.
        # ``_canonical_json`` can expand one Unicode code point into multiple
        # ASCII escape characters. Drop whole identities until the emitted log
        # line, rather than only its source fields, satisfies the hard bound.
        #
        # The resource histogram competes for the same ceiling, so it is dropped
        # BEFORE the last identity rather than after: an identity row is the
        # older, load-bearing guarantee, and the histogram is a convenience that
        # must never be able to squeeze it out.
        if len(identities) > 1:
            identities.pop()
            continue
        if resources is not None:
            resources = None
            continue
        identities.pop()


def _unexpected_drift_error(drift: list[dict[str, Any]]) -> ContractError:
    """Fail-closed rejection carrying the bounded, value-free drift identity."""
    return ContractError(
        "unexpected Terraform resource drift; only an exact reviewed state "
        "normalization is admitted; resource_drift_identity="
        f"{_drift_identity_diagnostic(drift)}"
    )


def _refresh_only_value_shape(value: Any) -> str:
    """Return a bounded, value-free diagnostic for Terraform value-tree drift."""
    if not isinstance(value, dict):
        return f"planned={type(value).__name__}"
    root = value.get("root_module")
    outputs = value.get("outputs")
    entries = list(outputs.values()) if isinstance(outputs, dict) else []
    object_entries = [entry for entry in entries if isinstance(entry, dict)]
    return ";".join(
        (
            f"planned=dict:{len(value)}",
            f"root={type(root).__name__}:"
            f"{len(root) if isinstance(root, dict) else '-'}",
            f"outputs={type(outputs).__name__}:"
            f"{len(outputs) if isinstance(outputs, dict) else '-'}",
            f"entry_objects={len(object_entries)}",
            "entry_sensitive_false="
            f"{sum(entry.get('sensitive') is False for entry in object_entries)}",
            f"entry_type_present={sum('type' in entry for entry in object_entries)}",
            f"entry_value_present={sum('value' in entry for entry in object_entries)}",
        )
    )


def _is_exact_nonsensitive_output_entry(value: Any) -> bool:
    """Require Terraform's exact non-sensitive root-output entry shape."""
    return (
        isinstance(value, dict)
        and set(value) == _OUTPUT_ENTRY_KEYS
        and value.get("sensitive") is False
    )


def contract_sha256() -> str:
    """Fingerprint the reviewed resource-address/type inventory."""
    return _json_sha256(EXPECTED_RESOURCES)


def _non_noop(items: Any, label: str) -> list[dict[str, Any]]:
    if items is None:
        return []
    if not isinstance(items, list):
        raise ContractError(f"{label} must be an array")
    result = []
    for item in items:
        if not isinstance(item, dict):
            raise ContractError(f"{label} entries must be objects")
        change = item.get("change")
        if not isinstance(change, dict):
            raise ContractError(f"{label} change entries must be objects")
        if change.get("actions") != ["no-op"]:
            result.append(item)
    return result


def _iter_configuration_modules(
    module: Any, prefix: str = ""
) -> Iterable[tuple[str, dict[str, Any]]]:
    if not isinstance(module, dict):
        raise ContractError("Terraform configuration module must be an object")
    yield prefix, module
    calls = module.get("module_calls", {})
    if not isinstance(calls, dict):
        raise ContractError("Terraform configuration module_calls must be an object")
    for name, call in calls.items():
        if not isinstance(call, dict) or not isinstance(call.get("module"), dict):
            raise ContractError(
                f"Terraform configuration module call is malformed: {name}"
            )
        child_prefix = f"{prefix}.module.{name}" if prefix else f"module.{name}"
        yield from _iter_configuration_modules(call["module"], child_prefix)


def _configuration_resource_map(plan: dict[str, Any]) -> dict[str, dict[str, Any]]:
    configuration = plan.get("configuration")
    if not isinstance(configuration, dict) or not isinstance(
        configuration.get("root_module"), dict
    ):
        raise ContractError("Terraform plan configuration root_module is missing")
    provider_config = configuration.get("provider_config")
    if not isinstance(provider_config, dict) or set(provider_config) != {
        "aws",
        "module.control:terraform",
        "module.control:archive",
    }:
        raise ContractError("Terraform provider configuration map is not exact")
    aws_provider = provider_config["aws"]
    terraform_provider = provider_config["module.control:terraform"]
    # The Hub keygen (slice 5b) packages its handler via data.archive_file, a
    # module-local provider (declared in the module's required_providers, not
    # configured at the root), so it appears namespaced like terraform_data's
    # provider. It carries no provider config block; validate its identity
    # tolerantly (the version_constraint field may or may not be projected).
    archive_provider = provider_config["module.control:archive"]
    if (
        not isinstance(aws_provider, dict)
        or set(aws_provider)
        != {"name", "full_name", "version_constraint", "expressions"}
        or aws_provider.get("name") != "aws"
        or aws_provider.get("full_name") != "registry.terraform.io/hashicorp/aws"
        or aws_provider.get("version_constraint") != "~> 6.27"
        or not isinstance(aws_provider.get("expressions"), dict)
        or set(aws_provider.get("expressions", {})) != {"default_tags", "region"}
        or aws_provider.get("expressions", {}).get("region")
        != {"references": ["var.aws_region"]}
        or not isinstance(terraform_provider, dict)
        or terraform_provider
        != {
            "name": "terraform",
            "full_name": "terraform.io/builtin/terraform",
            "module_address": "module.control",
        }
        or not isinstance(archive_provider, dict)
        or archive_provider.get("name") != "archive"
        or archive_provider.get("full_name")
        != "registry.terraform.io/hashicorp/archive"
        or archive_provider.get("module_address") != "module.control"
    ):
        raise ContractError("Terraform provider configuration identity drifted")

    by_address: dict[str, dict[str, Any]] = {}
    for prefix, module in _iter_configuration_modules(configuration["root_module"]):
        resources = module.get("resources", [])
        if not isinstance(resources, list):
            raise ContractError("Terraform configuration resources must be an array")
        for resource in resources:
            if not isinstance(resource, dict) or not isinstance(
                resource.get("address"), str
            ):
                raise ContractError("Terraform configuration resource is malformed")
            address = (
                f"{prefix}.{resource['address']}" if prefix else resource["address"]
            )
            if address in by_address:
                raise ContractError(
                    f"duplicate Terraform configuration resource: {address}"
                )
            if resource.get("provisioners") not in (None, []):
                raise ContractError(
                    f"Terraform configuration resource has provisioners: {address}"
                )
            by_address[address] = resource
    actual = {
        address: (
            resource.get("mode"),
            resource.get("type"),
            resource.get("provider_config_key"),
        )
        for address, resource in by_address.items()
    }
    if actual != EXPECTED_CONFIGURATION_RESOURCES:
        missing = sorted(set(EXPECTED_CONFIGURATION_RESOURCES) - set(actual))
        extra = sorted(set(actual) - set(EXPECTED_CONFIGURATION_RESOURCES))
        mismatched = sorted(
            address
            for address in set(actual) & set(EXPECTED_CONFIGURATION_RESOURCES)
            if actual[address] != EXPECTED_CONFIGURATION_RESOURCES[address]
        )
        raise ContractError(
            "Terraform configuration resource map differs; "
            f"missing={missing}, extra={extra}, mode_type_provider={mismatched}"
        )
    return by_address


_MISSING = object()


def _expression_at(expressions: Any, path: ExpressionPath) -> Any:
    current = expressions
    for part in path:
        if isinstance(part, str):
            if not isinstance(current, dict) or part not in current:
                return _MISSING
            current = current[part]
        else:
            if not isinstance(current, list) or part >= len(current):
                return _MISSING
            current = current[part]
    return current


def _check_configuration_security(
    resources: dict[str, dict[str, Any]],
) -> None:
    def expressions_of(address: str) -> dict[str, Any]:
        expressions = resources[address].get("expressions")
        if not isinstance(expressions, dict):
            raise ContractError(
                f"Terraform configuration expressions missing: {address}"
            )
        normalized = dict(expressions)
        # The Authority Lambda and OTP Redis SGs deliberately own all rules via
        # standalone aws_vpc_security_group_*_rule resources. Terraform omits
        # their inline ingress/egress expressions while the planned/state value
        # remains []. Normalize only that omission to the existing exact-empty
        # contract; any configured nonempty inline rule still differs and fails.
        if address in STANDALONE_RULE_SECURITY_GROUPS:
            for path in STANDALONE_RULE_EMPTY_PATHS:
                if _expression_at(normalized, path) is _MISSING:
                    normalized[path[0]] = {"constant_value": []}
        count_expression = resources[address].get("count_expression", _MISSING)
        if count_expression is not _MISSING:
            normalized["count"] = count_expression
        for_each_expression = resources[address].get(
            "for_each_expression", _MISSING
        )
        if for_each_expression is not _MISSING:
            normalized["for_each"] = for_each_expression
        return normalized

    for address, paths in CONFIG_REFERENCE_CONTRACT.items():
        expressions = expressions_of(address)
        for path, references in paths.items():
            actual = _expression_at(expressions, path)
            if actual != {"references": references}:
                raise ContractError(
                    f"Terraform configuration reference differs: {address} {path}"
                )
    for address, paths in CONFIG_CONSTANT_CONTRACT.items():
        expressions = expressions_of(address)
        for path, constant in paths.items():
            actual = _expression_at(expressions, path)
            if actual != {"constant_value": constant}:
                raise ContractError(
                    f"Terraform configuration constant differs: {address} {path}"
                )
    for address, paths in CONFIG_ABSENT_PATHS.items():
        expressions = expressions_of(address)
        for path in paths:
            if _expression_at(expressions, path) is not _MISSING:
                raise ContractError(
                    f"forbidden Terraform configuration input exists: {address} {path}"
                )


def _check_no_embedded_actions(plan: dict[str, Any]) -> None:
    action_invocations = plan.get("action_invocations")
    if action_invocations not in (None, []):
        raise ContractError("Terraform plan contains action_invocations")
    _check_configuration_security(_configuration_resource_map(plan))


def _require_fields(
    values: Any, expected: dict[str, Any], address: str, label: str = "planned"
) -> None:
    if not isinstance(values, dict):
        raise ContractError(f"{address} {label} values must be an object")
    mismatches = [key for key, value in expected.items() if values.get(key) != value]
    if mismatches:
        raise ContractError(
            f"{address} {label} security fields differ: {sorted(mismatches)}"
        )


def _provisioned_cell_resource_id(cell_id: str) -> str:
    """Derive the row's Terraform resource id from its pinned key components.

    The provider composes `id` from three attributes this checker already pins
    exactly -- table name, hash key value, range key value -- glued with the
    standard AWS-provider resource-id separator. #3458 calibrated the whole
    string as "|"-joined against the create plan, where `id` is unknown and so
    was never observed; every applied row renders ","-joined. Compose the
    pinned components rather than restating a spelling, so the separator is
    the only thing this literal asserts.
    """
    return PROVISIONED_CELL_ID_SEPARATOR.join(
        (PROVISIONED_CELL_TABLE_NAME, "REGISTRY", f"CELL#{cell_id}")
    )


# general_assignable is the single OPTIONAL provisioned-cell attribute (B6,
# qurl-service #1351). It is a DynamoDB Boolean the weighted-HRW selector reads
# to decide whether a cell may take NEW general placements. qurl-service decodes
# an ABSENT attribute as true, so an assignable cell OMITS it and only a
# non-assignable cell carries {"BOOL": false}. Exactly these three spellings are
# admitted anywhere a catalog item is pinned; every OTHER attribute stays
# byte-identical to the reviewed row.
_GENERAL_ASSIGNABLE_ITEM_VALUES: tuple[dict[str, bool], ...] = (
    {"BOOL": True},
    {"BOOL": False},
)


def _split_general_assignable_item(
    decoded: dict[str, Any], address: str
) -> tuple[dict[str, Any], "dict[str, bool] | None"]:
    """Peel the optional general_assignable Boolean off a decoded catalog item.

    Returns the item with general_assignable removed (so the remaining
    attributes can be compared byte-for-byte against the reviewed row) and the
    attribute itself, or None when absent. Rejects any spelling other than
    absent / {"BOOL": true} / {"BOOL": false}; nothing else about the row may
    ride in on this key.
    """
    general_assignable = decoded.get("general_assignable", _MISSING)
    if (
        general_assignable is not _MISSING
        and general_assignable not in _GENERAL_ASSIGNABLE_ITEM_VALUES
    ):
        raise ContractError(
            f"{address} provisioned-cell general_assignable must be an absent or "
            "Boolean DynamoDB attribute"
        )
    core = {k: v for k, v in decoded.items() if k != "general_assignable"}
    return core, (None if general_assignable is _MISSING else general_assignable)


def _strip_general_assignable_output(value: Any) -> "dict[str, Any] | None":
    """Drop the resolved general_assignable Boolean from each cell of the public
    catalog output so the remainder is pinned exactly. Returns None when the
    shape is not the expected cell->object mapping, or when a present
    general_assignable is not a Boolean.
    """
    if not isinstance(value, dict):
        return None
    normalized: dict[str, Any] = {}
    for cell_id, cell in value.items():
        if not isinstance(cell, dict):
            return None
        general_assignable = cell.get("general_assignable", _MISSING)
        if general_assignable is not _MISSING and not isinstance(
            general_assignable, bool
        ):
            return None
        normalized[cell_id] = {
            k: v for k, v in cell.items() if k != "general_assignable"
        }
    return normalized


def _require_provisioned_cell_item(
    values: dict[str, Any], cell_id: str, address: str
) -> None:
    """Pin the catalog row to its exact producer-owned attribute projection.

    `item` is compared as a DECODED object rather than as JSON text. Terraform
    carries the create plan's value straight from the configuration's
    `jsonencode`, but every refreshed read re-renders it from the live
    AttributeValue map through the provider's Go `json.Encoder`, which
    terminates the document with a newline. Both spellings are the same
    object, so a string comparison rejects the applied row over a
    serialisation the checker does not own. Decoding admits only that
    rendering: every attribute name, type tag and value stays pinned exactly,
    and because DynamoDB numbers travel as JSON strings even numeric spelling
    ("1" vs "1.0") remains byte-exact.
    """
    expected_item = PROVISIONED_CELL_DYNAMODB_ITEMS[cell_id]
    decoded = _decode_exact_json(values.get("item"), "item", address)
    if not isinstance(decoded, dict):
        raise ContractError(f"{address} provisioned-cell item is not a JSON object")
    # Admit the optional general_assignable Boolean; pin every other attribute
    # (including updated_at) exactly to the reviewed row. An absent attribute is
    # the pre-B6 shape and still validates unchanged.
    core, _general_assignable = _split_general_assignable_item(decoded, address)
    if core != expected_item:
        differing = sorted(
            attribute
            for attribute in {*expected_item, *core}
            if core.get(attribute) != expected_item.get(attribute)
        )
        raise ContractError(
            f"{address} provisioned-cell item attributes differ: {differing}"
        )


def _require_provisioned_cell_values(
    values: Any,
    unknown: Any,
    address: str,
    *,
    create: bool,
) -> None:
    """Pin every catalog row to its exact producer-owned UDP endpoint contract."""
    cell_id = PROVISIONED_CELL_ID_BY_ADDRESS.get(address)
    if cell_id is None or not isinstance(values, dict) or not isinstance(unknown, dict):
        raise ContractError(f"{address} provisioned-cell values are malformed")

    expected = {
        "hash_key": "pk",
        "range_key": "sk",
        "region": AWS_REGION,
        "table_name": PROVISIONED_CELL_TABLE_NAME,
    }
    _require_fields(values, expected, address)
    _require_provisioned_cell_item(values, cell_id, address)
    expected_fields = {*expected, "item"}

    if create:
        # The sandbox Control root currently pins hashicorp/aws 6.55.0. A
        # provider upgrade must re-prove this exact create envelope from a real
        # reviewed plan before changing the trusted checker.
        if set(values) != expected_fields:
            raise ContractError(
                f"{address} create values contain an unexpected field set"
            )
        if unknown != {
            "hash_key_value": True,
            "id": True,
            "range_key_value": True,
        }:
            raise ContractError(
                f"{address} create unknown-value envelope is not exact"
            )
        return

    if set(values) != {
        *expected_fields,
        "hash_key_value",
        "id",
        "range_key_value",
    }:
        raise ContractError(f"{address} steady values contain an unexpected field set")
    if (
        values.get("hash_key_value") != "REGISTRY"
        or values.get("range_key_value") != f"CELL#{cell_id}"
        or values.get("id") != _provisioned_cell_resource_id(cell_id)
        or unknown != {}
    ):
        raise ContractError(f"{address} steady key identity is not exact")


def _require_provisioned_cell_create_output(plan: dict[str, Any]) -> None:
    """Bind the catalog-row create to the exact public Control output."""
    _require_provisioned_cell_planned_output(plan, catalog_present=True)

    output_changes = plan.get("output_changes")
    change = (
        output_changes.get("provisioned_cells")
        if isinstance(output_changes, dict)
        else None
    )
    # The catalog output is DECLARED unconditionally, so it has existed as an
    # empty map since the Control root was first applied. Populating it is
    # therefore an `update` from {}, not a `create` from null -- the create
    # shape only ever existed before the output was declared. Admit both, since
    # they are the same transition: nothing -> exactly the reviewed two rows.
    actions = change.get("actions") if isinstance(change, dict) else None
    before = change.get("before") if isinstance(change, dict) else None
    catalog_appears = (actions == ["create"] and before is None) or (
        actions == ["update"] and before == {}
    )
    if (
        not isinstance(change, dict)
        or set(change) != _CHANGE_KEYS
        or not catalog_appears
        or _strip_general_assignable_output(change.get("after"))
        != PROVISIONED_CELL_CATALOG
        or change.get("after_unknown") is not False
        or change.get("before_sensitive") is not False
        or change.get("after_sensitive") is not False
    ):
        raise ContractError(
            "provisioned-cell create output change is not the exact public contract"
        )


def _require_provisioned_cell_planned_output(
    plan: dict[str, Any], *, catalog_present: bool
) -> None:
    """Bind every plan mode to the catalog slice's exact public projection."""
    planned_values = plan.get("planned_values")
    outputs = (
        planned_values.get("outputs")
        if isinstance(planned_values, dict)
        else None
    )
    output = outputs.get("provisioned_cells") if isinstance(outputs, dict) else None
    expected = PROVISIONED_CELL_CATALOG if catalog_present else {}
    if not _is_exact_nonsensitive_output_entry(output):
        raise ContractError(
            "planned provisioned-cell output does not match the all-or-nothing "
            "catalog inventory"
        )
    # The public catalog output surfaces general_assignable as a RESOLVED
    # Boolean per cell (an assignable cell shows true even though its stored item
    # omits the attribute). Admit that optional Boolean and pin every other
    # projected field exactly. An output with no general_assignable at all is
    # the pre-B6 shape and still matches unchanged.
    normalized = _strip_general_assignable_output(output.get("value"))
    if normalized != expected:
        raise ContractError(
            "planned provisioned-cell output does not match the all-or-nothing "
            "catalog inventory"
        )


def _reject_repeated_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Refuse rendered JSON whose objects repeat a key.

    Python decodes a repeated key last-writer-wins, which would let a repeat
    park a real value behind an admitted one. No pinned projection repeats a
    key, so a repeat is never a rendering difference.
    """
    decoded = dict(pairs)
    if len(decoded) != len(pairs):
        raise ValueError("object repeats a key")
    return decoded


def _decode_exact_json(raw: Any, field: str, address: str) -> Any:
    """Decode a rendered JSON attribute for exact semantic comparison."""
    if not isinstance(raw, str):
        raise ContractError(f"{address} {field} must be JSON text")
    try:
        # json.JSONDecodeError subclasses ValueError, so this also carries the
        # repeated-key refusal above.
        return json.loads(raw, object_pairs_hook=_reject_repeated_json_keys)
    except ValueError as exc:
        raise ContractError(f"{address} {field} is malformed JSON: {exc}") from exc


def _require_json_field(
    values: dict[str, Any], field: str, expected: Any, address: str
) -> None:
    if _decode_exact_json(values.get(field), field, address) != expected:
        raise ContractError(f"{address} {field} differs from the dark contract")


def _require_publisher_identity(
    role: dict[str, Any],
    policy: dict[str, Any],
    *,
    reflected_inline_policy: bool | None,
    role_address: str,
    policy_address: str,
    role_name: str,
    trust_policy: dict[str, Any],
    inline_policy_name: str,
    inline_policy: dict[str, Any],
    label: str,
) -> None:
    _require_fields(
        role,
        {
            "max_session_duration": 3600,
            "name": role_name,
            "path": "/",
        },
        role_address,
    )
    _require_json_field(
        role,
        "assume_role_policy",
        trust_policy,
        role_address,
    )
    if role.get("managed_policy_arns") not in (None, []):
        raise ContractError(f"{label} publisher may not attach managed policies")
    # The locked AWS provider renders an absent permissions boundary as null on
    # create and as an empty string after refresh. Configuration validation
    # independently forbids the input; reject every nonempty live ARN here.
    if role.get("permissions_boundary") not in (None, ""):
        raise ContractError(f"{label} publisher may not use a permissions boundary")
    inline_policies = role.get("inline_policy")
    if inline_policies in (None, []):
        if reflected_inline_policy is True:
            raise ContractError(
                f"{label} publisher role must reflect its separately managed inline policy"
            )
    else:
        if reflected_inline_policy is False:
            raise ContractError(
                f"{label} publisher role reflected an inline policy before its separate policy exists"
            )
        if (
            not isinstance(inline_policies, list)
            or len(inline_policies) != 1
            or not isinstance(inline_policies[0], dict)
            or set(inline_policies[0]) != {"name", "policy"}
        ):
            raise ContractError(
                f"{label} publisher role must reflect exactly its separately managed inline policy"
            )
        _require_fields(
            inline_policies[0],
            {"name": inline_policy_name},
            role_address,
        )
        _require_json_field(
            inline_policies[0],
            "policy",
            inline_policy,
            role_address,
        )
    _require_fields(
        policy,
        {"name": inline_policy_name},
        policy_address,
    )
    _require_json_field(
        policy,
        "policy",
        inline_policy,
        policy_address,
    )


def _require_authority_publisher_identity(
    role: dict[str, Any],
    policy: dict[str, Any],
    *,
    reflected_inline_policy: bool | None,
) -> None:
    _require_publisher_identity(
        role,
        policy,
        reflected_inline_policy=reflected_inline_policy,
        role_address="module.control.aws_iam_role.authority_publisher",
        policy_address="module.control.aws_iam_role_policy.authority_publisher",
        role_name=AUTHORITY_PUBLISHER_ROLE_NAME,
        trust_policy=AUTHORITY_PUBLISHER_TRUST_POLICY,
        inline_policy_name="publish-connector-authority",
        inline_policy=AUTHORITY_PUBLISHER_POLICY,
        label="authority",
    )


def _require_hub_publisher_identity(
    role: dict[str, Any],
    policy: dict[str, Any],
    *,
    reflected_inline_policy: bool | None,
) -> None:
    _require_publisher_identity(
        role,
        policy,
        reflected_inline_policy=reflected_inline_policy,
        role_address="module.control.aws_iam_role.hub_publisher",
        policy_address="module.control.aws_iam_role_policy.hub_publisher",
        role_name=HUB_PUBLISHER_ROLE_NAME,
        trust_policy=HUB_PUBLISHER_TRUST_POLICY,
        inline_policy_name="publish-connector-hub",
        inline_policy=HUB_PUBLISHER_POLICY,
        label="Hub",
    )


def _require_authority_runtime_binding(
    values: dict[str, Any], *, proof_enabled: bool | None = None
) -> bool:
    """Require the generated contract to bind one immutable ECR image URI.

    The exact-main generator owns byte/schema validation. This independent plan
    boundary verifies that Terraform received the generator's closed evidence
    shape and that the only deployable image identity is repository@digest.
    """
    payload = values.get("input")
    if not isinstance(payload, dict):
        raise ContractError("foundation contract input must be an object")
    dark_keys = {"account_id", "control_table_prefix", "region"}
    if set(payload) == dark_keys:
        return False
    runtime_keys = {
        *dark_keys,
        "authority_image_uri",
        "authority_runtime_contract",
    }
    staging_keys = {"authority_proof_policy_consumers_staged"}
    rollout_keys = {
        "authority_proof_policy_selected_color",
        "authority_proof_policy_prepared_color",
    }
    extras = set(payload) - runtime_keys
    if extras not in (set(), staging_keys, staging_keys | rollout_keys):
        raise ContractError("foundation runtime input keys are not exact")
    if extras and payload.get("authority_proof_policy_consumers_staged") is not True:
        raise ContractError("foundation proof-policy staging latch is not exact")
    if extras == staging_keys | rollout_keys and (
        payload.get("authority_proof_policy_selected_color") not in {"blue", "green"}
        or payload.get("authority_proof_policy_prepared_color")
        not in {"blue", "green"}
    ):
        raise ContractError("foundation proof-policy rollout colors are not exact")
    contract = payload.get("authority_runtime_contract")
    if not isinstance(contract, dict):
        raise ContractError("foundation runtime contract must be an object")
    global_contract = contract.get("global")
    functions = contract.get("functions")
    catalog = contract.get("provisioned_cells")
    evidence = contract.get("provisioned_cells_evidence")
    function_names = set(functions) if isinstance(functions, dict) else set()
    inferred_proof_enabled = (
        function_names == set(AUTHORITY_RUNTIME_FUNCTIONS_WITH_PROOF)
    )
    if (
        contract.get("schema_version") != 1
        or contract.get("phase") != "measurement"
        or contract.get("selected_authority_color") not in ("blue", "green")
        or not isinstance(global_contract, dict)
        or not isinstance(functions, dict)
        or function_names
        not in (
            set(AUTHORITY_RUNTIME_FUNCTIONS),
            set(AUTHORITY_RUNTIME_FUNCTIONS_WITH_PROOF),
        )
        or not isinstance(catalog, dict)
        or set(catalog) != set(AUTHORITY_CELLS)
    ):
        raise ContractError("foundation runtime contract graph is not exact measurement")
    if proof_enabled is not None and inferred_proof_enabled is not proof_enabled:
        raise ContractError(
            "foundation attended-proof graph does not match the required gate state"
        )
    caller_capacity = global_contract.get("caller_capacity")
    if not isinstance(caller_capacity, dict):
        raise ContractError("foundation runtime caller capacity is malformed")
    expected_proof_capacity = {
        "max_replicas": 1,
        "preinvoke_limits": {
            operation: 1 for operation in AUTHORITY_PROOF_FUNCTIONS.values()
        },
        "preinvoke_rate_limits": {
            operation: {
                "burst": 1,
                "refill_per_second": 1,
            }
            for operation in AUTHORITY_PROOF_FUNCTIONS.values()
        },
    }
    expected_proof_function = {
        "basis_evidence": evidence,
        "max_caller_in_flight": 1,
        "max_caller_requests_per_second": 2,
        "result_evidence": None,
        "rollback_retention_seconds": 3600,
        "rollout_active_provisioned_concurrency": 1,
        "rollout_reserved_concurrency": 2,
        "rollout_standby_provisioned_concurrency": 1,
        "steady_provisioned_concurrency": 1,
        "steady_reserved_concurrency": 1,
    }
    if inferred_proof_enabled:
        if (
            caller_capacity.get("proof_controller") != expected_proof_capacity
            or any(
                functions.get(function_name) != expected_proof_function
                for function_name in AUTHORITY_PROOF_FUNCTIONS
            )
        ):
            raise ContractError(
                "foundation attended-proof caller/function capacity is not exact"
            )
    elif "proof_controller" in caller_capacity:
        raise ContractError(
            "foundation runtime carries proof-controller capacity while the proof "
            "function is absent"
        )
    # The invariant here is that the functions run an immutable digest
    # reference, never a tag. That holds under both image sources, so the
    # digest is read out of the RESOLVED uri rather than assumed to be in the
    # contract -- a publish-tracking contract deliberately names none.
    # A contract applied before this key existed carries no source. It is the
    # pinned shape by definition -- it names a digest and nothing resolves one
    # for it -- so absence means pinned, exactly as the Terraform closed key set
    # treats it. This is what lets the currently-applied state, captured under
    # the old schema, still be validated as the "before" side of a plan. An
    # unrecognized non-empty value is still refused below: absent is legacy,
    # wrong is wrong.
    source = global_contract.get("authority_image_source", "pinned_digest")
    digest = global_contract.get("authority_image_digest")
    repository = global_contract.get("authority_repository_url")
    image_uri = payload.get("authority_image_uri")
    expected_repository = (
        f"{ACCOUNT_ID}.dkr.ecr.{AWS_REGION}.amazonaws.com/"
        "layerv/qurl-connector-authority"
    )
    if (
        repository != expected_repository
        or not isinstance(image_uri, str)
        or not image_uri.startswith(f"{repository}@")
        or _DIGEST_PATTERN.fullmatch(image_uri[len(repository) + 1 :]) is None
    ):
        raise ContractError("foundation runtime image URI is not exact repository@digest")
    resolved_digest = image_uri[len(repository) + 1 :]
    if source == "pinned_digest":
        # A pinned contract must deploy the digest it names; anything else means
        # the resolution path ignored the pin.
        if digest != resolved_digest:
            raise ContractError(
                "foundation runtime image URI does not match the pinned basis digest"
            )
    elif source == "publish_parameter":
        if digest is not None:
            raise ContractError(
                "publish-tracking contract must not also name a basis digest"
            )
    else:
        raise ContractError("foundation runtime image source is not a known value")
    evidence_objects = [
        evidence,
        global_contract.get("basis_evidence"),
        *(function.get("basis_evidence") for function in functions.values()),
    ]
    if (
        any(not isinstance(item, dict) for item in evidence_objects)
        or any(item != evidence_objects[0] for item in evidence_objects[1:])
        or set(evidence_objects[0])
        != {"path", "repository", "schema_version", "sha256", "source_commit"}
        or evidence_objects[0].get("repository") != "layervai/nhp"
        or evidence_objects[0].get("path")
        != "docs/evidence/connector-authority/v1/sandbox-measurement-basis.json"
        or evidence_objects[0].get("schema_version") != 1
        or re.fullmatch(r"[0-9a-f]{40}", str(evidence_objects[0].get("source_commit")))
        is None
        or re.fullmatch(r"[0-9a-f]{64}", str(evidence_objects[0].get("sha256")))
        is None
        or global_contract.get("result_evidence") is not None
        or any(function.get("result_evidence") is not None for function in functions.values())
    ):
        raise ContractError("foundation runtime evidence binding is not exact")
    return True


def _authority_proof_rollout_colors(
    foundation: dict[str, Any],
) -> tuple[str, str] | None:
    payload = foundation.get("input")
    if not isinstance(payload, dict):
        raise ContractError("foundation contract input must be an object")
    selected = payload.get("authority_proof_policy_selected_color")
    prepared = payload.get("authority_proof_policy_prepared_color")
    if selected is None and prepared is None:
        return None
    if (
        payload.get("authority_proof_policy_consumers_staged") is not True
        or selected not in {"blue", "green"}
        or prepared not in {"blue", "green"}
    ):
        raise ContractError("foundation proof-policy rollout binding is malformed")
    contract = payload.get("authority_runtime_contract")
    if (
        not isinstance(contract, dict)
        or contract.get("selected_authority_color") != "blue"
    ):
        raise ContractError("proof-policy rollout must retain the fixed blue basis")
    return selected, prepared


def _authority_proof_selected_colors(
    foundation: dict[str, Any],
) -> dict[str, str]:
    payload = foundation["input"]
    contract_selected = payload["authority_runtime_contract"][
        "selected_authority_color"
    ]
    rollout_colors = _authority_proof_rollout_colors(foundation)
    return {
        AUTHORITY_PROOF_FUNCTION_NAME: (
            rollout_colors[0] if rollout_colors is not None else contract_selected
        ),
        AUTHORITY_PROOF_RECOVERY_FUNCTION_NAME: contract_selected,
    }


def _authority_proof_rollout_transition(
    before: dict[str, Any], after: dict[str, Any]
) -> str | None:
    before_colors = _authority_proof_rollout_colors(before)
    after_colors = _authority_proof_rollout_colors(after)
    if after_colors is None:
        return None
    selected, prepared = after_colors
    if selected != prepared:
        if before_colors is None:
            return "prepare" if (selected, prepared) == ("blue", "green") else None
        before_selected, before_prepared = before_colors
        if (
            before_selected == selected
            and before_prepared != prepared
            and prepared != selected
        ):
            return "prepare"
        return None
    if before_colors is None:
        return None
    before_selected, before_prepared = before_colors
    if (
        before_selected != selected
        and before_prepared == prepared
        and selected == prepared
    ):
        return "selector"
    return None


def _is_exact_authority_proof_rollout_prepare_recovery(
    actual_non_noop: dict[str, list[str]],
    foundation_after: dict[str, Any],
) -> bool:
    """Admit only the observed, bounded retry after a partial prepare apply.

    The foundation already records blue selected / green prepared. The three
    failed consumer pools are tainted replacements, while ca-pm never entered
    state and remains a create. Every function and green alias must move
    together; any other address or action shape fails closed.
    """
    if _authority_proof_rollout_colors(foundation_after) != ("blue", "green"):
        return False
    expected: dict[str, list[str]] = {}
    for function_name in AUTHORITY_PROOF_ROLLOUT_FUNCTIONS:
        expected[
            f'module.control.aws_lambda_function.authority["{function_name}"]'
        ] = ["update"]
        expected[
            f'module.control.aws_lambda_alias.authority["{function_name}:green"]'
        ] = ["update"]
        expected[
            "module.control.aws_lambda_provisioned_concurrency_config."
            f'authority_proof_standby["{function_name}"]'
        ] = (
            ["create"]
            if function_name == AUTHORITY_PROOF_FUNCTION_NAME
            else ["delete", "create"]
        )
    return actual_non_noop == expected


def _check_authority_proof_rollout_prepare_recovery(
    by_address: dict[str, dict[str, Any]],
    *,
    refresh_disabled: bool,
) -> None:
    """Prove every field of the observed partial-prepare recovery.

    Address/action matching alone is insufficient for an update: an alias could
    add weighted routing, or a function could change its role/runtime envelope,
    while retaining the same action class. Bind the three consumer functions
    to exactly the two missing proof-policy variables, ca-pm to exactly its
    prepared-color description marker, all four green aliases to version-only
    movement, and all four standby pools to the observed taint recovery.
    """
    computed_fields = frozenset(
        {"qualified_arn", "qualified_invoke_arn", "version"}
    )
    previous_versions = {
        function_name: ("2" if function_name == AUTHORITY_PROOF_FUNCTION_NAME else "8")
        for function_name in AUTHORITY_PROOF_ROLLOUT_FUNCTIONS
    }

    for function_name in AUTHORITY_PROOF_ROLLOUT_FUNCTIONS:
        function_address = (
            f'module.control.aws_lambda_function.authority["{function_name}"]'
        )
        item = by_address[function_address]
        change = item.get("change")
        before = change.get("before") if isinstance(change, dict) else None
        after = change.get("after") if isinstance(change, dict) else None
        before_sensitive = (
            change.get("before_sensitive") if isinstance(change, dict) else None
        )
        expected_unknown = copy.deepcopy(before_sensitive)
        if isinstance(expected_unknown, dict):
            expected_unknown.update({field: True for field in computed_fields})
        changed_fields = (
            {
                field
                for field in set(before) | set(after)
                if field not in before
                or field not in after
                or not _json_equal(before[field], after[field])
            }
            if isinstance(before, dict) and isinstance(after, dict)
            else set()
        )
        expected_changed_fields = set(computed_fields)
        expected_changed_fields.add(
            "description"
            if function_name == AUTHORITY_PROOF_FUNCTION_NAME
            else "environment"
        )
        expected_identity = _authority_function_identity(function_name)
        if (
            item.get("mode") != "managed"
            or item.get("type") != "aws_lambda_function"
            or item.get("module_address") != "module.control"
            or item.get("name") != "authority"
            or item.get("index") != function_name
            or item.get("deposed") is not None
            or item.get("action_reason") is not None
            or not isinstance(change, dict)
            or set(change)
            != {*_CHANGE_KEYS, "before_identity", "after_identity"}
            or change.get("actions") != ["update"]
            or not isinstance(before, dict)
            or not isinstance(after, dict)
            or change.get("before_identity") != expected_identity
            or change.get("after_identity") != expected_identity
            or before.get("function_name") != function_name
            or after.get("function_name") != function_name
            or before.get("version") != previous_versions[function_name]
            or any(field in after for field in computed_fields)
            or changed_fields != expected_changed_fields
            or change.get("after_unknown") != expected_unknown
            or change.get("after_sensitive") != before_sensitive
            or _has_unknown_value(before_sensitive)
            or after.get("architectures") != ["x86_64"]
            or after.get("memory_size") != 512
            or after.get("timeout") != 10
            or after.get("package_type") != "Image"
            or after.get("publish") is not True
            or after.get("region") != AWS_REGION
            or after.get("role")
            != f"arn:aws:iam::{ACCOUNT_ID}:role/{function_name}-exec"
        ):
            raise ContractError(
                f"{function_address} is not the exact proof-prepare recovery update"
            )

        if function_name == AUTHORITY_PROOF_FUNCTION_NAME:
            if (
                before.get("description")
                != "Connector Authority mutate_proof_agent (sandbox)"
                or after.get("description")
                != (
                    "Connector Authority mutate_proof_agent "
                    "(sandbox; proof-policy-prepared=green)"
                )
                or not _json_equal(before.get("environment"), after.get("environment"))
            ):
                raise ContractError(
                    "ca-pm recovery may change only its prepared-color description"
                )
        else:
            before_environment = before.get("environment")
            after_environment = after.get("environment")
            before_variables = (
                before_environment[0].get("variables")
                if isinstance(before_environment, list)
                and len(before_environment) == 1
                and isinstance(before_environment[0], dict)
                else None
            )
            after_variables = (
                after_environment[0].get("variables")
                if isinstance(after_environment, list)
                and len(after_environment) == 1
                and isinstance(after_environment[0], dict)
                else None
            )
            stripped_after = copy.deepcopy(after_variables)
            if isinstance(stripped_after, dict):
                directive_ttl = stripped_after.pop(
                    "CONNECTOR_AUTHORITY_PROOF_DIRECTIVE_TTL", None
                )
                minimum_lease = stripped_after.pop(
                    "CONNECTOR_AUTHORITY_PROOF_MIN_LEASE_SECONDS", None
                )
            else:
                directive_ttl = None
                minimum_lease = None
            if (
                not isinstance(before_variables, dict)
                or stripped_after != before_variables
                or directive_ttl != "5400"
                or minimum_lease != "30"
                or before.get("description") != after.get("description")
            ):
                raise ContractError(
                    f"{function_name} recovery may add only the exact proof-policy "
                    "TTL and minimum-lease variables"
                )

        alias_address = (
            "module.control.aws_lambda_alias.authority"
            f'["{function_name}:green"]'
        )
        alias_item = by_address[alias_address]
        alias_change = alias_item.get("change")
        alias_before = (
            alias_change.get("before") if isinstance(alias_change, dict) else None
        )
        alias_after = (
            alias_change.get("after") if isinstance(alias_change, dict) else None
        )
        alias_sensitive = (
            alias_change.get("before_sensitive")
            if isinstance(alias_change, dict)
            else None
        )
        alias_expected_unknown = copy.deepcopy(alias_sensitive)
        if isinstance(alias_expected_unknown, dict):
            alias_expected_unknown["function_version"] = True
        alias_changed_fields = (
            {
                field
                for field in set(alias_before) | set(alias_after)
                if field not in alias_before
                or field not in alias_after
                or not _json_equal(alias_before[field], alias_after[field])
            }
            if isinstance(alias_before, dict) and isinstance(alias_after, dict)
            else set()
        )
        if (
            alias_item.get("mode") != "managed"
            or alias_item.get("type") != "aws_lambda_alias"
            or alias_item.get("module_address") != "module.control"
            or alias_item.get("name") != "authority"
            or alias_item.get("index") != f"{function_name}:green"
            or alias_item.get("deposed") is not None
            or alias_item.get("action_reason") is not None
            or not isinstance(alias_change, dict)
            or set(alias_change) != _CHANGE_KEYS
            or alias_change.get("actions") != ["update"]
            or not isinstance(alias_before, dict)
            or not isinstance(alias_after, dict)
            or alias_before.get("function_name") != function_name
            or alias_after.get("function_name") != function_name
            or alias_before.get("name") != "green"
            or alias_after.get("name") != "green"
            or alias_before.get("description")
            != "Closed green deployment qualifier"
            or alias_after.get("description")
            != "Closed green deployment qualifier"
            or alias_before.get("routing_config") != []
            or alias_after.get("routing_config") != []
            or alias_before.get("function_version")
            != previous_versions[function_name]
            or "function_version" in alias_after
            or alias_changed_fields != {"function_version"}
            or alias_change.get("after_unknown") != alias_expected_unknown
            or alias_change.get("after_sensitive") != alias_sensitive
            or _has_unknown_value(alias_sensitive)
        ):
            raise ContractError(
                f"{alias_address} may change only its green function version"
            )

        pool_address = (
            "module.control.aws_lambda_provisioned_concurrency_config."
            f'authority_proof_standby["{function_name}"]'
        )
        pool_item = by_address[pool_address]
        pool_change = pool_item.get("change")
        pool_before = (
            pool_change.get("before") if isinstance(pool_change, dict) else None
        )
        pool_after = (
            pool_change.get("after") if isinstance(pool_change, dict) else None
        )
        expected_pool_after = {
            "function_name": function_name,
            "provisioned_concurrent_executions": (
                1 if function_name == AUTHORITY_PROOF_FUNCTION_NAME else 2
            ),
            "qualifier": "green",
            "region": AWS_REGION,
            "skip_destroy": False,
            "timeouts": None,
        }
        if not isinstance(pool_change, dict):
            pool_exact = False
        elif function_name == AUTHORITY_PROOF_FUNCTION_NAME:
            pool_exact = (
                pool_item.get("action_reason") is None
                and pool_change.get("actions") == ["create"]
                and pool_before is None
                and pool_after == expected_pool_after
                and pool_change.get("after_unknown") == {"id": True}
                and pool_change.get("before_sensitive") is False
                and pool_change.get("after_sensitive") == {}
            )
        else:
            pool_exact = (
                pool_item.get("action_reason") == "replace_because_tainted"
                and pool_change.get("actions") == ["delete", "create"]
                and pool_before
                == {
                    **expected_pool_after,
                    "id": f"{function_name},green",
                    "provisioned_concurrent_executions": (
                        2 if refresh_disabled else 0
                    ),
                }
                and pool_after == expected_pool_after
                and pool_change.get("after_unknown") == {"id": True}
                and pool_change.get("before_sensitive") == {}
                and pool_change.get("after_sensitive") == {}
            )
        if (
            pool_item.get("mode") != "managed"
            or pool_item.get("type")
            != "aws_lambda_provisioned_concurrency_config"
            or pool_item.get("module_address") != "module.control"
            or pool_item.get("name") != "authority_proof_standby"
            or pool_item.get("index") != function_name
            or pool_item.get("deposed") is not None
            or not isinstance(pool_change, dict)
            or set(pool_change) != _CHANGE_KEYS
            or not pool_exact
        ):
            raise ContractError(
                f"{pool_address} is not the exact green standby recovery"
            )


def _selected_authority_color_from_contract(payload: Any) -> str:
    """The blue/green switch pointer, read from a foundation-contract input.

    "blue" only when the CONTRACT ITSELF is absent (rollout-era shapes and
    pre-contract states keep their historical meaning). A contract that is
    present but missing or mis-spelling `selected_authority_color` raises
    instead of degrading: a silent "blue" here would wedge every plan at
    exactly the moment the pointer moves to green -- the scenario this helper
    exists to unblock -- and a schema drift should surface as itself, not as a
    phantom colour disagreement.
    """
    if not isinstance(payload, dict):
        return "blue"
    contract = payload.get("authority_runtime_contract")
    if not isinstance(contract, dict):
        return "blue"
    color = contract.get("selected_authority_color")
    if color not in ("blue", "green"):
        raise ContractError(
            "authority_runtime_contract carries no valid "
            f"selected_authority_color; got {color!r}"
        )
    return color


def _hub_authority_alias_arns(rollout: bool, selected: str = "blue") -> set[str]:
    """The alias ARNs the Hub may invoke.

    During a rollout both colours are reachable. Outside one, exactly the
    SELECTED colour is -- and that is the contract's selected_authority_color,
    not a constant: the selector is the blue/green switch pointer, so pinning
    "blue" here would wedge every plan the moment the pointer moves.
    """
    colors = ("blue", "green") if rollout else (selected,)
    return {
        f"arn:aws:lambda:{AWS_REGION}:{ACCOUNT_ID}:function:{function_name}:{color}"
        for function_name in AUTHORITY_RUNTIME_HUB_FUNCTIONS
        for color in colors
    }


def _is_exact_legacy_hub_runtime_expansion(
    before_values: dict[str, Any],
    after_values: dict[str, Any],
    by_address: dict[str, dict[str, Any]],
) -> bool:
    """Prove the one-time live three-Hub-function -> two-cell expansion.

    The prior sandbox slice is already live. Its contract has exactly the three
    Hub functions and cell0 caller-capacity/catalog metadata, all bound to one of
    the two reviewed predecessor bases
    (AUTHORITY_RUNTIME_LEGACY_HUB_EVIDENCE_CANDIDATES). Build that exact
    predecessor from the fully validated after-contract so every unchanged field
    is compared rather than duplicated here.
    """
    if not _require_authority_runtime_binding(after_values):
        return False
    before_payload = before_values.get("input")
    after_payload = after_values.get("input")
    if not isinstance(before_payload, dict) or not isinstance(after_payload, dict):
        return False

    after_contract = after_payload.get("authority_runtime_contract")
    if not isinstance(after_contract, dict):
        return False
    after_global = after_contract.get("global")
    if not isinstance(after_global, dict):
        return False
    before_contract = before_payload.get("authority_runtime_contract")
    before_global = (
        before_contract.get("global")
        if isinstance(before_contract, dict)
        else None
    )
    before_digest = (
        before_global.get("authority_image_digest")
        if isinstance(before_global, dict)
        else None
    )
    repository = after_global.get("authority_repository_url")
    # This admits ONE historical hub expansion, whose predecessor was captured
    # under the pinned-digest shape. A publish-tracking contract cannot be that
    # predecessor: the reconstruction below injects a basis digest and compares
    # byte-equal, and a publish-tracking payload names none. Refusing here keeps
    # the byte-equality honest instead of silently reshaping it. The sibling
    # already-expanded branch covers the current state, where this expansion has
    # long since applied.
    if _authority_image_tracks_publish(
        after_payload.get("authority_runtime_contract")
    ) or _authority_image_tracks_publish(before_contract):
        return False
    # qurl-service publishes a new immutable exact-main image independently of
    # this one-time infrastructure expansion. If that happens before apply, the
    # live predecessor is still bound to the previous digest while the reviewed
    # after-graph must roll every retained Hub function to the new one. Admit
    # only that exact repository@sha256 pair; every other predecessor field is
    # still reconstructed from and compared with the fully validated after
    # contract below.
    if (
        not isinstance(repository, str)
        or not isinstance(before_digest, str)
        or _DIGEST_PATTERN.fullmatch(before_digest) is None
        or before_payload.get("authority_image_uri")
        != f"{repository}@{before_digest}"
    ):
        return False
    before_image_uri = f"{repository}@{before_digest}"
    for function_name in AUTHORITY_RUNTIME_HUB_FUNCTIONS:
        function = by_address.get(
            f'module.control.aws_lambda_function.authority["{function_name}"]'
        )
        change = function.get("change") if isinstance(function, dict) else None
        function_before = (
            change.get("before") if isinstance(change, dict) else None
        )
        if (
            not isinstance(function_before, dict)
            or function_before.get("image_uri") != before_image_uri
        ):
            return False
    after_caller_capacity = after_global.get("caller_capacity")
    after_cell_workers = (
        after_caller_capacity.get("cell_workers")
        if isinstance(after_caller_capacity, dict)
        else None
    )
    if not isinstance(after_cell_workers, dict) or set(after_cell_workers) != set(
        AUTHORITY_CELLS
    ):
        return False
    # Reconstruct the WHOLE predecessor payload once per reviewed basis and
    # compare it entire. Nothing is matched field-by-field or by pattern: a
    # predecessor is admitted only when it is byte-equal to one of the exactly
    # two enumerated reconstructions, so a third basis -- or the same basis in
    # only some of the four evidence slots -- still fails closed.
    for evidence in AUTHORITY_RUNTIME_LEGACY_HUB_EVIDENCE_CANDIDATES:
        expected_before = json.loads(json.dumps(after_payload))
        contract = expected_before["authority_runtime_contract"]
        global_contract = contract["global"]
        expected_before["authority_image_uri"] = before_image_uri
        global_contract["authority_image_digest"] = before_digest
        global_contract["basis_evidence"] = dict(evidence)
        global_contract["caller_capacity"]["cell_workers"].pop("cell1")
        contract["functions"] = {
            function_name: {
                **contract["functions"][function_name],
                "basis_evidence": dict(evidence),
            }
            for function_name in AUTHORITY_RUNTIME_HUB_FUNCTIONS
        }
        contract["provisioned_cells"].pop("cell1")
        contract["provisioned_cells_evidence"] = dict(evidence)
        if before_payload == expected_before:
            return True
    return False


def _is_exact_legacy_authority_sg_before(before: Any) -> bool:
    """Prove the exact generation-1 Authority function-SG state.

    Shared by the one-time generation-2 replacement and by its deposed
    continuation so the two admissions cannot drift apart: both must carry this
    same predecessor, inline VPC-CIDR egress rule and all.
    """
    if (
        not isinstance(before, dict)
        or before.get("name_prefix") != f"{CONTROL_PREFIX}-ca-fn-"
        or before.get("description")
        != (
            "Connector Authority function ENIs; egress to Control dependency "
            "endpoints only"
        )
        or re.fullmatch(r"vpc-[0-9a-f]+", str(before.get("vpc_id"))) is None
        or before.get("ingress") not in ([], None)
    ):
        return False

    egress = before.get("egress")
    if not isinstance(egress, list) or len(egress) != 2:
        return False
    by_description = {
        rule.get("description"): rule for rule in egress if isinstance(rule, dict)
    }
    if len(by_description) != 2:
        return False
    interface_rule = by_description.get(
        "HTTPS to Control interface endpoints (KMS) in-VPC"
    )
    dynamodb_rule = by_description.get(
        "HTTPS to the DynamoDB gateway endpoint prefix list"
    )
    if interface_rule != {
        "cidr_blocks": [CONTROL_VPC_CIDR],
        "description": "HTTPS to Control interface endpoints (KMS) in-VPC",
        "from_port": 443,
        "ipv6_cidr_blocks": [],
        "prefix_list_ids": [],
        "protocol": "tcp",
        "security_groups": [],
        "self": False,
        "to_port": 443,
    }:
        return False
    if not isinstance(dynamodb_rule, dict):
        return False
    prefix_list_ids = dynamodb_rule.get("prefix_list_ids")
    return (
        set(dynamodb_rule)
        == {
            "cidr_blocks",
            "description",
            "from_port",
            "ipv6_cidr_blocks",
            "prefix_list_ids",
            "protocol",
            "security_groups",
            "self",
            "to_port",
        }
        and dynamodb_rule.get("cidr_blocks") == []
        and dynamodb_rule.get("from_port") == 443
        and dynamodb_rule.get("ipv6_cidr_blocks") == []
        and isinstance(prefix_list_ids, list)
        and len(prefix_list_ids) == 1
        and re.fullmatch(r"pl-[0-9a-f]+", str(prefix_list_ids[0])) is not None
        and dynamodb_rule.get("protocol") == "tcp"
        and dynamodb_rule.get("security_groups") == []
        and dynamodb_rule.get("self") is False
        and dynamodb_rule.get("to_port") == 443
    )


def _is_exact_legacy_authority_sg_replacement(change: dict[str, Any]) -> bool:
    """Prove the one-time removal of the legacy function-SG inline rules.

    Omitting inline rules does not revoke rules already represented in the
    ``aws_security_group`` state. The generation-2 name prefix therefore forces
    an empty replacement group; the exact standalone rules then add only the
    reviewed SG-to-SG, DynamoDB-prefix-list, and Redis paths.
    """
    if change.get("actions") != ["create", "delete"] or change.get("replace_paths") != [
        ["name_prefix"]
    ]:
        return False
    before = change.get("before")
    after = change.get("after")
    unknown = change.get("after_unknown")
    return not (
        not _is_exact_legacy_authority_sg_before(before)
        or not isinstance(after, dict)
        or not isinstance(unknown, dict)
        or after.get("name_prefix") != f"{CONTROL_PREFIX}-ca-fn-v2-"
        or after.get("description") != before.get("description")
        or after.get("vpc_id") != before.get("vpc_id")
        or after.get("ingress") not in ([], None)
        or after.get("egress") not in ([], None)
        or unknown.get("ingress") is not True
        or unknown.get("egress") is not True
    )


def _is_exact_legacy_authority_sg_deposed_delete(item: dict[str, Any]) -> bool:
    """Prove the deposed continuation of the function-SG generation change.

    ``_is_exact_legacy_authority_sg_replacement`` above is create-before-destroy.
    Its create half applied -- the generation-2 group is live and every Authority
    function already points at it -- but the generation-1 delete could not
    complete while published function versions still pinned that group to live
    Lambda ENIs, so Terraform left the predecessor deposed and pending delete.

    Deleting it is therefore the completion of an already-reviewed replacement,
    not a net teardown. This admits ONLY that one captured object: the reviewed
    deposed key, its live group id, and the same generation-1 before-state the
    replacement carries. Deposed objects are not admitted generally -- every
    other one still fails closed in ``_check_hub_source_fence_transition`` or the
    fail-closed fallback.

    Remove once the object is reaped -- when a plan carries no deposed entry at
    all. Five coupled sites go together: the three AUTHORITY_FUNCTION_SG_*
    constants, this function, its ``continue`` hook in ``check_plan``, the jq
    deposed branch in check-connector-authority-foundation.sh, and the fixtures
    in both test suites. KEEP ``_is_exact_legacy_authority_sg_before`` -- the
    generation-2 replacement admission above still uses it.
    """
    change = item.get("change")
    if (
        item.get("address") != AUTHORITY_FUNCTION_SG_ADDRESS
        or item.get("type") != "aws_security_group"
        or item.get("mode") != "managed"
        or item.get("deposed") != AUTHORITY_FUNCTION_SG_DEPOSED_KEY
        or not isinstance(change, dict)
        or change.get("actions") != ["delete"]
        or change.get("after") is not None
    ):
        return False
    before = change.get("before")
    return (
        isinstance(before, dict)
        and before.get("id") == AUTHORITY_FUNCTION_SG_DEPOSED_ID
        and _is_exact_legacy_authority_sg_before(before)
    )


def _is_exact_legacy_hub_source_fence_delete(item: dict[str, Any]) -> bool:
    """Prove the one reviewed delete of the Hub proof-runner source fence.

    Sandbox is open to developers inside and outside the company (qurl-go ADR
    0001), so this exact /32 ingress rule is replaced by an 0.0.0.0/0 rule. The
    only plan that may still name this address is its exact delete.

    This pins the whole before-state -- the reviewed source CIDR, the protocol,
    and both ports -- so a rule that has drifted (a different source, a widened
    port range, or a non-UDP protocol) fails closed and is reviewed rather than
    silently destroyed.

    Remove once the delete is applied and its no-op proof is recorded. Four
    coupled sites go together: the three LEGACY_HUB_SOURCE_FENCE_* constants,
    this function, its hook in ``check_plan``, and the reviewed-destructive
    branch in scripts/check-connector-authority-foundation.sh.
    """
    change = item.get("change")
    if (
        item.get("address") != LEGACY_HUB_SOURCE_FENCE_ADDRESS
        or item.get("type") != LEGACY_HUB_SOURCE_FENCE_TYPE
        or item.get("mode") != "managed"
        or item.get("deposed") is not None
        or not isinstance(change, dict)
        or change.get("actions") != ["delete"]
        or change.get("after") is not None
    ):
        return False
    before = change.get("before")
    if not isinstance(before, dict):
        return False
    return (
        before.get("cidr_ipv4") == LEGACY_HUB_SOURCE_FENCE_CIDR
        and before.get("ip_protocol") == "udp"
        and before.get("from_port") == HUB_CLIENT_EDGE_PORT
        and before.get("to_port") == HUB_CLIENT_EDGE_PORT
    )


def _is_exact_legacy_otp_user_delete(item: dict[str, Any]) -> bool:
    """Prove the one reviewed delete of the detached legacy OTP Redis user.

    The issuer/activator split detached this broad `~connector:*` user from the
    active user group but kept the resource so a destructive cleanup never rode
    along with that reviewed migration. NHP #3362 removes it from source, so the
    only plan that may still name this address is its exact delete.

    This pins the whole before-state -- the reviewed user id, the identical user
    name, the exact legacy ACL, the engine, and IAM-only zero-password identity
    -- so a user that has drifted (a widened ACL, a password-backed identity, or
    a re-attached group membership) fails closed and is reviewed rather than
    silently destroyed. ``check_plan`` separately refuses to combine this delete
    with any other Control change, so it can never ride along with publisher
    bootstrap, split-user creation, or runtime activation.

    Remove once the delete is applied and its no-op proof is recorded. Four
    coupled sites go together: the three LEGACY_OTP_REDIS_USER_* constants, this
    function, its hook in ``check_plan``, and the fixtures in both test suites.
    """
    change = item.get("change")
    if (
        item.get("address") != LEGACY_OTP_REDIS_USER_ADDRESS
        or item.get("type") != LEGACY_OTP_REDIS_USER_TYPE
        or item.get("mode") != "managed"
        or item.get("deposed") is not None
        or not isinstance(change, dict)
        or change.get("actions") != ["delete"]
        or change.get("after") is not None
    ):
        return False
    before = change.get("before")
    if not isinstance(before, dict):
        return False
    return (
        before.get("user_id") == LEGACY_OTP_REDIS_USER_ID
        and before.get("user_name") == LEGACY_OTP_REDIS_USER_ID
        and before.get("access_string") == OTP_REDIS_LEGACY_ACCESS
        and before.get("engine") == "redis"
        and before.get("user_group_ids") in (None, [], set())
        and _is_exact_passwordless_authentication_mode(
            before.get("authentication_mode"), "iam"
        )
    )


# The dark contract input is `{account_id, control_table_prefix, region}` and the
# enabled input adds `authority_image_uri`/`authority_runtime_contract`. To keep
# the dark shape exactly three keys (a no-op against live state) while adding two
# heterogeneously-typed keys, main.tf builds the input with
# `merge(base, jsondecode(jsonencode(enabled ? {...} : "{}")))`. Terraform then
# marks those two jsondecode-derived keys in `after_unknown.input` even though
# `after.input` already holds their exact concrete values. That is a false
# positive: `_require_authority_runtime_binding` verifies `after.input` is the
# exact repository@digest contract, and the enablement is applied from the
# reviewed *saved plan* (`op=apply`), which binds `after.input` deterministically
# without re-reading data sources. Tolerate that exact artifact only.
_FOUNDATION_INPUT_JSONDECODE_KEYS = frozenset(
    {"authority_image_uri", "authority_runtime_contract"}
)


def _require_foundation_input_known(
    after_unknown: dict[str, Any], *, enabled: bool
) -> None:
    """Reject a non-deterministic foundation contract input.

    The dark input is pure data-source/local values and must be fully known. The
    enabled input may carry the jsondecode false-positive described above, but
    only on the two derived keys; the static merge-base keys
    (``account_id``/``control_table_prefix``/``region``) must stay known.
    """
    input_unknown = after_unknown.get("input")
    if input_unknown in (None, {}, False):
        return
    if not enabled or not isinstance(input_unknown, dict):
        raise ContractError("foundation runtime input may not remain unknown")
    stray = sorted(
        key
        for key, marked in input_unknown.items()
        if marked not in (None, {}, False)
        and key not in _FOUNDATION_INPUT_JSONDECODE_KEYS
    )
    if stray:
        raise ContractError(
            f"foundation runtime input has unexpected unknown keys: {stray}"
        )


def _canonical_base64_32(value: Any) -> bytes | None:
    if not isinstance(value, str):
        return None
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        return None
    if (
        len(decoded) != 32
        or base64.b64encode(decoded).decode("ascii") != value
    ):
        return None
    return decoded


def _check_hub_identity_resources(
    by_address: dict[str, dict[str, Any]],
    *,
    refresh_disabled: bool = False,
) -> None:
    """Prove the Hub seeder's complete secret-to-public identity transaction.

    The Hub worker predates public identity publication in sandbox. This
    checker therefore validates both the one-time CREATE_ONLY invocation
    replacement and the converged no-op state. It never renders secret values
    in diagnostics.
    """

    def values(address: str) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
        item = by_address.get(address)
        change = item.get("change") if isinstance(item, dict) else None
        after = change.get("after") if isinstance(change, dict) else None
        unknown = change.get("after_unknown", {}) if isinstance(change, dict) else None
        if (
            not isinstance(change, dict)
            or not isinstance(after, dict)
            or not isinstance(unknown, dict)
        ):
            raise ContractError(f"{address} planned values are malformed")
        return after, unknown, change

    secret_address = "module.control.aws_secretsmanager_secret.hub_key_material[0]"
    secret, secret_unknown, _ = values(secret_address)
    authority_key, _, _ = values("module.control.aws_kms_key.authority_data")
    authority_key_arn = authority_key.get("arn")
    secret_arn = secret.get("arn")
    if (
        not isinstance(authority_key_arn, str)
        or not isinstance(secret_arn, str)
        or HUB_KEY_MATERIAL_SECRET_ARN_RE.fullmatch(secret_arn) is None
    ):
        raise ContractError("Hub identity KMS/secret identity is not exact")
    _require_fields(
        secret,
        {
            "description": (
                "Connector Hub private key and cookie keys; seeded once by the "
                "keygen Lambda, never via Terraform state"
            ),
            "kms_key_id": authority_key_arn,
            "name": HUB_KEY_MATERIAL_SECRET_NAME,
            "policy": "",
            "recovery_window_in_days": 7,
            "region": AWS_REGION,
        },
        secret_address,
    )
    if any(
        secret_unknown.get(field) not in (None, False, {}, [])
        for field in ("arn", "kms_key_id", "name", "policy")
    ):
        raise ContractError("Hub identity secret has unknown security fields")

    kms_condition = {
        "StringEquals": {
            "kms:EncryptionContext:SecretARN": secret_arn,
            "kms:ViaService": HUB_SECRETSMANAGER_KMS_VIA_SERVICE,
        }
    }
    keygen_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Action": [
                    "secretsmanager:DescribeSecret",
                    "secretsmanager:GetSecretValue",
                    "secretsmanager:PutSecretValue",
                ],
                "Effect": "Allow",
                "Resource": secret_arn,
                "Sid": "SeedHubKeyMaterial",
            },
            {
                "Action": ["ssm:GetParameter", "ssm:PutParameter"],
                "Effect": "Allow",
                "Resource": HUB_PUBLIC_KEY_PARAMETER_ARN,
                "Sid": "PublishHubPublicIdentity",
            },
            {
                "Action": ["kms:GenerateDataKey", "kms:Decrypt"],
                "Condition": kms_condition,
                "Effect": "Allow",
                "Resource": authority_key_arn,
                "Sid": "WrapHubKeyMaterial",
            },
            {
                "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
                "Effect": "Allow",
                "Resource": HUB_KEYGEN_LOG_GROUP_ARN,
                "Sid": "OwnLogStream",
            },
        ],
    }
    execution_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Action": "secretsmanager:GetSecretValue",
                "Effect": "Allow",
                "Resource": secret_arn,
                "Sid": "ReadHubKeyMaterial",
            },
            {
                "Action": "kms:Decrypt",
                "Condition": kms_condition,
                "Effect": "Allow",
                "Resource": authority_key_arn,
                "Sid": "DecryptHubKeyMaterial",
            },
        ],
    }
    keygen_policy_address = "module.control.aws_iam_role_policy.hub_keygen[0]"
    keygen_policy_after, keygen_policy_unknown, _ = values(keygen_policy_address)
    _require_fields(
        keygen_policy_after,
        {"name": "hub-keygen", "role": f"{CONTROL_PREFIX}-hub-keygen"},
        keygen_policy_address,
    )
    _require_json_field(
        keygen_policy_after,
        "policy",
        keygen_policy,
        keygen_policy_address,
    )
    execution_policy_address = (
        "module.control.aws_iam_role_policy.hub_execution[0]"
    )
    execution_policy_after, execution_policy_unknown, _ = values(
        execution_policy_address
    )
    _require_fields(
        execution_policy_after,
        {"name": "hub-execution", "role": f"{CONTROL_PREFIX}-hub-exec"},
        execution_policy_address,
    )
    _require_json_field(
        execution_policy_after,
        "policy",
        execution_policy,
        execution_policy_address,
    )
    if keygen_policy_unknown or execution_policy_unknown:
        raise ContractError("Hub identity IAM policies must be fully known")

    role_address = "module.control.aws_iam_role.hub_keygen[0]"
    role, role_unknown, _ = values(role_address)
    _require_fields(
        role,
        {
            "arn": HUB_KEYGEN_ROLE_ARN,
            "max_session_duration": 3600,
            "name": f"{CONTROL_PREFIX}-hub-keygen",
            "path": "/",
        },
        role_address,
    )
    _require_json_field(
        role,
        "assume_role_policy",
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Action": "sts:AssumeRole",
                    "Effect": "Allow",
                    "Principal": {"Service": "lambda.amazonaws.com"},
                    "Sid": "LambdaAssume",
                }
            ],
        },
        role_address,
    )
    if (
        role.get("managed_policy_arns") not in (None, [])
        or role.get("permissions_boundary") not in (None, "")
        or role_unknown
    ):
        raise ContractError("Hub keygen role boundary is not least privilege")

    public_address = "module.control.aws_ssm_parameter.hub_public_key[0]"
    public, _, public_change = values(public_address)
    _require_fields(
        public,
        {
            "description": (
                "Connector Hub X25519 public identity; private key remains in "
                "Secrets Manager"
            ),
            "name": HUB_PUBLIC_KEY_PARAMETER_NAME,
            "region": AWS_REGION,
            "type": "String",
            "value_wo": None,
            "value_wo_version": None,
        },
        public_address,
    )
    public_value = public.get("value")

    lambda_address = "module.control.aws_lambda_function.hub_keygen[0]"
    keygen_lambda, lambda_unknown, _ = values(lambda_address)
    source_hash = keygen_lambda.get("source_code_hash")
    if _canonical_base64_32(source_hash) is None:
        raise ContractError("Hub keygen source hash is not canonical SHA-256")
    _require_fields(
        keygen_lambda,
        {
            "description": (
                "Seeds or repairs the Connector Hub identity and publishes its "
                "public key at worker create (sandbox)"
            ),
            "environment": [
                {
                    "variables": {
                        "ENVIRONMENT": "sandbox",
                        "PUBLIC_KEY_PARAMETER": HUB_PUBLIC_KEY_PARAMETER_NAME,
                        "SECRET_ID": secret_arn,
                    }
                }
            ],
            "filename": (
                "../../../modules/connector-authority-foundation/lambda/"
                "hub-keygen.zip"
            ),
            "function_name": HUB_KEYGEN_FUNCTION_NAME,
            "handler": "keygen.handler",
            "package_type": "Zip",
            "reserved_concurrent_executions": 1,
            "role": HUB_KEYGEN_ROLE_ARN,
            "runtime": "nodejs22.x",
            "timeout": 30,
            "vpc_config": [],
        },
        lambda_address,
    )
    if lambda_unknown.get("environment") not in (
        None,
        [],
        [{"variables": {}}],
    ) or lambda_unknown.get("vpc_config") not in (None, []):
        raise ContractError("Hub keygen network/environment is not fully known")
    for field in (
        "filename",
        "function_name",
        "handler",
        "package_type",
        "reserved_concurrent_executions",
        "role",
        "runtime",
        "source_code_hash",
        "timeout",
    ):
        if lambda_unknown.get(field) not in (None, False, {}, []):
            raise ContractError(f"Hub keygen has unknown security field: {field}")

    invocation_address = (
        "module.control.aws_lambda_invocation.hub_identity_publication[0]"
    )
    invocation, invocation_unknown, invocation_change = values(invocation_address)
    expected_invocation = {
        "function_name": HUB_KEYGEN_FUNCTION_NAME,
        "input": "{}",
        "lifecycle_scope": "CREATE_ONLY",
        "qualifier": "$LATEST",
        "region": AWS_REGION,
        "tenant_id": None,
        "terraform_key": "tf",
        "triggers": None,
    }
    _require_fields(invocation, expected_invocation, invocation_address)
    invocation_actions = invocation_change.get("actions")
    public_actions = public_change.get("actions")
    public_bytes = _canonical_base64_32(public_value)
    if invocation_actions == ["create"]:
        create_shape_is_exact = (
            invocation_change.get("before") is None
            and invocation_change.get("replace_paths") in (None, [])
        )
        if (
            not create_shape_is_exact
            or invocation_unknown
            not in (
                {"id": True, "result": True},
                {"id": True, "result": True, "triggers": True},
            )
            or public_value != "pending-keygen"
            and (public_bytes is None or not any(public_bytes))
        ):
            raise ContractError("Hub identity publication create is not exact")
    elif invocation_actions == ["no-op"]:
        if invocation_unknown or invocation_change.get("replace_paths") not in (
            None,
            [],
        ):
            raise ContractError("Hub identity invocation no-op is not exact")
        result = invocation.get("result")
        try:
            decoded_result = json.loads(result) if isinstance(result, str) else None
        except json.JSONDecodeError as exc:
            raise ContractError("Hub identity invocation result is malformed") from exc
        publication_is_settled = bool(public_bytes) and any(public_bytes)
        # The placeholder must NEVER pass as converged on a refreshed plan --
        # there it genuinely means the seeder did not publish, which is the
        # invariant test_placeholder_cannot_be_a_converged_noop pins.
        #
        # On the refresh-DISABLED lane it means something else entirely. The
        # parameter carries `ignore_changes = [value]`, Terraform created it
        # holding the sentinel, and the KEYGEN LAMBDA replaced the live value
        # out of band, so stored state still reads `pending-keygen` no matter
        # what AWS holds. Demanding a canonical key there became unsatisfiable
        # the moment the identity was actually published.
        #
        # Admit the sentinel ONLY on that lane, and only alongside a seeded
        # invocation result. Every other value -- non-canonical, all-zero --
        # still fails closed on both lanes, and the live key is independently
        # proved by check_live and by the manifest producer, which rejects the
        # sentinel outright.
        publication_is_unrefreshed = refresh_disabled and public_value == "pending-keygen"
        if decoded_result != {"seeded": True} or not (
            publication_is_settled or publication_is_unrefreshed
        ):
            raise ContractError("Hub identity steady publication is not proven")
    else:
        raise ContractError("Hub identity invocation action is not admitted")
    if public_actions == ["create"] and invocation_actions != ["create"]:
        raise ContractError(
            "Hub public identity creation requires a keygen invocation"
        )


def _check_planned_security(
    by_address: dict[str, dict[str, Any]],
    *,
    catalog_mode: bool = False,
    runtime_mode: bool = False,
    proof_mode: bool = False,
    proof_rollout_mode: bool = False,
    hub_worker_mode: bool = False,
    refresh_disabled: bool = False,
) -> None:
    def values(address: str) -> tuple[dict[str, Any], dict[str, Any]]:
        change = by_address[address].get("change", {})
        after = change.get("after")
        unknown = change.get("after_unknown", {})
        if not isinstance(after, dict) or not isinstance(unknown, dict):
            raise ContractError(f"{address} planned values are malformed")
        return after, unknown

    vpc, _ = values("module.control.aws_vpc.control")
    foundation, foundation_unknown = values(
        "module.control.terraform_data.foundation_contract"
    )
    enabled = _require_authority_runtime_binding(
        foundation, proof_enabled=proof_mode if runtime_mode else None
    )
    _require_foundation_input_known(foundation_unknown, enabled=enabled)
    if catalog_mode:
        for address in PROVISIONED_CELL_RESOURCES:
            item, item_unknown = values(address)
            change = by_address[address]["change"]
            create = change.get("actions") == ["create"]
            _require_provisioned_cell_values(
                item,
                item_unknown,
                address,
                create=create,
            )
            if create and (
                change.get("before_sensitive") is not False
                or change.get("after_sensitive") != {}
                or change.get("after_identity")
                != {
                    "account_id": None,
                    "hash_key_value": None,
                    "range_key_value": None,
                    "region": None,
                    "table_name": None,
                }
            ):
                raise ContractError(
                    f"{address} create metadata envelope is not exact"
                )
    # Keep the complete provider-version-specific no-op shape visible here as
    # literals rather than deriving its dimensions independently. The empty-
    # string / zero IPv6 values below are the exact no-op shape emitted by the
    # locked AWS provider version (see the authentication-mode note below
    # before changing them).
    _require_fields(
        vpc,
        {
            "cidr_block": "10.102.0.0/16",
            "enable_dns_hostnames": True,
            "enable_dns_support": True,
            "instance_tenancy": "default",
            "ipv4_ipam_pool_id": None,
            "ipv4_netmask_length": None,
            "ipv6_ipam_pool_id": "",
            "ipv6_netmask_length": 0,
            "region": AWS_REGION,
        },
        "module.control.aws_vpc.control",
    )
    if vpc.get("assign_generated_ipv6_cidr_block") not in (None, False):
        raise ContractError(
            "module.control.aws_vpc.control must not request generated IPv6"
        )

    for address in (
        "module.control.aws_default_security_group.control",
        "module.control.aws_security_group.interface_endpoints",
        "module.control.aws_security_group.otp_redis",
    ):
        after, unknown = values(address)
        # The interface-endpoint SG gains exactly one TLS/443 SG-scoped ingress
        # in the runtime slice, and the OTP Redis SG gains exactly one TLS/6379
        # SG-scoped ingress from the function SG. The default SG stays closed.
        # Egress stays empty on all three.
        if (
            runtime_mode or hub_worker_mode
        ) and address == AUTHORITY_RUNTIME_INTERFACE_SG_ADDRESS:
            _require_fields(after, {"egress": []}, address)
            if unknown.get("egress", []) != []:
                raise ContractError(f"{address} has unknown planned egress rules")
            _check_authority_interface_endpoint_ingress(
                after, unknown, address, hub_worker_mode=hub_worker_mode
            )
            continue
        if (runtime_mode or hub_worker_mode) and address == (
            "module.control.aws_security_group.otp_redis"
        ):
            _require_fields(after, {"egress": []}, address)
            if unknown.get("egress", []) != []:
                raise ContractError(f"{address} has unknown planned egress rules")
            _check_otp_redis_ingress(after, unknown, address)
            continue
        _require_fields(after, {"ingress": [], "egress": []}, address)
        if unknown.get("ingress", []) != [] or unknown.get("egress", []) != []:
            raise ContractError(f"{address} has unknown planned traffic rules")

    # The public Hub edge is source-fenced at the NLB. Its SG has no inline
    # rules, its sole public rule is the open sandbox edge on the
    # public client edge UDP 443, and the NLB attaches exactly one SG in the
    # create request.
    hub_edge_mode = "module.control.aws_security_group.hub_nlb[0]" in by_address
    if hub_edge_mode:
        nlb_sg, nlb_sg_unknown = values(
            "module.control.aws_security_group.hub_nlb[0]"
        )
        for field in ("ingress", "egress"):
            planned_rules = nlb_sg.get(field)
            unknown_rules = nlb_sg_unknown.get(field)
            # A new standalone-rule-only SG has no concrete inline collection
            # until AWS allocates it (after omits the field, after_unknown=true).
            # A steady SG projects the same authored absence as an explicit
            # empty collection. Any concrete rule or other unknown shape fails.
            #
            # KNOWN LATENT DEFECT: that second sentence is false. ingress/egress
            # are Optional+Computed, so once hub_nlb_udp and the egress rules
            # apply, a REFRESHED plan projects them as concrete entries and this
            # rejects them -- the same class as the Authority function SG (#3495)
            # and OTP Redis (#3496). It has not fired only because
            # module.control.aws_security_group.hub_nlb[0] is absent from Control
            # state, and hub_edge_mode gates this whole block on its presence.
            # Left strict deliberately: unlike those two, this SG has no exact
            # configuration-expression contract to carry the state-independent
            # "declares no inline block" guarantee, so relaxing the planned-value
            # assertion here would remove the only check without replacing it.
            # Fix alongside the hub-edge SG slice, giving it that contract first.
            # `ingress`/`egress` are Optional+Computed. Before the edge slice
            # applies the SG does not exist, so both are absent/unknown; AFTER it
            # applies the provider projects the standalone rules AWS actually
            # holds (hub_nlb_udp ingress plus the udp/health egress pair). This
            # check previously demanded the pre-apply shape and so rejected every
            # plan and verify once the slice landed -- the LATENT defect recorded
            # in #3497, now fired by the applied Hub edge.
            #
            # Admit the settled projection; reject only a shape that is neither
            # the create-time projection nor a rule collection. The rules'
            # CONTENTS stay pinned by their own exact resource checks
            # (aws_vpc_security_group_ingress_rule.hub_nlb_udp is the open edge
            # /32 UDP 443; the egress pair is worker UDP 62206 + TCP 62207),
            # and check_live re-proves the live SG posture independently.
            if planned_rules is None and unknown_rules is not True:
                raise ContractError(
                    f"Hub NLB SG {field} must be exactly create-time unknown"
                )
            if planned_rules is not None and not isinstance(planned_rules, list):
                raise ContractError(
                    f"Hub NLB SG must not declare inline {field} rules"
                )

        nlb_ingress, _ = values(
            'module.control.aws_vpc_security_group_ingress_rule.hub_nlb_udp["0.0.0.0/0"]'
        )
        _require_fields(
            nlb_ingress,
            {
                "cidr_ipv4": HUB_PUBLIC_UDP_INGRESS_CIDR,
                "from_port": 443,
                "ip_protocol": "udp",
                "to_port": 443,
            },
            "Hub NLB public ingress",
        )
        if nlb_ingress.get("cidr_ipv6") not in (None, ""):
            raise ContractError("Hub NLB public ingress must not admit IPv6")

        hub_lb, hub_lb_unknown = values("module.control.aws_lb.hub[0]")
        _require_fields(
            hub_lb,
            {
                "internal": False,
                "load_balancer_type": "network",
                "name": HUB_EDGE_LOAD_BALANCER_NAME,
            },
            "module.control.aws_lb.hub[0]",
        )
        lb_groups = hub_lb.get("security_groups")
        if not (
            (isinstance(lb_groups, list) and len(lb_groups) == 1)
            or (
                lb_groups in (None, [])
                and bool(hub_lb_unknown.get("security_groups"))
            )
        ):
            raise ContractError(
                "Hub NLB must attach exactly one security group at creation"
            )

    # Worker targets trust only the Hub NLB SG on the data and health ports.
    # NLB egress is the exact inverse SG-scoped pair; CIDR egress is forbidden.
    if hub_worker_mode:
        worker_sg, worker_unknown = values(
            "module.control.aws_security_group.hub_worker[0]"
        )
        worker_ingress = worker_sg.get("ingress")
        if not isinstance(worker_ingress, list) or len(worker_ingress) != 2:
            raise ContractError(
                "Hub worker SG must have exactly two NLB-SG ingress rules"
            )
        expected_worker_ports = {("udp", 62206), ("tcp", 62207)}
        actual_worker_ports: set[tuple[str, int]] = set()
        for rule in worker_ingress:
            if not isinstance(rule, dict):
                raise ContractError("Hub worker SG ingress is malformed")
            protocol = rule.get("protocol")
            from_port = rule.get("from_port")
            if (
                from_port != rule.get("to_port")
                or (protocol, from_port) not in expected_worker_ports
                or rule.get("cidr_blocks") not in (None, [])
                or rule.get("ipv6_cidr_blocks") not in (None, [])
                or rule.get("prefix_list_ids") not in (None, [])
                or rule.get("self") not in (None, False)
            ):
                raise ContractError(
                    "Hub worker SG ingress must be only NLB-SG UDP 62206 and TCP 62207"
                )
            groups = rule.get("security_groups")
            if not (
                (isinstance(groups, list) and len(groups) == 1)
                or (
                    groups in (None, [])
                    and bool(worker_unknown.get("ingress"))
                )
            ):
                raise ContractError(
                    "Hub worker SG ingress must reference exactly the Hub NLB SG"
                )
            actual_worker_ports.add((str(protocol), int(from_port)))
        if actual_worker_ports != expected_worker_ports:
            raise ContractError(
                "Hub worker SG ingress ports do not match the exact NLB contract"
            )

        for address, protocol, port in (
            (
                "module.control.aws_vpc_security_group_egress_rule.hub_nlb_udp[0]",
                "udp",
                62206,
            ),
            (
                "module.control.aws_vpc_security_group_egress_rule.hub_nlb_health[0]",
                "tcp",
                62207,
            ),
        ):
            after, unknown = values(address)
            _require_fields(
                after,
                {
                    "from_port": port,
                    "ip_protocol": protocol,
                    "to_port": port,
                },
                address,
            )
            if after.get("cidr_ipv4") not in (None, "") or after.get(
                "cidr_ipv6"
            ) not in (None, ""):
                raise ContractError(f"{address} must be SG-scoped, never CIDR-scoped")
            if after.get("referenced_security_group_id") in (None, "") and not (
                unknown.get("referenced_security_group_id")
            ):
                raise ContractError(
                    f"{address} must reference exactly the Hub worker SG"
                )

    for index, availability_zone in enumerate(
        ("us-east-2a", "us-east-2b", "us-east-2c")
    ):
        address = f"module.control.aws_subnet.isolated[{index}]"
        after, _ = values(address)
        _require_fields(
            after,
            {
                "assign_ipv6_address_on_creation": False,
                "availability_zone": availability_zone,
                "cidr_block": f"10.102.{index}.0/24",
                "enable_dns64": False,
                "ipv4_ipam_pool_id": None,
                "ipv4_netmask_length": None,
                "ipv6_ipam_pool_id": None,
                "ipv6_native": False,
                "ipv6_netmask_length": None,
                "map_public_ip_on_launch": False,
                "region": AWS_REGION,
            },
            address,
        )

    kms_contracts = {
        "module.control.aws_kms_key.authority_data": (
            {
                "bypass_policy_lockout_safety_check": False,
                "customer_master_key_spec": "SYMMETRIC_DEFAULT",
                "deletion_window_in_days": 7,
                "enable_key_rotation": True,
                "is_enabled": True,
                "key_usage": "ENCRYPT_DECRYPT",
                "region": AWS_REGION,
            },
            AUTHORITY_DATA_KMS_POLICY,
        ),
        "module.control.aws_kms_key.qat1_signing": (
            {
                "bypass_policy_lockout_safety_check": False,
                "customer_master_key_spec": "ECC_NIST_P256",
                "deletion_window_in_days": 7,
                "enable_key_rotation": False,
                "is_enabled": True,
                "key_usage": "SIGN_VERIFY",
                "region": AWS_REGION,
            },
            QAT1_SIGNING_KMS_POLICY,
        ),
    }
    for address, (expected, policy) in kms_contracts.items():
        after, _ = values(address)
        _require_fields(after, expected, address)
        _require_json_field(after, "policy", policy, address)

    endpoint_contracts = {"dynamodb": "Gateway"}
    endpoint_contracts.update(
        {service: "Interface" for service in INTERFACE_ENDPOINT_SERVICES}
    )
    for service, endpoint_type in endpoint_contracts.items():
        address = (
            "module.control.aws_vpc_endpoint.dynamodb"
            if service == "dynamodb"
            else f'module.control.aws_vpc_endpoint.interface["{service}"]'
        )
        after, _ = values(address)
        expected = {
            "region": AWS_REGION,
            "service_name": f"com.amazonaws.{AWS_REGION}.{service}",
            "vpc_endpoint_type": endpoint_type,
        }
        if endpoint_type == "Interface":
            expected["private_dns_enabled"] = True
        _require_fields(after, expected, address)
        # In the runtime slice DynamoDB, KMS, Secrets Manager, and SES carry
        # operation-scoped Allows; the Hub worker slice additionally opens the
        # lambda interface endpoint to the worker task role. Every other
        # endpoint (logs, monitoring, and lambda while the worker is dark) stays
        # deny-all
        # and fails closed here otherwise.
        if runtime_mode and address == AUTHORITY_RUNTIME_DYNAMODB_ADDRESS:
            _check_authority_dynamodb_endpoint_policy(
                after, address, proof_enabled=proof_mode
            )
        elif runtime_mode and address == AUTHORITY_RUNTIME_KMS_ENDPOINT_ADDRESS:
            _check_authority_kms_endpoint_policy(after, address)
        elif runtime_mode and address == AUTHORITY_RUNTIME_SECRETS_ENDPOINT_ADDRESS:
            _check_authority_secrets_endpoint_policy(
                after, address, hub_worker_mode=hub_worker_mode
            )
        elif runtime_mode and address == AUTHORITY_RUNTIME_EMAIL_ENDPOINT_ADDRESS:
            _check_authority_email_endpoint_policy(after, address)
        elif hub_worker_mode and address == HUB_WORKER_LAMBDA_ENDPOINT_ADDRESS:
            # While the rollout window is CLOSING, the standby pools still
            # exist pre-apply so proof_rollout_mode is true -- but the policy
            # correctly narrows back to the selected colour alone. Judge it on
            # the window's after-state, not on inventory that is being deleted
            # in this very plan.
            _contract_after = (
                by_address.get(AUTHORITY_IMAGE_UPDATE_FOUNDATION_ADDRESS, {})
                .get("change", {})
                .get("after")
            )
            _contract_payload = (
                _contract_after.get("input")
                if isinstance(_contract_after, dict)
                else None
            )
            _check_hub_lambda_endpoint_policy(
                after,
                address,
                rollout=(
                    proof_rollout_mode
                    and not _authority_proof_window_closes_to_null(by_address)
                ),
                selected=_selected_authority_color_from_contract(_contract_payload),
            )
        elif (
            hub_worker_mode
            and not runtime_mode
            and address == HUB_WORKER_SECRETSMANAGER_ENDPOINT_ADDRESS
        ):
            _check_hub_secretsmanager_endpoint_policy(after, address)
        elif hub_worker_mode and address == HUB_WORKER_LOGS_ENDPOINT_ADDRESS:
            _check_hub_logs_endpoint_policy(after, address)
        elif hub_worker_mode and address == HUB_WORKER_MONITORING_ENDPOINT_ADDRESS:
            _check_hub_monitoring_endpoint_policy(after, address)
        else:
            _require_json_field(after, "policy", DENY_ENDPOINT_POLICY, address)

    # The Hub worker slice adds three image-pull endpoints that are NOT part of
    # the base interface_endpoint_services for_each: the ecr.api + ecr.dkr
    # interface endpoints and the S3 gateway endpoint, each opened ONLY to the Hub
    # execution role for the exact pull actions. While the worker is dark these
    # resources do not exist (the inventory admission gates that); when live their
    # policies are validated here exactly like the runtime dependency endpoints.
    if hub_worker_mode:
        _check_hub_identity_resources(by_address, refresh_disabled=refresh_disabled)
        for address, service, endpoint_type in (
            ("module.control.aws_vpc_endpoint.hub_ecr_api[0]", "ecr.api", "Interface"),
            ("module.control.aws_vpc_endpoint.hub_ecr_dkr[0]", "ecr.dkr", "Interface"),
            ("module.control.aws_vpc_endpoint.hub_s3[0]", "s3", "Gateway"),
        ):
            after, _ = values(address)
            expected = {
                "region": AWS_REGION,
                "service_name": f"com.amazonaws.{AWS_REGION}.{service}",
                "vpc_endpoint_type": endpoint_type,
            }
            if endpoint_type == "Interface":
                expected["private_dns_enabled"] = True
            _require_fields(after, expected, address)
            if service == "s3":
                _check_hub_s3_endpoint_policy(after, address)
            else:
                _check_hub_ecr_endpoint_policy(after, address)

    redis_contracts = {
        "module.control.aws_elasticache_user.otp_activator": {
            "access_string": OTP_REDIS_ACTIVATOR_ACCESS,
            "engine": "redis",
            "region": AWS_REGION,
            "user_id": f"{CONTROL_PREFIX}-otp-activator",
            "user_name": f"{CONTROL_PREFIX}-otp-activator",
        },
        "module.control.aws_elasticache_user.otp_disabled_default": {
            "access_string": "off ~* -@all",
            "engine": "redis",
            "region": AWS_REGION,
            "user_id": f"{CONTROL_PREFIX}-otp-default",
            "user_name": "default",
        },
        "module.control.aws_elasticache_user.otp_issuer": {
            "access_string": OTP_REDIS_ISSUER_ACCESS,
            "engine": "redis",
            "region": AWS_REGION,
            "user_id": f"{CONTROL_PREFIX}-otp-issuer",
            "user_name": f"{CONTROL_PREFIX}-otp-issuer",
        },
        "module.control.aws_elasticache_user_group.otp": {
            "engine": "redis",
            "region": AWS_REGION,
            "user_group_id": f"{CONTROL_PREFIX}-otp-users",
        },
        "module.control.aws_elasticache_serverless_cache.otp": {
            "engine": "redis",
            "major_engine_version": "7",
            "name": f"{CONTROL_PREFIX}-otp",
            "region": AWS_REGION,
            "snapshot_arns_to_restore": None,
            "snapshot_retention_limit": 0,
            "user_group_id": f"{CONTROL_PREFIX}-otp-users",
        },
    }
    for address, expected in redis_contracts.items():
        after, _ = values(address)
        _require_fields(after, expected, address)

    # These shapes are exact for the locked AWS provider version; any provider
    # upgrade must regenerate and re-review the plan fixtures before changing
    # this split (including the analogous IPv6 null/empty shapes).
    for address, auth_type in (
        ("module.control.aws_elasticache_user.otp_activator", "iam"),
        (
            "module.control.aws_elasticache_user.otp_disabled_default",
            "no-password",
        ),
        ("module.control.aws_elasticache_user.otp_issuer", "iam"),
    ):
        after, unknown = values(address)
        auth = after.get("authentication_mode")
        change = by_address[address]["change"]
        if change.get("actions") == ["create"]:
            after_sensitive = change.get("after_sensitive")
            if (
                address not in REDIS_SPLIT_USER_RESOURCES
                or auth != _REDIS_IAM_CREATE_AUTHENTICATION_MODE
                or unknown.get("authentication_mode")
                != _REDIS_IAM_CREATE_AUTHENTICATION_MODE_UNKNOWN
                or not isinstance(after_sensitive, dict)
                or after_sensitive.get("authentication_mode")
                != _REDIS_IAM_CREATE_AUTHENTICATION_MODE_SENSITIVE
            ):
                raise ContractError(
                    f"{address} IAM create authentication mode is not the exact "
                    "fail-closed provider shape"
                )
            continue
        if (
            not _is_exact_passwordless_authentication_mode(auth, auth_type)
            or "authentication_mode" in unknown
        ):
            raise ContractError(f"{address} authentication mode is not fail closed")

    group, group_unknown = values("module.control.aws_elasticache_user_group.otp")
    expected_users = {
        f"{CONTROL_PREFIX}-otp-activator",
        f"{CONTROL_PREFIX}-otp-default",
        f"{CONTROL_PREFIX}-otp-issuer",
    }
    users = group.get("user_ids")
    if (
        not isinstance(users, list)
        or len(users) != 3
        or set(users) != expected_users
        or "user_ids" in group_unknown
    ):
        raise ContractError("planned OTP Redis user-group membership drifted")

    cache, _ = values("module.control.aws_elasticache_serverless_cache.otp")
    usage = cache.get("cache_usage_limits")
    if not isinstance(usage, list) or len(usage) != 1 or not isinstance(usage[0], dict):
        raise ContractError("planned OTP Redis usage limits are malformed")
    data_storage = usage[0].get("data_storage")
    ecpu = usage[0].get("ecpu_per_second")
    if (
        not isinstance(data_storage, list)
        or len(data_storage) != 1
        or not isinstance(data_storage[0], dict)
        or data_storage[0].get("maximum") != 1
        or data_storage[0].get("unit") != "GB"
        or not isinstance(ecpu, list)
        or len(ecpu) != 1
        or not isinstance(ecpu[0], dict)
        or ecpu[0].get("maximum") != 1000
    ):
        raise ContractError("planned OTP Redis usage limits drifted")

    authority_data_key, _ = values("module.control.aws_kms_key.authority_data")
    authority_data_key_arn = authority_data_key.get("arn")
    if not isinstance(authority_data_key_arn, str):
        raise ContractError("authority data KMS ARN is absent from the plan")

    hub_repository_address = "module.control.aws_ecr_repository.hub"
    hub_repository, _ = values(hub_repository_address)
    _require_fields(
        hub_repository,
        {
            "encryption_configuration": [
                {
                    "encryption_type": "KMS",
                    "kms_key": authority_data_key_arn,
                }
            ],
            "force_delete": False,
            "image_scanning_configuration": [{"scan_on_push": True}],
            "image_tag_mutability": "IMMUTABLE",
            "name": HUB_ECR_REPOSITORY_NAME,
            "region": AWS_REGION,
        },
        hub_repository_address,
    )
    hub_lifecycle_address = "module.control.aws_ecr_lifecycle_policy.hub"
    hub_lifecycle, _ = values(hub_lifecycle_address)
    _require_json_field(
        hub_lifecycle,
        "policy",
        HUB_ECR_LIFECYCLE_POLICY,
        hub_lifecycle_address,
    )
    # The repository is a reference in configuration, but its configured name
    # is known before apply. The locked provider therefore emits the exact name
    # even when both resources are being created.
    if hub_lifecycle.get("repository") != HUB_ECR_REPOSITORY_NAME:
        raise ContractError("Hub lifecycle repository drifted")

    hub_digest_address = "module.control.aws_ssm_parameter.hub_image_digest"
    hub_digest, hub_digest_unknown = values(hub_digest_address)
    hub_digest_is_create = (
        by_address[hub_digest_address].get("change", {}).get("actions")
        == ["create"]
    )
    _require_fields(
        hub_digest,
        {
            "description": _HUB_DIGEST_SPEC["description"],
            "name": HUB_IMAGE_DIGEST_PARAMETER_NAME,
            "overwrite": None,
            "region": AWS_REGION,
            "type": "String",
            "value_wo": None,
            "value_wo_version": None,
        },
        hub_digest_address,
    )
    provider_default_fields = {
        "data_type": "text",
        "has_value_wo": False,
        "insecure_value": None,
        "key_id": "",
        "tier": "Standard",
    }
    if hub_digest_is_create:
        _require_fields(
            hub_digest,
            {"allowed_pattern": None},
            hub_digest_address,
        )
        if hub_digest_unknown.get("allowed_pattern") not in (None, False):
            raise ContractError(
                "Hub image digest allowed pattern may not be unknown"
            )
        _require_fields(
            hub_digest,
            {field: None for field in provider_default_fields},
            hub_digest_address,
        )
        if any(
            hub_digest_unknown.get(field) is not True
            for field in provider_default_fields
        ):
            raise ContractError(
                "Hub image digest create defaults are not the exact "
                "fail-closed provider shape"
            )
    else:
        _require_fields(
            hub_digest,
            {
                "allowed_pattern": "",
                **provider_default_fields,
            },
            hub_digest_address,
        )
        if any(
            hub_digest_unknown.get(field) not in (None, False)
            for field in ("allowed_pattern", *provider_default_fields)
        ):
            raise ContractError("Hub image digest defaults may not remain unknown")

    hub_digest_value = hub_digest.get("value")
    if (
        (hub_digest_is_create and hub_digest_value != "UNPUBLISHED")
        or (
            not hub_digest_is_create
            and hub_digest_value != "UNPUBLISHED"
            and (
                not isinstance(hub_digest_value, str)
                or _DIGEST_PATTERN.fullmatch(hub_digest_value) is None
            )
        )
    ):
        raise ContractError("planned Hub image digest pin is invalid")

    for (
        label,
        publisher_role_address,
        publisher_policy_address,
        publisher_role_name,
        identity_checker,
    ) in (
        (
            "authority",
            "module.control.aws_iam_role.authority_publisher",
            "module.control.aws_iam_role_policy.authority_publisher",
            AUTHORITY_PUBLISHER_ROLE_NAME,
            _require_authority_publisher_identity,
        ),
        (
            "Hub",
            "module.control.aws_iam_role.hub_publisher",
            "module.control.aws_iam_role_policy.hub_publisher",
            HUB_PUBLISHER_ROLE_NAME,
            _require_hub_publisher_identity,
        ),
    ):
        publisher_role, publisher_role_unknown = values(publisher_role_address)
        publisher_policy, publisher_policy_unknown = values(publisher_policy_address)
        publisher_role_is_create = (
            by_address[publisher_role_address].get("change", {}).get("actions")
            == ["create"]
        )
        allowed_managed_policy_unknown = (
            (None, [], False, True)
            if publisher_role_is_create
            else (None, [], False)
        )
        if (
            publisher_role_unknown.get("managed_policy_arns")
            not in allowed_managed_policy_unknown
        ):
            raise ContractError(
                f"{label} publisher managed policies may not be unknown"
            )

        publisher_policy_is_create = (
            by_address[publisher_policy_address].get("change", {}).get("actions")
            == ["create"]
        )
        identity_checker(
            publisher_role,
            publisher_policy,
            # The refresh-disabled PR plan sees the pre-normalization empty
            # computed field; a refreshed plan sees the exact reflected policy.
            # Both are safe no-op representations, while create/partial-retry
            # must remain empty until the separate policy exists.
            reflected_inline_policy=(
                False
                if publisher_role_is_create or publisher_policy_is_create
                else None
            ),
        )
        _require_fields(
            publisher_role,
            {"path": "/"},
            publisher_role_address,
        )
        if publisher_policy_is_create and publisher_role_is_create:
            if (
                publisher_policy.get("role") is not None
                or publisher_policy_unknown.get("role") is not True
            ):
                raise ContractError(
                    f"{label} publisher create must derive its role"
                )
        elif publisher_policy.get("role") != publisher_role_name:
            raise ContractError(f"{label} publisher policy role drifted")

    if runtime_mode:
        _check_authority_runtime_resources(by_address, foundation)


def _authority_runtime_after(
    by_address: dict[str, dict[str, Any]], address: str
) -> dict[str, Any]:
    change = by_address.get(address, {}).get("change", {})
    after = change.get("after")
    if not isinstance(after, dict):
        raise ContractError(f"{address} planned values are malformed")
    return after


def _authority_decode_policy(after: dict[str, Any], address: str) -> Any:
    raw = after.get("policy")
    if not isinstance(raw, str):
        raise ContractError(f"{address} policy must be JSON text")
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ContractError(f"{address} policy is malformed JSON: {exc}") from exc


def _authority_single_allow_statement(
    after: dict[str, Any], address: str, expected_sid: str
) -> dict[str, Any]:
    policy = _authority_decode_policy(after, address)
    if not isinstance(policy, dict) or policy.get("Version") != "2012-10-17":
        raise ContractError(f"{address} scoped policy is not a 2012-10-17 document")
    statements = policy.get("Statement")
    if not isinstance(statements, list) or len(statements) != 1:
        raise ContractError(f"{address} scoped policy must hold exactly one statement")
    stmt = statements[0]
    if not isinstance(stmt, dict):
        raise ContractError(f"{address} scoped statement is malformed")
    if stmt.get("Effect") != "Allow" or stmt.get("Sid") != expected_sid:
        raise ContractError(f"{address} scoped statement effect/sid drifted")
    if any(key in stmt for key in ("NotPrincipal", "NotAction", "NotResource")):
        raise ContractError(f"{address} scoped statement may not use Not* elements")
    # The runtime endpoint policies REQUIRE a Condition: a VPC endpoint policy
    # does not match an assumed-role session against a role-ARN Principal, so each
    # grant is Principal "*" scoped by an exact aws:PrincipalArn condition (see
    # _authority_principalarn_condition). The callers validate that precise shape;
    # no other condition operator or key may appear.
    return stmt


def _authority_principalarn_condition(stmt: dict[str, Any], address: str) -> set[str]:
    # A VPC endpoint policy does not match an assumed-role session against a
    # role-ARN (or account-root) Principal -- the session is denied with "no VPC
    # endpoint policy allows ..." even when the identity policy grants the action.
    # So the runtime grants use Principal "*" scoped by an exact aws:PrincipalArn
    # StringEquals condition. Require that precise shape and return the scoped
    # role-ARN set; fail closed on any broadening (a Principal that is not "*", a
    # missing/extra condition operator or key, or a "*" arn value).
    if stmt.get("Principal") != "*":
        raise ContractError(
            f'{address} principal must be "*" scoped by an aws:PrincipalArn condition'
        )
    condition = stmt.get("Condition")
    if not isinstance(condition, dict) or set(condition) != {"StringEquals"}:
        raise ContractError(
            f"{address} must scope with exactly one StringEquals condition"
        )
    equals = condition["StringEquals"]
    if not isinstance(equals, dict) or set(equals) != {"aws:PrincipalArn"}:
        raise ContractError(f"{address} condition must key on exactly aws:PrincipalArn")
    return _authority_string_set(equals["aws:PrincipalArn"], address, "aws:PrincipalArn")


def _authority_string_set(value: Any, address: str, field: str) -> set[str]:
    values = value if isinstance(value, list) else [value]
    result: set[str] = set()
    for item in values:
        if not isinstance(item, str) or item == "*":
            raise ContractError(f"{address} {field} must be exact strings, never '*'")
        result.add(item)
    return result


def _check_authority_dynamodb_decrypt(
    statement: dict[str, Any], fn: str, sid: str = "AuthorityDynamoDBDecrypt"
) -> None:
    """Pin the CMK grant to DynamoDB-mediated use of the Authority data key."""
    resources = _authority_string_set(statement.get("Resource"), fn, f"{sid} Resource")
    if (
        statement.get("Effect") != "Allow"
        or _authority_string_set(statement.get("Action"), fn, f"{sid} Action")
        != {"kms:Decrypt"}
        or len(resources) != 1
        or _AUTHORITY_DATA_KEY_ARN_RE.fullmatch(next(iter(resources))) is None
        or statement.get("Condition")
        != {
            "StringEquals": {
                "kms:ViaService": f"dynamodb.{AWS_REGION}.amazonaws.com"
            }
        }
    ):
        raise ContractError(f"{fn} DynamoDB decrypt grant drifted")


def _check_authority_dynamodb_endpoint_policy(
    after: dict[str, Any],
    address: str,
    *,
    proof_enabled: bool = False,
    legacy_recovery_resources: bool = False,
) -> None:
    stmt = _authority_single_allow_statement(after, address, "AuthorityFunctionsData")
    expected_principals = set(AUTHORITY_RUNTIME_EXEC_ROLE_ARNS)
    if proof_enabled:
        expected_principals.update(AUTHORITY_PROOF_EXEC_ROLE_ARNS)
    if _authority_principalarn_condition(stmt, address) != expected_principals:
        raise ContractError(
            f"{address} principals must be exactly the enabled Authority execution roles"
        )
    if _authority_string_set(stmt.get("Action"), address, "Action") != set(
        AUTHORITY_RUNTIME_DYNAMODB_ACTIONS
    ):
        raise ContractError(f"{address} actions drifted from the reviewed DynamoDB set")
    expected_resources = (
        AUTHORITY_RUNTIME_DYNAMODB_LEGACY_RESOURCES
        if legacy_recovery_resources
        else AUTHORITY_RUNTIME_DYNAMODB_RESOURCES
    )
    if _authority_string_set(
        stmt.get("Resource"), address, "Resource"
    ) != set(expected_resources):
        raise ContractError(
            f"{address} resources must be exactly the reviewed base-table set"
        )


def _check_authority_kms_endpoint_policy(
    after: dict[str, Any], address: str
) -> None:
    statements = _endpoint_allow_statements(after, address, 2)
    if set(statements) != {"AuthorityFunctionsQat1PublicKey", "IssueAssignmentQat1Sign"}:
        raise ContractError(f"{address} KMS statement set drifted")
    public_key = statements["AuthorityFunctionsQat1PublicKey"]
    sign = statements["IssueAssignmentQat1Sign"]
    if _authority_principalarn_condition(public_key, address) != set(
        AUTHORITY_RUNTIME_PUBLIC_KEY_ROLE_ARNS
    ):
        raise ContractError(
            f"{address} GetPublicKey principals must be exactly IA/IRO/AR"
        )
    if _authority_string_set(public_key.get("Action"), address, "Action") != {
        "kms:GetPublicKey"
    }:
        raise ContractError(f"{address} public-key action drifted")
    if _authority_principalarn_condition(sign, address) != set(
        AUTHORITY_RUNTIME_SIGN_ROLE_ARNS
    ):
        raise ContractError(f"{address} Sign principal must be exactly IssueAssignment")
    if _authority_string_set(sign.get("Action"), address, "Action") != {"kms:Sign"}:
        raise ContractError(f"{address} Sign action drifted")
    for statement in (public_key, sign):
        resources = _authority_string_set(
            statement.get("Resource"), address, "Resource"
        )
        if (
            len(resources) != 1
            or _QAT1_KEY_ARN_RE.fullmatch(next(iter(resources))) is None
        ):
            raise ContractError(f"{address} must target exactly the qat1 signing key")


def _check_authority_secrets_endpoint_policy(
    after: dict[str, Any], address: str, *, hub_worker_mode: bool
) -> None:
    expected_count = 2 if hub_worker_mode else 1
    statements = _endpoint_allow_statements(after, address, expected_count)
    authority = statements.get("AuthorityOTPSecret")
    if authority is None:
        raise ContractError(f"{address} lacks the Authority OTP secret grant")
    if _authority_principalarn_condition(authority, address) != set(
        AUTHORITY_RUNTIME_OTP_ROLE_ARNS
    ):
        raise ContractError(f"{address} OTP principals must be exactly IRO/AR")
    if _authority_string_set(authority.get("Action"), address, "Action") != {
        "secretsmanager:GetSecretValue"
    }:
        raise ContractError(f"{address} OTP secret action drifted")
    resources = _authority_string_set(authority.get("Resource"), address, "Resource")
    if (
        len(resources) != 1
        or _AUTHORITY_OTP_SECRET_ARN_RE.fullmatch(next(iter(resources))) is None
    ):
        raise ContractError(f"{address} must target exactly the OTP pepper secret")
    if hub_worker_mode:
        # Reuse the existing exact Hub validation against the same combined policy
        # by validating its statement inline.
        hub = statements.get("HubWorkerReadKeyMaterial")
        if hub is None:
            raise ContractError(f"{address} lacks the Hub key-material grant")
        if _authority_principalarn_condition(hub, address) != {HUB_EXECUTION_ROLE_ARN}:
            raise ContractError(f"{address} Hub secret principal drifted")
        if _authority_string_set(hub.get("Action"), address, "Action") != {
            "secretsmanager:GetSecretValue"
        }:
            raise ContractError(f"{address} Hub secret action drifted")
        hub_resources = _authority_string_set(
            hub.get("Resource"), address, "Resource"
        )
        if (
            len(hub_resources) != 1
            or HUB_KEY_MATERIAL_SECRET_ARN_RE.fullmatch(next(iter(hub_resources)))
            is None
        ):
            raise ContractError(f"{address} Hub secret resource drifted")


def _check_authority_email_endpoint_policy(
    after: dict[str, Any], address: str
) -> None:
    stmt = _authority_single_allow_statement(
        after, address, "AuthorityOTPSendEmail"
    )
    if _authority_principalarn_condition(stmt, address) != set(
        AUTHORITY_RUNTIME_SES_ROLE_ARNS
    ):
        raise ContractError(f"{address} SES principals must be exactly IRO")
    if _authority_string_set(stmt.get("Action"), address, "Action") != {
        "ses:SendEmail"
    }:
        raise ContractError(f"{address} SES action drifted")
    if _authority_string_set(stmt.get("Resource"), address, "Resource") != set(
        AUTHORITY_RUNTIME_SES_RESOURCES
    ):
        raise ContractError(f"{address} SES resources drifted")


def _endpoint_allow_statements(
    after: dict[str, Any], address: str, count: int
) -> dict[str, dict[str, Any]]:
    # Decode a scoped endpoint policy holding exactly ``count`` Allow statements
    # with unique Sids and no Not* elements; return them keyed by Sid. The
    # multi-statement generalization of _authority_single_allow_statement (used by
    # the two-statement ECR pull policy).
    policy = _authority_decode_policy(after, address)
    if not isinstance(policy, dict) or policy.get("Version") != "2012-10-17":
        raise ContractError(f"{address} scoped policy is not a 2012-10-17 document")
    statements = policy.get("Statement")
    if not isinstance(statements, list) or len(statements) != count:
        raise ContractError(
            f"{address} scoped policy must hold exactly {count} statements"
        )
    by_sid: dict[str, dict[str, Any]] = {}
    for stmt in statements:
        if not isinstance(stmt, dict):
            raise ContractError(f"{address} scoped statement is malformed")
        if stmt.get("Effect") != "Allow":
            raise ContractError(f"{address} scoped statement must be Allow")
        if any(key in stmt for key in ("NotPrincipal", "NotAction", "NotResource")):
            raise ContractError(f"{address} scoped statement may not use Not* elements")
        sid = stmt.get("Sid")
        if not isinstance(sid, str) or sid in by_sid:
            raise ContractError(f"{address} statements must carry unique string Sids")
        by_sid[sid] = stmt
    return by_sid


def _check_hub_lambda_endpoint_policy(
    after: dict[str, Any],
    address: str,
    *,
    rollout: bool = False,
    selected: str = "blue",
) -> None:
    # The opened lambda interface endpoint admits ONLY the Hub worker task role,
    # invoking ONLY the 3 selected-color authority aliases. Same Principal "*" +
    # aws:PrincipalArn shape as the runtime dependency endpoints -- a role-ARN
    # Principal would silently deny the worker's assumed-role session.
    stmt = _authority_single_allow_statement(
        after, address, "HubWorkersInvokeAuthority"
    )
    if _authority_principalarn_condition(stmt, address) != {HUB_TASK_ROLE_ARN}:
        raise ContractError(
            f"{address} principal must be exactly the Hub worker task role"
        )
    if _authority_string_set(stmt.get("Action"), address, "Action") != {
        "lambda:InvokeFunction"
    }:
        raise ContractError(f"{address} action must be exactly lambda:InvokeFunction")
    if _authority_string_set(
        stmt.get("Resource"), address, "Resource"
    ) != _hub_authority_alias_arns(rollout, selected):
        raise ContractError(
            f"{address} resources must be exactly the bounded Authority alias set"
        )


def _check_hub_secretsmanager_endpoint_policy(
    after: dict[str, Any], address: str
) -> None:
    # The opened secretsmanager interface endpoint admits ONLY the Hub execution
    # role reading the Hub key-material secret (the ECS agent fetches it to inject
    # the init container's key env vars). Same Principal "*" + aws:PrincipalArn
    # shape; the secret ARN carries a random Secrets Manager suffix so it is
    # matched by shape rather than a constructed literal.
    stmt = _authority_single_allow_statement(
        after, address, "HubWorkerReadKeyMaterial"
    )
    if _authority_principalarn_condition(stmt, address) != {HUB_EXECUTION_ROLE_ARN}:
        raise ContractError(
            f"{address} principal must be exactly the Hub execution role"
        )
    if _authority_string_set(stmt.get("Action"), address, "Action") != {
        "secretsmanager:GetSecretValue"
    }:
        raise ContractError(
            f"{address} action must be exactly secretsmanager:GetSecretValue"
        )
    resources = _authority_string_set(stmt.get("Resource"), address, "Resource")
    if (
        len(resources) != 1
        or HUB_KEY_MATERIAL_SECRET_ARN_RE.fullmatch(next(iter(resources))) is None
    ):
        raise ContractError(
            f"{address} resource must be exactly the Hub key-material secret"
        )


def _check_hub_logs_endpoint_policy(after: dict[str, Any], address: str) -> None:
    # The opened logs interface endpoint admits ONLY the Hub execution role's
    # awslogs driver creating the stream + putting events, scoped to EXACTLY the
    # Hub worker container log group. No CreateLogGroup (the group is pre-created).
    stmt = _authority_single_allow_statement(after, address, "HubWorkerContainerLogs")
    if _authority_principalarn_condition(stmt, address) != {HUB_EXECUTION_ROLE_ARN}:
        raise ContractError(
            f"{address} principal must be exactly the Hub execution role"
        )
    if _authority_string_set(stmt.get("Action"), address, "Action") != {
        "logs:CreateLogStream",
        "logs:PutLogEvents",
    }:
        raise ContractError(
            f"{address} actions must be exactly CreateLogStream+PutLogEvents"
        )
    if _authority_string_set(stmt.get("Resource"), address, "Resource") != {
        HUB_LOG_GROUP_ARN
    }:
        raise ContractError(
            f"{address} resource must be exactly the Hub worker log group"
        )


def _check_hub_monitoring_endpoint_policy(
    after: dict[str, Any], address: str
) -> None:
    # The opened monitoring interface endpoint admits ONLY the Hub task role
    # publishing metrics. PutMetricData is resource-less (Resource "*"), so BOTH
    # the caller AND the LayerV/NHP namespace are fenced in the condition (every
    # Terraform PutMetricData grant must be namespace-scoped).
    stmt = _authority_single_allow_statement(
        after, address, "HubWorkerPublishMetrics"
    )
    if stmt.get("Principal") != "*":
        raise ContractError(
            f'{address} principal must be "*" scoped by an aws:PrincipalArn condition'
        )
    condition = stmt.get("Condition")
    if not isinstance(condition, dict) or set(condition) != {"StringEquals"}:
        raise ContractError(
            f"{address} must scope with exactly one StringEquals condition"
        )
    equals = condition["StringEquals"]
    if not isinstance(equals, dict) or set(equals) != {
        "aws:PrincipalArn",
        "cloudwatch:namespace",
    }:
        raise ContractError(
            f"{address} condition must key on exactly aws:PrincipalArn + "
            "cloudwatch:namespace"
        )
    if _authority_string_set(
        equals["aws:PrincipalArn"], address, "aws:PrincipalArn"
    ) != {HUB_TASK_ROLE_ARN}:
        raise ContractError(f"{address} principal must be exactly the Hub task role")
    if equals.get("cloudwatch:namespace") != "LayerV/NHP":
        raise ContractError(
            f"{address} PutMetricData must be scoped to the LayerV/NHP namespace"
        )
    if _authority_string_set(stmt.get("Action"), address, "Action") != {
        "cloudwatch:PutMetricData"
    }:
        raise ContractError(
            f"{address} action must be exactly cloudwatch:PutMetricData"
        )
    if stmt.get("Resource") != "*":
        raise ContractError(f'{address} PutMetricData resource must be "*"')


def _check_hub_ecr_endpoint_policy(after: dict[str, Any], address: str) -> None:
    # Both ECR interface endpoints (api + dkr) open with the SAME policy: the Hub
    # execution role may pull ONLY the nhp-hub repository (layers/manifest), plus
    # the resource-less GetAuthorizationToken. No push, no other repo/principal.
    by_sid = _endpoint_allow_statements(after, address, 2)
    if set(by_sid) != {"HubPullImage", "HubAuthToken"}:
        raise ContractError(
            f"{address} statements must be exactly HubPullImage + HubAuthToken"
        )
    pull = by_sid["HubPullImage"]
    if _authority_principalarn_condition(pull, address) != {HUB_EXECUTION_ROLE_ARN}:
        raise ContractError(
            f"{address} pull principal must be exactly the Hub execution role"
        )
    if _authority_string_set(pull.get("Action"), address, "Action") != set(
        HUB_ECR_PULL_ACTIONS
    ):
        raise ContractError(f"{address} pull actions drifted from the reviewed ECR set")
    if _authority_string_set(pull.get("Resource"), address, "Resource") != {
        HUB_ECR_REPOSITORY_ARN
    }:
        raise ContractError(
            f"{address} pull resource must be exactly the nhp-hub repository"
        )
    auth = by_sid["HubAuthToken"]
    if _authority_principalarn_condition(auth, address) != {HUB_EXECUTION_ROLE_ARN}:
        raise ContractError(
            f"{address} auth-token principal must be exactly the Hub execution role"
        )
    if _authority_string_set(auth.get("Action"), address, "Action") != {
        "ecr:GetAuthorizationToken"
    }:
        raise ContractError(
            f"{address} auth-token action must be exactly ecr:GetAuthorizationToken"
        )
    # GetAuthorizationToken is resource-less; AWS requires Resource "*" here -- the
    # only place a "*" resource is admitted, and only for this one action.
    if auth.get("Resource") != "*":
        raise ContractError(f'{address} auth-token resource must be "*"')


def _check_hub_s3_endpoint_policy(after: dict[str, Any], address: str) -> None:
    # The S3 GATEWAY endpoint opens s3:GetObject on EXACTLY the region's ECR layer
    # bucket. Unlike the other Hub endpoint policies it carries NO aws:PrincipalArn
    # condition: ECR layer blobs are fetched via presigned URLs signed by the ECR
    # service, not the execution role, so a principal condition 403s the pull. The
    # exact starport bucket + opaque layer-digest keys are the access control.
    stmt = _authority_single_allow_statement(after, address, "HubPullLayers")
    if stmt.get("Principal") != "*":
        raise ContractError(f'{address} principal must be "*"')
    if "Condition" in stmt:
        raise ContractError(
            f"{address} must carry no Condition: ECR presigned-URL layer GETs are "
            "not signed by the execution role, so a principal condition denies them"
        )
    if _authority_string_set(stmt.get("Action"), address, "Action") != {"s3:GetObject"}:
        raise ContractError(f"{address} action must be exactly s3:GetObject")
    if _authority_string_set(stmt.get("Resource"), address, "Resource") != {
        HUB_S3_LAYER_BUCKET_ARN
    }:
        raise ContractError(
            f"{address} resource must be exactly the region ECR layer bucket"
        )


def _check_authority_interface_endpoint_ingress(
    after: dict[str, Any],
    unknown: dict[str, Any],
    address: str,
    *,
    hub_worker_mode: bool = False,
) -> None:
    # The shared interface-endpoints SG carries exactly one TLS/443 SG-scoped
    # ingress per live caller slice: the runtime function SG (always, in this
    # lane) plus -- once the Hub worker slice (5b) is live -- the Hub worker SG.
    # Each rule is validated to the same exact 443/tcp SG-scoped shape; only the
    # count grows. A CIDR/prefix/self-reachable or multi-SG rule fails closed.
    ingress = after.get("ingress")
    expected_count = 2 if hub_worker_mode else 1
    if not isinstance(ingress, list) or len(ingress) != expected_count:
        raise ContractError(
            f"{address} must open exactly {expected_count} TLS/443 ingress rule(s)"
        )
    # The referenced caller SG id is computed at create. Accept exactly one known
    # id per rule, or the provider's single-element unknown projection (empty list
    # in after with ingress marked unknown); reject a broader/absent set. If a
    # future provider render hides the rules, this fails closed and the
    # POST-STEP-3 calibration must observe and admit the exact shape.
    ingress_unknown = unknown.get("ingress")
    for rule in ingress:
        if not isinstance(rule, dict):
            raise ContractError(f"{address} ingress rule is malformed")
        if (
            rule.get("from_port") != 443
            or rule.get("to_port") != 443
            or rule.get("protocol") != "tcp"
        ):
            raise ContractError(f"{address} ingress must be exactly TLS/443/tcp")
        if (
            rule.get("cidr_blocks") not in (None, [])
            or rule.get("ipv6_cidr_blocks") not in (None, [])
            or rule.get("prefix_list_ids") not in (None, [])
            or rule.get("self") not in (None, False)
        ):
            raise ContractError(
                f"{address} ingress must be SG-scoped, never CIDR/prefix/self reachable"
            )
        security_groups = rule.get("security_groups")
        known_single = isinstance(security_groups, list) and len(security_groups) == 1
        unknown_single = security_groups in (None, []) and bool(ingress_unknown)
        if not (known_single or unknown_single):
            raise ContractError(
                f"{address} each ingress rule must reference exactly one caller SG"
            )


def _check_otp_redis_ingress(
    after: dict[str, Any], unknown: dict[str, Any], address: str
) -> None:
    # The OTP Redis SG is created closed and stays closed until the
    # authority-runtime slice attaches its ONE standalone SG-to-SG TLS/6379
    # ingress rule (aws_vpc_security_group_ingress_rule.otp_redis_authority),
    # which is itself contract-checked. `ingress` is Optional+Computed, so once
    # that rule applies a refreshed plan reports it here -- demanding an empty
    # list admitted only the pre-slice state and rejected every plan after it.
    #
    # Admit exactly the two lawful shapes: closed (pre-slice), or precisely one
    # SG-scoped TLS/6379 rule. Anything CIDR/prefix/self-reachable, a second
    # rule, or a different port fails closed.
    ingress = after.get("ingress")
    if ingress in (None, []):
        return
    if not isinstance(ingress, list) or len(ingress) != 1:
        raise ContractError(
            f"{address} must carry at most one TLS/6379 ingress rule"
        )
    rule = ingress[0]
    if not isinstance(rule, dict):
        raise ContractError(f"{address} ingress rule is malformed")
    if (
        rule.get("from_port") != 6379
        or rule.get("to_port") != 6379
        or rule.get("protocol") != "tcp"
    ):
        raise ContractError(f"{address} ingress must be exactly TLS/6379/tcp")
    if (
        rule.get("cidr_blocks") not in (None, [])
        or rule.get("ipv6_cidr_blocks") not in (None, [])
        or rule.get("prefix_list_ids") not in (None, [])
        or rule.get("self") not in (None, False)
    ):
        raise ContractError(
            f"{address} ingress must be SG-scoped, never CIDR/prefix/self reachable"
        )
    security_groups = rule.get("security_groups")
    known_single = isinstance(security_groups, list) and len(security_groups) == 1
    unknown_single = security_groups in (None, []) and bool(unknown.get("ingress"))
    if not (known_single or unknown_single):
        raise ContractError(
            f"{address} ingress must reference exactly one caller SG"
        )


def _check_authority_exec_role_trust(role_after: dict[str, Any], fn: str) -> None:
    if role_after.get("permissions_boundary") not in (None, ""):
        raise ContractError(f"{fn} execution role must not use a permissions boundary")
    if role_after.get("managed_policy_arns") not in (None, []):
        raise ContractError(f"{fn} execution role must not attach managed policies")
    if role_after.get("max_session_duration") != 3600:
        raise ContractError(f"{fn} execution role session duration drifted")
    raw = role_after.get("assume_role_policy")
    if not isinstance(raw, str):
        raise ContractError(f"{fn} execution role trust policy must be JSON text")
    try:
        trust = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ContractError(f"{fn} trust policy is malformed: {exc}") from exc
    statements = trust.get("Statement") if isinstance(trust, dict) else None
    if not isinstance(statements, list) or len(statements) != 1:
        raise ContractError(f"{fn} trust policy must hold exactly one statement")
    stmt = statements[0]
    principal = stmt.get("Principal") if isinstance(stmt, dict) else None
    if (
        not isinstance(principal, dict)
        or principal.get("Service") != "lambda.amazonaws.com"
        or stmt.get("Effect") != "Allow"
        or stmt.get("Action") != "sts:AssumeRole"
    ):
        raise ContractError(f"{fn} trust must allow only the Lambda service to assume")
    # A Lambda EXECUTION role trust must carry NO aws:SourceArn/aws:SourceAccount
    # confused-deputy Condition. The Lambda Hyperplane assumes the execution role
    # to create the function's VPC ENI in a context that does not satisfy a
    # per-function SourceArn condition, so such a condition denies that assume and
    # the function fails to reach Active with InsufficientRolePermissions (all
    # complete Authority graph hits this on the first live apply). The
    # execution role is usable only by the function wired to it (its role=
    # attribute), never by arbitrary assumption, so the bare lambda-principal
    # trust is the correct least privilege -- and the only trust that lets a VPC
    # function initialize.
    if "Condition" in stmt:
        raise ContractError(
            f"{fn} execution-role trust must carry no Condition: an aws:SourceArn/"
            "aws:SourceAccount confused-deputy scope breaks VPC ENI creation"
        )


def _check_authority_exec_role_policy(
    after: dict[str, Any],
    fn: str,
    operation: str,
    *,
    proof_policy_consumer: bool = False,
) -> None:
    """Validate one function's per-operation execution (identity) policy.

    Every referenced ARN is plan-known (the own-log-group ARN is a constructed
    literal, not the computed resource attribute), so the exact least-privilege
    scope is checkable at first apply: reads including DescribeTable scoped to the
    op's SSE-verified tables, writes scoped to connector_authority with the op's
    exact verbs, KMS Sign only for IssueAssignment, and no wildcard resource
    outside the single AWS-required ENI statement.
    """
    if operation == AUTHORITY_PROOF_OPERATION:
        _check_authority_proof_exec_role_policy(after, fn)
        return
    if operation == AUTHORITY_PROOF_RECOVERY_OPERATION:
        _check_authority_proof_recovery_exec_role_policy(after, fn)
        return
    if operation in AUTHORITY_RUNTIME_CELL_OPERATION_IAM:
        _check_authority_cell_exec_role_policy(after, fn, operation)
        return
    spec = AUTHORITY_RUNTIME_OPERATION_IAM.get(operation)
    if spec is None:
        raise ContractError(f"{fn} execution policy has unknown operation {operation!r}")
    policy = _authority_decode_policy(after, fn)
    if not isinstance(policy, dict) or policy.get("Version") != "2012-10-17":
        raise ContractError(f"{fn} execution policy is not a 2012-10-17 document")
    statements = policy.get("Statement")
    if not isinstance(statements, list):
        raise ContractError(f"{fn} execution policy Statement must be a list")
    by_sid: dict[str, dict[str, Any]] = {}
    for stmt in statements:
        if not isinstance(stmt, dict):
            raise ContractError(f"{fn} execution statements must all be objects")
        effect = stmt.get("Effect")
        if effect not in {"Allow", "Deny"}:
            raise ContractError(f"{fn} execution statement effect is invalid")
        if any(
            key in stmt
            for key in ("NotAction", "NotResource", "NotPrincipal", "Principal")
        ):
            raise ContractError(f"{fn} execution statement uses a forbidden element")
        sid = stmt.get("Sid")
        if not isinstance(sid, str) or sid in by_sid:
            raise ContractError(f"{fn} execution statement Sid missing or duplicated")
        by_sid[sid] = stmt

    expected_sids = {
        "LambdaVpcEni",
        "AuthorityDynamoDBDecrypt",
        "OwnLogStream",
        "AuthorityReads",
        spec["write_sid"],
    }
    if spec["signs"]:
        expected_sids.add("Qat1Sign")
    if spec.get("ticket_handle_write"):
        expected_sids.add("AuthorityTicketHandleWrite")
    if proof_policy_consumer:
        expected_sids.update({"ProofPolicyRead", "DenyProofPolicyWrite"})
    if set(by_sid) != expected_sids:
        raise ContractError(
            f"{fn} execution policy statement set drifted: "
            f"{sorted(by_sid)} != {sorted(expected_sids)}"
        )
    if any(
        statement.get("Effect") != "Allow"
        for sid, statement in by_sid.items()
        if sid != "DenyProofPolicyWrite"
    ):
        raise ContractError(f"{fn} carries a non-Allow ordinary execution statement")

    # ENI lifecycle: the ONLY statement permitted a wildcard resource.
    eni = by_sid["LambdaVpcEni"]
    if _authority_string_set(eni.get("Action"), fn, "ENI Action") != set(
        AUTHORITY_RUNTIME_ENI_ACTIONS
    ):
        raise ContractError(f"{fn} ENI statement actions drifted")
    if eni.get("Resource") not in ("*", ["*"]):
        raise ContractError(f"{fn} ENI statement must keep exactly Resource '*'")

    # Own log stream: scoped to this function's own constructed log-group ARN.
    log_stmt = by_sid["OwnLogStream"]
    if _authority_string_set(log_stmt.get("Action"), fn, "log Action") != set(
        AUTHORITY_RUNTIME_LOG_ACTIONS
    ):
        raise ContractError(f"{fn} log statement actions drifted")
    expected_log = f"arn:aws:logs:{AWS_REGION}:{ACCOUNT_ID}:log-group:/aws/lambda/{fn}:*"
    if _authority_string_set(log_stmt.get("Resource"), fn, "log Resource") != {
        expected_log
    }:
        raise ContractError(f"{fn} log statement must target only its own log group")

    # Reads (including DescribeTable) scoped to the op's SSE-verified tables.
    reads = by_sid["AuthorityReads"]
    if _authority_string_set(reads.get("Action"), fn, "read Action") != set(
        AUTHORITY_RUNTIME_DYNAMODB_READ_ACTIONS
    ):
        raise ContractError(
            f"{fn} read actions must be exactly the reviewed set including DescribeTable"
        )
    expected_read_resources = set().union(
        *(AUTHORITY_RUNTIME_TABLE_RESOURCES[table] for table in spec["read_tables"])
    )
    if (
        _authority_string_set(reads.get("Resource"), fn, "read Resource")
        != expected_read_resources
    ):
        raise ContractError(f"{fn} read resources must be exactly its SSE-verified tables")
    _check_authority_dynamodb_decrypt(by_sid["AuthorityDynamoDBDecrypt"], fn)

    # Writes: connector_authority only, with the op's exact verbs.
    write = by_sid[spec["write_sid"]]
    if _authority_string_set(write.get("Action"), fn, "write Action") != set(
        spec["write_actions"]
    ):
        raise ContractError(f"{fn} write actions drifted from the reviewed per-op set")
    if _authority_string_set(write.get("Resource"), fn, "write Resource") != set(
        AUTHORITY_RUNTIME_TABLE_RESOURCES["connector_authority"]
    ):
        raise ContractError(f"{fn} writes must be scoped to connector_authority only")
    if spec.get("ticket_handle_write"):
        # Asserted separately from the replay write above, with its own action
        # set and prefix, so the two grants cannot converge by someone widening
        # one of them. That separation is the reason there are two Sids at all.
        handle_write = by_sid["AuthorityTicketHandleWrite"]
        if _authority_string_set(
            handle_write.get("Action"), fn, "ticket handle write Action"
        ) != set(spec["ticket_handle_write_actions"]):
            raise ContractError(
                f"{fn} ticket-handle write actions drifted from the reviewed set"
            )
        if _authority_string_set(
            handle_write.get("Resource"), fn, "ticket handle write Resource"
        ) != set(AUTHORITY_RUNTIME_TABLE_RESOURCES["connector_authority"]):
            raise ContractError(
                f"{fn} ticket-handle writes must be scoped to connector_authority only"
            )
        # The Null guard is load-bearing, not decoration: ForAllValues:* is
        # vacuously true when a request carries no LeadingKeys at all, so
        # without it an unkeyed request slips past the prefix scope entirely.
        if handle_write.get("Condition") != {
            "ForAllValues:StringLike": {
                "dynamodb:LeadingKeys": ["ASSIGNMENT_TICKET#*"],
            },
            "Null": {"dynamodb:LeadingKeys": "false"},
        }:
            raise ContractError(
                f"{fn} ticket-handle write is not fenced to the ASSIGNMENT_TICKET# prefix"
            )
    expected_write_keys = {
        "issue_assignment": ["HUB_REQUEST#IssueAssignment#*"],
        "refresh_assignment": ["HUB_REQUEST#RefreshAssignment#*"],
        "issue_credential_recovery": [
            "CREDENTIAL_RECOVERY_GRANT#*",
            "CREDENTIAL_RECOVERY_ISSUE#*",
            "HUB_REQUEST#IssueCredentialRecovery#*",
            "OWNER#*",
        ],
    }[operation]
    if write.get("Condition") != {
        "ForAllValues:StringLike": {
            "dynamodb:LeadingKeys": expected_write_keys,
        },
        "Null": {"dynamodb:LeadingKeys": "false"},
    }:
        raise ContractError(f"{fn} ordinary writes are not partition-fenced")

    unconditional_sids = {
        "LambdaVpcEni",
        "OwnLogStream",
        "AuthorityReads",
        *(["Qat1Sign"] if spec["signs"] else []),
    }
    if any("Condition" in by_sid[sid] for sid in unconditional_sids):
        raise ContractError(f"{fn} carries a condition on an unconditioned statement")

    if proof_policy_consumer:
        proof_read = by_sid["ProofPolicyRead"]
        proof_deny = by_sid["DenyProofPolicyWrite"]
        table_resources = set(AUTHORITY_RUNTIME_TABLE_RESOURCES["connector_authority"])
        expected_read_condition = {
            "ForAllValues:StringEquals": {
                "dynamodb:LeadingKeys": ["PROOF"],
            },
            "Null": {"dynamodb:LeadingKeys": "false"},
        }
        # A read allow must require every requested key to be the proof
        # partition. The explicit write deny is deliberately stronger: deny
        # the request when any requested key is the proof partition.
        expected_deny_condition = {
            "ForAnyValue:StringEquals": {
                "dynamodb:LeadingKeys": ["PROOF"],
            },
            "Null": {"dynamodb:LeadingKeys": "false"},
        }
        if (
            proof_read.get("Effect") != "Allow"
            or _authority_string_set(proof_read.get("Action"), fn, "proof read")
            != {"dynamodb:GetItem"}
            or _authority_string_set(proof_read.get("Resource"), fn, "proof read")
            != table_resources
            or proof_read.get("Condition") != expected_read_condition
            or proof_deny.get("Effect") != "Deny"
            or _authority_string_set(proof_deny.get("Action"), fn, "proof deny")
            != {
                "dynamodb:DeleteItem",
                "dynamodb:PutItem",
                "dynamodb:UpdateItem",
            }
            or _authority_string_set(proof_deny.get("Resource"), fn, "proof deny")
            != table_resources
            or proof_deny.get("Condition") != expected_deny_condition
        ):
            raise ContractError(
                f"{fn} proof policy must be exact GetItem plus an explicit write deny"
            )
    elif any(sid in by_sid for sid in ("ProofPolicyRead", "DenyProofPolicyWrite")):
        raise ContractError(f"{fn} carries proof policy while its rollout gate is dark")

    # KMS Sign: IssueAssignment alone (GetPublicKey + Sign on exactly the qat1 key).
    if spec["signs"]:
        sign = by_sid["Qat1Sign"]
        if _authority_string_set(sign.get("Action"), fn, "Sign Action") != set(
            AUTHORITY_RUNTIME_KMS_ACTIONS
        ):
            raise ContractError(f"{fn} qat1 Sign actions must be exactly GetPublicKey+Sign")
        resources = _authority_string_set(sign.get("Resource"), fn, "Sign Resource")
        if len(resources) != 1 or _QAT1_KEY_ARN_RE.fullmatch(next(iter(resources))) is None:
            raise ContractError(f"{fn} Sign statement must target exactly the qat1 key")


def _check_authority_proof_exec_role_policy(
    after: dict[str, Any], fn: str
) -> None:
    """Pin ca-pm to the proof tenant/directive/catalog/replay namespaces."""
    if fn != AUTHORITY_PROOF_FUNCTION_NAME:
        raise ContractError("proof execution policy is attached to a foreign function")
    policy = _authority_decode_policy(after, fn)
    if not isinstance(policy, dict) or policy.get("Version") != "2012-10-17":
        raise ContractError(f"{fn} execution policy is not a 2012-10-17 document")
    statements = policy.get("Statement")
    if not isinstance(statements, list):
        raise ContractError(f"{fn} execution policy Statement must be a list")
    by_sid: dict[str, dict[str, Any]] = {}
    for stmt in statements:
        if not isinstance(stmt, dict) or stmt.get("Effect") != "Allow":
            raise ContractError(f"{fn} execution statements must all be Allow objects")
        if any(
            key in stmt
            for key in ("NotAction", "NotResource", "NotPrincipal", "Principal")
        ):
            raise ContractError(f"{fn} execution statement uses a forbidden element")
        sid = stmt.get("Sid")
        if not isinstance(sid, str) or sid in by_sid:
            raise ContractError(f"{fn} execution statement Sid missing or duplicated")
        by_sid[sid] = stmt

    expected_sids = {
        "LambdaVpcEni",
        "OwnLogStream",
        "ProofVerifyTableEncryption",
        "ProofDynamoDBDecrypt",
        "ProofFencedPlacementRead",
        "ProofRegistryRead",
        "ProofFencedPlacementWrite",
        "ProofReplayReadWrite",
    }
    if set(by_sid) != expected_sids:
        raise ContractError(f"{fn} proof execution statement set drifted")

    eni = by_sid["LambdaVpcEni"]
    if _authority_string_set(eni.get("Action"), fn, "ENI Action") != set(
        AUTHORITY_RUNTIME_ENI_ACTIONS
    ) or eni.get("Resource") not in ("*", ["*"]):
        raise ContractError(f"{fn} ENI statement drifted")
    if "Condition" in eni:
        raise ContractError(f"{fn} ENI statement may not carry a condition")

    log_stmt = by_sid["OwnLogStream"]
    expected_log = (
        f"arn:aws:logs:{AWS_REGION}:{ACCOUNT_ID}:log-group:/aws/lambda/{fn}:*"
    )
    if _authority_string_set(log_stmt.get("Action"), fn, "log Action") != set(
        AUTHORITY_RUNTIME_LOG_ACTIONS
    ) or _authority_string_set(log_stmt.get("Resource"), fn, "log Resource") != {
        expected_log
    } or "Condition" in log_stmt:
        raise ContractError(f"{fn} own-log statement drifted")

    table_resources = set(AUTHORITY_RUNTIME_TABLE_RESOURCES["connector_authority"])
    decrypt = by_sid["ProofDynamoDBDecrypt"]
    decrypt_resources = _authority_string_set(
        decrypt.get("Resource"), fn, "ProofDynamoDBDecrypt Resource"
    )
    if (
        _authority_string_set(
            decrypt.get("Action"), fn, "ProofDynamoDBDecrypt Action"
        )
        != {"kms:Decrypt"}
        or len(decrypt_resources) != 1
        or _AUTHORITY_DATA_KEY_ARN_RE.fullmatch(next(iter(decrypt_resources))) is None
        or decrypt.get("Condition")
        != {
            "StringEquals": {
                "kms:ViaService": f"dynamodb.{AWS_REGION}.amazonaws.com"
            }
        }
    ):
        raise ContractError(f"{fn} DynamoDB decrypt grant drifted")

    owner_partition = (
        "OWNER#"
        + hashlib.sha256(AUTHORITY_PROOF_OWNER_ID.encode("utf-8")).hexdigest()
    )
    expected = {
        "ProofVerifyTableEncryption": (
            {"dynamodb:DescribeTable"},
            None,
            None,
        ),
        "ProofFencedPlacementRead": (
            set(AUTHORITY_RUNTIME_DYNAMODB_READ_ACTIONS)
            - {"dynamodb:DescribeTable"},
            "ForAllValues:StringEquals",
            [owner_partition, "PROOF"],
        ),
        "ProofRegistryRead": (
            set(AUTHORITY_RUNTIME_DYNAMODB_READ_ACTIONS)
            - {"dynamodb:DescribeTable"},
            "ForAllValues:StringEquals",
            ["REGISTRY"],
        ),
        "ProofFencedPlacementWrite": (
            {"dynamodb:PutItem", "dynamodb:UpdateItem"},
            "ForAllValues:StringEquals",
            [owner_partition, "PROOF"],
        ),
        "ProofReplayReadWrite": (
            {"dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem"},
            "ForAllValues:StringLike",
            ["HUB_REQUEST#MutateProofAgent#*"],
        ),
    }
    for sid, (actions, operator, leading_keys) in expected.items():
        stmt = by_sid[sid]
        if (
            _authority_string_set(stmt.get("Action"), fn, f"{sid} Action")
            != actions
            or _authority_string_set(stmt.get("Resource"), fn, f"{sid} Resource")
            != table_resources
        ):
            raise ContractError(f"{fn} {sid} actions/resources drifted")
        if operator is None:
            if "Condition" in stmt:
                raise ContractError(f"{fn} {sid} must be unconditioned")
            continue
        condition = stmt.get("Condition")
        if (
            not isinstance(condition, dict)
            or set(condition) != {operator, "Null"}
            or not isinstance(condition[operator], dict)
            or condition[operator]
            != {"dynamodb:LeadingKeys": leading_keys}
            or condition["Null"] != {"dynamodb:LeadingKeys": "false"}
        ):
            raise ContractError(f"{fn} {sid} LeadingKeys fence drifted")


def _check_authority_proof_recovery_exec_role_policy(
    after: dict[str, Any], fn: str
) -> None:
    """Pin ca-pcr to the dedicated proof tenant's recovery namespaces."""
    if fn != AUTHORITY_PROOF_RECOVERY_FUNCTION_NAME:
        raise ContractError(
            "proof recovery execution policy is attached to a foreign function"
        )
    policy = _authority_decode_policy(after, fn)
    if not isinstance(policy, dict) or policy.get("Version") != "2012-10-17":
        raise ContractError(f"{fn} execution policy is not a 2012-10-17 document")
    statements = policy.get("Statement")
    if not isinstance(statements, list):
        raise ContractError(f"{fn} execution policy Statement must be a list")
    by_sid: dict[str, dict[str, Any]] = {}
    for stmt in statements:
        if not isinstance(stmt, dict) or stmt.get("Effect") != "Allow":
            raise ContractError(f"{fn} execution statements must all be Allow objects")
        if any(
            key in stmt
            for key in ("NotAction", "NotResource", "NotPrincipal", "Principal")
        ):
            raise ContractError(f"{fn} execution statement uses a forbidden element")
        sid = stmt.get("Sid")
        if not isinstance(sid, str) or sid in by_sid:
            raise ContractError(f"{fn} execution statement Sid missing or duplicated")
        by_sid[sid] = stmt

    expected_sids = {
        "LambdaVpcEni",
        "AuthorityDynamoDBDecrypt",
        "OwnLogStream",
        "ProofRecoveryVerifyTableEncryption",
        "ProofRecoveryCredentialReadWrite",
        "ProofRecoveryReplayReadWrite",
        "ProofRecoveryOwnerRead",
        "ProofRecoveryAssignmentReadWrite",
    }
    if set(by_sid) != expected_sids:
        raise ContractError(f"{fn} proof recovery execution statement set drifted")

    eni = by_sid["LambdaVpcEni"]
    if _authority_string_set(eni.get("Action"), fn, "ENI Action") != set(
        AUTHORITY_RUNTIME_ENI_ACTIONS
    ) or eni.get("Resource") not in ("*", ["*"]):
        raise ContractError(f"{fn} ENI statement drifted")
    if "Condition" in eni:
        raise ContractError(f"{fn} ENI statement may not carry a condition")
    _check_authority_dynamodb_decrypt(by_sid["AuthorityDynamoDBDecrypt"], fn)

    log_stmt = by_sid["OwnLogStream"]
    expected_log = (
        f"arn:aws:logs:{AWS_REGION}:{ACCOUNT_ID}:log-group:/aws/lambda/{fn}:*"
    )
    if _authority_string_set(log_stmt.get("Action"), fn, "log Action") != set(
        AUTHORITY_RUNTIME_LOG_ACTIONS
    ) or _authority_string_set(log_stmt.get("Resource"), fn, "log Resource") != {
        expected_log
    } or "Condition" in log_stmt:
        raise ContractError(f"{fn} own-log statement drifted")

    table_resources = {
        name: set(AUTHORITY_RUNTIME_TABLE_RESOURCES[name])
        for name in (
            "api_keys",
            "api_key_idempotency",
            "customers",
            "connector_authority",
        )
    }
    api_keys_with_indexes = {
        *table_resources["api_keys"],
        f"{AUTHORITY_RUNTIME_TABLE_ARNS['api_keys']}/index/*",
    }
    expected = {
        "ProofRecoveryVerifyTableEncryption": (
            {"dynamodb:DescribeTable"},
            set().union(*table_resources.values()),
            None,
        ),
        "ProofRecoveryCredentialReadWrite": (
            {
                "dynamodb:ConditionCheckItem",
                "dynamodb:GetItem",
                "dynamodb:PutItem",
                "dynamodb:Query",
                "dynamodb:UpdateItem",
            },
            api_keys_with_indexes,
            None,
        ),
        "ProofRecoveryReplayReadWrite": (
            {"dynamodb:GetItem", "dynamodb:PutItem"},
            table_resources["api_key_idempotency"],
            None,
        ),
        "ProofRecoveryOwnerRead": (
            {"dynamodb:ConditionCheckItem", "dynamodb:GetItem"},
            table_resources["customers"],
            {
                "ForAllValues:StringEquals": {
                    "dynamodb:LeadingKeys": [AUTHORITY_PROOF_OWNER_ID]
                }
            },
        ),
        "ProofRecoveryAssignmentReadWrite": (
            {"dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem"},
            table_resources["connector_authority"],
            {
                "ForAllValues:StringEquals": {
                    "dynamodb:LeadingKeys": [
                        "OWNER#"
                        + hashlib.sha256(
                            AUTHORITY_PROOF_OWNER_ID.encode("utf-8")
                        ).hexdigest()
                    ]
                }
            },
        ),
    }
    for sid, (actions, resources, condition) in expected.items():
        stmt = by_sid[sid]
        if (
            _authority_string_set(stmt.get("Action"), fn, f"{sid} Action")
            != actions
            or _authority_string_set(stmt.get("Resource"), fn, f"{sid} Resource")
            != resources
            or stmt.get("Condition") != condition
            or ("Condition" in stmt) != (condition is not None)
        ):
            raise ContractError(f"{fn} {sid} recovery fence drifted")


def _check_authority_cell_exec_role_policy(
    after: dict[str, Any], fn: str, operation: str
) -> None:
    spec = AUTHORITY_RUNTIME_CELL_OPERATION_IAM[operation]
    policy = _authority_decode_policy(after, fn)
    if not isinstance(policy, dict) or policy.get("Version") != "2012-10-17":
        raise ContractError(f"{fn} execution policy is not a 2012-10-17 document")
    statements = policy.get("Statement")
    if not isinstance(statements, list):
        raise ContractError(f"{fn} execution policy Statement must be a list")
    by_sid: dict[str, dict[str, Any]] = {}
    for stmt in statements:
        if not isinstance(stmt, dict) or stmt.get("Effect") != "Allow":
            raise ContractError(f"{fn} execution statements must all be Allow objects")
        if any(
            key in stmt
            for key in ("NotAction", "NotResource", "NotPrincipal", "Principal")
        ):
            raise ContractError(f"{fn} execution statement uses a forbidden element")
        sid = stmt.get("Sid")
        if not isinstance(sid, str) or sid in by_sid:
            raise ContractError(f"{fn} execution statement Sid missing or duplicated")
        # The handle read is LeadingKeys-scoped on purpose: it resolves a ticket
        # and must not become a general read of connector_authority. Its
        # Condition IS the scope, so it belongs on this list.
        if "Condition" in stmt and sid not in {
            "AuthorityDynamoDBDecrypt",
            "OTPSecretDecrypt",
            "AuthorityTicketHandleRead",
        }:
            raise ContractError(
                f"{fn} only DynamoDB/OTP decrypt and ticket-handle statements "
                "may carry a Condition"
            )
        by_sid[sid] = stmt

    expected_sids = {
        "LambdaVpcEni",
        "AuthorityDynamoDBDecrypt",
        "OwnLogStream",
        "AuthorityReads",
        *spec["writes"],
    }
    if spec["public_key"]:
        expected_sids.add("Qat1PublicKey")
    if spec["otp_user"] is not None:
        expected_sids.update({"OTPSecretRead", "OTPSecretDecrypt", "OTPRedisConnect"})
    if spec["sends_email"]:
        expected_sids.add("OTPSendEmail")
    if spec.get("ticket_handle_read"):
        expected_sids.add("AuthorityTicketHandleRead")
    if set(by_sid) != expected_sids:
        raise ContractError(
            f"{fn} execution policy statement set drifted: "
            f"{sorted(by_sid)} != {sorted(expected_sids)}"
        )

    if spec.get("ticket_handle_read"):
        # Fenced symmetrically with the write grant. Asserting only the Sid and
        # the allowed-Condition membership left the read's actual scope
        # unchecked: its Action, Resource, prefix and Null guard could all be
        # weakened and every gate would still pass. A GetItem always carries a
        # key, so ForAllValues:* is not vacuous here -- but that is exactly the
        # argument the write side declined to rely on, so neither does this.
        handle_read = by_sid["AuthorityTicketHandleRead"]
        if _authority_string_set(
            handle_read.get("Action"), fn, "ticket handle read Action"
        ) != {"dynamodb:GetItem"}:
            raise ContractError(f"{fn} ticket-handle read must be GetItem only")
        if _authority_string_set(
            handle_read.get("Resource"), fn, "ticket handle read Resource"
        ) != set(AUTHORITY_RUNTIME_TABLE_RESOURCES["connector_authority"]):
            raise ContractError(
                f"{fn} ticket-handle read must be scoped to connector_authority only"
            )
        if handle_read.get("Condition") != {
            "ForAllValues:StringLike": {
                "dynamodb:LeadingKeys": ["ASSIGNMENT_TICKET#*"],
            },
            "Null": {"dynamodb:LeadingKeys": "false"},
        }:
            raise ContractError(
                f"{fn} ticket-handle read is not fenced to the ASSIGNMENT_TICKET# prefix"
            )
    eni = by_sid["LambdaVpcEni"]
    if _authority_string_set(eni.get("Action"), fn, "ENI Action") != set(
        AUTHORITY_RUNTIME_ENI_ACTIONS
    ) or eni.get("Resource") not in ("*", ["*"]):
        raise ContractError(f"{fn} ENI statement drifted")
    log_stmt = by_sid["OwnLogStream"]
    expected_log = (
        f"arn:aws:logs:{AWS_REGION}:{ACCOUNT_ID}:log-group:/aws/lambda/{fn}:*"
    )
    if _authority_string_set(log_stmt.get("Action"), fn, "log Action") != set(
        AUTHORITY_RUNTIME_LOG_ACTIONS
    ) or _authority_string_set(log_stmt.get("Resource"), fn, "log Resource") != {
        expected_log
    }:
        raise ContractError(f"{fn} own-log statement drifted")
    _check_authority_dynamodb_decrypt(by_sid["AuthorityDynamoDBDecrypt"], fn)

    reads = by_sid["AuthorityReads"]
    expected_read_resources = set().union(
        *(AUTHORITY_RUNTIME_TABLE_RESOURCES[table] for table in spec["read_tables"])
    )
    if _authority_string_set(reads.get("Action"), fn, "read Action") != set(
        AUTHORITY_RUNTIME_DYNAMODB_READ_ACTIONS
    ) or _authority_string_set(
        reads.get("Resource"), fn, "read Resource"
    ) != expected_read_resources:
        raise ContractError(f"{fn} read actions/resources drifted")

    for sid, (actions, resources) in spec["writes"].items():
        stmt = by_sid[sid]
        if _authority_string_set(stmt.get("Action"), fn, sid) != set(
            actions
        ) or _authority_string_set(stmt.get("Resource"), fn, sid) != set(resources):
            raise ContractError(f"{fn} {sid} actions/resources drifted")

    if spec["public_key"]:
        public_key = by_sid["Qat1PublicKey"]
        if _authority_string_set(public_key.get("Action"), fn, "Qat1PublicKey") != {
            "kms:GetPublicKey"
        }:
            raise ContractError(f"{fn} qat1 public-key action drifted")
        resources = _authority_string_set(
            public_key.get("Resource"), fn, "Qat1PublicKey"
        )
        if (
            len(resources) != 1
            or _QAT1_KEY_ARN_RE.fullmatch(next(iter(resources))) is None
        ):
            raise ContractError(f"{fn} qat1 public-key resource drifted")

    otp_user = spec["otp_user"]
    if otp_user is not None:
        secret_read = by_sid["OTPSecretRead"]
        if _authority_string_set(
            secret_read.get("Action"), fn, "OTPSecretRead"
        ) != {"secretsmanager:GetSecretValue"}:
            raise ContractError(f"{fn} OTP secret read action drifted")
        secret_resources = _authority_string_set(
            secret_read.get("Resource"), fn, "OTPSecretRead"
        )
        if (
            len(secret_resources) != 1
            or _AUTHORITY_OTP_SECRET_ARN_RE.fullmatch(next(iter(secret_resources)))
            is None
        ):
            raise ContractError(f"{fn} OTP secret resource drifted")
        decrypt = by_sid["OTPSecretDecrypt"]
        decrypt_resources = _authority_string_set(
            decrypt.get("Resource"), fn, "OTPSecretDecrypt"
        )
        if _authority_string_set(
            decrypt.get("Action"), fn, "OTPSecretDecrypt"
        ) != {"kms:Decrypt"} or (
            len(decrypt_resources) != 1
            or _AUTHORITY_DATA_KEY_ARN_RE.fullmatch(next(iter(decrypt_resources)))
            is None
        ):
            raise ContractError(f"{fn} OTP secret decrypt grant drifted")
        condition = decrypt.get("Condition")
        if (
            not isinstance(condition, dict)
            or set(condition) != {"StringEquals"}
            or not isinstance(condition["StringEquals"], dict)
            or set(condition["StringEquals"])
            != {
                "kms:ViaService",
                "kms:EncryptionContext:SecretARN",
            }
            or condition["StringEquals"].get("kms:ViaService")
            != f"secretsmanager.{AWS_REGION}.amazonaws.com"
            or _AUTHORITY_OTP_SECRET_ARN_RE.fullmatch(
                str(
                    condition["StringEquals"].get(
                        "kms:EncryptionContext:SecretARN", ""
                    )
                )
            )
            is None
        ):
            raise ContractError(f"{fn} OTP decrypt condition drifted")
        redis = by_sid["OTPRedisConnect"]
        if _authority_string_set(redis.get("Action"), fn, "OTPRedisConnect") != {
            "elasticache:Connect"
        } or _authority_string_set(redis.get("Resource"), fn, "OTPRedisConnect") != {
            AUTHORITY_RUNTIME_REDIS_CACHE_ARN,
            AUTHORITY_RUNTIME_REDIS_USER_ARNS[otp_user],
        }:
            raise ContractError(f"{fn} Redis IAM grant drifted")

    if spec["sends_email"]:
        email = by_sid["OTPSendEmail"]
        if _authority_string_set(email.get("Action"), fn, "OTPSendEmail") != {
            "ses:SendEmail"
        } or _authority_string_set(
            email.get("Resource"), fn, "OTPSendEmail"
        ) != set(AUTHORITY_RUNTIME_SES_RESOURCES):
            raise ContractError(f"{fn} SES grant drifted")


def _authority_alarm_actions(after: dict[str, Any], address: str) -> list[str]:
    """The alarm's operator destinations, rejected unless exactly reviewed.

    An alarm with no action is silent on a real fault while presenting a green
    OK in the console, and a wildcard destination is not a destination at all.
    Both fail closed here rather than being reported as coverage.
    """
    actions = after.get("alarm_actions")
    if isinstance(actions, (set, frozenset)):
        actions = sorted(actions)
    if not isinstance(actions, list) or not actions:
        raise ContractError(f"{address} must carry at least one operator alarm action")
    for action in actions:
        if not isinstance(action, str) or not re.fullmatch(
            rf"arn:aws:sns:{AWS_REGION}:{ACCOUNT_ID}:[A-Za-z0-9_-]{{1,256}}", action
        ):
            raise ContractError(
                f"{address} alarm action {action!r} must be an exact in-account, "
                "in-region SNS topic ARN; wildcard and partial ARNs are rejected"
            )
    return sorted(actions)


def _authority_alarm_statistic(after: dict[str, Any], field: str) -> Any:
    """One alarm statistic field, with the provider's unset rendering normalized.

    `statistic` and `extended_statistic` are mutually exclusive optional strings:
    every alarm in this set declares exactly one and leaves the other `null`. A
    CREATION plan renders the unset one straight from config as `null`, but the
    applied state that a steady-state plan refreshes from holds the AWS
    provider's read-back of an absent optional string, which is `""`. Both spell
    "this alarm does not carry that statistic", and this checker runs on both
    lanes, so they must compare equal.

    Only that one equivalence is admitted. A wrong statistic still fails, and an
    unset field where the reviewed shape requires a value still fails, because
    the normalized `None` never equals a required `"Sum"`/`"p99"`.
    """
    value = after.get(field)
    return None if value == "" else value


def _check_authority_alarm_routing(
    by_address: dict[str, dict[str, Any]], functions: dict[str, Any]
) -> None:
    """Validate operator routing, dim sets, and thresholds for every alarm.

    Fails closed on the four regressions NHP #3455 names: a missing or wildcard
    operator destination, a function omitted from any per-function alarm family,
    a weakened threshold, and a dimension set the publisher does not emit.
    """
    expected = set().union(
        *(
            AUTHORITY_ALARM_ADDRESSES_BY_FUNCTION[fn]
            for fn in functions
            if fn in AUTHORITY_ALARM_ADDRESSES_BY_FUNCTION
        )
    )
    if set(functions) not in (
        set(AUTHORITY_RUNTIME_FUNCTIONS),
        set(AUTHORITY_RUNTIME_FUNCTIONS_WITH_PROOF),
    ):
        raise ContractError("Authority alarm function graph is not exact")
    present = {address for address in expected if address in by_address}
    if present != expected:
        missing = sorted(expected - present)
        raise ContractError(
            f"Authority alarm coverage is incomplete; missing={missing}"
        )

    destinations: set[tuple[str, ...]] = set()
    for address in sorted(expected):
        after = _authority_runtime_after(by_address, address)
        destinations.add(tuple(_authority_alarm_actions(after, address)))

        expected_dimensions = AUTHORITY_ALARM_DIMENSIONS.get(address)
        if expected_dimensions is None:
            # Composite alarms select their children by name, not by dimension.
            continue
        if after.get("dimensions") != expected_dimensions:
            raise ContractError(
                f"{address} must key on exactly {expected_dimensions}; a partial "
                "or extra dimension selects a stream the publisher never emits"
            )
        if after.get("treat_missing_data") != "notBreaching":
            raise ContractError(
                f"{address} must treat missing data as notBreaching; every metric "
                "here is a zero-baseline counter that publishes nothing when idle"
            )
        namespace = (
            AUTHORITY_ALARM_NAMESPACE_LAMBDA
            if set(expected_dimensions) == {"FunctionName"}
            else AUTHORITY_ALARM_NAMESPACE_CUSTOM
        )
        if after.get("namespace") != namespace:
            raise ContractError(f"{address} must publish against {namespace}")
        if namespace == AUTHORITY_ALARM_NAMESPACE_CUSTOM:
            # Every custom EMF alarm is a zero-baseline fault counter; a
            # nonzero threshold silently tolerates the fault it exists to page.
            if (
                after.get("statistic") != "Sum"
                or after.get("comparison_operator") != "GreaterThanThreshold"
                or after.get("threshold") != 0
            ):
                raise ContractError(
                    f"{address} must stay a zero-tolerance Sum counter; a "
                    "weakened threshold is a silent loss of coverage"
                )

    # Every alarm must reach the SAME reviewed destination set; a split routing
    # is how one family quietly stops paging.
    if len(destinations) != 1:
        raise ContractError(
            "every Connector Authority alarm must route to the identical "
            f"reviewed operator destination set; got {sorted(destinations)}"
        )

    for fn in functions:
        spillover_address = (
            "module.control.aws_cloudwatch_metric_alarm."
            f'authority_spillover["{fn}"]'
        )
        spillover_after = _authority_runtime_after(by_address, spillover_address)
        if (
            spillover_after.get("metric_name")
            != "ProvisionedConcurrencySpilloverInvocations"
            or spillover_after.get("statistic") != "Sum"
            or spillover_after.get("comparison_operator") != "GreaterThanThreshold"
            or spillover_after.get("threshold") != 0
        ):
            raise ContractError(
                f"{spillover_address} must stay the zero-tolerance spillover guard"
            )

        for family, (
            metric_name,
            statistic,
            extended_statistic,
            comparison,
            threshold,
        ) in AUTHORITY_ALARM_LAMBDA_FAMILIES.items():
            address = (
                "module.control.aws_cloudwatch_metric_alarm."
                f'authority_runtime["{fn}:{family}"]'
            )
            after = _authority_runtime_after(by_address, address)
            if (
                after.get("metric_name") != metric_name
                or _authority_alarm_statistic(after, "statistic") != statistic
                or _authority_alarm_statistic(after, "extended_statistic")
                != extended_statistic
                or after.get("comparison_operator") != comparison
            ):
                raise ContractError(
                    f"{address} must stay the reviewed {metric_name} alarm shape"
                )
            expected_threshold = threshold
            if expected_threshold is None:
                # Concurrency exhaustion is pinned to the bound contract's
                # steady reserved envelope, never a hand-typed number.
                spec = functions.get(fn)
                expected_threshold = (
                    spec.get("steady_reserved_concurrency")
                    if isinstance(spec, dict)
                    else None
                )
            if expected_threshold is None or after.get("threshold") != (
                expected_threshold
            ):
                raise ContractError(
                    f"{address} threshold must be exactly {expected_threshold}; a "
                    "weakened threshold is a silent loss of coverage"
                )

        composite_address = (
            "module.control.aws_cloudwatch_composite_alarm."
            f'authority_non_provisioned_initialization["{fn}"]'
        )
        composite_after = _authority_runtime_after(by_address, composite_address)
        expected_rule = (
            f'ALARM("{fn}-provisioned-concurrency-spillover") '
            f'AND ALARM("{fn}-errors")'
        )
        if composite_after.get("alarm_rule") != expected_rule:
            raise ContractError(
                f"{composite_address} must be exactly the conjunction of the "
                "published spillover and Errors alarms; the non-provisioned "
                "initialization event has no emitted metric of its own"
            )


def _check_authority_runtime_resources(
    by_address: dict[str, dict[str, Any]], foundation: dict[str, Any]
) -> None:
    """Validate the runtime resource security fields against the bound contract.

    Runs on every runtime-inventory plan (the creation transition and the steady
    post-slice state). The exhaustive per-field create envelope is a POST-STEP-3
    calibration; these are the security-load-bearing, plan-known fields.
    """
    payload = foundation.get("input")
    contract = payload.get("authority_runtime_contract") if isinstance(payload, dict) else None
    functions = contract.get("functions") if isinstance(contract, dict) else None
    image_uri = payload.get("authority_image_uri") if isinstance(payload, dict) else None
    selected = contract.get("selected_authority_color") if isinstance(contract, dict) else None
    rollout_colors = _authority_proof_rollout_colors(foundation)
    proof_rollout = rollout_colors is not None
    if not isinstance(functions, dict) or selected not in ("blue", "green"):
        raise ContractError("runtime slice cannot resolve the bound contract functions")

    operations = (
        AUTHORITY_RUNTIME_FUNCTIONS_WITH_PROOF
        if set(AUTHORITY_PROOF_FUNCTIONS).issubset(functions)
        else AUTHORITY_RUNTIME_FUNCTIONS
    )
    for fn, _operation in operations.items():
        spec = functions.get(fn)
        if not isinstance(spec, dict):
            raise ContractError(f"runtime function {fn} is absent from the bound contract")

        function_after = _authority_runtime_after(
            by_address, f'module.control.aws_lambda_function.authority["{fn}"]'
        )
        if function_after.get("package_type") != "Image":
            raise ContractError(f"{fn} must be Image-packaged")
        if function_after.get("image_uri") != image_uri:
            raise ContractError(f"{fn} image_uri must be the contract-pinned repository@digest")
        expected_description = (
            "Connector Authority mutate_proof_agent "
            f"(sandbox; proof-policy-prepared={rollout_colors[1]})"
            if proof_rollout and fn == AUTHORITY_PROOF_FUNCTION_NAME
            else f"Connector Authority {_operation} (sandbox)"
        )
        if function_after.get("description") != expected_description:
            raise ContractError(f"{fn} immutable rollout description drifted")
        proof_rollout_function = fn in AUTHORITY_PROOF_ROLLOUT_FUNCTIONS
        expected_reserved = spec.get(
            "rollout_reserved_concurrency"
            if proof_rollout and proof_rollout_function
            else "steady_reserved_concurrency"
        )
        if function_after.get("reserved_concurrent_executions") != expected_reserved:
            raise ContractError(
                f"{fn} reserved concurrency does not match its retained envelope"
            )
        vpc_config = function_after.get("vpc_config")
        if not isinstance(vpc_config, list) or len(vpc_config) != 1:
            raise ContractError(f"{fn} must be attached to exactly the isolated VPC config")

        provisioned_after = _authority_runtime_after(
            by_address,
            f'module.control.aws_lambda_provisioned_concurrency_config.authority["{fn}"]',
        )
        expected_provisioned = spec.get(
            "rollout_active_provisioned_concurrency"
            if proof_rollout and proof_rollout_function
            else "steady_provisioned_concurrency"
        )
        if (
            provisioned_after.get("provisioned_concurrent_executions")
            != expected_provisioned
        ):
            raise ContractError(
                f"{fn} provisioned concurrency does not match its retained envelope"
            )
        if provisioned_after.get("qualifier") not in (selected, None):
            raise ContractError(f"{fn} provisioned concurrency must target the selected color")
        if proof_rollout and proof_rollout_function:
            standby_after = _authority_runtime_after(
                by_address,
                (
                    "module.control.aws_lambda_provisioned_concurrency_config."
                    f'authority_proof_standby["{fn}"]'
                ),
            )
            if (
                standby_after.get("qualifier") not in ("green", None)
                or standby_after.get("provisioned_concurrent_executions")
                != spec.get("rollout_standby_provisioned_concurrency")
            ):
                raise ContractError(
                    f"{fn} standby provisioned concurrency is not exact green READY capacity"
                )

        _check_authority_exec_role_trust(
            _authority_runtime_after(
                by_address, f'module.control.aws_iam_role.authority_exec["{fn}"]'
            ),
            fn,
        )
        _check_authority_exec_role_policy(
            _authority_runtime_after(
                by_address,
                f'module.control.aws_iam_role_policy.authority_exec["{fn}"]',
            ),
            fn,
            _operation,
            proof_policy_consumer=(
                payload.get("authority_proof_policy_consumers_staged") is True
                and _operation
                in {
                    "issue_assignment",
                    "refresh_assignment",
                    "issue_credential_recovery",
                }
            ),
        )

        for color in ("blue", "green"):
            alias_after = _authority_runtime_after(
                by_address, f'module.control.aws_lambda_alias.authority["{fn}:{color}"]'
            )
            if alias_after.get("name") != color:
                raise ContractError(f"{fn} {color} alias name drifted")

        if function_after.get("dead_letter_config") not in (None, []):
            raise ContractError(
                f"{fn} may not declare a dead_letter_config; the Authority is a "
                "synchronous RequestResponse contract"
            )

    proof_environment = {
        "CONNECTOR_AUTHORITY_PROOF_OWNER_ID": AUTHORITY_PROOF_OWNER_ID,
        "CONNECTOR_AUTHORITY_PROOF_AGENT_ID_PREFIX": "qurl-go-sandbox-",
    }
    proof_environment_functions = set(AUTHORITY_PROOF_FUNCTIONS)
    if payload.get("authority_proof_policy_consumers_staged") is True:
        proof_environment_functions.update(
            {
                "layerv-nhp-sandbox-ca-ia",
                "layerv-nhp-sandbox-ca-ra",
                "layerv-nhp-sandbox-ca-icr",
            }
        )
    for fn in operations:
        function_after = _authority_runtime_after(
            by_address, f'module.control.aws_lambda_function.authority["{fn}"]'
        )
        environment = function_after.get("environment")
        variables = (
            environment[0].get("variables")
            if isinstance(environment, list)
            and len(environment) == 1
            and isinstance(environment[0], dict)
            and isinstance(environment[0].get("variables"), dict)
            else {}
        )
        observed = {
            key: value
            for key, value in variables.items()
            if key.startswith("CONNECTOR_AUTHORITY_PROOF_")
        }
        expected = (
            {
                **proof_environment,
                **(
                    {
                        "CONNECTOR_AUTHORITY_PROOF_DIRECTIVE_TTL": "5400",
                        "CONNECTOR_AUTHORITY_PROOF_MIN_LEASE_SECONDS": "30",
                    }
                    if fn != AUTHORITY_PROOF_RECOVERY_FUNCTION_NAME
                    else {}
                ),
            }
            if set(AUTHORITY_PROOF_FUNCTIONS).issubset(functions)
            and fn in proof_environment_functions
            else {}
        )
        if observed != expected:
            raise ContractError(f"{fn} attended-proof environment fence drifted")

    # The controller invoke grant that used to be validated here is gone. It
    # managed an inline policy on layerv-nhp-sandbox-udp-proof-controller, a
    # role owned by the separate udp-proof-runner root; destroying that root
    # (#3804) left it pointing at a role AWS reports as NoSuchEntity, so the
    # module released it through a `removed` block. There is no grant left to
    # pin -- and no caller either, the runner workflow was removed with its App
    # credentials revoked (#3806).

    _check_authority_alarm_routing(by_address, functions)

    lambda_sg_change = by_address[AUTHORITY_RUNTIME_LAMBDA_SG_ADDRESS]["change"]
    lambda_sg_after = _authority_runtime_after(
        by_address, AUTHORITY_RUNTIME_LAMBDA_SG_ADDRESS
    )
    lambda_sg_unknown = lambda_sg_change.get("after_unknown")
    if not isinstance(lambda_sg_unknown, dict):
        lambda_sg_unknown = {}
    lambda_sg_before = lambda_sg_change.get("before")
    if not isinstance(lambda_sg_before, dict):
        lambda_sg_before = {}
    if lambda_sg_after.get("name_prefix") != f"{CONTROL_PREFIX}-ca-fn-v2-":
        raise ContractError(
            "function SG must be generation 2 with no inline ingress or egress"
        )
    # Nothing dials the functions on the network path, so ingress stays empty
    # in every state; a populated one is a real posture change, not drift.
    if lambda_sg_after.get("ingress") not in ([], None):
        raise ContractError(
            "function SG must be generation 2 with no inline ingress or egress"
        )
    # `egress` is Optional+Computed. The generation-2 SG declares no inline
    # block, so a REFRESHED plan reports the standalone rules AWS actually
    # holds -- exactly the three aws_vpc_security_group_egress_rule resources
    # contract-checked below. Demanding an empty list here was only ever
    # satisfiable on the creating plan, so this check began failing every plan
    # the moment the slice applied and the rules existed. The load-bearing
    # property in the steady state is not emptiness but that THIS plan does not
    # rewrite the attribute: an inline block (even `egress = []`) without
    # `ignore_changes` would show up here as a revoking diff, which is the
    # first-apply-vs-refresh trap documented on modules/bootstrap-alb's SG.
    def _sg_rule_set(value: Any) -> list[Any]:
        # Terraform encodes "no rules" as both `[]` and an absent/None key
        # depending on whether the attribute was ever written; normalize so the
        # comparison reports real rule changes rather than encoding changes.
        return value if isinstance(value, list) else []

    lambda_sg_actions = lambda_sg_change.get("actions")
    if not isinstance(lambda_sg_actions, list):
        lambda_sg_actions = []
    if "create" in lambda_sg_actions:
        # Creating the group, including the generation-1 -> generation-2
        # replacement, where `before` describes the OUTGOING legacy group and
        # so cannot be compared against. A freshly created generation-2 group
        # declares no rules: they are empty, or unknown until the standalone
        # rules apply.
        if lambda_sg_after.get("egress") not in ([], None) and (
            lambda_sg_unknown.get("egress") is not True
        ):
            raise ContractError(
                "function SG must be generation 2 with no inline ingress or egress"
            )
    elif _sg_rule_set(lambda_sg_after.get("egress")) != _sg_rule_set(
        lambda_sg_before.get("egress")
    ):
        raise ContractError(
            "function SG egress must not be rewritten by the security group "
            "itself; the standalone egress rules are the only owner"
        )
    lambda_sg_id = lambda_sg_after.get("id")
    lambda_sg_id_is_known = (
        isinstance(lambda_sg_id, str)
        and re.fullmatch(r"sg-[0-9a-f]+", lambda_sg_id) is not None
    )
    if not lambda_sg_id_is_known and not (
        lambda_sg_id in (None, "") and lambda_sg_unknown.get("id") is True
    ):
        raise ContractError(
            "function SG ID must be known or exactly create-time unknown"
        )
    # The exact SG ID once settled; None while create-time unknown, which the
    # reference checks treat as "matches the pending function SG".
    expected_lambda_sg_id = lambda_sg_id if lambda_sg_id_is_known else None

    def require_sg_reference(
        rule: dict[str, Any],
        unknown: dict[str, Any],
        field: str,
        expected_id: str | None,
        address: str,
    ) -> None:
        actual = rule.get(field)
        if expected_id is not None:
            if actual != expected_id:
                raise ContractError(
                    f"{address} {field} must reference the exact reviewed SG"
                )
            return
        if actual not in (None, "") or unknown.get(field) is not True:
            raise ContractError(
                f"{address} {field} must be exactly create-time unknown"
            )

    interface_address = (
        "module.control.aws_vpc_security_group_egress_rule."
        "authority_interface_endpoints[0]"
    )
    interface_sg = _authority_runtime_after(
        by_address, AUTHORITY_RUNTIME_INTERFACE_SG_ADDRESS
    )
    interface_sg_id = interface_sg.get("id")
    if (
        not isinstance(interface_sg_id, str)
        or re.fullmatch(r"sg-[0-9a-f]+", interface_sg_id) is None
    ):
        raise ContractError("interface-endpoint SG ID must be known in the runtime plan")
    interface_change = by_address[interface_address]["change"]
    interface_unknown = interface_change.get("after_unknown")
    if not isinstance(interface_unknown, dict):
        interface_unknown = {}
    interface_rule = _authority_runtime_after(by_address, interface_address)
    if (
        interface_rule.get("description") != "HTTPS to Control interface endpoints"
        or interface_rule.get("from_port") != 443
        or interface_rule.get("to_port") != 443
        or interface_rule.get("ip_protocol") != "tcp"
        or interface_rule.get("cidr_ipv4") not in (None, "")
        or interface_rule.get("cidr_ipv6") not in (None, "")
        or interface_rule.get("prefix_list_id") not in (None, "")
        or interface_rule.get("referenced_security_group_id") != interface_sg_id
    ):
        raise ContractError(
            f"{interface_address} must be exact interface-endpoint-SG HTTPS egress"
        )
    require_sg_reference(
        interface_rule,
        interface_unknown,
        "security_group_id",
        expected_lambda_sg_id,
        interface_address,
    )

    dynamodb_address = (
        "module.control.aws_vpc_security_group_egress_rule.authority_dynamodb[0]"
    )
    dynamodb_change = by_address.get(dynamodb_address, {}).get("change", {})
    dynamodb_unknown = dynamodb_change.get("after_unknown")
    if not isinstance(dynamodb_unknown, dict):
        dynamodb_unknown = {}
    dynamodb_rule = _authority_runtime_after(by_address, dynamodb_address)
    prefix_list_is_exact = (
        isinstance(dynamodb_rule.get("prefix_list_id"), str)
        and re.fullmatch(r"pl-[0-9a-f]+", dynamodb_rule["prefix_list_id"]) is not None
    ) or (
        dynamodb_rule.get("prefix_list_id") in (None, "")
        and dynamodb_unknown.get("prefix_list_id") is True
    )
    if (
        dynamodb_rule.get("description") != "HTTPS to the DynamoDB gateway endpoint"
        or dynamodb_rule.get("from_port") != 443
        or dynamodb_rule.get("to_port") != 443
        or dynamodb_rule.get("ip_protocol") != "tcp"
        or dynamodb_rule.get("cidr_ipv4") not in (None, "")
        or dynamodb_rule.get("cidr_ipv6") not in (None, "")
        or dynamodb_rule.get("referenced_security_group_id") not in (None, "")
        or not prefix_list_is_exact
    ):
        raise ContractError(
            f"{dynamodb_address} must be exact DynamoDB-prefix-list HTTPS egress"
        )
    require_sg_reference(
        dynamodb_rule,
        dynamodb_unknown,
        "security_group_id",
        expected_lambda_sg_id,
        dynamodb_address,
    )

    otp_redis_sg_after = _authority_runtime_after(
        by_address, "module.control.aws_security_group.otp_redis"
    )
    otp_redis_sg_id = otp_redis_sg_after.get("id")
    if (
        not isinstance(otp_redis_sg_id, str)
        or re.fullmatch(r"sg-[0-9a-f]+", otp_redis_sg_id) is None
    ):
        raise ContractError("OTP Redis SG ID must be known in the runtime plan")

    for address, description, source_sg_id, referenced_sg_id in (
        (
            "module.control.aws_vpc_security_group_egress_rule.authority_otp_redis[0]",
            "TLS to Connector OTP Redis",
            expected_lambda_sg_id,
            otp_redis_sg_id,
        ),
        (
            "module.control.aws_vpc_security_group_ingress_rule.otp_redis_authority[0]",
            "TLS from Connector Authority OTP functions",
            otp_redis_sg_id,
            expected_lambda_sg_id,
        ),
    ):
        change = by_address.get(address, {}).get("change", {})
        rule = _authority_runtime_after(by_address, address)
        unknown = change.get("after_unknown")
        if not isinstance(unknown, dict):
            unknown = {}
        if (
            rule.get("description") != description
            or rule.get("from_port") != 6379
            or rule.get("to_port") != 6379
            or rule.get("ip_protocol") != "tcp"
            or rule.get("cidr_ipv4") not in (None, "")
            or rule.get("cidr_ipv6") not in (None, "")
            or rule.get("prefix_list_id") not in (None, "")
        ):
            raise ContractError(
                f"{address} must be the exact SG-to-SG Redis TLS/6379 rule"
            )
        require_sg_reference(rule, unknown, "security_group_id", source_sg_id, address)
        require_sg_reference(
            rule,
            unknown,
            "referenced_security_group_id",
            referenced_sg_id,
            address,
        )


def _has_unknown_value(value: Any) -> bool:
    if value is True:
        return True
    if isinstance(value, dict):
        return any(_has_unknown_value(item) for item in value.values())
    if isinstance(value, list):
        return any(_has_unknown_value(item) for item in value)
    return False


def _mapping_shape(value: dict[str, Any]) -> dict[str, Any]:
    """Return Terraform's value-free object mask for a dynamic value."""
    return {
        key: _mapping_shape(item)
        for key, item in value.items()
        if isinstance(item, dict)
    }


def _authority_basis_evidence(payload: dict[str, Any]) -> list[dict[str, Any]]:
    contract = payload["authority_runtime_contract"]
    # Enumerate every function the contract carries, not just the Hub-facing
    # ones. _require_authority_runtime_binding requires basis evidence to be
    # identical across ALL functions, so any function the contract carries must
    # also satisfy the reviewed FROM/TO evidence pins. Enumerating only the Hub
    # functions would leave a contract that carries more (this repository's
    # expanded 3 + 4N graph) with its per-cell basis_evidence unpinned by the
    # image-update checks. Every object this adds must match the reviewed pins,
    # so the wider enumeration is strictly fail-closed. Note this is independent
    # of AUTHORITY_IMAGE_UPDATE_RESOURCES, which stays Hub-only because only the
    # live Hub resources can be retagged; here the concern is evidence coverage
    # of the contract, not membership of the admitted action set.
    return [
        contract["provisioned_cells_evidence"],
        contract["global"]["basis_evidence"],
        *(
            contract["functions"][function_name]["basis_evidence"]
            for function_name in sorted(contract["functions"])
        ),
    ]


def _check_authority_image_foundation_update(
    by_address: dict[str, dict[str, Any]],
) -> None:
    """Validate the exact reviewed foundation input/evidence migration."""
    item = by_address[AUTHORITY_IMAGE_UPDATE_FOUNDATION_ADDRESS]
    change = item.get("change")
    if (
        item.get("mode") != "managed"
        or item.get("type") != "terraform_data"
        or not isinstance(change, dict)
        or set(change) != _CHANGE_KEYS
        or change.get("actions") != ["update"]
    ):
        raise ContractError("Authority image foundation update envelope is not exact")

    before = change.get("before")
    after = change.get("after")
    if (
        not isinstance(before, dict)
        or set(before) != {"id", "input", "output", "triggers_replace"}
        or not isinstance(after, dict)
        or set(after) != {"id", "input", "triggers_replace"}
        or not isinstance(before.get("id"), str)
        or re.fullmatch(
            r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}",
            before["id"],
        )
        is None
        or after.get("id") != before["id"]
        or before.get("triggers_replace") is not None
        or after.get("triggers_replace") is not None
    ):
        raise ContractError(
            "Authority image foundation id/triggers envelope is not exact"
        )

    before_input = before.get("input")
    before_output = before.get("output")
    after_input = after.get("input")
    if (
        not isinstance(before_input, dict)
        or not isinstance(before_output, dict)
        or not isinstance(after_input, dict)
        or not _json_equal(before_input, before_output)
        or not _require_authority_runtime_binding({"input": before_input})
        or not _require_authority_runtime_binding({"input": after_input})
    ):
        raise ContractError(
            "Authority image foundation input/output binding is not exact"
        )

    before_contract = before_input["authority_runtime_contract"]
    after_contract = after_input["authority_runtime_contract"]

    # Under publish tracking there is no enumerated migration to match: the
    # digest advances whenever qurl-service publishes, which is the point. The
    # invariant becomes narrower AND stronger than the pinned one -- the image
    # uri is the only field permitted to differ at all, and both sides must be
    # immutable digest references.
    if _authority_image_tracks_publish(after_contract):
        before_uri = before_input.get("authority_image_uri")
        after_uri = after_input.get("authority_image_uri")
        for label, uri in (("before", before_uri), ("after", after_uri)):
            if not isinstance(uri, str) or _AUTHORITY_IMAGE_URI_PATTERN.fullmatch(uri) is None:
                raise ContractError(
                    f"Authority image foundation {label} uri is not an immutable "
                    "repository@sha256 reference"
                )
        if after_contract["global"].get("authority_image_digest") is not None:
            raise ContractError(
                "publish-tracking contract must not also name a basis digest"
            )
        # One reconstruction covers both shapes of this update, and refuses
        # everything else. In steady state the before side already tracks
        # publishes, so the pop and the set are no-ops and only the image uri
        # may differ. On the one-time migration the before side is the pinned
        # or pre-key contract, so exactly two things change: the digest goes and
        # the source arrives. Any other field moving still fails byte-equality.
        #
        # The uris are deliberately NOT required to differ. The migration can
        # land on the digest already deployed, and demanding a change would
        # refuse the safest possible version of it.
        # Basis evidence necessarily moves with this migration: switching the
        # source EDITS the basis manifest, so its sha256 and blob-owning commit
        # change. Admitting that is not a loosening, because the evidence is
        # first required to be uniform and well formed across every object the
        # contract carries, and it is then copied into the reconstruction -- so
        # evidence may move, and nothing else may.
        after_evidence = _authority_basis_evidence(after_input)
        witness = after_evidence[0] if after_evidence else None
        if not isinstance(witness, dict) or any(
            not isinstance(evidence, dict)
            or evidence.get("repository") != "layervai/nhp"
            or evidence.get("path")
            != "docs/evidence/connector-authority/v1/sandbox-measurement-basis.json"
            or evidence.get("schema_version") != 1
            or not isinstance(evidence.get("sha256"), str)
            or re.fullmatch(r"[0-9a-f]{64}", evidence["sha256"]) is None
            or not isinstance(evidence.get("source_commit"), str)
            or re.fullmatch(r"[0-9a-f]{40}", evidence["source_commit"]) is None
            or evidence.get("sha256") != witness.get("sha256")
            or evidence.get("source_commit") != witness.get("source_commit")
            for evidence in after_evidence
        ):
            raise ContractError(
                "Authority image foundation basis evidence is not uniform and well formed"
            )
        expected_after = copy.deepcopy(before_input)
        expected_after["authority_image_uri"] = after_uri
        expected_global = expected_after["authority_runtime_contract"]["global"]
        expected_global.pop("authority_image_digest", None)
        expected_global["authority_image_source"] = "publish_parameter"
        for evidence in _authority_basis_evidence(expected_after):
            evidence["sha256"] = witness["sha256"]
            evidence["source_commit"] = witness["source_commit"]
        if not _json_equal(after_input, expected_after):
            raise ContractError(
                "Authority image foundation update changed an unrelated contract field"
            )
        _check_authority_image_foundation_envelope(change, after_contract)
        return

    before_evidence = _authority_basis_evidence(before_input)
    after_evidence = _authority_basis_evidence(after_input)
    after_source = after_evidence[0].get("source_commit")
    if (
        before_input.get("authority_image_uri") != AUTHORITY_IMAGE_UPDATE_FROM_URI
        or before_contract["global"].get("authority_image_digest")
        != AUTHORITY_IMAGE_UPDATE_FROM_URI.rsplit("@", 1)[1]
        or any(
            evidence.get("sha256")
            != AUTHORITY_IMAGE_UPDATE_FROM_EVIDENCE_SHA256
            or evidence.get("source_commit")
            != AUTHORITY_IMAGE_UPDATE_FROM_EVIDENCE_SOURCE
            for evidence in before_evidence
        )
        or after_input.get("authority_image_uri") != AUTHORITY_IMAGE_UPDATE_TO_URI
        or after_contract["global"].get("authority_image_digest")
        != AUTHORITY_IMAGE_UPDATE_TO_URI.rsplit("@", 1)[1]
        or after_source != AUTHORITY_IMAGE_UPDATE_TO_EVIDENCE_SOURCE
        or any(
            evidence.get("sha256")
            != AUTHORITY_IMAGE_UPDATE_TO_EVIDENCE_SHA256
            or evidence.get("source_commit") != after_source
            for evidence in after_evidence
        )
    ):
        raise ContractError(
            "Authority image foundation is not the exact reviewed "
            "image/evidence migration"
        )

    expected_after = copy.deepcopy(before_input)
    expected_after["authority_image_uri"] = AUTHORITY_IMAGE_UPDATE_TO_URI
    expected_after_contract = expected_after["authority_runtime_contract"]
    expected_after_contract["global"]["authority_image_digest"] = (
        AUTHORITY_IMAGE_UPDATE_TO_URI.rsplit("@", 1)[1]
    )
    for evidence in _authority_basis_evidence(expected_after):
        evidence["sha256"] = AUTHORITY_IMAGE_UPDATE_TO_EVIDENCE_SHA256
        evidence["source_commit"] = after_source
    if not _json_equal(after_input, expected_after):
        raise ContractError(
            "Authority image foundation migration changed an unrelated contract field"
        )

    _check_authority_image_foundation_envelope(change, after_contract)


def _check_authority_image_foundation_envelope(
    change: dict[str, Any], after_contract: Any
) -> None:
    """Shared by both image sources; the envelope shape does not depend on one."""
    contract_shape = _mapping_shape(after_contract)
    expected_unknown = {
        "input": {"authority_runtime_contract": contract_shape},
        "output": True,
    }
    expected_before_sensitive = {
        "input": {"authority_runtime_contract": contract_shape},
        "output": {"authority_runtime_contract": contract_shape},
    }
    expected_after_sensitive = {
        "input": {"authority_runtime_contract": contract_shape},
        "output": {},
    }
    if (
        change.get("after_unknown") != expected_unknown
        or change.get("before_sensitive") != expected_before_sensitive
        or change.get("after_sensitive") != expected_after_sensitive
    ):
        raise ContractError(
            "Authority image foundation unknown/sensitive envelope is not exact"
        )


def _check_authority_image_foundation_noop(
    by_address: dict[str, dict[str, Any]],
) -> None:
    """Require the already-applied foundation to be the exact target no-op."""
    item = by_address[AUTHORITY_IMAGE_UPDATE_FOUNDATION_ADDRESS]
    change = item.get("change")
    if (
        item.get("mode") != "managed"
        or item.get("type") != "terraform_data"
        or not isinstance(change, dict)
        or set(change) != _CHANGE_KEYS
        or change.get("actions") != ["no-op"]
        or change.get("after_unknown") != {}
    ):
        raise ContractError(
            "Authority image recovery foundation no-op envelope is not exact"
        )
    before = change.get("before")
    after = change.get("after")
    if (
        not isinstance(before, dict)
        or set(before) != {"id", "input", "output", "triggers_replace"}
        or not isinstance(after, dict)
        or not _json_equal(before, after)
        or not isinstance(after.get("id"), str)
        or re.fullmatch(
            r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}",
            after["id"],
        )
        is None
        or after.get("triggers_replace") is not None
        or not isinstance(after.get("input"), dict)
        or not _json_equal(after.get("input"), after.get("output"))
        or not _require_authority_runtime_binding({"input": after["input"]})
    ):
        raise ContractError(
            "Authority image recovery foundation value is not the exact target no-op"
        )
    payload = after["input"]
    contract = payload["authority_runtime_contract"]
    evidence_objects = _authority_basis_evidence(payload)
    if _authority_image_tracks_publish(contract):
        # No enumerated target to bind to: the deployed digest is whatever was
        # published. What must still hold is that it is an immutable reference
        # and that the contract names no competing digest. Basis evidence is the
        # generator's responsibility -- it derives it from the committed
        # manifest -- so pinning it to a constant here would just go stale.
        uri = payload.get("authority_image_uri")
        if (
            not isinstance(uri, str)
            or _AUTHORITY_IMAGE_URI_PATTERN.fullmatch(uri) is None
            or contract["global"].get("authority_image_digest") is not None
        ):
            raise ContractError(
                "Authority image recovery foundation is not an immutable "
                "repository@sha256 reference under publish tracking"
            )
    elif (
        payload.get("authority_image_uri") != AUTHORITY_IMAGE_UPDATE_TO_URI
        or contract["global"].get("authority_image_digest")
        != AUTHORITY_IMAGE_UPDATE_TO_URI.rsplit("@", 1)[1]
        or any(
            evidence.get("sha256")
            != AUTHORITY_IMAGE_UPDATE_TO_EVIDENCE_SHA256
            or evidence.get("source_commit")
            != AUTHORITY_IMAGE_UPDATE_TO_EVIDENCE_SOURCE
            for evidence in evidence_objects
        )
    ):
        raise ContractError(
            "Authority image recovery foundation is not bound to target evidence"
        )
    contract_shape = _mapping_shape(contract)
    expected_sensitive = {
        "input": {"authority_runtime_contract": contract_shape},
        "output": {"authority_runtime_contract": contract_shape},
    }
    if (
        change.get("before_sensitive") != expected_sensitive
        or change.get("after_sensitive") != expected_sensitive
    ):
        raise ContractError(
            "Authority image recovery foundation sensitive envelope is not exact"
        )


def _is_exact_output_change(
    change: Any, *, actions: list[str], before: Any, after: Any
) -> bool:
    return (
        isinstance(change, dict)
        and set(change) == _CHANGE_KEYS
        and change.get("actions") == actions
        and change.get("after_unknown") is False
        and change.get("before_sensitive") is False
        and change.get("after_sensitive") is False
        and _json_equal(change.get("before"), before)
        and _json_equal(change.get("after"), after)
    )


def _check_authority_proof_enable_transition(
    plan: dict[str, Any], by_address: dict[str, dict[str, Any]]
) -> None:
    """Prove the one attended sandbox gate-off -> proof-on transition."""
    foundation_address = "module.control.terraform_data.foundation_contract"
    foundation_change = by_address[foundation_address]["change"]
    before_foundation = foundation_change.get("before")
    after_foundation = foundation_change.get("after")
    before_input = (
        before_foundation.get("input")
        if isinstance(before_foundation, dict)
        else None
    )
    after_input = (
        after_foundation.get("input")
        if isinstance(after_foundation, dict)
        else None
    )
    if (
        not isinstance(before_input, dict)
        or not isinstance(after_input, dict)
        or not _require_authority_runtime_binding(
            {"input": before_input}, proof_enabled=False
        )
        or not _require_authority_runtime_binding(
            {"input": after_input}, proof_enabled=True
        )
    ):
        raise ContractError(
            "attended-proof enablement must update the exact dark runtime binding"
        )
    stripped_after = copy.deepcopy(after_input)
    stripped_contract = stripped_after["authority_runtime_contract"]
    for function_name in AUTHORITY_PROOF_FUNCTIONS:
        stripped_contract["functions"].pop(function_name)
    stripped_contract["global"]["caller_capacity"].pop("proof_controller")
    if not _json_equal(stripped_after, before_input):
        raise ContractError(
            "attended-proof foundation update contains changes beyond the exact "
            "proof caller/function addition"
        )

    ddb_address = "module.control.aws_vpc_endpoint.dynamodb"
    ddb_change = by_address[ddb_address]["change"]
    ddb_before = ddb_change.get("before")
    ddb_after = ddb_change.get("after")
    if not isinstance(ddb_before, dict) or not isinstance(ddb_after, dict):
        raise ContractError("attended-proof DynamoDB endpoint update is malformed")
    _check_authority_dynamodb_endpoint_policy(
        ddb_before,
        ddb_address,
        proof_enabled=False,
        legacy_recovery_resources=True,
    )
    _check_authority_dynamodb_endpoint_policy(
        ddb_after, ddb_address, proof_enabled=True
    )
    if {
        key: value for key, value in ddb_before.items() if key != "policy"
    } != {
        key: value for key, value in ddb_after.items() if key != "policy"
    }:
        raise ContractError(
            "attended-proof DynamoDB endpoint may change only its exact proof "
            "principals and recovery-table resource"
        )

    output_changes = plan.get("output_changes")
    planned_outputs = plan.get("planned_values", {}).get("outputs")
    selected_color = after_input["authority_runtime_contract"][
        "selected_authority_color"
    ]
    selected_aliases = {
        output_name: (
            f"arn:aws:lambda:{AWS_REGION}:{ACCOUNT_ID}:function:"
            f"{function_name}:{selected_color}"
        )
        for function_name, output_name in AUTHORITY_PROOF_ALIAS_OUTPUTS.items()
    }
    if (
        not isinstance(output_changes, dict)
        or set(output_changes) != EXPECTED_CONTROL_OUTPUTS
        or not isinstance(planned_outputs, dict)
        or any(
            not _is_exact_nonsensitive_output_entry(planned_outputs.get(output_name))
            or planned_outputs[output_name].get("value") != selected_alias
            or not _is_exact_output_change(
                output_changes[output_name],
                actions=["create"],
                before=None,
                after=selected_alias,
            )
            for output_name, selected_alias in selected_aliases.items()
        )
    ):
        raise ContractError(
            "attended-proof enablement must create both exact selected-color "
            "proof alias outputs"
        )
    for output_name in EXPECTED_CONTROL_OUTPUTS - set(
        AUTHORITY_PROOF_ALIAS_OUTPUTS.values()
    ):
        change = output_changes[output_name]
        if (
            not isinstance(change, dict)
            or set(change) != _CHANGE_KEYS
            or change.get("actions") != ["no-op"]
            or change.get("after_unknown") is not False
            or change.get("before_sensitive") is not False
            or change.get("after_sensitive") is not False
            or not _json_equal(change.get("before"), change.get("after"))
        ):
            raise ContractError(
                f"attended-proof enablement may not change root output {output_name}"
            )


def _authority_proof_consumer_transition_addresses(
    by_address: dict[str, dict[str, Any]], *, enabling: bool
) -> set[str] | None:
    foundation = by_address.get("module.control.terraform_data.foundation_contract")
    change = foundation.get("change") if isinstance(foundation, dict) else None
    before = change.get("before") if isinstance(change, dict) else None
    after = change.get("after") if isinstance(change, dict) else None
    before_input = before.get("input") if isinstance(before, dict) else None
    after_input = after.get("input") if isinstance(after, dict) else None
    if not isinstance(before_input, dict) or not isinstance(after_input, dict):
        return None
    disabled = before_input if enabling else after_input
    enabled = after_input if enabling else before_input
    if (
        enabled.get("authority_proof_policy_consumers_staged") is not True
        or disabled.get("authority_proof_policy_consumers_staged") not in (None, False)
        or not _require_authority_runtime_binding(
            {"input": enabled}, proof_enabled=True
        )
        or not _require_authority_runtime_binding(
            {"input": disabled}, proof_enabled=True
        )
    ):
        return None
    stripped = copy.deepcopy(enabled)
    stripped.pop("authority_proof_policy_consumers_staged", None)
    if not _json_equal(stripped, disabled):
        return None
    return set(AUTHORITY_PROOF_CONSUMER_BASE_UPDATE_ADDRESSES)


def _check_authority_proof_consumer_transition(
    by_address: dict[str, dict[str, Any]], *, enabling: bool
) -> None:
    addresses = _authority_proof_consumer_transition_addresses(
        by_address, enabling=enabling
    )
    if addresses is None:
        raise ContractError("proof-policy consumer transition binding is invalid")
    for address in addresses:
        change = by_address[address]["change"]
        if change.get("actions") != ["update"]:
            raise ContractError(f"{address} must be an in-place proof-policy update")
    for function_name in AUTHORITY_PROOF_CONSUMER_FUNCTIONS:
        live_alias_addresses = {
            f'module.control.aws_lambda_alias.authority["{function_name}:blue"]',
            f'module.control.aws_lambda_alias.authority["{function_name}:green"]',
        }
        for address in live_alias_addresses:
            change = by_address[address]["change"]
            if (
                change.get("actions") != ["no-op"]
                or change.get("before") != change.get("after")
            ):
                raise ContractError(
                    f"{address} live alias must remain byte-for-byte unchanged; "
                    "consumer activation requires the separate governed rollout"
                )


def _check_authority_proof_disable_transition(
    plan: dict[str, Any], by_address: dict[str, dict[str, Any]]
) -> None:
    """Prove the exact attended sandbox proof-on -> gate-off rollback."""
    foundation_address = "module.control.terraform_data.foundation_contract"
    foundation_change = by_address[foundation_address]["change"]
    before_foundation = foundation_change.get("before")
    after_foundation = foundation_change.get("after")
    before_input = (
        before_foundation.get("input")
        if isinstance(before_foundation, dict)
        else None
    )
    after_input = (
        after_foundation.get("input")
        if isinstance(after_foundation, dict)
        else None
    )
    if (
        not isinstance(before_input, dict)
        or not isinstance(after_input, dict)
        or not _require_authority_runtime_binding(
            {"input": before_input}, proof_enabled=True
        )
        or not _require_authority_runtime_binding(
            {"input": after_input}, proof_enabled=False
        )
    ):
        raise ContractError(
            "attended-proof rollback must update the exact enabled runtime binding"
        )
    stripped_before = copy.deepcopy(before_input)
    stripped_contract = stripped_before["authority_runtime_contract"]
    for function_name in AUTHORITY_PROOF_FUNCTIONS:
        stripped_contract["functions"].pop(function_name)
    stripped_contract["global"]["caller_capacity"].pop("proof_controller")
    if not _json_equal(stripped_before, after_input):
        raise ContractError(
            "attended-proof rollback contains foundation changes beyond removing "
            "the exact proof caller/function"
        )

    ddb_address = "module.control.aws_vpc_endpoint.dynamodb"
    ddb_change = by_address[ddb_address]["change"]
    ddb_before = ddb_change.get("before")
    ddb_after = ddb_change.get("after")
    if not isinstance(ddb_before, dict) or not isinstance(ddb_after, dict):
        raise ContractError("attended-proof rollback DynamoDB endpoint is malformed")
    _check_authority_dynamodb_endpoint_policy(
        ddb_before, ddb_address, proof_enabled=True
    )
    _check_authority_dynamodb_endpoint_policy(
        ddb_after, ddb_address, proof_enabled=False
    )
    if {
        key: value for key, value in ddb_before.items() if key != "policy"
    } != {
        key: value for key, value in ddb_after.items() if key != "policy"
    }:
        raise ContractError(
            "attended-proof rollback may remove only the ca-pm/ca-pcr endpoint "
            "principals"
        )

    for address in AUTHORITY_PROOF_RESOURCES:
        item = by_address[address]
        change = item.get("change")
        if (
            item.get("deposed") is not None
            or not isinstance(change, dict)
            or change.get("actions") != ["delete"]
            or not isinstance(change.get("before"), dict)
            or change.get("after") is not None
            or change.get("after_unknown") not in (None, {})
        ):
            raise ContractError(
                f"{address} must be an exact attended-proof resource delete"
            )

    # Validate the entire enabled before-state with the same security checker
    # used for a steady proof-on graph. This binds ca-pm replay IAM, alarms,
    # execution trust, concurrency, selected invoke grant, aliases, and proof
    # environment
    # before any of it may be removed.
    before_view = copy.deepcopy(by_address)
    for address in (
        set(AUTHORITY_PROOF_RESOURCES)
        | set(AUTHORITY_PROOF_ENABLE_UPDATE_ADDRESSES)
    ):
        change = before_view[address]["change"]
        before = change.get("before")
        if not isinstance(before, dict):
            raise ContractError(
                f"{address} attended-proof rollback before-state is malformed"
            )
        change["actions"] = ["no-op"]
        change["after"] = copy.deepcopy(before)
        change["after_unknown"] = {}
    _check_authority_runtime_resources(
        before_view,
        before_view[foundation_address]["change"]["after"],
    )

    output_changes = plan.get("output_changes")
    planned_outputs = plan.get("planned_values", {}).get("outputs")
    selected_colors = _authority_proof_selected_colors(before_foundation)
    selected_aliases = {
        output_name: (
            f"arn:aws:lambda:{AWS_REGION}:{ACCOUNT_ID}:function:"
            f"{function_name}:{selected_colors[function_name]}"
        )
        for function_name, output_name in AUTHORITY_PROOF_ALIAS_OUTPUTS.items()
    }
    if (
        not isinstance(output_changes, dict)
        or set(output_changes) != EXPECTED_CONTROL_OUTPUTS
        or not isinstance(planned_outputs, dict)
        or set(planned_outputs)
        != EXPECTED_CONTROL_OUTPUTS - set(AUTHORITY_PROOF_ALIAS_OUTPUTS.values())
        or any(
            not _is_exact_output_change(
                output_changes[output_name],
                actions=["delete"],
                before=selected_alias,
                after=None,
            )
            for output_name, selected_alias in selected_aliases.items()
        )
    ):
        raise ContractError(
            "attended-proof rollback must destroy and omit only both selected "
            "proof alias outputs"
        )
    for output_name in EXPECTED_CONTROL_OUTPUTS - set(
        AUTHORITY_PROOF_ALIAS_OUTPUTS.values()
    ):
        change = output_changes[output_name]
        planned = planned_outputs.get(output_name)
        if (
            not isinstance(change, dict)
            or set(change) != _CHANGE_KEYS
            or change.get("actions") != ["no-op"]
            or change.get("after_unknown") is not False
            or change.get("before_sensitive") is not False
            or change.get("after_sensitive") is not False
            or not _json_equal(change.get("before"), change.get("after"))
            or not _is_exact_nonsensitive_output_entry(planned)
            or not _json_equal(planned.get("value"), change.get("after"))
        ):
            raise ContractError(
                f"attended-proof rollback may not change root output {output_name}"
            )


def _check_authority_proof_steady_output(
    plan: dict[str, Any], foundation: dict[str, Any]
) -> None:
    selected_colors = _authority_proof_selected_colors(foundation)
    planned_outputs = plan.get("planned_values", {}).get("outputs")
    output_changes = plan.get("output_changes")
    if (
        any(color not in ("blue", "green") for color in selected_colors.values())
        or not isinstance(planned_outputs, dict)
        or not isinstance(output_changes, dict)
        or set(output_changes) != EXPECTED_CONTROL_OUTPUTS
    ):
        raise ContractError(
            "steady attended-proof graph must retain both exact selected colors"
        )
    for function_name, output_name in AUTHORITY_PROOF_ALIAS_OUTPUTS.items():
        selected_color = selected_colors[function_name]
        selected_alias = (
            f"arn:aws:lambda:{AWS_REGION}:{ACCOUNT_ID}:function:"
            f"{function_name}:{selected_color}"
        )
        if (
            not _is_exact_nonsensitive_output_entry(planned_outputs.get(output_name))
            or planned_outputs[output_name].get("value") != selected_alias
        ):
            raise ContractError(
                f"steady attended-proof output {output_name} is not exact"
            )
        change = output_changes[output_name]
        valid = _is_exact_output_change(
            change,
            actions=["no-op"],
            before=selected_alias,
            after=selected_alias,
        )
        if function_name == AUTHORITY_PROOF_FUNCTION_NAME:
            prefix = (
                f"arn:aws:lambda:{AWS_REGION}:{ACCOUNT_ID}:function:"
                f"{function_name}:"
            )
            other_alias = (
                f"{prefix}{'green' if selected_color == 'blue' else 'blue'}"
            )
            valid = valid or _is_exact_output_change(
                change,
                actions=["update"],
                before=other_alias,
                after=selected_alias,
            )
        if not valid:
            raise ContractError(
                f"attended-proof output {output_name} action is invalid"
            )


def _check_authority_image_output_changes(
    plan: dict[str, Any],
    plan_from_uri: str,
    plan_to_uri: str,
    *,
    full_transition: bool,
) -> None:
    """Bind the image migration to the exact root-output projection."""
    output_changes = plan.get("output_changes")
    if (
        not isinstance(output_changes, dict)
        or set(output_changes) != EXPECTED_CONTROL_OUTPUTS
    ):
        raise ContractError("Authority image root-output inventory is not exact")

    image_change = output_changes["authority_image_uri"]
    exact_image_transition = _is_exact_output_change(
        image_change,
        actions=["update"],
        before=plan_from_uri,
        after=plan_to_uri,
    )
    if full_transition:
        if not exact_image_transition:
            raise ContractError(
                "full Authority image migration must update the exact image output"
            )
    elif not exact_image_transition and not _is_exact_output_change(
            image_change,
            actions=["no-op"],
            before=plan_to_uri,
            after=plan_to_uri,
        ):
        raise ContractError(
            "Authority image recovery output changes are outside the bounded "
            "transition/no-op envelope"
        )

    for output_name in EXPECTED_CONTROL_OUTPUTS - {"authority_image_uri"}:
        change = output_changes[output_name]
        if (
            not isinstance(change, dict)
            or set(change) != _CHANGE_KEYS
            or change.get("actions") != ["no-op"]
            or change.get("after_unknown") is not False
            or change.get("before_sensitive") is not False
            or change.get("after_sensitive") is not False
            or not _json_equal(change.get("before"), change.get("after"))
        ):
            raise ContractError(
                f"Authority image migration may not change root output {output_name}"
            )


def _authority_function_identity(function_name: str) -> dict[str, str]:
    return {
        "account_id": ACCOUNT_ID,
        "function_name": function_name,
        "region": AWS_REGION,
    }


def _check_authority_image_new_noops(
    by_address: dict[str, dict[str, Any]],
    addresses: set[str],
) -> None:
    """Prove every already-applied runtime complement is an exact target no-op."""
    _, plan_to_uri = _authority_image_plan_uris(by_address)
    for address in addresses:
        resource_type = AUTHORITY_IMAGE_UPDATE_RESOURCES[address]
        change = by_address[address]["change"]
        after = change.get("after")
        expected_change_keys = _CHANGE_KEYS
        if resource_type == "aws_lambda_function":
            expected_change_keys = {
                *_CHANGE_KEYS,
                "before_identity",
                "after_identity",
            }
        if (
            set(change) != expected_change_keys
            or not isinstance(change.get("after_unknown"), dict)
            or change.get("actions") != ["no-op"]
            or not isinstance(after, dict)
            or not _json_equal(change.get("before"), after)
            or _has_unknown_value(change.get("after_unknown"))
            or change.get("before_sensitive") != change.get("after_sensitive")
            or _has_unknown_value(change.get("before_sensitive"))
        ):
            raise ContractError(
                "Authority image recovery requires exact target runtime no-ops"
            )
        if resource_type == "aws_lambda_function":
            function_name = address.rsplit('["', 1)[1][:-2]
            if (
                change.get("before_identity")
                != _authority_function_identity(function_name)
                or change.get("after_identity")
                != _authority_function_identity(function_name)
                or after.get("function_name") != function_name
                or after.get("package_type") != "Image"
                or after.get("image_uri") != plan_to_uri
                or re.fullmatch(r"[1-9][0-9]*", str(after.get("version"))) is None
            ):
                raise ContractError(
                    "Authority recovery function state is not exact new image"
                )
            continue
        instance = address.rsplit('["', 1)[1][:-2]
        function_name, color = instance.rsplit(":", 1)
        if (
            color not in {"blue", "green"}
            or after.get("function_name") != function_name
            or after.get("name") != color
            or after.get("routing_config") != []
            or re.fullmatch(
                r"[1-9][0-9]*", str(after.get("function_version"))
            )
            is None
        ):
            raise ContractError(
                "Authority recovery alias state is not exact new version"
            )


HUB_WORKER_TASK_DEFINITION_ADDRESS = "module.control.aws_ecs_task_definition.hub[0]"
HUB_WORKER_SERVICE_ADDRESS = "module.control.aws_ecs_service.hub[0]"
# Attributes ECS/Terraform recompute for every new task-definition revision.
# Everything NOT listed here must be byte-identical across the replacement.
HUB_WORKER_TASK_DEFINITION_COMPUTED = frozenset(
    {"arn", "arn_without_revision", "id", "revision"}
)


def _claim_hub_worker_image_update(
    changed: set[str], actual_non_noop: dict[str, Any], by_address: dict[str, Any]
) -> frozenset[str] | None:
    """Claim the Hub worker task definition, and the service that follows it.

    An ECS task definition is immutable, so a new Hub image is delete+create --
    and the service must then be updated to point at the new revision. A Hub
    image deploy therefore ALWAYS carries both addresses.

    This lane used to claim only the task definition, which left the service
    unclaimed. Composition requires the union of claims to equal the changed set
    exactly, so a single unclaimed address refuses the whole plan: no COMPOSITE
    plan containing a Hub deploy could ever be admitted, no matter how ordinary
    the other slice was. Verified against the live registry -- three lanes fired
    and `module.control.aws_ecs_service.hub[0]` was claimed by none of them.

    The service is claimed only ALONGSIDE the immutable replacement, never on its
    own: the task-definition guard above returns early first, so this cannot
    become a route for a lone service edit. `_check_hub_service_task_revision_update`
    then pins every service field except `task_definition` and binds that to the
    revision this same plan creates -- the identical pairing the proof-rollout
    lane already uses.
    """
    # Stand down while the proof rollout window is closing. The Hub task
    # definition is replaced then because hub-init's environment carries the
    # ca-pm alias ARN and that alias moves -- which this lane correctly refuses,
    # since it admits an image change and nothing else.
    # authority-proof-rollout-retirement owns that replacement and proves the
    # environment delta is exactly the proof alias ARN.
    if _authority_proof_retirement_closes_the_window(by_address):
        return frozenset()

    address = HUB_WORKER_TASK_DEFINITION_ADDRESS
    if address not in changed:
        return None
    if sorted(actual_non_noop.get(address) or ()) != ["create", "delete"]:
        return None
    claimed = {address}
    if HUB_WORKER_SERVICE_ADDRESS in changed and (
        actual_non_noop.get(HUB_WORKER_SERVICE_ADDRESS) or ()
    ) == ["update"]:
        claimed.add(HUB_WORKER_SERVICE_ADDRESS)
    return frozenset(claimed)


def _check_hub_service_task_revision_update(
    by_address: dict[str, Any], *, require_planned_target: bool = False
) -> None:
    """Admit only an ECS service update to its planned Hub task revision."""
    service_change = by_address[HUB_WORKER_SERVICE_ADDRESS]["change"]
    service_before = service_change.get("before")
    service_after = service_change.get("after")
    service_after_unknown = service_change.get("after_unknown")
    if (
        service_change.get("actions") != ["update"]
        or not isinstance(service_before, dict)
        or not isinstance(service_after, dict)
        or (
            service_before.get("task_definition")
            == service_after.get("task_definition")
            and not (
                isinstance(service_after_unknown, dict)
                and service_after_unknown.get("task_definition") is True
            )
        )
        or {
            key: value
            for key, value in service_before.items()
            if key != "task_definition"
        }
        != {
            key: value
            for key, value in service_after.items()
            if key != "task_definition"
        }
    ):
        raise ContractError("proof rollout may update only the Hub task revision")

    if require_planned_target:
        task_after = by_address[HUB_WORKER_TASK_DEFINITION_ADDRESS]["change"].get(
            "after"
        )
        if (
            not isinstance(task_after, dict)
            or service_after.get("task_definition") != task_after.get("arn")
        ):
            raise ContractError(
                "proof rollout Hub service must select the planned task revision"
            )


def _claim_provisioned_cell_status_update(changed, actual_non_noop, by_address):
    """Admit ONLY an in-place status change on provisioned-cell catalog rows.

    Draining a cell is a reviewed lifecycle decision, not a shape change: the
    Authority stops placing new agents on it while existing assignments keep
    being served. It must not be able to smuggle an endpoint, key, or weight
    edit through the same plan, because those decide where an agent is sent and
    which server identity it trusts.
    """
    claimed = {
        address
        for address in changed
        if address in set(PROVISIONED_CELL_ADDRESSES.values())
        and (actual_non_noop.get(address) or ()) == ["update"]
    }
    if not claimed:
        return None
    for address in claimed:
        cell_id = PROVISIONED_CELL_ID_BY_ADDRESS[address]
        after = by_address[address].get("change", {}).get("after", {})
        try:
            item = json.loads(after.get("item") or "{}")
        except (TypeError, ValueError):
            return None
        expected = PROVISIONED_CELL_DYNAMODB_ITEMS[cell_id]
        # Everything except status and its paired revision stamp must be
        # byte-identical to the reviewed catalog.
        for field, value in expected.items():
            if field in ("status", "updated_at"):
                continue
            if item.get(field) != value:
                return None
        if item.get("status") != expected["status"]:
            return None
        if item.get("updated_at") != expected["updated_at"]:
            return None
        # This lane owns ONLY the status/updated_at revision. A row carrying any
        # attribute beyond the reviewed set -- e.g. the general_assignable
        # Boolean -- is a different transition and must fall through to its own
        # lane rather than be admitted here without validating that attribute.
        if set(item) != set(expected):
            return None
    return frozenset(claimed)

# The public Hub UDP client edge, before and after nhp#3649.
#
# check_live runs BEFORE the apply that moves the ingress rule, so it must admit
# the pre-migration port too. Pinning only the post value made the check demand
# the state its own apply produces -- the identical mistake the NLB-SG-absence
# branch below already documents ("Requiring a singular SG here demanded the
# post-apply state and so rejected the exact state this check gates").
#
# The EGRESS to the worker is deliberately NOT part of this pair and stays 62206
# permanently: the edge translates, it does not renumber the backend.
#
# Remove HUB_CLIENT_EDGE_PORT_LEGACY once every environment's ingress is on 443;
# test_live_boundary_admits_only_the_two_migration_ports pins that decision.
HUB_CLIENT_EDGE_PORT = 443
HUB_CLIENT_EDGE_PORT_LEGACY = 62206

HUB_CLIENT_EDGE_PORT_ADDRESSES = frozenset(
    {
        "module.control.aws_lb_listener.hub[0]",
        "module.control.aws_vpc_security_group_ingress_rule."
        f'hub_nlb_udp["{HUB_PUBLIC_UDP_INGRESS_CIDR}"]',
    }
)


def _claim_hub_client_edge_port_migration(
    changed: set[str], actual_non_noop: dict[str, Any], by_address: dict[str, Any]
) -> "frozenset[str] | None":
    """Admit ONLY the public Hub UDP edge moving to the client-edge port.

    Both addresses must move together. The listener is what callers dial and
    the NLB-SG rule is what admits them; a plan that moved one without the
    other would either black-hole the edge or leave the old port reachable, so
    a partial claim is refused rather than composed.
    """
    claimed = {
        address
        for address in changed
        if address in HUB_CLIENT_EDGE_PORT_ADDRESSES
        and (actual_non_noop.get(address) or ()) == ["update"]
    }
    if claimed != set(HUB_CLIENT_EDGE_PORT_ADDRESSES):
        return None
    return frozenset(claimed)


def _validate_hub_client_edge_port_migration(
    claimed: frozenset[str], by_address: dict[str, Any], plan: dict[str, Any]
) -> None:
    """Pin an exact in-place 62206 -> 443 move and nothing else.

    Everything that decides WHERE traffic goes -- the load balancer, the
    forwarded target group, the admitted source CIDR, the security group -- must
    be byte-identical across the move. Only the port may differ, and only in
    that one direction. The target group itself stays on the server's private
    bind: this edge translates, it does not renumber the backend.
    """
    listener_address = "module.control.aws_lb_listener.hub[0]"
    rule_address = (
        "module.control.aws_vpc_security_group_ingress_rule."
        f'hub_nlb_udp["{HUB_PUBLIC_UDP_INGRESS_CIDR}"]'
    )

    change = (by_address.get(listener_address) or {}).get("change")
    if not isinstance(change, dict) or list(change.get("actions") or ()) != ["update"]:
        raise ContractError("Hub client-edge listener move is not an in-place update")
    before = change.get("before") or {}
    after = change.get("after") or {}
    if (
        before.get("port") != 62206
        or after.get("port") != 443
        or before.get("protocol") != "UDP"
        or after.get("protocol") != "UDP"
        or before.get("load_balancer_arn") != after.get("load_balancer_arn")
        or before.get("default_action") != after.get("default_action")
    ):
        raise ContractError(
            "Hub client-edge listener must move exactly UDP 62206 -> 443 on the "
            "same load balancer and forwarded target group"
        )

    change = (by_address.get(rule_address) or {}).get("change")
    if not isinstance(change, dict) or list(change.get("actions") or ()) != ["update"]:
        raise ContractError("Hub client-edge NLB SG move is not an in-place update")
    before = change.get("before") or {}
    after = change.get("after") or {}
    if (
        before.get("from_port") != 62206
        or before.get("to_port") != 62206
        or after.get("from_port") != 443
        or after.get("to_port") != 443
        or before.get("ip_protocol") != "udp"
        or after.get("ip_protocol") != "udp"
        or before.get("cidr_ipv4") != HUB_PUBLIC_UDP_INGRESS_CIDR
        or after.get("cidr_ipv4") != HUB_PUBLIC_UDP_INGRESS_CIDR
        or before.get("security_group_id") != after.get("security_group_id")
    ):
        raise ContractError(
            "Hub client-edge NLB SG ingress must move exactly the admitted source "
            f"{HUB_PUBLIC_UDP_INGRESS_CIDR} from UDP 62206 to UDP 443 on the same security group"
        )


def _claim_authority_hub_exec_policy_update(
    changed: set[str], actual_non_noop: dict[str, Any], by_address: dict[str, Any]
) -> frozenset[str] | None:
    """Claim update-only Hub function exec policies.

    Precedence over the consumer-staging lane is deliberate and explicit. When
    the staged proof-policy binding is present, that lane resolves the SAME exec
    policies as part of a strictly larger, more deeply validated slice, and two
    lanes claiming one address is ambiguous ownership that fails composition
    closed. So this lane stands down whenever staging claims them, and covers
    only the case where the exec policies move on their own.

    Scoped to exec policies of KNOWN authority functions, so a policy belonging
    to anything else is never claimed. It deliberately covers the per-cell and
    proof functions too: their exec policies move together with the hub ones,
    and pinning only the hub subset made every later plan unadmittable while the
    shape was identical.
    """
    staged = _claim_authority_proof_consumer_staging(changed, actual_non_noop, by_address)
    claimed = {
        address
        for address in changed
        if address in AUTHORITY_EXEC_POLICY_ADDRESSES
        and (actual_non_noop.get(address) or ()) == ["update"]
    }
    if staged and (claimed & set(staged)):
        return None
    return frozenset(claimed) or None


def _validate_authority_hub_exec_policy_update(
    claimed: frozenset[str], by_address: dict[str, Any], plan: dict[str, Any]
) -> None:
    """Pin the SHAPE; policy CONTENT is validated unconditionally elsewhere.

    _check_planned_security runs outside the transition dispatch for every plan,
    so the statements these policies carry are already checked in full. What
    composition must add is that nothing but an in-place update reached this
    claim, and that the policy stayed attached to the same role.
    """
    for address in claimed:
        change = (by_address.get(address) or {}).get("change")
        if not isinstance(change, dict):
            raise ContractError(f"composed exec-policy {address} change is malformed")
        if list(change.get("actions") or ()) != ["update"]:
            raise ContractError(f"composed exec-policy {address} is not an update")
        before, after = change.get("before"), change.get("after")
        if not isinstance(before, dict) or not isinstance(after, dict):
            raise ContractError(f"composed exec-policy {address} has no before/after")
        for key in ("name", "role"):
            if before.get(key) != after.get(key):
                raise ContractError(
                    f"composed exec-policy {address} moved {key!r}; only the "
                    "policy document may change"
                )


def _check_authority_proof_mutation_decrypt_update(
    by_address: dict[str, Any],
) -> None:
    """Admit only adding the exact DynamoDB-via-KMS decrypt statement to ca-pm."""
    item = by_address.get(AUTHORITY_PROOF_EXEC_POLICY_ADDRESS)
    if (
        not isinstance(item, dict)
        or item.get("mode") != "managed"
        or item.get("type") != "aws_iam_role_policy"
        or item.get("deposed") is not None
    ):
        raise ContractError("proof mutation decrypt update identity drifted")
    change = item.get("change")
    if (
        not isinstance(change, dict)
        or set(change) != _CHANGE_KEYS
        or change.get("actions") != ["update"]
        or _has_unknown_value(change.get("after_unknown"))
        or change.get("before_sensitive") != change.get("after_sensitive")
        or _has_unknown_value(change.get("before_sensitive"))
    ):
        raise ContractError("proof mutation decrypt update envelope drifted")
    before, after = change.get("before"), change.get("after")
    if not isinstance(before, dict) or not isinstance(after, dict):
        raise ContractError("proof mutation decrypt update has no before/after")
    if set(before) != set(after) or any(
        not _json_equal(before[key], after[key])
        for key in before
        if key != "policy"
    ):
        raise ContractError(
            "proof mutation decrypt update may change only the policy document"
        )

    before_policy = _authority_decode_policy(before, AUTHORITY_PROOF_FUNCTION_NAME)
    after_policy = _authority_decode_policy(after, AUTHORITY_PROOF_FUNCTION_NAME)
    if (
        not isinstance(before_policy, dict)
        or not isinstance(after_policy, dict)
        or set(before_policy) != {"Version", "Statement"}
        or set(after_policy) != {"Version", "Statement"}
        or before_policy.get("Version") != "2012-10-17"
        or after_policy.get("Version") != "2012-10-17"
        or not isinstance(before_policy.get("Statement"), list)
        or not isinstance(after_policy.get("Statement"), list)
    ):
        raise ContractError("proof mutation decrypt policy envelope drifted")

    expected = {
        "Sid": "ProofDynamoDBDecrypt",
        "Effect": "Allow",
        "Action": ["kms:Decrypt"],
        "Resource": None,
        "Condition": {
            "StringEquals": {
                "kms:ViaService": f"dynamodb.{AWS_REGION}.amazonaws.com"
            }
        },
    }
    added = [
        statement
        for statement in after_policy["Statement"]
        if isinstance(statement, dict)
        and statement.get("Sid") == "ProofDynamoDBDecrypt"
    ]
    if len(added) != 1:
        raise ContractError("proof mutation decrypt update must add one exact statement")
    resource = added[0].get("Resource")
    if (
        not isinstance(resource, list)
        or len(resource) != 1
        or not isinstance(resource[0], str)
        or _AUTHORITY_DATA_KEY_ARN_RE.fullmatch(resource[0]) is None
    ):
        raise ContractError("proof mutation decrypt update key resource drifted")
    expected["Resource"] = resource
    if added[0] != expected:
        raise ContractError("proof mutation decrypt statement drifted")
    if any(
        isinstance(statement, dict)
        and statement.get("Sid") == "ProofDynamoDBDecrypt"
        for statement in before_policy["Statement"]
    ) or before_policy["Statement"] != [
        statement
        for statement in after_policy["Statement"]
        if not (
            isinstance(statement, dict)
            and statement.get("Sid") == "ProofDynamoDBDecrypt"
        )
    ]:
        raise ContractError(
            "proof mutation decrypt update changed more than the reviewed statement"
        )

    _check_authority_proof_exec_role_policy(
        after, AUTHORITY_PROOF_FUNCTION_NAME
    )


def _claim_authority_proof_enable(
    changed: set[str], actual_non_noop: dict[str, Any], by_address: dict[str, Any]
) -> frozenset[str] | None:
    """Claim the attended-proof enablement slice when its exact shape is present."""
    scope = set(AUTHORITY_PROOF_ENABLE_ALL_CHANGES)
    if not scope <= changed:
        return None
    if not all(
        (actual_non_noop.get(address) or ()) == ["create"]
        for address in AUTHORITY_PROOF_RESOURCES
    ):
        return None
    if not all(
        (actual_non_noop.get(address) or ()) == ["update"]
        for address in AUTHORITY_PROOF_ENABLE_UPDATE_ADDRESSES
    ):
        return None
    return frozenset(scope)


def _claim_authority_proof_consumer_staging(
    changed: set[str], actual_non_noop: dict[str, Any], by_address: dict[str, Any]
) -> frozenset[str] | None:
    """Claim the proof-policy consumer staging slice.

    Reuses the transition's own binding resolver, so the claim is exactly the
    set that resolver proves belongs to a staging (or rollback) move -- never a
    hand-rolled address guess.
    """
    for enabling in (True, False):
        try:
            addresses = _authority_proof_consumer_transition_addresses(
                by_address, enabling=enabling
            )
        except Exception:
            addresses = None
        if addresses and set(addresses) <= changed:
            return frozenset(addresses)
    return None


def _validate_hub_worker_image_update(
    claimed: frozenset[str], by_address: dict[str, Any], plan: dict[str, Any]
) -> None:
    _check_hub_worker_image_update(by_address)
    if HUB_WORKER_SERVICE_ADDRESS in claimed:
        # Claiming the service without validating it would be widening. This
        # pins every service field except task_definition and requires that one
        # to be the revision THIS plan creates, so the slice admits a deploy and
        # nothing else -- not a role change, not a desired-count change, and not
        # a jump to some other revision.
        _check_hub_service_task_revision_update(
            by_address, require_planned_target=True
        )


def _validate_authority_proof_enable(
    claimed: frozenset[str], by_address: dict[str, Any], plan: dict[str, Any]
) -> None:
    _require_create_shapes(
        set(AUTHORITY_PROOF_RESOURCES),
        by_address,
        "attended-proof Authority resources must be new",
    )
    _check_authority_proof_enable_transition(plan, by_address)


def _validate_authority_proof_consumer_staging(
    claimed: frozenset[str], by_address: dict[str, Any], plan: dict[str, Any]
) -> None:
    for enabling in (True, False):
        addresses = _authority_proof_consumer_transition_addresses(
            by_address, enabling=enabling
        )
        if addresses and set(addresses) == set(claimed):
            _check_authority_proof_consumer_transition(by_address, enabling=enabling)
            return
    raise ContractError("composed proof-policy consumer claim is not a valid staging")


# Transitions that may appear TOGETHER in one plan. Each entry claims a disjoint
# slice of the changed set and validates that slice on its own.
def _validate_provisioned_cell_status_update(claimed, by_address, plan):
    """Pin the SHAPE. The claim already proved the exact reviewed after-state.

    Composition only needs to know nothing but an in-place update reached here;
    a create or replace would re-materialize a catalog row rather than
    transition it.
    """
    del plan
    for address in sorted(claimed):
        change = by_address.get(address, {}).get("change")
        if not isinstance(change, dict):
            raise ContractError(f"composed provisioned-cell {address} change is malformed")
        if list(change.get("actions") or ()) != ["update"]:
            raise ContractError(f"composed provisioned-cell {address} is not an update")
        if not isinstance(change.get("before"), dict) or not isinstance(change.get("after"), dict):
            raise ContractError(f"composed provisioned-cell {address} has no before/after")


def _claim_provisioned_cell_general_assignable_update(
    changed, actual_non_noop, by_address
):
    """Admit ONLY setting/flipping the general_assignable Boolean on catalog rows.

    Withdrawing (or restoring) a cell's general assignability is a reviewed
    placement-eligibility decision: the weighted-HRW selector stops choosing the
    cell for NEW general agents while status stays active and its weight stays
    positive, so tenant-pinned and attended-proof placement still reach it. It
    must NOT smuggle an endpoint, key, weight, status, or updated_at edit through
    the same plan -- those decide where an agent is sent, which server identity
    it trusts, and the optimistic cell fence for in-flight assignments. Only the
    single general_assignable attribute may move, and only to a Boolean.
    """
    claimed = {
        address
        for address in changed
        if address in set(PROVISIONED_CELL_ADDRESSES.values())
        and (actual_non_noop.get(address) or ()) == ["update"]
    }
    if not claimed:
        return None
    for address in claimed:
        cell_id = PROVISIONED_CELL_ID_BY_ADDRESS[address]
        change = by_address[address].get("change", {})
        try:
            before = json.loads((change.get("before") or {}).get("item") or "{}")
            after = json.loads((change.get("after") or {}).get("item") or "{}")
        except (AttributeError, TypeError, ValueError):
            return None
        if not isinstance(before, dict) or not isinstance(after, dict):
            return None
        expected = PROVISIONED_CELL_DYNAMODB_ITEMS[cell_id]
        # Everything except general_assignable must be byte-identical to the
        # reviewed row on BOTH sides of the change: status, weight, endpoint,
        # keys, and the updated_at fence all stay put.
        try:
            before_core, before_ga = _split_general_assignable_item(before, address)
            after_core, after_ga = _split_general_assignable_item(after, address)
        except ContractError:
            return None
        if before_core != expected or after_core != expected:
            return None
        # The plan must actually MOVE general_assignable to a Boolean; an
        # unchanged attribute is a no-op, not this transition.
        if after_ga is None or after_ga == before_ga:
            return None
    return frozenset(claimed)


def _validate_provisioned_cell_general_assignable_update(claimed, by_address, plan):
    """Pin the SHAPE. The claim already proved the exact reviewed after-state:
    an in-place update that moves only general_assignable to a Boolean and
    leaves every other catalog field byte-identical to the reviewed row.
    """
    del plan
    for address in sorted(claimed):
        change = by_address.get(address, {}).get("change")
        if not isinstance(change, dict):
            raise ContractError(
                f"composed provisioned-cell {address} change is malformed"
            )
        if list(change.get("actions") or ()) != ["update"]:
            raise ContractError(
                f"composed provisioned-cell {address} is not an update"
            )
        if not isinstance(change.get("before"), dict) or not isinstance(
            change.get("after"), dict
        ):
            raise ContractError(
                f"composed provisioned-cell {address} has no before/after"
            )


def _claim_authority_image_uri_move(
    changed: set[str], actual_non_noop: dict[str, Any], by_address: dict[str, Any]
) -> frozenset[str] | None:
    """Claim a foundation contract whose ONLY input change is the image uri.

    Publish tracking resolves the deployed digest from the publisher-owned
    parameter at plan time, so this now moves on its own whenever qurl-service
    publishes -- and therefore lands alongside whatever else a Control PR
    happens to change. No composable lane existed because, while the digest was
    pinned in the basis, it could only move as part of an enumerated image
    migration; a floating digest makes that assumption false for every future
    Control plan, not just the one that introduced it.

    Deliberately narrow: if anything else in the contract moved, this is not the
    lane and the enumerated migration paths still own it.
    """
    # Stand down while the proof rollout window is closing. The contract change
    # is then not an image-URI move at all -- it also drops both selector
    # colours -- and this lane's validator would correctly call that an
    # unrelated field. authority-proof-rollout-retirement owns that shape, and
    # foundation_contract is a shared address so it still composes.
    if _authority_proof_retirement_closes_the_window(by_address):
        return frozenset()

    address = AUTHORITY_IMAGE_UPDATE_FOUNDATION_ADDRESS
    if address not in changed or (actual_non_noop.get(address) or ()) != ["update"]:
        return None
    change = (by_address.get(address) or {}).get("change") or {}
    before = (change.get("before") or {}).get("input") or {}
    after = (change.get("after") or {}).get("input") or {}
    if not isinstance(before, dict) or not isinstance(after, dict) or not before or not after:
        return None
    if not _authority_image_tracks_publish(after.get("authority_runtime_contract")):
        return None
    # Claim on the structural signal only, and let the validator speak.
    #
    # Two earlier versions got this wrong in opposite directions. Restating the
    # rule here missed the migration-plus-image-move shape. Asking the validator
    # inside the claim then SWALLOWED its error, so a malformed foundation
    # change fell through to the generic "unadmittable shape" reject and hid the
    # actual reason -- three CI rounds of guessing, caused by the diagnostic
    # being thrown away.
    #
    # A foundation contract updating while the contract tracks publishes IS this
    # lane. If the change is malformed, the validator below must raise its own
    # specific error rather than have the plan reported as unrecognised.
    return frozenset({address})


def _validate_authority_image_uri_move(
    claimed: frozenset[str], by_address: dict[str, Any], plan: dict[str, Any]
) -> None:
    """Reuse the full foundation validator; the claim only selects the lane."""
    _check_authority_image_foundation_update(by_address)


def _validate_authority_proof_controller_orphan_forget(
    by_address: dict[str, Any],
) -> None:
    """Prove the orphaned proof-controller grant is being RELEASED, not destroyed.

    `aws_iam_role_policy.authority_proof_controller_invoke` managed an inline
    policy on `layerv-nhp-sandbox-udp-proof-controller`, a role owned by the
    separate udp-proof-runner root. Destroying that root (#3804) deleted the
    role, and the resource's `count` keyed off
    `authority_proof_mutation_controls_enabled` rather than off the role
    existing, so Control kept re-rendering a grant pointing at nothing -- and
    any apply would call PutRolePolicy against a role AWS reports as
    NoSuchEntity.

    The module now drops the resource behind a `removed` block with
    `destroy = false`, which plans as `forget`: Terraform releases the address
    from state and calls no AWS API. Nothing is destroyed, because AWS deleted
    the policy already.

    The address is absent from the config resource map, so it never reaches the
    change-set dispatch; the inventory gate is what admits it, and this is that
    gate's deep check. A `delete` never gets here -- the caller admits only
    `forget` -- which keeps this from becoming a route for tearing the grant
    down while a live controller still depends on it. That ordering stays
    reserved for the `authority-proof-disable` transition.
    """
    address = AUTHORITY_PROOF_CONTROLLER_POLICY_ADDRESS
    item = by_address.get(address)
    if not isinstance(item, dict):
        raise ContractError("the orphaned proof-controller forget must be planned")
    change = item.get("change")
    if not isinstance(change, dict):
        raise ContractError("the orphaned proof-controller change must be an object")
    if change.get("actions") != ["forget"]:
        raise ContractError(
            "the orphaned proof-controller grant must be forgotten, never "
            f"destroyed; got {change.get('actions')!r}"
        )
    # A forget is state-only: Terraform plans no after-state because it is
    # releasing the address, not managing it. An after-state would mean the
    # resource is being re-created rather than released.
    if change.get("after") is not None:
        raise ContractError(
            "a forgotten proof-controller grant must plan no after-state"
        )
    before = change.get("before")
    if not isinstance(before, dict):
        raise ContractError(
            "the orphaned proof-controller forget must carry its prior state"
        )
    if before.get("name") != AUTHORITY_PROOF_CONTROLLER_POLICY_NAME:
        raise ContractError(
            "the forgotten grant must be the proof-controller invoke policy; "
            f"got {before.get('name')!r}"
        )
    if before.get("role") != AUTHORITY_PROOF_CONTROLLER_ROLE_NAME:
        raise ContractError(
            "the forgotten grant must be attached to the deterministic "
            f"proof-controller role; got {before.get('role')!r}"
        )


AUTHORITY_FUNCTION_ADDRESS_PREFIX = 'module.control.aws_lambda_function.authority["'
AUTHORITY_ALIAS_ADDRESS_PREFIX = 'module.control.aws_lambda_alias.authority["'


def _authority_contract_target_image(by_address: dict[str, Any]) -> str | None:
    """The image URI the foundation contract binds for this plan, or None."""
    item = by_address.get(AUTHORITY_IMAGE_UPDATE_FOUNDATION_ADDRESS)
    if not isinstance(item, dict):
        return None
    after = item.get("change", {}).get("after")
    if not isinstance(after, dict):
        return None
    payload = after.get("input")
    if not isinstance(payload, dict):
        return None
    target = payload.get("authority_image_uri")
    return target if isinstance(target, str) and "@sha256:" in target else None


def _claim_authority_image_roll(
    changed: set[str],
    actual_non_noop: dict[str, Any],
    by_address: dict[str, Any],
) -> frozenset[str]:
    """Claim a routine Authority image roll, structurally rather than by digest.

    Every merge to main can publish a new Authority image, so a lane that pins
    a literal FROM->TO digest pair (AUTHORITY_IMAGE_UPDATE_{FROM,TO}_URI) can
    only ever admit one migration. It stops matching the moment the next image
    lands, and re-pinning it by hand cannot keep up with a stream of merges --
    main moves again before the re-pin merges. That is how sandbox Control
    wedged.

    The invariant that actually matters is not "someone typed this digest", it
    is **uniform convergence**: every Authority function lands on the single
    image the foundation contract binds for this plan, and no function is left
    behind on a previous one. A mixed-digest fleet is the real hazard, and a
    literal pin does not detect it. This checks the property directly, so it
    holds for every future roll without an edit.

    Two assumptions this rests on, stated so they are not rediscovered:

    1. **Digest provenance lives elsewhere, on a required path.** This lane
       constrains only that the fleet converges on whatever `authority_image_uri`
       the foundation contract binds; it does not judge WHICH digest that is
       (`"@sha256:" in target` is a well-formedness check, not a provenance one).
       That is deliberate -- the digest is not operator-supplied, because the
       generated tfvars derive it from the measurement-basis manifest under
       `--mode sandbox-exact-main --expected-checkout-commit`, and the apply job
       regenerates and byte-compares them against the reviewed plan input under
       `set -euo pipefail`. If that comparison ever becomes skippable, this lane
       degrades to "any uniformly-asserted digest is admitted", so treat it as
       load-bearing for this check rather than as workflow hygiene.
    2. **Terraform emits a `resource_changes` entry for every function**, even
       untouched ones. "No function is left behind" is only as strong as that:
       it silently weakens to "no *listed* function is left behind" if a plan
       ever omits an untouched resource. `_plan_resource_changes` preserving
       no-ops is pinned by test, but that pins the helper, not Terraform.
    """
    functions = {a for a in changed if a.startswith(AUTHORITY_FUNCTION_ADDRESS_PREFIX)}
    aliases = {a for a in changed if a.startswith(AUTHORITY_ALIAS_ADDRESS_PREFIX)}
    if not functions:
        return frozenset()
    # An image roll is update-only. A create, delete or replace is a different
    # transition with different ordering, and never composes through this lane.
    if any(actual_non_noop.get(address) != ["update"] for address in functions | aliases):
        return frozenset()
    target = _authority_contract_target_image(by_address)
    if target is None:
        return frozenset()
    # Uniform convergence, across EVERY Authority function in the plan -- not
    # merely the changed ones. A function sitting no-op on a stale digest means
    # the fleet is being split, which is exactly what this must refuse.
    for address, item in by_address.items():
        if not address.startswith(AUTHORITY_FUNCTION_ADDRESS_PREFIX):
            continue
        after = item.get("change", {}).get("after")
        if not isinstance(after, dict) or after.get("image_uri") != target:
            return frozenset()
    claimed = functions | aliases
    if AUTHORITY_IMAGE_UPDATE_FOUNDATION_ADDRESS in changed:
        claimed.add(AUTHORITY_IMAGE_UPDATE_FOUNDATION_ADDRESS)
    return frozenset(claimed)


def _validate_authority_image_roll(
    claimed: frozenset[str],
    by_address: dict[str, Any],
    plan: dict[str, Any],
) -> None:
    """Re-prove uniform convergence independently of the claim."""
    target = _authority_contract_target_image(by_address)
    if target is None:
        raise ContractError(
            "an Authority image roll requires the foundation contract to bind "
            "an image digest"
        )
    functions = {a for a in claimed if a.startswith(AUTHORITY_FUNCTION_ADDRESS_PREFIX)}
    if not functions:
        raise ContractError("an Authority image roll must move at least one function")
    for address, item in by_address.items():
        if not address.startswith(AUTHORITY_FUNCTION_ADDRESS_PREFIX):
            continue
        after = item.get("change", {}).get("after")
        if not isinstance(after, dict):
            raise ContractError(f"{address} planned values are malformed")
        if after.get("image_uri") != target:
            raise ContractError(
                "every Authority function must converge on the contract image; "
                f"{address} does not"
            )
    for address in claimed:
        actions = by_address.get(address, {}).get("change", {}).get("actions")
        if actions != ["update"]:
            raise ContractError(
                f"an Authority image roll is update-only; {address} is {actions!r}"
            )
        if address.startswith(AUTHORITY_ALIAS_ADDRESS_PREFIX):
            function_name = address[len(AUTHORITY_ALIAS_ADDRESS_PREFIX):].split(":", 1)[0]
            owner = f'{AUTHORITY_FUNCTION_ADDRESS_PREFIX}{function_name}"]'
            if owner not in by_address:
                raise ContractError(
                    f"{address} names no Authority function in this plan"
                )


AUTHORITY_PROOF_STANDBY_PREFIX = (
    "module.control.aws_lambda_provisioned_concurrency_config.authority_proof_standby["
)
# The Hub task definition and its service are NOT here: hub-worker-image-update
# already owns that pair, and two claims on one address fail composition's
# disjointness. Ceding them keeps this lane composable with the roll that
# always accompanies it.
AUTHORITY_PROOF_RETIREMENT_TASK_DEFINITION = (
    "module.control.aws_ecs_task_definition.hub[0]"
)
AUTHORITY_PROOF_RETIREMENT_UPDATES = frozenset(
    {
        "module.control.aws_ecs_service.hub[0]",
        "module.control.aws_iam_role_policy.hub_task[0]",
        'module.control.aws_vpc_endpoint.interface["lambda"]',
        AUTHORITY_IMAGE_UPDATE_FOUNDATION_ADDRESS,
    }
)


def _authority_proof_retirement_closes_the_window(by_address: dict[str, Any]) -> bool:
    """True when the contract MOVES the proof selector colours.

    Two shapes qualify and they are the same operation in two steps:

    * set -> different colour: the catch-up cutover. The standby colour has been
      frozen for the length of the rollout, so it must be advanced and the Hub
      moved onto it before the window can close -- otherwise closing the window
      drops live Hub traffic onto a stale alias.
    * set -> null: closing the window itself.

    Both repoint the Hub's Authority alias ARNs by colour, which is why both
    need this lane rather than hub-worker-image-update.
    """
    item = by_address.get(AUTHORITY_IMAGE_UPDATE_FOUNDATION_ADDRESS)
    if not isinstance(item, dict):
        return False
    change = item.get("change")
    if not isinstance(change, dict):
        return False
    before, after = change.get("before"), change.get("after")
    if not isinstance(before, dict) or not isinstance(after, dict):
        return False
    b_in, a_in = before.get("input"), after.get("input")
    if not isinstance(b_in, dict) or not isinstance(a_in, dict):
        return False
    before_colors = (
        b_in.get("authority_proof_policy_selected_color"),
        b_in.get("authority_proof_policy_prepared_color"),
    )
    after_colors = (
        a_in.get("authority_proof_policy_selected_color"),
        a_in.get("authority_proof_policy_prepared_color"),
    )
    if before_colors == after_colors:
        return False
    # The window must already be OPEN. Without this, null -> (green, green) --
    # opening the window -- also matched, which is not a shape this lane or its
    # stand-down callers should recognise. It was masked downstream (an opening
    # plan CREATES pools, and the claim requires deletes), but the same
    # predicate gates the stand-downs in _claim_hub_worker_image_update and
    # _claim_authority_image_uri_move, where nothing would have caught it.
    if None in before_colors:
        return False
    # Closing (-> null, null) or moving to a complete new pair. A half-set pair
    # is not a shape this lane recognises.
    return after_colors == (None, None) or None not in after_colors


def _check_hub_task_definition_proof_alias_only(by_address: dict[str, Any]) -> None:
    """Prove the Hub replacement is EXACTLY an Authority alias colour move.

    Admitting a bare "hub-init environment changed" here would be the widening
    the rest of this lane avoids, so pin the delta: every container, and every
    environment entry inside them, must be identical except values mentioning
    the ca-pm function, which may differ only in their alias colour suffix.
    """
    change = by_address.get(AUTHORITY_PROOF_RETIREMENT_TASK_DEFINITION, {}).get("change")
    if not isinstance(change, dict):
        raise ContractError("the Hub task definition replacement must be planned")
    before, after = change.get("before"), change.get("after")
    if not isinstance(before, dict) or not isinstance(after, dict):
        raise ContractError("the Hub task definition planned values are malformed")

    def strip_defaults(node: Any) -> Any:
        """Drop provider-normalised empties so only real deltas survive.

        The provider omits empty collections and nulls on one side of the
        replacement and renders them on the other (environment: [],
        portMappings: [], systemControls: [], volumesFrom: []). Comparing raw
        text would show those as differences and mask the one field that
        actually matters.
        """
        if isinstance(node, dict):
            cleaned = {
                key: strip_defaults(value)
                for key, value in node.items()
                # hostPort is derived from containerPort by the provider and is
                # rendered on one side of the replacement only.
                if key != "hostPort" and value not in (None, [], {}, "")
            }
            return {k: v for k, v in cleaned.items() if v not in (None, [], {}, "")}
        if isinstance(node, list):
            return [strip_defaults(item) for item in node]
        return node

    def normalise(raw: Any) -> str:
        parsed = raw
        if isinstance(parsed, str):
            try:
                parsed = json.loads(parsed)
            except ValueError:
                pass
        # Recurse into JSON embedded in environment values (the Hub public
        # config is a JSON string inside a container env var), so the alias ARN
        # is masked wherever it lives.
        text = json.dumps(strip_defaults(parsed), sort_keys=True)
        # Mask the deployment colour on any Authority alias ARN. The mask is
        # per-ARN and does not cross-check that every ARN moved the SAME way, so
        # two aliases moving in opposite directions would pass here. The
        # surrounding zero-spill guards are what constrain that: the claim cedes
        # all alias movement to authority-image-roll, which proves uniform
        # convergence across the whole fleet. The colour is
        # what this operation legitimately moves; everything else in the Hub's
        # container definitions must be byte-identical, which is what keeps this
        # from becoming a bare "hub-init environment changed" admission.
        return re.sub(
            r"(function:[A-Za-z0-9_-]+):(?:blue|green)\b", r"\1:<color>", text
        )

    if normalise(before.get("container_definitions")) != normalise(
        after.get("container_definitions")
    ):
        raise ContractError(
            "the Hub task definition replacement must change only the proof "
            "alias colour in its container definitions"
        )


def _authority_proof_window_closes_to_null(by_address: dict[str, Any]) -> bool:
    """True only for the CLOSING half of the transition (colours -> null).

    Distinct from _authority_proof_retirement_closes_the_window, which also
    matches the catch-up cutover. The endpoint policy spans both colours for as
    long as the window is open -- including during the cutover, when the pair is
    blue/blue -- and narrows to the selected colour only once it shuts. Using
    the broader predicate here narrowed it a step too early.
    """
    item = by_address.get(AUTHORITY_IMAGE_UPDATE_FOUNDATION_ADDRESS)
    if not isinstance(item, dict):
        return False
    after = item.get("change", {}).get("after")
    if not isinstance(after, dict):
        return False
    payload = after.get("input")
    if not isinstance(payload, dict):
        return False
    return (
        payload.get("authority_proof_policy_selected_color") is None
        and payload.get("authority_proof_policy_prepared_color") is None
    )


def _claim_authority_proof_rollout_retirement(
    changed: set[str],
    actual_non_noop: dict[str, Any],
    by_address: dict[str, Any],
) -> frozenset[str]:
    """Claim closing the attended-proof rollout window.

    Dropping the selector colours ends the rollout. That deletes the four
    standby warm pools the window created, moves the ca-pm alias the Hub
    resolves, and so replaces the Hub task definition (immutable) and redeploys
    its service. IA/RA/ICR aliases must NOT move: with the blue/green hold live
    the selected colour holds its version, and any movement there would mean the
    consumer path is being retargeted by what is supposed to be a teardown.

    This is the live-first half of the retirement -- live state goes dark here,
    the Terraform removal follows separately. That ordering is the whole reason
    it is admissible; a code-first teardown stays forbidden (#3809).
    """
    if not _authority_proof_retirement_closes_the_window(by_address):
        return frozenset()
    # Pools are deleted only when the window CLOSES. The catch-up cutover keeps
    # the window open, so an empty set here is a valid shape -- what defines the
    # lane is the colour transition, not the pools.
    pools = {a for a in changed if a.startswith(AUTHORITY_PROOF_STANDBY_PREFIX)}
    if any(actual_non_noop.get(a) != ["delete"] for a in pools):
        return frozenset()
    # Function and alias movement belongs to authority-image-roll, which owns
    # the uniform-convergence proof for them. Closing the window always
    # republishes the proof functions (they lose their proof-policy env), so
    # that lane fires here too and the two compose. Claiming them in both would
    # overlap, and overlapping claims fail composition's disjointness -- the
    # retirement would then only ever match alone, which is not how it lands:
    # main publishes a new image on merge, so a roll rides along.
    if not _claim_authority_image_roll(changed, actual_non_noop, by_address) and any(
        a.startswith(AUTHORITY_FUNCTION_ADDRESS_PREFIX)
        or a.startswith(AUTHORITY_ALIAS_ADDRESS_PREFIX)
        for a in changed
    ):
        return frozenset()
    updates = changed & AUTHORITY_PROOF_RETIREMENT_UPDATES
    if any(actual_non_noop.get(a) != ["update"] for a in updates):
        return frozenset()
    # NOT checked here: that the claim covers all of `changed`. Exactness is the
    # composer's job (it requires the union of claims to equal `changed`), and
    # the standalone lane re-checks it. Enforcing it inside the claim would stop
    # the retirement composing with an Authority image roll -- and a roll
    # legitimately lands alongside it, since main publishes a new image on merge.
    replaces = changed & {AUTHORITY_PROOF_RETIREMENT_TASK_DEFINITION}
    if any(
        actual_non_noop.get(a) not in (["delete", "create"], ["create", "delete"])
        for a in replaces
    ):
        return frozenset()
    return frozenset(pools | updates | replaces)


def _validate_authority_proof_rollout_retirement(
    claimed: frozenset[str],
    by_address: dict[str, Any],
    plan: dict[str, Any],
) -> None:
    """Re-prove the retirement independently of the claim."""
    if not _authority_proof_retirement_closes_the_window(by_address):
        raise ContractError(
            "a proof rollout retirement must close the selector window "
            "(both colours to null)"
        )
    pools = {a for a in claimed if a.startswith(AUTHORITY_PROOF_STANDBY_PREFIX)}
    if AUTHORITY_PROOF_RETIREMENT_TASK_DEFINITION in claimed:
        _check_hub_task_definition_proof_alias_only(by_address)
    if not claimed:
        raise ContractError(
            "a proof selector transition must claim at least one address"
        )
    for address in claimed:
        actions = by_address.get(address, {}).get("change", {}).get("actions")
        if address in pools:
            if actions != ["delete"]:
                raise ContractError(
                    f"{address} must be a plain delete; got {actions!r}"
                )
            continue
        if address == AUTHORITY_PROOF_RETIREMENT_TASK_DEFINITION:
            # Immutable by construction, so a colour move can only present as a
            # replacement; its content is proved above.
            if actions not in (["delete", "create"], ["create", "delete"]):
                raise ContractError(
                    f"{address} must be a replacement; got {actions!r}"
                )
            continue
        if actions != ["update"]:
            raise ContractError(
                f"{address} must be an in-place update; got {actions!r}"
            )


_COMPOSABLE_TRANSITIONS: tuple[tuple[str, Any, Any], ...] = (
    (
        "authority-proof-rollout-retirement",
        _claim_authority_proof_rollout_retirement,
        _validate_authority_proof_rollout_retirement,
    ),
    (
        "authority-image-roll",
        _claim_authority_image_roll,
        _validate_authority_image_roll,
    ),
    (
        "authority-image-uri-move",
        _claim_authority_image_uri_move,
        _validate_authority_image_uri_move,
    ),
    (
        "provisioned-cell-status-update",
        _claim_provisioned_cell_status_update,
        _validate_provisioned_cell_status_update,
    ),
    (
        "provisioned-cell-general-assignable-update",
        _claim_provisioned_cell_general_assignable_update,
        _validate_provisioned_cell_general_assignable_update,
    ),
    (
        "hub-worker-image-update",
        _claim_hub_worker_image_update,
        _validate_hub_worker_image_update,
    ),
    (
        "authority-proof-enable",
        _claim_authority_proof_enable,
        _validate_authority_proof_enable,
    ),
    (
        "authority-proof-consumer-staging",
        _claim_authority_proof_consumer_staging,
        _validate_authority_proof_consumer_staging,
    ),
    (
        "authority-hub-exec-policy-update",
        _claim_authority_hub_exec_policy_update,
        _validate_authority_hub_exec_policy_update,
    ),
    (
        "hub-client-edge-port-migration",
        _claim_hub_client_edge_port_migration,
        _validate_hub_client_edge_port_migration,
    ),
)

# Addresses more than one transition may legitimately claim at once.
#
# terraform_data.foundation_contract is the single record of the foundation's
# DECLARED configuration, so every transition that changes a flag updates it by
# construction. Requiring it to belong to exactly one claim would make any two
# config-changing transitions permanently uncomposable. Each claiming lane
# validates its own binding of that contract -- proof-enable through
# _check_authority_proof_enable_transition, consumer staging through the
# resolver that produced its claim -- so sharing it costs no validation.
#
# It is an explicit one-address allowlist, not a general relaxation: every other
# address must still be claimed by exactly one transition.
_COMPOSED_PLAN_MODE_PREFIX = "composed-"
_COMPOSED_PLAN_MODE_SEPARATOR = "-with-"


def _plan_mode_parts(plan_mode: str) -> set[str]:
    """The atomic transition names inside a (possibly composed) plan mode.

    `_compose_admitted_transitions` renders "composed-<a>-with-<b>", so a caller
    gating on a transition name must not compare the composed string literally:
    a reviewed transition would silently lose its allowance merely by landing
    alongside another one.

    Splitting the display string is sound only while no atomic mode name
    contains the separator. Nothing in the type system enforces that, so
    test_no_registered_lane_name_contains_the_composition_separator pins it. If
    a future lane needs "-with-" in its name, thread the parts through the
    composer's return value rather than widening this.
    """
    if not plan_mode.startswith(_COMPOSED_PLAN_MODE_PREFIX):
        return {plan_mode}
    return set(
        plan_mode[len(_COMPOSED_PLAN_MODE_PREFIX):].split(
            _COMPOSED_PLAN_MODE_SEPARATOR
        )
    )


_COMPOSABLE_SHARED_ADDRESSES = frozenset(
    {"module.control.terraform_data.foundation_contract"}
)


def _compose_admitted_transitions(
    changed: set[str],
    actual_non_noop: dict[str, Any],
    by_address: dict[str, Any],
    deposed_by_address: dict[str, Any],
    plan: dict[str, Any],
) -> str | None:
    """Admit a PARTITION of the changed set into independently reviewed slices.

    Every transition above encodes a single reviewed shape and matches with
    `changed == <its exact set>`. That is correct for one transition at a time
    and wrong the moment two legitimately land together -- a Hub image deploy
    while a reviewed exec-policy edit is pending, say. The plan is then rejected
    even though BOTH halves are individually admitted, which is how a contract
    ends up blocking the ordinary act of shipping.

    Composition here is deliberately partitioning, never permissive:

      * deposed objects never compose -- they are a pending-destroy continuation
        whose ordering matters, so any deposed entry refuses composition
        outright;
      * at least TWO claims are required, so this can never quietly become an
        alternative route for a single transition that the chain above already
        judges on stricter terms;
      * claims must be pairwise DISJOINT -- an address claimed twice is
        ambiguous about which validator owns it, and ambiguity fails closed;
      * the union of claims must equal `changed` EXACTLY -- one unclaimed
        address and the whole plan falls through to the terminal rejection, so
        composition can never widen a plan by absorbing a stray change;
      * each slice still runs its own deep validator.

    Content security is unaffected: _check_planned_security runs outside this
    dispatch for every plan, so policies, endpoint policies and SG ingress are
    validated whether a plan composes or not. What composition decides is only
    whether the SHAPE of the change set is fully accounted for by reviewed
    transitions.

    Returns the composed plan mode, or None to fall through unchanged.
    """
    if deposed_by_address:
        return None
    claims: list[tuple[str, frozenset[str], Any]] = []
    for name, claim_fn, validate_fn in _COMPOSABLE_TRANSITIONS:
        claimed = claim_fn(changed, actual_non_noop, by_address)
        if claimed:
            claims.append((name, claimed, validate_fn))
    if len(claims) < 2:
        return None
    seen: set[str] = set()
    for _, claimed, _ in claims:
        if (seen & claimed) - _COMPOSABLE_SHARED_ADDRESSES:
            return None
        seen |= claimed
    if seen != set(changed):
        return None
    for _, claimed, validate_fn in claims:
        validate_fn(claimed, by_address, plan)
    return _COMPOSED_PLAN_MODE_PREFIX + _COMPOSED_PLAN_MODE_SEPARATOR.join(
        sorted(name for name, _, _ in claims)
    )


def _check_hub_worker_image_update(by_address: dict[str, Any]) -> None:
    """Prove a Hub worker replacement is EXACTLY a container-image change.

    ECS task definitions are immutable, so deploying a new Hub image can only
    ever present as delete+create. The allow-list already carries a lane for the
    Authority runtime's image update and had none for the Hub worker, so the
    ordinary act of shipping a reviewed Hub image was not expressible at all --
    the same create-time-only shape this checker has hit repeatedly.

    Admitting it is safe only if the replacement is provably image-only, so this
    pins every other field: the container set, their names, and every non-image
    key inside each container definition, plus every top-level task-definition
    attribute apart from the ones ECS recomputes per revision. A change that also
    moved a role, a port, a log group, or an environment variable fails here.

    The new image must be the sandbox Hub ECR repository pinned by digest, never
    a tag, so this lane cannot be used to float the worker onto a mutable ref.
    """
    item = by_address.get(HUB_WORKER_TASK_DEFINITION_ADDRESS)
    if (
        not isinstance(item, dict)
        or item.get("address") != HUB_WORKER_TASK_DEFINITION_ADDRESS
        or item.get("type") != "aws_ecs_task_definition"
        or item.get("mode") != "managed"
        or item.get("deposed") is not None
    ):
        raise ContractError("Hub worker task definition identity is not exact")
    change = item.get("change")
    if not isinstance(change, dict):
        raise ContractError("Hub worker task definition change is malformed")
    if change.get("actions") != ["delete", "create"]:
        raise ContractError(
            "Hub worker image update must be exactly one destroy-then-create "
            "task-definition replacement"
        )
    if change.get("replace_paths") != [["container_definitions"]]:
        raise ContractError(
            "Hub worker replacement must be caused only by container_definitions"
        )
    after_unknown = change.get("after_unknown")
    if not isinstance(after_unknown, dict) or not after_unknown:
        # A brand-new revision always defers arn/revision, so an empty
        # after_unknown means this is not the replacement it claims to be.
        raise ContractError("Hub worker replacement must defer its computed revision")
    before = change.get("before")
    after = change.get("after")
    if not isinstance(before, dict) or not isinstance(after, dict):
        raise ContractError("Hub worker task definition before/after are malformed")
    expected_before_only = HUB_WORKER_TASK_DEFINITION_COMPUTED | {
        "enable_fault_injection"
    }
    if set(after) - set(before) or set(before) - set(after) != expected_before_only:
        raise ContractError("Hub worker task definition attribute set changed")

    _check_hub_worker_provider_projections(before, after, after_unknown)

    before_containers = _loads_container_definitions(before, "before")
    after_containers = _loads_container_definitions(after, "after")
    expected_container_names = ["hub", "hub-init"]
    if (
        [item.get("name") for item in before_containers if isinstance(item, dict)]
        != expected_container_names
        or [item.get("name") for item in after_containers if isinstance(item, dict)]
        != expected_container_names
        or len(before_containers) != len(expected_container_names)
        or len(after_containers) != len(expected_container_names)
    ):
        raise ContractError(
            "Hub worker containers must remain exactly hub then hub-init"
        )

    moved_images: list[tuple[str, str]] = []
    for old, new in zip(before_containers, after_containers):
        if not isinstance(old, dict) or not isinstance(new, dict):
            raise ContractError("Hub worker container definition is malformed")
        if old.get("name") != new.get("name"):
            raise ContractError("Hub worker container order or naming changed")
        normalized_old = _normalize_hub_worker_container(old)
        normalized_new = _normalize_hub_worker_container(new)
        if set(normalized_old) != set(normalized_new):
            raise ContractError("Hub worker container key set changed")
        for key in normalized_old:
            if key == "image":
                continue
            if normalized_old[key] != normalized_new[key]:
                raise ContractError(
                    f"Hub worker container {old.get('name')!r} changed {key!r}; "
                    "this lane admits an image change and nothing else"
                )
        if old.get("image") != new.get("image"):
            moved_images.append((str(old.get("image")), str(new.get("image"))))

    if len(moved_images) != len(expected_container_names):
        raise ContractError("Hub worker replacement must update both container images")
    if (
        len({old_image for old_image, _ in moved_images}) != 1
        or len({new_image for _, new_image in moved_images}) != 1
    ):
        raise ContractError(
            "Hub worker containers must move together between identical image digests"
        )
    for old_image, new_image in moved_images:
        if not HUB_WORKER_IMAGE_RE.fullmatch(old_image):
            raise ContractError(
                "Hub worker prior image must be the sandbox Hub repository pinned "
                "by digest"
            )
        if not HUB_WORKER_IMAGE_RE.fullmatch(new_image):
            raise ContractError(
                "Hub worker image must be the sandbox Hub repository pinned by "
                "digest"
            )

    for key in before:
        if key in (
            *HUB_WORKER_TASK_DEFINITION_COMPUTED,
            "container_definitions",
            "enable_fault_injection",
            "ipc_mode",
            "pid_mode",
            "volume",
        ):
            continue
        if before[key] != after[key]:
            raise ContractError(
                f"Hub worker task definition changed {key!r}; this lane admits an "
                "image change and nothing else"
            )


def _check_authority_proof_selector_update(
    by_address: dict[str, Any], before_color: str, after_color: str
) -> None:
    item = by_address[HUB_WORKER_TASK_DEFINITION_ADDRESS]
    change = item.get("change")
    if (
        item.get("type") != "aws_ecs_task_definition"
        or item.get("mode") != "managed"
        or not isinstance(change, dict)
        or change.get("actions") != ["delete", "create"]
        or change.get("replace_paths") != [["container_definitions"]]
    ):
        raise ContractError("proof selector must replace only the Hub task config")
    before = change.get("before")
    after = change.get("after")
    after_unknown = change.get("after_unknown")
    if (
        not isinstance(before, dict)
        or not isinstance(after, dict)
        or not isinstance(after_unknown, dict)
    ):
        raise ContractError("proof selector Hub task replacement is malformed")
    expected_before_only = HUB_WORKER_TASK_DEFINITION_COMPUTED | {
        "enable_fault_injection"
    }
    if set(after) - set(before) or set(before) - set(after) != expected_before_only:
        raise ContractError("proof selector Hub task attribute set changed")
    _check_hub_worker_provider_projections(before, after, after_unknown)
    before_containers = _loads_container_definitions(before, "before")
    after_containers = _loads_container_definitions(after, "after")
    if (
        [container.get("name") for container in before_containers] != ["hub", "hub-init"]
        or [container.get("name") for container in after_containers] != ["hub", "hub-init"]
    ):
        raise ContractError("proof selector Hub container inventory changed")
    if (
        _normalize_hub_worker_container(before_containers[0])
        != _normalize_hub_worker_container(after_containers[0])
    ):
        raise ContractError("proof selector changed the Hub runtime container")
    before_init = _normalize_hub_worker_container(before_containers[1])
    after_init = _normalize_hub_worker_container(after_containers[1])
    before_environment = before_init.pop("environment", None)
    after_environment = after_init.pop("environment", None)
    if before_init != after_init:
        raise ContractError("proof selector changed Hub init outside its environment")

    def environment_map(value: Any) -> dict[str, Any]:
        if not isinstance(value, list):
            raise ContractError("proof selector Hub init environment is malformed")
        result = {
            entry.get("name"): entry.get("value")
            for entry in value
            if isinstance(entry, dict) and set(entry) == {"name", "value"}
        }
        if len(result) != len(value):
            raise ContractError("proof selector Hub init environment is not unique")
        return result

    before_env = environment_map(before_environment)
    after_env = environment_map(after_environment)
    if set(before_env) != {"NHP_HUB_PUBLIC_CONFIG_JSON"} or set(after_env) != set(
        before_env
    ):
        raise ContractError("proof selector Hub init environment surface changed")
    try:
        before_config = json.loads(before_env["NHP_HUB_PUBLIC_CONFIG_JSON"])
        after_config = json.loads(after_env["NHP_HUB_PUBLIC_CONFIG_JSON"])
    except (TypeError, json.JSONDecodeError) as error:
        raise ContractError("proof selector Hub config is not JSON") from error
    alias_fields = {
        "issue_assignment_alias_arn": "layerv-nhp-sandbox-ca-ia",
        "refresh_assignment_alias_arn": "layerv-nhp-sandbox-ca-ra",
        "issue_credential_recovery_alias_arn": "layerv-nhp-sandbox-ca-icr",
    }
    if not isinstance(before_config, dict) or not isinstance(after_config, dict):
        raise ContractError("proof selector Hub config is not an object")
    if set(before_config) != set(after_config):
        raise ContractError("proof selector Hub config key set changed")
    for key in before_config:
        if key in alias_fields:
            function_name = alias_fields[key]
            prefix = (
                f"arn:aws:lambda:{AWS_REGION}:{ACCOUNT_ID}:function:{function_name}:"
            )
            if (
                before_config[key] != f"{prefix}{before_color}"
                or after_config[key] != f"{prefix}{after_color}"
            ):
                raise ContractError("proof selector Hub alias transition is not exact")
        elif before_config[key] != after_config[key]:
            raise ContractError("proof selector changed unrelated Hub config")
    for key in before:
        if key in (
            *HUB_WORKER_TASK_DEFINITION_COMPUTED,
            "container_definitions",
            "enable_fault_injection",
            "ipc_mode",
            "pid_mode",
            "volume",
        ):
            continue
        if before[key] != after[key]:
            raise ContractError("proof selector changed unrelated Hub task attributes")

    _check_hub_service_task_revision_update(by_address)


def _normalize_hub_worker_container(container: dict[str, Any]) -> dict[str, Any]:
    """Remove only the AWS provider's proven container JSON defaults."""
    normalized = copy.deepcopy(container)
    name = normalized.get("name")

    for key in ("systemControls", "volumesFrom"):
        if normalized.get(key) == []:
            normalized.pop(key)

    if name == "hub":
        if normalized.get("environment") == []:
            normalized.pop("environment")
        port_mappings = normalized.get("portMappings")
        if isinstance(port_mappings, list):
            for mapping in port_mappings:
                if (
                    isinstance(mapping, dict)
                    and "hostPort" in mapping
                    and mapping.get("hostPort") == mapping.get("containerPort")
                ):
                    mapping.pop("hostPort")
    elif name == "hub-init" and normalized.get("portMappings") == []:
        normalized.pop("portMappings")

    return normalized


def _true_unknown_paths(value: Any, path: tuple[Any, ...] = ()) -> set[tuple[Any, ...]]:
    """Return the exact paths Terraform marks unknown with boolean true."""
    if value is True:
        return {path}
    if isinstance(value, dict):
        paths: set[tuple[Any, ...]] = set()
        for key, item in value.items():
            paths.update(_true_unknown_paths(item, (*path, key)))
        return paths
    if isinstance(value, list):
        paths = set()
        for index, item in enumerate(value):
            paths.update(_true_unknown_paths(item, (*path, index)))
        return paths
    return set()


def _check_hub_worker_provider_projections(
    before: dict[str, Any],
    after: dict[str, Any],
    after_unknown: dict[str, Any],
) -> None:
    """Admit only the exact AWS-provider projections in the live replace."""
    expected_true_unknowns = {
        ("arn",),
        ("arn_without_revision",),
        ("enable_fault_injection",),
        ("id",),
        ("revision",),
        ("volume", 0, "configure_at_launch"),
    }
    if _true_unknown_paths(after_unknown) != expected_true_unknowns:
        raise ContractError("Hub worker deferred attributes are not exact")

    if (
        before.get("enable_fault_injection") is not False
        or "enable_fault_injection" in after
        or after_unknown.get("enable_fault_injection") is not True
    ):
        raise ContractError(
            "Hub worker enable_fault_injection projection is not exact"
        )

    before_volumes = before.get("volume")
    after_volumes = after.get("volume")
    expected_old_volume = {
        "configure_at_launch": False,
        "docker_volume_configuration": [],
        "efs_volume_configuration": [],
        "fsx_windows_file_server_volume_configuration": [],
        "host_path": "",
        "name": "hub-etc",
        "s3files_volume_configuration": [],
    }
    expected_new_volume = {
        key: value
        for key, value in expected_old_volume.items()
        if key != "configure_at_launch"
    }
    if (
        before_volumes != [expected_old_volume]
        or after_volumes != [expected_new_volume]
    ):
        raise ContractError("Hub worker volume projection is not exact")

    if (
        before.get("ipc_mode") != ""
        or after.get("ipc_mode") is not None
        or before.get("pid_mode") != ""
        or after.get("pid_mode") is not None
    ):
        raise ContractError("Hub worker ipc_mode/pid_mode projections are not exact")


def check_hub_worker_image_update_plan(plan: Any) -> dict[str, str | int]:
    """Validate the one destructive Hub image transition for the shell fence.

    ``check-connector-authority-foundation.sh`` runs before the complete Control
    plan checker. It must reject destructive actions generally while allowing
    this one immutable ECS replacement. Reuse the authoritative Python validator
    here instead of maintaining a second field-by-field implementation in jq.
    """
    if not isinstance(plan, dict):
        raise ContractError("Terraform plan must be an object")

    destructive: list[dict[str, Any]] = []
    for field in ("resource_changes", "resource_drift"):
        entries = plan.get(field, [])
        if entries is None:
            entries = []
        if not isinstance(entries, list):
            raise ContractError(f"Terraform plan {field} must be an array")
        for item in entries:
            if not isinstance(item, dict):
                raise ContractError(f"Terraform plan {field} item is malformed")
            change = item.get("change")
            if not isinstance(change, dict):
                raise ContractError(f"Terraform plan {field} change is malformed")
            actions = change.get("actions")
            if isinstance(actions, list) and "delete" in actions:
                destructive.append(item)

    if (
        len(destructive) != 1
        or destructive[0].get("address") != HUB_WORKER_TASK_DEFINITION_ADDRESS
    ):
        raise ContractError(
            "Hub worker image update must be the only destructive resource change"
        )
    _check_hub_worker_image_update(
        {HUB_WORKER_TASK_DEFINITION_ADDRESS: destructive[0]}
    )
    return {"changed_resources": 1, "plan_mode": "hub-worker-image-update"}


def _loads_container_definitions(state: dict[str, Any], side: str) -> list:
    raw = state.get("container_definitions")
    if not isinstance(raw, str):
        raise ContractError(f"Hub worker {side} container_definitions is not JSON text")
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as error:
        raise ContractError(
            f"Hub worker {side} container_definitions is not valid JSON"
        ) from error
    if not isinstance(parsed, list) or not parsed:
        raise ContractError(f"Hub worker {side} container_definitions is empty")
    return parsed


def _authority_image_plan_uris(
    by_address: dict[str, dict[str, Any]],
) -> tuple[str, str]:
    """The (from, to) image uris this plan's foundation declares.

    Under the pinned source this returns the enumerated constants unchanged, so
    every assertion that used them keeps exactly its current meaning. Under
    publish tracking there are no constants to return -- the digest advances on
    its own -- so the pair is taken from the foundation change itself and each
    side is required to be an immutable reference. Deriving both from one place
    also means the function, output and no-op checks agree with the foundation
    by construction rather than by coincidence.
    """
    item = by_address.get(AUTHORITY_IMAGE_UPDATE_FOUNDATION_ADDRESS) or {}
    change = item.get("change") or {}
    before_input = (change.get("before") or {}).get("input") or {}
    after_input = (change.get("after") or {}).get("input") or {}
    contract = after_input.get("authority_runtime_contract") or before_input.get(
        "authority_runtime_contract"
    )
    if not _authority_image_tracks_publish(contract):
        return AUTHORITY_IMAGE_UPDATE_FROM_URI, AUTHORITY_IMAGE_UPDATE_TO_URI
    before_uri = before_input.get("authority_image_uri")
    # A no-op foundation carries the same input on both sides; the applied image
    # is then both the source and the target.
    after_uri = after_input.get("authority_image_uri", before_uri)
    for uri in (before_uri, after_uri):
        if not isinstance(uri, str) or _AUTHORITY_IMAGE_URI_PATTERN.fullmatch(uri) is None:
            raise ContractError(
                "Authority image plan uris are not immutable repository@sha256 references"
            )
    return before_uri, after_uri


def _check_authority_image_update(
    changed: set[str],
    by_address: dict[str, dict[str, Any]],
    plan: dict[str, Any],
    *,
    refresh_disabled: bool,
) -> None:
    """Admit only the reviewed 65421e -> e147b2 sandbox image migration."""
    plan_from_uri, plan_to_uri = _authority_image_plan_uris(by_address)
    foundation_changed = AUTHORITY_IMAGE_UPDATE_FOUNDATION_ADDRESS in changed
    image_changed = changed & set(AUTHORITY_IMAGE_UPDATE_RESOURCES)
    recovery_replaces = changed & set(AUTHORITY_IMAGE_UPDATE_RECOVERY_REPLACES)
    if foundation_changed:
        _check_authority_image_foundation_update(by_address)
    else:
        _check_authority_image_foundation_noop(by_address)
    _check_authority_image_new_noops(
        by_address,
        set(AUTHORITY_IMAGE_UPDATE_RESOURCES) - image_changed,
    )
    for address in recovery_replaces:
        item = by_address[address]
        change = item.get("change")
        function_name = address.rsplit('["', 1)[1][:-2]
        before = change.get("before") if isinstance(change, dict) else None
        after = change.get("after") if isinstance(change, dict) else None
        if (
            item.get("mode") != "managed"
            or item.get("type")
            != "aws_lambda_provisioned_concurrency_config"
            or not isinstance(before, dict)
            or not isinstance(after, dict)
            or change.get("actions") != ["delete", "create"]
            or before.get("function_name") != function_name
            or after.get("function_name") != function_name
            or before.get("id") != f"{function_name},blue"
            or "id" in after
            or before.get("provisioned_concurrent_executions")
            != (1 if refresh_disabled else 0)
            or after.get("provisioned_concurrent_executions") != 1
            or before.get("qualifier") != "blue"
            or after.get("qualifier") != "blue"
            or before.get("skip_destroy") is not False
            or after.get("skip_destroy") is not False
            or before.get("timeouts") is not None
            or after.get("timeouts") is not None
            or {
                key: value
                for key, value in before.items()
                if key not in {"id", "provisioned_concurrent_executions"}
            }
            != {
                key: value
                for key, value in after.items()
                if key != "provisioned_concurrent_executions"
            }
            or change.get("after_unknown") != {"id": True}
            or change.get("before_sensitive") != change.get("after_sensitive")
            or _has_unknown_value(change.get("before_sensitive"))
        ):
            raise ContractError(
                f"{address} must be the exact failed proof concurrency replacement"
            )

    for address in image_changed:
        item = by_address[address]
        change = item.get("change")
        expected_change_keys = _CHANGE_KEYS
        if item.get("type") == "aws_lambda_function":
            expected_change_keys = {
                *_CHANGE_KEYS,
                "before_identity",
                "after_identity",
            }
        if (
            item.get("mode") != "managed"
            or item.get("type") != AUTHORITY_IMAGE_UPDATE_RESOURCES[address]
            or not isinstance(change, dict)
            or set(change) != expected_change_keys
            or change.get("actions") != ["update"]
        ):
            raise ContractError("Authority image update envelope is not exact")
        before = change.get("before")
        after = change.get("after")
        after_unknown = change.get("after_unknown")
        if (
            not isinstance(before, dict)
            or not isinstance(after, dict)
            or not isinstance(after_unknown, dict)
            or change.get("before_sensitive") != change.get("after_sensitive")
            or _has_unknown_value(change.get("before_sensitive"))
        ):
            raise ContractError("Authority image update values are malformed")
        changed_fields = {
            field
            for field in set(before) | set(after)
            if field not in before
            or field not in after
            or not _json_equal(before[field], after[field])
        }
        unknown_fields = {
            field
            for field, value in after_unknown.items()
            if _has_unknown_value(value)
        }

        if item["type"] == "aws_lambda_function":
            function_name = address.rsplit('["', 1)[1][:-2]
            expected_identity = _authority_function_identity(function_name)
            expected_changed_fields = {
                "image_uri",
                *_AUTHORITY_FUNCTION_UPDATE_COMPUTED_FIELDS,
            }
            if (
                before.get("function_name") != function_name
                or after.get("function_name") != function_name
                or before.get("package_type") != "Image"
                or after.get("package_type") != "Image"
                or change.get("before_identity") != expected_identity
                or change.get("after_identity") != expected_identity
                or before.get("image_uri") != plan_from_uri
                or after.get("image_uri") != plan_to_uri
                or changed_fields != expected_changed_fields
                or unknown_fields != _AUTHORITY_FUNCTION_UPDATE_COMPUTED_FIELDS
                or any(
                    field in after
                    for field in _AUTHORITY_FUNCTION_UPDATE_COMPUTED_FIELDS
                )
                or not re.fullmatch(r"[1-9][0-9]*", str(before.get("version")))
            ):
                raise ContractError(
                    "Authority function update is not the exact 65421e-to-e147b2 "
                    "immutable image/version migration"
                )
            continue

        instance = address.rsplit('["', 1)[1][:-2]
        function_name, color = instance.rsplit(":", 1)
        if (
            color not in {"blue", "green"}
            or before.get("function_name") != function_name
            or after.get("function_name") != function_name
            or before.get("name") != color
            or after.get("name") != color
            or before.get("routing_config") != []
            or after.get("routing_config") != []
            or changed_fields != {"function_version"}
            or unknown_fields != {"function_version"}
            or "function_version" in after
            or not re.fullmatch(
                r"[1-9][0-9]*", str(before.get("function_version"))
            )
        ):
            raise ContractError(
                "Authority alias update may change only its provider-computed "
                "function_version while retaining exact function/name/routing"
            )
    _check_authority_image_output_changes(
        plan,
        plan_from_uri,
        plan_to_uri,
        full_transition=(
            foundation_changed
            and image_changed == set(AUTHORITY_IMAGE_UPDATE_RESOURCES)
        ),
    )


def _check_authority_proof_concurrency_recovery_drift(
    drift: list[dict[str, Any]],
    by_address: dict[str, dict[str, Any]] | None = None,
) -> None:
    """Prove the exact state-1 -> live-0 PM/PCR failure observation.

    The stale image left the proof Lambdas unable to initialize. Terraform state
    still records each configured blue pool at one, while the refreshed provider
    read reports zero and the taint produces the separately validated
    delete/create replacement. Admit only those exact two proof-pool identities
    and only when the plan carries the same replacement set.
    """
    addresses = [item.get("address") for item in drift]
    if not all(isinstance(address, str) for address in addresses):
        raise _unexpected_drift_error(drift)
    address_set = set(addresses)
    if (
        not drift
        or len(address_set) != len(addresses)
        or not address_set <= set(AUTHORITY_IMAGE_UPDATE_RECOVERY_REPLACES)
    ):
        raise _unexpected_drift_error(drift)

    if by_address is not None:
        planned_replacements = {
            address
            for address in AUTHORITY_IMAGE_UPDATE_RECOVERY_REPLACES
            if (
                isinstance(by_address.get(address), dict)
                and isinstance(by_address[address].get("change"), dict)
                and by_address[address]["change"].get("actions")
                == ["delete", "create"]
            )
        }
        if address_set != planned_replacements:
            raise ContractError(
                "proof concurrency drift must exactly match the planned "
                "PM/PCR recovery replacements"
            )

    expected_value_keys = {
        "function_name",
        "id",
        "provisioned_concurrent_executions",
        "qualifier",
        "region",
        "skip_destroy",
        "timeouts",
    }
    for item in drift:
        address = item["address"]
        function_name = address.rsplit('["', 1)[1][:-2]
        change = item.get("change")
        before = change.get("before") if isinstance(change, dict) else None
        after = change.get("after") if isinstance(change, dict) else None
        if (
            item.get("mode") != "managed"
            or item.get("module_address") != "module.control"
            or item.get("name") != "authority"
            or item.get("provider_name")
            != "registry.terraform.io/hashicorp/aws"
            or item.get("type")
            != "aws_lambda_provisioned_concurrency_config"
            or item.get("index") != function_name
            or item.get("deposed") is not None
            or not isinstance(change, dict)
            or set(change) != _CHANGE_KEYS
            or change.get("actions") != ["update"]
            or not isinstance(before, dict)
            or not isinstance(after, dict)
            or set(before) != expected_value_keys
            or set(after) != expected_value_keys
            or before.get("function_name") != function_name
            or after.get("function_name") != function_name
            or before.get("id") != f"{function_name},blue"
            or after.get("id") != f"{function_name},blue"
            or before.get("provisioned_concurrent_executions") != 1
            or after.get("provisioned_concurrent_executions") != 0
            or before.get("qualifier") != "blue"
            or after.get("qualifier") != "blue"
            or before.get("region") != AWS_REGION
            or after.get("region") != AWS_REGION
            or before.get("skip_destroy") is not False
            or after.get("skip_destroy") is not False
            or before.get("timeouts") is not None
            or after.get("timeouts") is not None
            or {
                key: value
                for key, value in before.items()
                if key != "provisioned_concurrent_executions"
            }
            != {
                key: value
                for key, value in after.items()
                if key != "provisioned_concurrent_executions"
            }
            or change.get("after_unknown") != {}
            or change.get("before_sensitive") != {}
            or change.get("after_sensitive") != {}
        ):
            raise ContractError(
                f"{address} is not the exact failed proof concurrency drift"
            )


def _expected_hub_task_inline_policy(*, rollout: bool) -> dict[str, Any]:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Action": "lambda:InvokeFunction",
                "Effect": "Allow",
                "Resource": sorted(_hub_authority_alias_arns(rollout)),
                "Sid": "AuthorityInvoke",
            },
            {
                "Action": "cloudwatch:PutMetricData",
                "Condition": {
                    "StringEquals": {"cloudwatch:namespace": "LayerV/NHP"}
                },
                "Effect": "Allow",
                "Resource": "*",
                "Sid": "PublishHubMetrics",
            },
        ],
    }


def _check_authority_proof_prepare_recovery_drift(
    drift: list[dict[str, Any]],
    by_address: dict[str, dict[str, Any]] | None = None,
) -> None:
    """Prove the exact four-entry drift left by the failed green prepare.

    Three tainted IA/RA/ICR standby pools changed from configured two to live
    zero. The Hub role's provider projection caught up with the separately
    managed inline policy that the partial apply already expanded from blue to
    both colors. Nothing here changes configuration; the recovery plan remains
    the separately validated 12-address function/alias/pool repair.
    """
    by_drift = {
        item.get("address"): item
        for item in drift
        if isinstance(item.get("address"), str)
    }
    if (
        len(by_drift) != len(drift)
        or set(by_drift) != set(AUTHORITY_PROOF_PREPARE_RECOVERY_DRIFT_ADDRESSES)
    ):
        raise _unexpected_drift_error(drift)

    concurrency_value_keys = {
        "function_name",
        "id",
        "provisioned_concurrent_executions",
        "qualifier",
        "region",
        "skip_destroy",
        "timeouts",
    }
    for address in AUTHORITY_PROOF_PREPARE_RECOVERY_CONCURRENCY_ADDRESSES:
        item = by_drift[address]
        function_name = address.rsplit('["', 1)[1][:-2]
        change = item.get("change")
        before = change.get("before") if isinstance(change, dict) else None
        after = change.get("after") if isinstance(change, dict) else None
        if (
            item.get("mode") != "managed"
            or item.get("module_address") != "module.control"
            or item.get("name") != "authority_proof_standby"
            or item.get("provider_name")
            != "registry.terraform.io/hashicorp/aws"
            or item.get("type")
            != "aws_lambda_provisioned_concurrency_config"
            or item.get("index") != function_name
            or item.get("deposed") is not None
            or not isinstance(change, dict)
            or set(change) != _CHANGE_KEYS
            or change.get("actions") != ["update"]
            or not isinstance(before, dict)
            or not isinstance(after, dict)
            or set(before) != concurrency_value_keys
            or set(after) != concurrency_value_keys
            or before.get("function_name") != function_name
            or after.get("function_name") != function_name
            or before.get("id") != f"{function_name},green"
            or after.get("id") != f"{function_name},green"
            or before.get("provisioned_concurrent_executions") != 2
            or after.get("provisioned_concurrent_executions") != 0
            or before.get("qualifier") != "green"
            or after.get("qualifier") != "green"
            or before.get("region") != AWS_REGION
            or after.get("region") != AWS_REGION
            or before.get("skip_destroy") is not False
            or after.get("skip_destroy") is not False
            or before.get("timeouts") is not None
            or after.get("timeouts") is not None
            or change.get("after_unknown") != {}
            or change.get("before_sensitive") != {}
            or change.get("after_sensitive") != {}
        ):
            raise ContractError(
                f"{address} is not the exact failed green concurrency drift"
            )
        if by_address is not None:
            planned = by_address.get(address, {}).get("change", {})
            if planned.get("actions") != ["delete", "create"]:
                raise ContractError(
                    f"{address} drift requires its exact tainted replacement"
                )

    role_address = AUTHORITY_PROOF_PREPARE_RECOVERY_HUB_ROLE_ADDRESS
    role_item = by_drift[role_address]
    role_change = role_item.get("change")
    role_before = (
        role_change.get("before") if isinstance(role_change, dict) else None
    )
    role_after = (
        role_change.get("after") if isinstance(role_change, dict) else None
    )
    role_value_keys = {
        "arn",
        "assume_role_policy",
        "create_date",
        "description",
        "force_detach_policies",
        "id",
        "inline_policy",
        "managed_policy_arns",
        "max_session_duration",
        "name",
        "name_prefix",
        "path",
        "permissions_boundary",
        "tags",
        "tags_all",
        "unique_id",
    }
    expected_sensitive = {
        "inline_policy": [{}],
        "managed_policy_arns": [],
        "tags": {},
        "tags_all": {},
    }
    if (
        role_item.get("mode") != "managed"
        or role_item.get("module_address") != "module.control"
        or role_item.get("name") != "hub_task"
        or role_item.get("provider_name")
        != "registry.terraform.io/hashicorp/aws"
        or role_item.get("type") != "aws_iam_role"
        or role_item.get("index") != 0
        or role_item.get("deposed") is not None
        or not isinstance(role_change, dict)
        or set(role_change) != _CHANGE_KEYS
        or role_change.get("actions") != ["update"]
        or not isinstance(role_before, dict)
        or not isinstance(role_after, dict)
        or set(role_before) != role_value_keys
        or set(role_after) != role_value_keys
        or role_change.get("after_unknown") != {}
        or role_change.get("before_sensitive") != expected_sensitive
        or role_change.get("after_sensitive") != expected_sensitive
        or {
            key: value
            for key, value in role_before.items()
            if key != "inline_policy"
        }
        != {
            key: value
            for key, value in role_after.items()
            if key != "inline_policy"
        }
        or not isinstance(role_before.get("inline_policy"), list)
        or len(role_before["inline_policy"]) != 1
        or not isinstance(role_after.get("inline_policy"), list)
        or len(role_after["inline_policy"]) != 1
        or role_before["inline_policy"][0].get("name") != "hub-task"
        or role_after["inline_policy"][0].get("name") != "hub-task"
        or _decode_exact_json(
            role_before["inline_policy"][0].get("policy"),
            "policy",
            role_address,
        )
        != _expected_hub_task_inline_policy(rollout=False)
        or _decode_exact_json(
            role_after["inline_policy"][0].get("policy"),
            "policy",
            role_address,
        )
        != _expected_hub_task_inline_policy(rollout=True)
    ):
        raise ContractError(
            "Hub task role drift is not the exact blue-to-both-colors "
            "inline-policy projection"
        )
    if by_address is not None:
        planned_role = by_address.get(role_address, {}).get("change", {})
        policy_address = "module.control.aws_iam_role_policy.hub_task[0]"
        planned_policy = by_address.get(policy_address, {}).get("change", {})
        if (
            planned_role.get("actions") != ["no-op"]
            or planned_role.get("before") != role_after
            or planned_role.get("after") != role_after
            or planned_policy.get("actions") != ["no-op"]
            or planned_policy.get("after", {}).get("policy")
            != role_after["inline_policy"][0]["policy"]
        ):
            raise ContractError(
                "Hub task role projection must match the exact no-op managed policy"
            )


# Every Authority exec IDENTITY -- the role and its inline policy, for all
# thirteen functions including the two proof ones (ca-pcr, ca-pm).
#
# AUTHORITY_RUNTIME_RESOURCES covers only the ELEVEN runtime functions, so the
# two proof functions' exec role and policy sit outside the runtime slice. Their
# drift therefore broke the slice subset test even though it is the same benign
# re-projection as the other eleven. That was 4 of the 27 entries that blocked
# every Control plan.
#
# Scoped to exec identities, deliberately NOT to AUTHORITY_PROOF_RESOURCES: that
# set has 33 members, and admitting drift across all of them on membership alone
# would be a widening. Policy CONTENT is validated for every plan by
# _check_planned_security, outside this dispatch.
_AUTHORITY_EXEC_IDENTITY_ADDRESSES = AUTHORITY_EXEC_POLICY_ADDRESSES | frozenset(
    f'module.control.aws_iam_role.authority_exec["{_fn}"]'
    for _fn in AUTHORITY_RUNTIME_FUNCTIONS_WITH_PROOF
)


_RUNTIME_SLICE_NORMALIZATION_KINDS = frozenset(
    {
        "authority-runtime-slice-normalization",
        _SLICE_AND_AUTHORITY_DIGEST_NORMALIZATION_KIND,
    }
)


def _require_slice_and_digest_plan_mode(
    normalization_drift_kind: str, plan_mode: str
) -> None:
    """One gate for the slice kind AND the composed pair.

    Both kinds go through here rather than the composed kind carrying a private
    copy of the same rule. A duplicated gate is a gate that drifts: anything a
    future change adds under the slice kind would silently not apply to the
    composed one, and the composed one is the shape the sandbox actually
    produces. Code review raised exactly this risk.

    A named function rather than an inline branch so it can be tested directly.
    The inline version's only test asserted the error STRING was present in the
    source, which survived replacing the condition with ``if False`` -- a
    vacuous test that reported the gate as covered when it was gone.

    The digest half is strictly additive information: it rolls on every upstream
    publish regardless of what the plan does. So composing must not widen the
    plan surface beyond the runtime-slice half, which is the one that constrains
    what may be applied.
    """
    if normalization_drift_kind not in _RUNTIME_SLICE_NORMALIZATION_KINDS:
        return
    # Composed modes are admitted when a part is: the re-projection belongs to
    # whichever reviewed transition touched the slice, and composition does not
    # make that transition less reviewed. Same reasoning as the authority-digest
    # allowlist; the drift half stays validated by the exec-identity subset test
    # and _check_planned_security regardless.
    if _plan_mode_parts(plan_mode) & _AUTHORITY_RUNTIME_NORMALIZATION_PLAN_MODES:
        return
    if (
        normalization_drift_kind == _SLICE_AND_AUTHORITY_DIGEST_NORMALIZATION_KIND
        and plan_mode.startswith("composed-")
    ):
        # A COMPOSED plan mode is admissible for the composed drift kind.
        #
        # This is a widening, stated plainly. What justifies it is that
        # "composed-" is not a loose category -- it is the strongest shape
        # guarantee this checker produces. _compose_admitted_transitions only
        # returns it after proving every changed address belongs to a reviewed
        # transition, that the transitions are pairwise disjoint, that their
        # union is EXACTLY the change set, and after running each transition's
        # own deep validator. Several single modes already in the allowlist above
        # carry a weaker guarantee than that.
        #
        # The drift half is likewise fully validated: the digest by
        # _check_digest_normalization, the exec identities by the subset test
        # plus _check_planned_security, which runs for every plan outside this
        # dispatch and is where policy CONTENT is actually judged.
        #
        # Deliberately NOT extended to the slice-only kind: that kind predates
        # this and its narrower binding is not mine to loosen without a reason
        # of its own.
        return
    raise ContractError(
        "authority runtime-slice state normalization is admitted only for "
        "a runtime-slice transition, proof rollout, or steady no-op re-read"
    )


def _require_normalization_plan_mode(
    normalization_drift_kind: str, plan_mode: str, plan: dict[str, Any]
) -> None:
    """Gate which transition the combined digest normalization may accompany.

    A refresh-only absorb, OR the Hub image update that the Hub digest write is
    precisely what causes. This mirrors the authority-digest rule, which already
    admits "authority-image-update" for exactly that reason.

    Without it the pair deadlocks: a refresh-only absorb is the only other
    route, and any SSM write re-drifts the parameter on version, so the drift is
    back by the time the transition plan runs.

    The drift itself is unaffected -- _check_digest_normalization still pins each
    parameter's identity, description, ARN, an immutable sha256 value that
    actually changed, and a planned no-op on the parameter -- and the Hub image
    transition remains separately proven image-only.
    """
    if normalization_drift_kind != "authority-and-hub-digest":
        return
    allowed = plan_mode in ("no-op", "hub-worker-image-update") or (
        plan_mode.startswith("composed-") and "hub-worker-image-update" in plan_mode
    )
    if not allowed:
        raise ContractError(
            "combined Authority and Hub digest normalization may accompany "
            "only a refresh-only plan or the reviewed Hub worker image update"
        )
    if plan_mode == "no-op" and "resource_changes" in plan:
        raise ContractError(
            "combined digest-only state normalization requires a refresh-only plan"
        )


def _check_state_normalization_drift(
    drift: list[dict[str, Any]],
    by_address: dict[str, dict[str, Any]],
    *,
    refresh_only: bool,
) -> str:
    """Admit one exact, reviewed state-only normalization kind.

    Terraform marks that delta applyable for ``-refresh-only``. An ordinary
    refresh-enabled plan with no configuration changes is not applyable; both
    plan shapes are admitted only when their exact applyability matches below.

    Pure first projections (``_drift_is_first_projection_only``) are filtered
    FIRST and carry no signal, so they never need a reviewed kind. Whatever
    remains -- every entry where state held a prior value that changed -- still
    requires an exact reviewed normalization below, unchanged.
    """
    if not drift:
        return "none"
    # Invert the default. Matching an allowlist of attribute names and addresses
    # made every newly applied slice a blocking widening PR, because a
    # first-applied resource necessarily projects attributes no allowlist
    # anticipated -- five such PRs in one day, none of which caught a defect. The
    # measured sandbox Control drift was 108 of 110 pure first projections (106
    # alarms re-projecting ok_actions/insufficient_data_actions, a listener tags
    # -> {}, and the Hub NLB security group's ingress/egress read back from an
    # empty state). Filtering on the before-value keeps the two real value
    # changes -- the seeded Hub identity parameter and a replaced load-balancer
    # ARN -- on the strict path, where they still must match a reviewed shape.
    _, drift = _partition_first_projection_drift(drift)
    if not drift:
        return "first-projection"
    # From here down ``drift`` is the substantive remainder, and every existing
    # reviewed-kind matcher below sees exactly that. Rejection diagnostics
    # therefore name only the entries that actually carry a signal.
    # Derived positionally from ``drift``: every zip() below pairs each address
    # with its own drift item by construction.
    addresses = tuple(item.get("address") for item in drift)
    if (
        all(isinstance(address, str) for address in addresses)
        and set(addresses)
        == set(AUTHORITY_PROOF_PREPARE_RECOVERY_DRIFT_ADDRESSES)
    ):
        _check_authority_proof_prepare_recovery_drift(drift, by_address)
        return AUTHORITY_PROOF_PREPARE_RECOVERY_NORMALIZATION_KIND
    if (
        all(isinstance(address, str) for address in addresses)
        and set(addresses)
        and set(addresses) <= set(AUTHORITY_IMAGE_UPDATE_RECOVERY_REPLACES)
    ):
        _check_authority_proof_concurrency_recovery_drift(drift, by_address)
        return AUTHORITY_PROOF_CONCURRENCY_RECOVERY_NORMALIZATION_KIND
    if not all(isinstance(address, str) for address in addresses):
        raise _unexpected_drift_error(drift)
    if addresses and all(
        (
            address.startswith("module.control.aws_lambda_alias.authority[")
            or address.startswith("module.control.aws_lambda_function.authority[")
        )
        and item.get("change", {}).get("actions") == ["update"]
        and by_address.get(address, {}).get("change", {}).get("actions")
        == ["no-op"]
        for address, item in zip(addresses, drift)
    ):
        # A failed Authority apply leaves state behind live on exactly the
        # aliases/functions whose AWS calls succeeded before the error (the
        # 2026-08-11 prepare apply died on ResourceConflictException after the
        # ca-pm publish went through). The refresh reconciles state to live, and
        # requiring every drifted address to be planned NO-OP is what confines
        # this to pure state catch-up: a drifted address with a pending change
        # still fails closed to the terminal rejection below.
        #
        # Deliberately a GENERAL kind, not a one-shot heal: any future failed
        # Authority apply leaves this same residue, and the confinement (all
        # no-op, plus the immediately-before-apply state binding) is what makes
        # it safe -- not the specific 2026-08-11 event. Also deliberately does
        # NOT require refresh_only, unlike redis-passwords: this catch-up
        # legitimately rides ordinary deploy plans, and gating it to
        # refresh-only dispatches would leave every routine deploy wedged
        # behind an attended refresh. Skipping plan-mode gating is safe for the
        # same reason it is safe to skip here (see the check_plan comment).
        return "authority-alias-refresh"
    if addresses == _REDIS_PASSWORD_NORMALIZATION_ADDRESSES:
        if not refresh_only:
            raise ContractError(
                "Redis password projection normalization requires a refresh-only plan"
            )
        _check_redis_password_normalization(drift, by_address)
        return "redis-passwords"
    if (
        len(drift) == 2
        and {item.get("address") for item in drift}
        == _AUTHORITY_ENABLEMENT_NORMALIZATION_ADDRESSES
    ):
        # The Step-3 enablement plan refreshes both benign normalizations at
        # once (see ``_AUTHORITY_ENABLEMENT_NORMALIZATION_ADDRESSES``). Validate
        # EACH drift against its own exact single-drift reviewed shape -- the
        # same ``_check_publisher_role_normalization`` /
        # ``_check_digest_normalization`` used for the singly admitted kinds,
        # neither weakened -- and admit the pair only when BOTH pass. Dispatch by
        # address, so admission is independent of the order Terraform serializes
        # the pair in (we cannot observe the live ordering locally, and order
        # carries no security weight once each item is exactly validated). The
        # matched length/set guarantees exactly one of each address. Unlike the
        # Redis pair, this is admissible in a config-changing (non-refresh-only)
        # plan: the caller restricts it to ``authority-contract-binding`` because
        # the authority digest rolls permanently and must bind into the same
        # enablement plan that changes the foundation contract.
        by_drift_address = {item.get("address"): item for item in drift}
        _check_publisher_role_normalization(
            by_drift_address["module.control.aws_iam_role.hub_publisher"],
            by_address,
            role_address="module.control.aws_iam_role.hub_publisher",
            policy_address="module.control.aws_iam_role_policy.hub_publisher",
            identity_checker=_require_hub_publisher_identity,
            label="Hub",
        )
        _check_digest_normalization(
            by_drift_address[_AUTHORITY_DIGEST_ADDRESS],
            by_address,
            spec=_AUTHORITY_DIGEST_SPEC,
        )
        return _AUTHORITY_ENABLEMENT_NORMALIZATION_KIND
    drift_addresses = [item.get("address") for item in drift]
    if (
        all(isinstance(address, str) for address in drift_addresses)
        and _AUTHORITY_DIGEST_ADDRESS in drift_addresses
        and set(drift_addresses) - {_AUTHORITY_DIGEST_ADDRESS}
        and set(drift_addresses)
        <= (
            set(AUTHORITY_RUNTIME_RESOURCES)
            | AUTHORITY_RUNTIME_OPENED_ADDRESSES
            | _AUTHORITY_EXEC_IDENTITY_ADDRESSES
            | {_AUTHORITY_DIGEST_ADDRESS}
        )
    ):
        # The runtime-slice re-projection and the Authority image digest, in one
        # plan. Each already has a reviewed kind; neither matches their UNION, so
        # a plan carrying both fell through to the terminal rejection -- and both
        # arrive together by construction, because the digest rolls on every
        # upstream publish while the slice re-projects on every partial-apply
        # retry. Observed as a 27-entry rejection (26 slice + 1 digest) that
        # blocked every Control plan, including the ones that would have fixed it.
        #
        # This is a PARTITION, not a relaxation, and it mirrors what
        # ``_compose_admitted_transitions`` already does for planned changes and
        # what ``_AUTHORITY_ENABLEMENT_NORMALIZATION_KIND`` already does for the
        # Hub-publisher + digest pair:
        #
        #   * both halves must be NON-EMPTY, so this can never become a second,
        #     looser route to a kind the single-kind chain judges on its own;
        #   * the two halves must together be exactly the drift, so no third
        #     address rides along unvalidated;
        #   * each half runs its OWN existing validator, unchanged.
        digest_item = next(
            item
            for item in drift
            if item.get("address") == _AUTHORITY_DIGEST_ADDRESS
        )
        _check_digest_normalization(
            digest_item, by_address, spec=_AUTHORITY_DIGEST_SPEC
        )
        return _SLICE_AND_AUTHORITY_DIGEST_NORMALIZATION_KIND
    if all(isinstance(address, str) for address in drift_addresses) and set(
        drift_addresses
    ) <= (set(AUTHORITY_RUNTIME_RESOURCES) | AUTHORITY_RUNTIME_OPENED_ADDRESSES):
        # Partial-apply RETRY of the runtime slice. When some slice resources
        # already applied on an earlier attempt, a refresh-enabled completion
        # plan re-reads them (and the dependency endpoints being opened) and
        # records benign provider re-projections in ``resource_drift`` -- no
        # "changed outside of Terraform" config delta, only state normalization
        # of already-applied objects. This admission is STRICTLY confined: every
        # drifted address must be one of the slice's own resources
        # (AUTHORITY_RUNTIME_RESOURCES) or one of its opened dependency
        # endpoints (AUTHORITY_RUNTIME_OPENED_ADDRESSES). It does NOT relax the
        # field contract: the security-load-bearing fields of every slice
        # resource are still validated on the post-drift after-state by
        # ``_check_authority_runtime_resources`` and the endpoint-policy checks,
        # so this only lets the completion plan reach those checks. Any drift
        # address OUTSIDE the slice fails this subset test and falls through to
        # the exact single-drift handling below, which fails closed. The caller
        # binds this kind to the runtime-slice completion (or a refresh-only
        # steady re-read); it is rejected against any other plan shape.
        return "authority-runtime-slice-normalization"
    # The digest address is admitted here only ALONGSIDE a real re-projection. A
    # digest-only drift keeps falling through to its own exact single-drift
    # handler below, which is the reviewed shape for that kind.
    if (
        # Must stay FIRST: a malformed (unhashable) address would raise in the
        # set expressions below instead of being masked by the diagnostic.
        all(isinstance(address, str) for address in drift_addresses)
        and (set(drift_addresses) - {_AUTHORITY_DIGEST_ADDRESS})
        and set(drift_addresses)
        <= (
            set(AUTHORITY_RUNTIME_RESOURCES)
            | AUTHORITY_RUNTIME_OPENED_ADDRESSES
            | _PROVIDER_REPROJECTION_ADDRESSES
            # The per-function execution ROLES re-project `inline_policy` for
            # the same reason the Hub roles already in the allowlist do: IAM
            # canonicalises a policy document on read-back (a scalar `Action`
            # comes back as a one-element list), so a role whose policy is owned
            # by a separate aws_iam_role_policy drifts on refresh without
            # anything having changed in AWS. Their POLICY addresses were
            # already admitted; the roles that carry the read-back were not, so
            # the set test failed and the whole branch was unreachable.
            | _AUTHORITY_EXEC_IDENTITY_ADDRESSES
            | {_AUTHORITY_DIGEST_ADDRESS}
        )
    ):
        # The same benign re-projection as the branch above, but spanning the
        # Hub keygen/execution roles and the OTP Redis SG as well, which are
        # foundation and hub-worker resources rather than runtime-slice ones and
        # so fail that branch's subset test. Observed live on the sandbox Control
        # root: 27 drift entries over six addresses, every one of them the
        # provider recording an Optional+Computed collection that was absent from
        # state (`layers`, `alarm_actions`, `ok_actions`,
        # `insufficient_data_actions`) plus the OTP Redis standalone TLS/6379
        # ingress read-back. Nothing changed in AWS out of band.
        #
        # Admission is gated on the DELTA SHAPE, not merely the address set:
        # `_check_provider_reprojection_drift` requires every differing key to be
        # an absent/null -> [] normalization, with the single exception of the
        # OTP Redis `ingress`, which is handed to the same
        # `_check_otp_redis_ingress` used everywhere else and so still must be
        # exactly one SG-scoped TLS/6379 rule. A real value change to any of
        # these resources -- including a widened SG rule -- fails closed here.
        #
        # NOT gated on refresh-only, following the runtime-slice branch above
        # rather than the Redis-password one. The safety here is carried by the
        # delta-shape gate, not by the operation mode, and gating on
        # refresh-only would make the admission unreachable in practice:
        # `-refresh-only` currently cannot complete against this module at all.
        # It dies before writing a plan, in four places -- hub_keygen.tf's
        # postcondition indexing `self` on an instance that does not exist yet,
        # and hub_worker.tf's locals dereferencing
        # `local.authority_selected_alias_targets.hub` while it is null. Those
        # are separate defects worth their own fix; this drift shows up on the
        # ordinary refresh-enabled plan, which is where it must be admitted.
        # The Authority image digest parameter rolls on every qurl-service main
        # publish, so it can co-occur with the re-projection set. It is NOT
        # admitted loosely: each digest drift is handed to the SAME
        # _check_digest_normalization used for the single-drift kind, unchanged,
        # exactly as the enablement pair above validates each of its two drifts
        # with its own exact checker. Only the remainder goes to the
        # re-projection gate.
        digest_drift = [
            item for item in drift if item.get("address") == _AUTHORITY_DIGEST_ADDRESS
        ]
        for item in digest_drift:
            _check_digest_normalization(item, by_address, spec=_AUTHORITY_DIGEST_SPEC)
        _check_provider_reprojection_drift(
            [item for item in drift if item.get("address") != _AUTHORITY_DIGEST_ADDRESS]
        )
        if digest_drift:
            return "provider-reprojection-with-authority-digest"
        return "provider-reprojection"
    # BOTH publisher-owned digests drifting at once.
    #
    # Each is already an admitted normalization on its own, and they are
    # independent: the Authority publisher and the Hub publisher advance their
    # own parameter with no relation to each other. Handling only one at a time
    # deadlocks -- reducing two drifts to one requires an apply to absorb the
    # other, and the apply is exactly what this check gates. Any SSM write also
    # bumps the parameter version, so even rewriting a value back to what is
    # deployed re-drifts it rather than clearing it.
    #
    # This admits nothing new about either drift. Each is still validated by the
    # same _check_digest_normalization against its OWN spec, so a digest that is
    # not a clean value-plus-version projection still fails closed. What changes
    # is only that two independently reviewed normalizations may land together.
    if len(drift) == 2:
        by_drift_address = {item.get("address"): item for item in drift}
        if set(by_drift_address) == {_AUTHORITY_DIGEST_ADDRESS, _HUB_DIGEST_ADDRESS}:
            _check_digest_normalization(
                by_drift_address[_AUTHORITY_DIGEST_ADDRESS],
                by_address,
                spec=_AUTHORITY_DIGEST_SPEC,
            )
            _check_digest_normalization(
                by_drift_address[_HUB_DIGEST_ADDRESS],
                by_address,
                spec=_HUB_DIGEST_SPEC,
            )
            return "authority-and-hub-digest"
    if len(drift) != 1:
        raise _unexpected_drift_error(drift)
    item = drift[0]
    if item.get("address") == "module.control.aws_iam_role.authority_publisher":
        _check_publisher_role_normalization(
            item,
            by_address,
            role_address="module.control.aws_iam_role.authority_publisher",
            policy_address="module.control.aws_iam_role_policy.authority_publisher",
            identity_checker=_require_authority_publisher_identity,
            label="authority",
        )
        return "publisher-role"
    if item.get("address") == "module.control.aws_iam_role.hub_publisher":
        _check_publisher_role_normalization(
            item,
            by_address,
            role_address="module.control.aws_iam_role.hub_publisher",
            policy_address="module.control.aws_iam_role_policy.hub_publisher",
            identity_checker=_require_hub_publisher_identity,
            label="Hub",
        )
        return "hub-publisher-role"
    if item.get("address") == _AUTHORITY_DIGEST_ADDRESS:
        _check_digest_normalization(
            item,
            by_address,
            spec=_AUTHORITY_DIGEST_SPEC,
        )
        return "authority-digest"
    if item.get("address") == _HUB_DIGEST_ADDRESS:
        _check_digest_normalization(item, by_address, spec=_HUB_DIGEST_SPEC)
        return "hub-digest"
    raise _unexpected_drift_error(drift)


_OTP_REDIS_SG_ADDRESS = "module.control.aws_security_group.otp_redis"
# Foundation / hub-worker resources that sit OUTSIDE the runtime slice but
# re-project the same absent -> empty-collection normalization on a refreshed
# read. Kept as an exact allowlist so a newly drifting address fails closed.
_PROVIDER_REPROJECTION_ADDRESSES = frozenset(
    {
        "module.control.aws_iam_role.hub_keygen[0]",
        "module.control.aws_iam_role.hub_execution[0]",
        _OTP_REDIS_SG_ADDRESS,
        # The Hub edge slice settles these on its first refreshed read: the
        # listener projects `tags`, the target group picks up the REPLACED load
        # balancer's ARN, the NLB SG reads back its standalone rules, and the
        # identity parameter carries the key the keygen Lambda published.
        "module.control.aws_lb_listener.hub[0]",
        "module.control.aws_lb_target_group.hub[0]",
        "module.control.aws_security_group.hub_nlb[0]",
        "module.control.aws_ssm_parameter.hub_public_key[0]",
    }
    # Every Authority alarm re-projects `ok_actions` and
    # `insufficient_data_actions` from absent to []. 106 of them applied with
    # the Hub edge slice. Enumerated from the same constant the alarm contract
    # uses, so a new alarm family cannot silently widen this set -- it has to be
    # added to AUTHORITY_ALARM_RESOURCES, which its own exact checks then bind.
    | set(AUTHORITY_ALARM_RESOURCES)
    | set(AUTHORITY_ALARM_UPDATE_ADDRESSES)
)


def _require_hub_nlb_ingress_projection(value: Any, address: str) -> None:
    """Require a hub NLB ``ingress`` re-projection to be exactly UDP edge rules.

    The attribute is a deprecated read-back of the standalone
    ``aws_vpc_security_group_ingress_rule.hub_nlb_udp`` rules, so a refreshed
    plan re-projects whatever AWS holds. The SOURCE set is deliberately not
    asserted here: it is owned by those rule resources in this same plan, and
    check_live asserts the live group separately. Widening the sources is a
    reviewed decision (qurl-go ADR 0001 opened the sandbox edge), and pinning
    them in two places again is what made the port migration unappliable.

    What is pinned is the shape: every projected rule must be UDP on the exact
    client edge port. A rule on another protocol or port is not a projection of
    the reviewed edge and fails closed.
    """
    if not isinstance(value, list) or not value:
        raise ContractError(
            f"{address} ingress projection must be a non-empty collection"
        )
    for entry in value:
        if not isinstance(entry, dict):
            raise ContractError(f"{address} ingress entry must be an object")
        protocol = str(entry.get("protocol") or "").lower()
        if protocol != "udp":
            raise ContractError(
                f"{address} ingress projection admits UDP only, got {protocol!r}"
            )
        if (
            entry.get("from_port") != HUB_CLIENT_EDGE_PORT
            or entry.get("to_port") != HUB_CLIENT_EDGE_PORT
        ):
            raise ContractError(
                f"{address} ingress projection must be on the client edge port "
                f"{HUB_CLIENT_EDGE_PORT}"
            )


def _require_inline_policy_projection(value: Any, address: str) -> None:
    """Require an ``inline_policy`` re-projection to be exactly that.

    Every entry must be a named, non-empty, parseable IAM policy document. A
    scalar, a malformed entry, or an unparseable document is not a projection
    of the managed ``aws_iam_role_policy`` and fails closed.
    """
    if not isinstance(value, list) or not value:
        raise ContractError(
            f"{address} inline_policy projection must be a non-empty collection"
        )
    for entry in value:
        if not isinstance(entry, dict) or set(entry) != {"name", "policy"}:
            raise ContractError(
                f"{address} inline_policy entry must carry exactly name and policy"
            )
        name = entry.get("name")
        policy = entry.get("policy")
        if not isinstance(name, str) or not name:
            raise ContractError(f"{address} inline_policy entry name is invalid")
        if not isinstance(policy, str) or not policy:
            raise ContractError(f"{address} inline_policy {name} document is invalid")
        try:
            document = json.loads(policy)
        except json.JSONDecodeError as exc:
            raise ContractError(
                f"{address} inline_policy {name} is not parseable JSON: {exc}"
            ) from exc
        statements = document.get("Statement") if isinstance(document, dict) else None
        if not isinstance(statements, list) or not statements:
            raise ContractError(
                f"{address} inline_policy {name} must hold at least one statement"
            )
        for statement in statements:
            if not isinstance(statement, dict) or not statement.get("Effect"):
                raise ContractError(
                    f"{address} inline_policy {name} statement is malformed"
                )
        # Deliberately SHAPE ONLY -- no assertion about actions or resources.
        # The policy content is owned by aws_iam_role_policy and gated by
        # check-terraform-iam-coverage.py; re-asserting it from a drift
        # projection would duplicate that contract in a weaker place and get it
        # wrong. It already did once here: an earlier revision rejected a
        # wildcard Resource, which fails against the Lambda VPC ENI statement
        # (ec2:CreateNetworkInterface and friends do not support resource-level
        # permissions, so AWS requires "*").


def _require_hub_carrier_move(before: Any, after: Any, address: str) -> None:
    """Admit exactly the reviewed Hub NLB replacement, nothing else."""
    if not isinstance(before, list) or not isinstance(after, list):
        raise ContractError(f"{address} load_balancer_arns must be collections")
    if len(before) != 1 or len(after) != 1:
        raise ContractError(
            f"{address} must stay associated with exactly one load balancer"
        )
    if not str(before[0]).endswith(f"/{HUB_EDGE_LEGACY_LOAD_BALANCER_NAME}") and (
        f"/{HUB_EDGE_LEGACY_LOAD_BALANCER_NAME}/" not in str(before[0])
    ):
        raise ContractError(f"{address} did not move from the reviewed legacy carrier")
    if f"/{HUB_EDGE_LOAD_BALANCER_NAME}/" not in str(after[0]):
        raise ContractError(f"{address} did not move to the reviewed edge carrier")


def _require_hub_identity_seeding(
    key: str, before: Any, after: Any, address: str
) -> None:
    """Admit exactly the sentinel -> published-key transition, one direction."""
    if key == "version":
        if not isinstance(before, int) or not isinstance(after, int) or after <= before:
            raise ContractError(f"{address} version must advance")
        return
    if before != "pending-keygen":
        raise ContractError(
            f"{address} may only be seeded from the pending-keygen sentinel"
        )
    decoded = _canonical_base64_32(after)
    if not decoded or not any(decoded):
        raise ContractError(
            f"{address} must be seeded with a canonical non-zero 32-byte key"
        )


def _check_provider_reprojection_drift(drift: list[dict[str, Any]]) -> None:
    """Require every admitted re-projection to be a pure state normalization.

    The address allowlist alone would admit ANY change to those resources. This
    pins the delta itself: a differing key is admissible only when it went from
    absent/null to an empty collection, or when it is the OTP Redis ``ingress``
    carrying exactly the one standalone SG-scoped TLS/6379 rule.
    """
    for item in drift:
        address = item.get("address")
        change = item.get("change")
        before = change.get("before") if isinstance(change, dict) else None
        after = change.get("after") if isinstance(change, dict) else None
        if not isinstance(before, dict) or not isinstance(after, dict):
            raise ContractError(
                f"{address} re-projection drift must carry object before and after"
            )
        for key in sorted(set(before) | set(after)):
            if before.get(key) == after.get(key):
                continue
            if address == _OTP_REDIS_SG_ADDRESS and key == "ingress":
                # Same exact-shape gate used on the planned and state paths.
                _check_otp_redis_ingress(after, {}, address)
                continue
            if (
                address.split("[")[0]
                == "module.control.aws_security_group.hub_nlb"
                and key == "ingress"
            ):
                # Deprecated Optional+Computed read-back of the standalone
                # aws_vpc_security_group_ingress_rule.hub_nlb_udp rules, exactly
                # like `inline_policy` below. State keeps whatever the attribute
                # held when the SG was last written, so every change made through
                # the standalone rules re-projects here once.
                #
                # Content is NOT taken on trust. The rules are owned by their own
                # resources in this same plan, and check_live asserts the LIVE
                # security group separately. What is pinned here is the shape:
                # UDP only, on the reviewed client edge port, and nothing else.
                # A rule on another protocol or port still fails closed.
                _require_hub_nlb_ingress_projection(after.get(key), address)
                continue
            if key == "inline_policy" and ".aws_iam_role." in str(address):
                # `inline_policy` is a deprecated Optional+Computed READ-BACK of
                # the separately managed aws_iam_role_policy resource, so a
                # refreshed plan re-projects whatever AWS holds even though the
                # role block declares no inline policy. Live sandbox Control
                # shows it on authority_exec (state had []), hub_execution and
                # hub_keygen (state had a stale earlier projection).
                #
                # This does NOT take the policy CONTENT on trust. The content is
                # owned by aws_iam_role_policy, which is in this same plan: if
                # live differed from config, Terraform would plan a change to
                # that resource. Verified on the CI plan, where every
                # aws_iam_role_policy is a no-op and the only non-no-op changes
                # are the Hub edge slice. What is asserted here is the shape --
                # a projection of named policy documents and nothing else.
                _require_inline_policy_projection(after.get(key), address)
                continue
            if (
                address.split("[")[0]
                == "module.control.aws_lb_target_group.hub"
                and key == "load_balancer_arns"
            ):
                # The Hub edge replaced the NLB, so the target group's sole
                # association follows it. Admit ONLY a one-for-one move between
                # the two reviewed carrier names -- legacy -> generation 2. A
                # target group that gains a second load balancer, loses its
                # association, or points at an unreviewed carrier still fails.
                _require_hub_carrier_move(before.get(key), after.get(key), address)
                continue
            if (
                address.split("[")[0]
                == "module.control.aws_ssm_parameter.hub_public_key"
                and key in ("value", "version")
            ):
                # The identity seeding itself: the keygen Lambda replaced the
                # sentinel with the published key, bumping the parameter version.
                # This is the ONE transition this parameter may make -- proved
                # exactly, in that direction only.
                _require_hub_identity_seeding(key, before.get(key), after.get(key), address)
                continue
            if before.get(key) is None and after.get(key) == []:
                continue
            raise ContractError(
                f"{address} drift is not an empty-collection re-projection: {key}"
            )


def _check_redis_password_normalization(
    drift: list[dict[str, Any]],
    by_address: dict[str, dict[str, Any]],
) -> None:
    """Admit the exact one-time null-to-empty provider state projection."""
    if (
        len(drift) != len(_REDIS_PASSWORD_NORMALIZATION_ADDRESSES)
        or tuple(item.get("address") for item in drift)
        != _REDIS_PASSWORD_NORMALIZATION_ADDRESSES
    ):
        raise _unexpected_drift_error(drift)

    for item, address in zip(
        drift,
        _REDIS_PASSWORD_NORMALIZATION_ADDRESSES,
        strict=True,
    ):
        expected_identity = {
            "address": address,
            "mode": "managed",
            "module_address": "module.control",
            "name": address.rsplit(".", 1)[1],
            "provider_name": "registry.terraform.io/hashicorp/aws",
            "type": "aws_elasticache_user",
        }
        if (
            set(item) != {*expected_identity, "change"}
            or any(
                item.get(field) != value
                for field, value in expected_identity.items()
            )
        ):
            raise _unexpected_drift_error([item])

        change = item.get("change")
        if (
            not isinstance(change, dict)
            or set(change) != _CHANGE_KEYS
            or change.get("actions") != ["update"]
            or not _json_equal(change.get("after_unknown"), {})
            or not _json_equal(
                change.get("before_sensitive"),
                _REDIS_PASSWORD_NORMALIZATION_SENSITIVE,
            )
            or not _json_equal(
                change.get("after_sensitive"),
                _REDIS_PASSWORD_NORMALIZATION_SENSITIVE,
            )
        ):
            raise ContractError(
                "Redis password projection normalization envelope is not exact"
            )

        before = change.get("before")
        after = change.get("after")
        if (
            not isinstance(before, dict)
            or not isinstance(after, dict)
            or set(before) != set(after)
        ):
            raise ContractError(
                "Redis password projection normalization values are malformed"
            )
        changed_fields = {
            field
            for field in before
            if not _json_equal(before[field], after[field])
        }
        if (
            changed_fields != {"authentication_mode"}
            or not _json_equal(
                before.get("authentication_mode"),
                [{"password_count": 0, "passwords": None, "type": "iam"}],
            )
            or not _json_equal(
                after.get("authentication_mode"),
                [{"password_count": 0, "passwords": [], "type": "iam"}],
            )
        ):
            raise ContractError(
                "Redis password projection normalization must be exactly null-to-empty"
            )

        planned = by_address[address].get("change", {})
        if (
            planned.get("actions") != ["no-op"]
            or not _json_equal(planned.get("before"), after)
            or not _json_equal(planned.get("after"), after)
        ):
            raise ContractError(
                "Redis password projection normalization must match the "
                "refresh-only no-op state"
            )


def _check_publisher_role_normalization(
    item: dict[str, Any],
    by_address: dict[str, dict[str, Any]],
    *,
    role_address: str,
    policy_address: str,
    identity_checker: Any,
    label: str,
) -> None:
    """Admit the provider's exact state-only inline-policy reflection."""
    if (
        item.get("address") != role_address
        or item.get("mode") != "managed"
        or item.get("type") != "aws_iam_role"
    ):
        raise _unexpected_drift_error([item])
    change = item.get("change")
    if not isinstance(change, dict) or change.get("actions") != ["update"]:
        raise ContractError(
            f"{label} publisher role normalization must be an in-state update"
        )
    before = change.get("before")
    after = change.get("after")
    if not isinstance(before, dict) or not isinstance(after, dict):
        raise ContractError(
            f"{label} publisher role normalization values are malformed"
        )
    changed_fields = {
        field
        for field in set(before) | set(after)
        if field not in before or field not in after or before[field] != after[field]
    }
    if changed_fields != {"inline_policy"} or before.get("inline_policy") not in (
        None,
        [],
    ):
        raise ContractError(
            f"{label} publisher role normalization may only reflect its separately "
            "managed inline policy; "
            f"changed_fields={sorted(changed_fields)}"
        )
    planned_role = by_address[role_address].get("change", {})
    if planned_role.get("actions") != ["no-op"] or planned_role.get("after") != after:
        raise ContractError(
            f"{label} publisher role normalization must match the refresh-only "
            "no-op state"
        )
    publisher_policy = by_address[policy_address].get("change", {}).get("after")
    if not isinstance(publisher_policy, dict):
        raise ContractError(
            f"{label} publisher policy normalization values are malformed"
        )
    identity_checker(
        after,
        publisher_policy,
        reflected_inline_policy=True,
    )


def _check_digest_normalization(
    item: dict[str, Any],
    by_address: dict[str, dict[str, Any]],
    *,
    spec: dict[str, str],
) -> None:
    """Admit only a dedicated publisher's externally owned digest update.

    Terraform owns the parameter and intentionally ignores its value after
    creation; the trusted repository publisher owns subsequent value updates.
    Bind that observed value/version pair into the saved Control plan. When it
    accompanies the one reviewed Redis transition, the apply workflow re-proves
    the exact live drift immediately before consuming the saved plan.
    """
    _, after = _validate_digest_normalization(item, spec=spec)
    planned = by_address[spec["address"]].get("change", {})
    if planned.get("actions") != ["no-op"] or planned.get("after") != after:
        raise ContractError(
            f"{spec['label']} digest normalization must match the refreshed "
            "planned state"
        )


def _validate_digest_normalization(
    item: dict[str, Any],
    *,
    spec: dict[str, str],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Validate the provider-version-specific external digest drift shape."""
    expected_identity = {
        "address": spec["address"],
        "mode": "managed",
        "module_address": "module.control",
        "name": spec["name"],
        "provider_name": "registry.terraform.io/hashicorp/aws",
        "type": "aws_ssm_parameter",
    }
    if (
        set(item) != {*expected_identity, "change"}
        or any(
            item.get(field) != value
            for field, value in expected_identity.items()
        )
    ):
        raise _unexpected_drift_error([item])
    change = item.get("change")
    if (
        not isinstance(change, dict)
        or set(change) != _CHANGE_KEYS
        or change.get("actions") != ["update"]
    ):
        raise ContractError(
            f"{spec['label']} digest normalization must be an in-state update"
        )
    before = change.get("before")
    after = change.get("after")
    if not isinstance(before, dict) or not isinstance(after, dict):
        raise ContractError(
            f"{spec['label']} digest normalization values are malformed"
        )
    parameter_name = spec["parameter_name"]
    parameter_contract = {
        "allowed_pattern": "",
        "arn": spec["parameter_arn"],
        "data_type": "text",
        "description": spec["description"],
        "has_value_wo": False,
        "id": parameter_name,
        "insecure_value": None,
        "key_id": "",
        "name": parameter_name,
        "overwrite": None,
        "region": AWS_REGION,
        "tier": "Standard",
        "type": "String",
        "value_wo": None,
        "value_wo_version": None,
    }
    value_keys = {*parameter_contract, "tags", "tags_all", "value", "version"}
    if set(before) != value_keys or set(after) != value_keys:
        raise ContractError(
            f"{spec['label']} digest normalization value shape is not exact"
        )
    _require_fields(
        before,
        parameter_contract,
        f"{spec['label']} digest drift before",
    )
    _require_fields(
        after,
        parameter_contract,
        f"{spec['label']} digest drift after",
    )
    # ``before`` and ``after`` share the exact ``value_keys`` set asserted above,
    # so a plain per-key comparison over that set finds every changed field.
    changed_fields = {field for field in value_keys if before[field] != after[field]}
    if changed_fields != {"value", "version"}:
        raise ContractError(
            f"{spec['label']} digest normalization may change only value and "
            "version; "
            f"changed_fields={sorted(changed_fields)}"
        )
    before_value = before.get("value")
    after_value = after.get("value")
    if (
        not isinstance(before_value, str)
        or (
            before_value != "UNPUBLISHED"
            and _DIGEST_PATTERN.fullmatch(before_value) is None
        )
        or not isinstance(after_value, str)
        or _DIGEST_PATTERN.fullmatch(after_value) is None
        or before_value == after_value
    ):
        raise ContractError(
            f"{spec['label']} digest normalization values are not immutable digests"
        )
    before_version = before.get("version")
    after_version = after.get("version")
    if (
        not isinstance(before_version, int)
        or isinstance(before_version, bool)
        or not isinstance(after_version, int)
        or isinstance(after_version, bool)
        or before_version < 1
        or after_version <= before_version
    ):
        raise ContractError(
            f"{spec['label']} digest normalization version did not advance"
        )
    if (
        change.get("after_unknown") != {}
        or change.get("before_sensitive") != _DIGEST_REFRESH_SENSITIVE
        or change.get("after_sensitive") != _DIGEST_REFRESH_SENSITIVE
    ):
        raise ContractError(
            f"{spec['label']} digest normalization has unexpected value metadata"
        )
    return before, after


# The Hub edge slice settles these three on the first refreshed read after it
# applies: the listener projects `tags`, the target group picks up the REPLACED
# load balancer's ARN, and the NLB SG projects the standalone rules AWS holds.
# None carries secret material, so each is proved by the same structural
# placeholder rule as the alarms.
_HUB_EDGE_SETTLING_PREFIXES = (
    "module.control.aws_lb_listener.hub",
    "module.control.aws_lb_target_group.hub",
    "module.control.aws_security_group.hub_nlb",
)
# The Hub public identity parameter is DIFFERENT: its `value` is genuinely
# sensitive (`true`, not a placeholder), so it must never take the structural
# path -- that path exists to prove nothing sensitive is present. Its metadata is
# fixed and identical on both sides, so it gets an exact literal instead.
_HUB_PUBLIC_KEY_REFRESH_SENSITIVE = {
    "tags": {},
    "tags_all": {},
    "value": True,
    "value_wo": True,
}
_ALARM_REFRESH_NORMALIZATION_PREFIXES = (
    "module.control.aws_cloudwatch_metric_alarm.authority_runtime",
    "module.control.aws_cloudwatch_metric_alarm.authority_terminal_outcome",
    "module.control.aws_cloudwatch_metric_alarm.authority_admission_rejected",
    "module.control.aws_cloudwatch_metric_alarm.authority_adapter_contract_violation",
    "module.control.aws_cloudwatch_metric_alarm.authority_adapter_late_result",
    "module.control.aws_cloudwatch_metric_alarm.authority_completion_identity_rejected",
    "module.control.aws_cloudwatch_metric_alarm.authority_spillover",
    "module.control.aws_cloudwatch_composite_alarm."
    "authority_non_provisioned_initialization",
)


def _is_placeholder_sensitive(value: Any) -> bool:
    """True when a sensitive map marks only WHERE a value could be sensitive.

    Terraform renders these maps structurally: `False` for a scalar that is not
    sensitive, and empty collections for lists/maps. A `True` anywhere means a
    REAL sensitive value is present. The alarm families carry no secret material,
    so their maps must be placeholders all the way down -- this refuses to admit
    an alarm re-projection that suddenly carries one.
    """
    if value is True:
        return False
    if value is False or value is None:
        return True
    if isinstance(value, list):
        return all(_is_placeholder_sensitive(item) for item in value)
    if isinstance(value, dict):
        return all(_is_placeholder_sensitive(item) for item in value.values())
    return False


def _refresh_sensitive_contract(
    address: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    if address in _REDIS_PASSWORD_NORMALIZATION_ADDRESSES:
        return (
            _REDIS_PASSWORD_NORMALIZATION_SENSITIVE,
            _REDIS_PASSWORD_NORMALIZATION_SENSITIVE,
        )
    if address in (
        "module.control.aws_iam_role.authority_publisher",
        "module.control.aws_iam_role.hub_publisher",
    ):
        return (
            _PUBLISHER_REFRESH_BEFORE_SENSITIVE,
            _PUBLISHER_REFRESH_AFTER_SENSITIVE,
        )
    if address in (_AUTHORITY_DIGEST_ADDRESS, _HUB_DIGEST_ADDRESS):
        return (
            _DIGEST_REFRESH_SENSITIVE,
            _DIGEST_REFRESH_SENSITIVE,
        )
    if address.split("[")[0] == "module.control.aws_ssm_parameter.hub_public_key":
        return (
            _HUB_PUBLIC_KEY_REFRESH_SENSITIVE,
            _HUB_PUBLIC_KEY_REFRESH_SENSITIVE,
        )
    if address.split("[")[0] in (
        _ALARM_REFRESH_NORMALIZATION_PREFIXES + _HUB_EDGE_SETTLING_PREFIXES
    ):
        # Alarm re-projection. Returning the observed pair would be circular, and
        # a fixed literal cannot work: the shapes differ per family and the
        # composite's `after` legitimately gains a key the `before` lacked --
        # the same first-projection settling the value side shows. `None` asks
        # the caller to validate STRUCTURALLY instead: both maps must be
        # placeholders all the way down, so an alarm drift that ever carried a
        # real sensitive value is rejected rather than normalized.
        return None, None
    raise ContractError(f"refresh drift is not approved for normalization: {address}")


# authority_image_uri tracks the PUBLISHED image digest by design (#3761): the
# digest is read from an SSM parameter the publisher updates out of band, so a
# refresh legitimately observes a newer image than the captured state. Before
# #3761 the digest was pinned in the reviewed basis and every root output was
# stable across a refresh, which is the assumption this normalizer was written
# under.
#
# Permit exactly that movement and nothing else: the SAME repository, differing
# only in the digest. A repository change, a tag-form URI, or a malformed digest
# is still a hard failure, and every other output must still match byte for
# byte.
_DIGEST_TRACKING_OUTPUT = "authority_image_uri"
_ECR_DIGEST_URI = re.compile(r"^(?P<repo>[^@\s]+)@sha256:(?P<digest>[0-9a-f]{64})$")


def _is_published_digest_move(planned: Any, state: Any) -> bool:
    """Report whether two output entries differ only by a same-repo image digest."""
    planned_value = planned.get("value") if isinstance(planned, dict) else None
    state_value = state.get("value") if isinstance(state, dict) else None
    if not isinstance(planned_value, str) or not isinstance(state_value, str):
        return False
    planned_uri = _ECR_DIGEST_URI.match(planned_value)
    state_uri = _ECR_DIGEST_URI.match(state_value)
    if planned_uri is None or state_uri is None:
        return False
    return planned_uri.group("repo") == state_uri.group("repo")


def _check_refresh_only_outputs(
    plan: dict[str, Any], prior_state: dict[str, Any]
) -> None:
    """Bind Terraform's value-only refresh envelope to captured state.

    Terraform 1.14.3 omits unchanged resources from a refresh-only plan, but
    still serializes all root outputs. Keep the resource/module tree exactly
    empty and require those outputs, plus their changes, to be exact
    non-sensitive no-ops against the version-bound pre-plan state.
    """
    planned_values = plan.get("planned_values")
    if (
        not isinstance(planned_values, dict)
        or set(planned_values) != {"outputs", "root_module"}
        or planned_values.get("root_module") != {}
    ):
        raise ContractError(
            f"refresh-only Terraform {TF_VERSION} value tree is malformed; "
            f"{_refresh_only_value_shape(planned_values)}"
        )

    planned_outputs = planned_values.get("outputs")
    state_values = prior_state.get("values")
    state_outputs = (
        state_values.get("outputs") if isinstance(state_values, dict) else None
    )
    if (
        not isinstance(planned_outputs, dict)
        or set(planned_outputs) != EXPECTED_CONTROL_OUTPUTS
        or not isinstance(state_outputs, dict)
        or set(state_outputs)
        not in (
            set(EXPECTED_CONTROL_OUTPUTS),
            set(EXPECTED_CONTROL_OUTPUTS)
            - set(AUTHORITY_PROOF_ALIAS_OUTPUTS.values()),
        )
    ):
        raise ContractError(
            f"refresh-only Terraform {TF_VERSION} output inventory is malformed; "
            f"{_refresh_only_value_shape(planned_values)}"
        )

    for output_name in set(state_outputs):
        planned_output = planned_outputs[output_name]
        state_output = state_outputs[output_name]
        # Terraform 1.14.3 collapses non-sensitive scalar and complex root
        # outputs to the literal false; the version-pinned fixture covers both
        # object and tuple values so a representation change fails closed.
        if not _is_exact_nonsensitive_output_entry(
            planned_output
        ) or not _is_exact_nonsensitive_output_entry(state_output):
            raise ContractError(
                f"refresh-only Terraform {TF_VERSION} output entry {output_name} is malformed; "
                f"{_refresh_only_value_shape(planned_values)}"
            )
        if _json_equal(planned_output, state_output):
            continue
        if output_name == _DIGEST_TRACKING_OUTPUT and _is_published_digest_move(
            planned_output, state_output
        ):
            continue
        raise ContractError(
            f"refresh-only Terraform {TF_VERSION} output {output_name} does not match "
            f"captured state; {_refresh_only_value_shape(planned_values)}"
        )
    for output_name in set(AUTHORITY_PROOF_ALIAS_OUTPUTS.values()) - set(
        state_outputs
    ):
        proof_output = planned_outputs[output_name]
        if (
            not _is_exact_nonsensitive_output_entry(proof_output)
            or proof_output.get("value") is not None
        ):
            raise ContractError(
                f"refresh-only omitted proof alias state output {output_name} "
                "must plan as null"
            )

    output_changes = plan.get("output_changes")
    if (
        not isinstance(output_changes, dict)
        or set(output_changes) != EXPECTED_CONTROL_OUTPUTS
    ):
        raise ContractError(
            f"refresh-only Terraform {TF_VERSION} output changes are malformed; "
            f"{_refresh_only_value_shape(planned_values)}"
        )
    for output_name in EXPECTED_CONTROL_OUTPUTS:
        change = output_changes[output_name]
        output_value = planned_outputs[output_name]["value"]
        if (
            not isinstance(change, dict)
            or set(change) != _CHANGE_KEYS
            or change.get("actions") != ["no-op"]
            or change.get("after_unknown") is not False
            or change.get("before_sensitive") is not False
            or change.get("after_sensitive") is not False
            or not _json_equal(change.get("before"), output_value)
            or not _json_equal(change.get("after"), output_value)
        ):
            raise ContractError(
                f"refresh-only Terraform {TF_VERSION} outputs must be exact no-ops; "
                f"{_refresh_only_value_shape(planned_values)}"
            )


def _reconstruct_refresh_only_changes(
    prior_state: dict[str, Any],
    drift: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Reconstruct the no-op change set from captured state plus admitted drift.

    Shared by the refresh-only ``check_plan`` lane and the pre-apply
    ``check_normalization_drift`` lane so both bind the same way: every entry is a
    no-op against the captured pre-plan inventory, and each admitted drift is
    overlaid only after proving its ``before`` equals the captured state value and
    its sensitive envelope is the exact reviewed refresh shape. The caller
    validates ``prior_state``'s format/version before calling; this function then
    fails closed on any missing inventory, malformed entry, unknown drift value,
    sensitive-metadata mismatch, or drift address absent from the captured state.
    """
    state_values = prior_state.get("values")
    root = (
        state_values.get("root_module") if isinstance(state_values, dict) else None
    )
    resources = [
        item for item in _iter_resources(root) if item.get("mode") == "managed"
    ]
    if not resources:
        raise ContractError(
            "refresh-only plan requires the captured pre-plan state inventory"
        )

    drift_by_address: dict[str, dict[str, Any]] = {}
    for item in drift:
        address = item.get("address") if isinstance(item, dict) else None
        if not isinstance(address, str):
            raise ContractError("Terraform resource drift is malformed")
        if address in drift_by_address:
            raise ContractError(f"duplicate Terraform resource drift: {address}")
        drift_by_address[address] = item

    changes: list[dict[str, Any]] = []
    matched_drift_addresses: set[str] = set()
    for item in resources:
        address = item.get("address")
        resource_values = item.get("values")
        if not isinstance(address, str) or not isinstance(resource_values, dict):
            raise ContractError("Terraform prior-state resource is malformed")
        resolved_values = resource_values
        drift_item = drift_by_address.get(address)
        if drift_item is not None:
            matched_drift_addresses.add(address)
            change = drift_item.get("change")
            if not isinstance(change, dict):
                raise ContractError("Terraform resource drift change is malformed")
            if change.get("after_unknown") != {}:
                raise ContractError(
                    "refresh-only normalization drift contains unknown values"
                )
            before_sensitive, after_sensitive = _refresh_sensitive_contract(address)
            if before_sensitive is None:
                if (
                    "before_sensitive" not in change
                    or "after_sensitive" not in change
                    or not _is_placeholder_sensitive(change["before_sensitive"])
                    or not _is_placeholder_sensitive(change["after_sensitive"])
                ):
                    raise ContractError(
                        "refresh-only normalization drift has unexpected "
                        "sensitive-value metadata"
                    )
            elif (
                "before_sensitive" not in change
                or "after_sensitive" not in change
                or not _json_equal(
                    change["before_sensitive"],
                    before_sensitive,
                )
                or not _json_equal(
                    change["after_sensitive"],
                    after_sensitive,
                )
            ):
                raise ContractError(
                    "refresh-only normalization drift has unexpected sensitive-value metadata"
                )
            # Terraform 1.14.3 renders the same resource values in the captured
            # state and drift.before. Keep that equality exact: a provider or
            # Terraform representation change must abort rather than weaken the
            # state-to-plan binding.
            if change.get("before") != resource_values:
                raise ContractError(
                    f"refresh drift before value does not match captured state: {address}"
                )
            resolved_values = change.get("after")
            if not isinstance(resolved_values, dict):
                raise ContractError("Terraform resource drift after value is malformed")
        changes.append(
            {
                "address": address,
                "mode": item.get("mode"),
                "type": item.get("type"),
                "change": {
                    "actions": ["no-op"],
                    "after": resolved_values,
                    "after_unknown": {},
                    "before": resolved_values,
                },
            }
        )
    unmatched_drift = sorted(set(drift_by_address) - matched_drift_addresses)
    if unmatched_drift:
        raise ContractError(
            f"refresh drift is absent from captured state: {unmatched_drift}"
        )
    return changes


def _plan_resource_changes(
    plan: dict[str, Any],
    drift: list[dict[str, Any]],
    prior_state: Any,
) -> list[dict[str, Any]]:
    """Return ordinary changes or reconstruct Terraform's refresh-only shape.

    Terraform 1.14 omits ``resource_changes`` when ``-refresh-only`` has no
    configuration changes, and its ``planned_values`` may omit every unchanged
    resource. Preserve the exact-inventory and planned-value checks by using the
    separately captured, version-bound pre-plan state for the unchanged
    inventory and overlaying only the admitted refresh drift. The workflow
    proves that state object did not move while planning and re-captures the
    identical object before apply.
    """
    if "resource_changes" in plan:
        changes = plan["resource_changes"]
        if not isinstance(changes, list):
            raise ContractError("Terraform plan resource_changes must be an array")
        return changes
    if not drift:
        raise ContractError("Terraform plan resource_changes must be an array")

    if (
        not isinstance(prior_state, dict)
        or prior_state.get("format_version") != "1.0"
        or prior_state.get("terraform_version") != TF_VERSION
    ):
        raise ContractError(
            f"refresh-only compatibility requires exact Terraform {TF_VERSION} state JSON"
        )
    _check_refresh_only_outputs(plan, prior_state)
    return _reconstruct_refresh_only_changes(prior_state, drift)


def _require_create_shapes(
    addresses: set[str],
    by_address: dict[str, dict[str, Any]],
    message: str | None = None,
) -> None:
    """Assert every address is a pure create (no ``before``, dict ``after``)."""
    for address in addresses:
        change = by_address[address]["change"]
        if change.get("before") is not None or not isinstance(
            change.get("after"), dict
        ):
            raise ContractError(message or f"{address} create shape is malformed")


def _load_hub_source_fence_provider_changes() -> dict[str, dict[str, Any]]:
    """Load the pinned provider envelopes for the one-time Hub replacement."""

    try:
        payload = HUB_SOURCE_FENCE_PROVIDER_FIXTURE_PATH.read_bytes()
    except OSError as exc:
        raise ContractError(
            "Hub UDP source-fence provider fixture is unavailable"
        ) from exc
    if (
        hashlib.sha256(payload).hexdigest()
        != HUB_SOURCE_FENCE_PROVIDER_FIXTURE_SHA256
    ):
        raise ContractError(
            "Hub UDP source-fence provider fixture digest is not the reviewed value"
        )
    try:
        fixture = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ContractError(
            "Hub UDP source-fence provider fixture is malformed"
        ) from exc

    expected_fixture_fields = {
        "terraform_version",
        "aws_provider_version",
        "source_plan_sha256",
        "source_plan_json_sha256",
        "source_participant_envelope_sha256",
        "source_plan_complete",
        "source_plan_errored",
        "evidence_scope",
        "source_participant_count",
        "selected_participant_addresses",
        "changes",
    }
    expected_evidence_scope = (
        "Exact Terraform 1.14.3/AWS provider 6.55.0 envelopes for the five "
        "persisted Hub replacement carriers selected from the fresh "
        "nine-participant plan; not deployable apply evidence."
    )
    if (
        not isinstance(fixture, dict)
        or set(fixture) != expected_fixture_fields
        or fixture.get("terraform_version") != TF_VERSION
        or fixture.get("aws_provider_version") != "6.55.0"
        or fixture.get("source_plan_sha256")
        != HUB_SOURCE_FENCE_SOURCE_PLAN_SHA256
        or fixture.get("source_plan_json_sha256")
        != HUB_SOURCE_FENCE_SOURCE_PLAN_JSON_SHA256
        or fixture.get("source_participant_envelope_sha256")
        != HUB_SOURCE_FENCE_SOURCE_ENVELOPE_SHA256
        or fixture.get("source_plan_complete") is not False
        or fixture.get("source_plan_errored") is not True
        or fixture.get("evidence_scope") != expected_evidence_scope
        or fixture.get("source_participant_count") != 9
        or fixture.get("selected_participant_addresses")
        != list(HUB_SOURCE_FENCE_PROVIDER_ADDRESSES)
    ):
        raise ContractError(
            "Hub UDP source-fence provider fixture provenance is not exact"
        )

    changes = fixture.get("changes")
    if (
        not isinstance(changes, dict)
        or tuple(changes) != HUB_SOURCE_FENCE_PROVIDER_ADDRESSES
        or any(not isinstance(changes[address], dict) for address in changes)
    ):
        raise ContractError(
            "Hub UDP source-fence provider fixture inventory is not exact"
        )
    return changes


def _build_hub_source_fence_change_key_sets() -> "frozenset[frozenset[str]]":
    """The exact change-key envelopes an already-applied Hub source-fence
    participant may carry: the base keys, optionally paired with the sensitive
    and/or identity key pairs. Mirrors the relay plan checker's
    ``_build_udp_source_fence_change_key_sets``; derived once so the tolerated
    envelope set is not rebuilt on every per-address call."""
    allowed = {frozenset({"actions", "before", "after", "after_unknown"})}
    for pair in (
        {"before_sensitive", "after_sensitive"},
        {"before_identity", "after_identity"},
    ):
        allowed |= {frozenset(keys | pair) for keys in allowed}
    return frozenset(allowed)


_HUB_SOURCE_FENCE_ALLOWED_CHANGE_KEY_SETS = _build_hub_source_fence_change_key_sets()


def _is_exact_hub_source_fence_target_noop(change: Any) -> bool:
    """Prove an already-applied participant is an exact target no-op."""
    if not isinstance(change, dict):
        return False
    if frozenset(change) not in _HUB_SOURCE_FENCE_ALLOWED_CHANGE_KEY_SETS:
        return False
    before = change.get("before")
    after = change.get("after")
    if (
        change.get("actions") != ["no-op"]
        or not isinstance(before, dict)
        or before != after
        or change.get("after_unknown") != {}
    ):
        return False
    if ("before_sensitive" in change) != ("after_sensitive" in change) or (
        "before_sensitive" in change
        and change["before_sensitive"] != change["after_sensitive"]
    ):
        return False
    return not (
        ("before_identity" in change) != ("after_identity" in change)
        or (
            "before_identity" in change
            and change["before_identity"] != change["after_identity"]
        )
    )


def _is_exact_hub_privatelink_enforcement_update(item: dict[str, Any]) -> bool:
    """Prove the Hub edge change is EXACTLY the PrivateLink-enforcement flip.

    Pinning this attribute makes the Hub fence's PrivateLink posture
    Terraform-owned rather than an inherited AWS default (AWS enforces inbound
    rules on PrivateLink traffic by default and omits the member from
    DescribeLoadBalancers until it is set explicitly). Turning it on is an
    in-place ModifyLoadBalancerAttributes (the attribute is Optional+Computed,
    not ForceNew), so it must NOT be admitted through the replacement lane, whose
    reviewed envelope is a create/delete edge hand-over carrying a DNS repoint.

    Deliberately total: it admits a lone "update" whose before and after differ
    in this ONE attribute and nothing else, moving from unset or "off" to "on",
    with no unknowns and no replacement paths. Any additional field drift, any
    unknown, any replace_paths, or a deposed/data address fails it, so the lane
    cannot be widened into a general Hub-edge mutation escape.
    """
    if item.get("mode") != "managed" or item.get("type") != "aws_lb":
        return False
    change = item.get("change")
    if not isinstance(change, dict):
        return False
    before = change.get("before")
    after = change.get("after")
    if (
        change.get("actions") != ["update"]
        or not isinstance(before, dict)
        or not isinstance(after, dict)
        # Nothing may be deferred to apply time.
        or change.get("after_unknown") != {}
        # An in-place update must not carry replacement paths; a ForceNew
        # regression in a future provider would surface here and fail closed.
        or change.get("replace_paths") is not None
        or set(before) != set(after)
        or before.get(PRIVATELINK_ENFORCEMENT_ATTRIBUTE)
        not in PRIVATELINK_ENFORCEMENT_BEFORE_VALUES
        or after.get(PRIVATELINK_ENFORCEMENT_ATTRIBUTE) != "on"
        # The edge identity itself must be the reviewed one, so the lane cannot
        # be reached by a differently named or re-scoped load balancer.
        or before.get("name") != HUB_EDGE_LOAD_BALANCER_NAME
        or before.get("internal") is not False
        or before.get("load_balancer_type") != "network"
    ):
        return False
    # Every other attribute must be byte-identical: this is the clause that keeps
    # the lane from smuggling a subnet, security-group, or name change.
    if any(
        before[key] != after[key]
        for key in before
        if key != PRIVATELINK_ENFORCEMENT_ATTRIBUTE
    ):
        return False
    for before_key, after_key in (
        ("before_sensitive", "after_sensitive"),
        ("before_identity", "after_identity"),
    ):
        if (before_key in change) != (after_key in change) or (
            before_key in change and change[before_key] != change[after_key]
        ):
            return False
    return True


def _check_hub_source_fence_transition(
    by_address: dict[str, dict[str, Any]],
    deposed_by_address: dict[str, list[dict[str, Any]]] | None = None,
) -> None:
    """Bind a full or remaining Hub replacement to exact carrier state."""

    deposed_by_address = deposed_by_address or {}
    lb_address = "module.control.aws_lb.hub[0]"
    listener_address = "module.control.aws_lb_listener.hub[0]"
    target_address = "module.control.aws_lb_target_group.hub[0]"
    worker_address = "module.control.aws_security_group.hub_worker[0]"
    parameter_address = (
        "module.control.aws_ssm_parameter.hub_udp_listener_arn[0]"
    )
    unexpected_deposed = sorted(
        address
        for address, values in deposed_by_address.items()
        if address != lb_address or len(values) != 1
    )
    if unexpected_deposed:
        raise ContractError(
            "Hub UDP source-fence recovery has unreviewed deposed resources: "
            + ", ".join(unexpected_deposed)
        )
    deposed_lb = (
        deposed_by_address.get(lb_address, [None])[0]
        if deposed_by_address.get(lb_address)
        else None
    )
    actual_non_noop = {
        address: item.get("change", {}).get("actions")
        for address, item in by_address.items()
        if item.get("change", {}).get("actions") != ["no-op"]
    }
    allowed_actions = {
        address: [expected]
        for address, expected in HUB_SOURCE_FENCE_ACTIONS.items()
    }
    allowed_actions[listener_address].append(["create"])
    if (
        (not actual_non_noop and deposed_lb is None)
        or not set(actual_non_noop).issubset(HUB_SOURCE_FENCE_ACTIONS)
        or any(
            actions not in allowed_actions[address]
            for address, actions in actual_non_noop.items()
        )
    ):
        raise ContractError(
            "Hub UDP source-fence replacement must contain only an exact "
            f"reviewed remaining action subset; got {actual_non_noop}"
        )
    pending = set(actual_non_noop)
    listener_create_recovery = (
        actual_non_noop.get(listener_address) == ["create"]
    )
    lb_initial_replacement = (
        actual_non_noop.get(lb_address)
        == HUB_SOURCE_FENCE_ACTIONS[lb_address]
    )
    listener_initial_replacement = (
        actual_non_noop.get(listener_address)
        == HUB_SOURCE_FENCE_ACTIONS[listener_address]
    )
    if lb_initial_replacement and not listener_initial_replacement:
        raise ContractError(
            "initial Hub NLB replacement requires the exact "
            "destroy-before-create listener replacement"
        )
    if (
        listener_initial_replacement
        and not lb_initial_replacement
        and deposed_lb is None
    ):
        raise ContractError(
            "legacy Hub listener replacement requires the initial NLB "
            "replacement or its exact deposed-delete recovery"
        )
    if listener_create_recovery and lb_address in pending:
        raise ContractError(
            "Hub listener create recovery requires the fenced NLB target no-op"
        )

    def change(address: str) -> dict[str, Any]:
        value = by_address.get(address, {}).get("change")
        if not isinstance(value, dict):
            raise ContractError(f"{address} replacement change is malformed")
        return value

    def values(address: str, side: str) -> dict[str, Any]:
        value = change(address).get(side)
        if not isinstance(value, dict):
            raise ContractError(f"{address} replacement {side} is malformed")
        return value

    for address in set(HUB_SOURCE_FENCE_ACTIONS) - pending:
        if not _is_exact_hub_source_fence_target_noop(change(address)):
            raise ContractError(
                f"{address} already-applied complement is not an exact target no-op"
            )

    provider_changes = _load_hub_source_fence_provider_changes()
    if deposed_lb is not None:
        deposed_change = deposed_lb.get("change")
        expected_before = provider_changes[lb_address]["before"]
        if (
            deposed_lb.get("mode") != "managed"
            or deposed_lb.get("type") != "aws_lb"
            or deposed_lb.get("name") != "hub"
            or not isinstance(deposed_change, dict)
            or deposed_change.get("actions") != ["delete"]
            or deposed_change.get("before") != expected_before
            or deposed_change.get("after") is not None
            or deposed_change.get("after_unknown") != {}
            or lb_address in pending
        ):
            raise ContractError(
                "deposed Hub NLB delete is not the exact captured SG-less "
                "legacy carrier"
            )
    nlb_sg_address = "module.control.aws_security_group.hub_nlb[0]"
    nlb_sg_id: str | None = None
    if nlb_sg_address not in pending:
        nlb_sg_id = values(nlb_sg_address, "after").get("id")
        if (
            not isinstance(nlb_sg_id, str)
            or re.fullmatch(r"sg-[0-9a-f]{17}", nlb_sg_id) is None
        ):
            raise ContractError(
                "already-applied Hub NLB SG no-op identity is malformed"
            )

    def known_reference_mask_is_clear(value: Any) -> bool:
        return value in (None, False, [], [False])

    def normalized_pending_change(address: str) -> dict[str, Any]:
        actual = copy.deepcopy(change(address))
        expected = provider_changes[address]
        if address == "module.control.aws_lb.hub[0]" and nlb_sg_id is not None:
            actual_after = actual.get("after")
            actual_unknown = actual.get("after_unknown")
            if (
                not isinstance(actual_after, dict)
                or not isinstance(actual_unknown, dict)
                or actual_after.get("security_groups") != [nlb_sg_id]
                or not known_reference_mask_is_clear(
                    actual_unknown.get("security_groups")
                )
            ):
                raise ContractError(
                    "pending Hub NLB must bind the already-applied NLB SG"
                )
            actual_after.pop("security_groups")
            actual_unknown["security_groups"] = True

        if (
            address == "module.control.aws_security_group.hub_worker[0]"
            and nlb_sg_id is not None
        ):
            actual_after = actual.get("after")
            actual_unknown = actual.get("after_unknown")
            ingress = (
                actual_after.get("ingress")
                if isinstance(actual_after, dict)
                else None
            )
            ingress_unknown = (
                actual_unknown.get("ingress")
                if isinstance(actual_unknown, dict)
                else None
            )
            if (
                not isinstance(ingress, list)
                or len(ingress) != 2
                or not isinstance(ingress_unknown, list)
                or len(ingress_unknown) != 2
            ):
                raise ContractError(
                    "pending Hub worker SG known-reference envelope is malformed"
                )
            for rule, rule_unknown in zip(ingress, ingress_unknown, strict=True):
                if (
                    not isinstance(rule, dict)
                    or not isinstance(rule_unknown, dict)
                    or rule.get("security_groups") != [nlb_sg_id]
                    or not known_reference_mask_is_clear(
                        rule_unknown.get("security_groups")
                    )
                ):
                    raise ContractError(
                        "pending Hub worker SG must bind the already-applied NLB SG"
                    )
                rule.pop("security_groups")
                rule_unknown.pop("security_groups", None)
            expected_unknown = copy.deepcopy(expected["after_unknown"])
            for rule_unknown in expected_unknown["ingress"]:
                rule_unknown.pop("security_groups")
            if actual_unknown != expected_unknown:
                raise ContractError(
                    "pending Hub worker SG known-reference metadata is not exact"
                )
            actual["after_unknown"] = copy.deepcopy(expected["after_unknown"])

        if (
            address == "module.control.aws_lb_listener.hub[0]"
            and "module.control.aws_lb.hub[0]" not in pending
        ):
            nlb_arn = values("module.control.aws_lb.hub[0]", "after").get("arn")
            actual_after = actual.get("after")
            actual_unknown = actual.get("after_unknown")
            if (
                not isinstance(actual_after, dict)
                or not isinstance(actual_unknown, dict)
                or actual_after.get("load_balancer_arn") != nlb_arn
                or not known_reference_mask_is_clear(
                    actual_unknown.get("load_balancer_arn")
                )
            ):
                raise ContractError(
                    "pending Hub listener must bind the already-applied NLB"
                )
            actual_after.pop("load_balancer_arn")
            actual_unknown["load_balancer_arn"] = True

        if (
            address
            == "module.control.aws_ssm_parameter.hub_udp_listener_arn[0]"
            and "module.control.aws_lb_listener.hub[0]" not in pending
        ):
            listener_arn = values(
                "module.control.aws_lb_listener.hub[0]", "after"
            ).get("arn")
            actual_after = actual.get("after")
            actual_unknown = actual.get("after_unknown")
            if (
                not isinstance(actual_after, dict)
                or not isinstance(actual_unknown, dict)
                or actual_after.get("value") != listener_arn
                or not known_reference_mask_is_clear(actual_unknown.get("value"))
            ):
                raise ContractError(
                    "pending listener parameter must bind the applied Hub listener"
                )
            actual_after.pop("value")
            actual_unknown["value"] = True
        return actual

    def require_exact_provider_change(
        address: str, actual: dict[str, Any]
    ) -> None:
        expected = provider_changes[address]
        if set(actual) != set(expected):
            raise ContractError(
                f"{address} replacement envelope fields are not the exact "
                "Terraform 1.14.3/AWS provider 6.55.0 shape"
            )
        for field, expected_value in expected.items():
            if actual[field] != expected_value:
                raise ContractError(
                    f"{address} replacement {field} is not the exact "
                    "Terraform 1.14.3/AWS provider 6.55.0 envelope"
                )

    for address in HUB_SOURCE_FENCE_PROVIDER_ADDRESSES:
        if address in pending and not (
            address == listener_address and listener_create_recovery
        ):
            require_exact_provider_change(
                address, normalized_pending_change(address)
            )

    if lb_address in pending:
        require_exact_provider_change(
            target_address, copy.deepcopy(change(target_address))
        )
    elif not _is_exact_hub_source_fence_target_noop(change(target_address)):
        raise ContractError(
            "already-applied Hub target group is not an exact target no-op"
        )

    if listener_address not in pending and lb_address in pending:
        raise ContractError(
            "an applied Hub listener requires the replacement NLB target no-op"
        )
    if parameter_address not in pending and listener_address in pending:
        raise ContractError(
            "an applied listener parameter requires the Hub listener target no-op"
        )
    if lb_address not in pending and nlb_sg_address in pending:
        raise ContractError(
            "an applied Hub NLB requires the NLB SG target no-op"
        )
    if worker_address not in pending and nlb_sg_address in pending:
        raise ContractError(
            "an applied Hub worker SG fence requires the NLB SG target no-op"
        )
    applied_nlb_rule_addresses = (
        {
            address
            for address, actions in HUB_SOURCE_FENCE_ACTIONS.items()
            if actions == ["create"] and address != nlb_sg_address
        }
        - pending
    )
    if applied_nlb_rule_addresses and nlb_sg_address in pending:
        raise ContractError(
            "applied Hub NLB rules require the NLB SG target no-op"
        )

    legacy_lb_arn_re = re.compile(
        rf"^arn:aws:elasticloadbalancing:{AWS_REGION}:{ACCOUNT_ID}:"
        rf"loadbalancer/net/{re.escape(HUB_EDGE_LEGACY_LOAD_BALANCER_NAME)}/"
        r"[0-9a-f]{16}$"
    )
    target_lb_arn_re = re.compile(
        rf"^arn:aws:elasticloadbalancing:{AWS_REGION}:{ACCOUNT_ID}:"
        rf"loadbalancer/net/{re.escape(HUB_EDGE_LOAD_BALANCER_NAME)}/"
        r"[0-9a-f]{16}$"
    )
    legacy_listener_arn_re = re.compile(
        rf"^arn:aws:elasticloadbalancing:{AWS_REGION}:{ACCOUNT_ID}:"
        rf"listener/net/{re.escape(HUB_EDGE_LEGACY_LOAD_BALANCER_NAME)}/"
        r"[0-9a-f]{16}/[0-9a-f]{16}$"
    )
    target_listener_arn_re = re.compile(
        rf"^arn:aws:elasticloadbalancing:{AWS_REGION}:{ACCOUNT_ID}:"
        rf"listener/net/{re.escape(HUB_EDGE_LOAD_BALANCER_NAME)}/"
        r"[0-9a-f]{16}/[0-9a-f]{16}$"
    )
    target_group_arn_re = re.compile(
        rf"^arn:aws:elasticloadbalancing:{AWS_REGION}:{ACCOUNT_ID}:"
        rf"targetgroup/{re.escape(HUB_EDGE_TARGET_GROUP_NAME)}/[0-9a-f]{{16}}$"
    )

    lb_before = values(lb_address, "before")
    lb_after = values(lb_address, "after")
    if lb_address in pending:
        legacy_lb_arn = lb_before.get("arn")
        if (
            not isinstance(legacy_lb_arn, str)
            or legacy_lb_arn_re.fullmatch(legacy_lb_arn) is None
            or lb_before.get("security_groups") != []
        ):
            raise ContractError(
                "Hub replacement must start from the exact legacy SG-less NLB"
            )
        target_group_lb_arn = legacy_lb_arn
    else:
        target_group_lb_arn = lb_after.get("arn")
        if (
            not isinstance(target_group_lb_arn, str)
            or target_lb_arn_re.fullmatch(target_group_lb_arn) is None
            or lb_after.get("id") != target_group_lb_arn
            or lb_after.get("security_groups") != [nlb_sg_id]
        ):
            raise ContractError(
                "already-applied Hub NLB is not the exact fenced target"
            )
    if lb_after.get("name") != HUB_EDGE_LOAD_BALANCER_NAME:
        raise ContractError("Hub replacement NLB name is not exact")

    target_after = values(target_address, "after")
    target_group_arn = target_after.get("arn")
    if (
        target_group_arn_re.fullmatch(str(target_group_arn or "")) is None
        or target_after.get("id") != target_group_arn
        or target_after.get("load_balancer_arns") != [target_group_lb_arn]
        or target_after.get("name") != HUB_EDGE_TARGET_GROUP_NAME
        or target_after.get("port") != 62206
        or target_after.get("protocol") != "UDP"
        or target_after.get("target_type") != "ip"
        or target_after.get("preserve_client_ip") != "true"
    ):
        raise ContractError(
            "Hub replacement must retain the exact target-group carrier state"
        )

    listener_change = change(listener_address)
    listener_before_raw = listener_change.get("before")
    listener_before = (
        listener_before_raw if isinstance(listener_before_raw, dict) else None
    )
    listener_after = values(listener_address, "after")
    before_action = (
        listener_before.get("default_action")
        if isinstance(listener_before, dict)
        else None
    )
    after_action = listener_after.get("default_action")
    if (
        (
            not listener_create_recovery
            and (
                not isinstance(before_action, list)
                or len(before_action) != 1
                or before_action[0].get("target_group_arn") != target_group_arn
            )
        )
        or not isinstance(after_action, list)
        or len(after_action) != 1
        or after_action[0].get("target_group_arn") != target_group_arn
    ):
        raise ContractError("Hub listener target-group binding is not exact")
    if listener_create_recovery:
        load_balancer_arn = listener_after.get("load_balancer_arn")
        if (
            listener_before is not None
            or listener_change.get("actions") != ["create"]
            or listener_after.get("protocol") != "UDP"
            # Stays on the server bind, not the client edge: this recovery
            # replays the byte-pinned Hub source-fence provider envelope
            # captured while the listener was on 62206. The live listener's
            # client-edge port is proved by
            # collect_udp_proof_deployment_evidence.py against contract.UDP_PORT.
            or listener_after.get("port") != 62206
            or load_balancer_arn != target_group_lb_arn
            or listener_change.get("after_unknown", {}).get(
                "load_balancer_arn"
            )
            not in (None, False)
        ):
            raise ContractError(
                "Hub listener create recovery is not the exact fenced target"
            )
        current_listener_arn = None
    elif listener_address in pending:
        assert listener_before is not None
        current_listener_arn = listener_before.get("arn")
        if (
            not isinstance(current_listener_arn, str)
            or legacy_listener_arn_re.fullmatch(current_listener_arn) is None
            or not current_listener_arn.startswith(
                provider_changes[lb_address]["before"]["arn"].replace(
                    "loadbalancer/", "listener/"
                )
                + "/"
            )
        ):
            raise ContractError(
                "Hub replacement must start from the exact legacy listener"
            )
    else:
        current_listener_arn = listener_after.get("arn")
        if (
            not isinstance(current_listener_arn, str)
            or target_listener_arn_re.fullmatch(current_listener_arn) is None
            or listener_after.get("id") != current_listener_arn
            or listener_after.get("load_balancer_arn") != target_group_lb_arn
        ):
            raise ContractError(
                "already-applied Hub listener is not the exact fenced target"
            )

    worker_before = values(worker_address, "before")
    worker_after = values(worker_address, "after")
    if worker_address in pending:
        before_without_ingress = {
            key: value for key, value in worker_before.items() if key != "ingress"
        }
        after_without_ingress = {
            key: value for key, value in worker_after.items() if key != "ingress"
        }
        legacy_worker_ingress = {
            (
                rule.get("protocol"),
                rule.get("from_port"),
                rule.get("to_port"),
                tuple(rule.get("cidr_blocks", [])),
            )
            for rule in worker_before.get("ingress", [])
            if isinstance(rule, dict)
        }
        if (
            before_without_ingress != after_without_ingress
            or legacy_worker_ingress
            != {
                ("udp", 62206, 62206, ("0.0.0.0/0",)),
                ("tcp", 62207, 62207, ("10.102.0.0/16",)),
            }
            or len(worker_before.get("ingress", [])) != 2
        ):
            raise ContractError(
                "Hub replacement must update only the exact legacy worker ingress"
            )
    else:
        ingress = worker_after.get("ingress")
        if (
            not isinstance(ingress, list)
            or len(ingress) != 2
            or {
                (
                    rule.get("protocol"),
                    rule.get("from_port"),
                    rule.get("to_port"),
                    tuple(rule.get("security_groups", [])),
                    tuple(rule.get("cidr_blocks", [])),
                )
                for rule in ingress
                if isinstance(rule, dict)
            }
            != {
                ("udp", 62206, 62206, (nlb_sg_id,), ()),
                ("tcp", 62207, 62207, (nlb_sg_id,), ()),
            }
        ):
            raise ContractError(
                "already-applied Hub worker SG is not the exact fenced target"
            )

    parameter_before = values(parameter_address, "before")
    parameter_after = values(parameter_address, "after")
    expected_parameter_name = "/sandbox/nhp/control/hub/udp-listener-arn"
    if (
        parameter_before.get("name") != expected_parameter_name
        or parameter_before.get("id") != expected_parameter_name
    ):
        raise ContractError("Hub listener-ARN parameter identity is not exact")
    if parameter_address in pending:
        if (
            parameter_before.get("value")
            != provider_changes[listener_address]["before"]["arn"]
            or "value" in parameter_after
            and parameter_after.get("value") is not None
        ):
            raise ContractError(
                "pending Hub listener parameter is not the exact value update"
            )
    elif current_listener_arn is None or parameter_after.get(
        "value"
    ) != current_listener_arn:
        raise ContractError(
            "already-applied Hub listener parameter is not the exact target no-op"
        )


def _hub_identity_transition_pending(
    actual_non_noop: dict[str, list[str]],
) -> tuple[bool, set[str], set[str]]:
    creates = {
        address
        for address in HUB_IDENTITY_CREATE_ADDRESSES
        if actual_non_noop.get(address) == ["create"]
    }
    updates = {
        address
        for address in HUB_IDENTITY_UPDATE_ADDRESSES
        if actual_non_noop.get(address) == ["update"]
    }
    changed = creates | updates
    exact = (
        bool(changed)
        and all(
            actual_non_noop.get(address) in (None, ["create"])
            for address in HUB_IDENTITY_CREATE_ADDRESSES
        )
        and all(
            actual_non_noop.get(address) in (None, ["update"])
            for address in HUB_IDENTITY_UPDATE_ADDRESSES
        )
        and (set(actual_non_noop) & HUB_IDENTITY_MIGRATION_ADDRESSES) == changed
    )
    return exact, creates, updates


def check_plan(
    plan: Any, prior_state: Any = None, *, refresh_disabled: bool = False
) -> dict[str, str | int]:
    """Validate one exact reviewed plan shape.

    ``prior_state`` is required only when Terraform omits ``resource_changes``
    for the reviewed refresh-only compatibility shape. Ordinary callers, such
    as the refresh-disabled PR plan lane, may omit it; if their plan shape ever
    loses ``resource_changes``, this checker deliberately fails closed.
    """
    if not isinstance(plan, dict):
        raise ContractError("Terraform plan must be an object")
    if plan.get("format_version") != "1.2":
        raise ContractError("Terraform plan format_version must be 1.2")
    if plan.get("terraform_version") != TF_VERSION:
        raise ContractError(f"Terraform plan must use exact {TF_VERSION}")
    if plan.get("complete") is not True or plan.get("errored") is not False:
        raise ContractError("Terraform plan must be complete and non-errored")
    drift = _non_noop(plan.get("resource_drift"), "resource_drift")
    _check_no_embedded_actions(plan)

    changes = _plan_resource_changes(plan, drift, prior_state)
    by_address: dict[str, dict[str, Any]] = {}
    deposed_by_address: dict[str, list[dict[str, Any]]] = {}
    for item in changes:
        if not isinstance(item, dict) or not isinstance(item.get("address"), str):
            raise ContractError("Terraform resource change is malformed")
        address = item["address"]
        deposed = item.get("deposed")
        if deposed is not None:
            if not isinstance(deposed, str) or not re.fullmatch(
                r"[0-9a-f]{8}", deposed
            ):
                raise ContractError(
                    f"Terraform deposed resource key is malformed for {address}"
                )
            # The one reviewed Authority function-SG deposed object is validated
            # exactly here and then retired from the inventory, so it cannot
            # widen any downstream deposed handling: it must not make a plan look
            # like the Hub source-fence transition, and every OTHER deposed
            # object still reaches _check_hub_source_fence_transition's
            # unreviewed-deposed guard (or the fail-closed fallback) untouched.
            if _is_exact_legacy_authority_sg_deposed_delete(item):
                continue
            deposed_by_address.setdefault(address, []).append(item)
            continue
        if address in by_address:
            raise ContractError(f"duplicate Terraform resource change: {address}")
        by_address[address] = item

    # Source no longer declares the detached legacy OTP Redis user, so a plan
    # against the pre-cleanup state carries exactly one address outside the
    # then-current inventory: its delete. Validate that delete field-for-field
    # and retire the address here, before the exact-inventory equality below, so
    # every other contract keeps seeing only the then-current inventory and the
    # state/state-list lanes -- which run only after this apply -- stay exact.
    # Any other action on this address (an update, a re-create, or a deposed
    # object) fails closed rather than widening the plan contract.
    # Same shape as the legacy OTP user below: source no longer declares the
    # fenced rule, so a plan against the pre-transition state carries its delete
    # as one address outside the current inventory. Validate it field-for-field
    # and retire it here, before the exact-set equality, so every other contract
    # and the post-apply state lanes keep seeing only the current inventory.
    if LEGACY_HUB_SOURCE_FENCE_ADDRESS in by_address:
        if not _is_exact_legacy_hub_source_fence_delete(
            by_address.pop(LEGACY_HUB_SOURCE_FENCE_ADDRESS)
        ):
            raise ContractError(
                "the Hub proof-runner source fence may appear only as its exact "
                "reviewed delete; review the drift rather than applying"
            )

    legacy_otp_user_delete = LEGACY_OTP_REDIS_USER_ADDRESS in by_address
    if legacy_otp_user_delete and not _is_exact_legacy_otp_user_delete(
        by_address.pop(LEGACY_OTP_REDIS_USER_ADDRESS)
    ):
        raise ContractError(
            "the detached legacy Connector OTP Redis user may appear only as its "
            "exact reviewed delete; review the drift rather than applying"
        )

    # The base foundation, plus any complete subset of the independent optional
    # slices: the two-row provisioned-cell catalog, authority runtime (Lambda
    # functions/aliases/roles/…), Hub public edge
    # (public subnets/IGW/route/NLB/…), and Hub Fargate worker
    # (ECS/secret/keygen/endpoints/…). Each slice is ALL-OR-NOTHING -- its
    # resources appear together or not at all. The catalog's temporary absence
    # permits the reviewed Authority-first rollout without weakening its exact
    # later two-row transition. The worker DEPENDS on the edge and runtime (it
    # fronts the edge target group and invokes the runtime aliases), so a worker
    # inventory without both is rejected below.
    # Data sources are resolved at plan time (planned_values/configuration, not
    # resource_changes), so ``by_address`` here is effectively managed-only; the
    # worker's two data sources are gated by the configuration map and the state
    # list, not this managed inventory. A partial slice (some but not all of its
    # addresses) or any address outside base∪slices fails closed via the exact-set
    # equality below.
    catalog_extra = set(PROVISIONED_CELL_RESOURCES)
    base_inventory = set(EXPECTED_RESOURCES) - catalog_extra
    runtime_extra = set(AUTHORITY_RUNTIME_RESOURCES)
    proof_extra = set(AUTHORITY_PROOF_RESOURCES)
    proof_rollout_extra = set(AUTHORITY_PROOF_ROLLOUT_RESOURCES)
    hub_edge_extra = set(HUB_EDGE_RESOURCES)
    hub_worker_extra = set(HUB_WORKER_RESOURCES)
    actual_inventory = set(by_address)
    catalog_mode = bool(actual_inventory & catalog_extra)
    runtime_mode = bool(actual_inventory & runtime_extra)
    # Deleted resources remain in resource_changes even though they are absent
    # from the planned after-state. Keep that pre-apply inventory available for
    # exact type/delete validation, while deriving proof_mode from the target
    # state so the rollback can be checked against the dark security contract.
    proof_inventory_mode = bool(actual_inventory & proof_extra)
    proof_mode = proof_inventory_mode and any(
        isinstance(by_address[address].get("change", {}).get("after"), dict)
        for address in actual_inventory & proof_extra
    )
    proof_rollout_mode = bool(actual_inventory & proof_rollout_extra)
    hub_edge_mode = bool(actual_inventory & hub_edge_extra)
    hub_worker_mode = bool(actual_inventory & hub_worker_extra)
    if proof_mode and not runtime_mode:
        raise ContractError(
            "attended-proof Authority slice requires the complete runtime slice"
        )
    if proof_rollout_mode and not (
        proof_mode and runtime_mode and hub_worker_mode
    ):
        raise ContractError(
            "proof-policy rollout requires the complete attended-proof, "
            "Authority runtime, and Hub worker slices"
        )
    if hub_worker_mode and not (hub_edge_mode and runtime_mode):
        raise ContractError(
            "Hub worker slice requires both the Hub edge slice and the authority "
            "runtime slice to be present"
        )
    # The orphaned proof-controller grant is no longer in the module, but it is
    # still in state until its `forget` applies, so it legitimately appears in
    # this pre-apply inventory exactly once. Tolerate it only while that release
    # is the planned action -- any other action on the address (a create, or a
    # real delete) falls straight back to the mismatch below. See
    # _claim_authority_proof_controller_orphan_forget.
    _orphan_change = by_address.get(AUTHORITY_PROOF_CONTROLLER_POLICY_ADDRESS)
    _orphan_forget_pending = (
        isinstance(_orphan_change, dict)
        and isinstance(_orphan_change.get("change"), dict)
        and _orphan_change["change"].get("actions") == ["forget"]
    )
    if _orphan_forget_pending:
        _validate_authority_proof_controller_orphan_forget(by_address)
    expected_inventory = (
        base_inventory
        | (catalog_extra if catalog_mode else set())
        | (runtime_extra if runtime_mode else set())
        | (proof_extra if proof_inventory_mode else set())
        | (proof_rollout_extra if proof_rollout_mode else set())
        | (hub_edge_extra if hub_edge_mode else set())
        | (hub_worker_extra if hub_worker_mode else set())
        | (
            {AUTHORITY_PROOF_CONTROLLER_POLICY_ADDRESS}
            if _orphan_forget_pending
            else set()
        )
    )
    if actual_inventory != expected_inventory:
        missing = sorted(expected_inventory - actual_inventory)
        extra = sorted(actual_inventory - expected_inventory)
        raise ContractError(
            f"Terraform resource inventory mismatch; missing={missing}, extra={extra}"
        )
    _require_provisioned_cell_planned_output(plan, catalog_present=catalog_mode)
    expected_resources = {
        address: resource_type
        for address, resource_type in EXPECTED_RESOURCES.items()
        if address not in catalog_extra
    }
    if catalog_mode:
        expected_resources.update(PROVISIONED_CELL_RESOURCES)
    if runtime_mode:
        expected_resources.update(AUTHORITY_RUNTIME_RESOURCES)
    if proof_inventory_mode:
        expected_resources.update(AUTHORITY_PROOF_RESOURCES)
    if proof_rollout_mode:
        expected_resources.update(AUTHORITY_PROOF_ROLLOUT_RESOURCES)
    if hub_edge_mode:
        expected_resources.update(HUB_EDGE_RESOURCES)
    if hub_worker_mode:
        expected_resources.update(HUB_WORKER_RESOURCES)

    actual_non_noop: dict[str, list[str]] = {}
    for address, expected_type in expected_resources.items():
        item = by_address[address]
        if item.get("mode") != "managed" or item.get("type") != expected_type:
            raise ContractError(f"unexpected mode/type for {address}")
        change = item.get("change")
        if not isinstance(change, dict) or not isinstance(
            change.get("actions"), list
        ):
            raise ContractError(f"{address} change/actions are malformed")
        actions = change["actions"]
        if actions == ["no-op"]:
            if change.get("before") != change.get("after"):
                raise ContractError(f"{address} no-op before and after differ")
        else:
            actual_non_noop[address] = actions

    plan_mode = "no-op"
    bootstrap_creates: set[str] = set()
    changed = set(actual_non_noop)
    publisher_transition = (
        bool(changed)
        and changed.issubset(PUBLISHER_BOOTSTRAP_RESOURCES)
        and all(actual_non_noop[address] == ["create"] for address in changed)
        and (
            "module.control.aws_iam_role.authority_publisher" not in changed
            or "module.control.aws_iam_role_policy.authority_publisher" in changed
        )
    )
    hub_artifact_transition = (
        bool(changed)
        and changed.issubset(HUB_ARTIFACT_BOOTSTRAP_RESOURCES)
        and all(actual_non_noop[address] == ["create"] for address in changed)
        and (
            "module.control.aws_iam_role.hub_publisher" not in changed
            or "module.control.aws_iam_role_policy.hub_publisher" in changed
        )
        and (
            "module.control.aws_ecr_repository.hub" not in changed
            or "module.control.aws_ecr_lifecycle_policy.hub" in changed
        )
    )
    redis_group_address = "module.control.aws_elasticache_user_group.otp"
    redis_user_addresses = REDIS_SPLIT_USER_RESOURCES
    changed_redis_user_addresses = changed & redis_user_addresses
    redis_transition = (
        redis_group_address in changed
        and changed.issubset({redis_group_address, *redis_user_addresses})
        and actual_non_noop.get(redis_group_address) == ["update"]
        and all(
            actual_non_noop.get(address) == ["create"]
            for address in changed_redis_user_addresses
        )
    )
    authority_contract_address = (
        "module.control.terraform_data.foundation_contract"
    )
    authority_contract_transition = (
        changed == {authority_contract_address}
        and actual_non_noop.get(authority_contract_address) == ["update"]
        and not _require_authority_runtime_binding(
            by_address[authority_contract_address]["change"].get("before", {})
        )
        and _require_authority_runtime_binding(
            by_address[authority_contract_address]["change"].get("after", {})
        )
    )
    authority_proof_enable_transition = (
        proof_mode
        and changed == set(AUTHORITY_PROOF_ENABLE_ALL_CHANGES)
        and all(
            actual_non_noop.get(address) == ["create"]
            for address in AUTHORITY_PROOF_RESOURCES
        )
        and all(
            actual_non_noop.get(address) == ["update"]
            for address in AUTHORITY_PROOF_ENABLE_UPDATE_ADDRESSES
        )
    )
    authority_proof_disable_transition = (
        proof_inventory_mode
        and not proof_mode
        and changed == set(AUTHORITY_PROOF_ENABLE_ALL_CHANGES)
        and all(
            actual_non_noop.get(address) == ["delete"]
            for address in AUTHORITY_PROOF_RESOURCES
        )
        and all(
            actual_non_noop.get(address) == ["update"]
            for address in AUTHORITY_PROOF_ENABLE_UPDATE_ADDRESSES
        )
    )
    authority_proof_consumer_enable_addresses = (
        _authority_proof_consumer_transition_addresses(
            by_address, enabling=True
        )
    )
    authority_proof_consumer_enable_transition = (
        proof_mode
        and authority_proof_consumer_enable_addresses is not None
        and changed == authority_proof_consumer_enable_addresses
        and all(actual_non_noop.get(address) == ["update"] for address in changed)
    )
    authority_proof_consumer_disable_addresses = (
        _authority_proof_consumer_transition_addresses(
            by_address, enabling=False
        )
    )
    authority_proof_consumer_disable_transition = (
        proof_mode
        and authority_proof_consumer_disable_addresses is not None
        and changed == authority_proof_consumer_disable_addresses
        and all(actual_non_noop.get(address) == ["update"] for address in changed)
    )
    foundation_change = by_address[authority_contract_address]["change"]
    authority_proof_rollout_transition_kind = (
        _authority_proof_rollout_transition(
            foundation_change.get("before", {}),
            foundation_change.get("after", {}),
        )
        if authority_contract_address in changed
        else None
    )
    rollout_after_colors = _authority_proof_rollout_colors(
        foundation_change.get("after", {})
    )
    rollout_prepared_color = (
        rollout_after_colors[1] if rollout_after_colors is not None else None
    )
    rollout_prepare_alias_changes = {
        f'module.control.aws_lambda_alias.authority["{function_name}:{rollout_prepared_color}"]'
        for function_name in AUTHORITY_PROOF_ROLLOUT_FUNCTIONS
    }
    rollout_initial_changes = {
        authority_contract_address,
        "module.control.aws_iam_role_policy.hub_task[0]",
        'module.control.aws_vpc_endpoint.interface["lambda"]',
        *AUTHORITY_PROOF_ROLLOUT_RESOURCES,
        *rollout_prepare_alias_changes,
        *(
            f'module.control.aws_lambda_function.authority["{function_name}"]'
            for function_name in AUTHORITY_PROOF_ROLLOUT_FUNCTIONS
        ),
    }
    rollout_reprepare_changes = {
        authority_contract_address,
        *rollout_prepare_alias_changes,
    }
    rollout_before_absent = (
        foundation_change.get("before", {})
        .get("input", {})
        .get("authority_proof_policy_selected_color")
        is None
    )
    authority_proof_rollout_prepare_transition = (
        proof_rollout_mode
        and authority_proof_rollout_transition_kind == "prepare"
        and frozenset(changed)
        in (
            {
                frozenset(rollout_initial_changes),
                frozenset({*rollout_initial_changes, HUB_WORKER_SERVICE_ADDRESS}),
            }
            if rollout_before_absent
            else {frozenset(rollout_reprepare_changes)}
        )
        and all(
            actual_non_noop.get(address)
            == (
                ["create"]
                if address in AUTHORITY_PROOF_ROLLOUT_RESOURCES
                else ["update"]
            )
            for address in changed
        )
    )
    authority_proof_rollout_prepare_recovery = (
        proof_rollout_mode
        and _is_exact_authority_proof_rollout_prepare_recovery(
            actual_non_noop,
            foundation_change.get("after", {}),
        )
    )
    authority_proof_rollout_selector_transition = (
        proof_rollout_mode
        and authority_proof_rollout_transition_kind == "selector"
        and changed == set(AUTHORITY_PROOF_ROLLOUT_SELECTOR_CHANGES)
        and actual_non_noop.get(authority_contract_address) == ["update"]
        and actual_non_noop.get("module.control.aws_ecs_service.hub[0]")
        == ["update"]
        and actual_non_noop.get(HUB_WORKER_TASK_DEFINITION_ADDRESS)
        == ["delete", "create"]
    )
    provisioned_cell_catalog_transition = (
        changed == set(PROVISIONED_CELL_RESOURCES)
        and all(
            actual_non_noop.get(address) == ["create"]
            for address in PROVISIONED_CELL_RESOURCES
        )
    )
    # The catalog's first MUTATION, as distinct from its materialization above.
    # Row content is an attended lifecycle decision (cell activation, endpoint
    # revision), so the rows update in place rather than being created. The
    # create-only predicate above cannot describe that, and before this the
    # catalog could be born but never changed.
    #
    # This admits ONLY update-in-place on exactly the reviewed row set. The
    # after-state is still pinned field-for-field by
    # _require_provisioned_cell_values against PROVISIONED_CELL_EXPECTED_ITEM_JSON,
    # which derives from the reviewed catalog constant -- so a row may only
    # become what this repo's reviewed catalog already says it is. A create, a
    # delete, a partial row set, or any content the constant does not name still
    # fails closed.
    provisioned_cell_catalog_lifecycle = (
        changed == set(PROVISIONED_CELL_RESOURCES)
        and bool(PROVISIONED_CELL_RESOURCES)
        and all(
            actual_non_noop.get(address) == ["update"]
            for address in PROVISIONED_CELL_RESOURCES
        )
    )
    provisioned_cell_catalog_creates_pending = {
        address
        for address in PROVISIONED_CELL_RESOURCES
        if actual_non_noop.get(address) == ["create"]
    }
    # Main may merge the catalog declaration before this Authority expansion is
    # applied. Admit that overlap only when BOTH reviewed rows are still exact
    # pure creates; one-row partial state remains a separate failed transition.
    provisioned_cell_catalog_full_create = (
        provisioned_cell_catalog_creates_pending
        == set(PROVISIONED_CELL_RESOURCES)
    )
    (
        hub_identity_transition,
        hub_identity_creates_pending,
        hub_identity_updates_pending,
    ) = _hub_identity_transition_pending(actual_non_noop)
    hub_identity_changed = hub_identity_creates_pending | hub_identity_updates_pending
    # COPY: the subtractions below narrow the candidate set for the legacy
    # expansion only. Aliasing ``changed`` here instead would mutate it in place
    # and silently shrink every later transition test AND the final
    # ``elif changed:`` rejection guard -- a plan whose whole content was
    # subtracted away would fall through as plan_mode "no-op", skipping the
    # create-shape proofs and relaxing the drift gates that key on "no-op".
    legacy_candidate_changed = set(changed)
    if hub_identity_transition:
        legacy_candidate_changed -= hub_identity_changed
    if provisioned_cell_catalog_full_create:
        legacy_candidate_changed -= provisioned_cell_catalog_creates_pending
    # One-time expansion of the already-live legacy sandbox runtime (three Hub
    # functions) to the complete cell0+cell1 graph. The first plan must start
    # from the exact predecessor contract/evidence; a partial-apply retry may
    # see that foundation update already converged to a no-op. In either case
    # only the exact missing cell resources, standalone SG rules, dependency
    # policy expansions, the generation-2 function-SG replacement, and the
    # dependent Hub function/alias republish may move. The ordinary clean
    # runtime-slice contract remains unchanged.
    legacy_expansion_creates_pending = {
        address
        for address in AUTHORITY_RUNTIME_LEGACY_EXPANSION_CREATE_ADDRESSES
        if actual_non_noop.get(address) == ["create"]
    }
    legacy_expansion_updates_pending = {
        address
        for address in AUTHORITY_RUNTIME_LEGACY_EXPANSION_UPDATE_ADDRESSES
        if actual_non_noop.get(address) == ["update"]
    }
    legacy_expansion_replaces_pending = {
        address
        for address in AUTHORITY_RUNTIME_LEGACY_EXPANSION_REPLACE_ADDRESSES
        if actual_non_noop.get(address) == ["create", "delete"]
    }
    foundation_change = by_address[authority_contract_address]["change"]
    legacy_expansion_action_shape = (
        runtime_mode
        and bool(legacy_candidate_changed)
        and all(
            actual_non_noop.get(address) in (None, ["create"])
            for address in AUTHORITY_RUNTIME_LEGACY_EXPANSION_CREATE_ADDRESSES
        )
        and all(
            actual_non_noop.get(address) in (None, ["update"])
            for address in AUTHORITY_RUNTIME_LEGACY_EXPANSION_UPDATE_ADDRESSES
        )
        and all(
            actual_non_noop.get(address) in (None, ["create", "delete"])
            for address in AUTHORITY_RUNTIME_LEGACY_EXPANSION_REPLACE_ADDRESSES
        )
        and legacy_candidate_changed
        == (
            legacy_expansion_creates_pending
            | legacy_expansion_updates_pending
            | legacy_expansion_replaces_pending
        )
    )
    foundation_expands_legacy = False
    foundation_already_expanded = False
    if legacy_expansion_action_shape:
        foundation_expands_legacy = (
            actual_non_noop.get(authority_contract_address) == ["update"]
            and _is_exact_legacy_hub_runtime_expansion(
                foundation_change.get("before", {}),
                foundation_change.get("after", {}),
                by_address,
            )
        )
        foundation_already_expanded = (
            actual_non_noop.get(authority_contract_address) is None
            and _require_authority_runtime_binding(
                foundation_change.get("after", {})
            )
        )
    authority_runtime_legacy_expansion = (
        legacy_expansion_action_shape
        and (foundation_expands_legacy or foundation_already_expanded)
        and (not hub_identity_changed or hub_identity_transition)
        and (
            not provisioned_cell_catalog_creates_pending
            or provisioned_cell_catalog_full_create
        )
    )
    standalone_hub_identity_migration = (
        hub_worker_mode
        and hub_identity_transition
        and changed == hub_identity_changed
    )
    # The runtime slice: every runtime resource is created and exactly the three
    # dependency-endpoint/SG opens are updated. This admits BOTH the clean full
    # slice AND a partial-apply RETRY. A create that already succeeded on an
    # earlier attempt replans as a validated no-op (before==after, proven in the
    # no-op branch above), so it is neither "pending" here nor a drift; the same
    # holds for an open that already applied. The split is:
    #   pending create = slice resource this plan still creates (actions ["create"])
    #   pending open    = dependency open this plan still updates (actions ["update"])
    # An already-applied create/open is simply absent from actual_non_noop. The
    # transition requires: nothing in the slice is updated/replaced/destroyed
    # (creates are ["create"] or no-op; opens are ["update"] or no-op), at least
    # one thing moves, and NOTHING outside the pending creates + pending opens
    # moves — a drifted base resource lands in ``changed`` and fails the equality.
    authority_runtime_creates = set(AUTHORITY_RUNTIME_RESOURCES)
    runtime_creates_pending = {
        address
        for address in authority_runtime_creates
        if actual_non_noop.get(address) == ["create"]
    }
    runtime_opens_pending = {
        address
        for address in AUTHORITY_RUNTIME_OPENED_ADDRESSES
        if actual_non_noop.get(address) == ["update"]
    }
    authority_runtime_transition = (
        runtime_mode
        and bool(changed)
        and all(
            actual_non_noop.get(address) in (None, ["create"])
            for address in authority_runtime_creates
        )
        and all(
            actual_non_noop.get(address) in (None, ["update"])
            for address in AUTHORITY_RUNTIME_OPENED_ADDRESSES
        )
        and changed == (runtime_creates_pending | runtime_opens_pending)
    )

    # Bounded RECOVERY transition, distinct from the strict completion above so
    # the clean slice contract is not weakened. Admitted only when an earlier
    # partial apply left one or more hub functions in a Failed state (Terraform
    # auto-taints them, so they replan as ["delete","create"]) AND the exec-role
    # trust is being normalized (the confused-deputy Condition removed -> an
    # in-place ["update"]). Everything else stays as in the completion: aliases /
    # provisioned-concurrency are pending creates, the three opens are updates or
    # no-op, and NOTHING outside {pending creates, tainted-function replaces,
    # exec-role trust updates, pending opens} may move. Every function and role
    # after-state is still fully validated by _check_authority_runtime_resources.
    runtime_function_addresses = {
        address
        for address, resource_type in AUTHORITY_RUNTIME_RESOURCES.items()
        if resource_type == "aws_lambda_function"
    }
    runtime_exec_role_addresses = {
        address
        for address, resource_type in AUTHORITY_RUNTIME_RESOURCES.items()
        if resource_type == "aws_iam_role"
    }
    runtime_functions_replaced = {
        address
        for address in runtime_function_addresses
        if actual_non_noop.get(address) == ["delete", "create"]
    }
    runtime_roles_updated = {
        address
        for address in runtime_exec_role_addresses
        if actual_non_noop.get(address) == ["update"]
    }
    authority_runtime_retry_transition = (
        runtime_mode
        and bool(runtime_functions_replaced)
        and all(
            actual_non_noop.get(address) in (None, ["create"], ["delete", "create"])
            for address in runtime_function_addresses
        )
        and all(
            actual_non_noop.get(address) in (None, ["create"], ["update"])
            for address in runtime_exec_role_addresses
        )
        and all(
            actual_non_noop.get(address) in (None, ["create"])
            for address in (
                authority_runtime_creates
                - runtime_function_addresses
                - runtime_exec_role_addresses
            )
        )
        and all(
            actual_non_noop.get(address) in (None, ["update"])
            for address in AUTHORITY_RUNTIME_OPENED_ADDRESSES
        )
        and changed
        == (
            runtime_creates_pending
            | runtime_functions_replaced
            | runtime_roles_updated
            | runtime_opens_pending
        )
    )

    # Operator alert routing and the full runtime alarm set (NHP #3455). The 11
    # already-live spillover alarms take an in-place update (they gain
    # alarm_actions); every other alarm address is a pending pure create. No
    # function, role, alias, endpoint, or SG may move in this transition — the
    # alarm slice is observability-only by construction, and anything else
    # moving alongside it means the plan is not what it claims to be.
    alarm_creates_pending = {
        address
        for address in AUTHORITY_ALARM_RESOURCES
        if actual_non_noop.get(address) == ["create"]
    }
    alarm_updates_pending = {
        address
        for address in AUTHORITY_ALARM_UPDATE_ADDRESSES
        if actual_non_noop.get(address) == ["update"]
    }
    # Every address the alarm slice may ever touch. Used to prove a plan is not
    # quietly moving an alarm outside the reviewed shape when the slice composes
    # with another transition.
    alarm_slice_scope = set(AUTHORITY_ALARM_RESOURCES) | set(
        AUTHORITY_ALARM_UPDATE_ADDRESSES
    )
    alarm_slice_changed = alarm_creates_pending | alarm_updates_pending
    # "The alarm slice moved as EXACTLY its reviewed shape" — independent of
    # whether it is the only thing in the plan. Every alarm address is either
    # settled or moving in its one permitted direction (new alarms create, the
    # live spillover alarms update in place), and at least one is moving.
    # This is the precondition for composing with the Hub source-fence
    # transition below, mirroring how the fence composes with the Hub identity
    # migration: a NON-exact alarm move leaves this false, so the fence subset
    # test still sees the alarm addresses and the whole plan falls through to
    # the fail-closed fallback.
    authority_alarm_slice_exact = (
        runtime_mode
        and bool(alarm_slice_changed)
        and all(
            actual_non_noop.get(address) in (None, ["create"])
            for address in AUTHORITY_ALARM_RESOURCES
        )
        and all(
            actual_non_noop.get(address) in (None, ["update"])
            for address in AUTHORITY_ALARM_UPDATE_ADDRESSES
        )
    )
    # The standalone slice: the alarm work is the ENTIRE plan.
    authority_alarm_routing_transition = (
        authority_alarm_slice_exact and changed == alarm_slice_changed
    )

    # Immutable Authority image refresh. Terraform publishes one new version of
    # every function in the complete runtime plus proof graph and advances both
    # closed aliases to that version. The failed stale-image first apply left
    # the two proof provisioned-concurrency resources tainted; only their exact
    # replacements may accompany the migration.
    # Existing runtime/config checks below still validate every function and
    # alias against the contract-pinned image and exact Terraform references.
    authority_image_update_addresses = set(AUTHORITY_IMAGE_UPDATE_RESOURCES)
    authority_image_update_scope = {
        *authority_image_update_addresses,
        AUTHORITY_IMAGE_UPDATE_FOUNDATION_ADDRESS,
        *AUTHORITY_IMAGE_UPDATE_RECOVERY_REPLACES,
    }
    # This lane admits ONE reviewed migration. It must therefore claim only that
    # migration -- claiming any image-shaped plan and then failing on the pinned
    # digests turns every later image roll into a hard stop, which is exactly
    # what it did once sandbox moved past 65421e -> e147b2. Ordinary rolls now
    # fall through to authority-image-roll, which proves uniform convergence
    # structurally instead of by literal digest.
    try:
        _plan_image_uris = _authority_image_plan_uris(by_address)
    except ContractError:
        _plan_image_uris = None
    authority_image_update_transition = (
        runtime_mode
        and bool(changed)
        and _plan_image_uris
        == (AUTHORITY_IMAGE_UPDATE_FROM_URI, AUTHORITY_IMAGE_UPDATE_TO_URI)
        and changed.issubset(authority_image_update_scope)
        and all(
            actual_non_noop.get(address) == ["delete", "create"]
            for address in changed & set(AUTHORITY_IMAGE_UPDATE_RECOVERY_REPLACES)
        )
        and all(
            actual_non_noop.get(address) == ["update"]
            for address in changed - set(AUTHORITY_IMAGE_UPDATE_RECOVERY_REPLACES)
        )
    )

    # The Hub public edge slice (5a): every edge resource is a pending create (or
    # an already-applied no-op) and NOTHING else moves. This slice opens no
    # endpoint -- the caller lambda endpoint opens with the workers (5b).
    hub_edge_creates_pending = {
        address
        for address in HUB_EDGE_RESOURCES
        if actual_non_noop.get(address) == ["create"]
    }
    hub_edge_transition = (
        hub_edge_mode
        and bool(changed)
        and all(
            actual_non_noop.get(address) in (None, ["create"])
            for address in HUB_EDGE_RESOURCES
        )
        and changed == hub_edge_creates_pending
    )

    # One-time replacement of the already-live Hub NLB that was created without
    # a security group. AWS cannot attach an SG to that NLB in place. The new
    # source-fence resources must arrive together. The NLB uses
    # create-before-destroy, but its listener must use destroy-before-create:
    # AWS forbids one target group from being in use by listeners on two load
    # balancers. Only the listener-ARN parameter plus the worker target SG may
    # update in place. Any wider mutation fails closed.
    hub_source_fence_creates = {
        address
        for address, actions in HUB_SOURCE_FENCE_ACTIONS.items()
        if actions == ["create"]
    }
    # The fence may co-occur with a still-pending Hub identity publication. The
    # identity migration republishes the Hub public key through a
    # lambda_invocation whose create is independent of the NLB replacement, so a
    # plan can legitimately carry both and neither is a superset of the other.
    # Composed exactly as the legacy expansion composes with it above: the
    # identity addresses must form their OWN exact transition before they are
    # excluded from the fence subset test, and they are separately create-shape
    # proved in the branch body. A non-exact identity move keeps the whole
    # predicate false and falls through to the fail-closed fallback.
    # The fence may equally co-occur with the NHP #3455 alarm slice, which is
    # observability-only: it creates CloudWatch alarms and adds alarm_actions to
    # the 11 live spillover alarms, touching no NLB, listener, SG, parameter, or
    # function. Its address set is disjoint from the fence's (asserted by
    # test_alarm_and_fence_address_sets_are_disjoint), so neither is a superset
    # of the other and a plan can legitimately carry both while the fence waits
    # on an attended apply. Composed under the SAME contract as the identity
    # migration above: the alarm addresses must form their OWN exact transition
    # (authority_alarm_slice_exact) before they are excluded from the fence
    # subset test, and they are separately create-shape proved in the branch
    # body. Their contents are validated regardless of which branch wins, by
    # _check_authority_alarm_routing via the inventory-derived runtime_mode. A
    # non-exact alarm move keeps this predicate false and falls through to the
    # fail-closed fallback.
    # A bounded, post-fence hardening of the Hub public edge: pin ON
    # enforce_security_group_inbound_rules_on_private_link_traffic. The fence
    # (#3362) attached an SG admitting exactly the reviewed public source on
    # UDP 443; this makes that SG's PrivateLink posture Terraform-owned rather
    # than an inherited AWS default, so an out-of-band flip to "off" becomes
    # visible drift. collect_udp_proof_deployment_evidence.py has required the
    # literal "on" of the live edge since #3462 and cannot pass while
    # DescribeLoadBalancers omits the member.
    # This lane admits EXACTLY the single in-place attribute flip with
    # nothing else moving and no deposed object, proved byte-for-byte by
    # _is_exact_hub_privatelink_enforcement_update.
    #
    # It CANNOT mask the replacement lane: a pending fence carries the SG creates
    # and the listener replacement too, so `changed` would exceed this singleton,
    # and the fence's own NLB action is ["create", "delete"], not ["update"].
    # Gated on hub_edge_mode so it cannot fire before the edge exists; once
    # applied the address is a no-op again and the steady-state edge checks still
    # enforce the fenced shape. Remove this lane once applied.
    hub_privatelink_enforcement = (
        hub_edge_mode
        and not deposed_by_address
        and changed == {HUB_EDGE_LOAD_BALANCER_ADDRESS}
        and actual_non_noop.get(HUB_EDGE_LOAD_BALANCER_ADDRESS) == ["update"]
        and _is_exact_hub_privatelink_enforcement_update(
            by_address[HUB_EDGE_LOAD_BALANCER_ADDRESS]
        )
    )

    hub_source_fence_candidate = set(actual_non_noop)
    if hub_identity_transition:
        hub_source_fence_candidate -= hub_identity_changed
    if authority_alarm_slice_exact:
        hub_source_fence_candidate -= alarm_slice_changed
    hub_source_fence_transition = (
        hub_edge_mode
        and hub_worker_mode
        and (not hub_identity_changed or hub_identity_transition)
        and (not (changed & alarm_slice_scope) or authority_alarm_slice_exact)
        and (
            bool(deposed_by_address)
            or (
                bool(hub_source_fence_candidate)
                and hub_source_fence_candidate.issubset(HUB_SOURCE_FENCE_ACTIONS)
            )
        )
    )

    # The Hub Fargate worker slice (5b): every worker resource is a still-pending
    # pure create (or an already-applied no-op), the two opened base resources
    # UPDATE (the lambda endpoint policy deny->scoped, the interface-endpoints SG
    # ingress 1->2), and NOTHING else moves. Modeled on the runtime slice
    # (creates+opens), not the edge slice (creates only).
    hub_worker_creates_pending = {
        address
        for address in HUB_WORKER_RESOURCES
        if actual_non_noop.get(address) == ["create"]
    }
    hub_worker_opens_pending = {
        address
        for address in HUB_WORKER_OPENED_ADDRESSES
        if actual_non_noop.get(address) == ["update"]
    }
    hub_worker_transition = (
        hub_worker_mode
        and bool(changed)
        and all(
            actual_non_noop.get(address) in (None, ["create"])
            for address in HUB_WORKER_RESOURCES
        )
        and all(
            actual_non_noop.get(address) in (None, ["update"])
            for address in HUB_WORKER_OPENED_ADDRESSES
        )
        and changed == (hub_worker_creates_pending | hub_worker_opens_pending)
    )

    # A bounded, post-slice correction to the Hub S3 gateway-endpoint policy. The
    # worker slice (5b) created hub_s3 with an aws:PrincipalArn=hub-exec Condition,
    # but ECR layer-blob GETs ride presigned URLs signed by the ECR service -- NOT
    # the execution role -- so that Condition 403'd the image pull
    # (CannotPullContainerError). This lane admits EXACTLY the single hub_s3 in-place
    # policy update with nothing else moving; the corrected after-state (Principal
    # "*", no Condition, s3:GetObject on exactly the region starport layer bucket) is
    # validated by _check_hub_s3_endpoint_policy in _check_planned_security. Gated on
    # the worker slice being the committed default (hub_worker_mode), so it cannot
    # fire before the endpoint exists; once applied, hub_s3 is no-op and the steady
    # post-slice state's s3 policy check still enforces the corrected shape.
    hub_s3_correction = (
        hub_worker_mode
        and changed == {HUB_WORKER_S3_ENDPOINT_ADDRESS}
        and actual_non_noop.get(HUB_WORKER_S3_ENDPOINT_ADDRESS) == ["update"]
    )

    # The legacy-user cleanup is delete-only against every transition EXCEPT the
    # Hub UDP source-fence replacement, which was already pending and unapplied
    # when NHP #3362 removed the user from source. Once source stopped declaring
    # the user, no plan could carry the delete alone: every plan necessarily
    # carries the pending fence too, so a delete-only contract became unreachable
    # by construction and deadlocked BOTH the PR and apply lanes. Compose the two
    # exactly, the same way the fence already composes with authority-alarm
    # routing -- each half must independently match its own reviewed shape
    # (_is_exact_legacy_otp_user_delete above; _check_hub_source_fence_transition
    # in the branch body), and the delete is still refused alongside publisher
    # bootstrap, split-user creation, runtime activation, or anything else.
    # Remove this composition once the fence is applied and the delete is the
    # only pending change again.
    if (
        legacy_otp_user_delete
        and (changed or deposed_by_address)
        and not hub_source_fence_transition
    ):
        raise ContractError(
            "the detached legacy Connector OTP Redis user delete may accompany "
            "only the reviewed Hub UDP source-fence replacement; got "
            f"{actual_non_noop}"
        )

    if publisher_transition:
        plan_mode = "publisher-bootstrap"
        bootstrap_creates = changed
        _require_create_shapes(changed, by_address)
    elif hub_artifact_transition:
        plan_mode = "hub-artifact-bootstrap"
        bootstrap_creates = changed
        _require_create_shapes(changed, by_address)
    elif redis_transition:
        plan_mode = "redis-split-transition"
        _require_create_shapes(
            changed_redis_user_addresses,
            by_address,
            "split Redis users must be new resources",
        )
        group_change = by_address[redis_group_address]["change"]
        group_before = group_change.get("before")
        group_after = group_change.get("after")
        group_before_users = (
            group_before.get("user_ids") if isinstance(group_before, dict) else None
        )
        # The legacy membership this transition starts from. NHP #3362 removes
        # the legacy user itself, which makes this starting state unreachable
        # from source; the transition is kept only so the split-user create
        # contract (and its exact IAM create envelope) stays reviewed and
        # testable, and so this cleanup's delete-only plan can never be
        # mistaken for it.
        if (
            not isinstance(group_before, dict)
            or not isinstance(group_after, dict)
            or not isinstance(group_before_users, list)
            or len(group_before_users) != 2
            or set(group_before_users)
            != {
                LEGACY_OTP_REDIS_USER_ID,
                f"{CONTROL_PREFIX}-otp-default",
            }
        ):
            raise ContractError(
                "Redis split must start from the exact legacy user-group membership"
            )
        before_without_users = {
            key: value for key, value in group_before.items() if key != "user_ids"
        }
        after_without_users = {
            key: value for key, value in group_after.items() if key != "user_ids"
        }
        if before_without_users != after_without_users:
            raise ContractError(
                "Redis split user-group update may change only user_ids"
            )
    elif authority_contract_transition:
        plan_mode = "authority-contract-binding"
    elif provisioned_cell_catalog_lifecycle:
        plan_mode = "provisioned-cell-catalog-lifecycle"
        # No create shapes to assert -- every row already exists. The exact
        # after-state check below is what binds this to the reviewed catalog.
        _require_provisioned_cell_planned_output(plan, catalog_present=True)
    elif provisioned_cell_catalog_transition:
        plan_mode = "provisioned-cell-catalog"
        _require_create_shapes(changed, by_address)
        _require_provisioned_cell_create_output(plan)
    elif hub_privatelink_enforcement:
        plan_mode = "hub-privatelink-enforcement"
        # Ordered ahead of the source-fence branch because the fence's address
        # subset test would otherwise claim this singleton and reject it as a
        # non-exact remaining action subset. No create shape to assert -- the
        # edge already exists; the exact in-place delta is proved by the
        # predicate above, and the fenced after-state is still validated by the
        # steady-state edge checks in _check_planned_security.
    elif hub_source_fence_transition:
        # Ordered ahead of the image-update branch (and therefore ahead of every
        # branch it precedes) on purpose: deposed resources are validated ONLY
        # here (or by the fail-closed fallback below), because deposed entries
        # never enter ``by_address``/``changed``. The shapes cannot be confused
        # -- the fence address set is disjoint from the image-update, legacy
        # expansion, Hub identity, runtime, edge and worker sets, so any of those
        # plans leaves this predicate false and falls through. A co-occurring
        # Hub identity transition is the one deliberate exception, admitted only
        # as its own exact shape and proved separately below; ordering ahead of
        # the standalone identity branch keeps the deposed proof reachable.
        plan_mode_parts = ["hub-udp-source-fence-replacement"]
        if authority_alarm_slice_exact and (changed & alarm_slice_scope):
            plan_mode_parts.append("authority-alarm-routing")
        if legacy_otp_user_delete:
            # Its exact before-state was already proved above, and the address
            # was retired from by_address before the inventory check, so it
            # cannot reach any fence validation below.
            plan_mode_parts.append("legacy-otp-user-delete")
        plan_mode = "-with-".join(plan_mode_parts)
        _require_create_shapes(hub_source_fence_creates & changed, by_address)
        if hub_identity_creates_pending:
            _require_create_shapes(
                hub_identity_creates_pending,
                by_address,
                "Hub public identity parameter must be new",
            )
        if alarm_creates_pending:
            _require_create_shapes(
                alarm_creates_pending,
                by_address,
                "Authority alarm resources must be new",
            )
        # The identity and alarm addresses are disjoint from the fence set
        # (asserted by test_identity_and_fence_address_sets_are_disjoint and
        # test_alarm_and_fence_address_sets_are_disjoint), so withholding them
        # here cannot hide a fence resource from its own deep validation.
        _check_hub_source_fence_transition(
            {
                address: item
                for address, item in by_address.items()
                if address not in hub_identity_changed
                and address not in alarm_slice_changed
            },
            deposed_by_address,
        )
    # Precedence over the legacy expansion below is deliberate. The expansion's
    # update set (AUTHORITY_RUNTIME_LEGACY_EXPANSION_UPDATE_ADDRESSES) contains
    # the foundation plus the three Hub functions and their six aliases, so a
    # plan whose entire pending work is update-only on exactly those addresses
    # satisfies BOTH shapes and is indistinguishable from the plan JSON alone --
    # an expansion whose creates all applied looks exactly like a partially
    # applied image retag. _check_authority_image_update is the strictly
    # stronger envelope for that overlap (it pins the FROM->TO image, version
    # and basis evidence, which the expansion branch does not re-check for pure
    # updates), so the ambiguous shape must land here. Any plan that still has a
    # pending create/replace, or that moves a dependency-open address, is not a
    # subset of authority_image_update_scope and falls through unchanged.
    elif authority_proof_enable_transition:
        plan_mode = "authority-proof-enable"
        _require_create_shapes(
            set(AUTHORITY_PROOF_RESOURCES),
            by_address,
            "attended-proof Authority resources must be new",
        )
        _check_authority_proof_enable_transition(plan, by_address)
    elif authority_proof_disable_transition:
        plan_mode = "authority-proof-disable"
        _check_authority_proof_disable_transition(plan, by_address)
    elif authority_proof_consumer_enable_transition:
        plan_mode = "authority-proof-consumers-enable"
        _check_authority_proof_consumer_transition(by_address, enabling=True)
    elif authority_proof_consumer_disable_transition:
        plan_mode = "authority-proof-consumers-disable"
        _check_authority_proof_consumer_transition(by_address, enabling=False)
    elif (
        authority_proof_rollout_prepare_transition
        or authority_proof_rollout_prepare_recovery
    ):
        plan_mode = "authority-proof-rollout-prepare"
        if authority_proof_rollout_prepare_transition:
            _require_create_shapes(
                set(AUTHORITY_PROOF_ROLLOUT_RESOURCES) & changed,
                by_address,
                "proof rollout standby pools must be new",
            )
        else:
            _check_authority_proof_rollout_prepare_recovery(
                by_address,
                refresh_disabled=refresh_disabled,
            )
        if HUB_WORKER_SERVICE_ADDRESS in changed:
            _check_hub_service_task_revision_update(
                by_address, require_planned_target=True
            )
    elif authority_proof_rollout_selector_transition:
        plan_mode = "authority-proof-rollout-selector"
        before_colors = _authority_proof_rollout_colors(
            foundation_change.get("before", {})
        )
        after_colors = _authority_proof_rollout_colors(
            foundation_change.get("after", {})
        )
        if before_colors is None or after_colors is None:
            raise ContractError("proof selector colors are absent")
        _check_authority_proof_selector_update(
            by_address, before_colors[0], after_colors[0]
        )
    elif authority_image_update_transition:
        plan_mode = "authority-image-update"
        _check_authority_image_update(
            changed,
            by_address,
            plan,
            refresh_disabled=refresh_disabled,
        )
    elif authority_runtime_legacy_expansion:
        plan_mode_parts = ["authority-runtime-legacy-expansion"]
        if hub_identity_changed:
            plan_mode_parts.append("hub-identity")
        if provisioned_cell_catalog_full_create:
            plan_mode_parts.append("provisioned-cell-catalog")
        plan_mode = "-".join(plan_mode_parts)
        _require_create_shapes(
            legacy_expansion_creates_pending,
            by_address,
            "legacy Authority expansion resources must be new",
        )
        _require_create_shapes(
            hub_identity_creates_pending,
            by_address,
            "Hub public identity parameter must be new",
        )
        _require_create_shapes(
            provisioned_cell_catalog_creates_pending,
            by_address,
            "provisioned-cell catalog rows must be new",
        )
        if provisioned_cell_catalog_full_create:
            _require_provisioned_cell_create_output(plan)
        if legacy_expansion_replaces_pending and not (
            legacy_expansion_replaces_pending
            == set(AUTHORITY_RUNTIME_LEGACY_EXPANSION_REPLACE_ADDRESSES)
            and _is_exact_legacy_authority_sg_replacement(
                by_address[AUTHORITY_RUNTIME_LAMBDA_SG_ADDRESS]["change"]
            )
        ):
            raise ContractError(
                "legacy Authority expansion must exactly replace the inline-rule "
                "function security group"
            )
    elif standalone_hub_identity_migration:
        plan_mode = "hub-identity-migration"
        _require_create_shapes(
            hub_identity_creates_pending,
            by_address,
            "Hub public identity parameter must be new",
        )
    elif authority_runtime_transition:
        plan_mode = "authority-runtime-slice"
        # Only the still-pending creates must present a pure-create shape; any
        # create that already applied on an earlier attempt is a validated no-op.
        _require_create_shapes(runtime_creates_pending, by_address)
    elif authority_runtime_retry_transition:
        plan_mode = "authority-runtime-slice-retry"
        # Pending pure-creates (aliases / provisioned-concurrency) present a
        # create shape; the tainted-function replaces and the exec-role trust
        # updates are validated by their exact after-state security checks below
        # (_check_authority_runtime_resources), not as pure creates.
        _require_create_shapes(runtime_creates_pending, by_address)
    elif hub_edge_transition:
        plan_mode = "hub-edge-slice"
        # Every edge resource is a still-pending pure create; an edge resource
        # that already applied on an earlier attempt is a validated no-op.
        _require_create_shapes(hub_edge_creates_pending, by_address)
    elif hub_worker_transition:
        plan_mode = "hub-worker-slice"
        # Only the still-pending worker creates must present a pure-create shape;
        # the two opened base resources present as updates validated by their
        # exact after-state security checks in _check_planned_security below.
        _require_create_shapes(hub_worker_creates_pending, by_address)
    elif authority_alarm_routing_transition:
        plan_mode = "authority-alarm-routing"
        # The already-live spillover alarms present as in-place updates whose
        # after-state is validated by _check_authority_alarm_routing; only the
        # still-pending new alarms must present a pure-create shape.
        _require_create_shapes(
            alarm_creates_pending,
            by_address,
            "Authority alarm resources must be new",
        )
    elif (
        _cells_only := _claim_provisioned_cell_status_update(
            changed, actual_non_noop, by_address
        )
    ) is not None and set(_cells_only) == changed:
        # Reviewed cell lifecycle transition (e.g. active -> draining). The
        # claim above already proved every other catalog field matches the
        # reviewed values byte-for-byte.
        plan_mode = "provisioned-cell-status-update"
    elif (
        _assignability_only := _claim_provisioned_cell_general_assignable_update(
            changed, actual_non_noop, by_address
        )
    ) is not None and set(_assignability_only) == changed:
        # Reviewed placement-eligibility flip (general_assignable). The claim
        # above already proved status, weight, endpoint, keys, and updated_at are
        # byte-identical to the reviewed row; only general_assignable moved.
        plan_mode = "provisioned-cell-general-assignable-update"
        _validate_provisioned_cell_general_assignable_update(
            _assignability_only, by_address, plan
        )
    elif (
        _hub_image_only := _claim_hub_worker_image_update(
            changed, actual_non_noop, by_address
        )
    ) is not None and set(_hub_image_only) == changed and not deposed_by_address:
        # Deploying a reviewed Hub image. Immutable task definitions make this a
        # replacement by construction; _check_hub_worker_image_update proves the
        # replacement is image-only before it is admitted.
        #
        # Matched through the CLAIM rather than `changed == {task definition}`.
        # Replacing the task definition of a resource an ECS SERVICE references
        # always updates that service too, so the literal single-address form
        # this branch used to require is a shape a real Hub image deploy never
        # produces -- the plan fell through to the terminal reject, and the
        # composer could not rescue it either because composition needs two or
        # more claims and this is one. Same fix, and same reason, as
        # authority-hub-exec-policy-update above.
        plan_mode = "hub-worker-image-update"
        _validate_hub_worker_image_update(_hub_image_only, by_address, plan)
    elif hub_s3_correction:
        plan_mode = "hub-s3-endpoint-policy-correction"
        # A single in-place policy update on the already-created hub_s3 gateway
        # endpoint -- no create shape to assert. The corrected after-state is
        # validated by _check_hub_s3_endpoint_policy in _check_planned_security.
    elif (
        changed == {AUTHORITY_PROOF_EXEC_POLICY_ADDRESS}
        and actual_non_noop.get(AUTHORITY_PROOF_EXEC_POLICY_ADDRESS) == ["update"]
        and not deposed_by_address
    ):
        plan_mode = "authority-proof-mutation-decrypt-update"
        _check_authority_proof_mutation_decrypt_update(by_address)
    elif (
        _exec_policy_only := _claim_authority_hub_exec_policy_update(
            changed, actual_non_noop, by_address
        )
    ) is not None and set(_exec_policy_only) == changed and not deposed_by_address:
        # The Hub function exec policies moving on their own. Composition needs
        # two or more claims by design, so this shape -- one reviewed lane and
        # nothing else -- would otherwise fall through to the terminal reject
        # even though the very same claim and validator are already trusted
        # inside a composed plan.
        plan_mode = "authority-hub-exec-policy-update"
        _validate_authority_hub_exec_policy_update(
            _exec_policy_only, by_address, plan
        )
    elif (
        _retirement_only := _claim_authority_proof_rollout_retirement(
            changed, actual_non_noop, by_address
        )
    ) and set(_retirement_only) == changed and not deposed_by_address:
        # Closing the attended-proof rollout window on its own. Composition
        # needs two or more claims by design, so this shape would otherwise
        # fall through to the terminal reject.
        plan_mode = "authority-proof-rollout-retirement"
        _validate_authority_proof_rollout_retirement(
            _retirement_only, by_address, plan
        )
    elif (
        _composed_plan_mode := _compose_admitted_transitions(
            changed, actual_non_noop, by_address, deposed_by_address, plan
        )
    ) is not None:
        # Two or more individually reviewed transitions landing in one plan.
        plan_mode = _composed_plan_mode
    elif changed or deposed_by_address:
        raise ContractError(
            "Terraform changes must be an exact no-op, publisher bootstrap, "
            "Hub artifact bootstrap, reviewed Redis split, the exact detached "
            "legacy OTP Redis user delete, exact Authority "
            "contract binding, the exact provisioned-cell catalog create, the exact "
            "legacy Authority expansion, the exact Hub identity migration, the exact "
            "Authority runtime slice or image update, the exact Authority alarm "
            "routing slice, the exact attended-proof enablement or rollback, the exact "
            "proof-policy consumer version staging or rollback with both live "
            "aliases unchanged, the exact proof rollout prepare or selector apply, the exact "
            "Hub public edge slice, the exact Hub Fargate worker slice, or the "
            "exact proof-mutation DynamoDB decrypt grant, the "
            "exact Hub S3 endpoint-policy correction, the exact Hub worker "
            "image update, Hub PrivateLink "
            "inbound-rule enforcement, the exact Hub client-edge port "
            "migration, or Hub UDP source-fence "
            "replacement; "
            f"got {actual_non_noop}"
        )

    if legacy_otp_user_delete and plan_mode == "no-op":
        # The standalone delete: reached only with an otherwise-exact no-op
        # inventory, so it cannot mask a second transition. Guarded on "no-op"
        # so it cannot overwrite the source-fence composite, which already
        # appended its own part. Naming it distinctly keeps the delete out of
        # the "no-op" bucket that gates state normalization and plan
        # applyability below, and binds the mode into the contract summary.
        plan_mode = "legacy-otp-user-delete"

    if proof_mode and plan_mode != "authority-proof-enable":
        _check_authority_proof_steady_output(
            plan,
            by_address[
                "module.control.terraform_data.foundation_contract"
            ]["change"]["after"],
        )

    # runtime_mode / hub_worker_mode with no non-no-op change is the steady
    # post-slice state; the scoped policies, endpoint opens, and SG ingress are
    # still validated below regardless of transition vs steady.
    _check_planned_security(
        by_address,
        catalog_mode=catalog_mode,
        runtime_mode=runtime_mode,
        proof_mode=proof_mode,
        proof_rollout_mode=proof_rollout_mode,
        hub_worker_mode=hub_worker_mode,
        refresh_disabled=refresh_disabled,
    )

    normalization_drift_kind = _check_state_normalization_drift(
        drift,
        by_address,
        refresh_only="resource_changes" not in plan,
    )
    # ``_check_state_normalization_drift`` returns "none" iff ``drift`` is
    # empty, so ``len(drift)`` already yields 0 in that case. This stays the
    # TOTAL observed drift, benign projections included, so the plan lane and
    # the pre-apply live lane keep counting the same thing.
    normalization_drift_count = len(drift)

    # "first-projection" is deliberately NOT bound to a plan_mode. Every other
    # kind below is pinned to the transitions it may accompany because it
    # reports a real value change whose blast radius depends on what else the
    # plan does. A pure first projection reports no change at all -- state had no
    # prior value -- so there is no interaction to constrain, and pinning it
    # would rebuild exactly the per-transition treadmill this replaces. The
    # planned changes it accompanies are still fully validated on their own.
    if normalization_drift_kind in (
        "publisher-role",
        "hub-publisher-role",
    ) and plan_mode != "no-op":
        raise ContractError(
            "publisher role normalization cannot be combined with a resource transition"
        )
    if normalization_drift_kind == "authority-digest":
        # A composed plan_mode is "composed-<a>-with-<b>"; admit it when one of
        # its parts is admitted here, so a reviewed transition does not lose its
        # allowance merely by landing alongside another reviewed one.
        #
        # The OR is safe because admission here is not the check. Each part is
        # independently claimed and validated, and the drift itself goes through
        # _check_digest_normalization(item, by_address, spec=...), whose
        # signature takes no plan_mode at all -- so it cannot be relaxed by what
        # a mode is composed with. Composition widens WHICH plans may carry the
        # drift; it can never weaken what the drift must look like.
        if not _plan_mode_parts(plan_mode) & set((
            "no-op",
            "redis-split-transition",
            # The detached legacy OTP Redis user delete, for the same reason the
            # Redis split may carry this drift: the publisher owns this
            # parameter and may have written since the last apply, which is
            # inherent refresh noise rather than a signal. The delete stays
            # address-level exact -- every other Control address is still a
            # no-op, and _check_digest_normalization independently pins the
            # parameter identity and requires its planned action be no-op.
            "legacy-otp-user-delete",
            "authority-contract-binding",
            # The publisher owns this parameter's value and Terraform ignores it
            # after creation, so the refresh reports this drift whenever the
            # publisher has written since the last apply -- it is inherent, not a
            # signal. An authority image update is precisely the reviewed
            # transition that follows such a write, so excluding it here blocked
            # the one plan_mode most likely to carry the drift. The drift itself
            # is unaffected by this list: _check_digest_normalization still
            # requires the exact parameter identity, description, ARN, a
            # well-formed sha256, and a planned no-op matching the refreshed
            # value, and the image transition remains pinned to its exact
            # reviewed from/to URIs and evidence.
            "authority-image-update",
            # The publisher-owned digest may have advanced since the last
            # Control apply. The attended-proof transition binds the freshly
            # generated contract to that same immutable digest, while the
            # normalization checker still requires the SSM resource itself to
            # remain an exact no-op at the refreshed value.
            "authority-proof-enable",
            "authority-proof-disable",
            "authority-proof-consumers-enable",
            "authority-proof-consumers-disable",
            # The routine, structurally-validated image roll. Publisher writes
            # to the digest parameter are exactly what precedes a roll, so this
            # is the transition most likely to carry the drift.
            "authority-image-roll",
        )):
            raise ContractError(
                "authority digest normalization may accompany only a reviewed "
                "Redis split, the legacy OTP Redis user delete, contract "
                "binding, authority image transition, or attended-proof "
                "enablement/rollback"
            )
        if plan_mode == "no-op" and "resource_changes" in plan:
            raise ContractError(
                "authority digest-only state normalization requires a "
                "refresh-only plan"
            )
    if normalization_drift_kind == "hub-digest":
        if plan_mode != "no-op" or "resource_changes" in plan:
            raise ContractError(
                "Hub digest state normalization requires a refresh-only plan"
            )
    if normalization_drift_kind == "authority-and-hub-digest":
        _require_normalization_plan_mode(normalization_drift_kind, plan_mode, plan)
    # "authority-alias-refresh" is deliberately NOT plan-mode-gated: the
    # classifier only returns it when every drifted address is planned no-op,
    # so the drift cannot smuggle a change into any plan mode -- it is pure
    # state catch-up from a failed apply's partial success.
    if normalization_drift_kind == "redis-passwords" and plan_mode != "no-op":
        raise ContractError(
            "Redis password projection normalization cannot be combined with "
            "a resource transition"
        )
    if normalization_drift_kind == _AUTHORITY_ENABLEMENT_NORMALIZATION_KIND:
        # The benign Hub-publisher-role + authority-digest drift pair is admitted
        # ONLY for the reviewed Authority contract enablement transition. Each
        # drift was already validated independently in
        # ``_check_state_normalization_drift``; here we bind it to the exact plan
        # shape it may accompany. The pair is deliberately admissible in this
        # config-changing (not refresh-only) plan because the authority image
        # digest rolls permanently on every upstream publish, so it must bind
        # into the same enablement plan rather than requiring a separate
        # refresh-only observation. Any other plan_mode carrying this pair (no-op,
        # refresh-only, or another transition) stays fail-closed here.
        if plan_mode != "authority-contract-binding":
            raise ContractError(
                "the benign Hub-publisher-role + authority-digest drift pair is "
                "admitted only for the Authority contract enablement transition"
            )
    _require_slice_and_digest_plan_mode(normalization_drift_kind, plan_mode)
    if (
        normalization_drift_kind
        == AUTHORITY_PROOF_CONCURRENCY_RECOVERY_NORMALIZATION_KIND
        and plan_mode != "authority-image-update"
    ):
        raise ContractError(
            "proof concurrency recovery drift may accompany only the exact "
            "Authority image recovery transition"
        )
    if (
        normalization_drift_kind
        == AUTHORITY_PROOF_PREPARE_RECOVERY_NORMALIZATION_KIND
        and plan_mode != "authority-proof-rollout-prepare"
    ):
        raise ContractError(
            "proof prepare recovery drift may accompany only the exact "
            "Authority proof rollout recovery transition"
        )

    # A no-op plan is normally NOT applyable: nothing would be written. Two
    # shapes legitimately break that, and both are enumerated rather than
    # inferred from Terraform's own flag.
    #
    #  1. a refresh-only state normalization (drift absorbed, no resource_changes)
    #  2. an OUTPUTS-ONLY change -- adding, removing or re-valuing a root output
    #     touches no resource, so `changed` is empty and plan_mode is "no-op",
    #     but the apply still rewrites state outputs and Terraform reports
    #     applyable=true. Before this, any outputs-only Control change was
    #     unmergeable: it failed here with an applyability mismatch no message
    #     explained.
    #
    # This does not widen what may be applied. The output SET is still pinned to
    # EXPECTED_CONTROL_OUTPUTS by _check_authority_proof_steady_output, and the
    # empty `changed` set already proves no resource moves; all this recognises
    # is that writing an output is real work.
    #  3. a state-only `forget` of the orphaned proof-controller grant. That
    #     address is absent from the config resource map, so it never enters
    #     `changed` and plan_mode stays "no-op" -- but releasing it from state
    #     is still an apply, and Terraform reports applyable=true. Bounded to
    #     the `forget` action on that one address, so a delete cannot borrow it;
    #     see _validate_authority_proof_controller_orphan_forget.
    output_only_change = any(
        isinstance(change, dict) and change.get("actions") != ["no-op"]
        for change in (plan.get("output_changes") or {}).values()
    )
    orphan_forget_pending = any(
        isinstance(item, dict)
        and item.get("address") == AUTHORITY_PROOF_CONTROLLER_POLICY_ADDRESS
        and isinstance(item.get("change"), dict)
        and item["change"].get("actions") == ["forget"]
        for item in (plan.get("resource_changes") or [])
    )
    expected_applyable = (
        plan_mode != "no-op"
        or (normalization_drift_count > 0 and "resource_changes" not in plan)
        or output_only_change
        or orphan_forget_pending
    )
    if plan.get("applyable") is not expected_applyable:
        raise ContractError(
            f"Terraform {plan_mode} plan applyability must match its exact resource "
            "transition or the exact refresh-only state normalization"
        )
    # Bind the complete admitted drift across the review-time and immediate
    # pre-apply plans. Canonical object-key ordering removes JSON presentation
    # noise, while any value or list-order change intentionally aborts apply.
    return {
        "bootstrap_create_count": len(bootstrap_creates),
        "contract_sha256": contract_sha256(),
        "normalization_drift_sha256": _normalization_drift_sha256(drift),
        "normalization_drift_count": normalization_drift_count,
        "normalization_drift_kind": normalization_drift_kind,
        "plan_mode": plan_mode,
        "resource_count": len(expected_resources),
    }


def check_state_list(path: Path) -> dict[str, int]:
    try:
        addresses = {
            line.strip() for line in path.read_text().splitlines() if line.strip()
        }
    except OSError as exc:
        raise ContractError(f"cannot read Terraform state list: {exc}") from exc

    # `terraform state list` includes both managed resources and cached data
    # sources. Admit the base union plus any complete subset of the independent
    # optional slices ({provisioned-cell catalog, authority runtime, Hub edge,
    # Hub worker}); each slice is all-or-nothing. The subsequent JSON state
    # check remains mode-aware and independently enforces types and
    # security-sensitive values.
    data_expected = set(EXPECTED_DATA_RESOURCES)
    catalog_extra = set(PROVISIONED_CELL_RESOURCES)
    base_expected = (set(EXPECTED_RESOURCES) - catalog_extra) | data_expected
    runtime_extra = set(AUTHORITY_RUNTIME_RESOURCES)
    proof_extra = set(AUTHORITY_PROOF_RESOURCES)
    proof_consumer_data_extra = set(
        AUTHORITY_PROOF_CONSUMER_LIVE_ALIAS_DATA_RESOURCES
    )
    proof_rollout_data_extra = set(
        AUTHORITY_PROOF_ROLLOUT_LIVE_ALIAS_DATA_RESOURCES
    )
    proof_rollout_extra = set(AUTHORITY_PROOF_ROLLOUT_RESOURCES)
    hub_edge_extra = set(HUB_EDGE_RESOURCES)
    # The worker slice contributes both managed resources AND its two count-gated
    # data sources (the published image digest and the keygen zip); presence is
    # detected on the managed set. It may appear only alongside both the edge and
    # runtime slices (the same dependency the plan lane enforces).
    hub_worker_managed = set(HUB_WORKER_RESOURCES)
    hub_worker_extra = hub_worker_managed | set(HUB_WORKER_DATA_RESOURCES)
    catalog_present = bool(addresses & catalog_extra)
    runtime_present = bool(addresses & runtime_extra)
    proof_present = bool(addresses & proof_extra)
    proof_alias_reads_present = bool(addresses & proof_consumer_data_extra)
    proof_rollout_alias_reads_present = bool(addresses & proof_rollout_data_extra)
    proof_rollout_present = bool(addresses & proof_rollout_extra)
    hub_edge_present = bool(addresses & hub_edge_extra)
    hub_worker_present = bool(addresses & hub_worker_managed)
    if proof_present and not runtime_present:
        raise ContractError(
            "attended-proof Authority slice requires the complete runtime slice "
            "in state"
        )
    if proof_alias_reads_present and not (runtime_present and proof_present):
        raise ContractError(
            "proof-policy consumer staging requires the complete runtime and "
            "attended-proof slices in state"
        )
    if proof_rollout_alias_reads_present and not proof_rollout_present:
        raise ContractError(
            "proof-policy mutation alias reads require the complete rollout state"
        )
    if proof_rollout_present and not (
        runtime_present and proof_present and hub_worker_present
    ):
        raise ContractError(
            "proof-policy rollout state requires the complete runtime, "
            "attended-proof, and Hub worker slices"
        )
    if hub_worker_present and not (hub_edge_present and runtime_present):
        raise ContractError(
            "Hub worker slice requires both the Hub edge slice and the authority "
            "runtime slice in state"
        )
    expected = (
        base_expected
        | (catalog_extra if catalog_present else set())
        | (runtime_extra if runtime_present else set())
        | (proof_extra if proof_present else set())
        | (proof_rollout_extra if proof_rollout_present else set())
        | (proof_consumer_data_extra if proof_present else set())
        | (proof_rollout_data_extra if proof_rollout_present else set())
        | (hub_edge_extra if hub_edge_present else set())
        | (hub_worker_extra if hub_worker_present else set())
    )
    if addresses != expected:
        missing = sorted(expected - addresses)
        extra = sorted(addresses - expected)
        raise ContractError(
            f"Terraform state inventory mismatch; missing={missing}, extra={extra}"
        )
    return {
        "data_resource_count": (
            len(EXPECTED_DATA_RESOURCES)
            + (
                len(AUTHORITY_PROOF_CONSUMER_LIVE_ALIAS_DATA_RESOURCES)
                if proof_present
                else 0
            )
            + (
                len(AUTHORITY_PROOF_ROLLOUT_LIVE_ALIAS_DATA_RESOURCES)
                if proof_rollout_present
                else 0
            )
            + (len(HUB_WORKER_DATA_RESOURCES) if hub_worker_present else 0)
        ),
        "managed_resource_count": (
            len(EXPECTED_RESOURCES)
            - len(PROVISIONED_CELL_RESOURCES)
            + (len(PROVISIONED_CELL_RESOURCES) if catalog_present else 0)
            + (len(AUTHORITY_RUNTIME_RESOURCES) if runtime_present else 0)
            + (len(AUTHORITY_PROOF_RESOURCES) if proof_present else 0)
            + (len(AUTHORITY_PROOF_ROLLOUT_RESOURCES) if proof_rollout_present else 0)
            + (len(HUB_EDGE_RESOURCES) if hub_edge_present else 0)
            + (len(HUB_WORKER_RESOURCES) if hub_worker_present else 0)
        ),
    }


def _iter_resources(module: Any) -> Iterable[dict[str, Any]]:
    if not isinstance(module, dict):
        return
    for resource in module.get("resources", []):
        yield resource
    for child in module.get("child_modules", []):
        yield from _iter_resources(child)


def _check_authority_enablement_normalization_drift(
    drift: list[dict[str, Any]],
    prior_state: Any,
) -> dict[str, str | int]:
    """Re-prove the benign enablement drift pair against the captured state.

    Pre-apply live-refresh counterpart to the plan-lane admission in
    ``_check_state_normalization_drift``: it binds the same benign pair
    (Hub-publisher inline-policy reflection + Authority image-digest roll) in the
    output-ignoring ``check_normalization_drift`` mode so ``op=apply`` /
    ``op=verify`` can re-prove the reviewed drift even though the enablement's
    unapplied ``authority_image_uri`` output change stops the full refresh-only
    plan contract from describing the observation.

    The pair is reconstructed from the captured pre-plan state exactly as the
    refresh-only ``check_plan`` lane does -- ``_reconstruct_refresh_only_changes``
    binds each drift ``before`` to the captured state value and pins the refresh
    sensitivity envelope -- then dispatched through the SAME
    ``_check_state_normalization_drift`` the plan lane uses, so each drift is
    validated by its existing ``_check_publisher_role_normalization`` /
    ``_check_digest_normalization`` (neither weakened), order-insensitive. The
    Authority digest rolls permanently and the Hub-publisher role reflection is
    benign, so the enablement plan/apply/verify lanes must all bind WITH the pair
    present. Any other address, count, shape, or an unmatched captured state fails
    closed. The returned ``normalization_drift_sha256`` is canonical (address
    sorted) so it matches the plan lane's summary regardless of serialization
    order.
    """
    if (
        not isinstance(prior_state, dict)
        or prior_state.get("format_version") != "1.0"
        or prior_state.get("terraform_version") != TF_VERSION
    ):
        raise ContractError(
            f"normalization observation requires exact Terraform {TF_VERSION} state JSON"
        )
    reconstructed = _reconstruct_refresh_only_changes(prior_state, drift)
    by_address = {item["address"]: item for item in reconstructed}
    # The pair validators additionally need the Hub publisher inline policy from
    # the captured inventory to prove the role identity; the policy carries no
    # drift, so require it explicitly here.
    for required in (
        "module.control.aws_iam_role.hub_publisher",
        "module.control.aws_iam_role_policy.hub_publisher",
        _AUTHORITY_DIGEST_ADDRESS,
    ):
        if required not in by_address:
            raise ContractError(
                f"captured state does not contain the exact {required} resource"
            )
    kind = _check_state_normalization_drift(drift, by_address, refresh_only=True)
    if kind != _AUTHORITY_ENABLEMENT_NORMALIZATION_KIND:
        # The caller matched the exact 2-address set, so the shared dispatch must
        # return the combined kind. Anything else is a contract regression.
        raise _unexpected_drift_error(drift)
    return {
        "normalization_drift_count": 2,
        "normalization_drift_kind": kind,
        "normalization_drift_sha256": _normalization_drift_sha256(drift),
    }


def _check_dual_digest_normalization_drift(
    drift: list[dict[str, Any]],
    prior_state: Any,
) -> dict[str, str | int]:
    """Re-prove the exact Authority+Hub digest pair against captured state."""
    if (
        len(drift) != 2
        or {item.get("address") for item in drift}
        != {_AUTHORITY_DIGEST_ADDRESS, _HUB_DIGEST_ADDRESS}
    ):
        raise _unexpected_drift_error(drift)
    if (
        not isinstance(prior_state, dict)
        or prior_state.get("format_version") != "1.0"
        or prior_state.get("terraform_version") != TF_VERSION
    ):
        raise ContractError(
            f"normalization observation requires exact Terraform {TF_VERSION} state JSON"
        )
    reconstructed = _reconstruct_refresh_only_changes(prior_state, drift)
    for address in (_AUTHORITY_DIGEST_ADDRESS, _HUB_DIGEST_ADDRESS):
        matches = [item for item in reconstructed if item.get("address") == address]
        if len(matches) != 1 or matches[0].get("type") != "aws_ssm_parameter":
            raise ContractError(
                f"captured state does not contain the exact digest parameter: {address}"
            )
    by_address = {item["address"]: item for item in reconstructed}
    kind = _check_state_normalization_drift(drift, by_address, refresh_only=True)
    if kind != "authority-and-hub-digest":
        raise _unexpected_drift_error(drift)
    return {
        "normalization_drift_count": 2,
        "normalization_drift_kind": kind,
        "normalization_drift_sha256": _normalization_drift_sha256(drift),
    }


def check_normalization_drift(plan: Any, prior_state: Any) -> dict[str, str | int]:
    """Bind a live refresh observation to the externally owned digest drift.

    This narrow mode is used immediately before applying a saved plan when
    pending output changes mean the full refresh-only plan contract cannot
    describe the observation. It covers the Authority digest alongside the
    reviewed Redis transition and the separately published Hub digest. The
    check ignores unapplied outputs and binds only the exact SSM value/version
    observation to the captured state.
    """
    if not isinstance(plan, dict):
        raise ContractError("Terraform normalization plan must be an object")
    if (
        plan.get("format_version") != "1.2"
        or plan.get("terraform_version") != TF_VERSION
        or plan.get("complete") is not True
        or plan.get("errored") is not False
        or plan.get("applyable") is not True
        or "resource_changes" in plan
    ):
        raise ContractError(
            "Terraform normalization observation must be an exact applyable "
            f"refresh-only {TF_VERSION} plan"
        )
    planned_values = plan.get("planned_values")
    if (
        not isinstance(planned_values, dict)
        or planned_values.get("root_module") != {}
    ):
        raise ContractError(
            "Terraform normalization observation must not plan resource values"
        )
    _check_no_embedded_actions(plan)
    drift = _non_noop(plan.get("resource_drift"), "resource_drift")
    # Same first-projection filter, and in the same position (ahead of every
    # reviewed-kind match), as the ``check_plan`` lane. The workflow compares
    # {count, kind, sha256} between this live pre-apply observation and the
    # reviewed plan, so the two lanes MUST classify identical drift identically
    # or a benign projection aborts the apply. The count stays the TOTAL observed
    # drift on both sides, and the sha256 covers the full array.
    _, substantive = _partition_first_projection_drift(drift)
    if drift and not substantive:
        return {
            "normalization_drift_count": len(drift),
            "normalization_drift_kind": "first-projection",
            "normalization_drift_sha256": _normalization_drift_sha256(drift),
        }
    if (
        len(drift) == 2
        and {item.get("address") for item in drift}
        == {_AUTHORITY_DIGEST_ADDRESS, _HUB_DIGEST_ADDRESS}
    ):
        return _check_dual_digest_normalization_drift(drift, prior_state)
    if (
        len(drift) == 2
        and {item.get("address") for item in drift}
        == _AUTHORITY_ENABLEMENT_NORMALIZATION_ADDRESSES
    ):
        # The enablement plan binds the benign Hub-publisher-role + authority-digest
        # pair (see ``_AUTHORITY_ENABLEMENT_NORMALIZATION_ADDRESSES``). The pre-apply
        # live-refresh lane re-proves the same pair here, in this output-ignoring
        # narrow mode, because the enablement's unapplied output change means the
        # full refresh-only ``check_plan`` contract cannot describe the observation.
        return _check_authority_enablement_normalization_drift(drift, prior_state)
    # The reviewed image-recovery observation currently carries 22 benign
    # first-projection alarm entries alongside the substantive PM/PCR pool
    # failures. Classify and validate only the substantive remainder, just as
    # the saved-plan lane above does, while binding the returned count/hash to
    # the full observation that the workflow compares across plan and apply.
    proof_recovery_addresses = [item.get("address") for item in substantive]
    if (
        all(isinstance(address, str) for address in proof_recovery_addresses)
        and set(proof_recovery_addresses)
        and set(proof_recovery_addresses)
        <= set(AUTHORITY_IMAGE_UPDATE_RECOVERY_REPLACES)
    ):
        _check_authority_proof_concurrency_recovery_drift(substantive)
        if (
            not isinstance(prior_state, dict)
            or prior_state.get("format_version") != "1.0"
            or prior_state.get("terraform_version") != TF_VERSION
        ):
            raise ContractError(
                f"normalization observation requires exact Terraform "
                f"{TF_VERSION} state JSON"
            )
        state_values = prior_state.get("values")
        root = (
            state_values.get("root_module")
            if isinstance(state_values, dict)
            else None
        )
        for item in substantive:
            address = item["address"]
            matches = [
                resource
                for resource in _iter_resources(root)
                if resource.get("mode") == "managed"
                and resource.get("address") == address
            ]
            if (
                len(matches) != 1
                or matches[0].get("type")
                != "aws_lambda_provisioned_concurrency_config"
                or matches[0].get("values") != item["change"]["before"]
            ):
                raise ContractError(
                    "proof concurrency recovery drift does not match captured "
                    f"state for {address}"
                )
        return {
            "normalization_drift_count": len(drift),
            "normalization_drift_kind": (
                AUTHORITY_PROOF_CONCURRENCY_RECOVERY_NORMALIZATION_KIND
            ),
            "normalization_drift_sha256": _normalization_drift_sha256(drift),
        }
    prepare_recovery_addresses = [item.get("address") for item in substantive]
    if (
        all(isinstance(address, str) for address in prepare_recovery_addresses)
        and set(prepare_recovery_addresses)
        == set(AUTHORITY_PROOF_PREPARE_RECOVERY_DRIFT_ADDRESSES)
    ):
        _check_authority_proof_prepare_recovery_drift(substantive)
        if (
            not isinstance(prior_state, dict)
            or prior_state.get("format_version") != "1.0"
            or prior_state.get("terraform_version") != TF_VERSION
        ):
            raise ContractError(
                f"normalization observation requires exact Terraform "
                f"{TF_VERSION} state JSON"
            )
        state_values = prior_state.get("values")
        root = (
            state_values.get("root_module")
            if isinstance(state_values, dict)
            else None
        )
        for item in substantive:
            address = item["address"]
            matches = [
                resource
                for resource in _iter_resources(root)
                if resource.get("mode") == "managed"
                and resource.get("address") == address
            ]
            expected_type = (
                "aws_iam_role"
                if address == AUTHORITY_PROOF_PREPARE_RECOVERY_HUB_ROLE_ADDRESS
                else "aws_lambda_provisioned_concurrency_config"
            )
            if (
                len(matches) != 1
                or matches[0].get("type") != expected_type
                or matches[0].get("values") != item["change"]["before"]
            ):
                raise ContractError(
                    "proof prepare recovery drift does not match captured "
                    f"state for {address}"
                )
        return {
            "normalization_drift_count": len(drift),
            "normalization_drift_kind": (
                AUTHORITY_PROOF_PREPARE_RECOVERY_NORMALIZATION_KIND
            ),
            "normalization_drift_sha256": _normalization_drift_sha256(drift),
        }
    slice_drift_addresses = [item.get("address") for item in drift]
    if all(isinstance(a, str) for a in slice_drift_addresses) and set(
        slice_drift_addresses
    ) <= (set(AUTHORITY_RUNTIME_RESOURCES) | AUTHORITY_RUNTIME_OPENED_ADDRESSES):
        # Partial-apply RETRY of the runtime slice. The pre-apply live refresh
        # re-reads the already-applied slice resources and the dependency
        # endpoints being opened (benign provider re-projection). Same strict
        # confinement rule as the check_plan lane (every drifted address inside
        # the slice + its three opens); any address outside falls through and
        # fails closed. This narrow lane binds only the exact {count, kind,
        # sha256} the reviewed completion plan emitted, so a MOVED live
        # observation aborts the apply. The security-load-bearing after-state
        # fields are validated by check_plan on the reviewed completion plan, not
        # in this output-ignoring re-observation.
        return {
            "normalization_drift_count": len(drift),
            "normalization_drift_kind": "authority-runtime-slice-normalization",
            "normalization_drift_sha256": _normalization_drift_sha256(drift),
        }
    if len(drift) != 1:
        raise _unexpected_drift_error(drift)
    specs = {
        _AUTHORITY_DIGEST_ADDRESS: _AUTHORITY_DIGEST_SPEC,
        _HUB_DIGEST_ADDRESS: _HUB_DIGEST_SPEC,
    }
    spec = specs.get(drift[0].get("address"))
    if spec is None:
        raise _unexpected_drift_error(drift)
    before, _ = _validate_digest_normalization(drift[0], spec=spec)

    if (
        not isinstance(prior_state, dict)
        or prior_state.get("format_version") != "1.0"
        or prior_state.get("terraform_version") != TF_VERSION
    ):
        raise ContractError(
            f"normalization observation requires exact Terraform {TF_VERSION} state JSON"
        )
    state_values = prior_state.get("values")
    root = (
        state_values.get("root_module") if isinstance(state_values, dict) else None
    )
    matches = [
        item
        for item in _iter_resources(root)
        if item.get("mode") == "managed"
        and item.get("address") == spec["address"]
    ]
    if len(matches) != 1 or matches[0].get("type") != "aws_ssm_parameter":
        raise ContractError(
            f"captured state does not contain the exact {spec['label']} "
            "digest parameter"
        )
    if matches[0].get("values") != before:
        raise ContractError(
            f"{spec['label']} digest refresh before value does not match "
            "captured state"
        )
    return {
        "normalization_drift_count": 1,
        "normalization_drift_kind": spec["kind"],
        "normalization_drift_sha256": _normalization_drift_sha256(drift),
    }


def _require_iam_redis_user(
    user: dict[str, Any], user_id: str, access_string: str, message: str
) -> None:
    # Every runtime OTP Redis user must be IAM-only, passwordless, name==id, and
    # pinned to its exact reviewed ACL. Any drift fails the state contract.
    auth = user.get("authentication_mode", [])
    if (
        user.get("user_name") != user_id
        or user.get("user_id") != user_id
        or user.get("access_string") != access_string
        or [item.get("type") for item in auth] != ["iam"]
        or [item.get("password_count") for item in auth] != [0]
    ):
        raise ContractError(message)


def _require_exact_state_sg_rule(
    values: dict[str, Any],
    address: str,
    *,
    description: str,
    port: int,
    security_group_id: str,
    referenced_security_group_id: str | None = None,
    prefix_list_id: str | None = None,
) -> None:
    """Require one persisted standalone rule with no CIDR escape hatch."""
    rule = values[address]
    if (
        rule.get("description") != description
        or rule.get("from_port") != port
        or rule.get("to_port") != port
        or rule.get("ip_protocol") != "tcp"
        or rule.get("security_group_id") != security_group_id
        or rule.get("cidr_ipv4") not in (None, "")
        or rule.get("cidr_ipv6") not in (None, "")
        or rule.get("referenced_security_group_id") != referenced_security_group_id
        or rule.get("prefix_list_id") != prefix_list_id
    ):
        raise ContractError(f"{address} is not the exact reviewed standalone SG rule")


def check_state(state: Any) -> dict[str, Any]:
    # Accept both `terraform show -json` state and plan shapes so this contract
    # remains reusable for direct state evidence as well as refreshed plans.
    values_root = state.get("values") if isinstance(state, dict) else None
    prior_state = state.get("prior_state") if isinstance(state, dict) else None
    if not isinstance(values_root, dict) and isinstance(prior_state, dict):
        values_root = prior_state.get("values")
    root = values_root.get("root_module") if isinstance(values_root, dict) else None
    resources = [
        item for item in _iter_resources(root) if item.get("mode") == "managed"
    ]
    by_address = {item.get("address"): item for item in resources}
    if len(by_address) != len(resources):
        raise ContractError("refreshed state contains duplicate managed addresses")
    catalog_extra = set(PROVISIONED_CELL_RESOURCES)
    base_expected = set(EXPECTED_RESOURCES) - catalog_extra
    runtime_extra = set(AUTHORITY_RUNTIME_RESOURCES)
    proof_extra = set(AUTHORITY_PROOF_RESOURCES)
    proof_rollout_extra = set(AUTHORITY_PROOF_ROLLOUT_RESOURCES)
    hub_edge_extra = set(HUB_EDGE_RESOURCES)
    hub_worker_extra = set(HUB_WORKER_RESOURCES)
    actual_addresses = set(by_address)
    catalog_present = bool(actual_addresses & catalog_extra)
    runtime_present = bool(actual_addresses & runtime_extra)
    proof_present = bool(actual_addresses & proof_extra)
    proof_rollout_present = bool(actual_addresses & proof_rollout_extra)
    hub_edge_present = bool(actual_addresses & hub_edge_extra)
    hub_worker_present = bool(actual_addresses & hub_worker_extra)
    if proof_present and not runtime_present:
        raise ContractError(
            "attended-proof Authority slice requires the complete runtime slice "
            "in refreshed state"
        )
    if proof_rollout_present and not (
        proof_present and runtime_present and hub_worker_present
    ):
        raise ContractError(
            "proof-policy rollout state requires the complete runtime, "
            "attended-proof, and Hub worker slices"
        )
    if hub_worker_present and not (hub_edge_present and runtime_present):
        raise ContractError(
            "Hub worker slice requires both the Hub edge slice and the authority "
            "runtime slice in refreshed state"
        )
    state_expected = (
        base_expected
        | (catalog_extra if catalog_present else set())
        | (runtime_extra if runtime_present else set())
        | (proof_extra if proof_present else set())
        | (proof_rollout_extra if proof_rollout_present else set())
        | (hub_edge_extra if hub_edge_present else set())
        | (hub_worker_extra if hub_worker_present else set())
    )
    if actual_addresses != state_expected:
        missing = sorted(state_expected - actual_addresses)
        extra = sorted(actual_addresses - state_expected)
        raise ContractError(
            f"refreshed state inventory mismatch; missing={missing}, extra={extra}"
        )
    state_expected_resources = {
        address: resource_type
        for address, resource_type in EXPECTED_RESOURCES.items()
        if address not in catalog_extra
    }
    if catalog_present:
        state_expected_resources.update(PROVISIONED_CELL_RESOURCES)
    if runtime_present:
        state_expected_resources.update(AUTHORITY_RUNTIME_RESOURCES)
    if proof_present:
        state_expected_resources.update(AUTHORITY_PROOF_RESOURCES)
    if proof_rollout_present:
        state_expected_resources.update(AUTHORITY_PROOF_ROLLOUT_RESOURCES)
    if hub_edge_present:
        state_expected_resources.update(HUB_EDGE_RESOURCES)
    if hub_worker_present:
        state_expected_resources.update(HUB_WORKER_RESOURCES)
    for address, expected_type in state_expected_resources.items():
        resource = by_address[address]
        if resource.get("mode") != "managed" or resource.get("type") != expected_type:
            raise ContractError(f"refreshed state mode/type mismatch for {address}")
        if not isinstance(resource.get("values"), dict):
            raise ContractError(f"refreshed state values missing for {address}")

    values = {address: item["values"] for address, item in by_address.items()}
    foundation = values["module.control.terraform_data.foundation_contract"]
    if not _require_authority_runtime_binding(
        foundation, proof_enabled=proof_present
    ):
        raise ContractError("refreshed state is missing the Authority runtime binding")
    if catalog_present:
        for address in PROVISIONED_CELL_RESOURCES:
            _require_provisioned_cell_values(
                values[address],
                {},
                address,
                create=False,
            )
    outputs = values_root.get("outputs")
    authority_image_output = (
        outputs.get("authority_image_uri") if isinstance(outputs, dict) else None
    )
    if (
        not _is_exact_nonsensitive_output_entry(authority_image_output)
        or authority_image_output.get("value")
        != foundation["input"]["authority_image_uri"]
    ):
        raise ContractError("refreshed state Authority image URI output is not exact")
    catalog_output = (
        outputs.get("provisioned_cells") if isinstance(outputs, dict) else None
    )
    expected_catalog = PROVISIONED_CELL_CATALOG if catalog_present else {}
    if not _is_exact_nonsensitive_output_entry(catalog_output):
        raise ContractError(
            "refreshed state provisioned-cell catalog output is not exact"
        )
    # Admit the optional resolved general_assignable Boolean per cell (absent ⇒
    # true) and pin every other projected field exactly, mirroring the plan-time
    # output inventory. A refreshed output with no general_assignable at all is
    # the pre-B6 shape and still matches unchanged.
    if _strip_general_assignable_output(catalog_output.get("value")) != expected_catalog:
        raise ContractError(
            "refreshed state provisioned-cell catalog output is not exact"
        )
    selected_colors = _authority_proof_selected_colors(foundation)
    for function_name, output_name in AUTHORITY_PROOF_ALIAS_OUTPUTS.items():
        proof_alias_output = (
            outputs.get(output_name) if isinstance(outputs, dict) else None
        )
        expected_proof_alias = (
            f"arn:aws:lambda:{AWS_REGION}:{ACCOUNT_ID}:function:"
            f"{function_name}:{selected_colors[function_name]}"
        )
        if proof_present:
            if (
                not _is_exact_nonsensitive_output_entry(proof_alias_output)
                or proof_alias_output.get("value") != expected_proof_alias
            ):
                raise ContractError(
                    f"refreshed state attended-proof output {output_name} is not exact"
                )
        elif proof_alias_output is not None and (
            not _is_exact_nonsensitive_output_entry(proof_alias_output)
            or proof_alias_output.get("value") is not None
        ):
            raise ContractError(
                f"dark refreshed state proof output {output_name} must be omitted or null"
            )
    vpc_id = values["module.control.aws_vpc.control"].get("id")
    if (
        not re.fullmatch(r"vpc-[0-9a-f]+", str(vpc_id))
        or values["module.control.aws_vpc.control"].get("cidr_block") != "10.102.0.0/16"
    ):
        raise ContractError("Control VPC identity/CIDR is invalid")

    runtime_function_sg_id: str | None = None
    if runtime_present:
        function_sg = values[AUTHORITY_RUNTIME_LAMBDA_SG_ADDRESS]
        function_sg_id = function_sg.get("id")
        interface_sg_id = values[AUTHORITY_RUNTIME_INTERFACE_SG_ADDRESS].get("id")
        otp_redis_sg_id = values["module.control.aws_security_group.otp_redis"].get(
            "id"
        )
        dynamodb_prefix_list_id = values[AUTHORITY_RUNTIME_DYNAMODB_ADDRESS].get(
            "prefix_list_id"
        )
        for label, identifier in (
            ("function", function_sg_id),
            ("interface-endpoint", interface_sg_id),
            ("OTP Redis", otp_redis_sg_id),
        ):
            if (
                not isinstance(identifier, str)
                or re.fullmatch(r"sg-[0-9a-f]+", identifier) is None
            ):
                raise ContractError(f"{label} SG identity is invalid")
        if (
            not isinstance(dynamodb_prefix_list_id, str)
            or re.fullmatch(r"pl-[0-9a-f]+", dynamodb_prefix_list_id) is None
        ):
            raise ContractError("DynamoDB endpoint prefix-list identity is invalid")
        if (
            function_sg.get("name_prefix") != f"{CONTROL_PREFIX}-ca-fn-v2-"
            or function_sg.get("description")
            != (
                "Connector Authority function ENIs; egress to Control dependency "
                "endpoints only"
            )
            or function_sg.get("vpc_id") != vpc_id
            # `ingress` stays empty in every state: nothing dials the functions
            # on the network path. `egress` deliberately is NOT asserted empty
            # here -- this reads REFRESHED state, where the Optional+Computed
            # attribute reflects the standalone egress rules AWS holds. Those
            # three rules are pinned exactly by the _require_exact_state_sg_rule
            # calls immediately below, which is the stronger assertion; an empty
            # egress here would contradict them.
            or function_sg.get("ingress") not in ([], None)
        ):
            raise ContractError(
                "Authority function SG must be generation 2, in the Control VPC, "
                "and carry no inline ingress"
            )
        # The reflected egress is whatever the standalone rules put in AWS. Each
        # of those three is pinned exactly by _require_exact_state_sg_rule below,
        # but assert the SHAPE here as well so an inline CIDR- or self-reachable
        # rule can never masquerade as a reflected standalone rule: the lawful
        # ones are SG-referenced (interface endpoints, OTP Redis) or prefix-list
        # scoped (DynamoDB gateway), never raw CIDR.
        function_sg_egress = function_sg.get("egress")
        if function_sg_egress not in (None, []):
            if not isinstance(function_sg_egress, list):
                raise ContractError(
                    "Authority function SG egress must be a rule collection"
                )
            for rule in function_sg_egress:
                if not isinstance(rule, dict):
                    raise ContractError(
                        "Authority function SG egress rule is malformed"
                    )
                if (
                    rule.get("cidr_blocks") not in (None, [])
                    or rule.get("ipv6_cidr_blocks") not in (None, [])
                    or rule.get("self") not in (None, False)
                ):
                    raise ContractError(
                        "Authority function SG egress must be SG- or "
                        "prefix-list-scoped, never CIDR/self reachable"
                    )
        runtime_function_sg_id = function_sg_id
        _require_exact_state_sg_rule(
            values,
            "module.control.aws_vpc_security_group_egress_rule."
            "authority_interface_endpoints[0]",
            description="HTTPS to Control interface endpoints",
            port=443,
            security_group_id=function_sg_id,
            referenced_security_group_id=interface_sg_id,
        )
        _require_exact_state_sg_rule(
            values,
            "module.control.aws_vpc_security_group_egress_rule."
            "authority_dynamodb[0]",
            description="HTTPS to the DynamoDB gateway endpoint",
            port=443,
            security_group_id=function_sg_id,
            prefix_list_id=dynamodb_prefix_list_id,
        )
        _require_exact_state_sg_rule(
            values,
            "module.control.aws_vpc_security_group_egress_rule."
            "authority_otp_redis[0]",
            description="TLS to Connector OTP Redis",
            port=6379,
            security_group_id=function_sg_id,
            referenced_security_group_id=otp_redis_sg_id,
        )
        _require_exact_state_sg_rule(
            values,
            "module.control.aws_vpc_security_group_ingress_rule."
            "otp_redis_authority[0]",
            description="TLS from Connector Authority OTP functions",
            port=6379,
            security_group_id=otp_redis_sg_id,
            referenced_security_group_id=function_sg_id,
        )

    for address in (
        "module.control.aws_default_security_group.control",
        "module.control.aws_security_group.interface_endpoints",
        "module.control.aws_security_group.otp_redis",
    ):
        item = values[address]
        # The interface-endpoint SG carries exactly one TLS/443 SG-scoped ingress
        # per live caller slice: the runtime function SG, plus -- once the Hub
        # worker slice is live -- the Hub worker SG. The OTP Redis SG carries the
        # one TLS/6379 rule the runtime slice attaches. The default SG stays
        # closed. Egress stays empty on all three.
        if (
            runtime_present or hub_worker_present
        ) and address == AUTHORITY_RUNTIME_INTERFACE_SG_ADDRESS:
            ingress = item.get("ingress")
            if item.get("egress") not in ([], None):
                raise ContractError(f"interface-endpoint SG has egress rules: {address}")
            expected_sources: dict[str, str] = {}
            if runtime_present:
                assert runtime_function_sg_id is not None
                expected_sources["HTTPS from Connector Authority function ENIs"] = (
                    runtime_function_sg_id
                )
            if hub_worker_present:
                hub_worker_sg_id = values[
                    "module.control.aws_security_group.hub_worker[0]"
                ].get("id")
                if (
                    not isinstance(hub_worker_sg_id, str)
                    or re.fullmatch(r"sg-[0-9a-f]+", hub_worker_sg_id) is None
                ):
                    raise ContractError("Hub worker SG identity is invalid")
                expected_sources["HTTPS from Hub worker ENIs"] = hub_worker_sg_id
            if not isinstance(ingress, list) or len(ingress) != len(expected_sources):
                raise ContractError(
                    "interface-endpoint SG must carry exactly "
                    f"{len(expected_sources)} TLS/443 ingress rule(s): {address}"
                )
            by_description = {
                rule.get("description"): rule
                for rule in ingress
                if isinstance(rule, dict)
            }
            if set(by_description) != set(expected_sources):
                raise ContractError(
                    f"interface-endpoint SG ingress identities drifted: {address}"
                )
            for description, expected_source in expected_sources.items():
                rule = by_description[description]
                if (
                    rule.get("from_port") != 443
                    or rule.get("to_port") != 443
                    or rule.get("protocol") != "tcp"
                    or rule.get("cidr_blocks") not in (None, [])
                    or rule.get("ipv6_cidr_blocks") not in (None, [])
                    or rule.get("prefix_list_ids") not in (None, [])
                    or rule.get("self") not in (None, False)
                    or rule.get("security_groups") != [expected_source]
                ):
                    raise ContractError(
                        "interface-endpoint SG ingress is not exactly TLS/443 from "
                        f"one caller SG: {address}"
                    )
            continue
        if address == "module.control.aws_security_group.otp_redis":
            # Not dark once the runtime slice lands: it carries exactly the one
            # standalone SG-to-SG TLS/6379 rule the slice attaches, which this
            # same function pins exactly via _require_exact_state_sg_rule. This
            # reads REFRESHED state, so demanding an empty ingress here both
            # contradicted that rule check and rejected every post-slice state.
            if item.get("egress") not in ([], None):
                raise ContractError(f"dark security group has egress rules: {address}")
            _check_otp_redis_ingress(item, {}, address)
            continue
        if item.get("ingress") not in ([], None) or item.get("egress") not in (
            [],
            None,
        ):
            raise ContractError(f"dark security group has traffic rules: {address}")

    data_key = values["module.control.aws_kms_key.authority_data"]
    signer = values["module.control.aws_kms_key.qat1_signing"]
    if (
        data_key.get("key_usage") != "ENCRYPT_DECRYPT"
        or data_key.get("is_enabled") is not True
    ):
        raise ContractError("authority data KMS key is not enabled ENCRYPT_DECRYPT")
    if (
        signer.get("key_usage") != "SIGN_VERIFY"
        or signer.get("customer_master_key_spec") != "ECC_NIST_P256"
        or signer.get("is_enabled") is not True
    ):
        raise ContractError("qat1 KMS signer is not enabled P-256 SIGN_VERIFY")

    flow = values["module.control.aws_flow_log.control"]
    log_group = values["module.control.aws_cloudwatch_log_group.flow_logs"]
    if log_group.get("kms_key_id") != data_key.get("arn"):
        raise ContractError(
            "Control Flow Log group is not encrypted by authority data KMS"
        )
    if (
        flow.get("traffic_type") != "ALL"
        or flow.get("max_aggregation_interval") != 60
        or flow.get("log_destination_type") != "cloud-watch-logs"
        or flow.get("log_destination") != log_group.get("arn")
        or flow.get("iam_role_arn")
        != values["module.control.aws_iam_role.flow_logs"].get("arn")
    ):
        raise ContractError("Control Flow Log state contract drifted")

    publisher_role = values["module.control.aws_iam_role.authority_publisher"]
    publisher_policy = values[
        "module.control.aws_iam_role_policy.authority_publisher"
    ]
    _require_authority_publisher_identity(
        publisher_role,
        publisher_policy,
        reflected_inline_policy=True,
    )
    if publisher_policy.get("role") != AUTHORITY_PUBLISHER_ROLE_NAME:
        raise ContractError("authority publisher inline policy identity drifted")

    hub_repository = values["module.control.aws_ecr_repository.hub"]
    if (
        hub_repository.get("arn") != HUB_ECR_REPOSITORY_ARN
        or hub_repository.get("name") != HUB_ECR_REPOSITORY_NAME
        or hub_repository.get("force_delete") is not False
        or hub_repository.get("image_tag_mutability") != "IMMUTABLE"
        or hub_repository.get("image_scanning_configuration")
        != [{"scan_on_push": True}]
        or hub_repository.get("encryption_configuration")
        != [{"encryption_type": "KMS", "kms_key": data_key.get("arn")}]
    ):
        raise ContractError("Hub ECR repository security contract drifted")
    hub_lifecycle = values["module.control.aws_ecr_lifecycle_policy.hub"]
    if (
        hub_lifecycle.get("repository") != HUB_ECR_REPOSITORY_NAME
        or not isinstance(hub_lifecycle.get("policy"), str)
    ):
        raise ContractError("Hub ECR lifecycle identity drifted")
    try:
        hub_lifecycle_policy = json.loads(hub_lifecycle["policy"])
    except json.JSONDecodeError as exc:
        raise ContractError("Hub ECR lifecycle policy is malformed") from exc
    if hub_lifecycle_policy != HUB_ECR_LIFECYCLE_POLICY:
        raise ContractError("Hub ECR lifecycle policy drifted")

    hub_digest = values["module.control.aws_ssm_parameter.hub_image_digest"]
    hub_digest_value = hub_digest.get("value")
    if (
        hub_digest.get("arn") != HUB_IMAGE_DIGEST_PARAMETER_ARN
        or hub_digest.get("name") != HUB_IMAGE_DIGEST_PARAMETER_NAME
        or hub_digest.get("data_type") != "text"
        or hub_digest.get("description") != _HUB_DIGEST_SPEC["description"]
        or hub_digest.get("tier") != "Standard"
        or hub_digest.get("type") != "String"
        or (
            hub_digest_value != "UNPUBLISHED"
            and (
                not isinstance(hub_digest_value, str)
                or _DIGEST_PATTERN.fullmatch(hub_digest_value) is None
            )
        )
    ):
        raise ContractError("Hub image digest parameter contract drifted")

    hub_publisher_role = values["module.control.aws_iam_role.hub_publisher"]
    hub_publisher_policy = values[
        "module.control.aws_iam_role_policy.hub_publisher"
    ]
    _require_hub_publisher_identity(
        hub_publisher_role,
        hub_publisher_policy,
        reflected_inline_policy=True,
    )
    if hub_publisher_policy.get("role") != HUB_PUBLISHER_ROLE_NAME:
        raise ContractError("Hub publisher inline policy identity drifted")

    interface_sg = values["module.control.aws_security_group.interface_endpoints"].get(
        "id"
    )
    subnet_ids = {
        values[f"module.control.aws_subnet.isolated[{index}]"].get("id")
        for index in range(3)
    }
    route_table_ids = {
        values[f"module.control.aws_route_table.isolated[{index}]"].get("id")
        for index in range(3)
    }
    deny_policy = DENY_ENDPOINT_POLICY
    for service in INTERFACE_ENDPOINT_SERVICES:
        address = f'module.control.aws_vpc_endpoint.interface["{service}"]'
        item = values[address]
        if (
            item.get("state") != "available"
            or item.get("vpc_endpoint_type") != "Interface"
            or item.get("service_name") != f"com.amazonaws.{AWS_REGION}.{service}"
            or item.get("private_dns_enabled") is not True
            or item.get("vpc_id") != vpc_id
            or set(item.get("subnet_ids", [])) != subnet_ids
            or set(item.get("security_group_ids", [])) != {interface_sg}
        ):
            raise ContractError(
                f"dark interface endpoint contract failed for {service}"
            )
        # Only the KMS interface endpoint opens (to the execution roles) once the
        # runtime slice is live, and the lambda interface endpoint opens (to the
        # worker task role) once the Hub worker slice is live; every other
        # interface endpoint stays deny-all.
        if runtime_present and service == "kms":
            _check_authority_kms_endpoint_policy(item, address)
        elif runtime_present and service == "secretsmanager":
            _check_authority_secrets_endpoint_policy(
                item, address, hub_worker_mode=hub_worker_present
            )
        elif runtime_present and service == "email":
            _check_authority_email_endpoint_policy(item, address)
        elif hub_worker_present and service == "lambda":
            _check_hub_lambda_endpoint_policy(
                item,
                address,
                rollout=proof_rollout_present,
                selected=_selected_authority_color_from_contract(
                    foundation.get("input")
                ),
            )
        elif hub_worker_present and not runtime_present and service == "secretsmanager":
            _check_hub_secretsmanager_endpoint_policy(item, address)
        elif hub_worker_present and service == "logs":
            _check_hub_logs_endpoint_policy(item, address)
        elif hub_worker_present and service == "monitoring":
            _check_hub_monitoring_endpoint_policy(item, address)
        elif json.loads(item.get("policy", "{}")) != deny_policy:
            raise ContractError(
                f"dark interface endpoint contract failed for {service}"
            )
    dynamodb = values["module.control.aws_vpc_endpoint.dynamodb"]
    if (
        dynamodb.get("state") != "available"
        or dynamodb.get("vpc_endpoint_type") != "Gateway"
        or dynamodb.get("service_name") != f"com.amazonaws.{AWS_REGION}.dynamodb"
        or dynamodb.get("vpc_id") != vpc_id
        or set(dynamodb.get("route_table_ids", [])) != route_table_ids
    ):
        raise ContractError("dark DynamoDB endpoint contract failed")
    if runtime_present:
        _check_authority_dynamodb_endpoint_policy(
            dynamodb,
            "module.control.aws_vpc_endpoint.dynamodb",
            proof_enabled=proof_present,
        )
    elif json.loads(dynamodb.get("policy", "{}")) != deny_policy:
        raise ContractError("dark DynamoDB endpoint contract failed")

    # The Hub worker slice's three image-pull endpoints exist only when the worker
    # is live (the inventory admission gates that). The two ECR interface
    # endpoints share the interface-endpoints SG and isolated subnets; the S3
    # gateway attaches to the isolated route tables. Each opens ONLY to the Hub
    # execution role for the exact pull actions.
    if hub_worker_present:
        for hub_address, hub_service, hub_type in (
            ("module.control.aws_vpc_endpoint.hub_ecr_api[0]", "ecr.api", "Interface"),
            ("module.control.aws_vpc_endpoint.hub_ecr_dkr[0]", "ecr.dkr", "Interface"),
            ("module.control.aws_vpc_endpoint.hub_s3[0]", "s3", "Gateway"),
        ):
            hub_item = values[hub_address]
            if (
                hub_item.get("state") != "available"
                or hub_item.get("vpc_endpoint_type") != hub_type
                or hub_item.get("service_name")
                != f"com.amazonaws.{AWS_REGION}.{hub_service}"
                or hub_item.get("vpc_id") != vpc_id
            ):
                raise ContractError(f"Hub {hub_service} endpoint contract failed")
            if hub_type == "Interface":
                if (
                    hub_item.get("private_dns_enabled") is not True
                    or set(hub_item.get("subnet_ids", [])) != subnet_ids
                    or set(hub_item.get("security_group_ids", [])) != {interface_sg}
                ):
                    raise ContractError(
                        f"Hub {hub_service} interface endpoint contract failed"
                    )
                _check_hub_ecr_endpoint_policy(hub_item, hub_address)
            else:
                if set(hub_item.get("route_table_ids", [])) != route_table_ids:
                    raise ContractError(
                        f"Hub {hub_service} gateway endpoint route tables drifted"
                    )
                _check_hub_s3_endpoint_policy(hub_item, hub_address)

    cache = values["module.control.aws_elasticache_serverless_cache.otp"]
    if (
        cache.get("status") != "available"
        or cache.get("engine") != "redis"
        or cache.get("major_engine_version") != "7"
        or cache.get("user_group_id") != f"{CONTROL_PREFIX}-otp-users"
        or cache.get("kms_key_id") != data_key.get("arn")
        or cache.get("snapshot_retention_limit") != 0
        or set(cache.get("security_group_ids", []))
        != {values["module.control.aws_security_group.otp_redis"].get("id")}
        or set(cache.get("subnet_ids", [])) != subnet_ids
    ):
        raise ContractError("OTP Redis cache contract failed")
    activator = values["module.control.aws_elasticache_user.otp_activator"]
    disabled = values["module.control.aws_elasticache_user.otp_disabled_default"]
    issuer = values["module.control.aws_elasticache_user.otp_issuer"]
    group = values["module.control.aws_elasticache_user_group.otp"]
    disabled_auth = disabled.get("authentication_mode", [])
    if (
        disabled.get("user_name") != "default"
        or disabled.get("access_string") != "off ~* -@all"
        or [item.get("type") for item in disabled_auth] != ["no-password"]
        or [item.get("password_count") for item in disabled_auth] != [0]
    ):
        raise ContractError("Redis default user is not disabled")
    _require_iam_redis_user(
        issuer,
        f"{CONTROL_PREFIX}-otp-issuer",
        OTP_REDIS_ISSUER_ACCESS,
        "Redis issuer ACL drifted",
    )
    _require_iam_redis_user(
        activator,
        f"{CONTROL_PREFIX}-otp-activator",
        OTP_REDIS_ACTIVATOR_ACCESS,
        "Redis activator ACL drifted",
    )
    group_users = group.get("user_ids")
    if (
        group.get("user_group_id") != f"{CONTROL_PREFIX}-otp-users"
        or not isinstance(group_users, list)
        or len(group_users) != 3
        or set(group_users)
        != {
            disabled.get("user_id"),
            issuer.get("user_id"),
            activator.get("user_id"),
        }
    ):
        raise ContractError("Redis user-group membership drifted")

    return {"resource_count": len(resources), "vpc_id": vpc_id}


def check_live(
    evidence_dir: Path, *, pre_apply: bool = False
) -> dict[str, Any]:
    """Prove the live Control boundary.

    ``pre_apply`` asserts INVARIANTS ONLY for anything a reviewed apply is
    allowed to change. Asserting a transition TARGET before the apply makes the
    apply that produces it unreachable, and that is structural rather than bad
    luck: it deadlocked the 62206 -> 443 port migration, and again when the Hub
    edge source opened. The target is asserted post-apply, where it exists, and
    the exact rule change is separately reviewed by the plan gate.
    """
    expected = load_json(evidence_dir / "expected-live.json")
    required_expected = {
        "dynamodb_endpoint_id",
        "flow_log_destination",
        "flow_log_id",
        "flow_log_role_arn",
        "isolated_route_table_ids",
        # The Hub worker slice's S3 gateway endpoint id. ALWAYS present in the
        # manifest for exact-set equality; null while the worker is dark (the
        # evidence generator emits null when the endpoint is absent from state).
        "s3_endpoint_id",
        "vpc_id",
    }
    if not isinstance(expected, dict) or set(expected) != required_expected:
        raise ContractError("live expected-ID manifest is not exact")
    vpc_id = expected["vpc_id"]
    if not re.fullmatch(r"vpc-[0-9a-f]+", str(vpc_id)):
        raise ContractError("live VPC ID is malformed")
    isolated = set(expected["isolated_route_table_ids"])
    if len(isolated) != 3 or not all(
        re.fullmatch(r"rtb-[0-9a-f]+", str(value)) for value in isolated
    ):
        raise ContractError("live isolated route-table IDs are malformed")
    # The S3 gateway endpoint (Hub worker slice) injects one prefix-list route
    # into EACH isolated route table. Its id is null while the worker is dark; a
    # vpce-id once live. s3_present toggles the isolated-table route accounting
    # below from local+DynamoDB (2) to local+DynamoDB+S3 (3).
    s3_endpoint_id = expected["s3_endpoint_id"]
    s3_present = s3_endpoint_id is not None
    if s3_present and not re.fullmatch(r"vpce-[0-9a-f]+", str(s3_endpoint_id)):
        raise ContractError("live S3 gateway endpoint ID is malformed")

    route_tables = load_json(evidence_dir / "route-tables.json").get("RouteTables")
    if not isinstance(route_tables, list):
        raise ContractError("Control VPC route tables evidence is malformed")
    by_id = {item.get("RouteTableId"): item for item in route_tables}
    if not isolated.issubset(by_id):
        raise ContractError("isolated route tables are absent from live VPC")
    main = [
        item
        for item in route_tables
        if any(
            association.get("Main") is True
            for association in item.get("Associations", [])
        )
    ]
    if len(main) != 1 or main[0].get("RouteTableId") in isolated:
        raise ContractError("Control VPC main route table is not singular/unmanaged")
    main_id = main[0].get("RouteTableId")

    # The Hub public edge (Step 5) adds ONE public route table tagged
    # Type=public-edge -- the only table permitted an internet route. Every live
    # table must be one of: the three isolated workload tables, the single
    # unmanaged main table, or a tagged public-edge table. Anything else fails
    # closed, so a hidden internet route cannot hide in an untagged table.
    def _route_table_type(route_table: dict[str, Any]) -> str | None:
        for tag in route_table.get("Tags", []):
            if tag.get("Key") == "Type":
                return tag.get("Value")
        return None

    public_edge_ids = {
        route_table_id
        for route_table_id, route_table in by_id.items()
        if route_table_id not in isolated
        and route_table_id != main_id
        and _route_table_type(route_table) == "public-edge"
    }
    unexpected = set(by_id) - isolated - {main_id} - public_edge_ids
    if unexpected:
        raise ContractError(
            f"Control VPC has unexpected route tables: {sorted(unexpected)}"
        )
    if len(route_tables) != 4 + len(public_edge_ids):
        raise ContractError(
            "Control VPC route-table count is not isolated(3)+main(1)+public-edge"
        )
    for route_table_id, route_table in by_id.items():
        routes = route_table.get("Routes")
        if not isinstance(routes, list):
            raise ContractError(f"live routes missing for {route_table_id}")
        local_routes = [
            route
            for route in routes
            if route.get("GatewayId") == "local"
            and route.get("DestinationCidrBlock") == "10.102.0.0/16"
            and route.get("State") == "active"
        ]
        if route_table_id in public_edge_ids:
            # The public edge table: exactly the local route plus ONE default
            # route to an internet gateway. The internet route lives here and
            # ONLY here; the isolated/main tables are proven internet-free by the
            # else-branch below.
            internet_routes = [
                route
                for route in routes
                if re.fullmatch(r"igw-[0-9a-f]+", str(route.get("GatewayId", "")))
                and route.get("DestinationCidrBlock") == "0.0.0.0/0"
                and route.get("State") == "active"
            ]
            allowed = [*local_routes, *internet_routes]
            if len(local_routes) != 1 or len(internet_routes) != 1:
                raise ContractError(
                    f"public edge route ownership drifted for {route_table_id}"
                )
        else:
            dynamodb_routes = [
                route
                for route in routes
                if route.get("GatewayId") == expected["dynamodb_endpoint_id"]
                and re.fullmatch(
                    r"pl-[0-9a-f]+", str(route.get("DestinationPrefixListId", ""))
                )
                and route.get("State") == "active"
            ]
            # The S3 gateway route lives ONLY on the isolated tables (the endpoint
            # attaches to aws_route_table.isolated[*]), exactly like DynamoDB, and
            # ONLY once the Hub worker slice is live.
            s3_routes = (
                [
                    route
                    for route in routes
                    if route.get("GatewayId") == s3_endpoint_id
                    and re.fullmatch(
                        r"pl-[0-9a-f]+", str(route.get("DestinationPrefixListId", ""))
                    )
                    and route.get("State") == "active"
                ]
                if s3_present and route_table_id in isolated
                else []
            )
            allowed = [*local_routes, *dynamodb_routes, *s3_routes]
            dynamodb_expected = 1 if route_table_id in isolated else 0
            s3_expected = 1 if (s3_present and route_table_id in isolated) else 0
            if (
                len(local_routes) != 1
                or len(dynamodb_routes) != dynamodb_expected
                or len(s3_routes) != s3_expected
            ):
                raise ContractError(
                    f"live route ownership drifted for {route_table_id}"
                )
        if len(routes) != len(allowed):
            raise ContractError(
                f"live route table has an internet/remote route: {route_table_id}"
            )

    # The Hub public edge attaches exactly one internet gateway; while dark there
    # is none. Egress-only IGW, peering, and transit-gateway attachments stay
    # empty regardless -- the workers never egress to the internet.
    internet_gateways = load_json(evidence_dir / "internet-gateways.json").get(
        "InternetGateways"
    )
    igw_expected = 1 if public_edge_ids else 0
    if (
        not isinstance(internet_gateways, list)
        or len(internet_gateways) != igw_expected
    ):
        raise ContractError(
            f"Control VPC internet gateway count must be {igw_expected}"
        )
    empty_arrays = {
        "egress-only-internet-gateways.json": "EgressOnlyInternetGateways",
        "vpc-peerings.json": "VpcPeeringConnections",
        "transit-gateway-attachments.json": "TransitGatewayAttachments",
    }
    for filename, key in empty_arrays.items():
        value = load_json(evidence_dir / filename).get(key)
        if value != []:
            raise ContractError(
                f"Control VPC has forbidden live resources in {filename}"
            )
    nat_gateways = load_json(evidence_dir / "nat-gateways.json").get("NatGateways")
    if not isinstance(nat_gateways, list) or any(
        item.get("State") != "deleted" for item in nat_gateways
    ):
        raise ContractError("Control VPC has a nondeleted NAT gateway")

    flows = load_json(evidence_dir / "flow-logs.json").get("FlowLogs")
    if not isinstance(flows, list) or len(flows) != 1:
        raise ContractError("Control VPC must have exactly one Flow Log")
    flow = flows[0]
    if (
        flow.get("FlowLogId") != expected["flow_log_id"]
        or flow.get("FlowLogStatus") != "ACTIVE"
        or flow.get("DeliverLogsStatus") != "SUCCESS"
        or flow.get("DeliverLogsErrorMessage") not in (None, "")
        or flow.get("TrafficType") != "ALL"
        or flow.get("MaxAggregationInterval") != 60
        or flow.get("LogDestinationType") != "cloud-watch-logs"
        or flow.get("LogDestination") != expected["flow_log_destination"]
        or flow.get("DeliverLogsPermissionArn") != expected["flow_log_role_arn"]
    ):
        raise ContractError("Control Flow Log live delivery contract failed")

    state_head = load_json(evidence_dir / "state-head.json")
    if (
        state_head.get("ServerSideEncryption") != "aws:kms"
        or state_head.get("SSEKMSKeyId") != STATE_KMS_KEY_ARN
        or not isinstance(state_head.get("VersionId"), str)
        or not state_head["VersionId"]
        or state_head["VersionId"] == "null"
    ):
        raise ContractError(
            "Control state object is not versioned under the exact KMS key"
        )

    # The Control/authority prefixes own no Lambda while dark; exactly the 11
    # complete functions once the runtime slice is live; and additionally the
    # Hub keygen function once the Hub worker slice (5b) is live (the keygen only
    # appears alongside the runtime). Any other function set fails closed.
    # `control-lambdas.json` is the reviewed `aws lambda list-functions`
    # projection (function objects filtered to the control and layerv-nhp-<env>-ca-
    # prefixes).
    live_lambdas = load_json(evidence_dir / "control-lambdas.json")
    if not isinstance(live_lambdas, list):
        raise ContractError("Control Lambda inventory evidence is malformed")
    live_lambda_names: set[str] = set()
    for item in live_lambdas:
        name = item.get("FunctionName") if isinstance(item, dict) else None
        if not isinstance(name, str):
            raise ContractError("Control Lambda inventory evidence is malformed")
        live_lambda_names.add(name)
    # This proof runs BEFORE the apply, so it must admit the predecessor state as
    # well as the successor. The complete graph is the 11 functions, but the
    # legacy Hub-only trio is exactly what is live until the expansion applies;
    # accepting only the 11 makes that expansion unappliable, because the gate
    # demands the very functions the apply is about to create. Both sets are
    # named constants and each is matched whole, so this admits two exact live
    # shapes rather than relaxing the check to a subset or prefix test.
    complete_authority_functions = set(AUTHORITY_RUNTIME_FUNCTIONS)
    proof_authority_functions = set(AUTHORITY_RUNTIME_FUNCTIONS_WITH_PROOF)
    legacy_authority_functions = set(AUTHORITY_RUNTIME_HUB_FUNCTIONS)
    if live_lambda_names not in (
        set(),
        legacy_authority_functions,
        legacy_authority_functions | {HUB_KEYGEN_FUNCTION_NAME},
        complete_authority_functions,
        complete_authority_functions | {HUB_KEYGEN_FUNCTION_NAME},
        proof_authority_functions,
        proof_authority_functions | {HUB_KEYGEN_FUNCTION_NAME},
    ):
        raise ContractError(
            "Control prefix owns an unexpected Lambda function set; only the exact "
            "3 legacy Hub-facing Authority functions, the exact 11 complete "
            "Authority functions, or the exact 12-function attended-proof graph "
            "(each optionally plus the Hub keygen once the worker slice is live) "
            "are admitted"
        )
    # The Hub public UDP edge (slice 5a) is the authority's only load balancer,
    # and it exists in lockstep with the tagged public-edge route table proven
    # above: while the edge is dark (no public-edge table) the Control/authority
    # prefixes own no load balancer; once it is live they own EXACTLY the one
    # internet-facing network NLB fronting the Hub workers, in the Control VPC.
    # `control-load-balancers.json` is the reviewed `aws elbv2
    # describe-load-balancers` projection filtered to the control and
    # layerv-nhp-<env>-ca- prefixes. Any other shape fails closed.
    live_load_balancers = load_json(evidence_dir / "control-load-balancers.json")
    if not isinstance(live_load_balancers, list):
        raise ContractError("Control load-balancer inventory evidence is malformed")
    if not public_edge_ids:
        if live_load_balancers != []:
            raise ContractError(
                "Control prefix owns a load balancer while the public edge is dark"
            )
    else:
        if len(live_load_balancers) != 1:
            raise ContractError(
                "Control prefix owns an unexpected load-balancer set; only the "
                "single Hub public UDP edge NLB is admitted"
            )
        hub_lb = live_load_balancers[0]
        if not isinstance(hub_lb, dict):
            raise ContractError("Control load-balancer evidence is malformed")
        if (
            hub_lb.get("LoadBalancerName")
            not in HUB_EDGE_REVIEWED_LOAD_BALANCER_NAMES
            or hub_lb.get("Type") != "network"
            or hub_lb.get("Scheme") != "internet-facing"
            or hub_lb.get("VpcId") != vpc_id
            or (hub_lb.get("State") or {}).get("Code") != "active"
        ):
            raise ContractError(
                "Control Hub load balancer is not the exact active internet-facing "
                "network edge in the Control VPC"
            )

    security_groups = load_json(evidence_dir / "control-security-groups.json").get(
        "SecurityGroups"
    )
    if not isinstance(security_groups, list):
        raise ContractError("Control security-group evidence is malformed")

    def tag_value(row: dict[str, Any], key: str) -> str | None:
        matches = [
            tag.get("Value")
            for tag in row.get("Tags", [])
            if isinstance(tag, dict) and tag.get("Key") == key
        ]
        return matches[0] if len(matches) == 1 and isinstance(matches[0], str) else None

    def normalized_permissions(
        row: dict[str, Any], field: str
    ) -> set[tuple[str, int | None, int | None, str, str]]:
        result: set[tuple[str, int | None, int | None, str, str]] = set()
        permissions = row.get(field)
        if not isinstance(permissions, list):
            raise ContractError(f"Control SG {field} evidence is malformed")
        for permission in permissions:
            if not isinstance(permission, dict):
                raise ContractError(f"Control SG {field} rule is malformed")
            protocol = str(permission.get("IpProtocol"))
            start = permission.get("FromPort")
            end = permission.get("ToPort")
            for item in permission.get("IpRanges", []):
                result.add(
                    (protocol, start, end, "cidr_ipv4", str(item.get("CidrIp")))
                )
            for item in permission.get("Ipv6Ranges", []):
                result.add(
                    (protocol, start, end, "cidr_ipv6", str(item.get("CidrIpv6")))
                )
            for item in permission.get("PrefixListIds", []):
                result.add(
                    (
                        protocol,
                        start,
                        end,
                        "prefix_list",
                        str(item.get("PrefixListId")),
                    )
                )
            for item in permission.get("UserIdGroupPairs", []):
                result.add(
                    (protocol, start, end, "security_group", str(item.get("GroupId")))
                )
        return result

    hub_nlb_groups = [
        row
        for row in security_groups
        if isinstance(row, dict)
        and tag_value(row, "Component") == "connector-hub-edge"
        and tag_value(row, "Name") == f"{CONTROL_PREFIX}-hub-nlb"
    ]
    hub_worker_groups = [
        row
        for row in security_groups
        if isinstance(row, dict)
        and tag_value(row, "Component") == "connector-hub"
        and tag_value(row, "Name") == f"{CONTROL_PREFIX}-hub"
    ]
    if not public_edge_ids:
        if hub_nlb_groups:
            raise ContractError("Control Hub NLB SG exists while the edge is dark")
    elif not hub_nlb_groups and live_load_balancers[0].get("SecurityGroups") in (
        None,
        [],
    ):
        # PRE-fence steady state. The public edge route tables are live, but the
        # reviewed NLB SG does not exist yet and the NLB attaches none -- which is
        # precisely WHY the fence transition replaces the NLB: AWS accepts
        # `security_groups` only at creation. Requiring a singular SG here demanded
        # the post-apply state and so rejected the exact state this check gates.
        #
        # Admitted ONLY when both are absent together. An NLB carrying security
        # groups that are not the reviewed edge SG, or a reviewed SG with no
        # attachment, still falls through to the strict branch below and fails.
        pass
    else:
        if len(hub_nlb_groups) != 1:
            raise ContractError("Control Hub NLB SG is not singular")
        nlb_group = hub_nlb_groups[0]
        nlb_group_id = nlb_group.get("GroupId")
        if (
            not isinstance(nlb_group_id, str)
            or not re.fullmatch(r"sg-[0-9a-f]+", nlb_group_id)
            or live_load_balancers[0].get("SecurityGroups") != [nlb_group_id]
        ):
            raise ContractError(
                "Control Hub NLB does not attach exactly the reviewed NLB SG"
            )
        hub_ingress = normalized_permissions(nlb_group, "IpPermissions")
        if pre_apply:
            # Invariants only. Which port and which source are exactly what a
            # reviewed apply moves, so pinning them here gates the apply on its
            # own outcome. Still fails closed on the things no apply may do:
            # more than one rule, a non-UDP rule, a port range, or a
            # security-group/prefix-list source instead of a CIDR.
            if len(hub_ingress) != 1 or not all(
                protocol == "udp" and from_port == to_port and kind == "cidr_ipv4"
                for protocol, from_port, to_port, kind, _ in hub_ingress
            ):
                raise ContractError(
                    "Control Hub NLB SG ingress is not exactly one CIDR-sourced UDP rule"
                )
        elif hub_ingress != {
            (
                "udp",
                HUB_CLIENT_EDGE_PORT,
                HUB_CLIENT_EDGE_PORT,
                "cidr_ipv4",
                HUB_PUBLIC_UDP_INGRESS_CIDR,
            )
        }:
            # Exact, and no longer tolerant of the legacy port: the 62206 -> 443
            # migration is complete on every edge, so accepting both here only
            # weakened the steady-state assertion.
            raise ContractError(
                "Control Hub NLB SG ingress is not exactly the open sandbox edge UDP "
                f"{HUB_CLIENT_EDGE_PORT}"
            )
        if hub_worker_groups:
            if len(hub_worker_groups) != 1:
                raise ContractError("Control Hub worker SG is not singular")
            worker_group = hub_worker_groups[0]
            worker_group_id = worker_group.get("GroupId")
            if not isinstance(worker_group_id, str) or not re.fullmatch(
                r"sg-[0-9a-f]+", worker_group_id
            ):
                raise ContractError("Control Hub worker SG id is malformed")
            if normalized_permissions(nlb_group, "IpPermissionsEgress") != {
                ("udp", 62206, 62206, "security_group", worker_group_id),
                ("tcp", 62207, 62207, "security_group", worker_group_id),
            }:
                raise ContractError(
                    "Control Hub NLB SG egress is not exactly worker UDP 62206 plus TCP 62207"
                )
            if normalized_permissions(worker_group, "IpPermissions") != {
                ("udp", 62206, 62206, "security_group", nlb_group_id),
                ("tcp", 62207, 62207, "security_group", nlb_group_id),
            }:
                raise ContractError(
                    "Control Hub worker SG ingress is not exactly from the Hub NLB SG"
                )
        elif normalized_permissions(nlb_group, "IpPermissionsEgress"):
            raise ContractError("Control Hub NLB SG has egress while workers are dark")
    return {
        "flow_log_id": flow["FlowLogId"],
        "vpc_id": vpc_id,
        "authority_function_count": len(live_lambda_names),
        "hub_load_balancer_count": len(live_load_balancers),
        "hub_nlb_security_group_count": len(hub_nlb_groups),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)

    plan = sub.add_parser("plan")
    plan.add_argument("plan_json", type=Path)
    plan.add_argument("prior_state_json", nargs="?", type=Path)
    # The PR lane plans with `-refresh=false` (terraform-plan-pr.yml), so any
    # attribute a resource changed OUT OF BAND still reads as whatever Terraform
    # last wrote. Declared explicitly rather than inferred from the presence of
    # prior_state_json: that coupling is incidental and would silently invert if
    # either caller changed its arguments.
    plan.add_argument("--refresh-disabled", action="store_true")

    normalization_drift = sub.add_parser("normalization-drift")
    normalization_drift.add_argument("plan_json", type=Path)
    normalization_drift.add_argument("prior_state_json", type=Path)

    hub_worker_image_update = sub.add_parser("hub-worker-image-update")
    hub_worker_image_update.add_argument("plan_json", type=Path)

    state_list = sub.add_parser("state-list")
    state_list.add_argument("path", type=Path)

    state = sub.add_parser("state")
    state.add_argument("state_json", type=Path)
    live = sub.add_parser("live")
    live.add_argument("evidence_dir", type=Path)
    live.add_argument(
        "--pre-apply",
        action="store_true",
        help=(
            "Assert invariants only for boundary fields a reviewed apply may "
            "change. Use before an apply; omit to assert the exact target."
        ),
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        if args.command == "plan":
            prior_state = (
                load_json(args.prior_state_json) if args.prior_state_json else None
            )
            result = check_plan(
                load_json(args.plan_json),
                prior_state,
                refresh_disabled=args.refresh_disabled,
            )
        elif args.command == "normalization-drift":
            result = check_normalization_drift(
                load_json(args.plan_json),
                load_json(args.prior_state_json),
            )
        elif args.command == "hub-worker-image-update":
            result = check_hub_worker_image_update_plan(load_json(args.plan_json))
        elif args.command == "state-list":
            result = check_state_list(args.path)
        elif args.command == "state":
            result = check_state(load_json(args.state_json))
        elif args.command == "live":
            result = check_live(args.evidence_dir, pre_apply=args.pre_apply)
        else:
            raise AssertionError(args.command)
    except ContractError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
