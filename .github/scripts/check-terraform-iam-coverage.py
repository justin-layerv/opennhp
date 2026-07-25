#!/usr/bin/env python3
"""check-terraform-iam-coverage.py

Class-A drift detector (#1324). Asserts that every IAM-consuming block in the
terraform configuration has matching IAM actions granted somewhere in the
`aws_iam_role.github_actions` role's policy set. Two consumer kinds:

- `data "aws_*"` blocks — the *read* actions `terraform plan`'s refresh
  calls. Checked against DATA_SOURCE_ACTIONS (fail-closed on unmapped).
- `resource "aws_*"` blocks — the *write* actions `terraform apply`'s
  create/update/destroy calls. Checked against RESOURCE_ACTIONS, with
  RESOURCE_UNCHECKED_ACK grandfathering the not-yet-mapped remainder
  (fail-closed on any type in neither set).

Why this exists
===============

#1323 (data-source half): `data "aws_cloudformation_stack" "website_api"` was
added to `terraform/main.tf` and gated on a prod-only tfvar. Sandbox
`terraform plan` never refreshed the data source (count = 0), so the missing
`cloudformation:DescribeStacks` + `cloudformation:GetTemplate` grants on
`nhp-prod-github-actions` were invisible until prod-promote tried the
refresh.

#2996 (resource half): `aws_cloudwatch_composite_alarm` was added needing
`cloudwatch:PutCompositeAlarm` — a distinct action from the
`cloudwatch:PutMetricAlarm` the apply role already granted. The PR-time
`terraform plan` runs under a read-only role and never calls the write API,
so the gap was invisible until the post-merge `terraform apply` hit
`AccessDenied: PutCompositeAlarm` and turned `main` red. The resource-side
map closes this class.

Both halves catch the same failure statically — at PR time, no AWS
credentials needed (#1121's privesc gate stays closed).

The same pass also counts the canonical role's worst-case customer-managed
policy attachments and rejects configurations above AWS's default quota of 10.
Conditional attachments count as enabled so every shared-module environment is
covered; an unbounded computed cardinality fails closed.

What it does NOT check
======================

- Per-environment role-attachment differences. The lint takes the *union*
  of all attached policies regardless of `count` predicates. A grant
  conditionally attached only in sandbox would pass even though prod
  doesn't get it. Catching that requires walking gating predicates per env;
  tracked separately (see docs/design/TERRAFORM_PROD_DRIFT_DETECTOR.md
  "Out of scope"). For the regression class this lint targets (#1323), the
  failure mode is "no grant anywhere in source" — which the union check
  catches.
- Resource-ARN scope, except for the shared apply role's five Terraform helper
  Lambda invocations, the qualified relay semantic-read Lambda invocation, and
  the unqualified acme cert-status integration-test invocation. Other consumers
  still need manual scope review.
- `count`/`for_each` gating. Consumers are checked as a union regardless of
  gating, so a mapped resource that is `count = 0` in every environment
  still demands its grants exist. This errs toward requiring grants (safe
  direction) and matches the data-source union behavior above; a mapped
  type added purely as dead/conditional code could produce a false red.

See `docs/runbooks/terraform-prod-drift.md` for what to do when this fires.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import re
import sys
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any

# Importable as a sibling — both lints live in .github/scripts/.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from _tf_lint_lib import (  # noqa: E402  # pyright: ignore[reportMissingImports]
    error,
    extract_policy_body,
    iter_data_sources,
    iter_resources,
    parse_tf_files,
    policy_has_mixed_effects,
    statement_actions,
    unquote,
    warn,
    warn_undecodable_policy,
)


# Map of `data "aws_<type>"` -> required IAM actions. Two value shapes:
#
# - `list[str]`: static action set — most data sources need the same
#   actions regardless of the body's filter arguments.
# - `Callable[[dict], list[str]]`: body-aware action set — the data
#   source's required actions depend on which optional arguments are
#   set (e.g. `aws_route53_zone` calls `route53:ListTagsForResource`
#   only when the `tags` filter is set). The callable receives the
#   data block's body dict and returns the full action list. Adding
#   the next body-aware entry doesn't grow `main()`'s logic, just
#   the table.
#
# When adding a new data source: read the provider source for that type
# (https://github.com/hashicorp/terraform-provider-aws/tree/main/internal/service/),
# find every AWS API call the read function makes, translate to IAM action
# names, and add an entry here. Each entry's comment cites the provider
# source file the actions were derived from.
#
# Empty list means the data source needs no IAM grant — either it makes no
# AWS API call (aws_iam_policy_document is a renderer), the call is
# unauthenticated (aws_ip_ranges hits a public S3 URL), or the action is
# implicitly allowed for every authenticated principal
# (sts:GetCallerIdentity).
#
# `ActionSpec` is the map-value shape shared by DATA_SOURCE_ACTIONS and
# RESOURCE_ACTIONS: a static action list, or a body-aware callable.
ActionSpec = list[str] | Callable[[dict[str, Any]], list[str]]

HELPER_INVOKE_ACTION = "lambda:InvokeFunction"
_HELPER_SUFFIXES = (
    "keygen",
    "ac-keygen",
    "etcd-tls-gen",
    "registration-keygen",
    "relay-keygen",
    # Slice 5b: the Connector Hub keygen seeds the Hub key-material secret
    # in-account at apply, invoked by the shared apply role like the others.
    "control-hub-keygen",
)
HELPER_INVOKE_RESOURCES = frozenset(
    "arn:aws:lambda:${local.region}:${local.account_id}:function:${var.name_prefix}-"
    + suffix
    for suffix in _HELPER_SUFFIXES
)
SEMANTIC_READ_INVOKE_RESOURCES = {
    "RelayIdentityStatusInvoke": (
        "arn:aws:lambda:${local.region}:${local.account_id}:"
        "function:${var.name_prefix}-relay-status:$LATEST"
    ),
}
# The Deploy Sandbox - Validate integration test invokes the read-only acme
# cert-status function under the shared deploy role after apply. The SDK call
# passes no Qualifier, so IAM authorizes it against the UNqualified function
# ARN — the opposite of the relay refresh invoke above, which pins $LATEST.
# This lives on terraform_apply_data (a runtime-invoke policy), never on
# terraform_read, because no Terraform data source invokes it.
INTEGRATION_TEST_INVOKE_RESOURCES = {
    "AcmeCertManagerStatusInvoke": (
        "arn:aws:lambda:${local.region}:${local.account_id}:"
        "function:${var.name_prefix}-acme-cert-manager"
    ),
}


def _terraform_helper_invoke_scope_error(policy: dict[str, Any] | None) -> str | None:
    """Keep deploy-time helper invokes exact and Authority aliases unreachable."""

    if not policy or not isinstance(policy.get("Statement"), list):
        return "terraform_apply_data policy could not be decoded"

    def strings(value: Any) -> list[str] | None:
        values = value if isinstance(value, list) else [value]
        if not all(isinstance(item, str) for item in values):
            return None
        return [unquote(item) for item in values]

    grants = []
    for statement in policy["Statement"]:
        if not isinstance(statement, dict):
            continue
        effect = unquote(statement.get("Effect", "Allow"))
        if isinstance(effect, str) and effect.lower() != "allow":
            continue
        actions = strings(statement.get("Action")) or []
        if "NotAction" in statement or action_allowed(
            HELPER_INVOKE_ACTION, [action.lower() for action in actions]
        ):
            grants.append(statement)

    # The acme integration-test invoke shares this policy but is fenced
    # separately (_terraform_integration_test_invoke_scope_error); exclude it by
    # Sid so the helper set stays independently exact. A rogue invoke that
    # borrows the acme Sid but broadens action/resource is still caught by that
    # companion fence.
    grants = [
        grant
        for grant in grants
        if unquote(grant.get("Sid", "")) not in INTEGRATION_TEST_INVOKE_RESOURCES
    ]

    if len(grants) != 1:
        return "terraform_apply_data must have exactly one helper InvokeFunction-capable Allow"
    grant = grants[0]
    actions = strings(grant.get("Action"))
    resources = strings(grant.get("Resource"))
    if (
        set(grant) != {"Sid", "Effect", "Action", "Resource"}
        or unquote(grant.get("Sid")) != "TerraformHelperInvoke"
        or actions != [HELPER_INVOKE_ACTION]
        or resources is None
        or len(resources) != len(HELPER_INVOKE_RESOURCES)
        or set(resources) != HELPER_INVOKE_RESOURCES
    ):
        return "TerraformHelperInvoke must grant only the six exact helper ARNs"
    return None


def _exact_single_invoke_statement_ok(statement: dict[str, Any], resource: str) -> bool:
    """Shared exact-shape check for the deploy role's per-Sid invoke fences.

    True iff `statement` grants only `lambda:InvokeFunction` on exactly the one
    `resource` ARN, with no extra keys (a stray Condition/Principal fails). The
    qualified-vs-unqualified distinction lives entirely in the caller's ARN
    string, so both the relay refresh fence and the acme integration-test fence
    reuse this identical verification — keep the security-critical shape check in
    one place so the two fences cannot drift.
    """

    raw_actions = statement.get("Action")
    actions = raw_actions if isinstance(raw_actions, list) else [raw_actions]
    raw_resources = statement.get("Resource")
    resources = raw_resources if isinstance(raw_resources, list) else [raw_resources]
    return (
        set(statement) == {"Sid", "Effect", "Action", "Resource"}
        and [unquote(action) for action in actions if isinstance(action, str)]
        == [HELPER_INVOKE_ACTION]
        and [unquote(item) for item in resources if isinstance(item, str)] == [resource]
    )


def _terraform_semantic_read_invoke_scope_error(
    policy: dict[str, Any] | None,
) -> str | None:
    """Keep refresh-time semantic reads exact on the shared deploy role."""

    if not policy or not isinstance(policy.get("Statement"), list):
        return "terraform_read policy could not be decoded"

    grants: dict[str, dict[str, Any]] = {}
    for statement in policy["Statement"]:
        if not isinstance(statement, dict):
            continue
        effect = unquote(statement.get("Effect", "Allow"))
        if isinstance(effect, str) and effect.lower() != "allow":
            continue
        raw_actions = statement.get("Action", [])
        actions = raw_actions if isinstance(raw_actions, list) else [raw_actions]
        normalized_actions = [
            unquote(action).lower() for action in actions if isinstance(action, str)
        ]
        if "NotAction" not in statement and not action_allowed(
            HELPER_INVOKE_ACTION, normalized_actions
        ):
            continue
        sid = unquote(statement.get("Sid", ""))
        if not isinstance(sid, str) or sid in grants:
            return "terraform_read must have unique Sids for semantic-read invokes"
        grants[sid] = statement

    if set(grants) != set(SEMANTIC_READ_INVOKE_RESOURCES):
        return "terraform_read must grant exactly the qualified relay semantic-read invoke"

    for sid, resource in SEMANTIC_READ_INVOKE_RESOURCES.items():
        if not _exact_single_invoke_statement_ok(grants[sid], resource):
            return f"terraform_read {sid} must grant only its exact qualified target ARN"
    return None


def _terraform_integration_test_invoke_scope_error(
    policy: dict[str, Any] | None,
) -> str | None:
    """Keep the post-deploy acme cert-status invoke exact and unqualified.

    terraform_apply_data also carries the five Terraform helper invokes (fenced
    by `_terraform_helper_invoke_scope_error`); this check inspects only the
    integration-test Sid(s) so the two invoke categories stay independently
    exact. Unlike the relay refresh invoke, the acme target must NOT be
    qualified: the SDK invoke passes no Qualifier, so a `:$LATEST`/versioned
    grant would not authorize it.
    """

    if not policy or not isinstance(policy.get("Statement"), list):
        return "terraform_apply_data policy could not be decoded"

    grants: dict[str, dict[str, Any]] = {}
    for statement in policy["Statement"]:
        if not isinstance(statement, dict):
            continue
        effect = unquote(statement.get("Effect", "Allow"))
        if isinstance(effect, str) and effect.lower() != "allow":
            continue
        raw_actions = statement.get("Action", [])
        actions = raw_actions if isinstance(raw_actions, list) else [raw_actions]
        normalized_actions = [
            unquote(action).lower() for action in actions if isinstance(action, str)
        ]
        if "NotAction" not in statement and not action_allowed(
            HELPER_INVOKE_ACTION, normalized_actions
        ):
            continue
        sid = unquote(statement.get("Sid", ""))
        if sid not in INTEGRATION_TEST_INVOKE_RESOURCES:
            continue  # helper invokes are fenced separately
        if sid in grants:
            return "terraform_apply_data must have unique Sids for the integration-test invoke"
        grants[sid] = statement

    if set(grants) != set(INTEGRATION_TEST_INVOKE_RESOURCES):
        return "terraform_apply_data must grant exactly the unqualified acme cert-status invoke"

    for sid, resource in INTEGRATION_TEST_INVOKE_RESOURCES.items():
        if not _exact_single_invoke_statement_ok(grants[sid], resource):
            return f"terraform_apply_data {sid} must grant only its exact unqualified target ARN"
    return None


def terraform_helper_invoke_scope_error(
    parsed: list[tuple[Path, dict[str, Any]]],
) -> str | None:
    matches = [
        (name, body)
        for file, rtype, name, body in iter_resources(parsed)
        if _in_canonical_module(file)
        and rtype == "aws_iam_policy"
        and name in {"terraform_apply_data", "terraform_read"}
    ]
    if sorted(name for name, _ in matches) != [
        "terraform_apply_data",
        "terraform_read",
    ]:
        return "expected exactly one canonical terraform_apply_data and terraform_read policy"
    policies = dict(matches)
    apply_data_body = extract_policy_body(policies["terraform_apply_data"].get("policy"))
    return (
        _terraform_helper_invoke_scope_error(apply_data_body)
        or _terraform_integration_test_invoke_scope_error(apply_data_body)
        or _terraform_semantic_read_invoke_scope_error(
            extract_policy_body(policies["terraform_read"].get("policy"))
        )
    )


def _route53_zone_actions(body: dict[str, Any]) -> list[str]:
    """`aws_route53_zone` requires the extra `route53:ListTagsForResource`
    action when the `tags` filter argument is set; the basic action
    suffices otherwise.
    """
    actions = ["route53:ListHostedZones"]
    if "tags" in body:
        actions.append("route53:ListTagsForResource")
    return actions


DATA_SOURCE_ACTIONS: dict[str, ActionSpec] = {
    # internal/service/ecr/image_data_source.go calls ecr:DescribeImages.
    "aws_ecr_image": ["ecr:DescribeImages"],
    # internal/service/ecr/repository_data_source.go calls
    # ecr:DescribeRepositories (+ ListTagsForResource for tags). The plan-read
    # role already holds ecr:DescribeRepositories for refresh.
    "aws_ecr_repository": ["ecr:DescribeRepositories"],
    # No-grant data sources -------------------------------------------
    # internal/service/iam/policy_document_data_source.go — no API call.
    "aws_iam_policy_document": [],
    # internal/service/sts/caller_identity_data_source.go — sts:GetCallerIdentity
    # is implicitly allowed for every authenticated principal; no IAM grant
    # is required.
    "aws_caller_identity": [],
    # internal/service/meta/region_data_source.go — pure metadata, no API.
    "aws_region": [],
    # internal/service/meta/partition_data_source.go — pure metadata.
    "aws_partition": [],
    # internal/service/meta/ip_ranges_data_source.go — fetches the public
    # https://ip-ranges.amazonaws.com/ip-ranges.json over HTTPS, no AWS auth.
    "aws_ip_ranges": [],
    # Real-grant data sources -----------------------------------------
    # internal/service/lambda/invocation_data_source.go invokes the named
    # function during Read.
    "aws_lambda_invocation": ["lambda:InvokeFunction"],
    # internal/service/ec2/availability_zones_data_source.go calls
    # ec2:DescribeAvailabilityZones.
    "aws_availability_zones": ["ec2:DescribeAvailabilityZones"],
    # internal/service/ec2/ec2_ami_data_source.go calls ec2:DescribeImages.
    "aws_ami": ["ec2:DescribeImages"],
    # internal/service/ec2/vpc_prefix_list_data_source.go calls
    # ec2:DescribePrefixLists.
    "aws_prefix_list": ["ec2:DescribePrefixLists"],
    # internal/service/ec2/subnet_data_source.go calls ec2:DescribeSubnets.
    "aws_subnet": ["ec2:DescribeSubnets"],
    # internal/service/cloudformation/stack_data_source.go: findStackByName
    # calls cloudformation:DescribeStacks; the resource then unconditionally
    # calls cloudformation:GetTemplate. Both required (#1323).
    "aws_cloudformation_stack": [
        "cloudformation:DescribeStacks",
        "cloudformation:GetTemplate",
    ],
    # internal/service/cloudfront/cache_policy_data_source.go calls
    # cloudfront:ListCachePolicies and filters client-side by name (the
    # codebase's only consumer at terraform/modules/qurl-link/main.tf:257
    # looks up by name). Grant the action that matches the actual lookup
    # path. cloudfront:GetCachePolicy is also accepted by the provider when
    # the lookup is by id; cover both with a wildcard.
    "aws_cloudfront_cache_policy": [
        "cloudfront:ListCachePolicies",
        "cloudfront:GetCachePolicy",
    ],
    # internal/service/iam/openid_connect_provider_data_source.go calls
    # iam:GetOpenIDConnectProvider.
    "aws_iam_openid_connect_provider": ["iam:GetOpenIDConnectProvider"],
    # internal/service/route53/zone_data_source.go calls
    # route53:ListHostedZones for primary lookup. When the data source
    # is used with the `tags` filter argument the provider ALSO calls
    # route53:ListTagsForResource — `_route53_zone_actions` returns
    # the extra action conditionally rather than over-granting always.
    "aws_route53_zone": _route53_zone_actions,
    # internal/service/s3/object_data_source.go calls s3:GetObject.
    "aws_s3_object": ["s3:GetObject"],
    # internal/service/secretsmanager/secret_data_source.go calls
    # secretsmanager:DescribeSecret.
    "aws_secretsmanager_secret": ["secretsmanager:DescribeSecret"],
    # internal/service/secretsmanager/secret_version_data_source.go calls
    # secretsmanager:GetSecretValue. KMS decrypt happens inside that call
    # if the secret is CMK-encrypted; that grant is on the CMK key policy,
    # not the principal, so it isn't checked here.
    "aws_secretsmanager_secret_version": ["secretsmanager:GetSecretValue"],
    # internal/service/ssm/parameter_data_source.go calls ssm:GetParameter.
    "aws_ssm_parameter": ["ssm:GetParameter"],
    # internal/service/kms/public_key_data_source.go calls kms:GetPublicKey
    # (GetPublicKey on the key id). The github_actions role already grants
    # kms:Get* which covers this via IAM glob.
    "aws_kms_public_key": ["kms:GetPublicKey"],
}


# Map of `resource "aws_<type>"` -> IAM actions the CI apply role needs to
# create/update/delete it. Same two value shapes as DATA_SOURCE_ACTIONS
# (static `list[str]` or body-aware `Callable[[dict], list[str]]`).
#
# Class A (#1324) is defined as "a consumer — data source OR RESOURCE —
# that requires an IAM action the apply role does not have." The
# data-source half shipped first; this is the resource half, added after
# #2996: `aws_cloudwatch_composite_alarm` needs `cloudwatch:PutCompositeAlarm`
# — a DISTINCT action from the `cloudwatch:PutMetricAlarm` the apply role
# already had — so `terraform plan` (read-only role) was green while the
# post-merge `apply` hit `AccessDenied: PutCompositeAlarm`.
#
# Unlike DATA_SOURCE_ACTIONS, this map does NOT enumerate every resource
# type in the tree (there are ~130). It maps the types we've chosen to
# action-check; the rest are grandfathered in RESOURCE_UNCHECKED_ACK
# below, and any type in NEITHER set is fail-closed. Burn the grandfather
# set down by moving entries here over time.
#
# When adding an entry: read the terraform-aws-provider service package
# for the type, list the create/update/delete (and tag) API calls its
# CRUD functions make, and translate to IAM action names — same
# convention as DATA_SOURCE_ACTIONS, each entry citing its provider
# source file. Over-listing a read/tag action the apply role covers via a
# broad `Describe*`/`List*`/`Get*` grant is harmless (glob-matched); the
# load-bearing entries are the mutating `Put*`/`Delete*`/`Create*` verbs
# the least-privilege apply policy enumerates explicitly. Under-listing a
# mutating verb is the only real risk (a passing apply surfaces it) — the
# action sets are hand-derived and unversioned against the provider, so
# re-check the mapped families on a terraform-aws-provider major bump; the
# per-entry source citations make that tractable.

# Tag actions are listed UNCONDITIONALLY for taggable types — not gated on
# an explicit `tags` block. Every `provider "aws"` in
# terraform/environments/{prod,sandbox}/backend.tf sets `default_tags`, so
# the provider tags every taggable resource at apply and reads tags on
# every refresh (to populate `tags_all`) even when the HCL omits `tags`. A
# `if "tags" in body` conditional would therefore under-require the tag
# trio for an untagged alarm and re-open the green-at-PR / red-at-apply gap
# this lint exists to close — narrower, but the same class. That's why
# these are static lists, not body-aware callables like the data-source
# `_route53_zone_actions` (whose `tags` is a read-time *filter arg*, a
# different semantic from resource tagging under default_tags). The
# `resource-metric-alarm-tag-gap` fixture fences the regression: an
# *untagged* alarm whose apply role lacks a tag verb must still flag.
RESOURCE_ACTIONS: dict[str, ActionSpec] = {
    # internal/service/ec2/vpc_default_security_group.go — the provider adopts
    # the VPC-created default group, removes/reconciles its rules, and applies
    # default tags. It does not create or delete the group itself.
    "aws_default_security_group": [
        "ec2:DescribeSecurityGroups",
        "ec2:AuthorizeSecurityGroupIngress",
        "ec2:AuthorizeSecurityGroupEgress",
        "ec2:RevokeSecurityGroupIngress",
        "ec2:RevokeSecurityGroupEgress",
        "ec2:CreateTags",
        "ec2:DeleteTags",
    ],
    # internal/service/elasticache/user.go — complete user lifecycle plus the
    # tag APIs exercised by default_tags.
    "aws_elasticache_user": [
        "elasticache:CreateUser",
        "elasticache:ModifyUser",
        "elasticache:DeleteUser",
        "elasticache:DescribeUsers",
        "elasticache:AddTagsToResource",
        "elasticache:RemoveTagsFromResource",
        "elasticache:ListTagsForResource",
    ],
    # internal/service/elasticache/user_group.go — complete group lifecycle;
    # ModifyUserGroup owns membership updates.
    "aws_elasticache_user_group": [
        "elasticache:CreateUserGroup",
        "elasticache:ModifyUserGroup",
        "elasticache:DeleteUserGroup",
        "elasticache:DescribeUserGroups",
        "elasticache:AddTagsToResource",
        "elasticache:RemoveTagsFromResource",
        "elasticache:ListTagsForResource",
    ],
    # internal/service/elasticache/serverless_cache.go — complete serverless
    # cache lifecycle plus tag APIs exercised by default_tags. Create/modify
    # can also authorize the referenced user-group ARN; the apply policy and
    # Control preflight separately fence that dependent-resource scope.
    "aws_elasticache_serverless_cache": [
        "elasticache:CreateServerlessCache",
        "elasticache:ModifyServerlessCache",
        "elasticache:DeleteServerlessCache",
        "elasticache:DescribeServerlessCaches",
        "elasticache:AddTagsToResource",
        "elasticache:RemoveTagsFromResource",
        "elasticache:ListTagsForResource",
    ],
    # internal/service/ec2/vpc_route.go — standalone route CRUD uses
    # CreateRoute, ReplaceRoute, DeleteRoute, and DescribeRouteTables.
    # Route-table and endpoint-owned inline routes are separate resources.
    "aws_route": [
        "ec2:CreateRoute",
        "ec2:ReplaceRoute",
        "ec2:DeleteRoute",
        "ec2:DescribeRouteTables",
    ],
    # internal/service/ec2/vpc_peering_connection.go — same-account
    # auto_accept exercises both create and accept; default_tags exercise the
    # EC2 tag pair. Read/delete complete the lifecycle.
    "aws_vpc_peering_connection": [
        "ec2:CreateVpcPeeringConnection",
        "ec2:AcceptVpcPeeringConnection",
        "ec2:DeleteVpcPeeringConnection",
        "ec2:DescribeVpcPeeringConnections",
        "ec2:CreateTags",
        "ec2:DeleteTags",
    ],
    # internal/service/ec2/vpc_peering_connection_options.go — both requester
    # and accepter DNS options are applied through the same modify API.
    "aws_vpc_peering_connection_options": [
        "ec2:ModifyVpcPeeringConnectionOptions",
        "ec2:DescribeVpcPeeringConnections",
    ],
    # internal/service/route53resolver/resolver_query_log_config.go.
    "aws_route53_resolver_query_log_config": [
        "route53resolver:CreateResolverQueryLogConfig",
        "route53resolver:GetResolverQueryLogConfig",
        "route53resolver:DeleteResolverQueryLogConfig",
        "route53resolver:ListTagsForResource",
        "route53resolver:TagResource",
        "route53resolver:UntagResource",
    ],
    # internal/service/route53resolver/resolver_query_log_config_association.go.
    # The first association may create Resolver's service-linked role.
    "aws_route53_resolver_query_log_config_association": [
        "route53resolver:AssociateResolverQueryLogConfig",
        "route53resolver:GetResolverQueryLogConfigAssociation",
        "route53resolver:DisassociateResolverQueryLogConfig",
        "iam:CreateServiceLinkedRole",
    ],
    # internal/service/route53resolver/firewall_domain_list.go — domains are
    # populated and changed through UpdateFirewallDomains after list creation.
    "aws_route53_resolver_firewall_domain_list": [
        "route53resolver:CreateFirewallDomainList",
        "route53resolver:GetFirewallDomainList",
        "route53resolver:ListFirewallDomains",
        "route53resolver:UpdateFirewallDomains",
        "route53resolver:DeleteFirewallDomainList",
        "route53resolver:ListTagsForResource",
        "route53resolver:TagResource",
        "route53resolver:UntagResource",
    ],
    # internal/service/route53resolver/firewall_rule_group.go.
    "aws_route53_resolver_firewall_rule_group": [
        "route53resolver:CreateFirewallRuleGroup",
        "route53resolver:GetFirewallRuleGroup",
        "route53resolver:DeleteFirewallRuleGroup",
        "route53resolver:ListTagsForResource",
        "route53resolver:TagResource",
        "route53resolver:UntagResource",
    ],
    # internal/service/route53resolver/firewall_rule.go.
    "aws_route53_resolver_firewall_rule": [
        "route53resolver:CreateFirewallRule",
        "route53resolver:ListFirewallRules",
        "route53resolver:UpdateFirewallRule",
        "route53resolver:DeleteFirewallRule",
    ],
    # internal/service/route53resolver/firewall_rule_group_association.go.
    "aws_route53_resolver_firewall_rule_group_association": [
        "route53resolver:AssociateFirewallRuleGroup",
        "route53resolver:GetFirewallRuleGroupAssociation",
        "route53resolver:UpdateFirewallRuleGroupAssociation",
        "route53resolver:DisassociateFirewallRuleGroup",
        "route53resolver:ListTagsForResource",
        "route53resolver:TagResource",
        "route53resolver:UntagResource",
    ],
    # internal/service/route53resolver/firewall_config.go.
    "aws_route53_resolver_firewall_config": [
        "route53resolver:GetFirewallConfig",
        "route53resolver:UpdateFirewallConfig",
    ],
    # internal/service/cloudwatch/metric_alarm.go — PutMetricAlarm on
    # create/update, DescribeAlarms on read, DeleteAlarms on destroy, and
    # the tag trio (ListTagsForResource read + TagResource/UntagResource)
    # exercised via default_tags. The composite alarm's sibling; mapped
    # together so the whole alarm family is covered, not just the subtype
    # that bit us in #2996.
    "aws_cloudwatch_metric_alarm": [
        "cloudwatch:PutMetricAlarm",
        "cloudwatch:DescribeAlarms",
        "cloudwatch:DeleteAlarms",
        "cloudwatch:ListTagsForResource",
        "cloudwatch:TagResource",
        "cloudwatch:UntagResource",
    ],
    # internal/service/cloudwatch/composite_alarm.go — PutCompositeAlarm on
    # create/update (DISTINCT from PutMetricAlarm — the exact #2996 gap),
    # DescribeAlarms on read, DeleteAlarms on destroy (there is no separate
    # DeleteCompositeAlarms action; DeleteAlarms deletes both kinds), tag
    # trio via default_tags. The regression this extension exists to catch.
    "aws_cloudwatch_composite_alarm": [
        "cloudwatch:PutCompositeAlarm",
        "cloudwatch:DescribeAlarms",
        "cloudwatch:DeleteAlarms",
        "cloudwatch:ListTagsForResource",
        "cloudwatch:TagResource",
        "cloudwatch:UntagResource",
    ],
    # internal/service/cloudwatch/dashboard.go: PutDashboard on
    # create/update, GetDashboard on read, DeleteDashboards on destroy.
    # CloudWatch dashboards are not taggable, so no tag actions.
    "aws_cloudwatch_dashboard": [
        "cloudwatch:PutDashboard",
        "cloudwatch:GetDashboard",
        "cloudwatch:DeleteDashboards",
    ],
    # internal/service/s3/bucket_notification.go — PutBucketNotificationConfiguration
    # on create/update/delete (delete writes an empty notification config), and
    # GetBucketNotificationConfiguration on read.
    "aws_s3_bucket_notification": [
        "s3:GetBucketNotification",
        "s3:PutBucketNotification",
    ],
    # Agent-registration email OTP (T1), terraform/agent_otp_ses.tf.
    # internal/service/sesv2/email_identity.go — CreateEmailIdentity on create,
    # GetEmailIdentity on read, DeleteEmailIdentity on destroy,
    # PutEmailIdentityDkimSigningAttributes on the EasyDKIM key-length update,
    # PutEmailIdentityConfigurationSetAttributes to associate/alter the
    # configuration_set_name on the identity (a clean create may ride
    # CreateEmailIdentity, but a later config-set change issues this Put), plus
    # the tag trio (TagResource/UntagResource/ListTagsForResource) via
    # default_tags. Matches the "SESAgentOTP" statement in the dedicated
    # terraform_apply_ses policy attached to the github_actions apply role in
    # modules/ecr/main.tf.
    "aws_sesv2_email_identity": [
        "ses:CreateEmailIdentity",
        "ses:GetEmailIdentity",
        "ses:DeleteEmailIdentity",
        "ses:PutEmailIdentityDkimSigningAttributes",
        "ses:PutEmailIdentityConfigurationSetAttributes",
        "ses:TagResource",
        "ses:UntagResource",
        "ses:ListTagsForResource",
    ],
    # internal/service/sesv2/email_identity_mail_from_attributes.go —
    # PutEmailIdentityMailFromAttributes on create/update AND destroy (destroy
    # resets the MAIL FROM to the default), GetEmailIdentity on read. Not
    # separately taggable (attributes of the identity).
    "aws_sesv2_email_identity_mail_from_attributes": [
        "ses:PutEmailIdentityMailFromAttributes",
        "ses:GetEmailIdentity",
    ],
    # internal/service/sesv2/configuration_set.go — CreateConfigurationSet on
    # create, GetConfigurationSet on read, DeleteConfigurationSet on destroy,
    # the three Put*Options calls the update path issues (delivery/reputation/
    # sending), plus the tag trio via default_tags.
    "aws_sesv2_configuration_set": [
        "ses:CreateConfigurationSet",
        "ses:GetConfigurationSet",
        "ses:DeleteConfigurationSet",
        "ses:PutConfigurationSetDeliveryOptions",
        "ses:PutConfigurationSetReputationOptions",
        "ses:PutConfigurationSetSendingOptions",
        "ses:TagResource",
        "ses:UntagResource",
        "ses:ListTagsForResource",
    ],
    # internal/service/sesv2/configuration_set_event_destination.go —
    # CreateConfigurationSetEventDestination on create,
    # UpdateConfigurationSetEventDestination on update,
    # DeleteConfigurationSetEventDestination on destroy,
    # GetConfigurationSetEventDestinations on read. Not separately taggable.
    "aws_sesv2_configuration_set_event_destination": [
        "ses:CreateConfigurationSetEventDestination",
        "ses:UpdateConfigurationSetEventDestination",
        "ses:DeleteConfigurationSetEventDestination",
        "ses:GetConfigurationSetEventDestinations",
    ],
}

# Grandfathered resource types: present in `terraform/` when resource-create
# coverage was added, but not yet action-mapped in RESOURCE_ACTIONS. The
# coverage check SKIPS these — the
# apply role already carries whatever their CRUD needs (every one is
# exercised by a passing apply today), so re-deriving and asserting their
# action sets is burn-down work, not a live gap.
#
# What makes this safe (and NOT the silent-passthrough the data-source
# lint was built to kill): a resource type in NEITHER RESOURCE_ACTIONS NOR
# this set is FAIL-CLOSED (exit 2). A genuinely new resource type added in
# a PR forces an explicit, reviewed decision — map its actions
# (RESOURCE_ACTIONS) or grandfather it here — which is the #2996-class
# catch, one PR before apply. This is an explicit allowlist, not a
# per-line escape hatch.
#
# Burn down by moving entries into RESOURCE_ACTIONS, highest-value first:
# the write-heavy services whose action sets are non-obvious and
# least-privilege-enumerated (events:, lambda:, sqs:, dynamodb:, sns:,
# iam:). Tracked in #2998.
#
# This set is PROD-DERIVED — the resource types in `terraform/` only.
# Fixture-only scaffolding types live in `_FIXTURE_SCAFFOLD_ACK` below,
# kept separate so (a) this set regenerates cleanly from `terraform/` alone
# and (b) the fixture-only fail-closed erosion stays explicit, not buried
# here. A type later removed from `terraform/` leaves a stale entry —
# harmless, since a type absent from the scanned tree is never iterated, so
# no lockstep-drift gate guards this set.
#
# Regenerate (resource types in terraform/, minus the mapped keys above):
#   grep -rhoE 'resource[[:space:]]+"aws_[a-z0-9_]+"' terraform \
#     --include='*.tf' | grep -oE 'aws_[a-z0-9_]+' | sort -u
RESOURCE_UNCHECKED_ACK: frozenset[str] = frozenset({
    "aws_acm_certificate",
    "aws_acm_certificate_validation",
    "aws_api_gateway_account",
    "aws_apigatewayv2_api",
    "aws_apigatewayv2_api_mapping",
    "aws_apigatewayv2_authorizer",
    "aws_apigatewayv2_domain_name",
    "aws_apigatewayv2_integration",
    "aws_apigatewayv2_route",
    "aws_apigatewayv2_stage",
    "aws_appautoscaling_policy",
    "aws_appautoscaling_target",
    "aws_athena_workgroup",
    "aws_autoscaling_attachment",
    "aws_autoscaling_group",
    "aws_autoscaling_lifecycle_hook",
    "aws_autoscaling_policy",
    "aws_bcmdataexports_export",
    "aws_ce_cost_allocation_tag",
    "aws_chatbot_slack_channel_configuration",
    "aws_cloudfront_cache_policy",
    "aws_cloudfront_distribution",
    "aws_cloudfront_function",
    "aws_cloudfront_monitoring_subscription",
    "aws_cloudfront_origin_access_control",
    "aws_cloudfront_response_headers_policy",
    "aws_cloudtrail",
    "aws_cloudwatch_event_rule",
    "aws_cloudwatch_event_target",
    "aws_cloudwatch_log_delivery",
    "aws_cloudwatch_log_delivery_destination",
    "aws_cloudwatch_log_delivery_source",
    "aws_cloudwatch_log_group",
    "aws_cloudwatch_log_metric_filter",
    "aws_config_config_rule",
    "aws_config_configuration_recorder",
    "aws_config_configuration_recorder_status",
    "aws_config_delivery_channel",
    "aws_dynamodb_table",
    "aws_dynamodb_table_item",
    "aws_ecr_lifecycle_policy",
    "aws_ecr_registry_policy",
    "aws_ecr_replication_configuration",
    "aws_ecr_repository",
    "aws_ecr_repository_policy",
    "aws_ecs_cluster",
    "aws_ecs_service",
    "aws_ecs_task_definition",
    "aws_efs_access_point",
    "aws_efs_backup_policy",
    "aws_efs_file_system",
    "aws_efs_mount_target",
    "aws_eip",
    "aws_elasticache_subnet_group",
    "aws_flow_log",
    "aws_glue_catalog_database",
    "aws_glue_catalog_table",
    "aws_guardduty_detector",
    "aws_guardduty_detector_feature",
    "aws_iam_access_key",
    "aws_iam_account_password_policy",
    "aws_iam_instance_profile",
    "aws_iam_openid_connect_provider",
    "aws_iam_policy",
    "aws_iam_role",
    "aws_iam_role_policy",
    "aws_iam_role_policy_attachment",
    "aws_iam_user",
    "aws_iam_user_policy",
    "aws_internet_gateway",
    "aws_kms_alias",
    "aws_kms_key",
    "aws_lambda_alias",
    "aws_lambda_event_source_mapping",
    "aws_lambda_function",
    "aws_lambda_function_event_invoke_config",
    "aws_lambda_function_url",
    "aws_lambda_invocation",
    "aws_lambda_layer_version",
    "aws_lambda_permission",
    "aws_lambda_provisioned_concurrency_config",
    "aws_launch_template",
    "aws_lb",
    "aws_lb_listener",
    "aws_lb_listener_rule",
    "aws_lb_target_group",
    "aws_nat_gateway",
    "aws_network_acl",
    "aws_route53_record",
    "aws_route53_zone",
    "aws_route_table",
    "aws_route_table_association",
    "aws_s3_bucket",
    "aws_s3_bucket_acl",
    "aws_s3_bucket_lifecycle_configuration",
    "aws_s3_bucket_ownership_controls",
    "aws_s3_bucket_policy",
    "aws_s3_bucket_public_access_block",
    "aws_s3_bucket_server_side_encryption_configuration",
    "aws_s3_bucket_versioning",
    "aws_s3_object",
    "aws_secretsmanager_secret",
    "aws_secretsmanager_secret_rotation",
    "aws_secretsmanager_secret_version",
    "aws_security_group",
    "aws_security_group_rule",
    "aws_securityhub_account",
    "aws_securityhub_product_subscription",
    "aws_securityhub_standards_subscription",
    "aws_service_discovery_private_dns_namespace",
    "aws_service_discovery_service",
    "aws_sfn_state_machine",
    "aws_sns_topic",
    "aws_sns_topic_policy",
    "aws_sns_topic_subscription",
    "aws_sqs_queue",
    "aws_sqs_queue_redrive_policy",
    "aws_ssm_association",
    "aws_ssm_document",
    "aws_ssm_parameter",
    "aws_subnet",
    "aws_vpc",
    "aws_vpc_endpoint",
    "aws_vpc_security_group_egress_rule",
    "aws_vpc_security_group_ingress_rule",
    "aws_wafv2_web_acl",
    "aws_wafv2_web_acl_association",
    "aws_wafv2_web_acl_logging_configuration",
})

# IAM-management resource types used ONLY by this lint's own fixtures (to
# exercise role-attribution / attachment shapes) and NOT present in the
# real `terraform/` tree. Grandfathered so those fixtures don't trip the
# resource fail-closed, but kept OUT of the prod-derived
# RESOURCE_UNCHECKED_ACK above.
#
# TRADEOFF (cr #2997): the lint can't tell a fixture scan from a real-tree
# scan, so these are grandfathered on every scan. Today that only bites
# during fixture runs — the CI scan roots at `terraform/`, where none of
# these types are present, so nothing is actually skipped there. The
# erosion only becomes real if one is later ADDED to production needing a
# new IAM action, at which point the check won't force the
# map-or-grandfather decision. Accepted as low risk: they're IAM-management
# types unlikely to land in the NHP tree, and the apply role's `iam:` grants
# are broad. If one does move to production, delete it here and let the
# fail-closed force the decision (or map it in RESOURCE_ACTIONS).
_FIXTURE_SCAFFOLD_ACK: frozenset[str] = frozenset({
    "aws_iam_group",
    "aws_iam_group_policy",
    "aws_iam_policy_attachment",
    "aws_iam_role_policies_exclusive",
    "aws_iam_role_policy_attachments_exclusive",
})


# The canonical `nhp-${env}-github-actions` role is declared in
# `terraform/modules/ecr/main.tf`. Other modules (e.g.
# `terraform/modules/traefik-plugins-deploy/main.tf`) declare their own
# `aws_iam_role.github_actions` for unrelated repos. Within HCL scope each
# module's local refs resolve to its own role; the lint walks files flat
# and would otherwise conflate them. So the role-attached-resource match
# is module-scoped:
#   - same-module refs (`aws_iam_role.github_actions[?].{id,name}`) only
#     count when the file is in the canonical module's directory tree;
#   - cross-module refs via the canonical module's role-name output
#     (`module.ecr.github_actions_role_name`) count from anywhere outside
#     the canonical module.
CANONICAL_ROLE_MODULE_PATH = ("modules", "ecr")
# Indexed `[<idx>]` group covers a future count/for_each-gated role. The
# regex shape mirrors the customer-managed-policy ARN regex below.
SAME_MODULE_ROLE_REFS = (
    re.compile(r"aws_iam_role\.github_actions(?:\[[^\]]+\])?\.id\b"),
    re.compile(r"aws_iam_role\.github_actions(?:\[[^\]]+\])?\.name\b"),
)
CROSS_MODULE_ROLE_REF = "module.ecr.github_actions_role_name"
# Literal-string match for the canonical role's runtime name. The role
# is created with `name = "nhp-${var.environment}-github-actions"`
# (terraform/modules/ecr/main.tf), so a hardcoded reference is shaped
# `nhp-<env>-github-actions`. Anchor on BOTH the `nhp-` prefix and the
# `-github-actions` suffix so we credit `"nhp-prod-github-actions"`
# and `"nhp-sandbox-github-actions"` but NOT a sibling like
# `"traefik-plugins-prod-github-actions"` (declared by
# `terraform/modules/traefik-plugins-deploy/`, which has its own
# `aws_iam_role.github_actions` for that module's CI). A substring
# `in` check would false-positive on the sibling — anchor on both
# ends.
LITERAL_ROLE_NAME_PREFIX = "nhp-"
LITERAL_ROLE_NAME_SUFFIX = "-github-actions"
# AWS's default quota is 10 managed policies attached to one IAM role. Count
# every conditional attachment as present so PR linting models the maximum
# configured shape across environments, not whichever tfvars happen to be
# active in CI. This is one shared ceiling across accounts: raise it only after
# every environment account has the matching quota increase.
GITHUB_ACTIONS_MANAGED_POLICY_ATTACHMENT_LIMIT = 10


# Set by `main()` from the `--terraform-root` argument so
# `_in_canonical_module` can compare path components relative to the
# scan root. Without this, an absolute terraform_root that itself
# contains a `modules/ecr` segment (e.g.
# `/home/foo/modules/ecr/some-other-repo/terraform`) would classify
# every file as canonical.
_TERRAFORM_ROOT: Path | None = None


def _in_canonical_module(file: Path) -> bool:
    """True when `file` is in the canonical role's module directory tree.

    Uses path-component containment (not substring) so a sibling like
    `modules/ecr-foo/` doesn't get mistakenly attributed to the canonical
    `modules/ecr/` role. Components are computed relative to the
    `--terraform-root` so segments above the scan root can't false-
    positive.
    """
    if _TERRAFORM_ROOT is not None:
        try:
            # `file` may be relative or absolute depending on how
            # `terraform_root` was passed; resolve both so
            # `relative_to` succeeds regardless.
            relative = file.resolve().relative_to(_TERRAFORM_ROOT)
        except ValueError:
            # File isn't under the scan root — shouldn't happen in
            # practice, fall back to the absolute parts.
            relative = file
        parts = relative.parts
    else:
        parts = file.parts
    needle = CANONICAL_ROLE_MODULE_PATH
    return any(
        parts[i : i + len(needle)] == needle for i in range(len(parts) - len(needle) + 1)
    )


def _attached_to_github_actions(file: Path, role_ref: str) -> bool:
    in_canonical = _in_canonical_module(file)
    if in_canonical and any(p.search(role_ref) for p in SAME_MODULE_ROLE_REFS):
        return True
    if not in_canonical and CROSS_MODULE_ROLE_REF in role_ref:
        return True
    # Literal-string match: a hardcoded role name like
    # `"nhp-prod-github-actions"` won't match either HCL ref above, so
    # the attachment would silently miss the coverage union. The repo
    # doesn't use literal role names today; this fence is forward-
    # looking. Anchor on BOTH `nhp-` prefix and `-github-actions`
    # suffix so a sibling module's role like
    # `"traefik-plugins-prod-github-actions"` doesn't silently get
    # credited to the canonical NHP role.
    unquoted = unquote(role_ref)
    if (
        isinstance(unquoted, str)
        and unquoted.startswith(LITERAL_ROLE_NAME_PREFIX)
        and unquoted.endswith(LITERAL_ROLE_NAME_SUFFIX)
    ):
        return True
    return False


def count_github_actions_managed_policy_attachments(
    parsed: list[tuple[Path, dict[str, Any]]],
) -> int:
    """Return the canonical role's worst-case managed-policy attachment count.

    A simple conditional ``count`` with numeric branches uses the larger branch,
    so ``var.enabled ? 1 : 0`` counts as one. Every other computed count fails
    closed above the limit rather than guessing at arithmetic. This relies on
    python-hcl2 rendering expressions as ``${...}``; the real-HCL integration
    test fences that parser contract so a dependency change fails loud.
    Environment-gated bindings are intentionally treated as enabled: the quota
    must hold for every environment represented by the shared module. It is a
    conservative union, not a constraint solver: mutually exclusive attachment
    blocks are summed. Keep attachment cardinalities literal or a simple
    numeric-branch ternary.
    """

    def instance_count(body: dict[str, Any]) -> int:
        count = body.get("count")
        if isinstance(count, int):
            return max(count, 0)
        if isinstance(count, str):
            ternary = re.fullmatch(
                r"\$\{[^?]+\?\s*(\d+)\s*:\s*(\d+)\s*\}", count
            )
            if ternary:
                return max(int(ternary.group(1)), int(ternary.group(2)))
            return GITHUB_ACTIONS_MANAGED_POLICY_ATTACHMENT_LIMIT + 1
        for_each = body.get("for_each")
        if isinstance(for_each, dict):
            return len(for_each)
        if for_each is not None:
            return GITHUB_ACTIONS_MANAGED_POLICY_ATTACHMENT_LIMIT + 1
        return 1

    total = 0
    for file, rtype, _name, body in iter_resources(parsed):
        if not isinstance(body, dict):
            continue
        if rtype == "aws_iam_role_policy_attachment":
            if _attached_to_github_actions(file, str(body.get("role", ""))):
                total += instance_count(body)
        elif rtype == "aws_iam_policy_attachment":
            roles = body.get("roles")
            if isinstance(roles, list) and any(
                _attached_to_github_actions(file, str(role)) for role in roles
            ):
                total += instance_count(body)
        elif rtype == "aws_iam_role_policy_attachments_exclusive":
            if _attached_to_github_actions(file, str(body.get("role_name", ""))):
                policy_arns = body.get("policy_arns")
                # A computed list cannot be bounded statically, so fail closed
                # above the quota. Literal lists get their exact cardinality.
                # Provider guidance forbids mixing this authoritative resource
                # with singular attachments for the same role; if mixed, the
                # conservative counter sums both and fails safe.
                policy_count = (
                    len(policy_arns)
                    if isinstance(policy_arns, list)
                    else GITHUB_ACTIONS_MANAGED_POLICY_ATTACHMENT_LIMIT + 1
                )
                total += instance_count(body) * policy_count
    return total


def collect_role_actions(
    parsed: list[tuple[Path, dict[str, Any]]],
) -> set[str]:
    """Build the union of action globs allowed by every policy attached to
    `aws_iam_role.github_actions`. Surfaces a warning for any policy
    attached to that role that the parser couldn't decode — the alternative
    (silent empty-set) would turn a future legitimate refactor (e.g.,
    extracting a policy body via `data.aws_iam_policy_document`) into a
    silent false-positive on the actions that policy granted.
    """

    # Map (in_canonical_module, name) -> action set, for resolution via
    # aws_iam_role_policy_attachment. Scoping by canonical-vs-not
    # disambiguates a future bare-name collision — an attachment in the
    # canonical module resolves to its same-module declaration, not to
    # a same-named declaration in a sibling module.
    managed_policies: dict[tuple[bool, str], set[str]] = {}
    seen_managed_names: dict[str, list[Path]] = {}
    actions: set[str] = set()
    # Normalized to (file, arn-string) — one entry per ARN regardless
    # of which attachment shape it came from. Lets the resolver below
    # be shape-agnostic.
    attachments: list[tuple[Path, str]] = []

    for file, rtype, name, body in iter_resources(parsed):
        if rtype == "aws_iam_role_policy":
            role_ref = str(body.get("role", ""))
            # An `aws_iam_role_policy` in a non-canonical-module file
            # with `role = var.<X>` may be plumbing the canonical role
            # through a child-module variable — a shape
            # `_attached_to_github_actions` can't resolve, leaving a
            # silent coverage gap. The `var.` regex is intentionally
            # over-broad; false positives are sibling modules legitimately
            # using their own role var, where the warn is informational.
            if (
                not _in_canonical_module(file)
                and re.search(r"\bvar\.[A-Za-z_]\w*", role_ref)
            ):
                warn(
                    f"aws_iam_role_policy.{name}: role attribute is "
                    f"`{role_ref.strip('${}')}` (a `var.X` reference in a "
                    f"non-canonical-module file). If this variable is "
                    f"plumbing the canonical "
                    f"`module.ecr.github_actions_role_name` through, the "
                    f"lint can't follow it and the policy's actions will "
                    f"silently miss the coverage union. Either move the "
                    f"policy declaration up to the canonical module's "
                    f"caller or extend the lint to resolve module-input "
                    f"variables.",
                    file=file,
                )
            if _attached_to_github_actions(file, role_ref):
                policy = extract_policy_body(body.get("policy"))
                if policy is None and body.get("policy") is not None:
                    warn_undecodable_policy(
                        file,
                        "aws_iam_role_policy",
                        name,
                        finding=(
                            "the actions it grants will be excluded from "
                            "the coverage union"
                        ),
                    )
                if policy_has_mixed_effects(policy):
                    # Limited to inline role policies because shared
                    # managed policies (e.g. permission boundaries)
                    # legitimately mix effects.
                    warn(
                        f"aws_iam_role_policy.{name}: policy mixes `Allow` "
                        f"and `Deny` effects — the lint counts only the "
                        f"Allow grants and ignores the Deny narrowing, so "
                        f"the role's effective permission set may be "
                        f"narrower than what the lint sees. If a Deny is "
                        f"the only thing fencing a sensitive action, "
                        f"extend .github/scripts/_tf_lint_lib.py to model "
                        f"the subtraction.",
                        file=file,
                    )
                actions |= statement_actions(policy)
        elif rtype == "aws_iam_policy":
            # Track bare-name declarations across modules so a future
            # collision still lands loud (the resolution-side keying
            # handles correctness; this warn handles human confusion).
            seen_managed_names.setdefault(name, []).append(file)
            in_canonical = _in_canonical_module(file)
            managed_policies[(in_canonical, name)] = statement_actions(
                extract_policy_body(body.get("policy"))
            )
        elif rtype == "aws_iam_role_policy_attachment":
            role_ref = str(body.get("role", ""))
            if _attached_to_github_actions(file, role_ref):
                attachments.append((file, str(body.get("policy_arn", ""))))
        elif rtype == "aws_iam_policy_attachment":
            # Legacy multi-target attachment: takes a `roles = [...]`
            # array (also `users`/`groups`). Deprecated by AWS but
            # still valid HCL. Walk the role list and credit the
            # actions if the canonical role appears.
            roles = body.get("roles")
            if isinstance(roles, list) and any(
                _attached_to_github_actions(file, str(r)) for r in roles
            ):
                attachments.append((file, str(body.get("policy_arn", ""))))
        elif rtype == "aws_iam_role_policy_attachments_exclusive":
            # Newer terraform-aws-provider resource that *replaces* a
            # role's `aws_iam_role_policy_attachment` blocks: takes
            # `role_name` and `policy_arns = [...]`. Walk the ARN list
            # the same as the singular shape — a future migration to
            # this resource shouldn't silently drop the role's
            # coverage union.
            role_ref = str(body.get("role_name", ""))
            if _attached_to_github_actions(file, role_ref):
                policy_arns = body.get("policy_arns")
                if isinstance(policy_arns, list):
                    for arn in policy_arns:
                        attachments.append((file, str(arn)))
        elif rtype == "aws_iam_role_policies_exclusive":
            # Declares the *exhaustive* set of inline-policy NAMES on
            # a role — it doesn't carry the policy body. The bodies
            # still come from `aws_iam_role_policy` blocks, which the
            # lint already covers. This shape doesn't carry actions,
            # so it can't drop them; skip silently.
            pass

    for name, files in seen_managed_names.items():
        if len(files) > 1:
            warn(
                f"aws_iam_policy.{name} is declared in multiple modules "
                f"({', '.join(str(f) for f in files)}) — attachments are "
                f"resolved per-module, but the bare-name collision is "
                f"confusing. Disambiguate the resource name.",
                file=files[0],
            )

    # Resolve managed-policy ARNs back to their action sets. The optional
    # `[<idx>]` group covers `count`/`for_each`-instantiated policies — e.g.,
    # `aws_iam_policy.plugin_bucket_write[0].arn`. Without the index
    # match, count-gated policies' actions get silently dropped.
    customer_managed_re = re.compile(
        r"aws_iam_policy\.([A-Za-z0-9_]+)(?:\[[^\]]+\])?\.arn"
    )
    # Any `arn:aws<partition>:iam::<account>:policy/...` literal that we
    # can't resolve to an in-tree `aws_iam_policy` resource — the policy
    # body lives outside the terraform tree (AWS-managed when account is
    # `aws`, cross-account customer-managed otherwise). Either way the
    # lint can't enumerate its actions and warns so a future PR can't
    # silently delete coverage. Partition wildcard covers `aws-us-gov`
    # and `aws-cn` (no GovCloud/China presence today, but silent-miss
    # class avoidance is the design posture).
    #
    # The account portion accepts only well-formed AWS shapes: a
    # 12-digit literal, the `aws` literal (AWS-managed policies), or
    # an HCL `${...}` interpolation. A malformed placeholder like
    # `arn:aws:iam::ACCOUNT_PLACEHOLDER:policy/foo` falls through both
    # `customer_managed_re` and this regex and hits the unresolved-
    # attachment warn below — the right outcome for a typo'd ARN.
    external_arn_re = re.compile(
        r"arn:aws[a-z-]*:iam::(?:[0-9]{12}|aws|\$\{[^}]+\}):policy/"
    )
    # `policy_arn = module.<m>.<output>` — a cross-module module-output
    # reference. The lint doesn't walk module outputs, so the actions
    # are excluded from the coverage union. Recognize it explicitly
    # rather than letting it fall through to the "unrecognized policy_arn"
    # warn (which would imply a typo) — it's a known-unresolvable shape
    # and the operator should know the difference.
    cross_module_arn_re = re.compile(
        r"\bmodule\.([A-Za-z0-9_]+)\.([A-Za-z0-9_]+)\b"
    )
    for file, arn in attachments:
        m = customer_managed_re.search(arn)
        if m:
            # `aws_iam_policy.X.arn` is a same-module HCL reference —
            # resolve it against the same-module declaration only. A
            # miss here is either a dangling reference (terraform
            # itself would fail apply) or a genuine cross-module use
            # written wrong (cross-module refs go through
            # `module.X.<output>` in HCL, never `aws_iam_policy.X.arn`
            # directly). Either way: warn and skip rather than papering
            # with the other module's actions — fail-closed matches
            # the rest of the lint's posture.
            in_canonical = _in_canonical_module(file)
            key = (in_canonical, m.group(1))
            if key in managed_policies:
                actions |= managed_policies[key]
                continue
            warn(
                f"aws_iam_role_policy_attachment references "
                f"aws_iam_policy.{m.group(1)}, but no declaration exists "
                f"in the {'canonical' if in_canonical else 'sibling'} "
                f"module that contains this attachment. The actions it "
                f"would grant are excluded from the coverage union — fix "
                f"the dangling reference, declare the policy in the same "
                f"module, or extend the lint to handle cross-module refs.",
                file=file,
            )
            continue
        if external_arn_re.search(arn):
            warn(
                f"aws_iam_role_policy_attachment binds an out-of-tree "
                f"managed policy ({arn.strip('${}')}) to "
                f"`aws_iam_role.github_actions`; the lint can't enumerate "
                f"its actions and will exclude them from the coverage "
                f"union. If this attachment is the only grant for a data "
                f"source's required action, the lint will report a false "
                f"missing-grant — curate the actions or refactor to an "
                f"inline policy. See docs/runbooks/terraform-prod-drift.md.",
                file=file,
            )
            continue
        m = cross_module_arn_re.search(arn)
        if m:
            warn(
                f"aws_iam_role_policy_attachment binds a cross-module "
                f"module-output managed policy "
                f"(module.{m.group(1)}.{m.group(2)}) to "
                f"`aws_iam_role.github_actions`; the lint doesn't walk "
                f"module outputs and will exclude its actions from the "
                f"coverage union. If this attachment is the only grant "
                f"for a data source's required action, the lint will "
                f"report a false missing-grant — declare the policy in "
                f"the canonical role's module or extend the lint to "
                f"resolve module outputs.",
                file=file,
            )
            continue
        # Neither in-tree (`aws_iam_policy.X.arn`) nor a recognized
        # external ARN shape — likely a typo or placeholder.
        warn(
            f"aws_iam_role_policy_attachment references a policy_arn "
            f"({arn.strip('${}')}) the lint can't recognize. Expected "
            f"forms: `aws_iam_policy.X.arn` (same-module HCL ref), "
            f"`module.X.Y` (cross-module module-output ref), or "
            f"`arn:aws*:iam::(<12-digit account>|aws|${{...}}):policy/<name>` "
            f"(external). Fix the reference or extend "
            f"`.github/scripts/check-terraform-iam-coverage.py`.",
            file=file,
        )

    return actions


def action_allowed(required: str, allowed: Iterable[str]) -> bool:
    """IAM glob match — `cloudformation:*` matches `cloudformation:DescribeStacks`,
    `*` matches anything. Case-insensitive — `allowed` is lowercased at
    insertion in `statement_actions`; lowercase the required action here too.

    `fnmatch.fnmatchcase` is a slight superset of IAM glob semantics — it
    also accepts `[seq]` and `[!seq]` character classes, which IAM does
    not. Real IAM action names never contain `[`, so the gap is academic;
    flagging here so a future reader doesn't waste time wondering. (cr
    round 10 widened from `[seq]` to also call out the negated form.)"""
    rl = required.lower()
    for grant in allowed:
        if fnmatch.fnmatchcase(rl, grant):
            return True
    return False


def _required_actions(
    entry: ActionSpec, body: Any
) -> list[str]:
    """Resolve a DATA_SOURCE_ACTIONS / RESOURCE_ACTIONS map value to a
    concrete action list.

    A static `list[str]` entry passes through; a body-aware `Callable`
    entry is invoked with `body`, coerced to `{}` when it isn't a dict.
    The coercion matters for the resource side: `iter_resources` (unlike
    `iter_data_sources`) doesn't coerce a malformed block's body, so a
    callable that indexes `body` would otherwise crash. `_check_consumer_type`
    calls this for every consumer (data source or resource), so the callable
    path has a single implementation to test.
    """
    if callable(entry):
        return entry(body if isinstance(body, dict) else {})
    return list(entry)


def _check_consumer_type(
    consumers: list[tuple[Path, str, str, Any]],
    action_map: dict[str, ActionSpec],
    unchecked_ack: frozenset[str] | None,
    role_actions: set[str],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Check one class of `aws_*` consumers against its action map.

    Data sources and resources share this: for each consumer whose type is
    in `action_map`, `_required_actions` resolves the required actions and
    each is checked against `role_actions`; a gap lands in `findings`. A
    type NOT in the map is `unmapped` (fail-closed) — UNLESS `unchecked_ack`
    lists it, in which case it's grandfathered (skipped).

    The grandfather tier is the only thing that differs between the two
    consumer classes, and it's pure data: data sources pass
    `unchecked_ack=None` (every unmapped type fails closed); resources pass
    the grandfather set (RESOURCE_UNCHECKED_ACK + the fixture-scaffold set).
    Returns `(findings, unmapped)`.
    """
    findings: list[dict[str, Any]] = []
    unmapped: list[dict[str, Any]] = []
    for file, ctype, name, body in consumers:
        if not ctype.startswith("aws_"):
            continue
        if ctype in action_map:
            required = _required_actions(action_map[ctype], body)
            missing = [a for a in required if not action_allowed(a, role_actions)]
            if missing:
                findings.append(
                    {
                        "file": str(file),
                        "type": ctype,
                        "name": name,
                        "missing_actions": missing,
                    }
                )
        elif unchecked_ack is not None and ctype in unchecked_ack:
            # Grandfathered — the apply role already covers its CRUD; the
            # action set just isn't re-derived here yet. Skip, don't flag.
            continue
        else:
            # Fail-closed: a type in no map. For resources this is the
            # #2996-class catch; for data sources the #1323-class catch.
            unmapped.append({"file": str(file), "type": ctype, "name": name})
    return findings, unmapped


def main() -> int:
    epilog = (
        "Exit codes: 0 = clean; 1 = a data source/resource is missing a "
        "required action or the canonical role exceeds its managed-policy "
        "attachment quota; 2 = a data source type is not in DATA_SOURCE_ACTIONS, "
        "or a resource type is in neither RESOURCE_ACTIONS nor "
        "RESOURCE_UNCHECKED_ACK (fail-closed — add the entry in the same PR); "
        "3 = internal error."
    )
    ap = argparse.ArgumentParser(epilog=epilog)
    ap.add_argument(
        "--terraform-root",
        default=str(Path(__file__).resolve().parent.parent.parent / "terraform"),
        help="Path to the terraform/ directory to scan.",
    )
    ap.add_argument(
        "--json",
        action="store_true",
        help="Emit findings as JSON instead of human-readable text.",
    )
    args = ap.parse_args()

    # The grandfather set the resource check consults: prod-derived types
    # plus the fixture-only scaffolding types.
    grandfathered = RESOURCE_UNCHECKED_ACK | _FIXTURE_SCAFFOLD_ACK
    # A resource type must be either action-checked (RESOURCE_ACTIONS) or
    # grandfathered, never both — an entry in both lets the grandfather skip
    # shadow the action check. Fail fast with exit 3 (internal error) rather
    # than silently preferring one.
    overlap = set(RESOURCE_ACTIONS) & grandfathered
    if overlap:
        error(
            f"resource type(s) appear in BOTH RESOURCE_ACTIONS and the "
            f"grandfather set (RESOURCE_UNCHECKED_ACK / _FIXTURE_SCAFFOLD_ACK): "
            f"{', '.join(sorted(overlap))}. Remove them from the grandfather "
            f"set — a mapped type is not grandfathered."
        )
        return 3

    root = Path(args.terraform_root)
    if not root.is_dir():
        error(f"terraform root not found: {root}")
        return 3
    # Resolve to absolute so `Path.relative_to` works regardless of
    # whether the caller passed a relative or absolute path.
    global _TERRAFORM_ROOT
    _TERRAFORM_ROOT = root.resolve()

    parsed = parse_tf_files(root)
    role_actions = collect_role_actions(parsed)
    helper_invoke_scope_error = None
    if root.resolve() == Path(__file__).resolve().parents[2] / "terraform":
        helper_invoke_scope_error = terraform_helper_invoke_scope_error(parsed)
    managed_policy_attachment_count = count_github_actions_managed_policy_attachments(
        parsed
    )
    attachment_quota_exceeded = (
        managed_policy_attachment_count
        > GITHUB_ACTIONS_MANAGED_POLICY_ATTACHMENT_LIMIT
    )

    # Sanity check the module-scoping coupling. If `CANONICAL_ROLE_MODULE_PATH`
    # ever drifts from where `aws_iam_role.github_actions` actually lives,
    # `_in_canonical_module` returns False everywhere and `role_actions`
    # ends up empty — every data source then flags as missing actions
    # (load-bearing fail-loud). Better: detect the empty-attribution case
    # specifically and surface the coupling, so the next maintainer doesn't
    # have to reverse-engineer the failure cascade.
    # Cache the data-source and resource lists: `iter_*` are generators,
    # and the empty-attribution diagnostic + the findings loops each walk
    # them. Materializing once means the parse tree is walked once instead
    # of twice — negligible perf today, code hygiene for when the tree
    # grows.
    data_sources = list(iter_data_sources(parsed))
    resources = list(iter_resources(parsed))
    # Only *mapped* consumers need a grant, so only they can distinguish a
    # genuine empty-attribution (canonical role module path drifted) from
    # a legitimately grant-free tree. Unmapped/grandfathered blocks don't
    # require role_actions, so they can't feed this diagnostic.
    has_grant_needing_consumer = any(
        dtype.startswith("aws_") and DATA_SOURCE_ACTIONS.get(dtype)
        for _, dtype, _, _ in data_sources
    ) or any(rtype in RESOURCE_ACTIONS for _, rtype, _, _ in resources)
    if has_grant_needing_consumer and not role_actions:
        error(
            "collect_role_actions returned an empty action set, but the "
            "terraform tree contains data sources or resources that "
            "require IAM grants. The canonical role's module path may have "
            "moved from `terraform/modules/ecr/` — update "
            "`CANONICAL_ROLE_MODULE_PATH` in "
            ".github/scripts/check-terraform-iam-coverage.py."
        )
        return 3

    # Data sources have no grandfather tier (unchecked_ack=None → every
    # unmapped type fails closed); resources pass the grandfather set.
    findings, unmapped = _check_consumer_type(
        data_sources, DATA_SOURCE_ACTIONS, None, role_actions
    )
    resource_findings, resource_unmapped = _check_consumer_type(
        resources, RESOURCE_ACTIONS, grandfathered, role_actions
    )

    if args.json:
        json.dump(
            {
                "findings": findings,
                "unmapped": unmapped,
                "resource_findings": resource_findings,
                "resource_unmapped": resource_unmapped,
                "helper_invoke_scope_error": helper_invoke_scope_error,
                "role_actions": sorted(role_actions),
                "managed_policy_attachment_count": managed_policy_attachment_count,
                "managed_policy_attachment_limit": GITHUB_ACTIONS_MANAGED_POLICY_ATTACHMENT_LIMIT,
            },
            sys.stdout,
            indent=2,
        )
        sys.stdout.write("\n")
    else:
        # Pin unmapped errors to the lint script (the file that needs the new
        # entry), not to the .tf file containing the block — the .tf is
        # fine, the lint just doesn't know about that type. The .tf path +
        # block name is in the message body so the author knows the use site.
        lint_script = Path(".github/scripts/check-terraform-iam-coverage.py")
        if helper_invoke_scope_error:
            error(
                helper_invoke_scope_error,
                file=Path("terraform/modules/ecr/main.tf"),
            )
        for u in unmapped:
            error(
                f"data source `{u['type']}.{u['name']}` (used at "
                f"{u['file']}) is not in DATA_SOURCE_ACTIONS — add an "
                f"entry with the IAM actions terraform-aws-provider's "
                f"read function calls.",
                file=lint_script,
            )
        for u in resource_unmapped:
            error(
                f"resource `{u['type']}.{u['name']}` (declared at "
                f"{u['file']}) is in neither RESOURCE_ACTIONS nor "
                f"RESOURCE_UNCHECKED_ACK. Either map it in RESOURCE_ACTIONS "
                f"(with the IAM actions its create/update/delete calls make) "
                f"or grandfather it in RESOURCE_UNCHECKED_ACK — but ONLY "
                f"after confirming the apply role already covers its CRUD "
                f"(e.g. this type already applies cleanly elsewhere in the "
                f"tree). An unverified grandfather claim silently re-opens "
                f"the exact gap this check exists to close. Same PR, "
                f"fail-closed.",
                file=lint_script,
            )
        for f in findings:
            error(
                f"data source `{f['type']}.{f['name']}` requires IAM "
                f"action(s) not granted to `aws_iam_role.github_actions`: "
                f"{', '.join(f['missing_actions'])}. Add an "
                f"`aws_iam_role_policy` or extend an existing policy. "
                f"NOTE: this lint does not verify Resource scope — apply "
                f"least-privilege ARN scoping manually.",
                file=Path(f["file"]),
            )
        for f in resource_findings:
            error(
                f"resource `{f['type']}.{f['name']}` requires IAM action(s) "
                f"not granted to `aws_iam_role.github_actions`: "
                f"{', '.join(f['missing_actions'])}. The apply role can't "
                f"create/update/destroy it — extend the `terraform_apply_*` "
                f"policy in terraform/modules/ecr/main.tf. NOTE: this lint "
                f"does not verify Resource scope — apply least-privilege ARN "
                f"scoping manually.",
                file=Path(f["file"]),
            )
        if attachment_quota_exceeded:
            error(
                f"`aws_iam_role.github_actions` declares "
                f"{managed_policy_attachment_count} worst-case managed-policy "
                f"attachments, exceeding AWS's default per-role quota of "
                f"{GITHUB_ACTIONS_MANAGED_POLICY_ATTACHMENT_LIMIT}. Consolidate "
                f"existing grants or raise the account quota before adding the "
                f"attachment. Keep attachment count/for_each cardinalities "
                f"statically bounded; computed or mutually exclusive shapes "
                f"are conservatively over-counted.",
                file=Path("terraform/modules/ecr/main.tf"),
            )
        total_gaps = len(findings) + len(resource_findings)
        total_unmapped = len(unmapped) + len(resource_unmapped)
        if (
            total_gaps
            or total_unmapped
            or attachment_quota_exceeded
            or helper_invoke_scope_error
        ):
            print(
                f"\nterraform IAM coverage check: FAILED "
                f"({total_gaps} gap(s), {total_unmapped} unmapped, "
                f"{int(attachment_quota_exceeded)} attachment-quota violation(s))",
                file=sys.stderr,
            )
        else:
            print("terraform IAM coverage check: OK")

    if unmapped or resource_unmapped:
        return 2
    if findings or resource_findings:
        return 1
    if attachment_quota_exceeded:
        return 1
    if helper_invoke_scope_error:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
