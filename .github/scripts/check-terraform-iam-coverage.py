#!/usr/bin/env python3
"""check-terraform-iam-coverage.py

Class-A drift detector (#1324). Asserts every `data "aws_*"` block in the
terraform configuration has matching IAM actions granted somewhere in the
`aws_iam_role.github_actions` role's policy set.

Why this exists
===============

#1323: `data "aws_cloudformation_stack" "website_api"` was added to
`terraform/main.tf` and gated on a prod-only tfvar. Sandbox `terraform plan`
never refreshed the data source (count = 0), so the missing
`cloudformation:DescribeStacks` + `cloudformation:GetTemplate` grants on
`nhp-prod-github-actions` were invisible until prod-promote tried the
refresh. This lint catches the same class statically — at PR time, no AWS
credentials needed (#1121's privesc gate stays closed).

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
- Resource-ARN scope. The lint only checks action names, not whether the
  Resource glob covers the data source's target. Tightening this is
  follow-up work.

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
DataSourceActions = list[str] | Callable[[dict[str, Any]], list[str]]


def _route53_zone_actions(body: dict[str, Any]) -> list[str]:
    """`aws_route53_zone` requires the extra `route53:ListTagsForResource`
    action when the `tags` filter argument is set; the basic action
    suffices otherwise.
    """
    actions = ["route53:ListHostedZones"]
    if "tags" in body:
        actions.append("route53:ListTagsForResource")
    return actions


DATA_SOURCE_ACTIONS: dict[str, DataSourceActions] = {
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
    # internal/service/ec2/availability_zones_data_source.go calls
    # ec2:DescribeAvailabilityZones.
    "aws_availability_zones": ["ec2:DescribeAvailabilityZones"],
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
}

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


def main() -> int:
    epilog = (
        "Exit codes: 0 = clean; 1 = at least one data source missing required "
        "actions; 2 = at least one data source has a type not in "
        "DATA_SOURCE_ACTIONS (fail-closed — add the entry in the same PR); "
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

    # Sanity check the module-scoping coupling. If `CANONICAL_ROLE_MODULE_PATH`
    # ever drifts from where `aws_iam_role.github_actions` actually lives,
    # `_in_canonical_module` returns False everywhere and `role_actions`
    # ends up empty — every data source then flags as missing actions
    # (load-bearing fail-loud). Better: detect the empty-attribution case
    # specifically and surface the coupling, so the next maintainer doesn't
    # have to reverse-engineer the failure cascade.
    # Cache the data-source list: `iter_data_sources` is a generator,
    # and the empty-attribution diagnostic + the findings loop both
    # walk it. Materializing once means the parse tree is walked once
    # instead of twice — negligible perf today, code hygiene for when
    # the tree grows.
    data_sources = list(iter_data_sources(parsed))
    has_data_sources = any(
        dtype.startswith("aws_") and DATA_SOURCE_ACTIONS.get(dtype)
        for _, dtype, _, _ in data_sources
    )
    if has_data_sources and not role_actions:
        error(
            "collect_role_actions returned an empty action set, but the "
            "terraform tree contains data sources that require IAM "
            "grants. The canonical role's module path may have moved "
            "from `terraform/modules/ecr/` — update "
            "`CANONICAL_ROLE_MODULE_PATH` in "
            ".github/scripts/check-terraform-iam-coverage.py."
        )
        return 3

    findings: list[dict[str, Any]] = []
    unmapped: list[dict[str, Any]] = []

    for file, dtype, name, body in data_sources:
        if not dtype.startswith("aws_"):
            continue
        if dtype not in DATA_SOURCE_ACTIONS:
            unmapped.append({"file": str(file), "type": dtype, "name": name})
            continue
        # Each entry is either a static `list[str]` or a body-aware
        # `Callable[[dict], list[str]]`. Dispatch in one place so
        # adding a new body-aware data source doesn't grow this loop.
        entry = DATA_SOURCE_ACTIONS[dtype]
        required = entry(body) if callable(entry) else list(entry)
        missing = [a for a in required if not action_allowed(a, role_actions)]
        if missing:
            findings.append(
                {
                    "file": str(file),
                    "type": dtype,
                    "name": name,
                    "missing_actions": missing,
                }
            )

    if args.json:
        json.dump(
            {
                "findings": findings,
                "unmapped": unmapped,
                "role_actions": sorted(role_actions),
            },
            sys.stdout,
            indent=2,
        )
        sys.stdout.write("\n")
    else:
        # Pin unmapped errors to the lint script (the file that needs the new
        # entry), not to the .tf file containing the data source — the .tf
        # is fine, the lint just doesn't know about that data source type.
        # The path to .tf + data source name is in the message body so the
        # author knows where the use site is.
        lint_script = Path(".github/scripts/check-terraform-iam-coverage.py")
        for u in unmapped:
            error(
                f"data source `{u['type']}.{u['name']}` (used at "
                f"{u['file']}) is not in DATA_SOURCE_ACTIONS — add an "
                f"entry with the IAM actions terraform-aws-provider's "
                f"read function calls.",
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
        if findings or unmapped:
            print(
                f"\nterraform IAM coverage check: FAILED ({len(findings)} gap(s), "
                f"{len(unmapped)} unmapped)",
                file=sys.stderr,
            )
        else:
            print("terraform IAM coverage check: OK")

    if unmapped:
        return 2
    if findings:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
