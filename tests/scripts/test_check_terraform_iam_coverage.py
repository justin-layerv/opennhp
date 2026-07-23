#!/usr/bin/env python3
"""Unit tests for check-terraform-iam-coverage.py's resource-coverage
internals — the branches the exit-code fixtures under
tests/lints/terraform-prod-drift/ can't reach:

- the shared `_required_actions` dispatch — callable entries and the
  non-dict body coercion (no shipped RESOURCE_ACTIONS entry is a callable,
  so no exit-code fixture exercises this), and
- the RESOURCE_ACTIONS / RESOURCE_UNCHECKED_ACK disjointness guard, whose
  positive path (overlap -> exit 3) needs the module maps mutated, which a
  terraform-tree fixture cannot do, and
- the canonical role's managed-policy attachment ceiling, including the
  fail-closed path for an unbounded computed cardinality.

Fixtures cover terraform-tree behavior; these cover the script's own
invariants. Run directly (wired into build-and-push.yml): `python3 <this>`.
"""

from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from io import StringIO
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = REPO_ROOT / ".github" / "scripts" / "check-terraform-iam-coverage.py"


def _load_module():
    # The script has a hyphenated filename (not importable by name); load
    # it by path. Its own top-level `sys.path.insert(... parent ...)` makes
    # the sibling `_tf_lint_lib` import resolve, and loading under a
    # non-`__main__` name means the `if __name__ == "__main__"` guard at the
    # bottom does not execute.
    spec = importlib.util.spec_from_file_location(
        "check_terraform_iam_coverage", SCRIPT_PATH
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


IAM = _load_module()


class TerraformHelperInvokeScope(unittest.TestCase):
    def policy(self):
        return {
            "Statement": [
                {
                    "Sid": "OtherApplyActions",
                    "Effect": "Allow",
                    "Action": ["lambda:CreateFunction"],
                    "Resource": "*",
                },
                {
                    "Sid": "TerraformHelperInvoke",
                    "Effect": "Allow",
                    "Action": [IAM.HELPER_INVOKE_ACTION],
                    "Resource": sorted(IAM.HELPER_INVOKE_RESOURCES),
                },
            ]
        }

    def test_exact_helper_scope_passes(self):
        self.assertIsNone(IAM._terraform_helper_invoke_scope_error(self.policy()))

    def test_broad_or_second_invoke_grant_fails(self):
        for field, value in (
            ("Action", "*"),
            ("Action", "lambda:*"),
            ("Action", "lambda:Invoke*"),
            ("NotAction", "lambda:DeleteFunction"),
        ):
            policy = self.policy()
            policy["Statement"][0][field] = value
            with self.subTest(field=field):
                self.assertIsNotNone(IAM._terraform_helper_invoke_scope_error(policy))

    def test_missing_extra_or_duplicate_helper_fails(self):
        for mutation in ("missing", "extra", "duplicate"):
            policy = self.policy()
            resources = policy["Statement"][1]["Resource"]
            if mutation == "missing":
                resources.pop()
            elif mutation == "extra":
                resources.append("arn:aws:lambda:us-east-2:123:function:authority")
            else:
                resources[0] = resources[1]
            with self.subTest(mutation=mutation):
                self.assertIsNotNone(IAM._terraform_helper_invoke_scope_error(policy))

    def semantic_read_policy(self):
        return {
            "Statement": [
                {
                    "Sid": sid,
                    "Effect": "Allow",
                    "Action": [IAM.HELPER_INVOKE_ACTION],
                    "Resource": [resource],
                }
                for sid, resource in IAM.SEMANTIC_READ_INVOKE_RESOURCES.items()
            ]
        }

    def test_exact_semantic_read_scope_passes(self):
        self.assertIsNone(
            IAM._terraform_semantic_read_invoke_scope_error(self.semantic_read_policy())
        )

    def test_missing_broad_or_wrong_semantic_read_fails(self):
        mutations = (
            "missing",
            "broad",
            "unqualified",
            "wrong-resource",
            "extra-field",
        )
        for mutation in mutations:
            policy = self.semantic_read_policy()
            if mutation == "missing":
                policy["Statement"].pop()
            elif mutation == "broad":
                policy["Statement"][0]["Action"] = "lambda:*"
            elif mutation == "unqualified":
                policy["Statement"][0]["Resource"][0] = policy["Statement"][0][
                    "Resource"
                ][0].removesuffix(":$LATEST")
            elif mutation == "wrong-resource":
                policy["Statement"][0]["Resource"][0] = policy["Statement"][0][
                    "Resource"
                ][0].replace("-relay-status:", "-key-validator:")
            else:
                policy["Statement"][0]["Condition"] = {}
            with self.subTest(mutation=mutation):
                self.assertIsNotNone(
                    IAM._terraform_semantic_read_invoke_scope_error(policy)
                )

    def test_real_tree_scope_covers_exact_invocation_inventory(self):
        root = REPO_ROOT / "terraform"
        keygen = "${aws_lambda_function.keygen.function_name}"
        etcd = "${aws_lambda_function.etcd_tls[0].function_name}"
        parsed = IAM.parse_tf_files(root)
        self.assertIsNone(IAM.terraform_helper_invoke_scope_error(parsed))
        actual = {
            (str(file.relative_to(root)), name, body.get("function_name"))
            for file, rtype, name, body in IAM.iter_resources(parsed)
            if rtype == "aws_lambda_invocation"
        }
        # Read-time data.aws_lambda_invocation calls are intentionally outside
        # this deploy-time inventory. The same real-tree scope check above
        # separately requires terraform_read to grant the qualified
        # relay-status:$LATEST target. Converting it to a resource makes it
        # enter this exact set and requires an explicit apply-role decision.
        self.assertEqual(
            actual,
            {
                ("modules/ac/main.tf", "keygen", keygen),
                ("modules/compute/main.tf", "keygen", keygen),
                ("modules/data/main.tf", "etcd_tls", etcd),
                ("modules/nhp-keypair/main.tf", "keygen", keygen),
                ("modules/relay-identity/main.tf", "keygen", keygen),
                ("modules/relay-identity/main.tf", "publish_public_key", keygen),
            },
        )

    def test_main_surfaces_helper_scope_failure(self):
        original_argv = sys.argv
        try:
            sys.argv = [
                "check-terraform-iam-coverage",
                "--terraform-root",
                str(REPO_ROOT / "terraform"),
            ]
            stderr = StringIO()
            with (
                patch.object(
                    IAM,
                    "terraform_helper_invoke_scope_error",
                    return_value="helper scope broadened",
                ),
                redirect_stderr(stderr),
            ):
                self.assertEqual(IAM.main(), 1)
            self.assertIn("helper scope broadened", stderr.getvalue())
        finally:
            sys.argv = original_argv


class ShippedConstants(unittest.TestCase):
    def test_maps_are_disjoint(self):
        """A resource type must be action-checked OR grandfathered, never
        both — RESOURCE_ACTIONS must not overlap either grandfather set (the
        invariant the overlap guard enforces at runtime)."""
        grandfathered = IAM.RESOURCE_UNCHECKED_ACK | IAM._FIXTURE_SCAFFOLD_ACK
        overlap = set(IAM.RESOURCE_ACTIONS) & grandfathered
        self.assertEqual(overlap, set(), f"types in both maps: {sorted(overlap)}")

    def test_prod_and_fixture_ack_disjoint(self):
        """The fixture-scaffold set holds types NOT in the prod tree; a type
        in both sets means a fixture-only entry leaked into (or a prod type
        was misfiled under) the wrong set."""
        both = IAM.RESOURCE_UNCHECKED_ACK & IAM._FIXTURE_SCAFFOLD_ACK
        self.assertEqual(both, frozenset(), f"types in both ack sets: {sorted(both)}")

    def test_alarm_family_stays_mapped(self):
        """Regression fence for #2996: the composite alarm and its siblings
        stay action-checked, not silently grandfathered."""
        grandfathered = IAM.RESOURCE_UNCHECKED_ACK | IAM._FIXTURE_SCAFFOLD_ACK
        for rtype in (
            "aws_cloudwatch_composite_alarm",
            "aws_cloudwatch_metric_alarm",
            "aws_cloudwatch_dashboard",
        ):
            self.assertIn(rtype, IAM.RESOURCE_ACTIONS)
            self.assertNotIn(rtype, grandfathered)

    def test_relay_dmz_resource_families_stay_mapped(self):
        """The PR1 DMZ resource types are action-checked, not grandfathered."""
        grandfathered = IAM.RESOURCE_UNCHECKED_ACK | IAM._FIXTURE_SCAFFOLD_ACK
        for rtype in (
            "aws_route",
            "aws_vpc_peering_connection",
            "aws_vpc_peering_connection_options",
            "aws_route53_resolver_query_log_config",
            "aws_route53_resolver_query_log_config_association",
            "aws_route53_resolver_firewall_domain_list",
            "aws_route53_resolver_firewall_rule_group",
            "aws_route53_resolver_firewall_rule",
            "aws_route53_resolver_firewall_rule_group_association",
            "aws_route53_resolver_firewall_config",
        ):
            self.assertIn(rtype, IAM.RESOURCE_ACTIONS)
            self.assertNotIn(rtype, grandfathered)

        self.assertIn("ec2:ReplaceRoute", IAM.RESOURCE_ACTIONS["aws_route"])
        self.assertIn(
            "iam:CreateServiceLinkedRole",
            IAM.RESOURCE_ACTIONS["aws_route53_resolver_query_log_config_association"],
        )

    def test_connector_foundation_resource_families_stay_mapped(self):
        """The foundation's new default-SG and Redis RBAC resource types
        remain action-checked instead of silently grandfathered."""
        grandfathered = IAM.RESOURCE_UNCHECKED_ACK | IAM._FIXTURE_SCAFFOLD_ACK
        for rtype in (
            "aws_default_security_group",
            "aws_elasticache_user",
            "aws_elasticache_user_group",
            "aws_elasticache_serverless_cache",
        ):
            self.assertIn(rtype, IAM.RESOURCE_ACTIONS)
            self.assertNotIn(rtype, grandfathered)

        self.assertIn(
            "ec2:RevokeSecurityGroupEgress",
            IAM.RESOURCE_ACTIONS["aws_default_security_group"],
        )
        self.assertIn(
            "elasticache:CreateUserGroup",
            IAM.RESOURCE_ACTIONS["aws_elasticache_user_group"],
        )
        self.assertEqual(
            [
                "elasticache:CreateServerlessCache",
                "elasticache:ModifyServerlessCache",
                "elasticache:DeleteServerlessCache",
                "elasticache:DescribeServerlessCaches",
                "elasticache:AddTagsToResource",
                "elasticache:RemoveTagsFromResource",
                "elasticache:ListTagsForResource",
            ],
            IAM.RESOURCE_ACTIONS["aws_elasticache_serverless_cache"],
        )


class RequiredActionsDispatch(unittest.TestCase):
    """The shared `_required_actions` dispatch. All shipped RESOURCE_ACTIONS
    entries are static lists (the tag trio is unconditional under
    default_tags — see the map comment), so the callable path and its
    non-dict body coercion have no exit-code fixture and are covered here.
    """

    def test_static_list_passthrough(self):
        # Returns a fresh list, not the map's own object (caller must not
        # be able to mutate the map through the result).
        original = ["a:B", "c:D"]
        result = IAM._required_actions(original, {"anything": 1})
        self.assertEqual(result, ["a:B", "c:D"])
        self.assertIsNot(result, original)

    def test_callable_receives_body(self):
        seen = {}

        def entry(body):
            seen["body"] = body
            return ["svc:Wide"] if body.get("flag") else ["svc:Narrow"]

        self.assertEqual(IAM._required_actions(entry, {"flag": True}), ["svc:Wide"])
        self.assertEqual(seen["body"], {"flag": True})

    def test_callable_non_dict_body_coerced_to_empty(self):
        # iter_resources can surface a non-dict body for a malformed block;
        # the dispatch must coerce to {} so a body-indexing callable
        # doesn't crash (the `else {}` branch, otherwise untested).
        received = {}

        def entry(body):
            received["body"] = body
            return ["svc:Action"]

        IAM._required_actions(entry, "not-a-dict")
        self.assertEqual(received["body"], {})


class ManagedPolicyAttachmentQuota(unittest.TestCase):
    def _count(self, *resources):
        parsed = [
            (
                Path("terraform/modules/ecr/main.tf"),
                {"resource": list(resources)},
            )
        ]
        original_root = IAM._TERRAFORM_ROOT
        try:
            IAM._TERRAFORM_ROOT = Path("terraform").resolve()
            return IAM.count_github_actions_managed_policy_attachments(parsed)
        finally:
            IAM._TERRAFORM_ROOT = original_root

    def test_counts_conditional_bindings_as_worst_case(self):
        original_root = IAM._TERRAFORM_ROOT
        original_argv = sys.argv
        try:
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                module = root / "modules" / "ecr"
                module.mkdir(parents=True)
                attachments = "\n".join(
                    f'''resource "aws_iam_role_policy_attachment" "p{i}" {{
  count      = var.enabled ? 1 : 0
  role       = aws_iam_role.github_actions.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}}'''
                    for i in range(11)
                )
                (module / "main.tf").write_text(attachments)
                IAM._TERRAFORM_ROOT = root.resolve()
                parsed = IAM.parse_tf_files(root)
                self.assertEqual(
                    IAM.count_github_actions_managed_policy_attachments(parsed), 11
                )
                stderr = StringIO()
                sys.argv = [
                    "check-terraform-iam-coverage",
                    "--terraform-root",
                    str(root),
                ]
                with redirect_stderr(stderr):
                    self.assertEqual(IAM.main(), 1)
                self.assertIn(
                    "11 worst-case managed-policy attachments", stderr.getvalue()
                )
        finally:
            IAM._TERRAFORM_ROOT = original_root
            sys.argv = original_argv

    def test_condition_integer_does_not_change_ternary_cardinality(self):
        count = self._count(
            {
                "aws_iam_role_policy_attachment": {
                    "comparison_literal": {
                        "count": "${var.max_azs >= 3 ? 1 : 0}",
                        "role": "${aws_iam_role.github_actions.name}",
                        "policy_arn": "arn:aws:iam::aws:policy/ReadOnlyAccess",
                    }
                }
            }
        )
        self.assertEqual(count, 1)

    def test_arithmetic_count_fails_closed(self):
        count = self._count(
            {
                "aws_iam_role_policy_attachment": {
                    "arithmetic": {
                        "count": "${3 * var.multiplier}",
                        "role": "${aws_iam_role.github_actions.name}",
                        "policy_arn": "arn:aws:iam::aws:policy/ReadOnlyAccess",
                    }
                }
            }
        )
        self.assertGreater(count, IAM.GITHUB_ACTIONS_MANAGED_POLICY_ATTACHMENT_LIMIT)

    def test_nested_ternary_count_fails_closed(self):
        count = self._count(
            {
                "aws_iam_role_policy_attachment": {
                    "nested_ternary": {
                        "count": "${var.a ? (var.b ? 2 : 1) : 0}",
                        "role": "${aws_iam_role.github_actions.name}",
                        "policy_arn": "arn:aws:iam::aws:policy/ReadOnlyAccess",
                    }
                }
            }
        )
        self.assertGreater(count, IAM.GITHUB_ACTIONS_MANAGED_POLICY_ATTACHMENT_LIMIT)

    def test_unbounded_for_each_fails_closed(self):
        count = self._count(
            {
                "aws_iam_role_policy_attachment": {
                    "unbounded": {
                        "for_each": "${var.policy_arns}",
                        "role": "${aws_iam_role.github_actions.name}",
                        "policy_arn": "${each.value}",
                    }
                }
            }
        )
        self.assertGreater(count, IAM.GITHUB_ACTIONS_MANAGED_POLICY_ATTACHMENT_LIMIT)

    def test_counts_literal_for_each_map(self):
        count = self._count(
            {
                "aws_iam_role_policy_attachment": {
                    "literal_map": {
                        "for_each": {"first": "policy-a", "second": "policy-b"},
                        "role": "${aws_iam_role.github_actions.name}",
                        "policy_arn": "${each.value}",
                    }
                }
            }
        )
        self.assertEqual(count, 2)

    def test_counts_integer_legacy_and_exclusive_shapes(self):
        count = self._count(
            {
                "aws_iam_role_policy_attachment": {
                    "integer_count": {
                        "count": 3,
                        "role": "${aws_iam_role.github_actions.name}",
                        "policy_arn": "arn:aws:iam::aws:policy/ReadOnlyAccess",
                    }
                }
            },
            {
                "aws_iam_policy_attachment": {
                    "legacy_multi_role": {
                        "roles": [
                            "${aws_iam_role.github_actions.name}",
                            "${aws_iam_role.other.name}",
                        ],
                        "policy_arn": "arn:aws:iam::aws:policy/SecurityAudit",
                    }
                }
            },
            {
                "aws_iam_role_policy_attachments_exclusive": {
                    "literal_list": {
                        # Arithmetic-only fixture: two authoritative resources
                        # for one role are not a supported Terraform pattern.
                        "count": 2,
                        "role_name": "${aws_iam_role.github_actions.name}",
                        "policy_arns": ["policy-a", "policy-b"],
                    }
                }
            },
        )
        # 3 counted instances + 1 legacy policy + (2 instances * 2 policies).
        self.assertEqual(count, 8)

    def test_computed_exclusive_list_fails_closed(self):
        count = self._count(
            {
                "aws_iam_role_policy_attachments_exclusive": {
                    "computed_list": {
                        "role_name": "${aws_iam_role.github_actions.name}",
                        "policy_arns": "${var.policy_arns}",
                    }
                }
            }
        )
        self.assertGreater(count, IAM.GITHUB_ACTIONS_MANAGED_POLICY_ATTACHMENT_LIMIT)


class OverlapGuard(unittest.TestCase):
    def test_overlap_exits_3(self):
        """Positive path of the disjointness guard: a mapped type that also
        appears in the grandfather set must fail main() with exit 3
        (internal error) rather than let the grandfather skip shadow the
        action check. Unreachable by fixtures — needs the module constants
        mutated, so it lives here."""
        mapped = next(iter(IAM.RESOURCE_ACTIONS))
        original_ack = IAM.RESOURCE_UNCHECKED_ACK
        original_argv = sys.argv
        try:
            IAM.RESOURCE_UNCHECKED_ACK = frozenset(original_ack | {mapped})
            with tempfile.TemporaryDirectory() as tmp:
                # The guard runs before the tree is parsed, so an empty
                # (but valid) --terraform-root reaches it and returns 3.
                sys.argv = ["check-terraform-iam-coverage", "--terraform-root", tmp]
                self.assertEqual(IAM.main(), 3)
        finally:
            IAM.RESOURCE_UNCHECKED_ACK = original_ack
            sys.argv = original_argv


if __name__ == "__main__":
    unittest.main()
