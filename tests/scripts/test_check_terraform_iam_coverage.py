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
