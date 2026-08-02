#!/usr/bin/env python3
"""Every normalization kind the checker can return must be applyable.

The checker decides which drift is admissible; the apply workflow carries its
own `case` allow-list of `kind:count` pairs. They are two hand-maintained lists
of the same vocabulary, and nothing kept them in sync.

So a kind could pass `plan` and then be refused at apply with

    ::error::Saved plan has an invalid normalization kind/count.

which is exactly what happened to `authority-runtime-slice-with-authority-digest`
-- three plan/apply cycles, each ~5 minutes, all reaching apply and failing on a
list the plan had no reason to consult.

This fails at unit-test speed instead.
"""

from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CHECKER = ROOT / ".github" / "scripts" / "check-control-sandbox-first-apply.py"
WORKFLOW = ROOT / ".github" / "workflows" / "control-sandbox-update.yml"

# The apply gate short-circuits on a zero count, so "none" never reaches the
# allow-list. Kinds returned only by helper paths that never populate the plan
# contract summary are likewise out of scope.
NOT_APPLY_GATED = {"none", "first-projection"}


def checker_kinds() -> set[str]:
    """Every normalization kind the checker can return.

    Scoped to the normalization dispatch by AST, not a whole-file regex: a
    file-wide scan for `return "..."` also caught unrelated helpers returning
    "prepare"/"selector", which would have demanded they be added to a gate they
    never reach.
    """
    import ast

    source = CHECKER.read_text(encoding="utf-8")
    tree = ast.parse(source)
    kinds: set[str] = set()

    # Constants named *_NORMALIZATION_KIND are kinds by definition.
    constants: dict[str, str] = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id.endswith(
                    "NORMALIZATION_KIND"
                ):
                    constants[target.id] = node.value.value
    kinds.update(constants.values())

    # Every literal or constant returned by the normalization dispatch itself.
    dispatch = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef)
        and node.name == "_check_state_normalization_drift"
    )
    for node in ast.walk(dispatch):
        if not isinstance(node, ast.Return) or node.value is None:
            continue
        if isinstance(node.value, ast.Constant) and isinstance(
            node.value.value, str
        ):
            kinds.add(node.value.value)
        elif isinstance(node.value, ast.Name) and node.value.id in constants:
            kinds.add(constants[node.value.id])

    return {kind for kind in kinds if kind not in NOT_APPLY_GATED}


def workflow_allowed_kinds() -> set[str]:
    """The kinds named in the apply gate's `case` allow-list."""
    source = WORKFLOW.read_text(encoding="utf-8")
    match = re.search(r"\n(\s*)([a-z0-9-]+:[^\n]*\))\n\s*;;\n\s*\*\)", source)
    if not match:
        raise AssertionError("apply gate allow-list not found; has it moved?")
    return {
        pattern.split(":", 1)[0]
        for pattern in match.group(2).rstrip(")").split("|")
        if ":" in pattern
    }


class ApplyAdmitsEveryCheckerKindTest(unittest.TestCase):
    def test_the_two_lists_are_not_empty(self) -> None:
        """A parse failure must not make this vacuously pass."""
        self.assertGreater(len(checker_kinds()), 3, checker_kinds())
        self.assertGreater(len(workflow_allowed_kinds()), 3)

    def test_every_checker_kind_is_applyable(self) -> None:
        missing = sorted(checker_kinds() - workflow_allowed_kinds())
        self.assertEqual(
            missing,
            [],
            "these normalization kinds pass `plan` but are refused at apply "
            f"with 'invalid normalization kind/count': {missing}. Add them to "
            "the case allow-list in control-sandbox-update.yml, and decide "
            "whether they also belong in the live-re-observation skip below.",
        )

    def test_the_composed_slice_digest_kind_is_covered(self) -> None:
        """The specific desync that cost three apply cycles."""
        self.assertIn(
            "authority-runtime-slice-with-authority-digest",
            workflow_allowed_kinds(),
        )


if __name__ == "__main__":
    unittest.main()
