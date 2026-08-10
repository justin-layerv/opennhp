#!/usr/bin/env python3
"""Every `python3 -m unittest tests.scripts.X` in a workflow must resolve.

Deleting a test suite is a normal thing to do. Deleting it while a workflow
still names it is not, and it fails in the worst possible place: unittest's
loader turns the missing module into a synthetic failing test, so the step
exits 1 with `ModuleNotFoundError` and every LATER step in that job never
runs. One stale reference silently disables the rest of a lint job.

Observed 2026-08-10: #3799 removed the attended UDP proof, deleting seven
modules under tests/scripts/ and trimming 29 lines from
validate-workflows.yml — but leaving the step that ran them. main went red on
the very next push, and the failure named `test_udp_proof_runtime_evidence`
rather than the change that orphaned it:

    ModuleNotFoundError: No module named 'tests.scripts.test_udp_proof_runtime_evidence'
    Ran 7 tests in 0.001s
    FAILED (errors=7)

Cheap to state, cheap to check, and it fails on the PR that does the deleting
instead of on main afterwards.

Known limits, stated because a fence with a silent blind spot is the thing
this exists to prevent:

- Only inline `run:` bodies are inspected. A `tests.scripts.X` reached through
  a composite/reusable action, through a checked-in shell script invoked from
  `run:`, or built by matrix/env interpolation is invisible here. The recurring
  failure came from a literal inline `python3 -m unittest`, which is what this
  covers.
- Conversely, a `run:` body is one opaque string to the YAML parser, so the
  match is on its text: a module named in a SHELL comment or an `echo` inside
  `run:` counts as a reference. For the existence check that is harmless (it
  demands a named module exist). For the ordering check it is sharper — an
  earlier step that merely mentions `tests.scripts.something` without running
  it would be treated as the first referencing step and trip a false ordering
  failure. Red, not silent-green, and unlikely, but real: dropping the
  offending mention or moving the fence above it is the fix, not deleting the
  assertion.
- A malformed workflow makes `yaml.safe_load` raise and errors this test out
  for an unrelated reason. Acceptable, arguably desirable — but it does mean
  this fence's health is coupled to every workflow parsing cleanly.
"""

from __future__ import annotations

import re
import shutil
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github/workflows"

# Dotted module references passed to `python3 -m unittest`. The tail is fully
# dotted rather than a single segment so a nested `tests.scripts.pkg.test_x`
# resolves to tests/scripts/pkg/test_x.py instead of being mis-read as the
# module `pkg`. A path-style reference needs no fence — the shell already
# fails loudly on a missing file.
_MODULE_RE = re.compile(r"\btests\.scripts\.([A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)*)")

# Both extensions: GitHub accepts either, and a workflow this fence silently
# skipped would be the same blind spot it exists to close.
_WORKFLOW_GLOB = "*.y*ml"

# The step that runs this fence, and the workflow it lives in.
_FENCE_WORKFLOW = "validate-workflows.yml"
_FENCE_MODULE = "tests.scripts.test_workflow_python_modules_exist"


def _resolves(dotted: str, base: "Path | None" = None) -> bool:
    """True if `dotted` names something `unittest` could actually load.

    `unittest` accepts a class or method target — `tests.scripts.test_foo`,
    `tests.scripts.test_foo.MyTest`, and `tests.scripts.test_foo.MyTest.test_x`
    are all valid — and a dotted string alone cannot say where the module ends
    and the class begins. Requiring the WHOLE tail to be a file would report a
    perfectly good `Class.method` target as missing: a false red naming a path
    that was never supposed to exist.

    Resolution is therefore in two stages, and the second is deliberately
    narrow — see the inline comments. Accepting *any* resolvable prefix would
    be simpler and wrong: once a subpackage exists, a deleted
    `subpkg.test_gone` resolves via `subpkg/__init__.py` and the fence reports
    the very thing it was built to catch as present.
    """
    parts = dotted.split(".")
    base = base or ROOT / "tests" / "scripts"

    # The whole path as a module or a runnable package — the common case, and
    # the only shape in which a bare package is a legitimate target.
    whole = base.joinpath(*parts)
    if whole.with_suffix(".py").is_file() or (whole / "__init__.py").is_file():
        return True

    # Otherwise the tail must be a Class[.method] suffix on a real module. Two
    # constraints, and both matter:
    #
    #   - the prefix must be a MODULE (`x.py`), never a package. Accepting a
    #     package prefix reopens the hole this fence exists for: with a
    #     `tests/scripts/subpkg/__init__.py` present, a reference to a DELETED
    #     `subpkg.test_gone` would resolve via `subpkg` and report present.
    #   - the first leftover segment must look like a class (leading capital),
    #     which is what actually distinguishes `module.Class` from
    #     `package.module` in the dotted string.
    for stop in range(len(parts) - 1, 0, -1):
        if not base.joinpath(*parts[:stop]).with_suffix(".py").is_file():
            continue
        return parts[stop][:1].isupper()
    return False


def _ordering_problem(parsed: object) -> "str | None":
    """Describe why the fence is not first among tests.scripts.* steps, if so.

    Pure and parsed-input-only so synthetic workflows can exercise it — the
    real file is the thing protected, but the assertion logic deserves its own
    coverage rather than being verified solely by the tree it runs against.
    """
    jobs = (parsed or {}).get("jobs") or {} if isinstance(parsed, dict) else {}

    def runs(step: object) -> str:
        return step["run"] if isinstance(step, dict) and isinstance(step.get("run"), str) else ""

    # Scoped to the fence's OWN job. The hazard is intra-job — a failing step
    # skips later steps in that job only — so a tests.scripts.* step in another
    # job is none of this fence's business, and asserting over every job would
    # fail a legitimate addition elsewhere for no protective gain.
    hosts = [
        name
        for name, job in jobs.items()
        if any(_FENCE_MODULE in runs(step) for step in ((job or {}).get("steps") or []))
    ]
    if len(hosts) != 1:
        return f"expected exactly one job to run {_FENCE_MODULE}; found {hosts}"

    job_name = hosts[0]
    steps = (jobs[job_name] or {}).get("steps") or []
    referencing = [step for step in steps if _MODULE_RE.search(runs(step))]
    if _FENCE_MODULE not in runs(referencing[0]):
        return (
            f"in job {job_name!r}, a tests.scripts.* step runs before this fence; "
            "move the fence above it or it can be skipped by the very failure it reports"
        )
    return None


def _run_scripts(node: object) -> "list[str]":
    """Every `run:` body in a parsed workflow.

    Scanning the parsed tree rather than the raw text is deliberate: comments
    are not in it. Scanning raw text matches prose — this fence's own first
    draft failed on a placeholder module name written inside a YAML comment
    two lines above the step it documented.
    """
    found: list[str] = []
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "run" and isinstance(value, str):
                found.append(value)
            else:
                found.extend(_run_scripts(value))
    elif isinstance(node, list):
        for item in node:
            found.extend(_run_scripts(item))
    return found


class WorkflowPythonModulesExistTest(unittest.TestCase):
    def test_every_referenced_tests_scripts_module_exists(self) -> None:
        missing: list[str] = []
        seen = 0
        for workflow in sorted(WORKFLOWS.glob(_WORKFLOW_GLOB)):
            parsed = yaml.safe_load(workflow.read_text())
            for script in _run_scripts(parsed):
                for module in _MODULE_RE.findall(script):
                    seen += 1
                    if not _resolves(module):
                        missing.append(f"{workflow.name} -> tests.scripts.{module}")

        # A regex that stops matching would make this vacuously green, which is
        # the same silent-pass failure the fence exists to prevent.
        self.assertGreater(seen, 0, "no tests.scripts.* references found — has the regex rotted?")
        self.assertEqual(
            [],
            sorted(set(missing)),
            "workflow references a tests/scripts module that does not exist; "
            "delete the reference in the same change as the file",
        )

    def test_this_fence_runs_before_any_other_tests_scripts_step(self) -> None:
        """Placement is load-bearing, so it is asserted rather than intended.

        A missing module makes its own step exit 1, and every later step in
        that job is then skipped — including this fence. Sitting after another
        `tests.scripts.*` step, it would be preempted by exactly the raw
        ModuleNotFoundError it exists to translate, and the clear message would
        never print.
        """
        workflow = WORKFLOWS / _FENCE_WORKFLOW
        self.assertTrue(
            workflow.is_file(),
            f"{_FENCE_WORKFLOW} not found — if it was renamed, update "
            "_FENCE_WORKFLOW so this assertion keeps protecting the fence",
        )
        self.assertIsNone(_ordering_problem(yaml.safe_load(workflow.read_text())))


class OrderingProblemTest(unittest.TestCase):
    """Synthetic coverage for the placement logic itself.

    The real workflow is what the assertion protects, but running only against
    it means a refactor could break the detection and still look green — the
    tree happens to be correctly ordered.
    """

    @staticmethod
    def _wf(*jobs: "tuple[str, list[str]]") -> dict:
        return {
            "jobs": {
                name: {"steps": [{"run": run} for run in runs]} for name, runs in jobs
            }
        }

    def test_fence_first_in_its_job_is_clean(self) -> None:
        wf = self._wf(("lint", [f"python3 -m unittest {_FENCE_MODULE}", "python3 -m unittest tests.scripts.test_other"]))
        self.assertIsNone(_ordering_problem(wf))

    def test_earlier_referencing_step_is_reported(self) -> None:
        wf = self._wf(("lint", ["python3 -m unittest tests.scripts.test_other", f"python3 -m unittest {_FENCE_MODULE}"]))
        self.assertIn("runs before this fence", _ordering_problem(wf) or "")

    def test_reference_in_another_job_is_not_this_fence_s_business(self) -> None:
        wf = self._wf(
            ("lint", [f"python3 -m unittest {_FENCE_MODULE}"]),
            ("other", ["python3 -m unittest tests.scripts.test_other"]),
        )
        self.assertIsNone(_ordering_problem(wf))

    def test_missing_or_duplicated_host_job_is_reported(self) -> None:
        self.assertIn("found []", _ordering_problem(self._wf(("lint", ["echo hi"]))) or "")
        duplicated = self._wf(
            ("a", [f"python3 -m unittest {_FENCE_MODULE}"]),
            ("b", [f"python3 -m unittest {_FENCE_MODULE}"]),
        )
        self.assertIn("exactly one job", _ordering_problem(duplicated) or "")

    def test_malformed_input_does_not_raise(self) -> None:
        for parsed in (None, [], "nope", {}, {"jobs": None}, {"jobs": {"lint": None}}):
            self.assertIsInstance(_ordering_problem(parsed), (str, type(None)))


class ResolvesTest(unittest.TestCase):
    """Pin the module-vs-Class.method disambiguation, incl. the subpackage hole."""

    def setUp(self) -> None:
        self.base = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.base)
        (self.base / "test_flat.py").write_text("")
        sub = self.base / "subpkg"
        sub.mkdir()
        (sub / "__init__.py").write_text("")
        (sub / "test_present.py").write_text("")

    def test_resolution(self) -> None:
        cases = [
            ("test_flat", True, "bare module"),
            ("test_flat.SomeClass", True, "module.Class"),
            ("test_flat.SomeClass.test_x", True, "module.Class.method"),
            ("test_gone", False, "deleted flat module"),
            ("subpkg", True, "runnable package"),
            ("subpkg.test_present", True, "nested module"),
            # The hole: accepting a PACKAGE prefix would report this present.
            ("subpkg.test_gone", False, "deleted nested module"),
            ("subpkg.test_present.SomeClass", True, "nested module.Class"),
            # A lowercase leftover is a module path, not a class, so a missing
            # one must not be excused by its parent module existing.
            ("test_flat.test_nested_gone", False, "lowercase leftover is not a class"),
        ]
        for dotted, expected, label in cases:
            with self.subTest(label):
                self.assertIs(_resolves(dotted, base=self.base), expected)


if __name__ == "__main__":
    unittest.main()
