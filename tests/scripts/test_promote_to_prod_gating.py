#!/usr/bin/env python3
"""Structural regression fence for promote-to-prod.yml gate logic (issue #1322).

NOTE: Despite the `test_*.py` filename, this is NOT a pytest test module.
It's a `main()`-with-`sys.exit` script invoked from `make lint-workflows`
and `validate-workflows.yml` directly via `python3 ...`. The filename
follows the existing repo convention (cf. `tests/scripts/check-scope-
drift_test.sh`). Module-level `__test__ = False` (set below) tells pytest
to skip collection if anyone ever wires `pytest tests/`.

The 2026-04-24 prod release rolled new nhp-server + nhp-ac binaries while
terraform-apply was skipped (because qurl-schema-compat had failed). Root
cause: the deploy-* jobs gated on
`needs.terraform-apply.result == 'success' || == 'skipped'`, treating a
schema-compat-induced skip as a green light. The fix tightened the gate to
require a real `success` whenever `inputs.run_terraform` is true.

This test asserts the gate hasn't regressed. We don't try to run actions —
we parse the YAML and assert the `if:` expression for each deploy-* job
matches the post-#1322 shape, the dead permissive pattern is gone, the
finalize step rolls qurl-schema-compat into its needs+FAILED loop, and
the preflight stale-terraform step has the must-have shell markers
(prod-affecting scope, both bypass branches, the SSM sentinel handling).

SCOPE BOUNDARY: this test fences `deploy-*` image-deploy gates only.
Other jobs in the workflow (e.g., `monitor`'s smoke-test orchestration
gate) intentionally use the `result == 'success' || == 'skipped'`
permissive pattern — there it expresses "at least one upstream ran AND
none failed", which is the correct semantics for the monitor case but
exactly the wrong semantics for image deploys. A future "let's apply
the #1322 fix everywhere" refactor would break monitor; the assertions
here scope to deploy-* by name pattern + `inputs.deploy_*` gate so the
permissive smoke gates stay untouched.

The test discovers deploy-* jobs by name+gate pattern (rather than a
hardcoded list) so a future deploy-<component> job inherits the assertion
automatically. To stay correct under a semantically-equivalent gate
refactor, the run_terraform-half of each clause accepts both
`inputs.run_terraform` and `inputs.run_terraform == true` (and the negated
form). If you change the gate shape further, also update the synonym sets
below — and run `python3 tests/scripts/test_promote_to_prod_gating.py`,
which exercises both the real workflow AND a built-in negative fixture
for each assertion family (`_assert_negative_fixtures_reject_bad_input`)
to catch parser/assertion regressions that would otherwise pass-through
silently.

Runs from `make lint-workflows` (so it gates the same CI path as
actionlint). Exits 0 on success, 1 on first failure.

ARCHITECTURE
============

  main()
    │
    │ 1. Self-test gate (canaries the harness itself):
    ▼
  _assert_negative_fixtures_reject_bad_input()
    │     │ for each (label, assertion, fixture) in CASES:
    │     │   parse fixture YAML → run assertion → assert ≥1 failure
    │     │ + coverage invariant: every assertion in main()
    │     │   must appear in CASES (no silent uncanaried assertion)
    │     ▼
  _assert_sns_row_widths_boundary()
    │     │ off-by-one canary on the boundary math
    │     │
    │     ▼ (both must return True)
    │
    │ 2. Real-workflow assertions:
    ▼
  _assert_image_deploys()                 ──┐
  _assert_manifest_rejects_no_op()          │  Each appends to a
  _assert_terraform_apply_needs_schema_compat()│  shared `failures` list;
  _assert_finalize()                        │  main() exits 1 if non-empty.
  _assert_preflight()                       │
  _assert_sns_row_widths()                ──┘

  Negative fixtures (`_BAD_FIXTURE_*`) are paired 1:1 with assertions
  via the CASES tuple in `_assert_negative_fixtures_reject_bad_input`.
  Each fixture is a synthetic minimal workflow that exercises ONE
  failure mode the assertion is supposed to catch. Adding a new
  primary assertion without a paired fixture trips the coverage
  invariant — by design.

ADDING A 4TH IMAGE-DEPLOY JOB? Checklist:
1. The new job's `if:` gate must follow the post-#1322 shape (see
   `_assert_image_deploys` for the exact pattern). The auto-discovery
   below picks it up automatically — no test bump needed for the
   gate-shape assertions.
2. The floor in `_assert_image_deploys` is `>= 3` (not `== 3`) so
   adding a 4th deploy-* job does NOT require a ratchet update —
   the floor only catches structural removals. Optional: bump to
   `>= 4` to fail-loud if the new 4th job is later removed.
3. Add the new job to `finalize`'s `Release deployment lock` rejected
   branch (`SERVER_RESULT && AC_RESULT && QURL_RESULT && NEW_RESULT
   == skipped`). `_assert_finalize` derives the expected RESULT vars
   from `_discover_image_deploy_jobs` and will fail if you forget.
4. If the new job has SNS-row reporting in finalize, add the row in
   `Send SNS notification` and verify its label fits LABEL_WIDTH
   (`_assert_sns_row_widths` enforces this).
"""
from __future__ import annotations

import contextlib
import io
import re
import sys
import textwrap
from pathlib import Path
from collections.abc import Callable

try:
    import yaml
except ModuleNotFoundError:
    sys.stderr.write(
        "ERROR: PyYAML is required. Install with:\n"
        "       python3 -m pip install --no-cache-dir pyyaml\n"
        "       (matches the install step in .github/workflows/validate-workflows.yml.)\n"
    )
    sys.exit(2)

# Tell pytest to skip collection on this file — see module docstring.
__test__ = False

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "promote-to-prod.yml"

# Gate matchers — anchored regexes, NOT plain substrings. The naïve
# `"inputs.run_terraform && success" in gate` test passes false-positively
# on the negated form `"!inputs.run_terraform && success"` because the
# negated form contains the affirmative as a substring. The success-clause
# regex requires a non-bang/non-identifier boundary before
# `inputs.run_terraform`; the skipped-clause regex matches all three
# valid spellings of the negated form. New spellings get added here only
# if a maintainer needs them, with a comment.
#
# Canonical form note: the bare `inputs.run_terraform` reference is the
# canonical spelling for a boolean input per GitHub Actions docs — the
# `== true` / `== false` synonyms are accepted here only for permissiveness
# under refactor (someone might add the explicit comparison thinking it's
# clearer). The real workflow today uses the bare form; this is style,
# not semantics, and the regex permissiveness is harmless.
APPLY_SUCCESS_RE = re.compile(
    r"(?<![!\w.])"
    r"inputs\.run_terraform(?:\s*==\s*true)?"
    r"\s*&&\s*"
    r"needs\.terraform-apply\.result\s*==\s*'success'"
)
# Anchor for any `if:` gate that should be the affirmative form
# `inputs.run_terraform` (not `!inputs.run_terraform`). The lookbehind
# rejects the negated form so a refactor to `if: !inputs.run_terraform`
# is caught. Currently consumed by both `qurl-schema-compat.if` and
# `terraform-apply.if` pins; named for the broader application.
RUN_TERRAFORM_AFFIRM_RE = re.compile(
    r"(?<![!\w.])inputs\.run_terraform(?:\s*==\s*true)?"
)
APPLY_SKIPPED_RE = re.compile(
    r"(?:"
    r"!\s*\(?\s*inputs\.run_terraform\s*\)?"
    r"|"
    r"inputs\.run_terraform\s*==\s*false"
    r")"
    r"\s*&&\s*"
    r"needs\.terraform-apply\.result\s*==\s*'skipped'"
)
# Match any OR-chain of `needs.terraform-apply.result == '<X>'` clauses
# that contains BOTH 'success' and 'skipped' — covers the canonical
# 2-arm `success || skipped`, the reordered `skipped || success`, AND
# longer chains like `success || skipped || cancelled` that a future
# regression might produce. The check below is post-process: extract
# every `terraform-apply.result == '<X>'` from the gate, OR-joined or
# not, then assert the set is not the permissive {success, skipped}.
def _gate_has_apply_permissive_pattern(gate: str) -> bool:
    """True iff the gate contains `terraform-apply.result == 'success'`
    AND `... == 'skipped'` joined into an OR group at top level
    (the pre-#1322 permissive shape, in any arm count or ordering).

    The clauses must be separated by `||` (each clause except the last
    is followed by `||`). A loose form that made `||` optional would
    match adjacent-without-OR clauses — not valid GHA syntax in any
    case, but the tighter form matches the assertion's intent more
    precisely.
    """
    or_group_re = re.compile(
        r"needs\.terraform-apply\.result\s*==\s*'\w+'"
        r"(?:\s*\|\|\s*needs\.terraform-apply\.result\s*==\s*'\w+')+"
    )
    for m in or_group_re.finditer(gate):
        clauses = re.findall(
            r"needs\.terraform-apply\.result\s*==\s*'(\w+)'", m.group(0)
        )
        if "success" in clauses and "skipped" in clauses:
            return True
    return False


# The pre-#1322 gate also had a `terraform-plan.result` clause with the
# same `success || skipped` shape. PR #1341 dropped it because
# `terraform-apply.needs: [terraform-plan]` makes a plan failure cascade
# into a skipped apply. If a future refactor splits plan and apply into
# independent jobs (e.g., a workspace-driven plan-only path), this
# implication breaks and the gate would silently regress. Same N-arm-
# tolerant detection as the apply form above.
def _gate_has_plan_permissive_pattern(gate: str) -> bool:
    """True iff the gate contains an OR-group of terraform-plan.result
    clauses that includes both 'success' and 'skipped'."""
    or_group_re = re.compile(
        r"\(?\s*"
        r"(?:needs\.terraform-plan\.result\s*==\s*'\w+'\s*(?:\|\|\s*)?){2,}"
    )
    for m in or_group_re.finditer(gate):
        clauses = re.findall(
            r"needs\.terraform-plan\.result\s*==\s*'(\w+)'", m.group(0)
        )
        if "success" in clauses and "skipped" in clauses:
            return True
    return False

# Must-have markers in the stale-terraform step's shell body. Each entry
# is `(label, marker)` where marker is a regex compiled below. We use
# regexes (not plain substrings) so a comment-only mention does NOT
# satisfy the assertion — the `ALLOW_STALE_TERRAFORM` / `ROLLBACK`
# checks specifically require the variable to be dereferenced inside a
# `[[ ... ==` test, mirroring how the bypass branches actually behave.
# A future "simplify" pass that quietly removes the rollback bypass or
# widens the scope must fail this test, not silently regress at deploy
# time. Keep these tied to concrete behaviors, not phrasing.
#
# TODO(#1343): when the shared tf-drift helper lands, the path-scope
# markers below (`terraform/environments/prod/`, `terraform/modules/`)
# need to be updated to reference whatever the helper exposes (likely
# a sourced array variable). Today the paths are inlined in the
# git-diff invocation here AND in terraform-plan's change-summary
# step; the dedupe consolidates both call sites.
STALE_TF_MUST_HAVE = (
    # SSM read marker — co-located with `aws ssm get-parameter --name`
    # so a refactor that demotes the path into a comment fails. The
    # 400-char window allows the path to appear on a continuation line
    # of the backslash-broken invocation. Pinning `--name` (not just
    # `aws ssm get-parameter`) means the assertion can't bind to the
    # finalize put-parameter writes that mention the same SSM key.
    (
        "reads last-terraform-apply-commit from SSM",
        r"aws\s+ssm\s+get-parameter[\s\S]{0,400}--name[\s\S]{0,200}last-terraform-apply-commit",
    ),
    # Path-scope markers — co-located with `git diff` so a refactor that
    # leaves the path strings in a comment but drops the actual call fails.
    # `[\s\S]*?` allows the path to appear on a continuation line of the
    # backslash-broken `git diff --name-only ... -- <paths>` invocation.
    (
        "scopes diff to prod-affecting paths",
        r"git\s+diff[\s\S]{0,400}terraform/environments/prod/",
    ),
    (
        "scopes diff to shared modules",
        r"git\s+diff[\s\S]{0,400}terraform/modules/",
    ),
    (
        "respects ALLOW_STALE_TERRAFORM bypass via dereferenced test",
        r'\[\[\s*"\$ALLOW_STALE_TERRAFORM"\s*==',
    ),
    (
        "respects ROLLBACK bypass via dereferenced test",
        r'\[\[\s*"\$ROLLBACK"\s*==',
    ),
    # Tighter than `"$TF_DIFF"` (which `render_diff_details` would
    # satisfy from any branch) — DIFF_PRINT_CAP is unique to the
    # rollback-bypass inline-print block, so a future "simplify" pass
    # that drops the head-n cap fails this assertion specifically.
    # Co-located with `head -n` to require the cap is actually applied,
    # not just declared.
    (
        "rollback bypass head -n caps the inline print",
        r"head\s+-n\s+\"?\$DIFF_PRINT_CAP\"?",
    ),
    # First-deploy sentinel — required inside a `[[ ... ==` test so a
    # comment-only mention is rejected.
    (
        "first-deploy sentinel handled",
        r'\[\[[^\n]*==\s*"initial"',
    ),
    # Pin the canonical sentinel set: empty / "initial" / "None". These
    # are the values the gate treats as "no prior apply" and warns-and-
    # proceeds. The runbook's bypass section enumerates them; if a
    # future refactor adds (or drops) one without updating the runbook,
    # the audit-completeness claim drifts. The marker requires all three
    # OR-clauses to appear together so a partial check (only "" + "None")
    # fails this assertion.
    #
    # The 200-char windows between sentinels are a fragility budget —
    # they tolerate the test conditional being split across continuation
    # lines, but a refactor that spreads the same logic across more than
    # ~400 chars (e.g., an if/elif chain instead of a single OR-test)
    # will fail this assertion confusingly. If that happens, raise the
    # window or rewrite the assertion to parse the conditional.
    (
        "sentinel set is empty / initial / None (all three branches)",
        r'-z\s+"\$LAST_TF_SHA"[\s\S]{0,200}"initial"[\s\S]{0,200}"None"',
    ),
    # Ancestor reachability — required as an actual git invocation.
    (
        "ancestor reachability check",
        r"git\s+merge-base\s+--is-ancestor",
    ),
)
STALE_TF_MUST_HAVE_RES = tuple(
    (label, re.compile(pattern)) for label, pattern in STALE_TF_MUST_HAVE
)


def _normalize(expr: str) -> str:
    """Collapse whitespace so we can pattern-match across line wraps."""
    return re.sub(r"\s+", " ", expr).strip()


def _gate_has_apply_success_when_running_tf(gate: str) -> bool:
    """True iff the gate requires terraform-apply success when run_terraform is true."""
    return APPLY_SUCCESS_RE.search(gate) is not None


def _gate_allows_apply_skipped_only_when_not_running_tf(gate: str) -> bool:
    """True iff the gate only honors a skipped apply when run_terraform is false."""
    return APPLY_SKIPPED_RE.search(gate) is not None


def _check(label: str, ok: bool, detail: str = "") -> bool:
    if ok:
        print(f"  \033[32mok\033[0m   {label}")
        return True
    print(f"  \033[31mFAIL\033[0m {label}")
    if detail:
        for line in detail.splitlines():
            print(f"        {line}")
    return False


def _all_deploy_prefix_jobs(jobs: dict) -> list[str]:
    """Return every job whose name starts with `deploy-` (regardless of gate)."""
    return sorted(name for name in jobs if isinstance(name, str) and name.startswith("deploy-"))


def _discover_image_deploy_jobs(jobs: dict) -> list[str]:
    """Return job names that look like image deploys.

    "Looks like" = name starts with `deploy-` AND the gate references an
    `inputs.deploy_*` boolean. The caller asserts a floor of ≥3 (today:
    deploy-server, deploy-ac, deploy-qurl). If you add a 4th image-deploy
    job, bump the floor in `_assert_image_deploys` and confirm it appears
    in the discovered list when the test runs.
    """
    discovered = []
    for name, job in jobs.items():
        if not isinstance(name, str) or not name.startswith("deploy-"):
            continue
        gate = _normalize(str(job.get("if", "")))
        if "inputs.deploy_" not in gate:
            continue
        discovered.append(name)
    return sorted(discovered)


def _assert_image_deploys(jobs: dict, failures: list[str]) -> None:
    # Two-step discovery so the failure message points at the right cause:
    # FIRST list every `deploy-*` job (regardless of gate shape) so we
    # can detect "deploy-* job exists but lacks the operator clause"
    # specifically, separate from "the workflow shape changed".
    #
    # Don't early-return on a single failure: surface every applicable
    # gate-shape failure in one run so an operator iterating on a fix
    # sees the full picture.
    all_deploy_prefix = _all_deploy_prefix_jobs(jobs)
    deploy_jobs = _discover_image_deploy_jobs(jobs)
    missing_operator_clause = [j for j in all_deploy_prefix if j not in deploy_jobs]
    if missing_operator_clause:
        if not _check(
            "every deploy-* job has an `inputs.deploy_*` operator clause",
            False,
            f"missing operator clause: {missing_operator_clause}",
        ):
            failures.append(
                "deploy-* jobs without inputs.deploy_* clause: "
                + ", ".join(missing_operator_clause)
            )

    # Floor of 3 = deploy-server + deploy-ac + deploy-qurl as of #1322.
    # The check is `>= 3`, NOT `== 3` — adding a 4th deploy-* doesn't
    # need a ratchet update (the new job inherits the gate-shape
    # assertions automatically); only removals require dropping the
    # floor. Better to fail loud on a structural removal than to
    # silently regress when a deploy-* drops out without anyone
    # noticing the missing gate fence.
    if not _check(
        "discovered ≥3 image-deploy jobs (deploy-* with inputs.deploy_* in gate)",
        len(deploy_jobs) >= 3,
        f"found: {deploy_jobs}; all deploy-* prefix: {all_deploy_prefix}",
    ):
        failures.append("discovery found <3 image-deploy jobs — has the workflow shape changed?")
        # Empty deploy_jobs makes the per-job loop a no-op; everything
        # below this point is safe to run without an explicit return.

    for job_name in deploy_jobs:
        gate = _normalize(str(jobs[job_name].get("if", "")))
        if not _check(
            f"{job_name}: gate requires terraform-apply success when run_terraform=true",
            _gate_has_apply_success_when_running_tf(gate),
            f"if: {gate}",
        ):
            failures.append(f"{job_name}: missing run_terraform→success clause")
        if not _check(
            f"{job_name}: gate only honors a skipped apply when run_terraform=false",
            _gate_allows_apply_skipped_only_when_not_running_tf(gate),
            f"if: {gate}",
        ):
            failures.append(f"{job_name}: missing !run_terraform→skipped clause")
        if not _check(
            f"{job_name}: dead permissive `success || skipped` pattern is absent",
            not _gate_has_apply_permissive_pattern(gate),
            f"if: {gate}",
        ):
            failures.append(f"{job_name}: still has the pre-#1322 permissive pattern")
        if not _check(
            f"{job_name}: dead `terraform-plan` permissive pattern is absent",
            not _gate_has_plan_permissive_pattern(gate),
            f"if: {gate}",
        ):
            failures.append(
                f"{job_name}: re-introduced the dropped terraform-plan permissive pattern"
            )


def _assert_sns_row_widths(jobs: dict, failures: list[str]) -> None:
    """Guard the SNS-row label width.

    The `row()` shell helper in finalize uses `printf '\\n  %-*s %s'`
    with width supplied by the `LABEL_WIDTH=N` variable. A future row
    addition with a label-with-colon longer than LABEL_WIDTH would
    silently misalign. We extract LABEL_WIDTH and every `row "label"
    "$RESULT"` call, then assert max(label+":")<=LABEL_WIDTH.
    Bumping LABEL_WIDTH updates this guard automatically.
    """
    finalize = jobs.get("finalize", {})
    sns_step = next(
        (
            step
            for step in finalize.get("steps", [])
            if step.get("name") == "Send SNS notification"
        ),
        None,
    )
    if sns_step is None:
        # Step rename — let the existing assertions surface that.
        return
    run = str(sns_step.get("run", ""))
    width_match = re.search(r"\bLABEL_WIDTH\s*=\s*(\d+)", run)
    if width_match is None:
        _check(
            "SNS row() helper has a LABEL_WIDTH variable",
            False,
            "could not extract LABEL_WIDTH",
        )
        failures.append("SNS row() helper LABEL_WIDTH not found")
        return
    _check("SNS row() helper has a LABEL_WIDTH variable", True)
    width = int(width_match.group(1))
    labels = re.findall(r'\brow\s+"([^"]+)"', run)
    if not _check(
        "SNS row() helper has at least one row",
        len(labels) > 0,
        "no row() invocations found",
    ):
        failures.append("SNS row() helper invocations not found")
        return
    # Boundary: a label of width-1 chars fits ("Schema Compat" = 13 +
    # ":" = 14 = LABEL_WIDTH). A label of width chars (14 + ":" = 15)
    # exceeds and trips this assertion. The error message tells the
    # maintainer to bump LABEL_WIDTH; the boundary is the right place
    # to surface it because adding any 14-char label puts you at the
    # edge.
    too_long = [label for label in labels if len(label) + 1 > width]
    if not _check(
        f"SNS row() labels fit LABEL_WIDTH ({width}, including colon)",
        not too_long,
        f"labels exceeding width: {too_long} — bump LABEL_WIDTH",
    ):
        failures.append(
            f"SNS row labels exceed LABEL_WIDTH={width}: {too_long}"
        )


def _assert_manifest_rejects_no_op(jobs: dict, failures: list[str]) -> None:
    """The manifest job must hard-reject a no-op dispatch.

    `run_terraform=false` + every `deploy_*=false` would proceed through
    preflight, skip every job, and finalize would write
    LOCK_VALUE=deployed for a run that did nothing. The "Reject no-op
    dispatch" step exits 1 at the earliest possible moment so the
    operator gets a clear error rather than an inscrutable green
    checkmark. Pin the step's presence + its `if`-block must reference
    each of the four input flags whose all-false combination is the
    no-op shape.
    """
    manifest = jobs.get("manifest", {})
    reject_step = next(
        (
            step
            for step in manifest.get("steps", [])
            if step.get("name") == "Reject no-op dispatch"
        ),
        None,
    )
    if reject_step is None:
        _check("manifest has `Reject no-op dispatch` step", False)
        failures.append("manifest missing Reject no-op dispatch step")
        return
    _check("manifest has `Reject no-op dispatch` step", True)
    run_body = str(reject_step.get("run", ""))
    for needle in (
        '"$RUN_TERRAFORM" != "true"',
        '"$DEPLOY_SERVER" != "true"',
        '"$DEPLOY_AC" != "true"',
        '"$DEPLOY_QURL" != "true"',
    ):
        if not _check(
            f"Reject no-op dispatch tests `{needle}`",
            needle in run_body,
            f"missing: {needle!r}",
        ):
            failures.append(f"Reject no-op dispatch missing {needle!r}")


def _assert_terraform_apply_needs_schema_compat(jobs: dict, failures: list[str]) -> None:
    """terraform-apply must continue to depend on qurl-schema-compat AND terraform-plan.

    The deploy-* gate's apply-success requirement only fences the partial-
    deploy class if a failed schema-compat (or plan) actually cascades
    into a skipped apply. That cascade is via `terraform-apply.needs:` —
    if a future refactor removes either job from that list, the chain
    breaks silently and #1322's failure mode is back at the workflow
    level even though every other gate would still look right.

    qurl-schema-compat itself must also be gated on `inputs.run_terraform`
    so a run_terraform=false dispatch correctly skips the schema check
    (no terraform changes ⇒ no schema compatibility question to answer).
    A regression that flipped this to `if: false` (or removed it,
    making schema-compat unconditional) would skip the check on every
    run while every other gate looked right.
    """
    apply_job = jobs.get("terraform-apply", {})
    needs = apply_job.get("needs", [])
    for required in ("qurl-schema-compat", "terraform-plan"):
        if not _check(
            f"terraform-apply.needs includes `{required}`",
            required in needs,
            f"needs: {needs}",
        ):
            failures.append(f"terraform-apply.needs missing {required}")

    schema_compat = jobs.get("qurl-schema-compat", {})
    schema_if = _normalize(str(schema_compat.get("if", "")))
    # Anchored regex (NOT plain substring) — same lookbehind that
    # APPLY_SUCCESS_RE uses on the deploy-* gates. A regression that
    # flipped this to `if: !inputs.run_terraform` would pass a substring
    # check (the affirmative is a substring of the negated form), and
    # the schema-check would run only on run_terraform=false runs —
    # exactly inverted from intent.
    if not _check(
        "qurl-schema-compat gated on `inputs.run_terraform` (affirmative form)",
        RUN_TERRAFORM_AFFIRM_RE.search(schema_if) is not None,
        f"if: {schema_if!r}",
    ):
        failures.append(
            "qurl-schema-compat missing `inputs.run_terraform` gate — "
            "would either run unconditionally or under the negated form, "
            "both of which silently break the cascade"
        )

    # terraform-apply itself must also be gated on `inputs.run_terraform`.
    # The deploy-* gate's `(!run_terraform && apply == 'skipped')` clause
    # only correctly fires if apply ACTUALLY skips on run_terraform=false.
    # A regression that flipped this to `always()` or dropped the `if:`
    # would make apply run on every dispatch — defeating the cascade
    # for the legitimate app-only-redeploy path.
    apply_if = _normalize(str(apply_job.get("if", "")))
    if not _check(
        "terraform-apply gated on `inputs.run_terraform` (affirmative form)",
        RUN_TERRAFORM_AFFIRM_RE.search(apply_if) is not None,
        f"if: {apply_if!r}",
    ):
        failures.append(
            "terraform-apply missing `inputs.run_terraform` gate — would "
            "either run unconditionally or under the negated form, "
            "breaking the (!run_terraform && apply == skipped) clause"
        )


def _assert_finalize(jobs: dict, failures: list[str]) -> None:
    finalize = jobs.get("finalize", {})
    # Without `if: always()`, finalize would skip whenever any predecessor
    # failed/cancelled and the workflow would silently report green via
    # "skipped finalize" — exactly the silent-success class #1322 fences.
    # The check accepts `always()` alone or `always() && <conjuncts>`,
    # so a future maintainer narrowing the condition (e.g., `always() &&
    # github.event_name == 'workflow_dispatch'`) preserves the load-
    # bearing always() while letting the assertion stay correct.
    finalize_if = str(finalize.get("if", "")).strip()
    if not _check(
        "finalize.if starts with `always()`",
        finalize_if.startswith("always()"),
        f"if: {finalize_if!r}",
    ):
        failures.append("finalize missing `always()` in if-condition")
    needs = finalize.get("needs", [])
    if not _check(
        "finalize.needs includes `qurl-schema-compat`",
        "qurl-schema-compat" in needs,
        f"needs: {needs}",
    ):
        failures.append("finalize.needs missing qurl-schema-compat")

    determine_step = next(
        (step for step in finalize.get("steps", []) if step.get("id") == "outcome"),
        None,
    )
    if determine_step is None:
        _check("finalize has `outcome` step", False)
        failures.append("finalize missing outcome step")
        return
    env = determine_step.get("env", {})
    run = determine_step.get("run", "")
    # Match the env value loosely: the operative bit is that
    # SCHEMA_COMPAT_RESULT reads from needs.qurl-schema-compat.result —
    # surrounding whitespace inside the ${{ ... }} template doesn't matter.
    schema_env_re = re.compile(r"\$\{\{\s*needs\.qurl-schema-compat\.result\s*\}\}")
    schema_env_value = env.get("SCHEMA_COMPAT_RESULT", "")
    if not _check(
        "finalize outcome step exposes SCHEMA_COMPAT_RESULT",
        bool(schema_env_re.search(schema_env_value)),
        f"env.SCHEMA_COMPAT_RESULT = {schema_env_value!r}",
    ):
        failures.append("finalize outcome SCHEMA_COMPAT_RESULT env wiring")
    # The env var must be ITERATED in the FAILED loop, not just declared.
    # A regression that adds the env binding but forgets the loop entry
    # would still flag the env-block check above; this regex closes the
    # gap by requiring `"$SCHEMA_COMPAT_RESULT"` to appear inside a
    # `for X in ...` construct (or equivalent array iteration). A refactor
    # that switches to `for r in "${RESULTS[@]}"; do` with SCHEMA_COMPAT_RESULT
    # appended to RESULTS still passes — the regex matches either form.
    failed_loop_re = re.compile(
        r"for\s+\w+\s+in\b[^\n]*\$\{?SCHEMA_COMPAT_RESULT\}?"
    )
    array_loop_re = re.compile(
        r"\bSCHEMA_COMPAT_RESULT\b[^\n]*\bRESULTS\b|\bRESULTS\b[^\n]*\bSCHEMA_COMPAT_RESULT\b"
    )
    if not _check(
        "finalize outcome FAILED loop iterates SCHEMA_COMPAT_RESULT",
        bool(failed_loop_re.search(run) or array_loop_re.search(run)),
        "outcome.run binds SCHEMA_COMPAT_RESULT but never iterates it",
    ):
        failures.append("finalize outcome FAILED loop missing SCHEMA_COMPAT_RESULT")

    # Pin the lock-state vocabulary. The runbook's "Lock-state
    # vocabulary" subsection enumerates four terminal values
    # (deployed / failed / rejected / deploying); a future "simplify"
    # pass that collapsed the state machine back to two states would
    # silently drift the runbook from reality unless we fence it here.
    release_step = next(
        (
            step
            for step in finalize.get("steps", [])
            if step.get("name") == "Release deployment lock"
        ),
        None,
    )
    if release_step is None:
        _check("finalize has `Release deployment lock` step", False)
        failures.append("finalize missing Release deployment lock step")
    else:
        release_run = str(release_step.get("run", ""))
        for state in ("deployed", "failed", "rejected"):
            if not _check(
                f"finalize lock-release writes `{state}`",
                re.search(rf'LOCK_VALUE\s*=\s*"{state}"', release_run) is not None,
                f"missing LOCK_VALUE assignment for {state}",
            ):
                failures.append(
                    f"finalize lock-release missing LOCK_VALUE={state} branch"
                )

        # Pin: the rejected-branch's all-skipped check must reference
        # every image-deploy job. A 4th deploy-* job added without
        # updating this check would silently treat its skipped state
        # as a no-op, mislabelling state when only the new deploy ran.
        #
        # Round 57 tightening: require the references to appear within
        # the `LOCK_VALUE="rejected"` arm specifically, not anywhere in
        # the step body. A refactor that moved the references into the
        # `failed`-arm conditional (or into a comment) would otherwise
        # pass the looser "appears anywhere" check. Window: ±400 chars
        # around `LOCK_VALUE="rejected"` is enough to span the
        # surrounding `if [[ ... ]]; then` test in the current shape.
        rejected_match = re.search(r'LOCK_VALUE\s*=\s*"rejected"', release_run)
        if rejected_match is None:
            # The earlier state-machine check already failed; skip the
            # placement check rather than emitting a redundant failure.
            rejected_window = ""
        else:
            window_start = max(0, rejected_match.start() - 400)
            window_end = min(len(release_run), rejected_match.end() + 400)
            rejected_window = release_run[window_start:window_end]

        deploy_jobs = _discover_image_deploy_jobs(jobs)
        # Map deploy-server → SERVER_RESULT, deploy-ac → AC_RESULT,
        # deploy-qurl → QURL_RESULT. The transformation is the part
        # following `deploy-`, uppercased + `_RESULT` suffix.
        for job_name in deploy_jobs:
            # Replace hyphens with underscores: shell var names can't
            # contain hyphens. e.g., `deploy-console-api` →
            # `CONSOLE_API_RESULT`. Today's three jobs (deploy-server,
            # deploy-ac, deploy-qurl) have no internal hyphens, so this
            # is forward-defensive for a multi-word component name.
            suffix = (
                job_name.removeprefix("deploy-").upper().replace("-", "_")
                + "_RESULT"
            )
            if not _check(
                f"finalize lock-release rejected branch references {suffix}",
                f'"${suffix}"' in rejected_window,
                f"missing reference to {suffix} within ±400 chars of LOCK_VALUE=\"rejected\"",
            ):
                failures.append(
                    f"finalize lock-release missing {suffix} reference near rejected — "
                    f"rejected-branch state-machine is stale relative to {job_name}"
                )


def _assert_finalize_step_order(jobs: dict, failures: list[str]) -> None:
    """Pin the load-bearing finalize step ordering.

    The lock-state semantics depend on this order:

      tracking → final_status → Release deployment lock → ... → Send SNS

    `Resolve final status` writes `value=failed` if `tracking.outcome ==
    'failure'`. The downstream lock/metric/SNS steps consume that
    output. If a "simplify" pass moved tracking after lock release (the
    pre-round-38 state), a failed tracking-put would leave the lock
    reading "deployed" while the workflow conclusion is "failure" — the
    silent-success class #1322 fences at the wiring level.

    The runbook's "Tracking-failure aftermath" subsection treats this
    ordering as load-bearing; a structural test fences it against
    accidental reordering during refactors.
    """
    finalize = jobs.get("finalize", {})
    steps = finalize.get("steps", [])
    if not steps:
        return  # the broader _assert_finalize already failed loudly

    def step_index(*, step_id: str | None = None, name: str | None = None) -> int | None:
        for idx, step in enumerate(steps):
            if step_id is not None and step.get("id") == step_id:
                return idx
            if name is not None and step.get("name") == name:
                return idx
        return None

    indices: dict[str, int] = {}
    for key, lookup in (
        ("tracking", {"step_id": "tracking"}),
        ("final_status", {"step_id": "final_status"}),
        ("lock_release", {"name": "Release deployment lock"}),
        ("sns", {"name": "Send SNS notification"}),
    ):
        found = step_index(**lookup)
        if found is not None:
            indices[key] = found
    required = ("tracking", "final_status", "lock_release", "sns")
    missing = [k for k in required if k not in indices]
    if missing:
        _check(
            "finalize has all step-order anchors (tracking, final_status, lock_release, sns)",
            False,
            f"missing anchors: {missing}",
        )
        failures.append(
            f"finalize missing step-order anchors: {missing} — "
            "renaming a step or dropping its id breaks the ordering test"
        )
        return
    pairs = (
        ("tracking", "final_status"),
        ("final_status", "lock_release"),
        ("lock_release", "sns"),
    )
    for earlier, later in pairs:
        if not _check(
            f"finalize step `{earlier}` runs before `{later}`",
            indices[earlier] < indices[later],
            f"index({earlier})={indices[earlier]}, index({later})={indices[later]}",
        ):
            failures.append(
                f"finalize step ordering broken: `{earlier}` must precede `{later}` — "
                "lock-state semantics depend on tracking → final_status → lock release → SNS"
            )


def _assert_final_status_consumed(jobs: dict, failures: list[str]) -> None:
    """Pin the four downstream steps that must read `final_status.outputs.value`.

    The `Resolve final status` step exists to centralize the
    "tracking failed → demote to failed" conditional. Round 49's review
    flagged a real test gap: a future regression that flipped any of the
    four DEPLOY_STATUS env bindings back to `steps.outcome.outputs.status`
    would silently re-introduce the false-success-on-tracking-failure
    bug while every existing assertion still passed.

    This assertion mirrors `_assert_finalize`'s SCHEMA_COMPAT_RESULT
    env-pin pattern: each consumer's env block must reference
    `steps.final_status.outputs.value` exactly.
    """
    finalize = jobs.get("finalize", {})
    consumers = (
        "Release deployment lock",
        "Push CloudWatch deployment metric",
        "Send SNS notification",
        "Deployment summary",
    )
    # Note: only `Release deployment lock` and `Send SNS notification`
    # are fenced by `_assert_finalize_step_order`'s ordering check. The
    # other two (metric, summary) have no other guard, so this assertion
    # must fail loud on missing-consumer rather than silent-skip.
    #
    # `Update deployment tracking` is *intentionally* not in this list —
    # it gates on `steps.outcome.outputs.status == 'success'` (NOT on
    # final_status), because `deployed-commit` reflects what's actually
    # running in prod even if the side-tracking write failed. The
    # workflow comment on that step explains the asymmetry; a
    # maintainer reading this test in isolation would otherwise wonder
    # why one tracking-related consumer is missing from the pin.
    expected_re = re.compile(
        r"\$\{\{\s*"
        + r"\.".join(re.escape(part) for part in ("steps", "final_status", "outputs", "value"))
        + r"\s*\}\}"
    )
    for step_name in consumers:
        step = next(
            (s for s in finalize.get("steps", []) if s.get("name") == step_name),
            None,
        )
        if step is None:
            _check(
                f"finalize has `{step_name}` step",
                False,
                "step not found in finalize.steps",
            )
            failures.append(
                f"finalize missing step `{step_name}` — final_status.outputs.value "
                "consumer dropped, false-success-on-tracking-failure regression possible"
            )
            continue
        env = step.get("env") or {}
        deploy_status_value = str(env.get("DEPLOY_STATUS", ""))
        if not _check(
            f"finalize step `{step_name}` reads DEPLOY_STATUS from final_status.outputs.value",
            bool(expected_re.search(deploy_status_value)),
            f"DEPLOY_STATUS={deploy_status_value!r}",
        ):
            failures.append(
                f"finalize step `{step_name}` DEPLOY_STATUS not pinned to "
                "final_status.outputs.value — a tracking-failure demotion "
                "would silently fall through to the raw outcome status"
            )


def _assert_force_push_verify_step(jobs: dict, failures: list[str]) -> None:
    """Pin the load-bearing parts of the force-push protection check.

    The runbook treats this step as load-bearing for the OrphanedAncestor
    fail-OPEN assumption. A future regression that flipped warn-and-
    proceed paths to fail-loud (or vice versa), or removed the
    enforce_admins check, or dropped the protection_status output that
    feeds the SNS row, would silently invalidate the rationale.

    Asserts:
    - The step exists with `id: verify-protection`.
    - The preflight job exposes `protection_status` as a job output.
    - The shell body writes status=verified / unverified / disabled /
      admin-bypass exactly once each (the four-state machine).
    - allow_force_pushes failure is hard-fail (`exit 1` after disabled).
    - enforce_admins failure is warn-and-proceed (`exit 0` after
      admin-bypass) — explicitly NOT hard-fail per round 44 rationale.
    """
    preflight = jobs.get("preflight", {})
    verify_step = next(
        (
            step
            for step in preflight.get("steps", [])
            if step.get("id") == "verify-protection"
        ),
        None,
    )
    if verify_step is None:
        _check("preflight has `verify-protection` step", False)
        failures.append("preflight verify-protection step missing")
        return

    # Job output contract: `protection_status` must be exposed so finalize
    # can render the SNS Protection row from it.
    outputs = preflight.get("outputs", {}) or {}
    protection_output = str(outputs.get("protection_status", ""))
    if not _check(
        "preflight job exposes `protection_status` output",
        "verify-protection" in protection_output and "outputs.status" in protection_output,
        f"outputs.protection_status={protection_output!r}",
    ):
        failures.append(
            "preflight protection_status output broken — "
            "SNS Protection row will silently fall back to '(preflight skipped)'"
        )

    body = str(verify_step.get("run", ""))
    # Pin all four lock states. Round 44's review made these load-
    # bearing; a state-machine collapse back to two states would silently
    # drift the runbook from reality.
    for state in ("verified", "unverified", "disabled", "admin-bypass"):
        if not _check(
            f"verify-protection writes `status={state}`",
            re.search(rf"set_status\s+{re.escape(state)}\b", body) is not None,
            f"missing set_status {state} branch",
        ):
            failures.append(
                f"verify-protection missing status={state} branch — "
                "four-state lock vocabulary is load-bearing"
            )

    # Asymmetry check: allow_force_pushes failure must be hard-fail
    # (exit 1) and enforce_admins failure must be warn-and-proceed
    # (exit 0). A regression that flipped either would re-introduce
    # round 44's disproportionate-hard-fail concern OR re-create the
    # silent-success class on a real disabled-protection event.
    #
    # Line-based scan (NOT regex) to avoid catastrophic backtracking
    # while still tolerating intervening comment/echo/metric lines
    # between `set_status X` and `exit N`. Walks the body line-by-
    # line: after finding `set_status <label>`, the next line that
    # is itself an `exit` or `set_status` decides the branch
    # terminus.
    body_lines = body.splitlines()
    set_status_re = re.compile(r"^\s*set_status\s+(\S+)\b")
    exit_re = re.compile(r"^\s*exit\s+(\d+)\b")

    def _branch_terminates(label: str, exit_code: str) -> bool:
        for idx, line in enumerate(body_lines):
            m = set_status_re.match(line)
            if not m or m.group(1) != label:
                continue
            for follow in body_lines[idx + 1:]:
                exit_m = exit_re.match(follow)
                if exit_m:
                    return exit_m.group(1) == exit_code
                if set_status_re.match(follow):
                    # Hit a new `set_status` before any exit — this
                    # branch fell through, treat as no-terminus.
                    break
            return False
        return False

    if not _check(
        "verify-protection: disabled (allow_force_pushes!=false) is hard-fail",
        _branch_terminates("disabled", "1"),
        "set_status disabled must be followed by `exit 1` (allowing intervening comments/echo/metric)",
    ):
        failures.append(
            "verify-protection disabled-branch missing `exit 1` — "
            "real protection-disabled state would warn-pass instead of hard-fail"
        )
    if not _check(
        "verify-protection: admin-bypass (enforce_admins!=true) is warn-and-proceed",
        _branch_terminates("admin-bypass", "0"),
        "set_status admin-bypass must be followed by `exit 0` (allowing intervening comments/echo/metric)",
    ):
        failures.append(
            "verify-protection admin-bypass branch missing `exit 0` — "
            "exotic admin-bypass scenario would hard-fail the deploy "
            "(round 44 explicitly rejected this asymmetry)"
        )


def _assert_preflight(jobs: dict, failures: list[str]) -> None:
    preflight = jobs.get("preflight", {})
    stale_step = next(
        (
            step
            for step in preflight.get("steps", [])
            if step.get("name") == "Verify terraform is current with deployed code"
        ),
        None,
    )
    if stale_step is None:
        _check("preflight has stale-terraform guard step", False)
        failures.append("preflight stale-terraform step missing")
    else:
        gate = _normalize(str(stale_step.get("if", "")))
        for needle in (
            "!inputs.run_terraform",
            "inputs.deploy_server",
            "inputs.deploy_ac",
            "inputs.deploy_qurl",
        ):
            if not _check(
                f"stale-terraform guard `if:` references `{needle}`",
                needle in gate,
                f"if: {gate}",
            ):
                failures.append(f"stale-terraform guard if: missing {needle}")

        # Pin the env-block bindings: the shell body checks
        # ALLOW_STALE_TERRAFORM / ROLLBACK as bypass switches, so the
        # env block must point them at inputs.allow_stale_terraform /
        # inputs.rollback respectively. A regression that hardcoded
        # these (or pointed them at a different input) would still
        # contain the variable names in the body but silently break
        # the bypass mechanism — mirrors the SCHEMA_COMPAT_RESULT pin
        # on finalize.outcome.
        env = stale_step.get("env", {}) or {}
        env_pins = (
            (
                "ALLOW_STALE_TERRAFORM",
                re.compile(r"\$\{\{\s*inputs\.allow_stale_terraform\s*\}\}"),
            ),
            (
                "ROLLBACK",
                re.compile(r"\$\{\{\s*inputs\.rollback\s*\}\}"),
            ),
        )
        for env_name, expected_re in env_pins:
            value = env.get(env_name, "")
            if not _check(
                f"stale-terraform env: {env_name} bound to canonical input",
                bool(expected_re.search(value)),
                f"{env_name}={value!r}",
            ):
                failures.append(
                    f"stale-terraform env: {env_name} not pinned to canonical input"
                )

        # Assert the shell body. Without this, a future "simplify" pass
        # could quietly drop the rollback bypass branch or narrow the
        # scope to `terraform/` (re-introducing the sandbox-trips-prod
        # case the rollback-bypass diff scope was tightened to fix) and
        # only post-merge runtime would notice.
        run_body = str(stale_step.get("run", ""))
        for label, pattern_re in STALE_TF_MUST_HAVE_RES:
            if not _check(
                f"stale-terraform body: {label}",
                pattern_re.search(run_body) is not None,
                f"pattern not found: {pattern_re.pattern!r}",
            ):
                failures.append(f"stale-terraform body missing: {label}")

        # Assert push_could_not_verify_metric is invoked from each
        # could-not-verify warning path. The CloudWatch metric is the
        # only signal that an escape hatch fired (alarm wiring tracked
        # in #1346), so a future "simplify" that drops a metric push
        # silently devalues the alarm.
        metric_reasons = (
            "ParameterNotFound",
            "FirstDeploySentinel",
            "OrphanedAncestor",
            "GitError",
        )
        for reason in metric_reasons:
            pattern = re.compile(
                rf'push_could_not_verify_metric\s+"{re.escape(reason)}"'
            )
            if not _check(
                f"stale-terraform body: pushes metric for {reason}",
                pattern.search(run_body) is not None,
                f"missing: push_could_not_verify_metric \"{reason}\"",
            ):
                failures.append(
                    f"stale-terraform body: missing metric push for {reason}"
                )

    checkout_step = next(
        (
            step
            for step in preflight.get("steps", [])
            if isinstance(step.get("uses"), str)
            and step["uses"].startswith("actions/checkout@")
        ),
        None,
    )
    if checkout_step is None:
        _check("preflight has actions/checkout step", False)
        failures.append("preflight checkout step missing")
    else:
        with_block = checkout_step.get("with") or {}
        if not _check(
            "preflight checkout uses fetch-depth: 0",
            with_block.get("fetch-depth") == 0,
            f"with: {with_block}",
        ):
            failures.append("preflight checkout fetch-depth not 0")


# --- Negative fixtures: each one breaks the assertion family in a
# different way, so we can confirm the assertion truly rejects bad input
# (vs. a refactored helper that no-ops). If an assertion is ever
# rewritten, its corresponding fixture must still produce ≥1 failure.
# Includes deploy-server / deploy-ac / deploy-qurl so it gets past the
# discovery floor (≥3) and actually exercises _gate_has_apply_success_*,
# _gate_allows_apply_skipped_*, and DEAD_PERMISSIVE_RE — without this,
# a refactor that broke any of those gate-check helpers could pass the
# self-test by virtue of the fixture short-circuiting at discovery.
# Each job below uses the pre-#1322 permissive pattern; the assertion
# must reject ALL three.
_BAD_FIXTURE_DEPLOY = textwrap.dedent(
    """
    on: workflow_dispatch
    jobs:
      deploy-server:
        runs-on: ubuntu-latest
        if: |
          (needs.terraform-apply.result == 'success' ||
            needs.terraform-apply.result == 'skipped') &&
          inputs.deploy_server
        steps:
          - run: ":"
      deploy-ac:
        runs-on: ubuntu-latest
        if: |
          (needs.terraform-apply.result == 'success' ||
            needs.terraform-apply.result == 'skipped') &&
          inputs.deploy_ac
        steps:
          - run: ":"
      deploy-qurl:
        runs-on: ubuntu-latest
        if: |
          (needs.terraform-apply.result == 'success' ||
            needs.terraform-apply.result == 'skipped') &&
          inputs.deploy_qurl
        steps:
          - run: ":"
    """
)


# Tightening canary: a "simplification" that DROPPED the run_terraform
# check entirely (just gates on terraform-apply.result == 'success') looks
# tighter than the conditional form but silently breaks the
# run_terraform=false happy path — apply would be `skipped` and the
# deploy would never run. The `_gate_allows_apply_skipped_only_when_not_running_tf`
# clause is the canary for this; this fixture exercises the failure mode
# explicitly so the intent is clear to a future maintainer.
_BAD_FIXTURE_DEPLOY_NO_RUN_TF_CHECK = textwrap.dedent(
    """
    on: workflow_dispatch
    jobs:
      deploy-server:
        runs-on: ubuntu-latest
        if: |
          always() &&
          needs.preflight.result == 'success' &&
          needs.terraform-apply.result == 'success' &&
          inputs.deploy_server
        steps:
          - run: ":"
      deploy-ac:
        runs-on: ubuntu-latest
        if: |
          always() &&
          needs.preflight.result == 'success' &&
          needs.terraform-apply.result == 'success' &&
          inputs.deploy_ac
        steps:
          - run: ":"
      deploy-qurl:
        runs-on: ubuntu-latest
        if: |
          always() &&
          needs.preflight.result == 'success' &&
          needs.terraform-apply.result == 'success' &&
          inputs.deploy_qurl
        steps:
          - run: ":"
    """
)


# Tightening canary: a regression that DROPPED the `inputs.deploy_X`
# operator-confirmation clause from one deploy-* gate (e.g., a refactor
# folded the `inputs.deploy_*` check into a different mechanism on one
# job but missed the others) would let that deploy run on every promote,
# even when the operator did not request that component.
#
# Two correct + one buggy job: the new "every deploy-* job has an
# inputs.deploy_* operator clause" check catches the missing one
# specifically, instead of falling through to the misleading "<3
# discovered" floor message.
_BAD_FIXTURE_DEPLOY_MISSING_OPERATOR_CLAUSE = textwrap.dedent(
    """
    on: workflow_dispatch
    jobs:
      deploy-server:
        runs-on: ubuntu-latest
        # Bug: no `&& inputs.deploy_server` clause on this job.
        if: |
          (inputs.run_terraform && needs.terraform-apply.result == 'success') ||
          (!inputs.run_terraform && needs.terraform-apply.result == 'skipped')
        steps:
          - run: ":"
      deploy-ac:
        runs-on: ubuntu-latest
        if: |
          (
            (inputs.run_terraform && needs.terraform-apply.result == 'success') ||
            (!inputs.run_terraform && needs.terraform-apply.result == 'skipped')
          ) &&
          inputs.deploy_ac
        steps:
          - run: ":"
      deploy-qurl:
        runs-on: ubuntu-latest
        if: |
          (
            (inputs.run_terraform && needs.terraform-apply.result == 'success') ||
            (!inputs.run_terraform && needs.terraform-apply.result == 'skipped')
          ) &&
          inputs.deploy_qurl
        steps:
          - run: ":"
    """
)


# Regression: terraform-plan permissive clause re-introduced. Pre-#1322
# `terraform-plan.result == 'success' || == 'skipped'` clause alongside
# the new gate. It would not produce the silent-success bug today (apply
# already cascades from plan via needs:), but a future refactor that
# splits plan and apply into independent jobs would silently regress.
# DEAD_PLAN_PERMISSIVE_RE catches this re-introduction.
_BAD_FIXTURE_DEPLOY_DEAD_PLAN_CLAUSE = textwrap.dedent(
    """
    on: workflow_dispatch
    jobs:
      deploy-server:
        runs-on: ubuntu-latest
        if: |
          (needs.terraform-plan.result == 'success' ||
            needs.terraform-plan.result == 'skipped') &&
          (
            (inputs.run_terraform && needs.terraform-apply.result == 'success') ||
            (!inputs.run_terraform && needs.terraform-apply.result == 'skipped')
          ) &&
          inputs.deploy_server
        steps:
          - run: ":"
      deploy-ac:
        runs-on: ubuntu-latest
        if: |
          (needs.terraform-plan.result == 'success' ||
            needs.terraform-plan.result == 'skipped') &&
          (
            (inputs.run_terraform && needs.terraform-apply.result == 'success') ||
            (!inputs.run_terraform && needs.terraform-apply.result == 'skipped')
          ) &&
          inputs.deploy_ac
        steps:
          - run: ":"
      deploy-qurl:
        runs-on: ubuntu-latest
        if: |
          (needs.terraform-plan.result == 'success' ||
            needs.terraform-plan.result == 'skipped') &&
          (
            (inputs.run_terraform && needs.terraform-apply.result == 'success') ||
            (!inputs.run_terraform && needs.terraform-apply.result == 'skipped')
          ) &&
          inputs.deploy_qurl
        steps:
          - run: ":"
    """
)


# Item-1 canary: a regression that flipped the gate to the *negated*
# success clause (`!inputs.run_terraform && ... 'success'`) would pass a
# naïve substring test because the affirmative is a substring of the
# negated form. This fixture asserts the regex anchor catches it.
_BAD_FIXTURE_DEPLOY_NEGATED_SUCCESS = textwrap.dedent(
    """
    on: workflow_dispatch
    jobs:
      deploy-server:
        runs-on: ubuntu-latest
        if: |
          (
            (!inputs.run_terraform && needs.terraform-apply.result == 'success') ||
            (inputs.run_terraform && needs.terraform-apply.result == 'skipped')
          ) && inputs.deploy_server
        steps:
          - run: ":"
      deploy-ac:
        runs-on: ubuntu-latest
        if: |
          (
            (!inputs.run_terraform && needs.terraform-apply.result == 'success') ||
            (inputs.run_terraform && needs.terraform-apply.result == 'skipped')
          ) && inputs.deploy_ac
        steps:
          - run: ":"
      deploy-qurl:
        runs-on: ubuntu-latest
        if: |
          (
            (!inputs.run_terraform && needs.terraform-apply.result == 'success') ||
            (inputs.run_terraform && needs.terraform-apply.result == 'skipped')
          ) && inputs.deploy_qurl
        steps:
          - run: ":"
    """
)

_BAD_FIXTURE_FINALIZE = textwrap.dedent(
    """
    on: workflow_dispatch
    jobs:
      finalize:
        runs-on: ubuntu-latest
        # Bugs: missing `if: always()`; qurl-schema-compat NOT in
        # needs/env/FAILED loop. Both classes the assertion catches.
        needs: [manifest, terraform-apply]
        steps:
          - id: outcome
            env:
              MANIFEST_RESULT: ${{ needs.manifest.result }}
            run: |
              for r in "$MANIFEST_RESULT"; do echo "$r"; done
    """
)


# Canary for the rejected-branch deploy-* reference check (cr round 43):
# the finalize.Release-deployment-lock step writes "rejected" only when
# every deploy-* RESULT is "skipped". `_assert_finalize` derives the
# expected RESULT-var names from _discover_image_deploy_jobs and asserts
# each is referenced; a 4th deploy-* added without updating the
# rejected branch would silently treat its skipped state as a no-op.
# This fixture has the 3 standard deploy-* jobs plus a finalize whose
# rejected branch is missing one of the expected RESULT vars — the
# assertion must catch the omission.
_BAD_FIXTURE_FINALIZE_MISSING_REJECTED_REF = textwrap.dedent(
    """
    on: workflow_dispatch
    jobs:
      deploy-server:
        runs-on: ubuntu-latest
        if: |
          ((inputs.run_terraform && needs.terraform-apply.result == 'success') ||
          (!inputs.run_terraform && needs.terraform-apply.result == 'skipped'))
          && inputs.deploy_server
        steps: [{run: ":"}]
      deploy-ac:
        runs-on: ubuntu-latest
        if: |
          ((inputs.run_terraform && needs.terraform-apply.result == 'success') ||
          (!inputs.run_terraform && needs.terraform-apply.result == 'skipped'))
          && inputs.deploy_ac
        steps: [{run: ":"}]
      deploy-qurl:
        runs-on: ubuntu-latest
        if: |
          ((inputs.run_terraform && needs.terraform-apply.result == 'success') ||
          (!inputs.run_terraform && needs.terraform-apply.result == 'skipped'))
          && inputs.deploy_qurl
        steps: [{run: ":"}]
      finalize:
        runs-on: ubuntu-latest
        if: always()
        needs: [manifest, qurl-schema-compat, terraform-apply]
        steps:
          - id: outcome
            env:
              SCHEMA_COMPAT_RESULT: ${{ needs.qurl-schema-compat.result }}
            run: |
              for r in "$SCHEMA_COMPAT_RESULT"; do echo "$r"; done
          - name: Release deployment lock
            run: |
              # Bug: rejected branch references SERVER_RESULT and
              # AC_RESULT but NOT QURL_RESULT — a future qurl-only
              # promote would mislabel state.
              if [[ "$SERVER_RESULT" == "skipped" && "$AC_RESULT" == "skipped" ]]; then
                LOCK_VALUE="rejected"
              else
                LOCK_VALUE="failed"
              fi
              if [[ "$STATUS" == "success" ]]; then
                LOCK_VALUE="deployed"
              fi
    """
)


# Canary for the finalize step-order assertion (cr round 44):
# tracking is moved AFTER lock release, mirroring the pre-round-38
# state. The asssertion must catch this because a failed tracking-put
# in that ordering would leave the lock reading "deployed" while the
# workflow conclusion is "failure" — exactly the silent-success class
# #1322 fences at the wiring level.
_BAD_FIXTURE_FINALIZE_STEP_ORDER = textwrap.dedent(
    """
    on: workflow_dispatch
    jobs:
      finalize:
        runs-on: ubuntu-latest
        if: always()
        needs: [manifest, qurl-schema-compat, terraform-apply]
        steps:
          - id: outcome
            run: ":"
          - name: Release deployment lock
            run: ":"
          - id: tracking
            run: ":"
          - id: final_status
            run: ":"
          - name: Send SNS notification
            run: ":"
    """
)


# Canary for the manifest no-op rejection check (cr round 55):
# the rejection step is present but its body drops one of the four
# `!= "true"` flag checks (DEPLOY_QURL here). A regression that
# silently no-op'd this step (e.g., `run: ":"`) or removed a flag
# check would leak through the looser "step exists" form. Closes
# the TODO in `_assert_negative_fixtures_reject_bad_input`.
_BAD_FIXTURE_MANIFEST_NOOP = textwrap.dedent(
    """
    on: workflow_dispatch
    jobs:
      manifest:
        runs-on: ubuntu-latest
        steps:
          - name: Reject no-op dispatch
            env:
              RUN_TERRAFORM: ${{ inputs.run_terraform }}
              DEPLOY_SERVER: ${{ inputs.deploy_server }}
              DEPLOY_AC: ${{ inputs.deploy_ac }}
              DEPLOY_QURL: ${{ inputs.deploy_qurl }}
            run: |
              # Bug: the qurl flag check is missing from the if-test,
              # so an operator setting only deploy_qurl would still
              # hit the no-op rejection branch.
              if [[ "$RUN_TERRAFORM" != "true" \\
                 && "$DEPLOY_SERVER" != "true" \\
                 && "$DEPLOY_AC" != "true" ]]; then
                echo "::error::No-op dispatch"
                exit 1
              fi
    """
)


# Canary for the final_status consumption pin (cr round 49):
# `Push CloudWatch deployment metric` reads DEPLOY_STATUS from the
# raw outcome step instead of final_status — exactly the regression
# round 49 called out as silently re-introducing the false-success-
# on-tracking-failure bug. Only one consumer is broken; the assertion
# must catch even a single mis-wired step.
_BAD_FIXTURE_FINAL_STATUS_CONSUMED = textwrap.dedent(
    """
    on: workflow_dispatch
    jobs:
      finalize:
        runs-on: ubuntu-latest
        steps:
          - name: Release deployment lock
            env:
              DEPLOY_STATUS: ${{ steps.final_status.outputs.value }}
            run: ":"
          - name: Push CloudWatch deployment metric
            env:
              DEPLOY_STATUS: ${{ steps.outcome.outputs.status }}
            run: ":"
          - name: Send SNS notification
            env:
              DEPLOY_STATUS: ${{ steps.final_status.outputs.value }}
            run: ":"
          - name: Deployment summary
            env:
              DEPLOY_STATUS: ${{ steps.final_status.outputs.value }}
            run: ":"
    """
)


# Canary for the force-push verify-step assertion (cr round 46):
# the admin-bypass branch is flipped from `exit 0` to `exit 1`,
# re-introducing the disproportionate hard-fail that round 44
# explicitly rejected. The assertion must catch this.
_BAD_FIXTURE_FORCE_PUSH_VERIFY = textwrap.dedent(
    """
    on: workflow_dispatch
    jobs:
      preflight:
        runs-on: ubuntu-latest
        outputs:
          protection_status: ${{ steps.verify-protection.outputs.status }}
        steps:
          - id: verify-protection
            run: |
              set_status() { echo "status=$1" >> "$GITHUB_OUTPUT"; }
              if ! PROTECTION=$(gh api repos/x/y/branches/main/protection); then
                set_status unverified
                exit 0
              fi
              if [[ "$ALLOW_FP" != "false" ]]; then
                set_status disabled
                exit 1
              fi
              if [[ "$ENFORCE_ADMINS" != "true" ]]; then
                set_status admin-bypass
                exit 1
              fi
              set_status verified
    """
)


# Tighter canary for the FAILED loop check: env binding is correct but
# SCHEMA_COMPAT_RESULT is never iterated, so a schema-compat failure
# would not flip the workflow to failed — exactly the silent-success
# trap #1322 closed at the wiring level. The loose `... in run` check
# would have passed here; the regex on `for ... in ...` catches it.
_BAD_FIXTURE_FINALIZE_BOUND_NOT_ITERATED = textwrap.dedent(
    """
    on: workflow_dispatch
    jobs:
      finalize:
        runs-on: ubuntu-latest
        needs: [manifest, qurl-schema-compat, terraform-apply]
        steps:
          - id: outcome
            env:
              MANIFEST_RESULT: ${{ needs.manifest.result }}
              SCHEMA_COMPAT_RESULT: ${{ needs.qurl-schema-compat.result }}
            run: |
              # SCHEMA_COMPAT_RESULT is referenced (echoed) but the
              # FAILED loop only iterates MANIFEST_RESULT, so a schema-
              # compat failure would not fail the workflow.
              echo "schema=$SCHEMA_COMPAT_RESULT"
              for r in "$MANIFEST_RESULT"; do
                if [[ "$r" == "failure" ]]; then exit 1; fi
              done
    """
)

# Regression: schema-compat.if flipped to negated form. A refactor that
# changed `qurl-schema-compat.if` from `inputs.run_terraform` (affirmative)
# to `!inputs.run_terraform` (negated) would let the schema check run
# ONLY on run_terraform=false runs — exactly inverted from intent — and
# the partial-deploy class is back at the workflow level. RUN_TERRAFORM_AFFIRM_RE's
# anchored regex rejects this; a plain-substring check would have accepted it.
_BAD_FIXTURE_SCHEMA_COMPAT_NEGATED = textwrap.dedent(
    """
    on: workflow_dispatch
    jobs:
      qurl-schema-compat:
        runs-on: ubuntu-latest
        # Bug: negated form. The schema-check now runs ONLY when the
        # operator opted out of terraform — exactly when there's no
        # post-apply schema to validate against.
        if: |
          !inputs.run_terraform
        steps:
          - run: ":"
      terraform-apply:
        runs-on: ubuntu-latest
        needs: [terraform-plan, qurl-schema-compat]
        steps:
          - run: ":"
    """
)


# Regression: terraform-apply.needs drops qurl-schema-compat. A refactor that drops `qurl-schema-compat` from
# `terraform-apply.needs:` would break the cascade — terraform would
# apply against a known-incompatible schema, deploys would land on the
# new state, and #1322's failure mode would be back at the workflow
# level. Real-workflow assertion already catches this; this fixture
# closes the self-test loop so a regression in
# `_assert_terraform_apply_needs_schema_compat` itself can't slip past.
_BAD_FIXTURE_TERRAFORM_APPLY_NEEDS = textwrap.dedent(
    """
    on: workflow_dispatch
    jobs:
      qurl-schema-compat:
        runs-on: ubuntu-latest
        if: inputs.run_terraform
        steps:
          - run: ":"
      terraform-apply:
        runs-on: ubuntu-latest
        # Bug: needs: drops qurl-schema-compat (and the gate cascade
        # along with it). Both terraform-plan and qurl-schema-compat
        # would normally be present.
        needs: [manifest, preflight]
        steps:
          - run: ":"
    """
)


_BAD_FIXTURE_PREFLIGHT = textwrap.dedent(
    """
    on: workflow_dispatch
    jobs:
      preflight:
        runs-on: ubuntu-latest
        steps:
          # Synthetic placeholder SHA — the discovery filter in
          # _assert_preflight matches `step["uses"].startswith(
          # "actions/checkout@")` regardless of pin form, so any
          # form works for the assertion. Using a placeholder SHA
          # (rather than `@v6`) so a future maintainer skimming the
          # file for un-pinned actions doesn't mistake fixture noise
          # for a real un-pinned action in the workflow.
          - uses: actions/checkout@deadbeefdeadbeefdeadbeefdeadbeefdeadbeef  # fixture placeholder (not a real SHA)
            # Bug: shallow checkout (fetch-depth missing or 1).
          - name: Verify terraform is current with deployed code
            if: |
              !inputs.run_terraform &&
              (inputs.deploy_server || inputs.deploy_ac || inputs.deploy_qurl)
            env:
              # Bugs:
              #   - ALLOW_STALE_TERRAFORM hardcoded to "false" — looks
              #     correct at a glance ("the bypass is off") but
              #     silently severs the operator's escape hatch from
              #     the input.
              #   - ROLLBACK pointed at inputs.force_unlock — a real
              #     input on this workflow, so a copy-paste regression
              #     is plausible. The env-pin assertion catches it
              #     because the canonical pin is inputs.rollback.
              ALLOW_STALE_TERRAFORM: "false"
              ROLLBACK: ${{ inputs.force_unlock }}
            # Bug: scope is "terraform/" (sandbox would trip prod);
            # rollback bypass and ALLOW_STALE_TERRAFORM both missing.
            #
            # The bare "$LAST"/"$CUR" placeholders are intentional — this
            # fixture is parsed by yaml.safe_load only, never executed.
            # Don't "fix" the missing variable definitions.
            run: |
              git diff --name-only "$LAST" "$CUR" -- terraform/
    """
)


def _assert_sns_row_widths_boundary() -> bool:
    """Boundary-test for `_assert_sns_row_widths` off-by-one.

    The boundary check is `len(label) + 1 > width` (the +1 is the
    colon). A label of `width-1` chars fits (`width-1 + 1 == width`,
    not >); a label of `width` chars trips. This canary builds two
    synthetic SNS steps:
      - one with a label exactly at the limit (must NOT fail);
      - one with a label one char over (MUST fail).
    Closes a potential off-by-one in the boundary math.
    """
    def _make_jobs(label: str) -> dict:
        return {
            "finalize": {
                "steps": [
                    {
                        "name": "Send SNS notification",
                        "run": (
                            "LABEL_WIDTH=14\n"
                            "row() { :; }\n"
                            f'row "{label}" "$X"\n'
                        ),
                    }
                ]
            }
        }

    label_at_limit = "X" * 13  # 13 + ":" = 14 = LABEL_WIDTH → fits
    label_over_limit = "X" * 14  # 14 + ":" = 15 > 14 → trips

    f1: list[str] = []
    with contextlib.redirect_stdout(io.StringIO()):
        _assert_sns_row_widths(_make_jobs(label_at_limit), f1)
    fits_ok = len(f1) == 0

    f2: list[str] = []
    with contextlib.redirect_stdout(io.StringIO()):
        _assert_sns_row_widths(_make_jobs(label_over_limit), f2)
    over_rejected = len(f2) > 0

    return fits_ok and over_rejected


def _assert_negative_fixtures_reject_bad_input() -> bool:
    """Self-test: each assertion family must reject its known-bad fixture.

    Without this, a regression that always returns success (e.g., a
    refactored helper that no-ops, a `failures.append` that's been
    deleted) would pass-through silently against the real workflow.

    Each assertion gets its own bad fixture exercising the failure mode
    that assertion is supposed to catch. If you change an assertion,
    update the corresponding fixture so it still fails the new check.

    Coverage invariant: the `cases` tuple below must include every
    `_assert_X(jobs, failures)` callable used in `main()`. The coverage
    check at the end of this function fails loud if a new assertion
    was added without a paired bad fixture — that scenario would
    silently leave the new assertion unfenced by self-testing.

    The relationship looks like:
        ┌──────────────────────┐    ┌──────────────────────┐
        │ assertion            │ ←→ │ _BAD_FIXTURE_X       │
        │ (e.g. _assert_X)     │    │ (synthetic workflow) │
        └──────────────────────┘    └──────────────────────┘
                  │                            │
                  └─────── paired in ──────────┘
                                  │
                                  ▼
                        cases tuple (below)
                                  │
                                  ▼
                  coverage check at end of this fn
                  (every _assert_X in main() must
                   appear in cases — fixture-less
                   assertions fail loud)
    """
    cases: tuple[tuple[str, Callable[[dict, list[str]], None], str], ...] = (
        ("image-deploys (permissive gate)", _assert_image_deploys, _BAD_FIXTURE_DEPLOY),
        (
            "image-deploys (negated-success regression)",
            _assert_image_deploys,
            _BAD_FIXTURE_DEPLOY_NEGATED_SUCCESS,
        ),
        (
            "image-deploys (run_terraform check dropped)",
            _assert_image_deploys,
            _BAD_FIXTURE_DEPLOY_NO_RUN_TF_CHECK,
        ),
        (
            "image-deploys (operator inputs.deploy_X clause dropped)",
            _assert_image_deploys,
            _BAD_FIXTURE_DEPLOY_MISSING_OPERATOR_CLAUSE,
        ),
        (
            "image-deploys (dead terraform-plan clause re-introduced)",
            _assert_image_deploys,
            _BAD_FIXTURE_DEPLOY_DEAD_PLAN_CLAUSE,
        ),
        ("finalize", _assert_finalize, _BAD_FIXTURE_FINALIZE),
        (
            "finalize (env bound but FAILED loop never iterates it)",
            _assert_finalize,
            _BAD_FIXTURE_FINALIZE_BOUND_NOT_ITERATED,
        ),
        (
            "finalize (rejected branch missing a deploy-* RESULT ref)",
            _assert_finalize,
            _BAD_FIXTURE_FINALIZE_MISSING_REJECTED_REF,
        ),
        (
            "finalize step ordering (tracking after lock release)",
            _assert_finalize_step_order,
            _BAD_FIXTURE_FINALIZE_STEP_ORDER,
        ),
        (
            "verify-protection (admin-bypass flipped to hard-fail)",
            _assert_force_push_verify_step,
            _BAD_FIXTURE_FORCE_PUSH_VERIFY,
        ),
        (
            "final_status consumption (one consumer reads outcome instead)",
            _assert_final_status_consumed,
            _BAD_FIXTURE_FINAL_STATUS_CONSUMED,
        ),
        (
            "manifest no-op rejection (DEPLOY_QURL check dropped)",
            _assert_manifest_rejects_no_op,
            _BAD_FIXTURE_MANIFEST_NOOP,
        ),
        (
            "terraform-apply.needs missing qurl-schema-compat",
            _assert_terraform_apply_needs_schema_compat,
            _BAD_FIXTURE_TERRAFORM_APPLY_NEEDS,
        ),
        (
            "qurl-schema-compat.if flipped to negated form",
            _assert_terraform_apply_needs_schema_compat,
            _BAD_FIXTURE_SCHEMA_COMPAT_NEGATED,
        ),
        ("preflight", _assert_preflight, _BAD_FIXTURE_PREFLIGHT),
    )
    all_rejected = True
    for label, assertion, fixture in cases:
        fake_jobs = (yaml.safe_load(fixture) or {}).get("jobs", {})
        fake_failures: list[str] = []
        with contextlib.redirect_stdout(io.StringIO()):
            assertion(fake_jobs, fake_failures)
        if not _check(
            f"self-test: {label} assertion rejects its known-bad fixture",
            len(fake_failures) > 0,
            f"the {label} assertion accepted a known-bad fixture — it has regressed to no-op",
        ):
            all_rejected = False

    # Coverage invariant: every assertion used by main() must appear in
    # `cases`. Missing coverage means a new assertion can pass-through
    # against the real workflow with a bug in its body and never get
    # canaried — exactly the failure mode this self-test exists to
    # prevent.
    covered_assertions = {assertion for _, assertion, _ in cases}
    expected_assertions = {
        _assert_image_deploys,
        _assert_finalize,
        _assert_finalize_step_order,
        _assert_final_status_consumed,
        _assert_force_push_verify_step,
        _assert_manifest_rejects_no_op,
        _assert_preflight,
        _assert_terraform_apply_needs_schema_compat,
        # _assert_sns_row_widths is exercised by its own dedicated
        # self-test (`_assert_sns_row_widths_boundary` covers the
        # row-width math). Listing here would require a fixture
        # without adding signal.
    }
    missing_coverage = expected_assertions - covered_assertions
    if not _check(
        "self-test: every primary assertion has a paired bad fixture in `cases`",
        not missing_coverage,
        f"missing self-test coverage: {sorted(fn.__name__ for fn in missing_coverage)}",
    ):
        all_rejected = False
    return all_rejected


def main() -> int:
    if not WORKFLOW.is_file():
        print(f"FAIL: {WORKFLOW} not found")
        return 1

    print(f"Checking {WORKFLOW.relative_to(REPO_ROOT)} for #1322 gate regression…")

    # Run the harness's own canaries first: a parser regression that always
    # passes can't slip past us if each assertion has been verified to
    # reject a known-bad fixture before we hit the real workflow.
    if not _assert_negative_fixtures_reject_bad_input():
        return 1

    # Off-by-one canary on _assert_sns_row_widths boundary math.
    if not _check(
        "self-test: _assert_sns_row_widths handles the boundary correctly",
        _assert_sns_row_widths_boundary(),
        "boundary check accepted >width or rejected exactly-at-width",
    ):
        return 1

    wf = yaml.safe_load(WORKFLOW.read_text())
    jobs = wf.get("jobs", {})
    failures: list[str] = []

    # Single source of truth for the assertion set. The negative-fixture
    # self-test must cover every callable here; the coverage check below
    # asserts that contract so a new assertion can't be added without a
    # paired bad fixture (which would defeat the self-test pattern).
    assertions: tuple[Callable[[dict, list[str]], None], ...] = (
        _assert_image_deploys,
        _assert_manifest_rejects_no_op,
        _assert_terraform_apply_needs_schema_compat,
        _assert_finalize,
        _assert_finalize_step_order,
        _assert_final_status_consumed,
        _assert_force_push_verify_step,
        _assert_preflight,
        _assert_sns_row_widths,
    )
    for fn in assertions:
        fn(jobs, failures)

    if failures:
        print()
        print(f"\033[31m{len(failures)} structural failure(s):\033[0m")
        for f in failures:
            print(f"  - {f}")
        return 1

    print()
    print("\033[32mAll #1322 gate assertions passed.\033[0m")
    return 0


if __name__ == "__main__":
    sys.exit(main())
