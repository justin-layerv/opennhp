#!/usr/bin/env python3
"""Lint `on.push.paths` against `dorny/paths-filter` filter groups.

Only the literal block-scalar form of `filters:` is supported. dorny
also accepts a YAML mapping (`filters: {app: ['nhp/**']}`) and a
separate-file form (`filters_from_source_file:`); both raise
EXIT_BAD_INPUT. Fail-loud is the right default for a lint — add
support if/when a workflow actually adopts those forms.

Workflows that use `dorny/paths-filter` have two layers of path
filtering: `on.push.paths` decides whether the workflow runs at all,
and the filter step's `filters:` block decides which jobs run inside.
If layer 2 cares about a path that layer 1 doesn't, a merge that only
touches that path silently skips the workflow — the inner filter
never sees the change. That's how the `packer/**` gap (#252/#980) and
the `.trivyignore` gap (#1775/#1776) shipped.

This lint walks every workflow under `.github/workflows/` (or files
passed as args). For each workflow with a `dorny/paths-filter` step,
it asserts every inner-filter pattern is covered by an `on.push.paths`
pattern. Workflows without the inner filter are skipped silently.

Per-group exemptions are comment-driven: a `# lint-allow:
paths-filter-coverage` annotation immediately above (or trailing) a
group key opts that group out. Surfaces the exemption next to the code
that needs it; portable across workflows.

Coverage semantics:
  - Exact match covers (`'.trivyignore'` covers `'.trivyignore'`).
  - `dir/**` covers anything under `dir/` (`dir/sub/**`, `dir/file`).
  - `**` alone covers everything.
  - Negations, brace expansion, character classes, `**/*.ext`, and
    trailing-slash directory paths are rejected (exit 2) — keep the
    pattern vocabulary small until a real need shows up.

Exit codes:
  0 — every covered pattern has an ancestor across all checked workflows
  1 — at least one inner-filter pattern is uncovered (drift detected)
  2 — at least one input is malformed or uses unsupported glob syntax

Usage:
  scripts/check-paths-filter-coverage.py
  scripts/check-paths-filter-coverage.py path/to/workflow.yml [...]
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import NamedTuple

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS_DIR = REPO_ROOT / ".github" / "workflows"

# Update if dorny/paths-filter is ever forked/renamed; an unmatched
# action ref silently no-ops, so a migration must update both ends
# in lockstep.
PATHS_FILTER_PREFIX = "dorny/paths-filter@"
ALLOW_COMMENT_TOKEN = "lint-allow: paths-filter-coverage"
UNSUPPORTED_GLOB_CHARS = ("!", "{", "}", "[", "]")

EXIT_OK = 0
EXIT_GAP = 1
EXIT_BAD_INPUT = 2


class CheckResult(NamedTuple):
    code: int
    msgs: "list[str]"
    # True iff the workflow had a dorny/paths-filter step and was
    # actually checked. False iff the lint was inapplicable (no
    # paths-filter step, or no push trigger). Used only for the
    # summary line; gap/bad-input cases also set this True.
    applicable: bool


def _is_supported_pattern(p: object) -> bool:
    """The lint speaks a deliberately small dialect of dorny/paths-filter
    (minimatch) globs: literal paths, `dir/**`, and bare `**`. Anything
    else — `**/foo`, `*.ext`, `dir/*`, negations, brace expansion,
    character classes, trailing-slash dirs — is rejected up front so
    the operator extends covers() rather than getting a silent
    mis-rule. Conservative on purpose; widen when a real need shows up.

    A non-string filter value (e.g., a per-change-type mapping like
    `{added|modified: 'src/**'}`) is also rejected: covers() reasons
    in path strings, and the lint shouldn't pretend to handle a
    structure it can't compare.
    """
    if not isinstance(p, str):
        return False
    if any(c in p for c in UNSUPPORTED_GLOB_CHARS):
        return False
    if p.startswith("**/") and p != "**":
        # `**/foo/**` would slip past the trailing-`/**` check and
        # `covers()` would compute root='**/foo' and ask
        # `inner.startswith('**/foo/')`, which is wrong (minimatch
        # treats leading `**/` as "match anywhere"). Reject; same
        # family as the leading-/-trailing cases below.
        return False
    if "**" in p and not p.endswith("/**") and p != "**":
        return False
    if "*" in p and "**" not in p:
        return False
    if p.endswith("/") and p != "/":
        return False
    return True


def covers(push_pat: str, inner_pat: str) -> bool:
    """True if `push_pat` matches every path that `inner_pat` matches.

    `dir/**` matches files under `dir/` only — it does NOT match the
    literal file at path `dir`. So `covers('dir/**', 'dir')` is False
    on purpose, even though it looks redundant: the two patterns mean
    different things in minimatch, and a consumer that wrote `dir`
    expecting `dir/**` to cover it would get silently-skipped pushes.

    The `dir/** vs literal dir` contract is pinned by
    `tests/lints/paths-filter-coverage/fail-bare-dir-not-covered.yml`
    — a refactor that loosens this rule (e.g., adding an
    `inner_pat == root` self-equal clause) flips that fixture from
    the expected exit-1 to exit-0 and surfaces immediately.
    """
    if push_pat == inner_pat or push_pat == "**":
        return True
    if push_pat.endswith("/**"):
        root = push_pat[: -len("/**")].rstrip("/")
        if not root:
            return True
        return inner_pat.startswith(root + "/")
    return False


def _extract_trigger_paths(workflow: dict, trigger: str) -> "list[str] | None":
    """Return `on.<trigger>.paths` as a list, or None if the trigger
    isn't configured at all (no `<trigger>:` block under `on:`).

    Returns `[]` for both "block exists but no `paths:` key" (the
    trigger fires on every event — no path filter) and the malformed
    `paths: []` shape; both collapse to "no path constraint" in
    `check_one`'s `if push_paths:` test, which is correct for the
    former and harmless for the latter (nobody writes the latter).
    Raises ValueError on malformed `on:` shape.
    """
    # PyYAML follows YAML 1.1 by default — `on/off/yes/no` are
    # parsed as booleans, so a bare `on:` becomes the True key.
    # PyYAML doesn't ship a YAML-1.2 mode (that's ruamel.yaml), so
    # the True-keyed branch is the live one for every PyYAML run.
    # The string-"on" key is reachable only via `'on':` (quoted) in
    # the source workflow — kept as a fallback rather than the
    # primary because real workflows uniformly use the bare form.
    # Explicit `dict.get` so a falsy-but-present `on: {}` doesn't
    # trip the `or` short-circuit.
    on = workflow.get("on", workflow.get(True))
    if not isinstance(on, dict):
        raise ValueError("workflow `on:` block missing or not a mapping")
    block = on.get(trigger)
    if not isinstance(block, dict):
        return None
    paths = block.get("paths")
    if paths is None:
        return []
    if not isinstance(paths, list):
        raise ValueError(f"workflow `on.{trigger}.paths` is not a list")
    return [str(p) for p in paths]


# Group key with optional same-line trailing comment. A trailing
# `# lint-allow: paths-filter-coverage` comment also opts the group
# out — the previous-line form is still supported for readability.
# Only multi-line group keys (`key:` on its own line, opening a list
# block) are detected. An inline form like `code: ['nhp/**']` would
# not match this regex, so the allowlist annotation would silently
# no-op against it. dorny filter blocks are conventionally written
# multi-line, so this is fine in practice — surfaced here so a future
# refactor doesn't accidentally rely on inline-form annotations.
_KEY_RE = re.compile(
    r"^\s*(?P<key>[A-Za-z_][A-Za-z0-9_-]*)\s*:\s*(?:#(?P<comment>.*))?$"
)


def _is_allow_token(text: str) -> bool:
    """True iff `text` is exactly the allow token, or the token followed
    by a space (allowing trailing notes like `lint-allow: ... TODO`).
    Rejects accidental prefix matches like `lint-allow: paths-filter-coverage-strict`,
    which a future stricter variant would silently inherit otherwise.
    """
    return text == ALLOW_COMMENT_TOKEN or text.startswith(ALLOW_COMMENT_TOKEN + " ")


def _parse_allowlist(filters_text: str) -> "set[str]":
    """Find filter groups annotated with `# lint-allow: paths-filter-coverage`.

    Two forms are accepted:
      1. Comment on its own line, immediately above the group's key
         (blank lines and other comments allowed in between).
      2. Trailing same-line comment on the key line itself.

    The token is matched after stripping the `#` prefix and leading
    whitespace, and must be either exactly the token or the token
    followed by a space — so a prose mention or a hypothetical
    `paths-filter-coverage-strict` variant does not opt the next
    group out.
    """
    allow: "set[str]" = set()
    pending = False
    for line in filters_text.splitlines():
        stripped = line.strip()
        if stripped == "":
            continue
        if stripped.startswith("#"):
            body = stripped.lstrip("#").lstrip()
            if _is_allow_token(body):
                pending = True
            continue
        m = _KEY_RE.match(line)
        if m:
            trailing = (m.group("comment") or "").lstrip()
            if pending or _is_allow_token(trailing):
                allow.add(m.group("key"))
            pending = False
        else:
            pending = False
    return allow


def _extract_filter_blocks(
    workflow: dict,
) -> "list[tuple[dict[str, list[str]], set[str]]]":
    out: "list[tuple[dict[str, list[str]], set[str]]]" = []
    jobs = workflow.get("jobs") or {}
    if not isinstance(jobs, dict):
        return out
    for job in jobs.values():
        if not isinstance(job, dict):
            continue
        for step in job.get("steps", []) or []:
            if not isinstance(step, dict):
                continue
            uses = str(step.get("uses", ""))
            if not uses.startswith(PATHS_FILTER_PREFIX):
                continue
            with_block = step.get("with") or {}
            filters_raw = with_block.get("filters")
            if filters_raw is None:
                # Could be `filters_from_source_file:`, dict-form
                # `filters:`, or a step with neither (operator error).
                # All three are out of scope; surface the cause to
                # speed diagnosis.
                if "filters_from_source_file" in with_block:
                    raise ValueError(
                        f"`{PATHS_FILTER_PREFIX}` step uses "
                        f"`filters_from_source_file:`; only the inline "
                        f"block-scalar `filters:` form is supported"
                    )
                raise ValueError(
                    f"`{PATHS_FILTER_PREFIX}` step has no `filters:` "
                    f"block-scalar (the `with:` mapping must include "
                    f"`filters: |` followed by the filter spec)"
                )
            if not isinstance(filters_raw, str):
                raise ValueError(
                    f"`{PATHS_FILTER_PREFIX}` step's `filters:` is "
                    f"not a literal block scalar (got "
                    f"{type(filters_raw).__name__}); only the inline "
                    f"string form is supported"
                )
            try:
                parsed = yaml.safe_load(filters_raw)
            except yaml.YAMLError as e:
                # Malformed YAML inside the inner block-scalar (stray
                # tab, mismatched quote, …) would otherwise surface as
                # an unhandled traceback. Re-raise as ValueError so
                # check_one's bad-input branch produces a clean
                # EXIT_BAD_INPUT with file context.
                raise ValueError(f"`filters:` block is not valid YAML: {e}")
            if not isinstance(parsed, dict):
                raise ValueError("`filters:` block did not parse as a mapping")
            filters: "dict[str, list[str]]" = {}
            for k, v in parsed.items():
                if v is None:
                    filters[k] = []
                    continue
                if not isinstance(v, list):
                    # Reject the shorthand `app: 'nhp/**'` (string
                    # instead of list-of-strings). `list('nhp/**')`
                    # would silently produce per-character patterns
                    # and trip downstream checks with a misleading
                    # message.
                    raise ValueError(
                        f"filter group {k!r}: value is "
                        f"{type(v).__name__}, expected a list of "
                        f"glob strings"
                    )
                filters[k] = list(v)
            allow = _parse_allowlist(filters_raw)
            out.append((filters, allow))
    return out


def check_one(workflow_path: Path) -> CheckResult:
    """Check a single workflow.

    `applicable` is True when the workflow has a `dorny/paths-filter`
    step and was actually checked (regardless of pass/gap). False
    when the lint didn't apply — no paths-filter step, or no
    push.paths to compare against.
    """
    if not workflow_path.is_file():
        return CheckResult(EXIT_BAD_INPUT, [f"{workflow_path}: file not found"], True)

    try:
        workflow = yaml.safe_load(workflow_path.read_text())
    except yaml.YAMLError as e:
        return CheckResult(
            EXIT_BAD_INPUT, [f"{workflow_path}: YAML parse failed: {e}"], True
        )
    if not isinstance(workflow, dict):
        return CheckResult(
            EXIT_BAD_INPUT, [f"{workflow_path}: did not parse as a mapping"], True
        )

    try:
        push_paths = _extract_trigger_paths(workflow, "push")
        pr_paths = _extract_trigger_paths(workflow, "pull_request")
        filter_blocks = _extract_filter_blocks(workflow)
    except ValueError as e:
        return CheckResult(EXIT_BAD_INPUT, [f"{workflow_path}: {e}"], True)

    if not filter_blocks:
        return CheckResult(EXIT_OK, [], False)

    # paths-ignore is the opposite-polarity failure class: a pattern
    # under paths-ignore that's also referenced by an inner filter
    # would silently skip on edits to that path. Only fail loud when
    # the workflow actually uses dorny/paths-filter (i.e., we already
    # know we're inside our scope) — workflows that use paths-ignore
    # without dorny aren't ours to police. Tracked in #1786.
    on = workflow.get("on", workflow.get(True)) or {}
    if isinstance(on, dict):
        for trigger in ("push", "pull_request"):
            block = on.get(trigger)
            if isinstance(block, dict) and "paths-ignore" in block:
                return CheckResult(
                    EXIT_BAD_INPUT,
                    [
                        f"{workflow_path}: on.{trigger}.paths-ignore "
                        f"present alongside dorny/paths-filter; this "
                        f"lint doesn't yet model paths-ignore (see "
                        f"#1786). Add coverage manually or extend "
                        f"the lint."
                    ],
                    True,
                )

    # Check both triggers independently. A path that gates inner work
    # but is missing from push.paths skips the deploy on merge; the
    # same gap on pull_request.paths skips the validation jobs at PR
    # time. Same failure class either way.
    triggers = []
    if push_paths:
        triggers.append(("push", push_paths))
    if pr_paths:
        triggers.append(("pull_request", pr_paths))

    if not triggers:
        return CheckResult(EXIT_OK, [], True)

    for trigger, paths in triggers:
        for p in paths:
            if not _is_supported_pattern(p):
                return CheckResult(
                    EXIT_BAD_INPUT,
                    [
                        f"{workflow_path}: on.{trigger}.paths uses unsupported "
                        f"glob syntax: {p!r}. Extend covers() if intentional."
                    ],
                    True,
                )

    gaps: "list[tuple[str, str, str]]" = []
    for filters, allow in filter_blocks:
        for group, patterns in filters.items():
            if group in allow:
                continue
            for pat in patterns:
                if not _is_supported_pattern(pat):
                    return CheckResult(
                        EXIT_BAD_INPUT,
                        [
                            f"{workflow_path}: filter group {group!r} uses "
                            f"unsupported glob syntax: {pat!r}. Extend "
                            f"covers() if intentional."
                        ],
                        True,
                    )
                for trigger, paths in triggers:
                    if not any(covers(pp, pat) for pp in paths):
                        gaps.append((trigger, group, pat))

    if not gaps:
        return CheckResult(EXIT_OK, [], True)

    msgs = [f"{workflow_path}: uncovered inner-filter patterns:"]
    msgs += [f"  - on.{trigger}.paths: {group}: {pat}" for trigger, group, pat in gaps]
    return CheckResult(EXIT_GAP, msgs, True)


GAP_HELP = (
    "FAIL: inner-filter patterns are not covered by on.push.paths.\n"
    "When a path is in a paths-filter group but not in on.push.paths,\n"
    "a merge to main that only touches that path will not trigger\n"
    "the workflow at all — the inner filter never runs. Fix by\n"
    "adding the uncovered pattern (or a covering ancestor) to\n"
    "on.push.paths. To intentionally exempt a group (e.g., a\n"
    "meta-filter for diagnostics that shouldn't gate work), add\n"
    "a `# lint-allow: paths-filter-coverage` comment on or above\n"
    "the group key in the `filters:` block."
)


def main(argv: "list[str]") -> int:
    if len(argv) > 1:
        targets = [Path(a) for a in argv[1:]]
    else:
        # Both extensions: GitHub honours `*.yml` and `*.yaml` and a
        # repo-wide convention of one or the other can drift over time.
        targets = sorted(
            list(WORKFLOWS_DIR.glob("*.yml")) + list(WORKFLOWS_DIR.glob("*.yaml"))
        )

    if not targets:
        print(f"no workflows found under {WORKFLOWS_DIR}", file=sys.stderr)
        return EXIT_BAD_INPUT

    any_bad = False
    any_gap = False
    checked = 0
    skipped = 0
    all_msgs: "list[str]" = []

    for t in targets:
        result = check_one(t)
        all_msgs.extend(result.msgs)
        if result.code == EXIT_BAD_INPUT:
            any_bad = True
        elif result.code == EXIT_GAP:
            any_gap = True
        if result.applicable:
            checked += 1
        else:
            skipped += 1

    if any_bad:
        print("\n".join(all_msgs))
        print("FAIL: malformed inputs (exit 2)")
        return EXIT_BAD_INPUT
    if any_gap:
        print("\n".join(all_msgs))
        print("")
        print(GAP_HELP)
        return EXIT_GAP

    print(
        f"OK: paths-filter coverage clean across {checked} workflow(s) "
        f"(skipped {skipped} without dorny/paths-filter)"
    )
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main(sys.argv))
