"""Shared helpers for the terraform-prod-drift lints (#1324).

Both `check-terraform-iam-coverage.py` and
`check-terraform-policy-conditions.py` walk the same terraform tree and
parse the same `policy = jsonencode({...})` constructs; the helpers here
keep them on a single canonical implementation. Adding a third lint? Reuse
these.

The non-obvious bits this module hides:

- `python-hcl2` returns resource type and instance name keys *quoted*
  (`'"aws_iam_role_policy"'`). `unquote` strips them so callers compare
  against bare strings.
- A `policy = jsonencode({...})` attribute returns as
  `'${jsonencode({...})}'`; a conditional one returns as
  `'${var.x ? jsonencode({...}) : jsonencode({...})}'`. `extract_policy_body`
  pulls every `jsonencode(...)` substring (balanced-paren scan), parses
  each, and unions the Statements — so a ternary policy is walked on both
  legs without a hand-rolled ternary parser.
"""

from __future__ import annotations

import io
import re
import sys
from collections.abc import Iterable
from pathlib import Path
from typing import Any

import hcl2  # type: ignore[import-untyped]


def warn(msg: str, *, file: Path | None = None) -> None:
    """Emit a `::warning::` annotation to stderr.

    GitHub Actions surfaces these inline against the file when `file=`
    is set; the lint scripts use file-scoped warns wherever the issue
    is tied to a specific source location.
    """
    prefix = f"::warning file={file}::" if file is not None else "::warning::"
    print(f"{prefix}{msg}", file=sys.stderr)


def error(msg: str, *, file: Path | None = None) -> None:
    """Emit a `::error::` annotation to stderr."""
    prefix = f"::error file={file}::" if file is not None else "::error::"
    print(f"{prefix}{msg}", file=sys.stderr)


def warn_undecodable_policy(
    file: Path,
    rtype: str,
    name: str,
    finding: str = "the actions it grants will be excluded from the coverage union",
) -> None:
    """Emit the shared "policy attribute couldn't be decoded" warn.

    Both lints share the same trigger (`policy is None and policy_attr
    is not None`) and the same fix path; the only thing that varies is
    a one-line statement of the consequence (e.g. "actions excluded
    from coverage union" vs "banned-condition checks skipped").
    """
    warn(
        f"{rtype}.{name}: policy attribute couldn't be decoded by the "
        f"lint — either it isn't a `jsonencode({{...}})` expression "
        f"(e.g. a `data.aws_iam_policy_document` reference) or every "
        f"`jsonencode(...)` leg failed to parse. "
        f"{finding}. Inline the policy or extend "
        f"`.github/scripts/_tf_lint_lib.py` to handle the form.",
        file=file,
    )


# Match a `${...}` template wrapper around an entire policy attribute. The
# greedy `.*` looks brittle but is correct: when the attribute is a compound
# template like `"${var.x}-${jsonencode({...})}"`, the inner walker
# (`_iter_jsonencode_args`) re-finds every `jsonencode(` call individually,
# so over-capture here is harmless.
POLICY_TEMPLATE_RE = re.compile(r"^\$\{(.*)\}$", re.DOTALL)


def parse_tf_files(terraform_root: Path) -> list[tuple[Path, dict[str, Any]]]:
    """Load every .tf file under terraform_root via python-hcl2.

    Skips `.terraform/` and `examples/` subtrees. Exits 3 on any parse
    failure — the lints don't try to recover from broken HCL because the
    `terraform validate` step in the same job would have caught it.
    """
    parsed: list[tuple[Path, dict[str, Any]]] = []
    # Sort the walk so iteration order is deterministic across
    # filesystems / runners — the lints' last-write-wins resolution for
    # bare-name `aws_iam_policy` declarations would otherwise be
    # filesystem-hash-dependent.
    for tf in sorted(terraform_root.rglob("*.tf")):
        # Skip vendored provider state (`.terraform/`) and the repo's
        # `terraform/modules/.../examples/` reference snippets — they
        # aren't part of the apply path.
        if any(part in {".terraform", "examples"} for part in tf.parts):
            continue
        with open(tf, encoding="utf-8") as f:
            try:
                parsed.append((tf, hcl2.load(f)))
            except Exception as exc:
                error(f"failed to parse: {exc}", file=tf)
                sys.exit(3)
    return parsed


def unquote(value: Any) -> Any:
    """Strip an outer pair of `"..."` or `'...'` quotes from `value`.

    python-hcl2 surfaces double-quoted HCL strings only — the single-
    quote branch is unreachable against today's parser. Kept as belt-
    and-braces against a future hcl2 grammar change (the dependabot
    `version-update:semver-major` ignore on python-hcl2 means a major
    bump won't land silently, but the cost of the extra `or` is zero).
    """
    if (
        isinstance(value, str)
        and len(value) >= 2
        and value[0] == value[-1]
        and value[0] in ('"', "'")
    ):
        return value[1:-1]
    return value


def iter_resources(
    parsed: list[tuple[Path, dict[str, Any]]],
) -> Iterable[tuple[Path, str, str, dict[str, Any]]]:
    """Yield (file, type, name, body) for every resource block.

    `count`/`for_each` aren't reported — the lints take a union view of
    what the source could attach. Per-env gating-aware analysis is
    out of scope (see docs/design/TERRAFORM_PROD_DRIFT_DETECTOR.md).
    """
    for file, doc in parsed:
        for resource in doc.get("resource", []):
            for rtype, instances in resource.items():
                for name, body in instances.items():
                    yield file, unquote(rtype), unquote(name), body


def iter_data_sources(
    parsed: list[tuple[Path, dict[str, Any]]],
) -> Iterable[tuple[Path, str, str, dict[str, Any]]]:
    """Yield (file, type, name, body) for every data block.

    The body is exposed so callers can do attribute-aware action
    lookup — e.g. `aws_route53_zone` requires the extra
    `route53:ListTagsForResource` action only when the `tags` filter
    is set; the lint demands the wider set conditionally rather than
    always.
    """
    for file, doc in parsed:
        for d in doc.get("data", []):
            for dtype, instances in d.items():
                for name, body in instances.items():
                    yield (
                        file,
                        unquote(dtype),
                        unquote(name),
                        body if isinstance(body, dict) else {},
                    )


def extract_policy_body(policy_value: Any) -> dict[str, Any] | None:
    """Re-parse a `policy = jsonencode({...})` attribute into a dict.

    Walks every `jsonencode(...)` substring in the value and unions the
    `Statement` arrays — covers the bare and ternary forms uniformly.
    Returns None if no jsonencode call is found.
    """
    if not isinstance(policy_value, str):
        return None
    m = POLICY_TEMPLATE_RE.match(policy_value)
    # Compound templates with a leading literal like `"prefix-${jsonencode(...)}"`
    # don't match the strict `^${...}$` regex but still contain a
    # `jsonencode(...)` call we can decode. Fall through to scanning the
    # whole value when the wrapper doesn't match — the inner walker is the
    # real semantic; the regex is just a fast path.
    inner = m.group(1) if m else policy_value

    # HCL heredoc form (`<<EOF ... EOF`) inside jsonencode is not
    # handled by the balanced-paren scanner. The repo doesn't use the
    # form today; promoting to a hard error closes the silent-miss
    # class (a heredoc-form leg that's the only grant for a required
    # action would otherwise drop the actions silently) without
    # false-positive risk.
    #
    # python-hcl2 v8.x surfaces `jsonencode(<<EOT ... EOT)` as either
    # a raw `jsonencode(<<...)` substring or a `jsonencode("<<...EOT")`
    # form (when the parser wraps the heredoc body in quotes). Match
    # both — the quoted form is what python-hcl2 emits today; the raw
    # form is defense against future parser changes.
    if re.search(r'jsonencode\(\s*"?<<', inner):
        error(
            "found heredoc-form `jsonencode(<<EOF ...)` policy body — "
            "the lint can't decode actions inside heredocs. Convert to "
            "an inline `jsonencode({...})` call or extend "
            ".github/scripts/_tf_lint_lib.py."
        )
        sys.exit(2)
    # HCL interpolation `${fn(arg)}` *inside* a string literal would
    # unbalance the balanced-paren scanner — the inner-paren count
    # would exceed the closing `)` of the `jsonencode(` and yield a
    # truncated body. Detect heuristically: a `${` followed by an
    # identifier-and-`(` somewhere inside an inner string. The repo
    # doesn't use this shape today; warn so the silent-miss is visible
    # with a specific diagnostic instead of the generic "policy
    # attribute couldn't be decoded" warn.
    if re.search(r'"[^"]*\$\{[A-Za-z_][A-Za-z0-9_]*\(', inner):
        warn(
            "found `${fn(...)}` interpolation inside a string literal in "
            "a policy body — `_iter_jsonencode_args` may miscount parens "
            "and truncate the decoded body. Convert the interpolation to "
            "a separate local/value or extend the scanner in "
            ".github/scripts/_tf_lint_lib.py."
        )

    statements: list[Any] = []
    seen_legs = 0
    failed_legs = 0
    for body in _iter_jsonencode_args(inner):
        seen_legs += 1
        if body is None:
            # _iter_jsonencode_args couldn't balance this leg's
            # parens; count as failed and continue.
            failed_legs += 1
            continue
        try:
            inner_doc = hcl2.load(io.StringIO("policy = " + body))
        except Exception:
            failed_legs += 1
            continue
        policy = inner_doc.get("policy") if isinstance(inner_doc, dict) else None
        if not isinstance(policy, dict):
            failed_legs += 1
            continue
        # AWS IAM accepts Statement as either a list or a single object.
        # Normalize to a list so statement_actions and the Condition
        # walker iterate uniformly.
        stmts = policy.get("Statement", [])
        if isinstance(stmts, dict):
            stmts = [stmts]
        if isinstance(stmts, list):
            statements.extend(stmts)

    # Partial-success warn: if a multi-leg policy (e.g., a ternary
    # `var.x ? jsonencode(A) : jsonencode(B)`) had at least one leg
    # parse and at least one fail, the caller's None-check doesn't
    # fire and the silent half of the union is the exact failure mode
    # this lint exists to prevent. Surface as a warning.
    if seen_legs > 1 and failed_legs > 0:
        warn(
            f"extract_policy_body decoded {seen_legs - failed_legs}"
            f"/{seen_legs} jsonencode legs in a multi-leg policy; "
            f"{failed_legs} leg(s) failed to parse and their actions are "
            f"excluded from the coverage union. Inspect the source for a "
            f"malformed jsonencode body."
        )

    # Distinguish decoded-but-empty (`Statement = []`) from undecodable
    # (no leg parsed at all). Callers warn on `None and policy_attr is
    # not None`; collapsing the empty case to None mis-fires that warn
    # against a perfectly valid policy. Return an empty Statement list
    # when at least one leg parsed — caller's `statement_actions` and
    # the Condition walker both iterate the empty list as a no-op.
    # `seen_legs == failed_legs` covers the zero-legs case too, since
    # both counters start at zero.
    if seen_legs == failed_legs:
        return None
    return {"Statement": statements}


def _iter_jsonencode_args(expr: str) -> Iterable[str | None]:
    """Yield each `jsonencode(<arg>)` call's body in `expr`.

    A `str` yield is the balanced argument substring; `None` is yielded
    when the scanner finds a `jsonencode(` that it can't close (e.g.
    parens unbalanced by a `${fn(arg)}` interpolation inside a string
    literal). `extract_policy_body` treats `None` as a failed leg so
    the caller's partial-success accounting still fires — recovering
    from a bad leg in a multi-leg policy means a subsequent well-
    formed leg still reaches the union, but the bad leg isn't
    silently invisible.

    Uses a balanced-paren scan that respects double-quoted string runs so a
    paren inside a string literal (e.g., `"foo:Bar(baz)"`) doesn't unbalance
    the count. Two known limitations:

    1. HCL heredocs (`<<EOF ... EOF`) are NOT recognized — a
       `jsonencode(<<EOF ... EOF)` form with parens inside the heredoc
       payload yields `None`. The shared `extract_policy_body` caller
       emits a heredoc-specific warning so the silent-miss case is
       visible.
    2. HCL interpolation `${...}` *inside* a string literal is treated as
       ordinary text. If a string contains an interpolation that itself
       contains parens (e.g., `"${endswith(var.x, \"-foo\")}"`), the
       inner-paren count would unbalance and the scan yields `None` for
       that leg. `extract_policy_body` emits a specific
       interpolation-with-parens warn before this scan runs, so the
       symptom is loud rather than silent.
    """
    needle = "jsonencode("
    i = 0
    while True:
        start = expr.find(needle, i)
        if start < 0:
            return
        arg_start = start + len(needle)
        depth = 1
        j = arg_start
        in_string = False
        while j < len(expr) and depth > 0:
            ch = expr[j]
            if in_string:
                if ch == "\\" and j + 1 < len(expr):
                    j += 2
                    continue
                if ch == '"':
                    in_string = False
            elif ch == '"':
                in_string = True
            elif ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
            j += 1
        if depth != 0:
            # Unbalanced parens — the scanner can't trust this leg's
            # boundary. Yield None so `extract_policy_body` counts it
            # as a failed leg, then advance past the bad needle and
            # keep walking so a subsequent well-formed leg in the
            # same expression (e.g. the second branch of a ternary)
            # still gets yielded. Without this advancement, a single
            # bad leg silently drops every leg after it.
            #
            # Re-entry caveat: if the unclosed body itself contains a
            # nested `jsonencode(...)` call (e.g.
            # `jsonencode(some_func(${x}, jsonencode({...})))`), the
            # next iteration's `expr.find(needle, i)` re-finds that
            # nested needle and yields its body — actions from the
            # nested call would then land in the union as if they
            # were the outer leg's grants. The partial-success warn
            # in `extract_policy_body` fires (failed_legs > 0), so
            # the outer breakage isn't silent; the union may include
            # the nested actions in addition to any well-formed
            # sibling legs. Repo doesn't use this shape today; if it
            # ever does, advance past the nested boundary explicitly
            # here.
            yield None
            i = arg_start
            continue
        yield expr[arg_start : j - 1]
        i = j


def statement_actions(policy: dict[str, Any] | None) -> set[str]:
    """Return the set of `Effect = Allow` action globs in `policy`.

    Action globs are lowercased at insertion (IAM is case-insensitive at
    eval time, and this lets `action_allowed` skip per-comparison casing).
    `Deny` statements are intentionally ignored — the lints check whether
    the role *can* perform an action, and a Deny doesn't grant. Mixed
    Allow/Deny role policies are rare in this codebase and out of scope;
    callers that care about that assumption can use `policy_has_mixed_effects`
    to surface the case.
    """
    if not policy:
        return set()
    actions: set[str] = set()
    for stmt in policy.get("Statement", []) or []:
        if not isinstance(stmt, dict):
            continue
        # AWS IAM requires `Effect`, but the parser may surface a missing
        # field if the source is malformed. Default to "Allow" so a
        # broken statement is conservatively counted as a grant — the
        # caller will then notice the action set is wider than expected,
        # not narrower. (Defense, not modeling.)
        effect = stmt.get("Effect", "Allow")
        # IAM accepts "Allow" / "allow" / "ALLOW" — match any case.
        if isinstance(effect, str) and unquote(effect).lower() != "allow":
            continue
        # `NotAction` (Allow-everything-except-X) is intentionally not
        # modeled — translating it back to a positive action set
        # requires enumerating every IAM action, which is out of scope
        # for a static lint. Surface as a warning so a future use can't
        # silently misread the grants. The repo doesn't use NotAction
        # today; if that changes, switch the policy to inline Allow
        # actions or extend the lint.
        if "NotAction" in stmt:
            warn(
                "statement uses `NotAction` — actions in this statement "
                "won't be added to the role's coverage union. Convert to "
                "a positive `Action` list or extend "
                ".github/scripts/_tf_lint_lib.py."
            )
            continue
        a = stmt.get("Action")
        if isinstance(a, str):
            actions.add(unquote(a).lower())
        elif isinstance(a, list):
            for item in a:
                if isinstance(item, str):
                    actions.add(unquote(item).lower())
    return actions


def policy_has_mixed_effects(policy: dict[str, Any] | None) -> bool:
    """True if `policy` has at least one `Allow` and one `Deny` statement.

    Caller's responsibility to gate this on the right policy shape — a
    permission-boundary or shared managed policy mixing effects is
    expected and not noteworthy, but an inline role policy doing the
    same hides intent from `statement_actions` (which only counts the
    Allow grants). Callers warn-once on the role-policy site only.
    """
    if not policy:
        return False
    has_allow = False
    has_deny = False
    for stmt in policy.get("Statement", []) or []:
        if not isinstance(stmt, dict):
            continue
        effect = stmt.get("Effect", "Allow")
        if not isinstance(effect, str):
            continue
        normalized = unquote(effect).lower()
        if normalized == "allow":
            has_allow = True
        elif normalized == "deny":
            has_deny = True
        if has_allow and has_deny:
            return True
    return False
