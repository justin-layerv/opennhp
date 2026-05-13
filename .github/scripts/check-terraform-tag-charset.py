#!/usr/bin/env python3
"""check-terraform-tag-charset.py

Fail PRs that introduce an AWS-resource tag value containing a character
outside this ASCII subset of AWS's allowed tag charset:

    [A-Za-z0-9_.:/=+\\-@\\s]

AWS itself allows Unicode letters/digits plus the punctuation set above,
so a tag value like `"café"` is AWS-valid but flagged here. The
ASCII-only floor is a team convention — it keeps tag values
copy-paste-safe in shell scripts, dashboards, and CLI output.

Regression fence for PR #1914 / PR #1915 — `qurl_agent_keys` shipped with
a `Purpose` tag value containing the unicode arrow `→`, parentheses,
and `>` characters. Each silently passed `terraform validate` and only
surfaced at sandbox `Terraform Apply` time as a `ValidationException` from
the AWS DynamoDB API; two follow-up PRs were needed because the first fix
only swapped `→` for `->`, leaving `>` and `(`,`)` in place.

Scope
-----

Scans every `*.tf` file under the repo's `terraform/` tree for four AWS
tag constructs:

1. `tags = { KEY = "VAL", ... }`               — literal map
2. `tags = merge(..., { KEY = "VAL", ... })`   — merge-into-default form
3. `default_tags { tags = { KEY = "VAL", ... } }` — provider default tags
4. `tag { key = "K"  value = "V" }`            — ASG singular tag block
   (`aws_autoscaling_group` and friends use this form for non-propagated
   tags; AWS enforces the same charset on these.)

Within each block, every multi-line KV literal **and** every KV pair
that shares a line with the opener is checked. KV scanning ignores
trailing `# ...` line comments and string-internal `{`/`(` so depth
tracking does not skew. `${...}` interpolations are recursively stripped
so nested-brace interpolations (e.g. `${jsonencode({...})}`) do not
leak `)` or `}` into the charset check. HCL string escapes (`\\n`,
`\\t`, `\\r`, `\\"`, `\\\\`) are unescaped before the charset check so
literal `"a\\nb"` is checked as `a` + newline + `b` — all chars in the
allowed set.

If after these transformations the literal portion has a disallowed
char, the lint fails with a `::error file=...,line=...::` annotation
that GitHub renders inline on the PR.

Known omissions
---------------

Tag values constructed via `locals { ... }` blocks and then assigned
with `tags = local.x` are NOT walked transitively today. The lint
DOES scan `locals` map literals whose member name contains the
substring `tag` (case-insensitive), which covers the common pattern
`locals { common_tags = { ... } }`. Indirection through a differently
named local (e.g. `locals { metadata = { Purpose = "..." } }` with
`tags = local.metadata`) would slip through.

Why not python-hcl2
-------------------

The merge-into-default form arrives from python-hcl2 as a single
`${merge(...)}` string with the embedded map values inline; decomposing
that requires a second-pass parser anyway. A pure-stdlib regex over the
raw .tf source is simpler, has zero extra deps (matters for the
pre-commit hook), and reuses the same KV pattern as the audit script
that found the regression in the first place. Tracked by fixtures under
`tests/lints/terraform-tag-charset/fixtures/`.

Exit codes
----------

  0 — no violations
  1 — one or more violations (annotations on stderr)
  2 — usage error (no terraform/ found)
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import NamedTuple

# AWS resource-tag charset. Documented at
# https://docs.aws.amazon.com/general/latest/gr/aws_tagging.html and
# enforced by the per-service CreateTable/CreateBucket/... APIs. Empty
# string is allowed (some services use empty-value tags as flags).
ALLOWED = re.compile(r"^[A-Za-z0-9_.:/=+\-@\s]*$")

# `KEY = "VAL"` — KEY is a bare HCL identifier, VAL is a double-quoted
# string with `\"` escapes. Used with `finditer` against a
# strings-and-comments-redacted line so multiple KVs on one line are
# all picked up.
_KV = re.compile(r'([A-Za-z_][A-Za-z0-9_]*)\s*=\s*"((?:[^"\\]|\\.)*)"')

# `"QUOTED KEY" = "VAL"` — rarer but valid HCL when the key has
# whitespace or non-bare-identifier chars. A tag key like `"Created By"
# = "..."` is fine AWS-side (spaces are allowed) and shouldn't trip the
# lint; we still scan both sides for disallowed chars.
_QKV = re.compile(r'"((?:[^"\\]|\\.)*)"\s*=\s*"((?:[^"\\]|\\.)*)"')

# Block openers we treat as starting a tag scope.
# 1) `tags = {`
# 2) `tags = merge(`
# 3) `default_tags {` — provider default-tags block; nested `tags = {` follows
_TAGS_OPEN = re.compile(r"(?:^|[^A-Za-z0-9_])tags\s*=\s*(?:\{|merge\()")
_DEFAULT_TAGS_OPEN = re.compile(r"(?:^|[^A-Za-z0-9_])default_tags\s*\{")
# ASG singular `tag {` block — distinct from plural `tags`. Matches
# `tag {` but NOT `tags {` or `tag_specifications {` etc.
_TAG_BLOCK_OPEN = re.compile(r"(?:^|[^A-Za-z0-9_])tag\s*\{")
# `locals {` opener — we only scan its inner map literals whose member
# name contains `tag` (case-insensitive).
_LOCALS_OPEN = re.compile(r"(?:^|[^A-Za-z0-9_])locals\s*\{")
# `<name> = {` inside a `locals` block where <name> matches *tag* —
# starts a nested tag-map scope.
_LOCAL_TAG_MAP_OPEN = re.compile(
    r"^\s*([A-Za-z_][A-Za-z0-9_]*tag[A-Za-z0-9_]*|tag[A-Za-z0-9_]*)\s*=\s*\{",
    re.IGNORECASE,
)

# `${...}` interpolation — stripped before the charset check by a
# balanced-brace walker (`_strip_interp`) rather than a single regex,
# because HCL interpolations can contain nested braces (e.g.
# `${jsonencode({a=1})}`). A non-greedy `\$\{[^}]*\}` regex would stop
# at the first `}` and leak `)}` into the charset check — a false
# positive on legitimate jsonencode-style values.

# HCL string escapes we unescape before the charset check. Only the
# three whitespace escapes are unescaped; their resolved chars (LF,
# TAB, CR) sit inside `\s` and are AWS-allowed. Without this, the raw
# regex match captures the escape sequence (`\` + letter), which the
# charset check rejects because `\` is not in the allowed set —
# producing false positives on heredoc-free multi-line tag values
# written with `\n`.
#
# `\"` and `\\` are deliberately NOT in this table: their resolved
# chars (`"` and `\`) are NOT in the AWS allowed set, so a tag value
# containing them is a real violation that should fire. Leaving the
# escape sequence intact for the charset check has the same end
# result (the `\` itself is disallowed); either form correctly fails.
_UNESCAPE = {
    r"\n": "\n",
    r"\t": "\t",
    r"\r": "\r",
}


def _strip_interp(s: str) -> str:
    """Remove `${...}` interpolations with balanced-brace matching.

    Walks the string left-to-right; when `${` is seen, advances a
    brace counter through nested `{`/`}` until the counter returns to
    zero. This handles `${jsonencode({a=1})}` (one extra `{...}`
    inside) without leaking the closing `}` into the output.

    If a `${` opens but no matching `}` is found before end-of-string
    (i.e. the interpolation spans multiple HCL source lines, which is
    legal but uncommon in tag values), the rest of the string is
    dropped — safe direction: false negative on a constructed value,
    not a false positive.
    """
    out: list[str] = []
    i = 0
    n = len(s)
    while i < n:
        if s[i] == "$" and i + 1 < n and s[i + 1] == "{":
            depth = 1
            j = i + 2
            while j < n and depth > 0:
                if s[j] == "{":
                    depth += 1
                elif s[j] == "}":
                    depth -= 1
                j += 1
            if depth == 0:
                # Successfully consumed a balanced `${...}` — skip it.
                i = j
                continue
            # Unbalanced — drop the rest of the string.
            break
        out.append(s[i])
        i += 1
    return "".join(out)


def _unescape_hcl(s: str) -> str:
    """Apply common HCL string escapes before the charset check."""
    # Walk the string with a small state machine rather than serial
    # replace() so `\\n` (an escaped backslash followed by `n`)
    # doesn't get treated as a newline. The escape table covers the
    # five sequences that produce chars relevant to the charset check;
    # others (`\xHH`, `\uHHHH`) are rare in tag values — fall through
    # and let the raw bytes hit the charset check.
    out: list[str] = []
    i = 0
    while i < len(s):
        if s[i] == "\\" and i + 1 < len(s):
            esc = s[i : i + 2]
            if esc in _UNESCAPE:
                out.append(_UNESCAPE[esc])
                i += 2
                continue
        out.append(s[i])
        i += 1
    return "".join(out)


def _strip_line_comments(line: str) -> str:
    """Return `line` with `#` and `//` line comments removed, preserving
    content inside double-quoted strings.

    `_check_kv` needs the line's KV literals intact (so the `_KV` /
    `_QKV` regexes still match) but with trailing comments cleared
    (so `Name = "x" # note` is matched). A naive
    `line.split("#", 1)[0]` truncates `Name = "Ticket #1234"` mid-string
    and the unbalanced-quote remainder fails the `_KV` regex —
    producing a silent false negative on `#` inside a tag value, which
    is the exact failure mode this lint exists to catch. Walk the line
    with a small in-string state machine so `#` / `//` outside strings
    cut, and inside strings pass through.
    """
    # Fast path: the lint walks ~10k lines per CI run; the vast
    # majority have no `#` or `//` at all, so the state-machine walk
    # is pure overhead. `in` is a C-level scan.
    if "#" not in line and "//" not in line:
        return line
    out: list[str] = []
    i = 0
    in_str = False
    while i < len(line):
        ch = line[i]
        if in_str:
            if ch == "\\" and i + 1 < len(line):
                out.append(line[i])
                out.append(line[i + 1])
                i += 2
                continue
            if ch == '"':
                in_str = False
            out.append(ch)
            i += 1
            continue
        if ch == '"':
            in_str = True
            out.append(ch)
            i += 1
            continue
        if ch == "#":
            break
        if ch == "/" and i + 1 < len(line) and line[i + 1] == "/":
            break
        out.append(ch)
        i += 1
    return "".join(out)


def _redact_strings_and_comments(line: str) -> str:
    """Return `line` with double-quoted strings and `#`/`//` line
    comments replaced by spaces.

    Used for two things:
      1. Brace/paren depth counting — so a tag value like `"name-{x}"`
         doesn't skew `depth_brace`.
      2. Detecting opener patterns — so `description = "tags = { ... }"`
         in a variable's description doesn't fire `_TAGS_OPEN`.

    KV regex matching is still done against the ORIGINAL line — those
    regexes consume quoted strings as a single token, so they handle
    in-string braces correctly without this transform.

    Trailing `/* ... */` block comments are not stripped; HCL allows
    them but they're vanishingly rare in tag context in this repo.
    """
    out: list[str] = []
    i = 0
    in_str = False
    while i < len(line):
        ch = line[i]
        if in_str:
            if ch == "\\" and i + 1 < len(line):
                out.append("  ")
                i += 2
                continue
            if ch == '"':
                in_str = False
                out.append(" ")
                i += 1
                continue
            out.append(" ")
            i += 1
            continue
        # not in string
        if ch == '"':
            in_str = True
            out.append(" ")
            i += 1
            continue
        if ch == "#":
            # rest of line is a comment
            out.append(" " * (len(line) - i))
            break
        if ch == "/" and i + 1 < len(line) and line[i + 1] == "/":
            out.append(" " * (len(line) - i))
            break
        out.append(ch)
        i += 1
    return "".join(out)


class Finding(NamedTuple):
    lineno: int
    # "key" or "value" — inserted directly into the annotation as
    # "tag {label} contains chars outside…". For the ASG singular
    # `tag { key = "K" value = "V" }` form, the label reflects the
    # AWS-side category (offending tag-key reads as "tag key…", not
    # "tag value…"). The plural-map form has the same key/value
    # semantics on the HCL side, so they line up.
    label: str
    # Identifier on the left of `=` in the source line — bare or
    # quoted. For ASG singular blocks this is the literal HCL keyword
    # "key" or "value", not the AWS-side tag-key.
    hcl_key: str
    # Quoted string on the right of `=` in the source line.
    hcl_value: str
    # The actual string that failed the charset check. Cannot be
    # derived from `(label, hcl_key, hcl_value)` alone: in the ASG
    # singular form, an offending AWS tag-key arrives as `label="key"`
    # but the offender is `hcl_value` (`hcl_key` is the literal
    # identifier "key").
    offender: str


def _check_kv(
    lineno: int,
    line: str,
    findings: list[Finding],
) -> None:
    """Scan `line` for KV and QKV matches and append any charset
    violations to `findings`.

    Strips trailing comments first so `Name = "value" # note` is still
    matched. Multiple KVs on one line are all reported (covers
    `tags = { A = "x", B = "y" }` single-line maps).
    """
    redacted_for_comment = _strip_line_comments(line)
    # `_QKV` is a strict superset of `_KV` for quoted-key lines, but
    # the bare-identifier form is by far the common one — try `_KV`
    # first and `_QKV` for any region the bare match didn't cover.
    seen_spans: list[tuple[int, int]] = []
    for m in _KV.finditer(redacted_for_comment):
        seen_spans.append(m.span())
        key, value = m.group(1), m.group(2)
        _record_if_bad(lineno, key, value, findings)
    for m in _QKV.finditer(redacted_for_comment):
        # Skip QKV matches that overlap with a KV match already
        # recorded — `_KV` wouldn't match a quoted key, so any overlap
        # here is benign double-coverage of the same VALUE span.
        if any(s <= m.start() < e for s, e in seen_spans):
            continue
        key, value = m.group(1), m.group(2)
        _record_if_bad(lineno, key, value, findings)


def _record_if_bad(
    lineno: int,
    key: str,
    value: str,
    findings: list[Finding],
) -> None:
    if not ALLOWED.fullmatch(_unescape_hcl(_strip_interp(key))):
        findings.append(Finding(lineno, "key", key, value, key))
    if not ALLOWED.fullmatch(_unescape_hcl(_strip_interp(value))):
        findings.append(Finding(lineno, "value", key, value, value))


def _scan_file(path: Path) -> list[Finding]:
    """Return per-violation findings for `path`. See `Finding` for the
    tuple shape.

    Tracks four overlapping scopes via boolean flags + structural depth:
      - in_tags_map: inside a `tags = { ... }` / `tags = merge(...)` /
        `default_tags { ... }` block. KV scan is "permissive": every
        `KEY = "VAL"` line is a candidate tag entry.
      - in_tag_block: inside an ASG singular `tag { ... }` block. Only
        `key`/`value` KVs are tag entries; others are ignored.
      - in_locals: inside a top-level `locals { ... }` block. KV scan
        runs only when also inside an `in_local_tag_map`.
      - in_local_tag_map: inside a `<name> = { ... }` literal in a
        `locals` block where <name> contains "tag" (case-insensitive).

    Depth is tracked with a single brace+paren counter that ignores
    chars inside double-quoted strings and `#`/`//` line comments (via
    `_redact_strings_and_comments`).
    """
    findings: list[Finding] = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return findings

    in_tags_map = False
    in_tag_block = False
    in_locals = False
    in_local_tag_map = False
    # Depth at which the current scope opens. When `depth_brace +
    # depth_paren` returns to that value, the scope ends.
    tags_map_open_depth = 0
    tag_block_open_depth = 0
    locals_open_depth = 0
    local_tag_map_open_depth = 0
    depth_brace = 0
    depth_paren = 0

    for lineno, line in enumerate(text.splitlines(), 1):
        redacted = _redact_strings_and_comments(line)

        # ---- detect new scope openers BEFORE updating depth ----
        # Order matters: `default_tags {` contains `tags`, so check it
        # first; `_TAGS_OPEN` also won't match `default_tags` because
        # of the `[^A-Za-z0-9_]` boundary. `_TAG_BLOCK_OPEN` would
        # match `tag {` but we suppress it if we're already inside a
        # tags map (rare nesting, not a real HCL pattern).
        opens_tag_block = False
        if not in_tags_map and not in_tag_block:
            if _DEFAULT_TAGS_OPEN.search(redacted):
                in_tags_map = True
                tags_map_open_depth = depth_brace + depth_paren
            elif _TAGS_OPEN.search(redacted):
                in_tags_map = True
                tags_map_open_depth = depth_brace + depth_paren
            elif _TAG_BLOCK_OPEN.search(redacted):
                in_tag_block = True
                opens_tag_block = True
                tag_block_open_depth = depth_brace + depth_paren
            elif not in_locals and _LOCALS_OPEN.search(redacted):
                in_locals = True
                locals_open_depth = depth_brace + depth_paren

        if in_locals and not in_local_tag_map:
            m = _LOCAL_TAG_MAP_OPEN.match(redacted)
            if m:
                in_local_tag_map = True
                local_tag_map_open_depth = depth_brace + depth_paren

        # ---- KV scan ----
        # Run BEFORE depth update so the opener line
        # (`tags = { A = "x" }`) is scanned: a single-line map closes
        # the scope on the same line, and depth-based closing would
        # otherwise short-circuit before KVs are read.
        if in_tags_map or in_local_tag_map:
            _check_kv(lineno, line, findings)
        elif in_tag_block:
            # ASG singular `tag` block: only `key`/`value` KVs are
            # tag entries. The HCL `key`/`value` identifier IS the
            # AWS-side label, so remap so an offending tag-key surfaces
            # as "tag key contains chars outside…" not "tag value …"
            # (which would suggest the wrong fix direction).
            local: list[Finding] = []
            _check_kv(lineno, line, local)
            for f in local:
                if f.hcl_key not in ("key", "value"):
                    continue
                findings.append(f._replace(label=f.hcl_key))

        # ---- update depth from the redacted line ----
        delta = redacted.count("{") + redacted.count("(") - redacted.count(
            "}"
        ) - redacted.count(")")
        depth_brace += redacted.count("{") - redacted.count("}")
        depth_paren += redacted.count("(") - redacted.count(")")
        current_depth = depth_brace + depth_paren

        # If this line both opened and closed the scope, the opener
        # check above set `in_*` True and the current_depth is now
        # back at open_depth. We've already scanned the opener line's
        # KVs, so close the scope here.
        if in_local_tag_map and current_depth <= local_tag_map_open_depth:
            in_local_tag_map = False
        if in_tags_map and current_depth <= tags_map_open_depth:
            in_tags_map = False
        if in_tag_block and current_depth <= tag_block_open_depth:
            # Don't close a `tag {` block on the same line it opened
            # if the line *only* contained the opener — `_TAG_BLOCK_OPEN`
            # consumed the `{`, depth went up by 1, so we shouldn't be
            # at or below open_depth yet. The condition triggers only
            # if the block actually closed on this line (single-line
            # `tag { key = "k" value = "v" }`).
            if not opens_tag_block or delta <= 0:
                in_tag_block = False
        if in_locals and current_depth <= locals_open_depth:
            in_locals = False
            in_local_tag_map = False

    return findings


def main() -> int:
    # `python -OO` strips docstrings to None; guard so the script still
    # runs under aggressive optimization (the description is only for
    # `--help` output, so an empty string is fine).
    description = (__doc__ or "").splitlines()[0] if __doc__ else ""
    ap = argparse.ArgumentParser(description=description)
    ap.add_argument(
        "root",
        nargs="?",
        default="terraform",
        help="Directory to scan recursively for *.tf files (default: terraform/).",
    )
    args = ap.parse_args()

    root = Path(args.root)
    if not root.is_dir():
        print(f"::error::{root} is not a directory", file=sys.stderr)
        return 2

    violations = 0
    # Sort the walk so the annotation order is deterministic across
    # runners — easier diffs on CI failure logs.
    for tf in sorted(root.rglob("*.tf")):
        # Skip vendored / build state. `examples/` are reference
        # snippets that aren't applied — same posture as
        # `_tf_lint_lib.parse_tf_files`.
        if any(part in {".terraform", "examples"} for part in tf.parts):
            continue
        for lineno, label, key, value, offender in _scan_file(tf):
            violations += 1
            # Display the offending side so the fix is obvious. Don't
            # try to point at the exact char column — multi-codepoint
            # offenders (e.g. a unicode arrow that displays as one
            # grapheme) make col= unreliable in the GitHub UI.
            print(
                f"::error file={tf},line={lineno}::"
                f"tag {label} contains chars outside AWS's allowed "
                f"set [A-Za-z0-9_.:/=+\\-@\\s]: "
                f'{key} = "{value}"  (offending {label}: {offender!r})',
                file=sys.stderr,
            )

    if violations:
        print(
            f"\n{violations} tag-charset violation(s) found. "
            "AWS rejects these at CreateTable/CreateBucket/etc. time with "
            '"ValidationException: The Tag Value provided is invalid". '
            "Fix by restricting the value to letters, digits, spaces, "
            "and the chars _.:/=+-@. Common offenders: unicode arrows "
            "(→), parens (...), angle brackets <...>.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
