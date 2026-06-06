#!/usr/bin/env python3
"""check-cis-metric-filter-patterns.py

Freeze the CIS v1.4.0 CloudWatch Logs metric-filter patterns defined in
`terraform/modules/security/cloudtrail_metric_filters.tf` against a golden
reference, so an accidental edit to a `pattern` fails CI at PR time.

Why
---
AWS Security Hub matches each CloudWatch.N control against the EXACT
CIS-prescribed filter term set and fails the control on any divergence
("this control fails if the exact metric filters prescribed by CIS are not
used. Additional fields or terms cannot be added."). A one-character edit
to a `pattern` therefore silently reverts a CIS control (CloudWatch.1/4/5/
6/7/8/9/10/11/12/13/14) to FAILED — and the only place that surfaces today
is the Security Hub re-evaluation ~18h after the *prod* apply (sandbox has
no trail, so it cannot pre-validate; `terraform validate` does not check
pattern fidelity). This lint converts that slow, post-apply failure into a
red check on the PR that touched the pattern.

How
---
The golden file (`tests/lints/cis-metric-filter-patterns/golden.json`)
holds the canonical patterns under a `patterns` object, each validated
verbatim against the AWS Security Hub CloudWatch.N remediation pages (see
the `cloudtrail_metric_filters.tf` header). The checker extracts the
`pattern` literals from the `cloudtrail_filters` map in the .tf (HCL
`\"`/`\\` escapes resolved) and asserts the set equals the golden. Editing
a pattern therefore requires editing BOTH the .tf and the golden in the
same PR — a deliberate, reviewed act — which is the entire point.

`--dump` prints the extracted `{key: pattern}` as JSON (used to (re)generate
the golden after a deliberate, re-validated change).

Why regex over python-hcl2: the patterns embed `{`, `}`, `$.`, and escaped
quotes; a pure-stdlib scan that redacts quoted strings before counting
braces is simpler, has zero extra deps (this runs in the PR lint job), and
mirrors `.github/scripts/check-terraform-tag-charset.py`.

Exit codes:
  0 — tf patterns exactly match the golden set
  1 — drift (a pattern was added, removed, or changed)
  2 — usage error (file not found / unreadable / malformed golden)
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import NamedTuple

DEFAULT_TF = "terraform/modules/security/cloudtrail_metric_filters.tf"
DEFAULT_GOLDEN = "tests/lints/cis-metric-filter-patterns/golden.json"

# `cloudtrail_filters = {` — opens the map whose entries we freeze.
_MAP_OPEN = re.compile(r"(?:^|[^A-Za-z0-9_])cloudtrail_filters\s*=\s*\{")
# A map entry opener: `  some_key = {` on its own line (no quotes, so the
# raw line is safe to match). Entries contain no nested `{` blocks, so
# within the map this uniquely identifies the 12 filter keys.
_ENTRY_OPEN = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*\{\s*$")
# `pattern = "<literal>"` — the double-quoted value with `\"` escapes.
# Anchored to line start (after indent) so only a real `pattern = "..."`
# field matches, never the substring `pattern` inside another value. The
# resource's `pattern = each.value.pattern` reference has no quote after
# `=`, so it is not matched either.
_PATTERN_KV = re.compile(r'^\s*pattern\s*=\s*"((?:[^"\\]|\\.)*)"')
# `control = "<literal>"` — the human/Security-Hub control id per entry.
# Captured for golden provenance only (NOT compared); it lets a reviewer
# cross-check each frozen pattern against its AWS CloudWatch.N remediation
# page when the golden is updated. Anchored like _PATTERN_KV above.
_CONTROL_KV = re.compile(r'^\s*control\s*=\s*"((?:[^"\\]|\\.)*)"')


def _redact_strings(line: str) -> str:
    """Return the line with double-quoted strings AND `#`/`//` comments
    dropped, for brace counting only.

    The `pattern` values contain literal `{`/`}` (e.g. `{ $.eventName =
    ... }`), so counting braces on the raw line would skew map depth.
    Comments are dropped too because a comment can carry an unbalanced
    brace (e.g. the `${` JSON-path note in this module's header) that
    would otherwise misalign the map bounds. Entry/pattern/control
    regexes still run on the RAW line, so dropping the comment tail here
    is safe. Outside the map this is harmless; inside it, it keeps the
    map-close depth math honest regardless of comment contents.

    Caveat: only single-line `#` / `//` comments are stripped, not
    multi-line `/* ... */` block comments. The guarded module uses only
    `#` comments, so this is correct today; if a `/* */` block comment is
    ever added inside the `cloudtrail_filters` map, keep any braces in it
    balanced or extend this helper (a fixture exercises an in-map
    `#`-comment-with-brace to fence the `#`/`//` path).
    """
    out: list[str] = []
    in_str = False
    i = 0
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
        if ch == '"':
            in_str = True
            out.append(" ")
            i += 1
            continue
        # Outside a string: a `#` or `//` starts a comment — drop the
        # rest of the line for depth-counting purposes.
        if ch == "#" or (ch == "/" and i + 1 < len(line) and line[i + 1] == "/"):
            break
        out.append(ch)
        i += 1
    return "".join(out)


def _unescape_hcl(s: str) -> str:
    """Resolve the HCL string escapes that appear in these patterns.

    Only `\\"` -> `"` and `\\\\` -> `\\` occur (the CIS patterns quote
    literals like "Root" / "Failed authentication"). Resolving them means
    the golden stores the human-readable canonical pattern with real
    quotes, matching the AWS remediation text.
    """
    out: list[str] = []
    i = 0
    while i < len(s):
        if s[i] == "\\" and i + 1 < len(s):
            nxt = s[i + 1]
            if nxt in ('"', "\\"):
                out.append(nxt)
                i += 2
                continue
        out.append(s[i])
        i += 1
    return "".join(out)


class Entry(NamedTuple):
    lineno: int
    pattern: str
    control: str  # provenance only (e.g. "CloudWatch.1 / CIS v1.4.0 4.3")


def extract_patterns(tf_path: Path) -> dict[str, Entry]:
    """Return {filter_key: Entry(lineno, pattern, control)} from the
    cloudtrail_filters map.

    Raises FileNotFoundError/OSError to the caller.
    """
    text = tf_path.read_text(encoding="utf-8")
    patterns: dict[str, str] = {}
    controls: dict[str, str] = {}
    linenos: dict[str, int] = {}

    in_map = False
    map_base_depth = 0
    depth = 0
    current_key: str | None = None

    for lineno, line in enumerate(text.splitlines(), 1):
        redacted = _redact_strings(line)

        if not in_map:
            if _MAP_OPEN.search(redacted):
                in_map = True
                # Depth BEFORE applying this line's braces is the base the
                # map closes back to.
                map_base_depth = depth
            depth += redacted.count("{") - redacted.count("}")
            continue

        # Inside the map. Detect entry keys, pattern literals, and the
        # control provenance on the raw line, then update depth and check
        # for map close.
        entry = _ENTRY_OPEN.match(line)
        if entry:
            current_key = entry.group(1)
        elif current_key is not None:
            pm = _PATTERN_KV.search(line)
            if pm:
                patterns[current_key] = _unescape_hcl(pm.group(1))
                linenos[current_key] = lineno
            else:
                cm = _CONTROL_KV.search(line)
                if cm:
                    controls[current_key] = _unescape_hcl(cm.group(1))

        depth += redacted.count("{") - redacted.count("}")
        if depth <= map_base_depth:
            in_map = False

    return {
        key: Entry(linenos[key], pattern, controls.get(key, ""))
        for key, pattern in patterns.items()
    }


def _load_golden(golden_path: Path) -> dict[str, str]:
    data = json.loads(golden_path.read_text(encoding="utf-8"))
    pats = data.get("patterns")
    if not isinstance(pats, dict):
        raise ValueError(
            f"{golden_path}: expected a top-level 'patterns' object"
        )
    return {str(k): str(v) for k, v in pats.items()}


def main() -> int:
    description = (__doc__ or "").splitlines()[0] if __doc__ else ""
    ap = argparse.ArgumentParser(description=description)
    ap.add_argument("--tf", default=DEFAULT_TF, help=f"(default: {DEFAULT_TF})")
    ap.add_argument(
        "--golden", default=DEFAULT_GOLDEN, help=f"(default: {DEFAULT_GOLDEN})"
    )
    ap.add_argument(
        "--dump",
        action="store_true",
        help="Print extracted {key: pattern} as JSON and exit 0 (regenerate golden).",
    )
    args = ap.parse_args()

    tf_path = Path(args.tf)
    try:
        extracted = extract_patterns(tf_path)
    except (FileNotFoundError, OSError) as exc:
        print(f"::error::cannot read {tf_path}: {exc}", file=sys.stderr)
        return 2

    if args.dump:
        ordered = sorted(extracted.items())
        json.dump(
            {
                # Provenance: the AWS Security Hub control each pattern
                # maps to, so a reviewer can re-validate the golden against
                # the named CloudWatch.N remediation page. Not compared.
                "_controls": {k: e.control for k, e in ordered},
                "patterns": {k: e.pattern for k, e in ordered},
            },
            sys.stdout,
            indent=2,
        )
        print()
        return 0

    golden_path = Path(args.golden)
    try:
        golden = _load_golden(golden_path)
    except (FileNotFoundError, OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"::error::cannot read golden {golden_path}: {exc}", file=sys.stderr)
        return 2

    tf_patterns = {k: e.pattern for k, e in extracted.items()}
    tf_lines = {k: e.lineno for k, e in extracted.items()}

    drift = 0

    # Added: in tf, not in golden.
    for key in sorted(set(tf_patterns) - set(golden)):
        drift += 1
        print(
            f"::error file={tf_path},line={tf_lines[key]}::"
            f"CIS metric-filter '{key}' is not in the golden set "
            f"({golden_path}). If this is a deliberate, AWS-validated "
            f"addition, add it to the golden (e.g. via --dump).",
            file=sys.stderr,
        )

    # Removed: in golden, not in tf.
    for key in sorted(set(golden) - set(tf_patterns)):
        drift += 1
        print(
            f"::error file={tf_path}::"
            f"CIS metric-filter '{key}' is in the golden set but missing "
            f"from {tf_path}. Removing a control's filter reverts its "
            f"Security Hub control to FAILED; remove it from the golden too "
            f"if that is intended.",
            file=sys.stderr,
        )

    # Changed: present in both, pattern differs.
    for key in sorted(set(tf_patterns) & set(golden)):
        if tf_patterns[key] != golden[key]:
            drift += 1
            print(
                f"::error file={tf_path},line={tf_lines[key]}::"
                f"CIS metric-filter '{key}' pattern diverges from the "
                f"frozen golden. Security Hub fails the control on ANY "
                f"divergence from the canonical CIS term set.\n"
                f"  golden: {golden[key]}\n"
                f"  found : {tf_patterns[key]}",
                file=sys.stderr,
            )

    if drift:
        print(
            f"\n{drift} CIS metric-filter pattern drift(s) found. These "
            "patterns are frozen: Security Hub matches them verbatim and a "
            "divergence silently FAILS the CloudWatch.N control ~18h after "
            "the prod apply. If the change is deliberate, re-validate against "
            "the AWS Security Hub CloudWatch.N remediation pages and update "
            f"{golden_path} (the script's --dump regenerates it from the .tf).",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
