#!/usr/bin/env python3
"""check-iam-description-charset.py

Fences IAM description strings that terraform will plan happily and AWS will
reject at apply.

WHY THIS EXISTS
===============

#3827 fixed a broken sandbox deploy on main:

    creating IAM Role (layerv-nhp-sandbox-qurl-otp-email-gate):
    ValidationError: Value at 'description' failed to satisfy constraint:
    Member must satisfy regular expression pattern:
    [\\u0009\\u000A\\u000D\\u0020-\\u007E\\u00A1-\\u00FF]*

The description contained an em dash (U+2014), which falls in the gap between
ASCII printable (U+007E) and the Latin-1 supplement (U+00A1). Typographic
punctuation is easy to introduce -- em dashes, curly quotes, ellipses, and
non-breaking spaces all live outside that range and all read as ordinary
prose.

WHAT MAKES THIS WORTH A STATIC CHECK
====================================

`terraform plan` validates such a description PERFECTLY CLEANLY. Only
`CreateRole`/`CreatePolicy` rejects it, at apply. So this class cannot fail in
review: it merges green and breaks the deploy afterwards. #3827's instance was
additionally masked -- the resource was `count = 0` until #3821 wired its flag
through, so the invalid description sat on main unexecuted until the day it
became real.

SCOPE
=====

Deliberately narrow, to what is actually known rather than guessed:

- `aws_iam_role.description` and `aws_iam_policy.description`, against the
  exact charset from the AWS error above.

Other services do NOT share this constraint and are intentionally not checked:
the Secrets Manager description in `terraform/agent_otp_ses.tf` contains an em
dash and applies fine today. Terraform `variable` descriptions are never sent
to AWS at all. Guessing at other services' charsets would produce false
positives on strings that work.

Interpolations (`${...}`) are checked as written: only the literal text can be
inspected here, and a non-ASCII character in the literal is the bug this
catches.

KNOWN COVERAGE GAP
==================

Only an inline `description = "literal"` inside an `aws_iam_role` or
`aws_iam_policy` block is scanned. A bad character can still reach IAM via a
module input that creates the role, a `local`/`var` default interpolated into
the description, or a heredoc-form description. Those are false negatives, not
false positives, so the check never blocks a valid change -- but a clean run
here is not proof that no IAM description anywhere carries a rejected
character. The parser also assumes `terraform fmt` layout: nested blocks
indented, and the resource closing brace at column zero.

Two more shapes in the same false-negative family: `str.splitlines()` also
breaks on U+2028/U+2029/U+0085/form-feed, so a description literal containing
one is split across "lines" and slips past the assignment pattern; and the
greedy capture can pull a trailing comment into the scanned value when the
comment itself contains a quote, which errs toward over-strictness rather than
under.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_ROOT = REPO_ROOT / "terraform"

# The exact set AWS names in the ValidationError: tab, LF, CR, ASCII printable,
# and the Latin-1 supplement. Anything else is rejected at apply.
IAM_DISALLOWED = re.compile(r"[^\t\n\r\x20-\x7e\xa1-\xff]")

RESOURCE_OPEN = re.compile(r'^\s*resource\s+"(aws_iam_role|aws_iam_policy)"\s+"([^"]+)"\s*\{')
BLOCK_CLOSE = re.compile(r"^\}")
# The trailing part is optional so `description = "..." # TODO` is still
# scanned. Anchoring on end-of-line let a bad character hide behind an inline
# comment while the fence stayed green -- the precise shape this exists to stop.
DESCRIPTION_ASSIGN = re.compile(r'^\s*description\s*=\s*"(.*)"\s*(?:(?:#|//).*)?$')
# A heredoc body can contain a column-zero `}` (JSON policy documents routinely
# do), which would otherwise look like the end of the resource block and stop
# scanning early, skipping any description that follows.
HEREDOC_OPEN = re.compile(r"=\s*<<-?\s*([A-Za-z_][A-Za-z0-9_]*)\s*$")


def offending_characters(value: str) -> list[str]:
    """The distinct disallowed characters in value, as U+XXXX labels."""
    seen: list[str] = []
    for ch in IAM_DISALLOWED.findall(value):
        if ch not in seen:
            seen.append(ch)
    return [f"{ch!r} (U+{ord(ch):04X})" for ch in seen]


def scan(tf_file: Path, base: Path) -> int:
    """Report IAM descriptions with characters AWS will reject. Returns failures."""
    failures = 0
    inside: str | None = None
    heredoc: str | None = None
    # errors="replace" rather than letting a non-UTF-8 byte raise: a traceback
    # would fail the run without the ::error:: framing every other message uses.
    # It also improves detection -- a mangled byte becomes U+FFFD, which the
    # disallowed-charset regex catches and reports properly.
    body = tf_file.read_text(encoding="utf-8", errors="replace")
    for lineno, line in enumerate(body.splitlines(), 1):
        if heredoc is not None:
            if line.strip() == heredoc:
                heredoc = None
            continue
        started = HEREDOC_OPEN.search(line)
        if started:
            heredoc = started.group(1)
            continue
        opened = RESOURCE_OPEN.match(line)
        if opened:
            inside = f"{opened.group(1)}.{opened.group(2)}"
            continue
        if inside and BLOCK_CLOSE.match(line):
            inside = None
            continue
        if not inside:
            continue
        assigned = DESCRIPTION_ASSIGN.match(line)
        if not assigned:
            continue
        bad = offending_characters(assigned.group(1))
        if bad:
            failures += 1
            print(
                f"::error file={tf_file.relative_to(base)},line={lineno}::"
                f"{inside}: description contains {', '.join(bad)}, which IAM rejects. "
                f"Allowed: tab/LF/CR, ASCII printable, and Latin-1 supplement "
                f"(U+00A1-U+00FF); the gap catches em dashes, curly quotes, "
                f"ellipses, and non-breaking spaces. terraform plan accepts this "
                f"and CreateRole/CreatePolicy fails at APPLY, so it breaks the "
                f"deploy rather than the review. Use plain ASCII punctuation."
            )
    return failures


def main(argv: list[str]) -> int:
    root = Path(argv[1]).resolve() if len(argv) > 1 else DEFAULT_ROOT
    base = root if len(argv) > 1 else REPO_ROOT

    if not root.is_dir():
        print(f"::error::{root} not found", file=sys.stderr)
        return 1

    tf_files = sorted(root.rglob("*.tf"))
    if not tf_files:
        print(f"::error::no .tf files under {root} — the check is not looking where it thinks it is", file=sys.stderr)
        return 1

    failures = sum(scan(tf, base) for tf in tf_files)

    if failures:
        print(f"\nIAM description charset check: FAILED ({failures} description(s))")
        return 1

    print(f"IAM description charset check: OK ({len(tf_files)} file(s))")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
