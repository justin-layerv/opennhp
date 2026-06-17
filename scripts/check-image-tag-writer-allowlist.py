#!/usr/bin/env python3
"""Allowlist guard for writers of /<env>/nhp/<component>/{,green-}image-tag.

See scripts/check-image-tag-writer-allowlist.sh for the contract and
background. This script does the actual scan.

Detection model:
  1. Find every `aws ssm put-parameter` invocation in each candidate
     file (workflows under .github/workflows/, scripts under
     .github/scripts/ and scripts/).
  2. Read the `--name` argument of that invocation (literal or
     variable reference, possibly on a continuation line within the
     LOOKAHEAD window — see constant below).
  3. Resolve the name:
       - Literal slot path → flagged write.
       - "$VAR" / "${VAR}"  → look backwards within the enclosing
         step / `run:` block for a `VAR=…` assignment, then fall
         back to YAML step-level `env:` blocks (sibling to `run:`).
         If the resolved RHS contains a slot path, flagged write.
  4. Files in the allowlist are skipped.

Known-uncovered shapes (out of scope today, tracked in #2028):
  - boto3 `ssm.put_parameter(Name=…)` calls (Python writers). The
    one in-tree boto3 writer is canary_orchestrator.py, which has
    a runtime guard at the set_ssm_value entry point until the
    bash detector is widened to cover boto3.
  - Heredoc / `file://` argument values for `--name`. AWS CLI
    accepts these; in-tree writers don't use them.
  - `aws ssm put-parameters` (plural, bulk API). PUT_RE is
    singular only.

Exit code: 0 clean, 1 if any out-of-allowlist writer is found.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path
from typing import Iterable

# Files allowed to write the {blue,green}-image-tag slots. Update this
# allowlist AND the rationale block in the .sh wrapper in the same PR
# that introduces a new legitimate writer. The lint's own .sh and .py
# files are listed because they contain slot-path regexes that look
# like writes to the detector. The fixture-test file lives outside
# scan_files' glob and is not allowlisted here — adding it would be
# dead weight.
ALLOWLIST = {
    ".github/workflows/blue-green-deploy.yml",
    ".github/workflows/canary-deploy.yml",
    ".github/scripts/update-ssm-image-tag.sh",
    # NHP-Relay CD deploy leg (#2624). The relay is a plain single ASG
    # (not blue/green), so it cannot route through blue-green-deploy.yml;
    # this dedicated, single-purpose helper writes /<env>/nhp/relay/image-tag
    # and triggers the relay ASG instance refresh. Keeping the write here
    # (rather than allowlisting build-and-push.yml itself) preserves the
    # fence's ability to catch a build-matrix re-introduction of the
    # image-tag write — the original race this guard exists to prevent.
    ".github/scripts/deploy-relay.sh",
    "scripts/check-image-tag-writer-allowlist.sh",
    "scripts/check-image-tag-writer-allowlist.py",
}

# Component segment is `[^/]+` (not literal `server|ac`) so the
# templated `${SSM_COMPONENT}` form used by real writers matches too.
SLOT_PATH_RE = re.compile(r"/nhp/[^/]+/(green-)?image-tag")
# Bash AWS CLI only — boto3's `ssm.put_parameter(...)` is NOT
# detected. One legitimate boto3 writer exists outside scope
# (terraform/modules/canary-deployment/lambda/canary_orchestrator.py
# — the prod canary's slot updater). Widening to cover boto3 is
# tracked in #2028. If you're adding a Python/Lambda writer of
# these slots, prefer routing through the bash deployer family
# until that lands.
PUT_RE = re.compile(r"aws\s+ssm\s+put-parameter")
# AWS CLI accepts `--name "v"`, `--name 'v'`, and `--name=v`.
NAME_ARG_RE = re.compile(r'--name(?:\s+|=)(?:"([^"]+)"|\'([^\']+)\'|(\S+))')
VAR_REF_RE = re.compile(r"^\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?$")

# How many lines forward to search from a `put-parameter` line for
# its `--name` argument; covers multi-line continuations. In-tree
# writers max out at 6; 10 absorbs future formatting choices.
NAME_ARG_LOOKAHEAD = 10

# Backward variable resolution stops at any of these so an unrelated
# assignment in an earlier YAML step cannot shadow the real one.
# Shell scripts have no such markers — file-global resolution there
# is correct (one shell file = one block).
BLOCK_BOUNDARY_RES = (
    re.compile(r"^\s*-\s*name:"),       # YAML step boundary
    re.compile(r"^\s*(-\s*)?run:"),     # start of `run:` block — covers
                                        # dashed list-item form (`- run: |`),
                                        # attribute-position form (`run: |`),
                                        # all scalar styles (|, |-, >, >-),
                                        # and inline shape (`run: cmd`).
)


def scan_files(repo_root: Path) -> Iterable[Path]:
    """All workflow YAML + shell scripts we want to police."""
    candidates: list[Path] = []
    candidates.extend((repo_root / ".github" / "workflows").glob("*.yml"))
    candidates.extend((repo_root / ".github" / "scripts").glob("*.sh"))
    candidates.extend((repo_root / ".github" / "scripts").glob("*.py"))
    candidates.extend((repo_root / "scripts").glob("*.sh"))
    candidates.extend((repo_root / "scripts").glob("*.py"))
    return sorted(candidates)


def relpath(p: Path, repo_root: Path) -> str:
    return os.path.relpath(p, repo_root)


def resolve_name_value(lines: list[str], put_idx: int) -> tuple[str | None, int | None]:
    """Return (name_value, line_idx) for the `--name` arg attached to the
    `put-parameter` at lines[put_idx]. Looks ahead up to
    NAME_ARG_LOOKAHEAD lines (covers multi-line continuations) but
    also stops at BLOCK_BOUNDARY_RES so a `put-parameter` without
    `--name` (unusual, e.g. `--cli-input-json`) can't pick up the
    `--name` arg of an unrelated command in a later YAML step."""
    # Skip the put-parameter line itself when checking boundaries —
    # the line where the search starts isn't a boundary into itself.
    for offset in range(0, NAME_ARG_LOOKAHEAD + 1):
        idx = put_idx + offset
        if idx >= len(lines):
            break
        if offset > 0 and any(b.match(lines[idx]) for b in BLOCK_BOUNDARY_RES):
            break
        m = NAME_ARG_RE.search(lines[idx])
        if m:
            # Three alternation groups (double-quoted, single-quoted,
            # unquoted) — exactly one matches when m is truthy.
            return next(g for g in m.groups() if g is not None), idx
    return None, None


def resolve_variable(lines: list[str], var_name: str, before_idx: int) -> str | None:
    """Find the most recent `VAR=...` assignment to a literal string
    above before_idx. Returns the literal (unquoted) RHS, or None.

    The backward walk stops at any line matching BLOCK_BOUNDARY_RES
    (step boundary / start of `run:` block in YAML) so an unrelated
    assignment in an earlier step cannot shadow the real one. Shell
    scripts have no such boundary markers, so resolution stays
    file-global there — which is correct because a shell script
    is one block."""
    # Three alternation groups for the RHS: double-quoted,
    # single-quoted, and unquoted (terminated by whitespace).
    pattern = re.compile(
        rf"\b{re.escape(var_name)}=(?:\"([^\"\n]+)\"|'([^'\n]+)'|(\S+))"
    )
    for idx in range(before_idx, -1, -1):
        if any(b.match(lines[idx]) for b in BLOCK_BOUNDARY_RES):
            return None
        m = pattern.search(lines[idx])
        if m:
            return next(g for g in m.groups() if g is not None)
    return None


def resolve_yaml_env_var(lines: list[str], var_name: str) -> str | None:
    """Find `<var_name>: <value>` inside any YAML `env:` block in the
    file. Returns the value or None.

    Step-level `env:` blocks are sibling to `run:` in a workflow
    step, so they're outside the run-block boundary that
    resolve_variable stops at. A step like:

        - run: |
            aws ssm put-parameter --name "$SSM_PARAM" ...
          env:
            SSM_PARAM: /sandbox/nhp/server/image-tag

    would otherwise smuggle a slot-path write past the lint. This
    is a coarse file-global scan (not bounded to a specific step's
    env block) — false-positive risk is acceptable for the same
    reason as the shell case: any env: assignment of $VAR to a slot
    path that is later used in `put-parameter --name "$VAR"` IS a
    write to that slot, regardless of which step the env: lives in.
    """
    name_re = re.compile(rf"^(\s+){re.escape(var_name)}:\s*[\"']?([^\"'\n]+?)[\"']?\s*(?:#.*)?$")
    env_re = re.compile(r"^(\s*)env:\s*$")
    in_env_block_indent: int | None = None
    for line in lines:
        em = env_re.match(line)
        if em:
            in_env_block_indent = len(em.group(1))
            continue
        if in_env_block_indent is None:
            continue
        # Skip blank / comment-only lines without leaving the block.
        stripped = line.lstrip()
        if not stripped or stripped.startswith("#"):
            continue
        # Determine current line's indent. Leaving the env: block when
        # indent regresses to env:'s level or less.
        line_indent = len(line) - len(stripped)
        if line_indent <= in_env_block_indent:
            in_env_block_indent = None
            # Re-evaluate this line in case it starts another env block.
            em2 = env_re.match(line)
            if em2:
                in_env_block_indent = len(em2.group(1))
            continue
        nm = name_re.match(line)
        if nm:
            return nm.group(2)
    return None


def find_writes(path: Path) -> list[tuple[int, str]]:
    """Return a list of (line_no, slot_path) tuples where the file writes
    a slot path via put-parameter."""
    text = path.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()
    hits: list[tuple[int, str]] = []
    for i, line in enumerate(lines):
        if not PUT_RE.search(line):
            continue
        name_value, name_idx = resolve_name_value(lines, i)
        if not name_value:
            continue
        # Direct literal slot path.
        if SLOT_PATH_RE.search(name_value):
            hits.append((i + 1, name_value))
            continue
        # Variable reference — trace assignment.
        m = VAR_REF_RE.match(name_value.strip())
        if not m:
            continue
        var_name = m.group(1)
        rhs = resolve_variable(lines, var_name, name_idx - 1 if name_idx else i)
        if rhs is None:
            # No shell-level assignment found within the step's run
            # block. Fall back to YAML step-level env: blocks, which
            # are sibling to run: (outside the run-block boundary).
            rhs = resolve_yaml_env_var(lines, var_name)
        if rhs and SLOT_PATH_RE.search(rhs):
            hits.append((i + 1, f'${{{var_name}}}="{rhs}"'))
    return hits


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path(__file__).resolve().parent.parent,
        help="Repository root to scan (default: this script's parent's parent)",
    )
    args = parser.parse_args()
    repo_root: Path = args.repo_root.resolve()

    violations: list[tuple[str, list[tuple[int, str]]]] = []
    for path in scan_files(repo_root):
        rel = relpath(path, repo_root)
        if rel in ALLOWLIST:
            continue
        hits = find_writes(path)
        if hits:
            violations.append((rel, hits))

    if not violations:
        print("OK: no out-of-allowlist writers of /<env>/nhp/<component>/{blue,green}-image-tag")
        return 0

    print(
        "ERROR: file(s) outside the allowlist write the {blue,green}-image-tag SSM slot:",
        file=sys.stderr,
    )
    for rel, hits in violations:
        print(f"  - {rel}", file=sys.stderr)
        for lineno, value in hits:
            print(f"      line {lineno}: --name {value}", file=sys.stderr)
    print("", file=sys.stderr)
    print(
        "Allowed writers (update both the ALLOWLIST in this script and the",
        file=sys.stderr,
    )
    print(
        "rationale block in scripts/check-image-tag-writer-allowlist.sh in",
        file=sys.stderr,
    )
    print("the same PR if you genuinely need a new one):", file=sys.stderr)
    for entry in sorted(ALLOWLIST):
        print(f"  - {entry}", file=sys.stderr)
    print("", file=sys.stderr)
    print(
        "If you're adding a new deployer, prefer routing through",
        file=sys.stderr,
    )
    print(
        "blue-green-deploy.yml (sandbox) or canary-deploy.yml (prod)",
        file=sys.stderr,
    )
    print(
        "rather than introducing a third writer.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
