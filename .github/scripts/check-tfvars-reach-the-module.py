#!/usr/bin/env python3
"""check-tfvars-reach-the-module.py

Fences the "flag set, nothing happens" class of bug.

WHY THIS EXISTS
===============

#3811 set `agent_otp_ci_send_gate_enabled = true` in
`terraform/environments/sandbox/terraform.tfvars`, merged, and applied to
sandbox creating NOTHING. Every signal was green -- the PR plan, the merge,
and `Deploy Sandbox - Infrastructure: completed/success`. The role it was
supposed to create simply did not exist afterwards, and `aws iam get-role`
was the only thing that said so.

`terraform/environments/<env>/` is its own root that consumes `terraform/` as
`module "nhp"`. Terraform treats a variable present in a root's tfvars but
never DECLARED in that root as an undeclared-variable WARNING, not an error:
it is ignored, the module keeps its default, `count` evaluates to 0, and the
resources are silently never created. Nothing fails.

Reaching the module takes BOTH halves, and each half fails silently on its
own:

  1. `variable "x" {}` declared in the environment root, and
  2. `x = var.x` passed through the `module "nhp"` block.

This checks both.

WHAT IT REPORTS
===============

- INERT: a key assigned in `terraform.tfvars` that the root never declares.
  This is the #3811 shape -- config that looks live and does nothing.

- UNPASSED: a variable the root declares but never references as `var.<name>`
  anywhere in its own `.tf` files. Declared-but-not-forwarded is the other
  half of the same bug, and equally silent.

USAGE
=====

    check-tfvars-reach-the-module.py [environments_dir]

Defaults to `terraform/environments`. The optional argument exists so the
fixture suite can point it at synthetic roots; when it is supplied the
grandfather allowlist below is NOT applied, because that allowlist describes
the real tree only.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_ENVIRONMENTS = REPO_ROOT / "terraform" / "environments"

# Settings this check found already inert when it was introduced, grandfathered
# so the fence can start blocking NEW ones immediately.
#
# These are NOT false positives -- each was verified by hand as genuinely doing
# nothing. They are excluded rather than fixed because making an inert flag live
# is a real infrastructure change, not a lint cleanup: `qurl_enforce_internal_alb_only`
# is set true in prod and sandbox today and applies nothing, so wiring it through
# would newly enforce an ALB restriction in production as a side effect of adding
# a lint. Each needs its own reviewed change deciding whether the intent was to
# enforce it or to delete the setting.
#
# ONLY REMOVE ENTRIES FROM THIS MAP. Adding one re-opens the exact hole the check
# exists to close.
KNOWN_INERT: dict[tuple[str, str], str] = {
    ("prod", "cloudmap_enabled"): "declared in neither the env root nor terraform/variables.tf - wholly dead config",
    ("sandbox", "cloudmap_enabled"): "declared in neither the env root nor terraform/variables.tf - wholly dead config",
    ("prod", "qurl_enforce_internal_alb_only"): "declared in terraform/variables.tf but never in the env root; set true and enforcing nothing",
    ("sandbox", "qurl_enforce_internal_alb_only"): "declared in terraform/variables.tf but never in the env root; set true and enforcing nothing",
    ("sandbox", "deploy_e2e_echo_server"): "declared in terraform/variables.tf but never in the env root",
}

# Column-zero assignment: `name = ...`. Anything indented belongs to a nested
# literal and is not a root variable.
TFVARS_ASSIGNMENT = re.compile(r"^([a-zA-Z_][a-zA-Z0-9_]*)\s*=")
# A heredoc opener only counts when it is the VALUE of an assignment and the
# marker ends the line. Searching the whole line would let `foo = "a << b"` or a
# trailing `# see <<note` set a bogus terminator and silently swallow every
# following line until something happened to match it.
HEREDOC_OPEN = re.compile(r"=\s*<<-?\s*([A-Za-z_][A-Za-z0-9_]*)\s*$")
VARIABLE_BLOCK = re.compile(r'^\s*variable\s+"([^"]+)"\s*\{')
LINE_COMMENT = re.compile(r"(^|\s)(#|//).*$")


def tfvars_keys(path: Path) -> dict[str, int]:
    """Top-level keys assigned in a tfvars file, mapped to line numbers."""
    keys: dict[str, int] = {}
    heredoc_terminator: str | None = None
    for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if heredoc_terminator is not None:
            if raw.strip() == heredoc_terminator:
                heredoc_terminator = None
            continue
        stripped = raw.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("//"):
            continue
        match = TFVARS_ASSIGNMENT.match(raw)
        if match:
            keys.setdefault(match.group(1), lineno)
        opened = HEREDOC_OPEN.search(raw)
        if opened:
            heredoc_terminator = opened.group(1)
    return keys


def declared_variables(directory: Path) -> dict[str, Path]:
    """Variables declared by the .tf files in exactly this directory."""
    declared: dict[str, Path] = {}
    for tf in sorted(directory.glob("*.tf")):
        for line in tf.read_text(encoding="utf-8").splitlines():
            match = VARIABLE_BLOCK.match(line)
            if match:
                declared[match.group(1)] = tf
    return declared


def referenced_variables(directory: Path) -> set[str]:
    """Every `var.<name>` referenced by the .tf files in this directory.

    Comments are stripped first: a commented-out `# x = var.foo` must not count
    as forwarding `foo`, or deleting a pass-through but leaving it commented
    would defeat the UNPASSED half of this check.
    """
    referenced: set[str] = set()
    for tf in sorted(directory.glob("*.tf")):
        for line in tf.read_text(encoding="utf-8").splitlines():
            code = LINE_COMMENT.sub("", line)
            referenced.update(re.findall(r"\bvar\.([a-zA-Z_][a-zA-Z0-9_]*)", code))
    return referenced


def main(argv: list[str]) -> int:
    if len(argv) > 1:
        environments = Path(argv[1]).resolve()
        allowlist: dict[tuple[str, str], str] = {}
        base = environments
    else:
        environments = DEFAULT_ENVIRONMENTS
        allowlist = KNOWN_INERT
        base = REPO_ROOT

    if not environments.is_dir():
        print(f"::error::{environments} not found", file=sys.stderr)
        return 1

    failures = 0
    checked = 0
    fired: set[tuple[str, str]] = set()

    for env_dir in sorted(p for p in environments.iterdir() if p.is_dir()):
        tfvars = env_dir / "terraform.tfvars"
        if not tfvars.is_file():
            continue
        checked += 1
        rel_tfvars = tfvars.relative_to(base)

        declared = declared_variables(env_dir)
        referenced = referenced_variables(env_dir)

        for key, lineno in sorted(tfvars_keys(tfvars).items()):
            if key not in declared:
                if (env_dir.name, key) in allowlist:
                    fired.add((env_dir.name, key))
                    continue
                failures += 1
                print(
                    f"::error file={rel_tfvars},line={lineno}::INERT: "
                    f'`{key}` is assigned here but no `variable "{key}"` is declared in '
                    f"{env_dir.relative_to(base)}/. Terraform ignores undeclared tfvars "
                    f"keys with a warning, so this setting does nothing: the module keeps its "
                    f"default and any count-gated resources are silently never created. "
                    f"Declare the variable in this root AND pass it through the module block."
                )

        for name, source in sorted(declared.items()):
            if name not in referenced:
                failures += 1
                print(
                    f"::error file={source.relative_to(base)}::UNPASSED: "
                    f'`variable "{name}"` is declared in '
                    f"{env_dir.relative_to(base)}/ but never referenced as `var.{name}` "
                    f"there. A declared-but-unforwarded variable is inert in exactly the same "
                    f"way as an undeclared one -- setting it changes nothing. Pass it into the "
                    f"module that consumes it, or delete the declaration."
                )

    if checked == 0:
        print(
            f"::error::no terraform.tfvars found under {environments} — "
            f"the check is not looking where it thinks it is",
            file=sys.stderr,
        )
        return 1

    # A grandfathered entry that no longer fires means the setting was fixed or
    # deleted. Force the allowlist to shrink with reality, naming the exact
    # entries, otherwise it silently becomes standing permission for the next one.
    stale = sorted(set(allowlist) - fired)
    if stale:
        for env, key in stale:
            print(
                f"::error::KNOWN_INERT entry ({env}, {key}) no longer fires — "
                f"it was fixed or removed. Delete it from KNOWN_INERT."
            )
        return 1

    if failures:
        print(
            f"\ntfvars reachability check: FAILED "
            f"({failures} inert setting(s) across {checked} environment root(s))"
        )
        return 1

    print(
        f"tfvars reachability check: OK "
        f"({checked} environment root(s), {len(fired)} grandfathered)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
