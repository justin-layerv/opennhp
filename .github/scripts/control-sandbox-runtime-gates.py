#!/usr/bin/env python3
"""Read the committed sandbox Control runtime gates and bind every consumer to them.

Every lane that plans or applies Control, one file:

  flags   emits the generate-connector-authority-runtime-contract.py flags the
          committed gates imply, newline-delimited, for the unattended
          build-and-push.yml deploy leg and for terraform-plan-pr.yml, which
          plans the gates a PR proposes rather than a list of its own.
  check   asserts a set of control-sandbox-update.yml dispatch inputs equals the
          committed gates, so an attended dispatch cannot leave live sandbox in a
          shape the next automatic push would silently revert.

The validation below is deliberately the same rule set the control-sandbox-update
guard applies to its inputs. A gate file that the guard would have rejected as
dispatch input must not be reachable just because it arrived from disk.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


# Resolved from this file's own location, not the process cwd. Callers run from
# the repository root today, but the plan and apply steps in build-and-push.yml
# set working-directory to the Control root — so a bare relative default is one
# copied step away from silently resolving to nothing, and "gate file not found"
# during a deploy is a worse way to learn that than never having it happen.
DEFAULT_GATES = (
    Path(__file__).resolve().parents[2] / ".github" / "control-sandbox-runtime-gates.json"
)

# Gate name -> the generator flag it implies when true. Order is the order the
# flags are emitted in, which is the order both workflows already pass them; the
# generated tfvars is byte-compared against the reviewed plan input, so a
# reordering here is a real (if recoverable) failure and not cosmetic.
BOOLEAN_GATES = (
    ("enable_runtime_functions", "--runtime-functions-enabled"),
    ("hub_edge_enabled", "--hub-edge-enabled"),
    ("hub_worker_enabled", "--hub-worker-enabled"),
    ("proof_mutation_controls_enabled", "--proof-mutation-controls-enabled"),
    ("proof_policy_consumers_staged", "--proof-policy-consumers-staged"),
)

COLOR_GATES = (
    ("proof_policy_selected_color", "--proof-policy-selected-color"),
    ("proof_policy_prepared_color", "--proof-policy-prepared-color"),
)

COLORS = ("none", "blue", "green")

# Gate name -> the tfvars key the generator emits for it. The names differ on
# three of the seven (enable_runtime_functions -> authority_runtime_functions_
# enabled, and the two proof_* pairs pick up an authority_ prefix), which is
# exactly why this mapping is written down rather than derived: a rename on
# either side is silent otherwise.
#
# A false/'none' gate is emitted as an ABSENT key, not an explicit false — the
# generator leaves it out so the committed Terraform default applies. Since
# every committed default is the dark value, absent and false agree.
TFVARS_KEYS = {
    "enable_runtime_functions": "authority_runtime_functions_enabled",
    "hub_edge_enabled": "hub_edge_enabled",
    "hub_worker_enabled": "hub_worker_enabled",
    "proof_mutation_controls_enabled": "authority_proof_mutation_controls_enabled",
    "proof_policy_consumers_staged": "authority_proof_policy_consumers_staged",
    "proof_policy_selected_color": "authority_proof_policy_selected_color",
    "proof_policy_prepared_color": "authority_proof_policy_prepared_color",
}


class GateError(Exception):
    """A gate file, or a dispatch input set, that must not reach Terraform."""


def load_gates(path: Path) -> dict[str, object]:
    try:
        raw = json.loads(path.read_text())
    except FileNotFoundError:
        raise GateError(f"gate file not found: {path}") from None
    except json.JSONDecodeError as exc:
        raise GateError(f"gate file is not valid JSON: {exc}") from None
    if not isinstance(raw, dict):
        raise GateError("gate file must be a JSON object")

    gates: dict[str, object] = {}
    for name, _ in BOOLEAN_GATES:
        if name not in raw:
            raise GateError(f"gate file is missing {name}")
        value = raw[name]
        if not isinstance(value, bool):
            raise GateError(f"{name} must be a JSON boolean, got {value!r}")
        gates[name] = value
    for name, _ in COLOR_GATES:
        if name not in raw:
            raise GateError(f"gate file is missing {name}")
        value = raw[name]
        if value not in COLORS:
            raise GateError(f"{name} must be one of {COLORS}, got {value!r}")
        gates[name] = value

    # Reject any key that is neither a gate nor the leading comment block, so a
    # typo'd gate name fails loudly here instead of silently keeping the dark
    # default and taking the Hub down on the next push.
    known = {name for name, _ in BOOLEAN_GATES} | {name for name, _ in COLOR_GATES}
    unknown = sorted(set(raw) - known - {"_comment"})
    if unknown:
        raise GateError(f"gate file has unknown keys: {', '.join(unknown)}")

    validate(gates)
    return gates


def validate(gates: dict[str, object]) -> None:
    """Apply the control-sandbox-update guard's own dependency rules."""
    if gates["proof_mutation_controls_enabled"] and not gates["enable_runtime_functions"]:
        raise GateError(
            "dark proof mutation capability requires the Authority runtime functions gate"
        )
    if gates["proof_policy_consumers_staged"] and not gates["proof_mutation_controls_enabled"]:
        raise GateError(
            "proof policy consumers require the attended-proof mutation control"
        )
    selected = gates["proof_policy_selected_color"]
    prepared = gates["proof_policy_prepared_color"]
    if (selected == "none") != (prepared == "none"):
        raise GateError(
            "proof rollout selected and prepared colors must be supplied together"
        )
    if selected != "none":
        if not gates["proof_policy_consumers_staged"] or not gates["hub_worker_enabled"]:
            raise GateError(
                "proof rollout colors require staged proof consumers and the live Hub worker"
            )


def emit_flags(gates: dict[str, object]) -> list[str]:
    flags: list[str] = []
    for name, flag in BOOLEAN_GATES:
        if gates[name]:
            flags.append(flag)
    if gates["proof_policy_selected_color"] != "none":
        for name, flag in COLOR_GATES:
            flags.extend((flag, gates[name]))  # type: ignore[arg-type]
    return flags


def verify_tfvars(gates: dict[str, object], path: Path) -> None:
    """Prove the generated tfvars carries exactly the committed gate values.

    The flags this script emits are an INSTRUCTION to the contract generator;
    this is the receipt. Without it, a generator change that renamed a variable,
    dropped a flag, or stopped honouring one would still produce a plausible
    tfvars, and the leg would apply a Control shape nobody chose — the failure
    is invisible precisely because the flags were passed correctly.
    """
    try:
        emitted = json.loads(path.read_text())
    except FileNotFoundError:
        raise GateError(f"generated tfvars not found: {path}") from None
    except json.JSONDecodeError as exc:
        raise GateError(f"generated tfvars is not valid JSON: {exc}") from None
    if not isinstance(emitted, dict):
        raise GateError("generated tfvars must be a JSON object")

    differences = []
    for gate, key in TFVARS_KEYS.items():
        want = gates[gate]
        # An absent key means "leave the committed Terraform default", and every
        # committed default is the dark value — so absent must agree with a dark
        # gate and must NOT satisfy an enabled one.
        if key not in emitted:
            if want is False or want == "none":
                continue
            differences.append(f"{key} absent, gate {gate} wants {want!r}")
            continue
        got = emitted[key]
        if want == "none":
            if got is not None:
                differences.append(f"{key} is {got!r}, gate {gate} wants no rollout")
            continue
        if got != want:
            differences.append(f"{key} is {got!r}, gate {gate} wants {want!r}")
    if differences:
        raise GateError(
            "generated Authority runtime tfvars does not carry the committed gates "
            "(" + "; ".join(differences) + "). The contract generator and "
            ".github/control-sandbox-runtime-gates.json have diverged; do not apply "
            "this plan."
        )


def check_inputs(gates: dict[str, object], args: argparse.Namespace) -> None:
    """Bind dispatch inputs to the committed gates, naming every difference."""
    supplied = {
        "enable_runtime_functions": args.enable_runtime_functions,
        "hub_edge_enabled": args.hub_edge_enabled,
        "hub_worker_enabled": args.hub_worker_enabled,
        "proof_mutation_controls_enabled": args.proof_mutation_controls_enabled,
        "proof_policy_consumers_staged": args.proof_policy_consumers_staged,
        "proof_policy_selected_color": args.proof_policy_selected_color,
        "proof_policy_prepared_color": args.proof_policy_prepared_color,
    }
    differences = []
    for name, value in supplied.items():
        expected = gates[name]
        # Dispatch inputs arrive as the strings 'true'/'false'/'none'/a color.
        actual: object = value
        if isinstance(expected, bool):
            if value not in ("true", "false"):
                raise GateError(f"{name} dispatch input must be 'true' or 'false', got {value!r}")
            actual = value == "true"
        # Range-check colors the same way load_gates does. Without this an
        # invalid color would only ever be reported as "differs from committed",
        # sending the operator to reconcile against the file when the real
        # problem is that the value is not a color at all.
        elif value not in COLORS:
            raise GateError(f"{name} dispatch input must be one of {COLORS}, got {value!r}")
        if actual != expected:
            differences.append(f"{name}: dispatched {value!r}, committed {expected!r}")
    if differences:
        # Print the committed values as a ready-to-paste input list. The seven
        # form defaults are all dark while the committed file is not, so every
        # dispatch that accepts the defaults lands here — including a read-only
        # `verify` someone is running mid-incident. Making them re-derive seven
        # values from a diff at that moment is how this guard turns from a
        # safety net into an obstacle.
        rendered = "\n".join(
            f"  -f {name}="
            + ("true" if value is True else "false" if value is False else str(value))
            for name, value in gates.items()
        )
        raise GateError(
            "dispatch inputs disagree with .github/control-sandbox-runtime-gates.json "
            "(" + "; ".join(differences) + "). Applying them would leave live sandbox in "
            "a shape the next automatic main push reverts. Update the gate file in the "
            "same commit as the Terraform, or re-dispatch with the committed values:\n"
            + rendered
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("flags", "check", "verify-tfvars", "env"))
    parser.add_argument("--gates", type=Path, default=DEFAULT_GATES)
    parser.add_argument("--tfvars", type=Path)
    for name, _ in BOOLEAN_GATES + COLOR_GATES:
        parser.add_argument(f"--{name.replace('_', '-')}")
    args = parser.parse_args(argv)

    try:
        gates = load_gates(args.gates)
        if args.command == "flags":
            for flag in emit_flags(gates):
                print(flag)
        elif args.command == "env":
            # $GITHUB_ENV lines for the later workflow steps that need a gate
            # value, so this file keeps exactly one parser. Colors only: those
            # are the sole values a downstream step reads today, and emitting
            # the booleans too would invite shell-side truthiness bugs on
            # strings that are always non-empty.
            for name, _ in COLOR_GATES:
                print(f"CONTROL_{name.removeprefix('proof_policy_').upper()}={gates[name]}")
        elif args.command == "verify-tfvars":
            if args.tfvars is None:
                raise GateError("verify-tfvars requires --tfvars")
            verify_tfvars(gates, args.tfvars)
        else:
            missing = [
                name
                for name, _ in BOOLEAN_GATES + COLOR_GATES
                if getattr(args, name) is None
            ]
            if missing:
                raise GateError(f"check requires every gate input: missing {', '.join(missing)}")
            check_inputs(gates, args)
    except GateError as exc:
        print(f"::error::{exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
