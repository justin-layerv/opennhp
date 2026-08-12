#!/usr/bin/env python3
"""Contract tests for the committed sandbox Control runtime gates.

The gate file is the only thing standing between an unattended `terraform apply`
and the seven dark Terraform defaults. Live sandbox is the opposite of those
defaults on all seven, so a gate file that silently degrades — a dropped key, a
typo'd key name, a string "true" instead of a boolean — does not fail to deploy
the Hub, it destroys it. These tests cover the degradation shapes, the
dependency rules the helper shares with control-sandbox-update.yml's guard, and
the flag emission build-and-push.yml's deploy leg consumes.

Usage: python3 tests/scripts/test_control_sandbox_runtime_gates.py
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / ".github" / "scripts" / "control-sandbox-runtime-gates.py"
COMMITTED = ROOT / ".github" / "control-sandbox-runtime-gates.json"

# The live sandbox shape. Held here as a literal so a gate flip has to be a
# deliberate edit in two places, not a one-character slip.
#
# Bound to the 2026-08-07 apply EXCEPT the two proof colours: those are the
# target of the catch-up cutover, not a confirmed-live reading. They become live
# when that applies; until then this file and live AWS disagree on them by
# design, because editing the gate file IS the rollout step.
LIVE = {
    "enable_runtime_functions": True,
    "hub_edge_enabled": True,
    "hub_worker_enabled": True,
    "proof_mutation_controls_enabled": False,
    "proof_policy_consumers_staged": False,
    "proof_policy_selected_color": "none",
    "proof_policy_prepared_color": "none",
    # Live: the rollout window is closed and the hold keeps the selected
    # colour on the version it serves; standby tracks each new publish.
    "blue_green_alias_hold_enabled": True,
}


def run(*args: str, gates: Path | None = None) -> subprocess.CompletedProcess:
    argv = [sys.executable, str(SCRIPT), *args]
    if gates is not None:
        argv += ["--gates", str(gates)]
    return subprocess.run(argv, capture_output=True, text=True, cwd=ROOT)


def write_gates(tmp: Path, **overrides: object) -> Path:
    """A valid gate file with the given keys replaced, or dropped when None."""
    data = dict(LIVE)
    for key, value in overrides.items():
        if value is None:
            data.pop(key, None)
        else:
            data[key] = value
    path = tmp / "gates.json"
    path.write_text(json.dumps(data))
    return path


def check_args(omit: str | None = None, **overrides: object) -> list[str]:
    values = dict(LIVE)
    values.update(overrides)
    args = ["check"]
    for key, value in values.items():
        if key == omit:
            continue
        rendered = (
            ("true" if value else "false") if isinstance(value, bool) else str(value)
        )
        args += [f"--{key.replace('_', '-')}", rendered]
    return args


class CommittedGateFile(unittest.TestCase):
    def test_committed_file_is_valid_and_emits_flags(self) -> None:
        result = run("flags")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(result.stdout.strip(), "committed gates emitted no flags")

    def test_committed_file_matches_the_recorded_live_shape(self) -> None:
        # Not redundant with the flag test: flags are emitted only for enabled
        # gates, so a file that turned everything off would still "emit flags"
        # for whatever remained. This pins the exact seven values.
        data = json.loads(COMMITTED.read_text())
        for key, expected in LIVE.items():
            self.assertEqual(data.get(key), expected, f"gate {key} drifted")

    def test_committed_file_documents_itself(self) -> None:
        data = json.loads(COMMITTED.read_text())
        self.assertIn("_comment", data, "the gate file must explain what it is")

    def test_default_gate_path_resolves_from_any_cwd(self) -> None:
        # The plan and apply steps run with working-directory set to the Control
        # root. A bare relative default would be one copied step away from
        # resolving to nothing, and a deploy is the worst place to discover it.
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "flags"],
            capture_output=True,
            text=True,
            cwd=tempfile.gettempdir(),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--hub-edge-enabled", result.stdout)

    def test_reader_is_executable(self) -> None:
        # Both call sites invoke the reader directly, relying on the shebang and
        # the exec bit. Everything else that touches this file goes around that:
        # these tests run it through sys.executable, and the workflow fence only
        # greps for the string. So a mode regression to 100644 would surface
        # first as "permission denied" in a live unattended deploy, with nothing
        # in CI having flagged it. Assert the bit here, where it is cheap.
        self.assertTrue(
            SCRIPT.stat().st_mode & 0o111,
            f"{SCRIPT} must stay executable; both workflows invoke it directly",
        )


class FlagEmission(unittest.TestCase):
    def test_live_shape_emits_every_flag_in_workflow_order(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = run("flags", gates=write_gates(Path(tmp)))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout.split(),
            [
                "--runtime-functions-enabled",
                "--hub-edge-enabled",
                "--hub-worker-enabled",
                # The proof surface is fully retired: no proof flags at all.
                "--blue-green-alias-hold-enabled",
            ],
        )

    def test_dark_shape_emits_nothing(self) -> None:
        # The all-dark file is valid (it is the documented rollback shape); it
        # must simply emit no flags rather than erroring.
        with tempfile.TemporaryDirectory() as tmp:
            gates = write_gates(
                Path(tmp),
                enable_runtime_functions=False,
                hub_edge_enabled=False,
                hub_worker_enabled=False,
                proof_mutation_controls_enabled=False,
                proof_policy_consumers_staged=False,
                proof_policy_selected_color="none",
                proof_policy_prepared_color="none",
                blue_green_alias_hold_enabled=False,
            )
            result = run("flags", gates=gates)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "")

    def test_colors_are_omitted_when_no_rollout_is_selected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            gates = write_gates(
                Path(tmp),
                proof_policy_selected_color="none",
                proof_policy_prepared_color="none",
            )
            result = run("flags", gates=gates)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("--proof-policy-selected-color", result.stdout)


class EnvEmission(unittest.TestCase):
    """The retired `env` subcommand."""

    def test_the_env_command_is_retired(self) -> None:
        """`env` published the two proof colours; its only consumer is gone.

        The deploy gate that read CONTROL_SELECTED_COLOR/CONTROL_PREPARED_COLOR
        now keys off the plan's own plan_mode instead, so this command emitted
        names nothing consumed -- and the cross-seam test that used to live here
        had no subject left. A publisher with no reader is exactly how a rename
        goes unnoticed until a live deploy, so retire it rather than keep it
        warm.
        """
        result = run("env")
        # argparse rejects the removed choice: exit 2, naming it.
        self.assertEqual(result.returncode, 2)
        self.assertIn("invalid choice: 'env'", result.stderr)


class FileDegradation(unittest.TestCase):
    """Every way the file can rot into something that plans against defaults."""

    def test_missing_file_fails(self) -> None:
        result = run("flags", gates=Path("/nonexistent/gates.json"))
        self.assertEqual(result.returncode, 1)
        self.assertIn("not found", result.stderr)

    def test_dropped_key_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = run("flags", gates=write_gates(Path(tmp), hub_worker_enabled=None))
        self.assertEqual(result.returncode, 1)
        self.assertIn("missing hub_worker_enabled", result.stderr)

    def test_typoed_key_fails_rather_than_silently_defaulting(self) -> None:
        # The dangerous shape: `hub_edge_enable` looks right in review, and a
        # lenient reader would take the dark default for the real key.
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "gates.json"
            data = dict(LIVE)
            data["hub_edge_enable"] = data.pop("hub_edge_enabled")
            path.write_text(json.dumps(data))
            result = run("flags", gates=path)
        self.assertEqual(result.returncode, 1)
        self.assertIn("missing hub_edge_enabled", result.stderr)

    def test_unknown_key_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = run("flags", gates=write_gates(Path(tmp), hub_edge_enbaled=True))
        self.assertEqual(result.returncode, 1)
        self.assertIn("unknown keys", result.stderr)

    def test_stringly_typed_boolean_fails(self) -> None:
        # "false" is truthy in Python; a lenient reader would enable the gate.
        with tempfile.TemporaryDirectory() as tmp:
            result = run("flags", gates=write_gates(Path(tmp), hub_edge_enabled="false"))
        self.assertEqual(result.returncode, 1)
        self.assertIn("must be a JSON boolean", result.stderr)

    def test_invalid_color_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = run(
                "flags", gates=write_gates(Path(tmp), proof_policy_selected_color="red")
            )
        self.assertEqual(result.returncode, 1)
        self.assertIn("must be one of", result.stderr)

    def test_malformed_json_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "gates.json"
            path.write_text("{not json")
            result = run("flags", gates=path)
        self.assertEqual(result.returncode, 1)
        self.assertIn("not valid JSON", result.stderr)


class DependencyRules(unittest.TestCase):
    """The same rules control-sandbox-update.yml's guard applies to its inputs.

    A gate file the guard would have rejected as dispatch input must not become
    reachable just because it arrived from disk.
    """

    def test_proof_mutation_requires_runtime_functions(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = run(
                "flags", gates=write_gates(Path(tmp), enable_runtime_functions=False)
            )
        self.assertEqual(result.returncode, 1)
        self.assertIn("requires the Authority runtime functions gate", result.stderr)

    def test_blue_green_hold_requires_runtime_functions(self) -> None:
        """validate() must mirror the generator's own dependency guard.

        Without this the bad shape passes gate-load and only fails several steps
        later inside generate, on the deploy leg rather than loudly up front.
        """
        with tempfile.TemporaryDirectory() as tmp:
            result = run(
                "flags",
                gates=write_gates(
                    Path(tmp),
                    blue_green_alias_hold_enabled=True,
                    enable_runtime_functions=False,
                    # Silence the proof rules, which are checked first and would
                    # otherwise mask the rule under test.
                    proof_mutation_controls_enabled=False,
                    proof_policy_consumers_staged=False,
                    proof_policy_selected_color="none",
                    proof_policy_prepared_color="none",
                ),
            )
        self.assertEqual(result.returncode, 1)
        self.assertIn("blue/green alias hold requires", result.stderr)

    def test_check_rejects_a_disagreeing_blue_green_input(self) -> None:
        """A dispatch that disagrees with the committed gate must be refused.

        The gate was in BOOLEAN_GATES and TFVARS_KEYS but missing from
        check_inputs' comparison dict, so a dispatch of true against a committed
        false was silently accepted -- exactly what the dispatch input's own help
        text promises the guard rejects.
        """
        with tempfile.TemporaryDirectory() as tmp:
            gates = write_gates(Path(tmp), blue_green_alias_hold_enabled=False)
            result = run(
                *check_args(blue_green_alias_hold_enabled="true"), gates=gates
            )
        self.assertEqual(result.returncode, 1)
        self.assertIn("blue_green_alias_hold_enabled", result.stderr)

    def test_blue_green_flag_is_emitted_last(self) -> None:
        """Flag ORDER is byte-compared against the reviewed plan input.

        The gate is APPENDED to BOOLEAN_GATES rather than inserted, so enabling
        it must leave every pre-existing flag in its existing relative position
        and add exactly one token. (It lands at the end of the boolean flags,
        before the colour flags, because emit_flags walks BOOLEAN_GATES then
        COLOR_GATES -- so "last overall" is the wrong assertion.) Inserting
        mid-list would fail the apply, not the review.
        """
        with tempfile.TemporaryDirectory() as tmp:
            base = run(
                "flags",
                gates=write_gates(Path(tmp), blue_green_alias_hold_enabled=False),
            )
            enabled = run("flags", gates=write_gates(Path(tmp)))
        self.assertEqual(base.returncode, 0)
        self.assertEqual(enabled.returncode, 0)
        flag = "--blue-green-alias-hold-enabled"
        enabled_tokens = enabled.stdout.split()
        self.assertIn(flag, enabled_tokens)
        self.assertEqual([t for t in enabled_tokens if t != flag], base.stdout.split())

    def test_staged_consumers_require_proof_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = run(
                "flags",
                gates=write_gates(
                    Path(tmp),
                    # LIVE is dark on both; state the divergent pair explicitly.
                    proof_policy_consumers_staged=True,
                    proof_mutation_controls_enabled=False,
                ),
            )
        self.assertEqual(result.returncode, 1)
        self.assertIn("attended-proof mutation control", result.stderr)

    def test_colors_must_be_supplied_together(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = run(
                "flags",
                gates=write_gates(
                    Path(tmp),
                    proof_policy_selected_color="green",
                    proof_policy_prepared_color="none",
                ),
            )
        self.assertEqual(result.returncode, 1)
        self.assertIn("must be supplied together", result.stderr)

    def test_rollout_colors_require_the_live_hub_worker(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = run(
                "flags",
                gates=write_gates(
                    Path(tmp),
                    hub_worker_enabled=False,
                    proof_policy_selected_color="green",
                    proof_policy_prepared_color="green",
                ),
            )
        self.assertEqual(result.returncode, 1)
        self.assertIn("live Hub worker", result.stderr)


class TfvarsReceipt(unittest.TestCase):
    """`verify-tfvars` is the receipt for what the generator actually emitted.

    Passing the right flags proves nothing about what the generator did with
    them. These cover the drift shapes that would otherwise produce a plausible
    tfvars and apply a Control shape nobody chose. The deploy leg runs the real
    generator and checks its real output; here the tfvars are synthetic so the
    checking logic is covered at PR time without a deep checkout.
    """

    LIVE_TFVARS = {
        "authority_runtime_functions_enabled": True,
        "hub_edge_enabled": True,
        "hub_worker_enabled": True,

        # Proof surface fully retired: no proof keys are emitted.
        "authority_blue_green_alias_hold_enabled": True,
        # A real tfvars also carries manifest-derived keys; they must be ignored.
        "authority_runtime_contract": {"schema_version": 1},
        "authority_proof_mutation_owner_id": "someone",
    }

    def verify(self, tmp: str, tfvars: dict, gates: Path | None = None):
        path = Path(tmp) / "tfvars.json"
        path.write_text(json.dumps(tfvars))
        return run("verify-tfvars", "--tfvars", str(path), gates=gates)

    def test_matching_tfvars_passes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = self.verify(tmp, self.LIVE_TFVARS)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_dropped_flag_fails(self) -> None:
        # The generator stops honouring a flag: the key vanishes and the dark
        # Terraform default silently applies.
        tfvars = {k: v for k, v in self.LIVE_TFVARS.items() if k != "hub_edge_enabled"}
        with tempfile.TemporaryDirectory() as tmp:
            result = self.verify(tmp, tfvars)
        self.assertEqual(result.returncode, 1)
        self.assertIn("hub_edge_enabled absent", result.stderr)

    def test_flipped_value_fails(self) -> None:
        tfvars = dict(self.LIVE_TFVARS, hub_worker_enabled=False)
        with tempfile.TemporaryDirectory() as tmp:
            result = self.verify(tmp, tfvars)
        self.assertEqual(result.returncode, 1)
        self.assertIn("hub_worker_enabled", result.stderr)

    def test_flipped_color_fails(self) -> None:
        # "blue" is the flip: the committed selector is green during prepare.
        tfvars = dict(self.LIVE_TFVARS, authority_proof_policy_selected_color="blue")
        with tempfile.TemporaryDirectory() as tmp:
            result = self.verify(tmp, tfvars)
        self.assertEqual(result.returncode, 1)
        self.assertIn("authority_proof_policy_selected_color", result.stderr)

    def test_renamed_key_fails(self) -> None:
        # A generator-side rename: the value is right, under a key Terraform
        # will not read, so the gate silently reverts to its dark default.
        tfvars = dict(self.LIVE_TFVARS)
        tfvars["authority_hub_edge_enabled"] = tfvars.pop("hub_edge_enabled")
        with tempfile.TemporaryDirectory() as tmp:
            result = self.verify(tmp, tfvars)
        self.assertEqual(result.returncode, 1)
        self.assertIn("hub_edge_enabled absent", result.stderr)

    def test_absent_key_satisfies_a_dark_gate(self) -> None:
        # Omission is how the generator expresses "leave the committed default",
        # and every committed default is dark — so absent must AGREE with a dark
        # gate rather than being reported as drift.
        with tempfile.TemporaryDirectory() as tmp:
            gates = write_gates(
                Path(tmp),
                proof_policy_selected_color="none",
                proof_policy_prepared_color="none",
            )
            # Only the two COLOUR keys go dark here; consumers_staged is a
            # boolean gate that stays true, so it must stay present.
            tfvars = {
                k: v
                for k, v in self.LIVE_TFVARS.items()
                if k
                not in (
                    "authority_proof_policy_selected_color",
                    "authority_proof_policy_prepared_color",
                )
            }
            result = self.verify(tmp, tfvars, gates=gates)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_missing_tfvars_file_fails(self) -> None:
        result = run("verify-tfvars", "--tfvars", "/nonexistent/tfvars.json")
        self.assertEqual(result.returncode, 1)
        self.assertIn("not found", result.stderr)

    def test_tfvars_argument_is_required(self) -> None:
        result = run("verify-tfvars")
        self.assertEqual(result.returncode, 1)
        self.assertIn("requires --tfvars", result.stderr)


class DispatchBinding(unittest.TestCase):
    """`check` is what stops an attended dispatch from diverging from the file."""

    def test_matching_inputs_pass(self) -> None:
        result = run(*check_args())
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_a_single_flipped_boolean_fails(self) -> None:
        result = run(*check_args(hub_edge_enabled=False))
        self.assertEqual(result.returncode, 1)
        self.assertIn("hub_edge_enabled", result.stderr)

    def test_a_flipped_color_fails(self) -> None:
        # "blue" is the flip: the committed selector is green during prepare.
        result = run(*check_args(proof_policy_selected_color="blue"))
        self.assertEqual(result.returncode, 1)
        self.assertIn("proof_policy_selected_color", result.stderr)

    def test_every_difference_is_named_not_just_the_first(self) -> None:
        # An operator re-dispatching should learn all of it in one round trip.
        result = run(
            *check_args(hub_edge_enabled=False, proof_policy_prepared_color="green")
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("hub_edge_enabled", result.stderr)
        self.assertIn("proof_policy_prepared_color", result.stderr)

    def test_omitted_input_fails_rather_than_defaulting(self) -> None:
        # A caller that forgets a gate must be told, not silently compared
        # against six of seven — the seventh is the one that takes the Hub down.
        result = run(*check_args(omit="hub_worker_enabled"))
        self.assertEqual(result.returncode, 1)
        self.assertIn("missing hub_worker_enabled", result.stderr)

    def test_non_boolean_dispatch_string_fails(self) -> None:
        result = run(*check_args(hub_edge_enabled="yes"))
        self.assertEqual(result.returncode, 1)
        self.assertIn("must be 'true' or 'false'", result.stderr)

    def test_failure_prints_the_committed_values_ready_to_paste(self) -> None:
        # Every dispatch that accepts the seven all-dark form defaults lands
        # here, including a read-only `verify` run mid-incident. The error must
        # hand back the values rather than making the operator derive them.
        result = run(*check_args(hub_edge_enabled=False))
        self.assertEqual(result.returncode, 1)
        for expected in (
            "-f enable_runtime_functions=true",
            "-f hub_edge_enabled=true",
            "-f proof_policy_selected_color=none",
            "-f proof_policy_prepared_color=none",
            "-f blue_green_alias_hold_enabled=true",
        ):
            self.assertIn(expected, result.stderr)

    def test_invalid_color_reports_the_range_not_a_difference(self) -> None:
        # Range-check before the comparison, so an operator who typo'd a colour
        # is told it is not a colour rather than being sent to reconcile against
        # the committed file.
        result = run(*check_args(proof_policy_selected_color="grene"))
        self.assertEqual(result.returncode, 1)
        self.assertIn("must be one of", result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
