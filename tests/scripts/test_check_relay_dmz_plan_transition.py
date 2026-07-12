#!/usr/bin/env python3
"""Fail-closed profile-selection tests for the temporary DMZ checker bridge."""

from __future__ import annotations

import importlib.util
import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / ".github" / "scripts" / "check-relay-dmz-plan.py"
SPEC = importlib.util.spec_from_file_location("relay_dmz_transition", SCRIPT)
assert SPEC and SPEC.loader
transition = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = transition
SPEC.loader.exec_module(transition)


def _load_fixture_module(filename: str, module_name: str):
    spec = importlib.util.spec_from_file_location(
        module_name, REPO_ROOT / "tests" / "scripts" / filename
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


native_fixtures = _load_fixture_module(
    "test_check_relay_dmz_plan.py", "relay_dmz_native_fixtures"
)
https_fixtures = _load_fixture_module(
    "test_check_relay_dmz_plan_https.py", "relay_dmz_https_fixtures"
)


def native_plan() -> dict:
    return {
        "configuration": {
            "root_module": {
                "resources": [],
                "module_calls": {
                    "relay": {
                        "expressions": {
                            "native_server": {"references": ["var.cell_id"]},
                            "native_nhp_edge_enabled": {
                                "references": ["var.native_nhp_edge_enabled"]
                            },
                        },
                        "module": {
                            "module_calls": {},
                            "resources": [
                                {"type": "aws_lb", "name": "native_nhp"},
                                {
                                    "type": "aws_lb_listener",
                                    "name": "native_nhp_udp",
                                },
                                {
                                    "type": "aws_lb_target_group",
                                    "name": "native_nhp",
                                },
                            ],
                        },
                    }
                },
            }
        },
        "resource_changes": [],
    }


def https_plan() -> dict:
    return {
        "configuration": {
            "root_module": {
                "resources": [
                    {
                        "type": "terraform_data",
                        "name": "relay_cell_routing",
                        "count_expression": {"references": ["var.deploy_relay"]},
                        "expressions": {
                            "input": {
                                "references": [
                                    "var.environment",
                                    "var.cell_id",
                                    "module.compute.server_public_key_b64",
                                    "module.compute.internal_nlb_dns_name",
                                    "module.compute",
                                ]
                            }
                        },
                    }
                ],
                "module_calls": {
                    "relay": {
                        "expressions": {
                            "cell_servers": {
                                "references": [
                                    "terraform_data.relay_cell_routing[0].input",
                                    "terraform_data.relay_cell_routing[0]",
                                    "terraform_data.relay_cell_routing",
                                ]
                            }
                        },
                        "module": {"module_calls": {}, "resources": []},
                    }
                },
            }
        },
        "resource_changes": [],
    }


def wrapped(plan: dict) -> dict:
    child = plan["configuration"]["root_module"]
    return {
        "configuration": {
            "root_module": {
                "resources": [],
                "module_calls": {
                    "wrapper": {
                        "expressions": {},
                        "module": {
                            "resources": [],
                            "module_calls": {
                                "nhp": {"expressions": {}, "module": child}
                            },
                        },
                    }
                },
            }
        },
        "resource_changes": [],
    }


def run_checker(plan: dict, *flags: str) -> subprocess.CompletedProcess[str]:
    with tempfile.TemporaryDirectory() as tmp:
        plan_path = Path(tmp) / "plan.json"
        plan_path.write_text(json.dumps(plan), encoding="utf-8")
        return subprocess.run(
            [sys.executable, str(SCRIPT), *flags, str(plan_path)],
            check=False,
            capture_output=True,
            text=True,
        )


class RelayDmzTransitionTests(unittest.TestCase):
    def test_full_sanitized_fixtures_dispatch_to_their_exact_contracts(self) -> None:
        native = native_fixtures.clean_plan()
        https = https_fixtures.clean_plan()
        self.assertNotEqual(
            native_fixtures.checker.__name__, https_fixtures.checker.__name__
        )
        self.assertEqual([], native_fixtures.checker.validate_plan(native))
        self.assertEqual([], https_fixtures.checker.validate_plan(https))
        self.assertEqual(("native", None), transition.detect_contract_profile(native))
        self.assertEqual(("https", None), transition.detect_contract_profile(https))

    def test_exact_profiles_and_wrapped_shapes_select_one_contract(self) -> None:
        for expected, layout, plan in (
            ("native", "root", native_plan()),
            ("https", "root", https_plan()),
            ("native", "wrapped", wrapped(native_plan())),
            ("https", "wrapped", wrapped(https_plan())),
        ):
            with self.subTest(expected=expected, layout=layout):
                self.assertEqual(
                    (expected, None), transition.detect_contract_profile(plan)
                )

    def test_mixed_profile_fails_closed(self) -> None:
        plan = native_plan()
        https = https_plan()["configuration"]["root_module"]
        root = plan["configuration"]["root_module"]
        root["resources"].extend(https["resources"])
        root["module_calls"]["relay"]["expressions"]["cell_servers"] = https[
            "module_calls"
        ]["relay"]["expressions"]["cell_servers"]
        profile, error = transition.detect_contract_profile(plan)
        self.assertIsNone(profile)
        self.assertIn("mixes native and HTTPS-only", str(error))

    def test_partial_profiles_fail_closed_and_absence_is_explicit(self) -> None:
        partial_native = native_plan()
        del partial_native["configuration"]["root_module"]["module_calls"]["relay"][
            "expressions"
        ]["native_server"]
        partial_https = https_plan()
        partial_https["configuration"]["root_module"]["resources"][0][
            "count_expression"
        ] = {"constant_value": 1}
        absent = {
            "configuration": {"root_module": {"resources": [], "module_calls": {}}}
        }
        for label, plan, expected in (
            ("native", partial_native, "native transition profile is incomplete"),
            ("https", partial_https, "HTTPS-only transition profile is incomplete"),
        ):
            with self.subTest(label=label):
                profile, error = transition.detect_contract_profile(plan)
                self.assertIsNone(profile)
                self.assertIn(expected, str(error))
        self.assertEqual(
            (transition.PROFILE_ABSENT, None),
            transition.detect_contract_profile(absent),
        )

    def test_partial_relay_profiles_fail_under_every_compatible_cli_mode(self) -> None:
        partial_native = native_plan()
        del partial_native["configuration"]["root_module"]["module_calls"]["relay"][
            "expressions"
        ]["native_server"]
        direct_cells = https_plan()
        root = direct_cells["configuration"]["root_module"]
        root["resources"] = []
        root["module_calls"]["relay"]["expressions"]["cell_servers"] = {
            "references": ["module.compute.internal_nlb_dns_name"]
        }
        marker_stripped = https_plan()
        marker_root = marker_stripped["configuration"]["root_module"]
        marker_root["resources"] = []
        marker_root["module_calls"]["relay"]["expressions"] = {}

        modes = (
            (),
            ("--allow-disabled",),
            ("--require-pr0-applied",),
            ("--require-dmz-boundary-noop",),
            ("--allow-disabled", "--require-dmz-boundary-noop"),
            ("--require-pr0-applied", "--require-dmz-boundary-noop"),
        )
        for shape, plan, expected in (
            ("partial-native", partial_native, "native transition profile is incomplete"),
            (
                "direct-cell-servers",
                direct_cells,
                "HTTPS-only transition profile is incomplete",
            ),
            (
                "marker-stripped",
                marker_stripped,
                "relay DMZ transition profile is incomplete",
            ),
        ):
            for mode in modes:
                with self.subTest(shape=shape, mode=mode):
                    result = run_checker(plan, *mode)
                    self.assertEqual(1, result.returncode, result.stdout + result.stderr)
                    self.assertIn(expected, result.stderr)

    def test_relay_dark_cli_requires_explicit_allow_disabled(self) -> None:
        plan = {
            "resource_changes": [],
            "configuration": {"root_module": {"resources": [], "module_calls": {}}},
        }
        required = run_checker(plan)
        allowed = run_checker(plan, "--allow-disabled")
        self.assertEqual(1, required.returncode, required.stdout + required.stderr)
        self.assertIn("relay DMZ is not present", required.stderr)
        self.assertEqual(0, allowed.returncode, allowed.stdout + allowed.stderr)

    def test_allow_disabled_rejects_missing_or_malformed_configuration(self) -> None:
        malformed_plans = (
            {"resource_changes": []},
            {"resource_changes": [], "configuration": {}},
            {"resource_changes": [], "configuration": {"root_module": []}},
            {
                "resource_changes": [],
                "configuration": {"root_module": {"module_calls": []}},
            },
            {
                "resource_changes": [],
                "configuration": {"root_module": {"resources": {}}},
            },
            {
                "resource_changes": [],
                "configuration": {"root_module": {"module_calls": [{}]}},
            },
            {
                "resource_changes": [],
                "configuration": {"root_module": {"module_calls": {"relay": []}}},
            },
            {
                "resource_changes": [],
                "configuration": {
                    "root_module": {
                        "module_calls": {"wrapper": {"expressions": []}}
                    }
                },
            },
            {
                "resource_changes": [],
                "configuration": {
                    "root_module": {
                        "module_calls": {
                            "wrapper": {"expressions": {}, "module": []}
                        }
                    }
                },
            },
            {
                "resource_changes": [],
                "configuration": {
                    "root_module": {
                        "module_calls": {
                            "wrapper": {
                                "expressions": {},
                                "module": {"resources": [[]]},
                            }
                        }
                    }
                },
            },
            {
                "resource_changes": [],
                "configuration": {
                    "root_module": {
                        "resources": [{"type": "aws_lb", "name": []}]
                    }
                },
            },
            {
                "resource_changes": [],
                "configuration": {
                    "root_module": {
                        "resources": [{"type": [], "name": "native_nhp"}]
                    }
                },
            },
            {
                "resource_changes": [],
                "configuration": {
                    "root_module": {
                        "resources": [
                            {
                                "type": "terraform_data",
                                "name": "relay_cell_routing",
                                "count_expression": {
                                    "references": ["var.deploy_relay"]
                                },
                                "expressions": [{}],
                            }
                        ]
                    }
                },
            },
        )
        for plan in malformed_plans:
            with self.subTest(plan=plan):
                result = run_checker(plan, "--allow-disabled")
                self.assertEqual(2, result.returncode, result.stdout + result.stderr)
                self.assertIn("Terraform plan JSON", result.stderr)
                self.assertNotIn("Traceback", result.stderr)

    def test_main_executes_only_the_fixed_https_checker(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            plan_path = Path(tmp) / "plan.json"
            plan_path.write_text(json.dumps(https_plan()))
            arguments = [
                str(SCRIPT),
                "--require-pr0-applied",
                str(plan_path),
            ]
            with (
                mock.patch.object(sys, "argv", arguments),
                mock.patch.object(
                    transition.os, "execv", side_effect=RuntimeError("exec")
                ) as execv,
                self.assertRaisesRegex(RuntimeError, "exec"),
            ):
                transition.main()
            self.assertEqual(sys.executable, execv.call_args.args[0])
            self.assertEqual(
                [
                    sys.executable,
                    str(transition.HTTPS_CHECKER),
                    "--require-pr0-applied",
                    str(plan_path),
                ],
                execv.call_args.args[1],
            )

    def test_missing_https_checker_is_an_annotated_input_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            plan_path = Path(tmp) / "plan.json"
            plan_path.write_text(json.dumps(https_plan()), encoding="utf-8")
            missing_checker = Path(tmp) / "missing-checker.py"
            with (
                mock.patch.object(sys, "argv", [str(SCRIPT), str(plan_path)]),
                mock.patch.object(transition, "HTTPS_CHECKER", missing_checker),
                mock.patch.object(transition.sys, "stderr") as stderr,
            ):
                self.assertEqual(2, transition.main())
            rendered = "".join(str(call.args[0]) for call in stderr.write.call_args_list)
            self.assertIn("trusted HTTPS-only relay DMZ checker is missing", rendered)

    def test_native_and_https_checkers_accept_the_same_transition_flags(self) -> None:
        expected = {
            "--allow-disabled",
            "--require-pr0-applied",
            "--require-dmz-boundary-noop",
        }
        observed: list[set[str]] = []
        for script in (SCRIPT, transition.HTTPS_CHECKER):
            result = subprocess.run(
                [sys.executable, str(script), "--help"],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            usage, separator, _ = result.stdout.partition("\n\n")
            self.assertEqual("\n\n", separator)
            observed.append(set(re.findall(r"--[a-z0-9-]+", usage)) - {"--help"})
        self.assertEqual([expected, expected], observed)

    def test_https_checker_exec_failure_is_an_annotated_input_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            plan_path = Path(tmp) / "plan.json"
            plan_path.write_text(json.dumps(https_plan()), encoding="utf-8")
            arguments = [str(SCRIPT), str(plan_path)]
            with (
                mock.patch.object(sys, "argv", arguments),
                mock.patch.object(
                    transition.os, "execv", side_effect=OSError("permission denied")
                ),
                mock.patch.object(transition.sys, "stderr") as stderr,
            ):
                self.assertEqual(2, transition.main())
            rendered = "".join(str(call.args[0]) for call in stderr.write.call_args_list)
            self.assertIn("cannot execute trusted HTTPS-only", rendered)
            self.assertIn("permission denied", rendered)

    def test_real_dispatcher_runs_both_full_contracts(self) -> None:
        for profile, plan in (
            ("native", native_fixtures.clean_plan()),
            ("https", https_fixtures.clean_plan()),
        ):
            with self.subTest(profile=profile):
                result = run_checker(plan)
                self.assertEqual(0, result.returncode, result.stdout + result.stderr)

    def test_fixed_trusted_checker_files_exist(self) -> None:
        self.assertTrue(SCRIPT.is_file())
        self.assertTrue(transition.HTTPS_CHECKER.is_file())


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])
    discovered = suite.countTestCases()
    if discovered < 13:
        raise SystemExit(
            f"refusing vacuous transition test run: discovered {discovered}, expected 13"
        )
    result = unittest.TextTestRunner().run(suite)
    raise SystemExit(0 if result.wasSuccessful() else 1)
