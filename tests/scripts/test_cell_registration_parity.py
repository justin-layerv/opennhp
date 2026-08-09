#!/usr/bin/env python3
"""Every cell root must wire what an assigned agent immediately needs.

The Connector Authority assigns agents across cells, so a cell that advertises
itself as assignable while its NHP servers lack native registration or qURL v2
admission is not a cell1-local problem: agents land there and fail.

They did. cell1 sat `active` with selection_weight 1 while its servers booted with

    [AGENT] Plugin initialized: agent v0.1.0
    (NHP-native registration DISABLED - set AGENT_OTP_REGISTRATION_ENABLED to enable)

and no v2 trust store. Enrollment failed with errCode 52107, which is the
fail-closed catch-all for server-side faults (see qurlErrCodeToRegErr in
endpoints/server/staticplugins/agent/plugin.go), so the failure never named the
missing configuration.

This is the source-level half of the fence. check_active_cell_capability.py is
the runtime half: it reads the live catalog and the rendered bootstrap script and
fails when an `active` cell cannot serve. Both exist because the defect was a
disagreement between configuration and running state, and neither view alone
could see it.
"""
from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

# Inputs an assigned agent needs the cell's NHP servers to have, and the concrete
# customer failure when each is missing.
REQUIRED_COMPUTE_INPUTS = {
    "agent_otp_registration_enabled": "enrollment fails with errCode 52107",
    "qurl_v2_admission_enabled": "the cell admits no qURL v2 connection",
}

# Roots that compose their own NHP server fleet. A new cell root belongs here on
# the commit that creates it.
CELL_ROOTS = (
    ROOT / "terraform/main.tf",
    ROOT / "terraform/environments/sandbox-cell1/main.tf",
)

# Environment roots that OWN a cell's Authority caller graph — the layer that
# decides the value rather than threading it. terraform/main.tf is deliberately
# absent: it is the shared module both cell0 and prod source, so taking the
# variable is correct there and the environment above it supplies the value.
CELL_ENVIRONMENT_ROOTS = (
    ROOT / "terraform/environments/sandbox/main.tf",
    ROOT / "terraform/environments/sandbox-cell1/main.tf",
)


class CellRegistrationParityTest(unittest.TestCase):
    def _compute_block(self, path: Path) -> str:
        match = re.search(r'module\s+"compute"\s*\{(.*?)\n\}', path.read_text(encoding="utf-8"), re.S)
        self.assertIsNotNone(match, f'{path} has no module "compute" block')
        return match.group(1)

    def test_every_cell_root_wires_agent_serving_inputs(self) -> None:
        for path in CELL_ROOTS:
            block = self._compute_block(path)
            for name, consequence in REQUIRED_COMPUTE_INPUTS.items():
                with self.subTest(root=path.name, input=name):
                    self.assertIn(
                        name, block,
                        f"{path.relative_to(ROOT)} does not pass {name} to module.compute; "
                        f"an agent the Authority assigns to that cell hits: {consequence}.",
                    )

    def test_cell1_binds_the_inputs_to_the_plugin_gate(self) -> None:
        """These render only inside the template's qurl_enabled block.

        Passing them true while the QURL plugin is dark drops them silently and
        recreates the original failure, so they must share the plugin's gate.
        """
        block = self._compute_block(ROOT / "terraform/environments/sandbox-cell1/main.tf")
        for name in REQUIRED_COMPUTE_INPUTS:
            with self.subTest(input=name):
                assignment = re.search(rf"{name}\s*=\s*(.+)", block)
                self.assertIsNotNone(assignment, f"{name} assignment not found")
                self.assertIn(
                    "qurl_service_deployable", assignment.group(1),
                    f"{name} must share the gate that turns the QURL plugin on; "
                    "ungated it drops silently whenever the plugin is off.",
                )

    def test_every_cell_root_derives_the_authority_caller_graph(self) -> None:
        """Turning the flags on is half the wiring; the alias ARNs are the rest.

        agent_otp_registration_enabled tells the server it WILL serve native
        registration. connector_authority_cell_config is what it serves it WITH.
        cell1 shipped with the first and not the second: its root passed
        `var.connector_authority_cell_config`, whose default is null, so
        user_data emitted no NHP_CONNECTOR_REGISTRATION_* line at all,
        configureConnectorCellAuthority returned early, and every agent the
        Authority placed there was unservable while the cell advertised itself
        `active`. The OTP leg hid it best: NHP_OTP carries no acknowledgement, so
        a missing issuer alias is not an error the agent can see — it waits out
        its assignment ticket and no code is ever emailed.

        Each root must DERIVE the graph from Control's published alias targets
        (a local), never leave it to an unset variable. Reading Control is also
        what makes a reviewed authority-color flip carry to the cells instead of
        stranding them on a retired alias.
        """
        for path in CELL_ENVIRONMENT_ROOTS:
            with self.subTest(root=str(path.parent.name)):
                source = path.read_text(encoding="utf-8")
                assignment = re.search(r"connector_authority_cell_config\s*=\s*(\S+)", source)
                self.assertIsNotNone(
                    assignment,
                    f"{path.relative_to(ROOT)} does not supply connector_authority_cell_config; "
                    "agents assigned to that cell cannot enroll and, on the OTP leg, are never "
                    "told why.",
                )
                self.assertIn(
                    "local.connector_authority_cell_config", assignment.group(1),
                    f"{path.relative_to(ROOT)} supplies the raw variable rather than the local that "
                    "derives the caller graph from Control. The variable defaults to null, which "
                    "renders no NHP_CONNECTOR_REGISTRATION_* config and silently disables "
                    "assigned-cell registration.",
                )
                derivation = path.parent / "connector_authority_cell.tf"
                self.assertTrue(
                    derivation.exists() and "authority_cell_alias_targets" in derivation.read_text(encoding="utf-8"),
                    f"{path.parent.relative_to(ROOT)} must derive its alias targets from Control's "
                    "published authority_cell_alias_targets; a pinned literal color strands the "
                    "cell the day the selector moves.",
                )

    def test_derived_authority_config_uses_the_protocol_environment(self) -> None:
        """The Authority environment is not always this root's var.environment.

        cell1 splits the two: var.environment is the INFRASTRUCTURE namespace
        ("sandbox-cell1") that keeps resource names and SSM paths from colliding
        with cell0, while the Authority/ticket environment is "sandbox" for both
        cells and travels as var.protocol_environment.

        Feeding var.environment into the caller graph is unbuildable rather than
        merely wrong: modules/compute requires
        contains(["sandbox","prod"], config.environment), and this root's
        variables.tf validates var.environment is neither, so the precondition
        could never pass. It would also reconstruct the expected alias ARNs as
        layerv-nhp-sandbox-cell1-ca-*-cell1 when Control publishes
        layerv-nhp-sandbox-ca-*-cell1.
        """
        for path in CELL_ENVIRONMENT_ROOTS:
            derivation = path.parent / "connector_authority_cell.tf"
            if not derivation.exists():
                continue
            source = derivation.read_text(encoding="utf-8")
            variables = (path.parent / "variables.tf").read_text(encoding="utf-8")
            if "protocol_environment" not in variables:
                # Roots without the split legitimately use var.environment.
                continue
            with self.subTest(root=str(path.parent.name)):
                assignment = re.search(r"^\s*environment\s*=\s*(\S+)", source, re.M)
                self.assertIsNotNone(
                    assignment, f"{derivation.relative_to(ROOT)} sets no environment"
                )
                self.assertEqual(
                    assignment.group(1),
                    "var.protocol_environment",
                    f"{derivation.relative_to(ROOT)} feeds the infrastructure namespace into the "
                    "Authority caller graph; modules/compute can never accept it.",
                )

    def test_cell1_reads_the_shared_issuer_key(self) -> None:
        """One issuer identity per deployment, not one per cell.

        A cell-local issuer key would mean a link minted by cell0 fails to verify
        at cell1 — the kind of split-brain that only shows up for whichever
        customers happen to be assigned to the wrong side.
        """
        source = (ROOT / "terraform/environments/sandbox-cell1/main.tf").read_text(encoding="utf-8")
        self.assertIn(
            'data "aws_kms_public_key" "qurl_v2_issuer"', source,
            "cell1 must READ the account-global issuer key",
        )
        self.assertNotIn(
            'resource "aws_kms_key" "qurl_v2_issuer"', source,
            "cell1 must never create its own issuer key",
        )
        kms = re.search(r'module\s+"kms"\s*\{(.*?)\n\}', source, re.S)
        self.assertIsNotNone(kms)
        self.assertIn(
            "qurl_v2_issuer_key_enabled = false", kms.group(1),
            "cell1's KMS module must not mint a second issuer key",
        )


if __name__ == "__main__":
    unittest.main()
