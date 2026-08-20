#!/usr/bin/env python3
"""Contract tests for the source-locked production Hub DNS root."""

from __future__ import annotations

import json
import re
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DNS_ROOT = ROOT / "terraform/environments/prod-hub-dns"
CHECKER = ROOT / "scripts/check-prod-hub-dns-plan.py"
WORKFLOW = ROOT / ".github/workflows/prod-hub-dns-update.yml"
CONTROL_PROD_WORKFLOW = ROOT / ".github/workflows/control-prod-update.yml"
AWS_PROVIDER_DARWIN_ARM64_H1 = (
    "h1:gSTd4VOv0lEjCGP5deZ4hRMBZhIOUbtS4AlCML+3gIo="
)
AWS_PROVIDER_LINUX_AMD64_H1 = (
    "h1:iWz9BgFQaDPA1ChVGYvgI3MlUnx3wSQCA2ggYqDPcz8="
)


def variable_block(name: str) -> str:
    text = (DNS_ROOT / "variables.tf").read_text(encoding="utf-8")
    marker = f'variable "{name}" {{'
    start = text.find(marker)
    if start < 0:
        raise AssertionError(f"missing {marker}")
    depth = 0
    for index in range(start, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return text[start : index + 1]
    raise AssertionError(f"unterminated {marker}")


class ProductionHubDNSContractTest(unittest.TestCase):
    def test_provider_lock_covers_developer_and_hosted_runner_platforms(self) -> None:
        lock = (DNS_ROOT / ".terraform.lock.hcl").read_text(encoding="utf-8")
        self.assertIn(AWS_PROVIDER_DARWIN_ARM64_H1, lock)
        self.assertIn(AWS_PROVIDER_LINUX_AMD64_H1, lock)

    def test_root_is_source_locked_dark(self) -> None:
        gate = variable_block("hub_dns_enabled")
        self.assertEqual(
            re.findall(r"(?m)^\s*default\s*=\s*(.+?)\s*$", gate), ["false"]
        )
        self.assertIn("condition     = !var.hub_dns_enabled", gate)
        self.assertIn(
            "hub_dns_enabled = false",
            (DNS_ROOT / "terraform.tfvars").read_text(encoding="utf-8"),
        )

    def test_absent_hub_edge_is_never_read_while_dark(self) -> None:
        main = (DNS_ROOT / "main.tf").read_text(encoding="utf-8")
        self.assertRegex(
            main,
            r'data "aws_lb" "hub" \{\s+count = var\.hub_dns_enabled \? 1 : 0',
        )
        self.assertRegex(
            main,
            r'resource "aws_route53_record" "hub" \{\s+'
            r"provider = aws\.route53_mgmt\s+"
            r"count\s+= var\.hub_dns_enabled \? 1 : 0",
        )
        self.assertNotIn("terraform_remote_state", main)

    def test_record_can_only_override_wildcard_with_the_hub_nlb(self) -> None:
        main = (DNS_ROOT / "main.tf").read_text(encoding="utf-8")
        variables = (DNS_ROOT / "variables.tf").read_text(encoding="utf-8")
        self.assertIn('default     = "hub.nhp.layerv.ai"', variables)
        self.assertIn('default     = "layerv-nhp-prod-hub-edge"', variables)
        self.assertIn('default     = "Z0748438C8EK6UAW94ST"', variables)
        self.assertIn("name                   = data.aws_lb.hub[0].dns_name", main)
        self.assertIn("zone_id                = data.aws_lb.hub[0].zone_id", main)
        self.assertIn("evaluate_target_health = true", main)
        self.assertNotIn('resource "aws_route53_record" "wildcard"', main)
        self.assertNotRegex(main, r"ac[_-].*nlb|wildcard\s+=\s+true")

    def run_checker(self, plan: dict[str, object]) -> subprocess.CompletedProcess[str]:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json") as handle:
            json.dump(plan, handle)
            handle.flush()
            return subprocess.run(
                ["python3", str(CHECKER), handle.name],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )

    def test_plan_checker_accepts_dark_and_exact_create_only(self) -> None:
        dark = {
            "format_version": "1.2",
            "terraform_version": "1.14.3",
            "resource_changes": [],
        }
        self.assertEqual(self.run_checker(dark).returncode, 0)
        exact_create = {
            "format_version": "1.2",
            "terraform_version": "1.14.3",
            "resource_changes": [
                {
                    "address": "data.aws_lb.hub[0]",
                    "mode": "data",
                    "type": "aws_lb",
                    "change": {"actions": ["read"]},
                },
                {
                    "address": "aws_route53_record.hub[0]",
                    "mode": "managed",
                    "type": "aws_route53_record",
                    "change": {
                        "actions": ["create"],
                        "after": {
                            "name": "hub.nhp.layerv.ai",
                            "type": "A",
                            "zone_id": "Z0748438C8EK6UAW94ST",
                            "alias": [{"evaluate_target_health": True}],
                        },
                    },
                },
            ],
            "output_changes": {"hub_nlb_dns_name": {"actions": ["update"]}},
        }
        self.assertEqual(self.run_checker(exact_create).returncode, 0)

    def test_plan_checker_rejects_update_destroy_and_other_resources(self) -> None:
        base = {
            "address": "aws_route53_record.hub[0]",
            "mode": "managed",
            "type": "aws_route53_record",
            "change": {
                "actions": ["update"],
                "after": {
                    "name": "hub.nhp.layerv.ai",
                    "type": "A",
                    "zone_id": "Z0748438C8EK6UAW94ST",
                    "alias": [{"evaluate_target_health": True}],
                },
            },
        }
        for plan in (
            {},
            {
                "format_version": "1.2",
                "terraform_version": "1.14.3",
                "resource_changes": [base],
            },
            {
                "format_version": "1.2",
                "terraform_version": "1.14.3",
                "resource_changes": [
                    {
                        **base,
                        "address": "aws_route53_record.wildcard[0]",
                        "change": {**base["change"], "actions": ["create"]},
                    }
                ]
            },
            {
                "format_version": "1.2",
                "terraform_version": "1.14.3",
                "resource_changes": [],
                "output_changes": {"wildcard_target": {"actions": ["create"]}},
            },
        ):
            with self.subTest(plan=plan):
                self.assertNotEqual(self.run_checker(plan).returncode, 0)

    def test_workflow_is_protected_exact_root_saved_plan_apply(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        for marker in (
            "ROOT: terraform/environments/prod-hub-dns",
            'if [[ "$GITHUB_REF" != \'refs/heads/main\' ]]',
            "PLAN_PROD_HUB_DNS",
            "APPLY_PROD_HUB_DNS",
            '[[ "$GITHUB_RUN_ATTEMPT" == \'1\' ]]',
            "group: deploy-prod-control",
            "cancel-in-progress: false",
            "environment: production",
            "scripts/check-live-main-ref.sh",
            "scripts/check-control-aws-identity.sh prod",
            "scripts/check-no-checkout-credentials.sh",
            "terraform init -reconfigure -input=false -lockfile=readonly",
            "terraform plan -input=false -lock=false",
            "../../../scripts/check-prod-hub-dns-plan.py tfplan.json",
            "sha256sum --check tfplan.sha256",
            "cmp tfplan.json",
            "terraform apply -input=false -lock-timeout=5m -no-color tfplan",
            "plan_age_seconds > 172800",
        ):
            self.assertIn(marker, workflow)

        self.assertEqual(workflow.count("environment: production"), 2)
        self.assertEqual(workflow.count("id-token: write"), 2)
        self.assertEqual(workflow.count("persist-credentials: false"), 2)
        self.assertEqual(workflow.count("-lockfile=readonly"), 2)
        self.assertEqual(workflow.count("GITHUB_RUN_ATTEMPT"), 2)

        guard_start = workflow.index("  guard:")
        plan_start = workflow.index("  plan:")
        apply_start = workflow.index("  apply:")
        self.assertNotIn("id-token: write", workflow[guard_start:plan_start])
        self.assertIn("environment: production", workflow[plan_start:apply_start])
        self.assertIn("environment: production", workflow[apply_start:])

        plan_body = workflow[plan_start:apply_start]
        apply_body = workflow[apply_start:]
        self.assertLess(
            plan_body.index("scripts/check-live-main-ref.sh"),
            plan_body.index("Configure narrowly scoped production planning session"),
        )
        self.assertLess(
            apply_body.index("Forbid replaying the apply job"),
            apply_body.index("Download reviewed saved plan"),
        )
        self.assertLess(
            apply_body.index("Forbid replaying the apply job"),
            apply_body.index("Configure narrowly scoped production apply session"),
        )
        self.assertLess(
            apply_body.index("Verify commit, plan bytes, and reviewed contract"),
            apply_body.index("Configure narrowly scoped production apply session"),
        )
        self.assertLess(
            apply_body.index("Re-render and re-check the exact saved plan"),
            apply_body.index("Apply exact reviewed plan"),
        )

        policy_texts = re.findall(
            r"inline-session-policy: >-\n\s+(\{[^\n]+\})", workflow
        )
        self.assertEqual(len(policy_texts), 2)
        self.assertTrue(all(len(policy) <= 2048 for policy in policy_texts))
        policies = [json.loads(policy) for policy in policy_texts]

        def actions(policy: dict[str, object]) -> set[str]:
            statements = policy["Statement"]
            assert isinstance(statements, list)
            return {
                action
                for statement in statements
                for action in statement["Action"]
            }

        plan_actions, apply_actions = map(actions, policies)
        self.assertNotIn("s3:PutObject", plan_actions)
        self.assertNotIn("s3:DeleteObject", plan_actions)
        self.assertNotIn("kms:Encrypt", plan_actions)
        self.assertIn("s3:ListBucket", plan_actions)
        self.assertIn("s3:PutObject", apply_actions)
        self.assertIn("s3:DeleteObject", apply_actions)
        self.assertIn("s3:ListBucket", apply_actions)
        self.assertIn("kms:Encrypt", apply_actions)
        for policy in policies:
            serialized = json.dumps(policy, sort_keys=True)
            self.assertIn(
                "arn:aws:iam::165115313779:role/nhp-ac-route53-access",
                serialized,
            )
            self.assertNotIn("route53:ChangeResourceRecordSets", serialized)
            state_prefix = next(
                statement
                for statement in policy["Statement"]
                if statement["Sid"] == "StatePrefixList"
            )
            self.assertEqual(state_prefix["Action"], ["s3:ListBucket"])
            self.assertEqual(
                state_prefix["Condition"]["StringLike"]["s3:prefix"],
                [
                    "nhp/prod-hub-dns/*",
                    "env:/",
                    "env:/*/nhp/prod-hub-dns/*",
                ],
            )

    def test_dns_and_control_writers_share_one_production_lane(self) -> None:
        # DNS planning runs without a state lock because its NLB dependency and
        # Control's NLB writer are serialized by this cross-workflow lane. A
        # one-sided rename must fail before it can reintroduce that race.
        groups = []
        for path in (WORKFLOW, CONTROL_PROD_WORKFLOW):
            workflow = path.read_text(encoding="utf-8")
            match = re.search(r"(?m)^  group: ([a-z0-9-]+)$", workflow)
            self.assertIsNotNone(
                match, f"missing top-level concurrency group in {path}"
            )
            assert match is not None
            groups.append(match.group(1))

        self.assertEqual(groups, ["deploy-prod-control", "deploy-prod-control"])


if __name__ == "__main__":
    unittest.main()
