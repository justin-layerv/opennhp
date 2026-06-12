#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "check-observability-parity.py"


def load_checker_module():
    spec = importlib.util.spec_from_file_location("check_observability_parity", SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"failed to load {SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


CHECKER = load_checker_module()
AC_ALARM_ACTION_EXPR = CHECKER.AC_ALARM_ACTION_EXPR
AC_CORE_ALARMS = CHECKER.AC_CORE_ALARM_NAMES


def write(path: Path, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(body).lstrip(), encoding="utf-8")


def ac_alarm_block(name: str) -> str:
    return textwrap.dedent(
        f"""
        resource "aws_cloudwatch_metric_alarm" "{name}" {{
          count = var.enable_cloudwatch_alarms ? 1 : 0

          alarm_actions = {AC_ALARM_ACTION_EXPR}
          ok_actions    = {AC_ALARM_ACTION_EXPR}
        }}
        """
    ).strip()


def build_fixture(root: Path) -> None:
    write(
        root / "terraform" / "main.tf",
        """
        module "monitoring" {
          source = "./modules/monitoring"

          environment                  = var.environment
          cell_id                      = var.cell_id
          server_stderr_log_group_name = module.compute.log_group_stderr_name
          name_prefix                  = local.name_prefix
          chatbot_owned_externally     = var.chatbot_owned_externally
        }

        module "ac" {
          source = "./modules/ac"
          count  = var.deploy_ac ? 1 : 0

          enable_cloudwatch_alarms = true
          alarm_sns_topic_arn      = module.monitoring.sns_topic_arn
          alerts_sns_topic_arn = module.monitoring.sns_topic_arn
        }
        """,
    )
    write(
        root / "terraform" / "modules" / "monitoring" / "main.tf",
        """
        resource "aws_sns_topic" "alerts" {}

        resource "aws_cloudwatch_log_metric_filter" "server_panic" {}

        resource "aws_cloudwatch_metric_alarm" "server_panic" {
          alarm_actions             = [aws_sns_topic.alerts.arn]
          ok_actions                = [aws_sns_topic.alerts.arn]
          insufficient_data_actions = [aws_sns_topic.alerts.arn]
        }

        resource "aws_cloudwatch_metric_alarm" "server_instance_restart" {
          alarm_actions = [aws_sns_topic.alerts.arn]
          ok_actions    = [aws_sns_topic.alerts.arn]
        }

        resource "aws_cloudwatch_metric_alarm" "ac_registration_latency" {
          alarm_actions = [aws_sns_topic.alerts.arn]
          ok_actions    = [aws_sns_topic.alerts.arn]
        }
        """,
    )
    write(
        root / "terraform" / "modules" / "ac" / "monitoring.tf",
        "\n\n".join(ac_alarm_block(name) for name in AC_CORE_ALARMS),
    )
    write(
        root / "terraform" / "modules" / "ac" / "variables.tf",
        """
        variable "enable_cloudwatch_alarms" {
          type    = bool
          default = true
        }
        """,
    )
    write(
        root / "terraform" / "modules" / "compute" / "main.tf",
        """
        resource "aws_cloudwatch_log_group" "server_stderr" {}
        """,
    )
    write(
        root / "terraform" / "modules" / "compute" / "outputs.tf",
        """
        output "log_group_stderr_name" {
          value = aws_cloudwatch_log_group.server_stderr.name
        }
        """,
    )

    for env in ("sandbox", "prod"):
        write(
            root / "terraform" / "environments" / env / "main.tf",
            """
            module "nhp" {
              source = "../.."

              deploy_ac                  = var.deploy_ac
              enable_slack_notifications = var.enable_slack_notifications
              slack_workspace_id         = var.slack_workspace_id
              slack_channel_id           = var.slack_channel_id
              chatbot_owned_externally   = var.chatbot_owned_externally
            }
            """,
        )
        write(
            root / "terraform" / "environments" / env / "variables.tf",
            """
            variable "deploy_ac" {
              type    = bool
              default = true
            }

            variable "enable_slack_notifications" {
              type    = bool
              default = true
            }

            variable "slack_workspace_id" {
              type    = string
              default = "T"
            }

            variable "slack_channel_id" {
              type    = string
              default = "C"
            }

            variable "chatbot_owned_externally" {
              type    = bool
              default = true
            }
            """,
        )
        write(
            root / "terraform" / "environments" / env / "terraform.tfvars",
            """
            deploy_ac = true
            enable_slack_notifications = true
            chatbot_owned_externally = true
            """,
        )


def run_check(root: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), "--repo-root", str(root)],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


class ObservabilityParityTests(unittest.TestCase):
    def test_aop_replay_detection_alarm_is_fenced(self) -> None:
        self.assertIn("aop_replay_detected", AC_CORE_ALARMS)

    def test_in_sync_fixture_passes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_fixture(root)

            result = run_check(root)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("observability parity surfaces are wired", result.stdout)

    def test_inline_comment_on_pinned_expression_passes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_fixture(root)
            main_tf = root / "terraform" / "main.tf"
            main_tf.write_text(
                main_tf.read_text(encoding="utf-8").replace(
                    "  chatbot_owned_externally     = var.chatbot_owned_externally\n",
                    "  chatbot_owned_externally     = var.chatbot_owned_externally # fixture note\n",
                ),
                encoding="utf-8",
            )

            result = run_check(root)

        self.assertEqual(result.returncode, 0, result.stderr)

    def test_missing_prod_passthrough_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_fixture(root)
            prod_main = root / "terraform" / "environments" / "prod" / "main.tf"
            prod_main.write_text(
                prod_main.read_text(encoding="utf-8").replace(
                    "  chatbot_owned_externally   = var.chatbot_owned_externally\n",
                    "",
                ),
                encoding="utf-8",
            )

            result = run_check(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("prod/main.tf", result.stderr)
        self.assertIn("chatbot_owned_externally", result.stderr)

    def test_new_env_root_is_checked(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_fixture(root)
            env_dir = root / "terraform" / "environments" / "dev"
            write(
                env_dir / "main.tf",
                """
                module "nhp" {
                  source = "../.."

                  deploy_ac                  = var.deploy_ac
                  enable_slack_notifications = var.enable_slack_notifications
                  slack_workspace_id         = var.slack_workspace_id
                  slack_channel_id           = var.slack_channel_id
                }
                """,
            )
            write(
                env_dir / "variables.tf",
                """
                variable "deploy_ac" {}
                variable "enable_slack_notifications" {}
                variable "slack_workspace_id" {}
                variable "slack_channel_id" {}
                variable "chatbot_owned_externally" {}
                """,
            )
            write(
                env_dir / "terraform.tfvars",
                """
                deploy_ac = true
                enable_slack_notifications = true
                chatbot_owned_externally = true
                """,
            )

            result = run_check(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("terraform/environments/dev", result.stderr)
        self.assertIn("chatbot_owned_externally", result.stderr)

    def test_missing_root_stderr_wiring_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_fixture(root)
            main_tf = root / "terraform" / "main.tf"
            main_tf.write_text(
                main_tf.read_text(encoding="utf-8").replace(
                    "  server_stderr_log_group_name = module.compute.log_group_stderr_name\n",
                    "",
                ),
                encoding="utf-8",
            )

            result = run_check(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("server_stderr_log_group_name", result.stderr)

    def test_monitoring_module_count_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_fixture(root)
            main_tf = root / "terraform" / "main.tf"
            main_tf.write_text(
                main_tf.read_text(encoding="utf-8").replace(
                    '  source = "./modules/monitoring"\n',
                    '  source = "./modules/monitoring"\n  count  = var.deploy_ac ? 1 : 0\n',
                ),
                encoding="utf-8",
            )

            result = run_check(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must not set `count`", result.stderr)

    def test_monitoring_module_for_each_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_fixture(root)
            main_tf = root / "terraform" / "main.tf"
            main_tf.write_text(
                main_tf.read_text(encoding="utf-8").replace(
                    '  source = "./modules/monitoring"\n',
                    '  source = "./modules/monitoring"\n  for_each = toset(["prod"])\n',
                ),
                encoding="utf-8",
            )

            result = run_check(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must not set `for_each`", result.stderr)

    def test_monitoring_sns_topic_count_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_fixture(root)
            monitoring_main = root / "terraform" / "modules" / "monitoring" / "main.tf"
            monitoring_main.write_text(
                monitoring_main.read_text(encoding="utf-8").replace(
                    'resource "aws_sns_topic" "alerts" {}',
                    'resource "aws_sns_topic" "alerts" {\n  count = 1\n}',
                ),
                encoding="utf-8",
            )

            result = run_check(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn('aws_sns_topic" "alerts"', result.stderr)
        self.assertIn("must not set `count`", result.stderr)

    def test_missing_required_alarm_resource_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_fixture(root)
            ac_monitoring = root / "terraform" / "modules" / "ac" / "monitoring.tf"
            ac_monitoring.write_text(
                ac_monitoring.read_text(encoding="utf-8").replace(
                    'resource "aws_cloudwatch_metric_alarm" "registration_stale"',
                    'resource "aws_cloudwatch_metric_alarm" "registration_stale_missing"',
                ),
                encoding="utf-8",
            )

            result = run_check(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("missing AC CloudWatch alarm", result.stderr)
        self.assertIn("registration_stale", result.stderr)

    def test_untracked_ac_alarm_resource_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_fixture(root)
            ac_monitoring = root / "terraform" / "modules" / "ac" / "monitoring.tf"
            ac_monitoring.write_text(
                ac_monitoring.read_text(encoding="utf-8")
                + "\n\n"
                + ac_alarm_block("new_unfenced_alarm"),
                encoding="utf-8",
            )

            result = run_check(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("AC CloudWatch alarm(s) must be added", result.stderr)
        self.assertIn("new_unfenced_alarm", result.stderr)

    def test_ac_alert_sns_wiring_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_fixture(root)
            main_tf = root / "terraform" / "main.tf"
            main_tf.write_text(
                main_tf.read_text(encoding="utf-8").replace(
                    "  alerts_sns_topic_arn = module.monitoring.sns_topic_arn\n",
                    "",
                ),
                encoding="utf-8",
            )

            result = run_check(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("alerts_sns_topic_arn", result.stderr)

    def test_ac_alarm_sns_wiring_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_fixture(root)
            main_tf = root / "terraform" / "main.tf"
            main_tf.write_text(
                main_tf.read_text(encoding="utf-8").replace(
                    "  alarm_sns_topic_arn      = module.monitoring.sns_topic_arn\n",
                    "",
                ),
                encoding="utf-8",
            )

            result = run_check(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("alarm_sns_topic_arn", result.stderr)

    def test_ac_cloudwatch_alarm_root_override_false_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_fixture(root)
            main_tf = root / "terraform" / "main.tf"
            main_tf.write_text(
                main_tf.read_text(encoding="utf-8").replace(
                    "  enable_cloudwatch_alarms = true\n",
                    "  enable_cloudwatch_alarms = false\n",
                ),
                encoding="utf-8",
            )

            result = run_check(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("enable_cloudwatch_alarms", result.stderr)
        self.assertIn("want `enable_cloudwatch_alarms = true`", result.stderr)

    def test_required_alarm_action_wiring_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_fixture(root)
            monitoring_main = root / "terraform" / "modules" / "monitoring" / "main.tf"
            monitoring_main.write_text(
                monitoring_main.read_text(encoding="utf-8").replace(
                    "  alarm_actions             = [aws_sns_topic.alerts.arn]\n",
                    "",
                    1,
                ),
                encoding="utf-8",
            )

            result = run_check(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("server_panic", result.stderr)
        self.assertIn("alarm_actions", result.stderr)

    def test_ac_registration_stale_action_wiring_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_fixture(root)
            ac_monitoring = root / "terraform" / "modules" / "ac" / "monitoring.tf"
            stale_block = ac_alarm_block("registration_stale")
            stale_without_actions = stale_block.replace(
                f"  alarm_actions = {AC_ALARM_ACTION_EXPR}\n",
                "",
            )
            ac_monitoring.write_text(
                ac_monitoring.read_text(encoding="utf-8").replace(
                    stale_block,
                    stale_without_actions,
                ),
                encoding="utf-8",
            )

            result = run_check(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("registration_stale", result.stderr)
        self.assertIn("alarm_actions", result.stderr)

    def test_compute_stderr_output_wiring_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_fixture(root)
            compute_outputs = root / "terraform" / "modules" / "compute" / "outputs.tf"
            compute_outputs.write_text(
                compute_outputs.read_text(encoding="utf-8").replace(
                    "  value = aws_cloudwatch_log_group.server_stderr.name\n",
                    "  value = aws_cloudwatch_log_group.server_stdout.name\n",
                ),
                encoding="utf-8",
            )

            result = run_check(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("log_group_stderr_name", result.stderr)
        self.assertIn("aws_cloudwatch_log_group.server_stderr.name", result.stderr)

    def test_ac_cloudwatch_alarm_default_false_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_fixture(root)
            ac_variables = root / "terraform" / "modules" / "ac" / "variables.tf"
            ac_variables.write_text(
                ac_variables.read_text(encoding="utf-8").replace(
                    "  default = true\n",
                    "  default = false\n",
                ),
                encoding="utf-8",
            )

            result = run_check(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("enable_cloudwatch_alarms", result.stderr)
        self.assertIn("want `default = true`", result.stderr)

    def test_tfvars_noop_variable_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_fixture(root)
            sandbox_vars = root / "terraform" / "environments" / "sandbox" / "variables.tf"
            sandbox_vars.write_text(
                sandbox_vars.read_text(encoding="utf-8").replace(
                    textwrap.dedent(
                        """
                    variable "chatbot_owned_externally" {
                      type    = bool
                      default = true
                    }
                    """
                    ).lstrip(),
                    "",
                ),
                encoding="utf-8",
            )

            result = run_check(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn('variable "chatbot_owned_externally"', result.stderr)

    def test_tfvars_false_value_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_fixture(root)
            sandbox_tfvars = (
                root / "terraform" / "environments" / "sandbox" / "terraform.tfvars"
            )
            sandbox_tfvars.write_text(
                sandbox_tfvars.read_text(encoding="utf-8").replace(
                    "chatbot_owned_externally = true\n",
                    "chatbot_owned_externally = false\n",
                ),
                encoding="utf-8",
            )

            result = run_check(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("sandbox/terraform.tfvars", result.stderr)
        self.assertIn("chatbot_owned_externally", result.stderr)
        self.assertIn("is false, want true", result.stderr)


if __name__ == "__main__":
    unittest.main()
