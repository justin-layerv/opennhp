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
RELAY_ALARM_ACTION_EXPR = CHECKER.RELAY_ALARM_ACTION_EXPR
RELAY_CORE_ALARMS = CHECKER.RELAY_CORE_ALARM_NAMES
RELAY_SINGLE_EVENT_ALARMS = CHECKER.RELAY_SINGLE_EVENT_ALARM_NAMES
QURL_SERVICE_ALARM_ACTION_EXPR = CHECKER.QURL_SERVICE_ALARM_ACTION_EXPR
QURL_CI_LOCK_FAILURE_DIAGNOSTIC_QUERY = (
    CHECKER.QURL_CI_LOCK_FAILURE_DIAGNOSTIC_QUERY
)
QURL_CI_LOCK_FAILURE_BREAKDOWN_QUERY = CHECKER.QURL_CI_LOCK_FAILURE_BREAKDOWN_QUERY

QURL_CI_LOCK_FAILURE_ALARM_BLOCK = r'''
resource "aws_cloudwatch_metric_alarm" "qurl_ci_sandbox_live_env_lock_failure" {
  count = var.environment == "sandbox" ? 1 : 0

  alarm_name          = "${local.name_prefix}-qurl-service-ci-live-env-lock-failure"
  alarm_description   = "Runbook: https://github.com/layervai/nhp/blob/main/docs/runbooks/qurl-sandbox-live-env-lock-alarm.md"
  actions_enabled     = true
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  datapoints_to_alarm = 1
  metric_name         = "SandboxLiveEnvLockFailure"
  namespace           = "LayerV/QURLServiceCI"
  period              = 60
  statistic           = "Sum"
  threshold           = 0
  treat_missing_data  = "notBreaching"

  alarm_actions             = [module.monitoring.sns_topic_arn]
  ok_actions                = [module.monitoring.sns_topic_arn]
  insufficient_data_actions = []

  tags = {
    Component = "qurl-service"
  }
}
'''.strip()


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


def relay_alarm_block(name: str) -> str:
    tg_dimensions = """
          dimensions = {
            LoadBalancer = aws_lb.relay.arn_suffix
            TargetGroup  = aws_lb_target_group.relay.arn_suffix
          }
        """
    dimensions = {
        "relay_tg_unhealthy_hosts": tg_dimensions,
        "relay_tg_zero_healthy_targets": """
          treat_missing_data = "breaching"

        """
        + tg_dimensions,
        "relay_bootstrap_failure": """
          dimensions = {
            Component   = "relay"
            Environment = var.environment
          }
        """,
        "relay_capacity_below_baseline": """
          metric_name = "GroupInServiceInstances"

          dimensions = {
            AutoScalingGroupName = aws_autoscaling_group.relay.name
          }
        """,
        "relay_shedding": """
          comparison_operator = "GreaterThanThreshold"
          metric_name         = "RelayShed"
          namespace           = "LayerV/NHP"
          statistic           = "Sum"
          threshold           = 0
          treat_missing_data  = "notBreaching"

          dimensions = {
            Environment = var.environment
          }
        """,
        "relay_shedding_unknown_environment": """
          comparison_operator = "GreaterThanThreshold"
          metric_name         = "RelayShed"
          namespace           = "LayerV/NHP"
          statistic           = "Sum"
          threshold           = 0
          treat_missing_data  = "notBreaching"

          dimensions = {
            Environment = "unknown"
          }
        """,
    }[name]
    ok_actions = "[]" if name in RELAY_SINGLE_EVENT_ALARMS else RELAY_ALARM_ACTION_EXPR
    return textwrap.dedent(
        f"""
        resource "aws_cloudwatch_metric_alarm" "{name}" {{
          alarm_actions = {RELAY_ALARM_ACTION_EXPR}
          ok_actions    = {ok_actions}
        {dimensions.rstrip()}
        }}
        """
    ).strip()


RELAY_FORWARD_REJECT_BLOCK = textwrap.dedent(
    """
    resource "aws_cloudwatch_metric_alarm" "relay_forward_reject" {
      count = var.deploy_relay ? 1 : 0

      alarm_actions = [aws_sns_topic.alerts.arn]
      metric_name   = "RelayForwardReject"
      namespace     = "LayerV/NHP"
      ok_actions    = [aws_sns_topic.alerts.arn]
      statistic     = "Sum"

      dimensions = {
        Environment = var.environment
        Cell        = var.cell_id
      }
    }
    """
).strip()

QURL_BROWSER_REJECTED_RATIO_BLOCK = textwrap.dedent(
    """
    locals {
      qurl_browser_rejected_alarms = {
        malformed = {
          metric_name = "QurlResolveBrowserRejectedMalformed"
        }
        out_of_range = {
          metric_name = "QurlResolveBrowserRejectedOutOfRange"
        }
      }

      qurl_browser_rejected_min_resolve_attempts = 20
    }

    resource "aws_cloudwatch_metric_alarm" "qurl_browser_rejected_ratio" {
      for_each = local.qurl_browser_rejected_alarms

      alarm_name          = "${var.name_prefix}-${var.cell_id}-${each.value.suffix}"
      comparison_operator = "GreaterThanThreshold"
      evaluation_periods  = 3
      datapoints_to_alarm = 3
      threshold           = each.value.threshold
      actions_enabled     = var.qurl_browser_rejected_alarm_actions_enabled
      alarm_actions       = [aws_sns_topic.alerts.arn]
      ok_actions          = [aws_sns_topic.alerts.arn]
      treat_missing_data  = "notBreaching"

      metric_query {
        id          = "ratio"
        expression  = "IF(resolve_attempts >= ${local.qurl_browser_rejected_min_resolve_attempts}, FILL(rejected, 0) / resolve_attempts, 0)"
        return_data = true
      }

      metric_query {
        id          = "resolve_attempts"
        expression  = "FILL(success, 0) + FILL(fail_validate, 0) + FILL(fail_resolve_catalog, 0) + FILL(fail_knock, 0) + FILL(fail_post_knock, 0) + FILL(fail_canceled, 0) + FILL(fail_unknown, 0)"
        return_data = false
      }

      metric_query {
        id          = "rejected"
        return_data = false

        metric {
          metric_name = each.value.metric_name
          namespace   = "LayerV/NHP"
          period      = 300
          stat        = "Sum"

          dimensions = {
            Environment = var.environment
            Cell        = var.cell_id
          }
        }
      }

      dynamic "metric_query" {
        for_each = {
          success              = "QurlResolveSuccess"
          fail_validate        = "QurlResolveFailValidate"
          fail_resolve_catalog = "QurlResolveFailResolveCatalog"
          fail_knock           = "QurlResolveFailKnock"
          fail_post_knock      = "QurlResolveFailPostKnock"
          fail_canceled        = "QurlResolveFailCanceled"
          fail_unknown         = "QurlResolveFailUnknown"
        }
        iterator = outcome

        content {
          id          = outcome.key
          return_data = false

          metric {
            metric_name = outcome.value
            namespace   = "LayerV/NHP"
            period      = 300
            stat        = "Sum"

            dimensions = {
              Environment = var.environment
              Cell        = var.cell_id
            }
          }
        }
      }
    }
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
          server_log_group_name        = module.compute.log_group_name
          server_stderr_log_group_name = module.compute.log_group_stderr_name
          name_prefix                  = local.name_prefix
          chatbot_owned_externally     = var.chatbot_owned_externally
          qurl_browser_rejected_alarm_actions_enabled = var.qurl_browser_rejected_alarm_actions_enabled
          deploy_relay                 = var.deploy_relay
        }

        module "ac" {
          source = "./modules/ac"
          count  = var.deploy_ac ? 1 : 0

          enable_cloudwatch_alarms = true
          alarm_sns_topic_arn      = module.monitoring.sns_topic_arn
          alerts_sns_topic_arn = module.monitoring.sns_topic_arn
        }

        module "qurl_service" {
          source = "./modules/qurl-service"
          count  = var.deploy_qurl_service ? 1 : 0

          qurl_service_alarm_sns_topic_arn = module.monitoring.sns_topic_arn
        }
        """,
    )
    write(
        root / "terraform" / "modules" / "monitoring" / "main.tf",
        textwrap.dedent(
            """
            resource "aws_sns_topic" "alerts" {}

            resource "aws_cloudwatch_log_metric_filter" "server_panic" {}
            resource "aws_cloudwatch_log_metric_filter" "server_async_runtime_panic" {
              pattern = "\\"msgToPacketRoutine\\" \\"runtime panic encountered\\""
            }
            resource "aws_cloudwatch_log_metric_filter" "server_handler_panic" {
              pattern = "\\"dispatchHandler\\" \\"runtime panic encountered\\""
            }

            resource "aws_cloudwatch_metric_alarm" "server_panic" {
              alarm_actions             = [aws_sns_topic.alerts.arn]
              ok_actions                = [aws_sns_topic.alerts.arn]
              insufficient_data_actions = [aws_sns_topic.alerts.arn]
            }

            resource "aws_cloudwatch_metric_alarm" "server_async_runtime_panic" {
              alarm_actions = [aws_sns_topic.alerts.arn]
              ok_actions    = [aws_sns_topic.alerts.arn]
            }

            resource "aws_cloudwatch_metric_alarm" "server_handler_panic" {
              alarm_actions = [aws_sns_topic.alerts.arn]
              ok_actions    = [aws_sns_topic.alerts.arn]
            }

            resource "aws_cloudwatch_metric_alarm" "server_forward_target_drop" {
              alarm_actions = [aws_sns_topic.alerts.arn]
              ok_actions    = [aws_sns_topic.alerts.arn]
            }

            resource "aws_cloudwatch_metric_alarm" "server_instance_restart" {
              alarm_actions = [aws_sns_topic.alerts.arn]
              ok_actions    = [aws_sns_topic.alerts.arn]
            }

            resource "aws_cloudwatch_metric_alarm" "ac_registration_latency" {
              alarm_actions = [aws_sns_topic.alerts.arn]
              ok_actions    = [aws_sns_topic.alerts.arn]
            }
            """
        ).strip()
        # relay_forward_reject is the block the forward-reject drift tests mutate,
        # so build it from the shared constant; otherwise the fixture and the
        # replacement anchor could drift and silently no-op those tests.
        + "\n\n"
        + RELAY_FORWARD_REJECT_BLOCK
        + "\n\n"
        + QURL_BROWSER_REJECTED_RATIO_BLOCK
        + "\n",
    )
    write(
        root / "endpoints" / "server" / "udpserver.go",
        """
        package server

        func buildServerMetricDimensions() {
          _ = []types.Dimension{
            {Name: aws.String("Environment"), Value: aws.String(environment)},
            {Name: aws.String("Cell"), Value: aws.String(cellID)},
          }
        }

        func recoverHandlerPanic(r any, htype, remote string) {
          err := core.ErrRuntimePanic.WithExtra(fmt.Errorf("%v\\n%s", r, debug.Stack()))
          log.Critical("dispatchHandler [%s] from %s recovered from panic: %v",
            htype, remote, err)
        }
        """,
    )
    write(
        root / "nhp" / "core" / "errors.go",
        """
        package core

        var (
          ErrRuntimePanic = newError(errNhpSdkRuntimePanic, "runtime panic encountered")
        )
        """,
    )
    write(
        root / "endpoints" / "relay" / "relay.go",
        """
        package relay

        func buildRelayMetricDimensions() {
          environment := os.Getenv("NHP_ENVIRONMENT")
          if environment == "" {
            environment = "unknown"
          }
          _ = []types.Dimension{
            {Name: aws.String("Environment"), Value: aws.String(environment)},
          }
        }
        """,
    )
    write(
        root / "terraform" / "modules" / "ac" / "monitoring.tf",
        "\n\n".join(ac_alarm_block(name) for name in AC_CORE_ALARMS),
    )
    write(
        root / "terraform" / "modules" / "relay" / "monitoring.tf",
        "\n\n".join(relay_alarm_block(name) for name in RELAY_CORE_ALARMS),
    )
    write(
        root / "terraform" / "modules" / "qurl-service" / "monitoring.tf",
        f"""
        resource "aws_cloudwatch_log_metric_filter" "qurl_api_resource_key_provisioning_failed" {{
          name           = "${{local.service_name}}-resource-key-provisioning-failed"
          log_group_name = aws_cloudwatch_log_group.qurl.name
          pattern        = "{{ $.msg = \\"resource-key provisioning failed\\" }}"

          metric_transformation {{
            name          = "ResourceKeyProvisioningFailedCount"
            namespace     = "LayerV/QurlService"
            value         = "1"
            default_value = 0
          }}
        }}

        resource "aws_cloudwatch_metric_alarm" "qurl_api_resource_key_provisioning_failures" {{
          comparison_operator = "GreaterThanThreshold"
          evaluation_periods  = 1
          datapoints_to_alarm = 1
          metric_name         = "ResourceKeyProvisioningFailedCount"
          namespace           = "LayerV/QurlService"
          period              = 60
          statistic           = "Sum"
          threshold           = 0
          treat_missing_data  = "notBreaching"

          alarm_actions = {QURL_SERVICE_ALARM_ACTION_EXPR}
          ok_actions    = []
        }}
        """,
    )
    write(
        root / "terraform" / "qurl_service_ci.tf",
        QURL_CI_LOCK_FAILURE_ALARM_BLOCK,
    )
    write(
        root / "docs" / "runbooks" / "qurl-sandbox-live-env-lock-alarm.md",
        f"""
        # qURL sandbox live-environment lock alarm

        Alarm: `layerv-nhp-sandbox-qurl-service-ci-live-env-lock-failure`

        ```sql
        SELECT SUM(SandboxLiveEnvLockFailure)
        FROM SCHEMA("LayerV/QURLServiceCI", Reason, Action)
        ```

        ```sql
        SELECT SUM(SandboxLiveEnvLockFailure)
        FROM SCHEMA("LayerV/QURLServiceCI", Reason, Action)
        GROUP BY Reason, Action
        ORDER BY SUM() DESC
        ```

        Topic: `layerv-nhp-sandbox-cell0-alerts`
        Subscription: `sandbox-alerts-sandbox`
        Lock: `/layerv-nhp-sandbox/qurl-live-env-lock`
        Canary: `Reason=AlarmCanary,Action=acquire`
        An ordinary lock collision emits no failure metric.
        `Reason=Contention` is emitted only after the 7,200-second wait budget is exhausted and the waiting job fails.

        ```bash
        aws cloudwatch put-metric-data \\
          --region us-east-2 \\
          --namespace 'LayerV/QURLServiceCI' \\
          --metric-name 'SandboxLiveEnvLockFailure' \\
          --value 1 \\
          --unit Count

        aws cloudwatch put-metric-data \\
          --region us-east-2 \\
          --namespace 'LayerV/QURLServiceCI' \\
          --metric-name 'SandboxLiveEnvLockFailure' \\
          --dimensions 'Reason=AlarmCanary,Action=acquire' \\
          --value 1 \\
          --unit Count
        ```

        Tracking: #3244, #3246, #3247
        """,
    )
    write(
        root / "docs" / "OBSERVABILITY.md",
        f"""
        # Observability

        `LayerV/QURLServiceCI` publishes `SandboxLiveEnvLockFailure`.
        The diagnostic query is `{QURL_CI_LOCK_FAILURE_DIAGNOSTIC_QUERY}`.
        See [the runbook](runbooks/qurl-sandbox-live-env-lock-alarm.md).
        """,
    )
    write(
        root / "terraform" / "modules" / "relay" / "compute.tf",
        """
        resource "aws_autoscaling_group" "relay" {
          enabled_metrics = [
            "GroupInServiceInstances",
          ]
        }
        """,
    )
    write(
        root / "terraform" / "modules" / "relay" / "user_data.sh.tpl",
        """
        aws cloudwatch put-metric-data \\
          --namespace "LayerV/NHP" \\
          --metric-name "BootstrapFailure" \\
          --dimensions "Component=relay,Environment=${environment}"

        ExecStart=/usr/bin/docker run \\
          -e NHP_ENVIRONMENT=${environment} \\
          image run
        """,
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
        output "log_group_name" {
          value = aws_cloudwatch_log_group.server.name
        }

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
              deploy_relay               = var.deploy_relay
              enable_slack_notifications = var.enable_slack_notifications
              slack_workspace_id         = var.slack_workspace_id
              slack_channel_id           = var.slack_channel_id
              chatbot_owned_externally   = var.chatbot_owned_externally
              qurl_browser_rejected_alarm_actions_enabled = var.qurl_browser_rejected_alarm_actions_enabled
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

            variable "deploy_relay" {
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

            variable "qurl_browser_rejected_alarm_actions_enabled" {
              type    = bool
              default = false
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


def mutate_relay_alarm(root: Path, name: str, old: str, new: str) -> None:
    path = root / "terraform" / "modules" / "relay" / "monitoring.tf"
    source = path.read_text(encoding="utf-8")
    block = CHECKER.find_block(path, 'resource "aws_cloudwatch_metric_alarm"', name)
    if old not in block.body:
        raise AssertionError(f"{name}: fixture lacks mutation source {old!r}")
    mutated = block.body.replace(old, new, 1)
    path.write_text(source.replace(block.body, mutated, 1), encoding="utf-8")


def mutate_qurl_ci_lock_alarm(root: Path, old: str, new: str) -> None:
    path = root / "terraform" / "qurl_service_ci.tf"
    source = path.read_text(encoding="utf-8")
    block = CHECKER.find_block(
        path,
        'resource "aws_cloudwatch_metric_alarm"',
        "qurl_ci_sandbox_live_env_lock_failure",
    )
    if old not in block.body:
        raise AssertionError(f"qURL CI fixture lacks mutation source {old!r}")
    mutated = block.body.replace(old, new, 1)
    path.write_text(source.replace(block.body, mutated, 1), encoding="utf-8")


class ObservabilityParityTests(unittest.TestCase):
    def test_run_id_mismatch_alarm_is_one_minute_zero_tolerance(self) -> None:
        alarm = CHECKER.find_block(
            REPO_ROOT / "terraform" / "modules" / "monitoring" / "main.tf",
            'resource "aws_cloudwatch_metric_alarm"',
            "internal_token_validate_run_id_mismatch",
        )

        CHECKER.require_assignment(alarm, "comparison_operator", '"GreaterThanThreshold"')
        CHECKER.require_assignment(alarm, "evaluation_periods", "1")
        CHECKER.require_assignment(alarm, "datapoints_to_alarm", "1")
        CHECKER.require_assignment(alarm, "period", "60")
        CHECKER.require_assignment(alarm, "statistic", '"Sum"')
        CHECKER.require_assignment(alarm, "threshold", "0")
        CHECKER.require_assignment(alarm, "treat_missing_data", '"notBreaching"')
        self.assertIn('Reason      = "run_id_mismatch"', alarm.body)

    def test_aop_replay_detection_alarm_is_fenced(self) -> None:
        self.assertIn("aop_replay_detected", AC_CORE_ALARMS)

    def test_ebpf_telemetry_sampling_alarms_are_fenced(self) -> None:
        self.assertIn("ebpf_perf_lost_samples", AC_CORE_ALARMS)
        self.assertIn("ebpf_deny_telemetry_suppressed", AC_CORE_ALARMS)

    def test_in_sync_fixture_passes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_fixture(root)

            result = run_check(root)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("observability parity surfaces are wired", result.stdout)

    def test_qurl_ci_lock_alarm_contract_drift_fails(self) -> None:
        mutations = (
            ('count = var.environment == "sandbox" ? 1 : 0', "count = 1", "count"),
            (
                'alarm_name          = "${local.name_prefix}-qurl-service-ci-live-env-lock-failure"',
                'alarm_name          = "${local.name_prefix}-qurl-service-ci-lock-failure"',
                "alarm_name",
            ),
            (
                'Component = "qurl-service"',
                'Component = "qurl-service-ci"',
                "Component",
            ),
            (
                "actions_enabled     = true",
                "actions_enabled     = false",
                "actions_enabled",
            ),
            (
                'comparison_operator = "GreaterThanThreshold"',
                'comparison_operator = "GreaterThanOrEqualToThreshold"',
                "comparison_operator",
            ),
            (
                "evaluation_periods  = 1",
                "evaluation_periods  = 2",
                "evaluation_periods",
            ),
            (
                "datapoints_to_alarm = 1",
                "datapoints_to_alarm = 2",
                "datapoints_to_alarm",
            ),
            ("threshold           = 0", "threshold           = 1", "threshold"),
            (
                'treat_missing_data  = "notBreaching"',
                'treat_missing_data  = "missing"',
                "treat_missing_data",
            ),
            (
                'metric_name         = "SandboxLiveEnvLockFailure"',
                'metric_name         = "SandboxLiveEnvLockFailureByReason"',
                "metric_name",
            ),
            (
                'namespace           = "LayerV/QURLServiceCI"',
                'namespace           = "LayerV/QURLService"',
                "namespace",
            ),
            (
                "https://github.com/layervai/nhp/blob/main/docs/runbooks/qurl-sandbox-live-env-lock-alarm.md",
                "https://github.com/layervai/nhp/blob/trunk/docs/runbooks/qurl-sandbox-live-env-lock-alarm.md",
                "blob/main",
            ),
            (
                "alarm_actions             = [module.monitoring.sns_topic_arn]",
                "alarm_actions             = []",
                "alarm_actions",
            ),
            (
                "ok_actions                = [module.monitoring.sns_topic_arn]",
                "ok_actions                = []",
                "ok_actions",
            ),
            (
                "insufficient_data_actions = []",
                "insufficient_data_actions = [module.monitoring.sns_topic_arn]",
                "insufficient_data_actions",
            ),
            ("period              = 60", "period              = 300", "period"),
            ('statistic           = "Sum"', 'statistic           = "Average"', "statistic"),
            (
                "threshold           = 0",
                'threshold           = 0\n  dimensions          = { Reason = "ReadFailed" }',
                "dimensions",
            ),
            (
                "threshold           = 0",
                'threshold           = 0\n  unit                = "Count"',
                "unit",
            ),
        )
        for old, new, expected in mutations:
            with self.subTest(expected=expected), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                build_fixture(root)
                mutate_qurl_ci_lock_alarm(root, old, new)

                result = run_check(root)

                self.assertNotEqual(result.returncode, 0)
                self.assertIn("qurl_ci_sandbox_live_env_lock_failure", result.stderr)
                self.assertIn(expected, result.stderr)

    def test_qurl_ci_lock_alarm_rejects_metric_query(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_fixture(root)
            mutate_qurl_ci_lock_alarm(
                root,
                "  alarm_actions             = [module.monitoring.sns_topic_arn]",
                '  metric_query {\n    id = "other"\n  }\n\n'
                "  alarm_actions             = [module.monitoring.sns_topic_arn]",
            )

            result = run_check(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not a `metric_query` block", result.stderr)

    def test_qurl_ci_lock_alarm_missing_resource_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_fixture(root)
            (root / "terraform" / "qurl_service_ci.tf").unlink()

            result = run_check(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("qurl_service_ci.tf", result.stderr)

    def test_qurl_ci_lock_alarm_runbook_owner_drift_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_fixture(root)
            runbook = root / "docs" / "runbooks" / "qurl-sandbox-live-env-lock-alarm.md"
            runbook.write_text(
                runbook.read_text(encoding="utf-8").replace(
                    "sandbox-alerts-sandbox",
                    "unowned-subscription",
                ),
                encoding="utf-8",
            )

            result = run_check(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("sandbox-alerts-sandbox", result.stderr)
        self.assertIn("owner/query/runbook contract drift", result.stderr)

    def test_qurl_ci_lock_alarm_runbook_canary_action_drift_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_fixture(root)
            runbook = root / "docs" / "runbooks" / "qurl-sandbox-live-env-lock-alarm.md"
            runbook.write_text(
                runbook.read_text(encoding="utf-8").replace(
                    "Reason=AlarmCanary,Action=acquire",
                    "Reason=AlarmCanary,Action=observe",
                ),
                encoding="utf-8",
            )

            result = run_check(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Reason=AlarmCanary,Action=acquire", result.stderr)
        self.assertIn("owner/query/runbook contract drift", result.stderr)

    def test_qurl_ci_lock_alarm_runbook_contention_semantics_drift_fails(
        self,
    ) -> None:
        mutations = (
            (
                "An ordinary lock collision emits no failure metric.",
                "An ordinary lock collision emits a failure metric.",
            ),
            ("7,200-second wait budget", "initial collision"),
        )
        for required, replacement in mutations:
            with self.subTest(required=required), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                build_fixture(root)
                runbook = (
                    root
                    / "docs"
                    / "runbooks"
                    / "qurl-sandbox-live-env-lock-alarm.md"
                )
                runbook.write_text(
                    runbook.read_text(encoding="utf-8").replace(
                        required,
                        replacement,
                    ),
                    encoding="utf-8",
                )

                result = run_check(root)

            self.assertNotEqual(result.returncode, 0)
            self.assertIn(required, result.stderr)
            self.assertIn("owner/query/runbook contract drift", result.stderr)

    def test_qurl_ci_lock_alarm_runbook_requires_dimensionless_canary_first(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_fixture(root)
            runbook = root / "docs" / "runbooks" / "qurl-sandbox-live-env-lock-alarm.md"
            source = runbook.read_text(encoding="utf-8")
            first_command = textwrap.dedent(
                r"""
                aws cloudwatch put-metric-data \
                  --region us-east-2 \
                  --namespace 'LayerV/QURLServiceCI' \
                  --metric-name 'SandboxLiveEnvLockFailure' \
                  --value 1 \
                  --unit Count

                """
            ).lstrip()
            self.assertIn(first_command, source)
            runbook.write_text(source.replace(first_command, ""), encoding="utf-8")

            result = run_check(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("dimensionless canary followed by", result.stderr)
        self.assertIn("producer/canary contract drift", result.stderr)

    def test_qurl_ci_lock_alarm_runbook_query_drift_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_fixture(root)
            runbook = root / "docs" / "runbooks" / "qurl-sandbox-live-env-lock-alarm.md"
            source = runbook.read_text(encoding="utf-8")
            runbook.write_text(
                source.replace(
                    'FROM SCHEMA("LayerV/QURLServiceCI", Reason, Action)\n```',
                    'FROM SCHEMA("LayerV/QURLServiceCI", Reason, Action)\n'
                    'GROUP BY Reason, Action\n```',
                ),
                encoding="utf-8",
            )

            result = run_check(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(QURL_CI_LOCK_FAILURE_DIAGNOSTIC_QUERY, result.stderr)
        self.assertIn("owner/query/runbook contract drift", result.stderr)

    def test_qurl_ci_lock_alarm_runbook_breakdown_selector_drift_fails(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_fixture(root)
            runbook = root / "docs" / "runbooks" / "qurl-sandbox-live-env-lock-alarm.md"
            source = runbook.read_text(encoding="utf-8")
            runbook.write_text(
                source.replace(
                    'FROM SCHEMA("LayerV/QURLServiceCI", Reason, Action)\n'
                    "GROUP BY Reason, Action",
                    'FROM "LayerV/QURLServiceCI"\nGROUP BY Reason, Action',
                ),
                encoding="utf-8",
            )

            result = run_check(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(QURL_CI_LOCK_FAILURE_BREAKDOWN_QUERY, result.stderr)
        self.assertIn("diagnostic breakdown contract drift", result.stderr)

    def test_qurl_ci_lock_alarm_observability_query_drift_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_fixture(root)
            docs = root / "docs" / "OBSERVABILITY.md"
            docs.write_text(
                docs.read_text(encoding="utf-8").replace(
                    QURL_CI_LOCK_FAILURE_DIAGNOSTIC_QUERY,
                    "SELECT SUM(SandboxLiveEnvLockFailure)",
                ),
                encoding="utf-8",
            )

            result = run_check(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(QURL_CI_LOCK_FAILURE_DIAGNOSTIC_QUERY, result.stderr)
        self.assertIn("observability documentation drift", result.stderr)

    def test_relay_unknown_environment_alarm_is_fenced(self) -> None:
        self.assertIn("relay_shedding_unknown_environment", RELAY_CORE_ALARMS)

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

    def test_inline_comment_tokens_inside_string_literal_pass(self) -> None:
        self.assertEqual(
            CHECKER._normalise_expr('"https://example.com/a#b" # fixture note'),
            '"https://example.com/a#b"',
        )

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_fixture(root)
            relay_monitoring = (
                root / "terraform" / "modules" / "relay" / "monitoring.tf"
            )
            relay_monitoring.write_text(
                relay_monitoring.read_text(encoding="utf-8").replace(
                    'Environment = "unknown"',
                    'Environment = "unknown" // https://example.com/a#b',
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
                  deploy_relay               = var.deploy_relay
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
                variable "deploy_relay" {}
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

    def test_exempt_env_root_without_module_nhp_passes(self) -> None:
        # sandbox-cell1 is a separately deployed cell that does NOT instantiate
        # `module "nhp"` — its always-on module.security would
        # collide with cell0's account-singleton GuardDuty/Config/SecurityHub.
        # It rides cell0 for observability, so it is on the parity guard's
        # explicit exemption set. A root by that name with no `module "nhp"`
        # (and none of the passthrough/tfvars wiring the guard otherwise
        # demands) must pass, whereas any other name fails closed — see
        # test_new_env_root_is_checked.
        self.assertIn(
            "sandbox-cell1", CHECKER.OBSERVABILITY_PARITY_ENV_ROOT_EXEMPTIONS
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_fixture(root)
            write(
                root / "terraform" / "environments" / "sandbox-cell1" / "main.tf",
                """
                module "networking" {
                  source = "../../modules/networking"
                }

                module "compute" {
                  source = "../../modules/compute"
                }
                """,
            )

            result = run_check(root)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("observability parity surfaces are wired", result.stdout)

    def test_exempt_hub_dns_root_without_module_nhp_passes(self) -> None:
        # sandbox-hub-dns is a DNS-only root emitting one public A-alias
        # (hub.nhp.layerv.xyz -> the Connector Hub NLB, Step 5 slice 5c). It
        # instantiates no compute/AC/relay/security and no `module "nhp"`; the
        # Hub worker and its alarms live in the Control tree, not here, so there
        # is no server observability surface to enforce parity on. It must pass
        # the guard by name while any other unexempted root fails closed.
        self.assertIn(
            "sandbox-hub-dns", CHECKER.OBSERVABILITY_PARITY_ENV_ROOT_EXEMPTIONS
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_fixture(root)
            write(
                root / "terraform" / "environments" / "sandbox-hub-dns" / "main.tf",
                """
                data "aws_lb" "hub" {
                  name = "layerv-nhp-sandbox-control-hub"
                }

                module "dns" {
                  source = "../../modules/dns"
                }
                """,
            )

            result = run_check(root)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("observability parity surfaces are wired", result.stdout)

    def test_exempt_source_locked_prod_hub_dns_root_without_module_nhp_passes(
        self,
    ) -> None:
        # prod-hub-dns owns only the explicit production Hub alias. Control owns
        # the worker/NLB and their alarms, and this root's source lock prevents
        # even the NLB lookup until a later reviewed activation.
        self.assertIn(
            "prod-hub-dns", CHECKER.OBSERVABILITY_PARITY_ENV_ROOT_EXEMPTIONS
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_fixture(root)
            write(
                root / "terraform" / "environments" / "prod-hub-dns" / "main.tf",
                """
                data "aws_lb" "hub" {
                  count = var.hub_dns_enabled ? 1 : 0
                  name  = "layerv-nhp-prod-hub-edge"
                }

                resource "aws_route53_record" "hub" {
                  count = var.hub_dns_enabled ? 1 : 0
                  name  = "hub.nhp.layerv.ai"
                }
                """,
            )

            result = run_check(root)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("observability parity surfaces are wired", result.stdout)

    def test_exempt_runtime_attestation_root_without_module_nhp_passes(self) -> None:
        # sandbox-runtime-attestation composes modules/runtime-attestation-store
        # (the immutable per-node runtime evidence channel) and instantiates no
        # `module "nhp"`; the fleets it attests + their alarms live in roots this
        # lint checks. It must pass the guard by name while any other unexempted
        # root fails closed.
        self.assertIn(
            "sandbox-runtime-attestation",
            CHECKER.OBSERVABILITY_PARITY_ENV_ROOT_EXEMPTIONS,
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_fixture(root)
            write(
                root
                / "terraform"
                / "environments"
                / "sandbox-runtime-attestation"
                / "main.tf",
                """
                module "runtime_attestation_store" {
                  source = "../../modules/runtime-attestation-store"
                }
                """,
            )

            result = run_check(root)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("observability parity surfaces are wired", result.stdout)

    def test_env_root_exemptions_stay_narrow(self) -> None:
        # The #1141 guard must keep checking every real deployable root; only
        # the explicitly-justified lean cells opt out. Guard against the
        # exemption set silently widening to cover sandbox/prod.
        exemptions = CHECKER.OBSERVABILITY_PARITY_ENV_ROOT_EXEMPTIONS
        self.assertNotIn("sandbox", exemptions)
        self.assertNotIn("prod", exemptions)

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

    def test_missing_monitoring_deploy_relay_wiring_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_fixture(root)
            main_tf = root / "terraform" / "main.tf"
            main_tf.write_text(
                main_tf.read_text(encoding="utf-8").replace(
                    "  deploy_relay                 = var.deploy_relay\n",
                    "",
                ),
                encoding="utf-8",
            )

            result = run_check(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("deploy_relay", result.stderr)

    def test_missing_env_deploy_relay_passthrough_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_fixture(root)
            prod_main = root / "terraform" / "environments" / "prod" / "main.tf"
            prod_main.write_text(
                prod_main.read_text(encoding="utf-8").replace(
                    "  deploy_relay               = var.deploy_relay\n",
                    "",
                ),
                encoding="utf-8",
            )

            result = run_check(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("prod/main.tf", result.stderr)
        self.assertIn("deploy_relay", result.stderr)

    def test_missing_root_structured_log_wiring_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_fixture(root)
            main_tf = root / "terraform" / "main.tf"
            main_tf.write_text(
                main_tf.read_text(encoding="utf-8").replace(
                    "  server_log_group_name        = module.compute.log_group_name\n",
                    "",
                ),
                encoding="utf-8",
            )

            result = run_check(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("server_log_group_name", result.stderr)

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

    def test_qurl_service_alarm_root_wiring_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_fixture(root)
            main_tf = root / "terraform" / "main.tf"
            main_tf.write_text(
                main_tf.read_text(encoding="utf-8").replace(
                    "  qurl_service_alarm_sns_topic_arn = module.monitoring.sns_topic_arn\n",
                    "",
                ),
                encoding="utf-8",
            )

            result = run_check(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("qurl_service", result.stderr)
        self.assertIn("qurl_service_alarm_sns_topic_arn", result.stderr)

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

    def test_missing_async_runtime_panic_filter_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_fixture(root)
            monitoring_main = root / "terraform" / "modules" / "monitoring" / "main.tf"
            monitoring_main.write_text(
                monitoring_main.read_text(encoding="utf-8").replace(
                    textwrap.dedent(
                        """
                    resource "aws_cloudwatch_log_metric_filter" "server_async_runtime_panic" {
                      pattern = "\\"msgToPacketRoutine\\" \\"runtime panic encountered\\""
                    }
                    """
                    ).lstrip(),
                    "",
                ),
                encoding="utf-8",
            )

            result = run_check(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("server_async_runtime_panic", result.stderr)

    def test_async_runtime_panic_filter_pattern_drift_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_fixture(root)
            monitoring_main = root / "terraform" / "modules" / "monitoring" / "main.tf"
            monitoring_main.write_text(
                monitoring_main.read_text(encoding="utf-8").replace(
                    '\\"msgToPacketRoutine\\"',
                    '\\"msgPacketRoutine\\"',
                ),
                encoding="utf-8",
            )

            result = run_check(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("server_async_runtime_panic", result.stderr)
        self.assertIn("pattern", result.stderr)

    def test_async_runtime_panic_go_message_drift_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_fixture(root)
            errors_go = root / "nhp" / "core" / "errors.go"
            errors_go.write_text(
                errors_go.read_text(encoding="utf-8").replace(
                    "runtime panic encountered",
                    "runtime panic renamed",
                ),
                encoding="utf-8",
            )

            result = run_check(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("ErrRuntimePanic", result.stderr)
        self.assertIn("runtime panic encountered", result.stderr)

    # dispatchHandler recover site (PR #3643). Recovering removed this class
    # from the stderr "panic:" detector, so the structured log line is the only
    # alarm signal left — each half of that coupling gets a drift test.
    def test_missing_handler_panic_filter_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_fixture(root)
            monitoring_main = root / "terraform" / "modules" / "monitoring" / "main.tf"
            monitoring_main.write_text(
                monitoring_main.read_text(encoding="utf-8").replace(
                    textwrap.dedent(
                        """
                    resource "aws_cloudwatch_log_metric_filter" "server_handler_panic" {
                      pattern = "\\"dispatchHandler\\" \\"runtime panic encountered\\""
                    }
                    """
                    ).lstrip(),
                    "",
                ),
                encoding="utf-8",
            )

            result = run_check(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("server_handler_panic", result.stderr)

    def test_handler_panic_filter_pattern_drift_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_fixture(root)
            monitoring_main = root / "terraform" / "modules" / "monitoring" / "main.tf"
            monitoring_main.write_text(
                monitoring_main.read_text(encoding="utf-8").replace(
                    '\\"dispatchHandler\\"',
                    '\\"dispatchHandlers\\"',
                ),
                encoding="utf-8",
            )

            result = run_check(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("server_handler_panic", result.stderr)
        self.assertIn("pattern", result.stderr)

    def test_handler_panic_alarm_routing_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_fixture(root)
            monitoring_main = root / "terraform" / "modules" / "monitoring" / "main.tf"
            monitoring_main.write_text(
                monitoring_main.read_text(encoding="utf-8").replace(
                    textwrap.dedent(
                        """
                    resource "aws_cloudwatch_metric_alarm" "server_handler_panic" {
                      alarm_actions = [aws_sns_topic.alerts.arn]
                    """
                    ).lstrip(),
                    textwrap.dedent(
                        """
                    resource "aws_cloudwatch_metric_alarm" "server_handler_panic" {
                      alarm_actions = []
                    """
                    ).lstrip(),
                ),
                encoding="utf-8",
            )

            result = run_check(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("server_handler_panic", result.stderr)
        self.assertIn("alarm_actions", result.stderr)

    def test_handler_panic_go_log_call_site_drift_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_fixture(root)
            udpserver_go = root / "endpoints" / "server" / "udpserver.go"
            udpserver_go.write_text(
                udpserver_go.read_text(encoding="utf-8").replace(
                    'log.Critical("dispatchHandler [%s]',
                    'log.Critical("handler [%s]',
                ),
                encoding="utf-8",
            )

            result = run_check(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("dispatchHandler", result.stderr)

    def test_handler_panic_go_error_wrapper_drift_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_fixture(root)
            udpserver_go = root / "endpoints" / "server" / "udpserver.go"
            udpserver_go.write_text(
                udpserver_go.read_text(encoding="utf-8").replace(
                    "core.ErrRuntimePanic.WithExtra(",
                    "fmt.Errorf(",
                ),
                encoding="utf-8",
            )

            result = run_check(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("core.ErrRuntimePanic.WithExtra(", result.stderr)

    def test_forward_target_drop_alarm_routing_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_fixture(root)
            monitoring_main = root / "terraform" / "modules" / "monitoring" / "main.tf"
            monitoring_main.write_text(
                monitoring_main.read_text(encoding="utf-8").replace(
                    textwrap.dedent(
                        """
                    resource "aws_cloudwatch_metric_alarm" "server_forward_target_drop" {
                      alarm_actions = [aws_sns_topic.alerts.arn]
                      ok_actions    = [aws_sns_topic.alerts.arn]
                    }
                    """
                    ).lstrip(),
                    textwrap.dedent(
                        """
                    resource "aws_cloudwatch_metric_alarm" "server_forward_target_drop" {
                      ok_actions    = [aws_sns_topic.alerts.arn]
                    }
                    """
                    ).lstrip(),
                ),
                encoding="utf-8",
            )

            result = run_check(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("server_forward_target_drop", result.stderr)
        self.assertIn("alarm_actions", result.stderr)

    def test_qurl_browser_rejected_ratio_dimension_drift_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_fixture(root)
            monitoring_main = root / "terraform" / "modules" / "monitoring" / "main.tf"
            monitoring_text = monitoring_main.read_text(encoding="utf-8")
            qurl_alarm_start = monitoring_text.index(
                'resource "aws_cloudwatch_metric_alarm" "qurl_browser_rejected_ratio"'
            )
            monitoring_main.write_text(
                monitoring_text[:qurl_alarm_start]
                + monitoring_text[qurl_alarm_start:].replace(
                    "        Cell        = var.cell_id\n",
                    "        Region      = var.aws_region\n",
                    1,
                ),
                encoding="utf-8",
            )

            result = run_check(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("qurl_browser_rejected_ratio", result.stderr)
        self.assertIn("dimensions", result.stderr)

    def test_qurl_browser_rejected_ratio_actions_enabled_wiring_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_fixture(root)
            monitoring_main = root / "terraform" / "modules" / "monitoring" / "main.tf"
            monitoring_main.write_text(
                monitoring_main.read_text(encoding="utf-8").replace(
                    "  actions_enabled     = var.qurl_browser_rejected_alarm_actions_enabled\n",
                    "  actions_enabled     = true\n",
                    1,
                ),
                encoding="utf-8",
            )

            result = run_check(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("qurl_browser_rejected_ratio", result.stderr)
        self.assertIn("actions_enabled", result.stderr)

    def test_qurl_browser_rejected_ratio_math_drift_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_fixture(root)
            monitoring_main = root / "terraform" / "modules" / "monitoring" / "main.tf"
            monitoring_main.write_text(
                monitoring_main.read_text(encoding="utf-8").replace(
                    "IF(resolve_attempts >= ${local.qurl_browser_rejected_min_resolve_attempts}, FILL(rejected, 0) / resolve_attempts, 0)",
                    "FILL(rejected, 0)",
                    1,
                ),
                encoding="utf-8",
            )

            result = run_check(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("qurl_browser_rejected_ratio", result.stderr)
        self.assertIn("normalized by resolve attempts", result.stderr)

    def test_qurl_browser_rejected_ratio_missing_floor_fails(self) -> None:
        # Dropping the low-volume floor back to `> 0` (the pre-#2924 guard) must
        # trip the lint: the gating *structure* (`>=` the floor local) is the hard
        # contract. The floor *value* stays tunable during the bake — the pinned
        # needle references the local, not the literal 20 — so retuning 20 does
        # not trip this.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_fixture(root)
            monitoring_main = root / "terraform" / "modules" / "monitoring" / "main.tf"
            monitoring_main.write_text(
                monitoring_main.read_text(encoding="utf-8").replace(
                    ">= ${local.qurl_browser_rejected_min_resolve_attempts}",
                    "> 0",
                    1,
                ),
                encoding="utf-8",
            )

            result = run_check(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("qurl_browser_rejected_ratio", result.stderr)
        self.assertIn("low-volume floor", result.stderr)

    def test_qurl_browser_rejected_ratio_numerator_wiring_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_fixture(root)
            monitoring_main = root / "terraform" / "modules" / "monitoring" / "main.tf"
            monitoring_main.write_text(
                monitoring_main.read_text(encoding="utf-8").replace(
                    "      metric_name = each.value.metric_name\n",
                    '      metric_name = "QurlResolveBrowserRejectedMalformed"\n',
                    1,
                ),
                encoding="utf-8",
            )

            result = run_check(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("qurl_browser_rejected_ratio", result.stderr)
        self.assertIn("selected alarm metric", result.stderr)

    def test_qurl_browser_rejected_ratio_denominator_wiring_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_fixture(root)
            monitoring_main = root / "terraform" / "modules" / "monitoring" / "main.tf"
            monitoring_text = monitoring_main.read_text(encoding="utf-8")
            mutated = monitoring_text.replace(
                'fail_unknown         = "QurlResolveFailUnknown"',
                'fail_unknown         = "QurlResolveFailOther"',
                1,
            )
            self.assertNotEqual(mutated, monitoring_text)
            monitoring_main.write_text(mutated, encoding="utf-8")

            result = run_check(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("qurl_browser_rejected_ratio", result.stderr)
        self.assertIn("denominator/numerator set", result.stderr)

    def test_qurl_resource_key_failure_filter_pattern_drift_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_fixture(root)
            qurl_monitoring = (
                root / "terraform" / "modules" / "qurl-service" / "monitoring.tf"
            )
            qurl_monitoring.write_text(
                qurl_monitoring.read_text(encoding="utf-8").replace(
                    "resource-key provisioning failed",
                    "create qurl failed",
                    1,
                ),
                encoding="utf-8",
            )

            result = run_check(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("qurl_api_resource_key_provisioning_failed", result.stderr)
        self.assertIn("pattern", result.stderr)

    def test_qurl_resource_key_failure_alarm_routing_drift_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_fixture(root)
            qurl_monitoring = (
                root / "terraform" / "modules" / "qurl-service" / "monitoring.tf"
            )
            qurl_monitoring.write_text(
                qurl_monitoring.read_text(encoding="utf-8").replace(
                    f"  alarm_actions = {QURL_SERVICE_ALARM_ACTION_EXPR}\n",
                    "  alarm_actions = []\n",
                    1,
                ),
                encoding="utf-8",
            )

            result = run_check(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("qurl_api_resource_key_provisioning_failures", result.stderr)
        self.assertIn("alarm_actions", result.stderr)

    def test_qurl_resource_key_failure_alarm_ok_actions_drift_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_fixture(root)
            qurl_monitoring = (
                root / "terraform" / "modules" / "qurl-service" / "monitoring.tf"
            )
            qurl_monitoring.write_text(
                qurl_monitoring.read_text(encoding="utf-8").replace(
                    "  ok_actions    = []\n",
                    f"  ok_actions    = {QURL_SERVICE_ALARM_ACTION_EXPR}\n",
                    1,
                ),
                encoding="utf-8",
            )

            result = run_check(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("qurl_api_resource_key_provisioning_failures", result.stderr)
        self.assertIn("ok_actions", result.stderr)

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

    def test_compute_structured_log_output_wiring_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_fixture(root)
            compute_outputs = root / "terraform" / "modules" / "compute" / "outputs.tf"
            compute_outputs.write_text(
                compute_outputs.read_text(encoding="utf-8").replace(
                    "  value = aws_cloudwatch_log_group.server.name\n",
                    "  value = aws_cloudwatch_log_group.server_stderr.name\n",
                ),
                encoding="utf-8",
            )

            result = run_check(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("log_group_name", result.stderr)
        self.assertIn("aws_cloudwatch_log_group.server.name", result.stderr)

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

    def test_missing_relay_alarm_resource_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_fixture(root)
            relay_monitoring = (
                root / "terraform" / "modules" / "relay" / "monitoring.tf"
            )
            relay_monitoring.write_text(
                relay_monitoring.read_text(encoding="utf-8").replace(
                    'resource "aws_cloudwatch_metric_alarm" "relay_shedding_unknown_environment"',
                    'resource "aws_cloudwatch_metric_alarm" "relay_shedding_unknown_environment_missing"',
                ),
                encoding="utf-8",
            )

            result = run_check(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("missing relay CloudWatch alarm", result.stderr)
        self.assertIn("relay_shedding_unknown_environment", result.stderr)

    def test_untracked_relay_alarm_resource_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_fixture(root)
            relay_monitoring = (
                root / "terraform" / "modules" / "relay" / "monitoring.tf"
            )
            relay_monitoring.write_text(
                relay_monitoring.read_text(encoding="utf-8")
                + textwrap.dedent(
                    """

                    resource "aws_cloudwatch_metric_alarm" "new_unfenced_relay_alarm" {
                      alarm_actions = local.relay_alarm_actions
                      ok_actions    = local.relay_alarm_actions

                      dimensions = {
                        Environment = var.environment
                      }
                    }
                    """
                ),
                encoding="utf-8",
            )

            result = run_check(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("relay CloudWatch alarm(s) must be added", result.stderr)
        self.assertIn("new_unfenced_relay_alarm", result.stderr)

    def test_relay_bootstrap_dimension_drift_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_fixture(root)
            relay_monitoring = (
                root / "terraform" / "modules" / "relay" / "monitoring.tf"
            )
            relay_monitoring.write_text(
                relay_monitoring.read_text(encoding="utf-8").replace(
                    'Component   = "relay"\n',
                    'Component   = "nhp-relay"\n',
                ),
                encoding="utf-8",
            )

            result = run_check(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("relay_bootstrap_failure", result.stderr)
        self.assertIn("Component", result.stderr)

    def test_relay_alarm_action_routing_drift_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_fixture(root)
            relay_monitoring = (
                root / "terraform" / "modules" / "relay" / "monitoring.tf"
            )
            relay_monitoring.write_text(
                relay_monitoring.read_text(encoding="utf-8").replace(
                    "  alarm_actions = local.relay_alarm_actions\n",
                    "  alarm_actions = []\n",
                    1,
                ),
                encoding="utf-8",
            )

            result = run_check(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("relay_tg_unhealthy_hosts", result.stderr)
        self.assertIn("alarm_actions", result.stderr)

    def test_relay_single_event_alarm_ok_action_drift_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_fixture(root)
            relay_monitoring = (
                root / "terraform" / "modules" / "relay" / "monitoring.tf"
            )
            relay_monitoring.write_text(
                relay_monitoring.read_text(encoding="utf-8").replace(
                    "  ok_actions    = []\n",
                    "  ok_actions    = local.relay_alarm_actions\n",
                    1,
                ),
                encoding="utf-8",
            )

            result = run_check(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("relay_bootstrap_failure", result.stderr)
        self.assertIn("ok_actions", result.stderr)

    def test_server_relay_forward_reject_action_routing_drift_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_fixture(root)
            monitoring_main = root / "terraform" / "modules" / "monitoring" / "main.tf"
            good_block = RELAY_FORWARD_REJECT_BLOCK
            monitoring_main.write_text(
                monitoring_main.read_text(encoding="utf-8").replace(
                    good_block,
                    good_block.replace(
                        "  ok_actions    = [aws_sns_topic.alerts.arn]",
                        "  ok_actions    = []",
                    ),
                ),
                encoding="utf-8",
            )

            result = run_check(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("relay_forward_reject", result.stderr)
        self.assertIn("ok_actions", result.stderr)

    def test_server_relay_forward_reject_alarm_action_drift_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_fixture(root)
            monitoring_main = root / "terraform" / "modules" / "monitoring" / "main.tf"
            good_block = RELAY_FORWARD_REJECT_BLOCK
            monitoring_main.write_text(
                monitoring_main.read_text(encoding="utf-8").replace(
                    good_block,
                    good_block.replace(
                        "  alarm_actions = [aws_sns_topic.alerts.arn]",
                        "  alarm_actions = []",
                    ),
                ),
                encoding="utf-8",
            )

            result = run_check(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("relay_forward_reject", result.stderr)
        self.assertIn("alarm_actions", result.stderr)

    def test_server_relay_forward_reject_metric_name_drift_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_fixture(root)
            monitoring_main = root / "terraform" / "modules" / "monitoring" / "main.tf"
            good_block = RELAY_FORWARD_REJECT_BLOCK
            monitoring_main.write_text(
                monitoring_main.read_text(encoding="utf-8").replace(
                    good_block,
                    good_block.replace(
                        '  metric_name   = "RelayForwardReject"',
                        '  metric_name   = "RelayForwardRejected"',
                    ),
                ),
                encoding="utf-8",
            )

            result = run_check(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("relay_forward_reject", result.stderr)
        self.assertIn("metric_name", result.stderr)

    def test_server_relay_forward_reject_namespace_drift_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_fixture(root)
            monitoring_main = root / "terraform" / "modules" / "monitoring" / "main.tf"
            good_block = RELAY_FORWARD_REJECT_BLOCK
            monitoring_main.write_text(
                monitoring_main.read_text(encoding="utf-8").replace(
                    good_block,
                    good_block.replace(
                        '  namespace     = "LayerV/NHP"',
                        '  namespace     = "LayerV/NHPRelay"',
                    ),
                ),
                encoding="utf-8",
            )

            result = run_check(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("relay_forward_reject", result.stderr)
        self.assertIn("namespace", result.stderr)

    def test_server_relay_forward_reject_statistic_drift_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_fixture(root)
            monitoring_main = root / "terraform" / "modules" / "monitoring" / "main.tf"
            good_block = RELAY_FORWARD_REJECT_BLOCK
            monitoring_main.write_text(
                monitoring_main.read_text(encoding="utf-8").replace(
                    good_block,
                    good_block.replace(
                        '  statistic     = "Sum"',
                        '  statistic     = "Average"',
                    ),
                ),
                encoding="utf-8",
            )

            result = run_check(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("relay_forward_reject", result.stderr)
        self.assertIn("statistic", result.stderr)

    def test_server_relay_forward_reject_count_drift_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_fixture(root)
            monitoring_main = root / "terraform" / "modules" / "monitoring" / "main.tf"
            monitoring_main.write_text(
                monitoring_main.read_text(encoding="utf-8").replace(
                    "  count = var.deploy_relay ? 1 : 0\n",
                    "  count = 1\n",
                ),
                encoding="utf-8",
            )

            result = run_check(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("relay_forward_reject", result.stderr)
        self.assertIn("count", result.stderr)

    def test_server_metric_environment_dimension_name_drift_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_fixture(root)
            server_udp = root / "endpoints" / "server" / "udpserver.go"
            server_udp.write_text(
                server_udp.read_text(encoding="utf-8").replace(
                    'Name: aws.String("Environment")',
                    'Name: aws.String("Env")',
                    1,
                )
                + '\nvar unrelatedEnvironmentDimension = aws.String("Environment")\n',
                encoding="utf-8",
            )

            result = run_check(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("relay_forward_reject", result.stderr)
        self.assertIn("Environment", result.stderr)

    def test_server_metric_cell_dimension_name_drift_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_fixture(root)
            server_udp = root / "endpoints" / "server" / "udpserver.go"
            server_udp.write_text(
                server_udp.read_text(encoding="utf-8").replace(
                    'Name: aws.String("Cell")',
                    'Name: aws.String("CellId")',
                    1,
                ),
                encoding="utf-8",
            )

            result = run_check(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("relay_forward_reject", result.stderr)
        self.assertIn("Cell", result.stderr)

    def test_go_function_scanner_ignores_raw_strings_and_rune_braces(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_fixture(root)
            for go_path in (
                root / "endpoints" / "server" / "udpserver.go",
                root / "endpoints" / "relay" / "relay.go",
            ):
                go_path.write_text(
                    go_path.read_text(encoding="utf-8").replace(
                        "  _ = []types.Dimension{",
                        "  _ = `raw } brace`\n  _ = '}'\n  _ = []types.Dimension{",
                        1,
                    ),
                    encoding="utf-8",
                )

            result = run_check(root)

        self.assertEqual(result.returncode, 0, result.stderr)

    def test_relay_user_data_bootstrap_dimension_drift_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_fixture(root)
            relay_user_data = (
                root / "terraform" / "modules" / "relay" / "user_data.sh.tpl"
            )
            relay_user_data.write_text(
                relay_user_data.read_text(encoding="utf-8").replace(
                    '--dimensions "Component=relay,Environment=${environment}"',
                    '--dimensions "Component=relay"',
                ),
                encoding="utf-8",
            )

            result = run_check(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("BootstrapFailure alarm dimensions", result.stderr)
        self.assertIn("--dimensions has", result.stderr)

    def test_relay_user_data_bootstrap_dimension_malformed_token_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_fixture(root)
            relay_user_data = (
                root / "terraform" / "modules" / "relay" / "user_data.sh.tpl"
            )
            relay_user_data.write_text(
                relay_user_data.read_text(encoding="utf-8").replace(
                    "Component=relay,Environment=${environment}",
                    "Component=relay,Environment:${environment}",
                ),
                encoding="utf-8",
            )

            result = run_check(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("malformed --dimensions token", result.stderr)

    def test_relay_user_data_bootstrap_dimension_reorder_passes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_fixture(root)
            relay_user_data = (
                root / "terraform" / "modules" / "relay" / "user_data.sh.tpl"
            )
            relay_user_data.write_text(
                relay_user_data.read_text(encoding="utf-8").replace(
                    "Component=relay,Environment=${environment}",
                    "Environment=${environment},Component=relay",
                ),
                encoding="utf-8",
            )

            result = run_check(root)

        self.assertEqual(result.returncode, 0, result.stderr)

    def test_relay_user_data_bootstrap_dimension_substring_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_fixture(root)
            relay_user_data = (
                root / "terraform" / "modules" / "relay" / "user_data.sh.tpl"
            )
            relay_user_data.write_text(
                relay_user_data.read_text(encoding="utf-8").replace(
                    "Component=relay,Environment=${environment}",
                    "Component=relay-x,Environment=${environment}",
                ),
                encoding="utf-8",
            )

            result = run_check(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("BootstrapFailure alarm dimensions", result.stderr)

    def test_relay_user_data_bootstrap_dimension_comment_only_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_fixture(root)
            relay_user_data = (
                root / "terraform" / "modules" / "relay" / "user_data.sh.tpl"
            )
            relay_user_data.write_text(
                relay_user_data.read_text(encoding="utf-8").replace(
                    '  --dimensions "Component=relay,Environment=${environment}"',
                    '  --dimensions "Component=relay"\n'
                    '# --dimensions "Component=relay,Environment=${environment}"',
                ),
                encoding="utf-8",
            )

            result = run_check(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("BootstrapFailure alarm dimensions", result.stderr)

    def test_relay_user_data_bootstrap_dimension_shell_single_quote_hash_passes(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_fixture(root)
            relay_user_data = (
                root / "terraform" / "modules" / "relay" / "user_data.sh.tpl"
            )
            relay_user_data.write_text(
                relay_user_data.read_text(encoding="utf-8").replace(
                    '  --dimensions "Component=relay,Environment=${environment}"',
                    "  echo 'literal # not a shell comment' && "
                    "aws cloudwatch put-metric-data --dimensions "
                    '"Component=relay,Environment=${environment}"',
                ),
                encoding="utf-8",
            )

            result = run_check(root)

        self.assertEqual(result.returncode, 0, result.stderr)

    def test_relay_alb_dimension_drift_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_fixture(root)
            relay_monitoring = (
                root / "terraform" / "modules" / "relay" / "monitoring.tf"
            )
            relay_monitoring.write_text(
                relay_monitoring.read_text(encoding="utf-8").replace(
                    "    TargetGroup  = aws_lb_target_group.relay.arn_suffix\n",
                    "",
                    1,
                ),
                encoding="utf-8",
            )

            result = run_check(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("relay_tg_unhealthy_hosts", result.stderr)
        self.assertIn("TargetGroup", result.stderr)

    def test_relay_zero_healthy_missing_data_semantic_drift_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_fixture(root)
            relay_monitoring = (
                root / "terraform" / "modules" / "relay" / "monitoring.tf"
            )
            relay_monitoring.write_text(
                relay_monitoring.read_text(encoding="utf-8").replace(
                    'treat_missing_data = "breaching"',
                    'treat_missing_data = "notBreaching"',
                ),
                encoding="utf-8",
            )

            result = run_check(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("relay_tg_zero_healthy_targets", result.stderr)
        self.assertIn("treat_missing_data", result.stderr)

    def test_relay_asg_enabled_metric_drift_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_fixture(root)
            relay_compute = root / "terraform" / "modules" / "relay" / "compute.tf"
            relay_compute.write_text(
                relay_compute.read_text(encoding="utf-8").replace(
                    '"GroupInServiceInstances"',
                    '"GroupDesiredCapacity"',
                ),
                encoding="utf-8",
            )

            result = run_check(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("GroupInServiceInstances", result.stderr)

    def test_relay_asg_enabled_metric_stray_occurrence_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_fixture(root)
            relay_compute = root / "terraform" / "modules" / "relay" / "compute.tf"
            relay_compute.write_text(
                relay_compute.read_text(encoding="utf-8").replace(
                    '"GroupInServiceInstances"',
                    '"GroupDesiredCapacity"',
                )
                + textwrap.dedent(
                    """

                    resource "null_resource" "fixture_metric_string" {
                      triggers = {
                        metric = "GroupInServiceInstances"
                      }
                    }
                    """
                ),
                encoding="utf-8",
            )

            result = run_check(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("aws_autoscaling_group", result.stderr)
        self.assertIn("GroupInServiceInstances", result.stderr)

    def test_relay_capacity_metric_name_drift_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_fixture(root)
            relay_monitoring = (
                root / "terraform" / "modules" / "relay" / "monitoring.tf"
            )
            relay_monitoring.write_text(
                relay_monitoring.read_text(encoding="utf-8").replace(
                    'metric_name = "GroupInServiceInstances"',
                    'metric_name = "GroupDesiredCapacity"',
                ),
                encoding="utf-8",
            )

            result = run_check(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("relay_capacity_below_baseline", result.stderr)
        self.assertIn("metric_name", result.stderr)

    def test_relay_shed_unknown_dimension_drift_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_fixture(root)
            relay_monitoring = (
                root / "terraform" / "modules" / "relay" / "monitoring.tf"
            )
            relay_monitoring.write_text(
                relay_monitoring.read_text(encoding="utf-8").replace(
                    'Environment = "unknown"',
                    "Environment = var.environment",
                ),
                encoding="utf-8",
            )

            result = run_check(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("relay_shedding_unknown_environment", result.stderr)
        self.assertIn("unknown", result.stderr)

    def test_relay_shed_dimension_drift_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_fixture(root)
            relay_monitoring = (
                root / "terraform" / "modules" / "relay" / "monitoring.tf"
            )
            good_block = relay_alarm_block("relay_shedding")
            relay_monitoring.write_text(
                relay_monitoring.read_text(encoding="utf-8").replace(
                    good_block,
                    good_block.replace(
                        "    Environment = var.environment",
                        '    Environment = "unknown"',
                    ),
                ),
                encoding="utf-8",
            )

            result = run_check(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("relay_shedding", result.stderr)
        self.assertIn("Environment", result.stderr)

    def test_relay_shed_static_semantic_drift_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_fixture(root)
            mutate_relay_alarm(
                root,
                "relay_shedding",
                'comparison_operator = "GreaterThanThreshold"',
                'comparison_operator = "GreaterThanOrEqualToThreshold"',
            )

            result = run_check(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("relay_shedding", result.stderr)
        self.assertIn("comparison_operator", result.stderr)

    def test_relay_shed_metric_name_drift_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_fixture(root)
            relay_monitoring = (
                root / "terraform" / "modules" / "relay" / "monitoring.tf"
            )
            relay_monitoring.write_text(
                relay_monitoring.read_text(encoding="utf-8").replace(
                    'metric_name         = "RelayShed"',
                    'metric_name         = "RelayShedded"',
                    1,
                ),
                encoding="utf-8",
            )

            result = run_check(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("relay_shedding", result.stderr)
        self.assertIn("metric_name", result.stderr)

    def test_relay_shed_statistic_drift_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_fixture(root)
            relay_monitoring = (
                root / "terraform" / "modules" / "relay" / "monitoring.tf"
            )
            relay_monitoring.write_text(
                relay_monitoring.read_text(encoding="utf-8").replace(
                    'statistic           = "Sum"',
                    'statistic           = "Average"',
                    1,
                ),
                encoding="utf-8",
            )

            result = run_check(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("relay_shedding", result.stderr)
        self.assertIn("statistic", result.stderr)

    def test_relay_shed_unknown_static_semantic_drift_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_fixture(root)
            relay_monitoring = (
                root / "terraform" / "modules" / "relay" / "monitoring.tf"
            )
            monitoring_text = relay_monitoring.read_text(encoding="utf-8")
            unknown_alarm_start = monitoring_text.index(
                'resource "aws_cloudwatch_metric_alarm" '
                '"relay_shedding_unknown_environment"'
            )
            relay_monitoring.write_text(
                monitoring_text[:unknown_alarm_start]
                + monitoring_text[unknown_alarm_start:].replace(
                    'treat_missing_data  = "notBreaching"',
                    'treat_missing_data  = "breaching"',
                    1,
                ),
                encoding="utf-8",
            )

            result = run_check(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("relay_shedding_unknown_environment", result.stderr)
        self.assertIn("treat_missing_data", result.stderr)

    def test_relay_shed_unknown_namespace_drift_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_fixture(root)
            relay_monitoring = (
                root / "terraform" / "modules" / "relay" / "monitoring.tf"
            )
            monitoring_text = relay_monitoring.read_text(encoding="utf-8")
            unknown_alarm_start = monitoring_text.index(
                'resource "aws_cloudwatch_metric_alarm" '
                '"relay_shedding_unknown_environment"'
            )
            relay_monitoring.write_text(
                monitoring_text[:unknown_alarm_start]
                + monitoring_text[unknown_alarm_start:].replace(
                    'namespace           = "LayerV/NHP"',
                    'namespace           = "LayerV/NHPRelay"',
                    1,
                ),
                encoding="utf-8",
            )

            result = run_check(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("relay_shedding_unknown_environment", result.stderr)
        self.assertIn("namespace", result.stderr)

    def test_relay_metric_environment_dimension_name_drift_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_fixture(root)
            relay_go = root / "endpoints" / "relay" / "relay.go"
            relay_go.write_text(
                relay_go.read_text(encoding="utf-8").replace(
                    'Name: aws.String("Environment")',
                    'Name: aws.String("Env")',
                    1,
                ),
                encoding="utf-8",
            )

            result = run_check(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("relay_shedding", result.stderr)
        self.assertIn("Environment", result.stderr)

    def test_relay_metric_unknown_environment_fallback_value_drift_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_fixture(root)
            relay_go = root / "endpoints" / "relay" / "relay.go"
            relay_go.write_text(
                relay_go.read_text(encoding="utf-8").replace(
                    'environment = "unknown"',
                    'environment = "unset"',
                    1,
                ),
                encoding="utf-8",
            )

            result = run_check(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("relay_shedding_unknown_environment", result.stderr)
        self.assertIn("unknown", result.stderr)

    def test_relay_process_environment_drift_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_fixture(root)
            relay_user_data = (
                root / "terraform" / "modules" / "relay" / "user_data.sh.tpl"
            )
            relay_user_data.write_text(
                relay_user_data.read_text(encoding="utf-8").replace(
                    "-e NHP_ENVIRONMENT=${environment}",
                    "",
                ),
                encoding="utf-8",
            )

            result = run_check(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("NHP_ENVIRONMENT", result.stderr)

    def test_relay_process_environment_value_suffix_drift_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_fixture(root)
            relay_user_data = (
                root / "terraform" / "modules" / "relay" / "user_data.sh.tpl"
            )
            relay_user_data.write_text(
                relay_user_data.read_text(encoding="utf-8").replace(
                    "-e NHP_ENVIRONMENT=${environment}",
                    "-e NHP_ENVIRONMENT=${environment}_TYPO",
                ),
                encoding="utf-8",
            )

            result = run_check(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("NHP_ENVIRONMENT", result.stderr)

    def test_relay_process_environment_comment_only_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_fixture(root)
            relay_user_data = (
                root / "terraform" / "modules" / "relay" / "user_data.sh.tpl"
            )
            relay_user_data.write_text(
                relay_user_data.read_text(encoding="utf-8").replace(
                    "-e NHP_ENVIRONMENT=${environment}",
                    "# -e NHP_ENVIRONMENT=${environment}",
                ),
                encoding="utf-8",
            )

            result = run_check(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("NHP_ENVIRONMENT", result.stderr)

    def test_relay_process_environment_trailing_comment_only_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_fixture(root)
            relay_user_data = (
                root / "terraform" / "modules" / "relay" / "user_data.sh.tpl"
            )
            relay_user_data.write_text(
                relay_user_data.read_text(encoding="utf-8").replace(
                    "-e NHP_ENVIRONMENT=${environment}",
                    "-e OTHER_ENVIRONMENT=${environment} # -e NHP_ENVIRONMENT=${environment}",
                ),
                encoding="utf-8",
            )

            result = run_check(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("NHP_ENVIRONMENT", result.stderr)

    def test_relay_process_environment_shell_slashes_are_not_comments(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_fixture(root)
            relay_user_data = (
                root / "terraform" / "modules" / "relay" / "user_data.sh.tpl"
            )
            relay_user_data.write_text(
                relay_user_data.read_text(encoding="utf-8").replace(
                    "-e NHP_ENVIRONMENT=${environment}",
                    "-e NHP_ENVIRONMENT=${environment} // shell literal, not a comment",
                ),
                encoding="utf-8",
            )

            result = run_check(root)

        self.assertEqual(result.returncode, 0, result.stderr)

    def test_relay_single_event_names_must_be_core_alarm_names(self) -> None:
        with self.assertRaises(CHECKER.LintError) as ctx:
            CHECKER.require_name_subset(
                ("relay_shedding", "relay_shedding_typo"),
                RELAY_CORE_ALARMS,
                "RELAY_SINGLE_EVENT_ALARM_NAMES",
                "RELAY_CORE_ALARM_NAMES",
            )

        self.assertIn("relay_shedding_typo", str(ctx.exception))

    def test_server_relay_forward_reject_dimension_drift_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_fixture(root)
            monitoring_main = root / "terraform" / "modules" / "monitoring" / "main.tf"
            monitoring_main.write_text(
                monitoring_main.read_text(encoding="utf-8").replace(
                    "    Cell        = var.cell_id\n",
                    "",
                ),
                encoding="utf-8",
            )

            result = run_check(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("relay_forward_reject", result.stderr)
        self.assertIn("Cell", result.stderr)

    def test_tfvars_noop_variable_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build_fixture(root)
            sandbox_vars = (
                root / "terraform" / "environments" / "sandbox" / "variables.tf"
            )
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
