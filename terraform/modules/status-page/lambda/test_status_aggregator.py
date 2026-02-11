"""
Unit tests for Status Aggregator Lambda.

Run with: pytest test_status_aggregator.py -v

Tests mock all AWS service calls (SSM, ELBv2, CloudWatch, AutoScaling)
to verify status derivation, parameter parsing, and error handling
without requiring actual infrastructure.
"""

import json
import os
from unittest.mock import MagicMock, patch

# Set required environment variables before importing the module
os.environ.setdefault("ENVIRONMENT", "sandbox")
os.environ.setdefault("SSM_PREFIX", "/sandbox/nhp")
os.environ.setdefault("ALARM_NAME_PREFIX", "nhp-sandbox")
os.environ.setdefault("SERVER_NLB_TG_ARNS", "arn:aws:elasticloadbalancing:us-east-1:123456789:targetgroup/server-blue/abc123")
os.environ.setdefault("AC_NLB_TG_ARNS", "arn:aws:elasticloadbalancing:us-east-1:123456789:targetgroup/ac-blue/def456")


# ---------------------------------------------------------------------------
# Status derivation (_derive_status)
# ---------------------------------------------------------------------------

class TestDeriveStatus:
    """Tests for the _derive_status function."""

    def test_healthy_all_hosts_up_no_alarms(self):
        from status_aggregator import _derive_status
        health = {"healthy": 2, "unhealthy": 0, "total": 2}
        assert _derive_status(health, False) == "healthy"

    def test_unhealthy_no_hosts(self):
        from status_aggregator import _derive_status
        health = {"healthy": 0, "unhealthy": 0, "total": 0}
        assert _derive_status(health, False) == "unhealthy"

    def test_unhealthy_all_hosts_down(self):
        from status_aggregator import _derive_status
        health = {"healthy": 0, "unhealthy": 2, "total": 2}
        assert _derive_status(health, False) == "unhealthy"

    def test_degraded_some_unhealthy(self):
        from status_aggregator import _derive_status
        health = {"healthy": 1, "unhealthy": 1, "total": 2}
        assert _derive_status(health, False) == "degraded"

    def test_degraded_alarm_active(self):
        from status_aggregator import _derive_status
        health = {"healthy": 2, "unhealthy": 0, "total": 2}
        assert _derive_status(health, True) == "degraded"

    def test_degraded_unhealthy_and_alarm(self):
        from status_aggregator import _derive_status
        health = {"healthy": 1, "unhealthy": 1, "total": 2}
        assert _derive_status(health, True) == "degraded"

    def test_unhealthy_zero_healthy_with_alarm(self):
        from status_aggregator import _derive_status
        health = {"healthy": 0, "unhealthy": 1, "total": 1}
        assert _derive_status(health, True) == "unhealthy"


# ---------------------------------------------------------------------------
# _build_component
# ---------------------------------------------------------------------------

class TestBuildComponent:
    """Tests for the _build_component function."""

    def test_builds_component_dict(self):
        from status_aggregator import _build_component
        params = {
            "active_color": "blue",
            "image_tag": "abc123",
            "deployed_at": "2025-01-01T00:00:00Z",
            "deployed_commit": "deadbeef",
            "green_image_tag": None,
            "last_switch_timestamp": None,
        }
        health = {"healthy": 2, "unhealthy": 0, "total": 2}
        result = _build_component(params, health, False)

        assert result["status"] == "healthy"
        assert result["active_color"] == "blue"
        assert result["image_tag"] == "abc123"
        assert result["deployed_at"] == "2025-01-01T00:00:00Z"
        assert result["deployed_commit"] == "deadbeef"
        assert result["healthy_hosts"] == 2
        assert result["unhealthy_hosts"] == 0
        assert result["total_hosts"] == 2

    def test_defaults_active_color_to_blue(self):
        from status_aggregator import _build_component
        params = {"active_color": None, "image_tag": None, "deployed_at": None,
                  "deployed_commit": None, "green_image_tag": None, "last_switch_timestamp": None}
        health = {"healthy": 1, "unhealthy": 0, "total": 1}
        result = _build_component(params, health, False)
        assert result["active_color"] == "blue"

    def test_empty_string_active_color_defaults_to_blue(self):
        from status_aggregator import _build_component
        params = {"active_color": "", "image_tag": None, "deployed_at": None,
                  "deployed_commit": None, "green_image_tag": None, "last_switch_timestamp": None}
        health = {"healthy": 1, "unhealthy": 0, "total": 1}
        result = _build_component(params, health, False)
        assert result["active_color"] == "blue"

    def test_includes_green_image_tag_and_last_switch(self):
        from status_aggregator import _build_component
        params = {
            "active_color": "blue",
            "image_tag": "abc123",
            "deployed_at": None,
            "deployed_commit": None,
            "green_image_tag": "def456",
            "last_switch_timestamp": "2025-01-15T10:30:00Z",
        }
        health = {"healthy": 1, "unhealthy": 0, "total": 1}
        result = _build_component(params, health, False)
        assert result["green_image_tag"] == "def456"
        assert result["last_switch_timestamp"] == "2025-01-15T10:30:00Z"

    def test_green_image_tag_none_when_not_set(self):
        from status_aggregator import _build_component
        params = {"active_color": "blue", "image_tag": "abc", "deployed_at": None,
                  "deployed_commit": None, "green_image_tag": None, "last_switch_timestamp": None}
        health = {"healthy": 1, "unhealthy": 0, "total": 1}
        result = _build_component(params, health, False)
        assert result["green_image_tag"] is None
        assert result["last_switch_timestamp"] is None


# ---------------------------------------------------------------------------
# _parse_csv
# ---------------------------------------------------------------------------

class TestParseCsv:
    """Tests for the _parse_csv utility function."""

    def test_empty_string(self):
        from status_aggregator import _parse_csv
        assert _parse_csv("") == []

    def test_none(self):
        from status_aggregator import _parse_csv
        assert _parse_csv(None) == []

    def test_single_value(self):
        from status_aggregator import _parse_csv
        assert _parse_csv("arn:aws:foo") == ["arn:aws:foo"]

    def test_multiple_values(self):
        from status_aggregator import _parse_csv
        result = _parse_csv("arn:one,arn:two,arn:three")
        assert result == ["arn:one", "arn:two", "arn:three"]

    def test_strips_whitespace(self):
        from status_aggregator import _parse_csv
        result = _parse_csv(" arn:one , arn:two ")
        assert result == ["arn:one", "arn:two"]

    def test_drops_empty_entries(self):
        from status_aggregator import _parse_csv
        result = _parse_csv("arn:one,,arn:two,")
        assert result == ["arn:one", "arn:two"]


# ---------------------------------------------------------------------------
# _aggregate_target_health
# ---------------------------------------------------------------------------

class TestAggregateTargetHealth:
    """Tests for ELBv2 target health aggregation."""

    @patch("status_aggregator.elbv2")
    def test_counts_healthy_and_unhealthy(self, mock_elbv2):
        from status_aggregator import _aggregate_target_health
        mock_elbv2.describe_target_health.return_value = {
            "TargetHealthDescriptions": [
                {"TargetHealth": {"State": "healthy"}},
                {"TargetHealth": {"State": "healthy"}},
                {"TargetHealth": {"State": "unhealthy"}},
            ]
        }
        agg, per_tg = _aggregate_target_health(["arn:aws:tg/test"])
        assert agg == {"healthy": 2, "unhealthy": 1, "total": 3}
        assert len(per_tg) == 1
        assert per_tg[0]["healthy"] == 2
        assert per_tg[0]["unhealthy"] == 1
        assert per_tg[0]["total"] == 3

    @patch("status_aggregator.elbv2")
    def test_empty_target_group(self, mock_elbv2):
        from status_aggregator import _aggregate_target_health
        mock_elbv2.describe_target_health.return_value = {
            "TargetHealthDescriptions": []
        }
        agg, per_tg = _aggregate_target_health(["arn:aws:tg/empty"])
        assert agg == {"healthy": 0, "unhealthy": 0, "total": 0}
        assert len(per_tg) == 1

    def test_no_arns(self):
        from status_aggregator import _aggregate_target_health
        agg, per_tg = _aggregate_target_health([])
        assert agg == {"healthy": 0, "unhealthy": 0, "total": 0}
        assert per_tg == []

    @patch("status_aggregator.elbv2")
    def test_aggregates_multiple_target_groups(self, mock_elbv2):
        from status_aggregator import _aggregate_target_health
        mock_elbv2.describe_target_health.side_effect = [
            {"TargetHealthDescriptions": [{"TargetHealth": {"State": "healthy"}}]},
            {"TargetHealthDescriptions": [{"TargetHealth": {"State": "unhealthy"}}]},
        ]
        agg, per_tg = _aggregate_target_health(["arn:tg/1", "arn:tg/2"])
        assert agg == {"healthy": 1, "unhealthy": 1, "total": 2}
        assert len(per_tg) == 2

    @patch("status_aggregator.elbv2")
    def test_continues_on_error(self, mock_elbv2):
        from status_aggregator import _aggregate_target_health
        mock_elbv2.describe_target_health.side_effect = [
            RuntimeError("access denied"),
            {"TargetHealthDescriptions": [{"TargetHealth": {"State": "healthy"}}]},
        ]
        agg, per_tg = _aggregate_target_health(["arn:tg/bad", "arn:tg/good"])
        assert agg == {"healthy": 1, "unhealthy": 0, "total": 1}
        assert len(per_tg) == 2
        assert per_tg[0]["healthy"] == 0  # errored TG
        assert per_tg[1]["healthy"] == 1

    @patch("status_aggregator.elbv2")
    def test_initial_and_draining_count_as_unhealthy(self, mock_elbv2):
        from status_aggregator import _aggregate_target_health
        mock_elbv2.describe_target_health.return_value = {
            "TargetHealthDescriptions": [
                {"TargetHealth": {"State": "initial"}},
                {"TargetHealth": {"State": "draining"}},
                {"TargetHealth": {"State": "healthy"}},
            ]
        }
        agg, per_tg = _aggregate_target_health(["arn:aws:tg/mixed"])
        assert agg == {"healthy": 1, "unhealthy": 2, "total": 3}

    @patch("status_aggregator.elbv2")
    def test_per_tg_extracts_name_from_arn(self, mock_elbv2):
        from status_aggregator import _aggregate_target_health
        mock_elbv2.describe_target_health.side_effect = [
            {"TargetHealthDescriptions": [
                {"TargetHealth": {"State": "healthy"}},
                {"TargetHealth": {"State": "healthy"}},
            ]},
            {"TargetHealthDescriptions": [
                {"TargetHealth": {"State": "unhealthy"}},
            ]},
        ]
        _, per_tg = _aggregate_target_health([
            "arn:aws:elasticloadbalancing:us-east-1:123:targetgroup/server-blue/abc",
            "arn:aws:elasticloadbalancing:us-east-1:123:targetgroup/server-green/def",
        ])
        assert len(per_tg) == 2
        assert per_tg[0]["name"] == "server-blue"
        assert per_tg[0]["healthy"] == 2
        assert per_tg[0]["total"] == 2
        assert per_tg[1]["name"] == "server-green"
        assert per_tg[1]["unhealthy"] == 1
        assert per_tg[1]["total"] == 1


# ---------------------------------------------------------------------------
# _get_alarm_states (enhanced - returns objects not strings)
# ---------------------------------------------------------------------------

class TestGetAlarmStates:
    """Tests for CloudWatch alarm state retrieval."""

    @patch("status_aggregator.cloudwatch")
    def test_separates_active_and_ok_as_objects(self, mock_cw):
        from status_aggregator import _get_alarm_states
        paginator = MagicMock()
        mock_cw.get_paginator.return_value = paginator
        paginator.paginate.return_value = [
            {
                "MetricAlarms": [
                    {
                        "AlarmName": "nhp-sandbox-server-cpu",
                        "AlarmDescription": "CPU too high",
                        "StateValue": "ALARM",
                        "MetricName": "CPUUtilization",
                        "Namespace": "AWS/EC2",
                        "Threshold": 80.0,
                        "ComparisonOperator": "GreaterThanThreshold",
                        "StateReason": "Threshold crossed",
                    },
                    {
                        "AlarmName": "nhp-sandbox-server-mem",
                        "AlarmDescription": "Memory OK",
                        "StateValue": "OK",
                        "MetricName": "MemoryUtilization",
                        "Namespace": "CWAgent",
                        "Threshold": 90.0,
                        "ComparisonOperator": "GreaterThanThreshold",
                        "StateReason": "OK",
                    },
                ],
                "CompositeAlarms": [],
            }
        ]
        result = _get_alarm_states("nhp-sandbox")

        assert len(result["active"]) == 1
        assert result["active"][0]["name"] == "nhp-sandbox-server-cpu"
        assert result["active"][0]["description"] == "CPU too high"
        assert result["active"][0]["metric_name"] == "CPUUtilization"
        assert result["active"][0]["namespace"] == "AWS/EC2"
        assert result["active"][0]["threshold"] == 80.0
        assert result["active"][0]["comparison"] == "GreaterThanThreshold"
        assert result["active"][0]["state_reason"] == "Threshold crossed"

        assert len(result["ok"]) == 1
        assert result["ok"][0]["name"] == "nhp-sandbox-server-mem"

    @patch("status_aggregator.cloudwatch")
    def test_composite_alarms_have_null_metric_fields(self, mock_cw):
        from status_aggregator import _get_alarm_states
        paginator = MagicMock()
        mock_cw.get_paginator.return_value = paginator
        paginator.paginate.return_value = [
            {
                "MetricAlarms": [],
                "CompositeAlarms": [
                    {
                        "AlarmName": "nhp-sandbox-composite",
                        "AlarmDescription": "Composite alarm",
                        "StateValue": "ALARM",
                        "StateReason": "Child alarms in ALARM",
                    },
                ],
            }
        ]
        result = _get_alarm_states("nhp-sandbox")

        assert len(result["active"]) == 1
        assert result["active"][0]["name"] == "nhp-sandbox-composite"
        assert result["active"][0]["metric_name"] is None
        assert result["active"][0]["namespace"] is None
        assert result["active"][0]["threshold"] is None
        assert result["active"][0]["comparison"] is None

    def test_empty_prefix_returns_empty(self):
        from status_aggregator import _get_alarm_states
        result = _get_alarm_states("")
        assert result == {"active": [], "ok": []}

    @patch("status_aggregator.cloudwatch")
    def test_returns_empty_on_error(self, mock_cw):
        from status_aggregator import _get_alarm_states
        paginator = MagicMock()
        mock_cw.get_paginator.return_value = paginator
        paginator.paginate.side_effect = RuntimeError("access denied")
        result = _get_alarm_states("nhp-sandbox")
        assert result == {"active": [], "ok": []}


# ---------------------------------------------------------------------------
# _get_all_ssm_params (batch SSM fetch)
# ---------------------------------------------------------------------------

class TestGetAllSsmParams:
    """Tests for batch SSM parameter fetching."""

    @patch("status_aggregator.ssm")
    def test_batch_fetch_returns_values(self, mock_ssm):
        from status_aggregator import _get_all_ssm_params
        mock_ssm.get_parameters.return_value = {
            "Parameters": [
                {"Name": "/sandbox/nhp/server/active-color", "Value": "blue"},
                {"Name": "/sandbox/nhp/server/image-tag", "Value": "abc123"},
                {"Name": "/sandbox/nhp/ac/image-tag", "Value": "def456"},
                {"Name": "/sandbox/nhp/deploy/deployed-commit", "Value": "deadbeef"},
            ],
            "InvalidParameters": [],
        }
        result = _get_all_ssm_params("/sandbox/nhp")
        assert result["/sandbox/nhp/server/active-color"] == "blue"
        assert result["/sandbox/nhp/server/image-tag"] == "abc123"
        assert result["/sandbox/nhp/ac/image-tag"] == "def456"
        assert result["/sandbox/nhp/deploy/deployed-commit"] == "deadbeef"

    @patch("status_aggregator.ssm")
    def test_missing_params_return_none(self, mock_ssm):
        from status_aggregator import _get_all_ssm_params
        mock_ssm.get_parameters.return_value = {
            "Parameters": [
                {"Name": "/sandbox/nhp/server/active-color", "Value": "blue"},
            ],
            "InvalidParameters": [
                "/sandbox/nhp/server/image-tag",
                "/sandbox/nhp/ac/active-color",
            ],
        }
        result = _get_all_ssm_params("/sandbox/nhp")
        assert result["/sandbox/nhp/server/active-color"] == "blue"
        assert result["/sandbox/nhp/server/image-tag"] is None
        assert result["/sandbox/nhp/ac/active-color"] is None

    @patch("status_aggregator.ssm")
    def test_initial_and_empty_values_return_none(self, mock_ssm):
        from status_aggregator import _get_all_ssm_params
        mock_ssm.get_parameters.return_value = {
            "Parameters": [
                {"Name": "/sandbox/nhp/server/image-tag", "Value": "initial"},
                {"Name": "/sandbox/nhp/ac/image-tag", "Value": ""},
                {"Name": "/sandbox/nhp/server/active-color", "Value": "green"},
            ],
            "InvalidParameters": [],
        }
        result = _get_all_ssm_params("/sandbox/nhp")
        assert result["/sandbox/nhp/server/image-tag"] is None
        assert result["/sandbox/nhp/ac/image-tag"] is None
        assert result["/sandbox/nhp/server/active-color"] == "green"

    @patch("status_aggregator.ssm")
    def test_api_error_returns_empty_dict(self, mock_ssm):
        from status_aggregator import _get_all_ssm_params
        mock_ssm.get_parameters.side_effect = RuntimeError("connection timeout")
        result = _get_all_ssm_params("/sandbox/nhp")
        assert result == {}


# ---------------------------------------------------------------------------
# _get_key_metrics
# ---------------------------------------------------------------------------

class TestGetKeyMetrics:
    """Tests for CloudWatch key metrics retrieval."""

    @patch.dict(os.environ, {
        "SERVER_NLB_ARN_SUFFIX": "net/server-nlb/abc123",
        "AC_NLB_ARN_SUFFIX": "net/ac-nlb/def456",
        "SERVER_ASG_NAME": "nhp-server-asg",
        "AC_ASG_NAME": "nhp-ac-asg",
    })
    @patch("status_aggregator.cloudwatch")
    def test_returns_current_values(self, mock_cw):
        from status_aggregator import _get_key_metrics
        mock_cw.get_metric_data.return_value = {
            "MetricDataResults": [
                {"Id": "server_active_flows", "Values": [42.0]},
                {"Id": "ac_active_flows", "Values": [10.0]},
                {"Id": "knock_latency_p99", "Values": [12.5]},
                {"Id": "auth_success", "Values": [150.0]},
                {"Id": "auth_failure", "Values": [2.0]},
                {"Id": "server_cpu", "Values": [23.5]},
                {"Id": "ac_cpu", "Values": [15.2]},
            ]
        }
        result = _get_key_metrics()

        assert result["server_active_flows"] == 42.0
        assert result["ac_active_flows"] == 10.0
        assert result["knock_latency_p99"] == 12.5
        assert result["auth_success"] == 150.0
        assert result["auth_failure"] == 2.0
        assert result["server_cpu"] == 23.5
        assert result["ac_cpu"] == 15.2

    @patch.dict(os.environ, {
        "SERVER_NLB_ARN_SUFFIX": "",
        "AC_NLB_ARN_SUFFIX": "",
        "SERVER_ASG_NAME": "",
        "AC_ASG_NAME": "",
    })
    def test_returns_none_when_no_env_vars(self):
        from status_aggregator import _get_key_metrics
        result = _get_key_metrics()
        assert result is None

    @patch.dict(os.environ, {
        "SERVER_NLB_ARN_SUFFIX": "net/server-nlb/abc123",
        "AC_NLB_ARN_SUFFIX": "",
        "SERVER_ASG_NAME": "",
        "AC_ASG_NAME": "",
    })
    @patch("status_aggregator.cloudwatch")
    def test_skips_metrics_with_empty_env_vars(self, mock_cw):
        from status_aggregator import _get_key_metrics
        mock_cw.get_metric_data.return_value = {
            "MetricDataResults": [
                {"Id": "server_active_flows", "Values": [5.0]},
                {"Id": "knock_latency_p99", "Values": []},
                {"Id": "auth_success", "Values": []},
                {"Id": "auth_failure", "Values": []},
            ]
        }
        result = _get_key_metrics()
        assert result is not None
        assert result["server_active_flows"] == 5.0
        assert result["knock_latency_p99"] is None  # no data points
        assert "ac_active_flows" not in result  # not in response
        assert "server_cpu" not in result

    @patch.dict(os.environ, {
        "SERVER_NLB_ARN_SUFFIX": "net/test/123",
        "AC_NLB_ARN_SUFFIX": "",
        "SERVER_ASG_NAME": "",
        "AC_ASG_NAME": "",
    })
    @patch("status_aggregator.cloudwatch")
    def test_returns_none_on_api_error(self, mock_cw):
        from status_aggregator import _get_key_metrics
        mock_cw.get_metric_data.side_effect = RuntimeError("access denied")
        result = _get_key_metrics()
        assert result is None


# ---------------------------------------------------------------------------
# _get_asg_details
# ---------------------------------------------------------------------------

class TestGetAsgDetails:
    """Tests for ASG detail retrieval."""

    @patch.dict(os.environ, {
        "SERVER_ASG_NAME": "nhp-server-asg",
        "AC_ASG_NAME": "nhp-ac-asg",
    })
    @patch("status_aggregator.autoscaling")
    def test_returns_asg_details(self, mock_asg):
        from status_aggregator import _get_asg_details
        mock_asg.describe_auto_scaling_groups.return_value = {
            "AutoScalingGroups": [
                {
                    "AutoScalingGroupName": "nhp-server-asg",
                    "DesiredCapacity": 2,
                    "MinSize": 1,
                    "MaxSize": 4,
                    "Instances": [
                        {"InstanceId": "i-abc", "HealthStatus": "Healthy", "LifecycleState": "InService"},
                        {"InstanceId": "i-def", "HealthStatus": "Healthy", "LifecycleState": "InService"},
                    ],
                },
                {
                    "AutoScalingGroupName": "nhp-ac-asg",
                    "DesiredCapacity": 1,
                    "MinSize": 1,
                    "MaxSize": 2,
                    "Instances": [
                        {"InstanceId": "i-ghi", "HealthStatus": "Healthy", "LifecycleState": "InService"},
                    ],
                },
            ]
        }
        result = _get_asg_details()

        assert result["server"]["desired_capacity"] == 2
        assert result["server"]["min_size"] == 1
        assert result["server"]["max_size"] == 4
        assert len(result["server"]["instances"]) == 2
        assert result["server"]["instances"][0]["id"] == "i-abc"
        assert result["ac"]["desired_capacity"] == 1

    @patch.dict(os.environ, {"SERVER_ASG_NAME": "", "AC_ASG_NAME": ""})
    def test_returns_none_when_no_names(self):
        from status_aggregator import _get_asg_details
        result = _get_asg_details()
        assert result is None

    @patch.dict(os.environ, {
        "SERVER_ASG_NAME": "nhp-server-asg",
        "AC_ASG_NAME": "",
    })
    @patch("status_aggregator.autoscaling")
    def test_returns_none_on_api_error(self, mock_asg):
        from status_aggregator import _get_asg_details
        mock_asg.describe_auto_scaling_groups.side_effect = RuntimeError("access denied")
        result = _get_asg_details()
        assert result is None

    @patch.dict(os.environ, {
        "SERVER_ASG_NAME": "nhp-server-asg",
        "AC_ASG_NAME": "",
    })
    @patch("status_aggregator.autoscaling")
    def test_partial_asg_names(self, mock_asg):
        from status_aggregator import _get_asg_details
        mock_asg.describe_auto_scaling_groups.return_value = {
            "AutoScalingGroups": [
                {
                    "AutoScalingGroupName": "nhp-server-asg",
                    "DesiredCapacity": 1,
                    "MinSize": 1,
                    "MaxSize": 1,
                    "Instances": [],
                },
            ]
        }
        result = _get_asg_details()
        assert "server" in result
        assert "ac" not in result


# ---------------------------------------------------------------------------
# _get_canary_state
# ---------------------------------------------------------------------------

class TestGetCanaryState:
    """Tests for canary deployment state retrieval."""

    @patch.dict(os.environ, {"CANARY_STATE_SSM_PARAM": "/sandbox/nhp/cell0/canary/state"})
    @patch("status_aggregator.ssm")
    def test_returns_state(self, mock_ssm):
        from status_aggregator import _get_canary_state
        mock_ssm.get_parameter.return_value = {
            "Parameter": {"Value": "deploying"}
        }
        result = _get_canary_state()
        assert result == {"state": "deploying"}

    @patch.dict(os.environ, {"CANARY_STATE_SSM_PARAM": "/sandbox/nhp/cell0/canary/state"})
    @patch("status_aggregator.ssm")
    def test_returns_idle(self, mock_ssm):
        from status_aggregator import _get_canary_state
        mock_ssm.get_parameter.return_value = {
            "Parameter": {"Value": "idle"}
        }
        result = _get_canary_state()
        assert result == {"state": "idle"}

    @patch.dict(os.environ, {"CANARY_STATE_SSM_PARAM": ""})
    def test_returns_none_when_param_empty(self):
        from status_aggregator import _get_canary_state
        result = _get_canary_state()
        assert result is None

    @patch.dict(os.environ, {"CANARY_STATE_SSM_PARAM": "/sandbox/nhp/cell0/canary/state"})
    @patch("status_aggregator.ssm")
    def test_returns_none_on_initial_value(self, mock_ssm):
        from status_aggregator import _get_canary_state
        mock_ssm.get_parameter.return_value = {
            "Parameter": {"Value": "initial"}
        }
        result = _get_canary_state()
        assert result is None

    @patch.dict(os.environ, {"CANARY_STATE_SSM_PARAM": "/sandbox/nhp/cell0/canary/state"})
    @patch("status_aggregator.ssm")
    def test_returns_none_on_error(self, mock_ssm):
        from status_aggregator import _get_canary_state
        mock_ssm.get_parameter.side_effect = RuntimeError("not found")
        result = _get_canary_state()
        assert result is None


# ---------------------------------------------------------------------------
# _check_dependent_services
# ---------------------------------------------------------------------------

class TestCheckDependentServices:
    """Tests for dependent service health checks."""

    @patch.dict(os.environ, {"DEPENDENT_SERVICE_URLS": '{"qurl_api": "https://api.layerv.xyz/health"}'})
    @patch("status_aggregator.urllib.request.urlopen")
    def test_returns_healthy_on_200(self, mock_urlopen):
        from status_aggregator import _check_dependent_services
        mock_resp = MagicMock()
        mock_resp.getcode.return_value = 200
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        result = _check_dependent_services()

        assert result is not None
        assert "qurl_api" in result
        assert result["qurl_api"]["status"] == "healthy"
        assert isinstance(result["qurl_api"]["response_time_ms"], int)

    @patch.dict(os.environ, {"DEPENDENT_SERVICE_URLS": '{"qurl_api": "https://api.layerv.xyz/health"}'})
    @patch("status_aggregator.urllib.request.urlopen")
    def test_returns_unhealthy_on_error(self, mock_urlopen):
        from status_aggregator import _check_dependent_services
        mock_urlopen.side_effect = Exception("Connection refused")

        result = _check_dependent_services()

        assert result is not None
        assert result["qurl_api"]["status"] == "unhealthy"
        assert isinstance(result["qurl_api"]["response_time_ms"], int)

    @patch.dict(os.environ, {"DEPENDENT_SERVICE_URLS": ""})
    def test_returns_none_when_empty(self):
        from status_aggregator import _check_dependent_services
        result = _check_dependent_services()
        assert result is None

    @patch.dict(os.environ, {"DEPENDENT_SERVICE_URLS": "{}"})
    def test_returns_none_when_empty_map(self):
        from status_aggregator import _check_dependent_services
        result = _check_dependent_services()
        assert result is None

    @patch.dict(os.environ, {"DEPENDENT_SERVICE_URLS": "not valid json"})
    def test_returns_none_on_invalid_json(self):
        from status_aggregator import _check_dependent_services
        result = _check_dependent_services()
        assert result is None

    @patch.dict(os.environ, {"DEPENDENT_SERVICE_URLS": '{"bad": "not-a-url", "good": "https://ok.test/health"}'})
    @patch("status_aggregator.urllib.request.urlopen")
    def test_malformed_url_returns_unhealthy(self, mock_urlopen):
        from status_aggregator import _check_dependent_services
        mock_resp = MagicMock()
        mock_resp.getcode.return_value = 200
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        result = _check_dependent_services()

        assert result is not None
        assert result["bad"]["status"] == "unhealthy"
        assert result["bad"]["response_time_ms"] == 0
        assert result["good"]["status"] == "healthy"
        mock_urlopen.assert_called_once()  # only called for the valid URL

    @patch.dict(os.environ, {"DEPENDENT_SERVICE_URLS": '{"svc_a": "https://a.test/health", "svc_b": "https://b.test/health"}'})
    @patch("status_aggregator.urllib.request.urlopen")
    def test_checks_multiple_services(self, mock_urlopen):
        from status_aggregator import _check_dependent_services
        mock_resp = MagicMock()
        mock_resp.getcode.return_value = 200
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        result = _check_dependent_services()

        assert result is not None
        assert "svc_a" in result
        assert "svc_b" in result
        assert result["svc_a"]["status"] == "healthy"
        assert result["svc_b"]["status"] == "healthy"


# ---------------------------------------------------------------------------
# handler (Lambda entry point)
# ---------------------------------------------------------------------------

class TestHandler:
    """Tests for the Lambda handler."""

    def test_options_returns_cors_headers_v2(self):
        from status_aggregator import handler
        event = {"requestContext": {"http": {"method": "OPTIONS"}}}
        result = handler(event, None)
        assert result["statusCode"] == 200
        assert result["headers"]["Access-Control-Allow-Origin"] == "*"
        assert result["body"] == ""

    def test_options_fallback_v1(self):
        from status_aggregator import handler
        result = handler({"httpMethod": "OPTIONS"}, None)
        assert result["statusCode"] == 200
        assert result["body"] == ""

    @patch("status_aggregator.build_status")
    def test_get_returns_status_json(self, mock_build):
        from status_aggregator import handler
        mock_build.return_value = {"environment": "sandbox", "components": {}}
        event = {"requestContext": {"http": {"method": "GET"}}}
        result = handler(event, None)
        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["environment"] == "sandbox"

    @patch("status_aggregator.build_status")
    def test_error_returns_500(self, mock_build):
        from status_aggregator import handler
        mock_build.side_effect = RuntimeError("boom")
        event = {"requestContext": {"http": {"method": "GET"}}}
        result = handler(event, None)
        assert result["statusCode"] == 500
        body = json.loads(result["body"])
        assert body["error"] == "Internal server error"
        assert result["headers"]["Content-Type"] == "application/json"


# ---------------------------------------------------------------------------
# build_status (integration of all components)
# ---------------------------------------------------------------------------

class TestBuildStatus:
    """Integration tests for build_status with all dependencies mocked."""

    @patch("status_aggregator._get_ssl_cert_expiry")
    @patch("status_aggregator._check_dependent_services")
    @patch("status_aggregator._get_canary_state")
    @patch("status_aggregator._get_asg_details")
    @patch("status_aggregator._get_key_metrics")
    @patch("status_aggregator._get_alarm_states")
    @patch("status_aggregator._aggregate_target_health")
    @patch("status_aggregator._get_all_ssm_params")
    def test_full_build_blue_green(self, mock_all_params, mock_health,
                                    mock_alarms, mock_metrics, mock_asg,
                                    mock_canary, mock_dep_svc, mock_ssl):
        from status_aggregator import build_status
        mock_all_params.return_value = {
            "/sandbox/nhp/server/active-color": "blue",
            "/sandbox/nhp/server/image-tag": "abc123",
            "/sandbox/nhp/server/green-image-tag": "def456",
            "/sandbox/nhp/server/last-switch-timestamp": "2025-01-15T10:30:00Z",
            "/sandbox/nhp/ac/active-color": "blue",
            "/sandbox/nhp/ac/image-tag": "abc123",
            "/sandbox/nhp/ac/green-image-tag": None,
            "/sandbox/nhp/ac/last-switch-timestamp": None,
            "/sandbox/nhp/deploy/deployed-commit": "deadbeef",
            "/sandbox/nhp/deploy/deployed-at": "2025-01-01T00:00:00Z",
        }
        per_tg_data = [{"arn": "arn:tg/blue", "name": "blue", "healthy": 2, "unhealthy": 0, "total": 2}]
        mock_health.return_value = ({"healthy": 2, "unhealthy": 0, "total": 2}, per_tg_data)
        mock_alarms.return_value = {"active": [], "ok": [{"name": "nhp-sandbox-server-cpu", "description": "", "metric_name": "CPUUtilization", "namespace": "AWS/EC2", "threshold": 80, "comparison": "GreaterThanThreshold", "state_reason": "OK"}]}
        mock_metrics.return_value = {"server_cpu": 23.5, "ac_cpu": 15.2}
        mock_asg.return_value = {"server": {"desired_capacity": 2, "min_size": 1, "max_size": 4, "instances": []}}
        mock_dep_svc.return_value = {"qurl_api": {"status": "healthy", "response_time_ms": 45}}
        mock_ssl.return_value = None

        result = build_status()

        assert result["environment"] == "sandbox"
        assert result["deployment_model"] == "blue_green"
        assert "timestamp" in result
        assert "region" in result
        assert result["components"]["server"]["status"] == "healthy"
        assert result["components"]["server"]["image_tag"] == "abc123"
        assert result["components"]["server"]["deployed_commit"] == "deadbeef"
        assert result["components"]["server"]["green_image_tag"] == "def456"
        assert result["components"]["server"]["last_switch_timestamp"] == "2025-01-15T10:30:00Z"
        assert result["components"]["server"]["per_tg_health"] is not None
        assert result["components"]["ac"]["status"] == "healthy"
        assert result["alarms"]["active"] == []
        assert result["key_metrics"]["server_cpu"] == 23.5
        assert result["asg_details"]["server"]["desired_capacity"] == 2
        assert result["canary"] is None  # blue_green model, canary not called
        assert result["dependent_services"]["qurl_api"]["status"] == "healthy"
        assert result["ssl_certs"] is None

    @patch.dict(os.environ, {"DEPLOYMENT_MODEL": "canary"})
    @patch("status_aggregator._get_ssl_cert_expiry")
    @patch("status_aggregator._check_dependent_services")
    @patch("status_aggregator._get_canary_state")
    @patch("status_aggregator._get_asg_details")
    @patch("status_aggregator._get_key_metrics")
    @patch("status_aggregator._get_alarm_states")
    @patch("status_aggregator._aggregate_target_health")
    @patch("status_aggregator._get_all_ssm_params")
    def test_full_build_canary(self, mock_all_params, mock_health,
                               mock_alarms, mock_metrics, mock_asg,
                               mock_canary, mock_dep_svc, mock_ssl):
        from status_aggregator import build_status
        mock_all_params.return_value = {
            "/sandbox/nhp/server/active-color": None,
            "/sandbox/nhp/server/image-tag": "abc123",
            "/sandbox/nhp/server/green-image-tag": None,
            "/sandbox/nhp/server/last-switch-timestamp": None,
            "/sandbox/nhp/ac/active-color": None,
            "/sandbox/nhp/ac/image-tag": "abc123",
            "/sandbox/nhp/ac/green-image-tag": None,
            "/sandbox/nhp/ac/last-switch-timestamp": None,
            "/sandbox/nhp/deploy/deployed-commit": "deadbeef",
            "/sandbox/nhp/deploy/deployed-at": "2025-01-01T00:00:00Z",
        }
        mock_health.return_value = ({"healthy": 1, "unhealthy": 0, "total": 1}, [])
        mock_alarms.return_value = {"active": [], "ok": []}
        mock_metrics.return_value = None
        mock_asg.return_value = None
        mock_canary.return_value = {"state": "deploying"}
        mock_dep_svc.return_value = None
        mock_ssl.return_value = None

        result = build_status()

        assert result["deployment_model"] == "canary"
        assert result["canary"] == {"state": "deploying"}
        assert result["dependent_services"] is None
        mock_canary.assert_called_once()

    @patch("status_aggregator._get_ssl_cert_expiry")
    @patch("status_aggregator._check_dependent_services")
    @patch("status_aggregator._get_canary_state")
    @patch("status_aggregator._get_asg_details")
    @patch("status_aggregator._get_key_metrics")
    @patch("status_aggregator._get_alarm_states")
    @patch("status_aggregator._aggregate_target_health")
    @patch("status_aggregator._get_all_ssm_params")
    def test_server_alarm_only_degrades_server(self, mock_all_params, mock_health,
                                                mock_alarms, mock_metrics, mock_asg,
                                                mock_canary, mock_dep_svc, mock_ssl):
        from status_aggregator import build_status
        mock_all_params.return_value = {
            "/sandbox/nhp/server/active-color": "green",
            "/sandbox/nhp/server/image-tag": "xyz",
            "/sandbox/nhp/server/green-image-tag": None,
            "/sandbox/nhp/server/last-switch-timestamp": None,
            "/sandbox/nhp/ac/active-color": "green",
            "/sandbox/nhp/ac/image-tag": "xyz",
            "/sandbox/nhp/ac/green-image-tag": None,
            "/sandbox/nhp/ac/last-switch-timestamp": None,
            "/sandbox/nhp/deploy/deployed-commit": None,
            "/sandbox/nhp/deploy/deployed-at": None,
        }
        mock_health.return_value = ({"healthy": 1, "unhealthy": 0, "total": 1}, [])
        mock_alarms.return_value = {
            "active": [{"name": "nhp-sandbox-server-cpu-high", "description": "", "metric_name": "CPUUtilization", "namespace": "AWS/EC2", "threshold": 80, "comparison": "GreaterThanThreshold", "state_reason": "Crossed"}],
            "ok": [],
        }
        mock_metrics.return_value = None
        mock_asg.return_value = None
        mock_ssl.return_value = None

        result = build_status()

        assert result["components"]["server"]["status"] == "degraded"
        assert result["components"]["ac"]["status"] == "healthy"


# ---------------------------------------------------------------------------
# _get_ssl_cert_expiry
# ---------------------------------------------------------------------------

class TestGetSslCertExpiry:
    """Tests for SSL certificate expiry checking."""

    @patch.dict(os.environ, {"SSL_CERT_ARNS": '{"console": "arn:aws:acm:us-east-1:123:certificate/abc"}'})
    @patch("status_aggregator.acm")
    def test_returns_cert_info(self, mock_acm):
        from status_aggregator import _get_ssl_cert_expiry
        from datetime import datetime, timezone, timedelta
        future = datetime.now(timezone.utc) + timedelta(days=90)
        mock_acm.describe_certificate.return_value = {
            "Certificate": {
                "DomainName": "console.nhp.layerv.xyz",
                "NotAfter": future,
            }
        }
        result = _get_ssl_cert_expiry()
        assert result is not None
        assert len(result) == 1
        assert result[0]["domain"] == "console.nhp.layerv.xyz"
        assert result[0]["days_remaining"] >= 89
        assert result[0]["status"] == "ok"

    @patch.dict(os.environ, {"SSL_CERT_ARNS": '{"console": "arn:aws:acm:us-east-1:123:certificate/abc"}'})
    @patch("status_aggregator.acm")
    def test_warning_when_expiring_soon(self, mock_acm):
        from status_aggregator import _get_ssl_cert_expiry
        from datetime import datetime, timezone, timedelta
        future = datetime.now(timezone.utc) + timedelta(days=15)
        mock_acm.describe_certificate.return_value = {
            "Certificate": {
                "DomainName": "console.nhp.layerv.xyz",
                "NotAfter": future,
            }
        }
        result = _get_ssl_cert_expiry()
        assert result[0]["status"] == "warning"

    @patch.dict(os.environ, {"SSL_CERT_ARNS": '{"console": "arn:aws:acm:us-east-1:123:certificate/abc"}'})
    @patch("status_aggregator.acm")
    def test_critical_when_expiring_very_soon(self, mock_acm):
        from status_aggregator import _get_ssl_cert_expiry
        from datetime import datetime, timezone, timedelta
        future = datetime.now(timezone.utc) + timedelta(days=3)
        mock_acm.describe_certificate.return_value = {
            "Certificate": {
                "DomainName": "console.nhp.layerv.xyz",
                "NotAfter": future,
            }
        }
        result = _get_ssl_cert_expiry()
        assert result[0]["status"] == "critical"

    @patch.dict(os.environ, {"SSL_CERT_ARNS": ""})
    def test_returns_none_when_empty(self):
        from status_aggregator import _get_ssl_cert_expiry
        result = _get_ssl_cert_expiry()
        assert result is None

    @patch.dict(os.environ, {"SSL_CERT_ARNS": "{}"})
    def test_returns_none_when_empty_map(self):
        from status_aggregator import _get_ssl_cert_expiry
        result = _get_ssl_cert_expiry()
        assert result is None

    @patch.dict(os.environ, {"SSL_CERT_ARNS": '{"console": "arn:aws:acm:us-east-1:123:certificate/abc"}'})
    @patch("status_aggregator.acm")
    def test_returns_unknown_on_error(self, mock_acm):
        from status_aggregator import _get_ssl_cert_expiry
        mock_acm.describe_certificate.side_effect = RuntimeError("not found")
        result = _get_ssl_cert_expiry()
        assert result is not None
        assert len(result) == 1
        assert result[0]["domain"] == "console"
        assert result[0]["status"] == "unknown"

    @patch.dict(os.environ, {"SSL_CERT_ARNS": "not valid json"})
    def test_returns_none_on_invalid_json(self):
        from status_aggregator import _get_ssl_cert_expiry
        result = _get_ssl_cert_expiry()
        assert result is None


# ---------------------------------------------------------------------------
# _build_component with per_tg_health
# ---------------------------------------------------------------------------

class TestBuildComponentPerTg:
    """Tests for _build_component with per-TG health data."""

    def test_includes_per_tg_health_when_present(self):
        from status_aggregator import _build_component
        params = {"active_color": "blue", "image_tag": "abc", "deployed_at": None,
                  "deployed_commit": None, "green_image_tag": None, "last_switch_timestamp": None}
        health = {"healthy": 2, "unhealthy": 0, "total": 2}
        per_tg = [{"arn": "arn:tg/blue", "name": "blue", "healthy": 2, "unhealthy": 0, "total": 2}]
        result = _build_component(params, health, False, per_tg_health=per_tg)
        assert "per_tg_health" in result
        assert result["per_tg_health"][0]["name"] == "blue"

    def test_omits_per_tg_health_when_empty(self):
        from status_aggregator import _build_component
        params = {"active_color": "blue", "image_tag": "abc", "deployed_at": None,
                  "deployed_commit": None, "green_image_tag": None, "last_switch_timestamp": None}
        health = {"healthy": 1, "unhealthy": 0, "total": 1}
        result = _build_component(params, health, False, per_tg_health=[])
        assert "per_tg_health" not in result

    def test_omits_per_tg_health_when_none(self):
        from status_aggregator import _build_component
        params = {"active_color": "blue", "image_tag": "abc", "deployed_at": None,
                  "deployed_commit": None, "green_image_tag": None, "last_switch_timestamp": None}
        health = {"healthy": 1, "unhealthy": 0, "total": 1}
        result = _build_component(params, health, False)
        assert "per_tg_health" not in result
