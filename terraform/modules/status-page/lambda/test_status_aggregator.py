"""
Unit tests for Status Aggregator Lambda.

Run with: pytest test_status_aggregator.py -v

Tests mock all AWS service calls (SSM, ELBv2, CloudWatch) to verify
status derivation, parameter parsing, and error handling without
requiring actual infrastructure.
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
        params = {"active_color": None, "image_tag": None, "deployed_at": None, "deployed_commit": None}
        health = {"healthy": 1, "unhealthy": 0, "total": 1}
        result = _build_component(params, health, False)
        assert result["active_color"] == "blue"

    def test_empty_string_active_color_defaults_to_blue(self):
        from status_aggregator import _build_component
        params = {"active_color": "", "image_tag": None, "deployed_at": None, "deployed_commit": None}
        health = {"healthy": 1, "unhealthy": 0, "total": 1}
        result = _build_component(params, health, False)
        assert result["active_color"] == "blue"


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
        result = _aggregate_target_health(["arn:aws:tg/test"])
        assert result == {"healthy": 2, "unhealthy": 1, "total": 3}

    @patch("status_aggregator.elbv2")
    def test_empty_target_group(self, mock_elbv2):
        from status_aggregator import _aggregate_target_health
        mock_elbv2.describe_target_health.return_value = {
            "TargetHealthDescriptions": []
        }
        result = _aggregate_target_health(["arn:aws:tg/empty"])
        assert result == {"healthy": 0, "unhealthy": 0, "total": 0}

    def test_no_arns(self):
        from status_aggregator import _aggregate_target_health
        result = _aggregate_target_health([])
        assert result == {"healthy": 0, "unhealthy": 0, "total": 0}

    @patch("status_aggregator.elbv2")
    def test_aggregates_multiple_target_groups(self, mock_elbv2):
        from status_aggregator import _aggregate_target_health
        mock_elbv2.describe_target_health.side_effect = [
            {"TargetHealthDescriptions": [{"TargetHealth": {"State": "healthy"}}]},
            {"TargetHealthDescriptions": [{"TargetHealth": {"State": "unhealthy"}}]},
        ]
        result = _aggregate_target_health(["arn:tg/1", "arn:tg/2"])
        assert result == {"healthy": 1, "unhealthy": 1, "total": 2}

    @patch("status_aggregator.elbv2")
    def test_continues_on_error(self, mock_elbv2):
        from status_aggregator import _aggregate_target_health
        mock_elbv2.describe_target_health.side_effect = [
            RuntimeError("access denied"),
            {"TargetHealthDescriptions": [{"TargetHealth": {"State": "healthy"}}]},
        ]
        result = _aggregate_target_health(["arn:tg/bad", "arn:tg/good"])
        assert result == {"healthy": 1, "unhealthy": 0, "total": 1}

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
        result = _aggregate_target_health(["arn:aws:tg/mixed"])
        assert result == {"healthy": 1, "unhealthy": 2, "total": 3}


# ---------------------------------------------------------------------------
# _get_alarm_states
# ---------------------------------------------------------------------------

class TestGetAlarmStates:
    """Tests for CloudWatch alarm state retrieval."""

    @patch("status_aggregator.cloudwatch")
    def test_separates_active_and_ok(self, mock_cw):
        from status_aggregator import _get_alarm_states
        paginator = MagicMock()
        mock_cw.get_paginator.return_value = paginator
        paginator.paginate.return_value = [
            {
                "MetricAlarms": [
                    {"AlarmName": "nhp-sandbox-server-cpu", "StateValue": "ALARM"},
                    {"AlarmName": "nhp-sandbox-server-mem", "StateValue": "OK"},
                ],
                "CompositeAlarms": [],
            }
        ]
        result = _get_alarm_states("nhp-sandbox")
        assert result["active"] == ["nhp-sandbox-server-cpu"]
        assert result["ok"] == ["nhp-sandbox-server-mem"]

    @patch("status_aggregator.cloudwatch")
    def test_includes_composite_alarms(self, mock_cw):
        from status_aggregator import _get_alarm_states
        paginator = MagicMock()
        mock_cw.get_paginator.return_value = paginator
        paginator.paginate.return_value = [
            {
                "MetricAlarms": [],
                "CompositeAlarms": [
                    {"AlarmName": "nhp-sandbox-composite", "StateValue": "ALARM"},
                ],
            }
        ]
        result = _get_alarm_states("nhp-sandbox")
        assert result["active"] == ["nhp-sandbox-composite"]

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

    @patch("status_aggregator._get_alarm_states")
    @patch("status_aggregator._aggregate_target_health")
    @patch("status_aggregator._get_all_ssm_params")
    def test_full_build(self, mock_all_params, mock_health, mock_alarms):
        from status_aggregator import build_status
        mock_all_params.return_value = {
            "/sandbox/nhp/server/active-color": "blue",
            "/sandbox/nhp/server/image-tag": "abc123",
            "/sandbox/nhp/server/green-image-tag": None,
            "/sandbox/nhp/server/last-switch-timestamp": None,
            "/sandbox/nhp/ac/active-color": "blue",
            "/sandbox/nhp/ac/image-tag": "abc123",
            "/sandbox/nhp/ac/green-image-tag": None,
            "/sandbox/nhp/ac/last-switch-timestamp": None,
            "/sandbox/nhp/deploy/deployed-commit": "deadbeef",
            "/sandbox/nhp/deploy/deployed-at": "2025-01-01T00:00:00Z",
        }
        mock_health.return_value = {"healthy": 2, "unhealthy": 0, "total": 2}
        mock_alarms.return_value = {"active": [], "ok": ["nhp-sandbox-server-cpu"]}

        result = build_status()

        assert result["environment"] == "sandbox"
        assert "timestamp" in result
        assert result["components"]["server"]["status"] == "healthy"
        assert result["components"]["server"]["image_tag"] == "abc123"
        assert result["components"]["server"]["deployed_commit"] == "deadbeef"
        assert result["components"]["ac"]["status"] == "healthy"
        assert result["components"]["ac"]["image_tag"] == "abc123"
        assert result["alarms"]["active"] == []

    @patch("status_aggregator._get_alarm_states")
    @patch("status_aggregator._aggregate_target_health")
    @patch("status_aggregator._get_all_ssm_params")
    def test_server_alarm_only_degrades_server(self, mock_all_params, mock_health, mock_alarms):
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
        mock_health.return_value = {"healthy": 1, "unhealthy": 0, "total": 1}
        mock_alarms.return_value = {
            "active": ["nhp-sandbox-server-cpu-high"],
            "ok": [],
        }

        result = build_status()

        assert result["components"]["server"]["status"] == "degraded"
        assert result["components"]["ac"]["status"] == "healthy"
