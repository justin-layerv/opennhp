"""
Unit tests for Status Aggregator Lambda.

Run with: pytest test_status_aggregator.py -v

Tests mock AWS service calls (ELBv2 and CloudWatch) to verify status
derivation, response redaction, parameter parsing, and error handling without
requiring actual infrastructure.
"""

import json
import os
from unittest.mock import MagicMock, patch

# Set required environment variables before importing the module
os.environ.setdefault("AWS_ACCESS_KEY_ID", "test")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "test")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("AWS_EC2_METADATA_DISABLED", "true")
os.environ.setdefault("ENVIRONMENT", "sandbox")
os.environ.setdefault("ALARM_NAME_PREFIX", "nhp-sandbox")
os.environ.setdefault("ALARM_NAME_PREFIXES", "nhp-sandbox-cell0,nhp-sandbox-ac-")
os.environ.setdefault("SERVER_ALARM_PREFIXES", "nhp-sandbox-cell0")
os.environ.setdefault("AC_ALARM_PREFIXES", "nhp-sandbox-ac-")
os.environ.setdefault("SERVER_NLB_TG_ARNS", "arn:aws:elasticloadbalancing:us-east-1:123456789:targetgroup/server-blue/abc123")
os.environ.setdefault("AC_NLB_TG_ARNS", "arn:aws:elasticloadbalancing:us-east-1:123456789:targetgroup/ac-blue/def456")


def _health(healthy, unhealthy, total, configured=None, described=None, errors=0):
    """Build the Lambda's internal health aggregate shape for tests."""
    if configured is None:
        configured = 1 if total > 0 else 0
    if described is None:
        described = 1 if total > 0 else 0
    return {
        "healthy": healthy,
        "unhealthy": unhealthy,
        "total": total,
        "configured": configured,
        "described": described,
        "errors": errors,
    }


# ---------------------------------------------------------------------------
# Status derivation (_derive_status)
# ---------------------------------------------------------------------------

class TestDeriveStatus:
    """Tests for the _derive_status function."""

    def test_healthy_all_hosts_up_no_alarms(self):
        from status_aggregator import _derive_status
        health = _health(2, 0, 2)
        assert _derive_status(health, False) == "healthy"

    def test_unknown_no_target_groups_configured(self):
        from status_aggregator import _derive_status
        health = _health(0, 0, 0, configured=0, described=0)
        assert _derive_status(health, False) == "unknown"

    def test_unknown_empty_target_group_data(self):
        from status_aggregator import _derive_status
        health = _health(0, 0, 0, configured=1, described=1)
        assert _derive_status(health, False) == "unknown"

    def test_unknown_all_target_group_describes_failed(self):
        from status_aggregator import _derive_status
        health = _health(0, 0, 0, configured=2, described=0, errors=2)
        assert _derive_status(health, False) == "unknown"

    def test_degraded_when_alarm_active_without_target_data(self):
        from status_aggregator import _derive_status
        health = _health(0, 0, 0, configured=1, described=0, errors=1)
        assert _derive_status(health, True) == "degraded"

    def test_unhealthy_all_hosts_down(self):
        from status_aggregator import _derive_status
        health = _health(0, 2, 2)
        assert _derive_status(health, False) == "unhealthy"

    def test_degraded_some_unhealthy(self):
        from status_aggregator import _derive_status
        health = _health(1, 1, 2)
        assert _derive_status(health, False) == "degraded"

    def test_degraded_alarm_active(self):
        from status_aggregator import _derive_status
        health = _health(2, 0, 2)
        assert _derive_status(health, True) == "degraded"

    def test_degraded_unhealthy_and_alarm(self):
        from status_aggregator import _derive_status
        health = _health(1, 1, 2)
        assert _derive_status(health, True) == "degraded"

    def test_unhealthy_zero_healthy_with_alarm(self):
        from status_aggregator import _derive_status
        health = _health(0, 1, 1)
        assert _derive_status(health, True) == "unhealthy"

    def test_healthy_partial_describe_error_with_known_healthy_signal(self):
        from status_aggregator import _derive_status
        health = _health(1, 0, 1, configured=2, described=1, errors=1)
        assert _derive_status(health, False) == "healthy"

    def test_unknown_partial_describe_error_with_visible_down_target(self):
        from status_aggregator import _derive_status
        health = _health(0, 1, 1, configured=2, described=1, errors=1)
        assert _derive_status(health, False) == "unknown"

    def test_degraded_partial_describe_error_with_alarm(self):
        from status_aggregator import _derive_status
        health = _health(0, 1, 1, configured=2, described=1, errors=1)
        assert _derive_status(health, True) == "degraded"

    def test_healthy_with_transitional_rollout_targets(self):
        from status_aggregator import _derive_status
        health = _health(1, 0, 2)
        assert _derive_status(health, False) == "healthy"

    def test_unknown_when_all_targets_are_transitional(self):
        from status_aggregator import _derive_status
        health = _health(0, 0, 2)
        assert _derive_status(health, False) == "unknown"


# ---------------------------------------------------------------------------
# _build_component
# ---------------------------------------------------------------------------

class TestBuildComponent:
    """Tests for the _build_component function."""

    def test_builds_public_component_status_only(self):
        from status_aggregator import _build_component
        health = _health(2, 0, 2)
        result = _build_component(health, False)

        assert result == {"status": "healthy"}

    def test_builds_degraded_component(self):
        from status_aggregator import _build_component
        health = _health(1, 1, 2)
        result = _build_component(health, False)
        assert result == {"status": "degraded"}

    def test_does_not_expose_health_counts(self):
        from status_aggregator import _build_component
        health = _health(1, 0, 2)
        result = _build_component(health, False)
        assert "healthy_hosts" not in result
        assert "unhealthy_hosts" not in result
        assert "total_hosts" not in result
        assert "transitional_hosts" not in result


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
        agg = _aggregate_target_health(["arn:aws:tg/test"])
        assert agg == _health(2, 1, 3)

    @patch("status_aggregator.elbv2")
    def test_empty_target_group(self, mock_elbv2):
        from status_aggregator import _aggregate_target_health
        mock_elbv2.describe_target_health.return_value = {
            "TargetHealthDescriptions": []
        }
        agg = _aggregate_target_health(["arn:aws:tg/empty"])
        assert agg == _health(0, 0, 0, configured=1, described=1)

    def test_no_arns(self):
        from status_aggregator import _aggregate_target_health
        agg = _aggregate_target_health([])
        assert agg == _health(0, 0, 0, configured=0, described=0)

    @patch("status_aggregator.elbv2")
    def test_aggregates_multiple_target_groups(self, mock_elbv2):
        from status_aggregator import _aggregate_target_health
        mock_elbv2.describe_target_health.side_effect = [
            {"TargetHealthDescriptions": [{"TargetHealth": {"State": "healthy"}}]},
            {"TargetHealthDescriptions": [{"TargetHealth": {"State": "unhealthy"}}]},
        ]
        agg = _aggregate_target_health(["arn:tg/1", "arn:tg/2"])
        assert agg == _health(1, 1, 2, configured=2, described=2)

    @patch("status_aggregator.elbv2")
    def test_continues_on_error(self, mock_elbv2):
        from status_aggregator import _aggregate_target_health
        mock_elbv2.describe_target_health.side_effect = [
            RuntimeError("access denied"),
            {"TargetHealthDescriptions": [{"TargetHealth": {"State": "healthy"}}]},
        ]
        agg = _aggregate_target_health(["arn:tg/bad", "arn:tg/good"])
        assert agg == _health(1, 0, 1, configured=2, described=1, errors=1)

    @patch("status_aggregator.elbv2")
    def test_initial_and_draining_are_neutral_private_states(self, mock_elbv2):
        from status_aggregator import _aggregate_target_health
        mock_elbv2.describe_target_health.return_value = {
            "TargetHealthDescriptions": [
                {"TargetHealth": {"State": "initial"}},
                {"TargetHealth": {"State": "draining"}},
                {"TargetHealth": {"State": "healthy"}},
            ]
        }
        agg = _aggregate_target_health(["arn:aws:tg/mixed"])
        assert agg == _health(1, 0, 3)


# ---------------------------------------------------------------------------
# _get_alarm_summary
# ---------------------------------------------------------------------------

class TestGetAlarmSummary:
    """Tests for CloudWatch alarm summary retrieval."""

    @patch("status_aggregator.cloudwatch")
    def test_counts_active_and_ok_without_details(self, mock_cw):
        from status_aggregator import _get_alarm_summary
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
        result = _get_alarm_summary("nhp-sandbox")

        assert result == {
            "active_count": 1,
            "ok_count": 1,
            "server_active": True,
            "ac_active": False,
        }
        serialized = json.dumps(result)
        assert "nhp-sandbox-server-cpu" not in serialized
        assert "CPUUtilization" not in serialized
        assert "Threshold crossed" not in serialized

    @patch("status_aggregator.cloudwatch")
    def test_composite_alarms_count_as_active(self, mock_cw):
        from status_aggregator import _get_alarm_summary
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
        result = _get_alarm_summary("nhp-sandbox")

        assert result == {
            "active_count": 1,
            "ok_count": 0,
            "server_active": False,
            "ac_active": False,
        }

    @patch("status_aggregator.cloudwatch")
    def test_ac_alarm_marks_ac_active(self, mock_cw):
        from status_aggregator import _get_alarm_summary
        paginator = MagicMock()
        mock_cw.get_paginator.return_value = paginator
        paginator.paginate.return_value = [
            {
                "MetricAlarms": [
                    {
                        "AlarmName": "nhp-sandbox-ac-registration-failure",
                        "StateValue": "ALARM",
                    }
                ],
                "CompositeAlarms": [],
            }
        ]
        result = _get_alarm_summary("nhp-sandbox")

        assert result == {
            "active_count": 1,
            "ok_count": 0,
            "server_active": False,
            "ac_active": True,
        }

    @patch("status_aggregator.cloudwatch")
    def test_real_prefix_families_mark_components(self, mock_cw):
        from status_aggregator import _get_alarm_summary
        paginator = MagicMock()
        mock_cw.get_paginator.return_value = paginator

        def paginate(AlarmNamePrefix):
            if AlarmNamePrefix == "nhp-sandbox-cell0":
                return [
                    {
                        "MetricAlarms": [
                            {
                                "AlarmName": "nhp-sandbox-cell0-no-healthy-hosts",
                                "StateValue": "ALARM",
                            },
                            {
                                "AlarmName": "nhp-sandbox-cell0-high-latency",
                                "StateValue": "OK",
                            },
                        ],
                        "CompositeAlarms": [],
                    }
                ]
            if AlarmNamePrefix == "nhp-sandbox-ac-":
                return [
                    {
                        "MetricAlarms": [
                            {
                                "AlarmName": "nhp-sandbox-ac-registration-failure",
                                "StateValue": "ALARM",
                            }
                        ],
                        "CompositeAlarms": [],
                    }
                ]
            return [{"MetricAlarms": [], "CompositeAlarms": []}]

        paginator.paginate.side_effect = paginate
        result = _get_alarm_summary(
            ["nhp-sandbox-cell0", "nhp-sandbox-ac-"],
            ["nhp-sandbox-cell0"],
            ["nhp-sandbox-ac-"],
        )

        assert result == {
            "active_count": 2,
            "ok_count": 1,
            "server_active": True,
            "ac_active": True,
        }

    @patch("status_aggregator.cloudwatch")
    def test_cell_prefix_alarm_families_map_to_impacted_components(self, mock_cw):
        from status_aggregator import _get_alarm_summary
        paginator = MagicMock()
        mock_cw.get_paginator.return_value = paginator
        alarm_names = [
            "nhp-sandbox-cell0-high-cpu",
            "nhp-sandbox-cell0-unhealthy-hosts",
            "nhp-sandbox-cell0-no-healthy-hosts",
            "nhp-sandbox-cell0-tcp-resets",
            "nhp-sandbox-cell0-tcp-resets-https",
            "nhp-sandbox-cell0-tcp-resets-https-green",
            "nhp-sandbox-cell0-low-instances",
            "nhp-sandbox-cell0-network-in-low",
            "nhp-sandbox-cell0-storage-health",
            "nhp-sandbox-cell0-auth-failures",
            "nhp-sandbox-cell0-high-latency",
            "nhp-sandbox-cell0-internal-auth-signer-unavailable",
            "nhp-sandbox-cell0-art-replay-gate-drop",
            "nhp-sandbox-cell0-relay-forward-reject",
            "nhp-sandbox-cell0-ac-peer-count-low",
            "nhp-sandbox-cell0-ac-registration-latency",
            "nhp-sandbox-cell0-dynamodb-throttled-licenses",
            "nhp-sandbox-cell0-dynamodb-latency-licenses",
            "nhp-sandbox-cell0-server-panic",
            "nhp-sandbox-cell0-server-instance-restart",
            "nhp-sandbox-cell0-server-cloudmap-register-failure",
            "nhp-sandbox-cell0-server-cloudmap-register-refresh-heartbeat",
            "nhp-sandbox-cell0-server-cloudmap-register-refresh-failure",
            "nhp-sandbox-cell0-server-publisher-failures",
        ]
        paginator.paginate.return_value = [
            {
                "MetricAlarms": [
                    {"AlarmName": name, "StateValue": "ALARM"}
                    for name in alarm_names
                ],
                "CompositeAlarms": [],
            }
        ]

        result = _get_alarm_summary(
            "nhp-sandbox-cell0",
            "nhp-sandbox-cell0",
            "nhp-sandbox-ac-",
        )

        assert result == {
            "active_count": len(alarm_names),
            "ok_count": 0,
            "server_active": True,
            "ac_active": True,
        }

    @patch("status_aggregator.cloudwatch")
    def test_dedupes_alarms_seen_through_multiple_prefixes(self, mock_cw):
        from status_aggregator import _get_alarm_summary
        paginator = MagicMock()
        mock_cw.get_paginator.return_value = paginator
        alarm = {
            "AlarmName": "nhp-sandbox-cell0-no-healthy-hosts",
            "StateValue": "ALARM",
        }
        paginator.paginate.return_value = [
            {"MetricAlarms": [alarm], "CompositeAlarms": []}
        ]

        result = _get_alarm_summary(["nhp-sandbox", "nhp-sandbox-cell0"])

        assert result == {
            "active_count": 1,
            "ok_count": 0,
            "server_active": True,
            "ac_active": False,
        }

    def test_empty_prefix_returns_empty(self):
        from status_aggregator import _get_alarm_summary
        result = _get_alarm_summary("")
        assert result == {
            "active_count": 0,
            "ok_count": 0,
            "server_active": False,
            "ac_active": False,
        }

    @patch("status_aggregator.cloudwatch")
    def test_returns_empty_on_error(self, mock_cw):
        from status_aggregator import _get_alarm_summary
        paginator = MagicMock()
        mock_cw.get_paginator.return_value = paginator
        paginator.paginate.side_effect = RuntimeError("access denied")
        result = _get_alarm_summary("nhp-sandbox")
        assert result == {
            "active_count": 0,
            "ok_count": 0,
            "server_active": False,
            "ac_active": False,
        }


# ---------------------------------------------------------------------------
# handler (Lambda entry point)
# ---------------------------------------------------------------------------

class TestHandler:
    """Tests for the Lambda handler."""

    def test_options_returns_cors_headers_v2(self):
        from status_aggregator import handler
        event = {"requestContext": {"http": {"method": "OPTIONS"}}}
        result = handler(event, None)
        assert set(result) == {"statusCode", "headers", "body"}
        assert result["statusCode"] == 200
        assert result["headers"]["Access-Control-Allow-Origin"] == "*"
        assert result["body"] == ""

    def test_options_fallback_v1(self):
        from status_aggregator import handler
        result = handler({"httpMethod": "OPTIONS"}, None)
        assert set(result) == {"statusCode", "headers", "body"}
        assert result["statusCode"] == 200
        assert result["body"] == ""

    @patch("status_aggregator.build_status")
    def test_get_returns_status_json(self, mock_build):
        import status_aggregator
        status_aggregator._STATUS_CACHE["body"] = None
        status_aggregator._STATUS_CACHE["expires_at"] = 0.0
        handler = status_aggregator.handler
        mock_build.return_value = {"environment": "sandbox", "components": {}}
        event = {"requestContext": {"http": {"method": "GET"}}}
        result = handler(event, None)
        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["environment"] == "sandbox"

    @patch("status_aggregator.build_status")
    def test_error_returns_500(self, mock_build):
        import status_aggregator
        status_aggregator._STATUS_CACHE["body"] = None
        status_aggregator._STATUS_CACHE["expires_at"] = 0.0
        handler = status_aggregator.handler
        mock_build.side_effect = RuntimeError("boom")
        event = {"requestContext": {"http": {"method": "GET"}}}
        result = handler(event, None)
        assert set(result) == {"statusCode", "headers", "body"}
        assert result["statusCode"] == 500
        body = json.loads(result["body"])
        assert body == {"error": "Internal server error"}
        assert result["headers"]["Content-Type"] == "application/json"

    @patch("status_aggregator.time.time")
    @patch("status_aggregator.build_status")
    def test_get_uses_short_lived_cache(self, mock_build, mock_time):
        import status_aggregator
        status_aggregator._STATUS_CACHE["body"] = None
        status_aggregator._STATUS_CACHE["expires_at"] = 0.0
        mock_time.side_effect = [1000.0, 1001.0]
        mock_build.return_value = {"environment": "sandbox", "components": {}}
        event = {"requestContext": {"http": {"method": "GET"}}}

        first = status_aggregator.handler(event, None)
        second = status_aggregator.handler(event, None)

        assert first["body"] == second["body"]
        assert mock_build.call_count == 1


# ---------------------------------------------------------------------------
# build_status (integration of all components)
# ---------------------------------------------------------------------------

class TestBuildStatus:
    """Integration tests for build_status with all dependencies mocked."""

    @patch("status_aggregator._get_alarm_summary")
    @patch("status_aggregator._aggregate_target_health")
    def test_builds_redacted_public_status(self, mock_health, mock_alarms):
        from status_aggregator import build_status
        mock_health.return_value = _health(2, 0, 2)
        mock_alarms.return_value = {
            "active_count": 0,
            "ok_count": 1,
            "server_active": False,
            "ac_active": False,
        }

        result = build_status()

        assert result["environment"] == "sandbox"
        assert "timestamp" in result
        assert result["components"] == {
            "server": {"status": "healthy"},
            "ac": {"status": "healthy"},
        }
        assert result["alarms"] == {"active_count": 0, "ok_count": 1}

        serialized = json.dumps(result)
        sensitive_fragments = [
            "235500187906",
            "us-east-2",
            "arn:aws",
            "prod-blue",
            "layerv-nhp-prod-cell0-server-cpu",
            "CPUUtilization",
            "AWS/EC2",
            "runbook",
            "image_tag",
            "deployed_commit",
            "asg_details",
            "key_metrics",
            "dependent_services",
            "ssl_certs",
        ]
        for fragment in sensitive_fragments:
            assert fragment not in serialized

    @patch("status_aggregator._get_alarm_summary")
    @patch("status_aggregator._aggregate_target_health")
    def test_public_status_contract_blocks_disclosure_regression(
        self, mock_health, mock_alarms
    ):
        from status_aggregator import build_status
        leaked_server_health = {
            **_health(2, 0, 2),
            "account_id": "235500187906",
            "region": "us-east-2",
            "target_groups": [
                "arn:aws:elasticloadbalancing:us-east-2:235500187906:targetgroup/server/abc123"
            ],
            "instance_ids": ["i-0123456789abcdef0"],
            "auto_scaling_group": "layerv-nhp-prod-cell0-server-asg",
            "deployment_commit": "deadbeefcafebabe",
            "container_image": (
                "235500187906.dkr.ecr.us-east-2.amazonaws.com/nhp:deadbeef"
            ),
            "dynamodb_tables": ["layerv-nhp-prod-cell0-licenses", "qurl-api-keys"],
        }
        leaked_ac_health = {
            **_health(1, 0, 1),
            "service_names": ["nhp-ac-internal", "qurl-service"],
            "runbooks": ["https://runbooks.internal/status-page"],
        }
        mock_health.side_effect = [leaked_server_health, leaked_ac_health]
        mock_alarms.return_value = {
            "active_count": 1,
            "ok_count": 3,
            "server_active": False,
            "ac_active": True,
            "alarm_names": ["layerv-nhp-prod-cell0-ac-registration-latency"],
            "alarm_descriptions": ["Internal AC registration latency alarm"],
            "metric_names": ["CPUUtilization"],
            "runbooks": ["https://runbooks.internal/ac-registration-latency"],
        }

        result = build_status()

        assert set(result) == {"environment", "timestamp", "components", "alarms"}
        assert set(result["components"]) == {"server", "ac"}
        assert result["components"]["server"] == {"status": "healthy"}
        assert result["components"]["ac"] == {"status": "degraded"}
        assert result["alarms"] == {"active_count": 1, "ok_count": 3}

        serialized = json.dumps(result, sort_keys=True)
        forbidden_fragments = [
            "235500187906",
            "us-east-2",
            "arn:aws",
            "i-0123456789abcdef0",
            "auto_scaling_group",
            "target_groups",
            "deployment_commit",
            "container_image",
            "dynamodb_tables",
            "layerv-nhp-prod-cell0-licenses",
            "qurl-api-keys",
            "nhp-ac-internal",
            "qurl-service",
            "alarm_names",
            "alarm_descriptions",
            "CPUUtilization",
            "runbook",
        ]
        for fragment in forbidden_fragments:
            assert fragment not in serialized

    def test_internal_detail_collectors_are_not_public_lambda_surface(self):
        import status_aggregator

        removed_collectors = [
            "_get_all_ssm_params",
            "_get_key_metrics",
            "_get_asg_details",
            "_get_canary_state",
            "_check_dependent_services",
            "_get_ssl_cert_expiry",
            "_get_alarm_states",
        ]
        for collector in removed_collectors:
            assert not hasattr(status_aggregator, collector)

    @patch("status_aggregator._get_alarm_summary")
    @patch("status_aggregator._aggregate_target_health")
    def test_server_alarm_only_degrades_server(self, mock_health, mock_alarms):
        from status_aggregator import build_status
        mock_health.return_value = _health(1, 0, 1)
        mock_alarms.return_value = {
            "active_count": 1,
            "ok_count": 0,
            "server_active": True,
            "ac_active": False,
        }

        result = build_status()

        assert result["components"]["server"]["status"] == "degraded"
        assert result["components"]["ac"]["status"] == "healthy"
        assert result["alarms"] == {"active_count": 1, "ok_count": 0}

    @patch("status_aggregator._get_alarm_summary")
    @patch("status_aggregator._aggregate_target_health")
    def test_ac_alarm_only_degrades_ac(self, mock_health, mock_alarms):
        from status_aggregator import build_status
        mock_health.return_value = _health(1, 0, 1)
        mock_alarms.return_value = {
            "active_count": 1,
            "ok_count": 0,
            "server_active": False,
            "ac_active": True,
        }

        result = build_status()

        assert result["components"]["server"]["status"] == "healthy"
        assert result["components"]["ac"]["status"] == "degraded"
        assert result["alarms"] == {"active_count": 1, "ok_count": 0}
