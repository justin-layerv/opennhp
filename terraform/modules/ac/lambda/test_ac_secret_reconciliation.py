"""
Unit tests for AC Secret Reconciliation Lambda

Run with: pytest test_ac_secret_reconciliation.py -v
"""

import json
import os
from unittest.mock import MagicMock

import pytest

# Set required environment variables before importing the module
os.environ.setdefault("SECRET_PREFIXES", '["nhp-sandbox-ac-i-", "nhp-sandbox-console-ac-i-"]')
os.environ.setdefault("RECOVERY_WINDOW_DAYS", "0")
os.environ.setdefault("ENVIRONMENT", "sandbox")

import ac_secret_reconciliation as module


def make_client_error(code="ResourceNotFoundException", message="Secret not found"):
    """Helper to create a botocore ClientError-like exception."""
    from botocore.exceptions import ClientError
    return ClientError(
        {"Error": {"Code": code, "Message": message}},
        "TestOperation",
    )


# ==================== list_ac_secrets ====================


class TestListAcSecrets:
    """Tests for list_ac_secrets() function."""

    def setup_method(self):
        self.mock_sm = MagicMock()
        module.secretsmanager = self.mock_sm

    def _make_paginator(self, pages):
        """Create a mock paginator that returns the given pages."""
        paginator = MagicMock()
        paginator.paginate.return_value = pages
        self.mock_sm.get_paginator.return_value = paginator
        return paginator

    def test_single_prefix_single_page(self):
        """Returns secrets matching a single prefix."""
        self._make_paginator([
            {"SecretList": [
                {"Name": "nhp-sandbox-ac-i-0abc123def456789a"},
                {"Name": "nhp-sandbox-ac-i-0def456789abc1234"},
            ]}
        ])

        result = module.list_ac_secrets(["nhp-sandbox-ac-i-"])

        assert len(result) == 2
        assert result[0] == {"name": "nhp-sandbox-ac-i-0abc123def456789a", "instance_id": "i-0abc123def456789a"}
        assert result[1] == {"name": "nhp-sandbox-ac-i-0def456789abc1234", "instance_id": "i-0def456789abc1234"}

    def test_multiple_prefixes(self):
        """Iterates over all prefixes and aggregates results."""
        pages_by_call = [
            [{"SecretList": [{"Name": "nhp-sandbox-ac-i-0abc123def456789a"}]}],
            [{"SecretList": [{"Name": "nhp-sandbox-console-ac-i-0def456789abc1234"}]}],
        ]
        paginator = MagicMock()
        paginator.paginate.side_effect = pages_by_call
        self.mock_sm.get_paginator.return_value = paginator

        result = module.list_ac_secrets(["nhp-sandbox-ac-i-", "nhp-sandbox-console-ac-i-"])

        assert len(result) == 2
        assert result[0]["instance_id"] == "i-0abc123def456789a"
        assert result[1]["instance_id"] == "i-0def456789abc1234"

    def test_pagination_multiple_pages(self):
        """Handles paginated responses correctly."""
        self._make_paginator([
            {"SecretList": [{"Name": "nhp-sandbox-ac-i-0abc123def456789a"}]},
            {"SecretList": [{"Name": "nhp-sandbox-ac-i-0def456789abc1234"}]},
        ])

        result = module.list_ac_secrets(["nhp-sandbox-ac-i-"])

        assert len(result) == 2

    def test_excludes_pending_deletion_via_api(self):
        """Verifies IncludePlannedDeletion is not set (defaults to False, API filters them)."""
        paginator = self._make_paginator([{"SecretList": []}])

        module.list_ac_secrets(["nhp-sandbox-ac-i-"])

        # IncludePlannedDeletion should NOT be in the call kwargs
        call_kwargs = paginator.paginate.call_args[1]
        assert "IncludePlannedDeletion" not in call_kwargs

    def test_skips_secrets_without_instance_id(self):
        """Skips secrets that don't contain a valid instance ID pattern."""
        self._make_paginator([
            {"SecretList": [
                {"Name": "nhp-sandbox-ac-i-not-an-id"},
                {"Name": "nhp-sandbox-ac-i-0abc123def456789a"},
            ]}
        ])

        result = module.list_ac_secrets(["nhp-sandbox-ac-i-"])

        assert len(result) == 1
        assert result[0]["instance_id"] == "i-0abc123def456789a"

    def test_empty_secret_list(self):
        """Returns empty list when no secrets match."""
        self._make_paginator([{"SecretList": []}])

        result = module.list_ac_secrets(["nhp-sandbox-ac-i-"])

        assert result == []

    def test_empty_page(self):
        """Handles pages with no SecretList key."""
        self._make_paginator([{}])

        result = module.list_ac_secrets(["nhp-sandbox-ac-i-"])

        assert result == []


# ==================== get_live_instance_ids ====================


class TestGetLiveInstanceIds:
    """Tests for get_live_instance_ids() function."""

    def setup_method(self):
        self.mock_ec2 = MagicMock()
        module.ec2 = self.mock_ec2

    def _make_paginator(self, pages):
        paginator = MagicMock()
        paginator.paginate.return_value = pages
        self.mock_ec2.get_paginator.return_value = paginator
        return paginator

    def test_returns_running_instances(self):
        """Returns instance IDs for running instances."""
        self._make_paginator([
            {"Reservations": [
                {"Instances": [
                    {"InstanceId": "i-0abc123def456789a"},
                    {"InstanceId": "i-0def456789abc1234"},
                ]}
            ]}
        ])

        result = module.get_live_instance_ids()

        assert result == {"i-0abc123def456789a", "i-0def456789abc1234"}

    def test_empty_results(self):
        """Returns empty set when no instances exist."""
        self._make_paginator([{"Reservations": []}])

        result = module.get_live_instance_ids()

        assert result == set()

    def test_pagination_multiple_pages(self):
        """Aggregates instances across pages."""
        self._make_paginator([
            {"Reservations": [{"Instances": [{"InstanceId": "i-0abc123def456789a"}]}]},
            {"Reservations": [{"Instances": [{"InstanceId": "i-0def456789abc1234"}]}]},
        ])

        result = module.get_live_instance_ids()

        assert result == {"i-0abc123def456789a", "i-0def456789abc1234"}

    def test_multiple_reservations(self):
        """Handles multiple reservations in a single page."""
        self._make_paginator([
            {"Reservations": [
                {"Instances": [{"InstanceId": "i-0abc123def456789a"}]},
                {"Instances": [{"InstanceId": "i-0def456789abc1234"}]},
            ]}
        ])

        result = module.get_live_instance_ids()

        assert result == {"i-0abc123def456789a", "i-0def456789abc1234"}

    def test_filters_non_terminated_states(self):
        """Verifies the correct instance state filter is passed."""
        paginator = self._make_paginator([{"Reservations": []}])

        module.get_live_instance_ids()

        paginator.paginate.assert_called_once_with(
            Filters=[{
                "Name": "instance-state-name",
                "Values": ["pending", "running", "stopping", "stopped", "shutting-down"],
            }]
        )


# ==================== delete_orphaned_secrets ====================


class TestDeleteOrphanedSecrets:
    """Tests for delete_orphaned_secrets() function."""

    def setup_method(self):
        self.mock_sm = MagicMock()
        module.secretsmanager = self.mock_sm
        # Ensure DRY_RUN is off for delete tests
        self._orig_dry_run = module.DRY_RUN
        module.DRY_RUN = False

    def teardown_method(self):
        module.DRY_RUN = self._orig_dry_run

    def test_force_delete_when_recovery_window_zero(self):
        """Uses ForceDeleteWithoutRecovery when recovery_window is 0."""
        orphans = [{"name": "nhp-sandbox-ac-i-0abc123def456789a", "instance_id": "i-0abc123def456789a"}]

        result = module.delete_orphaned_secrets(orphans, 0)

        assert result == 1
        self.mock_sm.delete_secret.assert_called_once_with(
            SecretId="nhp-sandbox-ac-i-0abc123def456789a",
            ForceDeleteWithoutRecovery=True,
        )

    def test_recovery_window_when_nonzero(self):
        """Uses RecoveryWindowInDays when recovery_window > 0."""
        orphans = [{"name": "nhp-prod-ac-i-0abc123def456789a", "instance_id": "i-0abc123def456789a"}]

        result = module.delete_orphaned_secrets(orphans, 7)

        assert result == 1
        self.mock_sm.delete_secret.assert_called_once_with(
            SecretId="nhp-prod-ac-i-0abc123def456789a",
            RecoveryWindowInDays=7,
        )

    def test_continues_on_individual_failure(self):
        """Continues deleting remaining secrets when one fails."""
        orphans = [
            {"name": "secret-1-i-0abc123def456789a", "instance_id": "i-0abc123def456789a"},
            {"name": "secret-2-i-0def456789abc1234", "instance_id": "i-0def456789abc1234"},
            {"name": "secret-3-i-0ghi789abc1234567", "instance_id": "i-0ghi789abc1234567"},
        ]
        self.mock_sm.delete_secret.side_effect = [
            None,                                           # secret-1 succeeds
            make_client_error("AccessDeniedException"),     # secret-2 fails
            None,                                           # secret-3 succeeds
        ]

        result = module.delete_orphaned_secrets(orphans, 0)

        assert result == 2  # 2 out of 3 succeeded
        assert self.mock_sm.delete_secret.call_count == 3

    def test_empty_orphans_list(self):
        """Returns 0 when there are no orphans to delete."""
        result = module.delete_orphaned_secrets([], 0)

        assert result == 0
        self.mock_sm.delete_secret.assert_not_called()

    def test_dry_run_mode(self):
        """In DRY_RUN mode, counts but does not actually delete."""
        module.DRY_RUN = True
        orphans = [
            {"name": "secret-1-i-0abc123def456789a", "instance_id": "i-0abc123def456789a"},
            {"name": "secret-2-i-0def456789abc1234", "instance_id": "i-0def456789abc1234"},
        ]

        result = module.delete_orphaned_secrets(orphans, 0)

        assert result == 2
        self.mock_sm.delete_secret.assert_not_called()

    def test_all_deletions_fail(self):
        """Returns 0 when all deletions fail."""
        orphans = [
            {"name": "secret-1-i-0abc123def456789a", "instance_id": "i-0abc123def456789a"},
            {"name": "secret-2-i-0def456789abc1234", "instance_id": "i-0def456789abc1234"},
        ]
        self.mock_sm.delete_secret.side_effect = make_client_error()

        result = module.delete_orphaned_secrets(orphans, 0)

        assert result == 0


# ==================== publish_metric ====================


class TestPublishMetric:
    """Tests for publish_metric() function."""

    def setup_method(self):
        self.mock_cw = MagicMock()
        module.cloudwatch = self.mock_cw

    def test_publishes_with_environment_dimension(self):
        """Publishes metric with Environment dimension."""
        module.publish_metric(5)

        self.mock_cw.put_metric_data.assert_called_once_with(
            Namespace="LayerV/NHP",
            MetricData=[{
                "MetricName": "OrphanedSecretsDeleted",
                "Dimensions": [{"Name": "Environment", "Value": module.ENVIRONMENT}],
                "Value": 5,
                "Unit": "Count",
            }],
        )

    def test_publishes_zero(self):
        """Publishes metric even when count is 0."""
        module.publish_metric(0)

        args = self.mock_cw.put_metric_data.call_args
        assert args[1]["MetricData"][0]["Value"] == 0

    def test_continues_on_cloudwatch_error(self):
        """Does not raise when CloudWatch fails."""
        self.mock_cw.put_metric_data.side_effect = make_client_error(
            "InternalServiceError", "CloudWatch unavailable"
        )

        # Should not raise
        module.publish_metric(5)


# ==================== Instance ID Pattern ====================


class TestInstanceIdPattern:
    """Tests for INSTANCE_ID_PATTERN regex edge cases."""

    def test_standard_17_char_id(self):
        match = module.INSTANCE_ID_PATTERN.search("nhp-sandbox-ac-i-0abc123def456789a")
        assert match and match.group(1) == "i-0abc123def456789a"

    def test_short_8_char_id(self):
        match = module.INSTANCE_ID_PATTERN.search("nhp-sandbox-ac-i-0abc1234")
        assert match and match.group(1) == "i-0abc1234"

    def test_no_match_too_short(self):
        """IDs shorter than 8 hex chars after i- should not match."""
        match = module.INSTANCE_ID_PATTERN.search("nhp-sandbox-ac-i-0abc12")
        assert match is None

    def test_no_match_invalid_chars(self):
        """Non-hex characters should not match."""
        match = module.INSTANCE_ID_PATTERN.search("nhp-sandbox-ac-i-0abcXYZdef456789a")
        assert match is None

    def test_anchored_to_end(self):
        """Pattern matches only at end of string (avoids false positives)."""
        # This has a valid-looking ID in the middle but extra text after
        match = module.INSTANCE_ID_PATTERN.search("nhp-sandbox-ac-i-0abc123def456789a-extra")
        assert match is None

    def test_console_ac_prefix(self):
        match = module.INSTANCE_ID_PATTERN.search("nhp-sandbox-console-ac-i-0abc123def456789a")
        assert match and match.group(1) == "i-0abc123def456789a"


# ==================== Handler Integration ====================


class TestHandler:
    """Integration tests for the handler function."""

    def setup_method(self):
        self.mock_sm = MagicMock()
        self.mock_ec2 = MagicMock()
        self.mock_cw = MagicMock()
        module.secretsmanager = self.mock_sm
        module.ec2 = self.mock_ec2
        module.cloudwatch = self.mock_cw
        self._orig_prefixes = module.SECRET_PREFIXES
        self._orig_dry_run = module.DRY_RUN
        module.SECRET_PREFIXES = ["nhp-sandbox-ac-i-"]
        module.DRY_RUN = False

    def teardown_method(self):
        module.SECRET_PREFIXES = self._orig_prefixes
        module.DRY_RUN = self._orig_dry_run

    def _setup_secrets(self, secrets):
        paginator = MagicMock()
        paginator.paginate.return_value = [{"SecretList": secrets}]
        self.mock_sm.get_paginator.return_value = paginator

    def _setup_instances(self, instance_ids):
        paginator = MagicMock()
        paginator.paginate.return_value = [
            {"Reservations": [{"Instances": [{"InstanceId": iid} for iid in instance_ids]}]}
        ]
        self.mock_ec2.get_paginator.return_value = paginator

    def test_handler_deletes_orphans(self):
        """Full flow: 2 secrets, 1 live instance = 1 orphan deleted."""
        self._setup_secrets([
            {"Name": "nhp-sandbox-ac-i-0abc123def456789a"},  # live
            {"Name": "nhp-sandbox-ac-i-0def456789abc1234"},  # orphan
        ])
        self._setup_instances(["i-0abc123def456789a"])

        result = module.handler({}, None)
        body = json.loads(result["body"])

        assert body["total_secrets"] == 2
        assert body["orphans_found"] == 1
        assert body["orphans_deleted"] == 1
        self.mock_sm.delete_secret.assert_called_once()

    def test_handler_no_orphans(self):
        """All secrets have live instances — nothing deleted."""
        self._setup_secrets([{"Name": "nhp-sandbox-ac-i-0abc123def456789a"}])
        self._setup_instances(["i-0abc123def456789a"])

        result = module.handler({}, None)
        body = json.loads(result["body"])

        assert body["orphans_found"] == 0
        assert body["orphans_deleted"] == 0
        self.mock_sm.delete_secret.assert_not_called()

    def test_handler_no_secrets(self):
        """No secrets found — early return with metric published."""
        self._setup_secrets([])

        result = module.handler({}, None)
        body = json.loads(result["body"])

        assert body["orphans_deleted"] == 0
        assert body["total_secrets"] == 0
        self.mock_cw.put_metric_data.assert_called_once()

    def test_handler_empty_prefixes_raises(self):
        """Raises ValueError when SECRET_PREFIXES is empty."""
        module.SECRET_PREFIXES = []

        with pytest.raises(ValueError, match="SECRET_PREFIXES"):
            module.handler({}, None)

    def test_handler_publishes_metric(self):
        """Metric is published with correct count after deletions."""
        self._setup_secrets([
            {"Name": "nhp-sandbox-ac-i-0abc123def456789a"},
            {"Name": "nhp-sandbox-ac-i-0def456789abc1234"},
        ])
        self._setup_instances([])  # both are orphans

        module.handler({}, None)

        # Verify metric was published with count=2
        metric_call = self.mock_cw.put_metric_data.call_args
        metric_data = metric_call[1]["MetricData"][0]
        assert metric_data["Value"] == 2
        assert metric_data["MetricName"] == "OrphanedSecretsDeleted"

    def test_handler_logs_orphan_ids(self, caplog):
        """Orphan instance IDs are logged before deletion for audit trail."""
        import logging
        self._setup_secrets([
            {"Name": "nhp-sandbox-ac-i-0abc123def456789a"},
            {"Name": "nhp-sandbox-ac-i-0def456789abc1234"},
        ])
        self._setup_instances([])  # both are orphans

        with caplog.at_level(logging.INFO):
            module.handler({}, None)

        orphan_log = [r for r in caplog.records if "Orphaned instance IDs" in r.message]
        assert len(orphan_log) == 1
        assert "i-0abc123def456789a" in orphan_log[0].message
        assert "i-0def456789abc1234" in orphan_log[0].message
