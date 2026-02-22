"""
Tests for Auth0 Test App Cleanup Lambda.

Run with: pytest terraform/modules/developer-portal/lambda/test_auth0_cleanup.py -v
"""

import pytest
import json
import time
import urllib.error
from unittest.mock import MagicMock, patch, call


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def setup_module():
    """Import the module with mocked AWS clients."""
    with patch('boto3.client'):
        import sys
        if 'auth0_cleanup' in sys.modules:
            del sys.modules['auth0_cleanup']


@pytest.fixture
def mock_mgmt_token():
    """Mock Auth0 management token retrieval."""
    with patch('auth0_cleanup._get_mgmt_token', return_value='test-mgmt-token'):
        yield


# ---------------------------------------------------------------------------
# ISO 8601 Parsing Tests
# ---------------------------------------------------------------------------

class TestParseISO8601:
    """Tests for _parse_iso8601() date parsing."""

    def test_parse_utc_z_suffix(self):
        """Verify parsing of Z-suffix UTC timestamps."""
        with patch('boto3.client'):
            import auth0_cleanup as ac
            ts = ac._parse_iso8601('2025-01-15T10:30:00Z')
            # Should parse without error; verify it's a reasonable timestamp
            assert ts > 0
            assert ts < time.time() + 86400  # Not in the far future

    def test_parse_utc_offset(self):
        """Verify parsing of +00:00 offset timestamps."""
        with patch('boto3.client'):
            import auth0_cleanup as ac
            ts = ac._parse_iso8601('2025-01-15T10:30:00+00:00')
            assert ts > 0

    def test_parse_with_milliseconds(self):
        """Verify parsing of timestamps with fractional seconds."""
        with patch('boto3.client'):
            import auth0_cleanup as ac
            ts = ac._parse_iso8601('2025-01-15T10:30:00.123Z')
            assert ts > 0

    def test_parse_z_and_offset_equivalent(self):
        """Verify Z and +00:00 produce the same timestamp."""
        with patch('boto3.client'):
            import auth0_cleanup as ac
            ts_z = ac._parse_iso8601('2025-06-01T12:00:00Z')
            ts_offset = ac._parse_iso8601('2025-06-01T12:00:00+00:00')
            assert abs(ts_z - ts_offset) < 1  # Within 1 second

    def test_parse_invalid_raises_value_error(self):
        """Verify invalid date strings raise ValueError."""
        with patch('boto3.client'):
            import auth0_cleanup as ac
            with pytest.raises(Exception):
                ac._parse_iso8601('not-a-date')


# ---------------------------------------------------------------------------
# Cleanup Logic Tests
# ---------------------------------------------------------------------------

class TestCleanupOrphanedApps:
    """Tests for the cleanup_orphaned_apps() function."""

    def test_deletes_old_matching_apps(self, mock_mgmt_token):
        """Verify old apps matching prefix are deleted."""
        with patch('boto3.client'):
            import auth0_cleanup as ac

            old_date = '2024-01-01T00:00:00Z'
            mock_clients = [
                {'client_id': 'c1', 'name': 'QURL Developer - playwright-test1',
                 'created_at': old_date},
                {'client_id': 'c2', 'name': 'QURL Developer - playwright-test2',
                 'created_at': old_date},
            ]

            with patch('auth0_cleanup._list_clients', return_value=mock_clients), \
                 patch('auth0_cleanup._delete_client') as mock_delete, \
                 patch('auth0_cleanup.time.sleep'):
                result = ac.cleanup_orphaned_apps()

            assert result == 2
            assert mock_delete.call_count == 2
            mock_delete.assert_any_call('test-mgmt-token', 'c1')
            mock_delete.assert_any_call('test-mgmt-token', 'c2')

    def test_skips_non_matching_apps(self, mock_mgmt_token):
        """Verify apps not matching prefix are skipped."""
        with patch('boto3.client'):
            import auth0_cleanup as ac

            mock_clients = [
                {'client_id': 'c1', 'name': 'QURL Developer - real-user@example.com',
                 'created_at': '2024-01-01T00:00:00Z'},
                {'client_id': 'c2', 'name': 'Some Other App',
                 'created_at': '2024-01-01T00:00:00Z'},
            ]

            with patch('auth0_cleanup._list_clients', return_value=mock_clients), \
                 patch('auth0_cleanup._delete_client') as mock_delete:
                result = ac.cleanup_orphaned_apps()

            assert result == 0
            mock_delete.assert_not_called()

    def test_skips_recent_apps(self, mock_mgmt_token):
        """Verify apps newer than MAX_AGE_HOURS are skipped."""
        with patch('boto3.client'):
            import auth0_cleanup as ac

            recent_date = '2099-01-01T00:00:00Z'  # Far future = recent
            mock_clients = [
                {'client_id': 'c1', 'name': 'QURL Developer - playwright-test1',
                 'created_at': recent_date},
            ]

            with patch('auth0_cleanup._list_clients', return_value=mock_clients), \
                 patch('auth0_cleanup._delete_client') as mock_delete:
                result = ac.cleanup_orphaned_apps()

            assert result == 0
            mock_delete.assert_not_called()

    def test_skips_apps_without_created_at(self, mock_mgmt_token):
        """Verify apps missing created_at are skipped with warning."""
        with patch('boto3.client'):
            import auth0_cleanup as ac

            mock_clients = [
                {'client_id': 'c1', 'name': 'QURL Developer - playwright-test1'},
            ]

            with patch('auth0_cleanup._list_clients', return_value=mock_clients), \
                 patch('auth0_cleanup._delete_client') as mock_delete:
                result = ac.cleanup_orphaned_apps()

            assert result == 0
            mock_delete.assert_not_called()

    def test_pagination(self, mock_mgmt_token):
        """Verify cleanup paginates through all pages."""
        with patch('boto3.client'):
            import auth0_cleanup as ac

            old_date = '2024-01-01T00:00:00Z'
            # First page: full (100 items), second page: partial (1 item)
            page1 = [{'client_id': f'c{i}', 'name': f'QURL Developer - playwright-{i}',
                       'created_at': old_date} for i in range(100)]
            page2 = [{'client_id': 'c100', 'name': 'QURL Developer - playwright-100',
                       'created_at': old_date}]

            with patch('auth0_cleanup._list_clients', side_effect=[page1, page2]) as mock_list, \
                 patch('auth0_cleanup._delete_client'), \
                 patch('auth0_cleanup.time.sleep'):
                result = ac.cleanup_orphaned_apps()

            assert result == 101
            assert mock_list.call_count == 2

    def test_empty_tenant(self, mock_mgmt_token):
        """Verify no errors on empty tenant."""
        with patch('boto3.client'):
            import auth0_cleanup as ac

            with patch('auth0_cleanup._list_clients', return_value=[]):
                result = ac.cleanup_orphaned_apps()

            assert result == 0

    def test_throttles_between_deletes(self, mock_mgmt_token):
        """Verify time.sleep is called between deletions."""
        with patch('boto3.client'):
            import auth0_cleanup as ac

            old_date = '2024-01-01T00:00:00Z'
            mock_clients = [
                {'client_id': 'c1', 'name': 'QURL Developer - playwright-1',
                 'created_at': old_date},
                {'client_id': 'c2', 'name': 'QURL Developer - playwright-2',
                 'created_at': old_date},
            ]

            with patch('auth0_cleanup._list_clients', return_value=mock_clients), \
                 patch('auth0_cleanup._delete_client'), \
                 patch('auth0_cleanup.time.sleep') as mock_sleep:
                ac.cleanup_orphaned_apps()

            assert mock_sleep.call_count == 2
            mock_sleep.assert_called_with(0.2)


# ---------------------------------------------------------------------------
# Delete Client Tests (429 retry)
# ---------------------------------------------------------------------------

class TestDeleteClient:
    """Tests for _delete_client() with retry behavior."""

    def test_successful_delete(self):
        """Verify successful deletion."""
        with patch('boto3.client'):
            import auth0_cleanup as ac

            mock_resp = MagicMock()
            mock_resp.read.return_value = b''

            with patch('auth0_cleanup.urllib.request.urlopen', return_value=mock_resp):
                # Should not raise
                ac._delete_client('token', 'client-123')

    def test_404_is_not_error(self):
        """Verify 404 is handled gracefully (already deleted)."""
        with patch('boto3.client'):
            import auth0_cleanup as ac

            error = urllib.error.HTTPError(
                'https://auth.layerv.ai/api/v2/clients/c1',
                404, 'Not Found', {}, None
            )

            with patch('auth0_cleanup.urllib.request.urlopen', side_effect=error):
                # Should not raise
                ac._delete_client('token', 'c1')

    def test_429_retries_with_backoff(self):
        """Verify 429 triggers retry with exponential backoff."""
        with patch('boto3.client'):
            import auth0_cleanup as ac

            error_429 = urllib.error.HTTPError(
                'https://auth.layerv.ai/api/v2/clients/c1',
                429, 'Too Many Requests', {}, None
            )

            mock_resp = MagicMock()
            mock_resp.read.return_value = b''

            with patch('auth0_cleanup.urllib.request.urlopen',
                       side_effect=[error_429, mock_resp]) as mock_urlopen, \
                 patch('auth0_cleanup.time.sleep') as mock_sleep:
                ac._delete_client('token', 'c1')

            assert mock_urlopen.call_count == 2
            mock_sleep.assert_called_once_with(1)  # 2^0 = 1

    def test_429_exhausts_retries(self):
        """Verify 429 raises after max retries."""
        with patch('boto3.client'):
            import auth0_cleanup as ac

            error_429 = urllib.error.HTTPError(
                'https://auth.layerv.ai/api/v2/clients/c1',
                429, 'Too Many Requests', {}, None
            )

            with patch('auth0_cleanup.urllib.request.urlopen', side_effect=error_429), \
                 patch('auth0_cleanup.time.sleep'):
                with pytest.raises(urllib.error.HTTPError):
                    ac._delete_client('token', 'c1', max_retries=3)

    def test_500_raises_immediately(self):
        """Verify non-429 errors raise immediately without retry."""
        with patch('boto3.client'):
            import auth0_cleanup as ac

            error_500 = urllib.error.HTTPError(
                'https://auth.layerv.ai/api/v2/clients/c1',
                500, 'Internal Server Error', {}, None
            )

            with patch('auth0_cleanup.urllib.request.urlopen', side_effect=error_500), \
                 patch('auth0_cleanup.time.sleep') as mock_sleep:
                with pytest.raises(urllib.error.HTTPError):
                    ac._delete_client('token', 'c1')

            mock_sleep.assert_not_called()
