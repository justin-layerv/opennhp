"""
Auth0 Test App Cleanup Lambda

Periodically deletes orphaned Auth0 M2M applications created by integration
tests. Runs on a weekly schedule via CloudWatch Events.

Targets apps matching the name prefix 'QURL Developer - playwright-' that
are older than 24 hours.
"""

import json
import boto3
import logging
import os
import time
import urllib.request
import urllib.error
from datetime import datetime

# JSON logging for CloudWatch Insights
_LOG_BUILTIN_KEYS = {
    'name', 'msg', 'args', 'created', 'filename', 'funcName', 'levelname',
    'levelno', 'lineno', 'module', 'msecs', 'pathname', 'process',
    'processName', 'relativeCreated', 'stack_info', 'thread', 'threadName',
    'exc_info', 'exc_text', 'message', 'asctime', 'taskName',
}


class JSONFormatter(logging.Formatter):
    def format(self, record):
        record.message = record.getMessage()
        log = {
            'level': record.levelname,
            'message': record.message,
            'timestamp': self.formatTime(record),
        }
        for key, val in record.__dict__.items():
            if key not in _LOG_BUILTIN_KEYS:
                log[key] = val
        if record.exc_info and record.exc_info[0]:
            log['exception'] = self.formatException(record.exc_info)
        return json.dumps(log, default=str)


logger = logging.getLogger()
logger.setLevel(logging.INFO)
if logger.handlers:
    logger.handlers[0].setFormatter(JSONFormatter())
else:
    handler = logging.StreamHandler()
    handler.setFormatter(JSONFormatter())
    logger.addHandler(handler)

# Configuration
AUTH0_MGMT_SECRET_NAME = os.environ.get('AUTH0_MGMT_SECRET_NAME', '')
AUTH0_DOMAIN = os.environ.get('AUTH0_DOMAIN', 'auth.layerv.ai')
APP_NAME_PREFIX = os.environ.get('APP_NAME_PREFIX', 'QURL Developer - playwright-')
MAX_AGE_HOURS = int(os.environ.get('MAX_AGE_HOURS', '24'))

# Module-level token cache
_mgmt_token = None
_mgmt_token_expires_at = 0


def lambda_handler(event, context):
    """Main entry point — clean up orphaned Auth0 test apps."""
    logger.info("Starting Auth0 test app cleanup",
                extra={"prefix": APP_NAME_PREFIX, "max_age_hours": MAX_AGE_HOURS})

    try:
        deleted_count = cleanup_orphaned_apps()
        logger.info("Cleanup complete", extra={"deleted_count": deleted_count})
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': f'Deleted {deleted_count} orphaned test apps',
                'deleted_count': deleted_count,
            })
        }
    except Exception as e:
        logger.error("Cleanup failed", exc_info=True, extra={"error": str(e)})
        raise


def cleanup_orphaned_apps():
    """Find and delete Auth0 apps matching the test prefix older than MAX_AGE_HOURS."""
    token = _get_mgmt_token()
    cutoff = time.time() - (MAX_AGE_HOURS * 3600)
    deleted = 0
    page = 0
    per_page = 100

    while True:
        clients = _list_clients(token, page, per_page)
        if not clients:
            break

        for client in clients:
            name = client.get('name', '')
            if not name.startswith(APP_NAME_PREFIX):
                continue

            # Auth0 standard field — always present on client objects
            created_at = client.get('created_at', '')
            if not created_at:
                logger.warning("Skipping client without created_at",
                               extra={"client_id": client.get('client_id')})
                continue

            try:
                created_ts = _parse_iso8601(created_at)
            except ValueError:
                logger.warning("Skipping client with unparseable date",
                               extra={"client_id": client.get('client_id'),
                                      "created_at": created_at})
                continue

            if created_ts < cutoff:
                client_id = client.get('client_id', '')
                logger.info("Deleting orphaned test app",
                            extra={"client_id": client_id, "app_name": name,
                                   "created_at": created_at})
                _delete_client(token, client_id)
                deleted += 1
                # Throttle deletes to avoid Auth0 Management API rate limits
                time.sleep(0.2)

        if len(clients) < per_page:
            break
        page += 1

    return deleted


def _parse_iso8601(date_str):
    """Parse ISO 8601 date string to Unix timestamp."""
    # Handle both 'Z' suffix and '+00:00' formats
    date_str = date_str.replace('Z', '+00:00')
    dt = datetime.fromisoformat(date_str)
    return dt.timestamp()


def _get_mgmt_token():
    """Get Auth0 Management API token (cached across warm invocations)."""
    global _mgmt_token, _mgmt_token_expires_at

    if _mgmt_token and time.time() < _mgmt_token_expires_at:
        return _mgmt_token

    sm = boto3.client('secretsmanager')
    secret = json.loads(
        sm.get_secret_value(SecretId=AUTH0_MGMT_SECRET_NAME)['SecretString']
    )

    missing = [
        k for k in ('client_id', 'client_secret', 'audience') if not secret.get(k)
    ]
    if missing:
        raise RuntimeError(
            f"Auth0 mgmt secret '{AUTH0_MGMT_SECRET_NAME}' missing or empty "
            f"required key(s) {missing}. The secret is written by "
            f"aws_secretsmanager_secret_version.dev_portal_mgmt in "
            f"terraform/modules/auth0, but its lifecycle has "
            f"ignore_changes=[secret_string], so a plain `terraform apply` "
            f"will NOT repopulate it. Repair with one of: "
            f"`terraform apply -replace='module.auth0."
            f"aws_secretsmanager_secret_version.dev_portal_mgmt[0]'`, OR "
            f"`aws secretsmanager put-secret-value --secret-id "
            f"{AUTH0_MGMT_SECRET_NAME} --secret-string ...`."
        )

    # The audience must be `secret['audience']`, not constructed from
    # AUTH0_DOMAIN. Auth0's Management API only accepts the tenant's canonical
    # domain (e.g. layerv.us.auth0.com); the custom login domain
    # (auth.layerv.ai) returns 403 access_denied. Terraform writes the
    # canonical-domain audience into the secret — forward it verbatim.
    payload = json.dumps({
        'client_id': secret['client_id'],
        'client_secret': secret['client_secret'],
        'audience': secret['audience'],
        'grant_type': 'client_credentials',
    }).encode()

    req = urllib.request.Request(
        f'https://{AUTH0_DOMAIN}/oauth/token',
        data=payload,
        headers={'Content-Type': 'application/json'},
        method='POST',
    )

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        # Auth0 returns the actual reason (e.g. access_denied + a specific
        # error_description) in the response body. urllib's default behavior
        # discards it, leaving only "HTTP Error 403: Forbidden" — useless for
        # diagnosing IP throttling, bot detection, grant revocation, etc.
        body = ''
        try:
            body = e.read().decode('utf-8', errors='replace')
        except Exception:
            pass
        logger.error(
            'Auth0 token request failed',
            extra={'status': e.code, 'response_body': body[:2000]},
        )
        raise

    _mgmt_token = data['access_token']
    _mgmt_token_expires_at = time.time() + data.get('expires_in', 86400) - 60
    return _mgmt_token


def _list_clients(token, page, per_page):
    """List Auth0 clients (non-interactive apps) with pagination."""
    url = (f'https://{AUTH0_DOMAIN}/api/v2/clients'
           f'?app_type=non_interactive&page={page}&per_page={per_page}'
           f'&fields=client_id,name,created_at,client_metadata')

    req = urllib.request.Request(
        url,
        headers={'Authorization': f'Bearer {token}'},
        method='GET',
    )

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        logger.error("Failed to list clients",
                     extra={"status": e.code, "body": e.read().decode()[:500]})
        raise


def _delete_client(token, client_id, max_retries=3):
    """Delete an Auth0 client by ID with retry on 429."""
    for attempt in range(max_retries):
        req = urllib.request.Request(
            f'https://{AUTH0_DOMAIN}/api/v2/clients/{client_id}',
            headers={'Authorization': f'Bearer {token}'},
            method='DELETE',
        )

        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                resp.read()
            return
        except urllib.error.HTTPError as e:
            if e.code == 404:
                logger.warning("Client already deleted",
                               extra={"client_id": client_id})
                return
            elif e.code == 429 and attempt < max_retries - 1:
                backoff = 2 ** attempt
                logger.warning("Auth0 rate limited, retrying",
                               extra={"client_id": client_id, "backoff": backoff,
                                      "attempt": attempt + 1})
                time.sleep(backoff)
            else:
                logger.error("Failed to delete client",
                             extra={"client_id": client_id, "status": e.code})
                raise
