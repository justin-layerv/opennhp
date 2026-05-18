"""
Custom Domain Certificate Manager Lambda

Manages TLS certificates for customer custom domains using Let's Encrypt
with DNS-01 challenge via CNAME delegation pattern.

Flow:
  0. Lambda re-verifies DNS ownership by checking that _layerv-verify.{domain}
     TXT still matches the verification_token in DynamoDB. This closes the
     TOCTOU gap between the Go service's initial verification (where the
     domain was first registered) and cert issuance here (which may happen
     up to ~15 minutes later).
  1. Customer creates CNAME: _acme-challenge.secure.example.com -> secure--example--com.acme.layerv.xyz
  2. Lambda creates TXT record at secure--example--com.acme.layerv.xyz in our ACME zone
  3. Let's Encrypt follows CNAME, finds TXT, validates domain ownership
  4. Certificate stored in SSM Parameter Store, domain status updated in DynamoDB

Storage strategy:
  - Cert key + chain stored as SecureString params in SSM Parameter Store
  - Metadata (expiry, acme_subdomain) stored as plain String param (no KMS cost)
  - ACME account key stays in Secrets Manager (single secret, no scale issue)

Security considerations:
- Private keys generated in Lambda, never exposed to Terraform state
- Cert secrets encrypted with KMS CMK via SSM SecureString
- Least privilege IAM permissions
- No sensitive data in CloudWatch logs
- DNS ownership re-verified before cert issuance to close TOCTOU gap
- Idempotency lock prevents duplicate cert provisioning on concurrent invocations

Author: LayerV Platform Team
"""

# Heavy crypto/ACME/DNS deps are loaded lazily via lazy_import_*() to keep
# cold start small. Two consequences for static analysis:
#
# 1. The `acme`, `josepy`, `dns.resolver`, and `dns.exception` packages
#    are Lambda-layer-only and not installed in the dev environment, so
#    Pyright reports them as missing imports. We silence reportMissingImports
#    at file level rather than per-line because the imports happen inside
#    helper functions and per-line suppressions would clutter the import
#    sites.
#
# 2. The lazy globals (`acme`, `josepy`, `cryptography`, `dns_resolver`,
#    `dns_exception`) start as `None` and the lazy_import_*() functions
#    set them to real modules before any access. Pyright cannot follow
#    that runtime invariant. reportOptionalMemberAccess and
#    reportOptionalSubscript are silenced at file level for the same
#    reason — every access site would otherwise need an inline ignore,
#    and any new access would need its own ignore. The runtime contract
#    is enforced by the lazy_import_*() helpers, not the type checker.
# pyright: reportMissingImports=false, reportOptionalMemberAccess=false, reportOptionalSubscript=false

import json
import logging
import os
import re
import shlex
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

import boto3
from botocore.exceptions import ClientError

# Configure logging - be careful not to log sensitive data
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Event types (must match EventBridge rule inputs in main.tf)
EVENT_PROVISION = 'provision'
EVENT_RENEWAL_SCAN = 'renewal_scan'
# SNS event_type value used by qurl-service when publishing domain deletions.
# The contract is owned by qurl-service/internal/events/domain_event_publisher.go.
EVENT_DOMAIN_CLEANUP = 'domain.cleanup'

# Domain statuses (must match qurl domain.Status constants)
STATUS_ACTIVE = 'active'
STATUS_FAILED = 'failed'
STATUS_PROVISIONING_TLS = 'provisioning_tls'

# Provision result statuses (returned in Lambda response)
RESULT_PROVISIONED = 'provisioned'
RESULT_SKIPPED = 'skipped'

# Results from handle_domain_cleanup() and _handle_sns_records()
RESULT_CLEANED = 'cleaned'
RESULT_REJECTED = 'rejected'
RESULT_ABORTED = 'aborted'
RESULT_IGNORED = 'ignored'
RESULT_INVALID_PAYLOAD = 'invalid_payload'

# Reasons paired with RESULT_REJECTED / RESULT_ABORTED (returned dict shape).
# REASON_*_UNAVAILABLE are surfaced in TransientCleanupError messages rather
# than as return reasons — those paths raise to drive SNS retry.
REASON_INVALID_DOMAIN = 'invalid_domain'
REASON_RACE_RE_REGISTERED = 'race_re_registered'
REASON_DDB_UNAVAILABLE = 'ddb_unavailable'
REASON_SSM_UNAVAILABLE = 'ssm_unavailable'

# Outcomes from _delete_orphan_domain_row()
DDB_DELETED = 'deleted'
DDB_ABSENT = 'absent'
DDB_RACE = 'race'
DDB_ERROR = 'error'

# Batch sync trigger identifiers (not real domain names). Membership in
# BATCH_SYNCS keeps trigger_cert_sync's full-mode-vs-incremental dispatch
# in sync as new batch modes are added.
#
# Note: cleanup events used to flow through BATCH_SYNC_CLEANUP (full sync per
# event), but #1994 switched them to trigger_cert_delete() — a per-domain
# `--delete <domain>` invocation that avoids a fleet-wide rebuild on every
# domain offboarding. Don't reintroduce a BATCH_SYNC_CLEANUP path without
# revisiting that change.
BATCH_SYNC_RENEWAL = 'renewal-scan-batch'
BATCH_SYNC_PROVISION = 'provision-batch'
BATCH_SYNCS = frozenset({BATCH_SYNC_RENEWAL, BATCH_SYNC_PROVISION})

# Domain name validation
DOMAIN_REGEX = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9.-]{0,251}[a-zA-Z0-9])?$')


class DnsValidationError(Exception):
    """Raised when DNS-01 challenge setup or propagation fails."""
    pass


class TransientCleanupError(Exception):
    """Raised by the cleanup handler when a transient AWS error prevented
    safe completion.

    SNS-to-Lambda async invocations only retry on a raised exception or a
    timeout — a return value (even one with status=aborted) is treated as
    delivered. Wrap the transient-failure paths in this exception so SNS's
    built-in retry kicks in, rather than relying entirely on the
    reconciliation safety net (#1992) as a backstop.
    """
    pass


class DnsOwnershipError(Exception):
    """Raised when DNS ownership re-verification fails before cert issuance.

    This closes the TOCTOU gap between the Go service's initial DNS verification
    and the Lambda's certificate issuance. If DNS ownership cannot be confirmed
    at issuance time, the cert request is rejected.
    """
    pass

# ACME account secret field names (Secrets Manager — single secret, no scale issue)
FIELD_ACCOUNT_KEY = 'account_key'

# SSM Parameter Store metadata field names (stored as JSON in /meta param)
FIELD_EXPIRES_AT = 'expires_at'
FIELD_DOMAIN = 'domain'
FIELD_ACME_SUBDOMAIN = 'acme_subdomain'

# CloudWatch metric constants (must match alarm definitions in main.tf)
CW_NAMESPACE = 'NHP/CustomDomainCerts'
CW_METRIC_DAYS_UNTIL_EXPIRY = 'DaysUntilExpiry'
CW_METRIC_PROVISIONING_FAILURES = 'ProvisioningFailures'

# Failure category constants — published as the FailureCategory dimension on
# the ProvisioningFailures metric so alarms identify the root cause at a glance.
#
#   Category                 Trigger
#   ──────────────────────── ───────────────────────────────────────────────────
#   AcmeAccountError         Secrets Manager access or ACME account registration
#   DnsOwnershipError        DNS ownership re-verification failed before cert issuance
#   DnsValidationError       Route53 TXT record creation or DNS propagation
#   AcmeChallengeError       Let's Encrypt challenge answer or cert finalization
#   CertStorageError         SSM Parameter Store write (key/chain/meta)
#   DynamoDBError            Domain status query or update
#   CertSyncError            SSM SendCommand to AC instances
#   DomainValidationError    Invalid domain format rejected at handler level
#   RenewalScanError         Per-domain failure during renewal scan
#   ProvisioningTimeoutError Domain stuck in provisioning_tls past timeout
#
FAILURE_ACME_ACCOUNT = 'AcmeAccountError'
FAILURE_DNS_OWNERSHIP = 'DnsOwnershipError'
FAILURE_DNS_VALIDATION = 'DnsValidationError'
FAILURE_ACME_CHALLENGE = 'AcmeChallengeError'
FAILURE_CERT_STORAGE = 'CertStorageError'
FAILURE_DYNAMODB = 'DynamoDBError'
FAILURE_CERT_SYNC = 'CertSyncError'
FAILURE_DOMAIN_VALIDATION = 'DomainValidationError'
FAILURE_RENEWAL_SCAN = 'RenewalScanError'
FAILURE_PROVISIONING_TIMEOUT = 'ProvisioningTimeoutError'
FAILURE_SNS_DECODE = 'SnsDecodeError'

# DNS ownership re-verification tunables. Centralized so the resolver
# behaviour is easy to change without hunting through the function body.
#
# DNS_NAMESERVERS — public recursive resolvers used to verify the
#   _layerv-verify TXT record. We deliberately use four independent
#   providers (Google, Cloudflare, Quad9, OpenDNS) so a regional outage
#   at any one of them — including a simultaneous Google + Cloudflare
#   incident, which has happened — doesn't fail certificate provisioning
#   for our customers. dnspython tries them in order until one answers,
#   so the per-resolver order is also a soft preference (Google and
#   Cloudflare have historically had the highest reachability from AWS
#   us-east-2).
# DNS_QUERY_TIMEOUT_SECONDS — per-query timeout. dnspython default is 2s;
#   we allow more headroom because we go to public resolvers over NAT,
#   which is slower than a VPC resolver.
# DNS_QUERY_LIFETIME_SECONDS — total time across all retries. Sized to
#   allow each of the DNS_NAMESERVERS to be tried once with a buffer:
#   len(nameservers) * DNS_QUERY_TIMEOUT_SECONDS. With 4 resolvers and
#   a 5s per-query timeout, the lifetime is 20s.
# DNS_SLOW_WARNING_SECONDS — log a warning when a single resolution takes
#   longer than this. Set just under DNS_QUERY_LIFETIME_SECONDS so
#   legitimate retries don't generate noise, but slow enough that any
#   warning is worth investigating (resolver pathology, NAT saturation).
DNS_NAMESERVERS = [
    '8.8.8.8',         # Google Public DNS
    '1.1.1.1',         # Cloudflare
    '9.9.9.9',         # Quad9
    '208.67.222.222',  # OpenDNS
]
DNS_QUERY_TIMEOUT_SECONDS = 5
DNS_QUERY_LIFETIME_SECONDS = len(DNS_NAMESERVERS) * DNS_QUERY_TIMEOUT_SECONDS
DNS_SLOW_WARNING_SECONDS = DNS_QUERY_LIFETIME_SECONDS - 2

# Lazy imports for cryptography and DNS (Lambda layer)
acme = None
josepy = None
cryptography = None
dns_resolver = None
dns_exception = None


def lazy_import_crypto():
    """Lazy import cryptography libraries to reduce cold start when not needed."""
    global cryptography
    if cryptography is None:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.backends import default_backend

        cryptography = {
            'x509': x509,
            'hashes': hashes,
            'serialization': serialization,
            'rsa': rsa,
            'default_backend': default_backend
        }


def lazy_import_acme():
    """Lazy import ACME/josepy libraries only when cert operations are needed."""
    global acme, josepy
    lazy_import_crypto()
    if acme is None:
        import importlib

        import acme as acme_lib
        import josepy as josepy_lib

        # Force the acme submodules to load so callers can reach them
        # via `acme_lib.client`, `acme_lib.messages`, `acme_lib.challenges`.
        # Plain `import acme` does NOT automatically import submodules,
        # so we use importlib to trigger the side effect without binding
        # any names that static analyzers would flag as unused.
        for _submodule in ('acme.client', 'acme.messages', 'acme.challenges'):
            importlib.import_module(_submodule)

        acme = acme_lib
        josepy = josepy_lib


# Environment variables
ACME_ZONE_ID = os.environ.get('ACME_ZONE_ID')
ACME_ZONE_NAME = os.environ.get('ACME_ZONE_NAME', '')
ACME_ACCOUNT_SECRET_ARN = os.environ.get('ACME_ACCOUNT_SECRET_ARN')
KMS_KEY_ARN = os.environ.get('KMS_KEY_ARN', '') or None
ACME_EMAIL = os.environ.get('ACME_EMAIL')
ACME_DIRECTORY = os.environ.get('ACME_DIRECTORY', 'https://acme-v02.api.letsencrypt.org/directory')
SNS_TOPIC_ARN = os.environ.get('SNS_TOPIC_ARN')
QURL_DOMAINS_TABLE = os.environ.get('QURL_DOMAINS_TABLE')
SSM_CERT_PREFIX = os.environ.get('SSM_CERT_PREFIX', '/nhp/certs')

# Cached ACME client (reused across multiple renewals in a single invocation)
_cached_acme_client = None

# Renewal threshold
RENEWAL_DAYS_BEFORE_EXPIRY = 30

# Auto-fail timeout: domains stuck in provisioning_tls longer than this
# are automatically failed by provision_pending_domains(). Sourced from
# the PROVISIONING_TIMEOUT_MINUTES Lambda environment variable so ops
# can tune it without a code deploy — for example to widen the window
# during a known DNS-propagation incident. Defaults to 30 minutes.
PROVISIONING_TIMEOUT_MINUTES = int(os.environ.get('PROVISIONING_TIMEOUT_MINUTES', '30'))

# Idempotency lock: provisioning_started_at entries older than this are
# considered stale (Lambda crashed or timed out without cleanup) and can
# be overwritten by a new invocation. 30 minutes = 2x the Lambda timeout
# (120s) plus generous buffer for ACME DNS propagation waits. Sourced
# from the PROVISIONING_LOCK_STALE_MINUTES env var, also defaulting to
# 30. The two values are independent so ops can widen one without the
# other if needed (e.g. extend the timeout while keeping the lock
# stale-detection on its existing schedule).
PROVISIONING_LOCK_STALE_MINUTES = int(os.environ.get('PROVISIONING_LOCK_STALE_MINUTES', '30'))


def is_valid_domain(domain: str) -> bool:
    """Validate domain name format. Rejects path traversal, wildcards, and injection."""
    return bool(DOMAIN_REGEX.match(domain)) and '..' not in domain


def domain_to_acme_subdomain(domain: str) -> str:
    """Derive ACME subdomain from a domain name (e.g. 'a.b.com' -> 'a--b--com')."""
    return domain.replace('.', '--')

# AWS clients
secrets_client = boto3.client('secretsmanager')
route53_client = boto3.client('route53')
sns_client = boto3.client('sns')
cloudwatch_client = boto3.client('cloudwatch')
dynamodb_client = boto3.client('dynamodb')
ssm_client = boto3.client('ssm')



def _acquire_provisioning_lock(domain: str) -> bool:
    """Acquire an idempotency lock for cert provisioning via DynamoDB conditional update.

    Uses a conditional write on the ``provisioning_started_at`` attribute to
    guarantee at-most-one concurrent provisioning per domain.  The condition
    succeeds when:

    * The attribute does not exist yet (first attempt), **or**
    * The existing timestamp is older than PROVISIONING_LOCK_STALE_MINUTES
      (previous invocation crashed / timed out without cleanup).

    Returns True if the lock was acquired, False if another invocation already
    holds an active lock for this domain.
    """
    if not QURL_DOMAINS_TABLE:
        logger.warning("No QURL_DOMAINS_TABLE configured, skipping idempotency lock")
        return True

    now = datetime.now(timezone.utc)
    stale_threshold = (now - timedelta(minutes=PROVISIONING_LOCK_STALE_MINUTES)).isoformat()

    try:
        dynamodb_client.update_item(
            TableName=QURL_DOMAINS_TABLE,
            Key={'domain': {'S': domain}},
            UpdateExpression='SET provisioning_started_at = :now',
            # String comparison works because ISO 8601 timestamps are lexicographically sortable.
            ConditionExpression=(
                'attribute_not_exists(provisioning_started_at) '
                'OR provisioning_started_at < :stale'
            ),
            ExpressionAttributeValues={
                ':now': {'S': now.isoformat()},
                ':stale': {'S': stale_threshold},
            },
        )
        logger.info(f"Acquired provisioning lock for {domain}")
        return True
    except ClientError as e:
        if e.response['Error']['Code'] == 'ConditionalCheckFailedException':
            logger.info(
                f"Provisioning lock held by another invocation for {domain}, skipping"
            )
            return False
        logger.error(f"Failed to acquire provisioning lock for {domain}: {e}")
        raise


def _release_provisioning_lock(domain: str):
    """Release the idempotency lock by removing provisioning_started_at.

    Called after successful provisioning so the next scheduled scan does not
    see a stale lock.  Best-effort: failure to release is logged but does not
    block the caller -- the stale-threshold fallback will recover automatically.
    """
    if not QURL_DOMAINS_TABLE:
        return

    try:
        dynamodb_client.update_item(
            TableName=QURL_DOMAINS_TABLE,
            Key={'domain': {'S': domain}},
            UpdateExpression='REMOVE provisioning_started_at',
        )
        logger.info(f"Released provisioning lock for {domain}")
    except Exception as e:
        logger.warning(f"Failed to release provisioning lock for {domain}: {e}")


def handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Lambda handler for custom domain certificate management.

    Event sources:
    - EventBridge (provision / renewal_scan):
      {"type": "provision", "domain": "secure.example.com", "acme_subdomain": "secure--example--com"}
      {"type": "renewal_scan"}
    - SNS (domain.cleanup from qurl-service — see nhp#1990):
      {"Records": [{"EventSource": "aws:sns", "Sns": {"Message": "<json>", "MessageAttributes": {...}}}]}
    """
    del context  # Required by the Lambda contract; not used here.

    if _is_sns_event(event):
        return _handle_sns_records(event)

    try:
        event_type = event.get('type', EVENT_RENEWAL_SCAN)
        logger.info(f"Custom domain cert manager invoked with event type: {event_type}")

        if event_type == EVENT_PROVISION:
            domain = event.get('domain')
            acme_subdomain = event.get('acme_subdomain')
            if not domain or not acme_subdomain:
                raise ValueError("provision event requires 'domain' and 'acme_subdomain' fields")
            # Validate domain format to prevent injection via malformed input
            if not is_valid_domain(domain):
                raise ValueError(f"Invalid domain format: {domain}")
            if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,251}[a-zA-Z0-9])?$', acme_subdomain):
                raise ValueError(f"Invalid acme_subdomain format: {acme_subdomain}")
            return provision_certificate(domain, acme_subdomain)
        elif event_type == EVENT_RENEWAL_SCAN:
            results = renewal_scan()
            results['pending'] = provision_pending_domains()
            return results
        else:
            raise ValueError(f"Unknown event type: {event_type}")

    except (DnsValidationError, DnsOwnershipError):
        # Already metricked in provision_certificate()
        raise
    except ValueError as e:
        logger.error(f"Custom domain cert manager validation failed: {str(e)}", exc_info=True)
        send_alert(f"Custom domain cert manager FAILED: {str(e)}")
        publish_failure_metric(FAILURE_DOMAIN_VALIDATION)
        raise
    except Exception as e:
        logger.error(f"Custom domain cert manager failed: {str(e)}", exc_info=True)
        send_alert(f"Custom domain cert manager FAILED: {str(e)}")
        publish_failure_metric()
        raise


def _is_sns_event(event: Dict[str, Any]) -> bool:
    records = event.get('Records')
    if not isinstance(records, list) or not records:
        return False
    first = records[0]
    return isinstance(first, dict) and first.get('EventSource') == 'aws:sns'


def _handle_sns_records(event: Dict[str, Any]) -> Dict[str, Any]:
    """Dispatch each SNS Record to its event handler.

    SNS→Lambda delivers Records[] (currently always length 1, but the API
    permits batching). The dispatcher tolerates batches in three distinct
    ways:
      - Malformed payload (terminal): logged + metricked + per-record
        `invalid_payload` result. Doesn't poison the batch.
      - Unknown event_type (terminal): per-record `ignored` result.
      - TransientCleanupError (retryable): aggregated and re-raised after
        every other record gets a chance to run. SNS retries the whole
        batch — terminal results from this run will be re-processed
        idempotently on retry, but transient records get another shot.
    """
    results = []
    pending_transient = None
    for record in event.get('Records') or []:
        if not isinstance(record, dict):
            logger.warning(f"Skipping non-dict SNS record: {type(record).__name__}")
            continue
        sns = record.get('Sns') or {}
        msg_attrs = sns.get('MessageAttributes') or {}
        event_type = (msg_attrs.get('event_type') or {}).get('Value', '')

        if event_type != EVENT_DOMAIN_CLEANUP:
            logger.warning(f"Unrecognized SNS event_type: {event_type!r}; ignoring")
            results.append({'status': RESULT_IGNORED, 'event_type': event_type})
            continue

        try:
            payload = json.loads(sns.get('Message') or '')
        except (json.JSONDecodeError, TypeError) as e:
            logger.error(f"Failed to parse cleanup event SNS message: {e}")
            publish_failure_metric(FAILURE_SNS_DECODE)
            results.append({'status': RESULT_INVALID_PAYLOAD})
            continue

        try:
            results.append(handle_domain_cleanup(payload))
        except TransientCleanupError as e:
            # Don't short-circuit the batch — let later records run, then
            # re-raise so SNS retries. Capture the first error to surface.
            logger.warning(f"Transient cleanup error on batch record: {e}")
            results.append({'status': RESULT_ABORTED, 'reason': REASON_DDB_UNAVAILABLE})
            if pending_transient is None:
                pending_transient = e

    if pending_transient is not None:
        raise pending_transient
    return {'records': results}


def _txt_rdata_to_string(rdata: Any) -> str:
    """Decode a dnspython TXT rdata into a single string.

    TXT records can contain multiple character-strings concatenated. dnspython
    exposes them via ``rdata.strings`` (a tuple of bytes objects). Joining the
    strings without a separator matches RFC 7208 / RFC 1035 semantics. Falls
    back to ``str(rdata)`` (with quote stripping) only if the ``strings``
    attribute is unavailable, e.g. when a unit test passes a MagicMock.
    """
    strings = getattr(rdata, 'strings', None)
    if strings:
        try:
            decoded = b''.join(strings).decode('utf-8', errors='replace')
        except (TypeError, AttributeError, UnicodeDecodeError):
            # TypeError/AttributeError: rdata.strings was not a tuple of
            #   bytes-like objects (corrupted record or unexpected mock).
            # UnicodeDecodeError: shouldn't fire because errors='replace',
            #   but listed defensively in case the underlying codec changes.
            # Anything else means a bug — let it propagate so we notice.
            return str(rdata).strip('"')
        # Surface the case where errors='replace' actually replaced
        # something. The Unicode REPLACEMENT CHARACTER (U+FFFD) appearing
        # in a TXT record means the customer's DNS provider stored binary
        # garbage in the record — usually a copy-paste error. Logging it
        # at WARNING level lets support point at the cause without having
        # to reproduce the failure locally.
        if '\ufffd' in decoded:
            logger.warning(
                "TXT record contained invalid UTF-8 bytes; replacement "
                "characters substituted (decoded value: %r)",
                decoded,
            )
        return decoded
    return str(rdata).strip('"')


def verify_dns_ownership(domain: str) -> None:
    """Re-verify DNS ownership before certificate issuance (TOCTOU mitigation).

    Resolves _layerv-verify.{domain} TXT record and confirms it still matches
    the verification_token stored in the qurl-domains DynamoDB table. This
    closes the time-of-check-time-of-use gap between the Go service's initial
    DNS verification and the Lambda's certificate issuance.

    Note: this check runs on **every** call to provision_certificate, including
    renewals scheduled by renewal_scan(). Customers must therefore keep the
    _layerv-verify TXT record in place for the lifetime of the domain — not
    only during initial onboarding. This is an intentional security property:
    if a domain changes hands, the new owner cannot inherit our certificate
    issuance just by leaving the ACME CNAME in place.

    Args:
        domain: The custom domain to verify ownership of.

    Raises:
        DnsOwnershipError: If the TXT record is missing, mismatched, or the
            verification token cannot be retrieved from DynamoDB.
    """
    if not QURL_DOMAINS_TABLE:
        logger.warning("No QURL_DOMAINS_TABLE configured, skipping DNS ownership re-verification")
        return

    # 1. Fetch the expected verification token from DynamoDB.
    # Use ConsistentRead so we never race against an in-flight Update from the
    # Go service that just rotated the token (e.g. operator-initiated reset).
    try:
        response = dynamodb_client.get_item(
            TableName=QURL_DOMAINS_TABLE,
            Key={'domain': {'S': domain}},
            ProjectionExpression='verification_token',
            ConsistentRead=True,
        )
    except ClientError as e:
        # Surface the AWS error code in logs but keep the customer-visible
        # error message generic so we never leak account/table identifiers.
        error_code = e.response.get('Error', {}).get('Code', 'Unknown')
        logger.error(
            f"DynamoDB GetItem failed during DNS ownership re-verification for {domain}: "
            f"code={error_code} err={e}"
        )
        raise DnsOwnershipError(
            f"Failed to fetch verification token from DynamoDB for {domain} "
            f"(code={error_code})"
        ) from e

    item = response.get('Item')
    if not item:
        raise DnsOwnershipError(
            f"Domain {domain} not found in DynamoDB during DNS ownership re-verification"
        )

    # Distinguish "attribute was never written" from "attribute exists but
    # is empty." The first state should be impossible for any domain that
    # went through the Go service's registration handler — it indicates
    # corruption, a manual table edit, or a legacy row that pre-dates the
    # verification_token column. The second state is a stronger signal of
    # active tampering (someone cleared the value). Operators get distinct
    # error messages so they can choose the right incident response.
    token_attr = item.get('verification_token')
    if token_attr is None:
        raise DnsOwnershipError(
            f"verification_token attribute missing for {domain} in DynamoDB "
            f"(legacy row or corrupted state)"
        )
    expected_token = token_attr.get('S', '') if isinstance(token_attr, dict) else ''
    if not expected_token:
        raise DnsOwnershipError(
            f"verification_token stored for {domain} in DynamoDB is empty "
            f"(possible tampering — investigate)"
        )

    # 2. Resolve _layerv-verify.{domain} TXT record via public DNS.
    # We deliberately bypass the VPC resolver here to mirror the path Let's
    # Encrypt itself uses (public recursive resolvers) — anything reachable
    # only from inside our VPC would be a false positive. Timeout values
    # are module-level constants (DNS_QUERY_TIMEOUT_SECONDS / _LIFETIME /
    # _SLOW_WARNING) so they're easy to tune without hunting through the
    # function body.
    lazy_import_dns()
    verify_name = f"_layerv-verify.{domain}"
    res = dns_resolver.Resolver()
    res.nameservers = list(DNS_NAMESERVERS)
    res.timeout = DNS_QUERY_TIMEOUT_SECONDS
    res.lifetime = DNS_QUERY_LIFETIME_SECONDS

    resolve_started = time.monotonic()
    try:
        answers = res.resolve(verify_name, 'TXT')
    except dns_resolver.NXDOMAIN as e:
        raise DnsOwnershipError(
            f"DNS ownership check failed for {domain}: "
            f"{verify_name} does not exist (NXDOMAIN)"
        ) from e
    except dns_resolver.NoAnswer as e:
        raise DnsOwnershipError(
            f"DNS ownership check failed for {domain}: "
            f"{verify_name} has no TXT records"
        ) from e
    except dns_exception.Timeout as e:
        raise DnsOwnershipError(
            f"DNS ownership check failed for {domain}: "
            f"timed out resolving {verify_name} TXT record"
        ) from e
    except dns_exception.DNSException as e:
        # Catch-all for other dnspython errors (NoNameservers, ServFail, etc).
        raise DnsOwnershipError(
            f"DNS ownership check failed for {domain}: "
            f"could not resolve {verify_name} TXT record: {type(e).__name__}"
        ) from e
    finally:
        elapsed = time.monotonic() - resolve_started
        # Warn close to the lifetime budget rather than at the per-query
        # timeout: legitimate retries can run a few seconds without indicating
        # a real problem, but anything beyond DNS_SLOW_WARNING_SECONDS is
        # approaching the lifetime ceiling and is worth surfacing in
        # CloudWatch.
        if elapsed > DNS_SLOW_WARNING_SECONDS:
            logger.warning(
                f"Slow DNS ownership resolution for {domain}: {elapsed:.1f}s "
                f"(threshold {DNS_SLOW_WARNING_SECONDS}s, lifetime {DNS_QUERY_LIFETIME_SECONDS}s)"
            )

    # 3. Compare resolved TXT value against expected token.
    #
    # Comparison is byte-for-byte case-sensitive on purpose. The Go service
    # generates verification tokens via crypto/rand and base64-url-encodes
    # them, so the alphabet is mixed case. A case-insensitive compare here
    # would let an attacker who guessed (or partially observed) a token
    # bypass verification by toggling case. The cost of strict matching is
    # zero — legitimate clients echo the token verbatim into the TXT record.
    expected_ttl = getattr(answers.rrset, 'ttl', None) if getattr(answers, 'rrset', None) else None
    for rdata in answers:
        txt_value = _txt_rdata_to_string(rdata)
        if txt_value == expected_token:
            # Log the TTL on success too: operators tracking cache behaviour
            # during normal operations want to see the same field they see
            # on the failure path, not have to dig it out of CloudTrail.
            logger.info(
                f"DNS ownership re-verified for {domain} (TTL: {expected_ttl})"
            )
            return

    # Collect what we found for the error message. expected_ttl was already
    # computed above so the operator sees the same value regardless of
    # whether the comparison succeeded or failed; the TTL helps distinguish
    # a slow-propagating cache (high TTL) from an actively-removed record.
    found_values = [_txt_rdata_to_string(rdata) for rdata in answers]
    if not found_values:
        # dnspython usually raises NoAnswer for an empty TXT rrset, but the
        # contract on `resolve()` does not strictly guarantee it — be explicit
        # so the operator-facing error doesn't say "Found: []" without
        # explanation.
        raise DnsOwnershipError(
            f"DNS ownership check failed for {domain}: "
            f"no TXT values returned for _layerv-verify (TTL: {expected_ttl})"
        )
    raise DnsOwnershipError(
        f"DNS ownership check failed for {domain}: "
        f"_layerv-verify TXT record does not match verification token. "
        f"Found: {found_values} (TTL: {expected_ttl})"
    )


def provision_certificate(domain: str, acme_subdomain: str, skip_sync: bool = False) -> Dict[str, Any]:
    """
    Provision a new TLS certificate for a custom domain.

    Acquires an idempotency lock (DynamoDB conditional write) before starting
    ACME operations to prevent duplicate cert provisioning when the Lambda is
    invoked concurrently for the same domain.

    Args:
        domain: The custom domain (e.g., "secure.example.com")
        acme_subdomain: The subdomain in our ACME zone for the TXT record
                        (e.g., "secure--example--com")
        skip_sync: If True, skip triggering cert sync (caller will batch it)

    Returns:
        Status dict with provisioning outcome
    """
    logger.info(f"Provisioning certificate for domain: {domain}")

    if not _acquire_provisioning_lock(domain):
        logger.info(f"Skipping {domain}: another invocation is already provisioning")
        return {
            'status': RESULT_SKIPPED,
            'domain': domain,
            'reason': 'concurrent provisioning in progress',
        }

    # Start with DNS ownership as the default failure category since the
    # re-verification below is the first fallible step. Once DNS ownership
    # is confirmed, we transition to FAILURE_ACME_ACCOUNT for ACME/issuance
    # failures downstream.
    failure_category = FAILURE_DNS_OWNERSHIP
    try:
        # Re-verify DNS ownership before proceeding (closes TOCTOU gap).
        # This confirms that _layerv-verify.{domain} TXT still matches the
        # token in DynamoDB, preventing cert issuance if DNS changed since
        # the Go service's initial verification.
        verify_dns_ownership(domain)

        failure_category = FAILURE_ACME_ACCOUNT
        lazy_import_acme()

        # Generate new RSA 4096 private key
        private_key = cryptography['rsa'].generate_private_key(
            public_exponent=65537,
            key_size=4096,
            backend=cryptography['default_backend']()
        )

        # Get or create ACME account
        acme_client = get_or_create_acme_account()

        # Request certificate via DNS-01 with CNAME delegation
        failure_category = FAILURE_ACME_CHALLENGE
        cert_pem, chain_pem = request_certificate(acme_client, private_key, domain, acme_subdomain)

        # Serialize private key
        private_key_pem = private_key.private_bytes(
            encoding=cryptography['serialization'].Encoding.PEM,
            format=cryptography['serialization'].PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=cryptography['serialization'].NoEncryption()
        ).decode('utf-8')

        # Parse certificate expiry
        cert = cryptography['x509'].load_pem_x509_certificate(
            cert_pem.encode(),
            cryptography['default_backend']()
        )
        expires_at = cert.not_valid_after_utc.isoformat()

        # Store certificate in SSM Parameter Store
        failure_category = FAILURE_CERT_STORAGE
        cert_param_prefix = store_certificate(domain, private_key_pem, cert_pem, chain_pem, expires_at, acme_subdomain)

        # Update DynamoDB domain status
        failure_category = FAILURE_DYNAMODB
        update_domain_status(domain, STATUS_ACTIVE, cert_param_prefix, expires_at)

        # Trigger cert sync on AC instances (unless caller will batch it)
        failure_category = FAILURE_CERT_SYNC
        if not skip_sync:
            trigger_cert_sync(domain)

        # Release the idempotency lock now that provisioning succeeded
        _release_provisioning_lock(domain)

        logger.info(f"Certificate provisioned successfully for {domain}, expires: {expires_at}")
        send_alert(f"Certificate provisioned for {domain}. Expires: {expires_at}", is_error=False)

        return {
            'status': RESULT_PROVISIONED,
            'domain': domain,
            'expires_at': expires_at,
            'cert_param_prefix': cert_param_prefix
        }

    except DnsOwnershipError as e:
        logger.error(f"DNS ownership re-verification failed for {domain}: {str(e)}", exc_info=True)
        update_domain_status(domain, STATUS_FAILED, error=str(e))
        send_alert(f"Certificate provisioning BLOCKED for {domain}: {str(e)}")
        publish_failure_metric(FAILURE_DNS_OWNERSHIP)
        _release_provisioning_lock(domain)
        raise
    except DnsValidationError as e:
        logger.error(f"Certificate provisioning failed for {domain}: {str(e)}", exc_info=True)
        update_domain_status(domain, STATUS_FAILED, error=str(e))
        send_alert(f"Certificate provisioning FAILED for {domain}: {str(e)}")
        publish_failure_metric(FAILURE_DNS_VALIDATION)
        _release_provisioning_lock(domain)
        raise
    except Exception as e:
        logger.error(f"Certificate provisioning failed for {domain}: {str(e)}", exc_info=True)
        update_domain_status(domain, STATUS_FAILED, error=str(e))
        send_alert(f"Certificate provisioning FAILED for {domain}: {str(e)}")
        publish_failure_metric(failure_category)
        _release_provisioning_lock(domain)
        raise


def renewal_scan() -> Dict[str, Any]:
    """
    Scan all custom domain certificates and renew those approaching expiry.

    Reads only /meta params (plain String, no KMS decryption) to check expiry.
    Only decrypts key+chain for domains that actually need renewal.

    Returns:
        Status dict with scan results
    """
    logger.info("Starting renewal scan for custom domain certificates")

    results = {
        'scanned': 0,
        'renewed': 0,
        'failed': 0,
        'skipped': 0,
        'details': []
    }

    # List all /meta params (non-encrypted) to check expiry without KMS cost
    meta_params = list_cert_meta_params()
    results['scanned'] = len(meta_params)
    expiry_metrics = []  # Batch metrics for a single put_metric_data call

    # Pre-compute prefix depth for domain extraction (constant across all params)
    prefix_depth = len(SSM_CERT_PREFIX.strip('/').split('/')) + 1

    for param in meta_params:
        param_name = param['Name']
        # Extract domain from param name: /nhp/certs/example.com/meta -> example.com
        parts = param_name.split('/')
        domain = '/'.join(parts[prefix_depth:-1])

        if not domain:
            logger.warning(f"Could not extract domain from param {param_name}, skipping")
            results['skipped'] += 1
            continue

        try:
            meta_data = json.loads(param['Value'])

            expires_at_str = meta_data.get(FIELD_EXPIRES_AT)
            if not expires_at_str:
                logger.warning(f"No {FIELD_EXPIRES_AT} in meta for {domain}, skipping")
                results['skipped'] += 1
                continue

            expires_at = datetime.fromisoformat(expires_at_str)
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)

            now = datetime.now(timezone.utc)
            days_until_expiry = (expires_at - now).days

            # Collect metric for batched publish
            expiry_metrics.append({
                'MetricName': CW_METRIC_DAYS_UNTIL_EXPIRY,
                'Dimensions': [{'Name': 'Domain', 'Value': domain}],
                'Value': days_until_expiry,
                'Unit': 'Count'
            })

            if days_until_expiry <= RENEWAL_DAYS_BEFORE_EXPIRY:
                logger.info(f"Certificate for {domain} expires in {days_until_expiry} days, renewing")
                acme_subdomain = meta_data.get(FIELD_ACME_SUBDOMAIN)
                if not acme_subdomain:
                    logger.warning(f"Meta for {domain} missing '{FIELD_ACME_SUBDOMAIN}' field, deriving from domain name")
                    acme_subdomain = domain_to_acme_subdomain(domain)

                result = provision_certificate(domain, acme_subdomain, skip_sync=True)
                if result.get('status') == RESULT_SKIPPED:
                    results['skipped'] += 1
                    results['details'].append({
                        'domain': domain,
                        'action': 'skipped_locked',
                        'days_until_expiry': days_until_expiry
                    })
                else:
                    results['renewed'] += 1
                    results['details'].append({
                        'domain': domain,
                        'action': 'renewed',
                        'days_until_expiry': days_until_expiry
                    })
            else:
                logger.info(f"Certificate for {domain} valid for {days_until_expiry} more days")
                results['skipped'] += 1
                results['details'].append({
                    'domain': domain,
                    'action': 'skipped',
                    'days_until_expiry': days_until_expiry
                })

        except Exception as e:
            logger.error(f"Failed to process certificate for {domain}: {str(e)}", exc_info=True)
            publish_failure_metric(FAILURE_RENEWAL_SCAN)
            results['failed'] += 1
            results['details'].append({
                'domain': domain,
                'action': 'failed',
                'error': str(e)
            })

    # Publish all expiry metrics in batches (max 1000 per API call)
    if expiry_metrics:
        try:
            for i in range(0, len(expiry_metrics), 1000):
                batch = expiry_metrics[i:i + 1000]
                cloudwatch_client.put_metric_data(
                    Namespace=CW_NAMESPACE,
                    MetricData=batch,
                )
            logger.info(f"Published {len(expiry_metrics)} expiry metrics")
        except Exception as e:
            logger.error(f"Failed to publish batched expiry metrics: {e}")

    # Trigger a single cert sync after all renewals (instead of per-domain)
    if results['renewed'] > 0:
        logger.info(f"Triggering cert sync after {results['renewed']} renewal(s)")
        trigger_cert_sync(BATCH_SYNC_RENEWAL)

    logger.info(f"Renewal scan complete: {results['scanned']} scanned, "
                f"{results['renewed']} renewed, {results['failed']} failed, "
                f"{results['skipped']} skipped")

    if results['failed'] > 0:
        send_alert(f"Renewal scan completed with {results['failed']} failure(s)")

    return results


def list_cert_meta_params() -> list:
    """List all /meta SSM parameters under the cert prefix.

    Only fetches /meta params (plain String type, no decryption needed).
    Used by renewal_scan to check expiry without KMS cost.
    """
    params = []
    paginator = ssm_client.get_paginator('get_parameters_by_path')

    for page in paginator.paginate(
        Path=f"{SSM_CERT_PREFIX}/",
        Recursive=True,
        WithDecryption=False,  # /meta params are String type, no decryption needed
    ):
        for param in page.get('Parameters', []):
            if param['Name'].endswith('/meta'):
                params.append(param)

    logger.info(f"Found {len(params)} custom domain certificate meta params")
    return params


def provision_pending_domains() -> Dict[str, Any]:
    """Provision certs for domains in 'provisioning_tls' status.

    Called alongside renewal_scan on every EventBridge trigger (every 15 min).
    Queries DynamoDB for domains awaiting cert provisioning and provisions
    each one. Triggers a single full cert sync after all provisioning.

    Domains stuck in provisioning_tls longer than PROVISIONING_TIMEOUT_MINUTES
    are auto-failed (status -> 'failed') with an alert and metric emission.

    Requires a GSI named 'status-index' on the qurl-domains DynamoDB table
    with partition key 'status' (String). This GSI is defined in the nhp
    repo's DynamoDB module (terraform/modules/dynamodb/main.tf).
    """
    if not QURL_DOMAINS_TABLE:
        return {'provisioned': 0, 'failed': 0, 'timed_out': 0, 'skipped': 0}

    try:
        items = []
        query_kwargs = {
            'TableName': QURL_DOMAINS_TABLE,
            'IndexName': 'status-index',
            'KeyConditionExpression': '#s = :status',
            'ExpressionAttributeNames': {'#s': 'status'},
            'ExpressionAttributeValues': {':status': {'S': STATUS_PROVISIONING_TLS}},
        }
        while True:
            response = dynamodb_client.query(**query_kwargs)
            items.extend(response.get('Items', []))
            last_key = response.get('LastEvaluatedKey')
            if not last_key:
                break
            query_kwargs['ExclusiveStartKey'] = last_key
    except Exception as e:
        logger.error(f"Failed to query pending domains: {e}")
        publish_failure_metric(FAILURE_DYNAMODB)
        return {'provisioned': 0, 'failed': 0, 'timed_out': 0, 'skipped': 0, 'error': str(e)}

    if not items:
        logger.info("No domains pending TLS provisioning")
        return {'provisioned': 0, 'failed': 0, 'timed_out': 0, 'skipped': 0}

    logger.info(f"Found {len(items)} domains pending TLS provisioning")
    provisioned = 0
    failed = 0
    timed_out_domains: List[str] = []
    skipped = 0
    now = datetime.now(timezone.utc)

    for item in items:
        domain_name = item['domain']['S']
        if not is_valid_domain(domain_name):
            # Invalid domain rows can never succeed; mark them failed so they
            # leave the provisioning_tls partition and stop being scanned.
            # update_domain_status() catches its own exceptions internally,
            # so a DynamoDB failure here will be logged but not raised.
            logger.warning(f"Auto-failing invalid domain from DynamoDB: {domain_name}")
            update_domain_status(
                domain_name,
                STATUS_FAILED,
                error="Domain failed format validation in cert manager",
            )
            publish_failure_metric(FAILURE_DOMAIN_VALIDATION)
            failed += 1
            continue

        started_at_str = item.get('provisioning_started_at', {}).get('S')
        timeout_check = _check_provisioning_timeout(domain_name, started_at_str, now)
        if timeout_check is not None:
            customer_reason, operator_reason = timeout_check
            # customer_reason → DynamoDB → dashboard. Plain English, actionable.
            update_domain_status(domain_name, STATUS_FAILED, error=customer_reason)
            publish_failure_metric(FAILURE_PROVISIONING_TIMEOUT)
            # operator_reason → SNS alert. Carries elapsed time / threshold /
            # started_at timestamp for on-call triage.
            send_alert(f"Domain {domain_name} auto-failed: {operator_reason}")
            timed_out_domains.append(domain_name)
            continue

        acme_subdomain = domain_to_acme_subdomain(domain_name)
        # NOTE: We intentionally do NOT pre-write provisioning_started_at here.
        # _acquire_provisioning_lock() inside provision_certificate() performs the
        # timestamped conditional write that *both* enforces concurrency control
        # and starts the timeout clock used by the auto-fail check above. Writing
        # the attribute before calling the lock would defeat the conditional and
        # cause every invocation to be skipped.
        try:
            result = provision_certificate(domain_name, acme_subdomain, skip_sync=True)
            if result.get('status') == RESULT_SKIPPED:
                logger.info(f"Skipped {domain_name}: {result.get('reason', 'unknown')}")
                skipped += 1
            else:
                provisioned += 1
        except Exception as e:
            logger.error(f"Failed to provision {domain_name}: {e}")
            failed += 1

    if provisioned > 0:
        logger.info(f"Triggering cert sync after provisioning {provisioned} domain(s)")
        trigger_cert_sync(BATCH_SYNC_PROVISION)

    timed_out = len(timed_out_domains)
    if timed_out > 0:
        logger.warning(
            f"Auto-failed {timed_out} domain(s) stuck in provisioning_tls past timeout: "
            f"{', '.join(timed_out_domains)}"
        )

    return {'provisioned': provisioned, 'failed': failed, 'timed_out': timed_out, 'skipped': skipped}


def _check_provisioning_timeout(
    domain_name: str,
    started_at_str: Optional[str],
    now: datetime,
) -> Optional[Tuple[str, str]]:
    """Return (customer_reason, operator_reason) if the domain has exceeded
    the provisioning timeout, otherwise None.

    Two strings are returned because they go to two different places:

    - customer_reason is written to DynamoDB as `failure_reason` and is what
      the customer sees in the dashboard. It must be plain English with an
      actionable next step and zero implementation details (no ISO timestamps,
      no thresholds, no internal jargon).
    - operator_reason is logged at WARNING and included in the SNS alert.
      It carries the implementation details (elapsed minutes, started_at
      timestamp, threshold) that the on-call needs to triage the incident.

    Malformed/missing timestamps return None so the domain proceeds to a
    normal provisioning attempt.
    """
    if not started_at_str:
        return None
    try:
        started_at = datetime.fromisoformat(started_at_str)
    except (ValueError, TypeError) as e:
        logger.warning(f"Invalid provisioning_started_at for {domain_name}: {e}, proceeding")
        return None
    if started_at.tzinfo is None:
        started_at = started_at.replace(tzinfo=timezone.utc)
    elapsed = now - started_at
    if elapsed <= timedelta(minutes=PROVISIONING_TIMEOUT_MINUTES):
        return None
    elapsed_min = int(elapsed.total_seconds() / 60)
    customer_reason = (
        f"Certificate provisioning didn't complete within {PROVISIONING_TIMEOUT_MINUTES} minutes. "
        f"Check that the DNS records you set up are still in place and try again."
    )
    operator_reason = (
        f"TLS provisioning timed out after {elapsed_min} minutes "
        f"(started_at: {started_at_str}, threshold: {PROVISIONING_TIMEOUT_MINUTES}m)"
    )
    logger.warning(f"Domain {domain_name} stuck in provisioning_tls: {operator_reason}")
    return customer_reason, operator_reason


def get_or_create_acme_account() -> Any:
    """
    Get existing ACME account or create new one.

    Persists the ACME account key in Secrets Manager to avoid creating new accounts
    on each invocation. Let's Encrypt has rate limits on account creation.
    Caches the client for reuse across multiple renewals in a single Lambda invocation.
    """
    global _cached_acme_client
    if _cached_acme_client is not None:
        return _cached_acme_client

    from acme import client, messages

    # Try to load existing account key
    account_key = None
    if ACME_ACCOUNT_SECRET_ARN:
        try:
            response = secrets_client.get_secret_value(SecretId=ACME_ACCOUNT_SECRET_ARN)
            secret_data = json.loads(response['SecretString'])
            account_key_pem = secret_data.get(FIELD_ACCOUNT_KEY)
            if account_key_pem:
                account_key = cryptography['serialization'].load_pem_private_key(
                    account_key_pem.encode(),
                    password=None,
                    backend=cryptography['default_backend']()
                )
                logger.info("Loaded existing ACME account key from Secrets Manager")
        except secrets_client.exceptions.ResourceNotFoundException:
            logger.info("ACME account secret not found, will create new account")
        except Exception as e:
            logger.warning(f"Failed to load ACME account key: {e}, will create new account")

    # Generate new account key if not found
    if account_key is None:
        logger.info("Generating new ACME account key")
        account_key = cryptography['rsa'].generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=cryptography['default_backend']()
        )

    # Wrap key for ACME
    account_key_jose = josepy.JWKRSA(key=account_key)

    # Create ACME client
    network = client.ClientNetwork(account_key_jose, user_agent='LayerV-CustomDomainCert/1.0')
    directory = messages.Directory.from_json(network.get(ACME_DIRECTORY).json())
    acme_client = client.ClientV2(directory, net=network)

    # Register account (or retrieve existing)
    registration = messages.NewRegistration.from_data(
        email=ACME_EMAIL,
        terms_of_service_agreed=True,
        only_return_existing=False
    )

    try:
        account = acme_client.new_account(registration)
        logger.info(f"ACME account registered: {account.uri}")

        # Save the account key for future use
        if ACME_ACCOUNT_SECRET_ARN:
            save_acme_account_key(account_key)
    except acme.errors.ConflictError as e:
        account_uri = str(e)
        logger.info(f"ACME account already exists at: {account_uri}")

        existing_reg = messages.RegistrationResource(
            uri=account_uri,
            body=messages.Registration()
        )
        acme_client.net.account = existing_reg
        account = acme_client.query_registration(existing_reg)
        acme_client.net.account = account
        logger.info(f"Using existing ACME account: {account.uri}")

    _cached_acme_client = acme_client
    return acme_client


def save_acme_account_key(account_key):
    """Save ACME account key to Secrets Manager for reuse across invocations."""
    if not ACME_ACCOUNT_SECRET_ARN:
        return

    try:
        account_key_pem = account_key.private_bytes(
            encoding=cryptography['serialization'].Encoding.PEM,
            format=cryptography['serialization'].PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=cryptography['serialization'].NoEncryption()
        ).decode('utf-8')

        secret_value = {
            FIELD_ACCOUNT_KEY: account_key_pem,
            'email': ACME_EMAIL,
            'created_at': datetime.now(timezone.utc).isoformat()
        }

        secrets_client.put_secret_value(
            SecretId=ACME_ACCOUNT_SECRET_ARN,
            SecretString=json.dumps(secret_value)
        )
        logger.info("Saved ACME account key to Secrets Manager")
    except Exception as e:
        logger.error(f"Failed to save ACME account key: {e}")


def request_certificate(acme_client, private_key, domain: str, acme_subdomain: str) -> Tuple[str, str]:
    """
    Request certificate from ACME server using DNS-01 challenge with CNAME delegation.

    The customer's _acme-challenge.{domain} CNAME points to {acme_subdomain}.{acme_zone}.
    We create the TXT record at {acme_subdomain}.{acme_zone} in our Route53 zone.
    Let's Encrypt follows the CNAME and finds our TXT record.

    Args:
        acme_client: ACME client instance
        private_key: RSA private key for CSR
        domain: The custom domain to issue cert for
        acme_subdomain: Subdomain in our ACME zone for the TXT record

    Returns:
        Tuple of (certificate_pem, chain_pem)
    """
    from acme import challenges
    from cryptography import x509
    from cryptography.x509.oid import NameOID

    logger.info(f"Requesting certificate for domain: {domain}")

    # Create CSR
    csr_builder = x509.CertificateSigningRequestBuilder()
    csr_builder = csr_builder.subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, domain)
    ]))
    csr_builder = csr_builder.add_extension(
        x509.SubjectAlternativeName([x509.DNSName(domain)]),
        critical=False
    )
    csr = csr_builder.sign(private_key, cryptography['hashes'].SHA256(), cryptography['default_backend']())
    csr_pem = csr.public_bytes(cryptography['serialization'].Encoding.PEM)

    # Request new order
    order = acme_client.new_order(csr_pem)

    # Process authorizations
    txt_record_name = f"{acme_subdomain}.{ACME_ZONE_NAME}"

    for auth in order.authorizations:
        auth_domain = auth.body.identifier.value
        logger.info(f"Processing authorization for: {auth_domain}")

        # Find DNS-01 challenge
        dns_challenge = None
        for challenge in auth.body.challenges:
            if isinstance(challenge.chall, challenges.DNS01):
                dns_challenge = challenge
                break

        if not dns_challenge:
            raise ValueError(f"No DNS-01 challenge found for {auth_domain}")

        # Get validation token
        validation = dns_challenge.chall.validation(acme_client.net.key)

        # Create TXT record in our ACME delegation zone
        logger.info(f"Creating TXT record: {txt_record_name}")
        try:
            create_acme_txt_record(txt_record_name, validation)
            wait_for_dns_propagation(txt_record_name, validation)
        except Exception as e:
            raise DnsValidationError(f"DNS validation failed for {domain}: {e}") from e

        # Answer challenge
        acme_client.answer_challenge(dns_challenge, dns_challenge.response(acme_client.net.key))

    # Finalize order
    logger.info("Finalizing certificate order")
    order = acme_client.poll_and_finalize(order)

    # Clean up DNS record
    try:
        delete_acme_txt_record(txt_record_name)
    except Exception as e:
        logger.warning(f"Failed to delete TXT record {txt_record_name}: {e}")

    # Extract certificate and chain
    fullchain = order.fullchain_pem
    certs = fullchain.split('-----END CERTIFICATE-----')
    cert_pem = certs[0] + '-----END CERTIFICATE-----\n'
    chain_pem = '-----END CERTIFICATE-----'.join(certs[1:]).strip()
    if chain_pem and not chain_pem.endswith('\n'):
        chain_pem += '\n'

    logger.info(f"Certificate obtained successfully for {domain}")
    return cert_pem, chain_pem


def create_acme_txt_record(record_name: str, value: str):
    """Create TXT record in the ACME delegation zone for DNS-01 challenge."""
    logger.info(f"Creating DNS TXT record: {record_name}")

    response = route53_client.change_resource_record_sets(
        HostedZoneId=ACME_ZONE_ID,
        ChangeBatch={
            'Changes': [{
                'Action': 'UPSERT',
                'ResourceRecordSet': {
                    'Name': record_name,
                    'Type': 'TXT',
                    'TTL': 60,
                    'ResourceRecords': [{'Value': f'"{value}"'}]
                }
            }]
        }
    )

    # Wait for Route53 change to propagate before checking external DNS
    change_id = response['ChangeInfo']['Id']
    logger.info(f"Waiting for Route53 change {change_id} to propagate...")
    waiter = route53_client.get_waiter('resource_record_sets_changed')
    try:
        waiter.wait(Id=change_id, WaiterConfig={'Delay': 5, 'MaxAttempts': 24})
        logger.info(f"Route53 change {change_id} propagated")
    except Exception as e:
        logger.warning(f"Route53 change waiter timed out: {e}, proceeding anyway")


def delete_acme_txt_record(record_name: str) -> bool:
    """Delete a TXT record from the ACME delegation zone.

    Used both for post-DNS-01-challenge cleanup (the canonical path) and as
    a defensive sweep during domain cleanup events when a TXT may have been
    orphaned by a crashed provisioning. Idempotent — missing records and
    non-TXT records at the same name return False without error.

    Returns True iff a record was actually deleted.
    """
    if not ACME_ZONE_ID:
        return False

    logger.info(f"Deleting DNS TXT record: {record_name}")
    try:
        response = route53_client.list_resource_record_sets(
            HostedZoneId=ACME_ZONE_ID,
            StartRecordName=record_name,
            StartRecordType='TXT',
            MaxItems='1'
        )

        records = response.get('ResourceRecordSets', [])
        # list_resource_record_sets returns records >= the start name in
        # lexical order; without an exact (name, type) match we'd risk
        # deleting a higher record that happens to share a prefix.
        if not records \
                or records[0].get('Name', '').rstrip('.') != record_name.rstrip('.') \
                or records[0].get('Type') != 'TXT':
            logger.info(f"DNS record {record_name} not found, skipping delete")
            return False

        route53_client.change_resource_record_sets(
            HostedZoneId=ACME_ZONE_ID,
            ChangeBatch={
                'Changes': [{
                    'Action': 'DELETE',
                    'ResourceRecordSet': records[0]
                }]
            }
        )
        return True
    except ClientError as e:
        logger.warning(f"Failed to delete DNS record {record_name}: {e}")
        return False


def lazy_import_dns():
    """Lazy import dns.resolver/dns.exception to reduce cold start when DNS checks aren't needed."""
    global dns_resolver, dns_exception
    if dns_resolver is None:
        import dns.resolver as _dns_resolver
        import dns.exception as _dns_exception
        dns_resolver = _dns_resolver
        dns_exception = _dns_exception


def wait_for_dns_propagation(record_name: str, expected_value: str, max_attempts: int = 30, delay: int = 10):
    """Wait for DNS TXT record to propagate."""
    logger.info(f"Waiting for DNS propagation of {record_name}")

    lazy_import_dns()
    res = dns_resolver.Resolver()
    res.nameservers = ['8.8.8.8', '1.1.1.1']

    for attempt in range(max_attempts):
        try:
            answers = res.resolve(record_name, 'TXT')
            for rdata in answers:
                txt_value = str(rdata).strip('"')
                if txt_value == expected_value:
                    logger.info(f"DNS propagation confirmed after {attempt + 1} attempts")
                    return
        except Exception as e:
            logger.debug(f"DNS query attempt {attempt + 1} failed: {e}")

        time.sleep(delay)

    logger.warning(f"Could not confirm DNS propagation after {max_attempts} attempts, proceeding anyway")


def _put_ssm_secure_param(name: str, value: str):
    """Store a SecureString parameter in SSM, optionally encrypted with KMS CMK."""
    put_kwargs = {
        'Name': name,
        'Value': value,
        'Type': 'SecureString',
        'Overwrite': True,
        'Tier': 'Standard',
    }
    if KMS_KEY_ARN:
        put_kwargs['KeyId'] = KMS_KEY_ARN
    ssm_client.put_parameter(**put_kwargs)


def store_certificate(domain: str, private_key_pem: str, cert_pem: str, chain_pem: str,
                      expires_at: str, acme_subdomain: Optional[str] = None) -> str:
    """
    Store certificate in SSM Parameter Store as three parameters.

    - {prefix}/{domain}/key — private key PEM (SecureString)
    - {prefix}/{domain}/chain — fullchain PEM (SecureString)
    - {prefix}/{domain}/meta — JSON metadata (String, no encryption)

    Returns:
        The SSM parameter prefix for this domain's cert params
    """
    param_prefix = f"{SSM_CERT_PREFIX}/{domain}"
    fullchain = cert_pem + chain_pem

    if not acme_subdomain:
        acme_subdomain = domain_to_acme_subdomain(domain)

    logger.info(f"Storing certificate in SSM Parameter Store: {param_prefix}")

    _put_ssm_secure_param(f"{param_prefix}/key", private_key_pem)
    _put_ssm_secure_param(f"{param_prefix}/chain", fullchain)

    # Store metadata (plain String — not sensitive, no KMS cost)
    ssm_client.put_parameter(
        Name=f"{param_prefix}/meta",
        Value=json.dumps({
            FIELD_DOMAIN: domain,
            FIELD_EXPIRES_AT: expires_at,
            FIELD_ACME_SUBDOMAIN: acme_subdomain,
        }),
        Type='String',
        Overwrite=True,
    )

    logger.info(f"Stored certificate params for {domain}")
    return param_prefix


def update_domain_status(domain: str, status: str, cert_param_prefix: Optional[str] = None,
                         cert_expires_at: Optional[str] = None, error: Optional[str] = None):
    """Update domain status in the qurl-domains DynamoDB table.

    Clears provisioning_started_at when transitioning to active or failed
    so the idempotency lock is released for any subsequent attempt.
    """
    if not QURL_DOMAINS_TABLE:
        logger.info("No QURL_DOMAINS_TABLE configured, skipping status update")
        return

    try:
        now_iso = datetime.now(timezone.utc).isoformat()
        update_expr_parts = ['#s = :status', '#ua = :updated_at']
        remove_expr_parts = []
        expr_names = {
            '#s': 'status',
            '#ua': 'updated_at'
        }
        expr_values = {
            ':status': {'S': status},
            ':updated_at': {'S': now_iso}
        }

        if cert_param_prefix:
            update_expr_parts.append('#cpp = :cert_param_prefix')
            expr_names['#cpp'] = 'cert_param_prefix'
            expr_values[':cert_param_prefix'] = {'S': cert_param_prefix}

        if cert_expires_at:
            update_expr_parts.append('#cea = :cert_expires_at')
            expr_names['#cea'] = 'cert_expires_at'
            expr_values[':cert_expires_at'] = {'S': cert_expires_at}

        if status == STATUS_ACTIVE:
            update_expr_parts.append('#aa = :activated_at')
            expr_names['#aa'] = 'activated_at'
            expr_values[':activated_at'] = {'S': now_iso}

        if error:
            update_expr_parts.append('#err = :error')
            expr_names['#err'] = 'failure_reason'
            expr_values[':error'] = {'S': error[:500]}

        if status in (STATUS_ACTIVE, STATUS_FAILED):
            remove_expr_parts.append('#psa')
            expr_names['#psa'] = 'provisioning_started_at'

        update_expression = 'SET ' + ', '.join(update_expr_parts)
        if remove_expr_parts:
            update_expression += ' REMOVE ' + ', '.join(remove_expr_parts)

        dynamodb_client.update_item(
            TableName=QURL_DOMAINS_TABLE,
            Key={
                'domain': {'S': domain}
            },
            UpdateExpression=update_expression,
            ExpressionAttributeNames=expr_names,
            ExpressionAttributeValues=expr_values
        )
        logger.info(f"Updated domain status for {domain}: {status}")
    except Exception as e:
        logger.error(f"Failed to update domain status for {domain}: {e}")


def handle_domain_cleanup(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Handle a domain.cleanup SNS event from qurl-service (nhp#1990 / qurl-service#148).

    Flow on a deleted domain:
      1. Validate payload (domain format, required fields).
      2. Conditional DDB DeleteItem — the condition fails if the row has a
         non-empty `verification_token` (re-registered). The conditional
         delete is intentionally first: it serves as the authoritative race
         guard against re-registration, so even a long-delayed SNS retry
         (up to ~25 min between attempts) that fires after the customer
         re-added the domain leaves both DDB and SSM intact.
      3. Delete SSM cert params (/nhp/certs/<domain>/{key,chain,meta}).
      4. Delete any stale Route53 TXT at the ACME CNAME target (best-effort).
      5. Trigger AC cert sync (full mode) so AC instances evict the cached
         cert via custom-domain-cert-sync.sh's stale-dir sweep.

    All AWS-side deletes are idempotent — replaying a cleanup event after a
    transient SNS retry is safe. Returns a result dict reflecting what was
    actually changed.
    """
    # Defensive normalisation — qurl-service already applies the same shape
    # via domain.NormalizeDomainName (qurl-service/internal/domain/domain.go:156:
    # "lowercases and trims whitespace") before the DDB write, so a correctly
    # produced payload arrives lowercased/trimmed already. If that contract
    # ever drifts on the producer side, this keeps the DDB key lookup honest
    # — without it, a mixed-case `domain_name` would miss the row entirely
    # and silently report `DDB_ABSENT`, bypassing the race guard.
    domain = (payload.get('domain_name') or '').strip().lower()
    cert_param_prefix = (payload.get('cert_param_prefix') or '').strip()
    acme_cname_target = (payload.get('acme_cname_target') or '').strip()

    if not domain or not is_valid_domain(domain):
        logger.error(f"Cleanup event rejected: invalid domain_name: {domain!r}")
        publish_failure_metric(FAILURE_DOMAIN_VALIDATION)
        return {'status': RESULT_REJECTED, 'reason': REASON_INVALID_DOMAIN, 'domain': domain}

    ddb_result = _delete_orphan_domain_row(domain)
    if ddb_result == DDB_RACE:
        # Terminal failure — no amount of retrying recovers a re-registered
        # domain, and we MUST NOT delete the new cert material. Return so
        # SNS treats the message as delivered and stops retrying.
        logger.warning(
            f"Cleanup aborted for {domain}: qurl-domains row has a fresh "
            f"verification_token (re-registered since cleanup event published)"
        )
        return {'status': RESULT_ABORTED, 'reason': REASON_RACE_RE_REGISTERED, 'domain': domain}
    if ddb_result == DDB_ERROR:
        # Transient failure (throttle, internal error, or unconfigured
        # table). RAISE so the Lambda invocation is marked failed and
        # SNS's async retry policy kicks in — a plain return would let
        # SNS treat the message as delivered and we'd only catch the
        # orphan on the next reconciliation scan.
        raise TransientCleanupError(
            f"Cleanup for {domain} aborted: {REASON_DDB_UNAVAILABLE}"
        )

    # qurl-service supplies `<SSM_CERT_PREFIX>/<domain>` as cert_param_prefix;
    # fall back to the conventional path if the payload field is empty.
    cert_prefix = cert_param_prefix or f"{SSM_CERT_PREFIX.rstrip('/')}/{domain}"
    deleted_ssm = _delete_ssm_cert_params(cert_prefix)
    if deleted_ssm is None:
        # Transient SSM failure — see TransientCleanupError rationale above.
        # The whole point of the cleanup event is to remove the SSM cert
        # material; raising forces SNS to retry rather than reporting a
        # false RESULT_CLEANED.
        raise TransientCleanupError(
            f"Cleanup for {domain} aborted: {REASON_SSM_UNAVAILABLE}"
        )

    # Route53 race window: by the time we get here, the DDB guard succeeded
    # (no managed row) and the SSM cert is gone. A delayed retry that finds
    # the customer re-registered would already have been caught by the
    # token-empty conditional check above and never reach this point. A
    # within-invocation race is impossible: the customer would need to
    # complete re-register + ACME provisioning in the ~ms between SSM and
    # Route53 calls.
    deleted_route53 = bool(acme_cname_target) and delete_acme_txt_record(acme_cname_target)

    # Per-domain incremental delete (#1994). Previously this fired
    # trigger_cert_sync(BATCH_SYNC_CLEANUP), which mapped to a full-mode
    # custom-domain-cert-sync.sh sweep on every AC for every cleanup event —
    # N domains offboarded ⇒ N full-fleet rebuilds. trigger_cert_delete()
    # invokes `custom-domain-cert-sync.sh --delete <domain>` instead, which
    # touches only $CERT_DIR/$DOMAIN and the matching [[tls.certificates]]
    # TOML block.
    trigger_cert_delete(domain)

    logger.info(
        f"Domain cleanup complete for {domain}: ssm_deleted={deleted_ssm}, "
        f"route53_deleted={deleted_route53}, ddb_result={ddb_result}"
    )
    return {
        'status': RESULT_CLEANED,
        'domain': domain,
        'ssm_deleted': deleted_ssm,
        'route53_deleted': deleted_route53,
        'ddb_result': ddb_result,
    }


def _delete_ssm_cert_params(cert_prefix: str) -> Optional[List[str]]:
    """Delete the three /key, /chain, /meta SSM params for a domain.

    Idempotent on not-found: delete_parameters returns the missing names in
    InvalidParameters rather than raising. Real ClientError failures (the API
    really threw, not "this param wasn't there") return None so the caller
    can ABORT and SNS gets to retry — silently returning [] on a real error
    would let downstream code report `RESULT_CLEANED` while the cert is
    still in SSM, defeating the point of the cleanup event.

    Returns:
        list of param names actually deleted (possibly empty if all were
        already absent), OR None on a true ClientError.
    """
    cert_prefix = cert_prefix.rstrip('/')
    names = [f"{cert_prefix}/key", f"{cert_prefix}/chain", f"{cert_prefix}/meta"]
    try:
        response = ssm_client.delete_parameters(Names=names)
    except ClientError as e:
        logger.error(f"SSM delete_parameters failed for {cert_prefix}: {e}")
        publish_failure_metric(FAILURE_CERT_STORAGE)
        return None
    deleted = list(response.get('DeletedParameters', []))
    invalid = list(response.get('InvalidParameters', []))
    if invalid:
        logger.info(f"SSM cert params not present at cleanup time (already gone): {invalid}")
    return deleted


def _delete_orphan_domain_row(domain: str) -> str:
    """Conditional DeleteItem on the qurl-domains row — the race guard for
    the cleanup handler.

    The condition `attribute_not_exists(verification_token) OR verification_token = :empty`
    holds in two safe cases:
      - The row does not exist (canonical clean state after qurl-service's
        own delete). DeleteItem succeeds idempotently.
      - The row exists in the partial-failed shape that the reconciliation
        loop writes via update_domain_status(STATUS_FAILED): no token, only
        {domain, status, updated_at, failure_reason}. DeleteItem removes it.

    The condition fails (ConditionalCheckFailedException) when the row has
    a non-empty verification_token — the canonical shape of a re-registered
    domain, regardless of status. Treating this as the authoritative race
    indicator means a delayed SNS retry that arrives after a customer
    re-registers will not damage the new cert material.

    Returns one of:
      - DDB_DELETED — row existed and was removed (ReturnValues=ALL_OLD).
      - DDB_ABSENT  — row did not exist; delete was a no-op.
      - DDB_RACE    — row exists with verification_token; ABORT downstream cleanup.
      - DDB_ERROR   — non-conditional ClientError or QURL_DOMAINS_TABLE unset;
                      caller aborts so SNS retries (or the reconciliation
                      scan) gets another shot. Crucially we never silently
                      proceed without a race guard — that would let a
                      misconfigured environment wipe a re-registered cert.
    """
    if not QURL_DOMAINS_TABLE:
        logger.error("QURL_DOMAINS_TABLE unset; cannot enforce race guard")
        return DDB_ERROR
    try:
        response = dynamodb_client.delete_item(
            TableName=QURL_DOMAINS_TABLE,
            Key={'domain': {'S': domain}},
            ConditionExpression='attribute_not_exists(verification_token) OR verification_token = :empty',
            ExpressionAttributeValues={':empty': {'S': ''}},
            ReturnValues='ALL_OLD',
        )
        return DDB_DELETED if response.get('Attributes') else DDB_ABSENT
    except ClientError as e:
        code = e.response.get('Error', {}).get('Code', 'Unknown')
        if code == 'ConditionalCheckFailedException':
            return DDB_RACE
        logger.warning(f"DDB delete_item failed for {domain}: code={code}")
        return DDB_ERROR


def trigger_cert_sync(domain: str):
    """Trigger certificate sync on AC instances via SSM SendCommand.

    For single-domain provisioning, uses incremental mode (--domain flag)
    to avoid a full rebuild. For batch operations (renewal-scan-batch,
    provision-batch), triggers a full sync.
    """
    try:
        ac_instance_tag = os.environ.get('AC_INSTANCE_TAG')
        if not ac_instance_tag:
            logger.info("No AC_INSTANCE_TAG configured, skipping cert sync trigger")
            return

        # Batch triggers use full sync; single-domain uses incremental
        if domain in BATCH_SYNCS:
            sync_cmd = '/home/ubuntu/scripts/custom-domain-cert-sync.sh'
        else:
            # Re-validate and shell-quote domain to prevent command injection.
            # Domain is validated in handler() but passes through DynamoDB in
            # provision_pending_domains(), so defense-in-depth matters here.
            if not is_valid_domain(domain):
                logger.error(f"Invalid domain format in trigger_cert_sync: {domain}")
                return
            sync_cmd = f'/home/ubuntu/scripts/custom-domain-cert-sync.sh --domain {shlex.quote(domain)}'

        response = ssm_client.send_command(
            Targets=[
                {
                    'Key': 'tag:Name',
                    'Values': [ac_instance_tag]
                }
            ],
            DocumentName='AWS-RunShellScript',
            Parameters={
                'commands': [
                    'echo "Custom domain cert sync triggered"',
                    f'{sync_cmd} || true'
                ]
            },
            TimeoutSeconds=120,
            Comment=f'Cert sync triggered for custom domain: {domain}'
        )
        command_id = response['Command']['CommandId']
        logger.info(f"Triggered cert sync on AC instances, command: {command_id}")
    except Exception as e:
        logger.error(f"Failed to trigger cert sync: {e}")
        publish_failure_metric(FAILURE_CERT_SYNC)


def trigger_cert_delete(domain: str):
    """Trigger an incremental per-domain cert removal on AC instances.

    Invokes `custom-domain-cert-sync.sh --delete <domain>` on every AC in the
    fleet. The script removes only that domain's $CERT_DIR/$DOMAIN and the
    matching [[tls.certificates]] TOML block, leaving every other domain's
    cert material intact.

    This replaces the pre-#1994 cleanup path that fired a full-mode sync per
    event (trigger_cert_sync(BATCH_SYNC_CLEANUP)). The full sweep was correct
    but cost the AC fleet a from-scratch rebuild for every domain offboarded;
    customers offboarding N domains in quick succession produced N fleet-wide
    full sweeps, while the incremental delete path is O(domains-removed).
    """
    try:
        ac_instance_tag = os.environ.get('AC_INSTANCE_TAG')
        if not ac_instance_tag:
            logger.info("No AC_INSTANCE_TAG configured, skipping cert delete trigger")
            return

        # Defense-in-depth — domain has already been validated in
        # handle_domain_cleanup, but re-validate before letting it through to
        # the shell command. shlex.quote() handles literal characters; the
        # is_valid_domain() check is the layer that refuses shell-meaningful
        # values in the first place.
        if not is_valid_domain(domain):
            logger.error(f"Invalid domain format in trigger_cert_delete: {domain}")
            return

        sync_cmd = f'/home/ubuntu/scripts/custom-domain-cert-sync.sh --delete {shlex.quote(domain)}'

        response = ssm_client.send_command(
            Targets=[
                {
                    'Key': 'tag:Name',
                    'Values': [ac_instance_tag]
                }
            ],
            DocumentName='AWS-RunShellScript',
            Parameters={
                'commands': [
                    'echo "Custom domain cert delete triggered"',
                    # `|| true` mirrors trigger_cert_sync: the AC script
                    # exits 0 on already-absent state. Anything that should
                    # actually retry should be surfaced through the script's
                    # CertSyncDomainsRemoved metric, not through this
                    # SendCommand's success/failure.
                    f'{sync_cmd} || true'
                ]
            },
            TimeoutSeconds=120,
            Comment=f'Cert delete triggered for custom domain: {domain}'
        )
        command_id = response['Command']['CommandId']
        logger.info(f"Triggered cert delete on AC instances, command: {command_id}")
    except Exception as e:
        logger.error(f"Failed to trigger cert delete: {e}")
        publish_failure_metric(FAILURE_CERT_SYNC)


def send_alert(message: str, is_error: bool = True):
    """Send alert to SNS topic."""
    if not SNS_TOPIC_ARN:
        logger.info("No SNS topic configured, skipping alert")
        return

    try:
        subject = f"[{'ERROR' if is_error else 'INFO'}] Custom Domain Cert Manager"

        sns_client.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=subject[:100],
            Message=json.dumps({
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'message': message,
                'is_error': is_error
            }, indent=2)
        )
    except Exception as e:
        logger.error(f"Failed to send SNS alert: {e}")


def publish_metric(metric_name: str, value: float, dimensions: Optional[List[Dict[str, str]]] = None):
    """Publish a metric to CloudWatch."""
    try:
        metric_data = {
            'MetricName': metric_name,
            'Value': value,
            'Unit': 'Count'
        }
        if dimensions:
            metric_data['Dimensions'] = dimensions

        cloudwatch_client.put_metric_data(
            Namespace=CW_NAMESPACE,
            MetricData=[metric_data]
        )
        logger.debug(f"Published {metric_name} metric: {value}")
    except Exception as e:
        logger.error(f"Failed to publish CloudWatch metric {metric_name}: {e}")


def publish_failure_metric(category: Optional[str] = None):
    """Publish a provisioning failure metric to CloudWatch.

    Publishes two data points: one without dimensions (for the existing alarm)
    and one with a FailureCategory dimension (for granular diagnosis).
    """
    # Always publish the aggregate metric (keeps existing alarm working)
    publish_metric(CW_METRIC_PROVISIONING_FAILURES, 1)
    # Also publish with category dimension for diagnosis without logs
    if category:
        publish_metric(
            CW_METRIC_PROVISIONING_FAILURES, 1,
            dimensions=[{'Name': 'FailureCategory', 'Value': category}]
        )
