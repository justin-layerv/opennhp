"""
ACME Certificate Manager Lambda

Manages centralized TLS certificates for AC fleet using Let's Encrypt.
Implements DNS-01 challenge via Route 53 for wildcard certificate issuance.

Security considerations:
- Private keys generated in Lambda, never exposed to Terraform state
- All secrets encrypted with KMS CMK
- Least privilege IAM permissions
- Comprehensive audit logging
- No sensitive data in CloudWatch logs

Author: LayerV Platform Team
"""

import json
import logging
import os
import time
import hashlib
import base64
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any, Tuple

import boto3
from botocore.exceptions import ClientError

# Configure logging - be careful not to log sensitive data
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Lazy imports for cryptography (Lambda layer)
acme = None
josepy = None
cryptography = None


def lazy_import_crypto():
    """Lazy import cryptography libraries to reduce cold start when not needed."""
    global cryptography
    if cryptography is None:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa, ec
        from cryptography.hazmat.backends import default_backend

        cryptography = {
            'x509': x509,
            'hashes': hashes,
            'serialization': serialization,
            'rsa': rsa,
            'ec': ec,
            'default_backend': default_backend
        }


def lazy_import_acme():
    """Lazy import ACME/josepy libraries only when renewal is needed."""
    global acme, josepy
    # Ensure cryptography is loaded first
    lazy_import_crypto()
    if acme is None:
        import acme as acme_lib
        from acme import client, messages, challenges
        import josepy as josepy_lib

        acme = acme_lib
        josepy = josepy_lib


# Environment variables
DOMAINS = os.environ.get('DOMAINS', '').split(',')
SECRET_ARN = os.environ.get('SECRET_ARN')
KMS_KEY_ARN = os.environ.get('KMS_KEY_ARN')
ACME_EMAIL = os.environ.get('ACME_EMAIL')
ACME_DIRECTORY = os.environ.get('ACME_DIRECTORY', 'https://acme-v02.api.letsencrypt.org/directory')
HOSTED_ZONE_ID = os.environ.get('HOSTED_ZONE_ID')  # Default zone for domains not in DOMAIN_ZONE_MAPPINGS
RENEWAL_DAYS_BEFORE_EXPIRY = int(os.environ.get('RENEWAL_DAYS_BEFORE_EXPIRY', '30'))
SNS_TOPIC_ARN = os.environ.get('SNS_TOPIC_ARN')

# Multi-zone support: JSON map of domain suffix -> zone ID
# Example: {"qurl.site": "Z1234", "qurl.link": "Z5678"}
DOMAIN_ZONE_MAPPINGS_RAW = os.environ.get('DOMAIN_ZONE_MAPPINGS', '{}')
try:
    DOMAIN_ZONE_MAPPINGS = json.loads(DOMAIN_ZONE_MAPPINGS_RAW)
except json.JSONDecodeError:
    logger.warning(f"Invalid DOMAIN_ZONE_MAPPINGS JSON: {DOMAIN_ZONE_MAPPINGS_RAW!r}, using empty map")
    DOMAIN_ZONE_MAPPINGS = {}

# Cross-account IAM role for Route53 access in another AWS account
CROSS_ACCOUNT_ROLE_ARN = os.environ.get('CROSS_ACCOUNT_ROLE_ARN')

# AWS clients
secrets_client = boto3.client('secretsmanager')
route53_client = boto3.client('route53')
sns_client = boto3.client('sns')
cloudwatch_client = boto3.client('cloudwatch')

# Cross-account Route53 client (lazy initialized with credential expiry tracking)
_cross_account_route53_client = None
_cross_account_credentials_expiry = None

# ACME account secret (for persisting account key across invocations)
ACME_ACCOUNT_SECRET_ARN = os.environ.get('ACME_ACCOUNT_SECRET_ARN')


def get_cross_account_route53_client():
    """Get Route53 client with cross-account credentials.

    Handles credential expiration by refreshing credentials when they're
    within 5 minutes of expiry. This prevents failures when Lambda containers
    stay warm for extended periods.
    """
    global _cross_account_route53_client, _cross_account_credentials_expiry

    if not CROSS_ACCOUNT_ROLE_ARN:
        return None

    now = datetime.now(timezone.utc)

    # Check if credentials need refresh (expired or within 5 minutes of expiry)
    if _cross_account_credentials_expiry is not None:
        if now >= _cross_account_credentials_expiry - timedelta(minutes=5):
            logger.debug("Cross-account credentials expiring soon, refreshing")
            _cross_account_route53_client = None
            _cross_account_credentials_expiry = None

    if _cross_account_route53_client is None:
        sts_client = boto3.client('sts')
        assumed_role = sts_client.assume_role(
            RoleArn=CROSS_ACCOUNT_ROLE_ARN,
            RoleSessionName='acme-cert-manager',
            DurationSeconds=3600  # 1 hour (reasonable for certificate operations)
        )
        credentials = assumed_role['Credentials']
        _cross_account_route53_client = boto3.client(
            'route53',
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken']
        )
        _cross_account_credentials_expiry = credentials['Expiration']
        logger.debug(f"Created cross-account Route53 client, expires: {_cross_account_credentials_expiry}")

    return _cross_account_route53_client


def get_zone_for_domain(domain: str) -> Tuple[str, Any]:
    """
    Get the hosted zone ID and Route53 client for a domain.

    Returns:
        Tuple of (zone_id, route53_client)
    """
    # Strip _acme-challenge. prefix and wildcard if present
    clean_domain = domain
    if clean_domain.startswith('_acme-challenge.'):
        clean_domain = clean_domain[len('_acme-challenge.'):]
    if clean_domain.startswith('*.'):
        clean_domain = clean_domain[2:]

    # Check DOMAIN_ZONE_MAPPINGS for matching suffix (longest match wins)
    best_match = None
    best_match_len = 0

    for zone_domain, zone_config in DOMAIN_ZONE_MAPPINGS.items():
        if clean_domain == zone_domain or clean_domain.endswith('.' + zone_domain):
            if len(zone_domain) > best_match_len:
                best_match = zone_config
                best_match_len = len(zone_domain)

    if best_match:
        # zone_config can be a string (zone ID) or dict with zone_id and cross_account
        if isinstance(best_match, dict):
            zone_id = best_match.get('zone_id')
            use_cross_account = best_match.get('cross_account', False)
        else:
            # Plain string = zone ID, same-account (cross_account defaults to False)
            zone_id = best_match
            use_cross_account = False

        # Validate zone_id is present
        if not zone_id:
            logger.error(f"No zone_id found in mapping for domain {clean_domain}, falling back to default")
            return HOSTED_ZONE_ID, route53_client

        if use_cross_account and CROSS_ACCOUNT_ROLE_ARN:
            client = get_cross_account_route53_client()
            if client:
                logger.debug(f"Using cross-account Route53 for {clean_domain} -> zone {zone_id}")
                return zone_id, client

        logger.debug(f"Using zone mapping for {clean_domain} -> zone {zone_id}")
        return zone_id, route53_client

    # Fall back to default zone
    logger.debug(f"Using default zone for {clean_domain} -> zone {HOSTED_ZONE_ID}")
    return HOSTED_ZONE_ID, route53_client


def handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Lambda handler for certificate management.

    Event types:
    - scheduled: Check if renewal needed, renew if so
    - force_renew: Force certificate renewal regardless of expiry
    - check_status: Return current certificate status without renewing
    """
    try:
        event_type = event.get('type', 'scheduled')
        logger.info(f"Certificate manager invoked with event type: {event_type}")

        if event_type == 'check_status':
            return check_certificate_status()
        elif event_type == 'force_renew':
            return renew_certificate(force=True)
        else:  # scheduled
            return renew_certificate(force=False)

    except Exception as e:
        logger.error(f"Certificate manager failed: {str(e)}", exc_info=True)
        send_alert(f"Certificate renewal FAILED: {str(e)}")
        raise


def check_certificate_status() -> Dict[str, Any]:
    """Check current certificate status without renewing."""
    try:
        secret = get_current_secret()
        if not secret:
            return {
                'status': 'missing',
                'message': 'No certificate found in Secrets Manager'
            }

        cert_pem = secret.get('certificate', '')
        if not cert_pem:
            return {
                'status': 'invalid',
                'message': 'Secret exists but no certificate found'
            }

        lazy_import_crypto()
        cert = cryptography['x509'].load_pem_x509_certificate(
            cert_pem.encode(),
            cryptography['default_backend']()
        )

        expiry = cert.not_valid_after_utc
        now = datetime.now(timezone.utc)
        days_until_expiry = (expiry - now).days

        # Publish metric for CloudWatch alarm
        publish_expiry_metric(days_until_expiry)

        return {
            'status': 'valid',
            'domains': DOMAINS,
            'expires_at': expiry.isoformat(),
            'days_until_expiry': days_until_expiry,
            'needs_renewal': days_until_expiry <= RENEWAL_DAYS_BEFORE_EXPIRY,
            'issuer': cert.issuer.rfc4514_string(),
            'serial_number': format(cert.serial_number, 'x')
        }

    except Exception as e:
        logger.error(f"Failed to check certificate status: {str(e)}")
        return {
            'status': 'error',
            'message': str(e)
        }


def renew_certificate(force: bool = False) -> Dict[str, Any]:
    """
    Renew certificate if needed or forced.

    Args:
        force: If True, renew regardless of expiry

    Returns:
        Status dict with renewal outcome
    """
    logger.info(f"Starting certificate renewal check (force={force})")

    # Check if renewal is needed
    if not force:
        status = check_certificate_status()
        if status.get('status') == 'valid' and not status.get('needs_renewal'):
            logger.info(f"Certificate valid for {status['days_until_expiry']} more days, skipping renewal")
            return {
                'status': 'skipped',
                'reason': 'Certificate not due for renewal',
                'days_until_expiry': status['days_until_expiry']
            }

    logger.info(f"Proceeding with certificate renewal for domains: {DOMAINS}")

    try:
        # Import crypto and ACME libraries
        lazy_import_acme()

        # Generate new private key (4096-bit RSA for compatibility)
        private_key = cryptography['rsa'].generate_private_key(
            public_exponent=65537,
            key_size=4096,
            backend=cryptography['default_backend']()
        )

        # Get or create ACME account
        acme_client, account = get_or_create_acme_account(private_key)

        # Request certificate
        cert_pem, chain_pem = request_certificate(acme_client, private_key, DOMAINS)

        # Serialize private key (no password - KMS provides encryption)
        private_key_pem = private_key.private_bytes(
            encoding=cryptography['serialization'].Encoding.PEM,
            format=cryptography['serialization'].PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=cryptography['serialization'].NoEncryption()
        ).decode('utf-8')

        # Store in Secrets Manager
        store_certificate(private_key_pem, cert_pem, chain_pem)

        # Verify the stored certificate
        status = check_certificate_status()

        logger.info(f"Certificate renewed successfully, expires: {status.get('expires_at')}")
        send_alert(f"Certificate renewed successfully for {DOMAINS}. Expires: {status.get('expires_at')}", is_error=False)

        return {
            'status': 'renewed',
            'domains': DOMAINS,
            'expires_at': status.get('expires_at'),
            'days_until_expiry': status.get('days_until_expiry')
        }

    except Exception as e:
        logger.error(f"Certificate renewal failed: {str(e)}", exc_info=True)
        send_alert(f"Certificate renewal FAILED for {DOMAINS}: {str(e)}")
        raise


def get_or_create_acme_account(private_key) -> Tuple[Any, Any]:
    """
    Get existing ACME account or create new one.

    Persists the ACME account key in Secrets Manager to avoid creating new accounts
    on each invocation. Let's Encrypt has rate limits on account creation (10 per IP
    per 3 hours), so reusing the same account is important.
    """
    from acme import client, messages

    # Try to load existing account key from Secrets Manager
    account_key = None
    if ACME_ACCOUNT_SECRET_ARN:
        try:
            response = secrets_client.get_secret_value(SecretId=ACME_ACCOUNT_SECRET_ARN)
            secret_data = json.loads(response['SecretString'])
            account_key_pem = secret_data.get('account_key')
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
    network = client.ClientNetwork(account_key_jose, user_agent='LayerV-ACME-Manager/1.0')
    directory = messages.Directory.from_json(network.get(ACME_DIRECTORY).json())
    acme_client = client.ClientV2(directory, net=network)

    # Register account (or retrieve existing)
    # Using only_return_existing=True returns existing account without error
    registration = messages.NewRegistration.from_data(
        email=ACME_EMAIL,
        terms_of_service_agreed=True,
        only_return_existing=False  # First try to create new
    )

    try:
        account = acme_client.new_account(registration)
        logger.info(f"ACME account registered: {account.uri}")

        # Save the account key for future use
        if ACME_ACCOUNT_SECRET_ARN:
            save_acme_account_key(account_key)
    except acme.errors.ConflictError as e:
        # Account already exists - ConflictError contains the account URI
        # Extract it and construct a RegistrationResource
        account_uri = str(e)  # ConflictError's str() returns the account URI
        logger.info(f"ACME account already exists at: {account_uri}")

        # Create a minimal RegistrationResource to query the full account
        existing_reg = messages.RegistrationResource(
            uri=account_uri,
            body=messages.Registration()
        )
        # Set on network first so query_registration can use it for signing
        acme_client.net.account = existing_reg

        # Query to get full registration details
        account = acme_client.query_registration(existing_reg)
        acme_client.net.account = account
        logger.info(f"Using existing ACME account: {account.uri}")

    return acme_client, account


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
            'account_key': account_key_pem,
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


def request_certificate(acme_client, private_key, domains: list) -> Tuple[str, str]:
    """
    Request certificate from ACME server using DNS-01 challenge.

    Args:
        acme_client: ACME client instance
        private_key: RSA private key for CSR
        domains: List of domains (first is main, rest are SANs)

    Returns:
        Tuple of (certificate_pem, chain_pem)
    """
    from acme import challenges, messages
    from cryptography import x509
    from cryptography.x509.oid import NameOID

    logger.info(f"Requesting certificate for domains: {domains}")

    # Create CSR
    csr_builder = x509.CertificateSigningRequestBuilder()
    csr_builder = csr_builder.subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, domains[0])
    ]))

    # Add SANs
    san_list = [x509.DNSName(d) for d in domains]
    csr_builder = csr_builder.add_extension(
        x509.SubjectAlternativeName(san_list),
        critical=False
    )

    csr = csr_builder.sign(private_key, cryptography['hashes'].SHA256(), cryptography['default_backend']())

    # Get CSR as PEM bytes (acme client.new_order expects PEM bytes)
    csr_pem = csr.public_bytes(cryptography['serialization'].Encoding.PEM)

    # Request new order
    order = acme_client.new_order(csr_pem)

    # Collect all challenges - group by record name since wildcard and base domain
    # share the same _acme-challenge record name but need different values
    challenges_by_record = {}  # record_name -> [(challenge, validation)]
    all_challenges = []

    for auth in order.authorizations:
        domain = auth.body.identifier.value
        logger.info(f"Collecting authorization for: {domain}")

        # Find DNS-01 challenge
        dns_challenge = None
        for challenge in auth.body.challenges:
            if isinstance(challenge.chall, challenges.DNS01):
                dns_challenge = challenge
                break

        if not dns_challenge:
            raise ValueError(f"No DNS-01 challenge found for {domain}")

        # Get validation token
        validation = dns_challenge.chall.validation(acme_client.net.key)
        record_name = f"_acme-challenge.{domain}"

        # Group challenges by record name
        if record_name not in challenges_by_record:
            challenges_by_record[record_name] = []
        challenges_by_record[record_name].append(validation)
        all_challenges.append(dns_challenge)

    # Create all DNS records (with multi-value support for wildcards)
    for record_name, validations in challenges_by_record.items():
        logger.info(f"Creating DNS record: {record_name} with {len(validations)} value(s)")
        create_dns_record_multi(record_name, validations)

    # Wait for DNS propagation of all records
    for record_name, validations in challenges_by_record.items():
        wait_for_dns_propagation_multi(record_name, validations)

    # Answer all challenges
    for dns_challenge in all_challenges:
        acme_client.answer_challenge(dns_challenge, dns_challenge.response(acme_client.net.key))

    # Finalize order
    logger.info("Finalizing certificate order")
    order = acme_client.poll_and_finalize(order)

    # Clean up DNS records
    for record_name in challenges_by_record.keys():
        try:
            delete_dns_record(record_name)
        except Exception as e:
            logger.warning(f"Failed to delete DNS record {record_name}: {e}")

    # Extract certificate and chain
    fullchain = order.fullchain_pem

    # Split into cert and chain
    certs = fullchain.split('-----END CERTIFICATE-----')
    cert_pem = certs[0] + '-----END CERTIFICATE-----\n'
    chain_pem = '-----END CERTIFICATE-----'.join(certs[1:]).strip()
    if chain_pem and not chain_pem.endswith('\n'):
        chain_pem += '\n'

    logger.info("Certificate obtained successfully")
    return cert_pem, chain_pem


def create_dns_record_multi(record_name: str, values: list):
    """Create TXT record with multiple values for ACME DNS-01 challenges.

    When requesting a cert for both a domain and its wildcard, both challenges
    use the same _acme-challenge.domain.com record but with different values.
    Route53 allows multiple values in a single TXT record set.
    """
    # Handle wildcard domains - the challenge record should not have the wildcard
    if record_name.startswith('_acme-challenge.*.'):
        record_name = record_name.replace('_acme-challenge.*.', '_acme-challenge.')

    logger.info(f"Creating DNS TXT record: {record_name} with {len(values)} value(s)")

    # Get the correct zone and client for this domain
    zone_id, r53_client = get_zone_for_domain(record_name)

    # Create ResourceRecords list with all values
    resource_records = [{'Value': f'"{v}"'} for v in values]

    r53_client.change_resource_record_sets(
        HostedZoneId=zone_id,
        ChangeBatch={
            'Changes': [{
                'Action': 'UPSERT',
                'ResourceRecordSet': {
                    'Name': record_name,
                    'Type': 'TXT',
                    'TTL': 60,
                    'ResourceRecords': resource_records
                }
            }]
        }
    )


def create_dns_record(record_name: str, value: str):
    """Create TXT record for ACME DNS-01 challenge."""
    # Handle wildcard domains - the challenge record should not have the wildcard
    if record_name.startswith('_acme-challenge.*.'):
        record_name = record_name.replace('_acme-challenge.*.', '_acme-challenge.')

    logger.info(f"Creating DNS TXT record: {record_name} = {value[:20]}...")

    # Get the correct zone and client for this domain
    zone_id, r53_client = get_zone_for_domain(record_name)

    r53_client.change_resource_record_sets(
        HostedZoneId=zone_id,
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


def delete_dns_record(record_name: str):
    """Delete TXT record after challenge completion."""
    if record_name.startswith('_acme-challenge.*.'):
        record_name = record_name.replace('_acme-challenge.*.', '_acme-challenge.')

    logger.info(f"Deleting DNS TXT record: {record_name}")

    # Get the correct zone and client for this domain
    zone_id, r53_client = get_zone_for_domain(record_name)

    # First, get the current record value
    try:
        response = r53_client.list_resource_record_sets(
            HostedZoneId=zone_id,
            StartRecordName=record_name,
            StartRecordType='TXT',
            MaxItems='1'
        )

        records = response.get('ResourceRecordSets', [])
        if not records or records[0]['Name'].rstrip('.') != record_name.rstrip('.'):
            logger.info(f"DNS record {record_name} not found, skipping delete")
            return

        record = records[0]

        r53_client.change_resource_record_sets(
            HostedZoneId=zone_id,
            ChangeBatch={
                'Changes': [{
                    'Action': 'DELETE',
                    'ResourceRecordSet': record
                }]
            }
        )
    except ClientError as e:
        logger.warning(f"Failed to delete DNS record: {e}")


def wait_for_dns_propagation_multi(record_name: str, expected_values: list, max_attempts: int = 30, delay: int = 10):
    """Wait for DNS record with multiple values to propagate."""
    if record_name.startswith('_acme-challenge.*.'):
        record_name = record_name.replace('_acme-challenge.*.', '_acme-challenge.')

    logger.info(f"Waiting for DNS propagation of {record_name} with {len(expected_values)} value(s)")
    expected_set = set(expected_values)

    for attempt in range(max_attempts):
        try:
            import dns.resolver
            resolver = dns.resolver.Resolver()
            resolver.nameservers = ['8.8.8.8', '1.1.1.1']

            answers = resolver.resolve(record_name, 'TXT')
            found_values = set()
            for rdata in answers:
                txt_value = str(rdata).strip('"')
                found_values.add(txt_value)

            # Check if all expected values are present
            if expected_set.issubset(found_values):
                logger.info(f"DNS propagation confirmed after {attempt + 1} attempts")
                return
        except Exception as e:
            logger.debug(f"DNS query attempt {attempt + 1} failed: {e}")

        time.sleep(delay)

    # Even if we can't confirm, proceed - Let's Encrypt will verify
    logger.warning(f"Could not confirm DNS propagation after {max_attempts} attempts, proceeding anyway")


def wait_for_dns_propagation(record_name: str, expected_value: str, max_attempts: int = 30, delay: int = 10):
    """Wait for DNS record to propagate."""
    import socket

    if record_name.startswith('_acme-challenge.*.'):
        record_name = record_name.replace('_acme-challenge.*.', '_acme-challenge.')

    logger.info(f"Waiting for DNS propagation of {record_name}")

    for attempt in range(max_attempts):
        try:
            # Query DNS directly
            import dns.resolver
            resolver = dns.resolver.Resolver()
            resolver.nameservers = ['8.8.8.8', '1.1.1.1']

            answers = resolver.resolve(record_name, 'TXT')
            for rdata in answers:
                txt_value = str(rdata).strip('"')
                if txt_value == expected_value:
                    logger.info(f"DNS propagation confirmed after {attempt + 1} attempts")
                    return
        except Exception as e:
            logger.debug(f"DNS query attempt {attempt + 1} failed: {e}")

        time.sleep(delay)

    # Even if we can't confirm, proceed - Let's Encrypt will verify
    logger.warning(f"Could not confirm DNS propagation after {max_attempts} attempts, proceeding anyway")


def get_current_secret() -> Optional[Dict[str, str]]:
    """Retrieve current certificate from Secrets Manager."""
    try:
        response = secrets_client.get_secret_value(SecretId=SECRET_ARN)
        return json.loads(response['SecretString'])
    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            return None
        raise


def store_certificate(private_key_pem: str, cert_pem: str, chain_pem: str):
    """
    Store certificate in Secrets Manager.

    Secret structure:
    {
        "private_key": "<PEM-encoded RSA key>",
        "certificate": "<PEM-encoded certificate>",
        "chain": "<PEM-encoded CA chain>",
        "fullchain": "cert + chain combined",
        "renewed_at": "2024-01-01T00:00:00Z",
        "domains": ["example.com", "*.example.com"]
    }
    """
    fullchain = cert_pem + chain_pem

    secret_value = {
        'private_key': private_key_pem,
        'certificate': cert_pem,
        'chain': chain_pem,
        'fullchain': fullchain,
        'renewed_at': datetime.now(timezone.utc).isoformat(),
        'domains': DOMAINS
    }

    # Don't log the actual secret value
    logger.info("Storing certificate in Secrets Manager")

    secrets_client.put_secret_value(
        SecretId=SECRET_ARN,
        SecretString=json.dumps(secret_value)
    )

    logger.info("Certificate stored successfully")


def send_alert(message: str, is_error: bool = True):
    """Send alert to SNS topic."""
    if not SNS_TOPIC_ARN:
        logger.info("No SNS topic configured, skipping alert")
        return

    try:
        subject = f"[{'ERROR' if is_error else 'INFO'}] ACME Certificate Manager"

        sns_client.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=subject[:100],  # SNS subject limit
            Message=json.dumps({
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'domains': DOMAINS,
                'message': message,
                'is_error': is_error
            }, indent=2)
        )
    except Exception as e:
        logger.error(f"Failed to send SNS alert: {e}")


def publish_expiry_metric(days_until_expiry: int):
    """
    Publish certificate expiry metric to CloudWatch.

    This metric is used by the DaysUntilExpiry alarm to alert when
    the certificate is approaching expiry.
    """
    try:
        cloudwatch_client.put_metric_data(
            Namespace='NHP/Certificates',
            MetricData=[
                {
                    'MetricName': 'DaysUntilExpiry',
                    'Dimensions': [
                        {
                            'Name': 'SecretArn',
                            'Value': SECRET_ARN
                        }
                    ],
                    'Value': days_until_expiry,
                    'Unit': 'Count'
                }
            ]
        )
        logger.info(f"Published DaysUntilExpiry metric: {days_until_expiry}")
    except Exception as e:
        logger.error(f"Failed to publish CloudWatch metric: {e}")
