"""
Custom Domain Certificate Manager Lambda

Manages TLS certificates for customer custom domains using Let's Encrypt
with DNS-01 challenge via CNAME delegation pattern.

Flow:
  1. Customer creates CNAME: _acme-challenge.secure.example.com -> secure--example--com.acme.layerv.xyz
  2. Lambda creates TXT record at secure--example--com.acme.layerv.xyz in our ACME zone
  3. Let's Encrypt follows CNAME, finds TXT, validates domain ownership
  4. Certificate stored in Secrets Manager, domain status updated in DynamoDB

Security considerations:
- Private keys generated in Lambda, never exposed to Terraform state
- All secrets encrypted with KMS CMK
- Least privilege IAM permissions
- No sensitive data in CloudWatch logs

Author: LayerV Platform Team
"""

import json
import logging
import os
import re
import time
from datetime import datetime, timezone
from typing import Optional, Dict, Any, Tuple

import boto3
from botocore.exceptions import ClientError

# Configure logging - be careful not to log sensitive data
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Event types (must match EventBridge rule inputs in main.tf)
EVENT_PROVISION = 'provision'
EVENT_RENEWAL_SCAN = 'renewal_scan'

# Domain cert statuses (stored in qurl-domains DynamoDB table)
STATUS_ACTIVE = 'active'
STATUS_CERT_FAILED = 'cert_failed'
STATUS_PENDING = 'pending'

# Provision result statuses (returned in Lambda response)
RESULT_PROVISIONED = 'provisioned'

# Secret JSON field names (contract between Lambda writer and cert-sync shell reader)
FIELD_PRIVATE_KEY = 'private_key'
FIELD_CERTIFICATE = 'certificate'
FIELD_CHAIN = 'chain'
FIELD_FULLCHAIN = 'fullchain'
FIELD_EXPIRES_AT = 'expires_at'
FIELD_DOMAIN = 'domain'
FIELD_ACME_SUBDOMAIN = 'acme_subdomain'
FIELD_RENEWED_AT = 'renewed_at'
FIELD_ACCOUNT_KEY = 'account_key'
FIELD_STATUS = 'status'

# CloudWatch metric constants (must match alarm definitions in main.tf)
CW_NAMESPACE = 'NHP/CustomDomainCerts'
CW_METRIC_DAYS_UNTIL_EXPIRY = 'DaysUntilExpiry'
CW_METRIC_PROVISIONING_FAILURES = 'ProvisioningFailures'

# Lazy imports for cryptography and DNS (Lambda layer)
acme = None
josepy = None
cryptography = None
dns_resolver = None


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
        import acme as acme_lib
        from acme import client, messages, challenges
        import josepy as josepy_lib

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
SECRETS_PREFIX = os.environ.get('SECRETS_PREFIX', 'custom-domain-cert')

# Cached ACME client (reused across multiple renewals in a single invocation)
_cached_acme_client = None

# Renewal threshold
RENEWAL_DAYS_BEFORE_EXPIRY = 30

# AWS clients
secrets_client = boto3.client('secretsmanager')
route53_client = boto3.client('route53')
sns_client = boto3.client('sns')
cloudwatch_client = boto3.client('cloudwatch')
dynamodb_client = boto3.client('dynamodb')
ssm_client = boto3.client('ssm')


def handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Lambda handler for custom domain certificate management.

    Event types:
    - provision: Issue certificate for a specific domain
      {"type": "provision", "domain": "secure.example.com", "acme_subdomain": "secure--example--com"}
    - renewal_scan: Scan all custom domain certs and renew those approaching expiry
      {"type": "renewal_scan"}
    """
    try:
        event_type = event.get('type', EVENT_RENEWAL_SCAN)
        logger.info(f"Custom domain cert manager invoked with event type: {event_type}")

        if event_type == EVENT_PROVISION:
            domain = event.get('domain')
            acme_subdomain = event.get('acme_subdomain')
            if not domain or not acme_subdomain:
                raise ValueError("provision event requires 'domain' and 'acme_subdomain' fields")
            # Validate domain format to prevent injection via malformed input
            if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9.-]{0,251}[a-zA-Z0-9])?$', domain) or '..' in domain:
                raise ValueError(f"Invalid domain format: {domain}")
            if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,251}[a-zA-Z0-9])?$', acme_subdomain):
                raise ValueError(f"Invalid acme_subdomain format: {acme_subdomain}")
            return provision_certificate(domain, acme_subdomain)
        elif event_type == EVENT_RENEWAL_SCAN:
            return renewal_scan()
        else:
            raise ValueError(f"Unknown event type: {event_type}")

    except Exception as e:
        logger.error(f"Custom domain cert manager failed: {str(e)}", exc_info=True)
        send_alert(f"Custom domain cert manager FAILED: {str(e)}")
        publish_failure_metric()
        raise


def provision_certificate(domain: str, acme_subdomain: str, skip_sync: bool = False) -> Dict[str, Any]:
    """
    Provision a new TLS certificate for a custom domain.

    Args:
        domain: The custom domain (e.g., "secure.example.com")
        acme_subdomain: The subdomain in our ACME zone for the TXT record
                        (e.g., "secure--example--com")
        skip_sync: If True, skip triggering cert sync (caller will batch it)

    Returns:
        Status dict with provisioning outcome
    """
    logger.info(f"Provisioning certificate for domain: {domain}")

    try:
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

        # Store certificate in Secrets Manager
        secret_arn = store_certificate(domain, private_key_pem, cert_pem, chain_pem, expires_at, acme_subdomain)

        # Update DynamoDB domain status
        update_domain_status(domain, STATUS_ACTIVE, secret_arn, expires_at)

        # Trigger cert sync on AC instances (unless caller will batch it)
        if not skip_sync:
            trigger_cert_sync(domain)

        logger.info(f"Certificate provisioned successfully for {domain}, expires: {expires_at}")
        send_alert(f"Certificate provisioned for {domain}. Expires: {expires_at}", is_error=False)

        return {
            'status': RESULT_PROVISIONED,
            'domain': domain,
            'expires_at': expires_at,
            'secret_arn': secret_arn
        }

    except Exception as e:
        logger.error(f"Certificate provisioning failed for {domain}: {str(e)}", exc_info=True)
        update_domain_status(domain, STATUS_CERT_FAILED, error=str(e))
        send_alert(f"Certificate provisioning FAILED for {domain}: {str(e)}")
        publish_failure_metric()
        raise


def renewal_scan() -> Dict[str, Any]:
    """
    Scan all custom domain certificates and renew those approaching expiry.

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

    # List all secrets with our prefix
    secrets = list_custom_domain_secrets()
    results['scanned'] = len(secrets)
    expiry_metrics = []  # Batch metrics for a single put_metric_data call

    for secret_info in secrets:
        secret_name = secret_info['Name']
        # Extract domain from secret name: {prefix}/{domain}
        domain = secret_name.replace(f"{SECRETS_PREFIX}/", "", 1)

        try:
            # Get secret value to check expiry
            response = secrets_client.get_secret_value(SecretId=secret_info['ARN'])
            secret_data = json.loads(response['SecretString'])

            expires_at_str = secret_data.get(FIELD_EXPIRES_AT)
            if not expires_at_str:
                logger.warning(f"No {FIELD_EXPIRES_AT} in secret for {domain}, skipping")
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
                acme_subdomain = secret_data.get(FIELD_ACME_SUBDOMAIN)
                if not acme_subdomain:
                    # Derive from domain: secure.example.com -> secure--example--com
                    logger.warning(f"Secret for {domain} missing '{FIELD_ACME_SUBDOMAIN}' field, deriving from domain name")
                    acme_subdomain = domain.replace('.', '--')

                provision_certificate(domain, acme_subdomain, skip_sync=True)
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
            results['failed'] += 1
            results['details'].append({
                'domain': domain,
                'action': 'failed',
                'error': str(e)
            })

    # Publish all expiry metrics in a single API call (max 1000 per call)
    if expiry_metrics:
        try:
            cloudwatch_client.put_metric_data(
                Namespace=CW_NAMESPACE,
                MetricData=expiry_metrics[:1000]
            )
            logger.info(f"Published {len(expiry_metrics)} expiry metrics")
        except Exception as e:
            logger.error(f"Failed to publish batched expiry metrics: {e}")

    # Trigger a single cert sync after all renewals (instead of per-domain)
    if results['renewed'] > 0:
        logger.info(f"Triggering cert sync after {results['renewed']} renewal(s)")
        trigger_cert_sync('renewal-scan-batch')

    logger.info(f"Renewal scan complete: {results['scanned']} scanned, "
                f"{results['renewed']} renewed, {results['failed']} failed, "
                f"{results['skipped']} skipped")

    if results['failed'] > 0:
        send_alert(f"Renewal scan completed with {results['failed']} failure(s)")

    return results


def list_custom_domain_secrets() -> list:
    """List all Secrets Manager secrets with our prefix."""
    secrets = []
    paginator = secrets_client.get_paginator('list_secrets')

    for page in paginator.paginate(
        Filters=[
            {
                'Key': 'name',
                'Values': [f"{SECRETS_PREFIX}/"]
            }
        ]
    ):
        for secret in page.get('SecretList', []):
            secrets.append(secret)

    logger.info(f"Found {len(secrets)} custom domain certificate secrets")
    return secrets


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
        create_acme_txt_record(txt_record_name, validation)

        # Wait for DNS propagation
        wait_for_dns_propagation(txt_record_name, validation)

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


def delete_acme_txt_record(record_name: str):
    """Delete TXT record from the ACME delegation zone after challenge completion."""
    logger.info(f"Deleting DNS TXT record: {record_name}")

    try:
        response = route53_client.list_resource_record_sets(
            HostedZoneId=ACME_ZONE_ID,
            StartRecordName=record_name,
            StartRecordType='TXT',
            MaxItems='1'
        )

        records = response.get('ResourceRecordSets', [])
        if not records or records[0]['Name'].rstrip('.') != record_name.rstrip('.'):
            logger.info(f"DNS record {record_name} not found, skipping delete")
            return

        record = records[0]
        route53_client.change_resource_record_sets(
            HostedZoneId=ACME_ZONE_ID,
            ChangeBatch={
                'Changes': [{
                    'Action': 'DELETE',
                    'ResourceRecordSet': record
                }]
            }
        )
    except ClientError as e:
        logger.warning(f"Failed to delete DNS record: {e}")


def lazy_import_dns():
    """Lazy import dns.resolver to reduce cold start when DNS checks aren't needed."""
    global dns_resolver
    if dns_resolver is None:
        import dns.resolver as _dns_resolver
        dns_resolver = _dns_resolver


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


def store_certificate(domain: str, private_key_pem: str, cert_pem: str, chain_pem: str,
                      expires_at: str, acme_subdomain: str = None) -> str:
    """
    Store certificate in Secrets Manager.

    Creates a new secret or updates an existing one at {prefix}/{domain}.

    Returns:
        ARN of the secret
    """
    secret_name = f"{SECRETS_PREFIX}/{domain}"
    fullchain = cert_pem + chain_pem

    if not acme_subdomain:
        acme_subdomain = domain.replace('.', '--')

    secret_value = {
        FIELD_PRIVATE_KEY: private_key_pem,
        FIELD_CERTIFICATE: cert_pem,
        FIELD_CHAIN: chain_pem,
        FIELD_FULLCHAIN: fullchain,
        FIELD_EXPIRES_AT: expires_at,
        FIELD_DOMAIN: domain,
        FIELD_ACME_SUBDOMAIN: acme_subdomain,
        FIELD_RENEWED_AT: datetime.now(timezone.utc).isoformat(),
        FIELD_STATUS: STATUS_ACTIVE,
    }

    logger.info(f"Storing certificate in Secrets Manager: {secret_name}")

    try:
        # Try to update existing secret
        response = secrets_client.put_secret_value(
            SecretId=secret_name,
            SecretString=json.dumps(secret_value)
        )
        return response['ARN']
    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            # Create new secret
            create_kwargs = {
                'Name': secret_name,
                'Description': f"TLS certificate for custom domain {domain}",
                'SecretString': json.dumps(secret_value),
                'Tags': [
                    {'Key': 'Module', 'Value': 'custom-domain-cert'},
                    {'Key': 'Domain', 'Value': domain}
                ]
            }
            if KMS_KEY_ARN:
                create_kwargs['KmsKeyId'] = KMS_KEY_ARN

            response = secrets_client.create_secret(**create_kwargs)
            logger.info(f"Created new secret for {domain}")
            return response['ARN']
        raise


def update_domain_status(domain: str, status: str, cert_secret_arn: str = None,
                         cert_expires_at: str = None, error: str = None):
    """Update domain status in the qurl-domains DynamoDB table."""
    if not QURL_DOMAINS_TABLE:
        logger.info("No QURL_DOMAINS_TABLE configured, skipping status update")
        return

    try:
        update_expr_parts = ['#s = :status', '#ua = :updated_at']
        expr_names = {
            '#s': 'cert_status',
            '#ua': 'updated_at'
        }
        expr_values = {
            ':status': {'S': status},
            ':updated_at': {'S': datetime.now(timezone.utc).isoformat()}
        }

        if cert_secret_arn:
            update_expr_parts.append('#csa = :cert_secret_arn')
            expr_names['#csa'] = 'cert_secret_arn'
            expr_values[':cert_secret_arn'] = {'S': cert_secret_arn}

        if cert_expires_at:
            update_expr_parts.append('#cea = :cert_expires_at')
            expr_names['#cea'] = 'cert_expires_at'
            expr_values[':cert_expires_at'] = {'S': cert_expires_at}

        if error:
            update_expr_parts.append('#err = :error')
            expr_names['#err'] = 'cert_error'
            expr_values[':error'] = {'S': error[:500]}

        dynamodb_client.update_item(
            TableName=QURL_DOMAINS_TABLE,
            Key={
                'domain': {'S': domain}
            },
            UpdateExpression='SET ' + ', '.join(update_expr_parts),
            ExpressionAttributeNames=expr_names,
            ExpressionAttributeValues=expr_values
        )
        logger.info(f"Updated domain status for {domain}: {status}")
    except Exception as e:
        logger.error(f"Failed to update domain status for {domain}: {e}")


def trigger_cert_sync(domain: str):
    """Trigger certificate sync on AC instances via SSM SendCommand."""
    try:
        ac_instance_tag = os.environ.get('AC_INSTANCE_TAG')
        if not ac_instance_tag:
            logger.info("No AC_INSTANCE_TAG configured, skipping cert sync trigger")
            return

        # Parse tag name:value from the tag string
        # Tag format is the Name tag value for the instances
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
                    '/home/ubuntu/scripts/custom-domain-cert-sync.sh || true'
                ]
            },
            TimeoutSeconds=120,
            Comment=f'Cert sync triggered for custom domain: {domain}'
        )
        command_id = response['Command']['CommandId']
        logger.info(f"Triggered cert sync on AC instances, command: {command_id}")
    except Exception as e:
        logger.error(f"Failed to trigger cert sync: {e}")


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


def publish_metric(metric_name: str, value: float, dimensions: list = None):
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


def publish_failure_metric():
    """Publish a provisioning failure metric to CloudWatch."""
    publish_metric(CW_METRIC_PROVISIONING_FAILURES, 1)
