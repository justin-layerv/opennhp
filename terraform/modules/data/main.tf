# Data Module
# etcd cluster, EFS, Secrets, Service Discovery

# ==================== Data Sources ====================

data "aws_region" "current" {}
data "aws_caller_identity" "current" {}

# ==================== Locals ====================

locals {
  is_prod            = var.environment == "prod"
  etcd_cluster_size  = local.is_prod ? 3 : 1
  etcd_cluster_token = "${var.name_prefix}-cluster"

  # Protocol for etcd communication - HTTPS with TLS
  etcd_protocol = "https"

  # Etcd service DNS name based on cluster size:
  # - Single-node (sandbox): Use shared 'etcd' service for simplicity
  # - Multi-node (prod): Use member-specific 'etcd-N' services for peer discovery
  etcd_service_name = local.etcd_cluster_size == 1 ? "etcd" : "etcd-0"

  # Generate etcd cluster member names and URLs for initial cluster formation
  # Single-node: Uses 'etcd' as the DNS name
  # Multi-node: Uses 'etcd-N' for each member for proper peer discovery
  etcd_initial_cluster = local.etcd_cluster_size == 1 ? (
    "etcd-0=${local.etcd_protocol}://etcd.nhp.${var.environment}.internal:2380"
    ) : (
    join(",", [
      for i in range(local.etcd_cluster_size) :
      "etcd-${i}=${local.etcd_protocol}://etcd-${i}.nhp.${var.environment}.internal:2380"
    ])
  )

  # Certificate paths inside container
  etcd_cert_dir = "/etc/etcd/tls"
}

# Private DNS Namespace for Service Discovery
resource "aws_service_discovery_private_dns_namespace" "main" {
  name        = "nhp.${var.environment}.internal"
  vpc         = var.vpc_id
  description = "LayerV NHP ${var.environment} internal service discovery"

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-namespace"
    Component = "data"
  })
}

# etcd credentials and TLS certificates
resource "random_password" "etcd" {
  count   = var.multi_tenant ? 1 : 0
  length  = 32
  special = false
}

resource "aws_secretsmanager_secret" "etcd" {
  count                   = var.multi_tenant ? 1 : 0
  name                    = "${var.name_prefix}-etcd-credentials"
  description             = "etcd authentication credentials for NHP ${var.environment}"
  recovery_window_in_days = local.is_prod ? 30 : 0
  kms_key_id              = var.secrets_kms_key_arn

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-etcd-credentials"
    Component = "data"
  })
}

resource "aws_secretsmanager_secret_version" "etcd" {
  count     = var.multi_tenant ? 1 : 0
  secret_id = aws_secretsmanager_secret.etcd[0].id
  secret_string = jsonencode({
    username = "root"
    password = random_password.etcd[0].result
  })

  lifecycle {
    ignore_changes = [secret_string]
  }
}

# TLS Certificates for etcd (CA + server certs)
resource "aws_secretsmanager_secret" "etcd_tls" {
  count                   = var.multi_tenant ? 1 : 0
  name                    = "${var.name_prefix}-etcd-tls"
  description             = "etcd mTLS certificates (CA, server, client) for NHP ${var.environment}"
  recovery_window_in_days = local.is_prod ? 30 : 0
  kms_key_id              = var.secrets_kms_key_arn

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-etcd-tls"
    Component = "data"
  })
}

# TLS certificate generation Lambda (Python with cryptography library)
resource "aws_iam_role" "etcd_tls_lambda" {
  count = var.multi_tenant ? 1 : 0
  name  = "${var.name_prefix}-etcd-tls-lambda"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
    }]
  })

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-etcd-tls-lambda"
    Component = "data"
  })
}

resource "aws_iam_role_policy_attachment" "etcd_tls_lambda_basic" {
  count      = var.multi_tenant ? 1 : 0
  role       = aws_iam_role.etcd_tls_lambda[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy" "etcd_tls_lambda_secrets" {
  count = var.multi_tenant ? 1 : 0
  name  = "secrets-access"
  role  = aws_iam_role.etcd_tls_lambda[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:PutSecretValue"
        ]
        Resource = aws_secretsmanager_secret.etcd_tls[0].arn
      },
      {
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = var.secrets_kms_key_arn
      }
    ]
  })
}

# Lambda layer for cryptography library
# NOTE: The layer zip must be pre-built before running terraform apply.
# Build using: docker run --rm -v "/tmp/lambda-layer-build:/output" public.ecr.aws/lambda/python:3.11 \
#   sh -c "pip install cryptography -t /output/python --no-cache-dir && cd /output && zip -r cryptography-layer.zip python/"
resource "aws_lambda_layer_version" "cryptography" {
  count               = var.multi_tenant ? 1 : 0
  layer_name          = "${var.name_prefix}-cryptography"
  description         = "Python cryptography library for Lambda"
  filename            = "/tmp/lambda-layer-build/cryptography-layer.zip"
  source_code_hash    = filebase64sha256("/tmp/lambda-layer-build/cryptography-layer.zip")
  compatible_runtimes = ["python3.11"]
}

# Lambda to generate TLS certificates using cryptography library
data "archive_file" "etcd_tls_lambda" {
  count       = var.multi_tenant ? 1 : 0
  type        = "zip"
  output_path = "${path.module}/etcd_tls_lambda.zip"

  source {
    content  = <<-PYTHON
import json
import boto3
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import ipaddress

def generate_certificates(dns_names, ip_addresses):
    """Generate CA, server, and client certificates for etcd mTLS."""

    # Generate CA key pair
    ca_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Generate CA certificate (10 years)
    ca_subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "etcd-ca"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "LayerV"),
    ])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_subject)
        .issuer_name(ca_subject)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=3650))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=0),
            critical=True
        )
        .sign(ca_key, hashes.SHA256(), default_backend())
    )

    # Generate server key pair
    server_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Build SANs for server certificate
    san_list = [x509.DNSName(name) for name in dns_names]
    san_list.extend([x509.IPAddress(ipaddress.ip_address(ip)) for ip in ip_addresses])

    # Generate server certificate (1 year)
    server_subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "etcd-server"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "LayerV"),
    ])
    server_cert = (
        x509.CertificateBuilder()
        .subject_name(server_subject)
        .issuer_name(ca_subject)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True
        )
        .add_extension(
            x509.SubjectAlternativeName(san_list),
            critical=False
        )
        .add_extension(
            x509.ExtendedKeyUsage([
                ExtendedKeyUsageOID.SERVER_AUTH,
                ExtendedKeyUsageOID.CLIENT_AUTH
            ]),
            critical=False
        )
        .sign(ca_key, hashes.SHA256(), default_backend())
    )

    # Generate client key pair
    client_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Generate client certificate (1 year)
    client_subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "etcd-client"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "LayerV"),
    ])
    client_cert = (
        x509.CertificateBuilder()
        .subject_name(client_subject)
        .issuer_name(ca_subject)
        .public_key(client_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False
        )
        .sign(ca_key, hashes.SHA256(), default_backend())
    )

    return {
        'caCert': ca_cert.public_bytes(serialization.Encoding.PEM).decode(),
        'caKey': ca_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ).decode(),
        'serverCert': server_cert.public_bytes(serialization.Encoding.PEM).decode(),
        'serverKey': server_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ).decode(),
        'clientCert': client_cert.public_bytes(serialization.Encoding.PEM).decode(),
        'clientKey': client_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ).decode(),
    }

def handler(event, context):
    print(f"TLS cert generation event: {json.dumps(event)}")

    if event.get('RequestType') == 'Delete':
        return {'PhysicalResourceId': event.get('PhysicalResourceId')}

    secrets_client = boto3.client('secretsmanager')
    secret_id = event['ResourceProperties']['SecretId']
    cluster_size = int(event['ResourceProperties'].get('ClusterSize', 1))
    environment = event['ResourceProperties']['Environment']
    force_regenerate = event['ResourceProperties'].get('ForceRegenerate', False)

    # Check if valid certs already exist (unless forced)
    if not force_regenerate:
        try:
            existing = secrets_client.get_secret_value(SecretId=secret_id)
            if existing.get('SecretString'):
                parsed = json.loads(existing['SecretString'])
                # Validate cert format (should start with proper PEM header)
                # Include clientCert check for mTLS support
                if (parsed.get('caCert', '').startswith('-----BEGIN CERTIFICATE-----') and
                    parsed.get('serverCert', '').startswith('-----BEGIN CERTIFICATE-----') and
                    parsed.get('serverKey', '').startswith('-----BEGIN') and
                    parsed.get('clientCert', '').startswith('-----BEGIN CERTIFICATE-----') and
                    parsed.get('clientKey', '').startswith('-----BEGIN')):
                    print("Valid TLS certs (including client cert) already exist, not regenerating")
                    return {'PhysicalResourceId': event.get('PhysicalResourceId') or secret_id}
                print("Existing certs are invalid or missing client cert, regenerating")
        except Exception as e:
            print(f"No existing certs or error reading: {e}")

    # Generate DNS names for etcd members
    dns_names = ['localhost']
    dns_names.append(f'etcd.nhp.{environment}.internal')
    for i in range(cluster_size):
        dns_names.append(f'etcd-{i}.nhp.{environment}.internal')

    print(f"Generating certs for DNS names: {dns_names}")
    certs = generate_certificates(dns_names, ['127.0.0.1'])
    certs['dnsNames'] = dns_names
    certs['generatedAt'] = datetime.utcnow().isoformat()

    secrets_client.put_secret_value(
        SecretId=secret_id,
        SecretString=json.dumps(certs)
    )

    print("TLS certificates generated and stored successfully")
    return {'PhysicalResourceId': event.get('PhysicalResourceId') or secret_id}
PYTHON
    filename = "lambda_function.py"
  }
}

resource "aws_lambda_function" "etcd_tls" {
  count            = var.multi_tenant ? 1 : 0
  function_name    = "${var.name_prefix}-etcd-tls-gen"
  role             = aws_iam_role.etcd_tls_lambda[0].arn
  handler          = "lambda_function.handler"
  runtime          = "python3.11"
  timeout          = 60
  filename         = data.archive_file.etcd_tls_lambda[0].output_path
  source_code_hash = data.archive_file.etcd_tls_lambda[0].output_base64sha256

  # Attach cryptography layer for certificate generation
  layers = [aws_lambda_layer_version.cryptography[0].arn]

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-etcd-tls-gen"
    Component = "data"
  })

  depends_on = [aws_lambda_layer_version.cryptography]
}

# Invoke Lambda to generate TLS certs
# Uses triggers to force regeneration when Lambda code changes or manually triggered
resource "aws_lambda_invocation" "etcd_tls" {
  count         = var.multi_tenant ? 1 : 0
  function_name = aws_lambda_function.etcd_tls[0].function_name

  input = jsonencode({
    RequestType = "Create"
    ResourceProperties = {
      SecretId        = aws_secretsmanager_secret.etcd_tls[0].id
      ClusterSize     = local.etcd_cluster_size
      Environment     = var.environment
      ForceRegenerate = true
    }
  })

  triggers = {
    # Regenerate when Lambda code changes (includes SAN configuration)
    lambda_hash = aws_lambda_function.etcd_tls[0].source_code_hash
    # Increment to force regeneration: v2 = add DNS SANs for etcd.nhp.{env}.internal
    force_regen = "2"
  }

  depends_on = [aws_iam_role_policy.etcd_tls_lambda_secrets]
}

# Secrets rotation for etcd credentials (production only)
resource "aws_iam_role" "secrets_rotation" {
  count = var.multi_tenant && local.is_prod ? 1 : 0
  name  = "${var.name_prefix}-secrets-rotation"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
    }]
  })

  tags = var.tags
}

resource "aws_iam_role_policy_attachment" "secrets_rotation_basic" {
  count      = var.multi_tenant && local.is_prod ? 1 : 0
  role       = aws_iam_role.secrets_rotation[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# VPC access policy for secrets rotation Lambda
resource "aws_iam_role_policy_attachment" "secrets_rotation_vpc" {
  count      = var.multi_tenant && local.is_prod ? 1 : 0
  role       = aws_iam_role.secrets_rotation[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}

resource "aws_iam_role_policy" "secrets_rotation" {
  count = var.multi_tenant && local.is_prod ? 1 : 0
  name  = "secrets-rotation"
  role  = aws_iam_role.secrets_rotation[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:PutSecretValue",
          "secretsmanager:UpdateSecretVersionStage",
          "secretsmanager:DescribeSecret"
        ]
        Resource = aws_secretsmanager_secret.etcd[0].arn
      },
      {
        Effect   = "Allow"
        Action   = ["secretsmanager:GetRandomPassword"]
        Resource = "*"
      }
    ]
  })
}

data "archive_file" "secrets_rotation" {
  count       = var.multi_tenant && local.is_prod ? 1 : 0
  type        = "zip"
  output_path = "${path.module}/secrets_rotation.zip"

  source {
    content  = <<-EOF
const { SecretsManagerClient, GetSecretValueCommand, PutSecretValueCommand, GetRandomPasswordCommand, UpdateSecretVersionStageCommand, DescribeSecretCommand } = require('@aws-sdk/client-secrets-manager');
const https = require('https');

// Helper to make HTTP requests to etcd
async function etcdRequest(endpoint, method, path, auth, body = null) {
  return new Promise((resolve, reject) => {
    const url = new URL(path, endpoint);
    const options = {
      hostname: url.hostname,
      port: url.port || 2379,
      path: url.pathname,
      method: method,
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Basic ' + Buffer.from(auth.username + ':' + auth.password).toString('base64')
      }
    };

    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          resolve({ status: res.statusCode, data: data ? JSON.parse(data) : null });
        } catch (e) {
          resolve({ status: res.statusCode, data: data });
        }
      });
    });

    req.on('error', reject);
    if (body) req.write(JSON.stringify(body));
    req.end();
  });
}

exports.handler = async (event) => {
  console.log('Rotation event:', JSON.stringify(event));

  const client = new SecretsManagerClient({});
  const secretId = event.SecretId;
  const step = event.Step;
  const token = event.ClientRequestToken;
  const etcdEndpoint = process.env.ETCD_ENDPOINT;

  switch (step) {
    case 'createSecret':
      // Generate new password
      const randomPw = await client.send(new GetRandomPasswordCommand({
        PasswordLength: 32,
        ExcludeCharacters: '"@/\\'
      }));

      const currentSecret = await client.send(new GetSecretValueCommand({
        SecretId: secretId,
        VersionStage: 'AWSCURRENT'
      }));

      const current = JSON.parse(currentSecret.SecretString);
      const newSecret = {
        username: current.username,
        password: randomPw.RandomPassword
      };

      await client.send(new PutSecretValueCommand({
        SecretId: secretId,
        ClientRequestToken: token,
        SecretString: JSON.stringify(newSecret),
        VersionStages: ['AWSPENDING']
      }));
      console.log('createSecret: New password generated and stored as AWSPENDING');
      break;

    case 'setSecret':
      // Update etcd with the new credentials
      // This step sets the new password in etcd before testing
      if (!etcdEndpoint) {
        console.log('setSecret: ETCD_ENDPOINT not configured, skipping etcd update');
        break;
      }

      try {
        const pendingSecret = await client.send(new GetSecretValueCommand({
          SecretId: secretId,
          VersionStage: 'AWSPENDING',
          VersionId: token
        }));
        const pending = JSON.parse(pendingSecret.SecretString);

        const currentForAuth = await client.send(new GetSecretValueCommand({
          SecretId: secretId,
          VersionStage: 'AWSCURRENT'
        }));
        const auth = JSON.parse(currentForAuth.SecretString);

        // Update etcd root user password using current credentials
        const response = await etcdRequest(
          etcdEndpoint,
          'POST',
          '/v3/auth/user/changepw',
          auth,
          { name: pending.username, password: pending.password }
        );

        if (response.status >= 200 && response.status < 300) {
          console.log('setSecret: Successfully updated etcd password');
        } else {
          throw new Error('Failed to update etcd password: ' + JSON.stringify(response));
        }
      } catch (error) {
        console.error('setSecret error:', error);
        throw error;
      }
      break;

    case 'testSecret':
      // Verify the new credentials work against etcd
      if (!etcdEndpoint) {
        console.log('testSecret: ETCD_ENDPOINT not configured, skipping verification');
        break;
      }

      try {
        const pendingSecret = await client.send(new GetSecretValueCommand({
          SecretId: secretId,
          VersionStage: 'AWSPENDING',
          VersionId: token
        }));
        const pending = JSON.parse(pendingSecret.SecretString);

        // Test connectivity with new credentials
        const response = await etcdRequest(
          etcdEndpoint,
          'POST',
          '/v3/auth/authenticate',
          pending,
          { name: pending.username, password: pending.password }
        );

        if (response.status >= 200 && response.status < 300) {
          console.log('testSecret: New credentials verified successfully');
        } else {
          throw new Error('testSecret: Authentication failed with new credentials');
        }
      } catch (error) {
        console.error('testSecret error:', error);
        throw error;
      }
      break;

    case 'finishSecret':
      // Move AWSPENDING to AWSCURRENT
      const desc = await client.send(new DescribeSecretCommand({ SecretId: secretId }));
      const currentVersion = Object.keys(desc.VersionIdsToStages || {})
        .find(v => (desc.VersionIdsToStages[v] || []).includes('AWSCURRENT'));

      if (currentVersion && currentVersion !== token) {
        await client.send(new UpdateSecretVersionStageCommand({
          SecretId: secretId,
          VersionStage: 'AWSCURRENT',
          MoveToVersionId: token,
          RemoveFromVersionId: currentVersion
        }));
        console.log('finishSecret: Rotation completed, AWSPENDING promoted to AWSCURRENT');
      }
      break;
  }

  return { statusCode: 200 };
};
EOF
    filename = "index.js"
  }
}

resource "aws_lambda_function" "secrets_rotation" {
  count            = var.multi_tenant && local.is_prod ? 1 : 0
  function_name    = "${var.name_prefix}-secrets-rotation"
  role             = aws_iam_role.secrets_rotation[0].arn
  handler          = "index.handler"
  runtime          = "nodejs20.x"
  timeout          = 60
  filename         = data.archive_file.secrets_rotation[0].output_path
  source_code_hash = data.archive_file.secrets_rotation[0].output_base64sha256

  environment {
    variables = {
      # Use shared etcd service for single-node, first member for multi-node
      ETCD_ENDPOINT = local.etcd_cluster_size == 1 ? (
        "http://etcd.${aws_service_discovery_private_dns_namespace.main.name}:2379"
        ) : (
        "http://etcd-0.${aws_service_discovery_private_dns_namespace.main.name}:2379"
      )
    }
  }

  # Lambda needs VPC access to reach etcd
  vpc_config {
    subnet_ids         = var.private_subnet_ids
    security_group_ids = [aws_security_group.etcd[0].id]
  }

  tags = var.tags
}

resource "aws_lambda_permission" "secrets_rotation" {
  count         = var.multi_tenant && local.is_prod ? 1 : 0
  statement_id  = "AllowSecretsManagerInvocation"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.secrets_rotation[0].function_name
  principal     = "secretsmanager.amazonaws.com"
}

resource "aws_secretsmanager_secret_rotation" "etcd" {
  count               = var.multi_tenant && local.is_prod ? 1 : 0
  secret_id           = aws_secretsmanager_secret.etcd[0].id
  rotation_lambda_arn = aws_lambda_function.secrets_rotation[0].arn

  rotation_rules {
    automatically_after_days = 30
  }

  depends_on = [aws_lambda_permission.secrets_rotation]
}

# Security Group for EFS mount targets
# Separate from etcd SG to allow proper NFS connectivity
resource "aws_security_group" "efs" {
  count       = var.multi_tenant ? 1 : 0
  name_prefix = "${var.name_prefix}-efs-"
  vpc_id      = var.vpc_id
  description = "Security group for EFS mount targets"

  # NFS from private subnets (where Fargate tasks run)
  ingress {
    from_port   = 2049
    to_port     = 2049
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
    description = "NFS from VPC"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "All outbound"
  }

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-sg-efs"
    Component = "data"
  })

  lifecycle {
    create_before_destroy = true
  }
}

# Security Group for etcd ECS tasks
resource "aws_security_group" "etcd" {
  count       = var.multi_tenant ? 1 : 0
  name_prefix = "${var.name_prefix}-etcd-"
  vpc_id      = var.vpc_id
  description = "Security group for etcd cluster"

  # etcd client port from VPC
  ingress {
    from_port   = 2379
    to_port     = 2379
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
    description = "etcd client port"
  }

  # etcd peer port (self)
  ingress {
    from_port   = 2380
    to_port     = 2380
    protocol    = "tcp"
    self        = true
    description = "etcd peer port"
  }

  # etcd peer outbound
  egress {
    from_port   = 2380
    to_port     = 2380
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
    description = "etcd peer outbound"
  }

  # NFS outbound to EFS mount targets
  egress {
    from_port       = 2049
    to_port         = 2049
    protocol        = "tcp"
    security_groups = [aws_security_group.efs[0].id]
    description     = "NFS to EFS"
  }

  # HTTPS for AWS APIs (ECR, Secrets Manager, CloudWatch)
  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTPS for AWS APIs"
  }

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-sg-etcd"
    Component = "data"
  })

  lifecycle {
    create_before_destroy = true
  }
}

# EFS for etcd persistent data
resource "aws_efs_file_system" "etcd" {
  count          = var.multi_tenant ? 1 : 0
  creation_token = "${var.name_prefix}-etcd"
  encrypted      = true
  kms_key_id     = var.efs_kms_key_arn

  performance_mode = "generalPurpose"
  throughput_mode  = "bursting"

  lifecycle_policy {
    transition_to_ia = "AFTER_14_DAYS"
  }

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-efs-etcd"
    Component = "data"
  })

  # Prevent recreation of EFS with existing data due to KMS key changes
  lifecycle {
    ignore_changes = [kms_key_id]
  }
}

# EFS Backup Policy for disaster recovery
resource "aws_efs_backup_policy" "etcd" {
  count          = var.multi_tenant ? 1 : 0
  file_system_id = aws_efs_file_system.etcd[0].id

  backup_policy {
    status = "ENABLED"
  }
}

# EFS mount targets - use EFS security group, not etcd SG
resource "aws_efs_mount_target" "etcd" {
  count           = var.multi_tenant ? length(var.private_subnet_ids) : 0
  file_system_id  = aws_efs_file_system.etcd[0].id
  subnet_id       = var.private_subnet_ids[count.index]
  security_groups = [aws_security_group.efs[0].id]
}

# EFS Access Points - one per cluster member for data isolation
resource "aws_efs_access_point" "etcd" {
  for_each       = var.multi_tenant ? toset([for i in range(local.etcd_cluster_size) : tostring(i)]) : []
  file_system_id = aws_efs_file_system.etcd[0].id

  root_directory {
    # v2: Regenerated path after fixing ETCD_INITIAL_CLUSTER hostname
    path = "/etcd-data-${each.key}-v2"
    creation_info {
      owner_uid   = 1000
      owner_gid   = 1000
      permissions = "755"
    }
  }

  posix_user {
    uid = 1000
    gid = 1000
  }

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-efs-ap-etcd-${each.key}"
    Component = "data"
  })
}

# ECS Cluster for etcd
resource "aws_ecs_cluster" "etcd" {
  count = var.multi_tenant ? 1 : 0
  name  = "${var.name_prefix}-etcd"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-ecs-etcd"
    Component = "data"
  })
}

# CloudWatch Log Group for etcd
resource "aws_cloudwatch_log_group" "etcd" {
  count             = var.multi_tenant ? 1 : 0
  name              = "/layerv/nhp/${var.environment}/etcd"
  retention_in_days = 30
  kms_key_id        = var.logs_kms_key_arn

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-logs-etcd"
    Component = "data"
  })
}

# ECS Task Execution Role
resource "aws_iam_role" "etcd_execution" {
  count = var.multi_tenant ? 1 : 0
  name  = "${var.name_prefix}-etcd-execution"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ecs-tasks.amazonaws.com"
      }
    }]
  })

  tags = var.tags
}

resource "aws_iam_role_policy_attachment" "etcd_execution" {
  count      = var.multi_tenant ? 1 : 0
  role       = aws_iam_role.etcd_execution[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

# ECS Execution Role - Secrets access for native secrets injection
resource "aws_iam_role_policy" "etcd_execution_secrets" {
  count = var.multi_tenant ? 1 : 0
  name  = "secrets-access"
  role  = aws_iam_role.etcd_execution[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue"
        ]
        Resource = [
          aws_secretsmanager_secret.etcd_tls[0].arn
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "kms:Decrypt"
        ]
        Resource = var.secrets_kms_key_arn
      }
    ]
  })
}

# ECS Task Role
resource "aws_iam_role" "etcd_task" {
  count = var.multi_tenant ? 1 : 0
  name  = "${var.name_prefix}-etcd-task"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ecs-tasks.amazonaws.com"
      }
    }]
  })

  tags = var.tags
}

resource "aws_iam_role_policy" "etcd_task" {
  count = var.multi_tenant ? 1 : 0
  name  = "etcd-task"
  role  = aws_iam_role.etcd_task[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue"
        ]
        Resource = [
          aws_secretsmanager_secret.etcd[0].arn,
          aws_secretsmanager_secret.etcd_tls[0].arn
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "kms:Decrypt"
        ]
        Resource = var.secrets_kms_key_arn
      },
      {
        Effect = "Allow"
        Action = [
          "elasticfilesystem:ClientMount",
          "elasticfilesystem:ClientWrite",
          "elasticfilesystem:ClientRootAccess"
        ]
        Resource = aws_efs_file_system.etcd[0].arn
        Condition = {
          StringEquals = {
            "elasticfilesystem:AccessPointArn" = [for ap in aws_efs_access_point.etcd : ap.arn]
          }
        }
      },
      {
        Effect = "Allow"
        Action = [
          "ssmmessages:CreateControlChannel",
          "ssmmessages:CreateDataChannel",
          "ssmmessages:OpenControlChannel",
          "ssmmessages:OpenDataChannel"
        ]
        Resource = "*"
      }
    ]
  })
}

# ECS Task Definition - one per cluster member with TLS and auth support
resource "aws_ecs_task_definition" "etcd" {
  for_each                 = var.multi_tenant ? toset([for i in range(local.etcd_cluster_size) : tostring(i)]) : []
  family                   = "${var.name_prefix}-etcd-${each.key}"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = "1024"
  memory                   = "2048"
  execution_role_arn       = aws_iam_role.etcd_execution[0].arn
  task_role_arn            = aws_iam_role.etcd_task[0].arn

  container_definitions = jsonencode([
    # Init container: Write TLS certificates to shared volume
    # ECS natively injects secrets as environment variables - no aws-cli or JSON parsing needed
    {
      name      = "tls-init"
      image     = "public.ecr.aws/docker/library/alpine:3.19"
      essential = false

      # ECS injects these from Secrets Manager automatically
      secrets = [
        {
          name      = "ETCD_CA_CERT"
          valueFrom = "${aws_secretsmanager_secret.etcd_tls[0].arn}:caCert::"
        },
        {
          name      = "ETCD_SERVER_CERT"
          valueFrom = "${aws_secretsmanager_secret.etcd_tls[0].arn}:serverCert::"
        },
        {
          name      = "ETCD_SERVER_KEY"
          valueFrom = "${aws_secretsmanager_secret.etcd_tls[0].arn}:serverKey::"
        }
      ]

      entryPoint = ["sh", "-c"]
      command = [
        join(" && ", [
          "set -e",
          "echo 'Writing TLS certificates from environment variables'",
          "mkdir -p ${local.etcd_cert_dir}",
          "printf '%s' \"$ETCD_CA_CERT\" > ${local.etcd_cert_dir}/ca.crt",
          "printf '%s' \"$ETCD_SERVER_CERT\" > ${local.etcd_cert_dir}/server.crt",
          "printf '%s' \"$ETCD_SERVER_KEY\" > ${local.etcd_cert_dir}/server.key",
          "chmod 644 ${local.etcd_cert_dir}/ca.crt ${local.etcd_cert_dir}/server.crt",
          "chmod 600 ${local.etcd_cert_dir}/server.key",
          "echo 'TLS certificates written successfully'",
          "ls -la ${local.etcd_cert_dir}/"
        ])
      ]

      mountPoints = [{
        sourceVolume  = "tls-certs"
        containerPath = local.etcd_cert_dir
        readOnly      = false
      }]

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.etcd[0].name
          "awslogs-region"        = data.aws_region.current.name
          "awslogs-stream-prefix" = "etcd-${each.key}-tls-init"
        }
      }
    },
    # Main etcd container with TLS enabled
    {
      name      = "etcd"
      image     = "quay.io/coreos/etcd:v3.5.11"
      essential = true

      dependsOn = [{
        containerName = "tls-init"
        condition     = "SUCCESS"
      }]

      portMappings = [
        { containerPort = 2379, protocol = "tcp" },
        { containerPort = 2380, protocol = "tcp" }
      ]

      environment = [
        { name = "ETCD_NAME", value = "etcd-${each.key}" },
        { name = "ETCD_DATA_DIR", value = "/etcd-data" },
        # Client TLS configuration
        { name = "ETCD_LISTEN_CLIENT_URLS", value = "https://0.0.0.0:2379" },
        { name = "ETCD_CERT_FILE", value = "${local.etcd_cert_dir}/server.crt" },
        { name = "ETCD_KEY_FILE", value = "${local.etcd_cert_dir}/server.key" },
        { name = "ETCD_TRUSTED_CA_FILE", value = "${local.etcd_cert_dir}/ca.crt" },
        # Peer TLS configuration
        { name = "ETCD_LISTEN_PEER_URLS", value = "https://0.0.0.0:2380" },
        { name = "ETCD_PEER_CERT_FILE", value = "${local.etcd_cert_dir}/server.crt" },
        { name = "ETCD_PEER_KEY_FILE", value = "${local.etcd_cert_dir}/server.key" },
        { name = "ETCD_PEER_TRUSTED_CA_FILE", value = "${local.etcd_cert_dir}/ca.crt" },
        # Single-node uses shared 'etcd' service; multi-node uses member-specific 'etcd-N'
        { name = "ETCD_ADVERTISE_CLIENT_URLS", value = local.etcd_cluster_size == 1 ? (
          "${local.etcd_protocol}://etcd.nhp.${var.environment}.internal:2379"
          ) : (
          "${local.etcd_protocol}://etcd-${each.key}.nhp.${var.environment}.internal:2379"
        ) },
        { name = "ETCD_INITIAL_ADVERTISE_PEER_URLS", value = local.etcd_cluster_size == 1 ? (
          "${local.etcd_protocol}://etcd.nhp.${var.environment}.internal:2380"
          ) : (
          "${local.etcd_protocol}://etcd-${each.key}.nhp.${var.environment}.internal:2380"
        ) },
        { name = "ETCD_INITIAL_CLUSTER", value = local.etcd_initial_cluster },
        { name = "ETCD_INITIAL_CLUSTER_STATE", value = "new" },
        { name = "ETCD_INITIAL_CLUSTER_TOKEN", value = local.etcd_cluster_token },
        { name = "ETCD_AUTO_COMPACTION_RETENTION", value = "1" },
        { name = "ETCD_AUTO_COMPACTION_MODE", value = "periodic" },
        { name = "ETCD_QUOTA_BACKEND_BYTES", value = "1073741824" },
        # Require client certificate authentication for mTLS security
        { name = "ETCD_CLIENT_CERT_AUTH", value = "true" }
      ]

      mountPoints = [
        {
          sourceVolume  = "etcd-data"
          containerPath = "/etcd-data"
          readOnly      = false
        },
        {
          sourceVolume  = "tls-certs"
          containerPath = local.etcd_cert_dir
          readOnly      = true
        }
      ]

      healthCheck = {
        command = [
          "CMD-SHELL",
          "ETCDCTL_API=3 etcdctl --endpoints=https://127.0.0.1:2379 --cacert=${local.etcd_cert_dir}/ca.crt --cert=${local.etcd_cert_dir}/server.crt --key=${local.etcd_cert_dir}/server.key endpoint health || exit 1"
        ]
        interval    = 30
        timeout     = 10
        retries     = 5
        startPeriod = 180
      }

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.etcd[0].name
          "awslogs-region"        = data.aws_region.current.name
          "awslogs-stream-prefix" = "etcd-${each.key}"
        }
      }
    }
  ])

  volume {
    name = "etcd-data"

    efs_volume_configuration {
      file_system_id     = aws_efs_file_system.etcd[0].id
      transit_encryption = "ENABLED"
      authorization_config {
        access_point_id = aws_efs_access_point.etcd[each.key].id
        iam             = "ENABLED"
      }
    }
  }

  # Shared volume for TLS certificates (between init and main container)
  volume {
    name = "tls-certs"
  }

  tags = var.tags
}

# Cloud Map Service for etcd members (one per cluster member for stable naming)
resource "aws_service_discovery_service" "etcd" {
  for_each = var.multi_tenant ? toset([for i in range(local.etcd_cluster_size) : "etcd-${i}"]) : []
  name     = each.key

  dns_config {
    namespace_id = aws_service_discovery_private_dns_namespace.main.id

    dns_records {
      ttl  = 30
      type = "A"
    }

    routing_policy = "MULTIVALUE"
  }

  health_check_custom_config {
    failure_threshold = 1
  }

  tags = var.tags
}

# Cloud Map Service for etcd client connections (all members)
resource "aws_service_discovery_service" "etcd_client" {
  count = var.multi_tenant ? 1 : 0
  name  = "etcd"

  dns_config {
    namespace_id = aws_service_discovery_private_dns_namespace.main.id

    dns_records {
      ttl  = 30
      type = "A"
    }

    routing_policy = "MULTIVALUE"
  }

  health_check_custom_config {
    failure_threshold = 1
  }

  tags = var.tags
}

# ECS Service for etcd - one per cluster member
resource "aws_ecs_service" "etcd" {
  for_each        = var.multi_tenant ? toset([for i in range(local.etcd_cluster_size) : tostring(i)]) : []
  name            = "${var.name_prefix}-etcd-${each.key}"
  cluster         = aws_ecs_cluster.etcd[0].id
  task_definition = aws_ecs_task_definition.etcd[each.key].arn
  desired_count   = 1
  launch_type     = "FARGATE"

  enable_execute_command = true

  network_configuration {
    subnets          = var.private_subnet_ids
    security_groups  = [aws_security_group.etcd[0].id]
    assign_public_ip = false
  }

  # Register to Cloud Map service:
  # - Single-node: Use shared 'etcd' service for client simplicity
  # - Multi-node: Use member-specific 'etcd-N' services for peer discovery
  service_registries {
    registry_arn = local.etcd_cluster_size == 1 ? (
      aws_service_discovery_service.etcd_client[0].arn
      ) : (
      aws_service_discovery_service.etcd["etcd-${each.key}"].arn
    )
  }

  deployment_minimum_healthy_percent = 0
  deployment_maximum_percent         = 100

  tags = merge(var.tags, {
    EtcdMember = "etcd-${each.key}"
  })

  # Explicit dependency: wait for all mount targets to be available
  depends_on = [aws_efs_mount_target.etcd]
}
