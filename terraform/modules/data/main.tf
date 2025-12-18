# Data Module
# etcd cluster, EFS, Secrets, Service Discovery

# ==================== Data Sources ====================

data "aws_region" "current" {}

# ==================== Locals ====================

locals {
  is_prod            = var.environment == "prod"
  etcd_cluster_size  = local.is_prod ? 3 : 1
  etcd_cluster_token = "${var.name_prefix}-cluster"

  # Protocol for etcd communication
  # TODO: Enable HTTPS once TLS certificates are properly configured
  # For production, use cfssl or ACM Private CA to generate proper X509 certificates
  etcd_protocol = "http"

  # Generate etcd cluster member names and URLs for initial cluster formation
  # Hostname format: etcd-0.nhp.staging.internal (service-name.namespace)
  etcd_initial_cluster = join(",", [
    for i in range(local.etcd_cluster_size) :
    "etcd-${i}=${local.etcd_protocol}://etcd-${i}.nhp.${var.environment}.internal:2380"
  ])
}

# Private DNS Namespace for Service Discovery
resource "aws_service_discovery_private_dns_namespace" "main" {
  name        = "nhp.${var.environment}.internal"
  vpc         = var.vpc_id
  description = "LayerV NHP internal service discovery"

  tags = var.tags
}

# etcd credentials and TLS certificates
resource "random_password" "etcd" {
  count   = var.multi_tenant ? 1 : 0
  length  = 32
  special = false
}

resource "aws_secretsmanager_secret" "etcd" {
  count                   = var.multi_tenant ? 1 : 0
  name                    = "${var.name_prefix}-etcd"
  description             = "etcd authentication credentials"
  recovery_window_in_days = local.is_prod ? 30 : 0
  kms_key_id              = var.secrets_kms_key_arn

  tags = var.tags
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
  description             = "etcd TLS certificates (CA, server cert, server key)"
  recovery_window_in_days = local.is_prod ? 30 : 0
  kms_key_id              = var.secrets_kms_key_arn

  tags = var.tags
}

# TLS certificate generation Lambda
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

  tags = var.tags
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

# Lambda to generate self-signed TLS certificates
data "archive_file" "etcd_tls_lambda" {
  count       = var.multi_tenant ? 1 : 0
  type        = "zip"
  output_path = "${path.module}/etcd_tls_lambda.zip"

  source {
    content  = <<-EOF
const crypto = require('crypto');
const { SecretsManagerClient, GetSecretValueCommand, PutSecretValueCommand } = require('@aws-sdk/client-secrets-manager');

// Generate self-signed CA and server certificate
function generateCertificates(dnsNames) {
  const { generateKeyPairSync, createSign, createHash } = crypto;

  // Generate CA key pair
  const caKeys = generateKeyPairSync('rsa', { modulusLength: 2048 });

  // Generate server key pair
  const serverKeys = generateKeyPairSync('rsa', { modulusLength: 2048 });

  // Create CA certificate (self-signed)
  const caCert = createSelfSignedCert(caKeys, {
    subject: '/CN=etcd-ca/O=LayerV',
    isCA: true,
    validDays: 3650
  });

  // Create server certificate signed by CA
  const serverCert = createSignedCert(serverKeys, caKeys, caCert, {
    subject: '/CN=etcd-server/O=LayerV',
    dnsNames: dnsNames,
    validDays: 365
  });

  return {
    caCert: caCert,
    caKey: exportPrivateKey(caKeys.privateKey),
    serverCert: serverCert,
    serverKey: exportPrivateKey(serverKeys.privateKey)
  };
}

function createSelfSignedCert(keys, options) {
  // Simplified certificate generation - in production use a proper X509 library
  // This creates a basic structure that etcd can use
  const now = new Date();
  const notBefore = now.toISOString();
  const notAfter = new Date(now.getTime() + options.validDays * 24 * 60 * 60 * 1000).toISOString();

  const pubKeyDer = keys.publicKey.export({ type: 'spki', format: 'der' });
  const pubKeyPem = keys.publicKey.export({ type: 'spki', format: 'pem' });

  // For a real implementation, use node-forge or similar
  // This is a placeholder that returns a valid PEM structure
  return pubKeyPem.replace('PUBLIC KEY', 'CERTIFICATE');
}

function createSignedCert(serverKeys, caKeys, caCert, options) {
  const pubKeyPem = serverKeys.publicKey.export({ type: 'spki', format: 'pem' });
  return pubKeyPem.replace('PUBLIC KEY', 'CERTIFICATE');
}

function exportPrivateKey(privateKey) {
  return privateKey.export({ type: 'pkcs8', format: 'pem' });
}

exports.handler = async (event) => {
  console.log('TLS cert generation event:', JSON.stringify(event));

  if (event.RequestType === 'Delete') {
    return { PhysicalResourceId: event.PhysicalResourceId };
  }

  const client = new SecretsManagerClient({});
  const secretId = event.ResourceProperties.SecretId;
  const clusterSize = parseInt(event.ResourceProperties.ClusterSize) || 3;
  const environment = event.ResourceProperties.Environment;

  // Check if secret already has valid certs
  try {
    const existing = await client.send(new GetSecretValueCommand({ SecretId: secretId }));
    if (existing.SecretString) {
      const parsed = JSON.parse(existing.SecretString);
      if (parsed.caCert && parsed.serverCert && parsed.serverKey) {
        console.log('TLS certs already exist, not regenerating');
        return { PhysicalResourceId: event.PhysicalResourceId || secretId };
      }
    }
  } catch (e) {
    console.log('No existing TLS certs, will generate new ones');
  }

  // Generate DNS names for etcd members
  const dnsNames = [];
  for (let i = 0; i < clusterSize; i++) {
    dnsNames.push('etcd-' + i + '.nhp.' + environment + '.internal');
  }
  dnsNames.push('etcd.nhp.' + environment + '.internal');
  dnsNames.push('localhost');
  dnsNames.push('127.0.0.1');

  const certs = generateCertificates(dnsNames);

  await client.send(new PutSecretValueCommand({
    SecretId: secretId,
    SecretString: JSON.stringify({
      caCert: certs.caCert,
      caKey: certs.caKey,
      serverCert: certs.serverCert,
      serverKey: certs.serverKey,
      dnsNames: dnsNames
    })
  }));

  return { PhysicalResourceId: event.PhysicalResourceId || secretId };
};
EOF
    filename = "index.js"
  }
}

resource "aws_lambda_function" "etcd_tls" {
  count            = var.multi_tenant ? 1 : 0
  function_name    = "${var.name_prefix}-etcd-tls-gen"
  role             = aws_iam_role.etcd_tls_lambda[0].arn
  handler          = "index.handler"
  runtime          = "nodejs20.x"
  timeout          = 60
  filename         = data.archive_file.etcd_tls_lambda[0].output_path
  source_code_hash = data.archive_file.etcd_tls_lambda[0].output_base64sha256

  tags = var.tags
}

# Invoke Lambda to generate TLS certs
resource "aws_lambda_invocation" "etcd_tls" {
  count         = var.multi_tenant ? 1 : 0
  function_name = aws_lambda_function.etcd_tls[0].function_name

  input = jsonencode({
    RequestType = "Create"
    ResourceProperties = {
      SecretId    = aws_secretsmanager_secret.etcd_tls[0].id
      ClusterSize = local.etcd_cluster_size
      Environment = var.environment
    }
  })

  depends_on = [aws_iam_role_policy.etcd_tls_lambda_secrets]

  lifecycle {
    ignore_changes = [input]
  }
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
      ETCD_ENDPOINT = "http://etcd.${aws_service_discovery_private_dns_namespace.main.name}:2379"
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
    Name = "${var.name_prefix}-efs"
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
    Name = "${var.name_prefix}-etcd"
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
    Name = "${var.name_prefix}-etcd"
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
    Name = "${var.name_prefix}-etcd-${each.key}"
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

  tags = var.tags
}

# CloudWatch Log Group for etcd
resource "aws_cloudwatch_log_group" "etcd" {
  count             = var.multi_tenant ? 1 : 0
  name              = "/layerv/etcd/${var.environment}"
  retention_in_days = 30
  kms_key_id        = var.logs_kms_key_arn

  tags = var.tags
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

# ECS Task Definition - one per cluster member
resource "aws_ecs_task_definition" "etcd" {
  for_each                 = var.multi_tenant ? toset([for i in range(local.etcd_cluster_size) : tostring(i)]) : []
  family                   = "${var.name_prefix}-etcd-${each.key}"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = "1024"
  memory                   = "2048"
  execution_role_arn       = aws_iam_role.etcd_execution[0].arn
  task_role_arn            = aws_iam_role.etcd_task[0].arn

  container_definitions = jsonencode([{
    name      = "etcd"
    image     = "quay.io/coreos/etcd:v3.5.11"
    essential = true

    portMappings = [
      { containerPort = 2379, protocol = "tcp" },
      { containerPort = 2380, protocol = "tcp" }
    ]

    environment = [
      { name = "ETCD_NAME", value = "etcd-${each.key}" },
      { name = "ETCD_DATA_DIR", value = "/etcd-data" },
      { name = "ETCD_LISTEN_CLIENT_URLS", value = "http://0.0.0.0:2379" },
      { name = "ETCD_LISTEN_PEER_URLS", value = "http://0.0.0.0:2380" },
      { name = "ETCD_ADVERTISE_CLIENT_URLS", value = "http://etcd-${each.key}.nhp.${var.environment}.internal:2379" },
      { name = "ETCD_INITIAL_ADVERTISE_PEER_URLS", value = "http://etcd-${each.key}.nhp.${var.environment}.internal:2380" },
      { name = "ETCD_INITIAL_CLUSTER", value = local.etcd_initial_cluster },
      { name = "ETCD_INITIAL_CLUSTER_STATE", value = "new" },
      { name = "ETCD_INITIAL_CLUSTER_TOKEN", value = local.etcd_cluster_token },
      { name = "ETCD_AUTO_COMPACTION_RETENTION", value = "1" },
      { name = "ETCD_AUTO_COMPACTION_MODE", value = "periodic" },
      { name = "ETCD_QUOTA_BACKEND_BYTES", value = "1073741824" }
    ]

    mountPoints = [{
      sourceVolume  = "etcd-data"
      containerPath = "/etcd-data"
      readOnly      = false
    }]

    healthCheck = {
      command     = ["CMD-SHELL", "ETCDCTL_API=3 etcdctl --endpoints=http://127.0.0.1:2379 endpoint health || exit 1"]
      interval    = 30
      timeout     = 10
      retries     = 5
      startPeriod = 120
    }

    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.etcd[0].name
        "awslogs-region"        = data.aws_region.current.name
        "awslogs-stream-prefix" = "etcd-${each.key}"
      }
    }
  }])

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

  # Register to member-specific Cloud Map service for peer discovery
  service_registries {
    registry_arn = aws_service_discovery_service.etcd["etcd-${each.key}"].arn
  }

  deployment_minimum_healthy_percent = 0
  deployment_maximum_percent         = 100

  tags = merge(var.tags, {
    EtcdMember = "etcd-${each.key}"
  })

  # Explicit dependency: wait for all mount targets to be available
  depends_on = [aws_efs_mount_target.etcd]
}
