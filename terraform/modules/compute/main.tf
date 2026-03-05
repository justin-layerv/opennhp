# Compute Module
# ASG, NLB, Launch Template, Cloud Map Service
#
# Cell Architecture:
# All resources in this module belong to a single cell (identified by var.cell_id).
# Each cell is an isolated failure domain with its own NLB, ASG, and server fleet.
#
# Secrets Manager Naming Convention:
# - Current: ${name_prefix}-server (e.g., nhp-sandbox-server)
# - Future cells: ${name_prefix}-${cell_id}-server (e.g., nhp-sandbox-cell1-server)
#
# The existing secret name is kept for backward compatibility with cell0.
# New cells should include cell_id in the secret name for clear isolation.
# IAM policies can then use ARN patterns: arn:aws:secretsmanager:*:*:secret:nhp-*-cell1-*

# ==================== Data Sources ====================

data "aws_region" "current" {}
data "aws_caller_identity" "current" {}

# Ubuntu 24.04 LTS (Noble Numbat) - latest LTS
data "aws_ssm_parameter" "ubuntu_ami" {
  name = "/aws/service/canonical/ubuntu/server/noble/stable/current/amd64/hvm/ebs-gp3/ami-id"
}

# ==================== Locals ====================

locals {
  is_prod = var.environment == "prod"
}

# Lambda for generating Curve25519 keys (same approach as CDK)
resource "aws_iam_role" "keygen_lambda" {
  name = "${var.name_prefix}-keygen-lambda"

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

resource "aws_iam_role_policy_attachment" "keygen_lambda_basic" {
  role       = aws_iam_role.keygen_lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy" "keygen_lambda_secrets" {
  name = "secrets-access"
  role = aws_iam_role.keygen_lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:PutSecretValue"
        ]
        Resource = [
          aws_secretsmanager_secret.server.arn,
          aws_secretsmanager_secret.cookie_secret.arn
        ]
      },
      {
        Effect   = "Allow"
        Action   = ["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey"]
        Resource = var.secrets_kms_key_arn != null ? [var.secrets_kms_key_arn] : []
      }
    ]
  })
}

# Lambda function to generate Curve25519 keys
resource "aws_lambda_function" "keygen" {
  function_name = "${var.name_prefix}-keygen"
  role          = aws_iam_role.keygen_lambda.arn
  handler       = "index.handler"
  runtime       = "nodejs20.x"
  timeout       = 30

  filename         = data.archive_file.keygen_lambda.output_path
  source_code_hash = data.archive_file.keygen_lambda.output_base64sha256

  tags = var.tags
}

data "archive_file" "keygen_lambda" {
  type        = "zip"
  output_path = "${path.module}/keygen_lambda.zip"

  source {
    content  = <<-EOF
const crypto = require('crypto');
const { SecretsManagerClient, GetSecretValueCommand, PutSecretValueCommand } = require('@aws-sdk/client-secrets-manager');

exports.handler = async (event) => {
  console.log('RequestType:', event.RequestType);

  if (event.RequestType === 'Delete') {
    return { PhysicalResourceId: event.PhysicalResourceId };
  }

  const client = new SecretsManagerClient({});
  const secretId = event.ResourceProperties.SecretId;
  const hostname = event.ResourceProperties.Hostname;
  const environment = event.ResourceProperties.Environment;

  // Check if secret already has a valid key pair
  try {
    const existing = await client.send(new GetSecretValueCommand({ SecretId: secretId }));
    if (existing.SecretString) {
      const parsed = JSON.parse(existing.SecretString);
      if (parsed.privateKey && parsed.privateKey.length === 44 && parsed.publicKey && parsed.publicKey.length === 44) {
        console.log('Secret already has valid key pair, not overwriting');
        return { PhysicalResourceId: event.PhysicalResourceId || secretId };
      }
    }
  } catch (e) {
    console.log('No existing secret value, will create new');
  }

  // Generate X25519 key pair using Node.js crypto
  const keyPair = crypto.generateKeyPairSync('x25519');

  // Export keys in raw format and base64 encode
  const privateKeyRaw = keyPair.privateKey.export({ type: 'pkcs8', format: 'der' });
  const publicKeyRaw = keyPair.publicKey.export({ type: 'spki', format: 'der' });

  // Extract the 32-byte keys from DER format (skip the header bytes)
  // PKCS8 X25519 private key: 48 bytes, last 32 are the key
  // SPKI X25519 public key: 44 bytes, last 32 are the key
  const privateKey = privateKeyRaw.slice(-32);
  const publicKey = publicKeyRaw.slice(-32);

  const privateKeyBase64 = privateKey.toString('base64');
  const publicKeyBase64 = publicKey.toString('base64');

  const secretValue = JSON.stringify({
    privateKey: privateKeyBase64,
    publicKey: publicKeyBase64,
    hostname: hostname,
    environment: environment,
  });

  await client.send(new PutSecretValueCommand({
    SecretId: secretId,
    SecretString: secretValue,
  }));

  console.log('Generated new key pair, publicKey:', publicKeyBase64);

  return {
    PhysicalResourceId: event.PhysicalResourceId || secretId,
  };
};
EOF
    filename = "index.js"
  }
}

# Store server configuration in Secrets Manager
resource "aws_secretsmanager_secret" "server" {
  name                    = "${var.name_prefix}-server"
  description             = "NHP Server private key and configuration"
  recovery_window_in_days = local.is_prod ? 30 : 0
  kms_key_id              = var.secrets_kms_key_arn

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-server-secret"
    Component = "compute"
    Cell      = var.cell_id
  })
}

# Custom resource to invoke Lambda for key generation
resource "aws_lambda_invocation" "keygen" {
  function_name = aws_lambda_function.keygen.function_name

  input = jsonencode({
    RequestType = "Create"
    ResourceProperties = {
      SecretId    = aws_secretsmanager_secret.server.id
      Hostname    = var.domain_name
      Environment = var.environment
    }
  })

  depends_on = [aws_iam_role_policy.keygen_lambda_secrets]

  lifecycle {
    ignore_changes = [input]
  }
}

# Cookie session keys for HTTP session cookies (shared across all server instances)
# JSON structure:
#   {
#     "current":  {"auth_key": "...", "encrypt_key": "..."},
#     "previous": {"auth_key": "...", "encrypt_key": "..."}  // optional
#   }
#
# - current: Used for writing new cookies AND reading existing ones
# - previous: Read-only, enables graceful rotation during rolling deployments
#
# Rotation procedure:
#   1. Read the current secret value
#   2. Move "current" → "previous"
#   3. Generate new keys for "current"
#   4. Update the secret with both current and previous
#   5. Trigger ASG instance refresh — as instances roll:
#      - New instances write cookies with new keys
#      - New instances can still read cookies signed with old keys
#   6. After all instances are refreshed, remove "previous" (optional)
resource "aws_secretsmanager_secret" "cookie_secret" {
  name                    = "${var.name_prefix}-cookie-secret"
  description             = "NHP Server cookie session keys (HMAC auth + AES-256 encryption)"
  recovery_window_in_days = local.is_prod ? 30 : 0
  kms_key_id              = var.secrets_kms_key_arn

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-cookie-secret"
    Component = "compute"
    Cell      = var.cell_id
  })
}

# Seed the secret with random keys generated server-side by AWS.
# Keys are generated via AWS CLI (secretsmanager:GetRandomPassword) and stored
# directly in Secrets Manager — they never appear in Terraform state.
# Only runs on first creation (triggered by secret ARN).
resource "terraform_data" "cookie_secret_seed" {
  triggers_replace = [aws_secretsmanager_secret.cookie_secret.arn]

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command     = <<-EOT
      set -euo pipefail
      AUTH_KEY=$(aws secretsmanager get-random-password --password-length 32 --exclude-punctuation --query RandomPassword --output text)
      ENCRYPT_KEY=$(aws secretsmanager get-random-password --password-length 32 --exclude-punctuation --query RandomPassword --output text)
      aws secretsmanager put-secret-value --secret-id "${aws_secretsmanager_secret.cookie_secret.id}" --secret-string "{\"current\":{\"auth_key\":\"$AUTH_KEY\",\"encrypt_key\":\"$ENCRYPT_KEY\"}}"
    EOT
  }
}

# CloudWatch Log Group for servers
resource "aws_cloudwatch_log_group" "server" {
  name              = "/layerv/nhp/${var.environment}/${var.cell_id}/server"
  retention_in_days = local.is_prod ? 365 : 30
  kms_key_id        = var.logs_kms_key_arn

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-logs-server"
    Component = "compute"
    Cell      = var.cell_id
  })
}

# =============================================================================
# SSM Parameters for Deployment State
# These parameters enable CI/CD to update image tags without Terraform apply.
# Instances read the image tag from SSM at boot time.
# =============================================================================

# Current deployed image tag - updated by CI/CD after successful builds
resource "aws_ssm_parameter" "image_tag" {
  name        = "/${var.environment}/nhp/server/image-tag"
  description = "NHP Server Docker image tag - updated by CI/CD"
  type        = "String"
  value       = var.image_tag

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-ssm-image-tag"
    Component = "compute"
    Cell      = var.cell_id
  })

  # Allow CI/CD to update the value without TF drift
  lifecycle {
    ignore_changes = [value]
  }
}

# ASG name - used by CI/CD scripts to trigger instance refresh
resource "aws_ssm_parameter" "asg_name" {
  name        = "/${var.environment}/nhp/server/asg-name"
  description = "NHP Server Auto Scaling Group name - used by CI/CD for instance refresh"
  type        = "String"
  value       = aws_autoscaling_group.server.name

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-ssm-asg-name"
    Component = "compute"
    Cell      = var.cell_id
  })
}

# Deployment tracking - commit SHA of the currently deployed version
resource "aws_ssm_parameter" "deployed_commit" {
  name        = "/${var.environment}/nhp/deploy/deployed-commit"
  description = "Git commit SHA of the currently deployed version"
  type        = "String"
  value       = "initial"

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-ssm-deployed-commit"
    Component = "deploy"
    Cell      = var.cell_id
  })

  lifecycle {
    ignore_changes = [value]
  }
}

resource "aws_ssm_parameter" "deployed_at" {
  name        = "/${var.environment}/nhp/deploy/deployed-at"
  description = "ISO 8601 timestamp of last successful deployment"
  type        = "String"
  value       = "never"

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-ssm-deployed-at"
    Component = "deploy"
    Cell      = var.cell_id
  })

  lifecycle {
    ignore_changes = [value]
  }
}

# Cloud Map Service for NHP servers
resource "aws_service_discovery_service" "server" {
  name        = "server"
  description = "NHP Server instances"

  dns_config {
    namespace_id = var.namespace_id

    dns_records {
      ttl  = 30
      type = "A"
    }

    routing_policy = "MULTIVALUE"
  }

  # No health_check_custom_config - instances register/deregister explicitly

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-cloudmap-server"
    Component = "compute"
    Cell      = var.cell_id
  })
}

# IAM Role for NHP Server instances
resource "aws_iam_role" "server" {
  name = "${var.name_prefix}-server"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ec2.amazonaws.com"
      }
    }]
  })

  tags = var.tags
}

resource "aws_iam_role_policy_attachment" "server_ssm" {
  role       = aws_iam_role.server.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# DynamoDB read access for per-AC assignment architecture (when storage_backend = "dynamodb")
# Uses boolean variable because Terraform cannot evaluate count based on module outputs at plan time
# See docs/design/PLUGGABLE_STORAGE_BACKEND.md
resource "aws_iam_role_policy_attachment" "server_dynamodb" {
  count      = var.attach_storage_policies ? 1 : 0
  role       = aws_iam_role.server.name
  policy_arn = var.dynamodb_read_policy_arn
}

# SSM keypair access for Noise K server-to-server forwarding
resource "aws_iam_role_policy_attachment" "server_keypair" {
  count      = var.attach_storage_policies ? 1 : 0
  role       = aws_iam_role.server.name
  policy_arn = var.keypair_policy_arn
}

# Note: Plugins are now baked into the Docker image - no S3 IAM policy needed

resource "aws_iam_role_policy" "server" {
  name = "server-permissions"
  role = aws_iam_role.server.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = ["secretsmanager:GetSecretValue"]
        Resource = compact(concat(
          [aws_secretsmanager_secret.server.arn],
          [aws_secretsmanager_secret.cookie_secret.arn],
          [var.etcd_secret_arn],
          [var.etcd_tls_secret_arn],
          [var.qurl_service_token_secret_arn]
        ))
      },
      {
        Effect = "Allow"
        Action = [
          "ecr:GetAuthorizationToken"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "ecr:BatchCheckLayerAvailability",
          "ecr:GetDownloadUrlForLayer",
          "ecr:BatchGetImage"
        ]
        Resource = var.server_repo_arn
      },
      {
        Effect = "Allow"
        Action = [
          "servicediscovery:RegisterInstance",
          "servicediscovery:DeregisterInstance",
          "servicediscovery:UpdateInstanceCustomHealthStatus",
          "servicediscovery:GetInstance"
        ]
        Resource = aws_service_discovery_service.server.arn
      },
      # Route 53 permissions required for Cloud Map DNS integration with custom health checks
      {
        Effect = "Allow"
        Action = [
          "route53:CreateHealthCheck",
          "route53:DeleteHealthCheck",
          "route53:UpdateHealthCheck",
          "route53:GetHealthCheck"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "servicediscovery:DiscoverInstances",
          "servicediscovery:GetNamespace",
          "servicediscovery:GetService"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "${aws_cloudwatch_log_group.server.arn}:*"
      },
      {
        Effect   = "Allow"
        Action   = ["kms:Decrypt"]
        Resource = var.secrets_kms_key_arn != null ? [var.secrets_kms_key_arn] : []
      },
      # Allow instance to mark itself unhealthy for ASG replacement
      {
        Effect   = "Allow"
        Action   = ["autoscaling:SetInstanceHealth"]
        Resource = aws_autoscaling_group.server.arn
      },
      # SSM Parameter Store access for deployment state (image tags)
      {
        Effect = "Allow"
        Action = ["ssm:GetParameter", "ssm:GetParameters"]
        Resource = [
          "arn:aws:ssm:${data.aws_region.current.id}:${data.aws_caller_identity.current.account_id}:parameter/${var.environment}/nhp/server/*"
        ]
      },
      # Allow instance to read its own tags (for DeployColor detection in blue/green deployments)
      {
        Effect   = "Allow"
        Action   = ["ec2:DescribeTags"]
        Resource = "*"
      },
      # CloudWatch Agent + application metrics (mem, disk, NHP custom metrics)
      {
        Effect   = "Allow"
        Action   = ["cloudwatch:PutMetricData"]
        Resource = "*"
        Condition = {
          StringEquals = {
            "cloudwatch:namespace" = "LayerV/NHP"
          }
        }
      }
    ]
  })
}

resource "aws_iam_instance_profile" "server" {
  name = "${var.name_prefix}-server"
  role = aws_iam_role.server.name

  tags = var.tags
}

# Security Group for NHP servers
resource "aws_security_group" "server" {
  name_prefix = "${var.name_prefix}-server-"
  vpc_id      = var.vpc_id
  description = "Security group for NHP Server instances"

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-sg-server"
    Component = "compute"
    Cell      = var.cell_id
  })

  lifecycle {
    create_before_destroy = true
  }
}

# --- Server SG Rules (separate resources to avoid inline/standalone conflicts) ---

# NHP Protocol (UDP 62206) - from NLB
resource "aws_vpc_security_group_ingress_rule" "server_nhp_udp" {
  security_group_id = aws_security_group.server.id
  description       = "NHP Protocol from NLB"
  from_port         = 62206
  to_port           = 62206
  ip_protocol       = "udp"
  cidr_ipv4         = "0.0.0.0/0"

  tags = {
    Name = "${var.name_prefix}-server-nhp-udp"
  }
}

# HTTP (TCP 62206) - from VPC (Traefik proxies here)
resource "aws_vpc_security_group_ingress_rule" "server_http_traefik" {
  security_group_id = aws_security_group.server.id
  description       = "HTTP from Traefik"
  from_port         = 62206
  to_port           = 62206
  ip_protocol       = "tcp"
  cidr_ipv4         = var.vpc_cidr

  tags = {
    Name = "${var.name_prefix}-server-http-traefik"
  }
}

# HTTP for plugin endpoints (AC Traefik and Demo Gateway route here)
resource "aws_vpc_security_group_ingress_rule" "server_http_plugins" {
  security_group_id = aws_security_group.server.id
  description       = "HTTP plugin endpoints from AC and Demo Gateway"
  from_port         = 8888
  to_port           = 8888
  ip_protocol       = "tcp"
  cidr_ipv4         = var.vpc_cidr

  tags = {
    Name = "${var.name_prefix}-server-http-plugins"
  }
}

# QURL resolve endpoint: NLB TLS termination → Server HTTP on 8888.
# Must allow all IPs because NLB preserve_client_ip=true forwards packets
# with the original client IP (or CloudFront IP) as source. The endpoint
# is protected by TLS, short-lived token validation, and WAF (when
# CloudFront is enabled).
resource "aws_vpc_security_group_ingress_rule" "server_qurl_resolve" {
  count = var.enable_qurl_resolve_endpoint ? 1 : 0

  security_group_id = aws_security_group.server.id
  description       = "QURL resolve endpoint - browser/CloudFront access via NLB TLS"
  from_port         = 8888
  to_port           = 8888
  ip_protocol       = "tcp"
  cidr_ipv4         = "0.0.0.0/0"

  tags = {
    Name = "${var.name_prefix}-server-qurl-resolve"
  }
}

# All outbound
resource "aws_vpc_security_group_egress_rule" "server_all" {
  security_group_id = aws_security_group.server.id
  description       = "All outbound"
  ip_protocol       = "-1"
  cidr_ipv4         = "0.0.0.0/0"

  tags = {
    Name = "${var.name_prefix}-server-egress"
  }
}

# User Data script - using templatefile for proper interpolation
locals {
  user_data = templatefile("${path.module}/user_data.sh.tpl", {
    secret_arn          = aws_secretsmanager_secret.server.arn
    region              = data.aws_region.current.id
    account_id          = data.aws_caller_identity.current.account_id
    cloudmap_service_id = aws_service_discovery_service.server.id
    server_repo_url     = var.server_repo_url
    environment         = var.environment
    cell_id             = var.cell_id
    multi_tenant        = var.multi_tenant
    etcd_endpoint       = var.etcd_endpoint
    etcd_tls_secret_arn = var.etcd_tls_secret_arn
    # Server configuration options
    log_level        = var.log_level
    dev_mode         = var.dev_mode
    resource_mode    = var.resource_mode
    auth_url         = var.auth_url
    auth_signing_key = var.auth_signing_key
    auth_aes_key     = var.auth_aes_key
    # Deployment configuration
    ssm_image_tag_parameter = aws_ssm_parameter.image_tag.name
    # Plugin configuration (plugins are baked into Docker image)
    server_plugins  = var.server_plugins
    auth_service_id = var.auth_service_id
    # Storage backend configuration (Phase 4)
    storage_backend               = var.storage_backend
    dynamodb_region               = coalesce(var.dynamodb_region, data.aws_region.current.id)
    dynamodb_licenses_table       = var.dynamodb_licenses_table
    dynamodb_ac_assignments_table = var.dynamodb_ac_assignments_table
    dynamodb_resources_table      = var.dynamodb_resources_table
    # Cloud Map configuration for server health discovery
    cloudmap_enabled        = var.cloudmap_enabled
    cloudmap_namespace_name = var.cloudmap_namespace_name
    cloudmap_service_name   = var.cloudmap_service_name
    # QURL plugin configuration
    qurl_enabled                  = var.qurl_config != null ? var.qurl_config.enabled : false
    qurl_api_url                  = var.qurl_config != null ? var.qurl_config.api_url : ""
    qurl_allowed_redirect_domain  = var.qurl_config != null ? var.qurl_config.allowed_redirect_domain : ""
    qurl_api_timeout              = var.qurl_config != null ? var.qurl_config.api_timeout : 10
    qurl_max_idle_conns           = var.qurl_config != null ? var.qurl_config.max_idle_conns : 10
    qurl_max_idle_conns_per_host  = var.qurl_config != null ? var.qurl_config.max_idle_conns_per_host : 5
    qurl_idle_conn_timeout        = var.qurl_config != null ? var.qurl_config.idle_conn_timeout : 30
    qurl_service_token_secret_arn = var.qurl_service_token_secret_arn != null ? var.qurl_service_token_secret_arn : ""
    # Blue/Green deployment configuration
    enable_blue_green = var.enable_blue_green
    # Cookie signing secret (shared across all instances)
    cookie_secret_arn = aws_secretsmanager_secret.cookie_secret.arn
    # CORS allowed origins for NHP HTTP server
    cors_allowed_origins = var.cors_allowed_origins
    # CloudFront trusted proxy CIDRs (for correct client IP via X-Forwarded-For)
    cloudfront_cidrs_ssm_parameter = var.cloudfront_cidrs_ssm_parameter
  })
}

# Launch Template
resource "aws_launch_template" "server" {
  name_prefix   = "${var.name_prefix}-server-"
  image_id      = data.aws_ssm_parameter.ubuntu_ami.value
  instance_type = local.is_prod ? "c6i.xlarge" : "t3.medium"

  iam_instance_profile {
    arn = aws_iam_instance_profile.server.arn
  }

  # NHP servers run in private subnets - NAT Gateway provides internet access
  # VPC endpoints provide access to ECR, Secrets Manager, CloudWatch Logs, SSM
  # NLB in public subnets routes traffic to servers in private subnets
  network_interfaces {
    associate_public_ip_address = false
    security_groups             = [aws_security_group.server.id]
  }

  block_device_mappings {
    device_name = "/dev/sda1"
    ebs {
      volume_size           = 50
      volume_type           = "gp3"
      encrypted             = true
      kms_key_id            = var.ebs_kms_key_arn
      delete_on_termination = true
    }
  }

  # Use base64gzip to compress user_data - AWS EC2 automatically decompresses
  # This allows scripts larger than the 16KB uncompressed limit
  user_data = base64gzip(local.user_data)

  monitoring {
    enabled = true
  }

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
    instance_metadata_tags      = "enabled"
  }

  tags = var.tags

  tag_specifications {
    resource_type = "instance"
    tags = merge(var.tags, {
      Name      = "${var.name_prefix}-server"
      Component = "compute"
      Cell      = var.cell_id
    })
  }

  lifecycle {
    create_before_destroy = true
  }

  depends_on = [aws_lambda_invocation.keygen]
}

# Auto Scaling Group
# NHP servers are deployed in PRIVATE subnets with NLB routing:
# 1. NLB in public subnets handles internet-facing traffic
# 2. Servers in private subnets are protected from direct internet access
# 3. NAT Gateway provides outbound internet (apt updates)
# 4. VPC endpoints provide access to AWS services (ECR, SSM, CloudWatch)
resource "aws_autoscaling_group" "server" {
  name                = "${var.name_prefix}-server"
  vpc_zone_identifier = var.private_subnet_ids
  min_size            = var.min_capacity
  max_size            = var.max_capacity
  desired_capacity    = var.min_capacity

  launch_template {
    id      = aws_launch_template.server.id
    version = aws_launch_template.server.latest_version
  }

  health_check_type         = "EC2"
  health_check_grace_period = 180 # Instance launch (~60s) + user data (~90s) + container start (~15s) = ~165s

  # Publish ASG group metrics to CloudWatch (AWS/AutoScaling namespace).
  # Without this, metrics like GroupInServiceInstances are not emitted.
  enabled_metrics = [
    "GroupInServiceInstances",
    "GroupDesiredCapacity",
    "GroupMinSize",
    "GroupMaxSize",
    "GroupPendingInstances",
    "GroupTerminatingInstances",
    "GroupTotalInstances",
  ]

  instance_refresh {
    strategy = "Rolling"
    preferences {
      min_healthy_percentage = 50
      instance_warmup        = 180
    }
  }

  tag {
    key                 = "Name"
    value               = "${var.name_prefix}-server"
    propagate_at_launch = true
  }

  tag {
    key                 = "Component"
    value               = "compute"
    propagate_at_launch = true
  }

  tag {
    key                 = "Cell"
    value               = var.cell_id
    propagate_at_launch = true
  }

  # Blue/Green deployment: Mark this as the blue ASG
  # user_data.sh.tpl reads this tag to determine which SSM image tag parameter to use
  tag {
    key                 = "DeployColor"
    value               = "blue"
    propagate_at_launch = true
  }

  dynamic "tag" {
    for_each = var.tags
    content {
      key                 = tag.key
      value               = tag.value
      propagate_at_launch = true
    }
  }

  lifecycle {
    create_before_destroy = true
  }
}

# Scaling Policies
resource "aws_autoscaling_policy" "cpu" {
  name                   = "${var.name_prefix}-cpu"
  autoscaling_group_name = aws_autoscaling_group.server.name
  policy_type            = "TargetTrackingScaling"

  target_tracking_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ASGAverageCPUUtilization"
    }
    target_value = 70.0
  }
}

resource "aws_autoscaling_policy" "network" {
  name                   = "${var.name_prefix}-network"
  autoscaling_group_name = aws_autoscaling_group.server.name
  policy_type            = "TargetTrackingScaling"

  target_tracking_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ASGAverageNetworkIn"
    }
    target_value = 10485760 # 10 MB/s
  }
}

# Network Load Balancer
resource "aws_lb" "server" {
  name               = replace("${var.name_prefix}-nlb", "_", "-")
  internal           = false
  load_balancer_type = "network"
  subnets            = var.public_subnet_ids

  enable_cross_zone_load_balancing = true
  enable_deletion_protection       = local.is_prod

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-nlb"
    Component = "compute"
    Cell      = var.cell_id
  })
}

# UDP Target Group
resource "aws_lb_target_group" "udp" {
  name        = replace("${var.name_prefix}-udp", "_", "-")
  port        = 62206
  protocol    = "UDP"
  vpc_id      = var.vpc_id
  target_type = "instance"

  # HTTP health check on port 8888 (NHP Server HTTP listener)
  # Uses /health/live endpoint for Kubernetes-style liveness probe
  # This checks that the server is running and can respond to requests
  health_check {
    enabled             = true
    protocol            = "HTTP"
    port                = "8888"
    path                = "/health/live"
    healthy_threshold   = 2
    unhealthy_threshold = 2
    interval            = 30
    matcher             = "200" # Expect HTTP 200 OK
  }

  deregistration_delay = 30

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-tg-udp"
    Component = "compute"
    Cell      = var.cell_id
  })
}

# Attach ASG to Target Group
resource "aws_autoscaling_attachment" "server" {
  autoscaling_group_name = aws_autoscaling_group.server.name
  lb_target_group_arn    = aws_lb_target_group.udp.arn
}

# UDP Listener
resource "aws_lb_listener" "udp" {
  load_balancer_arn = aws_lb.server.arn
  port              = 62206
  protocol          = "UDP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.udp.arn
  }

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-listener-udp"
    Component = "compute"
    Cell      = var.cell_id
  })
}

# =============================================================================
# TLS/HTTPS Target Group and Listener (for QURL resolve endpoint)
# =============================================================================
# When enable_qurl_resolve_endpoint is true, these resources create an HTTPS
# endpoint on the NHP Server NLB for resolve.qurl.link traffic.
#
# This allows the QURL authentication flow to reach the NHP Server's plugin
# endpoint directly, bypassing the AC which has port 443 blocked until NHP knock.
#
# Traffic flow:
#   resolve.qurl.link → NLB:443 (TLS termination) → Server:8888 (HTTP plugin)

# TCP Target Group for HTTPS traffic (routes to HTTP plugin endpoint)
resource "aws_lb_target_group" "https" {
  count = var.enable_qurl_resolve_endpoint ? 1 : 0

  name        = replace("${var.name_prefix}-https", "_", "-")
  port        = 8888
  protocol    = "TCP"
  vpc_id      = var.vpc_id
  target_type = "instance"

  # Health check on port 8888 (same as UDP target group)
  health_check {
    enabled             = true
    protocol            = "HTTP"
    port                = "8888"
    path                = "/health/live"
    healthy_threshold   = 2
    unhealthy_threshold = 2
    interval            = 30
    matcher             = "200"
  }

  deregistration_delay = 30

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-tg-https"
    Component = "compute"
    Cell      = var.cell_id
  })

  lifecycle {
    create_before_destroy = true
  }
}

# Attach ASG to HTTPS Target Group
resource "aws_autoscaling_attachment" "https" {
  count = var.enable_qurl_resolve_endpoint ? 1 : 0

  autoscaling_group_name = aws_autoscaling_group.server.name
  lb_target_group_arn    = aws_lb_target_group.https[0].arn
}

# TLS Listener (terminates TLS, forwards to TCP target group)
resource "aws_lb_listener" "https" {
  count = var.enable_qurl_resolve_endpoint ? 1 : 0

  load_balancer_arn = aws_lb.server.arn
  port              = 443
  protocol          = "TLS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.qurl_resolve_certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.https[0].arn
  }

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-listener-https"
    Component = "compute"
    Cell      = var.cell_id
  })

  lifecycle {
    precondition {
      condition     = var.qurl_resolve_certificate_arn != null
      error_message = "qurl_resolve_certificate_arn is required when enable_qurl_resolve_endpoint is true."
    }
  }
}

# =============================================================================
# ASG Lifecycle Hook for Server Termination Cleanup
# =============================================================================
# When an NHP Server terminates, this lifecycle hook pauses termination and
# triggers a Lambda function that cleans up DynamoDB assignments pointing to
# the terminating server. This provides immediate cleanup instead of waiting
# for Console health monitor.
#
# Flow:
# 1. ASG initiates instance termination
# 2. Lifecycle hook pauses termination, sends event to EventBridge
# 3. EventBridge triggers Lambda function
# 4. Lambda queries server-ac-index, updates/deletes assignments
# 5. Lambda completes lifecycle action
# 6. Instance terminates
# =============================================================================

# Lifecycle Hook - pauses termination to allow cleanup
resource "aws_autoscaling_lifecycle_hook" "termination" {
  count = var.enable_termination_cleanup ? 1 : 0

  name                   = "${var.name_prefix}-termination-hook"
  autoscaling_group_name = aws_autoscaling_group.server.name
  lifecycle_transition   = "autoscaling:EC2_INSTANCE_TERMINATING"
  default_result         = "CONTINUE" # Allow termination even if Lambda fails
  heartbeat_timeout      = 300        # 5 minutes max for cleanup

  # Note: We don't specify notification_target_arn here because we use
  # EventBridge to capture the lifecycle event instead of SNS
}

# EventBridge Rule - captures lifecycle hook events
resource "aws_cloudwatch_event_rule" "termination" {
  count = var.enable_termination_cleanup ? 1 : 0

  name        = "${var.name_prefix}-server-termination"
  description = "Captures NHP Server termination lifecycle events"

  event_pattern = jsonencode({
    source      = ["aws.autoscaling"]
    detail-type = ["EC2 Instance-terminate Lifecycle Action"]
    detail = {
      AutoScalingGroupName = [aws_autoscaling_group.server.name]
    }
  })

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-termination-rule"
    Component = "compute"
    Cell      = var.cell_id
  })
}

# EventBridge Target - triggers Lambda on lifecycle events
resource "aws_cloudwatch_event_target" "termination" {
  count = var.enable_termination_cleanup ? 1 : 0

  rule      = aws_cloudwatch_event_rule.termination[0].name
  target_id = "server-termination-cleanup"
  arn       = aws_lambda_function.termination_cleanup[0].arn
}

# Lambda Permission - allows EventBridge to invoke Lambda
resource "aws_lambda_permission" "termination" {
  count = var.enable_termination_cleanup ? 1 : 0

  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.termination_cleanup[0].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.termination[0].arn
}

# Lambda Function - performs DynamoDB cleanup
data "archive_file" "termination_cleanup" {
  count = var.enable_termination_cleanup ? 1 : 0

  type        = "zip"
  source_file = "${path.module}/lambda/server_termination_cleanup.py"
  output_path = "${path.module}/lambda/server_termination_cleanup.zip"
}

resource "aws_lambda_function" "termination_cleanup" {
  count = var.enable_termination_cleanup ? 1 : 0

  # Ensure log group is created first with KMS encryption and retention settings
  # Without this, Lambda auto-creates a log group without encryption
  depends_on = [aws_cloudwatch_log_group.termination_cleanup]

  filename         = data.archive_file.termination_cleanup[0].output_path
  function_name    = "${var.name_prefix}-server-termination-cleanup"
  role             = aws_iam_role.termination_cleanup[0].arn
  handler          = "server_termination_cleanup.handler"
  source_code_hash = data.archive_file.termination_cleanup[0].output_base64sha256
  runtime          = "python3.11"
  timeout          = 120 # 2 minutes; heartbeat_timeout is 300s
  memory_size      = 256

  environment {
    variables = {
      AC_ASSIGNMENTS_TABLE  = var.dynamodb_ac_assignments_table
      SERVER_AC_INDEX_TABLE = var.dynamodb_server_ac_index_table
    }
  }

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-termination-cleanup"
    Component = "compute"
    Cell      = var.cell_id
  })

  lifecycle {
    precondition {
      condition     = var.dynamodb_server_ac_index_table != null
      error_message = "dynamodb_server_ac_index_table is required when enable_termination_cleanup is true."
    }
    precondition {
      condition     = var.dynamodb_ac_assignments_table != null
      error_message = "dynamodb_ac_assignments_table is required when enable_termination_cleanup is true."
    }
    precondition {
      condition     = var.dynamodb_ac_assignments_arn != null
      error_message = "dynamodb_ac_assignments_arn is required when enable_termination_cleanup is true."
    }
    precondition {
      condition     = var.dynamodb_server_ac_index_arn != null
      error_message = "dynamodb_server_ac_index_arn is required when enable_termination_cleanup is true."
    }
  }
}

# CloudWatch Log Group for Lambda
resource "aws_cloudwatch_log_group" "termination_cleanup" {
  count = var.enable_termination_cleanup ? 1 : 0

  name              = "/aws/lambda/${var.name_prefix}-server-termination-cleanup"
  retention_in_days = local.is_prod ? 90 : 14
  kms_key_id        = var.logs_kms_key_arn

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-termination-cleanup-logs"
    Component = "compute"
    Cell      = var.cell_id
  })
}

# IAM Role for Lambda
resource "aws_iam_role" "termination_cleanup" {
  count = var.enable_termination_cleanup ? 1 : 0

  name = "${var.name_prefix}-termination-cleanup"

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

# IAM Policy for Lambda - DynamoDB access (includes KMS for encrypted tables)
resource "aws_iam_role_policy" "termination_cleanup_dynamodb" {
  count = var.enable_termination_cleanup ? 1 : 0

  name = "dynamodb-access"
  role = aws_iam_role.termination_cleanup[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat([
      {
        Sid    = "DynamoDBAccess"
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:Query",
          "dynamodb:UpdateItem",
          "dynamodb:DeleteItem",
          "dynamodb:BatchWriteItem"
        ]
        Resource = compact([
          var.dynamodb_ac_assignments_arn,
          var.dynamodb_server_ac_index_arn
        ])
      }
      ], var.secrets_kms_key_arn != null ? [{
        Sid    = "KMSAccess"
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:Encrypt",
          "kms:GenerateDataKey"
        ]
        Resource = [var.secrets_kms_key_arn]
    }] : [])
  })
}

# IAM Policy for Lambda - ASG lifecycle completion
resource "aws_iam_role_policy" "termination_cleanup_asg" {
  count = var.enable_termination_cleanup ? 1 : 0

  name = "asg-lifecycle"
  role = aws_iam_role.termination_cleanup[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "CompleteLifecycleAction"
        Effect   = "Allow"
        Action   = ["autoscaling:CompleteLifecycleAction"]
        Resource = aws_autoscaling_group.server.arn
      }
    ]
  })
}

# IAM Policy for Lambda - CloudWatch Logs
resource "aws_iam_role_policy_attachment" "termination_cleanup_logs" {
  count = var.enable_termination_cleanup ? 1 : 0

  role       = aws_iam_role.termination_cleanup[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# CloudWatch Alarm for Lambda errors
# Alerts when termination cleanup Lambda fails, which could indicate stale assignments not being cleaned
resource "aws_cloudwatch_metric_alarm" "termination_cleanup_errors" {
  count = var.enable_termination_cleanup && var.enable_sns_alerts ? 1 : 0

  alarm_name          = "${var.name_prefix}-termination-cleanup-errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = 300 # 5 minutes
  statistic           = "Sum"
  threshold           = 0
  alarm_description   = "Termination cleanup Lambda errors - stale AC assignments may not be cleaned"
  treat_missing_data  = "notBreaching"

  dimensions = {
    FunctionName = aws_lambda_function.termination_cleanup[0].function_name
  }

  alarm_actions = [var.alerts_sns_topic_arn]
  ok_actions    = [var.alerts_sns_topic_arn]

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-termination-cleanup-errors"
    Component = "compute"
    Cell      = var.cell_id
  })
}
