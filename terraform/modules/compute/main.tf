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

# AMI Selection (fail-fast, no fallback):
# 1. If var.server_ami_id is set directly, use it
# 2. Otherwise, read from SSM parameter /{environment}/nhp/server/ami-id
#
# The AMI must be pre-built with Docker installed. Without a custom AMI,
# Terraform will fail at plan time with a clear error.
#
# Build and publish AMI:
#   cd packer && packer build -var 'environment=sandbox' nhp-server-docker.pkr.hcl
#   aws ssm put-parameter --name "/sandbox/nhp/server/ami-id" \
#     --value "ami-xxx" --type String --overwrite
#
# Naming aligned with sibling /${env}/nhp/server/* parameters
# (image-tag, asg-name, active-color, ...). See blue_green.tf for the rest.
data "aws_ssm_parameter" "server_ami" {
  count = var.server_ami_id == null ? 1 : 0
  name  = "/${var.environment}/nhp/server/ami-id"
}

# ==================== Locals ====================

locals {
  is_prod = var.environment == "prod"

  # Fail fast: either var.server_ami_id is set, or SSM parameter must exist.
  server_ami_id = var.server_ami_id != null ? var.server_ami_id : data.aws_ssm_parameter.server_ami[0].value

  # Pinned uid:gid for the non-root nhp-server container (#1090). Single source
  # of truth: rendered into BOTH `docker run --user` and the host useradd in
  # user_data.sh.tpl, which must agree or the container can't read its mounts.
  nhp_server_uid = 10001
  nhp_server_gid = 10001
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
  runtime       = "nodejs22.x"
  timeout       = 30

  filename         = data.archive_file.keygen_lambda.output_path
  source_code_hash = data.archive_file.keygen_lambda.output_base64sha256

  tags = var.tags
}

# Adding a `count` here (or wrapping `module "compute"` in a toggle)
# requires removing the matching `lambda-compute-keygen` upload+download
# pair in promote-to-prod.yml in the same patch — see
# docs/runbooks/promote-to-prod-lambda-artifacts.md (loud-fail policy).
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

# Read back the publicKey the Lambda generated so we can thread it
# through terraform to other modules that need to know which key the
# running NHP server actually signs packets with (specifically
# qurl-service's agent-bootstrap response — see #server_public_key_b64
# in outputs.tf for the contract).
#
# tfstate exposure: this data source materializes secret_string
# (full JSON: privateKey + publicKey + hostname + environment) as a
# sensitive-marked attribute in state. tfstate access already implies
# Secrets Manager access in this org's threat model (S3+KMS+IAM
# scoped), and the same pattern is used by the auth0-backend / etcd-
# tls / cookie-secret data sources in this tree. The output above
# nonsensitive()-wraps only the publicKey so downstream consumers
# get a non-sensitive string for env-var injection; the privateKey
# stays in state, sensitive-marked.
#
# depends_on the lambda invocation so the secret_string is populated
# before the data source reads it. AWS provider caches the value
# within an apply, so refreshing this on every plan is a single
# Secrets Manager GET, not a per-resource cost.
#
# version_stage = "AWSCURRENT" is the AWS default and is set here
# explicitly because the keygen Lambda (line 175) writes via
# PutSecretValueCommand without a VersionStages arg — which also
# defaults to AWSCURRENT. A future rotation flow that stages a new
# key under AWSPENDING before promoting it would silently desync
# the terraform-exposed value from the running server until the
# stage promotion completed; pinning the stage here makes the
# rotation contract grep-discoverable and the desync window
# explicit at the boundary instead of buried in defaults.
data "aws_secretsmanager_secret_version" "server" {
  secret_id     = aws_secretsmanager_secret.server.id
  version_stage = "AWSCURRENT"
  depends_on    = [aws_lambda_invocation.keygen]
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

# CloudWatch Log Group for the server container's stdout/stderr. Routed
# by the docker --log-driver=awslogs on the systemd unit, so any panic
# or runtime error that Go writes directly to os.Stderr -- bypassing the
# structured file logger that feeds `aws_cloudwatch_log_group.server` --
# is captured here instead of being dropped to the host's docker json
# log file. This closes the observability gap that let the "panic: send
# on closed channel" crash loop (fixed in PR #1096) live undetected
# through every blue/green deploy. Retention is short on purpose: this
# group is an alert surface, not an archive; long-term diagnostics live
# in the structured `server` group alongside context.
resource "aws_cloudwatch_log_group" "server_stderr" {
  name              = "/layerv/nhp/${var.environment}/${var.cell_id}/server-stderr"
  retention_in_days = 7
  kms_key_id        = var.logs_kms_key_arn

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-logs-server-stderr"
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

# DynamoDB storage access for per-AC assignment architecture (when storage_backend = "dynamodb").
# Variable names retain the older "read" wording to avoid a broad Terraform
# interface rename; the attached policy also carries bounded server writes.
# Uses boolean variable because Terraform cannot evaluate count based on module outputs at plan time
# See docs/design/PLUGGABLE_STORAGE_BACKEND.md
resource "aws_iam_role_policy_attachment" "server_dynamodb" {
  count      = var.attach_storage_policies ? 1 : 0
  role       = aws_iam_role.server.name
  policy_arn = var.dynamodb_read_policy_arn
}

# Same-apply IAM policy edits can lag in AWS's authorization evaluator just
# long enough for freshly cycled instances to hit AccessDenied on their first
# DynamoDB calls. The 60s wait matches the observed upper edge of same-apply
# IAM evaluator lag in sandbox applies (last re-verified 2026-05-26 by the
# ACK token policy edit rollout). Re-verify with a sandbox apply that cycles
# fresh instances before shortening. Key this wait on the server DynamoDB
# policy content and the actual role-policy attachment, then make the launch
# template wait for it.
resource "time_sleep" "dynamodb_read_iam_propagation" {
  count = var.attach_storage_policies ? 1 : 0

  triggers = {
    policy_doc_hash = var.dynamodb_read_policy_doc_hash
    policy_arn      = var.dynamodb_read_policy_arn
    attachment_id   = aws_iam_role_policy_attachment.server_dynamodb[0].id
  }

  create_duration = "60s"
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
          [var.qurl_service_token_secret_arn],
          [var.nhp_internal_auth_secret_arn],
          # #2208 5c: read the relay fleet's keypair to render relay.toml at boot
          # (the server trusts the relay's pubkey). Constructed ARN by name — NOT
          # module.relay.secret_arn, which would close a compute→relay module
          # cycle (relay already consumes module.compute.server_public_key_b64).
          # `-*` matches Secrets Manager's random suffix; compact() drops the ""
          # when the relay is not deployed (relay_enabled=false).
          [var.relay_enabled ? "arn:aws:secretsmanager:${data.aws_region.current.id}:${data.aws_caller_identity.current.account_id}:secret:${var.name_prefix}-relay-*" : ""]
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
        Resource = [
          "${aws_cloudwatch_log_group.server.arn}:*",
          "${aws_cloudwatch_log_group.server_stderr.arn}:*",
        ]
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
    # Non-root container service account (#1090) — same numerics in --user and useradd.
    nhp_server_uid      = local.nhp_server_uid
    nhp_server_gid      = local.nhp_server_gid
    etcd_endpoint       = var.etcd_endpoint
    etcd_tls_secret_arn = var.etcd_tls_secret_arn
    # Pass the stderr log group name directly from the TF resource so
    # it cannot drift from the Terraform-managed resource. Consumed by
    # the docker --log-opt awslogs-group flag in the systemd unit.
    server_stderr_log_group = aws_cloudwatch_log_group.server_stderr.name
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
    dynamodb_agent_keys_table     = var.dynamodb_agent_keys_table
    dynamodb_ack_tokens_table     = var.dynamodb_ack_tokens_table
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
    # Shared HMAC secret for /nhp/internal/knock verification (matches qurl-service signer)
    nhp_internal_auth_secret_arn = var.nhp_internal_auth_secret_arn
    # CORS allowed origins for NHP HTTP server
    cors_allowed_origins = var.cors_allowed_origins
    # CloudFront trusted proxy CIDRs (for correct client IP via X-Forwarded-For)
    cloudfront_cidrs_ssm_parameter  = var.cloudfront_cidrs_ssm_parameter
    knock_headertype_verify_require = var.knock_headertype_verify_require
    internal_auth_require           = var.internal_auth_require
    # Knock-port DoS hardening (#1159): global rate cap + receive-buffer tuning.
    knock_global_rate_limit_pps   = var.knock_global_rate_limit_pps
    knock_global_rate_limit_burst = var.knock_global_rate_limit_burst
    udp_recv_buffer_bytes         = var.udp_recv_buffer_bytes
    # HTTP server timeouts. Surfaced as a TF variable (not hard-coded in
    # the heredoc) so the root module's `aws_cloudfront_distribution.qurl_resolve`
    # lifecycle.precondition can hard-fail plan/apply if IdleTimeoutMs
    # drops below origin_keepalive_timeout + buffer. Bumping CF without
    # touching these would silently re-open the keep-alive race; the
    # precondition fences that.
    http_read_timeout_ms  = var.http_timeouts_ms.read
    http_write_timeout_ms = var.http_timeouts_ms.write
    http_idle_timeout_ms  = var.http_timeouts_ms.idle
    # #2208 5c: server trusts the relay. relay_enabled (= deploy_relay) drives
    # DisableRelayValidation in config.toml AND gates the relay.toml render (the
    # server fetches the relay fleet pubkey from Secrets Manager at boot). Prod
    # (deploy_relay=false) → DisableRelayValidation=false + no relay.toml, so it
    # stays behaviorally dark. relay_secret_name is the deterministic relay secret
    # name (constructed, not a module ref → no compute→relay cycle).
    relay_enabled     = var.relay_enabled
    relay_secret_name = "${var.name_prefix}-relay"
  })

  # Launch template user_data — small fetcher when the plugin bucket exists,
  # legacy inline base64gzip path otherwise. Computed in a local so the
  # lifecycle.precondition on aws_launch_template.server can reference the
  # rendered bytes (TF preconditions can't reference `self`).
  server_launch_template_user_data = var.plugin_bucket_name != null ? base64encode(<<-BOOTSTRAP
#!/bin/bash
# -e: exit on error. -x: trace. pipefail: a write failure in the
# tee/logger pipe below shouldn't return 0 from the pipeline and let
# the rest of the script proceed logless.
set -exo pipefail
exec > >(tee /var/log/user-data.log | logger -t user-data) 2>&1
# Init script hash — md5 of local.user_data, NOT the S3 object's etag.
# The hash bumps the launch-template version whenever content changes.
# Referencing aws_s3_object.server_init_script[0].etag here triggers the
# AWS provider's "inconsistent values for sensitive attribute" bug on
# user_data updates: TF pre-computes one etag client-side, the apply-time
# S3 upload yields a different etag (sensitivity-handling or encoding
# divergence in the provider), and plan-expansion fails. md5(local.user_data)
# is computed entirely client-side, so it can't disagree with itself
# between plan and apply.
# Keep in sync with modules/ac/main.tf::aws_launch_template.ac.
# Init script hash: ${md5(local.user_data)}

# Fetch region from IMDSv2 BEFORE the trap and apt block. report_failure
# below uses --region "$REGION", and an early failure during apt/awscli
# install is the most common boot failure mode — fetching region after
# would leave the failure metric region-less and silently dropped.
#
# Defensive fetch: bash command-substitution failures don't trip set -e,
# and curl -s masks HTTP errors as empty bodies. Without retry, a single
# IMDS hiccup on a thundering-herd ASG scale-up bricks the instance with
# no signal. -f fails on HTTP non-2xx, explicit emptiness check catches
# the curl-returns-0-with-empty-body edge case.
fetch_imds_token_and_region() {
  local token region
  for _ in 1 2 3 4 5; do
    # Reset locals each iteration so a partial-success in one iteration
    # (token set, region failed) can't leak a stale token into the next
    # iteration's emptiness checks.
    token=""; region=""
    token=$(curl -fs -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 60") || { sleep 2; continue; }
    [ -n "$token" ] || { sleep 2; continue; }
    region=$(curl -fs -H "X-aws-ec2-metadata-token: $token" http://169.254.169.254/latest/meta-data/placement/region) || { sleep 2; continue; }
    [ -n "$region" ] || { sleep 2; continue; }
    TOKEN=$token; REGION=$region; return 0
  done
  return 1
}
if ! fetch_imds_token_and_region; then
  echo "FATAL: IMDSv2 unreachable after 5 attempts; bricking instance loud rather than silent"
  # IMDS-failure path: REGION is unset, so report_failure (which uses
  # --region "$REGION") would silently drop the metric. Use the
  # TF-interpolated literal as a fallback so on-call gets paged on
  # this exact failure mode (the most likely one on a thundering-herd
  # ASG scale-up — see fetch_imds_token_and_region docstring).
  command -v aws &>/dev/null && aws cloudwatch put-metric-data \
    --namespace "LayerV/NHP" \
    --metric-name "BootstrapFailure" \
    --value 1 --unit Count \
    --dimensions "Component=server,Environment=${var.environment},FailureMode=imds-unreachable" \
    --region "${data.aws_region.current.id}" 2>/dev/null || true
  exit 1
fi

report_failure() {
  echo "BOOTSTRAP FAILED: $1"
  command -v aws &>/dev/null && aws cloudwatch put-metric-data \
    --namespace "LayerV/NHP" \
    --metric-name "BootstrapFailure" \
    --value 1 --unit Count \
    --dimensions "Component=server,Environment=${var.environment}" \
    --region "$REGION" 2>/dev/null || true
}
trap 'report_failure "unexpected error on line $LINENO"' ERR
retry_with_backoff() {
  local max_attempts=$1 delay=$2 max_delay=$3; shift 3
  local attempt=1
  while true; do
    if "$@"; then return 0; fi
    if [ "$attempt" -ge "$max_attempts" ]; then echo "ERROR: $* failed after $max_attempts attempts"; return 1; fi
    echo "$* failed (attempt $attempt/$max_attempts), retrying in $${delay}s..."
    sleep "$delay"; attempt=$((attempt + 1)); delay=$((delay * 2))
    if [ "$delay" -gt "$max_delay" ]; then delay=$max_delay; fi
  done
}
apt_get_with_retry() { retry_with_backoff 10 2 60 apt-get "$@"; }
# Custom NHP server AMI ships with awscli pre-installed (packer/nhp-server-docker.pkr.hcl).
# Defensive: install if missing in case the AMI builder regresses.
if ! command -v aws &>/dev/null; then
  export DEBIAN_FRONTEND=noninteractive
  apt_get_with_retry update -y
  apt_get_with_retry install -y unzip curl
  curl -fsSL "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o /tmp/awscliv2.zip
  unzip -qo /tmp/awscliv2.zip -d /tmp && /tmp/aws/install --update
  rm -rf /tmp/awscliv2.zip /tmp/aws
fi
retry_with_backoff 3 5 30 aws s3 cp "s3://${var.plugin_bucket_name}/scripts/server-init.sh" /tmp/server-init.sh --region "$REGION"
chmod +x /tmp/server-init.sh
exec /tmp/server-init.sh
BOOTSTRAP
  ) : base64gzip(local.user_data) # legacy inline path — only kept as a structural fallback for bucket-not-yet-provisioned bootstrap; fails for the same size reason this PR exists to fix, so it's not a viable runtime rollback. To roll back, revert this PR.
}

# Server bootstrap script in S3 (mirrors AC module pattern). The rendered
# user_data sits at the EC2 16KB user_data limit (post-gzip), so we move
# the bulk to S3 and keep the launch template's user_data as a small
# fetcher. Introduced in PR #1809; the matching size-guard precondition
# on aws_launch_template.server fences regrowth.
resource "aws_s3_object" "server_init_script" {
  count = var.plugin_bucket_name != null ? 1 : 0

  bucket       = var.plugin_bucket_name
  key          = "scripts/server-init.sh"
  content      = local.user_data
  content_type = "text/x-shellscript"
}

# Attach the plugin-bucket download policy from modules/plugins to the
# server role. This grants s3:GetObject + KMS Decrypt on the bucket's
# CMK — needed because the plugin bucket is encrypted with
# module.kms.logs_key_arn, which is a different CMK from the server's
# secrets_kms_key_arn (modules/kms/outputs.tf:21,31). A scripts/*-only
# inline policy would land us with s3:GetObject but no KMS Decrypt, so
# `aws s3 cp` would AccessDenied at boot. Mirrors the AC module's
# pattern (modules/ac/main.tf::aws_iam_role_policy_attachment.ac_plugins).
resource "aws_iam_role_policy_attachment" "server_plugins" {
  count = var.plugin_download_policy_arn != null ? 1 : 0

  role       = aws_iam_role.server.name
  policy_arn = var.plugin_download_policy_arn
}

# Launch Template
resource "aws_launch_template" "server" {
  name_prefix   = "${var.name_prefix}-server-"
  image_id      = local.server_ami_id
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

  # Full init script lives in S3 because the rendered template exceeds
  # EC2's 16KB user_data limit (post-gzip). Bootstrap installs/uses AWS CLI,
  # downloads scripts/server-init.sh, and execs it. An md5 of the rendered
  # local.user_data is embedded so a content change forces a launch template
  # version bump (and thus an instance refresh on the next deploy). See the
  # in-heredoc comment for why md5(local.user_data) instead of the S3 object's
  # etag. Mirrors the AC module's battle-tested pattern
  # (modules/ac/main.tf::aws_launch_template.ac).
  # Computed via local.server_launch_template_user_data so the size guard
  # in lifecycle.precondition (below) can reference the rendered output.
  user_data = local.server_launch_template_user_data

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

    # Fail-loud guard against the size cliff this PR was created to escape.
    # EC2 caps user_data at 16,384 raw bytes (post-base64-decode); see
    # https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/user-data.html.
    # The whole point of the S3-hosted bootstrap is to keep the inline
    # user_data tiny — if a future PR adds enough to the bootstrap
    # heredoc to push past the limit, fail at plan time rather than at
    # apply time (where the only signal is a confusing "Modifying..."
    # error mid-apply).
    #
    # The user_data hash is md5(local.user_data) — fully plan-time computable
    # — so this precondition runs at plan, not apply.
    precondition {
      condition     = length(base64decode(local.server_launch_template_user_data)) <= 16384
      error_message = "Launch-template user_data exceeds EC2's 16384-byte cap (post-base64-decode). The S3 bootstrap pattern (modules/compute/main.tf::aws_s3_object.server_init_script) exists to keep the inline user_data tiny — move new logic into scripts/server-init.sh, not into the bootstrap heredoc."
    }

    # Both-or-neither: a future caller setting plugin_bucket_name without
    # plugin_download_policy_arn would render the BOOTSTRAP path, accept
    # the launch template, and brick instances at boot with AccessDenied
    # on the s3 cp (no KMS Decrypt grant). Plan-time fail is cheaper than
    # boot-time fail.
    precondition {
      condition     = (var.plugin_bucket_name == null) == (var.plugin_download_policy_arn == null)
      error_message = "plugin_bucket_name and plugin_download_policy_arn must be set together — the bucket needs the policy's KMS Decrypt grant or instances brick at boot."
    }
  }

  # Explicit dependency on the policy attachment so the first ASG launch
  # in a greenfield apply can't race ahead of IAM eventual consistency.
  # The S3 init script is an explicit dependency for runtime ordering: an
  # instance launched against this LT does `aws s3 cp` of the script at
  # boot, so the object must exist by the time the ASG can launch. (The
  # user_data hash is md5(local.user_data), not the object's etag — there
  # is no longer an attribute reference for TF to infer this from.)
  depends_on = [
    aws_lambda_invocation.keygen,
    aws_iam_role_policy_attachment.server_plugins,
    time_sleep.dynamodb_read_iam_propagation,
    aws_s3_object.server_init_script,
  ]
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

  # Use EC2 health checks (NOT ELB) for ASG lifecycle decisions. This is
  # load-bearing and prevents a bootstrap deadlock — see "Bootstrap deadlock
  # avoidance" below for the full chain.
  health_check_type = "EC2"
  # Docker is pre-baked into the AMI (see packer/nhp-server-docker.pkr.hcl),
  # so apt-get install Docker (~90s) and AWS CLI install (~30s) are no longer
  # in the critical path. Boot + user_data + container start now fit under
  # ~60s (~15s launch, ~15s user_data, ~15-30s ECR pull + container start).
  # 90s is ~1.5x the observed worst case to absorb slower ECR pulls when a
  # new image tag is rolled out for the first time.
  health_check_grace_period = 90
  #
  # Bootstrap deadlock avoidance:
  #
  # The HTTPS target group (aws_lb_target_group.https) uses /health/knock-ready
  # — that endpoint only returns 200 once the server has at least one connected
  # AC peer. That's intentional: HTTPS traffic on the QURL resolve listener
  # actually needs an AC peer to do anything useful, so we keep half-baked
  # servers out of the LB rotation.
  #
  # Naively, this would deadlock during bootstrap: the very first server has
  # no AC peers (no ACs have registered yet), so /health/knock-ready returns
  # non-200, the ELB marks it Unhealthy, and if the ASG were configured to
  # terminate on ELB failures, it would loop terminating fresh instances
  # forever — and ACs (which find servers via Cloud Map / DNS, not the LB)
  # would never get the chance to register against them.
  #
  # Two pieces break the deadlock:
  #   1. health_check_type = "EC2" above. The ASG only consults the EC2
  #      instance state (running/not-running) for lifecycle decisions and
  #      ignores the LB target group health entirely. Failing knock-ready
  #      affects LB routing, not instance termination.
  #   2. The HTTP forwarder fix in the server itself: when a knock arrives
  #      on a server that has no AC peers, the server forwards the knock to
  #      a peer server that does have AC peers, instead of failing. So
  #      bootstrap traffic still works even before the new server's own AC
  #      peers come up.
  #
  # The same /health/knock-ready path is used by the green HTTPS target group
  # (blue_green.tf::aws_lb_target_group.https_green); the same reasoning
  # applies. Keep this comment in sync if you ever change either.

  # Publish ASG group metrics to CloudWatch (AWS/AutoScaling namespace).
  # Without this, metrics like GroupInServiceInstances are not emitted.
  # Keep GroupDesiredCapacity + GroupInServiceInstances: green standby
  # capacity-deficit alarms use them as their publishable replacement for
  # AWS's non-existent GroupUnHealthyInstanceCount ASG group metric.
  enabled_metrics = [
    "GroupInServiceInstances",
    "GroupDesiredCapacity",
    "GroupMinSize",
    "GroupMaxSize",
    "GroupPendingInstances",
    "GroupTerminatingInstances",
    "GroupTotalInstances",
  ]

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
    # CI/CD manages capacity on this ASG during blue/green switches.
    # When traffic is switched to green, this (blue) ASG is scaled down
    # to a warm standby by the `scale-down-previous` job in
    # blue-green-deploy.yml. Without `ignore_changes` here, the next
    # `terraform apply` — which runs on every main-push CI deploy — resets
    # desired_capacity/min_size back to `var.min_capacity`, undoing the
    # scale-down within seconds and silently leaving two full-size ASGs
    # (2x cost, drift between TF state and reality).
    #
    # Matches the `aws_autoscaling_group.server_green` lifecycle in
    # blue_green.tf; the asymmetry (blue not having it) was the bug —
    # every CI deploy that ran a TF apply also reverted the blue/green
    # state that CI had just established.
    #
    # Trade-off: operators cannot change capacity via `var.min_capacity`
    # on an existing ASG through TF. Use the ASG API / console or a
    # blue/green deploy to adjust scale. This is consistent with the
    # green ASG's existing behaviour and matches how CI already operates.
    ignore_changes = [desired_capacity, min_size]
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

# Network scaling policy removed: the 10MB threshold was too low —
# deploy-time Docker image pulls (~50-100MB) triggered scale-up from 3→4,
# breaking AZ balance (3 instances = 1 per AZ). The blue-green workflow
# copies DesiredCapacity to the standby ASG, so the spurious 4 propagated
# permanently. CPU target-tracking (70%) is sufficient for real load scaling.

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

  lifecycle {
    # The Switch Traffic step in blue-green-deploy.yml points
    # `default_action.target_group_arn` at the blue or green TG to
    # flip which ASG serves production knocks. Without this ignore,
    # every `terraform apply` resets the listener back to
    # `aws_lb_target_group.udp.arn` (the blue TG), silently undoing
    # the blue/green traffic switch within seconds of CI making it.
    # The sandbox state-drift incident on 2026-04-08 was caused
    # exactly by this: a green-active deploy landed, the next CI
    # push ran a TF apply, and the apply reset the listener back to
    # blue while SSM still said green → `Reconcile Listener and SSM
    # State` validation step failed on the next dispatched deploy.
    ignore_changes = [default_action]
  }
}

# =============================================================================
# Internal UDP NLB for the relay -> cell-server hop (#2208 #8 / #2628 steps 1-2;
# closes #2626)
# =============================================================================
# The relay forwards NHP_RLY to the cell server over UDP 62206. Pointing it at
# CloudMap (`server.<namespace>`) resolves ONCE at the relay's boot to a single
# IP, which goes stale when the server fleet churns (#2626 — relay stale-IP on
# churn). This internal NLB gives the relay a stable, load-balanced,
# churn-resilient target whose DNS name never changes.
#
# This is a NON-BREAKING ADD that runs in parallel with the PUBLIC
# `aws_lb.server` above — that one stays untouched (legacy UDP agents, the
# resolver HTTPS listener, and external ACs still depend on it). Gated on
# var.relay_enabled (= deploy_relay): created ONLY where the relay is deployed,
# so there is no idle NLB in prod (deploy_relay=false → no relay to dial it; the
# NLB is created when prod enables the relay). The matching host flip lives in the
# root `module "relay"` call, which is likewise count-gated on deploy_relay.
#
# Mirrors the public UDP path's per-resource config (cross-zone, deletion
# protection per env, UDP 62206, instance target type, /health/live HTTP health
# check on 8888, deregistration_delay, tags) with these deliberate divergences:
#   - internal = true + private subnets (this is the in-VPC relay->server hop,
#     not an internet edge);
#   - UDP-only: NO resolver HTTPS listener/TG (the relay speaks only UDP knock);
#   - blue/green: a SINGLE internal TG fronts BOTH colors — the blue ASG via
#     aws_autoscaling_attachment.server_internal below, the green ASG via its
#     target_group_arns (blue_green.tf) — and the listener forwards statically to
#     it. The public path instead keeps per-color TGs and FLIPS its listener's
#     default_action in blue-green-deploy.yml's switch-traffic. Both-attach keeps
#     the internal NLB pointed at the active color's fleet across a flip (a
#     blue-only attach would route the relay to the stale warm-standby after a
#     green-active deploy). Trade-off: a fraction of knocks reach the warm-standby
#     (min=1, maybe old-image) color — benign, the NHP protocol is version-stable
#     and the relay forwards opaque packets. Active-color-only routing (full
#     public-path parity: green internal TG + listener flip) is tracked for #6 in
#     #2645.
#
# preserve_client_ip = true (mirrors the public TG's behaviour, see below): the
# server sees the relay INSTANCE's IP as the packet source and replies DIRECTLY
# to it, bypassing an NLB return hop. That is correct here — the relay's recvLoop
# reads the ACK from any source address and dispatches by inner counter, and the
# relay SG already admits this return (modules/relay/compute.tf
# ::aws_vpc_security_group_ingress_rule.relay_udp_ack_return, UDP from the VPC
# CIDR). The server-side inbound is already covered by
# aws_vpc_security_group_ingress_rule.server_nhp_udp (UDP 62206 from 0.0.0.0/0).
resource "aws_lb" "server_internal" {
  count              = var.relay_enabled ? 1 : 0
  name               = replace("${var.name_prefix}-srv-int", "_", "-")
  internal           = true
  load_balancer_type = "network"
  # Private subnets: the in-VPC relay->server hop lives with the ASG, not on the
  # public edge (see the divergences note in the block header above).
  subnets = var.private_subnet_ids

  # Cross-zone is correctness-relevant here, not just cost/parity: Go resolves
  # the relay.toml host ONCE at boot, so the relay may lock onto a single NLB
  # node IP (one AZ). With cross-zone disabled that node would only reach
  # same-AZ targets; enabling it lets the once-resolved relay reach the whole
  # fleet across AZs.
  enable_cross_zone_load_balancing = true
  enable_deletion_protection       = local.is_prod

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-srv-int-nlb"
    Component = "compute"
    Cell      = var.cell_id
  })
}

# Internal UDP Target Group (mirrors aws_lb_target_group.udp).
resource "aws_lb_target_group" "udp_internal" {
  count       = var.relay_enabled ? 1 : 0
  name        = replace("${var.name_prefix}-srv-int-udp", "_", "-")
  port        = 62206
  protocol    = "UDP"
  vpc_id      = var.vpc_id
  target_type = "instance"
  # Explicit (not relying on the AWS UDP-instance-TG default) because the
  # relay->server return path depends on it — see the NLB block comment above.
  preserve_client_ip = true

  # HTTP health check on port 8888 — same /health/live liveness probe the public
  # UDP TG uses (NOT the HTTPS TG's /health/knock-ready: this is the knock data
  # path, which works before the local server has AC peers via HTTP forwarding).
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
    Name      = "${var.name_prefix}-tg-srv-int-udp"
    Component = "compute"
    Cell      = var.cell_id
  })
}

# Attach the BLUE server ASG to the internal TG (multi-TG attach on this ASG is
# already in use — aws_autoscaling_attachment.https alongside .server). The GREEN
# ASG attaches to the SAME internal TG via its target_group_arns (blue_green.tf),
# see the udp_internal block comment above for the both-attach blue/green rationale.
resource "aws_autoscaling_attachment" "server_internal" {
  count                  = var.relay_enabled ? 1 : 0
  autoscaling_group_name = aws_autoscaling_group.server.name
  lb_target_group_arn    = aws_lb_target_group.udp_internal[0].arn
}

# Internal UDP Listener. Forwards statically to the single internal TG (which
# fronts both colors), so — unlike the public UDP listener — it is NOT flipped by
# the blue/green switch and needs no ignore_changes. Active-color-only routing via
# a per-color listener flip is the #2645 refinement.
resource "aws_lb_listener" "udp_internal" {
  count             = var.relay_enabled ? 1 : 0
  load_balancer_arn = aws_lb.server_internal[0].arn
  port              = 62206
  protocol          = "UDP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.udp_internal[0].arn
  }

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-listener-srv-int-udp"
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

  # Health check on port 8888 — uses /health/knock-ready to verify the server
  # has connected AC peers before routing knock traffic to it (H1 hardening).
  # /health/live is still used by ASG/Docker to avoid terminating servers
  # that are healthy but waiting for AC connections.
  health_check {
    enabled             = true
    protocol            = "HTTP"
    port                = "8888"
    path                = "/health/knock-ready"
    healthy_threshold   = 2
    unhealthy_threshold = 2
    interval            = 10
    matcher             = "200"
  }

  deregistration_delay = 30

  # Force immediate TCP RST on in-flight flows when an instance is
  # deregistered (e.g. blue/green flip + old-ASG shrink). Default is
  # `false` for TCP/TLS TGs, which lets in-flight flows drain over
  # `deregistration_delay`. That default was the trigger for the
  # 2026-05-22 sandbox "qurl.link verifying-access page spins 60s,
  # then redirects to a closed-L3 firewall" incident: CloudFront's
  # pooled origin connections were stranded on a draining green
  # instance, the gin handler returned 302 in 75ms but the TCP
  # response never flushed before the instance was SIGTERM'd, and CF
  # sat on its `OriginReadTimeout=60s` instead of detecting the dead
  # peer and retrying immediately. Setting this `true` makes the
  # dereg send RST → CF detects → CF retries on a fresh blue
  # connection on its own retry cadence (sub-second to single-digit
  # seconds in practice, bounded by CF's connection-error retry
  # budget — much faster than the 60s OriginReadTimeout the
  # pre-2026-05-22-fix behaviour incurred). Empirical retry
  # latency to be confirmed by
  # the sandbox repro listed in the PR test plan; the regime is
  # "much better than 60s" either way. Matches the AWS-default
  # behaviour the UDP TG already gets for free (UDP is stateless
  # from NLB's POV).
  #
  # **POST-replay idempotency on this TG**: CF's connection-error
  # retry will replay an in-flight POST. The /plugins/qurl path lands
  # on qurl-service's atomic DDB conditional update
  # (qurl-service/internal/repository/dynamodb/qurl_repo.go ConsumeTokenByHash);
  # a replay returns 403 "Access Link Invalid" rather than double-
  # consuming. See the parallel duplicate-POST writeup on
  # ac/main.tf::aws_lb_target_group.ac_tcp for the customer-backend
  # half (qurl-router forwards retries transparently — different
  # idempotency surface).
  #
  # **Role of deregistration_delay above is now disjoint from
  # in-flight TCP behaviour.** With connection_termination=true, the
  # 30s deregistration_delay only governs LB-side target-state
  # cleanup (the period during which the TG continues to report the
  # deregistering target while it stops accepting NEW traffic) —
  # in-flight TCP flows are RST'd immediately, NOT drained for up to
  # 30s. A future operator tuning deploy timing should not read
  # `deregistration_delay = 30` as "in-flight flows have 30s to
  # complete"; they have ~0s and rely on the upstream retry instead.
  #
  # Why 30s is kept (not tightened): the value still controls how
  # long the deregistering target stays visible in the TG before
  # the LB forgets it. Tightening to <30s would make the LB stop
  # routing NEW connections sooner but also race against
  # health-check propagation (interval=10s, unhealthy_threshold=2
  # = 20s minimum before a non-shutdown target stops being routed
  # to). 30s preserves a small safety margin against that race
  # without trading observable deploy speed; revisit only if
  # health-check tuning changes.
  connection_termination = true

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
    # Same blue/green traffic-switch concern as the UDP listener above —
    # blue-green-switch.sh flips `default_action.target_group_arn` on
    # every traffic switch, and we do not want `terraform apply` to
    # revert it.
    ignore_changes = [default_action]
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

# ============================================================================
# Bootstrap-deadlock invariant assertion
#
# The full deadlock-avoidance chain is documented at
# aws_autoscaling_group.server above (search "Bootstrap deadlock avoidance").
# Three conditions must all hold:
#   1. Both ASGs use health_check_type = "EC2" (NOT ELB).
#   2. The HTTPS target groups can use the strict /health/knock-ready path
#      because (1) means failing it doesn't trigger termination.
#   3. The server has an HTTP forwarder fallback that routes knocks to a
#      peer when the local AC peer count is zero.
#
# This check fires at plan time if anyone changes either ASG to ELB-based
# health checks. It is a non-blocking warning (Terraform `check` blocks
# emit ::warning::, not ::error::) — sufficient because anyone running
# `terraform plan` against this module will see the warning in CI output
# and on the PR. The first two conditions are easy to assert from
# Terraform; condition (3) is server-side Go code and is asserted in the
# server's own test suite.
# ============================================================================
check "asg_ec2_health_check_invariant" {
  assert {
    condition     = aws_autoscaling_group.server.health_check_type == "EC2"
    error_message = "BOOTSTRAP DEADLOCK RISK: aws_autoscaling_group.server.health_check_type must remain \"EC2\". Changing to ELB-based reintroduces the bootstrap deadlock documented at aws_autoscaling_group.server (search \"Bootstrap deadlock avoidance\"). If you genuinely need ELB health checks, update the documentation chain in main.tf and blue_green.tf, remove this check, AND verify the HTTP-forwarder fallback in the server still handles zero-AC-peers bootstrap correctly."
  }

  assert {
    # The conditional handles count=0 when blue/green is disabled — without
    # the guard the index lookup fails before the check runs.
    condition     = !var.enable_blue_green || (length(aws_autoscaling_group.server_green) > 0 && aws_autoscaling_group.server_green[0].health_check_type == "EC2")
    error_message = "BOOTSTRAP DEADLOCK RISK: aws_autoscaling_group.server_green.health_check_type must remain \"EC2\" when blue/green is enabled. Same reasoning as the blue ASG above; see aws_autoscaling_group.server in main.tf."
  }
}

# ============================================================================
# Blue/green HTTPS target group health-check drift detection
#
# The blue HTTPS target group (aws_lb_target_group.https in main.tf) and the
# green HTTPS target group (aws_lb_target_group.https_green in blue_green.tf)
# MUST have identical health check configurations. They serve the same
# traffic from the same kind of instance — any divergence means a blue/green
# swap will behave differently than blue/blue, which defeats the purpose of
# blue/green deployments and is exactly the class of bug that's invisible
# until you actually swap.
#
# Round-2 review of #252 caught a manual drift here (the green target group
# was using /health/live while blue used /health/knock-ready). Round-5 review
# asked for automated drift detection so the comment-only "keep these in
# sync" reminder doesn't decay into a lie.
#
# This check fires at plan time if any field of the two health check blocks
# diverges. Non-blocking warning (Terraform `check` blocks emit ::warning::,
# not ::error::) — sufficient because anyone running `terraform plan` will
# see the warning in CI output. To resolve the warning intentionally,
# update both blocks together AND keep the documentation cross-reference at
# blue_green.tf::https_green in sync.
# ============================================================================
check "https_target_group_blue_green_drift" {
  # Both asserts in this block use the same short-circuit shape:
  # `!var.enable_blue_green || length(https) == 0 || length(https_green) == 0`.
  # Strictly, `https` (blue) is counted on `enable_qurl_resolve_endpoint`
  # alone, while `https_green` is counted on
  # `enable_blue_green && enable_qurl_resolve_endpoint` — so the
  # `length(https) == 0` term covers the qurl-endpoint-off case and the
  # `!var.enable_blue_green` term covers the green-disabled case. The
  # `!var.enable_qurl_resolve_endpoint` clause is therefore redundant
  # with `length(https) == 0` and omitted.
  # Asymmetric with `ac/main.tf::ac_tcp_target_group_drift` because
  # ac_tcp (blue) is unconditional — that block has one `length == 0`
  # term to compute's two.
  assert {
    condition = (
      !var.enable_blue_green ||
      length(aws_lb_target_group.https) == 0 ||
      length(aws_lb_target_group.https_green) == 0 ||
      (
        aws_lb_target_group.https[0].health_check[0].path == aws_lb_target_group.https_green[0].health_check[0].path &&
        aws_lb_target_group.https[0].health_check[0].port == aws_lb_target_group.https_green[0].health_check[0].port &&
        aws_lb_target_group.https[0].health_check[0].protocol == aws_lb_target_group.https_green[0].health_check[0].protocol &&
        aws_lb_target_group.https[0].health_check[0].matcher == aws_lb_target_group.https_green[0].health_check[0].matcher &&
        aws_lb_target_group.https[0].health_check[0].interval == aws_lb_target_group.https_green[0].health_check[0].interval &&
        aws_lb_target_group.https[0].health_check[0].healthy_threshold == aws_lb_target_group.https_green[0].health_check[0].healthy_threshold &&
        aws_lb_target_group.https[0].health_check[0].unhealthy_threshold == aws_lb_target_group.https_green[0].health_check[0].unhealthy_threshold
      )
    )
    error_message = "BLUE/GREEN HEALTH CHECK DRIFT: aws_lb_target_group.https.health_check (main.tf) and aws_lb_target_group.https_green.health_check (blue_green.tf) have diverged. Both target groups serve the same traffic and MUST have identical health check configurations or a blue/green swap will silently change health-check semantics. Diff the two health_check blocks and align them. If the divergence is intentional (e.g. green is being upgraded), update this check together with the change so the next reader knows it was deliberate."
  }

  # connection_termination + deregistration_delay value-anchor. The
  # 2026-05-22 sandbox incident (see the comment block on
  # aws_lb_target_group.https) hinges on connection_termination=true
  # on BOTH colors. An equality-only assert would let a future PR
  # flip both to `false` together (silent regression on every flip);
  # the absolute value-anchor below structurally prevents that —
  # both colors must be `true` AND `deregistration_delay` must stay
  # at 30s. To tune either, edit BOTH resources AND this assert in
  # the same PR.
  assert {
    condition = (
      !var.enable_blue_green ||
      length(aws_lb_target_group.https) == 0 ||
      length(aws_lb_target_group.https_green) == 0 ||
      (
        aws_lb_target_group.https[0].connection_termination &&
        aws_lb_target_group.https_green[0].connection_termination &&
        aws_lb_target_group.https[0].deregistration_delay == 30 &&
        aws_lb_target_group.https_green[0].deregistration_delay == 30
      )
    )
    error_message = "BLUE/GREEN DEREG SEMANTICS VALUE-ANCHOR: aws_lb_target_group.https.{connection_termination,deregistration_delay} (main.tf) and aws_lb_target_group.https_green.{connection_termination,deregistration_delay} (blue_green.tf) must satisfy connection_termination=true AND deregistration_delay=30 on BOTH colors. The 2026-05-22 'CF stalled on stranded green-server flow for 60s' incident regresses if either color drops connection_termination=true (silent failure mode); deregistration_delay=30 here is calibrated against the COMPUTE-side health-check-propagation window (interval=10 × unhealthy_threshold=2 = 20s). The sibling AC value-anchor at ac/main.tf::ac_tcp_target_group_drift also pins =30 but for a DIFFERENT reason (intentional decoupling from AC's interval=30 × unhealthy_threshold=3 = 90s window); don't pattern-match both pins as a parallel calibration. Edit both colors AND this assert in the same PR; the comment block at main.tf::aws_lb_target_group.https carries the full incident history."
  }
}
