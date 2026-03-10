# QURL Service Module
# ECS Fargate deployment for the QURL API service
#
# Architecture:
# Internet → ALB (HTTPS 443) → ECS Fargate (port 8080)
#
# The QURL API handles:
# - Public API: QURL management (Auth0 JWT protected)
# - Internal API: Token resolution for NHP plugin, target lookup for Traefik

# ==================== Data Sources ====================

data "aws_region" "current" {}
data "aws_caller_identity" "current" {}

# SSM parameter for image tag - created with default, updated by CI
# The CI pipeline updates this parameter after pushing a new image to ECR.
# Using lifecycle ignore_changes so CI updates don't cause drift.
resource "aws_ssm_parameter" "image_tag" {
  name        = var.image_tag_ssm_param
  type        = "String"
  value       = "latest"
  description = "Current Docker image tag for QURL service (managed by CI)"

  tags = merge(var.tags, {
    Name      = "${local.service_name}-image-tag"
    Component = "qurl-service"
    Cell      = var.cell_id
  })

  lifecycle {
    ignore_changes = [value]
  }
}

# SSM parameters for ECS cluster/service names - consumed by CI for deployments.
# This avoids hardcoding infrastructure names in the CI workflow.
#
# Note: These use inline path construction (/${var.name_prefix}/...) rather than
# variables like image_tag_ssm_param because CI only needs to know name_prefix
# to construct the path. The image_tag param uses a variable because its path
# pattern is more complex and was established before this convention.
resource "aws_ssm_parameter" "ecs_cluster" {
  name        = "/${var.name_prefix}/qurl-ecs-cluster"
  type        = "String"
  value       = aws_ecs_cluster.qurl.name
  description = "ECS cluster name for QURL service (consumed by CI)"

  tags = merge(var.tags, {
    Name      = "${local.service_name}-ecs-cluster"
    Component = "qurl-service"
    Cell      = var.cell_id
  })
}

resource "aws_ssm_parameter" "ecs_service" {
  name        = "/${var.name_prefix}/qurl-ecs-service"
  type        = "String"
  value       = aws_ecs_service.qurl.name
  description = "ECS service name for QURL service (consumed by CI)"

  tags = merge(var.tags, {
    Name      = "${local.service_name}-ecs-service"
    Component = "qurl-service"
    Cell      = var.cell_id
  })
}

# SSM parameter for default AC ID - resolved by ECS at task launch time via
# valueFrom in the container definition. This ensures the value is always
# current, even when task definitions are cloned by CI.
resource "aws_ssm_parameter" "default_ac_id" {
  name        = "/${var.name_prefix}/qurl-default-ac-id"
  type        = "String"
  value       = var.default_ac_id
  description = "Default AC ID for QURL service (resolved by ECS at task launch)"

  tags = merge(var.tags, {
    Name      = "${local.service_name}-default-ac-id"
    Component = "qurl-service"
    Cell      = var.cell_id
  })
}

# ==================== Locals ====================

locals {
  is_prod      = var.environment == "prod"
  service_name = "${var.name_prefix}-${var.cell_id}-qurl-api"
  # Shorter name for resources with 32-char limit (ALB/NLB names)
  short_name = "${var.name_prefix}-${var.cell_id}-qurl"

  # Task-level CPU/memory with ADOT sidecar overhead.
  # Fargate requires specific CPU/memory combinations (memory in 1024 MB increments
  # for CPU values 256-4096). Round up to avoid invalid combinations like 512 CPU / 1280 MB.
  # See: https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-cpu-memory-error.html
  task_cpu    = var.grafana_cloud_enabled ? max(var.container_cpu, 512) : var.container_cpu
  task_memory = ceil((var.grafana_cloud_enabled ? var.container_memory + 256 : var.container_memory) / 1024) * 1024

  # Compute allowed hosts: ALB DNS + domain + localhost for health checks + any additional hosts
  # Note: aws_lb.qurl.dns_name is referenced later, terraform handles the dependency
  computed_allowed_hosts = join(",", compact(concat(
    [aws_lb.qurl.dns_name, "localhost", "127.0.0.1"],
    var.domain_name != null ? [var.domain_name] : [],
    var.additional_allowed_hosts
  )))

  # Compute API base URL for Location headers and absolute URLs
  # Priority: explicit > domain with cert > ALB DNS
  computed_api_base_url = coalesce(
    var.api_base_url,
    var.domain_name != null && var.certificate_arn != null ? "https://${var.domain_name}" : null,
    "http://${aws_lb.qurl.dns_name}"
  )

  # Container environment variables
  container_env = concat([
    { name = "QURL_ENV", value = local.is_prod ? "production" : "development" },
    { name = "AWS_REGION", value = data.aws_region.current.id },
    { name = "SERVER_HOST", value = "0.0.0.0" },
    { name = "SERVER_PORT", value = tostring(var.container_port) },
    { name = "API_BASE_URL", value = local.computed_api_base_url },
    { name = "DYNAMODB_TABLE_PREFIX", value = var.dynamodb_table_prefix },
    { name = "AUTH0_DOMAIN", value = var.auth0_domain },
    { name = "AUTH0_AUDIENCE", value = var.auth0_audience },
    { name = "AUTH0_JWKS_CACHE_TTL", value = tostring(var.auth0_jwks_cache_ttl_seconds) },
    { name = "AUTH0_JWKS_FETCH_TIMEOUT", value = tostring(var.auth0_jwks_fetch_timeout_seconds) },
    { name = "QURL_COOKIE_DOMAIN", value = var.cookie_domain },
    { name = "QURL_LINK_DOMAIN", value = var.qurl_link_domain },
    { name = "QURL_SITE_DOMAIN", value = var.qurl_site_domain },
    { name = "QURL_DEFAULT_TOKEN_EXPIRE", value = tostring(var.default_token_expire) },
    { name = "QURL_DEFAULT_OPEN_TIME", value = tostring(var.default_open_time) },
    { name = "QURL_AC_PORT", value = tostring(var.default_ac_port) },
    { name = "IP_RATE_LIMIT", value = tostring(var.ip_rate_limit) },
    { name = "IP_RATE_BURST", value = tostring(var.ip_rate_burst) },
    { name = "AUDIT_RETENTION_DAYS", value = tostring(var.audit_retention_days) },
    { name = "CORS_ALLOWED_ORIGINS", value = var.cors_allowed_origins },
    { name = "ALLOWED_HOSTS", value = local.computed_allowed_hosts },
    { name = "LICENSES_TABLE_NAME", value = var.licenses_table_name },
    # Idempotency cache configuration
    { name = "IDEMPOTENCY_CACHE_TTL", value = tostring(var.idempotency_cache_ttl_seconds) },
    { name = "IDEMPOTENCY_CACHE_MAX_SIZE", value = tostring(var.idempotency_cache_max_size) },
    { name = "IDEMPOTENCY_CLEANUP_INTERVAL", value = tostring(var.idempotency_cleanup_interval_seconds) },
    # Health check configuration
    { name = "HEALTH_CHECK_TIMEOUT", value = tostring(var.health_check_timeout_seconds) },
    { name = "HEALTH_STARTUP_TIMEOUT", value = tostring(var.health_startup_timeout_seconds) },
    # License cache configuration
    { name = "LICENSE_CACHE_TTL", value = tostring(var.license_cache_ttl_seconds) },
    { name = "LICENSE_CACHE_MAX_SIZE", value = tostring(var.license_cache_max_size) },
    # QURL resource configuration
    { name = "QURL_DEFAULT_EXPIRES_IN", value = tostring(var.qurl_default_expires_in_seconds) },
    { name = "QURL_RESOURCE_TTL_BUFFER", value = tostring(var.qurl_resource_ttl_buffer_seconds) },
    { name = "QURL_SESSION_TTL", value = tostring(var.qurl_session_ttl_seconds) },
    { name = "QURL_DEFAULT_LIST_LIMIT", value = tostring(var.qurl_default_list_limit) },
    ],
    # Redis configuration (for distributed rate limiting)
    var.redis_enabled ? [
      { name = "REDIS_ENABLED", value = "true" },
      { name = "REDIS_ENDPOINT", value = var.redis_endpoint },
      { name = "REDIS_TLS_ENABLED", value = "true" },
    ] : [],
    # Usage events (billing metered usage reporting via SQS)
    var.usage_events_enabled ? [
      { name = "USAGE_EVENTS_ENABLED", value = "true" },
      { name = "USAGE_SQS_QUEUE_URL", value = var.usage_events_queue_url },
    ] : [],
    # Idempotency table (for distributed idempotency)
    var.idempotency_table_name != "" ? [
      { name = "IDEMPOTENCY_TABLE_NAME", value = var.idempotency_table_name },
    ] : [],
    # Webhooks configuration
    var.webhooks_enabled ? [
      { name = "WEBHOOKS_ENABLED", value = "true" },
      { name = "WEBHOOKS_WORKER_COUNT", value = tostring(var.webhooks_worker_count) },
      { name = "WEBHOOKS_MAX_PER_OWNER", value = tostring(var.webhooks_max_webhooks_per_owner) },
      { name = "WEBHOOKS_DELIVERY_TIMEOUT", value = tostring(var.webhooks_delivery_timeout_seconds) },
      { name = "WEBHOOKS_MAX_RETRIES", value = tostring(var.webhooks_max_retries) },
      { name = "WEBHOOKS_EVENT_CHANNEL_SIZE", value = tostring(var.webhooks_event_channel_size) },
      { name = "WEBHOOKS_RETRY_WORKER_INTERVAL", value = tostring(var.webhooks_retry_worker_interval_seconds) },
      { name = "WEBHOOKS_DRAIN_TIMEOUT", value = tostring(var.webhooks_drain_timeout_seconds) },
      { name = "WEBHOOKS_RESPONSE_BODY_LIMIT", value = tostring(var.webhooks_response_body_limit) },
      { name = "WEBHOOKS_API_VERSION", value = var.webhooks_api_version },
    ] : [],
    # Custom domain management
    var.custom_domain_enabled ? [
      { name = "CUSTOM_DOMAIN_ENABLED", value = "true" },
      { name = "CUSTOM_DOMAIN_ACME_SUFFIX", value = var.custom_domain_acme_suffix },
      { name = "CUSTOM_DOMAIN_NLB_TARGET", value = var.custom_domain_nlb_target },
    ] : [],
    # NHP integration (headless resolve via POST /v1/resolve)
    var.nhp_server_internal_url != "" ? [
      { name = "NHP_SERVER_INTERNAL_URL", value = var.nhp_server_internal_url },
      { name = "NHP_KNOCK_TIMEOUT", value = tostring(var.nhp_knock_timeout_seconds) },
    ] : [],
    # GeoIP configuration (for geo-restriction policies)
    var.geoip_enabled ? concat([
      { name = "GEOIP_ENABLED", value = "true" },
      { name = "GEOIP_DB_PATH", value = var.geoip_db_path },
      ],
      var.geoip_s3_uri != "" ? [
        { name = "GEOIP_S3_URI", value = var.geoip_s3_uri },
      ] : [],
    ) : [],
    # Stripe billing integration (for checkout, portal, invoices)
    var.stripe_secret_arn != "" ? [
      { name = "STRIPE_SECRET_ARN", value = var.stripe_secret_arn },
      { name = "GROWTH_PRICE_ID", value = var.stripe_growth_price_id },
      { name = "STRIPE_CHECKOUT_SUCCESS_URL", value = var.stripe_checkout_success_url },
      { name = "STRIPE_CHECKOUT_CANCEL_URL", value = var.stripe_checkout_cancel_url },
    ] : [],
    # OpenTelemetry configuration
    # When Grafana Cloud is enabled, OTEL exports to the local ADOT sidecar
    # The sidecar then forwards to Grafana Cloud OTLP endpoint
    var.otel_enabled ? [
      { name = "OTEL_ENABLED", value = "true" },
      { name = "OTEL_SERVICE_NAME", value = var.otel_service_name },
      { name = "OTEL_SERVICE_VERSION", value = var.otel_service_version },
      { name = "OTEL_ENVIRONMENT", value = var.otel_environment },
      # When Grafana Cloud is enabled, send to local ADOT sidecar; otherwise use configured endpoint
      # gRPC endpoint must be host:port without scheme - http:// causes "too many colons" error
      { name = "OTEL_EXPORTER_OTLP_ENDPOINT", value = var.grafana_cloud_enabled ? "localhost:4317" : var.otel_exporter_endpoint },
      { name = "OTEL_EXPORTER_OTLP_PROTOCOL", value = var.grafana_cloud_enabled ? "grpc" : var.otel_exporter_protocol },
      { name = "OTEL_EXPORTER_OTLP_INSECURE", value = var.grafana_cloud_enabled ? "true" : (var.otel_exporter_insecure ? "true" : "false") },
      { name = "OTEL_TRACE_SAMPLE_RATE", value = tostring(var.otel_trace_sample_rate) },
      { name = "OTEL_METRICS_INTERVAL", value = tostring(var.otel_metrics_interval) },
      { name = "OTEL_METRICS_ENABLED", value = var.otel_metrics_enabled ? "true" : "false" },
      { name = "OTEL_TRACING_ENABLED", value = var.otel_tracing_enabled ? "true" : "false" },
      { name = "OTEL_LOG_CORRELATION", value = var.otel_log_correlation ? "true" : "false" },
    ] : [],
  )

  # Secrets and SSM parameters resolved by ECS at task launch time.
  # Despite the field name, ECS "secrets" supports both Secrets Manager ARNs
  # and SSM Parameter Store ARNs — it's the mechanism for dynamic value resolution.
  container_secrets = [
    { name = "QURL_JWT_SECRET", valueFrom = var.jwt_secret_arn },
    { name = "QURL_INTERNAL_SERVICE_TOKEN", valueFrom = var.internal_service_token_arn },
    { name = "QURL_AC_ID", valueFrom = aws_ssm_parameter.default_ac_id.arn },
  ]
}

# ==================== CloudWatch Log Group ====================

resource "aws_cloudwatch_log_group" "qurl" {
  name              = "/layerv/nhp/${var.environment}/${var.cell_id}/qurl-api"
  retention_in_days = local.is_prod ? 365 : 30
  kms_key_id        = var.logs_kms_key_arn

  # Prevent accidental deletion of production logs via Terraform
  skip_destroy = local.is_prod

  tags = merge(var.tags, {
    Name      = "${local.service_name}-logs"
    Component = "qurl-service"
    Cell      = var.cell_id
  })
}

# ==================== ECS Cluster ====================

resource "aws_ecs_cluster" "qurl" {
  name = local.service_name

  setting {
    name  = "containerInsights"
    value = "enabled"
  }

  tags = merge(var.tags, {
    Name      = local.service_name
    Component = "qurl-service"
    Cell      = var.cell_id
  })
}

# ==================== IAM Roles ====================

# Task execution role (used by ECS agent to pull images, write logs)
resource "aws_iam_role" "execution" {
  name = "${local.service_name}-execution"

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

resource "aws_iam_role_policy_attachment" "execution_basic" {
  role       = aws_iam_role.execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

# Policy to read secrets from Secrets Manager and SSM parameters for valueFrom
resource "aws_iam_role_policy" "execution_secrets" {
  name = "secrets-access"
  role = aws_iam_role.execution.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat([
      {
        Effect = "Allow"
        Action = ["secretsmanager:GetSecretValue"]
        Resource = concat(
          [
            var.jwt_secret_arn,
            var.internal_service_token_arn,
          ],
          # Add Grafana Cloud secret when ADOT sidecar is enabled
          var.grafana_cloud_enabled && var.grafana_secret_arn != null ? [var.grafana_secret_arn] : []
        )
      },
      {
        Effect   = "Allow"
        Action   = ["ssm:GetParameters"]
        Resource = [aws_ssm_parameter.default_ac_id.arn]
      }
      ], var.secrets_kms_key_arn != null ? [{
        Effect   = "Allow"
        Action   = ["kms:Decrypt"]
        Resource = [var.secrets_kms_key_arn]
    }] : [])
  })
}

# Task role (used by the container application)
resource "aws_iam_role" "task" {
  name = "${local.service_name}-task"

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

# Policy for DynamoDB access
resource "aws_iam_role_policy" "task_dynamodb" {
  name = "dynamodb-access"
  role = aws_iam_role.task.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat([
      {
        Sid    = "DynamoDBAccess"
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:UpdateItem",
          "dynamodb:DeleteItem",
          "dynamodb:Query",
          "dynamodb:Scan",
          "dynamodb:BatchGetItem",
          "dynamodb:BatchWriteItem",
        ]
        Resource = concat(
          var.dynamodb_table_arns,
          [for arn in var.dynamodb_table_arns : "${arn}/index/*"],
          # Idempotency table (if configured)
          var.idempotency_table_arn != "" ? [var.idempotency_table_arn] : []
        )
      },
      {
        Sid    = "LicensesTableReadAccess"
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:Query",
        ]
        Resource = [
          var.licenses_table_arn,
          "${var.licenses_table_arn}/index/*",
        ]
      }
      ],
      # KMS decrypt for DynamoDB (tables are encrypted with KMS)
      var.secrets_kms_key_arn != null ? [{
        Sid      = "KMSDecryptDynamoDB"
        Effect   = "Allow"
        Action   = ["kms:Decrypt"]
        Resource = [var.secrets_kms_key_arn]
      }] : [],
    )
  })
}

# Policy for GeoIP database download from S3 (conditional)
resource "aws_iam_role_policy" "task_geoip_s3" {
  count = var.geoip_s3_uri != "" ? 1 : 0
  name  = "geoip-s3-access"
  role  = aws_iam_role.task.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "GeoIPDatabaseDownload"
      Effect   = "Allow"
      Action   = ["s3:GetObject"]
      Resource = [replace(var.geoip_s3_uri, "s3://", "arn:aws:s3:::")]
    }]
  })
}

# Policy to read Stripe secret from Secrets Manager (conditional)
resource "aws_iam_role_policy" "task_stripe_secret" {
  count = var.stripe_secret_arn != "" ? 1 : 0
  name  = "stripe-secret-access"
  role  = aws_iam_role.task.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat([{
      Sid      = "StripeSecretRead"
      Effect   = "Allow"
      Action   = ["secretsmanager:GetSecretValue"]
      Resource = [var.stripe_secret_arn]
      }],
      var.secrets_kms_key_arn != null ? [{
        Sid      = "KMSDecryptStripeSecret"
        Effect   = "Allow"
        Action   = ["kms:Decrypt"]
        Resource = [var.secrets_kms_key_arn]
    }] : [])
  })
}

resource "aws_iam_role_policy" "task_usage_events" {
  count = var.usage_events_queue_arn != "" ? 1 : 0
  name  = "usage-events-sqs-send"
  role  = aws_iam_role.task.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat([{
      Sid      = "SQSSendUsageEvents"
      Effect   = "Allow"
      Action   = ["sqs:SendMessage"]
      Resource = [var.usage_events_queue_arn]
      }],
      var.secrets_kms_key_arn != null ? [{
        Sid      = "KMSEncryptSQS"
        Effect   = "Allow"
        Action   = ["kms:GenerateDataKey", "kms:Decrypt"]
        Resource = [var.secrets_kms_key_arn]
    }] : [])
  })
}

# ==================== Security Groups ====================

resource "aws_security_group" "alb" {
  name_prefix = "${local.service_name}-alb-"
  vpc_id      = var.vpc_id
  description = "Security group for QURL API ALB"

  # HTTPS from anywhere
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTPS from internet"
  }

  # HTTP redirect (optional)
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTP redirect"
  }

  # Outbound to ECS tasks - restrict to VPC only (least privilege)
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [var.vpc_cidr]
    description = "Outbound to VPC only"
  }

  tags = merge(var.tags, {
    Name      = "${local.service_name}-alb-sg"
    Component = "qurl-service"
    Cell      = var.cell_id
  })

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_security_group" "ecs" {
  name_prefix = "${local.service_name}-ecs-"
  vpc_id      = var.vpc_id
  description = "Security group for QURL API ECS tasks"

  # HTTP from ALB
  ingress {
    from_port       = var.container_port
    to_port         = var.container_port
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
    description     = "HTTP from ALB"
  }

  # Also allow from VPC for internal service calls (NHP Server, Traefik)
  ingress {
    from_port   = var.container_port
    to_port     = var.container_port
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
    description = "HTTP from VPC (internal services)"
  }

  # All outbound (DynamoDB, Secrets Manager, Redis, etc.)
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "All outbound"
  }

  tags = merge(var.tags, {
    Name      = "${local.service_name}-ecs-sg"
    Component = "qurl-service"
    Cell      = var.cell_id
  })

  lifecycle {
    create_before_destroy = true
  }
}

# Allow ECS tasks to connect to Redis (if enabled)
resource "aws_security_group_rule" "ecs_to_redis" {
  count = var.redis_enabled ? 1 : 0

  type                     = "ingress"
  from_port                = 6379
  to_port                  = 6380
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.ecs.id
  security_group_id        = var.redis_security_group_id
  description              = "Redis from QURL ECS tasks"
}

# ==================== ECS Task Definition ====================

resource "aws_ecs_task_definition" "qurl" {
  family                   = local.service_name
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = local.task_cpu
  memory                   = local.task_memory
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.task.arn

  # Note: Initial deployment uses "latest" tag from SSM parameter default value.
  # CI pipeline updates the SSM parameter and deploys new task definitions independently.
  # Terraform ignores task_definition changes after initial creation (lifecycle.ignore_changes).
  container_definitions = jsonencode(concat(
    # QURL API container (always present)
    [{
      name  = "qurl-api"
      image = "${var.ecr_repo_url}:${aws_ssm_parameter.image_tag.value}"

      portMappings = [{
        containerPort = var.container_port
        protocol      = "tcp"
      }]

      environment = local.container_env
      secrets     = local.container_secrets

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.qurl.name
          "awslogs-region"        = data.aws_region.current.id
          "awslogs-stream-prefix" = "ecs"
        }
      }

      # ECS container health check - uses liveness probe (fast, no dependency checks)
      # /health/live only verifies the service is running, not that dependencies are healthy
      # Note: Container uses Alpine with wget, not curl
      healthCheck = {
        command     = ["CMD-SHELL", "wget --quiet --tries=1 --spider http://localhost:${var.container_port}/health/live || exit 1"]
        interval    = 30
        timeout     = 5
        retries     = 3
        startPeriod = 60
      }

      # Increase file descriptor limits to prevent resource exhaustion under load
      ulimits = [{
        name      = "nofile"
        softLimit = 65536
        hardLimit = 65536
      }]
    }],
    # ADOT Collector sidecar (only when Grafana Cloud is enabled)
    # Receives OTLP from QURL container and exports to Grafana Cloud
    # Config is inline below; keep files/otel-collector-config.yaml in sync for reference
    var.grafana_cloud_enabled ? [{
      name      = "adot-collector"
      image     = var.adot_collector_image
      essential = false # Allow main container to continue if sidecar fails

      portMappings = [
        { containerPort = 4317, protocol = "tcp" }, # OTLP gRPC
        { containerPort = 4318, protocol = "tcp" }, # OTLP HTTP
      ]

      secrets = [
        { name = "GRAFANA_OTLP_ENDPOINT", valueFrom = "${var.grafana_secret_arn}:endpoint::" },
        { name = "GRAFANA_OTLP_AUTH", valueFrom = "${var.grafana_secret_arn}:auth::" },
      ]

      # Use inline config via AOT_CONFIG_CONTENT environment variable
      # This avoids needing to mount the config file from S3
      command = ["--config=env:AOT_CONFIG_CONTENT"]

      # ADOT collector config embedded as environment variable
      # See files/otel-collector-config.yaml for the source config
      environment = [
        { name = "ENVIRONMENT", value = var.environment },
        {
          name = "AOT_CONFIG_CONTENT"
          value = yamlencode({
            extensions = {
              health_check = {
                endpoint = "0.0.0.0:13133"
              }
            }
            receivers = {
              otlp = {
                protocols = {
                  grpc = { endpoint = "0.0.0.0:4317" }
                  http = { endpoint = "0.0.0.0:4318" }
                }
              }
            }
            processors = {
              # Prevent OOM by limiting memory usage - critical for sidecar containers
              memory_limiter = {
                check_interval  = "1s"
                limit_mib       = 200
                spike_limit_mib = 50
              }
              batch = {
                timeout         = "10s"
                send_batch_size = 1024
              }
              resourcedetection = {
                detectors = ["env", "ecs"]
                timeout   = "5s"
                override  = false
              }
              attributes = {
                actions = [
                  {
                    key    = "deployment.environment"
                    value  = var.environment
                    action = "upsert"
                  },
                  {
                    key    = "cell.id"
                    value  = var.cell_id
                    action = "upsert"
                  }
                ]
              }
            }
            exporters = {
              otlphttp = {
                endpoint = "$${GRAFANA_OTLP_ENDPOINT}"
                headers = {
                  Authorization = "Basic $${GRAFANA_OTLP_AUTH}"
                }
              }
            }
            service = {
              extensions = ["health_check"]
              pipelines = {
                traces = {
                  receivers  = ["otlp"]
                  processors = ["memory_limiter", "batch", "resourcedetection", "attributes"]
                  exporters  = ["otlphttp"]
                }
                metrics = {
                  receivers  = ["otlp"]
                  processors = ["memory_limiter", "batch", "resourcedetection", "attributes"]
                  exporters  = ["otlphttp"]
                }
                logs = {
                  receivers  = ["otlp"]
                  processors = ["memory_limiter", "batch", "resourcedetection", "attributes"]
                  exporters  = ["otlphttp"]
                }
              }
            }
          })
        },
      ]

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.qurl.name
          "awslogs-region"        = data.aws_region.current.id
          "awslogs-stream-prefix" = "adot"
        }
      }

      healthCheck = {
        command     = ["CMD", "/healthcheck"]
        interval    = 30
        timeout     = 5
        retries     = 3
        startPeriod = 60
      }
    }] : []
  ))

  tags = merge(var.tags, {
    Name      = local.service_name
    Component = "qurl-service"
    Cell      = var.cell_id
  })

  # Validate Fargate CPU/memory combinations at plan time
  # See: https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-cpu-memory-error.html
  # Note: When grafana_cloud_enabled=true, CPU is set to max(container_cpu, 512) and memory is increased by 256MB
  lifecycle {
    precondition {
      condition = (
        # When ADOT sidecar is enabled, effective CPU is max(container_cpu, 512) and memory += 256
        var.grafana_cloud_enabled ? (
          # Effective CPU: max(container_cpu, 512)
          # Effective memory: container_memory + 256
          (max(var.container_cpu, 512) == 512 && (var.container_memory + 256) >= 1024 && (var.container_memory + 256) <= 4096) ||
          (max(var.container_cpu, 512) == 1024 && (var.container_memory + 256) >= 2048 && (var.container_memory + 256) <= 8192) ||
          (max(var.container_cpu, 512) == 2048 && (var.container_memory + 256) >= 4096 && (var.container_memory + 256) <= 16384) ||
          (max(var.container_cpu, 512) == 4096 && (var.container_memory + 256) >= 8192 && (var.container_memory + 256) <= 30720) ||
          (max(var.container_cpu, 512) == 8192 && (var.container_memory + 256) >= 16384 && (var.container_memory + 256) <= 61440) ||
          (max(var.container_cpu, 512) == 16384 && (var.container_memory + 256) >= 32768 && (var.container_memory + 256) <= 122880)
          ) : (
          # Original validation when ADOT is disabled
          (var.container_cpu == 256 && var.container_memory >= 512 && var.container_memory <= 2048) ||
          (var.container_cpu == 512 && var.container_memory >= 1024 && var.container_memory <= 4096) ||
          (var.container_cpu == 1024 && var.container_memory >= 2048 && var.container_memory <= 8192) ||
          (var.container_cpu == 2048 && var.container_memory >= 4096 && var.container_memory <= 16384) ||
          (var.container_cpu == 4096 && var.container_memory >= 8192 && var.container_memory <= 30720) ||
          (var.container_cpu == 8192 && var.container_memory >= 16384 && var.container_memory <= 61440) ||
          (var.container_cpu == 16384 && var.container_memory >= 32768 && var.container_memory <= 122880)
        )
      )
      error_message = "Invalid Fargate CPU/memory combination. See AWS docs for valid combinations. When grafana_cloud_enabled=true, effective CPU is max(container_cpu, 512) and memory is increased by 256MB."
    }

    precondition {
      condition     = var.environment != "prod" || (var.cors_allowed_origins != "" && var.cors_allowed_origins != "*")
      error_message = "Production requires explicit CORS origins, not empty or wildcard."
    }

    precondition {
      condition     = var.environment != "prod" || startswith(local.computed_api_base_url, "https://")
      error_message = "Production requires HTTPS: API_BASE_URL must use https:// in prod environment. Either provide certificate_arn or set api_base_url to an https:// URL."
    }
  }
}

# ==================== Application Load Balancer ====================

resource "aws_lb" "qurl" {
  name               = replace(local.short_name, "_", "-")
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = var.public_subnet_ids

  # Access logging for production audit compliance
  dynamic "access_logs" {
    for_each = var.alb_access_logs_bucket != null ? [1] : []
    content {
      bucket  = var.alb_access_logs_bucket
      prefix  = var.alb_access_logs_prefix
      enabled = true
    }
  }

  tags = merge(var.tags, {
    Name      = local.service_name
    Component = "qurl-service"
    Cell      = var.cell_id
  })

  lifecycle {
    precondition {
      condition     = var.environment != "prod" || var.alb_access_logs_bucket != null
      error_message = "ALB access logs bucket is required for production environments for audit compliance."
    }
  }
}

resource "aws_lb_target_group" "qurl" {
  name        = replace("${var.name_prefix}-${var.cell_id}-qurl", "_", "-")
  port        = var.container_port
  protocol    = "HTTP"
  vpc_id      = var.vpc_id
  target_type = "ip"

  # ALB health check - uses readiness probe (deep dependency checks)
  # /health/ready verifies all critical dependencies are healthy before routing traffic
  # Returns 200 for healthy/degraded, 503 for unhealthy (critical dependency failure)
  health_check {
    enabled             = true
    healthy_threshold   = 2
    unhealthy_threshold = 3
    timeout             = 5
    interval            = 30
    path                = "/health/ready"
    matcher             = "200"
  }

  tags = merge(var.tags, {
    Name      = "${local.service_name}-tg"
    Component = "qurl-service"
    Cell      = var.cell_id
  })

  lifecycle {
    create_before_destroy = true
  }
}

# HTTPS Listener (requires certificate)
# Note: count uses domain_name (not certificate_arn) because certificate_arn may be
# computed at apply time (e.g., from aws_acm_certificate_validation), which would
# cause "Invalid count argument" errors during terraform plan.
resource "aws_lb_listener" "https" {
  count = var.domain_name != null ? 1 : 0

  load_balancer_arn = aws_lb.qurl.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.qurl.arn
  }

  tags = merge(var.tags, {
    Name      = "${local.service_name}-https"
    Component = "qurl-service"
    Cell      = var.cell_id
  })
}

# HTTP Listener (redirect to HTTPS when domain configured, otherwise forward)
# WARNING: When domain_name is null, traffic is served over unencrypted HTTP.
# This should only be used during initial setup before certificate provisioning.
# For production, always provide a domain_name (which implies certificate).
resource "aws_lb_listener" "http" {
  lifecycle {
    precondition {
      condition     = var.environment != "prod" || var.domain_name != null
      error_message = "Production requires HTTPS: domain_name must be provided for prod environment."
    }
  }

  load_balancer_arn = aws_lb.qurl.arn
  port              = 80
  protocol          = "HTTP"

  # When domain is configured, redirect HTTP to HTTPS
  # When no domain, forward directly to target group (HTTP only mode)
  dynamic "default_action" {
    for_each = var.domain_name != null ? [1] : []
    content {
      type = "redirect"
      redirect {
        port        = "443"
        protocol    = "HTTPS"
        status_code = "HTTP_301"
      }
    }
  }

  dynamic "default_action" {
    for_each = var.domain_name == null ? [1] : []
    content {
      type             = "forward"
      target_group_arn = aws_lb_target_group.qurl.arn
    }
  }

  tags = merge(var.tags, {
    Name      = "${local.service_name}-http"
    Component = "qurl-service"
    Cell      = var.cell_id
  })
}

# ==================== ECS Service ====================

resource "aws_ecs_service" "qurl" {
  name            = local.service_name
  cluster         = aws_ecs_cluster.qurl.id
  task_definition = aws_ecs_task_definition.qurl.arn
  desired_count   = var.desired_count
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = var.private_subnet_ids
    security_groups  = [aws_security_group.ecs.id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.qurl.arn
    container_name   = "qurl-api"
    container_port   = var.container_port
  }

  # Prevent premature unhealthy marking during slow container startups
  health_check_grace_period_seconds = 60

  # Allow external deployment tools (CI) to update the service
  deployment_controller {
    type = "ECS"
  }

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  # Ignore changes to desired_count (managed by auto-scaling) and task_definition (managed by CI)
  lifecycle {
    ignore_changes = [desired_count, task_definition]
  }

  tags = merge(var.tags, {
    Name      = local.service_name
    Component = "qurl-service"
    Cell      = var.cell_id
  })

  depends_on = [aws_lb_listener.http]
}

# ==================== Route53 Record ====================

resource "aws_route53_record" "qurl" {
  count = var.domain_name != null && var.hosted_zone_id != null ? 1 : 0

  zone_id = var.hosted_zone_id
  name    = var.domain_name
  type    = "A"

  alias {
    name                   = aws_lb.qurl.dns_name
    zone_id                = aws_lb.qurl.zone_id
    evaluate_target_health = true
  }
}

# ==================== Auto Scaling ====================

resource "aws_appautoscaling_target" "qurl" {
  count = local.is_prod ? 1 : 0

  max_capacity       = var.autoscaling_max_capacity
  min_capacity       = var.autoscaling_min_capacity
  resource_id        = "service/${aws_ecs_cluster.qurl.name}/${aws_ecs_service.qurl.name}"
  scalable_dimension = "ecs:service:DesiredCount"
  service_namespace  = "ecs"
}

resource "aws_appautoscaling_policy" "cpu" {
  count = local.is_prod ? 1 : 0

  name               = "${local.service_name}-cpu"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.qurl[0].resource_id
  scalable_dimension = aws_appautoscaling_target.qurl[0].scalable_dimension
  service_namespace  = aws_appautoscaling_target.qurl[0].service_namespace

  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageCPUUtilization"
    }
    target_value       = 70.0
    scale_in_cooldown  = 300
    scale_out_cooldown = 60
  }
}
