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

# ==================== Locals ====================

locals {
  is_prod      = var.environment == "prod"
  service_name = "${var.name_prefix}-${var.cell_id}-qurl-api"

  # Container environment variables
  container_env = [
    { name = "QURL_ENV", value = local.is_prod ? "production" : "development" },
    { name = "AWS_REGION", value = data.aws_region.current.id },
    { name = "SERVER_HOST", value = "0.0.0.0" },
    { name = "SERVER_PORT", value = tostring(var.container_port) },
    { name = "DYNAMODB_TABLE_PREFIX", value = var.dynamodb_table_prefix },
    { name = "AUTH0_DOMAIN", value = var.auth0_domain },
    { name = "AUTH0_AUDIENCE", value = var.auth0_audience },
    { name = "QURL_COOKIE_DOMAIN", value = var.cookie_domain },
    { name = "QURL_DEFAULT_TOKEN_EXPIRE", value = tostring(var.default_token_expire) },
    { name = "QURL_DEFAULT_OPEN_TIME", value = tostring(var.default_open_time) },
    { name = "QURL_AC_ID", value = var.default_ac_id },
    { name = "QURL_AC_HOST", value = var.default_ac_host },
    { name = "QURL_AC_PORT", value = tostring(var.default_ac_port) },
  ]

  # Secrets from Secrets Manager
  container_secrets = [
    { name = "QURL_JWT_SECRET", valueFrom = var.jwt_secret_arn },
    { name = "QURL_INTERNAL_SERVICE_TOKEN", valueFrom = var.internal_service_token_arn },
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
    value = local.is_prod ? "enabled" : "disabled"
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

# Policy to read secrets from Secrets Manager
resource "aws_iam_role_policy" "execution_secrets" {
  name = "secrets-access"
  role = aws_iam_role.execution.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat([
      {
        Effect = "Allow"
        Action = ["secretsmanager:GetSecretValue"]
        Resource = [
          var.jwt_secret_arn,
          var.internal_service_token_arn,
        ]
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
          [for arn in var.dynamodb_table_arns : "${arn}/index/*"]
        )
      }
      ],
      # KMS decrypt for DynamoDB (tables are encrypted with KMS)
      var.secrets_kms_key_arn != null ? [{
        Sid      = "KMSDecryptDynamoDB"
        Effect   = "Allow"
        Action   = ["kms:Decrypt"]
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

  # Outbound to ECS tasks
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "All outbound"
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

  # All outbound (DynamoDB, Secrets Manager, etc.)
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

# ==================== ECS Task Definition ====================

resource "aws_ecs_task_definition" "qurl" {
  family                   = local.service_name
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.container_cpu
  memory                   = var.container_memory
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.task.arn

  # Note: Initial deployment uses "latest" tag from SSM parameter default value.
  # CI pipeline updates the SSM parameter and deploys new task definitions independently.
  # Terraform ignores task_definition changes after initial creation (lifecycle.ignore_changes).
  container_definitions = jsonencode([{
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

    healthCheck = {
      command     = ["CMD-SHELL", "curl -f http://localhost:${var.container_port}/health || exit 1"]
      interval    = 30
      timeout     = 5
      retries     = 3
      startPeriod = 60
    }
  }])

  tags = merge(var.tags, {
    Name      = local.service_name
    Component = "qurl-service"
    Cell      = var.cell_id
  })

  # Validate Fargate CPU/memory combinations at plan time
  # See: https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-cpu-memory-error.html
  lifecycle {
    precondition {
      condition = (
        (var.container_cpu == 256 && var.container_memory >= 512 && var.container_memory <= 2048) ||
        (var.container_cpu == 512 && var.container_memory >= 1024 && var.container_memory <= 4096) ||
        (var.container_cpu == 1024 && var.container_memory >= 2048 && var.container_memory <= 8192) ||
        (var.container_cpu == 2048 && var.container_memory >= 4096 && var.container_memory <= 16384) ||
        (var.container_cpu == 4096 && var.container_memory >= 8192 && var.container_memory <= 30720) ||
        (var.container_cpu == 8192 && var.container_memory >= 16384 && var.container_memory <= 61440) ||
        (var.container_cpu == 16384 && var.container_memory >= 32768 && var.container_memory <= 122880)
      )
      error_message = "Invalid Fargate CPU/memory combination. See AWS docs for valid combinations."
    }
  }
}

# ==================== Application Load Balancer ====================

resource "aws_lb" "qurl" {
  name               = replace(local.service_name, "_", "-")
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = var.public_subnet_ids

  # Access logging for production audit compliance (optional)
  dynamic "access_logs" {
    for_each = var.alb_access_logs_bucket != null ? [1] : []
    content {
      bucket  = var.alb_access_logs_bucket
      prefix  = "qurl-api"
      enabled = true
    }
  }

  tags = merge(var.tags, {
    Name      = local.service_name
    Component = "qurl-service"
    Cell      = var.cell_id
  })
}

resource "aws_lb_target_group" "qurl" {
  name        = replace("${var.name_prefix}-${var.cell_id}-qurl", "_", "-")
  port        = var.container_port
  protocol    = "HTTP"
  vpc_id      = var.vpc_id
  target_type = "ip"

  health_check {
    enabled             = true
    healthy_threshold   = 2
    unhealthy_threshold = 3
    timeout             = 5
    interval            = 30
    path                = "/health"
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
resource "aws_lb_listener" "https" {
  count = var.certificate_arn != null ? 1 : 0

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

# HTTP Listener (redirect to HTTPS when cert available, otherwise forward)
# WARNING: When certificate_arn is null, traffic is served over unencrypted HTTP.
# This should only be used during initial setup before certificate provisioning.
# For production, always provide a certificate_arn.
resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.qurl.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = var.certificate_arn != null ? "redirect" : "forward"

    dynamic "redirect" {
      for_each = var.certificate_arn != null ? [1] : []
      content {
        port        = "443"
        protocol    = "HTTPS"
        status_code = "HTTP_301"
      }
    }

    target_group_arn = var.certificate_arn == null ? aws_lb_target_group.qurl.arn : null
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
