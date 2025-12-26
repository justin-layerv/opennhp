# Console Application Module
# Deploys the LayerV Console as an ECS Fargate service

data "aws_region" "current" {}
data "aws_caller_identity" "current" {}

locals {
  console_name = "${var.name_prefix}-console"

  # Build AC config JSON for container environment
  ac_config_json = jsonencode({
    enabled = length(var.ac_configs) > 0
    acs     = var.ac_configs
  })
}

# ==================== ECS Cluster ====================

resource "aws_ecs_cluster" "console" {
  name = local.console_name

  setting {
    name  = "containerInsights"
    value = "enabled"
  }

  tags = merge(var.tags, {
    Name = local.console_name
  })
}

# ==================== CloudWatch Log Group ====================

resource "aws_cloudwatch_log_group" "console" {
  name              = "/ecs/${local.console_name}"
  retention_in_days = var.environment == "prod" ? 365 : 30
  kms_key_id        = var.logs_kms_key_arn

  tags = merge(var.tags, {
    Name = local.console_name
  })
}

# ==================== Security Groups ====================

resource "aws_security_group" "console" {
  name        = "${local.console_name}-ecs"
  description = "Security group for Console ECS tasks"
  vpc_id      = var.vpc_id

  tags = merge(var.tags, {
    Name = "${local.console_name}-ecs"
  })
}

resource "aws_vpc_security_group_ingress_rule" "console_from_alb" {
  security_group_id            = aws_security_group.console.id
  description                  = "Allow traffic from ALB"
  from_port                    = var.console_port
  to_port                      = var.console_port
  ip_protocol                  = "tcp"
  referenced_security_group_id = aws_security_group.alb.id

  tags = {
    Name = "${local.console_name}-from-alb"
  }
}

resource "aws_vpc_security_group_egress_rule" "console_all" {
  security_group_id = aws_security_group.console.id
  description       = "Allow all outbound"
  ip_protocol       = "-1"
  cidr_ipv4         = "0.0.0.0/0"

  tags = {
    Name = "${local.console_name}-egress"
  }
}

resource "aws_security_group" "alb" {
  name        = "${local.console_name}-alb"
  description = "Security group for Console ALB"
  vpc_id      = var.vpc_id

  tags = merge(var.tags, {
    Name = "${local.console_name}-alb"
  })
}

resource "aws_vpc_security_group_ingress_rule" "alb_https" {
  count = var.acm_certificate_arn != null ? 1 : 0

  security_group_id = aws_security_group.alb.id
  description       = "HTTPS from anywhere"
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
  cidr_ipv4         = "0.0.0.0/0"

  tags = {
    Name = "${local.console_name}-alb-https"
  }
}

resource "aws_vpc_security_group_ingress_rule" "alb_http" {
  security_group_id = aws_security_group.alb.id
  description       = "HTTP from anywhere"
  from_port         = 80
  to_port           = 80
  ip_protocol       = "tcp"
  cidr_ipv4         = "0.0.0.0/0"

  tags = {
    Name = "${local.console_name}-alb-http"
  }
}

resource "aws_vpc_security_group_egress_rule" "alb_all" {
  security_group_id = aws_security_group.alb.id
  description       = "Allow all outbound"
  ip_protocol       = "-1"
  cidr_ipv4         = "0.0.0.0/0"

  tags = {
    Name = "${local.console_name}-alb-egress"
  }
}

# Allow console to access RDS
resource "aws_vpc_security_group_ingress_rule" "rds_from_console" {
  security_group_id            = var.rds_security_group_id
  description                  = "PostgreSQL from Console ECS"
  from_port                    = var.rds_port
  to_port                      = var.rds_port
  ip_protocol                  = "tcp"
  referenced_security_group_id = aws_security_group.console.id

  tags = {
    Name = "${local.console_name}-to-rds"
  }
}

# ==================== ALB ====================

resource "aws_lb" "console" {
  name               = local.console_name
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = var.public_subnet_ids

  enable_deletion_protection = var.environment == "prod"

  tags = merge(var.tags, {
    Name = local.console_name
  })
}

resource "aws_lb_target_group" "console" {
  name        = local.console_name
  port        = var.console_port
  protocol    = "HTTP"
  vpc_id      = var.vpc_id
  target_type = "ip"

  health_check {
    enabled             = true
    healthy_threshold   = 2
    interval            = 30
    matcher             = "200"
    path                = "/api/health"
    port                = "traffic-port"
    protocol            = "HTTP"
    timeout             = 5
    unhealthy_threshold = 3
  }

  tags = merge(var.tags, {
    Name = local.console_name
  })
}

resource "aws_lb_listener" "console_http" {
  load_balancer_arn = aws_lb.console.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = var.acm_certificate_arn != null ? "redirect" : "forward"

    dynamic "redirect" {
      for_each = var.acm_certificate_arn != null ? [1] : []
      content {
        port        = "443"
        protocol    = "HTTPS"
        status_code = "HTTP_301"
      }
    }

    dynamic "forward" {
      for_each = var.acm_certificate_arn == null ? [1] : []
      content {
        target_group {
          arn = aws_lb_target_group.console.arn
        }
      }
    }
  }

  tags = merge(var.tags, {
    Name = "${local.console_name}-http"
  })
}

resource "aws_lb_listener" "console_https" {
  count = var.acm_certificate_arn != null ? 1 : 0

  load_balancer_arn = aws_lb.console.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.acm_certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.console.arn
  }

  tags = merge(var.tags, {
    Name = "${local.console_name}-https"
  })
}

# ==================== IAM Role ====================

resource "aws_iam_role" "console_task" {
  name = "${local.console_name}-task"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
      }
    ]
  })

  tags = merge(var.tags, {
    Name = "${local.console_name}-task"
  })
}

resource "aws_iam_role" "console_execution" {
  name = "${local.console_name}-execution"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
      }
    ]
  })

  tags = merge(var.tags, {
    Name = "${local.console_name}-execution"
  })
}

resource "aws_iam_role_policy_attachment" "console_execution" {
  role       = aws_iam_role.console_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role_policy" "console_secrets" {
  name = "${local.console_name}-secrets"
  role = aws_iam_role.console_execution.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "GetSecrets"
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue"
        ]
        Resource = [
          var.rds_secret_arn
        ]
      }
    ]
  })
}

# ==================== ECS Task Definition ====================

resource "aws_ecs_task_definition" "console" {
  family                   = local.console_name
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.cpu
  memory                   = var.memory
  execution_role_arn       = aws_iam_role.console_execution.arn
  task_role_arn            = aws_iam_role.console_task.arn

  container_definitions = jsonencode([
    {
      name      = "console"
      image     = var.console_image
      essential = true

      portMappings = [
        {
          containerPort = var.console_port
          hostPort      = var.console_port
          protocol      = "tcp"
        }
      ]

      environment = [
        {
          name  = "GVA_CONFIG_SYSTEM_ADDR"
          value = tostring(var.console_port)
        },
        {
          name  = "GVA_CONFIG_SYSTEM_DBTYPE"
          value = "pgsql"
        },
        {
          name  = "GVA_CONFIG_SYSTEM_COOKIEDOMAIN"
          value = var.cookie_domain
        },
        {
          name  = "GVA_CONFIG_PGSQL_PATH"
          value = var.rds_endpoint
        },
        {
          name  = "GVA_CONFIG_PGSQL_PORT"
          value = tostring(var.rds_port)
        },
        {
          name  = "GVA_CONFIG_PGSQL_DBNAME"
          value = var.rds_database_name
        },
        {
          name  = "GVA_CONFIG_PGSQL_CONFIG"
          value = "sslmode=require TimeZone=UTC"
        },
        {
          name  = "GVA_CONFIG_ACCESSCONTROLLERS"
          value = local.ac_config_json
        }
      ]

      secrets = [
        {
          name      = "GVA_CONFIG_PGSQL_USERNAME"
          valueFrom = "${var.rds_secret_arn}:username::"
        },
        {
          name      = "GVA_CONFIG_PGSQL_PASSWORD"
          valueFrom = "${var.rds_secret_arn}:password::"
        }
      ]

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.console.name
          "awslogs-region"        = data.aws_region.current.name
          "awslogs-stream-prefix" = "console"
        }
      }

      healthCheck = {
        command     = ["CMD-SHELL", "wget -q --spider http://localhost:${var.console_port}/api/health || exit 1"]
        interval    = 30
        timeout     = 5
        retries     = 3
        startPeriod = 60
      }
    }
  ])

  tags = merge(var.tags, {
    Name = local.console_name
  })
}

# ==================== ECS Service ====================

resource "aws_ecs_service" "console" {
  name            = local.console_name
  cluster         = aws_ecs_cluster.console.id
  task_definition = aws_ecs_task_definition.console.arn
  desired_count   = var.desired_count
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = var.private_subnet_ids
    security_groups  = [aws_security_group.console.id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.console.arn
    container_name   = "console"
    container_port   = var.console_port
  }

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  tags = merge(var.tags, {
    Name = local.console_name
  })

  depends_on = [aws_lb_listener.console_http]
}

# ==================== Route 53 ====================

data "aws_route53_zone" "main" {
  count = var.hosted_zone != null ? 1 : 0
  name  = var.hosted_zone
}

resource "aws_route53_record" "console" {
  count = var.domain_name != null && var.hosted_zone != null ? 1 : 0

  zone_id = data.aws_route53_zone.main[0].zone_id
  name    = var.domain_name
  type    = "A"

  alias {
    name                   = aws_lb.console.dns_name
    zone_id                = aws_lb.console.zone_id
    evaluate_target_health = true
  }
}
