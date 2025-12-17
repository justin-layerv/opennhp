# Data Module
# etcd cluster, EFS, Secrets, Service Discovery

data "aws_region" "current" {}

locals {
  is_prod = var.environment == "prod"
}

# Private DNS Namespace for Service Discovery
resource "aws_service_discovery_private_dns_namespace" "main" {
  name        = "nhp.${var.environment}.internal"
  vpc         = var.vpc_id
  description = "LayerV NHP internal service discovery"

  tags = var.tags
}

# etcd credentials
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

  tags = var.tags
}

resource "aws_secretsmanager_secret_version" "etcd" {
  count     = var.multi_tenant ? 1 : 0
  secret_id = aws_secretsmanager_secret.etcd[0].id
  secret_string = jsonencode({
    username = "root"
    password = random_password.etcd[0].result
  })
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

  performance_mode = "generalPurpose"
  throughput_mode  = "bursting"

  lifecycle_policy {
    transition_to_ia = "AFTER_14_DAYS"
  }

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-etcd"
  })
}

# EFS mount targets - use EFS security group, not etcd SG
resource "aws_efs_mount_target" "etcd" {
  count           = var.multi_tenant ? length(var.private_subnet_ids) : 0
  file_system_id  = aws_efs_file_system.etcd[0].id
  subnet_id       = var.private_subnet_ids[count.index]
  security_groups = [aws_security_group.efs[0].id]
}

resource "aws_efs_access_point" "etcd" {
  count          = var.multi_tenant ? 1 : 0
  file_system_id = aws_efs_file_system.etcd[0].id

  root_directory {
    path = "/etcd-data"
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
    Name = "${var.name_prefix}-etcd"
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
        Resource = aws_secretsmanager_secret.etcd[0].arn
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
            "elasticfilesystem:AccessPointArn" = aws_efs_access_point.etcd[0].arn
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

# ECS Task Definition
resource "aws_ecs_task_definition" "etcd" {
  count                    = var.multi_tenant ? 1 : 0
  family                   = "${var.name_prefix}-etcd"
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
      { name = "ETCD_NAME", value = "etcd-0" },
      { name = "ETCD_DATA_DIR", value = "/etcd-data" },
      { name = "ETCD_LISTEN_CLIENT_URLS", value = "http://0.0.0.0:2379" },
      { name = "ETCD_LISTEN_PEER_URLS", value = "http://0.0.0.0:2380" },
      { name = "ETCD_ADVERTISE_CLIENT_URLS", value = "http://etcd.nhp.${var.environment}.internal:2379" },
      { name = "ETCD_INITIAL_ADVERTISE_PEER_URLS", value = "http://etcd.nhp.${var.environment}.internal:2380" },
      { name = "ETCD_INITIAL_CLUSTER", value = "etcd-0=http://etcd.nhp.${var.environment}.internal:2380" },
      { name = "ETCD_INITIAL_CLUSTER_STATE", value = "new" },
      { name = "ETCD_INITIAL_CLUSTER_TOKEN", value = var.name_prefix },
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
        "awslogs-stream-prefix" = "etcd"
      }
    }
  }])

  volume {
    name = "etcd-data"

    efs_volume_configuration {
      file_system_id     = aws_efs_file_system.etcd[0].id
      transit_encryption = "ENABLED"
      authorization_config {
        access_point_id = aws_efs_access_point.etcd[0].id
        iam             = "ENABLED"
      }
    }
  }

  tags = var.tags
}

# Cloud Map Service for etcd
resource "aws_service_discovery_service" "etcd" {
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

# ECS Service for etcd
resource "aws_ecs_service" "etcd" {
  count           = var.multi_tenant ? 1 : 0
  name            = "${var.name_prefix}-etcd"
  cluster         = aws_ecs_cluster.etcd[0].id
  task_definition = aws_ecs_task_definition.etcd[0].arn
  desired_count   = 1
  launch_type     = "FARGATE"

  enable_execute_command = true

  network_configuration {
    subnets          = var.private_subnet_ids
    security_groups  = [aws_security_group.etcd[0].id]
    assign_public_ip = false
  }

  service_registries {
    registry_arn = aws_service_discovery_service.etcd[0].arn
  }

  deployment_minimum_healthy_percent = 0
  deployment_maximum_percent         = 100

  tags = var.tags

  # Explicit dependency: wait for all mount targets to be available
  depends_on = [aws_efs_mount_target.etcd]
}
