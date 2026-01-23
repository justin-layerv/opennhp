# Redis Cluster Module
# ElastiCache Redis for distributed rate limiting and caching
#
# Architecture:
# - Serverless Redis (ElastiCache Serverless) for automatic scaling
# - Multi-AZ for high availability
# - Encryption at rest and in transit
# - VPC-only access (no public endpoint)

# ==================== Data Sources ====================

data "aws_region" "current" {}

# ==================== Locals ====================

locals {
  cluster_name = "${var.name_prefix}-${var.cell_id}-redis"
}

# ==================== Security Group ====================

resource "aws_security_group" "redis" {
  name_prefix = "${local.cluster_name}-"
  vpc_id      = var.vpc_id
  description = "Security group for Redis ElastiCache"

  # ElastiCache Serverless enforces TLS - only allow encrypted connections
  # Port 6379 (non-TLS) is intentionally not exposed for security
  ingress {
    from_port   = 6380
    to_port     = 6380
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
    description = "Redis TLS from VPC"
  }

  # No egress rules - Redis (ElastiCache Serverless) does not initiate
  # outbound connections. It only responds to inbound client requests.

  tags = merge(var.tags, {
    Name      = "${local.cluster_name}-sg"
    Component = "redis"
    Cell      = var.cell_id
  })

  lifecycle {
    create_before_destroy = true
  }
}

# ==================== Subnet Group ====================

resource "aws_elasticache_subnet_group" "redis" {
  name        = local.cluster_name
  description = "Subnet group for ${local.cluster_name}"
  subnet_ids  = var.private_subnet_ids

  tags = merge(var.tags, {
    Name      = local.cluster_name
    Component = "redis"
    Cell      = var.cell_id
  })
}

# ==================== ElastiCache Serverless ====================

resource "aws_elasticache_serverless_cache" "redis" {
  engine = "redis"
  name   = local.cluster_name

  cache_usage_limits {
    data_storage {
      maximum = var.max_data_storage_gb
      unit    = "GB"
    }
    ecpu_per_second {
      maximum = var.max_ecpu_per_second
    }
  }

  # Automatic daily snapshots with 1-day retention
  daily_snapshot_time      = "05:00"
  snapshot_retention_limit = var.snapshot_retention_days

  # KMS encryption
  kms_key_id = var.kms_key_arn

  # Use major version only for engine version
  major_engine_version = "7"

  # Security
  security_group_ids = [aws_security_group.redis.id]
  subnet_ids         = var.private_subnet_ids

  # User group for access control (optional)
  # user_group_id = aws_elasticache_user_group.redis.id

  tags = merge(var.tags, {
    Name      = local.cluster_name
    Component = "redis"
    Cell      = var.cell_id
  })
}

# ==================== Outputs ====================
# Outputs are defined in outputs.tf
