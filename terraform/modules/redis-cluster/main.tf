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

  # This resource deliberately declares NO inline ingress/egress blocks.
  # `security_group_id` is exported (outputs.tf) and qurl-service attaches
  # its own standalone rule to this SG cross-module, so the rule set has
  # more than one writer. `ingress`/`egress` on aws_security_group are
  # Optional+Computed: a single inline block makes this resource
  # authoritative for the WHOLE attribute and it then revokes every rule it
  # does not itself declare. That is what #3281 found in prod — the inline
  # VPC-CIDR block below was silently planning to revoke qurl-service's
  # ecs_to_redis rule on the next apply. Rules now live in standalone
  # resources only (this file, plus qurl-service's ecs_to_redis).
  #
  # No egress rules — Redis (ElastiCache Serverless) does not initiate
  # outbound connections. It only responds to inbound client requests.

  tags = merge(var.tags, {
    Name      = "${local.cluster_name}-sg"
    Component = "redis"
    Cell      = var.cell_id
  })

  lifecycle {
    create_before_destroy = true

    # Freeze both rule attributes so a future inline block cannot quietly
    # re-arm the revocation race against the standalone owners. Mirrors the
    # same guard on bootstrap-alb, relay, and relay-network's SGs.
    # `.github/scripts/check-terraform-sg-rule-ownership.py` fences the
    # source-level invariant; this is the runtime backstop.
    ignore_changes = [ingress, egress]
  }
}

# Sole owner of the VPC-CIDR ingress rule. Port/protocol/CIDR and the
# description are byte-identical to the inline block this replaces, so the
# environment-level import blocks adopt the existing rule in place rather
# than revoking and recreating it — there is no traffic gap during the
# ownership transition.
resource "aws_vpc_security_group_ingress_rule" "redis_from_vpc" {
  security_group_id = aws_security_group.redis.id

  # ElastiCache Serverless uses port 6379 with mandatory TLS.
  # (Legacy non-serverless ElastiCache used 6380 for TLS, but Serverless
  # standardized on 6379 for all connections.)
  from_port   = 6379
  to_port     = 6379
  ip_protocol = "tcp"
  cidr_ipv4   = var.vpc_cidr
  description = "Redis from VPC (ElastiCache Serverless, TLS enforced)"

  tags = merge(var.tags, {
    Name      = "${local.cluster_name}-from-vpc"
    Component = "redis"
    Cell      = var.cell_id
  })
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
