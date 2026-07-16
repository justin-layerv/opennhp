resource "aws_security_group" "otp_redis" {
  name_prefix = "${local.name_prefix}-otp-redis-"
  description = "Dark Connector OTP challenge Redis; runtime adds exact function ingress"
  vpc_id      = aws_vpc.control.id

  # No traffic until the cell-scoped OTP functions exist. The authority-runtime
  # slice adds only SG-to-SG TLS/6379 ingress.
  ingress = []
  egress  = []

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-otp-redis"
  })

  lifecycle {
    create_before_destroy = true
  }
}

locals {
  # ElastiCache IAM authentication requires user_name == user_id and limits
  # each to 40 characters. Keep the suffix short enough to leave prefix
  # headroom, then fence that provider limit in the module contract test.
  otp_redis_authority_user_id = "${local.name_prefix}-otp-auth"
}

# Redis OSS user groups must contain a user named "default". Replace the
# service-created permissive default with a disabled user so the cache never
# has an unauthenticated compatibility path. This user intentionally uses
# no-password authentication: its ACL is off and denies every command/key.
resource "aws_elasticache_user" "otp_disabled_default" {
  user_id       = "${local.name_prefix}-otp-default"
  user_name     = "default"
  access_string = "off ~* -@all"
  engine        = "redis"

  authentication_mode {
    type = "no-password-required"
  }

  tags = merge(local.common_tags, {
    Name    = "${local.name_prefix}-otp-default"
    Purpose = "Disabled Redis OSS default user"
  })
}

# Runtime functions authenticate with their execution role and a short-lived
# SigV4 token. No long-lived Redis password is generated or stored in Terraform
# state. The access string limits the authority to its own key namespace and
# the read/write/scripting operations needed for atomic OTP/rate-limit state.
resource "aws_elasticache_user" "otp_authority" {
  user_id       = local.otp_redis_authority_user_id
  user_name     = local.otp_redis_authority_user_id
  access_string = "on ~connector:* +@connection +@read +@write +@scripting"
  engine        = "redis"

  authentication_mode {
    type = "iam"
  }

  tags = merge(local.common_tags, {
    Name    = local.otp_redis_authority_user_id
    Purpose = "IAM-authenticated Connector OTP authority"
  })
}

resource "aws_elasticache_user_group" "otp" {
  engine        = "redis"
  user_group_id = "${local.name_prefix}-otp-users"
  user_ids = [
    aws_elasticache_user.otp_disabled_default.user_id,
    aws_elasticache_user.otp_authority.user_id,
  ]

  tags = merge(local.common_tags, {
    Name    = "${local.name_prefix}-otp-users"
    Purpose = "Fail-closed Connector OTP Redis RBAC"
  })
}

resource "aws_elasticache_serverless_cache" "otp" {
  engine = "redis"
  name   = "${local.name_prefix}-otp"

  cache_usage_limits {
    data_storage {
      maximum = local.is_prod ? 5 : 1
      unit    = "GB"
    }
    ecpu_per_second {
      maximum = local.is_prod ? 5000 : 1000
    }
  }

  # OTP challenges and rate-limit counters are short-lived and re-derivable.
  # Do not extend their at-rest lifetime or restore stale challenges.
  snapshot_retention_limit = 0
  kms_key_id               = aws_kms_key.authority_data.arn
  major_engine_version     = "7"
  security_group_ids       = [aws_security_group.otp_redis.id]
  subnet_ids               = aws_subnet.isolated[*].id
  user_group_id            = aws_elasticache_user_group.otp.user_group_id

  tags = merge(local.common_tags, {
    Name    = "${local.name_prefix}-otp"
    Purpose = "Bounded Connector OTP challenges and rate limits"
  })
}
