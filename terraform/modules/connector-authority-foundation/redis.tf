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

  lifecycle {
    # The provider accepts only no-password-required for configuration while
    # ElastiCache reads the same secure mode back as no-password. Suppress only
    # that provider/API spelling loop, then fail closed if the refreshed user
    # is ever password-backed or carries a password.
    ignore_changes = [authentication_mode[0].type]
    postcondition {
      condition = (
        length(self.authentication_mode) == 1 &&
        contains(
          ["no-password-required", "no-password"],
          self.authentication_mode[0].type,
        ) &&
        self.authentication_mode[0].password_count == 0
      )
      error_message = "The disabled Redis default user must remain passwordless."
    }
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
  user_id   = local.otp_redis_authority_user_id
  user_name = local.otp_redis_authority_user_id
  # ElastiCache canonicalizes an allow-list ACL by inserting an explicit
  # category reset. Keep that canonical form in configuration so a live
  # refresh does not propose a perpetual normalization update.
  access_string = "on ~connector:* -@all +@connection +@read +@write +@scripting"
  engine        = "redis"

  authentication_mode {
    type = "iam"
  }

  lifecycle {
    # Keep the live identity mode fail closed as well as the configured mode.
    # A password-backed authority would put a long-lived Redis credential back
    # into the design even if Terraform configuration still said IAM.
    postcondition {
      condition = (
        length(self.authentication_mode) == 1 &&
        self.authentication_mode[0].type == "iam" &&
        self.authentication_mode[0].password_count == 0
      )
      error_message = "The Connector OTP authority must remain IAM-only and passwordless."
    }
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
