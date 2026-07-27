resource "aws_security_group" "otp_redis" {
  name_prefix = "${local.name_prefix}-otp-redis-"
  description = "Dark Connector OTP challenge Redis; runtime adds exact function ingress"
  vpc_id      = aws_vpc.control.id

  # No traffic until the cell-scoped OTP functions exist. The authority-runtime
  # slice adds only a standalone SG-to-SG TLS/6379 ingress rule. Keep all rules
  # standalone; mixing inline and standalone security-group rules can overwrite
  # rules or cause perpetual Terraform drift.

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-otp-redis"
  })

  lifecycle {
    create_before_destroy = true
  }
}

locals {
  # ElastiCache IAM authentication requires user_name == user_id and limits
  # each to 40 characters. The AWS provider does not reject an overlong ID at
  # plan time, so foundation_contract fences every derived ID below.
  otp_redis_disabled_default_user_id = "${local.name_prefix}-otp-default"
  otp_redis_issuer_user_id           = "${local.name_prefix}-otp-issuer"
  otp_redis_activator_user_id        = "${local.name_prefix}-otp-activator"
  otp_redis_user_ids = [
    local.otp_redis_disabled_default_user_id,
    local.otp_redis_issuer_user_id,
    local.otp_redis_activator_user_id,
  ]
}

# Redis OSS user groups must contain a user named "default". Replace the
# service-created permissive default with a disabled user so the cache never
# has an unauthenticated compatibility path. This user intentionally uses
# no-password authentication: its ACL is off and denies every command/key.
resource "aws_elasticache_user" "otp_disabled_default" {
  user_id       = local.otp_redis_disabled_default_user_id
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
    Name    = local.otp_redis_disabled_default_user_id
    Purpose = "Disabled Redis OSS default user"
  })
}

# The broad `~connector:*` legacy authority user that predated this split is
# gone (NHP #3362). It was detached from the user group by the split rollout,
# never granted elasticache:Connect by any runtime role, and structurally
# unusable by the runtime, which derives its user id as this cache prefix plus
# an exact `-issuer`/`-activator` suffix and fails closed on anything else. Do
# not reintroduce it, including as a rollback path; leave the cache dark until
# the reviewed split configuration is restored instead.

# OTP issuance owns immutable challenge creation, reissue state reset, and the
# four admission-rate namespaces. Redis OSS 7 is required below because the
# directional %R/%W key permissions were added in that engine generation.
# Redis canonicalizes read/write `%RW~pattern` entries to `~pattern`, so the
# bidirectional namespaces use that canonical form to prevent perpetual drift.
# Commands are an exact allow list derived from the issuer's transaction and
# rate-limit script; no broad read, write, or scripting category is granted.
# The literal `{*}` glob requires the runtime's hash-tagged key shape; the
# source separately rejects JTI values containing delimiters or braces.
# ElastiCache Serverless is cluster-mode enabled, so go-redis receives only its
# exact bootstrap/routing commands and the CLUSTER SLOTS subcommand, not broad
# connection, CLIENT, or CLUSTER permissions. The runtime disables redirect
# replay, so ASKING is intentionally absent and an ASK response fails the
# current operation closed. ElastiCache reads these directional Redis OSS 7
# users back with an explicit `resetchannels`; configure that fail-closed reset
# so refresh does not propose removing it forever. The exact live no-op plan
# separately proves the legacy category-based and disabled users already match
# without this token; do not generalize it absent new live drift evidence.
resource "aws_elasticache_user" "otp_issuer" {
  user_id   = local.otp_redis_issuer_user_id
  user_name = local.otp_redis_issuer_user_id
  access_string = join(" ", [
    "on",
    "%W~connector:registration-otp:v2:{*}:challenge",
    "%W~connector:registration-otp:v2:{*}:state",
    "~connector:ratelimit:registration-otp:credential:*",
    "~connector:ratelimit:registration-otp:owner:*",
    "~connector:ratelimit:registration-otp:peer:*",
    "~connector:ratelimit:registration-otp:source:*",
    "resetchannels",
    "-@all",
    "+hello",
    "+auth",
    "+ping",
    "+command",
    "+cluster|slots",
    "+multi",
    "+exec",
    "+discard",
    "+del",
    "+hset",
    "+expire",
    "+eval",
    "+evalsha",
    "+zremrangebyscore",
    "+zcard",
    "+zrange",
    "+zadd",
  ])
  engine = "redis"

  authentication_mode {
    type = "iam"
  }

  lifecycle {
    postcondition {
      condition = (
        length(self.authentication_mode) == 1 &&
        self.authentication_mode[0].type == "iam" &&
        self.authentication_mode[0].password_count == 0
      )
      error_message = "The Connector OTP issuer must remain IAM-only and passwordless."
    }
  }

  tags = merge(local.common_tags, {
    Name    = local.otp_redis_issuer_user_id
    Purpose = "IAM-authenticated Connector OTP issuer"
  })
}

# Activation may read an issued challenge but may mutate only the separate
# attempt/consumption state key. The source uses WATCH/MULTI/EXEC rather than
# Lua so Redis never needs write permission on the immutable challenge key.
# Its cluster client needs the same exact bootstrap/routing permissions.
# Keep the same explicit fail-closed channel reset as the issuer.
resource "aws_elasticache_user" "otp_activator" {
  user_id   = local.otp_redis_activator_user_id
  user_name = local.otp_redis_activator_user_id
  access_string = join(" ", [
    "on",
    "%R~connector:registration-otp:v2:{*}:challenge",
    "~connector:registration-otp:v2:{*}:state",
    "resetchannels",
    "-@all",
    "+hello",
    "+auth",
    "+ping",
    "+command",
    "+cluster|slots",
    "+watch",
    "+unwatch",
    "+multi",
    "+exec",
    "+discard",
    "+hmget",
    "+hlen",
    "+pttl",
    "+hset",
    "+pexpire",
  ])
  engine = "redis"

  authentication_mode {
    type = "iam"
  }

  lifecycle {
    postcondition {
      condition = (
        length(self.authentication_mode) == 1 &&
        self.authentication_mode[0].type == "iam" &&
        self.authentication_mode[0].password_count == 0
      )
      error_message = "The Connector OTP activator must remain IAM-only and passwordless."
    }
  }

  tags = merge(local.common_tags, {
    Name    = local.otp_redis_activator_user_id
    Purpose = "IAM-authenticated Connector OTP activator"
  })
}

resource "aws_elasticache_user_group" "otp" {
  engine        = "redis"
  user_group_id = "${local.name_prefix}-otp-users"
  user_ids = [
    aws_elasticache_user.otp_disabled_default.user_id,
    aws_elasticache_user.otp_issuer.user_id,
    aws_elasticache_user.otp_activator.user_id,
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
