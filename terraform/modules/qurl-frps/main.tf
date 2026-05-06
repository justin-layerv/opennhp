# QURL FRP Server Module
#
# Deploys the FRP tunnel server (qurl-frps) as an EC2 Auto Scaling Group.
# The FRP server accepts connections from qurl-frpc clients and proxies
# HTTP traffic to customer backends via vhost-based routing.
#
# Traffic flows:
# - AC Traefik -> frps:7000 (FRP control channel, WebSocket)
# - AC Traefik -> frps:8080 (vhost HTTP, proxied to customer backends)
#
# v1: Single instance by default (min/max/desired all default to 1; the
# values are exposed as module variables but env tfvars do not override
# them yet — see #1499). Acceptable for initial deployment because FRP
# clients reconnect automatically on server restart. The ASG provides
# self-healing (auto-replace on instance failure). Multi-instance with
# sticky sessions / shared registry is a future enhancement tracked in
# #1499.
#
# Cloud Map lifecycle during ASG replacement: with `create_before_destroy`
# and min=max=1, a brief window (up to the 30s DNS TTL) exists where both
# the new and old instances are registered in the frps Cloud Map service
# using MULTIVALUE routing. Traefik will round-robin between them until
# the old instance's systemd shutdown runs `ExecStop=cloudmap-deregister`
# (`BindsTo=qurl-frps.service` guarantees this fires when the ASG
# terminate sends SIGTERM). Reconnecting FRP clients retry on failure
# so the ~30s split-brain is not user-visible. A stricter approach —
# `aws_autoscaling_lifecycle_hook` on `Terminating:Wait` blocking until
# deregister completes — is tracked in #1089 alongside the custom
# health-check work.
#
# At N>1 the same TTL window applies but with N concurrent registrations on
# each side, which compounds the routing problem (in-memory tunnel state on
# only one of the new instances). #1499 covers the registry-coherence work
# that makes the N>1 case correct, not just survivable.

# ==================== Data Sources ====================

data "aws_region" "current" {}
data "aws_caller_identity" "current" {}

# Ubuntu 24.04 LTS (Noble Numbat) - consistent with AC module.
# The public SSM parameters from Canonical carry the `SecureString` attribute
# which the provider exposes as `sensitive`, producing `(sensitive value)` in
# plan output. Use `insecure_value` to surface the AMI ID in plans — AMI IDs
# are public catalog identifiers, not secrets.
data "aws_ssm_parameter" "ubuntu_ami" {
  name = "/aws/service/canonical/ubuntu/server/noble/stable/current/amd64/hvm/ebs-gp3/ami-id"
}

# ==================== Locals ====================

locals {
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.id

  user_data = templatefile("${path.module}/user_data.sh.tpl", {
    region                    = local.region
    account_id                = local.account_id
    environment               = var.environment
    cloudmap_service_id       = aws_service_discovery_service.frps.id
    namespace_name            = var.namespace_name
    log_group_name            = aws_cloudwatch_log_group.frps.name
    frps_bind_port            = var.frps_bind_port
    frps_vhost_http_port      = var.frps_vhost_http_port
    frps_dashboard_port       = var.frps_dashboard_port
    frps_subdomain_host       = var.frps_subdomain_host
    qurl_api_internal_url     = var.qurl_api_internal_url
    qurl_api_token_secret_arn = var.qurl_api_token_secret_arn
    qurl_tunnel_auth_mode     = var.qurl_tunnel_auth_mode
    ssm_image_tag_param       = aws_ssm_parameter.image_tag.name
    # The user_data fallback command and the IAM grant must point at the
    # same bucket. Threading both from root (plugin_bucket_name + _arn)
    # instead of hardcoding the legacy `layerv-nhp-${env}-plugins` name
    # removes drift risk between the `aws s3 cp` call and its IAM grant.
    plugin_bucket_name = var.plugin_bucket_name
  })
}

# ==================== CloudWatch Log Group ====================

resource "aws_cloudwatch_log_group" "frps" {
  name              = "/layerv/nhp/${var.environment}/frps"
  retention_in_days = var.environment == "prod" ? 90 : 30
  kms_key_id        = var.logs_kms_key_arn

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-frps-logs"
    Component = "frps"
  })
}

# ==================== IAM Role ====================

resource "aws_iam_role" "frps" {
  name = "${var.name_prefix}-frps"

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

resource "aws_iam_instance_profile" "frps" {
  name = "${var.name_prefix}-frps"
  role = aws_iam_role.frps.name

  tags = var.tags
}

# SSM managed instance policy (for SSM Session Manager access)
resource "aws_iam_role_policy_attachment" "frps_ssm" {
  role       = aws_iam_role.frps.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role_policy" "frps" {
  name = "frps-permissions"
  role = aws_iam_role.frps.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      # CloudWatch Logs
      {
        Sid    = "CloudWatchLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "${aws_cloudwatch_log_group.frps.arn}:*"
      },
      # CloudWatch Metrics (for CloudWatch Agent)
      {
        Sid    = "CloudWatchMetrics"
        Effect = "Allow"
        Action = [
          "cloudwatch:PutMetricData"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "cloudwatch:namespace" = "LayerV/NHP"
          }
        }
      },
      # SSM Parameters (read FRP config). user_data makes a single
      # `aws ssm get-parameter` call on boot; `GetParameters` (batch) and
      # `GetParametersByPath` (prefix scan) are intentionally omitted —
      # least-privilege, and widening is a one-line change if a future need
      # arises.
      {
        Sid    = "SSMParameterRead"
        Effect = "Allow"
        Action = ["ssm:GetParameter"]
        # ARN pattern stays /<env>/nhp/frps/* to align with the SSM paths in ssm.tf
        # (renaming those would destroy the CI-published image_tag). Tracked by #1668.
        Resource = "arn:aws:ssm:${local.region}:${local.account_id}:parameter/${var.environment}/nhp/frps/*"
      },
      # Cloud Map registration
      {
        Sid    = "CloudMapRegister"
        Effect = "Allow"
        Action = [
          "servicediscovery:RegisterInstance",
          "servicediscovery:DeregisterInstance"
        ]
        Resource = aws_service_discovery_service.frps.arn
      },
      # ECR access (split: GetAuthorizationToken must be * per AWS docs;
      # pull actions scoped to specific repo ARN, consistent with AC module)
      {
        Sid      = "ECRAuth"
        Effect   = "Allow"
        Action   = ["ecr:GetAuthorizationToken"]
        Resource = "*"
      },
      {
        Sid    = "ECRPull"
        Effect = "Allow"
        Action = [
          "ecr:BatchCheckLayerAvailability",
          "ecr:GetDownloadUrlForLayer",
          "ecr:BatchGetImage"
        ]
        Resource = coalesce(var.frps_ecr_repo_arn, "arn:aws:ecr:${local.region}:${local.account_id}:repository/layerv/qurl-reverse-tunnel-server")
      },
    ]
  })
}

# Secrets Manager access for QURL API token (separate policy, conditional).
#
# KMS assumption: this policy grants `secretsmanager:GetSecretValue` only. If
# the target secret is encrypted with a customer-managed KMS key (CMK), the
# fetch will succeed only if the key policy on that CMK grants `kms:Decrypt`
# to this instance role (or to the account principal). Current QURL internal
# service-token secrets are encrypted with the default `aws/secretsmanager`
# AWS-managed key, so the account principal already has decrypt permission
# via IAM — no explicit `kms:Decrypt` grant needed here. If a future move
# encrypts the secret with a CMK, add a conditional `kms:Decrypt` statement
# scoped to that key ARN (or update the key policy) — otherwise `user_data`
# will fail with a 400 AccessDenied at boot that isn't obvious from this
# policy alone.
resource "aws_iam_role_policy" "frps_secrets" {
  count = var.qurl_api_token_secret_arn != "" ? 1 : 0
  name  = "frps-secrets"
  role  = aws_iam_role.frps.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "SecretsManagerRead"
        Effect   = "Allow"
        Action   = ["secretsmanager:GetSecretValue"]
        Resource = var.qurl_api_token_secret_arn
      }
    ]
  })
}

# S3 fallback read access for the binary download path in user_data.
# Conditional on the bucket ARN being threaded from root: an empty value
# means "ECR-only, no fallback" (the `aws s3 cp` branch will still fire
# on ECR failure but will AccessDenied, which matches the script's
# existing FATAL behavior). Scoped to the qurl-frps subtree of the
# plugins bucket — consistent with how `modules/ac/main.tf:715` scopes
# its own script-download grant. Integrity verification (#1258) layers
# on top of this grant in a follow-up PR.
resource "aws_iam_role_policy" "frps_s3_fallback" {
  count = var.plugin_bucket_arn != "" ? 1 : 0
  name  = "frps-s3-fallback"
  role  = aws_iam_role.frps.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "BinaryS3Fallback"
        Effect   = "Allow"
        Action   = ["s3:GetObject"]
        Resource = "${var.plugin_bucket_arn}/binaries/qurl-frps/*"
      }
    ]
  })
}

# ==================== Security Group ====================

resource "aws_security_group" "frps" {
  name_prefix = "${var.name_prefix}-frps-"
  vpc_id      = var.vpc_id
  description = "Security group for FRP server instances"

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-sg-frps"
    Component = "frps"
  })

  lifecycle {
    create_before_destroy = true
  }
}

# FRP control port - ingress from AC security group only
resource "aws_vpc_security_group_ingress_rule" "frps_control" {
  security_group_id            = aws_security_group.frps.id
  description                  = "FRP control channel from AC"
  from_port                    = var.frps_bind_port
  to_port                      = var.frps_bind_port
  ip_protocol                  = "tcp"
  referenced_security_group_id = var.ac_security_group_id

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-frps-control"
  })
}

# FRP vhost HTTP port - ingress from AC security group only
resource "aws_vpc_security_group_ingress_rule" "frps_vhost_http" {
  security_group_id            = aws_security_group.frps.id
  description                  = "FRP vhost HTTP from AC"
  from_port                    = var.frps_vhost_http_port
  to_port                      = var.frps_vhost_http_port
  ip_protocol                  = "tcp"
  referenced_security_group_id = var.ac_security_group_id

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-frps-vhost-http"
  })
}

# Egress — allow all outbound (FRP server needs to reach customer backends).
#
# Intentional wide egress: a tunnel server's whole purpose is to forward
# traffic to arbitrary customer-designated destinations (port 443 for an
# HTTPS backend, an internal IP for a private app, etc.), so we can't
# enumerate them ahead of time. This mirrors the AC module's egress posture,
# which exists for the same reason (customer backends + ACME + ECR + SSM).
# The defense-in-depth here is the *ingress* side: frps only accepts
# connections from the AC security group, and AC only accepts authenticated
# NHP knocks + Traefik traffic, so a compromised frps doesn't become a
# reachable open-internet pivot.
resource "aws_vpc_security_group_egress_rule" "frps_all" {
  security_group_id = aws_security_group.frps.id
  description       = "All outbound traffic"
  ip_protocol       = "-1"
  cidr_ipv4         = "0.0.0.0/0"

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-frps-egress"
  })
}

# ==================== Cloud Map Service Discovery ====================

resource "aws_service_discovery_service" "frps" {
  name        = "frps"
  description = "QURL FRP tunnel server"

  dns_config {
    namespace_id = var.namespace_id

    dns_records {
      ttl  = 30
      type = "A"
    }

    routing_policy = "MULTIVALUE"
  }

  # Custom health check config: registering this block enables Cloud Map to
  # track health state for instances in this service. Without it, Cloud Map
  # has no health-check machinery and keeps stale records indefinitely if an
  # instance OOM-kills frps without a clean systemd shutdown.
  #
  # With this block set, a future UpdateInstanceCustomHealthStatus call
  # (tracked in #1089) can deregister unhealthy instances faster than waiting
  # for the ASG replace cycle. On first boot, user_data verifies FRP is ready
  # before calling cloudmap-register.sh, so only healthy instances ever register.
  #
  # failure_threshold = 2: the AWS provider marks this argument deprecated
  # ("AWS ignores the value and always uses 1") so `terraform validate` emits a
  # deprecation warning. AWS still accepts the field on the wire; keeping it
  # explicit documents intent and matches the reviewer request. Once the
  # provider removes it entirely, simply delete the line.
  health_check_custom_config {
    failure_threshold = 2
  }

  tags = var.tags
}

# ==================== Launch Template ====================

resource "aws_launch_template" "frps" {
  name_prefix   = "${var.name_prefix}-frps-"
  image_id      = data.aws_ssm_parameter.ubuntu_ami.insecure_value
  instance_type = var.instance_type

  iam_instance_profile {
    arn = aws_iam_instance_profile.frps.arn
  }

  network_interfaces {
    associate_public_ip_address = false
    security_groups             = [aws_security_group.frps.id]
  }

  block_device_mappings {
    device_name = "/dev/sda1"
    ebs {
      volume_size           = 30
      volume_type           = "gp3"
      encrypted             = true
      kms_key_id            = var.ebs_kms_key_arn
      delete_on_termination = true
    }
  }

  user_data = base64gzip(local.user_data)

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
      Name      = "${var.name_prefix}-frps"
      Component = "frps"
    })
  }

  lifecycle {
    create_before_destroy = true
  }
}

# ==================== Auto Scaling Group ====================
# Single instance by default — see module header for v1 rationale and
# #1499 for the work required before raising min/max/desired above 1.

resource "aws_autoscaling_group" "frps" {
  name                = "${var.name_prefix}-frps"
  vpc_zone_identifier = var.private_subnet_ids
  min_size            = var.min_size
  max_size            = var.max_size
  desired_capacity    = var.desired_capacity

  launch_template {
    id      = aws_launch_template.frps.id
    version = aws_launch_template.frps.latest_version
  }

  health_check_type         = "EC2"
  health_check_grace_period = 180

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
    value               = "${var.name_prefix}-frps"
    propagate_at_launch = true
  }

  tag {
    key                 = "Component"
    value               = "frps"
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

    precondition {
      # If a QURL API token is configured, the API URL must also be set.
      # Otherwise the instance boots with a valid token but an empty
      # QURL_API_URL, which silently misconfigures the FRP auth plugin.
      condition     = var.qurl_api_token_secret_arn == "" || var.qurl_api_internal_url != ""
      error_message = "qurl_api_internal_url must be set when qurl_api_token_secret_arn is configured — otherwise the FRP auth plugin has a token but no URL to validate against."
    }

    precondition {
      # tunnel-auth mode requires the internal-service shared secret. The
      # user_data token-fetch + JSON/whitespace/empty-string validation
      # block is gated on qurl_api_token_secret_arn != "", so a caller that
      # opts into tunnel-auth without a token ARN would skip every check
      # and write QURL_INTERNAL_SERVICE_TOKEN= (empty) to the env. The
      # qurl-frps resolver then can't authenticate /internal/v1/tunnel/auth
      # calls, surfacing as opaque 401s at runtime — fail at plan time
      # instead, mirroring the qurl_api_internal_url precondition above.
      #
      # Transitively requires qurl_api_internal_url too: forcing the token
      # ARN non-empty here triggers the precondition above, which in turn
      # demands the URL. So tunnel-auth mode is fenced against both an
      # empty token AND an empty URL without an explicit third check here.
      condition     = var.qurl_tunnel_auth_mode != "tunnel-auth" || var.qurl_api_token_secret_arn != ""
      error_message = "qurl_tunnel_auth_mode = \"tunnel-auth\" requires qurl_api_token_secret_arn — the per-user-key resolver still needs the internal-service shared secret to call qurl-service /internal/v1/tunnel/auth."
    }

    precondition {
      # All three ports must be distinct: bind (control), vhost HTTP, and the
      # localhost dashboard. Overlapping would cause frps to fail to start
      # with a confusing bind-address-in-use error instead of a plan-time
      # rejection.
      condition     = length(toset([var.frps_bind_port, var.frps_vhost_http_port, var.frps_dashboard_port])) == 3
      error_message = "frps_bind_port, frps_vhost_http_port, and frps_dashboard_port must all be distinct — frps binds each independently."
    }

    precondition {
      # min <= desired <= max. Catch tfvars typos at plan time rather than
      # letting the ASG API reject them in the middle of an apply.
      condition     = var.min_size <= var.desired_capacity && var.desired_capacity <= var.max_size
      error_message = "qurl-frps ASG sizing must satisfy min_size <= desired_capacity <= max_size."
    }
  }
}
