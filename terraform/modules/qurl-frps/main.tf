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
# Multi-AZ tunnel routing (#1499): nhp-frps holds tunnel registrations in
# memory per process, so we can't put N instances behind one Cloud Map
# service and expect tunnel routing to work — DNS would return IPs in
# random order and ~(N-1)/N of requests would hit instances without the
# registration. Instead, we publish ONE Cloud Map service per AZ
# (`frps-a.${namespace}`, `frps-b.${namespace}`, ...) and qurl-service
# hashes `OwnerID` to a fixed AZ when emitting `frps_addr` in
# CreateResource / GetResourceTarget responses. Both `frpc` (registering
# tunnels) and the AC's qurl-router (forwarding vhost traffic) read the
# same `frps_addr` and converge on the same instance.
#
# Cross-repo contract enforced by:
# - frps_az_suffixes default `["a", "b", "c"]` (this module)
# - QURL_FRPS_AZ_SUFFIXES on qurl-service (must agree)
# - QURL_FRPS_DOMAIN     = "${namespace_name}"
# - QURL_FRPS_PORT       = ${frps_vhost_http_port}  (default 8080)
# Backend URL pattern: http://frps-${az_suffix}.${namespace_name}:${port}
#
# Cloud Map lifecycle during instance replacement (two distinct mechanisms):
#
# - The launch template's `lifecycle { create_before_destroy = true }`
#   (below) covers LT-version churn: a Terraform-driven LT change
#   provisions the new LT version before destroying the old one, so the
#   ASG never references a deleted version mid-apply.
# - The ASG's instance-refresh policy covers per-instance replacement
#   on a running fleet: each instance is launched, drained, and
#   terminated in series.
#
# Both paths produce a brief window (up to the 30s DNS TTL) where the
# new and old instances are registered against the same per-AZ Cloud
# Map service. Each per-AZ service has only ONE registration at steady
# state, so a replacement creates a transient pair. With WEIGHTED
# routing on a DNS-namespace service, the Route 53 resolver returns
# ONE A record per query (weight-biased; `1` default weight ⇒ uniform
# random) — `frpc` and `qurl-router` both consume `frps_addr` via DNS
# rather than the `DiscoverInstances` API, so each reconnect lands on
# one or the other instance until the old instance's systemd shutdown
# runs `ExecStop=cloudmap-deregister` (`BindsTo=qurl-frps.service`
# guarantees this fires when the ASG terminate sends SIGTERM). FRP
# clients reconnect on failure, so the ~30s split-brain isn't user-
# visible. A stricter approach — `aws_autoscaling_lifecycle_hook` on
# `Terminating:Wait` blocking until deregister completes — is tracked
# in #1089 alongside the custom health-check work.

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

# Resolve the AZ of each private subnet so we can fence
# `frps_az_suffixes` against the actual AZ coverage of the VPC. Without
# this fence, an environment with subnets in only `[a, b]` paired with
# `frps_az_suffixes = ["a","b","c"]` would silently apply, create a
# `frps-c` Cloud Map service, and never register a single instance
# against it — every OwnerID hashing to `c` would resolve NXDOMAIN.
data "aws_subnet" "private" {
  for_each = toset(var.private_subnet_ids)
  id       = each.value
}

# Subnet/AZ alignment fence (#1499). Plan-time, so a misconfigured VPC
# fails on PR review rather than at runtime when the empty Cloud Map
# service starts returning NXDOMAIN.
resource "terraform_data" "subnet_az_alignment" {
  lifecycle {
    precondition {
      # Trailing letter of each subnet's AZ name. AWS AZ names are
      # `{region}{letter}`; we extract the same single-letter suffix
      # the user_data extracts at boot from IMDS so the two views
      # agree by construction.
      condition = length(setsubtract(
        toset(var.frps_az_suffixes),
        toset([for s in data.aws_subnet.private : substr(s.availability_zone, length(s.availability_zone) - 1, 1)])
      )) == 0
      error_message = "private_subnet_ids must include at least one subnet in every AZ listed in frps_az_suffixes — otherwise the corresponding Cloud Map service will never get a registration and OwnerIDs hashing to that suffix will resolve NXDOMAIN."
    }
  }
}

# ==================== Locals ====================

locals {
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.id

  user_data = templatefile("${path.module}/user_data.sh.tpl", {
    region      = local.region
    account_id  = local.account_id
    environment = var.environment
    # Per-AZ Cloud Map service IDs, keyed by AZ suffix (`a` → service ID).
    # User_data renders these into a Bash associative array and looks up
    # the right service ID by the instance's IMDS-reported AZ at boot.
    # A bare for-expression (not a sorted list) is fine: templatefile
    # iterates the map deterministically (Terraform sorts string keys),
    # so the rendered Bash array is stable across plans for the same
    # input set. The deterministic-rendering note matters because the
    # whole user_data string flows through `base64gzip` — a non-stable
    # ordering would force the launch template to bump its
    # latest_version every plan.
    cloudmap_service_ids = {
      for s, svc in aws_service_discovery_service.frps_per_az : s => svc.id
    }
    frps_az_suffixes          = var.frps_az_suffixes
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
      # Cloud Map registration. Scoped to ALL per-AZ services rather than
      # just the one matching this instance's AZ — the instance picks its
      # service at boot from IMDS, and we don't know the AZ at IAM-policy
      # time. The set is bounded (one ARN per AZ suffix, default 3) and
      # the only privilege granted is to (de)register the instance's own
      # IP, so the scope here is still strictly tighter than `Resource =
      # "*"`. The `for ... : svc.arn` projection produces a deterministic
      # list (Terraform sorts string keys when iterating a `for_each` map),
      # which IAM then treats as a set — sorting is unnecessary.
      {
        Sid    = "CloudMapRegister"
        Effect = "Allow"
        Action = [
          "servicediscovery:RegisterInstance",
          "servicediscovery:DeregisterInstance"
        ]
        Resource = [for svc in aws_service_discovery_service.frps_per_az : svc.arn]
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

# ==================== Cloud Map Service Discovery (per-AZ) ====================
#
# One Cloud Map service per AZ suffix. qurl-service hashes OwnerID to one of
# these suffixes and emits the matching `frps-${suffix}.${namespace_name}`
# DNS name as `frps_addr` in CreateResource / GetResourceTarget responses,
# so frpc and qurl-router converge on the same instance. See module header
# and #1499 for the full cross-repo contract.
#
# Routing policy: WEIGHTED with 1 instance per service at steady state. The
# old single-service config used MULTIVALUE because the service held N
# instances; with one-per-AZ each service holds 1, and WEIGHTED returns
# that single record without the round-robin bias MULTIVALUE imposes. Both
# work in practice for N=1 but WEIGHTED matches intent.
resource "aws_service_discovery_service" "frps_per_az" {
  for_each = toset(var.frps_az_suffixes)

  name        = "frps-${each.key}"
  description = "qurl-reverse-tunnel-server — AZ suffix '${each.key}'"

  dns_config {
    namespace_id = var.namespace_id

    dns_records {
      ttl  = 30
      type = "A"
    }

    routing_policy = "WEIGHTED"
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
# Module default is 1/1/1 so the module is still consumable in isolation,
# but env tfvars override to N/N/N where N == length(frps_az_suffixes) to
# get one instance per AZ at steady state. AWS ASG balances launches
# across distinct subnets-per-AZ; capacity events (ICE in one AZ, instance
# refresh, single-AZ outage) can leave the steady-state distribution
# briefly skewed.
#
# Alarm coverage today: monitoring.tf has `instance_status_check_failed`
# (PAGE: fleet drops below 1 in-service) and `fleet_undersized` (TICKET:
# fleet count < desired_capacity for 15 min). Neither catches *intra-fleet
# AZ skew*: a fleet of 3 with distribution `(a=2, b=1, c=0)` satisfies
# both alarms while `frps-c.${var.namespace_name}` returns NXDOMAIN for
# ~1/3 of OwnerIDs. Two coverage layers exist for that bug class:
#
#   - Detection: an empty-AZ alarm (synthetic DNS canary or per-service
#     `DiscoverInstances` Lambda) tracked in #1542. Catches the skew
#     within a few minutes of it occurring; cheap to ship.
#   - Structural fence: an ASG-per-AZ refactor (one ASG pinned to one
#     subnet, each `min=max=desired=1`) eliminates the bug class entirely
#     by removing single-ASG distribution from the picture. Larger
#     refactor; tracked under parent #1499 (no PR filed yet).
#
# Deploy gating policy:
#   - Sandbox flip (`deploy_frps = true`, see #1544): #1542 is the minimum
#     bar — the alarm is the only fence between an `(a=2,b=1,c=0)`
#     rebalance and silent NXDOMAIN, but blast radius is sandbox-only and
#     #1542 surfaces the skew within minutes.
#   - Prod flip: requires the ASG-per-AZ refactor in addition to #1542.
#     Detection-only is acceptable for a single-env burn-in; it is not
#     acceptable for production where the failure mode is silent
#     ~1/N customer-traffic loss.

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
