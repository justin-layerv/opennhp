# ============================================================================
# Relay node: IAM, SG, SSM deploy-state params, log group, launch template, and
# an autoscaling ASG (one instance per AZ baseline). The shared-keypair fleet
# works because the server authenticates each NHP_RLY by the relay's Noise pubkey
# + relay.toml registration, not source IP (DisableRelayPeerValidation=true; 5c)
# — see the variables.tf header.
# ============================================================================

resource "aws_cloudwatch_log_group" "relay" {
  name              = "/layerv/nhp/${var.environment}/relay"
  retention_in_days = local.is_prod ? 365 : 30
  kms_key_id        = var.logs_kms_key_arn

  tags = merge(local.tags, { Name = "${var.name_prefix}-logs-relay" })
}

# ── IAM ──

resource "aws_iam_role" "relay" {
  name = "${var.name_prefix}-relay"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })

  tags = local.tags
}

# SSM session access (debugging / patching), mirrors the server role.
resource "aws_iam_role_policy_attachment" "relay_ssm" {
  role       = aws_iam_role.relay.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role_policy" "relay" {
  name = "relay-permissions"
  role = aws_iam_role.relay.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat([
      {
        Effect   = "Allow"
        Action   = ["secretsmanager:GetSecretValue"]
        Resource = [var.relay_secret_arn]
      },
      {
        Effect   = "Allow"
        Action   = ["ecr:GetAuthorizationToken"]
        Resource = "*"
      },
      {
        Effect   = "Allow"
        Action   = ["ecr:BatchCheckLayerAvailability", "ecr:GetDownloadUrlForLayer", "ecr:BatchGetImage"]
        Resource = var.relay_repo_arn
      },
      {
        Effect   = "Allow"
        Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = ["${aws_cloudwatch_log_group.relay.arn}:*"]
      },
      {
        Effect   = "Allow"
        Action   = ["ssm:GetParameter"]
        Resource = ["arn:aws:ssm:${data.aws_region.current.id}:${data.aws_caller_identity.current.account_id}:parameter${var.ssm_image_tag_parameter}"]
      },
      # Boot-failure metric (user_data emits LayerV/NHP BootstrapFailure).
      {
        Effect    = "Allow"
        Action    = ["cloudwatch:PutMetricData"]
        Resource  = "*"
        Condition = { StringEquals = { "cloudwatch:namespace" = "LayerV/NHP" } }
      }
      ],
      # KMS Decrypt only when the secret uses a customer-managed key. A null key
      # means the AWS-managed key (decryption is implicit via GetSecretValue, no
      # explicit grant needed) — OMIT the statement rather than render Resource=[]
      # (a malformed IAM statement that would fail apply for a null-keyed caller).
      var.secrets_kms_key_arn != null ? [
        {
          Effect   = "Allow"
          Action   = ["kms:Decrypt"]
          Resource = [var.secrets_kms_key_arn]
        }
    ] : [])
  })
}

resource "aws_iam_instance_profile" "relay" {
  name = "${var.name_prefix}-relay"
  role = aws_iam_role.relay.name

  tags = local.tags
}

# ── Security group ──

resource "aws_security_group" "relay" {
  name_prefix = "${var.name_prefix}-relay-"
  vpc_id      = var.vpc_id
  description = "NHP Relay node: ALB ingress, NHP UDP return from servers, scoped control-plane egress."

  tags = merge(local.tags, { Name = "${var.name_prefix}-sg-relay" })

  # `description` is ForceNew. A wording-only replacement creates a new SG, then
  # tries to delete the old one before the CI-driven relay instance refresh has
  # moved existing instance ENIs off it. Mirror the relay ALB SG's description
  # freeze, keep rule reconciliation Terraform-owned, and freeze only description
  # drift after create. Intentional future re-description requires an explicit
  # manual taint/recreate or out-of-band SG edit.
  lifecycle {
    create_before_destroy = true
    ignore_changes        = [description]
  }
}

# Inbound HTTPS from the ALB only (the relay is never directly internet-reachable;
# the ALB terminates client TLS, re-encrypts to the relay backend, and is the
# trusted hop that APPENDS the real client IP to X-Forwarded-For — its RIGHTMOST
# entry is ALB-attested, the precondition for source_addr_mode=trusted_header
# being safe; the rightmost-entry parse is #2622). The Terraform resource name is
# kept stable to avoid needless state churn.
resource "aws_vpc_security_group_ingress_rule" "relay_http_from_alb" {
  security_group_id            = aws_security_group.relay.id
  description                  = "HTTPS backend traffic from the relay ALB"
  from_port                    = var.listen_port
  to_port                      = var.listen_port
  ip_protocol                  = "tcp"
  referenced_security_group_id = aws_security_group.alb.id

  tags = { Name = "${var.name_prefix}-relay-https-from-alb" }
}

# Inbound UDP-ACK return from the cell server. SGs are stateful, but the
# relay->server hop uses the cell's internal UDP NLB with preserve_client_ip=true:
# the relay sends to an NLB node, while the server replies from its own ENI. That
# source differs from the original destination, so conntrack does not reliably
# classify the ACK as return traffic. Keep the explicit return hole, but scope it
# to the NHP server SG instead of the whole VPC.
resource "aws_vpc_security_group_ingress_rule" "relay_udp_ack_return" {
  security_group_id            = aws_security_group.relay.id
  description                  = "NHP_RLY ACK return from cell server instances"
  from_port                    = var.udp_listen_port
  to_port                      = var.udp_listen_port
  ip_protocol                  = "udp"
  referenced_security_group_id = var.server_security_group_id

  tags = { Name = "${var.name_prefix}-relay-udp-ack-return" }
}

# Data-plane egress: NHP_RLY only, UDP 62206, to the private subnet CIDRs that
# host the internal cell NLB and server fleet. The relay does not get generic
# internet egress.
resource "aws_vpc_security_group_egress_rule" "relay_to_nhp_udp" {
  for_each = local.private_subnet_cidr_blocks

  security_group_id = aws_security_group.relay.id
  description       = "NHP_RLY to cell servers on UDP 62206"
  from_port         = local.nhp_server_udp_port
  to_port           = local.nhp_server_udp_port
  ip_protocol       = "udp"
  cidr_ipv4         = each.value

  tags = { Name = "${var.name_prefix}-relay-egress-nhp-${replace(each.value, "/", "-")}" }
}

# Control-plane bootstrap egress. Relay instances pull their image, read SSM and
# Secrets Manager, and emit logs/metrics through interface VPC endpoints. This is
# intentionally SG-referenced and TCP/443-only; no NAT-wide egress.
resource "aws_vpc_security_group_egress_rule" "relay_to_vpc_endpoints_https" {
  security_group_id            = aws_security_group.relay.id
  description                  = "AWS control-plane endpoints over HTTPS"
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
  referenced_security_group_id = var.vpc_endpoint_security_group_id

  tags = { Name = "${var.name_prefix}-relay-egress-vpce-https" }
}

# ECR image layer downloads resolve to S3. S3 is a gateway endpoint (no endpoint
# SG), so scope HTTPS egress to AWS's regional S3 prefix list instead of 0/0.
resource "aws_vpc_security_group_egress_rule" "relay_to_s3_https" {
  security_group_id = aws_security_group.relay.id
  description       = "S3 gateway endpoint over HTTPS for ECR layer downloads"
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
  prefix_list_id    = data.aws_prefix_list.s3.id

  tags = { Name = "${var.name_prefix}-relay-egress-s3-https" }
}

# ── Launch template ──

resource "aws_launch_template" "relay" {
  name_prefix   = "${var.name_prefix}-relay-"
  image_id      = local.ami_id
  instance_type = var.instance_type

  iam_instance_profile {
    arn = aws_iam_instance_profile.relay.arn
  }

  # Private subnets; NAT for egress, no public IP.
  network_interfaces {
    associate_public_ip_address = false
    security_groups             = [aws_security_group.relay.id]
  }

  block_device_mappings {
    device_name = "/dev/sda1"
    ebs {
      volume_size           = 20
      volume_type           = "gp3"
      encrypted             = true
      kms_key_id            = var.ebs_kms_key_arn
      delete_on_termination = true
    }
  }

  # The relay user_data is small (no plugins/etcd/cookie/cloudmap), so it stays
  # well under EC2's 16KB cap and ships inline — no S3 fetcher needed (unlike
  # the server). The precondition fails loud if a future edit blows the cap.
  user_data = base64encode(local.user_data)

  monitoring {
    enabled = true
  }

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
    instance_metadata_tags      = "enabled"
  }

  tags = local.tags

  tag_specifications {
    resource_type = "instance"
    tags          = merge(local.tags, { Name = "${var.name_prefix}-relay" })
  }

  lifecycle {
    create_before_destroy = true

    precondition {
      condition     = alltrue([for s in var.cell_servers : s.public_key != ""])
      error_message = "a cell_servers entry has an empty public_key — a relay with no routable cell server is useless. Each entry needs its cell's server pubkey (e.g. module.compute.server_public_key_b64 for cell0), non-empty once that cell's keygen Lambda has run."
    }

    precondition {
      # local.user_data is the raw (pre-base64) script; EC2's 16KB cap is on
      # exactly these bytes. (The compute module measures
      # length(base64decode(...)) only because its local is already base64.)
      condition     = length(local.user_data) <= 16384
      error_message = "Relay user_data exceeds EC2's 16384-byte cap. Trim the bootstrap or move bulk to S3 (the server module's pattern)."
    }

    precondition {
      condition     = local.relay_max_capacity >= local.relay_min_capacity
      error_message = "relay max_capacity (${local.relay_max_capacity}) must be >= min_capacity (${local.relay_min_capacity})."
    }
  }
}

# ── ASG: horizontal fleet, one instance per AZ ──
# Static name + create_before_destroy per terraform/CLAUDE.md's ASG invariant.
# Baseline is ONE RELAY PER AZ (min/desired = the AZ count) — AZ-redundant HA for
# the only internet-facing surface; the ASG balances the desired count across the
# AZs in vpc_zone_identifier, so min = AZ count places one per AZ. desired is
# owned by the target-tracking policy below (ignore_changes), so a scale-out isn't
# reverted on the next apply; min/max stay TF-owned as the bounds.
locals {
  # Default capacity = one per AZ. Assumes the networking module's layout of one
  # private subnet per AZ (true today: slice(azs, 0, 3) → 3 subnets across 3 AZs),
  # so length(private_subnet_ids) == AZ count. If that layout ever changes to >1
  # private subnet per AZ, this would over-scale the baseline — revisit the
  # derivation (or pass min_capacity explicitly). max defaults to 2× the baseline
  # (2/AZ ceiling). Override either via the vars.
  relay_min_capacity = var.min_capacity != null ? var.min_capacity : length(var.private_subnet_ids)
  relay_max_capacity = var.max_capacity != null ? var.max_capacity : local.relay_min_capacity * 2
}

resource "aws_autoscaling_group" "relay" {
  name                = "${var.name_prefix}-relay"
  vpc_zone_identifier = var.private_subnet_ids
  min_size            = local.relay_min_capacity
  max_size            = local.relay_max_capacity
  desired_capacity    = local.relay_min_capacity

  # Attach to the ALB target group (alb.tf). target_group_arns (vs a separate
  # aws_autoscaling_attachment) keeps the wiring in one resource.
  target_group_arns = [aws_lb_target_group.relay.arn]

  launch_template {
    id      = aws_launch_template.relay.id
    version = aws_launch_template.relay.latest_version
  }

  # ELB health (not EC2) for ASG lifecycle. The relay's /health/live is pure
  # process-liveness — 200 whenever the daemon is up, independent of server
  # registration (unlike the server's /health/knock-ready, which needs an AC peer
  # and is exactly why modules/compute uses EC2 health to avoid a bootstrap
  # deadlock). So a DARK relay is /health/live-healthy and ELB health keeps it in
  # service; a genuinely boot-failed instance (bad ECR pull, crash-loop, missing
  # image tag) fails /health/live past the grace and the ASG AUTO-REPLACES it —
  # closing the no-self-heal gap EC2 health would leave (a wedged instance passes
  # EC2 status checks forever and, at one-per-AZ, silently drops an AZ's capacity).
  # The grace below covers the boot window (image pull + container start) before
  # health checks count, and the target group's unhealthy_threshold=2 × 15s
  # interval absorbs a transient systemd restart without a spurious replacement.
  # (#2630's UnHealthyHostCount + BootstrapFailure alarms are still wanted for
  # visibility, but ELB health means they're no longer the ONLY recovery path.)
  # TRADE-OFF of ELB health: a SYSTEMIC boot failure (e.g. the relay image tag
  # missing in ECR) fails /health/live on EVERY instance → ELB replaces them all →
  # a fleet-wide boot-loop with zero healthy targets. The normal path is safe:
  # build-and-push's deploy job `needs: [..., build, ...]`, so the relay image for
  # the deploy SHA is published before the apply seeds the SSM tag. #2630's
  # capacity/bootstrap alarms are the backstop for the abnormal case — a hard
  # pre-#6 gate.
  health_check_type         = "ELB"
  health_check_grace_period = 120

  enabled_metrics = [
    "GroupInServiceInstances",
    "GroupDesiredCapacity",
    "GroupMinSize",
    "GroupMaxSize",
    "GroupTotalInstances",
  ]

  tag {
    key                 = "Name"
    value               = "${var.name_prefix}-relay"
    propagate_at_launch = true
  }

  tag {
    key                 = "Component"
    value               = "relay"
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
    # The target-tracking policy owns desired_capacity; don't revert a scale-out
    # on the next apply. min/max are deliberately NOT ignored — they're the
    # TF-owned bounds (a scale beyond max should fight the cap, not stick).
    ignore_changes = [desired_capacity]
  }
}

# Scale on ALB requests per target: sparse knock traffic stays at min_capacity;
# a sustained burst (or distributed flood the WAF per-IP limit doesn't cap)
# scales out toward max_capacity. The resource_label ties the metric to this
# ALB + target group.
resource "aws_autoscaling_policy" "relay_requests" {
  name                   = "${var.name_prefix}-relay-requests"
  autoscaling_group_name = aws_autoscaling_group.relay.name
  policy_type            = "TargetTrackingScaling"

  target_tracking_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ALBRequestCountPerTarget"
      resource_label         = "${aws_lb.relay.arn_suffix}/${aws_lb_target_group.relay.arn_suffix}"
    }
    target_value = var.scale_requests_per_target
  }

  # PutScalingPolicy validates that the ALB routes to the target group named in
  # resource_label. The label only references the ALB/TG, so Terraform otherwise
  # may create this policy before the listener rule has made the TG routable.
  depends_on = [aws_lb_listener_rule.relay]
}
