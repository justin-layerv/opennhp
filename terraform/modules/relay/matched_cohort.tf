# Dormant candidate relay fleet. The canonical HTTPS listener remains on the
# ordinary relay target group. A protected runner reaches this fleet through a
# separate source-fenced ALB, and the candidate renders
# only the green server endpoint into relay.toml.

locals {
  matched_cohort_count = var.enable_matched_cohort_canary ? 1 : 0
}

data "aws_ssm_parameter" "matched_cohort_blue_image_tag" {
  count = local.matched_cohort_count

  name = var.ssm_image_tag_parameter
}

data "aws_ssm_parameter" "matched_cohort_candidate_image_tag" {
  count = local.matched_cohort_count

  name = var.matched_cohort_image_tag_parameter
}

resource "aws_iam_role_policy" "relay_matched_cohort_image" {
  count = local.matched_cohort_count

  name = "relay-matched-cohort-image"
  role = aws_iam_role.relay.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "CandidateImageSlot"
      Effect   = "Allow"
      Action   = ["ssm:GetParameter"]
      Resource = "arn:aws:ssm:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:parameter${var.matched_cohort_image_tag_parameter}"
    }]
  })
}

resource "aws_launch_template" "relay_candidate" {
  count = local.matched_cohort_count

  name_prefix   = "${var.name_prefix}-relay-candidate-"
  image_id      = local.ami_id
  instance_type = var.instance_type

  iam_instance_profile { arn = aws_iam_instance_profile.relay.arn }
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

  user_data = base64encode(local.matched_cohort_user_data)
  monitoring { enabled = true }
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
    instance_metadata_tags      = "enabled"
  }
  tag_specifications {
    resource_type = "instance"
    tags          = merge(local.tags, { Name = "${var.name_prefix}-relay-candidate", DeployColor = "green" })
  }

  lifecycle {
    create_before_destroy = true
    precondition {
      condition     = alltrue([for s in var.matched_cohort_cell_servers : s.public_key != ""])
      error_message = "Candidate relay cells require the exact non-empty cell server public key."
    }
    precondition {
      condition     = length(local.matched_cohort_user_data) <= 16384
      error_message = "Candidate relay user_data exceeds EC2's 16384-byte cap."
    }
  }
}

resource "aws_lb_target_group" "relay_candidate" {
  count = local.matched_cohort_count

  name_prefix = "rlycan"
  port        = var.listen_port
  protocol    = "HTTPS"
  target_type = "instance"
  vpc_id      = var.vpc_id

  deregistration_delay = 30
  health_check {
    enabled             = true
    path                = "/health/live"
    protocol            = "HTTPS"
    port                = "traffic-port"
    matcher             = "200"
    interval            = 5
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 2
  }

  tags = merge(local.tags, { Name = "${local.alb_name}-candidate", DeployColor = "green" })

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_security_group" "relay_candidate_alb" {
  count = local.matched_cohort_count

  name_prefix            = "${var.name_prefix}-relay-candidate-alb-"
  description            = "Restricted matched-cohort relay smoke ALB"
  vpc_id                 = var.vpc_id
  revoke_rules_on_delete = true

  tags = merge(local.tags, { Name = "${local.alb_name}-candidate-alb", Purpose = "protected-smoke" })

  lifecycle { create_before_destroy = true }
}

resource "aws_vpc_security_group_ingress_rule" "alb_candidate_https" {
  for_each = var.enable_matched_cohort_canary ? toset(var.matched_cohort_smoke_ingress_cidrs) : toset([])

  security_group_id = aws_security_group.relay_candidate_alb[0].id
  description       = "Protected matched-cohort relay smoke ${each.value}"
  cidr_ipv4         = each.value
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "relay_candidate_alb_to_relay" {
  count = local.matched_cohort_count

  security_group_id            = aws_security_group.relay_candidate_alb[0].id
  description                  = "Candidate ALB to candidate relay nodes"
  referenced_security_group_id = aws_security_group.relay.id
  from_port                    = var.listen_port
  to_port                      = var.listen_port
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "relay_candidate_from_alb" {
  count = local.matched_cohort_count

  security_group_id            = aws_security_group.relay.id
  description                  = "Candidate relay HTTPS from restricted candidate ALB"
  referenced_security_group_id = aws_security_group.relay_candidate_alb[0].id
  from_port                    = var.listen_port
  to_port                      = var.listen_port
  ip_protocol                  = "tcp"
}

# Keep candidate smoke off the canonical ALB. The canonical fixed-response
# gate can therefore block every public relay request without blocking the
# protected candidate journey that must run during the outage.
resource "aws_lb" "relay_candidate" {
  count = local.matched_cohort_count

  name               = replace("${var.name_prefix}-relay-candidate", "_", "-")
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.relay_candidate_alb[0].id]
  subnets            = var.public_subnet_ids
  ip_address_type    = "ipv4"

  idle_timeout               = 30
  drop_invalid_header_fields = true
  desync_mitigation_mode     = "defensive"
  enable_deletion_protection = local.is_prod

  access_logs {
    bucket  = aws_s3_bucket.alb_access_logs.bucket
    enabled = true
  }

  tags = merge(local.tags, { Name = "${local.alb_name}-candidate", Purpose = "protected-smoke" })

  depends_on = [aws_s3_bucket_policy.alb_access_logs, terraform_data.network_ready]
}

resource "aws_lb_listener" "candidate_https" {
  count = local.matched_cohort_count

  load_balancer_arn = aws_lb.relay_candidate[0].arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = aws_lb_listener.https.ssl_policy
  certificate_arn   = var.certificate_arn

  default_action {
    type = "fixed-response"
    fixed_response {
      content_type = "application/json"
      message_body = jsonencode({ error = "not_found" })
      status_code  = "404"
    }
  }
}

resource "aws_lb_listener_rule" "relay_candidate" {
  count = local.matched_cohort_count

  listener_arn = aws_lb_listener.candidate_https[0].arn
  priority     = 1

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.relay_candidate[0].arn
  }
  condition {
    path_pattern { values = ["/relay/*"] }
  }
  condition {
    http_request_method { values = ["POST", "OPTIONS"] }
  }
}

# Independent canonical relay maintenance gate. Its steady-state path is
# impossible. The attended gate helper changes only that path to /relay/*;
# priority 1 then returns 503 before the ordinary priority-2 forwarding rule.
resource "aws_lb_listener_rule" "relay_maintenance" {
  count = local.matched_cohort_count

  listener_arn = aws_lb_listener.https.arn
  priority     = 1

  action {
    type = "fixed-response"
    fixed_response {
      content_type = "application/json"
      message_body = jsonencode({ error = "maintenance" })
      status_code  = "503"
    }
  }
  condition {
    path_pattern { values = ["/__layerv_matched_cohort_maintenance_disabled__"] }
  }
  condition {
    http_request_method { values = ["POST", "OPTIONS"] }
  }

  tags = merge(local.tags, { Name = "${local.alb_name}-matched-cohort-maintenance", Purpose = "maintenance" })

  # AWS rejects two rules with priority 1. Move the existing customer rule to
  # priority 2 before this dormant rule is created; reverse dependency order
  # removes this rule before a feature disable restores priority 1.
  depends_on = [aws_lb_listener_rule.relay]
}

resource "aws_autoscaling_group" "relay_candidate" {
  count = local.matched_cohort_count

  name                = "${var.name_prefix}-relay-dmz-candidate"
  vpc_zone_identifier = var.relay_subnet_ids
  min_size            = local.relay_min_capacity
  max_size            = local.relay_max_capacity
  desired_capacity    = local.relay_min_capacity
  target_group_arns   = [aws_lb_target_group.relay_candidate[0].arn]

  launch_template {
    id      = aws_launch_template.relay_candidate[0].id
    version = aws_launch_template.relay_candidate[0].latest_version
  }

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
    value               = "${var.name_prefix}-relay-candidate"
    propagate_at_launch = true
  }
  tag {
    key                 = "Component"
    value               = "relay"
    propagate_at_launch = true
  }
  tag {
    key                 = "DeployColor"
    value               = "green"
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
    ignore_changes        = [desired_capacity]
  }

  depends_on = [
    terraform_data.network_ready,
    terraform_data.fleet_security_ready,
    aws_iam_role_policy.relay_matched_cohort_image,
  ]
}
