# Dormant AC matched-cohort slots. These resources do not change the canonical
# AC listener or the active ASG launch template. The outage orchestrator can
# move the old ASG to the pre-rendered blue-isolated launch template, while the
# candidate ASG is born against the green-only server registration endpoint.

locals {
  matched_cohort_count = var.enable_matched_cohort_canary ? 1 : 0
  matched_cohort_frps_controls = merge(
    var.frp_control_upstream_host != "" ? {
      primary = {
        listen_port = var.frp_control_port
      }
    } : {},
    {
      for name, upstream in var.frp_control_additional_upstreams :
      name => { listen_port = upstream.listen_port }
    },
  )
  matched_cohort_frps_smoke_sources = {
    for pair in setproduct(keys(local.matched_cohort_frps_controls), var.matched_cohort_smoke_ingress_cidrs) :
    "${pair[0]}|${pair[1]}" => {
      name = pair[0]
      cidr = pair[1]
      port = local.matched_cohort_frps_controls[pair[0]].listen_port
    }
  }
}

# The ordinary prod target rule is changed to a non-routable /32 while the
# attended outage gate is closed. Keep authenticated AC registration and
# assigned-server refresh independent from that public rule without widening
# the active server SG to the VPC: only instances in the exact AC SG may send
# UDP 62206 to the server SG.
resource "aws_vpc_security_group_ingress_rule" "server_matched_cohort_internal" {
  count = local.matched_cohort_count

  security_group_id            = var.server_security_group_id
  description                  = "Matched-cohort AC registration and assigned-server refresh"
  from_port                    = 62206
  to_port                      = 62206
  ip_protocol                  = "udp"
  referenced_security_group_id = aws_security_group.ac.id

  tags = {
    Name = "${var.name_prefix}-server-matched-cohort-internal"
  }
}

# The active AC ASG keeps its existing EIP pool throughout preparation and the
# rollback window. Give each additional full-size cohort its own max-capacity
# pool plus one replacement spare so no candidate or rollback boot can claim an
# address from another cohort. These resources are additive and the exact
# count is checked in the saved-plan gate.
resource "aws_eip" "matched_cohort_blue" {
  count = var.enable_matched_cohort_canary && var.enable_egress_eips ? local.resolved_max_capacity + 1 : 0

  domain = "vpc"

  tags = merge(var.tags, {
    Name        = "${var.name_prefix}-ac-matched-blue-eip-${count.index}"
    Component   = "ac"
    DeployColor = "blue"
    EIPPool     = local.matched_cohort_blue_eip_pool_tag
  })
}

resource "aws_eip" "matched_cohort_green" {
  count = var.enable_matched_cohort_canary && var.enable_egress_eips ? local.resolved_max_capacity + 1 : 0

  domain = "vpc"

  tags = merge(var.tags, {
    Name        = "${var.name_prefix}-ac-matched-green-eip-${count.index}"
    Component   = "ac"
    DeployColor = "green"
    EIPPool     = local.matched_cohort_green_eip_pool_tag
  })
}

resource "aws_ssm_parameter" "matched_cohort_ac_image_tag" {
  count = local.matched_cohort_count

  name        = "/${var.environment}/nhp/ac/green-image-tag"
  description = "Candidate NHP AC image tag for the coordinated matched-cohort canary"
  type        = "String"
  value       = var.image_tag

  tags = merge(var.tags, { Name = "${var.name_prefix}-matched-ac-image", DeployColor = "green" })

  lifecycle {
    ignore_changes = [value]
  }
}

# Bind the rollback clone to the exact live old-image slot value observed when
# the additive cohort contract is created. The attended selector re-reads this
# parameter before any listener mutation; ignore_changes on the managed slot
# must not turn Terraform state into image authority.
data "aws_ssm_parameter" "matched_cohort_blue_image_tag" {
  count = local.matched_cohort_count

  name = aws_ssm_parameter.image_tag.name
}

data "aws_ssm_parameter" "matched_cohort_candidate_image_tag" {
  count = local.matched_cohort_count

  name = aws_ssm_parameter.matched_cohort_ac_image_tag[0].name
}

resource "aws_s3_object" "matched_cohort_blue_init_script" {
  count = var.enable_matched_cohort_canary && var.plugin_bucket_name != null ? 1 : 0

  bucket       = var.plugin_bucket_name
  key          = "scripts/ac-init-matched-blue.sh"
  content      = local.matched_cohort_blue_user_data
  content_type = "text/x-shellscript"
}

resource "aws_s3_object" "matched_cohort_green_init_script" {
  count = var.enable_matched_cohort_canary && var.plugin_bucket_name != null ? 1 : 0

  bucket       = var.plugin_bucket_name
  key          = "scripts/ac-init-matched-green.sh"
  content      = local.matched_cohort_green_user_data
  content_type = "text/x-shellscript"
}

locals {
  matched_cohort_blue_bootstrap = var.plugin_bucket_name != null ? base64encode(<<-BOOTSTRAP
#!/bin/bash
set -euo pipefail
exec > >(tee /var/log/user-data.log | logger -t user-data) 2>&1
for binary in aws curl; do command -v "$binary" >/dev/null 2>&1 || exit 1; done
TOKEN=$(curl -fsS -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 60")
REGION=$(curl -fsS -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/placement/region)
aws s3 cp "s3://${var.plugin_bucket_name}/scripts/ac-init-matched-blue.sh" /tmp/ac-init.sh --region "$REGION"
test "$(md5sum /tmp/ac-init.sh | awk '{print $1}')" = "${md5(local.matched_cohort_blue_user_data)}"
chmod +x /tmp/ac-init.sh
exec /tmp/ac-init.sh
BOOTSTRAP
  ) : base64gzip(local.matched_cohort_blue_user_data)

  matched_cohort_green_bootstrap = var.plugin_bucket_name != null ? base64encode(<<-BOOTSTRAP
#!/bin/bash
set -euo pipefail
exec > >(tee /var/log/user-data.log | logger -t user-data) 2>&1
for binary in aws curl; do command -v "$binary" >/dev/null 2>&1 || exit 1; done
TOKEN=$(curl -fsS -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 60")
REGION=$(curl -fsS -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/placement/region)
aws s3 cp "s3://${var.plugin_bucket_name}/scripts/ac-init-matched-green.sh" /tmp/ac-init.sh --region "$REGION"
test "$(md5sum /tmp/ac-init.sh | awk '{print $1}')" = "${md5(local.matched_cohort_green_user_data)}"
chmod +x /tmp/ac-init.sh
exec /tmp/ac-init.sh
BOOTSTRAP
  ) : base64gzip(local.matched_cohort_green_user_data)
}

resource "aws_launch_template" "ac_matched_blue" {
  count = local.matched_cohort_count

  name_prefix   = "${var.name_prefix}-ac-match-blue-"
  image_id      = local.ac_ami_id
  instance_type = local.is_prod ? "c6i.xlarge" : "t3.medium"

  iam_instance_profile { arn = aws_iam_instance_profile.ac.arn }
  network_interfaces {
    associate_public_ip_address = true
    security_groups             = [aws_security_group.ac.id]
  }
  block_device_mappings {
    device_name = "/dev/sda1"
    ebs {
      volume_size           = 50
      volume_type           = "gp3"
      encrypted             = true
      kms_key_id            = var.ebs_kms_key_arn
      delete_on_termination = true
    }
  }
  user_data = local.matched_cohort_blue_bootstrap
  monitoring { enabled = true }
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
    instance_metadata_tags      = "enabled"
  }
  tag_specifications {
    resource_type = "instance"
    tags          = merge(var.tags, { Name = "${var.name_prefix}-ac", Component = "ac", DeployColor = "blue" })
  }
  lifecycle {
    create_before_destroy = true
    precondition {
      condition     = length(base64decode(local.matched_cohort_blue_bootstrap)) <= 16384
      error_message = "Matched blue AC bootstrap exceeds EC2's 16384-byte user_data limit."
    }
  }
  depends_on = [aws_s3_object.matched_cohort_blue_init_script]
}

resource "aws_launch_template" "ac_matched_green" {
  count = local.matched_cohort_count

  name_prefix   = "${var.name_prefix}-ac-match-green-"
  image_id      = local.ac_ami_id
  instance_type = local.is_prod ? "c6i.xlarge" : "t3.medium"

  iam_instance_profile { arn = aws_iam_instance_profile.ac.arn }
  network_interfaces {
    associate_public_ip_address = true
    security_groups             = [aws_security_group.ac.id]
  }
  block_device_mappings {
    device_name = "/dev/sda1"
    ebs {
      volume_size           = 50
      volume_type           = "gp3"
      encrypted             = true
      kms_key_id            = var.ebs_kms_key_arn
      delete_on_termination = true
    }
  }
  user_data = local.matched_cohort_green_bootstrap
  monitoring { enabled = true }
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
    instance_metadata_tags      = "enabled"
  }
  tag_specifications {
    resource_type = "instance"
    tags          = merge(var.tags, { Name = "${var.name_prefix}-ac-candidate", Component = "ac", DeployColor = "green" })
  }
  lifecycle {
    create_before_destroy = true
    precondition {
      condition     = length(base64decode(local.matched_cohort_green_bootstrap)) <= 16384
      error_message = "Matched green AC bootstrap exceeds EC2's 16384-byte user_data limit."
    }
  }
  depends_on = [aws_s3_object.matched_cohort_green_init_script]
}

resource "aws_lb_target_group" "ac_candidate" {
  count = local.matched_cohort_count

  name               = replace("${var.name_prefix}-ac-cand", "_", "-")
  port               = 443
  protocol           = "TCP"
  vpc_id             = var.vpc_id
  target_type        = "instance"
  preserve_client_ip = true
  proxy_protocol_v2  = false

  health_check {
    enabled             = true
    protocol            = "HTTP"
    port                = tostring(local.ac_health_check_port)
    path                = local.ac_admission_ready_path
    matcher             = "200"
    interval            = 5
    timeout             = 6
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }

  deregistration_delay   = 30
  connection_termination = true
  tags                   = merge(var.tags, { Name = "${var.name_prefix}-ac-candidate", DeployColor = "green" })
}

resource "aws_lb_target_group" "ac_candidate_smoke" {
  count = local.matched_cohort_count

  name               = replace("${var.name_prefix}-ac-csmoke", "_", "-")
  port               = 443
  protocol           = "TCP"
  vpc_id             = var.vpc_id
  target_type        = "instance"
  preserve_client_ip = true
  proxy_protocol_v2  = false

  health_check {
    enabled             = true
    protocol            = "HTTP"
    port                = tostring(local.ac_health_check_port)
    path                = local.ac_admission_ready_path
    matcher             = "200"
    interval            = 5
    timeout             = 6
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }

  deregistration_delay   = 30
  connection_termination = true
  tags                   = merge(var.tags, { Name = "${var.name_prefix}-ac-candidate-smoke", DeployColor = "green" })
}

# The customer tunnel journey dials the FRPS control listener after its NHP
# knock. Every public FRPS port therefore needs the same isolated candidate,
# selector, and rollback treatment as HTTPS; switching only :443 would send
# an otherwise-green customer journey back through the old AC fleet.
resource "aws_lb_target_group" "ac_candidate_frps" {
  for_each = var.enable_matched_cohort_canary ? local.matched_cohort_frps_controls : {}

  name_prefix        = "mcfrpc"
  port               = each.value.listen_port
  protocol           = "TCP"
  vpc_id             = var.vpc_id
  target_type        = "instance"
  preserve_client_ip = true

  health_check {
    enabled             = true
    protocol            = "HTTP"
    port                = tostring(local.ac_health_check_port)
    path                = "/ping"
    matcher             = "200"
    interval            = 5
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }

  deregistration_delay = 30
  tags = merge(var.tags, {
    Name        = "${var.name_prefix}-ac-candidate-frps-${each.key}"
    DeployColor = "green"
  })

  lifecycle { create_before_destroy = true }
}

resource "aws_security_group" "ac_candidate_nlb" {
  count = local.matched_cohort_count

  name_prefix            = "${var.name_prefix}-ac-cand-nlb-"
  description            = "Restricted matched-cohort candidate AC NLB"
  vpc_id                 = var.vpc_id
  revoke_rules_on_delete = true
  tags                   = merge(var.tags, { Name = "${var.name_prefix}-ac-candidate-nlb", Purpose = "protected-smoke" })

  lifecycle { create_before_destroy = true }
}

resource "aws_vpc_security_group_ingress_rule" "ac_candidate_nlb" {
  for_each = var.enable_matched_cohort_canary ? toset(var.matched_cohort_smoke_ingress_cidrs) : toset([])

  security_group_id = aws_security_group.ac_candidate_nlb[0].id
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
  cidr_ipv4         = each.value
  description       = "Protected matched-cohort smoke ${each.value}"
}

resource "aws_vpc_security_group_ingress_rule" "ac_candidate_nlb_frps" {
  for_each = var.enable_matched_cohort_canary ? local.matched_cohort_frps_smoke_sources : {}

  security_group_id = aws_security_group.ac_candidate_nlb[0].id
  from_port         = each.value.port
  to_port           = each.value.port
  ip_protocol       = "tcp"
  cidr_ipv4         = each.value.cidr
  description       = "Protected matched-cohort FRPS ${each.value.name} smoke ${each.value.cidr}"
}

resource "aws_vpc_security_group_egress_rule" "ac_candidate_nlb_https" {
  count = local.matched_cohort_count

  security_group_id            = aws_security_group.ac_candidate_nlb[0].id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
  referenced_security_group_id = aws_security_group.ac.id
}

resource "aws_vpc_security_group_egress_rule" "ac_candidate_nlb_frps" {
  for_each = var.enable_matched_cohort_canary ? local.matched_cohort_frps_controls : {}

  security_group_id            = aws_security_group.ac_candidate_nlb[0].id
  from_port                    = each.value.listen_port
  to_port                      = each.value.listen_port
  ip_protocol                  = "tcp"
  referenced_security_group_id = aws_security_group.ac.id
}

resource "aws_vpc_security_group_egress_rule" "ac_candidate_nlb_health" {
  count = local.matched_cohort_count

  security_group_id            = aws_security_group.ac_candidate_nlb[0].id
  from_port                    = local.ac_health_check_port
  to_port                      = local.ac_health_check_port
  ip_protocol                  = "tcp"
  referenced_security_group_id = aws_security_group.ac.id
}

# The attended maintenance gate changes only the ordinary 0.0.0.0/0 target
# rules. These source-identity rules keep the restricted candidate edge alive
# while that public gate is closed; they do not admit the canonical NLB or a
# direct public source.
resource "aws_vpc_security_group_ingress_rule" "ac_candidate_target_https" {
  count = local.matched_cohort_count

  security_group_id            = aws_security_group.ac.id
  description                  = "Matched-cohort candidate HTTPS from restricted NLB"
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
  referenced_security_group_id = aws_security_group.ac_candidate_nlb[0].id
}

resource "aws_vpc_security_group_ingress_rule" "ac_candidate_target_frps" {
  for_each = var.enable_matched_cohort_canary ? local.matched_cohort_frps_controls : {}

  security_group_id            = aws_security_group.ac.id
  description                  = "Matched-cohort candidate FRPS ${each.key} from restricted NLB"
  from_port                    = each.value.listen_port
  to_port                      = each.value.listen_port
  ip_protocol                  = "tcp"
  referenced_security_group_id = aws_security_group.ac_candidate_nlb[0].id
}

resource "aws_lb" "ac_candidate" {
  count = local.matched_cohort_count

  name               = replace("${var.name_prefix}-ac-candidate", "_", "-")
  internal           = false
  load_balancer_type = "network"
  subnets            = var.public_subnet_ids
  security_groups    = [aws_security_group.ac_candidate_nlb[0].id]

  enforce_security_group_inbound_rules_on_private_link_traffic = "on"
  enable_cross_zone_load_balancing                             = true
  enable_deletion_protection                                   = local.is_prod
  tags                                                         = merge(var.tags, { Purpose = "protected-smoke" })
}

resource "aws_lb_listener" "ac_candidate" {
  count = local.matched_cohort_count

  load_balancer_arn = aws_lb.ac_candidate[0].arn
  port              = 443
  protocol          = "TCP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.ac_candidate_smoke[0].arn
  }
}

resource "aws_lb_listener" "ac_candidate_frps" {
  for_each = var.enable_matched_cohort_canary ? local.matched_cohort_frps_controls : {}

  load_balancer_arn = aws_lb.ac_candidate[0].arn
  port              = each.value.listen_port
  protocol          = "TCP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.ac_candidate_frps[each.key].arn
  }
}

resource "aws_autoscaling_group" "ac_candidate" {
  count = local.matched_cohort_count

  name                = "${var.name_prefix}-ac-candidate"
  vpc_zone_identifier = var.public_subnet_ids
  min_size            = coalesce(var.ac_min_capacity, local.is_prod ? 2 : 1)
  max_size            = local.resolved_max_capacity
  desired_capacity    = coalesce(var.ac_min_capacity, local.is_prod ? 2 : 1)

  launch_template {
    id      = aws_launch_template.ac_matched_green[0].id
    version = aws_launch_template.ac_matched_green[0].latest_version
  }

  health_check_type         = "EC2"
  health_check_grace_period = 180
  target_group_arns = concat([
    aws_lb_target_group.ac_candidate[0].arn,
    aws_lb_target_group.ac_candidate_smoke[0].arn,
  ], [for name in sort(keys(local.matched_cohort_frps_controls)) : aws_lb_target_group.ac_candidate_frps[name].arn])
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
    value               = "${var.name_prefix}-ac-candidate"
    propagate_at_launch = true
  }
  tag {
    key                 = "DeployColor"
    value               = "green"
    propagate_at_launch = true
  }
  tag {
    key                 = "ImageTagSSMParam"
    value               = aws_ssm_parameter.matched_cohort_ac_image_tag[0].name
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
    ignore_changes        = [desired_capacity, min_size, max_size, suspended_processes]
    precondition {
      condition     = var.enable_egress_eips
      error_message = "The matched candidate AC fleet requires its isolated stable-egress EIP pool."
    }
  }
}

# Full-size rollback clone of the old AC cohort. It runs the active image but
# registers only through the blue server endpoint. PR2 can prove this clone
# ready, set the original canonical-endpoint AC ASG to zero during the outage,
# and keep this isolated clone available throughout promotion and rollback.
resource "aws_autoscaling_group" "ac_matched_blue" {
  count = local.matched_cohort_count

  name                = "${var.name_prefix}-ac-matched-blue"
  vpc_zone_identifier = var.public_subnet_ids
  min_size            = coalesce(var.ac_min_capacity, local.is_prod ? 2 : 1)
  max_size            = local.resolved_max_capacity
  desired_capacity    = coalesce(var.ac_min_capacity, local.is_prod ? 2 : 1)

  launch_template {
    id      = aws_launch_template.ac_matched_blue[0].id
    version = aws_launch_template.ac_matched_blue[0].latest_version
  }

  health_check_type         = "EC2"
  health_check_grace_period = 180
  target_group_arns = concat(
    [aws_lb_target_group.ac_tcp.arn],
    var.frp_control_upstream_host != "" ? [aws_lb_target_group.ac_frps_control[0].arn] : [],
    [for name in sort(keys(var.frp_control_additional_upstreams)) : aws_lb_target_group.ac_frps_control_additional[name].arn],
  )
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
    value               = "${var.name_prefix}-ac-matched-blue"
    propagate_at_launch = true
  }
  tag {
    key                 = "DeployColor"
    value               = "blue"
    propagate_at_launch = true
  }
  tag {
    key                 = "ImageTagSSMParam"
    value               = aws_ssm_parameter.image_tag.name
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
    ignore_changes        = [desired_capacity, min_size, max_size, suspended_processes]
    precondition {
      condition     = var.enable_egress_eips
      error_message = "The matched blue rollback AC fleet requires its isolated stable-egress EIP pool."
    }
  }
}
