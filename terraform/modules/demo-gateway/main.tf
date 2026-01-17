# Demo Gateway Module
# nginx + certbot for qurl.link routing to NHP Server HTTP plugins
#
# Architecture:
# Internet → NLB (TCP 443) → nginx (TLS termination) → NHP Server HTTP (port 8888)
#
# Routes:
# - qurl.link/{appId} → /plugins/passcode?resid={appId}&action=login
# - qurl.link/ → redirect to fallback_url

# ==================== Data Sources ====================

data "aws_region" "current" {}
data "aws_caller_identity" "current" {}

# Ubuntu 24.04 LTS (Noble Numbat)
data "aws_ssm_parameter" "ubuntu_ami" {
  name = "/aws/service/canonical/ubuntu/server/noble/stable/current/amd64/hvm/ebs-gp3/ami-id"
}

# ==================== Locals ====================

locals {
  is_prod = var.environment == "prod"
}

# ==================== CloudWatch Log Group ====================

resource "aws_cloudwatch_log_group" "demo_gateway" {
  name              = "/layerv/nhp/${var.environment}/demo-gateway"
  retention_in_days = local.is_prod ? 365 : 30
  kms_key_id        = var.logs_kms_key_arn

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-logs-demo-gateway"
    Component = "demo-gateway"
  })
}

# ==================== IAM Role ====================

resource "aws_iam_role" "demo_gateway" {
  name = "${var.name_prefix}-demo-gateway"

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

resource "aws_iam_role_policy_attachment" "demo_gateway_ssm" {
  role       = aws_iam_role.demo_gateway.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role_policy" "demo_gateway" {
  name = "demo-gateway-permissions"
  role = aws_iam_role.demo_gateway.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "${aws_cloudwatch_log_group.demo_gateway.arn}:*"
      },
      # Route 53 permissions for certbot DNS-01 challenge
      # If cross-account role is provided, this grants permission to assume it
      # If hosted_zone_id is in same account, direct access is granted
      {
        Effect = "Allow"
        Action = [
          "route53:ListHostedZones",
          "route53:GetChange"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "route53:ChangeResourceRecordSets",
          "route53:ListResourceRecordSets"
        ]
        Resource = var.hosted_zone_id != null ? ["arn:aws:route53:::hostedzone/${var.hosted_zone_id}"] : []
      }
    ]
  })
}

# Cross-account Route 53 access (if configured)
resource "aws_iam_role_policy" "demo_gateway_cross_account" {
  count = var.cross_account_route53_role_arn != null ? 1 : 0

  name = "cross-account-route53"
  role = aws_iam_role.demo_gateway.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "sts:AssumeRole"
      Resource = var.cross_account_route53_role_arn
    }]
  })
}

resource "aws_iam_instance_profile" "demo_gateway" {
  name = "${var.name_prefix}-demo-gateway"
  role = aws_iam_role.demo_gateway.name

  tags = var.tags
}

# ==================== Security Group ====================

resource "aws_security_group" "demo_gateway" {
  name_prefix = "${var.name_prefix}-demo-gateway-"
  vpc_id      = var.vpc_id
  description = "Security group for Demo Gateway (nginx + certbot)"

  # HTTPS from NLB
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTPS from NLB"
  }

  # HTTP for Let's Encrypt challenges and redirect
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTP for ACME and redirect"
  }

  # SSH from VPC for debugging (via SSM preferred)
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
    description = "SSH from VPC"
  }

  # All outbound
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "All outbound"
  }

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-sg-demo-gateway"
    Component = "demo-gateway"
  })

  lifecycle {
    create_before_destroy = true
  }
}

# ==================== User Data ====================

locals {
  user_data = templatefile("${path.module}/user_data.sh.tpl", {
    domain_name                    = var.domain_name
    acme_email                     = var.acme_email
    nhp_server_endpoint            = var.nhp_server_endpoint
    nhp_server_port                = var.nhp_server_port
    fallback_url                   = var.fallback_url
    cross_account_route53_role_arn = var.cross_account_route53_role_arn
    hosted_zone_id                 = var.hosted_zone_id
    region                         = data.aws_region.current.id
  })
}

# ==================== Launch Template ====================

resource "aws_launch_template" "demo_gateway" {
  name_prefix   = "${var.name_prefix}-demo-gateway-"
  image_id      = data.aws_ssm_parameter.ubuntu_ami.value
  instance_type = var.instance_type

  iam_instance_profile {
    arn = aws_iam_instance_profile.demo_gateway.arn
  }

  network_interfaces {
    associate_public_ip_address = true
    security_groups             = [aws_security_group.demo_gateway.id]
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

  user_data = base64encode(local.user_data)

  monitoring {
    enabled = true
  }

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  tags = var.tags

  tag_specifications {
    resource_type = "instance"
    tags = merge(var.tags, {
      Name      = "${var.name_prefix}-demo-gateway"
      Component = "demo-gateway"
    })
  }

  lifecycle {
    create_before_destroy = true
  }
}

# ==================== Auto Scaling Group ====================

resource "aws_autoscaling_group" "demo_gateway" {
  name                = "${var.name_prefix}-demo-gateway"
  vpc_zone_identifier = var.public_subnet_ids
  min_size            = 1
  max_size            = 2
  desired_capacity    = 1

  launch_template {
    id      = aws_launch_template.demo_gateway.id
    version = "$Latest"
  }

  health_check_type         = "EC2"
  health_check_grace_period = 300

  target_group_arns = [
    aws_lb_target_group.https.arn,
    aws_lb_target_group.http.arn
  ]

  instance_refresh {
    strategy = "Rolling"
    preferences {
      min_healthy_percentage = 50
      instance_warmup        = 300
    }
  }

  tag {
    key                 = "Name"
    value               = "${var.name_prefix}-demo-gateway"
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
  }
}

# ==================== Network Load Balancer ====================

resource "aws_lb" "demo_gateway" {
  name               = replace("${var.name_prefix}-demo-gw", "_", "-")
  internal           = false
  load_balancer_type = "network"
  subnets            = var.public_subnet_ids

  enable_cross_zone_load_balancing = true

  tags = var.tags
}

# HTTPS Target Group (TCP passthrough to nginx TLS)
resource "aws_lb_target_group" "https" {
  name        = replace("${var.name_prefix}-gw-https", "_", "-")
  port        = 443
  protocol    = "TCP"
  vpc_id      = var.vpc_id
  target_type = "instance"

  health_check {
    enabled             = true
    protocol            = "TCP"
    port                = "443"
    interval            = 30
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }

  deregistration_delay = 30

  tags = var.tags
}

# HTTP Target Group (for ACME HTTP-01 and redirects)
resource "aws_lb_target_group" "http" {
  name        = replace("${var.name_prefix}-gw-http", "_", "-")
  port        = 80
  protocol    = "TCP"
  vpc_id      = var.vpc_id
  target_type = "instance"

  health_check {
    enabled             = true
    protocol            = "TCP"
    port                = "80"
    interval            = 30
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }

  deregistration_delay = 30

  tags = var.tags
}

# HTTPS Listener
resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.demo_gateway.arn
  port              = 443
  protocol          = "TCP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.https.arn
  }

  tags = var.tags
}

# HTTP Listener
resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.demo_gateway.arn
  port              = 80
  protocol          = "TCP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.http.arn
  }

  tags = var.tags
}

# ==================== Route 53 Record ====================

# Create DNS record pointing to NLB
# This assumes the hosted zone is accessible (either same account or via cross-account role)
resource "aws_route53_record" "demo_gateway" {
  count = var.hosted_zone_id != null ? 1 : 0

  zone_id = var.hosted_zone_id
  name    = var.domain_name
  type    = "A"

  alias {
    name                   = aws_lb.demo_gateway.dns_name
    zone_id                = aws_lb.demo_gateway.zone_id
    evaluate_target_health = true
  }
}
