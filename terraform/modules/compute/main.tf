# Compute Module
# ASG, NLB, Launch Template, Cloud Map Service

data "aws_region" "current" {}
data "aws_caller_identity" "current" {}

data "aws_ssm_parameter" "ubuntu_ami" {
  name = "/aws/service/canonical/ubuntu/server/22.04/stable/current/amd64/hvm/ebs-gp2/ami-id"
}

locals {
  is_prod = var.environment == "prod"
}

# Lambda for generating Curve25519 keys (same approach as CDK)
resource "aws_iam_role" "keygen_lambda" {
  name = "${var.name_prefix}-keygen-lambda"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
    }]
  })

  tags = var.tags
}

resource "aws_iam_role_policy_attachment" "keygen_lambda_basic" {
  role       = aws_iam_role.keygen_lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy" "keygen_lambda_secrets" {
  name = "secrets-access"
  role = aws_iam_role.keygen_lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "secretsmanager:GetSecretValue",
        "secretsmanager:PutSecretValue"
      ]
      Resource = aws_secretsmanager_secret.server.arn
    }]
  })
}

# Lambda function to generate Curve25519 keys
resource "aws_lambda_function" "keygen" {
  function_name = "${var.name_prefix}-keygen"
  role          = aws_iam_role.keygen_lambda.arn
  handler       = "index.handler"
  runtime       = "nodejs20.x"
  timeout       = 30

  filename         = data.archive_file.keygen_lambda.output_path
  source_code_hash = data.archive_file.keygen_lambda.output_base64sha256

  tags = var.tags
}

data "archive_file" "keygen_lambda" {
  type        = "zip"
  output_path = "${path.module}/keygen_lambda.zip"

  source {
    content  = <<-EOF
const crypto = require('crypto');
const { SecretsManagerClient, GetSecretValueCommand, PutSecretValueCommand } = require('@aws-sdk/client-secrets-manager');

exports.handler = async (event) => {
  console.log('RequestType:', event.RequestType);

  if (event.RequestType === 'Delete') {
    return { PhysicalResourceId: event.PhysicalResourceId };
  }

  const client = new SecretsManagerClient({});
  const secretId = event.ResourceProperties.SecretId;
  const hostname = event.ResourceProperties.Hostname;
  const environment = event.ResourceProperties.Environment;

  // Check if secret already has a valid key
  try {
    const existing = await client.send(new GetSecretValueCommand({ SecretId: secretId }));
    if (existing.SecretString) {
      const parsed = JSON.parse(existing.SecretString);
      if (parsed.privateKey && parsed.privateKey.length === 44) {
        console.log('Secret already has a valid key, not overwriting');
        return { PhysicalResourceId: event.PhysicalResourceId || secretId };
      }
    }
  } catch (e) {
    console.log('No existing secret value, will create new');
  }

  // Generate 32 random bytes for Curve25519 private key
  const privateKey = crypto.randomBytes(32);

  // Apply Curve25519 clamping
  privateKey[0] &= 248;
  privateKey[31] = (privateKey[31] & 127) | 64;

  // Base64 encode
  const privateKeyBase64 = privateKey.toString('base64');

  const secretValue = JSON.stringify({
    privateKey: privateKeyBase64,
    hostname: hostname,
    environment: environment,
  });

  await client.send(new PutSecretValueCommand({
    SecretId: secretId,
    SecretString: secretValue,
  }));

  return {
    PhysicalResourceId: event.PhysicalResourceId || secretId,
  };
};
EOF
    filename = "index.js"
  }
}

# Store server configuration in Secrets Manager
resource "aws_secretsmanager_secret" "server" {
  name                    = "${var.name_prefix}-server"
  description             = "NHP Server private key and configuration"
  recovery_window_in_days = local.is_prod ? 30 : 0

  tags = var.tags
}

# Custom resource to invoke Lambda for key generation
resource "aws_lambda_invocation" "keygen" {
  function_name = aws_lambda_function.keygen.function_name

  input = jsonencode({
    RequestType = "Create"
    ResourceProperties = {
      SecretId    = aws_secretsmanager_secret.server.id
      Hostname    = var.domain_name
      Environment = var.environment
    }
  })

  depends_on = [aws_iam_role_policy.keygen_lambda_secrets]

  lifecycle {
    ignore_changes = [input]
  }
}

# CloudWatch Log Group for servers
resource "aws_cloudwatch_log_group" "server" {
  name              = "/layerv/nhp-server/${var.environment}"
  retention_in_days = local.is_prod ? 365 : 30

  tags = var.tags
}

# Cloud Map Service for NHP servers
resource "aws_service_discovery_service" "server" {
  name        = "server"
  description = "NHP Server instances"

  dns_config {
    namespace_id = var.namespace_id

    dns_records {
      ttl  = 30
      type = "A"
    }

    routing_policy = "MULTIVALUE"
  }

  health_check_custom_config {
    failure_threshold = 1
  }

  tags = var.tags
}

# IAM Role for NHP Server instances
resource "aws_iam_role" "server" {
  name = "${var.name_prefix}-server"

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

resource "aws_iam_role_policy_attachment" "server_ssm" {
  role       = aws_iam_role.server.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role_policy" "server" {
  name = "server-permissions"
  role = aws_iam_role.server.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = ["secretsmanager:GetSecretValue"]
        Resource = concat(
          [aws_secretsmanager_secret.server.arn],
          var.etcd_secret_arn != null ? [var.etcd_secret_arn] : []
        )
      },
      {
        Effect = "Allow"
        Action = [
          "ecr:GetAuthorizationToken"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "ecr:BatchCheckLayerAvailability",
          "ecr:GetDownloadUrlForLayer",
          "ecr:BatchGetImage"
        ]
        Resource = var.server_repo_arn
      },
      {
        Effect = "Allow"
        Action = [
          "servicediscovery:RegisterInstance",
          "servicediscovery:DeregisterInstance",
          "servicediscovery:UpdateInstanceCustomHealthStatus",
          "servicediscovery:GetInstance"
        ]
        Resource = aws_service_discovery_service.server.arn
      },
      {
        Effect = "Allow"
        Action = [
          "servicediscovery:DiscoverInstances",
          "servicediscovery:GetNamespace",
          "servicediscovery:GetService"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "${aws_cloudwatch_log_group.server.arn}:*"
      }
    ]
  })
}

resource "aws_iam_instance_profile" "server" {
  name = "${var.name_prefix}-server"
  role = aws_iam_role.server.name

  tags = var.tags
}

# Security Group for NHP servers
resource "aws_security_group" "server" {
  name_prefix = "${var.name_prefix}-server-"
  vpc_id      = var.vpc_id
  description = "Security group for NHP Server instances - UDP only"

  # NHP Protocol (UDP 62206) - only exposed port
  ingress {
    from_port   = 62206
    to_port     = 62206
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "NHP Protocol - only exposed port"
  }

  # SSH from VPC for NLB health checks (internal only)
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
    description = "NLB health check via SSH (internal only)"
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
    Name = "${var.name_prefix}-server"
  })

  lifecycle {
    create_before_destroy = true
  }
}

# User Data script - using templatefile for proper interpolation
locals {
  user_data = templatefile("${path.module}/user_data.sh.tpl", {
    secret_arn          = aws_secretsmanager_secret.server.arn
    region              = data.aws_region.current.name
    account_id          = data.aws_caller_identity.current.account_id
    cloudmap_service_id = aws_service_discovery_service.server.id
    server_repo_url     = var.server_repo_url
    environment         = var.environment
    multi_tenant        = var.multi_tenant
    etcd_endpoint       = var.etcd_endpoint
  })
}

# Launch Template
resource "aws_launch_template" "server" {
  name_prefix   = "${var.name_prefix}-server-"
  image_id      = data.aws_ssm_parameter.ubuntu_ami.value
  instance_type = local.is_prod ? "c6i.xlarge" : "t3.medium"

  iam_instance_profile {
    arn = aws_iam_instance_profile.server.arn
  }

  network_interfaces {
    associate_public_ip_address = false
    security_groups             = [aws_security_group.server.id]
  }

  block_device_mappings {
    device_name = "/dev/sda1"
    ebs {
      volume_size           = 50
      volume_type           = "gp3"
      encrypted             = true
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
      Name = "${var.name_prefix}-server"
    })
  }

  lifecycle {
    create_before_destroy = true
  }

  depends_on = [aws_lambda_invocation.keygen]
}

# Auto Scaling Group
resource "aws_autoscaling_group" "server" {
  name                = "${var.name_prefix}-server"
  vpc_zone_identifier = var.private_subnet_ids
  min_size            = var.min_capacity
  max_size            = var.max_capacity
  desired_capacity    = var.min_capacity

  launch_template {
    id      = aws_launch_template.server.id
    version = "$Latest"
  }

  health_check_type         = "EC2"
  health_check_grace_period = 300

  instance_refresh {
    strategy = "Rolling"
    preferences {
      min_healthy_percentage = 50
      instance_warmup        = 300
    }
  }

  tag {
    key                 = "Name"
    value               = "${var.name_prefix}-server"
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

# Scaling Policies
resource "aws_autoscaling_policy" "cpu" {
  name                   = "${var.name_prefix}-cpu"
  autoscaling_group_name = aws_autoscaling_group.server.name
  policy_type            = "TargetTrackingScaling"

  target_tracking_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ASGAverageCPUUtilization"
    }
    target_value = 70.0
  }
}

resource "aws_autoscaling_policy" "network" {
  name                   = "${var.name_prefix}-network"
  autoscaling_group_name = aws_autoscaling_group.server.name
  policy_type            = "TargetTrackingScaling"

  target_tracking_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ASGAverageNetworkIn"
    }
    target_value = 10485760 # 10 MB/s
  }
}

# Network Load Balancer
resource "aws_lb" "server" {
  name               = replace("${var.name_prefix}-nlb", "_", "-")
  internal           = false
  load_balancer_type = "network"
  subnets            = var.public_subnet_ids

  enable_cross_zone_load_balancing = true

  tags = var.tags
}

# UDP Target Group
resource "aws_lb_target_group" "udp" {
  name        = replace("${var.name_prefix}-udp", "_", "-")
  port        = 62206
  protocol    = "UDP"
  vpc_id      = var.vpc_id
  target_type = "instance"

  health_check {
    enabled             = true
    protocol            = "TCP"
    port                = "22"
    interval            = 30
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }

  deregistration_delay = 30

  tags = var.tags
}

# Attach ASG to Target Group
resource "aws_autoscaling_attachment" "server" {
  autoscaling_group_name = aws_autoscaling_group.server.name
  lb_target_group_arn    = aws_lb_target_group.udp.arn
}

# UDP Listener
resource "aws_lb_listener" "udp" {
  load_balancer_arn = aws_lb.server.arn
  port              = 62206
  protocol          = "UDP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.udp.arn
  }

  tags = var.tags
}
