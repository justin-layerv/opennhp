data "aws_region" "current" {}
data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_ami" "runner" {
  filter {
    name   = "image-id"
    values = [var.ami_id]
  }
}

locals {
  component = "udp-proof-runner"
  purpose   = "udp-proof"

  tags = merge(var.tags, {
    Component   = local.component
    Environment = var.environment
    Purpose     = local.purpose
    Repository  = var.github_repository
  })

  runner_name = "${var.name_prefix}-udp-proof-runner"
  runner_tags = merge(local.tags, { Name = local.runner_name })

  aws_cli_archive_url    = "https://awscli.amazonaws.com/awscli-exe-linux-x86_64-2.36.11.zip"
  aws_cli_archive_sha256 = "50fbb7a2f44a78eab4a210088040e8f0bc4b9937cac8043c2354269d58614df6"

  # The proof workflows call `gh` to authenticate the controller run and read the
  # deployment-producer artifact, and Ubuntu 24.04 does not ship it. Pin the
  # exact release archive by checksum for the same reason the AWS CLI is pinned
  # above: the runner must not depend on a moving distro or upstream surface.
  gh_cli_archive_url    = "https://github.com/cli/cli/releases/download/v2.83.0/gh_2.83.0_linux_amd64.tar.gz"
  gh_cli_archive_sha256 = "a5cf6cdb40fc67751adf561126b3314044779cea81ba4f254fbe8e9a69f1676f"
  gh_cli_archive_root   = "gh_2.83.0_linux_amd64"

  ec2_arn_prefix                       = "arn:${data.aws_partition.current.partition}:ec2:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:"
  jit_secret_prefix                    = "${var.name_prefix}/udp-proof/jit/"
  jit_secret_arn_pattern               = "arn:${data.aws_partition.current.partition}:secretsmanager:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:secret:${local.jit_secret_prefix}*"
  recovery_request_secret_prefix       = "${var.name_prefix}/udp-proof/recovery/request/"
  recovery_response_secret_prefix      = "${var.name_prefix}/udp-proof/recovery/response/"
  recovery_request_secret_arn_pattern  = "arn:${data.aws_partition.current.partition}:secretsmanager:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:secret:${local.recovery_request_secret_prefix}*"
  recovery_response_secret_arn_pattern = "arn:${data.aws_partition.current.partition}:secretsmanager:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:secret:${local.recovery_response_secret_prefix}*"
  proof_owner_id                       = "${var.name_prefix}-udp-proof"
  proof_customers_table_name           = "${var.name_prefix}-control-qurl-customers"
  proof_customers_table_arn            = "arn:${data.aws_partition.current.partition}:dynamodb:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:table/${local.proof_customers_table_name}"
  proof_kms_key_arn_prefix             = "arn:${data.aws_partition.current.partition}:kms:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:key/"
  secrets_kms_via_service              = "secretsmanager.${data.aws_region.current.region}.${data.aws_partition.current.dns_suffix}"
  vpc_resolver_cidr                    = "${cidrhost(var.vpc_cidr, 2)}/32"

  authority_proof_rollout_function_names = [
    "${var.name_prefix}-ca-ia",
    "${var.name_prefix}-ca-ra",
    "${var.name_prefix}-ca-icr",
    "${var.name_prefix}-ca-pm",
  ]
}

resource "aws_vpc" "runner" {
  cidr_block                           = var.vpc_cidr
  enable_dns_hostnames                 = true
  enable_dns_support                   = true
  enable_network_address_usage_metrics = true

  tags = merge(local.tags, { Name = "${local.runner_name}-vpc" })
}

resource "aws_internet_gateway" "runner" {
  vpc_id = aws_vpc.runner.id

  tags = merge(local.tags, { Name = "${local.runner_name}-igw" })
}

resource "aws_subnet" "runner" {
  vpc_id                  = aws_vpc.runner.id
  cidr_block              = var.vpc_cidr
  availability_zone       = var.availability_zone
  map_public_ip_on_launch = false

  tags = merge(local.runner_tags, { Tier = "public-ephemeral-runner" })
}

resource "aws_route_table" "runner" {
  vpc_id = aws_vpc.runner.id

  tags = local.runner_tags
}

resource "aws_route" "public" {
  route_table_id         = aws_route_table.runner.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.runner.id
}

resource "aws_route_table_association" "runner" {
  subnet_id      = aws_subnet.runner.id
  route_table_id = aws_route_table.runner.id
}

resource "aws_security_group" "runner" {
  name_prefix = "${local.runner_name}-"
  description = "No ingress; narrowly bounded egress for the ephemeral UDP proof runner"
  vpc_id      = aws_vpc.runner.id
  ingress     = []
  egress      = []

  tags = local.runner_tags

  lifecycle {
    create_before_destroy = true
    # egress = [] revokes the AWS default allow-all on create; the real
    # outbound rules are owned by the aws_vpc_security_group_egress_rule
    # resources below. Ignore inline egress drift so those authoritative
    # rules don't fight the empty inline set on every subsequent plan
    # (otherwise a plain re-apply strips the runner's egress). ingress
    # stays inline-[] and enforced: there are no separate ingress rules.
    ignore_changes = [egress]
  }
}

resource "aws_vpc_security_group_egress_rule" "dns_udp" {
  security_group_id = aws_security_group.runner.id
  description       = "VPC resolver UDP"
  cidr_ipv4         = local.vpc_resolver_cidr
  ip_protocol       = "udp"
  from_port         = 53
  to_port           = 53
}

resource "aws_vpc_security_group_egress_rule" "dns_tcp" {
  security_group_id = aws_security_group.runner.id
  description       = "VPC resolver TCP fallback"
  cidr_ipv4         = local.vpc_resolver_cidr
  ip_protocol       = "tcp"
  from_port         = 53
  to_port           = 53
}

resource "aws_vpc_security_group_egress_rule" "https" {
  security_group_id = aws_security_group.runner.id
  description       = "GitHub, package, registry, and AWS API HTTPS"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
}

# The runner is an NHP client: it dials the public Hub/cell NLB listeners on
# the client-edge port (UDP 443), never the server's own 62206 bind. This is
# UDP 443 and is distinct from the TCP 443 rule above.
resource "aws_vpc_security_group_egress_rule" "nhp_udp" {
  security_group_id = aws_security_group.runner.id
  description       = "Public sandbox Hub and cell NHP UDP"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "udp"
  from_port         = 443
  to_port           = 443
}

resource "aws_vpc_security_group_egress_rule" "time_sync" {
  security_group_id = aws_security_group.runner.id
  description       = "Amazon Time Sync Service"
  cidr_ipv4         = "169.254.169.123/32"
  ip_protocol       = "udp"
  from_port         = 123
  to_port           = 123
}

resource "aws_eip" "source" {
  domain = "vpc"

  tags = merge(local.tags, { Name = "${var.name_prefix}-udp-proof-source" })

  depends_on = [aws_internet_gateway.runner]
}

resource "aws_kms_key" "jit" {
  description             = "Ephemeral GitHub JIT runner configuration for ${var.name_prefix} UDP proof"
  enable_key_rotation     = true
  deletion_window_in_days = 30

  tags = merge(local.tags, { Name = "${var.name_prefix}-udp-proof-jit" })
}

resource "aws_kms_alias" "jit" {
  name          = "alias/${var.name_prefix}-udp-proof-jit"
  target_key_id = aws_kms_key.jit.key_id
}

resource "aws_iam_role" "runner" {
  name        = local.runner_name
  description = "Ephemeral sandbox UDP proof runner; no standing instance and no application-secret access"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })

  tags = local.tags
}

resource "aws_iam_instance_profile" "runner" {
  name = local.runner_name
  role = aws_iam_role.runner.name

  tags = local.tags
}

resource "aws_launch_template" "runner" {
  name          = local.runner_name
  description   = "Single-use attended sandbox UDP proof runner"
  image_id      = data.aws_ami.runner.id
  instance_type = var.instance_type

  update_default_version               = true
  instance_initiated_shutdown_behavior = "terminate"
  user_data = base64encode(templatefile("${path.module}/user_data.sh.tpl", {
    aws_cli_archive_sha256 = local.aws_cli_archive_sha256
    gh_cli_archive_url     = local.gh_cli_archive_url
    gh_cli_archive_sha256  = local.gh_cli_archive_sha256
    gh_cli_archive_root    = local.gh_cli_archive_root
    aws_cli_archive_url    = local.aws_cli_archive_url
    aws_region             = data.aws_region.current.region
    jit_secret_prefix      = local.jit_secret_prefix
    max_runtime_minutes    = var.max_runtime_minutes
    runner_archive_sha256  = var.runner_archive_sha256
    runner_archive_url     = var.runner_archive_url
  }))

  iam_instance_profile {
    arn = aws_iam_instance_profile.runner.arn
  }

  network_interfaces {
    associate_public_ip_address = false
    delete_on_termination       = true
    device_index                = 0
    security_groups             = [aws_security_group.runner.id]
    subnet_id                   = aws_subnet.runner.id
  }

  block_device_mappings {
    device_name = "/dev/sda1"

    ebs {
      delete_on_termination = true
      encrypted             = true
      volume_size           = var.root_volume_gib
      volume_type           = "gp3"
    }
  }

  metadata_options {
    http_endpoint               = "enabled"
    http_protocol_ipv6          = "disabled"
    http_put_response_hop_limit = 2
    http_tokens                 = "required"
    instance_metadata_tags      = "enabled"
  }

  monitoring {
    enabled = true
  }

  tag_specifications {
    resource_type = "instance"
    tags          = local.runner_tags
  }

  tag_specifications {
    resource_type = "volume"
    tags          = local.runner_tags
  }

  tags = local.runner_tags

  lifecycle {
    create_before_destroy = true

    precondition {
      condition     = data.aws_ami.runner.architecture == "x86_64"
      error_message = "The pinned proof-runner AMI must have x86_64 architecture."
    }
  }
}
