resource "aws_vpc" "control" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-vpc"
  })
}

# AWS creates a permissive same-group rule on every VPC's default security
# group. Manage it explicitly so an accidentally unassigned ENI cannot inherit
# lateral access through that default.
resource "aws_default_security_group" "control" {
  vpc_id = aws_vpc.control.id

  ingress = []
  egress  = []

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-default-deny"
  })
}

# The foundation has no public edge subnet, internet gateway, NAT gateway,
# public IP, peering, transit route, or default route. Its only non-local route
# is the AWS-managed DynamoDB gateway-endpoint prefix-list route. The later UDP
# Hub slice may add edge subnets without weakening these workload subnets.
resource "aws_subnet" "isolated" {
  count = 3

  vpc_id                  = aws_vpc.control.id
  cidr_block              = cidrsubnet(var.vpc_cidr, 8, count.index)
  availability_zone       = local.availability_zones[count.index]
  map_public_ip_on_launch = false

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-isolated-${local.availability_zones[count.index]}"
    Type = "isolated"
  })
}

# The AWS-created main route table is intentionally unmanaged and local-only.
# Every foundation subnet is explicitly associated below, while the lexical
# contract forbids aws_default_route_table so later work cannot add hidden
# routes through that otherwise unused table.
resource "aws_route_table" "isolated" {
  count = 3

  vpc_id = aws_vpc.control.id

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-isolated-${local.availability_zones[count.index]}"
    Type = "isolated"
  })
}

resource "aws_route_table_association" "isolated" {
  count = 3

  subnet_id      = aws_subnet.isolated[count.index].id
  route_table_id = aws_route_table.isolated[count.index].id
}

resource "aws_cloudwatch_log_group" "flow_logs" {
  name              = local.flow_log_group_name
  retention_in_days = local.is_prod ? 365 : 30
  kms_key_id        = aws_kms_key.authority_data.arn

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-vpc-flow-logs"
  })
}

resource "aws_iam_role" "flow_logs" {
  name = "${local.name_prefix}-vpc-flow-logs"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "vpc-flow-logs.amazonaws.com"
      }
      Action = "sts:AssumeRole"
      Condition = {
        StringEquals = {
          "aws:SourceAccount" = data.aws_caller_identity.current.account_id
        }
        ArnLike = {
          "aws:SourceArn" = "arn:${data.aws_partition.current.partition}:ec2:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:vpc-flow-log/*"
        }
      }
    }]
  })

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-vpc-flow-logs"
  })
}

resource "aws_iam_role_policy" "flow_logs" {
  name = "flow-logs"
  role = aws_iam_role.flow_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "DiscoverFlowLogGroups"
        Effect   = "Allow"
        Action   = "logs:DescribeLogGroups"
        Resource = "*"
      },
      {
        Sid      = "DescribeFlowLogStreams"
        Effect   = "Allow"
        Action   = "logs:DescribeLogStreams"
        Resource = "${local.flow_log_group_arn}:*"
      },
      {
        Sid    = "WriteFlowLogStreams"
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents",
        ]
        Resource = "${local.flow_log_group_arn}:*"
      },
    ]
  })
}

resource "aws_flow_log" "control" {
  vpc_id                   = aws_vpc.control.id
  traffic_type             = "ALL"
  log_destination_type     = "cloud-watch-logs"
  log_destination          = aws_cloudwatch_log_group.flow_logs.arn
  iam_role_arn             = aws_iam_role.flow_logs.arn
  max_aggregation_interval = 60

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-vpc-flow-log"
  })
}
