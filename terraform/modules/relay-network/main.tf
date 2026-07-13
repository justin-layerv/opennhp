data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_region" "current" {}
data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

locals {
  azs = slice(data.aws_availability_zones.available.names, 0, 3)

  # /24 tier offsets within the /16 VPC, one reserved block per AZ:
  #   0-9 public (ALB), 10-19 relay (isolated), 20-29 endpoint (isolated).
  # Distinct decades leave headroom to grow a tier without renumbering others.
  public_subnet_offset   = 0
  relay_subnet_offset    = 10
  endpoint_subnet_offset = 20

  public_subnet_cidr_blocks   = [for index in range(3) : cidrsubnet(var.vpc_cidr, 8, local.public_subnet_offset + index)]
  relay_subnet_cidr_blocks    = [for index in range(3) : cidrsubnet(var.vpc_cidr, 8, local.relay_subnet_offset + index)]
  endpoint_subnet_cidr_blocks = [for index in range(3) : cidrsubnet(var.vpc_cidr, 8, local.endpoint_subnet_offset + index)]

  tags = merge(var.tags, {
    Environment = var.environment
    Component   = "relay-network"
    Service     = "nhp-relay"
  })
}

resource "aws_vpc" "relay" {
  cidr_block                           = var.vpc_cidr
  enable_dns_hostnames                 = true
  enable_dns_support                   = true
  enable_network_address_usage_metrics = true

  tags = merge(local.tags, { Name = "${var.name_prefix}-relay-dmz-vpc" })

  # Preserve the one-apply IAM propagation barrier without a module-level
  # depends_on, which would defer every provider data source and make security
  # policies unknowable in the required final saved plan.
  depends_on = [terraform_data.apply_role_ready]
}

resource "aws_internet_gateway" "relay" {
  vpc_id = aws_vpc.relay.id

  tags = merge(local.tags, { Name = "${var.name_prefix}-relay-dmz-igw" })
}

resource "aws_subnet" "public" {
  count = 3

  vpc_id                  = aws_vpc.relay.id
  cidr_block              = local.public_subnet_cidr_blocks[count.index]
  availability_zone       = local.azs[count.index]
  map_public_ip_on_launch = false

  tags = merge(local.tags, {
    Name = "${var.name_prefix}-relay-dmz-public-${local.azs[count.index]}"
    Tier = "public-alb"
  })
}

resource "aws_subnet" "relay" {
  count = 3

  vpc_id                  = aws_vpc.relay.id
  cidr_block              = local.relay_subnet_cidr_blocks[count.index]
  availability_zone       = local.azs[count.index]
  map_public_ip_on_launch = false

  tags = merge(local.tags, {
    Name = "${var.name_prefix}-relay-dmz-node-${local.azs[count.index]}"
    Tier = "isolated-relay"
  })
}

resource "aws_subnet" "endpoint" {
  count = 3

  vpc_id                  = aws_vpc.relay.id
  cidr_block              = local.endpoint_subnet_cidr_blocks[count.index]
  availability_zone       = local.azs[count.index]
  map_public_ip_on_launch = false

  tags = merge(local.tags, {
    Name = "${var.name_prefix}-relay-dmz-endpoint-${local.azs[count.index]}"
    Tier = "isolated-endpoint"
  })
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.relay.id

  tags = merge(local.tags, { Name = "${var.name_prefix}-relay-dmz-public" })
}

resource "aws_route" "public_default" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.relay.id
}

resource "aws_route_table" "relay" {
  count = 3

  vpc_id = aws_vpc.relay.id
  tags   = merge(local.tags, { Name = "${var.name_prefix}-relay-dmz-node-${local.azs[count.index]}" })
}

# Endpoint subnets intentionally do not share relay route tables. The S3
# gateway endpoint is attached only to relay route tables, so endpoint ENIs
# remain on local-only route tables.
resource "aws_route_table" "endpoint" {
  count = 3

  vpc_id = aws_vpc.relay.id
  tags   = merge(local.tags, { Name = "${var.name_prefix}-relay-dmz-endpoint-${local.azs[count.index]}" })
}

resource "aws_route_table_association" "public" {
  count = 3

  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "relay" {
  count = 3

  subnet_id      = aws_subnet.relay[count.index].id
  route_table_id = aws_route_table.relay[count.index].id
}

resource "aws_route_table_association" "endpoint" {
  count = 3

  subnet_id      = aws_subnet.endpoint[count.index].id
  route_table_id = aws_route_table.endpoint[count.index].id
}

resource "aws_vpc_peering_connection" "main" {
  vpc_id      = aws_vpc.relay.id
  peer_vpc_id = var.main_vpc_id
  auto_accept = true

  tags = merge(local.tags, { Name = "${var.name_prefix}-relay-dmz-main" })
}

resource "aws_vpc_peering_connection_options" "main" {
  vpc_peering_connection_id = aws_vpc_peering_connection.main.id

  requester {
    allow_remote_vpc_dns_resolution = true
  }

  accepter {
    allow_remote_vpc_dns_resolution = true
  }
}

resource "aws_route" "relay_to_main_private" {
  count = length(aws_route_table.relay) * length(var.main_private_subnet_cidr_blocks)

  route_table_id = aws_route_table.relay[floor(count.index / length(var.main_private_subnet_cidr_blocks))].id
  destination_cidr_block = var.main_private_subnet_cidr_blocks[
    count.index % length(var.main_private_subnet_cidr_blocks)
  ]
  vpc_peering_connection_id = aws_vpc_peering_connection.main.id
}

resource "aws_route" "main_private_to_relay" {
  count = length(var.main_private_route_table_ids) * length(local.relay_subnet_cidr_blocks)

  route_table_id = var.main_private_route_table_ids[
    floor(count.index / length(local.relay_subnet_cidr_blocks))
  ]
  destination_cidr_block = local.relay_subnet_cidr_blocks[
    count.index % length(local.relay_subnet_cidr_blocks)
  ]
  vpc_peering_connection_id = aws_vpc_peering_connection.main.id
}

resource "aws_security_group" "endpoints" {
  name_prefix = "${var.name_prefix}-relay-dmz-vpce-"
  description = "Relay DMZ interface endpoints; ingress is owned by modules/relay after its node SG exists."
  vpc_id      = aws_vpc.relay.id

  ingress = []
  egress  = []

  tags = merge(local.tags, { Name = "${var.name_prefix}-relay-dmz-vpce" })

  lifecycle {
    create_before_destroy = true
    ignore_changes        = [description, ingress, egress]
  }
}

resource "aws_cloudwatch_log_group" "flow" {
  name              = "/layerv/nhp/${var.environment}/relay-dmz/flow"
  retention_in_days = var.environment == "prod" ? 365 : 30
  kms_key_id        = aws_kms_key.logs.arn

  tags = merge(local.tags, { Name = "${var.name_prefix}-relay-dmz-flow" })
}

resource "aws_iam_role" "flow" {
  name = "${var.name_prefix}-relay-dmz-flow"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "vpc-flow-logs.amazonaws.com" }
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

  tags = local.tags

  depends_on = [terraform_data.apply_role_ready]
}

resource "aws_iam_role_policy" "flow" {
  name = "flow-logs"
  role = aws_iam_role.flow.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "DiscoverFlowLogGroup"
        Effect   = "Allow"
        Action   = "logs:DescribeLogGroups"
        Resource = "*"
      },
      {
        Sid      = "DescribeFlowLogStreams"
        Effect   = "Allow"
        Action   = "logs:DescribeLogStreams"
        Resource = local.flow_log_group_arn
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

resource "aws_flow_log" "relay" {
  vpc_id                   = aws_vpc.relay.id
  traffic_type             = "ALL"
  log_destination_type     = "cloud-watch-logs"
  log_destination          = aws_cloudwatch_log_group.flow.arn
  iam_role_arn             = aws_iam_role.flow.arn
  max_aggregation_interval = 60
  log_format               = "$${version} $${account-id} $${interface-id} $${srcaddr} $${dstaddr} $${srcport} $${dstport} $${protocol} $${packets} $${bytes} $${start} $${end} $${action} $${log-status} $${pkt-srcaddr} $${pkt-dstaddr} $${pkt-src-aws-service} $${pkt-dst-aws-service} $${flow-direction} $${traffic-path}"

  tags = merge(local.tags, { Name = "${var.name_prefix}-relay-dmz-flow" })

  depends_on = [aws_kms_key.logs]
}
