# Networking Module
# VPC, Subnets, Security Groups, VPC Endpoints

# ==================== Data Sources ====================

data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_region" "current" {}

# ==================== Locals ====================

locals {
  azs     = slice(data.aws_availability_zones.available.names, 0, 3)
  is_prod = var.environment == "prod"

  # Interface VPC endpoints to create. Always-on endpoints cover the
  # shared AWS services every workload in the VPC depends on; optional
  # endpoints gated by var.deploy_vpc_endpoints are for QURL-specific
  # services we're willing to pay the per-AZ hourly cost for.
  interface_endpoints = merge(
    {
      "ecr-api"          = "ecr.api"
      "ecr-dkr"          = "ecr.dkr"
      "guardduty-data"   = "guardduty-data" # Required for Runtime Monitoring agent on EC2
      "logs"             = "logs"
      "secretsmanager"   = "secretsmanager"
      "servicediscovery" = "servicediscovery"
      "ssm"              = "ssm"
      "ssmmessages"      = "ssmmessages"
    },
    var.deploy_vpc_endpoints ? {
      "sqs" = "sqs" # QURL license event queue
    } : {},
  )
}

# VPC
resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-vpc"
    Component = "networking"
  })
}

# Internet Gateway
resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-igw"
    Component = "networking"
  })
}

# Public Subnets
resource "aws_subnet" "public" {
  count                   = 3
  vpc_id                  = aws_vpc.main.id
  cidr_block              = cidrsubnet(var.vpc_cidr, 8, count.index)
  availability_zone       = local.azs[count.index]
  map_public_ip_on_launch = true

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-public-${local.azs[count.index]}"
    Type      = "public"
    Component = "networking"
  })
}

# Private Subnets (with NAT egress)
resource "aws_subnet" "private" {
  count             = 3
  vpc_id            = aws_vpc.main.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 8, count.index + 10)
  availability_zone = local.azs[count.index]

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-private-${local.azs[count.index]}"
    Type      = "private"
    Component = "networking"
  })
}

# Isolated Subnets (no internet access)
resource "aws_subnet" "isolated" {
  count             = 3
  vpc_id            = aws_vpc.main.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 8, count.index + 20)
  availability_zone = local.azs[count.index]

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-isolated-${local.azs[count.index]}"
    Type      = "isolated"
    Component = "networking"
  })
}

# Elastic IPs for NAT Gateways
resource "aws_eip" "nat" {
  count  = local.is_prod ? 3 : 1
  domain = "vpc"

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-nat-eip-${count.index}"
    Component = "networking"
  })
}

# NAT Gateways
resource "aws_nat_gateway" "main" {
  count         = local.is_prod ? 3 : 1
  allocation_id = aws_eip.nat[count.index].id
  subnet_id     = aws_subnet.public[count.index].id

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-nat-gw-${count.index}"
    Component = "networking"
  })

  depends_on = [aws_internet_gateway.main]
}

# Public Route Table
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-rtb-public"
    Component = "networking"
  })
}

# Private Route Tables (one per AZ for prod, shared for dev/sandbox)
resource "aws_route_table" "private" {
  count  = local.is_prod ? 3 : 1
  vpc_id = aws_vpc.main.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.main[count.index].id
  }

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-rtb-private-${count.index}"
    Component = "networking"
  })
}

# Isolated Route Table (no routes to internet)
resource "aws_route_table" "isolated" {
  vpc_id = aws_vpc.main.id

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-rtb-isolated"
    Component = "networking"
  })
}

# Route Table Associations - Public
resource "aws_route_table_association" "public" {
  count          = 3
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

# Route Table Associations - Private
resource "aws_route_table_association" "private" {
  count          = 3
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private[local.is_prod ? count.index : 0].id
}

# Route Table Associations - Isolated
resource "aws_route_table_association" "isolated" {
  count          = 3
  subnet_id      = aws_subnet.isolated[count.index].id
  route_table_id = aws_route_table.isolated.id
}

# VPC Flow Logs
resource "aws_cloudwatch_log_group" "flow_logs" {
  name              = "/layerv/nhp/${var.environment}/vpc-flow-logs"
  retention_in_days = local.is_prod ? 365 : 30
  kms_key_id        = var.logs_kms_key_arn

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-vpc-flow-logs"
    Component = "networking"
  })
}

resource "aws_iam_role" "flow_logs" {
  name = "${var.name_prefix}-vpc-flow-logs"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "vpc-flow-logs.amazonaws.com"
      }
    }]
  })

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-vpc-flow-logs"
    Component = "networking"
  })
}

resource "aws_iam_role_policy" "flow_logs" {
  name = "flow-logs"
  role = aws_iam_role.flow_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = [
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams"
      ]
      Effect   = "Allow"
      Resource = "${aws_cloudwatch_log_group.flow_logs.arn}:*"
    }]
  })
}

resource "aws_flow_log" "main" {
  vpc_id                   = aws_vpc.main.id
  traffic_type             = "ALL"
  log_destination_type     = "cloud-watch-logs"
  log_destination          = aws_cloudwatch_log_group.flow_logs.arn
  iam_role_arn             = aws_iam_role.flow_logs.arn
  max_aggregation_interval = 60

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-vpc-flow-log"
    Component = "networking"
  })
}

# VPC Endpoints
resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${data.aws_region.current.id}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids = concat(
    [aws_route_table.public.id],
    aws_route_table.private[*].id,
    [aws_route_table.isolated.id]
  )

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-vpce-s3"
    Component = "networking"
  })
}

resource "aws_security_group" "vpc_endpoints" {
  name_prefix = "${var.name_prefix}-vpce-"
  vpc_id      = aws_vpc.main.id
  description = "Security group for VPC interface endpoints"

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
    description = "HTTPS from VPC"
  }

  # VPC endpoints only need to respond to VPC traffic, not initiate external connections
  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
    description = "HTTPS responses to VPC"
  }

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-sg-vpce"
    Component = "networking"
  })

  lifecycle {
    create_before_destroy = true
  }
}

# Interface VPC Endpoints - consolidated with for_each
resource "aws_vpc_endpoint" "interface" {
  for_each = local.interface_endpoints

  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${data.aws_region.current.id}.${each.value}"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.private[*].id
  security_group_ids  = [aws_security_group.vpc_endpoints.id]
  private_dns_enabled = true

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-vpce-${each.key}"
    Component = "networking"
  })
}

# ==================== Network ACLs ====================
# Stateless firewall rules for defense-in-depth
# NACLs complement Security Groups with subnet-level protection

# Public Subnet NACL
resource "aws_network_acl" "public" {
  vpc_id     = aws_vpc.main.id
  subnet_ids = aws_subnet.public[*].id

  # Inbound: Allow HTTPS
  ingress {
    protocol   = "tcp"
    rule_no    = 100
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 443
    to_port    = 443
  }

  # Inbound: Allow HTTP (for redirects and ACME)
  ingress {
    protocol   = "tcp"
    rule_no    = 110
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 80
    to_port    = 80
  }

  # Inbound: Allow NHP UDP knock packets
  ingress {
    protocol   = "udp"
    rule_no    = 120
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 62206
    to_port    = 62206
  }

  # Inbound: Allow NHP TCP connector
  ingress {
    protocol   = "tcp"
    rule_no    = 130
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 4732
    to_port    = 4732
  }

  # Inbound: Allow Portal service
  ingress {
    protocol   = "tcp"
    rule_no    = 140
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 8888
    to_port    = 8888
  }

  # Inbound: Allow ephemeral ports (return traffic)
  ingress {
    protocol   = "tcp"
    rule_no    = 200
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 1024
    to_port    = 65535
  }

  ingress {
    protocol   = "udp"
    rule_no    = 210
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 1024
    to_port    = 65535
  }

  # Inbound: Allow from VPC (all traffic)
  ingress {
    protocol   = -1
    rule_no    = 300
    action     = "allow"
    cidr_block = var.vpc_cidr
    from_port  = 0
    to_port    = 0
  }

  # Outbound: Allow all
  egress {
    protocol   = -1
    rule_no    = 100
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-nacl-public"
    Component = "networking"
  })
}

# Private Subnet NACL
resource "aws_network_acl" "private" {
  vpc_id     = aws_vpc.main.id
  subnet_ids = aws_subnet.private[*].id

  # Inbound: Allow from VPC (all traffic)
  ingress {
    protocol   = -1
    rule_no    = 100
    action     = "allow"
    cidr_block = var.vpc_cidr
    from_port  = 0
    to_port    = 0
  }

  # Inbound: Allow HTTPS from internet (for NHP-protected resources behind public NLB)
  # NHP protection is always enabled, and internet traffic is routed directly to
  # Console EC2 in private subnets via the protected NLB.
  #
  # SCOPE: This rule applies to ALL private subnets in the VPC, not just Console.
  # Other services (etcd, RDS, etc.) are protected by their security groups which
  # don't allow port 443 from internet sources. iptables on Console EC2 handles
  # DROP until NHP knock succeeds - this NACL rule just enables network reachability.
  dynamic "ingress" {
    for_each = var.allow_private_ingress_443 ? [1] : []
    content {
      protocol   = "tcp"
      rule_no    = 150
      action     = "allow"
      cidr_block = "0.0.0.0/0"
      from_port  = 443
      to_port    = 443
    }
  }

  # Inbound: Allow NHP UDP knock packets from internet (for NHP Server behind NLB)
  # NLB preserves client IPs, so traffic appears to come from external sources.
  # The NHP Server runs in private subnets with NLB forwarding UDP traffic.
  ingress {
    protocol   = "udp"
    rule_no    = 160
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 62206
    to_port    = 62206
  }

  # Inbound: Allow ephemeral ports (return traffic from internet via NAT)
  ingress {
    protocol   = "tcp"
    rule_no    = 200
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 1024
    to_port    = 65535
  }

  # Outbound: Allow all to VPC
  egress {
    protocol   = -1
    rule_no    = 100
    action     = "allow"
    cidr_block = var.vpc_cidr
    from_port  = 0
    to_port    = 0
  }

  # Outbound: Allow HTTPS to internet (via NAT)
  egress {
    protocol   = "tcp"
    rule_no    = 200
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 443
    to_port    = 443
  }

  # Outbound: Allow HTTP (for package updates)
  egress {
    protocol   = "tcp"
    rule_no    = 210
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 80
    to_port    = 80
  }

  # Outbound: Allow ephemeral ports (for return traffic)
  egress {
    protocol   = "tcp"
    rule_no    = 300
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 1024
    to_port    = 65535
  }

  # Outbound: Allow UDP ephemeral ports (for NHP Server responses)
  # Responses to UDP knock packets need to reach external clients via NAT.
  egress {
    protocol   = "udp"
    rule_no    = 310
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 1024
    to_port    = 65535
  }

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-nacl-private"
    Component = "networking"
  })
}

# Isolated Subnet NACL (most restrictive)
resource "aws_network_acl" "isolated" {
  vpc_id     = aws_vpc.main.id
  subnet_ids = aws_subnet.isolated[*].id

  # Inbound: Allow from VPC only
  ingress {
    protocol   = -1
    rule_no    = 100
    action     = "allow"
    cidr_block = var.vpc_cidr
    from_port  = 0
    to_port    = 0
  }

  # Outbound: Allow to VPC only
  egress {
    protocol   = -1
    rule_no    = 100
    action     = "allow"
    cidr_block = var.vpc_cidr
    from_port  = 0
    to_port    = 0
  }

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-nacl-isolated"
    Component = "networking"
  })
}
