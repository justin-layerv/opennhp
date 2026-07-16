locals {
  interface_endpoint_services = {
    email          = "email"
    kms            = "kms"
    lambda         = "lambda"
    logs           = "logs"
    monitoring     = "monitoring"
    secretsmanager = "secretsmanager"
  }

  # No caller or function exists in this foundation. Every endpoint therefore
  # starts fail-closed. The authority-runtime PR must replace these policies
  # and add SG ingress in lockstep with exact execution/caller roles and alias
  # ARNs; merely deploying an endpoint never creates a usable RPC surface.
  deny_all_endpoint_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyUntilAuthorityRuntimeExists"
      Effect    = "Deny"
      Principal = "*"
      Action    = "*"
      Resource  = "*"
    }]
  })
}

resource "aws_security_group" "interface_endpoints" {
  name_prefix = "${local.name_prefix}-vpce-"
  description = "Dark Connector Authority endpoints; runtime adds exact caller ingress"
  vpc_id      = aws_vpc.control.id

  # Interface endpoints are inert until the runtime slice adds SG-to-SG 443
  # ingress alongside scoped policy.
  ingress = []
  egress  = []

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-vpce"
  })

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_vpc_endpoint" "interface" {
  for_each = local.interface_endpoint_services

  vpc_id              = aws_vpc.control.id
  service_name        = "com.amazonaws.${data.aws_region.current.region}.${each.value}"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true
  subnet_ids          = aws_subnet.isolated[*].id
  security_group_ids  = [aws_security_group.interface_endpoints.id]
  policy              = local.deny_all_endpoint_policy

  tags = merge(local.common_tags, {
    Name    = "${local.name_prefix}-vpce-${each.key}"
    Service = each.key
  })
}

resource "aws_vpc_endpoint" "dynamodb" {
  vpc_id            = aws_vpc.control.id
  service_name      = "com.amazonaws.${data.aws_region.current.region}.dynamodb"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = aws_route_table.isolated[*].id
  policy            = local.deny_all_endpoint_policy

  tags = merge(local.common_tags, {
    Name    = "${local.name_prefix}-vpce-dynamodb"
    Service = "dynamodb"
  })
}
