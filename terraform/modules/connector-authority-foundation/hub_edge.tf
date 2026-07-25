# Connector Hub public UDP edge (Step 5, slice 5a). DARK-FIRST: every resource
# is gated on local.hub_edge_enabled and count=0 until the edge apply flips
# var.hub_edge_enabled true, exactly like the authority runtime slice. When
# dark, the Control VPC keeps its no-public-edge posture (see network.tf).
#
# The edge is the authority's ONLY public listener: a UDP-62206 network load
# balancer in three PUBLIC subnets fronting the Hub workers (added dark, in the
# ISOLATED subnets, by slice 5b). The isolated workload subnets are never
# weakened -- only this new public route table carries the internet default
# route, and the workers hold no public IP. The Hub speaks UDP only; the
# separate TCP-62207 health port is connect-only (endpoints/server/hub).

locals {
  # Single dark-first gate for the whole public edge. Kept separate from the
  # authority runtime gate: the Hub NLB/edge is caller-facing, the runtime
  # functions are dark; they flip in independent applies.
  hub_edge_enabled = var.hub_edge_enabled
  hub_edge_count   = local.hub_edge_enabled ? 3 : 0
  hub_edge_toggle  = local.hub_edge_enabled ? 1 : 0

  # Public subnets take the /28 blocks immediately after the three isolated
  # subnets (indices 0-2), so the two subnet families never overlap.
  hub_public_subnet_cidrs = [
    for index in range(3) : cidrsubnet(var.vpc_cidr, 8, index + 3)
  ]

  hub_udp_listener_parameter_name = "/${var.environment}/nhp/control/hub/udp-listener-arn"
}

# Public edge subnets. No auto-assigned public IP: only the NLB occupies these
# subnets and it manages its own edge addresses; nothing else is placed here.
resource "aws_subnet" "hub_public" {
  count = local.hub_edge_count

  vpc_id                  = aws_vpc.control.id
  cidr_block              = local.hub_public_subnet_cidrs[count.index]
  availability_zone       = local.availability_zones[count.index]
  map_public_ip_on_launch = false

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-public-${local.availability_zones[count.index]}"
    Type = "public-edge"
  })
}

resource "aws_internet_gateway" "hub_edge" {
  count = local.hub_edge_toggle

  vpc_id = aws_vpc.control.id

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-edge-igw"
  })
}

# One public route table shared by the three edge subnets. The internet default
# route lives ONLY here; the isolated route tables (network.tf) stay local-only.
resource "aws_route_table" "hub_public" {
  count = local.hub_edge_toggle

  vpc_id = aws_vpc.control.id

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-public"
    Type = "public-edge"
  })
}

# Standalone route (never an inline route block -- the lexical contract forbids
# inline routes so a later edit cannot smuggle a route into an isolated table).
resource "aws_route" "hub_public_default" {
  count = local.hub_edge_toggle

  route_table_id         = aws_route_table.hub_public[0].id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.hub_edge[0].id
}

resource "aws_route_table_association" "hub_public" {
  count = local.hub_edge_count

  subnet_id      = aws_subnet.hub_public[count.index].id
  route_table_id = aws_route_table.hub_public[0].id
}

# Public UDP-62206 network load balancer. Internet-facing, in the edge subnets.
# The authority has no other public listener; TLS/HTTP are never exposed.
resource "aws_lb" "hub" {
  count = local.hub_edge_toggle

  name                             = "${local.name_prefix}-hub"
  internal                         = false
  load_balancer_type               = "network"
  subnets                          = aws_subnet.hub_public[*].id
  enable_cross_zone_load_balancing = true
  enable_deletion_protection       = local.is_prod

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-hub"
  })
}

# IP-target group: Fargate Hub tasks (slice 5b) register their awsvpc IPs. UDP
# data on 62206; health is a bare TCP connect on 62207 (the Hub health port
# accepts and immediately closes, reading no payload), never HTTP/UDP.
resource "aws_lb_target_group" "hub" {
  count = local.hub_edge_toggle

  name        = "${local.name_prefix}-hub"
  port        = 62206
  protocol    = "UDP"
  target_type = "ip"
  vpc_id      = aws_vpc.control.id

  preserve_client_ip = true

  health_check {
    protocol            = "TCP"
    port                = "62207"
    healthy_threshold   = 3
    unhealthy_threshold = 3
    interval            = 10
  }

  deregistration_delay = 30

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-hub"
  })
}

resource "aws_lb_listener" "hub" {
  count = local.hub_edge_toggle

  load_balancer_arn = aws_lb.hub[0].arn
  port              = 62206
  protocol          = "UDP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.hub[0].arn
  }
}

# Listener ARN for the Hub controller/proof plane (mirrors the cell server's
# /nhp/server/udp-listener-arn). CI/CD never rewrites this one, so no
# ignore_changes is needed.
resource "aws_ssm_parameter" "hub_udp_listener_arn" {
  count = local.hub_edge_toggle

  name  = local.hub_udp_listener_parameter_name
  type  = "String"
  value = aws_lb_listener.hub[0].arn

  tags = local.common_tags
}
