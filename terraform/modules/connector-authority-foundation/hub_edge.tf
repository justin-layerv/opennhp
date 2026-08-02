# Connector Hub public UDP edge (Step 5, slice 5a). DARK-FIRST: every resource
# is gated on local.hub_edge_enabled and count=0 until the edge apply flips
# var.hub_edge_enabled true, exactly like the authority runtime slice. When
# dark, the Control VPC keeps its no-public-edge posture (see network.tf).
#
# The edge is the authority's ONLY public listener: a UDP-443 network load
# balancer in three PUBLIC subnets fronting the Hub workers (added dark, in the
# ISOLATED subnets, by slice 5b). The isolated workload subnets are never
# weakened -- only this new public route table carries the internet default
# route, and the workers hold no public IP. The Hub speaks UDP only; the
# separate TCP-62207 health port is connect-only (endpoints/server/hub).
#
# Callers dial UDP 443; the NLB translates to the target group's UDP 62206,
# which is what the Hub container binds. Restrictive egress filters commonly
# drop high-numbered outbound UDP but leave 443 open for QUIC, so connector
# registration has to meet callers there.

locals {
  # Single dark-first gate for the whole public edge. Kept separate from the
  # authority runtime gate: the Hub NLB/edge is caller-facing, the runtime
  # functions are dark; they flip in independent applies.
  hub_edge_enabled = var.hub_edge_enabled
  hub_edge_count   = local.hub_edge_enabled ? 3 : 0
  hub_edge_toggle  = local.hub_edge_enabled ? 1 : 0

  # NLB-to-worker egress rules exist only when both the edge and a worker target
  # are live, so an edge-only deployment has no public path into the Control VPC.
  hub_nlb_worker_egress_count = local.hub_worker_count > 0 && local.hub_edge_enabled ? 1 : 0

  # Public subnets take the /28 blocks immediately after the three isolated
  # subnets (indices 0-2), so the two subnet families never overlap.
  hub_public_subnet_cidrs = [
    for index in range(3) : cidrsubnet(var.vpc_cidr, 8, index + 3)
  ]

  hub_udp_listener_parameter_name = "/${var.environment}/nhp/control/hub/udp-listener-arn"

  # Public Hub NLB name. Deliberately shortened (drops the `-control` segment
  # carried by local.name_prefix) and distinct so a null -> SG-attached edge
  # forces physical replacement. Defined once so `name` and its `Name` tag stay
  # in lockstep.
  hub_edge_lb_name = "layerv-nhp-${var.environment}-hub-edge"
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

# Source fence for the only public Hub listener. AWS cannot add a security group
# to an NLB that was created without one, so this group is attached in the
# aws_lb create request. Its ingress is the proof runner's exact persistent
# public /32; its target and health egress appear only when Hub workers are live.
resource "aws_security_group" "hub_nlb" {
  count = local.hub_edge_toggle

  name_prefix            = "${local.name_prefix}-hub-nlb-"
  description            = "Source-fenced Connector Hub public UDP NLB"
  vpc_id                 = aws_vpc.control.id
  revoke_rules_on_delete = true

  tags = merge(local.common_tags, {
    Name      = "${local.name_prefix}-hub-nlb"
    Component = "connector-hub-edge"
  })

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_vpc_security_group_ingress_rule" "hub_nlb_udp" {
  for_each = local.hub_edge_enabled ? toset(coalesce(var.hub_public_udp_ingress_cidrs, [])) : toset([])

  security_group_id = aws_security_group.hub_nlb[0].id
  description       = "Connector Hub UDP proof source ${each.value}"
  from_port         = 443
  to_port           = 443
  ip_protocol       = "udp"
  cidr_ipv4         = each.value

  tags = {
    Name = "${local.name_prefix}-hub-nlb-udp-${replace(each.value, "/", "-")}"
  }
}

# Public UDP-443 network load balancer. Internet-facing, in the edge subnets.
# The authority has no other public listener; TLS/HTTP are never exposed. The
# shortened, distinct name deliberately forces physical replacement of the
# already-created sandbox NLB: AWS rejects attaching an SG to an NLB that was
# originally created without one.
resource "aws_lb" "hub" {
  count = local.hub_edge_toggle

  name                             = local.hub_edge_lb_name
  internal                         = false
  load_balancer_type               = "network"
  subnets                          = aws_subnet.hub_public[*].id
  security_groups                  = [aws_security_group.hub_nlb[0].id]
  enable_cross_zone_load_balancing = true
  enable_deletion_protection       = local.is_prod

  # Pin the PrivateLink posture of the source fence instead of inheriting it.
  # This governs whether the SG above -- which admits exactly the reviewed
  # proof-runner /32 on UDP 443 -- is evaluated for traffic that reaches the
  # NLB through a VPC endpoint service. Read the threat model precisely, because
  # the naive reading is wrong in BOTH directions:
  #
  #   * AWS's documented default is to ENFORCE inbound rules on PrivateLink
  #     traffic; the setting exists to turn enforcement OFF. So an unset
  #     attribute is not an open bypass.
  #   * DescribeLoadBalancers OMITS the member entirely until it is set
  #     explicitly (it is `Required: No` with no documented response default),
  #     which is exactly what the live sandbox Hub edge returns today.
  #
  # So this is hardening, not an exploit fix: it converts an unpinned AWS
  # default into an asserted, Terraform-owned invariant, so that an out-of-band
  # flip to "off" becomes drift this repo can see. It also satisfies
  # .github/scripts/collect_udp_proof_deployment_evidence.py, which requires the
  # literal "on" of the live edge and cannot pass while the member is omitted.
  #
  # In-place ModifyLoadBalancerAttributes, NOT a replacement: the attribute is
  # Optional+Computed and not ForceNew, so this never re-runs the DNS repoint or
  # the canary/pin cycle. The Hub edge always carries exactly one SG (above), so
  # the value is unconditional here.
  enforce_security_group_inbound_rules_on_private_link_traffic = "on"

  tags = merge(local.common_tags, {
    Name = local.hub_edge_lb_name
  })

  lifecycle {
    create_before_destroy = true
  }
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
  port              = 443
  protocol          = "UDP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.hub[0].arn
  }
}

# NLB-to-worker rules are worker-gated so an edge-only deployment has no route
# from the public NLB to any Control-VPC workload. Client data is exactly UDP
# 62206; health is exactly TCP 62207.
resource "aws_vpc_security_group_egress_rule" "hub_nlb_udp" {
  count = local.hub_nlb_worker_egress_count

  security_group_id            = aws_security_group.hub_nlb[0].id
  description                  = "Connector Hub UDP to worker targets"
  from_port                    = 62206
  to_port                      = 62206
  ip_protocol                  = "udp"
  referenced_security_group_id = aws_security_group.hub_worker[0].id

  tags = {
    Name = "${local.name_prefix}-hub-nlb-udp-target"
  }
}

resource "aws_vpc_security_group_egress_rule" "hub_nlb_health" {
  count = local.hub_nlb_worker_egress_count

  security_group_id            = aws_security_group.hub_nlb[0].id
  description                  = "Connector Hub health checks to worker targets"
  from_port                    = 62207
  to_port                      = 62207
  ip_protocol                  = "tcp"
  referenced_security_group_id = aws_security_group.hub_worker[0].id

  tags = {
    Name = "${local.name_prefix}-hub-nlb-health-target"
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
