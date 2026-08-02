# ============================================================================
# Elastic IPs for AC Instances
# Provides stable public IPs for customer origin firewall whitelisting.
# Customers whitelist these IPs so their origin is only accessible through LayerV.
#
# Pool is shared across blue/green ASGs. Instances claim an available EIP
# at boot via user_data (retry with jitter for race conditions).
# AWS auto-disassociates EIPs on instance termination.
# ============================================================================

locals {
  # Blue/green needs 2x EIPs: during a switch, both ASGs run at full capacity.
  # Blue holds its EIPs, green needs its own. After switch, blue scales down
  # and releases.
  #
  # The `+ 1` slack is load-bearing, not cosmetic. During an instance refresh
  # on either color's ASG, AWS terminates one instance and launches its
  # replacement in a rolling fashion. For a brief window the terminating
  # instance is still associated with its EIP (AWS disassociates on
  # termination *initiation*, but the release is eventually-consistent) while
  # the new instance has already booted and is running user_data that tries
  # to claim an EIP from the pool. If the pool is sized exactly at
  # `max_capacity * 2`, that transient moment has zero free EIPs and the new
  # instance's claim script races its retry budget (a 300s deadline — see
  # eip_backoff_sleep in user_data.sh.tpl) against the disassociation. The
  # deadline-bounded retry now wins that race in almost all cases; this `+ 1`
  # is the terraform-side backstop for the transient window. When the race is
  # nonetheless lost (a genuinely exhausted pool), user_data FATAL-exits and the
  # instance comes up with no EIP → traefik and nhp-acd never start → the
  # blue/green workflow's Verify Standby Health step correctly rejects the
  # ASG and the whole deploy halts. Observed 2026-04-08 on sandbox: every
  # component=both refresh failed at the same step until this `+ 1` landed.
  # One extra EIP is enough because ASG instance refresh only replaces one
  # instance at a time when MinHealthyPercentage >= 100 - (1 / desired) * 100
  # (true for the default 90 with desired=3, and for all higher MHP values).
  eip_count = var.enable_blue_green ? local.resolved_max_capacity * 2 + 1 : local.resolved_max_capacity
}

resource "aws_eip" "ac" {
  count  = var.enable_egress_eips ? local.eip_count : 0
  domain = "vpc"

  tags = merge(var.tags, {
    Name      = "${var.name_prefix}-ac-eip-${count.index}"
    Component = "ac"
    EIPPool   = local.eip_pool_tag
  })
}

# AC cloud registration uses the cell's public NHP endpoint. A source-fenced
# NLB must therefore admit the complete managed AC EIP pool as well as the
# external proof source. Index keys keep the for_each shape plan-known on a
# first apply while the EIP addresses themselves are still provider-unknown.
# The port is the client-edge listener port (UDP 443) the AC's ConnectorClient
# dials — see endpoints/ac.DefaultServerPort — not the server's 62206 bind.
resource "aws_vpc_security_group_ingress_rule" "server_nlb_registration" {
  for_each = var.server_nlb_source_fenced ? {
    for index, address in aws_eip.ac :
    tostring(index) => "${address.public_ip}/32"
  } : {}

  security_group_id = var.server_nlb_security_group_id
  description       = "NHP AC registration source ${each.value}"
  from_port         = 443
  to_port           = 443
  ip_protocol       = "udp"
  cidr_ipv4         = each.value

  tags = {
    Name = "${var.name_prefix}-nlb-ac-registration-${each.key}"
  }
}
