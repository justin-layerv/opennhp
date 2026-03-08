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
  # Blue holds its EIPs, green needs its own. After switch, blue scales down and releases.
  eip_count = var.enable_blue_green ? local.resolved_max_capacity * 2 : local.resolved_max_capacity
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
