# -----------------------------------------------------------------------------
# Sandbox proof-edge DNS — the public A-alias records whose target NLBs live in
# roots that cannot emit their own Route 53 record:
#
#   * hub.nhp.layerv.xyz   -> Connector Hub public UDP:62206 NLB  (Step 5 / 5c).
#       The Hub NLB is owned by the Control root, where aws_route53_record is
#       lexically forbidden and the convergence contract admits only an exact
#       inventory.
#   * cell0.nhp.layerv.xyz -> cell0 NHP-server public UDP:62206 NLB (Step 7).
#       cell0's server NLB lives in the giant main sandbox root; a specific
#       record here OVERRIDES the broad `*.nhp.layerv.xyz` wildcard (which points
#       at the AC HTTPS NLB) so a knock to cell0.nhp.layerv.xyz reaches the
#       server's UDP:62206 edge, not the AC. Kept out of the main root so it is
#       not gated on that root's (currently B/G-broken) deploy.
#
# cell1.nhp.layerv.xyz is emitted by the cell1 root itself (it owns its NLB), so
# it is intentionally NOT here. Every NLB is resolved BY NAME via data.aws_lb, so
# this root stays fully decoupled from the other roots' state and each lookup
# survives an NLB replacement. The directory keeps its original `sandbox-hub-dns`
# name (and backend key) for state continuity.
# -----------------------------------------------------------------------------

locals {
  name_prefix = "layerv-nhp-sandbox-hub-dns"

  common_tags = merge(
    {
      Project     = "LayerV-NHP"
      Environment = var.environment
      ManagedBy   = "terraform"
      Component   = "connector-proof-edge-dns"
    },
    var.tags,
  )
}

# The live Connector Hub public UDP NLB, resolved by name. Fails the plan loudly
# if the Hub edge (slice 5a) is not yet deployed, and the postconditions assert
# we aliased the intended public UDP network load balancer rather than some other
# same-named resource.
data "aws_lb" "hub" {
  name = var.hub_nlb_name

  lifecycle {
    postcondition {
      condition     = self.load_balancer_type == "network"
      error_message = "Hub NLB ${var.hub_nlb_name} must be a network load balancer (UDP 62206 edge), got ${self.load_balancer_type}."
    }
    postcondition {
      condition     = self.internal == false
      error_message = "Hub NLB ${var.hub_nlb_name} must be internet-facing so hub.nhp.layerv.xyz resolves to a public edge."
    }
  }
}

# The live cell0 NHP-server public UDP:62206 NLB, resolved by name. Same
# postconditions as the Hub: a public network load balancer.
data "aws_lb" "cell0" {
  name = var.cell0_nlb_name

  lifecycle {
    postcondition {
      condition     = self.load_balancer_type == "network"
      error_message = "cell0 NLB ${var.cell0_nlb_name} must be a network load balancer (UDP 62206 edge), got ${self.load_balancer_type}."
    }
    postcondition {
      condition     = self.internal == false
      error_message = "cell0 NLB ${var.cell0_nlb_name} must be internet-facing so cell0.nhp.layerv.xyz resolves to a public edge."
    }
  }
}

# hub.nhp.layerv.xyz -> Hub NLB. Module name kept as "dns" (not "hub_dns") so the
# already-applied record's state address does not move.
module "dns" {
  source = "../../modules/dns"

  environment    = var.environment
  domain_name    = var.hub_dns_name # hub.nhp.layerv.xyz
  hosted_zone_id = var.hosted_zone_id
  nlb_dns_name   = data.aws_lb.hub.dns_name
  nlb_zone_id    = data.aws_lb.hub.zone_id
  name_prefix    = local.name_prefix
  tags           = local.common_tags

  skip_main_record = false
  create_wildcard  = false
}

# cell0.nhp.layerv.xyz -> cell0 server NLB (overrides the *.nhp.layerv.xyz
# wildcard for this exact name).
module "cell0_dns" {
  source = "../../modules/dns"

  environment    = var.environment
  domain_name    = var.cell0_dns_name # cell0.nhp.layerv.xyz
  hosted_zone_id = var.hosted_zone_id
  nlb_dns_name   = data.aws_lb.cell0.dns_name
  nlb_zone_id    = data.aws_lb.cell0.zone_id
  name_prefix    = local.name_prefix
  tags           = local.common_tags

  skip_main_record = false
  create_wildcard  = false
}
